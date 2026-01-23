# -*- coding: utf-8 -*-
# ApplyNb09StructsFromJson.py
# @category: Stars

from dataclasses import dataclass
from typing import Optional, Iterable

from ghidra_utils import (
    DEFAULT_CAT_PATH,
    StructEntry,
    StructField,
    c_type_to_data_type,
    datatype_from_decl_info,
    datatype_from_decl_info,
    load_nb09_structs,
    wrapped_datatype,
)

# make IDE register built ins
try:
    from ghidra.ghidra_builtins import *
    from ghidra.program.model.listing import *

    currentProgram = currentProgram  # type: Program
except:
    pass

from ghidra.program.model.data import (
    DataTypeManager,
    DataType,
    DataTypeConflictHandler,
    StructureDataType,
    UnionDataType,
    PointerDataType,
)


# Populated in main(): name -> size (bytes) for NB09 structs/unions.
_STRUCT_BY_NAME: dict[str, StructEntry] = {}
_DT_STRUCT_BY_NAME: dict[str, StructureDataType] = {}


@dataclass(frozen=True)
class FieldSpan:
    """
    A StructField with a computed byte span [start, end).
    """

    f: StructField
    start: int
    size: int
    end: int  # start + size

    def __str__(self) -> str:
        return (
            f"{self.f.name}"
            f"@0x{self.start:04x}"
            f"+{self.size}"
            f"[0x{self.start:04x}..0x{self.end:04x})"
        )

    def __repr__(self) -> str:
        return str(self)


@dataclass(frozen=True)
class OverlayPlan:
    """
    Plan for a struct-alternative within a union.
    """

    base: StructField
    members: list[tuple[int, StructField]]  # (rel_off, field)

    def __str__(self) -> str:
        parts = []
        for rel, f in self.members:
            parts.append(f"+0x{rel:02x}:{f.name}")
        inner = ", ".join(parts)
        return f"overlay(base={self.base.name}, {{{inner}}})"

    def __repr__(self) -> str:
        return str(self)


@dataclass(frozen=True)
class OverlapRegion:
    """
    A maximal contiguous overlap region discovered by sweep-line.
    """

    start: int
    end: int
    spans: list[FieldSpan]
    by_offset: dict[int, list[FieldSpan]]
    start_fields: list[FieldSpan]
    inner_fields: list[FieldSpan]

    def __str__(self) -> str:
        span_desc = ", ".join(str(s) for s in self.spans)

        start_desc = (
            "[" + ", ".join(s.f.name for s in self.start_fields) + "]"
            if self.start_fields
            else "[]"
        )

        inner_desc = (
            "[" + ", ".join(s.f.name for s in self.inner_fields) + "]"
            if self.inner_fields
            else "[]"
        )

        return (
            f"[sz:{self.end-self.start} 0x{self.start:04x}..0x{self.end:04x}) "
            f"spans={len(self.spans)} "
            f"start={start_desc} "
            f"inner={inner_desc} "
            f"{{ {span_desc} }}"
        )

    def __repr__(self) -> str:
        return str(self)


def _field_size_bytes(f: StructField) -> int:
    """
    Compute byte size of the field. Assumes base_dt is valid.
    For bitfields, you should have already materialized a container field, OR treat base_dt length as container.
    """
    dt: DataType = f.base_dt
    if dt is None:
        raise ValueError(f"base_dt is None for field {f.name} ({f.c_decl})")
    if isinstance(dt, PointerDataType):
        # ghidra api messes up and just assumes all pointers are 4 bytes...
        return 4 if f.is_far_ptr else 2
    ln = dt.getLength()
    if ln <= 0:
        raise ValueError(f"non-positive datatype length for field {f.name}: {ln}")
    return ln


def build_overlap_regions(
    rec: StructEntry, fields: list[StructField]
) -> list[OverlapRegion]:
    """
    Build overlap regions from a struct's fields.

    An "overlap region" is a maximal interval [start,end) where at least one pair of fields overlaps
    (directly or via a chain). Regions also include size-1 groups (no overlaps) for uniform handling.

    Returns regions sorted by region.start.
    """
    # Build spans
    spans: list[FieldSpan] = []
    for f in fields:
        start = int(f.offset)
        size = _field_size_bytes(f)
        println(
            f"[FieldSpan] {rec.name} {f.name} start: {start} size: {size} dt: {f.base_dt.name}"
        )
        spans.append(FieldSpan(f=f, start=start, size=size, end=start + size))

    # Sort by start, then by larger size first (helps union span inference)
    spans.sort(key=lambda s: (s.start, -s.size, s.f.name))

    regions: list[OverlapRegion] = []
    cur: list[FieldSpan] = []
    cur_end: Optional[int] = None
    cur_start: Optional[int] = None

    # Sweep-line grouping into maximal connected overlap components
    for sp in spans:
        if not cur:
            cur = [sp]
            cur_start = sp.start
            cur_end = sp.end
            continue

        assert cur_end is not None and cur_start is not None

        # Overlap test with current region: start < cur_end means it overlaps/touches inside.
        # NOTE: This uses *strict* overlap; touching at boundary does NOT overlap.
        # If you want "touching merges", change `sp.start >= cur_end` to `sp.start > cur_end`.
        if sp.start >= cur_end:
            regions.append(_finalize_region(cur_start, cur_end, cur))
            cur = [sp]
            cur_start = sp.start
            cur_end = sp.end
        else:
            cur.append(sp)
            if sp.end > cur_end:
                cur_end = sp.end

    if cur:
        assert cur_start is not None and cur_end is not None
        regions.append(_finalize_region(cur_start, cur_end, cur))

    return regions


def _finalize_region(start: int, end: int, spans: list[FieldSpan]) -> OverlapRegion:
    spans_sorted = sorted(spans, key=lambda s: (s.start, -s.size, s.f.name))

    by_off: dict[int, list[FieldSpan]] = {}
    for sp in spans_sorted:
        by_off.setdefault(sp.start, []).append(sp)

    start_fields = by_off.get(start, [])
    inner_fields = [sp for sp in spans_sorted if start < sp.start < end]

    return OverlapRegion(
        start=start,
        end=end,
        spans=spans_sorted,
        by_offset=by_off,
        start_fields=start_fields,
        inner_fields=inner_fields,
    )


def _bitfield_container_from_candidates(
    cand_fields: list[StructField],
) -> tuple[DataType, str]:
    """Choose a stable *scalar* container field to represent bitfields.

    We do not create Ghidra bitfield components, because they can be fragile
    across Ghidra versions and we primarily care about correct Win16 layout.

    Preference order:
      1) If the offset group already contains a non-bitfield raw member
         (e.g. 'uint16_t wMdPlr'), use that type+name.
      2) Otherwise infer the container width from the bitfield declared type
         (uint16_t/uint32_t) and synthesize a name.

    Returns (dt_field, fname) or (None, None).
    """

    # 1) Use existing raw container if present.
    best = None  # (flen, dt_field, fname)
    for f in cand_fields:
        if f.bitlen:
            continue
        dt = f.base_dt

        if dt is None:
            continue
        flen = dt.getLength()
        if best is None or flen > best[0]:
            best = (flen, dt, f.name)

    if best is not None:
        return best[1], best[2]

    # 2) Infer from any bitfield's c_type.
    want_name = None
    want_bits = None
    for f in cand_fields:
        if f.bitlen is None:
            continue
        if "32" in f.c_type:
            want_bits = 32
        elif "16" in f.c_type:
            want_bits = 16
        else:
            want_bits = 8
        break

    if want_bits is None:
        return None, None

    if want_bits == 32:
        dt_field = c_type_to_data_type("uint32_t")
        want_name = "dwFlags"
    elif want_bits == 16:
        dt_field = c_type_to_data_type("uint16_t")
        want_name = "wFlags"
    else:
        dt_field = c_type_to_data_type("uint8_t")
        want_name = "bFlags"

    if cand_fields[0].offset > 0:
        want_name = "%s_0x%0x" % (want_name, cand_fields[0].offset)
    if dt_field is None:
        return None, None

    return dt_field, want_name


def _initialize_data_types(
    dtm: DataTypeManager,
    rec: StructEntry,
):
    global _STRUCT_BY_NAME
    global _DT_STRUCT_BY_NAME

    name = rec.name

    # Structures: do NOT allow 0-length, or replaceAtOffset will throw in some builds.
    struct_dt: StructureDataType = StructureDataType(name, rec.size)
    struct_dt.setCategoryPath(DEFAULT_CAT_PATH)
    println(f"[STRUCT] create {rec.name} sz={rec.size} dt_size={struct_dt.length}")

    # set struct packing
    # struct_dt.setExplicitMinimumAlignment(1)
    # struct_dt.setExplicitPackingValue(1)

    # replace the existing struct with our new struct of size 1
    # we will add to it as we go
    struct_dt = dtm.addDataType(struct_dt, DataTypeConflictHandler.REPLACE_HANDLER)

    # go through each field and resolve its DataType, or if it's a struct, recursively create it
    for f in rec.fields:
        decl_info = f.decl
        if f.base_dt is not None:
            continue
        if decl_info.base == rec.name:
            # self reference, just make sure any pointers or arrays are wrapped
            f.base_dt = wrapped_datatype(struct_dt, decl_info, f.is_far_ptr)
            println(
                f"[FIELD] {struct_dt.getPathName()} {f.name} off={f.offset} {f.c_decl} size={f.base_dt.length} has base_dt"
            )
            continue
        if _DT_STRUCT_BY_NAME.get(decl_info.base) is not None:
            # a struct we've already added to the DTM, just make sure any pointers or arrays are wrapped
            f.base_dt = wrapped_datatype(
                _DT_STRUCT_BY_NAME.get(decl_info.base), decl_info, f.is_far_ptr
            )
            println(
                f"[FIELD] {struct_dt.getPathName()} {f.name} off={f.offset} {f.c_decl} size={f.base_dt.length} base in _DT_STRUCT_BY_NAME"
            )
            continue

        if (
            _STRUCT_BY_NAME.get(decl_info.base) is not None
            and _DT_STRUCT_BY_NAME.get(decl_info.base) is None
        ):
            # this is a struct in our json and we haven't created a DataType for it yet
            println(
                f"[FIELD] {struct_dt.getPathName()} {f.name} off={f.offset} {decl_info.base} has no base_dt"
            )
            # call this recursively to setup DataTypes
            dt = _initialize_data_types(
                dtm,
                _STRUCT_BY_NAME[decl_info.base],
            )
            # turn this into an array or pointer if necessary
            dt = wrapped_datatype(dt, decl_info, f.is_far_ptr)
            f.base_dt = dt
            println(
                f"[FIELD] {struct_dt.getPathName()} {f.name} off={f.offset} created dt {dt.getName()}"
            )
        else:
            println(
                f"[FIELD] {struct_dt.getPathName()} {f.name} off={f.offset} {decl_info.base}"
            )
        if f.base_dt is None:
            f.base_dt, err = datatype_from_decl_info(dtm, f.name, f.decl, f.is_far_ptr)
            println(
                f"[FIELD] {struct_dt.getPathName()} {f.name} off={f.offset} {decl_info.base} looked up in dtm: {f.base_dt} err: {err}"
            )
    # return the created struct
    _DT_STRUCT_BY_NAME[rec.name] = struct_dt
    return struct_dt


def _is_bitfield(f: StructField) -> bool:
    return f.bitlen is not None and f.bitlen > 0


def _check_fits(rec: StructEntry, off: int, size: int, what: str) -> None:
    # Allow size==0 at off==rec.size (zero-length array at end)
    if size < 0:
        raise ValueError(f"{rec.name}: {what}: negative size {size}")
    if size == 0 and off == rec.size:
        return
    end = off + size
    if off < 0 or end > rec.size:
        raise ValueError(
            f"{rec.name}: {what}: out of bounds off=0x{off:x} size=0x{size:x} "
            f"end=0x{end:x} > rec.size=0x{rec.size:x}"
        )


def _unique_name(used: set[str], name: str) -> str:
    if name not in used:
        used.add(name)
        return name
    i = 2
    while f"{name}_{i}" in used:
        i += 1
    name2 = f"{name}_{i}"
    used.add(name2)
    return name2


def _build_overlay_struct_for_union(
    dtm: DataTypeManager,
    rec: StructEntry,
    region: OverlapRegion,
    union_start: int,
    union_len: int,
) -> StructureDataType | None:
    """
    Build a struct alternative inside a union spanning [union_start, union_start+union_len).
    It lays out any fields that start within that span using replaceAtOffset.
    Bitfield groups become scalar containers via _bitfield_container_from_candidates.
    """
    union_end = union_start + union_len

    # Collect offsets inside union span
    offs = sorted(
        [off for off in region.by_offset.keys() if union_start <= off < union_end]
    )
    if not offs:
        return None

    # If there are no "inner" offsets (strictly > start), no overlay struct needed.
    if not any(off != union_start for off in offs):
        return None

    sdt = StructureDataType(f"s_{rec.name}_0x{union_start:04x}", 1)
    sdt.setCategoryPath(DEFAULT_CAT_PATH)
    sdt = dtm.addDataType(sdt, DataTypeConflictHandler.REPLACE_HANDLER)

    used: set[str] = set()

    # Add members for each offset group within the union span.
    for off in offs:
        group = region.by_offset.get(off, [])
        if not group:
            continue

        rel = off - union_start

        # Bitfield pack -> scalar container
        if any(_is_bitfield(sp.f) for sp in group):
            dtc, fname = _bitfield_container_from_candidates([sp.f for sp in group])
            if dtc is None:
                raise ValueError(
                    f"{rec.name}: overlay bitfield container unresolved at 0x{off:x}"
                )
            sz = dtc.getLength()
            if rel + sz > union_len:
                raise ValueError(
                    f"{rec.name}: overlay {fname} overflows union rel=0x{rel:x} sz=0x{sz:x} union_len=0x{union_len:x}"
                )
            nm = _unique_name(used, fname)
            sdt.replaceAtOffset(rel, dtc, sz, nm, "")
            continue

        # Non-bitfield: choose the largest view at that offset (most representative)
        best = None  # (size, field)
        for sp in group:
            f = sp.f
            if f.base_dt is None:
                continue
            sz = f.base_dt.getLength()
            if best is None or sz > best[0]:
                best = (sz, f)
        if best is None:
            continue

        sz, f = best
        if rel + sz > union_len:
            raise ValueError(
                f"{rec.name}: overlay {f.name} overflows union rel=0x{rel:x} sz=0x{sz:x} union_len=0x{union_len:x}"
            )
        nm = _unique_name(used, f.name)
        sdt.replaceAtOffset(rel, f.base_dt, sz, nm, "")

    return sdt


def main():
    # currentProgram and UI helpers are provided by Ghidra at runtime.
    dtm = currentProgram.getDataTypeManager()

    json_file = askFile("Select nb09_ghidra_globals.json", "Open")
    path = json_file.getAbsolutePath()

    root = load_nb09_structs(path)

    # Pre-index declared sizes so forward references (e.g. POINT before definition) can create
    # correctly-sized placeholder structs instead of 1-byte typedefs.
    global _STRUCT_BY_NAME
    _STRUCT_BY_NAME = {}
    for r in root.structs:
        _STRUCT_BY_NAME[r.name] = r

    from ghidra.program.model.data import UnionDataType

    # Main emission
    for rec in root.structs:
        struct_dt: StructureDataType = _initialize_data_types(dtm, rec)
        regions: list[OverlapRegion] = build_overlap_regions(rec, rec.fields)

        for r in regions:
            println(f"[STRUCT]: {rec.name}: region: {r}")

            # Single-span region => place the field directly
            if len(r.spans) == 1:
                span = r.spans[0]
                field = span.f
                dt: DataType = field.base_dt

                if span.start == rec.size:
                    # probably a zero-length array at end (e.g. rgtok[0])
                    struct_dt.add(dt, field.name, "")
                    println(
                        f"[FIELD]: {rec.name}: {field.name} off={field.offset} size=0 add zero length array"
                    )
                else:
                    _check_fits(rec, span.start, span.size, f"field {field.name}")
                    struct_dt.replaceAtOffset(span.start, dt, span.size, field.name, "")
                    println(
                        f"[FIELD]: {rec.name}: {field.name} off={field.offset} size={dt.getLength()}"
                    )
                continue

            # Multi-span region: decide whether it's a bitfield-pack container or a union
            start_group = r.start_fields
            if not start_group:
                continue

            # Bitfield pack (or union containing raw+bitfields): use a stable scalar container
            if any(_is_bitfield(sp.f) for sp in start_group):
                dtc, fname = _bitfield_container_from_candidates(
                    [sp.f for sp in start_group]
                )
                if dtc is None:
                    raise ValueError(
                        f"{rec.name}: bitfield container unresolved at 0x{r.start:x}"
                    )
                sz = dtc.getLength()
                _check_fits(rec, r.start, sz, f"bitfield container {fname}")
                struct_dt.replaceAtOffset(r.start, dtc, sz, fname, "")
                println(
                    f"[BITFIELD]: {rec.name}: {fname} off=0x{r.start:04x} size={sz}"
                )
                continue

            # True union at region.start
            union_start = r.start
            union_len = max(sp.size for sp in start_group)

            _check_fits(
                rec, union_start, union_len, f"union u_{rec.name}_0x{union_start:04x}"
            )

            udt = UnionDataType(f"u_{rec.name}_0x{union_start:04x}")
            udt.setCategoryPath(DEFAULT_CAT_PATH)

            used: set[str] = set()

            # Add same-offset alternatives
            for sp in start_group:
                f = sp.f
                dt = f.base_dt
                nm = _unique_name(used, f.name)
                udt.add(dt, dt.getLength(), nm, "")

            # If there are inner fields inside the union span, build an overlay struct alternative
            if r.inner_fields:
                overlay = _build_overlay_struct_for_union(
                    dtm, rec, r, union_start, union_len
                )
                if overlay is not None:
                    udt.add(overlay, overlay.getLength(), overlay.getName(), "")
                    println(
                        f"[UNION-OVERLAY]: {rec.name}: off=0x{union_start:04x} add {overlay.getName()}"
                    )

            # Place union in parent struct
            struct_dt.replaceAtOffset(union_start, udt, union_len, udt.getName(), "")
            println(
                f"[UNION]: {rec.name}: {udt.getName()} off=0x{union_start:04x} len={union_len}"
            )

        # Enable packing only after all components are placed
        struct_dt.setExplicitPackingValue(1)
        struct_dt.setExplicitMinimumAlignment(1)

        got = struct_dt.getLength()
        if got > rec.size:
            raise ValueError(
                f"{rec.name}: struct too big: ghidra_len=0x{got:x} > rec.size=0x{rec.size:x}"
            )

        println(f"[STRUCT]: finalized: {rec.name} size: {got} wanted_size: {rec.size}")


main()
