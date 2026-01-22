# -*- coding: utf-8 -*-
# ApplyNb09StructsFromJson.py
# @category: Stars


from ghidra_utils import (
    StructEntry,
    StructField,
    c_type_to_data_type,
    datatype_from_decl_info,
    datatype_from_decl_info,
    load_nb09_structs,
    parse_c_decl,
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
    CategoryPath,
    DataTypeConflictHandler,
    StructureDataType,
    UnionDataType,
)


_DEFAULT_CAT_PATH = CategoryPath("/stars")
_WINDOWS_CAT_PATH = CategoryPath("/windows")

# Some Win16 "typedef" structs live under a separate category path.
# Map struct/typedef name -> CategoryPath.
_STRUCT_CAT_PATH_OVERRIDES = {
    # "POINT": _WINDOWS_CAT_PATH,
    # "RECT": _WINDOWS_CAT_PATH,
    # "LOGFONT": _WINDOWS_CAT_PATH,
    # "TEXTMETRIC": _WINDOWS_CAT_PATH,
    # "PAINTSTRUCT": _WINDOWS_CAT_PATH,
    # "DRAWITEMSTRUCT": _WINDOWS_CAT_PATH,
    # "MEASUREITEMSTRUCT": _WINDOWS_CAT_PATH,
    # "WNDCLASS": _WINDOWS_CAT_PATH,
    # "WINDOWPLACEMENT": _WINDOWS_CAT_PATH,
    # "MSG": _WINDOWS_CAT_PATH,
    # "OPENFILENAME": _WINDOWS_CAT_PATH,
    # "TIMERINFO": _WINDOWS_CAT_PATH,
    # "PD": _WINDOWS_CAT_PATH,
    # "BITMAP": _WINDOWS_CAT_PATH,
    # "BITMAPCOREHEADER": _WINDOWS_CAT_PATH,
    # "BITMAPINFOHEADER": _WINDOWS_CAT_PATH,
    # "BITMAPINFO": _WINDOWS_CAT_PATH,
    # "LOGPALETTE": _WINDOWS_CAT_PATH,
    # "OFSTRUCT": _WINDOWS_CAT_PATH,
}

# Populated in main(): name -> size (bytes) for NB09 structs/unions.
_STRUCT_BY_NAME: dict[str, StructEntry] = {}
_DT_STRUCT_BY_NAME: dict[str, StructureDataType] = {}


def _bitfield_container_from_candidates(
    dtm: DataTypeManager,
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
        dt, err = datatype_from_decl_info(dtm, f.name, f.decl, f.is_far_ptr)

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


def build_union_from_candidate_fields(
    rec: StructEntry, cand_fields: list[StructField]
) -> UnionDataType:
    """
    Build a Ghidra UnionDataType from NB09 "same offset" candidates.

    Assumptions (matches your current pipeline):
      - Each StructField in cand_fields already has .base_dt computed (wrapped for pointers/arrays).
      - Bitfields are NOT passed here (your caller should route bitfield groups elsewhere).

    Raises:
      - ValueError if cand_fields is empty or any member datatype is unresolved.
    """

    if not cand_fields:
        raise ValueError("cand_fields is empty")

    off = int(cand_fields[0].offset)
    udt = UnionDataType("u_%s_0x%04x" % (rec.name, off))

    used_names: set[str] = set()
    for f in cand_fields:
        dt: DataType = f.base_dt
        if dt is None:
            raise ValueError(
                "union member unresolved: name=%s offset=0x%x c_decl=%s"
                % (f.name, int(f.offset), f.c_decl)
            )

        # Ensure unique member names (Ghidra unions dislike duplicates)
        base_name = f.name or "m"
        name = base_name
        if name in used_names:
            i = 2
            while True:
                cand = "%s_%d" % (base_name, i)
                if cand not in used_names:
                    name = cand
                    break
                i += 1
        used_names.add(name)

        # UnionDataType.add(DataType, int length, String name, String comment)
        # The length parameter is ignored by unions in practice; pass dt.getLength()
        # so it’s consistent and explicit.
        dt_len = dt.getLength()
        if dt_len <= 0:
            raise ValueError(
                "union member has non-positive length: name=%s dt=%s len=%d"
                % (name, dt.getName(), dt_len)
            )

        udt.add(dt, dt_len, name, "")

    return udt


def _cat_path_for_name(name, fallback):
    """Return CategoryPath override for specific Win16 typedef structs, else fallback."""

    # Exact
    cp = _STRUCT_CAT_PATH_OVERRIDES.get(name)
    if cp is not None:
        return cp

    return fallback


def _dump_struct(struct_dt: StructureDataType, max_comps=40):
    """Debug dump of structure components."""
    println(
        "[DUMP] struct=%s len=%d" % (struct_dt.getPathName(), struct_dt.getLength())
    )

    comps = list(struct_dt.getComponents())
    for i, c in enumerate(comps):
        if i >= max_comps:
            println("[DUMP] ... (%d more comps)" % (len(comps) - max_comps))
            break
        println(
            "[DUMP]  off=0x%x len=0x%x dt=%s name=%s"
            % (
                c.getOffset(),
                c.getLength(),
                c.getDataType().getName(),
                c.getFieldName(),
            )
        )


def _create_struct_or_union_from_json(
    dtm: DataTypeManager,
    rec: StructEntry,
    cat_path: CategoryPath,
):
    global _STRUCT_BY_NAME
    global _DT_STRUCT_BY_NAME

    name = rec.name
    size = rec.size

    # Structures: do NOT allow 0-length, or replaceAtOffset will throw in some builds.
    struct_dt: StructureDataType = StructureDataType(name, 1)
    struct_dt.setCategoryPath(cat_path)

    # set struct packing
    struct_dt.setExplicitMinimumAlignment(1)
    struct_dt.setExplicitPackingValue(1)

    # replace the existing struct with our new struct of size 1
    # we will add to it as we go
    struct_dt = dtm.addDataType(struct_dt, DataTypeConflictHandler.REPLACE_HANDLER)

    for f in rec.fields:
        decl_info = f.decl
        if decl_info.base == rec.name:
            f.base_dt = wrapped_datatype(struct_dt, decl_info, f.is_far_ptr)
            continue
        if f.base_dt is not None:
            continue
        if _DT_STRUCT_BY_NAME.get(decl_info.base) is not None:
            f.base_dt = wrapped_datatype(
                _DT_STRUCT_BY_NAME.get(decl_info.base), decl_info, f.is_far_ptr
            )
            continue
        if _DT_STRUCT_BY_NAME.get(decl_info.base) is None:
            # this isn't a struct we are going to reload, so try and load the DataType from the decl_info
            dt, err = datatype_from_decl_info(dtm, f.name, decl_info, f.is_far_ptr)
            if dt is not None:
                f.base_dt = dt
                continue

        # create any structs we depend on first
        if (
            _STRUCT_BY_NAME.get(decl_info.base, None) is not None
            and _DT_STRUCT_BY_NAME.get(decl_info.base) is None
        ):
            println(
                f"[FIELD] {struct_dt.getPathName()} {f.name} off={f.offset} {decl_info.base} has no base_dt"
            )
            # this is a struct, create it first
            dt = _create_struct_or_union_from_json(
                dtm,
                _STRUCT_BY_NAME[decl_info.base],
                _cat_path_for_name(decl_info.base, _DEFAULT_CAT_PATH),
            )
            # turn this into an array or pointer if necessary
            dt = wrapped_datatype(dt, decl_info, f.is_far_ptr)
            f.base_dt = dt
            println(
                f"[FIELD] {struct_dt.getPathName()} {f.name} off={f.offset} created dt {dt.getName()}"
            )
        else:
            println(
                f"[FIELD] {struct_dt.getPathName()} {f.name} off={f.offset} {decl_info.base} base_dt already in _DT_STRUCT_BY_NAME, or not struct"
            )

    # Process in offset order to avoid back-filling issues.
    #
    # IMPORTANT: NB09 represents anonymous unions by emitting multiple "member" entries
    # that share the same offset. If we naively place them in sequence, the later entry
    # will delete/overwrite the earlier one, often leaving the smaller alternative plus a
    # tail of undefined1 fillers (e.g. FLEET: union { DV rgdv[16]; int32_t wtFleet; }).
    #
    # Strategy: group members by offset; for each offset, place the *widest* successfully
    # parsed member (this produces the correct packed layout with no undefined gaps).
    # We still keep bitfield containers as a special case.
    members_by_off: dict[int, list[StructField]] = {}
    for f in rec.fields:
        off = f.offset
        members_by_off.setdefault(off, []).append(f)

    next_off = 0
    for off in sorted(members_by_off.keys()):
        if off < next_off:
            # we placed a uint16_t or uint32_t for a bitfield
            # and need to skip
            continue
        cand_fields = members_by_off.get(off) or []
        if len(cand_fields) > 1:
            has_bitfield = False
            for cf in cand_fields:
                if cf.bitlen is not None and cf.bitlen > 0:
                    has_bitfield = True
                    break
            if has_bitfield:
                println(f"[FIELD] {struct_dt.getPathName()} off={off} bitfields")
                dt, field_name = _bitfield_container_from_candidates(dtm, cand_fields)
                if dt is None:
                    println(
                        f"[WARN] {struct_dt.getPathName()} off={off} UNABLE TO DETERMINE"
                    )
                    continue

                # add the bit field
                struct_dt.add(dt, field_name, "")
                next_off = off + dt.getLength()
                println(
                    f"[FIELD] {struct_dt.getPathName()} off={off} bitfield {field_name} {dt.getLength()} bytes, next_off={next_off}"
                )
                continue
            else:
                # add a union
                println(
                    f"[FIELD] {struct_dt.getPathName()} off={off} is union of {len(cand_fields)} fields"
                )
                udt = build_union_from_candidate_fields(rec, cand_fields)
                struct_dt.add(udt, udt.getName(), "")

        if len(cand_fields) == 1:
            cf = cand_fields[0]
            dt = cf.base_dt

            if dt is None:
                if decl_info.base == rec.name:
                    # pointer to ourselves
                    dt = struct_dt
                else:
                    println(
                        f"[FIELD] {struct_dt.getPathName()} off={off} field={cf.name} c_decl={cf.c_decl} UNABLE TO RESOLVE BASE TYPE"
                    )
                    continue

            # add the field with this datatype
            struct_dt.add(dt, cf.name, "")

    struct_dt = dtm.addDataType(struct_dt, DataTypeConflictHandler.REPLACE_HANDLER)
    _DT_STRUCT_BY_NAME[rec.name] = struct_dt

    println(
        "[STRUCT] %s created/replaced size_json=%d ghidra_len=%d"
        % (struct_dt.getPathName(), size, struct_dt.getLength())
    )

    if struct_dt.getLength() < size:
        println(
            "[WARN] %s wrong size size_json=%d ghidra_len=%d"
            % (struct_dt.getPathName(), size, struct_dt.getLength())
        )

    return struct_dt


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
    try:
        for r in root.structs:
            _STRUCT_BY_NAME[r.name] = r
    except Exception as e:
        println("[WARN] size preindex failed: %s" % str(e))

    # Default category for Stars! project datatypes
    default_cat_path = _DEFAULT_CAT_PATH

    created = 0
    for rec in root.structs:
        name = rec.name

        cat_path = _cat_path_for_name(name, default_cat_path)
        dt = _create_struct_or_union_from_json(dtm, rec, cat_path)
        if dt is not None:
            created += 1
            println("[CREATED] %s size=%d" % (name, dt.getLength()))

    println("ApplyNb09StructsFromJson.py> Created: %d" % created)


main()
