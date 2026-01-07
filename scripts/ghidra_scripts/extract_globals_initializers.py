#!/usr/bin/env python3
"""
Extract primitive global variable initializers from a 16-bit EXE using nb09_ghidra_globals.json.

- Uses `globals[*].ghidra.addr` (SEG:OFF) from the JSON.
- Uses `segments.csv` (exported from Ghidra) to map SEG:OFF -> file offset.
- Emits a C file with definitions + initializers for:
    * primitive kinds: int8/uint8/char, int16/uint16, int32/uint32
    * arrays of those primitives (1D or multi-D)
- Skips pointers, structs/unions, and arrays of structs.

Example:
    python3 extract_globals_initializers.py \
        --exe stars26jrc3.exe \
        --segments segments.csv \
        --globals nb09_ghidra_globals.json \
        --out globals_initializers.c
"""
from __future__ import annotations
import argparse
import json
import math
import re
import struct
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Iterable, Any


# ----------------------------
# Type parsing (types.h)
# ----------------------------

@dataclass(frozen=True)
class FieldDef:
    name: str
    c_type: str
    offset: int


@dataclass(frozen=True)
class StructDef:
    name: str
    size: int
    fields: Tuple[FieldDef, ...]


def _strip_c_comments(s: str) -> str:
    # Remove /* */ and // comments.
    s = re.sub(r"/\*.*?\*/", "", s, flags=re.S)
    s = re.sub(r"//.*?$", "", s, flags=re.M)
    return s


def parse_types_h_structs(types_h_path: str) -> Dict[str, StructDef]:
    """Parse a subset of types.h to recover struct layouts.

    We rely on per-field offset comments in types.h like:  `/* +0x0036 */`.
    This matches the format emitted by your nb09 struct dumping.
    """
    txt = open(types_h_path, "r", encoding="utf-8", errors="replace").read()

    # Match blocks like:
    # /* typind .... size=78 */
    # typedef struct _engine { ... } ENGINE;
    struct_re = re.compile(
        r"/\*\s*typind\s+\d+\s*\([^)]*\)\s*size=(\d+)\s*\*/\s*"
        r"typedef\s+struct\s+[^\{]*\{(.*?)\}\s*([A-Za-z_]\w*)\s*;",
        re.S,
    )

    field_re = re.compile(
        r"^\s*(?P<decl>[^;]+?)\s*;\s*/\*\s*\+0x(?P<off>[0-9a-fA-F]+)\s*\*/\s*$",
        re.M,
    )

    out: Dict[str, StructDef] = {}
    for m in struct_re.finditer(txt):
        size = int(m.group(1))
        body = m.group(2)
        name = m.group(3)

        fields: List[FieldDef] = []
        for fm in field_re.finditer(body):
            decl = fm.group("decl").strip()
            off = int(fm.group("off"), 16)

            # Skip unions/anonymous structs/bitfields/function pointers.
            if decl.startswith("union") or decl.startswith("struct"):
                continue
            if ":" in decl:
                continue
            if "(*" in decl:
                continue

            decl_nc = _strip_c_comments(decl).strip()
            parts = decl_nc.split()
            if len(parts) < 2:
                continue

            field_name = parts[-1]
            field_type = " ".join(parts[:-1]).strip()

            # Normalize array decls: name like foo[3][4]
            if "[" in field_name:
                nm = field_name.split("[")[0]
                dims = re.findall(r"\[(\d+)\]", field_name)
                field_name = nm
                field_type = field_type + "".join(f"[{d}]" for d in dims)

            fields.append(FieldDef(name=field_name, c_type=field_type, offset=off))

        out[name] = StructDef(name=name, size=size, fields=tuple(sorted(fields, key=lambda f: f.offset)))

    return out


# Backwards-compat alias (some earlier iterations used a different name).
parse_types_h_structs_from_file = parse_types_h_structs

@dataclass(frozen=True)
class SegRange:
    seg: int
    start_off: int
    end_off: int
    file_base: int
    name: str

def parse_seg_off(s: str) -> Tuple[int, int]:
    seg_s, off_s = s.split(":")
    return int(seg_s, 16), int(off_s, 16)

def parse_file_base(byte_source: str) -> Optional[int]:
    m = re.search(r"0x[0-9a-fA-F]+", str(byte_source))
    return int(m.group(0), 16) if m else None

def load_seg_ranges(segments_csv: str) -> Dict[int, List[SegRange]]:
    import csv
    by_seg: Dict[int, List[SegRange]] = {}
    with open(segments_csv, "r", newline="", encoding="utf-8") as f:
        r = csv.DictReader(f)
        for row in r:
            if "Start" not in row or "End" not in row or "Byte Source" not in row:
                continue
            seg, start_off = parse_seg_off(row["Start"])
            seg2, end_off = parse_seg_off(row["End"])
            if seg != seg2:
                continue
            base = parse_file_base(row["Byte Source"])
            if base is None:
                continue
            name = row.get("Name", "")
            by_seg.setdefault(seg, []).append(SegRange(seg, start_off, end_off, base, name))
    for seg in by_seg:
        by_seg[seg].sort(key=lambda x: x.start_off)
    return by_seg

def find_file_offset(seg_ranges_by_seg: Dict[int, List[SegRange]], seg: int, off: int) -> Optional[int]:
    ranges = seg_ranges_by_seg.get(seg)
    if not ranges:
        return None
    for r in ranges:
        if r.start_off <= off <= r.end_off:
            return r.file_base + (off - r.start_off)
    return None



# Some logical segments represent uninitialized/common data. Even if Ghidra maps bytes from the EXE,
# these locations are expected to be zero-initialized at load time (BSS / COMMON).
_ZERO_INIT_SEGNAMES = {"c_common", "_BSS"}

def is_zero_init_segment(segname: str) -> bool:
    return (segname or "").strip() in _ZERO_INIT_SEGNAMES

def zero_initializer_for_type(c_type: str, structs: Dict[str, Any]) -> str:
    ct = (c_type or "").strip()
    # Arrays and structs/unions can be succinctly zero-initialized with {0}
    if "[" in ct or ct in structs:
        return "{0}"
    # Scalar arithmetic types
    return "0"
def parse_array_dims(c_type: str) -> Tuple[str, List[int]]:
    base = re.split(r"\[", c_type)[0].strip()
    dims = [int(x) for x in re.findall(r"\[(\d+)\]", c_type)]
    return base, dims

def sizeof_ctype(base: str) -> Optional[Tuple[int, bool]]:
    """
    Return (size_bytes, signed) for primitives we support.
    """
    mapping = {
        "char": (1, True),
        "int8_t": (1, True),
        "uint8_t": (1, False),
        "byte": (1, False),

        "int16_t": (2, True),
        "uint16_t": (2, False),
        "short": (2, True),
        "unsigned short": (2, False),

        "int32_t": (4, True),
        "uint32_t": (4, False),
        "long": (4, True),
        "unsigned long": (4, False),

        # Add more here if you want (float/double etc)
    }
    return mapping.get(base)

def is_printable_byte(b: int) -> bool:
    return 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D)

def c_escape_bytes_as_string(bs: bytes) -> str:
    out: List[str] = []
    for b in bs:
        ch = chr(b)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif 0x20 <= b <= 0x7E:
            out.append(ch)
        else:
            out.append(f"\\x{b:02x}")
    return "".join(out)

def format_scalar(val: int, base: str, signed: bool) -> str:
    if base in ("char", "int8_t", "byte", "uint8_t"):
        if signed and base != "uint8_t":
            return str(int(val))
        return f"0x{int(val) & 0xFF:02x}"
    if base in ("int16_t", "short", "int32_t", "long"):
        return str(int(val))
    if base in ("uint16_t", "unsigned short"):
        return f"0x{int(val):04x}"
    if base in ("uint32_t", "unsigned long"):
        return f"0x{int(val):08x}"
    return str(val)

def format_array_initializer(base: str, dims: List[int], bs: bytes) -> str:
    s = sizeof_ctype(base)
    if not s:
        raise ValueError(f"unknown base type {base!r}")
    elem_size, signed = s

    # Special-case: char[N] -> string literal if it's mostly printable (including embedded \0)
    if base == "char" and len(dims) == 1:
        if all(is_printable_byte(b) or b == 0 for b in bs):
            return f"\"{c_escape_bytes_as_string(bs)}\""

    total = 1
    for d in dims:
        total *= d

    fmt_char = {1: ("b" if signed else "B"),
                2: ("h" if signed else "H"),
                4: ("i" if signed else "I")}[elem_size]
    vals = list(struct.unpack("<" + fmt_char * total, bs[:elem_size * total]))

    def rec(vs: List[int], ds: List[int]) -> str:
        if len(ds) == 1:
            return "{ " + ", ".join(format_scalar(v, base, signed) for v in vs) + " }"
        stride = math.prod(ds[1:])
        parts = [rec(vs[i * stride:(i + 1) * stride], ds[1:]) for i in range(ds[0])]
        return "{ " + ", ".join(parts) + " }"

    return rec(vals, dims)


# ----------------------------
# Struct decoding / formatting
# ----------------------------

def _unpack_primitive(bs: bytes, base: str) -> Optional[int]:
    s = sizeof_ctype(base)
    if not s:
        return None
    size, signed = s
    if len(bs) < size:
        return None
    fmt = {1: ("b" if signed else "B"),
           2: ("h" if signed else "H"),
           4: ("i" if signed else "I"),
           8: ("q" if signed else "Q")}[size]
    return int(struct.unpack("<" + fmt, bs[:size])[0])


def format_char_array_as_c_string(bs: bytes) -> Optional[str]:
    if not bs:
        return "\"\""
    cut = bs.split(b"\x00", 1)[0]
    if all(is_printable_byte(b) for b in cut):
        return f"\"{c_escape_bytes_as_string(cut)}\""
    return None


def format_struct_initializer(sd: StructDef, bs: bytes, structs: Dict[str, StructDef], _depth: int = 0) -> str:
    parts: List[str] = []
    for f in sd.fields:
        field_bs = bs[f.offset:]
        base, dims = parse_array_dims(f.c_type)

        # For char[N], only emit a string literal for likely-string fields.
        if base == "char" and dims and len(dims) == 1:
            looks_like_string = (
                f.name.startswith("sz")
                or f.name.endswith("Name")
                or f.name.endswith("Title")
                or f.name.endswith("Text")
            )
            if looks_like_string:
                n = dims[0]
                lit = format_char_array_as_c_string(field_bs[:n])
                if lit is not None:
                    parts.append(f".{f.name} = {lit}")
                    continue

        v = format_value_from_bytes(field_bs, f.c_type, structs, _depth=_depth + 1)
        if v is None:
            parts.append(f"/* .{f.name} unsupported: {f.c_type} */")
        else:
            parts.append(f".{f.name} = {v}")
    # Match common C designated-init style used in this project: `{.a = 1, .b = 2}`
    return "{" + ", ".join(parts) + "}"


def format_value_from_bytes(bs: bytes, c_type: str, structs: Dict[str, StructDef], _depth: int = 0) -> Optional[str]:
    if _depth > 8:
        return None

    base, dims = parse_array_dims(c_type)

    # Primitive scalar
    if not dims:
        prim = _unpack_primitive(bs, base)
        if prim is not None:
            size, signed = sizeof_ctype(base)  # type: ignore[misc]
            return format_scalar(prim, base, signed)

        # Struct scalar
        sd = structs.get(base)
        if sd:
            return format_struct_initializer(sd, bs[:sd.size], structs, _depth=_depth + 1)
        return None

    # Array
    if any(d == 0 for d in dims):
        return None

    # Array of primitives
    if sizeof_ctype(base):
        return format_array_initializer(base, dims, bs)

    # Array of structs
    sd = structs.get(base)
    if not sd:
        return None
    total = math.prod(dims)
    elem_size = sd.size
    needed = elem_size * total
    if len(bs) < needed:
        return None
    elems = [
        format_struct_initializer(sd, bs[i * elem_size:(i + 1) * elem_size], structs, _depth=_depth + 1)
        for i in range(total)
    ]

    def rec(vs: List[str], ds: List[int]) -> str:
        if len(ds) == 1:
            return "{ " + ", ".join(vs) + " }"
        stride = math.prod(ds[1:])
        parts = [rec(vs[i * stride:(i + 1) * stride], ds[1:]) for i in range(ds[0])]
        return "{ " + ", ".join(parts) + " }"

    return rec(elems, dims)


def sizeof_decl(c_type: str, structs: Dict[str, StructDef]) -> Optional[int]:
    """Return total size in bytes for a supported c_type (primitive/array/struct)."""
    base, dims = parse_array_dims(c_type)
    if not dims:
        s = sizeof_ctype(base)
        if s:
            return s[0]
        sd = structs.get(base)
        return sd.size if sd else None
    count = math.prod(dims)
    s = sizeof_ctype(base)
    if s:
        return s[0] * count
    sd = structs.get(base)
    return (sd.size * count) if sd else None


def find_seg_range(seg_ranges_by_seg: Dict[int, List[SegRange]], seg: int, off: int) -> Optional[SegRange]:
    ranges = seg_ranges_by_seg.get(seg)
    if not ranges:
        return None
    for r in ranges:
        if r.start_off <= off <= r.end_off:
            return r
    return None

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", required=True, help="Input Win16 EXE (e.g. stars26jrc3.exe)")
    ap.add_argument("--segments", required=True, help="segments.csv exported from Ghidra")
    ap.add_argument("--globals", required=True, help="nb09_ghidra_globals.json")
    ap.add_argument("--types", default="types.h", help="types.h used to decode struct layouts")
    ap.add_argument("--out", required=True, help="Output C file")
    args = ap.parse_args()

    seg_ranges_by_seg = load_seg_ranges(args.segments)

    with open(args.globals, "r", encoding="utf-8") as f:
        db = json.load(f)

    structs = parse_types_h_structs(args.types)

    globals_list = db.get("globals", [])

    # Prefer logical segment names from the NB09 segmap (e.g. MEMORY_AI, MEMORY_UTILGEN)
    # over Ghidra's generic segment block names (e.g. Data37/Code12).
    def logical_segname(g: Dict[str, Any]) -> str:
        sm = g.get("segmap") or {}
        nm = (sm.get("segname") or "").strip()
        if nm:
            return nm

        # Fallback: map by SEG:OFF into segments.csv and use its Name field.
        addr = (g.get("ghidra") or {}).get("addr")
        if addr and ":" in addr:
            seg_s, off_s = addr.split(":")
            try:
                seg, off = int(seg_s, 16), int(off_s, 16)
                sr = find_seg_range(seg_ranges_by_seg, seg, off)
                if sr and sr.name.strip():
                    return sr.name.strip()
            except Exception:
                pass
        return "UNKNOWN_SEG"

    @dataclass
    class Emitted:
        seg_name: str
        seg: int
        range_start: int
        name: str
        line: str

    emitted: List[Emitted] = []

    out_lines: List[str] = []
    out_lines.append("/* Auto-generated from stars26jrc3.exe + nb09_ghidra_globals.json */")
    out_lines.append("#include <stdint.h>")
    out_lines.append("#include \"types.h\"")
    out_lines.append("")
    out_lines.append("/* NOTE: This file includes primitives, arrays, and supported structs (see types.h). */")
    out_lines.append("")

    skipped: List[str] = []
    handled = 0

    with open(args.exe, "rb") as exef:
        for g in globals_list:
            t = g.get("types") or {}
            kind = t.get("kind")
            if kind not in ("primitive", "array", "struct"):
                continue

            name = (g.get("name") or "").strip()
            c_type = (t.get("c_type") or "").strip()
            if not name or not c_type:
                continue

            # pointers (and arrays-of-pointers) are out of scope for initializer extraction.
            if "*" in c_type:
                continue

            addr = (g.get("ghidra") or {}).get("addr")
            if not addr:
                continue
            seg_s, off_s = addr.split(":")
            seg, off = int(seg_s, 16), int(off_s, 16)

            file_off = find_file_offset(seg_ranges_by_seg, seg, off)
            if file_off is None:
                skipped.append(f"{name} @ {addr}: no segment mapping")
                continue

            size = sizeof_decl(c_type, structs)
            if size is None:
                skipped.append(f"{name} @ {addr}: unsupported type {c_type!r}")
                continue

            # Determine logical segment name early so we can apply BSS/COMMON rules.
            seg_name = logical_segname(g)
            if is_zero_init_segment(seg_name):
                init = zero_initializer_for_type(c_type, structs)
            else:
                exef.seek(file_off)
                bs = exef.read(size)
                if len(bs) != size:
                    skipped.append(f"{name} @ {addr}: short read")
                    continue

                init = format_value_from_bytes(bs, c_type, structs)
            if init is None:
                skipped.append(f"{name} @ {addr}: could not format {c_type!r}")
                continue

            c_decl = t.get("c_decl") or f"{c_type} {name}"
            line = f"{c_decl} = {init}; /* {addr} */"

            # Segment grouping/sorting: use the NB09 logical segname when available.
            seg_name = logical_segname(g)
            sr = find_seg_range(seg_ranges_by_seg, seg, off)
            range_start = sr.start_off if sr else 0

            emitted.append(Emitted(seg_name=seg_name, seg=seg, range_start=range_start, name=name, line=line))
            handled += 1

    # Sort by segment, then by variable name within each segment.
    emitted.sort(key=lambda e: (e.seg_name.lower(), e.seg, e.range_start, e.name.lower()))

    # Emit a single comment header per segment.
    last_seg = None
    for e in emitted:
        if e.seg_name != last_seg:
            if last_seg is not None:
                out_lines.append("")
            out_lines.append(f"/* {e.seg_name} */")
            last_seg = e.seg_name
        out_lines.append(e.line)

    out_lines.append("")
    out_lines.append("/* ---- skipped/unsupported ---- */")
    out_lines.append(f"/* handled: {handled} */")
    for s in skipped:
        out_lines.append(f"/* {s} */")

    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(out_lines) + "\n")

    print(f"[ok] wrote {args.out} (handled={handled}, skipped={len(skipped)})")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
