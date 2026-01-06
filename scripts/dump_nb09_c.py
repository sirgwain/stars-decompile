#!/usr/bin/env python3
"""
dump_nb09_c.py

CodeView NB09 -> C-oriented dumps and skeleton generator.

Commands:
  dump-globals   Dump global variables with types, grouped by inferred source file.
  dump-procs     Dump function signatures with types, grouped by inferred source file.
  dump-structs   Dump struct/union/enum output (from NB09 types table).
  skeleton       Create an output folder containing per-file .h/.c skeletons.

Notes:
- File grouping uses best-effort sstModule seginfo + sstSrcModule ranges.
- Filenames are normalized to basenames only (no full paths).
- Decls are annotated with SEGMENT_NAME:offset for easy Ghidra correlation.

"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from nb09_parser import load_nb09
from nb09_model import ArrayType, PointerType, PrimitiveType, StructType, UnionType, maybe_string_decl_from_typind


def _maybe_string_decl_from_typind(db, typind: int, name: str, *, byte_len_hint: int | None = None, local_semantics: bool = False) -> str | None:
    """Compatibility wrapper: shared string heuristic lives in nb09_model."""
    _ = local_semantics  # kept for older call sites
    return maybe_string_decl_from_typind(db, typind, name, byte_len_hint=byte_len_hint)


# -----------------------------
# Address / source mapping
# -----------------------------

@dataclass(frozen=True)
class Range:
    start: int
    end: int  # exclusive

    def contains(self, off: int) -> bool:
        return self.start <= off < self.end


def _basename(p: Optional[str]) -> Optional[str]:
    if not p:
        return None
    p = p.replace("\\", "/")
    return p.split("/")[-1] or None


def _seg_label(db, seg: int) -> str:
    """
    Return a human-friendly segment label.

    In NB09, runtime segment numbers used by symbols (seg=1..N) are mapped via sstSegMap
    and sstSegName. The parser usually exposes:
      - db.segmap as dict with key "segs": [{seg, iSegName, ...}, ...]
      - db.segname as dict mapping iSegName -> name (e.g. MEMORY_INIT)

    Fallbacks:
      - db.segname keyed by seg
      - db.segname list indexed by seg-1
    """
    segmap = getattr(db, "segmap", None)
    segname = getattr(db, "segname", None)

    if isinstance(segmap, dict) and isinstance(segname, dict):
        for ent in segmap.get("segs", []) or []:
            try:
                if int(ent.get("seg", -1)) == int(seg):
                    idx = ent.get("iSegName")
                    if idx is not None and segname.get(idx):
                        return segname[idx]
            except Exception:
                pass

    if isinstance(segname, dict):
        v = segname.get(seg) or segname.get(str(seg))
        if v:
            return v

    if isinstance(segname, list) and 1 <= seg <= len(segname):
        return segname[seg - 1]

    return f"SEG{seg}"


def _build_module_ranges(db) -> Dict[int, List[Tuple[int, Range]]]:
    out: Dict[int, List[Tuple[int, Range]]] = {}
    mods = getattr(db, "modules", None)

    if isinstance(mods, dict):
        items = sorted(mods.items(), key=lambda kv: int(kv[0]))
    elif isinstance(mods, list):
        items = list(enumerate(mods, start=1))
    else:
        items = []

    for imod, m in items:
        if not isinstance(m, dict):
            continue
        for si in m.get("seginfo") or []:
            seg = int(si.get("seg", 0) or 0)
            off = int(si.get("off", 0) or 0)
            cb = int(si.get("cb", 0) or 0)
            if seg > 0 and cb > 0:
                out.setdefault(int(imod), []).append((seg, Range(off, off + cb)))
    return out


def _normalize_srcmodules_by_imod(db) -> Dict[int, dict]:
    """Return db.srcmodules with integer imod keys.

    The NB09 parser exposes `db.srcmodules` as a dict keyed by imod, but depending on
    JSON roundtrips / other tooling it may be keyed by either `int` or `str`.
    """
    raw = getattr(db, "srcmodules", None)
    if not isinstance(raw, dict):
        return {}

    out: Dict[int, dict] = {}
    for k, v in raw.items():
        if not isinstance(v, dict):
            continue
        try:
            out[int(k)] = v
        except Exception:
            continue
    return out


def _build_file_range_index(srcmodules_by_imod: Dict[int, dict]) -> List[Tuple[int, Range, str, int]]:
    """Build an index of file address ranges.

    Returns a list of tuples: (seg, Range(start,end), basename, imod)
    """
    idx: List[Tuple[int, Range, str, int]] = []
    for imod, sm in srcmodules_by_imod.items():
        for f in sm.get("files") or []:
            nm = _basename(f.get("name"))
            if not nm:
                continue
            seg_ranges = f.get("seg_ranges") or {}
            for segk, rr in seg_ranges.items():
                try:
                    seg = int(segk)
                    start = int(rr.get("start"))
                    end = int(rr.get("end"))
                except Exception:
                    continue
                if seg > 0 and end > start:
                    idx.append((seg, Range(start, end), nm, int(imod)))
    return idx


def _heuristic_file_from_seglabel(seg_label: str) -> Optional[str]:
    """Last-ditch guess based on segment name like 'MEMORY_AI3' -> 'ai3.h'."""
    if not seg_label:
        return None
    m = re.match(r"^MEMORY_([A-Za-z0-9_]+)$", seg_label.strip())
    if not m:
        return None
    stem = m.group(1).lower()
    if not stem:
        return None
    return f"{stem}.h"


def resolve_src_file_guess(
    db,
    module_ranges: Dict[int, List[Tuple[int, Range]]],
    srcmodules_by_imod: Dict[int, dict],
    file_range_index: List[Tuple[int, Range, str, int]],
    seg: int,
    off: int,
) -> Optional[str]:
    """Best-effort resolver for source filename for an address.

    Order of attempts:
      1) module(seginfo) -> srcmodule(files seg_ranges)
      2) global scan across all srcmodules' file ranges
      3) segment-name heuristic (MEMORY_FOO -> foo.h)
    """
    seg = int(seg)
    off = int(off)

    imod = _find_module_for_addr(module_ranges, seg, off)
    if imod is not None:
        sm = srcmodules_by_imod.get(int(imod))
        if sm:
            nm = _find_file_for_addr(sm, seg, off)
            if nm:
                return nm

    # Fallback: scan all files for a containing seg/off. Choose smallest range.
    best: Optional[Tuple[int, str]] = None  # (range_size, name)
    for rseg, rr, nm, _imod in file_range_index:
        if rseg != seg:
            continue
        if rr.contains(off):
            sz = rr.end - rr.start
            if best is None or sz < best[0]:
                best = (sz, nm)
    if best is not None:
        return best[1]

    return _heuristic_file_from_seglabel(_seg_label(db, seg))


def _find_module_for_addr(module_ranges, seg, off) -> Optional[int]:
    best = None
    for imod, ranges in module_ranges.items():
        for rseg, rr in ranges:
            if rseg == seg and rr.contains(off):
                size = rr.end - rr.start
                if best is None or size < best[0]:
                    best = (size, imod)
    return best[1] if best else None


def _find_file_for_addr(srcmodule, seg, off) -> Optional[str]:
    for f in srcmodule.get("files") or []:
        seg_ranges = f.get("seg_ranges") or {}
        r = seg_ranges.get(str(seg)) or seg_ranges.get(seg)
        if r and int(r["start"]) <= off < int(r["end"]):
            return _basename(f.get("name"))
    return None


def _infer_file_for_global(db, module_ranges, srcmodules_by_imod, seg: int, off: int) -> Optional[str]:
    """Back-compat wrapper (older callers). Prefer resolve_src_file_guess()."""
    imod = _find_module_for_addr(module_ranges, seg, off)
    if imod is not None and int(imod) in srcmodules_by_imod:
        return _find_file_for_addr(srcmodules_by_imod[int(imod)], seg, off)
    return None


# -----------------------------
# Dump: Globals
# -----------------------------

def dump_globals(db, unknown_label="(unknown)", include_segment_comment=True, no_sort=False) -> str:
    module_ranges = _build_module_ranges(db)
    # Normalize imod keys (they can be str after JSON roundtrips)
    srcmods_by_imod = _normalize_srcmodules_by_imod(db)
    file_range_index = _build_file_range_index(srcmods_by_imod)

    # Merge globals across symbol sources using Stars!-tuned hierarchy (see Nb09Db.iter_globals_resolved).
    recs: Dict[Tuple[str, int, int], Dict] = {}

    if hasattr(db, "iter_globals_resolved"):
        globals_res = db.iter_globals_resolved()
        for g in globals_res:
            recs[(g.name, int(g.seg), int(g.off))] = {"name": g.name, "seg": int(g.seg), "off": int(g.off), "typind": g.typind, "c_type": None, "source": g.source}
    else:
        # Fallback: older db without the resolver (first wins).
        def add(name, seg, off, typind, c_type):
            k = (name, seg, off)
            if k in recs:
                return
            recs[k] = {"name": name, "seg": seg, "off": off, "typind": typind, "c_type": c_type}

        for s in db.global_data:
            add(s.name, int(s.seg), int(s.off), int(s.typind), getattr(s, "c_type", None))

        for s in getattr(db, "static_sym_syms", []) or []:
            add(s.name, int(s.seg), int(s.off), getattr(s, "typind", None), getattr(s, "c_type", None))

        for s in getattr(db, "global_pub_syms", []) or []:
            add(s.name, int(s.seg), int(s.off), getattr(s, "typind", None), getattr(s, "c_type", None))
    groups: Dict[str, List[str]] = {}
    for r in recs.values():
        seg, off = r["seg"], r["off"]
        fname = resolve_src_file_guess(db, module_ranges, srcmods_by_imod, file_range_index, seg, off)
        key = fname or unknown_label

        decl = None
        if r["typind"] is not None:
            try:
                fixed = _maybe_string_decl_from_typind(db, int(r["typind"]), r["name"], local_semantics=False)
                if fixed is not None:
                    d = fixed
                else:
                    d = db.c_decl_of(int(r["typind"]), r["name"], style="c")
                if d.strip().startswith("/*unknown*/") and r.get("c_type"):
                    d = f"{r['c_type']} {r['name']}"
                decl = d
            except Exception:
                decl = None

        if decl is None:
            if r.get("c_type"):
                decl = f"{r['c_type']} {r['name']}"
            elif r["typind"] is not None:
                decl = f"/*unknown_typind_{int(r['typind'])}*/ {r['name']}"
            else:
                decl = f"/*unknown_type*/ {r['name']}"

        decl += ";"
        if include_segment_comment:
            decl += f"  /* {_seg_label(db, seg)}:{off:#06x} */"

        groups.setdefault(key, []).append(decl)

    keys = list(groups.keys())
    if not no_sort:
        keys.sort(key=lambda k: (0 if k == unknown_label else 1, k.lower()))
        for k in keys:
            groups[k].sort(key=str.lower)

    out: List[str] = []
    for k in keys:
        out.append(f"/* {k} */")
        out.extend(groups[k])
        out.append("")
    return "\n".join(out).rstrip() + "\n"


# -----------------------------
# Dump: Procs
# -----------------------------

def dump_procs(db, unknown_label="(unknown)", include_segment_comment=True, no_sort=False) -> str:
    groups: Dict[str, List[str]] = {}

    for p in db.proc_symbols:
        fname = _basename(getattr(p, "src_file", None))
        key = fname or unknown_label

        decl = db.c_decl_of(int(p.typind), p.name, style="c") + ";"

        # Tags for tooling (Ghidra helpers)
        tags: list[str] = []
        try:
            pt = db.resolve_typind(int(p.typind))
            calltype = getattr(pt, "calltype", None)
            if calltype in (2, 3):
                tags.append("PASCAL")
            ret = getattr(pt, "ret", None)
            # Far return matters for segmented-model decompilers: far pointers return 4 bytes.
            if getattr(ret, "kind", None) == "pointer":
                ptrtype = int(getattr(ret, "ptrtype", 0) or 0)
                if ptrtype in (1, 2, 11):
                    tags.append("RETFAR")
        except Exception:
            pass

        if tags:
            decl += "  /* " + " ".join(tags) + " */"

        if include_segment_comment:
            decl += f"  /* {_seg_label(db, int(p.seg))}:{int(p.off):#06x} */"

        groups.setdefault(key, []).append(decl)

    keys = list(groups.keys())
    if not no_sort:
        keys.sort(key=lambda k: (0 if k == unknown_label else 1, k.lower()))
        for k in keys:
            groups[k].sort(key=str.lower)

    out: List[str] = []
    for k in keys:
        out.append(f"/* {k} */")
        out.extend(groups[k])
        out.append("")
    return "\n".join(out).rstrip() + "\n"

def dump_structs(db, no_sort=False) -> str:
    """
    Emit C definitions for all struct/union/enum types in the NB09 type table.

    - Struct/union members are read from the referenced LF_FIELDLIST records.
    - Bitfields are emitted using the BitfieldType's base + length.
    - When multiple members share the same offset, we emit an anonymous `union { ... };`
      at that offset. If that union contains bitfields, they are grouped into an
      anonymous `struct { ... };` inside the union (matching typical C source style).
    """
    include_typind = True
    tt = getattr(db, "global_types", None)
    if not tt:
        return "/* no global_types in this NB09 */\n"

    def emit_enum(tid: int, rec) -> str:
        name = rec.data.get("name") or f"/*anon_enum_{tid}*/"
        size = rec.data.get("size")
        header = f"/* typind {tid} (0x{tid:04x})" + (f" size={size}" if size is not None else "") + " */"
        # NB09 often does not contain full enumerators in the public type stream; emit a placeholder.
        return "\n".join([
            header,
            f"enum {name} {{",
            "    /* TODO: enumerators */",
            "};",
            "",
        ])

    def is_bitfield_type(tid: int) -> bool:
        try:
            r = tt.records.get(int(tid))
            return r is not None and r.kind == "bitfield"
        except Exception:
            return False

    def resolve_bitfield(tid: int):
        rt = db.resolve_typind(int(tid))
        # expects nb09_model.BitfieldType
        base = getattr(rt, "base", None)
        length = int(getattr(rt, "length", 0) or 0)
        position = int(getattr(rt, "position", 0) or 0)
        return rt, base, length, position

    def decl_for_member(mtype: int, name: str, bit_width: int | None = None) -> str:
        if bit_width is not None:
            # base type should come from resolving the bitfield typind, not from member typind itself
            rt, base, length, position = resolve_bitfield(mtype)
            base_c = base.to_c_style("c") if base is not None else "/*unknown*/"
            return f"{base_c} {name} : {bit_width};"
        # normal member
        try:
            return db.c_decl_of(int(mtype), name, style="c") + ";"
        except Exception:
            return f"/*unknown*/ {name};"

    def emit_struct_or_union(tid: int, rec) -> str:
        kind = rec.kind  # "struct"/"union"/"class"
        name = rec.data.get("name") or f"/*anon_{kind}_{tid}*/"
        size = rec.data.get("size")
        fieldlist_tid = rec.data.get("fieldlist")

        def typedef_alias(tag: str) -> str:
            """Create a prettier typedef name for common Win16 conventions.

            Examples:
              _btn    -> BTN
              tagRECT -> RECT
            """
            if not tag:
                return tag
            if tag.startswith("_") and len(tag) > 1:
                return tag[1:].upper()
            if tag.startswith("tag") and len(tag) > 3 and tag[3].isalpha():
                return tag[3:]
            return tag

        header = f"/* typind {tid} (0x{tid:04x})" + (f" size={size}" if size is not None else "") + " */"
        tag_kw = 'struct' if kind in ('struct','class') else 'union'
        alias = typedef_alias(name)
        out: list[str] = [header, f"typedef {tag_kw} {name} {{"]

        fields = []
        if fieldlist_tid and int(fieldlist_tid) in tt.records:
            fl = tt.records[int(fieldlist_tid)]
            fields = fl.data.get("fields") or []

        # group members by offset
        members = [f for f in fields if f.get("kind") == "member"]
        members.sort(key=lambda f: (int(f.get("offset", 0)), f.get("name", "")))

        groups = {}
        for f in members:
            off = int(f.get("offset", 0))
            groups.setdefault(off, []).append(f)

        def emit_offset_comment(off: int) -> str:
            return f"  /* +0x{off:04x} */"

        for off in sorted(groups.keys()):
            g = groups[off]
            if len(g) == 1:
                f = g[0]
                mtype = int(f.get("type", 0))
                nm = f.get("name") or "/*anon*/"
                # String buffer heuristic: if this looks like a sz*/psz* member, coerce arrays/pointers to char types.
                next_off = None
                # find next higher offset in the struct for sizing hints
                _offs_sorted = sorted(groups.keys())
                try:
                    idx_off = _offs_sorted.index(off)
                    if idx_off + 1 < len(_offs_sorted):
                        next_off = int(_offs_sorted[idx_off + 1])
                except Exception:
                    next_off = None
                byte_hint = None
                if next_off is not None:
                    byte_hint = max(0, next_off - off)
                elif size is not None:
                    try:
                        byte_hint = max(0, int(size) - off)
                    except Exception:
                        byte_hint = None
                fixed_decl = _maybe_string_decl_from_typind(db, mtype, nm, byte_len_hint=byte_hint, local_semantics=False)
                if fixed_decl is not None:
                    out.append(f"    {fixed_decl};{emit_offset_comment(off)}")
                    continue

                if is_bitfield_type(mtype):
                    _, _, blen, bpos = resolve_bitfield(mtype)
                    line = decl_for_member(mtype, nm, blen)
                else:
                    line = decl_for_member(mtype, nm)
                out.append(f"    {line}{emit_offset_comment(off)}")
                continue

            # Multiple members at same offset => anonymous union block
            out.append("    union {")
            # Separate normal members and bitfields
            bf = []
            normal = []
            for f in g:
                mtype = int(f.get("type", 0))
                if is_bitfield_type(mtype):
                    bf.append(f)
                else:
                    normal.append(f)

            # Emit normal members directly in the union
            for f in normal:
                mtype = int(f.get("type", 0))
                nm = f.get("name") or "/*anon*/"
                out.append("        " + decl_for_member(mtype, nm))

            # Emit bitfields inside anonymous struct in the union
            if bf:
                # Order by bit position
                bf_sorted = []
                for f in bf:
                    mtype = int(f.get("type", 0))
                    _, _, blen, bpos = resolve_bitfield(mtype)
                    bf_sorted.append((bpos, blen, f))
                bf_sorted.sort(key=lambda t: t[0])

                out.append("        struct {")
                for bpos, blen, f in bf_sorted:
                    mtype = int(f.get("type", 0))
                    nm = f.get("name") or "/*anon*/"
                    out.append("            " + decl_for_member(mtype, nm, blen))
                out.append("        };")

            out.append(f"    }};{emit_offset_comment(off)}")

        out.append(f"}} {alias};")
        out.append("")
        return "\n".join(out)

    # Build list in stable order
    tids = [int(tid) for tid, rec in tt.records.items() if rec.kind in ("struct", "class", "union", "enum")]
    if not no_sort:
        tids.sort()

    # Emit a self-contained header:
    #   - include guards
    #   - standard integer types
    #   - forward decls for all typedef aliases (so pointer members compile)
    #   - full definitions

    def typedef_alias(tag: str) -> str:
        if not tag:
            return tag
        if tag.startswith("_") and len(tag) > 1:
            return tag[1:].upper()
        if tag.startswith("tag") and len(tag) > 3 and tag[3].isalpha():
            return tag[3:]
        return tag

    # Map typedef alias -> tid for dependency sorting.
    alias_to_tid: Dict[str, int] = {}
    for tid in tids:
        rec = tt.records[tid]
        tag = (rec.data.get("name") or "").strip()
        if not tag:
            continue
        alias_to_tid[typedef_alias(tag)] = tid

    fwd: list[str] = []
    for tid in tids:
        rec = tt.records[tid]
        tag = (rec.data.get("name") or "").strip()
        if not tag:
            continue
        alias = typedef_alias(tag)
        if rec.kind in ("struct", "class"):
            fwd.append(f"typedef struct {tag} {alias};")
        elif rec.kind == "union":
            fwd.append(f"typedef union {tag} {alias};")
        elif rec.kind == "enum":
            fwd.append(f"typedef enum {tag} {alias};")

    # de-dupe while preserving order
    seen = set()
    fwd2: list[str] = []
    for ln in fwd:
        if ln not in seen:
            seen.add(ln)
            fwd2.append(ln)

    # Topologically sort definitions so that by-value members have their complete
    # types defined earlier. Pointers do not create ordering constraints.
    def _deps_for(tid: int) -> set[int]:
        rec = tt.records[tid]
        if rec.kind == "enum":
            return set()
        fieldlist_tid = rec.data.get("fieldlist")
        if not fieldlist_tid or int(fieldlist_tid) not in tt.records:
            return set()
        fl = tt.records[int(fieldlist_tid)]
        fields = fl.data.get("fields") or []
        deps: set[int] = set()
        for f in fields:
            if f.get("kind") != "member":
                continue
            mtype = int(f.get("type", 0) or 0)
            try:
                rt = db.resolve_typind(mtype)
            except Exception:
                continue

            # Peel arrays
            while isinstance(rt, ArrayType):
                rt = rt.elem
            # Pointers are fine with forward decls
            if isinstance(rt, PointerType):
                continue
            # By-value struct/union fields require full def
            if isinstance(rt, (StructType, UnionType)):
                dep_tid = alias_to_tid.get(rt.to_c_style("c"))
                if dep_tid is not None and dep_tid != tid:
                    deps.add(dep_tid)
        return deps

    dep_map: Dict[int, set[int]] = {tid: _deps_for(tid) for tid in tids}
    ready = [tid for tid in tids if not dep_map[tid]]
    ordered: list[int] = []
    remaining = set(tids)
    while ready:
        t = ready.pop(0)
        if t not in remaining:
            continue
        remaining.remove(t)
        ordered.append(t)
        for o in list(remaining):
            if t in dep_map[o]:
                dep_map[o].remove(t)
                if not dep_map[o]:
                    ready.append(o)
    if remaining:
        # Cycle or unresolved deps: fall back to stable numeric order for the rest.
        ordered.extend(sorted(remaining))

    body: list[str] = []
    for tid in ordered:
        rec = tt.records[tid]
        if rec.kind == "enum":
            body.append(emit_enum(tid, rec))
        else:
            body.append(emit_struct_or_union(tid, rec))

    hdr: list[str] = []
    hdr.append("#ifndef STARS_NB09_TYPES_H")
    hdr.append("#define STARS_NB09_TYPES_H")
    hdr.append("")
    hdr.append("/* ------------------------------------------------------------------ */")
    hdr.append("/*  Stars! NB09 primitive types                                       */")
    hdr.append("/*  Do NOT include stdint.h / stdbool.h / stdlib.h                     */")
    hdr.append("/* ------------------------------------------------------------------ */")
    hdr.append("")
    hdr.append("typedef signed char        int8_t;")
    hdr.append("typedef unsigned char      uint8_t;")
    hdr.append("typedef short              int16_t;")
    hdr.append("typedef unsigned short     uint16_t;")
    hdr.append("typedef long               int32_t;")
    hdr.append("typedef unsigned long      uint32_t;")
    hdr.append("typedef short              BOOL;")
    hdr.append("#ifndef true")
    hdr.append("#define true 1")
    hdr.append("#endif")
    hdr.append("#ifndef false")
    hdr.append("#define false 0")
    hdr.append("#endif")
    hdr.append("#ifndef NULL")
    hdr.append("#define NULL ((void*)0)")
    hdr.append("#endif")
    hdr.append("")
    hdr.append("_Static_assert(sizeof(int8_t)  == 1, \"int8_t must be 1 byte\");")
    hdr.append("_Static_assert(sizeof(uint8_t) == 1, \"uint8_t must be 1 byte\");")
    hdr.append("_Static_assert(sizeof(int16_t) == 2, \"int16_t must be 2 bytes\");")
    hdr.append("_Static_assert(sizeof(uint16_t)== 2, \"uint16_t must be 2 bytes\");")
    hdr.append("_Static_assert(sizeof(int32_t) == 4, \"int32_t must be 4 bytes\");")
    hdr.append("_Static_assert(sizeof(uint32_t)== 4, \"uint32_t must be 4 bytes\");")
    hdr.append("_Static_assert(sizeof(BOOL)    == 2, \"BOOL must be 2 bytes\");")
    hdr.append("")
    if fwd2:
        hdr.append("/* forward declarations (to satisfy pointer members) */")
        hdr.extend(fwd2)
        hdr.append("")

    out_all = "\n".join(hdr + body).rstrip() + "\n\n#endif /* STARS_NB09_TYPES_H */\n"
    return out_all


# -----------------------------
# Skeleton generator helpers
# -----------------------------

def _guard(stem: str) -> str:
    base = stem.upper()
    base = "".join(ch if ch.isalnum() else "_" for ch in base)
    return f"{base}_H_"


def _default_return_for(c_ret: str) -> Optional[str]:
    c_ret = c_ret.strip()
    if c_ret == "void":
        return None

    # pointers
    if "*" in c_ret:
        return "NULL"

    # common scalars
    if c_ret in ("bool", "_Bool"):
        return "false"
    if re.match(r"^(u?int(8|16|32|64)_t|size_t|ptrdiff_t)$", c_ret):
        return "0"
    if c_ret in ("int", "unsigned", "unsigned int", "long", "unsigned long", "short", "unsigned short", "char", "unsigned char"):
        return "0"
    if c_ret in ("float", "double"):
        return "0"

    # structs/unions/typedefs: use a zeroed compound literal (works for typedefs like POINT)
    return f"({c_ret}){{0}}"

def _strip_seg_comment(line: str) -> str:
    """Remove trailing '/* SEGMENT:0x.... */' comment from a declaration line."""
    if "/*" in line and line.rstrip().endswith("*/"):
        line = line[: line.rfind("/*")].rstrip()
    return line


def _strip_trailing_semicolon(line: str) -> str:
    line = line.rstrip()
    if line.endswith(";"):
        return line[:-1].rstrip()
    return line


def _proc_locals_by_name(db):
    """Build map: proc_name -> ProcLocals."""
    pm = {}
    for pl in getattr(db, "proc_locals", []) or []:
        pm[getattr(pl, "proc_name", "")] = pl
    return pm


def _format_param_list(db, ps, pl) -> str:
    """
    Prefer parameter names/types from ProcLocals (true names).
    Fallback to procedure arg types with synthetic names.
    """
    params = []
    if pl is not None:
        pl_params = [v for v in (pl.locals or []) if getattr(v, "kind", "") == "param"]

        # order params by bp_off ascending (e.g. +6, +8, +A...)
        def key(v):
            bo = getattr(v, "bp_off", None)
            return (0, int(bo)) if bo is not None else (1, 0)

        pl_params.sort(key=key, reverse=True)

        for v in pl_params:
            try:
                fixed = _maybe_string_decl_from_typind(db, int(v.typind), v.name, local_semantics=True)
                if fixed is not None:
                    d = fixed
                else:
                    d = db.c_decl_of(int(v.typind), v.name, style="c")
                if d.strip().startswith("/*unknown*/") and getattr(v, "c_type", None):
                    d = f"{v.c_type} {v.name}"
                params.append(d)
            except Exception:
                t = getattr(v, "c_type", None) or "int"
                params.append(f"{t} {v.name}")

        return ", ".join(params)

    # fallback: resolver args
    try:
        rt = db.resolve_typind(int(ps.typind))
        args = getattr(rt, "args", []) if hasattr(rt, "args") else []
        for i, a in enumerate(args):
            params.append(f"{a.to_c_style('c')} a{i+1}")
        return ", ".join(params)
    except Exception:
        return ""


def _format_function_signature(db, ps, pl) -> str:
    try:
        rt = db.resolve_typind(int(ps.typind))
        ret = rt.ret.to_c_style("c") if hasattr(rt, "ret") else "int"
    except Exception:
        ret = "int"
    return f"{ret} {ps.name}({_format_param_list(db, ps, pl)})"


def _format_local_decl(db, v) -> str:
    try:
        fixed = _maybe_string_decl_from_typind(db, int(v.typind), v.name, local_semantics=True)
        if fixed is not None:
            return fixed + ";"
        d = db.c_decl_of(int(v.typind), v.name, style="c")
        if d.strip().startswith("/*unknown*/") and getattr(v, "c_type", None):
            d = f"{v.c_type} {v.name}"
        return d + ";"
    except Exception:
        ct = getattr(v, "c_type", None) or "int"
        return f"{ct} {v.name};"


def _proto_for_definition(base_sig: str, pl, calltype: int | None = None) -> str:
    """Turn a prototype like `R Foo(T1, T2)` into a *definition* signature with names.

    - Keeps the exact type/order from `base_sig` (so it matches the header).
    - Uses ProcLocals param names if the count matches; otherwise uses a1..aN.
    - Handles unnamed function-pointer params by inserting the name inside `(* ... )`.
    """
    s = re.sub(r"/\*.*?\*/", "", base_sig, flags=re.S).strip()
    s = s.rstrip().rstrip(";").strip()
    l = s.find("(")
    r = s.rfind(")")
    if l < 0 or r < l:
        return s
    head = s[:l].rstrip()
    inside = s[l+1:r].strip()
    tail = s[r+1:].strip()
    if inside == "" or inside == "void":
        return f"{head}(void){(' ' + tail) if tail else ''}".strip()

    # split params on commas at paren depth 0
    params = []
    depth = 0
    cur = []
    for ch in inside:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth-1)
        if ch == "," and depth == 0:
            params.append("".join(cur).strip())
            cur = []
            continue
        cur.append(ch)
    if cur:
        params.append("".join(cur).strip())

    # pick names
    pl_names = []
    if pl is not None:
        pl_params = [v for v in (pl.locals or []) if getattr(v, "kind", "") == "param"]
        # IMPORTANT: parameter stack offsets depend on calling convention.
        # In Stars!' NB09 (16-bit FAR procs), parameters are typically at BP+6, BP+8, ...
        # - cdecl: args pushed right-to-left, so *leftmost* source param ends up at the
        #          *lowest* stack offset (closest to BP). => sort ascending.
        # - pascal: args pushed left-to-right, so *leftmost* source param ends up at the
        #           *highest* stack offset. => sort descending.
        from nb09_model import is_pascal_calltype
        pascal = is_pascal_calltype(calltype)
        def key(v):
            bo = getattr(v, "bp_off", None)
            if bo is None:
                return (1, 0)
            return (0, -int(bo)) if pascal else (0, int(bo))
        pl_params.sort(key=key)
        pl_names = [getattr(v, "name", "") or "" for v in pl_params if getattr(v, "name", None)]
    use_names = pl_names if len(pl_names) == len(params) else [f"a{i+1}" for i in range(len(params))]

    def add_name(ptype: str, nm: str) -> str:
        ptype = ptype.strip()
        # already has a name (very rough heuristic): ends with identifier
        if re.search(r"\b[A-Za-z_][A-Za-z0-9_]*\b\s*(\[[^\]]*\])?\s*$", ptype) and not ptype.endswith("*") and "(*)" not in ptype:
            # still may be unnamed like 'PROD *' (endswith '*'), so only accept if last token isn't '*' or ')'
            pass
        # unnamed function pointer like 'int16_t (*)(FLEET*,FLEET*)'
        if "(*)" in ptype:
            return ptype.replace("(*)", f"(*{nm})")
        # unnamed fp like 'int16_t (*)(...)' already ok? ensure name exists
        if "(*" in ptype and ")" in ptype and "(*" in ptype and "(*" + ")" not in ptype:
            # If it looks like '(*)(...)', insert name after '(*'
            ptype2 = re.sub(r"\(\*\s*\)", f"(*{nm})", ptype)
            if ptype2 != ptype:
                return ptype2
        # array without name: 'uint8_t[6]' => 'uint8_t a1[6]'
        m = re.match(r"^(.*?)(\[[^\]]*\])+$", ptype)
        if m and (" " not in ptype or ptype.rstrip().endswith("]")):
            base = m.group(1).strip()
            dims = ptype[len(m.group(1)):]
            return f"{base} {nm}{dims}"
        # pointer-ish: 'PROD *' => 'PROD *a1'
        if ptype.endswith("*"):
            return f"{ptype}{nm}"
        return f"{ptype} {nm}"

    named_params = [add_name(t, nm) for t, nm in zip(params, use_names)]
    return f"{head}({', '.join(named_params)}){(' ' + tail) if tail else ''}".strip()


# -----------------------------
# Skeleton generator
# -----------------------------

def generate_skeleton(db, out_dir: Path, unknown_label="(unknown)") -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    globals_text = dump_globals(db, unknown_label=unknown_label, include_segment_comment=True, no_sort=True)
    procs_text = dump_procs(db, unknown_label=unknown_label, include_segment_comment=True, no_sort=True)

    def parse_blocks(text: str):
        cur = None
        m = {}
        for line in text.splitlines():
            line = line.rstrip()
            if line.startswith("/* ") and line.endswith(" */") and len(line) > 6:
                cur = line[3:-3].strip()
                m.setdefault(cur, [])
                continue
            if cur is None or not line:
                continue
            m[cur].append(line)
        return m

    g_by_file = parse_blocks(globals_text)
    p_by_file = parse_blocks(procs_text)

    all_files = set(g_by_file.keys()) | set(p_by_file.keys())
    if unknown_label in all_files:
        all_files.remove(unknown_label)

    # types.h: structs/unions/enums
    (out_dir / "types.h").write_text(dump_structs(db), encoding="utf-8")

    pl_by_name = _proc_locals_by_name(db)

    # IMPORTANT:
    # dump_globals/dump_procs group by an inferred *filename*, and it's common to see both
    # "foo.c" and "foo.h" blocks.  If we iterate those directly we'd generate/overwrite
    # foo.[hc] twice.  Instead, merge all blocks that share the same stem.
    stems = sorted({Path(f).stem for f in all_files}, key=lambda s: s.lower())

    def _ext_pri(fn: str) -> int:
        ext = Path(fn).suffix.lower()
        if ext == ".h":
            return 0
        if ext == ".c":
            return 1
        return 2

    def _dedupe(lines):
        out = []
        seen = set()
        for ln in lines:
            key = ln.strip()
            if not key or key in seen:
                continue
            seen.add(key)
            out.append(ln)
        return out

    for stem in stems:
        h_name = f"{stem}.h"
        c_name = f"{stem}.c"
        guard = _guard(stem)

        block_names = [f for f in all_files if Path(f).stem == stem]
        block_names.sort(key=lambda fn: (_ext_pri(fn), fn.lower()))

        globals_lines = []
        proc_lines = []
        for bname in block_names:
            globals_lines.extend(g_by_file.get(bname, []))
            proc_lines.extend(p_by_file.get(bname, []))

        globals_lines = _dedupe(globals_lines)
        proc_lines = _dedupe(proc_lines)

        # Header
        h = []
        h.append(f"#ifndef {guard}")
        h.append(f"#define {guard}")
        h.append("")
        h.append("")
        h.append('#include "types.h"')
        h.append("")

        if globals_lines:
            h.append("/* globals */")
            for ln in globals_lines:
                h.append("extern " + ln)
            h.append("")

        if proc_lines:
            h.append("/* functions */")
            h.extend(proc_lines)
            h.append("")

        h.append(f"#endif /* {guard} */")
        h.append("")
        (out_dir / h_name).write_text("\n".join(h), encoding="utf-8")

        # C
        c = []
        c.append("")
        c.append('#include "types.h"')
        c.append("")
        c.append(f'#include "{h_name}"')
        c.append("")

        if globals_lines:
            c.append("/* globals */")
            for ln in globals_lines:
                c.append(ln)
            c.append("")

        if proc_lines:
            c.append("/* functions */")
            for proto in proc_lines:
                base = _strip_trailing_semicolon(_strip_seg_comment(proto))
                name = base.split("(")[0].strip().split()[-1]

                ps = next((p for p in db.proc_symbols if p.name == name), None)
                pl = pl_by_name.get(name)

                calltype = None
                if ps is not None:
                    try:
                        pt = db.resolve_typind(int(ps.typind))
                        calltype = getattr(pt, 'calltype', None)
                    except Exception:
                        calltype = None

                sig = _proto_for_definition(base, pl, calltype)

                c.append(sig)
                c.append("{")

                # locals (exclude params)
                if pl is not None:
                    locals_only = [v for v in (pl.locals or []) if getattr(v, "kind", "") != "param"]

                    # sort locals by bp_off descending (e.g. -2, -4, -6...) => nearest first
                    def lkey(v):
                        bo = getattr(v, "bp_off", None)
                        return (0, -int(bo)) if bo is not None else (1, 0)

                    locals_only.sort(key=lkey)

                    seen_names = set()
                    for v in locals_only:
                        nm = getattr(v, "name", None) or ""
                        if nm and nm in seen_names:
                            continue
                        if nm:
                            seen_names.add(nm)
                        c.append("    " + _format_local_decl(db, v))

                    blocks = getattr(pl, "blocks", []) or []
                    labels = getattr(pl, "labels", []) or []
                    if blocks or labels:
                        c.append("")
                        c.append("    /* debug symbols */")
                        for b in blocks:
                            bname = getattr(b, "name", None) or "(block)"
                            bseg = getattr(b, "seg", None)
                            boff = getattr(b, "off", None)
                            if bseg is not None and boff is not None:
                                c.append(f"    /* block {bname} @ {_seg_label(db, int(bseg))}:{int(boff):#06x} */")
                            else:
                                c.append(f"    /* block {bname} */")
                        for lab in labels:
                            lname = getattr(lab, "name", None) or "(label)"
                            lseg = getattr(lab, "seg", None)
                            loff = getattr(lab, "off", None)
                            if lseg is not None and loff is not None:
                                c.append(f"    /* label {lname} @ {_seg_label(db, int(lseg))}:{int(loff):#06x} */")
                            else:
                                c.append(f"    /* label {lname} */")

                c.append("")
                c.append("    /* TODO: implement */")

                # default return for non-void functions
                try:
                    ret_part = base.split("(", 1)[0].strip()
                    ret_tokens = ret_part.split()
                    ret_type = " ".join(ret_tokens[:-1]).strip() if len(ret_tokens) >= 2 else ""
                except Exception:
                    ret_type = ""

                if ret_type and ret_type != "void":
                    if "*" in ret_type:
                        c.append("    return NULL;")
                    else:
                        c.append("    return 0;")

                c.append("}")
                c.append("")

        (out_dir / c_name).write_text("\n".join(c), encoding="utf-8")

    # Unknown / unassigned
    unknown_globals = g_by_file.get(unknown_label, [])
    unknown_procs = p_by_file.get(unknown_label, [])
    if unknown_globals or unknown_procs:
        u = []
        u.append("#ifndef GLOBALS_H_")
        u.append("#define GLOBALS_H_")
        u.append("")
        u.append('#include "types.h"')
        u.append("")
        u.append("/* Unassigned symbols (no file inferred) */")
        u.append("")
        if unknown_globals:
            u.append("/* globals */")
            u.extend(unknown_globals)
            u.append("")
        if unknown_procs:
            u.append("/* functions */")
            u.extend(unknown_procs)
            u.append("")
        u.append("#endif /* GLOBALS_H_ */")
        u.append("")
        (out_dir / "globals.h").write_text("\n".join(u), encoding="utf-8")


    # -----------------------------
    # CLI
    # -----------------------------


def _write_out(path: str, content: str) -> None:
    if path in ("-", "stdout"):
        print(content, end="")
    else:
        Path(path).write_text(content, encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="NB09 -> C dumps and skeleton generator")
    ap.add_argument("nb09_bin", help="Path to extracted *.codeview.nb09.bin")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_g = sub.add_parser("dump-globals", help="Dump globals grouped by inferred file")
    p_g.add_argument("out", nargs="?", default="-")
    p_g.add_argument("--unknown-label", default="(unknown)")
    p_g.add_argument("--no-sort", action="store_true")

    p_p = sub.add_parser("dump-procs", help="Dump function signatures grouped by inferred file")
    p_p.add_argument("out", nargs="?", default="-")
    p_p.add_argument("--unknown-label", default="(unknown)")
    p_p.add_argument("--no-sort", action="store_true")

    p_s = sub.add_parser("dump-structs", help="Dump structs/unions/enums")
    p_s.add_argument("out", nargs="?", default="-")
    p_s.add_argument("--no-sort", action="store_true")

    p_k = sub.add_parser("skeleton", help="Generate per-file .h/.c skeletons into a folder")
    p_k.add_argument("outdir", help="Output directory, e.g. out")
    p_k.add_argument("--unknown-label", default="(unknown)")

    args = ap.parse_args()
    db = load_nb09(args.nb09_bin)

    if args.cmd == "dump-globals":
        _write_out(args.out, dump_globals(db, unknown_label=args.unknown_label, no_sort=args.no_sort))
    elif args.cmd == "dump-procs":
        _write_out(args.out, dump_procs(db, unknown_label=args.unknown_label, no_sort=args.no_sort))
    elif args.cmd == "dump-structs":
        _write_out(args.out, dump_structs(db, no_sort=args.no_sort))
    elif args.cmd == "skeleton":
        generate_skeleton(db, Path(args.outdir), unknown_label=args.unknown_label)
    else:
        raise SystemExit("unknown command")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
