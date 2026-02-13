#!/usr/bin/env python3
"""
print_nb09_proc_locals.py

Given an NB09-derived proc database (nb09_ghidra_globals.json) and a function name,
print a C-ish stub containing:
  - NB09 PROC header comment (seg:off + segment name + tags)
  - function signature (return + params with [BP+off])
  - locals grouped by lexical block id with [BP-off]
  - "TODO: implement" body

This is intended to match the "Stars! win16 decompiling" workflow where:
  - params are displayed in *call* order (highest BP offset first)
  - locals are displayed with least-negative offset first (closest to BP)
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


def _die(msg: str) -> "NoReturn":
    print(f"error: {msg}", file=sys.stderr)
    raise SystemExit(2)


def _hex4(n: int) -> str:
    return f"0x{n:04x}"


def _parse_seg_off(addr: str) -> Tuple[str, int]:
    # "1108:0018" -> ("1108", 0x0018)
    m = re.fullmatch(r"([0-9A-Fa-f]{4}):([0-9A-Fa-f]{4})", addr.strip())
    if not m:
        _die(f"unexpected address format: {addr!r}")
    return (m.group(1).lower(), int(m.group(2), 16))


def _find_proc(procs: List[Dict[str, Any]], name: str) -> Dict[str, Any]:
    name_l = name.lower()

    # exact match first
    for p in procs:
        if str(p.get("name", "")).lower() == name_l:
            return p

    # case-insensitive "starts with" / "contains" fallbacks
    starts = [p for p in procs if str(p.get("name", "")).lower().startswith(name_l)]
    if len(starts) == 1:
        return starts[0]

    contains = [p for p in procs if name_l in str(p.get("name", "")).lower()]
    if len(contains) == 1:
        return contains[0]

    # ambiguous / not found
    cand = sorted({p.get("name", "") for p in (starts or contains) if p.get("name")})
    if not cand:
        _die(f"proc not found: {name!r}")
    _die(f"ambiguous proc name {name!r}; candidates: {', '.join(cand[:30])}{'...' if len(cand)>30 else ''}")


def _format_bp(off: int) -> str:
    # off is signed; params are positive, locals negative.
    if off >= 0:
        return f"[BP+{off}]"
    return f"[BP{off}]"  # off already includes '-'


def _print_params(params: List[Dict[str, Any]]) -> str:
    # Desired order: highest BP offset first (e.g., hwnd @ +14 shown before lParam @ +6).
    # If some entries don't have bp_off (shouldn't happen), keep them last.
    def key(p: Dict[str, Any]) -> Tuple[int, int]:
        if "bp_off" in p and isinstance(p["bp_off"], int):
            return (0, -p["bp_off"])
        return (1, 0)

    out_lines: List[str] = []
    for i, p in enumerate(sorted(params, key=key)):
        c_type = p.get("c_type", "/*unknown*/")
        name = p.get("name", f"param_{i+1}")
        bp = _format_bp(int(p.get("bp_off", 0)))
        comma = "," if i != len(params) - 1 else ""
        # align a little
        out_lines.append(f"    {c_type:<6} {name}{comma:<2} /* {bp} */")
    return "\n".join(out_lines)


def _group_locals(locals_: List[Dict[str, Any]]) -> Dict[int, List[Dict[str, Any]]]:
    groups: Dict[int, List[Dict[str, Any]]] = {}
    for l in locals_:
        blk = int(l.get("block", 0))
        groups.setdefault(blk, []).append(l)
    return groups


def _print_locals(locals_: List[Dict[str, Any]]) -> str:
    if not locals_:
        return ""

    groups = _group_locals(locals_)

    # function scope first (block 0), then increasing block id
    blk_ids = sorted(groups.keys())
    if 0 in blk_ids:
        blk_ids.remove(0)
        blk_ids = [0] + blk_ids

    out: List[str] = []
    for blk in blk_ids:
        label = "locals (function scope)" if blk == 0 else f"locals (block {blk})"
        out.append(f"    /* {label} */")

        # Sort locals: closest to BP first (e.g. -4, -6, -14, -16...)
        def lkey(l: Dict[str, Any]) -> Tuple[int, int]:
            bo = l.get("bp_off")
            if isinstance(bo, int):
                return (0, -bo)  # -(-4)=4 => earlier than -(-16)=16
            return (1, 0)

        for l in sorted(groups[blk], key=lkey):
            c_type = l.get("c_type", "/*unknown*/")
            name = l.get("name", "local")
            bp = _format_bp(int(l.get("bp_off", 0)))
            out.append(f"    {c_type:<6} {name}; /* {bp} */")
        out.append("")  # blank line between blocks

    # drop trailing blank
    while out and out[-1] == "":
        out.pop()
    return "\n".join(out)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Print NB09 proc signature + BP-relative locals grouped by block.")
    ap.add_argument("--db", required=True, help="Path to nb09_ghidra_globals.json")
    ap.add_argument("proc", help="Procedure/function name (case-insensitive).")
    args = ap.parse_args(argv)

    db_path = Path(args.db)
    if not db_path.exists():
        _die(f"db not found: {db_path}")

    with db_path.open("r", encoding="utf-8") as f:
        db = json.load(f)

    procs = db.get("procs")
    if not isinstance(procs, list):
        _die("db missing 'procs' list")

    p = _find_proc(procs, args.proc)

    name = p.get("name", args.proc)
    gh = p.get("ghidra", {})
    segmap = p.get("segmap", {})
    typ = p.get("types", {})

    addr = str(gh.get("addr", "????:????"))
    seg, off = _parse_seg_off(addr) if re.fullmatch(r"[0-9A-Fa-f]{4}:[0-9A-Fa-f]{4}", addr) else ("????", 0)
    segname = segmap.get("segname", "UNKNOWN")

    tags = typ.get("tags", [])
    if not isinstance(tags, list):
        tags = []
    tags_s = ", ".join(str(t) for t in tags) if tags else ""

    ret = typ.get("ret", {})
    ret_type = ret.get("c_type", "void") if isinstance(ret, dict) else "void"

    params = typ.get("params", [])
    if not isinstance(params, list):
        params = []

    locals_ = typ.get("locals", [])
    if not isinstance(locals_, list):
        locals_ = []

    # PROC header comment, matching your style.
    tag_tail = f", {tags_s}" if tags_s else ""
    print(f"/* NB09 PROC: {name} @ {addr} ({segname}:{_hex4(off)}){tag_tail} */")

    # Signature line + params with BP offsets
    print(f"{ret_type} {name}(")
    if params:
        print(_print_params(params))
    print(")")
    print("{")

    locals_s = _print_locals(locals_)
    if locals_s:
        print(locals_s)
        print("")

    print("    /* TODO: implement */")
    print("}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
