#!/usr/bin/env python3
"""
dump_nb09_ghidra.py

Emit Ghidra-consumable JSON for applying NB09 names from CodeView NB09.

This script is intended to run under CPython 3 (outside Ghidra). It uses nb09_parser.py
to parse Stars!' extracted CodeView NB09 blob, then translates CodeView (seg,off)
addresses into Ghidra segmented addresses using:
  - NB09 sstSegMap: gives (seg -> frame, seg_base_off)
  - segments.csv (exported from Ghidra): gives (frame -> selector) via blocks like Data37/Code4

Address translation:
  selector = frame_to_selector[ segmap[seg].frame ]
  ghidra_off = segmap[seg].off + sym.off
  ghidra_addr = f"{selector:04x}:{ghidra_off:04x}"

Output JSON schema (top-level dict):
{
  "meta": {...},
  "frame_to_selector": { "37": "1120", ... },
  "seg_to_frame": { "76": 37, ... },
  "globals": [
     {
        "name": "hInst",
        "cv": {"seg": 76, "off": 12416, "typind": 115, "rectyp": 258, "from": "DATAREF"},
        "segmap": {"frame": 37, "base_off": 8848, "iSegName": 1011, "segname": "c_common"},
        "ghidra": {
           "selector": 4384,
           "off": 21264,
           "addr": "1120:5310",
           "default_label": "DAT_1120_5310"
        },
        "types": {"c_type": "uint16_t", "cv_typ": "T_UINT2"}
     },
     ...
  ],
  "procs": [...],
  "labels": [...]
}

Typical use:
  python3 dump_nb09_ghidra.py stars26jrc3.codeview.nb09.bin --out nb09_ghidra_globals.json

Then in Ghidra (Jython), load nb09_ghidra_globals.json and for each record:
  - locate symbol at ghidra.addr
  - if current label == default_label (or starts with DAT_), rename to record.name
  - optionally apply datatype from record.types.c_type or typind mapping
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
from dataclasses import asdict
from typing import Any, Dict, Iterable, List, Optional, Tuple

from nb09_parser import load_nb09
from nb09_model import PointerType, ProcedureType, is_far_ptrtype, is_pascal_calltype, maybe_string_decl_from_typind


def _parse_selector(start_field: str) -> Optional[int]:
    """
    Parse Ghidra CSV Start like '1120:0000' -> selector int(0x1120).
    """
    if not start_field:
        return None
    if ":" not in start_field:
        return None
    seg, _off = start_field.split(":", 1)
    seg = seg.strip()
    # selectors are shown hex without 0x
    try:
        return int(seg, 16)
    except ValueError:
        return None


def load_segments_csv(path: str) -> Tuple[Dict[int, int], Dict[int, str]]:
    """
    Build frame->selector map using Ghidra-exported segments.csv.
    We infer 'frame' from block names like 'Data37' or 'Code4' (case-sensitive as in export).
    """
    frame_to_selector: Dict[int, int] = {}
    frame_to_kind: Dict[int, str] = {}

    with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            name = (row.get("Name") or "").strip()
            start = (row.get("Start") or "").strip()
            if not name or not start:
                continue

            m = re.fullmatch(r"(Code|Data)(\d+)", name)
            if not m:
                continue

            kind = m.group(1)
            frame = int(m.group(2))
            selector = _parse_selector(start)
            if selector is None:
                continue

            frame_to_selector[frame] = selector
            frame_to_kind[frame] = kind

    return frame_to_selector, frame_to_kind


def build_segmap_tables(db) -> Tuple[Dict[int, Dict[str, Any]], Dict[int, int]]:
    """
    Returns:
      seg_to_ent: seg -> {frame, off, iSegName, iClassName, flags, ...}
      seg_to_frame: seg -> frame
    """
    seg_to_ent: Dict[int, Dict[str, Any]] = {}
    seg_to_frame: Dict[int, int] = {}

    segmap = getattr(db, "segmap", None)
    if not isinstance(segmap, dict):
        return seg_to_ent, seg_to_frame

    segs = segmap.get("segs", []) or []
    for ent in segs:
        try:
            seg = int(ent.get("seg"))
            frame = int(ent.get("frame"))
            seg_to_ent[seg] = dict(ent)
            seg_to_frame[seg] = frame
        except Exception:
            continue

    return seg_to_ent, seg_to_frame


def segname_lookup(db, iSegName: Optional[int]) -> Optional[str]:
    segname = getattr(db, "segname", None)
    if iSegName is None:
        return None
    if isinstance(segname, dict):
        # keys in dump are often strings
        if str(iSegName) in segname:
            return segname[str(iSegName)]
        if iSegName in segname:
            return segname[iSegName]
    return None


def _sym_to_dict(sym, origin: str) -> Optional[Dict[str, Any]]:
    try:
        return {
            "from": origin,
            "name": sym.name,
            "seg": int(sym.seg),
            "off": int(sym.off),
            "typind": getattr(sym, "typind", None),
            "rectyp": getattr(sym, "rectyp", None),
            "typ": getattr(sym, "typ", None),
            "c_type": getattr(sym, "c_type", None),
        }
    except Exception:
        return None


def _frame_kind_for_seg(seg: int, seg_to_ent: Dict[int, Dict[str, Any]], frame_to_kind: Dict[int, str]) -> Optional[str]:
    ent = seg_to_ent.get(seg)
    if not ent:
        return None
    try:
        frame = int(ent.get("frame"))
    except Exception:
        return None
    return frame_to_kind.get(frame)


def iter_unique_globals(db, seg_to_ent: Dict[int, Dict[str, Any]], frame_to_kind: Dict[int, str]) -> Iterable[Dict[str, Any]]:
    """Iterate globals, deduped by address, with Stars!-tuned type resolution.

    Prefer resolved globals from Nb09Db.iter_globals_resolved() (nb09_model.py),
    which merges candidates across multiple symbol sources via hierarchy:

      1) static_sym_dataref_symbols (DATAREF from SST_STATIC_SYM)
      2) global_sym_dataref_symbols (DATAREF from SST_GLOBAL_SYM)
      3) dataref_symbols (fallback)
      4) global_data (S_GDATA16 / 'GLOBAL')  [last resort]

    If iter_globals_resolved is not available (older nb09_model.py), fall back to
    legacy behavior: global_data + PUBLICs that look like data (filtered by segmap).
    """
    # Preferred: use the model's resolver (handles DATAREF vs GLOBAL correctly).
    if hasattr(db, "iter_globals_resolved"):
        seen: set[Tuple[int, int]] = set()

        def _source_to_from(src: str) -> str:
            s = (src or "").lower()
            if "dataref" in s:
                return "DATAREF"
            if "global" in s:
                return "GLOBAL"
            return (src or "GLOBAL").upper()

        for gr in db.iter_globals_resolved() or []:
            try:
                seg = int(getattr(gr, "seg"))
                off = int(getattr(gr, "off"))
                name = str(getattr(gr, "name") or "")
                typind = getattr(gr, "typind", None)
                source = str(getattr(gr, "source") or "")
                candidates = getattr(gr, "candidates", None) or []
            except Exception:
                continue

            k = (seg, off)
            if k in seen:
                continue
            seen.add(k)

            # Try to recover rectyp/from from the chosen candidate.
            chosen = None
            for c in candidates:
                try:
                    if (c.get("source") == source) and (c.get("typind") == typind):
                        chosen = c
                        break
                except Exception:
                    continue
            if chosen is None:
                for c in candidates:
                    try:
                        if c.get("source") == source:
                            chosen = c
                            break
                    except Exception:
                        continue

            d: Dict[str, Any] = {
                "name": name,
                "seg": seg,
                "off": off,
                "typind": typind,
                "rectyp": chosen.get("rectyp") if isinstance(chosen, dict) else None,
                "from": (chosen.get("from") if isinstance(chosen, dict) and chosen.get("from") else _source_to_from(source)),
            }
            yield d
        return

    # ---- legacy fallback ----
    seen = set()

    # Strongly-typed global data symbols.
    for s in getattr(db, "global_data", []) or []:
        d = _sym_to_dict(s, getattr(s, "from", "GLOBAL"))
        if not d:
            continue
        k = (d["seg"], d["off"])
        if k in seen:
            continue
        seen.add(k)
        yield d

    # Publics that appear to be data based on frame kind.
    data_addrs = set((int(d["seg"]), int(d["off"])) for d in getattr(db, "global_data", []) or [] if getattr(d, "seg", None) is not None)

    for s in getattr(db, "global_pub_syms", []) or []:
        d = _sym_to_dict(s, "PUBLIC")
        if not d:
            continue
        k = (d["seg"], d["off"])
        if k in seen:
            continue

        # If this PUBLIC has no type info and we already have data at this address,
        # treat it as a data alias rather than a function.
        try:
            if int(getattr(s, "typind", 0)) == 0 and k in data_addrs:
                continue
        except Exception:
            if k in data_addrs:
                continue

        kind = _frame_kind_for_seg(int(d["seg"]), seg_to_ent, frame_to_kind)
        if kind and kind.lower().startswith("data"):
            continue
        seen.add(k)
        yield d


def iter_unique_procs(db, seg_to_ent: Dict[int, Dict[str, Any]], frame_to_kind: Dict[int, str], data_addrs: Optional[set] = None) -> Iterable[Any]:
    """Procedures = sstGlobalSym procs + sstGlobalPub publics that live in Code frames.

    data_addrs: optional set of (seg,off) that are known data globals; used to avoid treating PUBLIC
               aliases as procedures when they overlap with real data (e.g. _rgbeam vs rgbeam).
    """
    seen = set()
    if data_addrs is None:
        data_addrs = set()

    for p in getattr(db, "proc_symbols", []) or []:
        try:
            k = (int(p.seg), int(p.off))
        except Exception:
            continue
        if k in seen:
            continue
        seen.add(k)
        yield (p, getattr(p, "from", "PROC"))

    for s in getattr(db, "global_pub_pubs", []) or []:
        try:
            seg = int(s.seg)
            off = int(s.off)
        except Exception:
            continue
        k = (seg, off)
        if k in seen:
            continue

        # If this PUBLIC has no type info and we already have data at this address,
        # treat it as a data alias rather than a function.
        try:
            if int(getattr(s, "typind", 0)) == 0 and k in data_addrs:
                continue
        except Exception:
            if k in data_addrs:
                continue

        kind = _frame_kind_for_seg(seg, seg_to_ent, frame_to_kind)
        if kind and kind.lower().startswith("data"):
            continue
        seen.add(k)
        yield (s, "PUBLIC")


def enrich_types_for_global(db, g: Dict[str, Any]) -> Dict[str, Any]:
    """Compute C-ish type strings and FAR-ness for a global symbol.

    This uses the same resolver + string heuristics as dump_nb09_c.py so the
    types match globals.h.
    """
    typind = g.get("typind")
    if typind is None:
        return {"typind": None, "c_type": None, "c_decl": None, "is_far_ptr": False}

    name = g.get("name") or ""
    fixed = maybe_string_decl_from_typind(db, int(typind), name)
    if fixed is not None:
        # fixed is a declaration like: "char szFoo[90]" or "char *pszFoo"
        m = re.match(r"^(?P<ty>.+?)\s+[A-Za-z_][A-Za-z0-9_]*", fixed)
        c_type = m.group("ty").strip() if m else None
        return {
            "typind": int(typind),
            "c_type": c_type,
            "c_decl": fixed,
            "is_far_ptr": False,
            "note": "string_heuristic",
        }

    rt = db.resolve_typind(int(typind))
    out: Dict[str, Any] = {
        "typind": int(typind),
        "c_type": rt.to_c(),
        "c_decl": rt.c_decl(name),
        "kind": getattr(rt, "kind", None),
    }
    if isinstance(rt, PointerType):
        out["ptrtype"] = int(getattr(rt, "ptrtype", 0) or 0)
        out["is_far_ptr"] = is_far_ptrtype(out["ptrtype"])
    else:
        out["is_far_ptr"] = False
    return out


def build_proc_locals_index(db) -> Dict[str, Dict[Any, Any]]:
    """Build indices to find ProcLocals for a given procedure.

    Returns a dict with keys:
      - "by_modsym": (imod, symoff) -> ProcLocals
      - "by_segoff": (seg, off) -> ProcLocals
      - "by_name": name -> ProcLocals (last-wins; best-effort fallback)
    """
    by_modsym: Dict[tuple[int, int], Any] = {}
    by_segoff: Dict[tuple[int, int], Any] = {}
    by_name: Dict[str, Any] = {}

    for pl in getattr(db, "proc_locals", []) or []:
        try:
            imod = int(getattr(pl, "imod"))
            symoff = int(getattr(pl, "symoff"))
            seg = int(getattr(pl, "seg"))
            off = int(getattr(pl, "off"))
            name = str(getattr(pl, "proc_name") or "")
        except Exception:
            continue
        by_modsym[(imod, symoff)] = pl
        by_segoff[(seg, off)] = pl
        if name:
            by_name[name] = pl

    return {"by_modsym": by_modsym, "by_segoff": by_segoff, "by_name": by_name}


def _type_meta(db, typind: int, name: str) -> Dict[str, Any]:
    """Return common metadata for a type+name pairing."""
    try:
        rt = db.resolve_typind(int(typind))
        c_type = rt.to_c_style("ghidra")
        c_decl = rt.c_decl(name)
        is_far_ptr = isinstance(rt, PointerType) and is_far_ptrtype(int(getattr(rt, "ptrtype", 0) or 0))
        size = getattr(rt, "size", None)
        return {
            "typind": int(typind),
            "c_type": c_type,
            "c_decl": c_decl,
            "size": size,
            "is_far_ptr": bool(is_far_ptr),
        }
    except Exception:
        return {"typind": int(typind), "c_type": None, "c_decl": None, "size": None, "is_far_ptr": False}

# def enrich_types_for_proc(db, p) -> Dict[str, Any]:
#     """Compute type tags for a procedure typind (PASCAL + RETFAR)."""
#     typind = getattr(p, "typind", None)
#     if typind is None:
#         return {"typind": None, "proto": None, "tags": []}
#     proto = db.c_decl_of(int(typind), getattr(p, "name", ""))
#     tags: list[str] = []
#     try:
#         rt = db.resolve_typind(int(typind))
#         if isinstance(rt, ProcedureType):
#             if is_pascal_calltype(getattr(rt, "calltype", None)):
#                 tags.append("PASCAL")
#             ret = getattr(rt, "ret", None)
#             if isinstance(ret, PointerType) and is_far_ptrtype(int(getattr(ret, "ptrtype", 0) or 0)):
#                 tags.append("RETFAR")
#     except Exception:
#         pass
#     return {"typind": int(typind), "proto": proto, "tags": tags}

def enrich_types_for_proc(db, p, proc_locals_index: Optional[Dict[str, Dict[Any, Any]]] = None) -> Dict[str, Any]:
    """Compute full procedure type info: return type, calling convention, params, locals.

    - Uses procedure typind (LF_PROCEDURE / LF_MFUNCTION) for return + arg types.
    - Uses ProcLocals (if present) for argument names + locals, including BP offsets.
    """
    typind = getattr(p, "typind", None)
    name = getattr(p, "name", "") or ""

    out: Dict[str, Any] = {
        "typind": int(typind) if typind is not None else None,
        "proto": None,
        "tags": [],
        "is_pascal": False,
        "ret": {"c_type": None, "is_far_ptr": False, "is_32bit": False, "size": None},
        "params": [],
        "locals": [],
    }
    if typind is None:
        return out

    # Base prototype string (kept for convenience / debugging).
    try:
        out["proto"] = db.c_decl_of(int(typind), name)
    except Exception:
        out["proto"] = None

    # Resolve type record and derive ret/args.
    rt = None
    try:
        rt = db.resolve_typind(int(typind))
    except Exception:
        rt = None

    arg_types = []
    if isinstance(rt, ProcedureType):
        out["is_pascal"] = bool(is_pascal_calltype(getattr(rt, "calltype", None)))
        if out["is_pascal"]:
            out["tags"].append("PASCAL")

        # Return type
        ret = getattr(rt, "ret", None)
        if ret is not None:
            ret_is_far_ptr = isinstance(ret, PointerType) and is_far_ptrtype(int(getattr(ret, "ptrtype", 0) or 0))
            ret_size = getattr(ret, "size", None)
            out["ret"] = {
                "c_type": ret.to_c_style("ghidra") if hasattr(ret, "to_c_style") else None,
                "is_far_ptr": bool(ret_is_far_ptr),
                "is_32bit": bool(ret_size == 4),
                "size": ret_size,
            }
            if ret_is_far_ptr:
                out["tags"].append("RETFAR")
            elif ret_size == 4:
                # Win16 DX:AX style return (long / far32/etc).
                out["tags"].append("RET32")

        arg_types = list(getattr(rt, "args", ()) or [])

    # Attach names+locals from ProcLocals if available.
    pl = None
    if proc_locals_index:
        try:
            imod = int(getattr(p, "imod"))
            symoff = int(getattr(p, "symoff"))
            seg = int(getattr(p, "seg"))
            off = int(getattr(p, "off"))
            pl = proc_locals_index["by_modsym"].get((imod, symoff)) \
                 or proc_locals_index["by_segoff"].get((seg, off)) \
                 or proc_locals_index["by_name"].get(name)
        except Exception:
            pl = None

    params = []
    locals_ = []

    if pl is not None:
        for ls in getattr(pl, "locals", []) or []:
            try:
                lkind = str(getattr(ls, "kind") or "")
                lname = str(getattr(ls, "name") or "")
                ltyp = int(getattr(ls, "typind"))
            except Exception:
                continue

            meta = _type_meta(db, ltyp, lname)
            entry = {
                "name": lname,
                "kind": lkind,
                **meta,
            }
            # Location info (BP offset or register)
            if getattr(ls, "bp_off", None) is not None:
                entry["bp_off"] = int(getattr(ls, "bp_off"))
            if getattr(ls, "reg", None) is not None:
                entry["reg"] = int(getattr(ls, "reg"))
            if getattr(ls, "reg_off", None) is not None:
                entry["reg_off"] = int(getattr(ls, "reg_off"))

            if lkind == "param":
                params.append(entry)
            elif lkind == "local":
                locals_.append(entry)
            else:
                # Best-effort: if it has a positive BP offset, treat as param; negative as local.
                bp = entry.get("bp_off")
                if isinstance(bp, int) and bp >= 0:
                    entry["kind"] = "param"
                    params.append(entry)
                else:
                    entry["kind"] = "local"
                    locals_.append(entry)

        # Sort params by stack order if we have BP offsets
        if params and any("bp_off" in x for x in params):
            params.sort(key=lambda x: (x.get("bp_off", 1 << 30), x.get("name", "")))
        out["params"] = params
        out["locals"] = locals_

    # If we have no named params, synthesize from the procedure arg types.
    if not out["params"] and arg_types:
        synth = []
        for i, aty in enumerate(arg_types, start=1):
            pname = f"a{i}"
            try:
                c_type = aty.to_c_style("ghidra")
                c_decl = aty.c_decl(pname)
                is_far_ptr = isinstance(aty, PointerType) and is_far_ptrtype(int(getattr(aty, "ptrtype", 0) or 0))
                size = getattr(aty, "size", None)
            except Exception:
                c_type = None
                c_decl = None
                is_far_ptr = False
                size = None
            synth.append({
                "name": pname,
                "kind": "param",
                "typind": None,
                "c_type": c_type,
                "c_decl": c_decl,
                "size": size,
                "is_far_ptr": bool(is_far_ptr),
            })
        out["params"] = synth

    return out



def compute_ghidra_addr(
    seg: int,
    off: int,
    seg_ent: Dict[str, Any],
    frame_to_selector: Dict[int, int],
    prefix: str,
) -> Optional[Dict[str, Any]]:
    """
    Returns dict with selector/off/addr/default_label or None if mapping missing.
    """
    try:
        frame = int(seg_ent.get("frame"))
        base_off = int(seg_ent.get("off"))
    except Exception:
        return None

    selector = frame_to_selector.get(frame)
    if selector is None:
        return None

    eff = base_off + off
    # Keep eff in 0..0xffff if it overflows (rare, but safe)
    eff16 = eff & 0xFFFF
    addr = f"{selector:04x}:{eff16:04x}"
    default_label = f"{prefix}_{selector:04x}_{eff16:04x}".upper()
    return {
        "selector": selector,
        "off": eff16,
        "addr": addr,
        "default_label": default_label,
        "frame": frame,
        "base_off": base_off,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Emit Ghidra JSON for renaming globals/procs/labels from NB09.")
    ap.add_argument("nb09", help="Path to extracted CodeView NB09 blob (e.g., stars26jrc3.codeview.nb09.bin)")
    ap.add_argument("--segments", default="segments.csv", help="Path to segments.csv exported from Ghidra (default: ./segments.csv)")
    ap.add_argument("--out", default="nb09_ghidra_globals.json", help="Output JSON path")
    ap.add_argument("--include-unmapped", action="store_true", help="Include globals we cannot map to a Ghidra address")
    args = ap.parse_args()

    db = load_nb09(args.nb09)

    frame_to_selector, frame_to_kind = load_segments_csv(args.segments)
    seg_to_ent, seg_to_frame = build_segmap_tables(db)
    proc_locals_index = build_proc_locals_index(db)

    globals_out: List[Dict[str, Any]] = []
    procs_out: List[Dict[str, Any]] = []
    labels_out: List[Dict[str, Any]] = []
    unmapped_globals = 0
    unmapped_procs = 0
    unmapped_labels = 0

    # --- globals ---
    all_globals = list(iter_unique_globals(db, seg_to_ent, frame_to_kind))
    for g in all_globals:
        seg = int(g["seg"])
        off = int(g["off"])
        seg_ent = seg_to_ent.get(seg)
        gh = None
        if seg_ent:
            gh = compute_ghidra_addr(seg, off, seg_ent, frame_to_selector, "DAT")

        if gh is None and not args.include_unmapped:
            unmapped_globals += 1
            continue

        rec: Dict[str, Any] = {
            "name": g["name"],
            "cv": {
                "seg": seg,
                "off": off,
                "typind": g.get("typind"),
                "rectyp": g.get("rectyp"),
                "from": g.get("from"),
            },
            "types": enrich_types_for_global(db, g),
            "segmap": None,
            "ghidra": gh,
        }

        if seg_ent:
            iSegName = seg_ent.get("iSegName")
            rec["segmap"] = {
                "frame": int(seg_ent.get("frame")) if seg_ent.get("frame") is not None else None,
                "base_off": int(seg_ent.get("off")) if seg_ent.get("off") is not None else None,
                "iSegName": iSegName,
                "segname": segname_lookup(db, int(iSegName)) if iSegName is not None else None,
                "iClassName": seg_ent.get("iClassName"),
                "flags": seg_ent.get("flags"),
                "group": seg_ent.get("group"),
            }

        globals_out.append(rec)

    # --- procs ---
    data_addrs = set((int(g['cv']['seg']), int(g['cv']['off'])) for g in globals_out)
    all_procs = list(iter_unique_procs(db, seg_to_ent, frame_to_kind, data_addrs))
    for p, origin in all_procs:
        try:
            seg = int(getattr(p, "seg"))
            off = int(getattr(p, "off"))
        except Exception:
            continue

        seg_ent = seg_to_ent.get(seg)
        gh = None
        if seg_ent:
            gh = compute_ghidra_addr(seg, off, seg_ent, frame_to_selector, "FUN")

        if gh is None and not args.include_unmapped:
            unmapped_procs += 1
            continue

        rec: Dict[str, Any] = {
            "name": getattr(p, "name", ""),
            "cv": {
                "seg": seg,
                "off": off,
                "typind": getattr(p, "typind", None),
                "rectyp": getattr(p, "rectyp", None),
                "from": origin,
            },
            "types": enrich_types_for_proc(db, p, proc_locals_index) if getattr(p, "typind", None) is not None else {"typind": None, "proto": None, "tags": []},
            "segmap": None,
            "ghidra": gh,
        }

        if seg_ent:
            iSegName = seg_ent.get("iSegName")
            rec["segmap"] = {
                "frame": int(seg_ent.get("frame")) if seg_ent.get("frame") is not None else None,
                "base_off": int(seg_ent.get("off")) if seg_ent.get("off") is not None else None,
                "iSegName": iSegName,
                "segname": segname_lookup(db, int(iSegName)) if iSegName is not None else None,
                "iClassName": seg_ent.get("iClassName"),
                "flags": seg_ent.get("flags"),
                "group": seg_ent.get("group"),
            }
        procs_out.append(rec)

    # --- labels ---
    for pl in getattr(db, "proc_locals", []) or []:
        proc_name = getattr(pl, "proc_name", None)
        for lab in getattr(pl, "labels", []) or []:
            try:
                seg = int(lab.seg)
                off = int(lab.off)
                name = lab.name
            except Exception:
                continue
            seg_ent = seg_to_ent.get(seg)
            gh = None
            if seg_ent:
                gh = compute_ghidra_addr(seg, off, seg_ent, frame_to_selector, "LAB")
            if gh is None and not args.include_unmapped:
                unmapped_labels += 1
                continue
            rec = {
                "name": name,
                "cv": {
                    "seg": seg,
                    "off": off,
                    "rectyp": getattr(lab, "rectyp", None),
                    "flags": getattr(lab, "flags", None),
                    "from": "LABEL",
                    "proc": proc_name,
                },
                "segmap": None,
                "ghidra": gh,
            }
            if seg_ent:
                iSegName = seg_ent.get("iSegName")
                rec["segmap"] = {
                    "frame": int(seg_ent.get("frame")) if seg_ent.get("frame") is not None else None,
                    "base_off": int(seg_ent.get("off")) if seg_ent.get("off") is not None else None,
                    "iSegName": iSegName,
                    "segname": segname_lookup(db, int(iSegName)) if iSegName is not None else None,
                    "iClassName": seg_ent.get("iClassName"),
                    "flags": seg_ent.get("flags"),
                    "group": seg_ent.get("group"),
                }
            labels_out.append(rec)

    out_obj = {
        "meta": {
            "nb09": os.path.basename(args.nb09),
            "segments_csv": os.path.basename(args.segments),
            "globals_total": len(all_globals),
            "procs_total": len(all_procs),
            "labels_total": len(labels_out) + (unmapped_labels if not args.include_unmapped else 0),
            "globals_emitted": len(globals_out),
            "procs_emitted": len(procs_out),
            "labels_emitted": len(labels_out),
            "globals_unmapped_dropped": unmapped_globals if not args.include_unmapped else 0,
            "procs_unmapped_dropped": unmapped_procs if not args.include_unmapped else 0,
            "labels_unmapped_dropped": unmapped_labels if not args.include_unmapped else 0,
        },
        "frame_to_selector": {str(k): f"{v:04x}" for k, v in sorted(frame_to_selector.items())},
        "seg_to_frame": {str(k): int(v) for k, v in sorted(seg_to_frame.items())},
        "globals": globals_out,
        "procs": procs_out,
        "labels": labels_out,
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out_obj, f, indent=2, sort_keys=False)

    print(
        f"Wrote {args.out} (globals={len(globals_out)} procs={len(procs_out)} labels={len(labels_out)}; "
        f"dropped unmapped globals={unmapped_globals} procs={unmapped_procs} labels={unmapped_labels})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
