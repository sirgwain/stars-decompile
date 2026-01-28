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
        if size is None and isinstance(rt, PointerType):
            size = 4 if is_far_ptrtype(int(getattr(rt, "ptrtype", 0))) else 2
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
            if getattr(ls, "is_arg_region", None) is not None:
                entry["is_arg_region"] = bool(getattr(ls, "is_arg_region"))

            # Lexical block id (CodeView S_BLOCK16 nesting). NB09 stores this as a 0-based
            # index into ProcLocals.blocks; we emit 1-based block numbers and only include
            # it for non-default locals (block != 1).
            if getattr(ls, "block", None) is not None:
                try:
                    blk1 = int(getattr(ls, "block")) + 1
                except Exception:
                    blk1 = None
                if isinstance(blk1, int) and blk1 != 1:
                    entry["block"] = blk1

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


        # If ProcLocals provided some params but not all (e.g. some arguments are described as
        # S_REGISTER and therefore show up as locals), promote register vars that appeared before
        # S_ENDARG to params using expected stack offsets derived from the procedure type.
        if arg_types and len(params) < len(arg_types):
            # Expected BP offsets in *stack order* (increasing BP offset). For Pascal, the last
            # prototype parameter is closest at BP+6; for non-Pascal, the first parameter is.
            exp_bp_offs: List[int] = []
            bp = 6
            stack_order = list(reversed(arg_types)) if out.get("is_pascal") else list(arg_types)
            for aty in stack_order:
                sz = getattr(aty, "size", None)
                if sz is None and isinstance(aty, PointerType):
                    sz = 4 if is_far_ptrtype(int(getattr(aty, "ptrtype", 0))) else 2

                try:
                    sz_i = int(sz) if sz is not None else 2
                except Exception:
                    sz_i = 2
                exp_bp_offs.append(bp)
                bp += sz_i

            have_bp = {x.get("bp_off") for x in params if isinstance(x.get("bp_off"), int)}
            missing_bp = [o for o in exp_bp_offs if o not in have_bp]

            if missing_bp:
                # Candidate register vars in the arg region (before S_ENDARG)
                cand_regs = [e for e in locals_ if e.get("is_arg_region") and ("reg" in e)]

                # Heuristic for common Win16 window procs: hwnd, msg/message, wParam, lParam
                # (do not reorder params here; we keep existing stack-order behavior for minimal diffs)
                wndproc_map: Dict[str, int] = {}
                if name.endswith("WndProc") and len(exp_bp_offs) == 4:
                    closest, second, third, farthest = exp_bp_offs[0], exp_bp_offs[1], exp_bp_offs[2], exp_bp_offs[3]
                    wndproc_map = {
                        "lparam": closest,
                        "wparam": second,
                        "msg": third,
                        "message": third,
                        "hwnd": farthest,
                    }

                def _promote(e: Dict[str, Any], bp_off: int) -> None:
                    e["kind"] = "param"
                    e["bp_off"] = int(bp_off)
                    params.append(e)
                    try:
                        locals_.remove(e)
                    except ValueError:
                        pass

                # First pass: name-based mapping (WndProc)
                if wndproc_map:
                    for e in list(cand_regs):
                        nm = (e.get("name") or "").lower()
                        if nm in wndproc_map:
                            bo = wndproc_map[nm]
                            if bo in missing_bp:
                                _promote(e, bo)
                                missing_bp.remove(bo)

                # Second pass: fill remaining missing BP slots with remaining register candidates
                for bo, e in zip(list(missing_bp), [x for x in cand_regs if x.get("kind") == "local"]):
                    _promote(e, bo)
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
                if size is None and isinstance(aty, PointerType):
                    size = 4 if is_far_ptrtype(int(getattr(aty, "ptrtype", 0))) else 2
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


# --- signature override mapping (function -> arg -> c_type) ---

def _normalize_func_keys(name: str) -> List[str]:
    """
    Produce a small set of keys that users are likely to write in override JSON.
    Examples:
      "MEMORY::LpAlloc" -> ["MEMORY::LpAlloc", "LpAlloc"]
      "_strcpy" -> ["_strcpy", "strcpy"]
    """
    keys: List[str] = []
    n = (name or "").strip()
    if not n:
        return keys
    keys.append(n)

    # Strip C++ namespace/class qualifiers.
    if "::" in n:
        keys.append(n.split("::")[-1])

    # Strip leading underscore common in CRT symbols.
    if n.startswith("_"):
        keys.append(n[1:])
        if "::" in n:
            keys.append(n.split("::")[-1].lstrip("_"))

    # De-dupe while preserving order.
    seen = set()
    out: List[str] = []
    for k in keys:
        if k and k not in seen:
            seen.add(k)
            out.append(k)
    return out


def load_signature_overrides(path: Optional[str]) -> Dict[str, Dict[str, str]]:
    """
    Load JSON mapping like:
      {
        "LpAlloc": {"ht": "HeapType"},
        "LpReAlloc": {"2": "HeapType"}          // param index (0-based) also allowed
      }

    Values must be C-ish type strings (as you want them to appear in output JSON),
    e.g. "HeapType", "const char *", "uint16_t".
    """
    if not path:
        return {}
    with open(path, "r", encoding="utf-8") as f:
        obj = json.load(f)
    if not isinstance(obj, dict):
        raise ValueError("override JSON must be an object mapping function -> {arg->type}")
    out: Dict[str, Dict[str, str]] = {}
    for fn, amap in obj.items():
        if not isinstance(fn, str) or not isinstance(amap, dict):
            continue
        clean: Dict[str, str] = {}
        for ak, tv in amap.items():
            if not isinstance(tv, str):
                continue
            # accept int keys, but normalize to string
            if isinstance(ak, int):
                ak = str(ak)
            if not isinstance(ak, str):
                continue
            ak2 = ak.strip()
            tv2 = tv.strip()
            if ak2 and tv2:
                clean[ak2] = tv2
        if clean:
            out[fn.strip()] = clean
    return out


def apply_signature_overrides_to_proc(proc_rec: Dict[str, Any], overrides: Dict[str, Dict[str, str]]) -> int:
    """
    Apply overrides to a single proc record (mutates proc_rec in place).
    Returns count of params updated.
    """
    if not overrides:
        return 0

    name = str(proc_rec.get("name") or "")
    if not name:
        return 0

    # Find mapping entry using a few normalized name variants.
    amap: Optional[Dict[str, str]] = None
    for k in _normalize_func_keys(name):
        amap = overrides.get(k)
        if amap:
            break
    if not amap:
        return 0

    tinfo = proc_rec.get("types") or {}
    params = tinfo.get("params") or []
    if not isinstance(params, list):
        return 0

    updated = 0

    for ak, ctype in amap.items():
        if not isinstance(ctype, str) or not ctype.strip():
            continue
        ak = str(ak).strip()
        ctype = ctype.strip()
        if not ak:
            continue

        # Special key: return type
        if ak in ("ret", "return"):
            ret = tinfo.get("ret")
            if isinstance(ret, dict):
                ret["c_type"] = ctype
                # If a decl exists, refresh it too.
                if "c_decl" in ret:
                    ret["c_decl"] = ctype
            continue

        # Index override (0-based)
        if ak.isdigit():
            try:
                idx = int(ak, 10)
            except Exception:
                idx = None
            if idx is not None and 0 <= idx < len(params) and isinstance(params[idx], dict):
                pname = str(params[idx].get("name") or f"a{idx+1}")
                params[idx]["c_type"] = ctype
                params[idx]["c_decl"] = f"{ctype} {pname}"
                updated += 1
            continue

        # Name-based override
        for p in params:
            if not isinstance(p, dict):
                continue
            if str(p.get("name") or "") == ak:
                p["c_type"] = ctype
                p["c_decl"] = f"{ctype} {ak}"
                updated += 1
                break

    return updated


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



# --- segment/global override mapping ---

def load_seg_overrides(path: Optional[str]) -> Dict[str, Any]:
    """Load segment/global override JSON.

    Currently supported:
      {
        "windows_retypes": {
          "enabled": true,
          "rules": [
            {"from": "uint16_t", "prefix": "hwnd", "to": "HWND"},
            {"from": "uint32_t", "prefix": "cr",   "to": "COLORREF"}
          ]
        }
      }
    """
    if not path:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
        return obj if isinstance(obj, dict) else {}
    except Exception as e:
        print(f"warning: could not load seg overrides {path}: {e}", file=sys.stderr)
        return {}


def build_windows_retype_rules(seg_overrides: Dict[str, Any]) -> List[Dict[str, str]]:
    """Return ordered retype rules: [{from, prefix, to}, ...].

    Fully data-driven: no built-in defaults. Provide rules in seg_overrides.json:

      {
        "windows_retypes": {
          "enabled": true,
          "rules": [
            {"from": "uint16_t", "prefix": "hwnd", "to": "HWND"},
            {"from": "uint32_t", "prefix": "cr",   "to": "COLORREF"}
          ]
        }
      }
    """
    cfg = (seg_overrides or {}).get("windows_retypes") or {}
    if not isinstance(cfg, dict):
        return []
    if not cfg.get("enabled", False):
        return []

    rules: List[Dict[str, str]] = []
    extra = cfg.get("rules", [])
    if isinstance(extra, list):
        for r in extra:
            if not isinstance(r, dict):
                continue
            frm = r.get("from")
            pfx = r.get("prefix")
            to = r.get("to")
            if not (isinstance(frm, str) and isinstance(pfx, str) and isinstance(to, str)):
                continue
            rules.append({"from": frm.strip(), "prefix": pfx.strip(), "to": to.strip()})

    return rules


def _rewrite_decl_leading_type(c_decl: Optional[str], old_type: str, new_type: str) -> Optional[str]:
    if c_decl is None:
        return None
    # Replace only the leading type token(s).
    # Common forms:
    #   "uint16_t hwnd" -> "HWND hwnd"
    #   "uint16_t __far *hwnd" -> "HWND __far *hwnd"
    #   "uint32_t crFoo" -> "COLORREF crFoo"
    pat = r'^\s*' + re.escape(old_type) + r'(\b)'
    if re.match(pat, c_decl):
        return re.sub(pat, new_type + r'\1', c_decl, count=1)
    return c_decl


def apply_windows_retypes_to_var(name: str, tyrec: Dict[str, Any], rules: List[Dict[str, str]]) -> bool:
    """Mutate tyrec {c_type,c_decl} based on name/type rules. Returns True if changed."""
    if not rules:
        return False
    if not isinstance(tyrec, dict):
        return False
    c_type = tyrec.get("c_type")
    c_decl = tyrec.get("c_decl")
    if not isinstance(c_type, str) or not isinstance(name, str) or not name:
        return False

    nl = name.lower()
    for r in rules:
        frm = r.get("from")
        pfx = r.get("prefix")
        to = r.get("to")
        if not (isinstance(frm, str) and isinstance(pfx, str) and isinstance(to, str)):
            continue
        if c_type == frm and nl.startswith(pfx.lower()):
            tyrec["c_type"] = to
            tyrec["c_decl"] = _rewrite_decl_leading_type(c_decl if isinstance(c_decl, str) else None, frm, to)
            tyrec["note"] = (tyrec.get("note") + "; " if tyrec.get("note") else "") + "windows_retype"
            return True
    return False


def apply_windows_retypes_to_proc(proc_rec: Dict[str, Any], rules: List[Dict[str, str]]) -> int:
    """Apply name-based retyping to proc params/locals. Returns count changed."""
    if not rules:
        return 0
    if not isinstance(proc_rec, dict):
        return 0
    types = proc_rec.get("types")
    if not isinstance(types, dict):
        return 0

    changed = 0
    for k in ("params", "locals"):
        lst = types.get(k)
        if not isinstance(lst, list):
            continue
        for ent in lst:
            if not isinstance(ent, dict):
                continue
            nm = ent.get("name") or ""
            if apply_windows_retypes_to_var(str(nm), ent, rules):
                changed += 1
    return changed


def _patch_existing_blocks_inplace(existing: Dict[str, Any], proc_locals_index: Dict[str, Any]) -> int:
    """
    Patch an already-generated nb09_ghidra_globals.json in-place by adding a 1-based
    "block" field to locals when NB09 indicates they belong to a non-default lexical
    block (S_BLOCK16 nesting).

    This intentionally *only* adds missing "block" keys and does not otherwise
    regenerate or normalize the JSON, so diffs stay minimal.
    """
    changed = 0

    procs = existing.get("procs")
    if not isinstance(procs, list):
        return 0

    for prec in procs:
        if not isinstance(prec, dict):
            continue
        name = prec.get("name") or ""
        cv = prec.get("cv") or {}
        seg = cv.get("seg")
        off = cv.get("off")
        if not isinstance(seg, int) or not isinstance(off, int):
            continue

        pl = proc_locals_index.get("by_segoff", {}).get((seg, off)) \
             or proc_locals_index.get("by_name", {}).get(name)
        if pl is None:
            continue

        types = prec.get("types")
        if not isinstance(types, dict):
            continue
        locals_list = types.get("locals")
        if not isinstance(locals_list, list) or not locals_list:
            continue

        # Build fast lookup for existing locals by (name, bp_off, reg, reg_off)
        by_key: Dict[Tuple[Any, Any, Any, Any], Dict[str, Any]] = {}
        for e in locals_list:
            if not isinstance(e, dict):
                continue
            if e.get("kind") != "local":
                continue
            k = (e.get("name"), e.get("bp_off"), e.get("reg"), e.get("reg_off"))
            by_key[k] = e

        for ls in getattr(pl, "locals", []) or []:
            try:
                if str(getattr(ls, "kind") or "") != "local":
                    continue
                blk = getattr(ls, "block", None)
                if blk is None:
                    continue
                blk1 = int(blk) + 1  # emit 1-based
                if blk1 == 1:
                    continue  # default block, omit
                lk = (str(getattr(ls, "name") or ""), getattr(ls, "bp_off", None),
                      getattr(ls, "reg", None), getattr(ls, "reg_off", None))
            except Exception:
                continue

            e = by_key.get(lk)
            if e is None:
                continue
            if "block" in e:
                continue
            e["block"] = blk1
            changed += 1

    return changed

def main() -> int:
    ap = argparse.ArgumentParser(description="Emit Ghidra JSON for renaming globals/procs/labels from NB09.")
    ap.add_argument("nb09", help="Path to extracted CodeView NB09 blob (e.g., stars26jrc3.codeview.nb09.bin)")
    ap.add_argument("--segments", default="segments.csv", help="Path to segments.csv exported from Ghidra (default: ./segments.csv)")
    ap.add_argument("--out", default="nb09_ghidra_globals.json", help="Output JSON path")
    ap.add_argument("--include-unmapped", action="store_true", help="Include globals we cannot map to a Ghidra address")
    ap.add_argument("--sig-overrides", dest="sig_overrides", default=None,
                    help="Path to JSON mapping function->arg->c_type overrides (e.g. {\"LpAlloc\": {\"ht\": \"HeapType\"}})")
    ap.add_argument("--seg-overrides", dest="seg_overrides", default=None,
                    help="Path to JSON mapping for segment/global retyping overrides (e.g. windows handle heuristics)")
    args = ap.parse_args()

    sig_overrides = load_signature_overrides(args.sig_overrides)
    seg_overrides = load_seg_overrides(args.seg_overrides)
    win_retype_rules = build_windows_retype_rules(seg_overrides)

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
    sig_overrides_applied = 0

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

        apply_windows_retypes_to_var(rec["name"], rec["types"], win_retype_rules)

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

        apply_windows_retypes_to_proc(rec, win_retype_rules)

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
        if sig_overrides:
            sig_overrides_applied += apply_signature_overrides_to_proc(rec, sig_overrides)
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
            "sig_overrides": os.path.basename(args.sig_overrides) if args.sig_overrides else None,
            "sig_overrides_params_applied": sig_overrides_applied,
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

    # If the output file already exists, keep the JSON stable and only patch in
    # local block ids (to keep git diffs minimal).
    if os.path.exists(args.out):
        with open(args.out, "r", encoding="utf-8") as f:
            existing = json.load(f)
        changed = _patch_existing_blocks_inplace(existing, proc_locals_index)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2, sort_keys=False)
        print(f"Patched {args.out} (added local block ids: {changed})")
        return 0

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out_obj, f, indent=2, sort_keys=False)

    print(
        f"Wrote {args.out} (globals={len(globals_out)} procs={len(procs_out)} labels={len(labels_out)}; "
        f"dropped unmapped globals={unmapped_globals} procs={unmapped_procs} labels={unmapped_labels})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())