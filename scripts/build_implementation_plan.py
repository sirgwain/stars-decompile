#!/usr/bin/env python3
"""Cross-reference call_graph.json and implementation_status.json to produce
an implementation plan sorted by call-graph depth and line count.

Flags:
  --exclude-ai            Exclude AI-related functions (files: ai.c, ai2.c, ai3.c, ai4.c, aiutil.c, aiu.c)
  --no-update-impl-locs   Do not rewrite implementation_status.json with root/decompiled file+line locations
"""

import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CALL_GRAPH = ROOT / "scripts" / "call_graph.json"
IMPL_STATUS = ROOT / "scripts" / "implementation_status.json"
DECOMPILED_DIR = ROOT / "decompiled" / "all"
PROJECT_INDEX = ROOT / "scripts" / "project_index_lite.json"
OUTPUT = ROOT / "notes" / "implementation-plan.md"

AI_FILES = {"ai.c", "ai2.c", "ai3.c", "ai4.c", "aiutil.c", "aiu.c"}


def load_data():
    with open(CALL_GRAPH) as f:
        cg = json.load(f)
    with open(IMPL_STATUS) as f:
        impl = json.load(f)
    return cg, impl


def get_decompiled_file_for_segment(segment):
    """Map MEMORY_FOO segment to decompiled/all/foo.c"""
    if not segment:
        return None
    name = segment.replace("MEMORY_", "").lower() + ".c"
    p = DECOMPILED_DIR / name
    return p if p.exists() else None


def is_ai_function(info):
    """Check if function belongs to an AI-related file."""
    src = info.get("src_file")
    if src and src in AI_FILES:
        return True
    seg = info.get("segment", "")
    return seg in ("MEMORY_AI", "MEMORY_AI2", "MEMORY_AI3", "MEMORY_AI4",
                    "MEMORY_AIU")


def _load_project_index():
    # Optional: project_index_lite.json maps function -> {file,line,signature,kind}
    try:
        with open(PROJECT_INDEX) as f:
            return json.load(f)
    except OSError:
        return None


def _find_decompiled_def_line(path: Path, func_name: str):
    """Return 1-based line number of the first likely function definition for func_name in path."""
    try:
        s = path.read_text(errors="replace")
    except OSError:
        return None

    pat = re.compile(r"^\s*(?:static\s+)?(?:inline\s+)?[A-Za-z_][\w\s\*\(\)\[\],]*\b" +
                     re.escape(func_name) + r"\s*\(", re.MULTILINE)
    m = pat.search(s)
    if not m:
        return None
    return s.count("\n", 0, m.start()) + 1


def enrich_implementation_status_with_locations(cg: dict, impl: dict):
    """Populate root/decompiled file+line fields in impl['functions'] and backfill missing root file/line.

    Returns (changed: bool, stats: dict).
    """
    changed = False
    stats = {"backfilled_root": 0, "set_decompiled_file": 0, "set_decompiled_line": 0}

    funcs = impl.get("functions", {})
    cg_funcs = (cg or {}).get("functions", {})

    proj = _load_project_index()
    proj_funcs = (proj or {}).get("functions", {})

    # project_index_lite.json stores a single entry per function; full project_index.json stores a list.
    def _proj_def(name: str):
        v = proj_funcs.get(name)
        if v is None:
            return None
        if isinstance(v, dict):
            return v if v.get("kind") == "definition" else v
        if isinstance(v, list):
            for it in v:
                if it.get("kind") == "definition":
                    return it
            return v[0] if v else None
        return None

    for name, info in funcs.items():
        # Root location: prefer existing file/line, otherwise try project index.
        if info.get("file") is None or info.get("line") is None:
            pd = _proj_def(name)
            if pd and pd.get("file") is not None and pd.get("line") is not None:
                if info.get("file") is None:
                    info["file"] = pd["file"]
                if info.get("line") is None:
                    info["line"] = pd["line"]
                stats["backfilled_root"] += 1
                changed = True

        if "root_file" not in info:
            info["root_file"] = info.get("file")
            changed = True
        if "root_line" not in info:
            info["root_line"] = info.get("line")
            changed = True

        # Decompiled location
        seg = info.get("segment")
        dec_path = get_decompiled_file_for_segment(seg)
        dec_rel = None
        if dec_path:
            try:
                dec_rel = str(dec_path.relative_to(ROOT))
            except ValueError:
                dec_rel = str(dec_path)

        if "decompiled_file" not in info and dec_rel is not None:
            info["decompiled_file"] = dec_rel
            stats["set_decompiled_file"] += 1
            changed = True

        if "decompiled_line" not in info:
            if dec_path and dec_path.exists():
                dec_line = _find_decompiled_def_line(dec_path, name)
            else:
                dec_line = None
            if dec_line is not None:
                info["decompiled_line"] = dec_line
                stats["set_decompiled_line"] += 1
                changed = True

        # Keep addr if missing.
        if "addr" not in info:
            cg_info = cg_funcs.get(name)
            if cg_info and "addr" in cg_info:
                info["addr"] = cg_info["addr"]
                changed = True

    return changed, stats


def build_plan(exclude_ai=False, update_impl_locations=True):
    cg, impl = load_data()

    if update_impl_locations:
        changed, stats = enrich_implementation_status_with_locations(cg, impl)
        if changed:
            IMPL_STATUS.parent.mkdir(parents=True, exist_ok=True)
            IMPL_STATUS.write_text(json.dumps(impl, indent=2, sort_keys=True) + "\n")
            print(f"Updated {IMPL_STATUS} with root/decompiled locations (backfilled_root={stats['backfilled_root']}, decompiled_file={stats['set_decompiled_file']}, decompiled_line={stats['set_decompiled_line']})")

    cg_funcs = cg["functions"]
    impl_funcs = impl["functions"]

    # Build a mapping: func_name -> merged info
    all_funcs = {}
    excluded_count = 0
    for name, cg_info in cg_funcs.items():
        impl_info = impl_funcs.get(name, {})
        status = impl_info.get("status", "missing")
        segment = impl_info.get("segment")
        src_file = impl_info.get("file")
        proto = impl_info.get("proto", "")
        depth = cg_info.get("depth", None)
        decompiled = get_decompiled_file_for_segment(segment)
        line_count = impl_info.get("decompiled_line_count")

        win32 = impl_info.get("win32", False)

        entry = {
            "status": status,
            "depth": depth,
            "proto": proto,
            "src_file": src_file,
            "segment": segment,
            "decompiled": decompiled,
            "line_count": line_count,
            "win32": win32,
        }

        if exclude_ai and is_ai_function(entry):
            excluded_count += 1
            continue

        all_funcs[name] = entry

    # Group by depth
    by_depth = defaultdict(list)
    for name, info in all_funcs.items():
        by_depth[info["depth"]].append((name, info))

    # Sort depths: 0, 1, 2, ... then -1 at end
    sorted_depths = sorted(
        (d for d in by_depth if d is not None and d >= 0)
    )
    if -1 in by_depth:
        sorted_depths.append(-1)
    if None in by_depth:
        sorted_depths.append(None)

    depth_labels = {
        0: "Depth 0 — Leaf Functions",
        1: "Depth 1 — Calls Only Leaves",
        -1: "Depth -1 — Cyclic Functions",
        None: "Unknown Depth",
    }

    # Build markdown
    md = []
    md.append("# Implementation Plan\n")
    md.append("Auto-generated cross-reference of call graph depth and implementation status.\n")
    if exclude_ai:
        md.append(f"*AI functions excluded ({excluded_count} functions from {', '.join(sorted(AI_FILES))})*\n")

    # Summary
    md.append("## Summary\n")
    md.append("| Depth | Label | Total | Implemented | Unimplemented |")
    md.append("|-------|-------|------:|------------:|--------------:|")
    for d in sorted_depths:
        funcs = by_depth[d]
        total = len(funcs)
        impl_count = sum(1 for _, i in funcs if i["status"] == "implemented")
        unimpl = total - impl_count
        label = depth_labels.get(d, f"Depth {d}")
        md.append(f"| {d} | {label} | {total} | {impl_count} | {unimpl} |")
    # Totals
    grand_total = sum(len(v) for v in by_depth.values())
    grand_impl = sum(1 for _, i in all_funcs.items() if i["status"] == "implemented")
    md.append(f"| | **Total** | **{grand_total}** | **{grand_impl}** | **{grand_total - grand_impl}** |")
    md.append("")

    # Per-depth sections
    for d in sorted_depths:
        label = depth_labels.get(d, f"Depth {d} — Calls up to depth {d-1}")
        md.append(f"## {label}\n")

        funcs = by_depth[d]
        unimplemented = [(n, i) for n, i in funcs if i["status"] != "implemented"]
        implemented = [(n, i) for n, i in funcs if i["status"] == "implemented"]

        # Sort unimplemented by line count ascending (None at end)
        unimplemented.sort(key=lambda x: (x[1]["line_count"] or 99999, x[0]))

        if unimplemented:
            md.append(f"### Unimplemented ({len(unimplemented)})\n")
            md.append("| | Function | Lines | Win | Prototype | Source | Decompiled |")
            md.append("|---|----------|------:|:---:|-----------|--------|------------|")
            for name, info in unimplemented:
                lc = info["line_count"] if info["line_count"] is not None else "?"
                win = "W" if info.get("win32") else ""
                src_link = ""
                if info["src_file"]:
                    src_link = f"[{info['src_file']}](../{info['src_file']})"
                dec_link = ""
                if info["decompiled"]:
                    dec_rel = os.path.relpath(info["decompiled"], ROOT / "notes")
                    dec_link = f"[{info['decompiled'].name}]({dec_rel})"
                proto = f"`{info['proto']}`" if info["proto"] else ""
                md.append(f"| ⬜ | **{name}** | {lc} | {win} | {proto} | {src_link} | {dec_link} |")
            md.append("")

        if implemented:
            md.append(f"### Implemented ({len(implemented)})\n")
            md.append("<details><summary>Show {0} implemented functions</summary>\n".format(len(implemented)))
            md.append("| | Function | Lines | Win | Source |")
            md.append("|---|----------|------:|:---:|--------|")
            for name, info in sorted(implemented, key=lambda x: x[0]):
                lc = info["line_count"] if info["line_count"] is not None else "?"
                win = "W" if info.get("win32") else ""
                src_link = ""
                if info["src_file"]:
                    src_link = f"[{info['src_file']}](../{info['src_file']})"
                md.append(f"| ✅ | {name} | {lc} | {win} | {src_link} |")
            md.append("\n</details>\n")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text("\n".join(md) + "\n")
    print(f"Wrote {OUTPUT} ({len(md)} lines)")
    if exclude_ai:
        print(f"Excluded {excluded_count} AI functions")


if __name__ == "__main__":
    exclude_ai = "--exclude-ai" in sys.argv
    update_impl_locations = "--no-update-impl-locs" not in sys.argv
    build_plan(exclude_ai=exclude_ai, update_impl_locations=update_impl_locations)
