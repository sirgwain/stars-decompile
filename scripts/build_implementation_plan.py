#!/usr/bin/env python3
"""Cross-reference call_graph.json and implementation_status.json to produce
an implementation plan sorted by call-graph depth and line count.

Flags:
  --exclude-ai   Exclude AI-related functions (files: ai.c, ai2.c, ai3.c, ai4.c, aiutil.c, aiu.c)
"""

import json
import os
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CALL_GRAPH = ROOT / "scripts" / "call_graph.json"
IMPL_STATUS = ROOT / "scripts" / "implementation_status.json"
DECOMPILED_DIR = ROOT / "decompiled" / "all"
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


def count_function_lines(decompiled_path, func_name):
    """Count lines from '// Function: FuncName' to next marker or EOF."""
    if not decompiled_path or not decompiled_path.exists():
        return None
    try:
        lines = decompiled_path.read_text().splitlines()
    except Exception:
        return None

    marker = f"// Function: {func_name}"
    start = None
    for i, line in enumerate(lines):
        if line.strip() == marker:
            start = i
        elif start is not None and line.strip().startswith("// Function:"):
            return i - start
    if start is not None:
        return len(lines) - start
    return None


def is_ai_function(info):
    """Check if function belongs to an AI-related file."""
    src = info.get("src_file")
    if src and src in AI_FILES:
        return True
    seg = info.get("segment", "")
    return seg in ("MEMORY_AI", "MEMORY_AI2", "MEMORY_AI3", "MEMORY_AI4",
                    "MEMORY_AIU")


def build_plan(exclude_ai=False):
    cg, impl = load_data()
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
        line_count = count_function_lines(decompiled, name)

        entry = {
            "status": status,
            "depth": depth,
            "proto": proto,
            "src_file": src_file,
            "segment": segment,
            "decompiled": decompiled,
            "line_count": line_count,
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
            md.append("| | Function | Lines | Prototype | Source | Decompiled |")
            md.append("|---|----------|------:|-----------|--------|------------|")
            for name, info in unimplemented:
                lc = info["line_count"] if info["line_count"] is not None else "?"
                src_link = ""
                if info["src_file"]:
                    src_link = f"[{info['src_file']}](../{info['src_file']})"
                dec_link = ""
                if info["decompiled"]:
                    dec_rel = os.path.relpath(info["decompiled"], ROOT / "notes")
                    dec_link = f"[{info['decompiled'].name}]({dec_rel})"
                proto = f"`{info['proto']}`" if info["proto"] else ""
                md.append(f"| ⬜ | **{name}** | {lc} | {proto} | {src_link} | {dec_link} |")
            md.append("")

        if implemented:
            md.append(f"### Implemented ({len(implemented)})\n")
            md.append("<details><summary>Show {0} implemented functions</summary>\n".format(len(implemented)))
            md.append("| | Function | Lines | Source |")
            md.append("|---|----------|------:|--------|")
            for name, info in sorted(implemented, key=lambda x: x[0]):
                lc = info["line_count"] if info["line_count"] is not None else "?"
                src_link = ""
                if info["src_file"]:
                    src_link = f"[{info['src_file']}](../{info['src_file']})"
                md.append(f"| ✅ | {name} | {lc} | {src_link} |")
            md.append("\n</details>\n")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text("\n".join(md) + "\n")
    print(f"Wrote {OUTPUT} ({len(md)} lines)")
    if exclude_ai:
        print(f"Excluded {excluded_count} AI functions")


if __name__ == "__main__":
    exclude_ai = "--exclude-ai" in sys.argv
    build_plan(exclude_ai=exclude_ai)
