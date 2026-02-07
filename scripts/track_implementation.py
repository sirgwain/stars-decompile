#!/usr/bin/env python3
"""
Track implementation status of Stars! decompiled functions.

Reads function names from nb09_ghidra_globals.json (excluding PUBLIC),
then scans .c files at the project root to determine which functions
have been implemented vs. which are still stubs (contain "TODO: implement").

Output: scripts/implementation_status.json

Flags:
  --update-docs   Also generate notes/implementation.md
"""

import json
import re
import sys
import os
from pathlib import Path


def find_function_bodies(c_files, target_names):
    """Find function definitions in C files for the given target names.

    For each target name, searches for lines containing the name followed by '('
    where the next '{' starts a function body. Then checks if the body contains
    "TODO: implement".

    Returns dict: func_name -> {"file": str, "line": int, "implemented": bool, "win32": bool}
    """
    results = {}

    # Build a regex that matches any target name followed by (
    # This handles: int16_t FuncName(...), INT_PTR CALLBACK FuncName(...), etc.
    name_pattern = re.compile(
        r'\b(' + '|'.join(re.escape(n) for n in target_names) + r')\s*\('
    )

    # Pattern to detect _WIN32 in preprocessor conditionals
    win32_if = re.compile(r'^\s*#\s*if.*\b_WIN32\b')
    pp_else = re.compile(r'^\s*#\s*(?:else|elif)\b')
    pp_endif = re.compile(r'^\s*#\s*endif\b')
    pp_if = re.compile(r'^\s*#\s*if')

    for c_file in c_files:
        with open(c_file, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        # Track preprocessor nesting to know if we're inside #ifdef _WIN32
        # Stack entries: True if this #if level is a _WIN32 block
        pp_stack = []
        in_win32 = False

        i = 0
        while i < len(lines):
            line = lines[i]

            # Track preprocessor directives
            if pp_endif.match(line):
                if pp_stack:
                    pp_stack.pop()
                in_win32 = any(pp_stack)
            elif pp_else.match(line):
                # #else inverts the condition at current level
                if pp_stack:
                    pp_stack[-1] = not pp_stack[-1]
                in_win32 = any(pp_stack)
            elif win32_if.match(line):
                # Check if it's #ifdef _WIN32 or #if defined(_WIN32)
                # For #ifndef _WIN32, the negation means we're NOT in win32
                is_ifndef = bool(re.match(r'^\s*#\s*ifndef\b', line))
                pp_stack.append(not is_ifndef)
                in_win32 = any(pp_stack)
            elif pp_if.match(line):
                pp_stack.append(False)
                in_win32 = any(pp_stack)

            m = name_pattern.search(line)
            if not m:
                i += 1
                continue

            func_name = m.group(1)

            stripped = line.lstrip()

            # Skip lines that are clearly not definitions
            if stripped.startswith(('/', '*', '{', '}', 'if ', 'if(', 'for ', 'for(',
                                    'while ', 'while(', 'return ', 'case ', 'switch')):
                i += 1
                continue

            # Check if this line is indented (likely a call, not a definition)
            indent = len(line) - len(line.lstrip())
            if indent > 4:
                i += 1
                continue

            # Look for opening brace within next few lines
            found_brace = False
            brace_line = i
            for j in range(i, min(i + 8, len(lines))):
                if '{' in lines[j]:
                    found_brace = True
                    brace_line = j
                    break
                # If we hit a semicolon before a brace, it's a declaration/prototype
                if ';' in lines[j]:
                    break

            if not found_brace:
                i += 1
                continue

            # Scan body for TODO: implement
            brace_depth = 0
            has_todo = False
            for k in range(brace_line, len(lines)):
                brace_depth += lines[k].count('{') - lines[k].count('}')
                if "TODO: implement" in lines[k]:
                    has_todo = True
                if brace_depth == 0 and k > brace_line:
                    break

            # Only record if not already found (first definition wins)
            if func_name not in results:
                results[func_name] = {
                    "file": os.path.basename(c_file),
                    "line": i + 1,
                    "implemented": not has_todo,
                    "win32": in_win32,
                }

            i += 1

    return results


def find_decompiled_lines(decompiled_dir, target_names):
    """Find line numbers and line counts for functions in decompiled/all/*.c files.

    Looks for '// Function: FuncName' comment lines and measures the distance
    to the next function marker (minus the separator block) to estimate size.

    Returns dict: func_name -> {"file": str, "line": int, "line_count": int|None}
    """
    results = {}
    if not decompiled_dir.is_dir():
        return results

    for c_file in sorted(decompiled_dir.glob("*.c")):
        with open(c_file, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        # Collect all function marker positions in this file
        markers = []
        for i, line in enumerate(lines):
            if line.startswith("// Function: "):
                name = line[len("// Function: "):].strip()
                markers.append((i, name))

        for idx, (line_idx, name) in enumerate(markers):
            if name not in target_names:
                continue
            # Line count: from this marker to next marker's separator block, or EOF
            if idx + 1 < len(markers):
                next_marker = markers[idx + 1][0]
                # The separator block is 4 lines before "// Function:" line:
                # blank, ====, // Function:, // Address:, // Segment:, ====, blank
                # Walk backwards from next_marker to find start of separator
                end = next_marker
                while end > line_idx and lines[end - 1].strip() in ("", "// ======================================================================"):
                    end -= 1
                line_count = end - line_idx
            else:
                # Last function in file: count to EOF, trimming trailing blanks
                end = len(lines)
                while end > line_idx and lines[end - 1].strip() == "":
                    end -= 1
                line_count = end - line_idx

            results[name] = {
                "file": c_file.name,
                "line": line_idx + 1,  # 1-based
                "line_count": max(line_count, 1),
            }

    return results


def segment_to_decompiled_file(segment_name):
    """Map segment name like MEMORY_PARTS to decompiled filename parts.c."""
    if segment_name.startswith("MEMORY_"):
        return segment_name[len("MEMORY_"):].lower() + ".c"
    return None


def generate_markdown(project_dir, functions, summary, by_file, decompiled_lines):
    """Generate notes/implementation.md."""
    notes_dir = project_dir / "notes"
    notes_dir.mkdir(exist_ok=True)
    md_path = notes_dir / "implementation.md"

    lines = []
    lines.append("# Stars! Decompilation Progress\n")
    lines.append("")
    lines.append("## Summary\n")
    lines.append("")
    lines.append(f"| Metric | Count |")
    lines.append(f"|--------|------:|")
    lines.append(f"| Total functions | {summary['total']} |")
    lines.append(f"| ✅ Implemented | {summary['implemented']} |")
    lines.append(f"| ⬜ Stub | {summary['stub']} |")
    lines.append(f"| ❌ Missing | {summary['missing']} |")
    lines.append(f"| **Progress** | **{summary['percent_implemented']}%** |")
    lines.append("")

    # By file table
    lines.append("## By File\n")
    lines.append("")
    lines.append("| File | Implemented | Stub | Missing | Progress |")
    lines.append("|------|------------:|-----:|--------:|---------:|")
    for fname, counts in sorted(by_file.items()):
        total = counts["implemented"] + counts["stub"] + counts.get("missing", 0)
        pct = round(100.0 * counts["implemented"] / total, 1) if total else 0
        lines.append(f"| {fname} | {counts['implemented']} | {counts['stub']} | {counts.get('missing', 0)} | {pct}% |")
    lines.append("")

    # All functions alphabetically
    lines.append("## All Functions\n")
    lines.append("")

    # Group by source file for the by-file sections
    funcs_by_file = {}
    for name, info in functions.items():
        key = info["file"] or segment_to_decompiled_file(info["segment"]) or "(unknown)"
        funcs_by_file.setdefault(key, []).append((name, info))

    for fname in sorted(funcs_by_file.keys()):
        # Sort: unimplemented before implemented, non-win32 before win32,
        # then by decompiled line count ascending, then alphabetically
        func_list = sorted(funcs_by_file[fname], key=lambda x: (
            0 if x[1]["status"] != "implemented" else 1,
            1 if x[1].get("win32") else 0,
            x[1].get("decompiled_line_count") or 99999,
            x[0].lower(),
        ))
        impl_count = sum(1 for _, info in func_list if info["status"] == "implemented")
        lines.append(f"### {fname} ({impl_count}/{len(func_list)})\n")
        lines.append("")

        for name, info in func_list:
            check = "✅" if info["status"] == "implemented" else "⬜"
            win_tag = " 🪟" if info.get("win32") else ""
            dlc = info.get("decompiled_line_count")
            size_tag = f" ({dlc}L)" if dlc else ""

            # Build links
            link_parts = []

            # Link to root source file
            if info["file"] and info["line"]:
                link_parts.append(f"[{info['file']}:{info['line']}](../{info['file']}#L{info['line']})")

            # Link to decompiled file
            decomp = decompiled_lines.get(name)
            if decomp:
                decomp_path = f"../decompiled/all/{decomp['file']}"
                link_parts.append(f"[decompiled]({decomp_path}#L{decomp['line']})")

            links = " · ".join(link_parts) if link_parts else ""
            proto = f"`{info['proto']}`"

            parts = [f"- {check} **{name}**{win_tag}{size_tag} — {proto}"]
            if links:
                parts.append(f" — {links}")
            lines.append("".join(parts))

        lines.append("")

    with open(md_path, "w") as f:
        f.write("\n".join(lines))

    print(f"Docs:   {md_path}")


def main():
    update_docs = "--update-docs" in sys.argv
    argv = [a for a in sys.argv[1:] if a != "--update-docs"]

    project_dir = Path(__file__).resolve().parent.parent
    globals_json = project_dir / "scripts" / "nb09_ghidra_globals.json"
    output_json = project_dir / "scripts" / "implementation_status.json"

    if argv:
        output_json = Path(argv[0])

    with open(globals_json, "r") as f:
        root = json.load(f)

    # Get all non-PUBLIC function names
    procs = {}
    for p in root["procs"]:
        if p["cv"]["from"] == "PUBLIC":
            continue
        procs[p["name"]] = {
            "addr": p["ghidra"]["addr"],
            "segment": p["segmap"]["segname"],
            "proto": p["types"]["proto"],
        }

    # Find all .c files at root
    c_files = sorted(project_dir.glob("*.c"))
    print(f"Scanning {len(c_files)} C files...")

    func_bodies = find_function_bodies(c_files, set(procs.keys()))

    # Find decompiled line numbers
    decompiled_dir = project_dir / "decompiled" / "all"
    decompiled_lines = find_decompiled_lines(decompiled_dir, set(procs.keys()))

    # Build result
    functions = {}
    for name, info in sorted(procs.items()):
        body = func_bodies.get(name)
        decomp = decompiled_lines.get(name)
        decomp_lines = decomp["line_count"] if decomp else None
        if body is not None:
            status = "implemented" if body["implemented"] else "stub"
            functions[name] = {
                **info,
                "status": status,
                "file": body["file"],
                "line": body["line"],
                "decompiled_line_count": decomp_lines,
                "win32": body["win32"],
            }
        else:
            functions[name] = {
                **info,
                "status": "missing",
                "file": None,
                "line": None,
                "decompiled_line_count": decomp_lines,
                "win32": False,
            }

    # Summary
    implemented = [n for n, f in functions.items() if f["status"] == "implemented"]
    stubs = [n for n, f in functions.items() if f["status"] == "stub"]
    missing = [n for n, f in functions.items() if f["status"] == "missing"]

    summary = {
        "total": len(functions),
        "implemented": len(implemented),
        "stub": len(stubs),
        "missing": len(missing),
        "percent_implemented": round(100.0 * len(implemented) / len(functions), 1)
        if functions
        else 0,
    }

    # Group by file
    by_file = {}
    for name, info in functions.items():
        f = info["file"] or segment_to_decompiled_file(info["segment"]) or "(unknown)"
        by_file.setdefault(f, {"implemented": 0, "stub": 0, "missing": 0})
        by_file[f][info["status"]] += 1

    result = {
        "summary": summary,
        "by_file": dict(sorted(by_file.items())),
        "functions": functions,
    }

    with open(output_json, "w") as f:
        json.dump(result, f, indent=2)

    print(f"Output: {output_json}")
    print(f"Total functions: {summary['total']}")
    print(f"Implemented:     {summary['implemented']}")
    print(f"Stub:            {summary['stub']}")
    print(f"Missing:         {summary['missing']}")
    print(f"Progress:        {summary['percent_implemented']}%")

    # Validate known cases
    for name, expected in [
        ("FLookupPartX", "implemented"),
        ("IPlrAlsoCheater", "stub"),
        ("WinMain", "implemented"),
    ]:
        if name in functions:
            s = functions[name]["status"]
            ok = "PASS" if s == expected else "FAIL"
            print(f"[{ok}] {name} status={s} (expected {expected})")

    if update_docs:
        generate_markdown(project_dir, functions, summary, by_file, decompiled_lines)


if __name__ == "__main__":
    main()
