#!/usr/bin/env python3
"""
make_project_index.py

Generate a searchable index for the Stars! decompile repo:
- types from types.h (structs/enums/typedefs)
- function signatures from .c/.h (prototypes + definitions)
- globals from headers (extern decls)
- file inventory

This is intentionally "good enough" and dependency-free. If you later want
perfect parsing, swap the function scanning with libclang using compile_commands.json.
"""
from __future__ import annotations
import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

EXCLUDE_DIRS = {
    ".git", ".hg", ".svn",
    "build", "out", "dist",
    ".idea", ".vscode",
    "__pycache__", ".pytest_cache",
}

C_EXTS = {".c", ".h", ".hpp", ".hh"}

# --- utilities ---

def find_repo_root(start: Path) -> Path:
    p = start.resolve()
    while True:
        if (p / "CMakeLists.txt").exists():
            return p
        if p.parent == p:
            break
        p = p.parent
    raise SystemExit("error: could not find repo root (CMakeLists.txt)")

def iter_source_files(root: Path, include_scripts: bool) -> List[Path]:
    files: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        d = Path(dirpath)
        # prune excluded dirs
        dirnames[:] = [dn for dn in dirnames if dn not in EXCLUDE_DIRS]
        if not include_scripts and d.name == "scripts":
            dirnames[:] = []
            continue
        for fn in filenames:
            p = d / fn
            if p.suffix.lower() in C_EXTS:
                files.append(p)
    return sorted(files)

def strip_c_comments(text: str) -> str:
    # remove /* ... */ and //... (best effort)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"//[^\n]*", "", text)
    return text

def one_line(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip())

# --- types.h parsing (best effort, tailored to generated format) ---

_field_re = re.compile(
    r"^\s*(?P<type>[^;/{]+?)\s+(?P<name>[A-Za-z_]\w*)\s*(?::\s*(?P<bits>\d+))?\s*;\s*(?P<comment>/\*.*\*/)?\s*$"
)

typedef_struct_start_re = re.compile(r"^\s*typedef\s+struct\s+_(?P<tag>\w+)\s*$")
typedef_struct_end_re = re.compile(r"^\s*}\s*(?P<name>\w+)\s*;\s*$")

typedef_enum_start_re = re.compile(r"^\s*typedef\s+enum\s+_(?P<tag>\w+)\s*$")
typedef_enum_end_re = re.compile(r"^\s*}\s*(?P<name>\w+)\s*;\s*$")

typedef_alias_re = re.compile(r"^\s*typedef\s+(?P<rhs>.+?)\s+(?P<lhs>\w+)\s*;\s*$")

@dataclass
class Field:
    name: str
    type: str
    bits: Optional[int]
    line: int

def parse_types_h(root: Path, types_path: Path) -> Dict:
    text = types_path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()

    structs: Dict[str, Dict] = {}
    enums: Dict[str, Dict] = {}
    typedefs: Dict[str, Dict] = {}

    i = 0
    while i < len(lines):
        line = lines[i]
        m = typedef_struct_start_re.match(line)
        if m:
            tag = m.group("tag")
            start_line = i + 1
            i += 1
            fields: List[Dict] = []
            # consume until end
            while i < len(lines):
                endm = typedef_struct_end_re.match(lines[i])
                if endm:
                    name = endm.group("name")
                    structs[name] = {
                        "kind": "struct",
                        "tag": f"_{tag}",
                        "file": str(types_path.relative_to(root).as_posix()),
                        "line": start_line,
                        "fields": fields,
                    }
                    break
                fm = _field_re.match(lines[i])
                if fm:
                    ftype = one_line(fm.group("type"))
                    fname = fm.group("name")
                    bits = fm.group("bits")
                    fields.append({
                        "name": fname,
                        "type": ftype,
                        "bits": int(bits) if bits else None,
                        "line": i + 1,
                    })
                i += 1
            i += 1
            continue

        m = typedef_enum_start_re.match(line)
        if m:
            tag = m.group("tag")
            start_line = i + 1
            i += 1
            members: List[Dict] = []
            while i < len(lines):
                endm = typedef_enum_end_re.match(lines[i])
                if endm:
                    name = endm.group("name")
                    enums[name] = {
                        "kind": "enum",
                        "tag": f"_{tag}",
                        "file": str(types_path.relative_to(root).as_posix()),
                        "line": start_line,
                        "members": members,
                    }
                    break
                # parse enum member: NAME = value,
                em = re.match(r"^\s*(?P<name>[A-Za-z_]\w*)\s*(=\s*(?P<val>[^,]+))?,?\s*$", lines[i])
                if em and em.group("name") not in {"typedef", "enum", "{", "}"}:
                    members.append({
                        "name": em.group("name"),
                        "value": one_line(em.group("val")) if em.group("val") else None,
                        "line": i + 1,
                    })
                i += 1
            i += 1
            continue

        # typedef alias
        m = typedef_alias_re.match(line)
        if m and "struct" not in line and "enum" not in line:
            lhs = m.group("lhs")
            rhs = one_line(m.group("rhs"))
            typedefs[lhs] = {
                "kind": "typedef",
                "rhs": rhs,
                "file": str(types_path.relative_to(root).as_posix()),
                "line": i + 1,
            }
        i += 1

    return {
        "file": str(types_path.relative_to(root).as_posix()),
        "structs": structs,
        "enums": enums,
        "typedefs": typedefs,
    }

# --- function/global scanning (regex based, best effort) ---

# Rough matcher for C function decl/def.
# Captures: return+qualifiers, name, args, terminator (; or {)
func_re = re.compile(
    r"""(?mx)
    ^(?P<prefix>
        (?:[A-Za-z_]\w*[\w\s\*\(\)]*?)      # return type + qualifiers + pointers
    )
    \b(?P<name>[A-Za-z_]\w*)\s*
    \((?P<args>[^;{}()]*(?:\([^)]*\)[^;{}()]*)*)\)\s*   # args (handles simple nested parens)
    (?P<term>;|\{)\s*$
    """
)

extern_re = re.compile(
    r"""(?mx)
    ^\s*extern\s+(?P<type>[^;]+?)\s+(?P<name>[A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*;\s*$
    """
)

def scan_functions_and_globals(root: Path, files: List[Path]) -> Tuple[Dict[str, List[Dict]], Dict[str, Dict]]:
    functions: Dict[str, List[Dict]] = {}
    globals_: Dict[str, Dict] = {}

    for p in files:
        try:
            raw = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        text = strip_c_comments(raw)
        lines = text.splitlines()

        for idx, line in enumerate(lines, start=1):
            # globals
            gm = extern_re.match(line)
            if gm:
                gname = gm.group("name")
                globals_[gname] = {
                    "type": one_line(gm.group("type")),
                    "file": str(p.relative_to(root).as_posix()),
                    "line": idx,
                }

            # functions
            fm = func_re.match(line)
            if fm:
                name = fm.group("name")
                sig = one_line(fm.group("prefix") + " " + name + "(" + fm.group("args") + ")")
                term = fm.group("term")
                kind = "prototype" if term == ";" else "definition"
                functions.setdefault(name, []).append({
                    "signature": sig,
                    "file": str(p.relative_to(root).as_posix()),
                    "line": idx,
                    "kind": kind,
                })

    return functions, globals_

def file_inventory(root: Path, files: List[Path]) -> List[Dict]:
    out = []
    for p in files:
        rel = p.relative_to(root).as_posix()
        out.append({"file": rel})
    return out

def choose_best_occ(occ_list: List[Dict]) -> Dict:
    def score(o: Dict) -> int:
        s = 0
        if o.get("kind") == "definition":
            s += 100
        elif o.get("kind") == "prototype":
            s += 50
        f = o.get("file", "")
        if f.endswith(".c"):
            s += 10
        elif f.endswith(".h"):
            s += 5
        return s
    return max(occ_list, key=score)

def write_outputs(index: Dict, out_full: Path, out_lite: Optional[Path]) -> None:
    out_full.write_text(json.dumps(index, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    if out_lite:
        lite = {
            "generated_at_utc": index.get("generated_at_utc"),
            "source_zip": index.get("source_zip"),
            "types": index.get("types"),
            "functions": {},
        }
        for name, occs in index["functions"].items():
            best = choose_best_occ(occs)
            lite["functions"][name] = {
                "signature": best.get("signature"),
                "file": best.get("file"),
                "line": best.get("line"),
                "kind": best.get("kind"),
            }
        out_lite.write_text(json.dumps(lite, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".", help="repo root (directory containing CMakeLists.txt)")
    ap.add_argument("--types", default=None, help="path to types.h (default: find in repo)")
    ap.add_argument("--out", default="project_index.json", help="output JSON path")
    ap.add_argument("--out-lite", default="project_index_lite.json", help="output lite JSON path")
    ap.add_argument("--no-lite", action="store_true", help="do not write lite index")
    ap.add_argument("--include-scripts", action="store_true", help="include scripts/ in scan")
    args = ap.parse_args(argv)

    root = find_repo_root(Path(args.root))
    files = iter_source_files(root, include_scripts=args.include_scripts)

    # locate types.h
    if args.types:
        types_path = (root / args.types).resolve()
    else:
        candidates = []
        for cand in [root / "types.h", root / "include" / "types.h", root / "src" / "types.h"]:
            if cand.exists():
                candidates.append(cand)
        if not candidates:
            # fallback: first file named types.h
            for p in files:
                if p.name == "types.h":
                    candidates.append(p)
                    break
        if not candidates:
            raise SystemExit("error: could not find types.h (use --types)")
        types_path = candidates[0]

    types_obj = parse_types_h(root, types_path)
    functions_obj, globals_obj = scan_functions_and_globals(root, files)

    index = {
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_zip": None,
        "types": types_obj,
        "functions": functions_obj,
        "globals": globals_obj,
        "file_inventory": file_inventory(root, files),
    }

    out_full = Path(args.out)
    out_lite = None if args.no_lite else Path(args.out_lite)
    write_outputs(index, out_full, out_lite)
    print(f"Wrote: {out_full}")
    if out_lite:
        print(f"Wrote: {out_lite}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
