#!/usr/bin/env python3
"""
Call graph analysis tool for Stars! decompilation project.

Commands:
- function-tree : show a (collapsed) call tree
- unimplemented : list all unimplemented (stub) functions reachable from a root
- todo          : show implementation frontiers (implemented -> first unimplemented)

Implementation status is read from implementation_status.json:
  functions[<name>].status in {implemented, stub, missing}

Defaults:
- "External-looking" symbols (leading underscore, e.g. __aFulmul/__ftol) are hidden.
  Use --include-externals to show them.
- "missing" is treated as external in this project (you said they’re all external),
  so missing symbols are skipped by default.
  Use --include-missing if you ever want to see them.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Set, List

SCRIPT_DIR = Path(__file__).parent
CALL_GRAPH_PATH = SCRIPT_DIR / "call_graph.json"
IMPL_STATUS_PATH = SCRIPT_DIR / "implementation_status.json"

# ANSI colors
RESET = "\033[0m"
BRIGHT_CYAN = "\033[96m"
BRIGHT_GREEN = "\033[92m"
BRIGHT_YELLOW = "\033[93m"
BRIGHT_RED = "\033[91m"
DIM = "\033[2m"

STATUS_IMPLEMENTED = "implemented"
STATUS_STUB = "stub"
STATUS_MISSING = "missing"


def load_call_graph() -> dict:
    with open(CALL_GRAPH_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def load_implementation_status() -> dict:
    with open(IMPL_STATUS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def is_external(name: str, *, include_externals: bool) -> bool:
    """Return True if a callee should be hidden as an external symbol.

    Default: hide anything with a leading underscore, which covers CRT/libc-ish
    names (_sqrt/_abs) and compiler helper thunks (__aFulmul/__ftol/etc).
    """
    if include_externals:
        return False
    return name.startswith("_")


def get_func_status(impl_status: dict, func_name: str) -> str:
    funcs = impl_status.get("functions", {})
    info = funcs.get(func_name)
    if not info:
        return STATUS_MISSING
    return info.get("status", STATUS_MISSING)


def get_decompiled_line_count(impl_status: dict, func_name: str) -> Optional[int]:
    """Return decompiled line count for a function if available."""
    funcs = impl_status.get("functions", {})
    info = funcs.get(func_name)
    if not info:
        return None
    return info.get("decompiled_line_count")


def is_win32_function(impl_status: dict, func_name: str) -> bool:
    """Return True if function is classified as win32 in implementation_status.json."""
    funcs = impl_status.get("functions", {})
    info = funcs.get(func_name)
    if not info:
        return False
    return bool(info.get("win32", False))


def get_func_file(impl_status: dict, func_name: str) -> Optional[str]:
    """Return the source file name for a function (e.g., 'aiutil.c') if known."""
    funcs = impl_status.get("functions", {})
    info = funcs.get(func_name)
    if not info:
        return None
    f = info.get("file")
    return str(f) if f else None


def is_ai_source_file(file_name: Optional[str]) -> bool:
    """Return True if the file is in the ai*.c family (ai.c, ai2.c, aiutil.c, ...)."""
    if not file_name:
        return False
    base = Path(file_name).name.lower()
    return base.startswith("ai") and base.endswith(".c")


def _ansi_256_color(n: int) -> str:
    return f"\033[38;5;{n}m"


def _stub_color_for_loc(loc: Optional[int]) -> str:
    """Color stub functions by decompiled LOC using simple thresholds.

    Green  : < 50 LOC
    Yellow : 51–200 LOC
    Red    : > 200 LOC

    If LOC is missing, fall back to BRIGHT_YELLOW.
    """
    if loc is None:
        return BRIGHT_YELLOW

    loc = int(loc)

    if loc < 50:
        return BRIGHT_GREEN
    elif loc <= 200:
        return BRIGHT_YELLOW
    else:
        return BRIGHT_RED


def parse_csv_set(s: Optional[str]) -> Set[str]:
    """Parse a comma-separated list into a set of non-empty strings."""
    if not s:
        return set()
    return {item.strip() for item in s.split(",") if item.strip()}


def status_tag(status: str) -> str:
    if status == STATUS_IMPLEMENTED:
        return "OK"
    if status == STATUS_STUB:
        return "STUB"
    return "MISSING"


def color_for_status(status: str) -> str:
    if status == STATUS_IMPLEMENTED:
        return BRIGHT_CYAN
    if status == STATUS_STUB:
        return BRIGHT_YELLOW
    return BRIGHT_RED


def color_for_func(impl_status: dict, func_name: str) -> str:
    st = get_func_status(impl_status, func_name)
    if st == STATUS_IMPLEMENTED:
        return BRIGHT_CYAN
    if st == STATUS_MISSING:
        return BRIGHT_RED
    # STUB: color-scale by LOC if available
    return _stub_color_for_loc(get_decompiled_line_count(impl_status, func_name))


def is_hidden_symbol(
    sym: str,
    impl_status: dict,
    *,
    include_externals: bool,
    include_missing: bool,
) -> bool:
    """Decide whether to hide a symbol from output/traversal."""
    if is_external(sym, include_externals=include_externals):
        return True
    st = get_func_status(impl_status, sym)
    if st == STATUS_MISSING and not include_missing:
        return True
    return False


def is_implemented(impl_status: dict, func_name: str) -> bool:
    return get_func_status(impl_status, func_name) == STATUS_IMPLEMENTED


def format_name(impl_status: dict, func_name: str) -> str:
    c = color_for_func(impl_status, func_name)
    return f"{c}{func_name}{RESET}"


def format_status(impl_status: dict, func_name: str) -> str:
    st = get_func_status(impl_status, func_name)
    if st == STATUS_STUB:
        loc = get_decompiled_line_count(impl_status, func_name)
        if loc is not None:
            return f"[{status_tag(st)}, {loc} loc]"
    return f"[{status_tag(st)}]"


def worst_descendant_status(
    functions: dict,
    impl_status: dict,
    func_name: str,
    *,
    include_externals: bool,
    include_missing: bool,
) -> Optional[str]:
    """Return worst (most unimplemented) descendant status: missing beats stub.

    Returns None if no unimplemented descendants exist (after filtering).
    """
    visited: Set[str] = set()

    def dfs(fn: str) -> Optional[str]:
        if fn in visited:
            return None
        visited.add(fn)

        node = functions.get(fn)
        if not node:
            return None

        worst: Optional[str] = None
        for callee in node.get("calls", []):
            if is_hidden_symbol(
                callee,
                impl_status,
                include_externals=include_externals,
                include_missing=include_missing,
            ):
                continue

            st = get_func_status(impl_status, callee)
            if st != STATUS_IMPLEMENTED:
                if st == STATUS_MISSING:
                    return STATUS_MISSING
                worst = STATUS_STUB

            sub = dfs(callee)
            if sub == STATUS_MISSING:
                return STATUS_MISSING
            if sub == STATUS_STUB:
                worst = STATUS_STUB

        return worst

    return dfs(func_name)


def format_asterisk(worst_unimpl: Optional[str]) -> str:
    if worst_unimpl is None:
        return ""
    if worst_unimpl == STATUS_MISSING:
        return f" {BRIGHT_RED}*{RESET}"
    return f" {BRIGHT_YELLOW}*{RESET}"


def print_function_tree(
    functions: dict,
    func_name: str,
    impl_status: dict,
    prefix: str = "",
    is_last: bool = True,
    visited: Optional[Set[str]] = None,
    is_root: bool = True,
    *,
    include_externals: bool = False,
    include_missing: bool = False,
) -> None:
    """Recursively print a tree of function calls, but:
    - Implemented nodes are bright green
    - Implemented nodes do NOT expand their subtree
    - Implemented nodes with any unimplemented descendant get a colored '*'
    - External/CRT symbols are hidden (unless --include-externals)
    - Missing are hidden by default (unless --include-missing)
    """
    if visited is None:
        visited = set()

    if func_name not in functions:
        return

    connector = "└── " if is_last else "├── "

    if func_name in visited:
        if is_root:
            print(
                f"{format_name(impl_status, func_name)} {format_status(impl_status, func_name)} {DIM}(recursive){RESET}"
            )
        else:
            print(
                f"{prefix}{connector}{format_name(impl_status, func_name)} {format_status(impl_status, func_name)} {DIM}(recursive){RESET}"
            )
        return

    visited = visited | {func_name}

    worst = worst_descendant_status(
        functions,
        impl_status,
        func_name,
        include_externals=include_externals,
        include_missing=include_missing,
    )
    star = format_asterisk(worst)

    if is_root:
        print(
            f"{format_name(impl_status, func_name)}{star} {format_status(impl_status, func_name)}"
        )
    else:
        calls = [
            c
            for c in functions[func_name].get("calls", [])
            if not is_hidden_symbol(
                c,
                impl_status,
                include_externals=include_externals,
                include_missing=include_missing,
            )
        ]
        suffix = f"{DIM}[{len(calls)} calls]{RESET}" if calls else f"{DIM}(leaf){RESET}"
        print(
            f"{prefix}{connector}{format_name(impl_status, func_name)}{star} {format_status(impl_status, func_name)} {suffix}"
        )

    # Collapse: do not expand implemented functions (including root)
    if is_implemented(impl_status, func_name):
        return

    calls = sorted(
        [
            c
            for c in functions[func_name].get("calls", [])
            if not is_hidden_symbol(
                c,
                impl_status,
                include_externals=include_externals,
                include_missing=include_missing,
            )
        ]
    )
    new_prefix = prefix + ("    " if is_last else "│   ")

    for i, callee in enumerate(calls):
        last_child = i == len(calls) - 1
        print_function_tree(
            functions,
            callee,
            impl_status,
            new_prefix,
            last_child,
            visited,
            is_root=False,
            include_externals=include_externals,
            include_missing=include_missing,
        )


def collect_unimplemented(
    functions: dict,
    func_name: str,
    impl_status: dict,
    visited: Optional[Set[str]] = None,
    result: Optional[Set[str]] = None,
    *,
    include_externals: bool = False,
    include_missing: bool = False,
) -> Set[str]:
    """Collect unimplemented functions reachable from func_name.

    By default, this collects only STUB (because MISSING is treated as external
    and skipped). Use --include-missing if you want missing listed too.
    """
    if visited is None:
        visited = set()
    if result is None:
        result = set()

    if func_name not in functions:
        return result
    if func_name in visited:
        return result

    visited.add(func_name)

    st = get_func_status(impl_status, func_name)
    if st == STATUS_STUB or (st == STATUS_MISSING and include_missing):
        result.add(func_name)

    for callee in functions[func_name].get("calls", []):
        if is_hidden_symbol(
            callee,
            impl_status,
            include_externals=include_externals,
            include_missing=include_missing,
        ):
            continue
        collect_unimplemented(
            functions,
            callee,
            impl_status,
            visited,
            result,
            include_externals=include_externals,
            include_missing=include_missing,
        )

    return result


def todo_frontiers(
    functions: dict,
    root: str,
    impl_status: dict,
    *,
    include_externals: bool = False,
    include_missing: bool = False,
    max_depth: Optional[int] = None,
    exclude_branches: Optional[Set[str]] = None,
    sort_stubs_by_loc: bool = False,
) -> None:
    """Show the next implementation work under a root.

    Behavior:
    - From implemented code, we show the *first* unimplemented function(s) reached.
    - When we hit an unimplemented function (STUB/MISSING), we also recurse into it
      to show additional unimplemented work underneath it (walking through any
      implemented helpers as needed).
    - To avoid noisy repetition, each unimplemented function subtree is expanded
      at most once, even if multiple paths reach it.
    """

    visited: Set[str] = set()
    expanded_unimpl: Set[str] = set()

    exclude_branches = exclude_branches or set()

    def print_node(prefix: str, fn: str, *, is_root: bool, is_last: bool) -> None:
        """Print a node in the todo tree.

        Unlike the old formatting (which only showed arrows for stub/missing), we
        always render an explicit parent→child connector so the structure is
        unambiguous.
        """
        if is_root:
            print(f"{format_name(impl_status, fn)} {format_status(impl_status, fn)}")
            return

        connector = "└─→ " if is_last else "├─→ "
        print(
            f"{prefix}{connector}{format_name(impl_status, fn)} {format_status(impl_status, fn)}"
        )

    def dfs_node(
        fn: str,
        prefix: str,
        *,
        printed: bool,
        in_unimpl_expand: bool,
        is_root: bool,
        depth: int,
        is_last: bool,
    ) -> None:
        if fn in visited:
            return
        visited.add(fn)

        st = get_func_status(impl_status, fn)
        if not printed:
            print_node(prefix, fn, is_root=is_root, is_last=is_last)

        # Branch pruning: if this node is explicitly excluded, stop here.
        # (We still print the node itself, but we do not traverse its callees.)
        if (not is_root) and (fn in exclude_branches):
            return

        # If we encounter an unimplemented function, decide whether to expand it.
        if st != STATUS_IMPLEMENTED:
            # Always expand the root (when user runs todo -f <stub>).
            if is_root:
                in_unimpl_expand = True
            else:
                # Expand each unimplemented subtree at most once.
                if fn in expanded_unimpl:
                    return
                expanded_unimpl.add(fn)
                in_unimpl_expand = True

        if max_depth is not None and depth >= max_depth:
            return

        callees_raw: List[str] = functions.get(fn, {}).get("calls", [])
        callees: List[str] = [
            c
            for c in callees_raw
            if not is_hidden_symbol(
                c,
                impl_status,
                include_externals=include_externals,
                include_missing=include_missing,
            )
        ]

        if sort_stubs_by_loc and callees:
            stubs: List[str] = []
            others: List[str] = []
            for c in callees:
                if get_func_status(impl_status, c) == STATUS_STUB:
                    stubs.append(c)
                else:
                    others.append(c)

            stubs.sort(
                key=lambda name: (
                    (
                        get_decompiled_line_count(impl_status, name)
                        if get_decompiled_line_count(impl_status, name) is not None
                        else 10**9
                    ),
                    name,
                )
            )

            # Put stubs first (sorted by LOC), followed by remaining callees in their natural order.
            callees = stubs + others
        for i, callee in enumerate(callees):
            last_child = i == (len(callees) - 1)
            child_prefix = prefix + ("    " if is_last else "│   ")

            # Always print the child with an explicit connector.
            # Then decide whether/how to expand.
            cst = get_func_status(impl_status, callee)
            if cst == STATUS_IMPLEMENTED:
                dfs_node(
                    callee,
                    child_prefix,
                    printed=False,
                    in_unimpl_expand=in_unimpl_expand,
                    is_root=False,
                    depth=depth + 1,
                    is_last=last_child,
                )
            else:
                dfs_node(
                    callee,
                    child_prefix,
                    printed=False,
                    in_unimpl_expand=True,
                    is_root=False,
                    depth=depth + 1,
                    is_last=last_child,
                )

    dfs_node(
        root,
        "",
        printed=False,
        in_unimpl_expand=False,
        is_root=True,
        depth=0,
        is_last=True,
    )


def cmd_unimplemented(args) -> None:
    data = load_call_graph()
    functions = data.get("functions", {})
    impl_status = load_implementation_status()

    func_name = args.function
    if func_name not in functions:
        print(
            f"Error: Function '{func_name}' not found in call graph.", file=sys.stderr
        )
        sys.exit(1)

    unimplemented = collect_unimplemented(
        functions,
        func_name,
        impl_status,
        include_externals=args.include_externals,
        include_missing=args.include_missing,
    )
    for name in sorted(unimplemented):
        # collect_unimplemented already respects filters; no extra skip needed
        print(name)


def cmd_function_tree(args) -> None:
    data = load_call_graph()
    functions = data.get("functions", {})
    impl_status = load_implementation_status()

    func_name = args.function
    if func_name not in functions:
        print(
            f"Error: Function '{func_name}' not found in call graph.", file=sys.stderr
        )
        sys.exit(1)

    print_function_tree(
        functions,
        func_name,
        impl_status=impl_status,
        include_externals=args.include_externals,
        include_missing=args.include_missing,
    )


def cmd_todo(args) -> None:
    data = load_call_graph()
    functions = data.get("functions", {})
    impl_status = load_implementation_status()

    func_name = args.function
    if func_name not in functions:
        print(
            f"Error: Function '{func_name}' not found in call graph.", file=sys.stderr
        )
        sys.exit(1)

    todo_frontiers(
        functions,
        func_name,
        impl_status,
        include_externals=args.include_externals,
        include_missing=args.include_missing,
        max_depth=args.max_depth,
        exclude_branches=parse_csv_set(args.exclude_branches),
        sort_stubs_by_loc=args.sort_stubs_by_loc,
    )


def cmd_unimplemented_all(args) -> None:
    """List all unimplemented functions, grouped by non-win32/win32.

    Sorting: decompiled LOC descending (missing/unknown LOC sorted last).

    Flags:
      --exclude-ai    : skip any functions whose source file matches ai*.c
      --exclude-win32 : skip functions classified as win32
    """
    impl_status = load_implementation_status()

    funcs = impl_status.get("functions", {})
    rows = []
    for name, info in funcs.items():
        st = info.get("status", STATUS_MISSING)
        if st not in (STATUS_STUB, STATUS_MISSING):
            continue

        file_name = info.get("file")
        if getattr(args, "exclude_ai", False) and is_ai_source_file(file_name):
            continue

        win32 = bool(info.get("win32", False))
        if getattr(args, "exclude_win32", False) and win32:
            continue

        loc = info.get("decompiled_line_count")
        loc_i = int(loc) if isinstance(loc, int) else (int(loc) if loc is not None else None)

        rows.append(
            {
                "name": name,
                "status": st,
                "win32": win32,
                "file": str(file_name) if file_name else "?",
                "loc": loc_i,
            }
        )

    def sort_key(r: dict) -> tuple:
        # LOC descending; unknown LOC sorted last.
        loc = r["loc"]
        loc_sort = -loc if loc is not None else 10**12
        return (loc_sort, r["status"], r["name"])

    rows.sort(key=sort_key)

    def emit_group(title: str, want_win32: bool) -> None:
        group = [r for r in rows if r["win32"] == want_win32]
        if not group:
            return
        print(f"{title}:")
        for r in group:
            loc_s = str(r["loc"]) if r["loc"] is not None else "?"
            print(f"  {loc_s:>5}  {status_tag(r['status']):<7}  {r['file']:<12}  {r['name']}")
        print()

    if not getattr(args, "exclude_win32", False):
        emit_group("non-win32", False)
        emit_group("win32", True)
    else:
        emit_group("non-win32", False)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Call graph analysis tool for Stars! decompilation project."
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    def add_common_flags(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--include-externals",
            action="store_true",
            help="Include external-looking symbols (leading underscore, incl. compiler helpers)",
        )
        p.add_argument(
            "--include-missing",
            action="store_true",
            help="Include missing symbols (default: hidden/treated as external)",
        )

    tree_parser = subparsers.add_parser(
        "function-tree",
        help="Display a (collapsed) tree of functions called by a given function",
    )
    tree_parser.add_argument(
        "--function", "-f", required=True, help="Name of the function to analyze"
    )
    add_common_flags(tree_parser)
    tree_parser.set_defaults(func=cmd_function_tree)

    unimpl_parser = subparsers.add_parser(
        "unimplemented",
        help="List all unimplemented functions in a function's call tree",
    )
    unimpl_parser.add_argument(
        "--function", "-f", required=True, help="Name of the function to analyze"
    )
    add_common_flags(unimpl_parser)
    unimpl_parser.set_defaults(func=cmd_unimplemented)

    todo_parser = subparsers.add_parser(
        "todo",
        help="Show implementation frontiers (implemented -> first unimplemented)",
    )
    todo_parser.add_argument(
        "--function", "-f", required=True, help="Name of the function to analyze"
    )
    todo_parser.add_argument(
        "--max-depth",
        type=int,
        default=None,
        help="Stop expanding the todo graph past this call depth from the root (root=0).",
    )
    todo_parser.add_argument(
        "--sort-stubs-by-loc",
        action="store_true",
        help="Within each node, list STUB callees first, ordered by decompiled LOC (ascending).",
    )
    todo_parser.add_argument(
        "--exclude-branches",
        "-x",
        default=None,
        help="Comma-separated list of function names whose call subtrees should be pruned (excluded) during traversal.",
    )
    add_common_flags(todo_parser)
    todo_parser.set_defaults(func=cmd_todo)

    unimpl_all_parser = subparsers.add_parser(
        "unimplemented-all",
        help=(
            "List all unimplemented functions (STUB+MISSING), grouped by win32/non-win32 "
            "and sorted by decompiled LOC (desc)."
        ),
    )
    unimpl_all_parser.add_argument(
        "--exclude-ai",
        action="store_true",
        help="Exclude any functions defined in ai*.c (ai.c, ai2.c, aiutil.c, ...).",
    )
    unimpl_all_parser.add_argument(
        "--exclude-win32",
        action="store_true",
        help="Exclude functions classified as win32.",
    )
    unimpl_all_parser.set_defaults(func=cmd_unimplemented_all)

    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        sys.exit(1)

    try:
        args.func(args)
    except BrokenPipeError:
        # Common when piping to tools like `head`. Exit cleanly.
        try:
            sys.stdout.close()
        finally:
            sys.exit(0)


if __name__ == "__main__":
    main()
