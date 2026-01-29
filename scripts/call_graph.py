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
from typing import Optional, Set

SCRIPT_DIR = Path(__file__).parent
CALL_GRAPH_PATH = SCRIPT_DIR / "call_graph.json"
IMPL_STATUS_PATH = SCRIPT_DIR / "implementation_status.json"

# ANSI colors
RESET = "\033[0m"
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


def status_tag(status: str) -> str:
    if status == STATUS_IMPLEMENTED:
        return "OK"
    if status == STATUS_STUB:
        return "STUB"
    return "MISSING"


def color_for_status(status: str) -> str:
    if status == STATUS_IMPLEMENTED:
        return BRIGHT_GREEN
    if status == STATUS_STUB:
        return BRIGHT_YELLOW
    return BRIGHT_RED


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
    st = get_func_status(impl_status, func_name)
    c = color_for_status(st)
    return f"{c}{func_name}{RESET}"


def format_status(impl_status: dict, func_name: str) -> str:
    st = get_func_status(impl_status, func_name)
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
        print(f"{format_name(impl_status, func_name)}{star} {format_status(impl_status, func_name)}")
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
) -> None:
    """Print only implementation frontiers: implemented paths that hit first unimplemented.

    - STUB nodes are frontiers (printed), and not expanded (except the root).
    - MISSING nodes are skipped by default (treated as external).
    """
    visited: Set[str] = set()

    def dfs(fn: str, indent: str, *, is_root: bool = False) -> None:
        if fn in visited:
            return
        visited.add(fn)

        st = get_func_status(impl_status, fn)
        print(f"{indent}{format_name(impl_status, fn)} {format_status(impl_status, fn)}")

        # If the root is stub/missing, still traverse to children.
        if st != STATUS_IMPLEMENTED and not is_root:
            return

        for callee in sorted(functions.get(fn, {}).get("calls", [])):
            if is_hidden_symbol(
                callee,
                impl_status,
                include_externals=include_externals,
                include_missing=include_missing,
            ):
                continue

            cst = get_func_status(impl_status, callee)
            if cst == STATUS_IMPLEMENTED:
                dfs(callee, indent + "  ")
            elif cst == STATUS_STUB:
                print(f"{indent}  └─→ {format_name(impl_status, callee)} {format_status(impl_status, callee)}")
            else:
                # missing: only reachable if include_missing=True
                print(f"{indent}  └─→ {format_name(impl_status, callee)} {format_status(impl_status, callee)}")

    dfs(root, "", is_root=True)


def cmd_unimplemented(args) -> None:
    data = load_call_graph()
    functions = data.get("functions", {})
    impl_status = load_implementation_status()

    func_name = args.function
    if func_name not in functions:
        print(f"Error: Function '{func_name}' not found in call graph.", file=sys.stderr)
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
        print(f"Error: Function '{func_name}' not found in call graph.", file=sys.stderr)
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
        print(f"Error: Function '{func_name}' not found in call graph.", file=sys.stderr)
        sys.exit(1)

    todo_frontiers(
        functions,
        func_name,
        impl_status,
        include_externals=args.include_externals,
        include_missing=args.include_missing,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Call graph analysis tool for Stars! decompilation project.")
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
    tree_parser.add_argument("--function", "-f", required=True, help="Name of the function to analyze")
    add_common_flags(tree_parser)
    tree_parser.set_defaults(func=cmd_function_tree)

    unimpl_parser = subparsers.add_parser(
        "unimplemented",
        help="List all unimplemented functions in a function's call tree",
    )
    unimpl_parser.add_argument("--function", "-f", required=True, help="Name of the function to analyze")
    add_common_flags(unimpl_parser)
    unimpl_parser.set_defaults(func=cmd_unimplemented)

    todo_parser = subparsers.add_parser(
        "todo",
        help="Show implementation frontiers (implemented -> first unimplemented)",
    )
    todo_parser.add_argument("--function", "-f", required=True, help="Name of the function to analyze")
    add_common_flags(todo_parser)
    todo_parser.set_defaults(func=cmd_todo)

    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
