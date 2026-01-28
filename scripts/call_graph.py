#!/usr/bin/env python3
"""
Call graph analysis tool for Stars! decompilation project.

Provides various analysis actions on the call graph data.
"""

import argparse
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
CALL_GRAPH_PATH = SCRIPT_DIR / "call_graph.json"
IMPL_STATUS_PATH = SCRIPT_DIR / "implementation_status.json"


def load_call_graph():
    """Load the call graph JSON data."""
    with open(CALL_GRAPH_PATH, "r") as f:
        return json.load(f)


def load_implementation_status():
    """Load the implementation status JSON data."""
    with open(IMPL_STATUS_PATH, "r") as f:
        return json.load(f)


def get_status_indicator(impl_status: dict, func_name: str) -> str:
    """Get a status indicator for a function."""
    if impl_status is None:
        return ""

    functions = impl_status.get("functions", {})
    if func_name not in functions:
        return ""

    status = functions[func_name].get("status", "")
    if status == "implemented":
        return " [OK]"
    elif status == "stub":
        return " [STUB]"
    elif status == "missing":
        return " [MISSING]"
    return ""


def print_function_tree(functions: dict, func_name: str, prefix: str = "", is_last: bool = True, visited: set = None, is_root: bool = True, impl_status: dict = None):
    """Recursively print a tree of function calls."""
    if visited is None:
        visited = set()

    # Determine the connector characters
    connector = "\u2514\u2500\u2500 " if is_last else "\u251c\u2500\u2500 "

    # Skip external functions (not in call graph)
    if func_name not in functions:
        return

    func_data = functions[func_name]
    calls = func_data.get("calls", [])
    status_ind = get_status_indicator(impl_status, func_name)

    # Mark if we've already visited this function (cycle detection)
    if func_name in visited:
        print(f"{prefix}{connector}{func_name}{status_ind} (recursive)")
        return

    # Print this function
    if is_root:
        # Root node
        print(f"{func_name}{status_ind}")
    else:
        call_count = len(calls)
        suffix = f" [{call_count} calls]" if call_count > 0 else " (leaf)"
        print(f"{prefix}{connector}{func_name}{status_ind}{suffix}")

    # Add to visited set
    visited = visited | {func_name}

    # Calculate new prefix for children
    if is_root:
        new_prefix = ""
    else:
        new_prefix = prefix + ("    " if is_last else "\u2502   ")

    # Print children
    for i, callee in enumerate(sorted(calls)):
        is_last_child = (i == len(calls) - 1)
        print_function_tree(functions, callee, new_prefix, is_last_child, visited, is_root=False, impl_status=impl_status)


def collect_unimplemented(functions: dict, func_name: str, impl_status: dict, visited: set = None, result: set = None):
    """Recursively collect all unimplemented functions in the call tree."""
    if visited is None:
        visited = set()
    if result is None:
        result = set()

    # Skip external functions
    if func_name not in functions:
        return result

    # Skip if already visited
    if func_name in visited:
        return result

    visited.add(func_name)

    # Check if this function is unimplemented
    impl_functions = impl_status.get("functions", {})
    if func_name in impl_functions:
        status = impl_functions[func_name].get("status", "")
        if status in ("stub", "missing"):
            result.add(func_name)

    # Recurse into called functions
    func_data = functions[func_name]
    for callee in func_data.get("calls", []):
        collect_unimplemented(functions, callee, impl_status, visited, result)

    return result


def cmd_unimplemented(args):
    """Handle the unimplemented command."""
    data = load_call_graph()
    functions = data.get("functions", {})
    impl_status = load_implementation_status()

    func_name = args.function

    if func_name not in functions:
        print(f"Error: Function '{func_name}' not found in call graph.", file=sys.stderr)
        sys.exit(1)

    unimplemented = collect_unimplemented(functions, func_name, impl_status)

    for name in sorted(unimplemented):
        print(name)

    print(f"\nTotal: {len(unimplemented)} unimplemented functions", file=sys.stderr)


def cmd_function_tree(args):
    """Handle the function-tree command."""
    data = load_call_graph()
    functions = data.get("functions", {})
    impl_status = load_implementation_status()

    func_name = args.function

    if func_name not in functions:
        print(f"Error: Function '{func_name}' not found in call graph.", file=sys.stderr)
        sys.exit(1)

    print_function_tree(functions, func_name, impl_status=impl_status)


def main():
    parser = argparse.ArgumentParser(
        description="Call graph analysis tool for Stars! decompilation project."
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # function-tree command
    tree_parser = subparsers.add_parser(
        "function-tree",
        help="Display a tree of functions called by a given function"
    )
    tree_parser.add_argument(
        "--function", "-f",
        required=True,
        help="Name of the function to analyze"
    )
    tree_parser.set_defaults(func=cmd_function_tree)

    # unimplemented command
    unimpl_parser = subparsers.add_parser(
        "unimplemented",
        help="List all unimplemented functions in a function's call tree"
    )
    unimpl_parser.add_argument(
        "--function", "-f",
        required=True,
        help="Name of the function to analyze"
    )
    unimpl_parser.set_defaults(func=cmd_unimplemented)

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
