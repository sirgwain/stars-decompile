# -*- coding: utf-8 -*-
# BuildCallGraph.py
# @category Stars
# @description Build a call graph of all non-PUBLIC, non-1118 functions and output as JSON.
#
# Usage (headless): -postScript BuildCallGraph.py <output_json> <globals_json>
#
# Output JSON structure:
# {
#   "functions": {
#     "FuncName": {
#       "addr": "1038:1234",
#       "calls": ["OtherFunc", ...],
#       "called_by": ["Caller", ...],
#       "is_leaf": true/false,
#       "depth": 0  // 0 = leaf, 1 = calls only leaves, etc.
#     }
#   },
#   "by_depth": {
#     "0": ["LeafFunc1", ...],
#     "1": ["CallsLeaves1", ...],
#     ...
#   }
# }

import json
from collections import defaultdict

# make IDE register built ins
try:
    from ghidra.ghidra_builtins import *
    from ghidra.program.model.listing import *

    currentProgram = currentProgram  # type: Program
except:
    pass


def get_called_function_names(func, fm):
    """Get names of all functions called by func."""
    called = set()
    if func is None:
        return called

    body = func.getBody()
    ref_mgr = currentProgram.getReferenceManager()
    addr_iter = body.getAddresses(True)

    while addr_iter.hasNext():
        addr = addr_iter.next()
        for ref in ref_mgr.getReferencesFrom(addr):
            if ref.getReferenceType().isCall():
                target_func = fm.getFunctionAt(ref.getToAddress())
                if target_func is not None:
                    called.add(target_func.getName())
    return called


def compute_depths(functions, calls_map):
    """Compute depth for each function. 0 = leaf, 1 = calls only leaves, etc.
    Functions in cycles get depth -1."""
    depths = {}

    def _depth(name, visiting):
        if name in depths:
            return depths[name]
        if name in visiting:
            return -1  # cycle
        visiting.add(name)

        callees = calls_map.get(name, set())
        # Only consider callees that are in our tracked set
        tracked_callees = callees & set(functions)
        if not tracked_callees:
            depths[name] = 0
            return 0

        max_d = 0
        for c in tracked_callees:
            d = _depth(c, visiting)
            if d == -1:
                depths[name] = -1
                return -1
            max_d = max(max_d, d)

        depths[name] = max_d + 1
        return max_d + 1

    for name in functions:
        if name not in depths:
            _depth(name, set())

    return depths


def main():
    args = getScriptArgs()
    if len(args) < 2:
        print("Usage: BuildCallGraph.py <output_json> <globals_json>")
        return

    output_path = args[0]
    globals_path = args[1]

    # Load the proc list from JSON to know which functions to include
    with open(globals_path, "r") as f:
        root = json.load(f)

    # Build set of included function names and their addresses
    included = {}  # name -> addr
    for proc in root.get("procs", []):
        if proc["cv"]["from"] == "PUBLIC":
            continue
        addr = proc["ghidra"]["addr"]
        if addr.startswith("1118:"):
            continue
        included[proc["name"]] = addr

    print("Included functions: %d" % len(included))

    fm = currentProgram.getFunctionManager()

    # Build call graph
    calls_map = {}  # name -> set of callee names
    called_by = defaultdict(set)

    for name, addr_str in included.items():
        func = fm.getFunctionAt(toAddr(addr_str))
        if func is None:
            print("[WARN] no func at %s for %s" % (addr_str, name))
            calls_map[name] = set()
            continue

        callees = get_called_function_names(func, fm)
        calls_map[name] = callees
        for callee in callees:
            called_by[callee].add(name)

    # Compute depths
    depths = compute_depths(set(included.keys()), calls_map)

    # Build output
    functions_out = {}
    for name in sorted(included.keys()):
        d = depths.get(name, -1)
        callees = calls_map.get(name, set())
        functions_out[name] = {
            "addr": included[name],
            "calls": sorted(callees),
            "called_by": sorted(called_by.get(name, set())),
            "is_leaf": d == 0,
            "depth": d,
        }

    by_depth = defaultdict(list)
    for name, info in functions_out.items():
        by_depth[str(info["depth"])].append(name)
    for k in by_depth:
        by_depth[k].sort()

    result = {
        "functions": functions_out,
        "by_depth": dict(sorted(by_depth.items(), key=lambda x: int(x[0]))),
    }

    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)

    # Summary
    print("Output written to: %s" % output_path)
    print("Total functions: %d" % len(functions_out))
    for d in sorted(by_depth.keys(), key=lambda x: int(x)):
        print("  depth %s: %d functions" % (d, len(by_depth[d])))

    # Validation
    if "LDistance2" in functions_out:
        info = functions_out["LDistance2"]
        status = "PASS" if info["is_leaf"] else "FAIL"
        print("[%s] LDistance2 is_leaf=%s (expected True)" % (status, info["is_leaf"]))

    if "WinMain" in functions_out:
        info = functions_out["WinMain"]
        status = "PASS" if not info["is_leaf"] else "FAIL"
        print("[%s] WinMain is_leaf=%s (expected False)" % (status, info["is_leaf"]))


if __name__ == "__main__":
    main()
