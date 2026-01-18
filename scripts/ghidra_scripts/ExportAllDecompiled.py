# ExportAllDecompiled.py
# @category Stars
# @description Export decompiled code for ALL functions.
#
# This project often wants per-module exports (MSG, PLANET, etc.) based on the
# CodeView segment classification contained in nb09_ghidra_globals.json.
#
# Output modes:
#   1) Single-file (legacy):
#        -postScript ExportAllDecompiled.py <out_file.c>
#
#   2) Per-module, flat output directory:
#        -postScript ExportAllDecompiled.py <out_dir> <nb09_ghidra_globals.json> [options]
#      Writes one file per module directly under <out_dir>:
#        <out_dir>/msg.c, <out_dir>/planet.c, ...
#      Module is derived from segmap.segname (e.g. MEMORY_MSG -> msg).
#      Unknown/unmapped functions go to <out_dir>/unknown.c.
#
# Options (headless or GUI):
#   --exclude <name1,name2,...>       Exact, case-sensitive function names to skip
#   --exclude-file <path>            File of function names to skip (one per line, # comments allowed)
#   --segment-filter <prefix>        Optional address string prefix filter (e.g. "1030" matches "1030:xxxx")
#   --strip-namespaces               Remove simple C++ scope qualifiers like MSG:: and _DATA::
#   --strip-cconv                    Remove Win16 calling convention markers like __cdecl16far
#
# Examples:
#   ExportAllDecompiled.py all_funcs.c
#   ExportAllDecompiled.py out_decomp /path/to/nb09_ghidra_globals.json
#   ExportAllDecompiled.py out_decomp /path/to/nb09_ghidra_globals.json --exclude-file excludes.txt
#   ExportAllDecompiled.py out_decomp /path/to/nb09_ghidra_globals.json --exclude MSG::ReadPlayerMessages
#   ExportAllDecompiled.py out_decomp /path/to/nb09_ghidra_globals.json --strip-namespaces
#   ExportAllDecompiled.py out_decomp /path/to/nb09_ghidra_globals.json --strip-cconv

import json
import os
import re

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


def decompile_function(func, decomp):
    """Decompile a function and return the C code string."""
    try:
        monitor = ConsoleTaskMonitor()
        res = decomp.decompileFunction(func, 60, monitor)
        if res.decompileCompleted():
            return res.getDecompiledFunction().getC()
        return "// Decompilation failed: %s" % res.getErrorMessage()
    except Exception as e:
        return "// Decompilation error: %s" % str(e)


_SCOPE_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*::")

# Win16 decompiler calling convention markers that we want to strip in the modern C port.
_CCONV_RE = re.compile(r"\b__(?:cdecl16far|pascal16far|stdcall16far)\b\s*")


def strip_cpp_scopes(code):
    """Remove simple C++ scope qualifiers like FOO:: from decompiler output.

    Stars! Win16 decompilation tends to emit namespaces like PLANET::, MSG::,
    _DATA::, c_common::, etc. In the modern C port, globals/functions are flat.

    NOTE: This is a deliberately simple text transform applied to the exported
    decompiler C, not a C++ parser. It is intended for this codebase's output.
    """
    if not code:
        return code
    return _SCOPE_RE.sub("", code)


def strip_calling_conventions(code):
    """Remove Win16 calling convention markers like __cdecl16far from decompiler output.

    This is a text transform applied at export time. We only strip the known
    Stars!/Ghidra Win16 convention tokens to avoid accidental rewriting.
    """
    if not code:
        return code
    return _CCONV_RE.sub("", code)


def _slugify_module(segname):
    """Convert segmap.segname (e.g., MEMORY_MSG) into a stable filename stem (e.g., msg)."""
    if not segname:
        return "unknown"
    s = str(segname)
    if s.startswith("MEMORY_"):
        s = s[len("MEMORY_"):]
    if s.startswith("_"):
        s = s[1:]
    s = s.strip().lower()
    if not s:
        return "unknown"
    out = []
    for ch in s:
        if ("a" <= ch <= "z") or ("0" <= ch <= "9") or ch in ("_", "-"):
            out.append(ch)
        else:
            out.append("_")
    return "".join(out) or "unknown"


def _load_addr_to_segname(nb09_json_path):
    """Build a mapping of ghidra.addr string -> segmap.segname from nb09_ghidra_globals.json."""
    with open(nb09_json_path, "rb") as f:
        data = json.loads(f.read())

    # Convention: records are in data["procs"], but tolerate other shapes.
    if isinstance(data, dict):
        procs = data.get("procs") or []
    elif isinstance(data, list):
        procs = data
    else:
        procs = []

    m = {}
    for r in procs:
        if not isinstance(r, dict):
            continue
        gh = r.get("ghidra") or {}
        addr = gh.get("addr")
        if not addr:
            continue
        segmap = r.get("segmap") or {}
        segname = segmap.get("segname")
        if segname:
            m[str(addr)] = str(segname)
    return m


def _load_exclude_file(path):
    names = set()
    if not path:
        return names
    try:
        with open(path, "r") as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                names.add(s)
    except Exception as e:
        println("WARNING: failed to read exclude file '%s': %s" % (path, str(e)))
    return names


def _parse_args(argv):
    """Parse getScriptArgs() style args with a tiny, predictable parser."""
    if not argv:
        return None

    out_path = argv[0]
    i = 1

    per_module = not out_path.lower().endswith(".c")
    nb09_json = None

    if per_module:
        # Next non-flag arg is nb09 json.
        while i < len(argv) and argv[i].startswith("--"):
            break
        if i < len(argv) and not argv[i].startswith("--"):
            nb09_json = argv[i]
            i += 1

    segment_filter = None
    exclude_csv = ""
    exclude_file = None
    strip_namespaces = False
    strip_cconv = False

    while i < len(argv):
        a = argv[i]

        def _need_value(flag):
            if i + 1 >= len(argv):
                raise Exception("Missing value for %s" % flag)
            return argv[i + 1]

        if a == "--segment-filter":
            segment_filter = _need_value(a)
            i += 2
            continue
        if a.startswith("--segment-filter="):
            segment_filter = a.split("=", 1)[1]
            i += 1
            continue

        if a == "--exclude":
            exclude_csv = _need_value(a)
            i += 2
            continue
        if a.startswith("--exclude="):
            exclude_csv = a.split("=", 1)[1]
            i += 1
            continue

        if a == "--exclude-file":
            exclude_file = _need_value(a)
            i += 2
            continue
        if a.startswith("--exclude-file="):
            exclude_file = a.split("=", 1)[1]
            i += 1
            continue

        if a == "--strip-namespaces":
            strip_namespaces = True
            i += 1
            continue

        if a == "--strip-cconv" or a == "--strip-calling-conventions":
            strip_cconv = True
            i += 1
            continue

        # Unknown token: tolerate to reduce friction.
        println("WARNING: ignoring unrecognized argument: %s" % a)
        i += 1

    exclude_set = set()
    if exclude_csv:
        for n in exclude_csv.split(","):
            n = n.strip()
            if n:
                exclude_set.add(n)
    if exclude_file:
        exclude_set |= _load_exclude_file(exclude_file)

    return {
        "out_path": out_path,
        "per_module": per_module,
        "nb09_json": nb09_json,
        "segment_filter": segment_filter,
        "exclude_set": exclude_set,
        "strip_namespaces": strip_namespaces,
        "strip_cconv": strip_cconv,
    }


def main():
    argv = getScriptArgs()

    if not argv:
        println("Usage:")
        println("  ExportAllDecompiled.py <out_file.c>")
        println("  ExportAllDecompiled.py <out_dir> <nb09_ghidra_globals.json> [--exclude ...] [--exclude-file ...] [--segment-filter ...] [--strip-namespaces] [--strip-cconv]")
        return

    try:
        cfg = _parse_args(argv)
    except Exception as e:
        println("ERROR: %s" % str(e))
        return

    out_path = cfg["out_path"]
    per_module = cfg["per_module"]
    nb09_json = cfg["nb09_json"]
    segment_filter = cfg["segment_filter"]
    exclude_set = cfg["exclude_set"]

    if per_module:
        if not nb09_json:
            try:
                nb09_json = askFile("Select nb09_ghidra_globals.json", "OK").getAbsolutePath()
            except Exception:
                nb09_json = None
        if not nb09_json or not os.path.exists(nb09_json):
            println("ERROR: per-module export requires nb09_ghidra_globals.json path")
            return

    println("Output: %s" % out_path)
    if per_module:
        println("Mode: per-module (flat directory)")
        println("NB09 JSON: %s" % nb09_json)
    else:
        println("Mode: single-file")
    if segment_filter:
        println("Segment filter: %s" % segment_filter)
    if exclude_set:
        println("Excluding %d functions" % len(exclude_set))

    addr_to_segname = {}
    if per_module:
        addr_to_segname = _load_addr_to_segname(nb09_json)

    fm = currentProgram.getFunctionManager()

    decomp = DecompInterface()
    decomp.openProgram(currentProgram)

    file_handles = {}

    def _get_out_file_for(addr_str):
        if not per_module:
            return out_path
        segname = addr_to_segname.get(addr_str)
        mod = _slugify_module(segname)
        return os.path.join(out_path, "%s.c" % mod)

    def _get_handle(path):
        h = file_handles.get(path)
        if h is not None:
            return h

        # Ensure output directory exists in per-module mode.
        if per_module:
            try:
                if not os.path.isdir(out_path):
                    os.makedirs(out_path)
            except Exception:
                pass

        h = open(path, "w")
        h.write("// Decompiled code from stars.exe\n")
        h.write("// Generated by Ghidra - ExportAllDecompiled.py\n")
        if per_module:
            h.write("// Grouped by nb09_ghidra_globals.json segmap.segname\n")
        h.write("// \n\n")
        file_handles[path] = h
        return h

    try:
        if not per_module:
            _get_handle(out_path)

        total = fm.getFunctionCount()
        println("Total functions: %d" % total)

        count = 0
        written = 0

        for func in fm.getFunctions(True):
            name = func.getName()
            if name.startswith("_"):
                continue
            if exclude_set and (name in exclude_set):
                continue

            addr_str = str(func.getEntryPoint())
            if segment_filter and not addr_str.startswith(segment_filter):
                continue

            count += 1
            if count % 100 == 0:
                println("Progress: %d functions processed" % count)

            out_file = _get_out_file_for(addr_str)
            f = _get_handle(out_file)

            f.write("// " + "=" * 70 + "\n")
            f.write("// Function: %s\n" % name)
            f.write("// Address: %s\n" % addr_str)
            if per_module:
                segname = addr_to_segname.get(addr_str) or "(unknown)"
                if not segname:
                    # skip unkonwn
                    continue
                f.write("// Segment: %s\n" % segname)
            f.write("// " + "=" * 70 + "\n\n")

            code = decompile_function(func, decomp)
            code = strip_cpp_scopes(code)
            code = strip_calling_conventions(code)
            if code:
                f.write(code)
                f.write("\n\n")
            else:
                f.write("// No code generated\n\n")

            written += 1

        for h in file_handles.values():
            try:
                h.close()
            except Exception:
                pass

        if per_module:
            println("Exported %d functions to directory: %s" % (written, out_path))
        else:
            println("Exported %d functions to file: %s" % (written, out_path))

    finally:
        try:
            decomp.dispose()
        except Exception:
            pass


if __name__ == "__main__":
    main()
