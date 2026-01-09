# DecompileFunction.py
# @category Stars
# @description: Decompile a function by name and print the C code
#
# Usage (headless): -postScript DecompileFunction.py <function_name>

import sys

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


def find_function_by_name(fm, name):
    """Find a function by name (case-insensitive partial match)."""
    name_lower = name.lower()

    # Try exact match first
    for f in fm.getFunctions(True):
        if f.getName().lower() == name_lower:
            return f

    # Try partial match
    matches = []
    for f in fm.getFunctions(True):
        if name_lower in f.getName().lower():
            matches.append(f)

    if len(matches) == 1:
        return matches[0]
    elif len(matches) > 1:
        println("Multiple matches found:")
        for m in matches[:20]:
            println("  %s @ %s" % (m.getName(), m.getEntryPoint()))
        if len(matches) > 20:
            println("  ... and %d more" % (len(matches) - 20))
        return None

    return None


def decompile_function(func):
    """Decompile a function and return the C code."""
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)

    try:
        monitor = ConsoleTaskMonitor()
        result = decomp.decompileFunction(func, 60, monitor)

        if result.decompileCompleted():
            return result.getDecompiledFunction().getC()
        else:
            println("Decompilation failed: %s" % result.getErrorMessage())
            return None
    finally:
        decomp.dispose()


def main():
    args = getScriptArgs()

    if len(args) < 1:
        println("Usage: DecompileFunction.py <function_name>")
        println("")
        println("Example: DecompileFunction.py LpflFromId")
        return

    func_name = args[0]
    println("Looking for function: %s" % func_name)

    fm = currentProgram.getFunctionManager()
    func = find_function_by_name(fm, func_name)

    if func is None:
        println("Function not found: %s" % func_name)
        return

    println("Found: %s @ %s" % (func.getName(), func.getEntryPoint()))
    println("")
    println("=" * 60)
    println("DECOMPILED CODE:")
    println("=" * 60)
    println("")

    code = decompile_function(func)
    if code:
        println(code)


if __name__ == "__main__":
    main()
