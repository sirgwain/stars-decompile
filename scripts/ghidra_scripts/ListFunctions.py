# ListFunctions.py
# @category Stars
# @description: List all functions matching a pattern

import sys


def main():
    args = getScriptArgs()
    pattern = args[0].lower() if args else ""

    fm = currentProgram.getFunctionManager()
    count = 0

    for f in fm.getFunctions(True):
        name = f.getName()
        if not pattern or pattern in name.lower():
            println("%s @ %s" % (name, f.getEntryPoint()))
            count += 1
            if count >= 50:
                println("... (showing first 50)")
                break

    println("Total found: %d" % count)


if __name__ == "__main__":
    main()
