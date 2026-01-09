# ImportWindowsH.py
# @category Stars
# @description: Parse WINDOWS.H and import types into Ghidra
#
# Usage (headless): -postScript ImportWindowsH.py <path_to_windows.h>

from ghidra.app.util.cparser import CParser
from ghidra.program.model.data import DataTypeManager
from ghidra.util.task import ConsoleTaskMonitor
import os


def main():
    args = getScriptArgs()

    if len(args) < 1:
        println("Usage: ImportWindowsH.py <path_to_windows.h>")
        println("")
        println("Example: ImportWindowsH.py /path/to/include/WINDOWS.H")
        return

    header_path = args[0]

    if not os.path.exists(header_path):
        println("ERROR: File not found: %s" % header_path)
        return

    println("Importing Windows types from: %s" % header_path)

    dtm = currentProgram.getDataTypeManager()

    # Create a CParser for 16-bit Windows
    parser = CParser(dtm)

    # Define preprocessor symbols for Win16
    defines = [
        "WINVER=0x030a",
        "_WINDOWS",
        "__MSDOS__",
        "M_I86",
        "M_I86SM",  # Small memory model
    ]

    try:
        # Parse the header file
        println("Parsing header file...")

        # Read the file
        with open(header_path, 'r') as f:
            content = f.read()

        # Use the CParser to parse
        # Note: This may require adjustments for Ghidra's specific CParser API
        parseResult = parser.parse(content)

        if parseResult is not None:
            println("Successfully parsed WINDOWS.H")
            println("Data types imported into program's data type manager")
        else:
            println("Warning: Parse returned no result - types may still have been imported")

    except Exception as e:
        println("Error parsing header: %s" % str(e))
        println("")
        println("TIP: You may need to parse manually in Ghidra GUI:")
        println("  1. File > Parse C Source...")
        println("  2. Add %s" % header_path)
        println("  3. Set parse options for Win16")
        println("  4. Parse")
        return

    # Count imported types
    count = 0
    for dt in dtm.getAllDataTypes():
        count += 1

    println("")
    println("Total data types in program: %d" % count)
    println("")
    println("Next steps:")
    println("  1. Run ApplyWindowsApiSignatures.py to fix Win API function signatures")


if __name__ == "__main__":
    main()
