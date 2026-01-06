# stars-decompile
Decompile and recompile of original stars 4x

All of the types, function signatures, and initial local variable declarations and structs are extracted from codeview nb09 binary (extracted from the end of the stars26jrc3.exe).

## scripts

* nb09_model.py/nb09_parser.py - parsed the nb09 binary into python data classes
* dump_nb09_c.py - dumps a c skeleton with types, globals, and function signatures in c format
* dump_nb09_ghidra.py - dumps a json file formatted for ghidra automation scripts mapping globals and function signatures to their ghidra locations (generates `nb09_ghidra_globals.json`)
* dump_nb09_structmeta.py - dumps type information into a ghidra format for creating DataTypes

## ghidra scripts
* ApplyNb09StructPackingFromJson.py - generate DataTypes for all structs in types.h
* ApplyNb09NamesFromJson.py - rename all function and data values (no typing)
* ApplyNb09GlobalsFromJson.py - apply typing to all data values
* ApplyNb09FuncSigsFromJson.py - apply function signatures and local variable reassignment

