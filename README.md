# stars-decompile
Decompile and recompile of original stars 4x

All of the types, function signatures, and initial local variable declarations and structs are extracted from codeview nb09 binary (extracted from the end of the stars26jrc3.exe).

## building
To build using cmake, execute the following

### macos/linux
```bash
cmake -S . -B build -G Ninja -DSTARS_BUILD_CLI=ON -DSTARS_BUILD_WIN32=OFF
cmake --build build
```

### win32
```bash
cmake -S . -B build -DSTARS_BUILD_CLI=ON -DSTARS_BUILD_WIN32=ON
cmake --build build --config Debug
```

### macos crossover build
```bash
cmake -S . -B build-win -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=toolchains/mingw-w64.cmake \
  -DSTARS_BUILD_CLI=OFF -DSTARS_BUILD_WIN32=ON

cmake --build build-win
cmake --build build-win --target run_in_crossover
```

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
* DecompileFunction.py - decompile a single function by name
* ListFunctions.py - list functions matching a pattern
* ExportDecompiled.py - export decompiled code for multiple functions to a file

## mise tasks

This project uses [mise](https://mise.jdx.dev/) for task automation. Install mise and run tasks with `mise run <task>`.

### Configuration

Set `GHIDRA_HOME` environment variable to override the default Ghidra path:
```bash
export GHIDRA_HOME=/path/to/your/ghidra
```
Default: `~/.local/ghidra/ghidra_10.3_DEV`

### Available Tasks

| Task | Description |
|------|-------------|
| `mise run ghidra-import` | Import stars.exe into Ghidra (16-bit Protected Mode) |
| `mise run ghidra-apply-structs` | Apply NB09 struct definitions |
| `mise run ghidra-apply-names` | Apply function and global names |
| `mise run ghidra-apply-globals` | Apply global variable types |
| `mise run ghidra-apply-funcsigs` | Apply function signatures |
| `mise run ghidra-setup` | Full setup: import + all 4 scripts |
| `mise run ghidra-gui` | Launch Ghidra GUI |
| `mise run list-functions -- <pattern>` | List functions matching a pattern |
| `mise run decompile -- <function>` | Decompile a single function |
| `mise run export-decompiled -- <output> <func1> ...` | Export multiple functions to file |
| `mise run export-p1-functions` | Export P1 utility functions to decompiled/p1_util.c |

### Quick Start

```bash
# Full Ghidra setup (import binary + apply all symbol scripts)
mise run ghidra-setup

# Decompile a specific function
mise run decompile -- LpflFromId

# Search for functions
mise run list-functions -- Rand

# Export multiple functions to a file
mise run export-decompiled -- output.c LpflFromId LpplFromId Random
```

