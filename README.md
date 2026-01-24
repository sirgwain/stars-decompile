# stars-decompile

Decompile and recompile of original stars 4x

All of the types, function signatures, and initial local variable declarations and structs are extracted from codeview nb09 binary (extracted from the end of the stars26jrc3.exe).

## building

This project uses CMake. The recommended way to configure and build is via **CMake Presets** (`CMakePresets.json`), which keeps build flags consistent across platforms.

### prerequisites

- CMake 3.23+
- A C compiler toolchain (clang/gcc on macOS/Linux, MSVC or clang-cl on Windows)
- Ninja (recommended on macOS/Linux)

---

## build with presets (recommended)

### macos / linux (cli only)

```bash
cmake --preset macos-linux
cmake --build --preset build-macos-linux
```

### win32 (cli + win32)

```bash
cmake --preset win32
cmake --build --preset build-win32-debug
```

### macos crossover build (mingw-w64)

```bash
cmake --preset macos-crossover
cmake --build --preset build-macos-crossover
cmake --build --preset run-crossover
```

---

## run tests

Tests are built and run via the `test_all` target:

```bash
cmake --build --preset run-tests
```

### notes

- Presets use the following build directories:
  - `build/` for native builds
  - `build-win/` for MinGW / Crossover builds
- If you change compiler or toolchain settings, it’s often easiest to delete the corresponding build directory and reconfigure.

## scripts

- [`nb09_model.py`](scripts/nb09_model.py) / [`nb09_parser.py`](scripts/nb09_parser.py)  
  Parse the NB09 debug binary into Python data classes

- [`dump_nb09_c.py`](scripts/dump_nb09_c.py)  
  Dump a C skeleton with types, globals, and function signatures

- [`dump_nb09_ghidra.py`](scripts/dump_nb09_ghidra.py)  
  Dump JSON formatted for Ghidra automation scripts mapping globals and function signatures to Ghidra locations  
  (generates `nb09_ghidra_globals.json`)

- [`dump_nb09_structmeta.py`](scripts/dump_nb09_structmeta.py)  
  Dump type information into a Ghidra-friendly format for creating `DataType`s

- [`extract_stars_messages.py`](scripts/extract_stars_messages.py)  
  Extract and decompress Stars! string tables (STR / MSG / TUT / PN) from `stars.exe`

- [`extract_globals_initializers.py`](scripts/extract_globals_initializers.py)  
  Extract global initializers and struct data for all global variables from `stars.exe`

## ghidra scripts

- ApplyNb09StructsFromJson.py - generate DataTypes for all structs in types.h
- ApplyNb09NamesFromJson.py - rename all function and data values (no typing)
- ApplyNb09TypesFromJson.py - apply typing to all data values
- ApplyNb09FuncLocalsFromJson.py - apply function signatures and local variable reassignment
- DecompileFunction.py - decompile a single function by name
- ListFunctions.py - list functions matching a pattern
- ExportDecompiled.py - export decompiled code for multiple functions to a file

## mise tasks

This project uses [mise](https://mise.jdx.dev/) for task automation. Install mise and run tasks with `mise run <task>`.

### Configuration

Set `GHIDRA_HOME` environment variable to override the default Ghidra path:

```bash
export GHIDRA_HOME=/path/to/your/ghidra
```

Default: `~/.local/ghidra/ghidra_12.0.1_DEV`

This project requires a custom version of ghidra with win16 support and decompile cleanup features hacked in for Stars!

https://github.com/sirgwain/ghidra/tree/win16-stars

### Available Tasks

| Task                                                 | Description                                          |
| ---------------------------------------------------- | ---------------------------------------------------- |
| `mise run ghidra-import`                             | Import stars.exe into Ghidra (16-bit Protected Mode) |
| `mise run ghidra-apply-structs`                      | Apply NB09 struct definitions                        |
| `mise run ghidra-apply-names`                        | Apply function and global names                      |
| `mise run ghidra-apply-globals`                      | Apply global variable types                          |
| `mise run ghidra-apply-funcsigs`                     | Apply function signatures                            |
| `mise run ghidra-parse-windowsh`                     | Parse WINDOWS.H for types                            |
| `mise run ghidra-update-runtime-helpers`             | Update sigs for `__aFl*`/`__aFul*`/`__strcmp`, etc   |
| `mise run ghidra-retype-doubles`                     | Retype known doubles in DATA segment                 |
| `mise run ghidra-setup`                              | Full setup: import + all 4 scripts                   |
| `mise run ghidra-gui`                                | Launch Ghidra GUI                                    |
| `mise run list-functions -- <pattern>`               | List functions matching a pattern                    |
| `mise run decompile -- <function>`                   | Decompile a single function                          |
| `mise run export-decompiled -- <output> <func1> ...` | Export multiple functions to file                    |
| `mise run export-p1-functions`                       | Export P1 utility functions to decompiled/p1_util.c  |

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
