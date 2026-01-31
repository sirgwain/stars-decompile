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

### macos wine build (mingw-w64)

```bash
cmake --preset macos-wine
cmake --build --preset build-macos-wine
cmake --build --preset run-wine
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
  - `build-win/` for MinGW / Wine builds
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

- [`call_graph.py`](scripts/call_graph.py)
  Call graph analysis tool for exploring function dependencies
  - `function-tree`: Display a tree of functions called by a given function
  - `unimplemented`: List all unimplemented functions in a function's call tree

- [`track_implementation.py`](scripts/track_implementation.py)
  Track implementation status of functions (implemented vs stub)

- [`build_implementation_plan.py`](scripts/build_implementation_plan.py)
  Generate implementation plan based on call graph and dependencies

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

#### Ghidra Setup & Import

| Task                      | Description                                             |
| ------------------------- | ------------------------------------------------------- |
| `mise run ghidra-setup`   | Full setup: import + apply all symbol scripts + analyze |
| `mise run ghidra-import`  | Import stars.exe into Ghidra (16-bit Protected Mode)    |
| `mise run ghidra-gui`     | Launch Ghidra GUI                                       |
| `mise run ghidra-analyze` | Run the Ghidra analyzer                                 |

#### Ghidra Symbol Application

| Task                                     | Description                                         |
| ---------------------------------------- | --------------------------------------------------- |
| `mise run ghidra-apply-structs`          | Apply NB09 struct definitions                       |
| `mise run ghidra-apply-names`            | Apply function and global names                     |
| `mise run ghidra-apply-types`            | Apply global variable types and function signatures |
| `mise run ghidra-apply-funclocals`       | Apply function local variables                      |
| `mise run ghidra-apply-win16api`         | Apply Win16 API signatures                          |
| `mise run ghidra-apply-race-attributes`  | Apply race attribute equates                        |
| `mise run ghidra-create-enums`           | Create enum types from enums.h                      |
| `mise run ghidra-update-runtime-helpers` | Update sigs for `__aFl*`/`__aFul*` helpers          |
| `mise run ghidra-retype-doubles`         | Retype unknown8 vars in 1120:\* to doubles          |
| `mise run ghidra-delete-default-dat`     | Delete analyzer-created DAT\_ references            |
| `mise run ghidra-parse-windowsh`         | Parse WINDOWS.H for types (GUI recommended)         |

#### Decompilation & Export

| Task                                                   | Description                              |
| ------------------------------------------------------ | ---------------------------------------- |
| `mise run decompile -- <function>`                     | Decompile a single function              |
| `mise run dump-asm -- <function>`                      | Dump assembly listing for a function     |
| `mise run dump-pcode -- <function>`                    | Dump pcode listing for a function        |
| `mise run list-functions -- <pattern>`                 | List functions matching a pattern        |
| `mise run export-decompiled -- <output> <func1> ...`   | Export multiple functions to file        |
| `mise run export-call-tree -- <output> <func> [depth]` | Export function and all called functions |
| `mise run export-all-decompiled -- <dir> [segment]`    | Export ALL decompiled code               |
| `mise run export-p1-functions`                         | Export P1 utility functions              |

#### Build Tasks

| Task                    | Description                            |
| ----------------------- | -------------------------------------- |
| `mise run build-native` | Build native (macOS/Linux) with CMake  |
| `mise run build-wine`  | Build Wine (mingw-w64) with CMake |
| `mise run build-test`   | Build and run all tests                |
| `mise run build-all`    | Build native + cross + run tests       |

#### Analysis & Tracking

| Task                               | Description                    |
| ---------------------------------- | ------------------------------ |
| `mise run call-graph -- <command>` | Call graph analysis tool       |
| `mise run track-implementation`    | Track implementation status    |
| `mise run build-impl-plan`         | Generate implementation plan   |
| `mise run update-progress`         | Update index + tracking + plan |
| `mise run build-call-graph`        | Build function call graph JSON |

#### Data Export

| Task                            | Description                   |
| ------------------------------- | ----------------------------- |
| `mise run dump-structmeta-json` | Dump nb09_structmeta.json     |
| `mise run dump-globals-json`    | Dump nb09_ghidra_globals.json |

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

# View call tree for a function (shows implementation status)
mise run call-graph -- function-tree -f CalcPlayerScore

# List unimplemented dependencies for a function
mise run call-graph -- unimplemented -f CalcPlayerScore
```
