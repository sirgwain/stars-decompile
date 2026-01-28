# Stars! 2.60j Decompilation Notes

This directory contains documentation and research notes for the Stars! 2.60j RC3 decompilation project.

## Overview

Stars! is a turn-based 4X (eXplore, eXpand, eXploit, eXterminate) space strategy game originally released in 1995 by Jeff Johnson and Jeff McBride. Version 2.60j RC3 was released around April 26, 2000 and is significant because it includes CodeView NB09 debug symbols, making reverse engineering significantly easier.

## Documentation Files

- `game-architecture.md` - High-level overview of game systems and data flow
- `data-structures.md` - Detailed documentation of key data structures
- `ship-components.md` - Ship parts, weapons, and their statistics
- `tech-tree.md` - Technology fields and requirements
- `ai-systems.md` - Computer player behavior and strategies
- `interesting-findings.md` - Bugs, quirks, and notable discoveries
- `ghidra-workflow.md` - Ghidra setup and decompilation workflow
- `decompilation-priorities.md` - Priority order for function implementation
- `translation-instructions.md` - Rules for translating decompiled code
- `implementation.md` - Auto-generated implementation status (run `mise run track-implementation --update-docs`)
- `implementation-plan.md` - Auto-generated implementation plan by depth
- `prompts.md` - Prompt templates for Claude assistance
- `todo.md` - Pending tasks

## Project Status

- **Total Source Files**: 46 C source files
- **Extracted Functions**: 846 with full signatures
- **Extracted Globals**: 612 variables
- **Functions Implemented**: ~18% (155 functions)

Run `mise run track-implementation` for current status.

## Tools Used

- **Ghidra** (custom win16 build) - Primary disassembler ([sirgwain/ghidra win16-stars branch](https://github.com/sirgwain/ghidra/tree/win16-stars))
- **Python 3** - Symbol extraction and analysis scripts
- **mise** - Task automation (`mise run ghidra-setup`, etc.)
- **CMake** - Build system with presets for native and cross-compilation
- **CodeView NB09** - Debug symbol format from the executable
