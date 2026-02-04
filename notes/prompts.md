# Zip Prompt

I have attached a zip of my project source files.

See @notes/implementation.md for locations of various functions and their decompiles

Translate the FRunLogRecord function from decompiled/all/planet.c and put it in the empty function signature in log.c. Make sure builds and tests run. After translating, compare against the original and note any differences in logic flow. Resolve those fixes and test again.

When complete, add a test to test_log.c and make it similar to the FLoadGame tests in test_file.c.

Use @project_index.json to locate related globals and functions, but treat @types.h as the source of truth for all struct fields and types.
Preserve 16-bit math behavior. Convert bitwise operations to flags referencing the bitfields in @types.h.

## tips and rules:

- Use bitfields instead of bitwise operations for structs where available (INI, GD, GAME, PLAYER, FLEET, etc all have bitfields)
- don't add extra scope blocks to functions
- code like `lphs->grhst == hstBeam && lphs->iItem == 0x12`, the hull slot iItem should match with i<part> enums in @enums.h, i.e. hstBeam 0x12 is `ibeamMultiContainedMunition`
- for windows api calls, swap hardcoded values for constants (i.e. WM*\*, ODC*\*) where possible
- add resource ids to resource.h for undefined windows item constants.
- If locals are already renamed in the decompile (e.g., `pl`, `lMaxPop`, `pctDesire`, `ihuldef`), **preserve those names**. For ghidra autonamed vars (i.e. pcVar1), rename them to be clear.

After implementing:

# build steps
Run this to build:

```bash
cmake --preset macos-linux
cmake --build --preset run-tests

cmake --preset macos-linux-win32-stubs
cmake --build --preset build-macos-linux-win32-stubs
```

Give me a download zip with any changed files.

# Copy/Paste Prompt
Translate this decompiled function to modern c. Don't change the general flow. Account for every instruction. Don't add bounds checking or extra functions. Rename ghidra generated locals to have sensible names. Update types to standard c types. Only add casting that is absolutely necessary.

After the first pass, go through the translated function and convert bitwise operations to bitfields where possible, referencing types.h in this project for struct definitions.