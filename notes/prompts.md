### Good prompt (best practice)

I have attached a zip of my project source files.

Translate the WriteIniSettings, FormatSerialAndEnv, SetWindowIniString, FSerialAndEnvFromSz, GetIniWinRc, and ReadIniTileSettings to modern win32 C.

See @notes/implementation.md for locations of various functions and their decompiles

Translate the WriteIniSettings to modern win32 C.

Use @project_index.json to locate related globals and functions, but treat @types.h as the source of truth for all struct fields and types.
Preserve 16-bit math behavior. Convert bitwise operations to flags referencing the bitfields in @types.h.

## tips and rules:

- don't add extra scope blocks to functions
- code like `lphs->grhst == hstBeam && lphs->iItem == 0x12`, the hull slot iItem should match with i<part> enums in @enums.h, i.e. hstBeam 0x12 is `ibeamMultiContainedMunition`
- for windows api calls, swap hardcoded values for constants (i.e. WM*\*, ODC*\*) where possible
- If locals are already renamed in the decompile (e.g., `pl`, `lMaxPop`, `pctDesire`, `ihuldef`), **preserve those names**. For ghidra autonamed vars (i.e. pcVar1), rename them to be clear.

After implementing:

1. Run `mise run build-native` and `mise run build-cross` (if available) — both must succeed.
2. For non-UI functions, add tests to the matching file in @test/ following existing test style.
3. Run `mise run build-test` — all tests must pass.
4. Run `mise run update-progress` — updates project index, implementation tracking, and implementation plan (with `--exclude-ai`).
