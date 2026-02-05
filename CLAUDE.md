## Project Instructions

### Context

You are helping decompile and re-implement the Win16 game **Stars!**.

### Source of truth

- **`types.h` is authoritative** for all struct layouts, field names, field widths, signedness, packing, and bitfields.
- I have `stars26jrc3.exe` with debug symbols and extracted NB09 CodeView symbols (`stars26jrc3.codeview.nb09.bin`) available as supporting evidence.

### Goals

- Produce modern, portable **32/64-bit C** that is **behavior-identical** to the original game logic.
- For game logic, preserve **16-bit-era math quirks** (truncation, sign extension, wrap/overflow behavior) even though we’re using 32-bit C types.
- For win32 API calls and message handling, we don't need to preserve 16 bit quirks, we can modernize and use windows types as long as the intent is the same.

### Modernization rules

- For game logic (non windows code) Use standard C types:
  - `uint8_t`, `int16_t`, `uint16_t`, `int32_t`, `uint32_t`, `bool`.

- Remove segmented / far pointer artifacts:
  - No `CONCAT22`, `._0_2_`, `SEG:OFF`, “far” pointer glue in output C.

- Replace compiler helper stubs:
  - Replace `__aFulmul`, `__aFuldiv`, `__aFldiv`, `__aFlshl`, etc. with explicit `int32_t/uint32_t` operations and casts.

- Strip namespaces:
  - Output `PctPlanetDesirability(...)`, not `PLANET::PctPlanetDesirability(...)`.

- Keep user-renamed locals:
  - If locals are already renamed in the decompile (e.g., `pl`, `lMaxPop`, `pctDesire`, `ihuldef`), **preserve those names**.
  - rename ghidra defaults i.e. `sVar1`, `uVar2`

- When translating a function:
  - Output **only the function body/signature** (no surrounding includes, externs, or unrelated code).
  - Assume globals are available via `#include "globals.h"` or the relevant header (but do not emit those includes unless asked).

### UI macro pattern recognition

Recognize UI patterns like:

- load string by id + alert + early return and rewrite to the project idiom, e.g.:

```c
Error(idsUnableToLoadStars);
return 0;
```
