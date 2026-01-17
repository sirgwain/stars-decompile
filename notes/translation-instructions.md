Here’s a set of “translation rules” that cover the _kinds_ of edits your project expects when going from Ghidra-ish Win16 decompile → your modern C port, while preserving exact behavior (including 16-bit weirdness).

---

## 0) Source of truth and goals

1. **`types.h` is the source of truth** for struct layouts, field names, and signedness.
2. **Preserve original game logic and integer math exactly** (16-bit truncation, sign extension, overflow behavior), even if the code looks “wrong”.
3. **Modernize representation, not behavior**: eliminate far pointers, segment:offset glue, and compiler helper stubs, but keep outcomes identical.

---

## 1) Names, namespaces, and signatures

- **Drop `FOO::Bar` namespaces** in emitted code: use `Bar(...)`.
- **Use the project’s chosen function signature** (from `types.h` / your sig json), even if the decompile shows `__cdecl16far`, `__stdcall16far`, etc.
- **Local variable names**:

  - Keep any locals you’ve already renamed (don’t “improve” them).
  - If a local is unnamed in the decompile, name it by role (`p`, `pEnd`, `cb`, `msgId`, `tail`, etc.) but don’t invent semantics.

---

## 2) Pointer + memory model normalization (Win16 → flat)

### Far pointers

- Replace segmented/far pointer operations like `CONCAT22(seg, off)` / `._0_2_` / `._2_2_` with **flat pointers**.
- Replace checks like:

  - `(*(int *)&p == 0) && (*(int *)((int)&p+2)==0)`
    with:
  - `p == NULL`

### Pointer arithmetic

- Prefer `uint8_t*` for byte-walking logic and offsets.
- When the decompile “casts through int” (`(int)ptr + off`), translate to `(uint8_t*)ptr + off`.

### Memory functions

- Map Win16 `__fmemcpy/__fmemmove` to `memcpy/memmove`.
- Preserve **overlap semantics**:

  - If original uses memmove, keep memmove.

---

## 3) Integer width rules (the big one)

### Canonical types

- Use fixed-width C types: `uint8_t, int16_t, uint16_t, int32_t, uint32_t, bool`.
- Avoid Win32 types and avoid `short/int/long` unless the project already standardized them.

### Truncation/sign-extension discipline

When the original code mixes sizes, preserve the _cast points_:

- **16-bit add/wrap**: if the original variable is `uint16_t`, do the math in a larger type _only if needed_, then cast back explicitly.
- **Signed vs unsigned comparisons**: reproduce exactly (often decompiles use `uint` casts to force unsigned behavior).

### Common decompile patterns → modern equivalents

- `CONCAT22(hi, lo)` (building a 32-bit) → explicit combine, respecting signedness:

  - unsigned: `uint32_t x = ((uint32_t)hi << 16) | lo;`
  - signed long represented as hi/lo: build then cast: `int32_t x = (int32_t)(((uint32_t)hi << 16) | lo);`

- “mystery negative bound check” patterns like:

  - `imemMsgCur + imemMsgT < -(cb) - 0x38`
    should be preserved _structurally_, not “fixed”. If needed, express with explicit intermediate casts like you did:
  - compute `cur` and `limit` in `int32_t`, compare, then cast results back to `uint16_t`.

---

## 4) Bitfields, packed flags, and masks

- Prefer **named bitmasks / enums** for flag fields (when you already have them), but:

  - Don’t change the bit meaning.
  - Don’t change the storage type (if it’s a `uint16_t` field, keep it `uint16_t`).

- Patterns like:

  - `x = x & ~(1<<b) | (1<<b)`
    are just `x |= (1<<b)`; you may simplify **only if it is provably identical** for all inputs and widths.
  - In your example, it’s safe; but the “rule” should be: _simplify only if algebraically identical under the original width_.

---

## 5) Replace compiler helper stubs (`__aF*`, `__ftol`, etc.)

- Replace Watcom/Microsoft helper calls with normal C arithmetic using explicit widths:

  - `__aFulmul` → `uint32_t` multiply (or `int32_t` if signed).
  - `__aFuldiv` / `__aFldiv` → division with correct signedness.
  - `__aFlshl` / `__aFulshr` → shifts with correct width and sign.

- Keep rounding behavior where relevant (e.g., the decompile uses `+9` before `/10` to emulate `(x+9)/10`).

---

## 6) Control flow normalization

- Convert decompiler `goto LAB_xxx` into structured loops/ifs **only if** it does not change evaluation order or side effects.
- Preserve “read-next-record” loop shapes:

  - If original does `ReadRt()` at the end of each iteration (or at loop head), keep that placement.

---

## 7) Setjmp/longjmp patterns (“OOM guard”)

- Recognize the pattern:

  - save `penvMem`, set `penvMem = &env`, `setjmp`, if nonzero → OOM happened, restore `penvMem`

- Translate to your project wrapper (`MemJump`, `setjmp(env.env)`), keeping:

  - **the same scope** of the guard,
  - **the same behavior** (“stop allocating but keep consuming records” vs “break out”).

- In your example: once OOM happens, keep calling `ReadRt()` but skip alloc/copy.

---

## 8) Linked list tail-walk patterns

- Tail find:

  - decompile checks far pointer halves; modern code should walk `->next != NULL`.

- When appending:

  - set `tail->next = node; tail = node; node->next = NULL;`

---

## 9) “Magic tables / arrays” indexing

- Preserve indexing width and masking:

  - e.g. `msgId = mh->wFlags & 0x01ff` then `rgcMsgArgs[msgId]`

- If the decompile uses a `char` table, treat it as unsigned/signed according to `types.h`. If unknown, preserve behavior by casting to `uint8_t` before widening.

---

## 10) Avoid unnecessary casts
If a cast is necessary to preserve functionality or ensure correctness, keep it, otherwise prefer cleaner code.

---

## 11) Output expectations when you ask for a translation

When you ask me to translate a function, you can instruct:

- **Return only the function body** (no includes, no unrelated globals).
- Use `#include "globals.h"` assumptions for globals; don’t redeclare them.
- Keep locals you’ve renamed.
- Keep 16-bit truncations explicit.
- Replace far-pointer glue and `__aF*` helpers with explicit `int32_t/uint32_t` math.

---
