### Good prompt (best practice)

Translate the next function in @notes/implementation-plan.md to modern C.
Use @project_index.json to locate related globals and functions, but treat @types.h as the source of truth for all struct fields and types.
Preserve 16-bit math behavior. Convert bitwise operations to flags referencing the bitfields in @types.h.

After implementing:

1. Run `mise run build-native` and `mise run build-cross` — both must succeed.
2. For non-UI functions, add tests to the matching file in @test/ following existing test style.
3. Run `mise run build-test` — all tests must pass.
4. Run `mise run track-implementation` - update implementation
5. run `mise run build-impl-plan --exclude-ai` - update implementation plan
