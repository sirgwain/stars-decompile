# Ghidra Decompilation Workflow

## Initial Setup

### 1. Create Ghidra Project

```bash
# Launch Ghidra
ghidraRun

# In Ghidra:
# 1. File -> New Project -> Non-Shared Project
# 2. Select project directory within the repo (e.g., ghidra_project/)
# 3. Name: "stars26jrc3"
```

### 2. Import the Executable

1. File -> Import File
2. Select: `target/stars.exe`
3. Format: "New Executable (NE)"
4. Language: "x86:LE:16:Protected Mode" (16-bit protected mode x86)
5. Click OK, then Analyze

Or use the mise task: `mise run ghidra-import`

### 3. Apply Symbol Scripts

The easiest way is to use the mise setup task which runs all scripts in order:

```bash
mise run ghidra-setup
```

This runs:

1. `ghidra-import` - Import the binary
2. `ghidra-create-enums` - Create enum types
3. `ghidra-apply-structs` - Apply struct definitions
4. `ghidra-apply-win16api` - Apply Win16 API signatures
5. `ghidra-apply-names` - Apply function and global names
6. `ghidra-apply-types` - Apply global variable types
7. `ghidra-update-runtime-helpers` - Update runtime helper signatures
8. `ghidra-analyze` - Run the analyzer
9. `ghidra-retype-doubles` - Retype double variables
10. `ghidra-delete-default-dat` - Delete default DAT\_ symbols
11. `ghidra-apply-race-attributes` - Apply race attribute equates
12. `ghidra-apply-funclocals` - Apply function local variables

**Manual script execution (if needed):**

1. **ApplyNb09StructsFromJson.py** - Creates DataTypes for all structs
2. **ApplyNb09NamesFromJson.py** - Renames all symbols (functions, globals)
3. **ApplyNb09TypesFromJson.py** - Applies types to global variables
4. **ApplyNb09FuncLocalsFromJson.py** - Applies function signatures and local variables

## Decompilation Process

### Finding Functions

1. Open the Symbol Table (Window -> Symbol Table)
2. Filter by name or address
3. Double-click to navigate to function

### Decompiling a Function

1. Navigate to function in Listing view
2. Open Decompiler (Window -> Decompile)
3. Ghidra will show pseudo-C

### Improving Decompilation

1. **Fix Data Types**: Right-click variable -> Retype Variable
2. **Rename Variables**: Right-click -> Rename Variable
3. **Set Calling Convention**: Right-click function -> Edit Function Signature
4. **Mark Code/Data**: 'C' to make code, 'D' to make data

### Exporting Decompiled Code

1. Select function in Decompiler window
2. Right-click -> Copy
3. Paste into corresponding .c file
4. Clean up output (remove Ghidra artifacts)

## Segment Mapping

From `scripts/segments.csv`:

| Segment      | Selector  | Description     |
| ------------ | --------- | --------------- |
| Code1-Code36 | 1000-1118 | Executable code |
| Data37       | 1120      | Global data     |
| Rsrc0-Rsrc11 | 1128-1180 | Resources       |

## Address Translation

The scripts handle translation between:

- **CodeView addresses**: segment:offset from debug symbols
- **Ghidra addresses**: selector:offset in the loaded program

Example:

```
CodeView: MEMORY_UTIL:0x3b68
Ghidra:   1058:3b68
```

## Common Issues

### Wrong Calling Convention

16-bit Pascal calling convention:

- Arguments pushed left-to-right
- Callee cleans stack
- Return in AX (or DX:AX for 32-bit)

Set with: Edit Function Signature -> Calling Convention: `__pascal`

### Far vs Near Pointers

- Far pointers: 4 bytes (segment:offset)
- Near pointers: 2 bytes (offset only)

Ghidra may need hints about pointer types.

### Structure Alignment

Win16 used pragma pack(1) or pack(2). The scripts attempt to handle this, but manual fixes may be needed.

## Tips

1. **Start with small functions**: Utility functions are easier to verify
2. **Cross-reference**: Use References window to find callers/callees
3. **Use debug labels**: Comments like `/* label LSrcChk @ ... */` mark jump targets
4. **Compare with skeleton**: The .c files have local variable names already
