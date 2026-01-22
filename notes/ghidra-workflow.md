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
4. Language: "x86:LE:16:Real Mode" (16-bit real mode x86)
5. Click OK, then Analyze

### 3. Apply Symbol Scripts

Scripts must be run in order:

```bash
# Copy scripts to Ghidra scripts directory or run from project
cp scripts/ghidra_scripts/*.py ~/.ghidra/.ghidra_<version>/Extensions/Ghidra/ghidra_scripts/
```

**Order of execution:**

1. **ApplyNb09StructsFromJson.py**
   - Creates DataTypes for all structs
   - Input: `scripts/nb09_structmeta.json`

2. **ApplyNb09NamesFromJson.py**
   - Renames all symbols (functions, globals)
   - Input: `scripts/nb09_ghidra_globals.json`

3. **ApplyNb09TypesFromJson.py**
   - Applies types to global variables
   - Input: `scripts/nb09_ghidra_globals.json`

4. **ApplyNb09FuncLocalsFromJson.py**
   - Applies function signatures and local variables
   - Input: `scripts/nb09_ghidra_globals.json`

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
