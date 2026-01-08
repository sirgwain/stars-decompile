# Ghidra script to dump assembly listing for a function
# Usage: mise run dump-asm -- FunctionName
# @category Stars

from ghidra.program.model.listing import CodeUnit
import sys

args = getScriptArgs()
if len(args) < 1:
    print("Usage: DumpAsm.py <function_name>")
    sys.exit(1)

func_name = args[0]

# Try to find function by name (may need to search)
func = getFunction(func_name)
if not func:
    # Search all functions for matching name
    fm = currentProgram.getFunctionManager()
    for f in fm.getFunctions(True):
        if func_name in f.getName():
            func = f
            break

if not func:
    print("Function not found: " + func_name)
    sys.exit(1)

listing = currentProgram.getListing()
addr = func.getEntryPoint()
end = func.getBody().getMaxAddress()

print("=== {} @ {} ===".format(func_name, addr))
print("")

cu = listing.getCodeUnitAt(addr)
while cu and cu.getAddress().compareTo(end) <= 0:
    addr_str = str(cu.getAddress())

    # Get bytes as hex
    bytes_arr = cu.getBytes()
    bytes_hex = " ".join("{:02x}".format(b & 0xff) for b in bytes_arr)

    # Format: address: bytes  instruction
    instr_str = str(cu) if cu else ""
    print("{}: {:24s} {}".format(addr_str, bytes_hex, instr_str))

    cu = listing.getCodeUnitAfter(cu.getAddress())

print("")
print("=== END ===")
