# DumpAsm.py
# Ghidra script to dump assembly listing for a function
# Usage:
#   DumpAsm.py <function_name> [--raw]
#     --raw  : print just the instruction text (no address / bytes header)
#
# Example:
#   mise run dump-asm -- FRAMEWNDPROC
#   mise run dump-asm -- FRAMEWNDPROC --raw
#
# @category Stars

# make IDE register built ins
try:
    from ghidra.ghidra_builtins import *
    from ghidra.program.model.listing import *
    from ghidra.util.task import *

    currentProgram = currentProgram  # type: Program
    monitor = monitor  # type: TaskMonitor
except:
    pass

from ghidra.program.model.listing import CodeUnit, Function, Instruction
import sys

def _find_function_by_name(func_name: str):
    f = getFunction(func_name)
    if f:
        return f

    fm = currentProgram.getFunctionManager()
    for it in fm.getFunctions(True):
        it = it  # type: Function
        if func_name in it.getName():
            return it
    return None

def _format_instr(instr: Instruction) -> str:
    """
    Try to mimic Listing view operand rendering (symbols, stack vars, etc.).
    Instruction.toString() is usually close, but getDefaultOperandRepresentation()
    tends to respect operand markup/references better in scripts.
    """
    mnem = instr.getMnemonicString()

    nops = instr.getNumOperands()
    if nops <= 0:
        return mnem

    # Join with ", " (good enough for x86; Listing sometimes varies, but close).
    ops = []
    for i in range(nops):
        ops.append(instr.getDefaultOperandRepresentation(i))
    return mnem + " " + ", ".join(ops)

args = getScriptArgs()
if len(args) < 1:
    print("Usage: DumpAsm.py <function_name> [--raw]")
    sys.exit(1)

func_name = args[0]
raw_only = any(a == "--raw" for a in args[1:])

func = _find_function_by_name(func_name)
if not func:
    print("Function not found: " + func_name)
    sys.exit(1)

listing = currentProgram.getListing()
start = func.getEntryPoint()
end = func.getBody().getMaxAddress()

if not raw_only:
    print("=== {} @ {} ===".format(func.getName(), start))
    print("")

# Walk instructions in the function body (skips embedded data more reliably than CodeUnit iteration).
it = listing.getInstructions(func.getBody(), True)
for instr in it:
    instr = instr  # type: Instruction
    if instr.getMinAddress().compareTo(end) > 0:
        break

    if raw_only:
        print(_format_instr(instr))
        continue

    addr_str = str(instr.getAddress())

    bytes_arr = instr.getBytes()
    bytes_hex = " ".join("{:02x}".format(b & 0xff) for b in bytes_arr)

    instr_str = _format_instr(instr)
    print("{}: {:24s} {}".format(addr_str, bytes_hex, instr_str))

if not raw_only:
    print("")
    print("=== END ===")
