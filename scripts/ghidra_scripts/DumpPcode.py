# DumpFunctionPcode.py
# @category Stars
#
# Dump P-code for a function, with a readability-first pretty printer (includes full instruction text).
#
# Usage:
#   DumpFunctionPcode.py <function_name> [--high] [--raw] [--no-flags]
#
# Defaults:
#   - low pcode (Instruction.getPcode())
#   - pretty-printed varnodes (register names, stack[], ram:seg:off)
#   - keeps flag-setting ops, but compacts them onto a single summary line
#
# Notes:
#   - --raw prints Ghidra's default op.toString() lines (least readable, most literal)
#   - --high tries to print "high" pcode (may be unavailable depending on analysis state)
#
import sys

# make IDE register built ins
try:
    from ghidra.ghidra_builtins import *
    from ghidra.program.model.listing import *
    from ghidra.util.task import *

    currentProgram = currentProgram  # type: Program
    monitor = monitor  # type: TaskMonitor
except:
    pass

from ghidra.program.model.listing import Instruction, Function
from ghidra.program.model.pcode import PcodeOp, Varnode
from ghidra.util.task import ConsoleTaskMonitor

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()
monitor = ConsoleTaskMonitor()


def _find_function_by_name(func_name: str) -> Function:
    f = getFunction(func_name)
    if f:
        return f

    for it in currentProgram.getFunctionManager().getFunctions(True):
        it = it  # type: Function
        # allow substring match for convenience
        if func_name in it.getName():
            return it
    return None


def _space_from_spaceid(spaceid_const: Varnode):
    """
    LOAD/STORE take an address space id as input(0), encoded as a constant.
    """
    try:
        sid = int(spaceid_const.getOffset())
        return currentProgram.getAddressFactory().getAddressSpace(sid)
    except Exception:
        return None


def _fmt_addr(addr):
    # For segmented addresses, Address.toString() is usually the best "seg:off" form.
    try:
        return addr.toString()
    except Exception:
        return "0x%x" % addr.getOffset()


def _fmt_varnode(vn: Varnode) -> str:
    if vn is None:
        return "<none>"

    if vn.isConstant():
        # show size to disambiguate trunc/extend patterns
        return "0x%x:%d" % (vn.getOffset(), vn.getSize())

    if vn.isRegister():
        reg = currentProgram.getLanguage().getRegister(vn.getAddress(), vn.getSize())
        if reg is not None:
            return reg.getName()
        return "reg@%s:%d" % (_fmt_addr(vn.getAddress()), vn.getSize())

    addr = vn.getAddress()
    space = addr.getAddressSpace()
    spname = space.getName()

    if spname == "unique":
        return "u_%x:%d" % (addr.getOffset(), vn.getSize())

    if spname == "stack":
        off = addr.getOffset()
        # Try to make stack offsets look like typical BP/SP-relative notation.
        # Ghidra stack offsets are usually signed-ish; render as signed 32-bit if large.
        if off & (1 << 63):
            # shouldn't happen, but keep sane
            soff = off - (1 << 64)
        else:
            # Heuristic: if it looks like a 16-bit signed stack offset, sign it.
            soff = off if off < 0x8000 else off - 0x10000
        sign = "+" if soff >= 0 else "-"
        return "stack[%s0x%x]:%d" % (sign, abs(int(soff)), vn.getSize())

    # default: memory space like ram, register space already handled
    return "%s:%s:%d" % (spname, _fmt_addr(addr), vn.getSize())


def _is_flag_reg(vn: Varnode) -> bool:
    if vn is None or not vn.isRegister():
        return False
    reg = currentProgram.getLanguage().getRegister(vn.getAddress(), vn.getSize())
    if reg is None:
        return False
    return reg.getName() in ("CF", "ZF", "SF", "OF", "PF", "AF")


def _userop_name(op: PcodeOp) -> str:
    # CALLOTHER input(0) is the userop id constant
    try:
        userop = op.getInput(0)
        if userop is None or not userop.isConstant():
            return None
        idx = int(userop.getOffset())
        return currentProgram.getLanguage().getUserDefinedOpName(idx)
    except Exception:
        return None


def _fmt_op_pretty(op: PcodeOp) -> str:
    """
    Produce a compact, readable one-liner for a PcodeOp without losing structure.
    """
    mnem = op.getMnemonic()

    out = op.getOutput()
    out_s = _fmt_varnode(out) if out is not None else None

    # Special cases first
    if mnem in ("LOAD", "STORE"):
        # inputs: [spaceid], [ptr], (value for STORE)
        space = _space_from_spaceid(op.getInput(0))
        spname = space.getName() if space else "spaceid(%s)" % _fmt_varnode(op.getInput(0))
        ptr = _fmt_varnode(op.getInput(1))
        if mnem == "LOAD":
            return "%s = *(%s)[%s]" % (out_s, spname, ptr)
        val = _fmt_varnode(op.getInput(2))
        return "*(%s)[%s] = %s" % (spname, ptr, val)

    if mnem == "CALLOTHER":
        nm = _userop_name(op)
        args = []
        for i in range(1, op.getNumInputs()):
            args.append(_fmt_varnode(op.getInput(i)))
        call = "CALLOTHER(%s)" % (nm if nm else _fmt_varnode(op.getInput(0)))
        if out_s:
            return "%s = %s(%s)" % (out_s, call, ", ".join(args))
        return "%s(%s)" % (call, ", ".join(args))

    if mnem in ("BRANCH", "CBRANCH", "CALL", "CALLIND", "RETURN"):
        args = [_fmt_varnode(op.getInput(i)) for i in range(op.getNumInputs())]
        if out_s:
            return "%s = %s %s" % (out_s, mnem, ", ".join(args))
        return "%s %s" % (mnem, ", ".join(args))

    if mnem == "SUBPIECE":
        # show as x[lo..] extraction-ish
        src = _fmt_varnode(op.getInput(0))
        lo = op.getInput(1)
        lo_s = _fmt_varnode(lo)
        return "%s = SUBPIECE(%s, %s)" % (out_s, src, lo_s)

    if mnem == "COPY":
        return "%s = %s" % (out_s, _fmt_varnode(op.getInput(0)))

    # Generic: out = MNEM(in0, in1, ...)
    ins = [_fmt_varnode(op.getInput(i)) for i in range(op.getNumInputs())]
    if out_s:
        return "%s = %s(%s)" % (out_s, mnem, ", ".join(ins))
    return "%s(%s)" % (mnem, ", ".join(ins))


def dump_instr_pcode(instr: Instruction, use_high: bool, raw: bool, no_flags: bool):
    print("  %-12s %s" % (instr.getAddress(), instr.toString()))

    if use_high:
        try:
            pcode = instr.getPcode(True)   # type: ignore[arg-type]
        except Exception:
            # Some builds don't expose getPcode(True) or require different state;
            # fall back to low pcode.
            pcode = instr.getPcode()
    else:
        pcode = instr.getPcode()

    if raw:
        for op in pcode:
            print("      %s" % op)
        return

    # Pretty mode: compact flag noise without dropping it unless --no-flags
    flag_ops = []
    main_ops = []

    for op in pcode:
        out = op.getOutput()
        if out is not None and _is_flag_reg(out):
            flag_ops.append(op)
        else:
            main_ops.append(op)

    for op in main_ops:
        print("      %s" % _fmt_op_pretty(op))

    if not no_flags and flag_ops:
        # Single summary line; still explicit about values.
        parts = []
        for op in flag_ops:
            out = _fmt_varnode(op.getOutput())
            parts.append("%s=%s" % (out, _fmt_op_pretty(op).split(" = ", 1)[1] if " = " in _fmt_op_pretty(op) else _fmt_op_pretty(op)))
        print("      ; flags: " + ", ".join(parts))


def dump_function_pcode(func: Function, use_high: bool, raw: bool, no_flags: bool):
    print("=== FUNCTION %s @ %s ===" % (func.getName(), func.getEntryPoint()))
    body = func.getBody()
    instr_iter = listing.getInstructions(body, True)
    for instr in instr_iter:
        dump_instr_pcode(instr, use_high=use_high, raw=raw, no_flags=no_flags)


def main():
    args = list(getScriptArgs())
    if len(args) < 1:
        print("Usage: DumpFunctionPcode.py <function_name> [--high] [--raw] [--no-flags]")
        sys.exit(1)

    func_name = args[0]
    flags = set(args[1:])

    use_high = "--high" in flags
    raw = "--raw" in flags
    no_flags = "--no-flags" in flags

    func = _find_function_by_name(func_name)
    if not func:
        print("Function not found: " + func_name)
        sys.exit(1)

    dump_function_pcode(func, use_high=use_high, raw=raw, no_flags=no_flags)


main()
