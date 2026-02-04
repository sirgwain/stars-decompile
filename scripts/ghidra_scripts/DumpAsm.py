# DumpAsm.py
# Ghidra script to dump assembly listing for a function (or all known procs) to .asm files.
#
# This variant emits "annotated asm" closer to Ghidra's Listing:
#  - function banner + prototype (when available)
#  - XREFs to entry point (calls/jumps)
#  - stack variables table (params + locals) pulled from the *decompiler* symbol map
#    (so you get dpBombs, pctCap, etc even if the function's stack frame isn't named)
#  - BP-relative stack refs rewritten to named vars
#  - synthetic LAB_<seg>_<off> labels for intra-function branch/call targets
#  - CALL/CALLF annotated with resolved callee names when possible
#
# Usage:
#   DumpAsm.py <function_name> [--out <path>]
#   DumpAsm.py --all [--globals <path>] [--out-dir <dir>]
#
# Defaults:
#   --out     decompiled/asm/<FuncName>.asm
#   --out-dir decompiled/asm
#   --globals scripts/nb09_ghidra_globals.json
#
# @category Stars

# make IDE register built ins
try:
    from ghidra.ghidra_builtins import *  # noqa: F401,F403
    from ghidra.program.model.listing import *  # noqa: F401,F403
    from ghidra.util.task import *  # noqa: F401,F403

    currentProgram = currentProgram  # type: Program  # noqa: F821
    monitor = monitor  # type: TaskMonitor  # noqa: F821
except Exception:
    pass

from ghidra.program.model.listing import Function, Instruction
from ghidra.program.model.symbol import SymbolType
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.address import Address
import os
import sys
import re

import ghidra_utils


def _find_function_by_name(func_name: str):
    f = getFunction(func_name)  # noqa: F821
    if f:
        return f

    fm = currentProgram.getFunctionManager()  # noqa: F821
    for it in fm.getFunctions(True):
        it = it  # type: Function
        if func_name in it.getName():  # allow partial match
            return it
    return None


def _sanitize_seg_folder(segname: str) -> str:
    if not segname:
        return "unknown"
    s = segname
    if s.startswith("MEMORY_"):
        s = s[len("MEMORY_") :]
    s = s.strip()
    out = []
    for ch in s:
        if ("a" <= ch <= "z") or ("A" <= ch <= "Z") or ("0" <= ch <= "9"):
            out.append(ch.lower())
        else:
            out.append("_")
    s2 = "".join(out).strip("_")
    return s2 or "unknown"


def _parse_out_path(args, func_name):
    out_path = None
    for i, a in enumerate(args):
        if a == "--out":
            if i + 1 >= len(args):
                raise ValueError("--out requires a path")
            out_path = args[i + 1]
            break
    if out_path:
        return out_path
    return os.path.join("decompiled", "asm", func_name + ".asm")


def _parse_kv_arg(args, key, default=None):
    for i, a in enumerate(args):
        if a == key:
            if i + 1 >= len(args):
                raise ValueError("%s requires a value" % key)
            return args[i + 1]
    return default


def _has_flag(args, key) -> bool:
    return key in args


def _primary_label_at(addr):
    st = currentProgram.getSymbolTable()  # noqa: F821
    sym = st.getPrimarySymbol(addr)
    if sym is None:
        return None
    try:
        if sym.getSymbolType() == SymbolType.LABEL:
            return sym.getName(True)
    except Exception:
        pass
    return sym.getName(True)


def _function_xrefs(func: Function):
    out = []
    try:
        rm = currentProgram.getReferenceManager()  # noqa: F821
        for r in rm.getReferencesTo(func.getEntryPoint()):
            try:
                rt = r.getReferenceType()
                if rt is None:
                    continue
                out.append((r.getFromAddress(), rt))
            except Exception:
                pass
    except Exception:
        pass
    return out


def _call_target_name(instr: Instruction):
    try:
        if not instr.getFlowType().isCall():
            return None
        dests = instr.getFlows()
        if not dests:
            return None
        dest = dests[0]
        f = getFunctionAt(dest)  # noqa: F821
        if f:
            return f.getName(True)
        return _primary_label_at(dest)
    except Exception:
        return None


# Match [BP +/- 0xNN] with common variations produced by operand renderers.
_RE_BP_DISP = re.compile(
    r"\[\s*(?:[A-Za-z]{2}:)?\s*BP\s*([+-])\s*([-]?)\s*(?:0x)?([0-9A-Fa-f]+)\s*(?:h)?\s*\]",
    re.IGNORECASE,
)


def _rewrite_bp_stackrefs(s: str, stackmap, force_off=None) -> str:
    def _sub(m):
        sign = m.group(1)
        neg = m.group(2)
        num = m.group(3)
        disp = int(num, 16)

        # Operand text sometimes uses "+ -0x1a". Treat that as negative.
        if sign == "-" or neg == "-":
            disp = -disp

        if force_off is not None and disp != int(force_off):
            return m.group(0)

        if disp in stackmap:
            return "[BP + %s]" % stackmap[disp]

        if disp < 0:
            return "[BP + -0x%x]" % (-disp)
        return "[BP + 0x%x]" % disp

    return _RE_BP_DISP.sub(_sub, s)


def _decompile_stack_symbols(func: Function):
    """
    Build:
      - stackmap: byte offset -> "name" or "name+0xN"
      - varinfo: list of dicts for table printing
    using the *decompiler* HighFunction symbol map.

    This is the key difference vs a plain stack frame query: it reflects
    what you see in the decompiler view (dpBombs, pctCap, etc).
    """
    stackmap = {}
    varinfo = []

    try:
        ifc = DecompInterface()
        # No need to open a special project; just attach the current program.
        ifc.openProgram(currentProgram)  # noqa: F821
        res = ifc.decompileFunction(func, 60, monitor)  # noqa: F821
        if not res or not res.decompileCompleted():
            return stackmap, varinfo

        hf = res.getHighFunction()
        if not hf:
            return stackmap, varinfo

        lsm = hf.getLocalSymbolMap()
        if not lsm:
            return stackmap, varinfo

        syms = list(lsm.getSymbols())
        for hs in syms:
            try:
                name = hs.getName()
                if not name:
                    continue

                storage = hs.getStorage()
                if not storage:
                    continue

                # Only rewrite stack-stored vars (BP/SP relative).
                if not storage.isStackStorage():
                    continue

                try:
                    off = int(storage.getStackOffset())
                except Exception:
                    continue

                # Variable size in bytes; may be 0 for some symbols.
                try:
                    size = int(storage.size())
                except Exception:
                    size = 0

                # Data type display name (best effort)
                ty = ""
                try:
                    dt = hs.getDataType()
                    if dt:
                        ty = dt.getDisplayName()
                except Exception:
                    pass

                varinfo.append({"off": off, "size": size, "name": name, "ty": ty})

                if size <= 0:
                    stackmap[off] = name
                    continue

                for delta in range(size):
                    o2 = off + delta
                    if delta == 0:
                        stackmap[o2] = name
                    else:
                        stackmap[o2] = "%s+0x%x" % (name, delta)
            except Exception:
                pass

        # Stable sort for table: params (positive) then locals (negative), by offset
        varinfo.sort(key=lambda d: (0 if d["off"] >= 0 else 1, d["off"]))
        return stackmap, varinfo
    except Exception:
        return stackmap, varinfo


def _make_synth_label(addr: Address) -> str:
    # addr string is like "1038:0b70" on x86:16.
    s = str(addr)
    s = s.replace(":", "_")
    return "LAB_" + s


def _build_intra_function_labels(func: Function):
    """
    Build a map Address->label_name for branch destinations within the function body.

    Ghidra's listing doesn't always have explicit label symbols for these targets;
    the decompiler invents LAB_... names. We do the same so the asm dump has labels.
    """
    listing = currentProgram.getListing()  # noqa: F821
    body = func.getBody()
    labels = {}

    it = listing.getInstructions(body, True)
    for instr in it:
        try:
            ft = instr.getFlowType()
            if not (ft.isJump() or ft.isConditional() or ft.isCall()):
                continue

            flows = instr.getFlows()
            if not flows:
                continue

            for dest in flows:
                if dest is None:
                    continue
                if not body.contains(dest):
                    continue

                # If the program already has a real label at dest, prefer it.
                real = _primary_label_at(dest)
                if real:
                    labels[dest] = real
                else:
                    if dest not in labels:
                        labels[dest] = _make_synth_label(dest)
        except Exception:
            pass

    return labels


def _format_instr(instr: Instruction, stackmap, labelmap) -> (str, str):
    """
    Returns (asm_text, extra_comment) where extra_comment may contain resolved symbols.
    """
    mnem = instr.getMnemonicString()
    extra = []

    nops = instr.getNumOperands()
    if nops <= 0:
        return mnem, ""

    ops = []
    for i in range(nops):
        op_txt = instr.getDefaultOperandRepresentation(i)

        # Prefer explicit references when available.
        try:
            refs = instr.getOperandReferences(i)
        except Exception:
            refs = None

        # 1) Rewrite flow targets to labels (jmp/call dests).
        if refs:
            for r in refs:
                try:
                    to = r.getToAddress()
                    if to and (to in labelmap):
                        op_txt = labelmap[to]
                        break
                except Exception:
                    pass

        # 2) Rewrite stack refs via explicit stack offset.
        if refs:
            for r in refs:
                try:
                    if r.isStackReference():
                        off = int(r.getStackOffset())
                        op_txt = _rewrite_bp_stackrefs(op_txt, stackmap, force_off=off)
                        break
                except Exception:
                    pass

        # 3) Fallback: generic textual rewrite for BP forms.
        op_txt = _rewrite_bp_stackrefs(op_txt, stackmap)

        # 4) If operand is a direct data reference, add a symbol hint.
        if refs:
            for r in refs:
                try:
                    if r.isMemoryReference() and (not r.isStackReference()):
                        to = r.getToAddress()
                        if to:
                            sym = _primary_label_at(to)
                            if sym and sym not in extra:
                                extra.append(sym)
                except Exception:
                    pass

        ops.append(op_txt)

    asm = mnem + " " + ", ".join(ops)
    return asm, (" ; refs: " + ", ".join(extra)) if extra else ""


def _dump_function(func: Function, out_path: str):
    listing = currentProgram.getListing()  # noqa: F821
    start = func.getEntryPoint()

    stackmap, varinfo = _decompile_stack_symbols(func)
    labelmap = _build_intra_function_labels(func)

    out_dir = os.path.dirname(out_path)
    if out_dir and not os.path.isdir(out_dir):
        os.makedirs(out_dir)

    with open(out_path, "w") as f:
        f.write("; ------------------------------------------------------------\n")
        f.write("; Function: %s\n" % func.getName())
        f.write("; Entry:    %s\n" % start)
        try:
            f.write("; Prototype:%s\n" % func.getPrototypeString(False, False))
        except Exception:
            pass
        f.write("; Program:  %s\n" % currentProgram.getName())  # noqa: F821
        f.write("; ------------------------------------------------------------\n\n")

        f.write("                             **************************************************************\n")
        f.write("                             *                          FUNCTION                          *\n")
        f.write("                             **************************************************************\n")
        try:
            sig = func.getPrototypeString(True, True)
            f.write("                               %s\n" % sig)
        except Exception:
            pass

        # XREFs to this function
        xrefs = _function_xrefs(func)
        if xrefs:
            xrefs = sorted(xrefs, key=lambda t: str(t[0]))
            f.write("                             %s                             XREF[%d]:\n" % (func.getName(True), len(xrefs)))
            for (fa, rt) in xrefs[:16]:
                try:
                    caller = getFunctionContaining(fa)  # noqa: F821
                    if caller:
                        f.write("                                                                                          %s:%s(%s)\n" % (caller.getName(True), fa, rt))
                    else:
                        f.write("                                                                                          %s(%s)\n" % (fa, rt))
                except Exception:
                    pass
        f.write("\n")

        # Stack symbol table (from decompiler)
        if varinfo:
            for v in varinfo:
                off = int(v["off"])
                size = int(v["size"]) if v["size"] is not None else 0
                ty = v["ty"] or ""
                name = v["name"] or ""
                if off < 0:
                    f.write("             %-18s Stack[-0x%x]:%d  %-36s\n" % (ty, -off, size, name))
                else:
                    f.write("             %-18s Stack[0x%x]:%d   %-36s\n" % (ty, off, size, name))
            f.write("\n")

        # Entry label
        f.write("%s:\n" % func.getName())

        # Body
        it = listing.getInstructions(func.getBody(), True)
        for instr in it:
            addr = instr.getAddress()
            addr_str = str(addr)

            # Emit a label line if this address is a jump target label.
            if addr in labelmap and labelmap[addr] != func.getName():
                f.write("%s:\n" % labelmap[addr])

            asm, extra = _format_instr(instr, stackmap, labelmap)

            callee = _call_target_name(instr)
            if callee:
                f.write("    %-40s ; %s  CALL %s%s\n" % (asm, addr_str, callee, extra))
            else:
                f.write("    %-40s ; %s%s\n" % (asm, addr_str, extra))


def _get_function_for_proc(proc):
    # 1) Prefer exact name lookup
    f = getFunction(proc.name)  # noqa: F821
    if f:
        return f

    # 2) Fall back to address lookup ("1058:8c5a")
    try:
        af = currentProgram.getAddressFactory()  # noqa: F821
        addr = af.getAddress(proc.ghidra.addr)
        if addr:
            f2 = getFunctionAt(addr)  # noqa: F821
            if f2:
                return f2
    except Exception:
        pass

    return None


def _usage():
    print("Usage: DumpAsm.py <function_name> [--out <path>]")
    print("   or: DumpAsm.py --all [--globals <path>] [--out-dir <dir>]")
    print("")
    print("Defaults:")
    print("  --out     decompiled/asm/<FuncName>.asm")
    print("  --out-dir decompiled/asm")
    print("  --globals scripts/nb09_ghidra_globals.json")


def main():
    args = list(getScriptArgs())  # noqa: F821
    if len(args) < 1:
        _usage()
        sys.exit(1)

    if _has_flag(args, "--all"):
        try:
            globals_path = _parse_kv_arg(args, "--globals", os.path.join("scripts", "nb09_ghidra_globals.json"))
            out_dir = _parse_kv_arg(args, "--out-dir", os.path.join("decompiled", "asm"))
            nb = ghidra_utils.load_nb09_ghidra_globals(globals_path)
        except Exception as e:
            print("Argument/load error: " + str(e))
            _usage()
            sys.exit(1)

        wrote = 0
        skipped = 0
        missing = 0

        for proc in nb.procs:
            # Skip helper/compiler stubs and other PUBLIC exports
            try:
                if (proc.cv is not None) and (proc.cv.from_ == "PUBLIC"):
                    skipped += 1
                    continue
            except Exception:
                pass

            func = _get_function_for_proc(proc)
            if not func:
                missing += 1
                continue

            seg_folder = _sanitize_seg_folder(proc.segmap.segname)
            out_path = os.path.join(out_dir, seg_folder, proc.name + ".asm")
            _dump_function(func, out_path)
            wrote += 1

        print("[ASM] wrote %d functions into %s (skipped PUBLIC=%d, missing=%d)" % (wrote, out_dir, skipped, missing))
        return

    # Single function mode
    func_name = args[0]
    try:
        out_path = _parse_out_path(args[1:], func_name)
    except Exception as e:
        print("Argument error: " + str(e))
        _usage()
        sys.exit(1)

    func = _find_function_by_name(func_name)
    if not func:
        print("Function not found: " + func_name)
        sys.exit(1)

    _dump_function(func, out_path)
    print("[ASM] wrote %s" % out_path)


if __name__ == "__main__":
    main()
