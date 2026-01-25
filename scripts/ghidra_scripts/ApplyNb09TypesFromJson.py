# -*- coding: utf-8 -*-
# ApplyNb09TypesFromJson.py
# @category Stars


from java.math import BigInteger

# make IDE register built ins
try:
    from ghidra.ghidra_builtins import *
    from ghidra.program.model.listing import *

    currentProgram = currentProgram  # type: Program
except:
    pass

from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.address import Address
from ghidra.program.model.data import (
    DataTypeManager,
    DataType,
    DataUtilities,
    FunctionDefinitionDataType,
    VoidDataType,
    Undefined2DataType,
    ParameterDefinitionImpl,
)


from ghidra_utils import (
    ProcEntry,
    datatype_from_decl_info,
    load_nb09_ghidra_globals,
    sanitize_name,
    dedupe_name,
    warn,
    log,
)


def _force_clear_and_create(listing: Listing, addr: Address, dt: DataType):
    """UI-style overwrite: clear any overlapping code/data, then create dt."""
    dt_len = dt.getLength()
    if dt_len <= 0:
        raise ValueError("datatype length is 0")
    end = addr.add(dt_len - 1)

    # If a conflicting unit starts before addr but overlaps (e.g. a string),
    # we must clear the *entire* containing units.
    try:
        cu0 = listing.getCodeUnitContaining(addr)
        clr_start = cu0.getMinAddress() if cu0 is not None else addr
    except Exception:
        clr_start = addr
    try:
        cu1 = listing.getCodeUnitContaining(end)
        clr_end = cu1.getMaxAddress() if cu1 is not None else end
    except Exception:
        clr_end = end

    try:
        listing.clearCodeUnits(clr_start, clr_end, False)
    except Exception:
        # Fallback to the minimal range
        listing.clearCodeUnits(addr, end, False)

    DataUtilities.createData(
        currentProgram,
        addr,
        dt,
        -1,
        False,
        DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA,
    )


def _parse_seg_selector(addr_s):
    # "1038:7fe6" -> 0x1038
    try:
        return int(addr_s.split(":")[0], 16)
    except:
        return None


def set_cs_at_function_entry(func):
    """Set CS register context at the function entry to the entry segment selector."""
    entry = func.getEntryPoint()
    seg = _parse_seg_selector(entry.toString())
    if seg is None:
        warn(f"{func.getName()} seg selector for entry {entry.toString()} is empty")
        return False

    reg = currentProgram.getRegister("CS")
    if reg is None:
        warn("CS register not found")
        return False

    ctx = currentProgram.getProgramContext()
    # Apply only at the entry point; keep the range minimal to avoid stepping
    # on other context propagation.
    ctx.setValue(reg, entry, func.getBody().getMaxAddress(), BigInteger.valueOf(seg))    
    return True


def calling_convention_for(proc: ProcEntry):
    if proc.types.is_pascal:
        return "__pascal16far"
    return "__cdecl16far"


def build_function_def(
    dtm: DataTypeManager, name: str, proc: ProcEntry, cc_name: str
) -> FunctionDefinitionDataType:
    """
    Build a FunctionDefinitionDataType for ApplyFunctionSignatureCmd.
    """
    fdef = FunctionDefinitionDataType(name)
    fdef.setCallingConvention(cc_name)
    println(f"setting calling convetion: {cc_name}")

    # return
    ret = proc.types.ret
    ret_dt = ret.base_dt
    if ret_dt is None:
        ret_dt, err = datatype_from_decl_info(dtm, "", ret.decl, ret.is_far_ptr)
        if ret_dt is None:
            warn(
                "Unknown return type '%s' for %s err=%s; using void"
                % (ret.c_type, name, err)
            )
            ret_dt = VoidDataType()
    fdef.setReturnType(ret_dt)

    # params
    params = []
    for p in proc.types.params:
        p_dt = p.base_dt
        if p_dt is None:
            p_dt, err = datatype_from_decl_info(dtm, p.name, p.decl, p.is_far_ptr)
            if p_dt is None:
                warn(
                    "Unknown param type '%s' for %s(%s) err = %s; using undefined2"
                    % (p.c_type, name, p.name, err)
                )
                p_dt = Undefined2DataType()
        params.append(ParameterDefinitionImpl(p.name, p_dt, None))
    if proc.types.is_pascal:
        # pascal args are reversed
        params.reverse()
    fdef.setArguments(params)
    return fdef


def apply_signature(func: Function, fdef: FunctionDefinitionDataType, cc_name: str):
    """
    Apply signature with dynamic storage, and force custom storage OFF.
    """
    # Apply signature command (handles params/return dt, names)
    cmd = ApplyFunctionSignatureCmd(func.getEntryPoint(), fdef, SourceType.USER_DEFINED)
    ok = cmd.applyTo(currentProgram, monitor)
    if not ok:
        return False, "ApplyFunctionSignatureCmd failed"

    # Force calling convention
    func.setCallingConvention(cc_name)

    # Force dynamic storage / custom storage off
    func.setCustomVariableStorage(False)

    return True, None


def main():
    print("---- ApplyNb09TypesFromJson ----")

    json_file = askFile("Select nb09_ghidra_globals.json", "Open")
    path = json_file.getAbsolutePath()

    root = load_nb09_ghidra_globals(path)

    # Apply global types
    if not root.globals or not root.procs:
        popup("No globals or procs found in JSON: %s" % path)
        return

    symtab = currentProgram.getSymbolTable()
    listing = currentProgram.getListing()
    dtm = currentProgram.getDataTypeManager()

    typed = 0
    type_ok = 0
    type_failed = 0

    for rec in root.globals:
        name = rec.name
        gh = rec.ghidra
        addr_str = gh.addr
        default_label = gh.default_label

        if not addr_str:
            print("[TYPE-FAIL] %s: missing ghidra.addr" % name)
            type_failed += 1
            continue

        try:
            addr: Address = toAddr(addr_str)
        except Exception as e:
            print("[TYPE-FAIL] %s @ %s: bad addr (%s)" % (name, addr_str, str(e)))
            type_failed += 1
            continue

        # ----- Label -----
        sym = symtab.getPrimarySymbol(addr)
        desired = sanitize_name(name, default_label)
        desired = dedupe_name(symtab, desired, addr)

        if sym is None:
            print("[LABEL-FAIL] %s @ %s: no existing symbol" % (desired, addr_str))
            continue

        # ----- Type -----
        dt, err = datatype_from_decl_info(dtm, rec.name, rec.types.decl, rec.types.is_far_ptr)
        if dt is None:
            print("[TYPE-FAIL] %s @ %s unable to resolve DataType, err=%s" % (name, addr_str, err))
            type_failed += 1
            continue

        try:
            d = listing.getDataAt(addr)
            if d is None:
                print("[TYPE-SKIP] %s @ %s: no data" % (name, addr_str))
                continue

            cur_dt = d.getDataType()
            if cur_dt.getName() == dt.getName():
                print("[TYPE-OK]   %s @ %s (%s)" % (name, addr_str, dt.getName()))
                type_ok += 1
            else:
                _force_clear_and_create(listing, addr, dt)
                if cur_dt is not None:
                    print(
                        "[TYPE-SET]  %s @ %s := %s (was %s)"
                        % (name, addr_str, dt.getName(), cur_dt.getName())
                    )
                else:
                    print("[TYPE-SET]  %s @ %s := %s" % (name, addr_str, dt.getName()))
                typed += 1
        except Exception as e:
            msg = str(e)
            if "datatype length is 0" in msg:
                print("[TYPE-SKIP] %s @ %s: datatype length is 0" % (name, addr_str))
            else:
                print("[TYPE-FAIL] %s @ %s: apply failed (%s)" % (name, addr_str, msg))
                type_failed += 1

    # Apply func sigs
    funcs = 0
    func_fails = 0
    func_skips = 0
    cs_set = 0

    for proc in root.procs:
        if proc.cv.from_ == "PUBLIC":
            # skip external references like __aFulMul
            log(f"skipping PUBLIC func {proc.name}")
            func_skips += 1
            continue
        func = currentProgram.getFunctionManager().getFunctionAt(
            toAddr(proc.ghidra.addr)
        )
        if func is None:
            warn("no func at %s" % proc.ghidra.addr)
            func_skips += 1
            continue
        if set_cs_at_function_entry(func):
            cs_set += 1

        cc_name = calling_convention_for(proc)
        fdef = build_function_def(dtm, name, proc, cc_name)
        ok, why = apply_signature(func, fdef, cc_name)
        if ok:
            funcs += 1
            log("[APPLY] %s <- %s  cc=%s" % (addr_str, proc.types.proto, cc_name))
        else:
            fails += 1
            err("[FAIL]  %s @ %s : %s" % (name, addr_str, why))

    print("---- ApplyNb09TypesFromJson summary ----")
    print("Globals processed : %d" % len(root.globals))
    print("Types set         : %d" % typed)
    print("Types already ok  : %d" % type_ok)
    print("Types failed      : %d" % funcs)
    print("Funcs processed   : %d" % len(root.procs))
    print("Funcs skipped     : %d" % func_skips)
    print("Func sigs applied : %d" % func_fails)
    print("CS on entry       : %d" % cs_set)
    print("----------------------------------------")


if __name__ == "__main__":
    main()
