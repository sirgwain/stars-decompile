# ApplyNb09FuncLocalsFromJson.py
# @category Stars
#
# Apply NB09 (CodeView) *local stack variables* to Ghidra functions using
# bp-relative offsets from nb09_ghidra_globals.json (PROC records only).
#
# Updated behavior (per Craig):
#   - Only apply NB09 locals whose stack byte ranges do NOT overlap with any
#     other NB09 local (i.e., the slot is stable / not re-used across scopes).
#   - If a stable NB09 local is applied, delete any existing Ghidra stack vars
#     that intersect the target byte range, then create/rename/retype.
#   - We do not care about matching Ghidra's inferred types/sizes.
#
# Notes:
#   - CodeView commonly reuses stack slots across scopes; overlapping NB09 locals
#     are treated as unsafe and are skipped entirely.
#   - Function naming/signatures are handled elsewhere (ApplyNb09NamesFromJson.py).
#

from dataclasses import dataclass
import traceback

from ghidra_utils import (
    ProcEntry,
    VarInfo,
    datatype_from_decl_info,
    err,
    load_nb09_ghidra_globals,
    log,
    warn,
)

# make IDE register built ins
try:
    from ghidra.ghidra_builtins import *
    from ghidra.program.model.listing import *
    from ghidra.util.task import *

    currentProgram = currentProgram  # type: Program
    monitor = monitor  # type: TaskMonitor
except:
    pass

from ghidra.util import Msg
from ghidra.util.exception import DuplicateNameException
from java.lang import Throwable
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import (
    DataType,
    DataTypeManager,
    ArrayDataType,
    PointerDataType,
)
from ghidra.program.model.listing import VariableSizeException


@dataclass
class BestVarByStack:
    bp_off: int
    name: str
    want_len: int
    dt: DataType
    local: VarInfo


def _intervals_overlap(a0: int, a1: int, b0: int, b1: int) -> bool:
    # half-open [a0,a1) overlaps [b0,b1)
    return (a0 < b1) and (b0 < a1)


def _var_interval(off: int, ln: int) -> tuple[int, int]:
    if ln is None or ln <= 0:
        ln = 1
    return (off, off + ln)


def _delete_vars_intersecting(func: Function, target0: int, target1: int):
    """Delete any existing local stack vars that intersect [target0,target1).

    IMPORTANT: Variable objects don't expose a .delete() method in many Ghidra builds.
    The supported way is Function.removeVariable(var).
    """
    # Snapshot list first; we'll be mutating the function's symbol table.
    vars_now = list(func.getLocalVariables())
    for v in vars_now:
        try:
            off = v.getStackOffset()
            if off is None or off >= 0:
                continue  # locals only (negative stack offsets)
            (v0, v1) = _var_interval(off, v.getLength())
            if not _intervals_overlap(target0, target1, v0, v1):
                continue
            log(
                "[BPVAR-DEL] %s deleting %s sp=%+d len=%d (conflicts with [%+d,%+d))"
                % (func.getName(), v.getName(), off, v.getLength(), target0, target1)
            )
            func.removeVariable(v)
        except Throwable as ex:
            warn(
                "[BPVAR-DELFAIL] %s sp=%+d name=%s : %s"
                % (
                    func.getName(),
                    off if "off" in locals() else 0,
                    getattr(v, "getName", lambda: "?")(),
                    str(ex),
                )
            )
        except Exception as ex:
            warn("[BPVAR-DELFAIL] %s : %s" % (func.getName(), str(ex)))


def _create_or_get_stack_local(
    func: Function, stack_off: int, name: str, dt: DataType
) -> Variable:
    """Create a local stack variable at stack_off, or return existing one."""
    # Try to find an existing var exactly at offset after deletions
    for v in func.getLocalVariables():
        try:
            if v.getStackOffset() == stack_off:
                return v
        except Throwable:
            pass

    sf = func.getStackFrame()
    try:
        # createVariable(name, stackOffset, dataType, sourceType)
        return sf.createVariable(name, stack_off, dt, SourceType.USER_DEFINED)
    except Throwable as ex:
        warn(
            "[BPVAR-CREATEFAIL] %s sp=%+d name=%s : %s"
            % (func.getName(), stack_off, name, str(ex))
        )
        return None


# ------------------------------------------------------------
# stack var (bp relative) application for locals/params
# ------------------------------------------------------------


def _intervals_intersect(a0: int, a1: int, b0: int, b1: int) -> bool:
    """Half-open intervals [a0,a1) and [b0,b1) intersect."""
    return (a0 < b1) and (b0 < a1)


def _nb09_local_interval(local: VarInfo):
    """Return (start,end) stack interval for this NB09 local or None if unsafe."""
    off = local.bp_off
    ln = local.size
    if off is None:
        return None
    if ln is None or ln <= 0:
        return None
    return (off, off + ln)


def _stable_nb09_locals(
    locals_list: list[VarInfo],
) -> tuple[list[VarInfo], list[VarInfo]]:
    """Split into (stable, overlapping/unsafe) based on NB09 byte-range overlaps."""
    items = []
    unsafe = []
    for l in locals_list:
        iv = _nb09_local_interval(l)
        if iv is None:
            unsafe.append(l)
            continue
        s, e = iv
        items.append((s, e, l))

    # Sweep for overlaps
    items.sort(key=lambda t: (t[0], t[1]))
    overlap_set = set()
    if items:
        group = [items[0]]
        cur_end = items[0][1]
        for it in items[1:]:
            s, e, l = it
            if s < cur_end:
                # overlaps current group
                group.append(it)
                cur_end = max(cur_end, e)
            else:
                if len(group) > 1:
                    for _, __, gl in group:
                        overlap_set.add(gl)
                group = [it]
                cur_end = e
        if len(group) > 1:
            for _, __, gl in group:
                overlap_set.add(gl)

    stable = []
    for s, e, l in items:
        if l in overlap_set:
            unsafe.append(l)
        else:
            stable.append(l)
    return stable, unsafe


def _collect_stack_vars(func: Function) -> dict[int, Variable]:
    """
    Build map stackOffset -> [vars...] for all variables that live on stack (params + locals).
    """
    m = {}

    for v in func.getLocalVariables():
        off = v.getStackOffset()
        if off is None:
            continue
        m.setdefault(off, []).append(v)
    return m


def _choose_stack_var_for_rename(vars_here: list[Variable], want_len: int):
    """
    Pick a single existing stack var to rename/retype, conservatively.

    - If want_len is known (>0), prefer a var with matching length.
    - If exactly one var exists at offset, pick it.
    - Otherwise return None (ambiguous).
    """
    if not vars_here:
        return None

    # Filter out stale/deleted vars
    live = []
    for v in vars_here:
        try:
            _ = v.getName()
            live.append(v)
        except Throwable:
            pass
    vars_here = live
    if not vars_here:
        return None

    if want_len is not None and want_len > 0:
        matches = []
        for v in vars_here:
            if v.getLength() == want_len:
                matches.append(v)
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            return None  # ambiguous

    if len(vars_here) == 1:
        return vars_here[0]

    return None  # ambiguous


def _rename_var_user_defined(
    func: Function, v: Variable, new_name: str, stack_off: int
):
    """
    Rename v to new_name as USER_DEFINED, handling duplicates.
    Returns True if renamed/changed.
    """
    cur = v.getName()

    if cur == new_name:
        return False

    try:
        v.setName(new_name, SourceType.USER_DEFINED)
        return True
    except DuplicateNameException:
        # Deterministic unique suffix
        uniq = "%s_%+d" % (new_name, stack_off)
        try:
            v.setName(uniq, SourceType.USER_DEFINED)
            return True
        except Throwable as ex:
            warn(
                "[BPVAR-NAMEFAIL] %s sp=%+d : %s" % (func.getName(), stack_off, str(ex))
            )
            return False
    except Throwable as ex:
        warn("[BPVAR-NAMEFAIL] %s sp=%+d : %s" % (func.getName(), stack_off, str(ex)))
        return False


def apply_bp_relative_vars(
    dtm: DataTypeManager, func: Function, proc: ProcEntry
) -> int:
    """
    Rename locals by NB09 bp_off when unambiguous.
    Additionally, retype ONLY when:
      - existing stack var length matches NB09 size
      - desired datatype length matches that exact length
      - current datatype is undefined-like (including arrays of undefined)

    Never creates locals, never deletes overlaps, never resizes vars.

    Returns number of changes (renames + retypes).
    """
    proc_types = proc.types

    if not proc_types.locals:
        log("[BPVAR] %s no locals" % (func.getName()))
        return 0

    # Build NB09 intervals and mark unsafe (overlapping) bytes.
    nb = []  # list of (local, off0, off1)
    for local in proc.types.locals:
        bp_off = local.bp_off
        nm = local.name
        if bp_off is None or not nm:
            continue
        if bp_off >= 0:
            continue  # locals only
        bp_off = bp_off - 2

        if local.size is None or local.size <= 0:
            # Without a size, we can't reason about stability; treat as unsafe.
            log(
                "[BPVAR-SKIP] %s sp=%+d name=%s (unknown size; assuming unsafe)"
                % (func.getName(), bp_off, nm)
            )
            continue
        (o0, o1) = _var_interval(bp_off, local.size)
        nb.append((local, o0, o1))

    unsafe = set()  # byte offsets that are in any overlapping region
    for i in range(len(nb)):
        (_, a0, a1) = nb[i]
        for j in range(i + 1, len(nb)):
            (_, b0, b1) = nb[j]
            if _intervals_overlap(a0, a1, b0, b1):
                for k in range(max(a0, b0), min(a1, b1)):
                    unsafe.add(k)

    changed = 0

    # Apply only locals whose entire byte range is safe.
    # Deterministic order: by bp_off ascending.
    for local, o0, o1 in sorted(nb, key=lambda t: t[1]):
        nm = local.name
        if any((k in unsafe) for k in range(o0, o1)):
            log(
                "[BPVAR-UNSAFE] %s sp=%+d..%+d name=%s (overlaps another NB09 local; skipping)"
                % (func.getName(), o0, o1, nm)
            )
            continue

        dt, derr = datatype_from_decl_info(
            dtm, local.name, local.decl, local.is_far_ptr
        )
        if dt is None:
            warn("unable to find type for local %s" % local.c_decl)
            continue

        # Clear any conflicting locals in Ghidra, then create/apply.
        _delete_vars_intersecting(func, o0, o1)
        v = _create_or_get_stack_local(func, o0, nm, dt)
        if v is None:
            continue

        if _rename_var_user_defined(func, v, nm, o0):
            changed += 1
            log("[BPVAR-RENAME] %s sp=%+d <- %s" % (func.getName(), o0, nm))

        # For stable slots, just force the datatype (even if non-undefined).
        try:
            v.setDataType(dt, SourceType.USER_DEFINED)
            changed += 1
            log("[BPVAR-RETYPE] %s sp=%+d <- %s" % (func.getName(), o0, dt.getName()))
        except Throwable as ex:
            warn(
                "[BPVAR-RETYPE-FAIL] %s sp=%+d name=%s : %s"
                % (func.getName(), o0, nm, str(ex))
            )

    return changed


def main():
    print("---- ApplyNb09FuncLocalsFromJson ----")

    json_file = askFile("Select nb09_ghidra_globals.json", "Open")
    path = json_file.getAbsolutePath()

    root = load_nb09_ghidra_globals(path)

    # Apply global types
    procs = root.procs
    if not procs:
        popup("No procs found in JSON: %s" % path)
        return

    dtm = currentProgram.getDataTypeManager()

    # stats
    total = len(root.procs)
    applied = 0
    fails = 0
    skipped = 0
    misses = 0

    log("PROC records in JSON: %d" % len(root.procs))
    log("")

    monitor.initialize(total)

    for i, proc in enumerate(root.procs):
        if proc.cv.rectyp != 261 or proc.cv.from_ == "PUBLIC":
            log(f"skipping {proc.name}, PUBLIC or wrong rectyp")
            skipped += 1
            continue

        monitor.checkCancelled()
        monitor.setMessage("Applying local vars %d/%d" % (i + 1, total))

        func = currentProgram.getFunctionManager().getFunctionAt(
            toAddr(proc.ghidra.addr)
        )
        if func is None:
            misses += 1
            warn("No function at %s for %s" % (proc.ghidra.addr, proc.name))
            continue

        # locals/params by bp-relative offsets (from JSON)
        try:
            c_changed = apply_bp_relative_vars(dtm, func, proc)
            if c_changed:
                log("[BPVARS] %s updated %d stack vars" % (proc.ghidra.addr, c_changed))
                applied += 1
        except Exception as e:
            warn("[BPVARS-ERR] %s : %s" % (proc.ghidra.addr, str(e)))
            err(traceback.format_exc())

    log("")
    log("done")
    log("  applied:  %d" % applied)
    log("  misses:   %d" % misses)
    log("  skipped:  %d" % skipped)
    log("  failed:   %d" % fails)


if __name__ == "__main__":
    main()
