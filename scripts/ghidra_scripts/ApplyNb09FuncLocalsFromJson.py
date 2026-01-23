# ApplyNb09FuncLocalsFromJson.py
# @category Stars
#
# Apply NB09 (CodeView) *local stack variables* to Ghidra functions using
# bp-relative offsets from nb09_ghidra_globals.json (PROC records only).
#
# What it does:
#   - For each function with a PROC record, matches NB09 locals to existing
#     Ghidra stack vars by stack offset (stack_off = bp_off - 2).
#   - Renames the chosen stack var to the NB09 name (USER_DEFINED).
#   - Retypes only when it is safe:
#       * current type is undefined-like (undefined*, arrays of undefined, etc.)
#       * NB09 size matches the stack var length exactly
#       * desired datatype length matches exactly
#
# What it does NOT do:
#   - Does not create new stack vars, resize vars, or delete overlaps.
#   - Skips ambiguous offsets (multiple vars at same offset with no unique match).
#
# Notes:
#   - CodeView commonly reuses stack slots across scopes; we select one “best”
#     NB09 local per stack slot (prefer larger/known sizes).
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


# ------------------------------------------------------------
# stack var (bp relative) application for locals/params
# ------------------------------------------------------------


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


def _is_undefined_like_datatype(dt: DataType):
    """
    True if dt is undefined/unknown-ish, including arrays of undefined.
    We key off the datatype name because exact classes vary by Ghidra version.
    """
    if dt is None:
        return True
    while isinstance(dt, ArrayDataType) or isinstance(dt, PointerDataType):
        dt = dt.getDataType()

    return dt.getName().lower().startswith("undefined")


def _maybe_retype_stack_var(
    func: Function,
    name: str,
    v: Variable,
    desired_dt: DataType,
    want_len: int,
    stack_off: int,
    is_far_ptr
):
    """
    Retype v to desired_dt ONLY if:
      - current dt is undefined-like
      - v.getLength == want_len (if provided)
      - desired_dt.getLength == v.getLength
    Returns True if changed.
    """
    if desired_dt is None:
        return False

    v_len = v.getLength()

    if want_len is not None and want_len > 0 and v_len != want_len:
        log(
            "[BPVAR-RETYPE] skip %s:%s sp=%+d %s v_dt=%s v_len=%d want_len=%d"
            % (
                func.getName(),
                name,
                stack_off,
                desired_dt.getName(),
                v.getDataType().getName(),
                v_len,
                want_len,
            )
        )
        return False
    
    # ghidra automatically makes pointer DataType.getLength() return 4
    if isinstance(desired_dt, PointerDataType):
        dt_len = 4 if is_far_ptr else 2
    else:
        dt_len = desired_dt.getLength()
    if dt_len != v_len:
        log(
            "[BPVAR-RETYPE] skip %s:%s sp=%+d dt_len=%d vs desired v_len=%d"
            % (func.getName(), name, stack_off, dt_len, v_len)
        )
        return False

    cur_dt = v.getDataType()

    if not _is_undefined_like_datatype(cur_dt):
        log(
            "[BPVAR-RETYPE] %s:%s sp=%+d %s %s is not undefined"
            % (func.getName(), name, stack_off, desired_dt.getName(), cur_dt.getName())
        )
        return False

    # Already correct?
    try:
        if cur_dt is not None and cur_dt.equals(desired_dt):
            return False
    except Exception:
        pass

    try:
        # Variable.setDataType(DataType, SourceType) exists on most versions
        v.setDataType(desired_dt, SourceType.USER_DEFINED)
        log(
            "[BPVAR-RETYPE] %s:%s sp=%+d <- %s"
            % (func.getName(), name, stack_off, desired_dt.getName())
        )
        return True
    except VariableSizeException:
        # We explicitly do not resize/recreate in this mode.
        log(
            "[BPVAR-RETYPE-SKIP] %s:%s sp=%+d : size mismatch (len=%d)"
            % (func.getName(), name, stack_off, v_len)
        )
        return False
    except Throwable as ex:
        warn(
            "[BPVAR-RETYPE-FAIL] %s:%s sp=%+d : %s"
            % (func.getName(), name, stack_off, str(ex))
        )
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

    log("[BPVAR] %s collecting stack vars" % (func.getName()))
    by_off = _collect_stack_vars(func)

    # One NB09 local per stack slot (CodeView slot reuse is common).
    # Prefer larger known sizes (arrays/structs win).
    best_by_stack: dict[int, BestVarByStack] = {}
    for local in proc.types.locals:
        bp_off = local.bp_off
        nm = local.name
        if bp_off is None or not nm:
            log("[BPVAR] %s local has no name or offset" % (func.getName()))
            continue

        stack_off = bp_off - 2
        log("[BPVAR] %s local %s stack_off %s" % (func.getName(), nm, stack_off))

        want_len = local.size
        try:
            want_len = want_len if want_len is not None else None
        except Exception:
            log(
                "[BPVAR] %s local %s unable to determine want_len %s"
                % (func.getName(), nm, want_len)
            )
            want_len = None

        dt, err = datatype_from_decl_info(dtm, local.name, local.decl, local.is_far_ptr)
        if dt is None:
            warn(f"unable to find type for local {local.c_decl}")
            continue
        cur = best_by_stack.get(stack_off)
        if cur is None:
            best_by_stack[stack_off] = BestVarByStack(
                bp_off=bp_off, name=nm, want_len=want_len, dt=dt, local=local
            )
            log(
                "[BPVAR] %s local %s best by stack stack_off %s"
                % (func.getName(), nm, stack_off)
            )
            continue

        log(
            "[BPVAR] %s sp=%+d bp=%+d name=%s c_type: %s"
            % (func.getName(), stack_off, bp_off, nm, local.c_type)
        )

        if (want_len is not None and want_len > 0) and not (
            cur.want_len is not None and cur.want_len > 0
        ):
            best_by_stack[stack_off] = BestVarByStack(
                bp_off=bp_off, name=nm, want_len=want_len, dt=dt, local=local
            )
        elif (
            want_len is not None
            and cur.want_len is not None
            and want_len > cur.want_len
        ):
            best_by_stack[stack_off] = BestVarByStack(
                bp_off=bp_off, name=nm, want_len=want_len, dt=dt, local=local
            )

    changed = 0

    for stack_off in sorted(best_by_stack.keys()):
        # bp_off, nm, want_len, c_type = best_by_stack[stack_off]
        best = best_by_stack[stack_off]
        bp_off = best.bp_off
        nm = best.name

        # We only target locals (negative stack offsets). Safety belt:
        if stack_off >= 0:
            continue

        vars_here = by_off.get(stack_off, [])
        v = _choose_stack_var_for_rename(vars_here, best.want_len)
        if v is None:
            log(
                "[BPVAR-SKIP] %s sp=%+d bp=%+d name=%s (ambiguous or missing)"
                % (func.getName(), stack_off, bp_off, nm)
            )
            continue

        if _rename_var_user_defined(func, v, nm, stack_off):
            changed += 1
            log(
                "[BPVAR-RENAME] %s sp=%+d bp=%+d <- %s"
                % (func.getName(), stack_off, bp_off, nm)
            )

        # Safe retype: only if same size and current is undefined-like
        if best.dt is not None:
            if _maybe_retype_stack_var(func, nm, v, best.dt, best.want_len, stack_off, best.local.is_far_ptr):
                changed += 1
                log(
                    "[BPVAR-RETYPE] %s sp=%+d bp=%+d name=%s <- %s"
                    % (
                        func.getName(),
                        stack_off,
                        bp_off,
                        nm,
                        best.dt.getName(),
                    )
                )
            else:
                log(
                    "[BPVAR-RETYPE] %s sp=%+d bp=%+d name=%s not retyping to %s"
                    % (
                        func.getName(),
                        stack_off,
                        bp_off,
                        nm,
                        best.local.c_type,
                    )
                )
        else:
            log(
                "[BPVAR-RETYPE] %s sp=%+d bp=%+d name=%s no c_type"
                % (func.getName(), stack_off, bp_off, nm)
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
    total = 0
    applied = 0
    fails = 0
    skipped = 0
    misses = 0

    log("PROC records in JSON: %d" % len(root.globals))
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
