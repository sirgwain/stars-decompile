# ApplyNb09FuncSigsFromJson.py
# @category Stars
#
# Apply function names + signatures from nb09_ghidra_globals.json (only PROC records).
#
# Expectations (per Craig's project conventions):
#   - int16_t -> int, uint16_t -> uint (Ghidra 16-bit int/uint under your compiler spec)
#   - "*32" types are 32-bit far pointers and should remain "*32"
#   - Calling conventions:
#       * if types.is_pascal:            __pascal16far
#       * else if return is far (*32):   __stdcall16far
#       * else:                          __cdecl16far
#   - "Use Custom Storage" must be OFF (we force dynamic storage for params/ret)
#
# Usage:
#   In Ghidra: Script Manager -> Run, and select the JSON file when prompted.

import json
import os
import re
import traceback

# make IDE register built ins
try:
    from ghidra.ghidra_builtins import *
    from ghidra.program.model.listing import *
    currentProgram = currentProgram # type: Program
except:
    pass

from java.math import BigInteger

from ghidra.util import Msg
from ghidra.util.exception import DuplicateNameException
from java.lang import Throwable
from java.util import ConcurrentModificationException
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import (
    DataType,
    VoidDataType,
    ByteDataType,
    CharDataType,
    ArrayDataType,
    ShortDataType,
    UnsignedShortDataType,
    IntegerDataType,
    FloatDataType,
    UnsignedIntegerDataType,
    LongDataType,
    UnsignedLongDataType,
    PointerDataType,
    Pointer32DataType,
    Undefined1DataType,
    Undefined2DataType,
    Undefined4DataType,
    ArrayDataType,
)
from ghidra.program.model.listing import ParameterImpl
from ghidra.program.model.listing import VariableSizeException
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.program.model.data import FunctionDefinitionDataType, ParameterDefinitionImpl

# ------------------------------------------------------------
# knobs
# ------------------------------------------------------------

# When applying locals-by-bp-offset, we sometimes need to delete overlapping USER_DEFINED locals
# to fit a larger struct/array. That can destroy manual work, so keep it off by default.
ALLOW_REMOVE_USER_DEFINED_OVERLAPS = False

# When var.setDataType() fails due to size/storage mismatches, remove/recreate the stack var.
# This is often required for by-value structs/arrays (e.g., PAINTSTRUCT, char[32]).
ALLOW_RECREATE_STACK_VAR_ON_TYPEFAIL = True

# When true, set the CS register value in program context at each function entry
# based on the function's entry address segment selector (e.g. "1008:1234" -> 0x1008).
# This helps the decompiler form concrete far pointers instead of unaff_CS.
SET_CS_ON_ENTRY = True

# ------------------------------------------------------------
# helpers
# ------------------------------------------------------------

def _log(s):
    print(s)

def _warn(s):
    print("[WARN] " + s)

def _err(s):
    print("[ERR] " + s)

def _parse_seg_selector(addr_s):
    # "1038:7fe6" -> 0x1038
    try:
        return int(addr_s.split(":")[0], 16)
    except:
        return None

def set_cs_at_function_entry(func):
    """Set CS register context at the function entry to the entry segment selector."""
    if not SET_CS_ON_ENTRY or func is None:
        return False
    try:
        entry = func.getEntryPoint()
        seg = _parse_seg_selector(entry.toString())
        if seg is None:
            _warn(f"{func.getName()} seg selector for entry {entry.toString()} is empty")
            return False

        reg = currentProgram.getRegister("CS")
        if reg is None:
            _warn("CS register not found")
            return False

        ctx = currentProgram.getProgramContext()
        # Apply only at the entry point; keep the range minimal to avoid stepping
        # on other context propagation.
        ctx.setValue(reg, entry, func.getBody().getMaxAddress(), BigInteger.valueOf(seg))
        return True
    except Throwable as t: 
        _err(f"{func.getName()} failed to set cs at entry")
        _err(traceback.format_exc())
        return False
    except Exception as e:
        _err(f"{func.getName()} failed to set cs at entry")
        _err(traceback.format_exc())
        return False

def build_logical_seg_map_from_memory():
    """
    Build mapping from CodeView logical segment indices (1-based) -> segment selector (hex, like 0x1038)
    using currentProgram memory block start addresses.
    """
    segs = set()
    mem = currentProgram.getMemory()
    for b in mem.getBlocks():
        a = b.getStart()
        s = a.toString()  # ex: "1038:0000"
        seg = _parse_seg_selector(s)
        if seg is not None:
            segs.add(seg)
    segs = sorted(segs)
    # Map 1..N to seg selector
    m = {}
    for i, seg in enumerate(segs):
        m[i + 1] = seg
    _log("Built logical segment map from memory: %d segments (min=%s max=%s)" % (
        len(segs),
        ("0x%04x" % segs[0]) if segs else "n/a",
        ("0x%04x" % segs[-1]) if segs else "n/a",
    ))
    return m

_INT_REMAP = {
    "int16_t": "int",
    "uint16_t": "uint",
    "short": "int",
    "unsigned short": "uint",
    "signed short": "int",
    # sometimes CodeView emits these:
    "WORD": "uint",
    "UINT": "uint",
    "INT": "int",
    "BOOL": "int",  # win16 BOOL is 16-bit
}

def normalize_c_type(c_type):
    """
    Normalize / project-convention adjustments.
    """
    if c_type is None:
        return None
    t = c_type.strip()
    # collapse whitespace
    t = re.sub(r"\s+", " ", t)

    # Exact remaps
    if t in _INT_REMAP:
        return _INT_REMAP[t]

    # Common patterns like "const int16_t"
    for k, v in _INT_REMAP.items():
        if t == "const " + k:
            return "const " + v

    # Keep "*32" suffix intact.
    # But remap base type if it's int16_t/uint16_t.
    if t.endswith("*32"):
        base = t[:-3].strip()  # remove "*32"
        # handle "char *32" style where there is already a space before '*'
        if base.endswith("*"):
            base = base[:-1].strip()
        base = normalize_c_type(base) or base
        return base + " *32"

    # Arrays like "char[100]" for locals (we ignore locals, but keep support)
    m = re.match(r"^(.+)\[(\d+)\]$", t)
    if m:
        base = normalize_c_type(m.group(1).strip()) or m.group(1).strip()
        return "%s[%s]" % (base, m.group(2))

    return t

def find_datatype_by_name(name):
    """
    Find a DataType by name, preferring /stars/* then /win16/typedefs/* then anything.
    """
    dtm = currentProgram.getDataTypeManager()

    # If it is already a path:
    if name.startswith("/"):
        dt = dtm.getDataType(name)
        if dt is not None:
            return dt

    # Direct primitive matches
    if name == "void":
        return VoidDataType.dataType
    if name == "char":
        return CharDataType.dataType
    if name == "int":
        # under your 16-bit compiler spec, this should be 2 bytes
        return ShortDataType.dataType
    if name == "uint8_t":
        return ByteDataType.dataType  # close enough for signatures
    if name == "int8_t":
        return Undefined1DataType.dataType
    if name == "uint":
        return UnsignedShortDataType.dataType
    if name == "long":
        return LongDataType.dataType
    if name == "ulong":
        return UnsignedLongDataType.dataType
    if name == "uint16_t":
        return UnsignedShortDataType.dataType
    if name == "int16_t":
        return ShortDataType.dataType
    if name == "int32_t":
        return LongDataType.dataType
    if name == "uint32_t":
        return UnsignedLongDataType.dataType
    if name == "float":
        return FloatDataType.dataType

    # Prefer stars folder by exact path first
    dt = dtm.getDataType("/stars/" + name)
    if dt is not None:
        return dt
    dt = dtm.getDataType("/win16/typedefs/" + name)
    if dt is not None:
        return dt

    # Search by name
    best = None
    best_rank = 9999
    it = dtm.getAllDataTypes()
    while it.hasNext():
        d = it.next()
        if d.getName() != name:
            continue
        cat = d.getCategoryPath().toString()
        rank = 100
        if cat.startswith("/stars"):
            rank = 0
        elif cat.startswith("/win16/typedefs"):
            rank = 10
        if rank < best_rank:
            best_rank = rank
            best = d
            if rank == 0:
                break
    return best

def datatype_from_c_type(c_type):
    """
    Convert your JSON c_type string to a Ghidra DataType.
    Supports:
      - primitives (int, uint, char, void)
      - /stars/<NAME> structs
      - "<BASE> *32" far pointers (as Pointer32DataType)
    """
    t = normalize_c_type(c_type)
    if t is None:
        return None

    # Function pointer (treat as opaque pointer; we can refine later)
    # Examples: "int16_t (*32)(void)", "int16_t (*32)(PLANET *32, PLANET *32)"
    if re.search(r"\(\s*\*32\s*\)\s*\(", t):
        return Pointer32DataType(VoidDataType.dataType)
    if re.search(r"\(\s*\*\s*\)\s*\(", t):
        return PointerDataType(VoidDataType.dataType)

    # pointer32
    if t.endswith(" *32"):
        base = t[:-4].strip()
        base_dt = datatype_from_c_type(base)
        if base_dt is None:
            _warn("Unknown base type for pointer32: '%s' (from '%s') -> using undefined4*32" % (base, c_type))
            base_dt = Undefined4DataType.dataType
        try:
            return Pointer32DataType(base_dt)
        except Exception as e:
            _warn("Pointer32DataType failed for base '%s': %s; using Undefined4*32" % (base, str(e)))
            return Pointer32DataType(Undefined4DataType.dataType)

    if t.endswith(" *"):
        base = t[:-2].strip()
        base_dt = datatype_from_c_type(base)
        if base_dt is None:
            _warn("Unknown base type for pointer: '%s' (from '%s') -> using undefined2*" % (base, c_type))
            base_dt = Undefined2DataType.dataType
        try:
            return PointerDataType(base_dt)
        except Exception as e:
            _warn("PointerDataType failed for base '%s': %s; using Undefined2*" % (base, str(e)))
            return PointerDataType(Undefined2DataType.dataType)

    # array (locals)
    m = re.match(r"^(.+)\[(\d+)\]$", t)
    if m:
        base_dt = datatype_from_c_type(m.group(1).strip())
        if base_dt is None:
            return None
        try:
            cnt = int(m.group(2))
            elem_len = int(base_dt.getLength())
            return ArrayDataType(base_dt, cnt, elem_len)
        except Exception:
            return base_dt

    dt = find_datatype_by_name(t)
    return dt

def function_at(addr):
    fm: FunctionManager = currentProgram.getFunctionManager()
    return fm.getFunctionAt(addr)


def calling_convention_for(types_obj):
    if types_obj is None:
        return "__cdecl16far"
    if types_obj.get("is_pascal"):
        return "__pascal16far"
    tags = types_obj.get("tags") or []
    ret = types_obj.get("ret") or {}
    # Win16 (MSC 6.x / Stars!): some functions that return values wider than 16 bits
    # are annotated in the NB09 with a RET32-style tag. In the original source these
    # were typically declared far stdcall to match the compiler's 16-bit ABI helpers.
    #
    # We already treat far-pointer returns (*32) as stdcall; extend the same rule to
    # 32-bit scalar returns (long/ulong/int32_t/uint32_t), which show up as RET32 in
    # our JSON.
    if ("RETFAR" in tags) or ret.get("is_far_ptr") or ("RET32" in tags) or ret.get("is_32bit") or (ret.get("size") == 4):
        return "__stdcall16far"
    return "__cdecl16far"

def build_function_def(name, types_obj, cc_name):
    """
    Build a FunctionDefinitionDataType for ApplyFunctionSignatureCmd.
    """
    fdef = FunctionDefinitionDataType(name)
    try:
        fdef.setCallingConvention(cc_name)
    except:
        # older Ghidra might not allow arbitrary cc names here; we'll set on function later.
        pass

    # return
    ret = (types_obj or {}).get("ret") or {}
    ret_type_s = ret.get("c_type") or "void"
    ret_dt = datatype_from_c_type(ret_type_s)
    if ret_dt is None:
        _warn("Unknown return type '%s' for %s; using void" % (ret_type_s, name))
        ret_dt = VoidDataType.dataType
    fdef.setReturnType(ret_dt)

    # params
    params = []
    for p in (types_obj or {}).get("params") or []:
        p_name = p.get("name") or "p"
        p_type_s = p.get("c_type")
        p_dt = datatype_from_c_type(p_type_s)
        if p_dt is None:
            _warn("Unknown param type '%s' for %s(%s); using undefined2" % (p_type_s, name, p_name))
            p_dt = Undefined2DataType.dataType
        params.append(ParameterDefinitionImpl(p_name, p_dt, None))
    if types_obj.get("is_pascal"):
        # pascal args are reversed
        params.reverse()
    fdef.setArguments(params)
    return fdef

def apply_signature(func, fdef, cc_name):
    """
    Apply signature with dynamic storage, and force custom storage OFF.
    """
    # Apply signature command (handles params/return dt, names)
    cmd = ApplyFunctionSignatureCmd(func.getEntryPoint(), fdef, SourceType.USER_DEFINED)
    ok = cmd.applyTo(currentProgram, monitor)
    if not ok:
        return False, "ApplyFunctionSignatureCmd failed"

    # Force calling convention
    try:
        func.setCallingConvention(cc_name)
    except Exception as e:
        _warn("setCallingConvention failed for %s: %s" % (func.getName(), str(e)))

    # Force dynamic storage / custom storage off
    try:
        func.setCustomVariableStorage(False)
    except Exception as e:
        _warn("setCustomVariableStorage(False) failed for %s: %s" % (func.getName(), str(e)))

    # Some Ghidra versions require an explicit update to re-assign storage after CC changes.
    # Unfortunately, the FunctionUpdateType enum moved/changed across versions.
    # We attempt it when available, but treat failure as non-fatal.
    try:
        update_type = None
        try:
            from ghidra.program.model.listing import FunctionUpdateType as _FUT
            # Common value name in newer versions
            update_type = getattr(_FUT, 'DYNAMIC_STORAGE_ALL_PARAMS', None)
        except Exception:
            update_type = None

        if update_type is not None:
            new_params = []
            for pd in fdef.getArguments():
                new_params.append(ParameterImpl(pd.getName(), pd.getDataType(), currentProgram))
            func.updateFunction(
                cc_name,
                fdef.getReturnType(),
                new_params,
                update_type,
                True,
                SourceType.USER_DEFINED
            )
            try:
                func.setCustomVariableStorage(False)
            except Exception:
                pass
    except Exception as e:
        _warn("updateFunction dynamic storage step failed for %s: %s" % (func.getName(), str(e)))

    return True, None



# ------------------------------------------------------------
# stack var (bp relative) application for locals/params
# ------------------------------------------------------------

def _get_stack_offset(var):
    """
    Return stack offset (relative to BP / frame base) for a variable, or None.
    Works across a couple of Ghidra versions by trying multiple APIs.
    """
    try:
        # Many variable implementations expose this directly.
        # In some cases (e.g. register-backed storage) Ghidra throws
        # java.lang.UnsupportedOperationException: "Storage does not have a stack varnode".
        return int(var.getStackOffset())
    except:
        # Jython may not reliably map Java runtime exceptions to `Exception`.
        pass
    try:
        vs = var.getVariableStorage()
        if vs is not None and vs.isStackStorage():
            try:
                return int(vs.getStackOffset())
            except:
                # Some versions: stack offset comes from first varnode
                try:
                    vn = vs.getVarnodes()
                    if vn and len(vn) > 0:
                        return int(vn[0].getOffset())
                except:
                    return None
    except:
        pass
    return None

def _collect_stack_vars(func: Function) -> dict[int, Variable]:
    """
    Build map stackOffset -> [vars...] for all variables that live on stack (params + locals).
    """
    m = {}
    try:
        vars_all = list(func.getAllVariables())
    except Exception:
        # fallback
        vars_all = []
        try:
            vars_all.extend(list(func.getParameters()))
        except Exception:
            pass
        try:
            vars_all.extend(list(func.getLocalVariables()))
        except Exception:
            pass

    for v in vars_all:
        off = _get_stack_offset(v)
        if off is None:
            continue
        m.setdefault(off, []).append(v)
    return m

def _choose_stack_var_for_rename(vars_here, want_len):
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

    if want_len is not None and int(want_len) > 0:
        matches = []
        for v in vars_here:
            try:
                if int(v.getLength()) == int(want_len):
                    matches.append(v)
            except Exception:
                pass
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            return None  # ambiguous

    if len(vars_here) == 1:
        return vars_here[0]

    return None  # ambiguous


def _rename_var_user_defined(func: Function, v: Variable, new_name: str, stack_off: int):
    """
    Rename v to new_name as USER_DEFINED, handling duplicates.
    Returns True if renamed/changed.
    """
    try:
        cur = v.getName()
    except Throwable:
        cur = None

    if cur == new_name:
        return False

    try:
        v.setName(new_name, SourceType.USER_DEFINED)
        return True
    except DuplicateNameException:
        # Deterministic unique suffix
        uniq = "%s_%+d" % (new_name, int(stack_off))
        try:
            v.setName(uniq, SourceType.USER_DEFINED)
            return True
        except Throwable as ex:
            _warn("[BPVAR-NAMEFAIL] %s sp=%+d : %s" % (func.getName(), int(stack_off), str(ex)))
            return False
    except Throwable as ex:
        _warn("[BPVAR-NAMEFAIL] %s sp=%+d : %s" % (func.getName(), int(stack_off), str(ex)))
        return False


def _is_undefined_like_datatype(dt):
    """
    True if dt is undefined/unknown-ish, including arrays of undefined.
    We key off the datatype name because exact classes vary by Ghidra version.
    """
    if dt is None:
        return True
    try:
        # Peel arrays: undefined2[16] should count as undefined-like
        while hasattr(dt, "getDataType") and dt.getClass().getName().endswith("ArrayDataType"):
            dt = dt.getDataType()
            if dt is None:
                return True
    except Exception:
        pass

    try:
        nm = dt.getName() or ""
        return nm.lower().startswith("undefined")
    except Exception:
        return False


def _maybe_retype_stack_var(func: Function, v: Variable, desired_dt: DataType, want_len: int, stack_off: int):
    """
    Retype v to desired_dt ONLY if:
      - current dt is undefined-like
      - v.getLength == want_len (if provided)
      - desired_dt.getLength == v.getLength
    Returns True if changed.
    """
    if desired_dt is None:
        return False

    try:
        v_len = int(v.getLength())
    except Exception:
        return False

    if want_len is not None and int(want_len) > 0 and v_len != int(want_len):
        _log("[BPVAR-RETYPE] %s sp=%+d %s v_dt=%s v_len=%d want_len=%d" % (func.getName(), int(stack_off), desired_dt.getName(), v.getDataType().getName(), v_len, want_len))
        return False

    try:
        dt_len = int(desired_dt.getLength())
    except Exception:
        return False

    if dt_len != v_len:
        _log("[BPVAR-RETYPE] %s sp=%+d %s is %d vs desired %d" % (func.getName(), int(stack_off), desired_dt.getName(), dt_len, v_len))
        return False

    try:
        cur_dt = v.getDataType()
    except Exception:
        _log("[BPVAR-RETYPE] %s sp=%+d %s no cur_dt" % (func.getName(), int(stack_off), desired_dt.getName()))
        cur_dt = None

    if not _is_undefined_like_datatype(cur_dt):
        _log("[BPVAR-RETYPE] %s sp=%+d %s %s is not undefined" % (func.getName(), int(stack_off), desired_dt.getName(), cur_dt.getName()))
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
        _log("[BPVAR-RETYPE] %s sp=%+d <- %s" % (func.getName(), int(stack_off), desired_dt.getName()))
        return True
    except VariableSizeException:
        # We explicitly do not resize/recreate in this mode.
        _log("[BPVAR-RETYPE-SKIP] %s sp=%+d : size mismatch (len=%d)" %
             (func.getName(), int(stack_off), v_len))
        return False
    except Throwable as ex:
        _warn("[BPVAR-RETYPE-FAIL] %s sp=%+d : %s" % (func.getName(), int(stack_off), str(ex)))
        return False

def apply_bp_relative_vars(func, types_obj):
    """
    Rename locals by NB09 bp_off when unambiguous.
    Additionally, retype ONLY when:
      - existing stack var length matches NB09 size
      - desired datatype length matches that exact length
      - current datatype is undefined-like (including arrays of undefined)

    Never creates locals, never deletes overlaps, never resizes vars.

    Returns number of changes (renames + retypes).
    """
    if types_obj is None:
        _log("[BPVAR] %s no types_obj" % (func.getName()))
        return 0

    locals_list = types_obj.get("locals") or []
    if not locals_list:
        _log("[BPVAR] %s no locals" % (func.getName()))
        return 0

    _log("[BPVAR] %s collecting stack vars" % (func.getName()))
    by_off = _collect_stack_vars(func)

    # One NB09 local per stack slot (CodeView slot reuse is common).
    # Prefer larger known sizes (arrays/structs win).
    best_by_stack = {}
    for e in locals_list:
        if not isinstance(e, dict):
            continue
        bp_off = e.get("bp_off")
        nm = e.get("name") or ""
        if bp_off is None or not nm:
            _log("[BPVAR] %s local has no name or offset" % (func.getName()))
            continue

        try:
            bp_off = int(bp_off)
        except Exception:
            _log("[BPVAR] %s local %s is has invalid offset %s" % (func.getName(), nm, bp_off))
            continue

        stack_off = bp_off - 2
        _log("[BPVAR] %s local %s stack_off %s" % (func.getName(), nm, stack_off))

        want_len = e.get("size", None)
        try:
            want_len = int(want_len) if want_len is not None else None
        except Exception:
            _log("[BPVAR] %s local %s unable to determine want_len %s" % (func.getName(), nm, want_len))
            want_len = None

        c_type = normalize_c_type(e.get("c_type") or "")
        cur = best_by_stack.get(stack_off)
        if cur is None:
            best_by_stack[stack_off] = (bp_off, nm, want_len, c_type)
            _log("[BPVAR] %s local %s best by stack stack_off %s" % (func.getName(), nm, stack_off))
            continue

        _log("[BPVAR] %s sp=%+d bp=%+d name=%s c_type: %s" %
                (func.getName(), int(stack_off), int(bp_off), nm, c_type))

        _, _, cur_len, _ = cur
        if (want_len is not None and want_len > 0) and not (cur_len is not None and cur_len > 0):
            best_by_stack[stack_off] = (bp_off, nm, want_len, c_type)
        elif (want_len is not None and cur_len is not None and want_len > cur_len):
            best_by_stack[stack_off] = (bp_off, nm, want_len, c_type)

    changed = 0


    for stack_off in sorted(best_by_stack.keys()):
        bp_off, nm, want_len, c_type = best_by_stack[stack_off]

        # We only target locals (negative stack offsets). Safety belt:
        if stack_off >= 0:
            continue

        vars_here = by_off.get(stack_off, [])
        v = _choose_stack_var_for_rename(vars_here, want_len)
        if v is None:
            _log("[BPVAR-SKIP] %s sp=%+d bp=%+d name=%s (ambiguous or missing)" %
                 (func.getName(), int(stack_off), int(bp_off), nm))
            continue

        if _rename_var_user_defined(func, v, nm, stack_off):
            changed += 1
            _log("[BPVAR-RENAME] %s sp=%+d bp=%+d <- %s" %
                 (func.getName(), int(stack_off), int(bp_off), nm))

        # Safe retype: only if same size and current is undefined-like
        if c_type:
            desired_dt = datatype_from_c_type(c_type)
            if desired_dt is not None:
                if _maybe_retype_stack_var(func, v, desired_dt, want_len, stack_off):
                    changed += 1
                    _log("[BPVAR-RETYPE] %s sp=%+d bp=%+d name=%s <- %s" %
                    (func.getName(), int(stack_off), int(bp_off), nm, desired_dt.getName()))
                else:
                    _log("[BPVAR-RETYPE] %s sp=%+d bp=%+d name=%s not retyping to %s" %
                    (func.getName(), int(stack_off), int(bp_off), nm, desired_dt.getName()))
            else:
                _log("[BPVAR-RETYPE] %s sp=%+d bp=%+d name=%s no desired_dt" %
                 (func.getName(), int(stack_off), int(bp_off), nm))
        else:
            _log("[BPVAR-RETYPE] %s sp=%+d bp=%+d name=%s no c_type" %
                 (func.getName(), int(stack_off), int(bp_off), nm))

    return changed


# ------------------------------------------------------------
# main
# ------------------------------------------------------------

def main():
    json_path = askFile("Select nb09_ghidra_globals.json", "OK").getAbsolutePath()
    _log("ApplyNb09FuncSigsFromJson")
    _log("JSON: %s" % json_path)
    _log("Program: %s" % currentProgram.getName())
    _log("")

    with open(json_path, "rb") as f:
        data = json.loads(f.read())

    # The file is a big object; the list of symbols is usually in data["globals"] or data itself.
    # We accept either a top-level list or a dict containing "globals".
    if isinstance(data, list):
        recs = data
    else:
        recs = data.get("procs") or data.get("symbols") or data.get("items") or []

    if not recs:
        # fall back: find first list value
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, list) and v and isinstance(v[0], dict) and ("cv" in v[0] or "name" in v[0]):
                    _warn("No 'procs' key; using list at key '%s' (%d records)" % (k, len(v)))
                    recs = v
                    break

    if not recs:
        raise Exception("Could not find list of records in JSON")

    seg_map = build_logical_seg_map_from_memory()

    # stats
    total = 0
    applied = 0
    renamed = 0
    misses = 0
    fails = 0
    skipped = 0
    cs_set = 0

    # filter procs
    procs = []
    for r in recs:
        cv = (r or {}).get("cv") or {}
        if cv.get("from") == "PROC" or cv.get("rectyp") == 261:
            procs.append(r)

    total = len(procs)
    _log("PROC records in JSON: %d" % total)
    _log("")

    monitor.initialize(total)

    for i, r in enumerate(procs):
        monitor.checkCanceled()
        monitor.setMessage("Applying sig %d/%d" % (i + 1, total))

        name = r.get("name")
        cv = r.get("cv") or {}
        types_obj = r.get("types") or {}
        gh = r.get("ghidra", {}) or {}

        addr_str = gh.get("addr") or ""
        default_label = gh.get("default_label") or ""

        if not addr_str:
            _warn("%s: missing ghidra.addr" % name)
            continue

        try:
            addr = toAddr(addr_str)
        except Exception as e:
            _warn("%s @ %s: bad addr (%s)" % (name, addr_str, str(e)))
            continue

        func = function_at(addr)
        if func is None:
            misses += 1
            _warn("No function at %s for %s" % (addr_str, name))
            continue

        # Set CS register context at entry (helps decompiler remove unaff_CS for far pointers)
        if set_cs_at_function_entry(func):
            cs_set += 1

        # NOTE: Renaming is handled by ApplyNb09NamesFromJson.py
        # We skip renaming here to avoid duplicate work and potential inconsistencies.
        # The naming script should be run before this one.

        # signature
        try:
            cc_name = calling_convention_for(types_obj)
            fdef = build_function_def(name, types_obj, cc_name)
            ok, why = apply_signature(func, fdef, cc_name)
            if ok:
                applied += 1
                _log("[APPLY] %s <- %s  cc=%s" % (addr_str, (types_obj.get("proto") or "<no proto>"), cc_name))
                # locals/params by bp-relative offsets (from JSON)
                try:
                    c_changed = apply_bp_relative_vars(func, types_obj)
                    if c_changed:
                        _log("[BPVARS] %s updated %d stack vars" % (addr_str, c_changed))
                except Exception as e:
                    _warn("[BPVARS-ERR] %s : %s" % (addr_str, str(e)))
            else:
                fails += 1
                _err("[FAIL]  %s @ %s : %s" % (name, addr_str, why))
        except Exception as e:
            fails += 1
            _err("[FAIL]  %s @ %s : %s" % (name, addr_str, str(e)))
            _err(traceback.format_exc())

    _log("")
    _log("done")
    _log("  applied:  %d" % applied)
    _log("  cs_set:   %d" % cs_set)
    _log("  renamed:  %d" % renamed)
    _log("  misses:   %d" % misses)
    _log("  skipped:  %d" % skipped)
    _log("  failed:   %d" % fails)
    _log("  cs_set:   %d" % cs_set)

if __name__ == "__main__":
    main()
