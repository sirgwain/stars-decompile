# ApplyNb09FuncSigsFromJson.py
# @category: Stars.NB09
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

from ghidra.util import Msg
from ghidra.util.exception import DuplicateNameException
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import (
    VoidDataType,
    ByteDataType,
    CharDataType,
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
)
from ghidra.program.model.listing import ParameterImpl
from ghidra.program.model.listing import VariableSizeException
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.program.model.data import FunctionDefinitionDataType, ParameterDefinitionImpl

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
    Find a DataType by name, preferring /stars/* then /NB09/* then anything.
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
    if name == "uint":
        return UnsignedShortDataType.dataType
    if name == "long":
        return LongDataType.dataType
    if name == "ulong":
        return UnsignedLongDataType.dataType
    if name == "int32_t":
        return LongDataType.dataType
    if name == "uint32_t":
        return UnsignedLongDataType.dataType
    if name == "uint8_t":
        return ByteDataType.dataType  # close enough for signatures
    if name == "int8_t":
        return Undefined1DataType.dataType
    if name == "uint16_t":
        return UnsignedShortDataType.dataType
    if name == "int16_t":
        return ShortDataType.dataType
    if name == "uint32_t":
        return UnsignedLongDataType.dataType
    if name == "int32_t":
        return LongDataType.dataType
    if name == "float":
        return FloatDataType.dataType

    # Prefer stars folder by exact path first
    dt = dtm.getDataType("/stars/" + name)
    if dt is not None:
        return dt
    dt = dtm.getDataType("/NB09/" + name)
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
        elif cat.startswith("/NB09"):
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

    # array (locals; not used for signature)
    m = re.match(r"^(.+)\[(\d+)\]$", t)
    if m:
        base_dt = datatype_from_c_type(m.group(1).strip())
        if base_dt is None:
            return None
        # We don't need arrays for function signatures; return base.
        return base_dt

    dt = find_datatype_by_name(t)
    return dt

def function_at(addr):
    fm = currentProgram.getFunctionManager()
    return fm.getFunctionAt(addr)


def calling_convention_for(types_obj):
    if types_obj is None:
        return "__cdecl16far"
    if types_obj.get("is_pascal"):
        return "__pascal16far"
    tags = types_obj.get("tags") or []
    ret = types_obj.get("ret") or {}
    if ("RETFAR" in tags) or ret.get("is_far_ptr"):
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
        # Many variable implementations expose this directly
        return int(var.getStackOffset())
    except Exception:
        pass
    try:
        vs = var.getVariableStorage()
        if vs is not None and vs.isStackStorage():
            try:
                return int(vs.getStackOffset())
            except Exception:
                # Some versions: stack offset comes from first varnode
                vn = vs.getVarnodes()
                if vn and len(vn) > 0:
                    try:
                        return int(vn[0].getOffset())
                    except Exception:
                        return None
    except Exception:
        pass
    return None

def _collect_stack_vars(func):
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

def _try_create_stack_var(func, name, stack_off, dt):
    """
    Try to create a new stack variable at stack_off (Ghidra stack offset).
    Returns (var, errstr_or_None).
    """
    sf = None
    try:
        sf = func.getStackFrame()
    except Exception as e:
        return None, "getStackFrame failed: %s" % str(e)

    # Different Ghidra versions have different overloads; try a few.
    tries = []
    if sf is not None:
        tries.append(lambda: sf.createVariable(name, stack_off, dt, SourceType.USER_DEFINED))
        tries.append(lambda: sf.createVariable(name, stack_off, dt))
        tries.append(lambda: sf.createVariable(stack_off, name, dt, SourceType.USER_DEFINED))
        tries.append(lambda: sf.createVariable(stack_off, name, dt))
        tries.append(lambda: sf.createVariable(stack_off, dt, name, SourceType.USER_DEFINED))
        tries.append(lambda: sf.createVariable(stack_off, dt, name))

    last_err = None
    for t in tries:
        try:
            v = t()
            if v is not None:
                return v, None
        except Exception as e:
            last_err = e
            continue

    return None, ("createVariable failed (%s)" % str(last_err) if last_err else "createVariable failed")

def apply_bp_relative_vars(func, types_obj):
    """
    Apply names + datatypes for parameters and locals based on bp_off from NB09.

    IMPORTANT: NB09 bp_off is BP-relative *after* 'push bp; mov bp, sp'.
    Ghidra stack offsets (Variable.getStackOffset / Stack[0x..]) are effectively SP-relative at entry,
    which are typically (bp_off - 2) because of the pushed BP word.

        ghidra_stack_off = nb09_bp_off - 2

    Returns number of vars updated/created.
    """
    if types_obj is None:
        return 0

    wanted = []
    for key in ("params", "locals"):
        for e in (types_obj.get(key) or []):
            if not isinstance(e, dict):
                continue
            bp_off = e.get("bp_off")
            if bp_off is None:
                continue
            nm = e.get("name") or ""
            ct = normalize_c_type(e.get("c_type") or "")
            if not nm or not ct:
                continue
            kind = e.get("kind") or ("param" if key == "params" else "local")
            wanted.append((kind, int(bp_off), nm, ct))

    if not wanted:
        return 0

    by_off = _collect_stack_vars(func)  # ghidra stack offsets
    changed = 0

    for kind, bp_off, name, ctype in wanted:
        stack_off = int(bp_off) - 2  # BP-relative -> Ghidra stack offset

        dt = datatype_from_c_type(ctype)
        if dt is None:
            _warn("[BPVAR-UNKTYPE] %s bp=%+d sp=%+d : %s (name=%s kind=%s)" %
                  (func.getName(), bp_off, stack_off, ctype, name, kind))
            continue

        # If earlier iterations deleted/recreated stack vars, refresh the cache.
        global _g_stackvars_dirty
        if _g_stackvars_dirty:
            by_off = _collect_stack_vars(func)
            _g_stackvars_dirty = False

        vars_here = by_off.get(stack_off, [])
        v = None
        if vars_here:
            # Filter out deleted vars (stale references after conflict resolution).
            live = []
            for cand in vars_here:
                try:
                    _ = cand.getName()
                    live.append(cand)
                except Throwable:
                    pass
            vars_here = live

            # Prefer matching length where possible
            want_len = -1
            try:
                want_len = int(dt.getLength())
            except Exception:
                want_len = -1

            if want_len > 0 and len(vars_here) > 1:
                for cand in vars_here:
                    try:
                        if int(cand.getLength()) == want_len:
                            v = cand
                            break
                    except Exception:
                        pass
            if v is None:
                v = vars_here[0]

        # Create missing locals (Ghidra generally doesn't allow creating params this way)
        if v is None and kind == "local":
            try:
                newv, err = _try_create_stack_var(func, name, stack_off, dt)
                if newv is None:
                    _warn("[BPVAR-FAIL] %s bp=%+d sp=%+d : %s (name=%s type=%s)" %
                        (func.getName(), bp_off, stack_off, err, name, ctype))
                    continue
                v = newv
                by_off.setdefault(stack_off, []).append(v)
                _log("[BPVAR-CREATE] %s bp=%+d sp=%+d %s : %s" %
                    (func.getName(), bp_off, stack_off, name, ctype))
                changed += 1
            except: 
                _warn("[BPVAR-MISS] %s bp=%+d sp=%+d : no existing var (name=%s type=%s kind=%s)" %
                    (func.getName(), bp_off, stack_off, name, ctype, kind))
                continue

        if v is None:
            _warn("[BPVAR-MISS] %s bp=%+d sp=%+d : no existing var (name=%s type=%s kind=%s)" %
                  (func.getName(), bp_off, stack_off, name, ctype, kind))
            continue

        # name (force unique) - catch Throwable because deleted vars throw ConcurrentModificationException
        try:
            cur_nm = None
            try:
                cur_nm = v.getName()
            except Throwable:
                cur_nm = None

            if cur_nm != name:
                try:
                    v.setName(name, SourceType.USER_DEFINED)
                except DuplicateNameException:
                    uniq = "%s_%+d" % (name, stack_off)
                    v.setName(uniq, SourceType.USER_DEFINED)
                except ConcurrentModificationException:
                    # The var reference is stale (deleted). Refresh and retry once.
                    by_off = _collect_stack_vars(func)
                    _g_stackvars_dirty = False
                    vars_here2 = by_off.get(stack_off, [])
                    v2 = None
                    for cand in vars_here2:
                        try:
                            _ = cand.getName()
                            v2 = cand
                            break
                        except Throwable:
                            pass
                    if v2 is not None:
                        v = v2
                        try:
                            v.setName(name, SourceType.USER_DEFINED)
                        except DuplicateNameException:
                            uniq = "%s_%+d" % (name, stack_off)
                            v.setName(uniq, SourceType.USER_DEFINED)
                changed += 1
        except Throwable as ex:
            _warn("[BPVAR-NAMEFAIL] %s bp=%+d sp=%+d : %s" %
                  (func.getName(), bp_off, stack_off, str(ex)))

        # type (force). NOTE: _set_var_dtype_force handles overlap deletion + retries.
        try:
            ok = _set_var_dtype_force(func, v, dt)
        except Throwable as ex:
            ok = False
            _warn("[BPVAR-TYPEEX] %s bp=%+d sp=%+d %s : %s" %
                  (func.getName(), bp_off, stack_off, name, str(ex)))

        if ok:
            changed += 1
        else:
            _warn("[BPVAR-TYPEFAIL] %s bp=%+d sp=%+d %s : could not set type %s" %
                  (func.getName(), bp_off, stack_off, name, ctype))

    return changed

def _ranges_overlap(a_off, a_len, b_off, b_len):
    try:
        a_off = int(a_off); a_len = int(a_len)
        b_off = int(b_off); b_len = int(b_len)
    except Exception:
        return False
    if a_len <= 0 or b_len <= 0:
        return False
    a0, a1 = a_off, a_off + a_len
    b0, b1 = b_off, b_off + b_len
    return not (a1 <= b0 or b1 <= a0)


def _resolve_stack_conflicts(func, target_off, target_len, keep_var=None, remove_user_defined=False):
    """Remove overlapping stack variables so we can apply a new type.

    By default, we avoid deleting USER_DEFINED vars (to preserve manual work).
    If remove_user_defined=True, we will delete *all* overlapping vars except keep_var.

    Returns number of variables removed.
    """
    removed = 0
    try:
        frame = func.getStackFrame()
        svars = list(frame.getStackVariables())
    except Exception:
        return 0

    for sv in svars:
        try:
            if keep_var is not None and sv == keep_var:
                continue
            if not sv.isStackVariable():
                continue
            off = sv.getStackOffset()
            ln = sv.getLength()
            if not _ranges_overlap(target_off, target_len, off, ln):
                continue

            # By default, only remove non-user-defined vars (avoid nuking manual work).
            # If remove_user_defined=True, we will also remove USER_DEFINED overlaps.
            if not remove_user_defined:
                try:
                    src = sv.getSource()
                    if src == SourceType.USER_DEFINED:
                        continue
                except Exception:
                    pass

            # Capture name/len BEFORE deletion, because the var object becomes invalid after removeVariable.
            sv_name = None
            try:
                sv_name = sv.getName()
            except Throwable:
                sv_name = "<unknown>"

            try:
                func.removeVariable(sv)
                removed += 1
                _warn("[BPVAR-DEL] %s %+d : removed overlapping var '%s' len=%d" %
                      (func.getName(), int(target_off), sv_name, int(ln)))
            except Throwable:
                pass
        except Exception:
            pass

    return removed


# Set when we delete stack vars; callers should rebuild any cached offset maps.
_g_stackvars_dirty = False


def _set_var_dtype_force(func, var, dt):
    """Try hard to set a stack var's datatype.

    Ghidra often throws VariableSizeException if any other stack variable overlaps the storage.
    In that case, we delete overlapping vars and retry.

    Returns True on success, False otherwise.
    """
    if var is None or dt is None:
        return False

    # Fast path: already the desired type (or equivalent)
    try:
        if var.getDataType() == dt:
            return True
    except Exception:
        pass

    # First attempt: just set it
    try:
        var.setDataType(dt, SourceType.USER_DEFINED)
        return True
    except VariableSizeException:
        pass
    except Throwable:
        # Not a size conflict; still may succeed after overlap clear, but treat similarly.
        pass

    # Determine desired length for overlap clearing
    want_len = -1
    try:
        want_len = int(dt.getLength())
    except Exception:
        want_len = -1
    if want_len <= 0:
        # Can't reason about overlap clearing
        return False

    target_off = None
    try:
        target_off = int(var.getStackOffset())
    except Exception:
        return False

    # Pass 1: remove non-user-defined overlaps
    global _g_stackvars_dirty
    if _resolve_stack_conflicts(func, target_off, want_len, keep_var=var, remove_user_defined=False) > 0:
        _g_stackvars_dirty = True
    try:
        var.setDataType(dt, SourceType.USER_DEFINED)
        return True
    except VariableSizeException:
        pass
    except Throwable:
        pass

    # Pass 2: remove *all* overlaps (including USER_DEFINED). This is the "convince the decompiler" mode.
    if _resolve_stack_conflicts(func, target_off, want_len, keep_var=var, remove_user_defined=True) > 0:
        _g_stackvars_dirty = True
    try:
        var.setDataType(dt, SourceType.USER_DEFINED)
        return True
    except Throwable:
        return False

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

        # rename
        try:
            if func.getName() != name:
                func.setName(name, SourceType.USER_DEFINED)
                renamed += 1
        except Exception as e:
            _warn("Rename failed for %s @ %s: %s" % (name, addr_str, str(e)))

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
    _log("  renamed:  %d" % renamed)
    _log("  misses:   %d" % misses)
    _log("  skipped:  %d" % skipped)
    _log("  failed:   %d" % fails)

if __name__ == "__main__":
    main()
