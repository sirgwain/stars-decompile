# -*- coding: utf-8 -*-
# ApplyNb09GlobalsFromJson.py
# @category Stars

import re
from dataclasses import dataclass
from typing import Literal, TypeAlias

# make IDE register built ins
try:
    from ghidra.ghidra_builtins import *
    from ghidra.program.model.listing import *

    currentProgram = currentProgram  # type: Program
except:
    pass

from ghidra.program.model.address import Address
from ghidra.program.model.symbol import SourceType, SymbolTable
from ghidra.program.model.data import (
    DataTypeManager,
    DataType,
    CategoryPath,
    ArrayDataType,
    PointerDataType,
    Pointer32DataType,
    FunctionDefinitionDataType,
    ParameterDefinitionImpl,
    VoidDataType,
    DataUtilities,
    Structure,
    TypeDef,
)


from ghidra_utils import (
    GlobalEntry,
    dts_by_name,
    load_nb09_ghidra_globals,
    c_type_to_data_type,
    parse_c_decl,
    sanitize_name,
    dedupe_name,
)



PREFERRED_CATEGORY_PREFIXES = [
    "/stars",  # your structs
    "/windows",  # if you imported windows types into a folder
    "/",  # anything else
]


def _is_typedef(dt: DataType) -> bool:
    return isinstance(dt, TypeDef)


def _dt_kind_rank(dt):
    # lower is better
    if isinstance(dt, Structure):
        return 0
    if _is_typedef(dt):
        return 1
    return 2


def build_dt_index(
    dtm: DataTypeManager,
) -> tuple[dict[str, DataType], dict[str, DataType]]:
    """
    Returns:
      by_name:  name -> [DataType...]
      by_path:  fullPath -> DataType
    """
    by_name: dict[str, DataType] = {}
    by_path: dict[str, DataType] = {}
    for dt in dtm.getAllDataTypes():
        dt = dt  # type: DataType
        name = dt.getName()
        path = dt.getDataTypePath().getPath()  # e.g. "/stars/SHDEF"
        by_path[path] = dt
        by_name.setdefault(name, []).append(dt)

    # sort each list by (category preference, kind rank)
    def cat_rank(dt: DataType) -> int:
        p = dt.getDataTypePath().getPath()
        for i, pref in enumerate(PREFERRED_CATEGORY_PREFIXES):
            if pref == "/":
                return i
            if p.startswith(pref + "/") or p == pref:
                return i
        return len(PREFERRED_CATEGORY_PREFIXES)

    for name, lst in by_name.items():
        lst.sort(key=lambda dt: (cat_rank(dt), _dt_kind_rank(dt)))

    return by_name, by_path


def resolve_named_type(
    type_name: str, by_name: dict[str, DataType], by_path: dict[str, DataType]
):
    """
    Tries exact path, then common name normalizations, then simple name.
    """
    if not type_name:
        return None

    # If caller passed "/stars/SHDEF" style:
    if type_name.startswith("/"):
        dt = by_path.get(type_name)
        if dt:
            return dt
        # maybe missing leading "/" normalization:
        dt = by_path.get("/" + type_name.lstrip("/"))
        if dt:
            return dt

    # Normalize common C-ish prefixes
    candidates = []
    tn = type_name.strip()
    candidates.append(tn)
    for pref in ("struct ", "enum ", "union "):
        if tn.startswith(pref):
            candidates.append(tn[len(pref) :].strip())

    # Windows tag-style variants
    # e.g. POINT might exist as tagPOINT
    candidates.append("tag" + tn)
    candidates.append("_" + tn)

    # Try each candidate as a simple name
    for c in candidates:
        lst = by_name.get(c)
        if lst:
            return lst[0]  # best after sorting

    return None


# Module-global cache (Jython can keep module state across runs)
dtm: DataTypeManager = currentProgram.getDataTypeManager()
BY_NAME, BY_PATH = build_dt_index(dtm)
_DT_NAME_INDEX: dict[str, DataType] = dts_by_name(dtm)


def _resolve_named_type(name):
    global _DT_NAME_INDEX
    # Exact first
    dt = _DT_NAME_INDEX.get(name, None)
    if dt is not None:
        return dt

    # Common typedef/struct naming patterns
    candidates = [
        "tag" + name,  # POINT -> tagPOINT
        "_" + name,  # RPT -> _RPT or _rpt
        name.lower(),
        "_" + name.lower(),
        "tag" + name.lower(),
        name.upper(),
        "_" + name.upper(),
    ]
    for cand in candidates:
        dt = _DT_NAME_INDEX.get(cand, None)
        if dt is not None:
            return dt

    return None


def _pointer_dt(base_dt: DataType, is_far_ptr: bool) -> DataType:
    if is_far_ptr:
        # FAR pointer => 4 bytes
        return Pointer32DataType(base_dt)
    # NEAR pointer => default pointer size (Win16 segments: 2 bytes in your setup)
    return PointerDataType(base_dt)


def _wrap_pointers(base_dt: DataType, star_count: int, is_far_ptr: bool) -> DataType:
    dt = base_dt
    for _ in range(star_count):
        dt = _pointer_dt(dt, is_far_ptr)
    return dt


def _wrap_arrays(base_dt: DataType, dims: list[int]) -> DataType:
    dt = base_dt
    # Build from inner to outer
    for n in reversed(dims):
        n_int = n or 1 # treat 0 length arrays as length 1
        el_len = dt.getLength()
        if el_len <= 0:
            el_len = 1
        dt = ArrayDataType(dt, n_int, el_len)
    return dt



def _make_func_def(
    dtm: DataTypeManager, ret_name: str, args_text: str, unique_name: str
) -> FunctionDefinitionDataType:
    # make a FunctionDefinitionDataType for a function pointer
    # Return type
    ret_dt = c_type_to_data_type(ret_name)
    if ret_dt is None:
        ret_dt = _resolve_named_type(ret_name)
    if ret_dt is None:
        ret_dt = VoidDataType.dataType

    # Construct function definition datatype
    fd = FunctionDefinitionDataType(CategoryPath.ROOT, unique_name, dtm)

    fd.setReturnType(ret_dt)

    args_text = args_text.strip()
    if args_text == "" or args_text == "void":
        return fd

    # Parameter details don't matter for global typing; keep placeholders
    try:
        argn = 1 + args_text.count(",")
        params = []
        for i in range(argn):
            params.append(
                ParameterDefinitionImpl(
                    "a%d" % i, PointerDataType(VoidDataType.dataType), ""
                )
            )
        fd.setArguments(params)
    except Exception:
        pass

    return fd


def datatype_from_record(
    rec: GlobalEntry, dtm: DataTypeManager
) -> tuple[DataType, str]:
    types = rec.types

    # "c_decl": "uint8_t rgPalGray[20]",
    decl = types.c_decl
    if not decl:
        return None, "empty type"

    is_far_ptr = types.is_far_ptr
    parsed = parse_c_decl(decl)

    if parsed.kind == "funcptr":
        fn_name = "fn_%s" % sanitize_name(rec.name, "sym")
        fd = _make_func_def(dtm, parsed.ret, parsed.args, fn_name)
        return _pointer_dt(fd, is_far_ptr), None

    base_name = parsed.base
    if not base_name:
        return None, "could not parse base type from '%s'" % decl

    base_dt = c_type_to_data_type(base_name)
    if base_dt is None:
        base_dt = _resolve_named_type(base_name)
    if base_dt is None:
        return None, "could not resolve base type '%s' (from '%s')" % (base_name, decl)

    dt = base_dt
    stars = parsed.stars
    dims = parsed.dims

    if parsed.kind == "normal" and parsed.ptr_to_array:
        # pointer-to-array: build the array first, then apply pointer(s)
        if dims:
            dt2 = _wrap_arrays(dt, dims)
            if dt2 is None:
                return None, "zero-length array in '%s' (skip)" % decl
            dt = dt2
        if stars > 0:
            dt = _wrap_pointers(dt, stars, is_far_ptr)
    else:
        # normal: pointers bind before arrays (array-of-pointers)
        if stars > 0:
            dt = _wrap_pointers(dt, stars, is_far_ptr)
        if dims:
            dt2 = _wrap_arrays(dt, dims)
            if dt2 is None:
                return None, "zero-length array in '%s' (skip)" % decl
            dt = dt2

    # A handful of external/stdlib placeholders end up with length 0 in the DTM.
    # We don't care about these; skip them quietly.
    try:
        if dt.getLength() == 0:
            return None, "datatype length is 0 (skip)"
    except Exception:
        pass

    return dt, None


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


def main():
    print("---- ApplyNb09GlobalsFromJson ----")

    json_file = askFile("Select nb09_ghidra_globals.json", "Open")
    path = json_file.getAbsolutePath()

    root = load_nb09_ghidra_globals(path)

    globals = root.globals
    if not globals:
        popup("No globals found in JSON: %s" % path)
        return

    symtab = currentProgram.getSymbolTable()
    listing = currentProgram.getListing()
    dtm = currentProgram.getDataTypeManager()

    typed = 0
    type_ok = 0
    type_failed = 0

    for rec in globals:
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
        dt, err = datatype_from_record(rec, dtm)
        if dt is None:
            if err and "zero-length array" in str(err):
                print("[TYPE-SKIP] %s @ %s: %s" % (name, addr_str, err))
            elif err and "datatype length is 0" in str(err):
                print("[TYPE-SKIP] %s @ %s: datatype length is 0" % (name, addr_str))
            else:
                print("[TYPE-FAIL] %s @ %s: %s" % (name, addr_str, err))
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

    print("---- ApplyNb09GlobalsFromJson summary ----")
    print("Globals processed : %d" % len(globals))
    print("Types set         : %d" % typed)
    print("Types already ok  : %d" % type_ok)
    print("Types failed      : %d" % type_failed)
    print("----------------------------------------")


if __name__ == "__main__":
    main()
