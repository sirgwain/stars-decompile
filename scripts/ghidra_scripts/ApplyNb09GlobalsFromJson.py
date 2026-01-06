# -*- coding: utf-8 -*-
# ApplyNb09GlobalsFromJson.py
# @category Stars

import json
import re

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import (
    CategoryPath,
    StructureDataType,
    ArrayDataType,
    PointerDataType,
    Pointer32DataType,
    FunctionDefinitionDataType,
    ParameterDefinitionImpl,
    VoidDataType,
    BooleanDataType,
    CharDataType,
    ByteDataType,
    ShortDataType,
    UnsignedShortDataType,
    IntegerDataType,
    LongDataType,
    UnsignedLongDataType,
    UnsignedIntegerDataType,
    DataUtilities,
)
from ghidra.program.model.data.DataUtilities import ClearDataMode
from ghidra.program.model.data import DataTypeConflictHandler

# Unsigned 8-bit name differs across versions.
try:
    from ghidra.program.model.data import UnsignedByteDataType as _Unsigned8
except Exception:
    from ghidra.program.model.data import UnsignedCharDataType as _Unsigned8

# Signed 8-bit may not exist.
try:
    from ghidra.program.model.data import SignedByteDataType as _Signed8
except Exception:
    _Signed8 = ByteDataType

# DataType classes vary slightly across Ghidra versions; keep imports tolerant.
try:
    from ghidra.program.model.data import (
        DataType, Structure, Union, Enum, Array, Pointer, BuiltInDataType, TypeDef
    )
except Exception:
    from ghidra.program.model.data import (
        DataType, Structure, Union, Enum, Array, Pointer, BuiltInDataType
    )
    TypeDef = None  # type: ignore

PREFERRED_CATEGORY_PREFIXES = [
    "/stars",     # your structs
    "/NB09",      # if you store NB09 stuff here
    "/windows",   # if you imported windows types into a folder
    "/",          # anything else
]

def _is_typedef(dt):
    try:
        if TypeDef is not None and isinstance(dt, TypeDef):
            return True
    except Exception:
        pass
    try:
        cn = dt.getClass().getSimpleName()
        return ("Typedef" in cn) or cn.startswith("TypeDef")
    except Exception:
        return False


def _dt_kind_rank(dt):
    # lower is better
    if isinstance(dt, Structure):
        return 0
    if _is_typedef(dt):
        return 1
    return 2


def build_dt_index(dtm):
    """
    Returns:
      by_name:  name -> [DataType...]
      by_path:  fullPath -> DataType
    """
    by_name = {}
    by_path = {}
    it = dtm.getAllDataTypes()
    for dt in it:
        name = dt.getName()
        path = dt.getDataTypePath().getPath()  # e.g. "/stars/SHDEF"
        by_path[path] = dt
        by_name.setdefault(name, []).append(dt)

    # sort each list by (category preference, kind rank)
    def cat_rank(dt):
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

def resolve_named_type(type_name, by_name, by_path):
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
            candidates.append(tn[len(pref):].strip())

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

dtm = currentProgram.getDataTypeManager()
BY_NAME, BY_PATH = build_dt_index(dtm)

_RE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_RE_ARRAY = re.compile(r"\[(\d+)\]")
_RE_FUNC_PTR = re.compile(r"^\s*(?P<ret>[A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\*\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\)\s*\((?P<args>.*)\)\s*$")
_RE_PTR_TO_ARRAY_HEAD = re.compile(r"^\s*(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\*\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\)\s*$")

# Module-global cache (Jython can keep module state across runs)
_DT_NAME_INDEX = None


def _norm(s):
    if s is None:
        return ""
    return str(s).strip()


def _sanitize_name(name, fallback):
    out = []
    for c in name:
        if c.isalnum() or c == "_":
            out.append(c)
        else:
            out.append("_")
    s = "".join(out)
    return s if s else fallback


def _dedupe_name(symtab, name, addr, max_tries=1000):
    if symtab.getGlobalSymbol(name, addr) is None:
        return name
    for i in range(1, max_tries + 1):
        cand = "%s_%d" % (name, i)
        if symtab.getGlobalSymbol(cand, addr) is None:
            return cand
    return "%s_%d" % (name, max_tries + 1)


def _primitive_dt(name):
    n = name.strip()
    if n in ("int8_t", "signed char"):
        return _Signed8.dataType
    if n in ("uint8_t", "byte"):
        return ByteDataType.dataType
    if n == "char":
        return CharDataType.dataType
    if n in ("bool", "_Bool"):
        return BooleanDataType.dataType
    if n in ("int16_t", "short"):
        return IntegerDataType.dataType
    if n in ("uint16_t", "unsigned short"):
        return UnsignedIntegerDataType.dataType
    if n in ("int32_t", "int", "long"):
        return LongDataType.dataType
    if n in ("uint32_t", "unsigned int", "unsigned long"):
        return UnsignedLongDataType.dataType
    if n == "void":
        return VoidDataType.dataType
    return None


def _ensure_dt_name_index(dtm):
    """Build a simple-name -> DataType map for the current program."""
    global _DT_NAME_INDEX
    if _DT_NAME_INDEX is not None:
        return

    idx = {}
    try:
        it = dtm.getAllDataTypes()
        # Some builds return a Java Iterator, others a Python iterable.
        if hasattr(it, "hasNext") and hasattr(it, "next"):
            while it.hasNext():
                dt = it.next()
                try:
                    nm = dt.getName()
                except Exception:
                    continue
                if nm and nm not in idx:
                    idx[nm] = dt
        else:
            for dt in it:
                try:
                    nm = dt.getName()
                except Exception:
                    continue
                if nm and nm not in idx:
                    idx[nm] = dt
    except Exception:
        idx = {}

    _DT_NAME_INDEX = idx


def _dtm_find_by_name(dtm, name):
    _ensure_dt_name_index(dtm)
    try:
        dt = _DT_NAME_INDEX.get(name, None)
        if dt is not None:
            return dt
    except Exception:
        pass

    # Prefer exact match by name anywhere in the DTM.
    # Ghidra APIs vary a bit across versions, so try a few approaches.

    # 1) Newer-ish API: findDataTypes(name, list)
    try:
        hits = []
        dtm.findDataTypes(name, hits)
        if hits:
            # Prefer typedefs/structs/enums over built-in placeholders.
            for dt in hits:
                try:
                    if dt.getName() == name:
                        return dt
                except Exception:
                    pass
            return hits[0]
    except Exception:
        pass

    # 2) Some builds have getDataType(CategoryPath,name)
    try:
        dt = dtm.getDataType(CategoryPath.ROOT, name)
        if dt is not None:
            return dt
    except Exception:
        pass

    return None


def _resolve_named_type(dtm, name):
    # Exact first
    dt = _dtm_find_by_name(dtm, name)
    if dt is not None:
        return dt

    # Common typedef/struct naming patterns
    candidates = [
        "tag" + name,            # POINT -> tagPOINT
        "_" + name,              # RPT -> _RPT or _rpt
        name.lower(),
        "_" + name.lower(),
        "tag" + name.lower(),
        name.upper(),
        "_" + name.upper(),
    ]
    for cand in candidates:
        dt = _dtm_find_by_name(dtm, cand)
        if dt is not None:
            return dt

    # Create very common Win16 structs if they are missing (reduces noise).
    if name in ("POINT", "RECT"):
        try:
            if name == "POINT":
                st = StructureDataType("POINT", 0)
                st.add(ShortDataType.dataType, 2, "x", None)
                st.add(ShortDataType.dataType, 2, "y", None)
            else:
                st = StructureDataType("RECT", 0)
                st.add(ShortDataType.dataType, 2, "left", None)
                st.add(ShortDataType.dataType, 2, "top", None)
                st.add(ShortDataType.dataType, 2, "right", None)
                st.add(ShortDataType.dataType, 2, "bottom", None)

            dt_added = dtm.addDataType(st, DataTypeConflictHandler.DEFAULT_HANDLER)
            # Refresh index so subsequent lookups see it.
            global _DT_NAME_INDEX
            _DT_NAME_INDEX = None
            _ensure_dt_name_index(dtm)
            return dt_added
        except Exception:
            pass

    return None


def _pointer_dt(base_dt, is_far_ptr):
    if is_far_ptr:
        # FAR pointer => 4 bytes
        try:
            return Pointer32DataType(base_dt)
        except Exception:
            # Very old builds sometimes only allow default
            return Pointer32DataType.dataType
    # NEAR pointer => default pointer size (Win16 segments: 2 bytes in your setup)
    return PointerDataType(base_dt)


def _wrap_pointers(base_dt, star_count, is_far_ptr):
    dt = base_dt
    for _ in range(star_count):
        dt = _pointer_dt(dt, is_far_ptr)
    return dt


def _wrap_arrays(base_dt, dims):
    dt = base_dt
    # Build from inner to outer
    for n in reversed(dims):
        n_int = int(n)
        if n_int == 0:
            return None
        el_len = dt.getLength()
        if el_len <= 0:
            el_len = 1
        dt = ArrayDataType(dt, n_int, el_len)
    return dt


def _parse_decl(decl):
    """
    Supports:
      - primitives / named typedefs
      - pointers '*'
      - arrays [N][M]...
      - function pointers: 'ret (*name)(args)'
    """
    s = _norm(decl)
    # NB09 sometimes encodes FAR pointers in the C decl using "*32".
    # The pointer size itself comes from types.is_far_ptr; "32" here is just
    # a marker and must NOT become part of the base type name.
    # Normalize these so parsing works consistently:
    #   "char *32 p"            -> "char * p"
    #   "int16_t (*32 fn)(void)" -> "int16_t (* fn)(void)"
    # Normalize both "*32" and "(*32 name)" forms.
    s = re.sub(r"\(\s*\*\s*32\b", "(*", s)
    s = re.sub(r"\*32\b", "*", s)
    if s.endswith(";"):
        s = s[:-1].strip()

    m = _RE_FUNC_PTR.match(s)
    if m:
        return {"kind": "funcptr", "ret": m.group("ret"), "args": m.group("args").strip()}

    # Remove initializer if present
    if "=" in s:
        s = s.split("=", 1)[0].strip()

    dims = _RE_ARRAY.findall(s)
    s_no_arr = _RE_ARRAY.sub("", s).strip()

    # Pointer-to-array head: "T (*name)" (after arrays stripped)
    m2 = _RE_PTR_TO_ARRAY_HEAD.match(s_no_arr)
    if m2:
        return {"kind": "normal", "base": m2.group("base"), "stars": 1, "dims": dims}

    # Drop trailing variable name token if present
    parts = s_no_arr.split()
    if len(parts) >= 2:
        last = parts[-1]
        last_no_ptr = last.lstrip("*")
        if _RE_NAME.match(last_no_ptr):
            parts = parts[:-1]
            s_no_arr = " ".join(parts)

    stars = s_no_arr.count("*")
    base = re.sub(r"\s+", " ", s_no_arr.replace("*", " ")).strip()

    return {"kind": "normal", "base": base, "stars": stars, "dims": dims}


def _make_func_def(dtm, ret_name, args_text, unique_name):
    # Return type
    ret_dt = _primitive_dt(ret_name)
    if ret_dt is None:
        ret_dt = _resolve_named_type(dtm, ret_name)
    if ret_dt is None:
        ret_dt = VoidDataType.dataType

    # Construct function definition datatype
    try:
        fd = FunctionDefinitionDataType(unique_name)
    except Exception:
        fd = FunctionDefinitionDataType(CategoryPath.ROOT, unique_name, dtm)

    try:
        fd.setReturnType(ret_dt)
    except Exception:
        pass

    args_text = args_text.strip()
    if args_text == "" or args_text == "void":
        return fd

    # Parameter details don't matter for global typing; keep placeholders
    try:
        argn = 1 + args_text.count(",")
        params = []
        for i in range(argn):
            params.append(ParameterDefinitionImpl("a%d" % i, PointerDataType(VoidDataType.dataType), ""))
        fd.setArguments(params)
    except Exception:
        pass

    return fd


def datatype_from_record(rec, dtm):
    ty = rec.get("types", {}) or {}

    # IMPORTANT: prefer c_decl (it preserves dims/placement) and covers c_type==None cases
    decl = _norm(ty.get("c_decl")) or _norm(ty.get("c_type"))
    if not decl:
        return None, "empty type"

    is_far_ptr = bool(ty.get("is_far_ptr", False))
    parsed = _parse_decl(decl)

    if parsed.get("kind") == "funcptr":
        fn_name = "fn_%s" % _sanitize_name(rec.get("name", "sym"), "sym")
        fd = _make_func_def(dtm, parsed.get("ret"), parsed.get("args"), fn_name)
        return _pointer_dt(fd, is_far_ptr), None

    base_name = parsed.get("base", "")
    if not base_name:
        return None, "could not parse base type from '%s'" % decl

    base_dt = _primitive_dt(base_name)
    if base_dt is None:
        base_dt = _resolve_named_type(dtm, base_name)
    if base_dt is None:
        return None, "could not resolve base type '%s' (from '%s')" % (base_name, decl)

    dt = base_dt
    stars = int(parsed.get("stars", 0))
    dims = parsed.get("dims", [])

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


def _is_undefined_data(data):
    if data is None:
        return True
    try:
        dt = data.getDataType()
        if dt is None:
            return True
        nm = dt.getName()
        return nm is not None and nm.startswith("undefined")
    except Exception:
        return False


def _force_clear_and_create(listing, addr, dt):
    """UI-style overwrite: clear any overlapping code/data, then create dt."""
    dt_len = int(dt.getLength())
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
        currentProgram, addr, dt, -1, False,
        ClearDataMode.CLEAR_ALL_CONFLICT_DATA
    )


def main():
    global _DT_NAME_INDEX
    _DT_NAME_INDEX = None

    json_file = askFile("Select nb09_ghidra_globals.json", "Open")
    path = json_file.getAbsolutePath()

    f = open(path, "rb")
    try:
        root = json.load(f)
    finally:
        f.close()

    items = root.get("globals", [])
    if not items:
        popup("No globals found in JSON: %s" % path)
        return

    symtab = currentProgram.getSymbolTable()
    listing = currentProgram.getListing()
    dtm = currentProgram.getDataTypeManager()

    renamed = 0
    created = 0
    label_skipped = 0
    typed = 0
    type_ok = 0
    type_failed = 0

    for rec in items:
        name = rec.get("name") or ""
        gh = rec.get("ghidra", {}) or {}
        addr_str = gh.get("addr") or ""
        default_label = gh.get("default_label") or ""

        if not addr_str:
            print("[TYPE-FAIL] %s: missing ghidra.addr" % name)
            type_failed += 1
            continue

        try:
            addr = toAddr(addr_str)
        except Exception as e:
            print("[TYPE-FAIL] %s @ %s: bad addr (%s)" % (name, addr_str, str(e)))
            type_failed += 1
            continue

        # ----- Label -----
        sym = symtab.getPrimarySymbol(addr)
        desired = _sanitize_name(name, default_label if default_label else "sym")
        desired = _dedupe_name(symtab, desired, addr)

        if sym is None:
            try:
                symtab.createLabel(addr, desired, SourceType.USER_DEFINED)
                print("[LABEL-CREATE] %s @ %s" % (desired, addr_str))
                created += 1
            except Exception as e:
                print("[LABEL-FAIL] %s @ %s: %s" % (desired, addr_str, str(e)))
        else:
            cur = sym.getName()
            if cur != desired and cur == default_label:
                try:
                    sym.setName(desired, SourceType.USER_DEFINED)
                    print("[LABEL-RENAME] %s -> %s @ %s" % (cur, desired, addr_str))
                    renamed += 1
                except Exception as e:
                    print("[LABEL-FAIL] %s @ %s: %s" % (cur, addr_str, str(e)))
            else:
                print("[LABEL-SKIP]  %s @ %s (existing='%s')" % (desired, addr_str, cur))
                label_skipped += 1

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
            cur_dt = d.getDataType() if d is not None else None
            if cur_dt is not None and cur_dt.getName() == dt.getName():
                print("[TYPE-OK]   %s @ %s (%s)" % (name, addr_str, dt.getName()))
                type_ok += 1
            else:
                _force_clear_and_create(listing, addr, dt)
                if cur_dt is not None:
                    print("[TYPE-SET]  %s @ %s := %s (was %s)" % (
                        name, addr_str, dt.getName(), cur_dt.getName()
                    ))
                else:
                    print("[TYPE-SET]  %s @ %s := %s" % (name, addr_str, dt.getName()))
                typed += 1
        except (Exception, Throwable) as e:
            msg = str(e)
            if "datatype length is 0" in msg:
                print("[TYPE-SKIP] %s @ %s: datatype length is 0" % (name, addr_str))
            else:
                print("[TYPE-FAIL] %s @ %s: apply failed (%s)" % (name, addr_str, msg))
                type_failed += 1

    print("---- ApplyNb09GlobalsFromJson summary ----")
    print("Globals processed : %d" % len(items))
    print("Labels created    : %d" % created)
    print("Labels renamed    : %d" % renamed)
    print("Labels skipped    : %d" % label_skipped)
    print("Types set         : %d" % typed)
    print("Types already ok  : %d" % type_ok)
    print("Types failed      : %d" % type_failed)
    print("----------------------------------------")


if __name__ == "__main__":
    main()
