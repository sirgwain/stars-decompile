# UpdateWin16WindowsApiSignatures.py
# @category Stars
#
# Apply Win16 Windows API prototypes (from WINDOWS.H or similar) to the CURRENT program.
#
# This is meant to mimic Ghidra's "F" (Edit Function Signature) behavior for APIs referenced
# by your main EXE (e.g., stars26jrc3.exe), without requiring you to open USER.EXE/GDI.EXE.
#
# In a Win16 EXE, API calls commonly appear as:
#   * Imported/external functions (External Manager / EXTERNAL space), and/or
#   * Thunks/stubs inside the EXE (normal functions) that jump through an import table.
#
# This script updates BOTH kinds when found by name:
#   - normal functions in the program (FunctionManager)
#   - external functions/locations (ExternalManager), creating an external function if needed
#
# Example desired signature:
#   __pascal16far BOOL BitBlt(HDC, int, int, int, int, HDC, int, int, DWORD)
#
# Notes:
# - Your project uses 32-bit pointers for Win16 far pointers ("*32" model); FAR_PTR_SIZE controls that.
# - The header parsing is intentionally lightweight; it handles classic SDK prototypes reasonably well.
#
from __future__ import print_function

import re

# make IDE register built ins
try:
    from ghidra.ghidra_builtins import *
    from ghidra.program.model.listing import *

    currentProgram = currentProgram  # type: Program
except:
    pass

from ghidra.program.model.symbol import SourceType, SymbolType
from ghidra.program.model.listing import ParameterImpl
from ghidra.program.model.data import CategoryPath, TypedefDataType, PointerDataType

# Optional structure helpers (availability varies by Ghidra version)
try:
    from ghidra.program.model.data import StructureDataType, ArrayDataType
except Exception:
    StructureDataType = None
    ArrayDataType = None

# Prefer concrete BuiltIn datatypes over DataTypeManager.parseDataType(),
# which is inconsistent across Ghidra versions and can yield Undefined types.
_BUILTIN_DT = {}
try:
    from ghidra.program.model.data import (
        VoidDataType,
        CharDataType,
        UnsignedCharDataType,
        ShortDataType,
        UnsignedShortDataType,
        LongDataType,
        UnsignedLongDataType,
        Undefined1DataType,
        Undefined2DataType,
        Undefined4DataType,
    )

    _BUILTIN_DT = {
        "void": VoidDataType.dataType,
        "char": CharDataType.dataType,
        "uchar": UnsignedCharDataType.dataType,
        "i16": ShortDataType.dataType,
        "u16": UnsignedShortDataType.dataType,
        "i32": LongDataType.dataType,
        "u32": UnsignedLongDataType.dataType,
        "u1": Undefined1DataType.dataType,
        "u2": Undefined2DataType.dataType,
        "u4": Undefined4DataType.dataType,
    }
except Exception:
    _BUILTIN_DT = {}

# DataTypeConflictHandler moved around across versions; optional
DataTypeConflictHandler = None
try:
    from ghidra.program.model.data import DataTypeConflictHandler as _DTCH

    DataTypeConflictHandler = _DTCH
except Exception:
    DataTypeConflictHandler = None

# FunctionUpdateType import varies by Ghidra version
FunctionUpdateType = None
try:
    from ghidra.program.model.listing import FunctionUpdateType as _FUT

    FunctionUpdateType = _FUT
except Exception:
    try:
        from ghidra.program.model.listing.Function import FunctionUpdateType as _FUT2

        FunctionUpdateType = _FUT2
    except Exception:
        FunctionUpdateType = None

WINDOWS_H_PROMPT = "Select WINDOWS.H (Win16 SDK header)"
PREFERRED_CALLING_CONVENTION = "__pascal16far"
# _WINDOWS_CAT_PATH = CategoryPath("/windows")
_CAT_PATH = CategoryPath("/stars")

# Far pointer size (your project uses 32-bit pointers for Win16 far pointers)
FAR_PTR_SIZE = 4

# ------------------------------------------------------------
# Header parsing
# ------------------------------------------------------------

_re_comment_block = re.compile(r"/\*.*?\*/", re.S)
_re_comment_line = re.compile(r"//.*?$", re.M)
_proto_re = re.compile(r"^(?P<left>.+?)\((?P<args>.*?)\)\s*;\s*$")

# Tokens to strip from prototypes while resolving types.
# (We still force calling convention separately via setCallingConvention.)
STRIP_TOKENS = set(
    [
        "WINAPI",
        "APIENTRY",
        "CALLBACK",
        "PASCAL",
        "_pascal",
        "__pascal",
        "FAR",
        "NEAR",
        "far",
        "near",
        "__far",
        "__near",
        "cdecl",
        "__cdecl",
        "huge",
        "__huge",
        "EXPORT",
        "__export",
        "extern",
    ]
)

# should be short __stdcallfar wsprintf (char *32 dst, char *32 fmt, ...)
API_OVERRIDES = [
    {
        "name": "wsprintf",
        "ret": "short",
        "cc": "__cdecl16far",
        "args": ["char *32 dst", "char *32 fmt", "..."],
        "varargs": True,
    },
    {
        "name": "_wsprintf",
        "ret": "short",
        "cc": "__cdecl16far",
        "args": ["char *32 dst", "char *32 fmt", "..."],
        "varargs": True,
    },
    {
        "name": "MessageBox",
        "ret": "short",
        "cc": "__pascal16far",
        "args": ["HWND hwnd", "LPCSTR text", "LPCSTR caption", "MessageBoxFlags uType"],
    },

]


def _strip_comments(text):
    text = _re_comment_block.sub(" ", text)
    text = _re_comment_line.sub(" ", text)
    return text


def _collapse_ws(s):
    return re.sub(r"\s+", " ", s).strip()


def _extract_statements(text):
    """Split into ';' terminated statements after stripping comments and preprocessor lines."""
    text = _strip_comments(text)
    text = re.sub(r"\\\n", " ", text)  # backslash continuation
    lines = []
    for ln in text.splitlines():
        if ln.lstrip().startswith("#"):
            continue
        lines.append(ln)
    text = "\n".join(lines)

    stmts = []
    cur = []
    for ch in text:
        cur.append(ch)
        if ch == ";":
            s = _collapse_ws("".join(cur))
            cur = []
            if s:
                stmts.append(s)
    return stmts


def _split_args(arg_blob):
    arg_blob = _collapse_ws(arg_blob)
    if not arg_blob or arg_blob == "void":
        return []

    parts = []
    cur = []
    depth = 0
    for ch in arg_blob:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            parts.append(_collapse_ws("".join(cur)))
            cur = []
        else:
            cur.append(ch)
    tail = _collapse_ws("".join(cur))
    if tail:
        parts.append(tail)
    return parts


def _drop_param_name(arg_type_str):
    """Convert 'HDC hdc' -> 'HDC', 'const char *psz' -> 'const char *'.

    Intentionally simplistic; aimed at SDK-style prototypes.
    """
    s = _collapse_ws(arg_type_str)
    if not s:
        return s

    # Function pointer parameters: keep as-is (too hard to split safely here).
    if "(" in s and ")" in s and "*" in s:
        return s

    toks = s.split(" ")
    if len(toks) == 1:
        return s

    last = toks[-1]
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", last):
        prev = toks[-2]
        if not prev.endswith("*") and not prev.endswith("]"):
            return _collapse_ws(" ".join(toks[:-1]))
    return s


def _parse_prototype(stmt):
    """Return (ret_type_str, name, [param_type_strs], raw_stmt) or None."""
    m = _proto_re.match(stmt)
    if not m:
        return None

    left = _collapse_ws(m.group("left"))
    args = _collapse_ws(m.group("args"))

    # Ignore typedefs / function pointer typedefs
    if left.startswith("typedef "):
        return None

    ltoks = left.split(" ")
    if len(ltoks) < 2:
        return None

    name = ltoks[-1]
    ret = _collapse_ws(" ".join(ltoks[:-1]))

    if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
        return None

    raw_args = _split_args(args)
    param_types = [_drop_param_name(a) for a in raw_args]
    return (ret, name, param_types, stmt, False)


# ------------------------------------------------------------
# Data type helpers
# ------------------------------------------------------------


def _dt_parse(dtm, decl_str):
    try:
        # parse a C decl into a datatype (works well once typedefs exist)
        return dtm.parseDataType(decl_str)
    except Exception:
        return None


def _dt_path(dtm, path_str):
    try:
        return dtm.getDataType(path_str)
    except Exception:
        return None


def _pointer_of(dtm, dt, size):
    try:
        return PointerDataType(dt, size, dtm)
    except Exception:
        try:
            return PointerDataType(dt)
        except Exception:
            return dt


def _ensure_typedef(dtm, cat, name, base_dt):
    """Create/replace a typedef under cat."""
    try:
        td = TypedefDataType(cat, name, base_dt)
        if DataTypeConflictHandler is not None:
            return dtm.addDataType(td, DataTypeConflictHandler.REPLACE_HANDLER)
        return dtm.addDataType(td, None)
    except Exception:
        # If it already exists or cannot be replaced, just fetch what we can.
        try:
            return dtm.getDataType(cat, name)
        except Exception:
            return base_dt


def _ensure_struct(dtm, cat, name, total_size, fields=None, min_align=2):
    """Create/replace a structure under cat.

    fields: optional list of tuples:
        (offset, DataType, field_name)

    If StructureDataType is unavailable (older Ghidra), returns None.
    """
    if StructureDataType is None:
        return None

    try:
        st = StructureDataType(cat, name, 0)
        try:
            st.setExplicitMinimumAlignment(int(min_align))
        except Exception:
            pass

        # Ensure backing size exists
        st.growStructure(int(total_size))

        if fields:
            for off, dt, fname in fields:
                if dt is None:
                    continue
                try:
                    st.replaceAtOffset(int(off), dt, int(dt.getLength()), fname, None)
                except Exception:
                    # If replaceAtOffset is not available, fall back to just leaving padding.
                    pass

        if DataTypeConflictHandler is not None:
            return dtm.addDataType(st, DataTypeConflictHandler.REPLACE_HANDLER)
        return dtm.addDataType(st, None)
    except Exception:
        try:
            return dtm.getDataType(cat, name)
        except Exception:
            return None


def _build_win16_typedefs(program: Program):
    """Inject minimal Win16 typedefs so WINDOWS.H prototypes resolve in this program."""
    dtm = program.getDataTypeManager()
    cat = _CAT_PATH

    # primitives: prefer built-ins (stable across versions), else fall back to manager paths
    t_void = _BUILTIN_DT.get("void") or _dt_path(dtm, "/void")
    t_char = _BUILTIN_DT.get("char") or _dt_path(dtm, "/char")
    t_i16 = _BUILTIN_DT.get("i16") or _dt_path(dtm, "/short")
    t_u16 = _BUILTIN_DT.get("u16") or _dt_path(dtm, "/ushort")
    t_i32 = _BUILTIN_DT.get("i32") or _dt_path(dtm, "/long")
    t_u32 = _BUILTIN_DT.get("u32") or _dt_path(dtm, "/ulong")

    # fallbacks
    t_undef1 = _BUILTIN_DT.get("u1") or _dt_path(dtm, "/undefined1")
    t_undef2 = _BUILTIN_DT.get("u2") or _dt_path(dtm, "/undefined2")
    t_undef4 = _BUILTIN_DT.get("u4") or _dt_path(dtm, "/undefined4")

    if t_void is None:
        t_void = t_undef2
    if t_char is None:
        t_char = t_undef1
    if t_i16 is None:
        t_i16 = t_undef2
    if t_u16 is None:
        t_u16 = t_undef2
    if t_i32 is None:
        t_i32 = t_undef4 or t_undef2
    if t_u32 is None:
        t_u32 = t_undef4 or t_undef2

    typedefs = {}

    # scalar typedefs
    scalars = {
        "BOOL": t_i16,
        "INT": t_i16,
        # plain 'int' in Win16 headers is 16-bit
        "int": t_i16,
        "UINT": t_u16,
        "WORD": t_u16,
        "DWORD": t_u32,
        "LONG": t_i32,
        "COLORREF": t_u32,
        "ATOM": t_u16,
        "WPARAM": t_u16,
        "LPARAM": t_i32,
        "LRESULT": t_i32,
        "BYTE": t_undef1,
    }

    # Win16 handles are 16-bit
    for hn in [
        "HACCEL",
        "HANDLE",
        "HBITMAP",
        "HBRUSH",
        "HCURSOR",
        "HDC",
        "HFILE",
        "HFONT",
        "HGDIOBJ",
        "HGLOBAL",
        "HHOOK",
        "HICON",
        "HINSTANCE",
        "HLOCAL",
        "HMENU",
        "HPALETTE",
        "HPEN",
        "HRGN",
        "HRSRC",
        "HWND",
    ]:
        scalars[hn] = t_u16

    for nm, base in scalars.items():
        typedefs[nm] = _ensure_typedef(dtm, cat, nm, base)

    # --------------------------------------------------------
    # Common Win16 API structs used in signatures.
    #
    # This script often runs before your NB09 struct import, so we create
    # minimal (but correctly-sized) definitions here under /windows.
    # Your later struct-packing/import script can REPLACE these with the
    # authoritative layouts.
    # --------------------------------------------------------

    # Helpers to fetch common scalar typedefs we just created
    t_BOOL = typedefs.get("BOOL", t_i16)
    t_HDC = typedefs.get("HDC", t_u16)
    t_BYTE = typedefs.get("BYTE", t_undef1)

    typedefs["POINT"] = dtm.getDataType(cat, "POINT")
    typedefs["POINT"] = dtm.getDataType(cat, "POINT")
    typedefs["RECT"] = dtm.getDataType(cat, "RECT")
    typedefs["LOGFONT"] = dtm.getDataType(cat, "LOGFONT")
    typedefs["TEXTMETRIC"] = dtm.getDataType(cat, "TEXTMETRIC")
    typedefs["PAINTSTRUCT"] = dtm.getDataType(cat, "PAINTSTRUCT")
    typedefs["DRAWITEMSTRUCT"] = dtm.getDataType(cat, "DRAWITEMSTRUCT")
    typedefs["MEASUREITEMSTRUCT"] = dtm.getDataType(cat, "MEASUREITEMSTRUCT")
    typedefs["WNDCLASS"] = dtm.getDataType(cat, "WNDCLASS")
    typedefs["WINDOWPLACEMENT"] = dtm.getDataType(cat, "WINDOWPLACEMENT")
    typedefs["MSG"] = dtm.getDataType(cat, "MSG")
    typedefs["OPENFILENAME"] = dtm.getDataType(cat, "OPENFILENAME")
    typedefs["TIMERINFO"] = dtm.getDataType(cat, "TIMERINFO")
    typedefs["PD"] = dtm.getDataType(cat, "PD")
    typedefs["BITMAP"] = dtm.getDataType(cat, "BITMAP")
    typedefs["BITMAPCOREHEADER"] = dtm.getDataType(cat, "BITMAPCOREHEADER")
    typedefs["BITMAPINFOHEADER"] = dtm.getDataType(cat, "BITMAPINFOHEADER")
    typedefs["BITMAPINFO"] = dtm.getDataType(cat, "BITMAPINFO")
    typedefs["LOGPALETTE"] = dtm.getDataType(cat, "LOGPALETTE")
    typedefs["OFSTRUCT"] = dtm.getDataType(cat, "OFSTRUCT")
    typedefs["MessageBoxFlags"] = dtm.getDataType(cat, "MessageBoxFlags")

    # pointer typedefs (far)
    typedefs["LPSTR"] = _ensure_typedef(
        dtm, cat, "LPSTR", _pointer_of(dtm, t_char, FAR_PTR_SIZE)
    )
    typedefs["LPCSTR"] = _ensure_typedef(
        dtm, cat, "LPCSTR", _pointer_of(dtm, t_char, FAR_PTR_SIZE)
    )
    typedefs["LPVOID"] = _ensure_typedef(
        dtm, cat, "LPVOID", _pointer_of(dtm, t_void, FAR_PTR_SIZE)
    )
    typedefs["LPCVOID"] = _ensure_typedef(
        dtm, cat, "LPCVOID", _pointer_of(dtm, t_void, FAR_PTR_SIZE)
    )

    # common far proc pointer approximation
    typedefs["FARPROC"] = _ensure_typedef(
        dtm, cat, "FARPROC", _pointer_of(dtm, t_void, FAR_PTR_SIZE)
    )

    return typedefs


def _resolve_type(program, typedefs, type_str):
    dtm = program.getDataTypeManager()

    s = _collapse_ws(type_str)
    if not s:
        return _dt_path(dtm, "/undefined2")

    # Count explicit "*32" occurrences and normalize them to '*' so base parsing
    # doesn't see the "32" as a token.
    ptr32_count = len(re.findall(r"\*\s*32\b", s))
    s = re.sub(r"\*\s*32\b", "*", s)

    # Count pointers, strip '*' from tokens
    star_count = s.count("*")
    s = s.replace("*", " ")

    toks = [t for t in s.split(" ") if t]
    toks = [t for t in toks if t not in STRIP_TOKENS and t not in ("const", "volatile")]

    # Drop any bare numeric tokens that can show up after "*" stripping.
    toks = [t for t in toks if not re.match(r"^\d+$", t)]

    signed = None
    if toks and toks[0] in ("signed", "unsigned"):
        signed = toks[0]
        toks = toks[1:]

    def resolve_base(base):
        base_lower = base.lower()

        if base_lower == "void":
            return _BUILTIN_DT.get("void") or _dt_path(dtm, "/undefined2")
        if base_lower == "char":
            return _BUILTIN_DT.get("char") or _dt_path(dtm, "/undefined1")
        if base_lower in ("int", "short", "short int"):
            return _BUILTIN_DT.get(
                "u16" if signed == "unsigned" else "i16"
            ) or _dt_path(dtm, "/undefined2")
        if base_lower in ("long", "long int"):
            return _BUILTIN_DT.get("u32" if signed == "unsigned" else "i32") or (
                _BUILTIN_DT.get("u4") or _dt_path(dtm, "/undefined2")
            )
        if base in typedefs:
            return typedefs[base]

        dt_direct = _dt_parse(dtm, base)
        if dt_direct is not None:
            return dt_direct

        return None

    # First try with all tokens (some types are multiword)
    base = _collapse_ws(" ".join(toks))
    dt = resolve_base(base)

    # If that failed and we have >1 token, assume last token may be a parameter name
    # and retry without it (e.g. "char dst", "POINT *32 pt").
    if dt is None and len(toks) > 1:
        base2 = _collapse_ws(" ".join(toks[:-1]))
        dt = resolve_base(base2)
        if dt is not None:
            base = base2  # for later heuristics

    if dt is None:
        # Heuristic: LPXxx => far pointer to Xxx
        if base.startswith("LP") and len(base) > 2:
            inner = base[2:]
            inner_dt = typedefs.get(inner)
            if inner_dt is None:
                if inner.lower() == "str":
                    inner_dt = _dt_parse(dtm, "char") or _dt_path(dtm, "/undefined1")
                else:
                    inner_dt = _dt_path(dtm, "/undefined1")
            dt = _pointer_of(dtm, inner_dt, FAR_PTR_SIZE)
            star_count = 0
            ptr32_count = 0  # already applied
        elif re.match(r"^H[A-Z0-9_]+$", base):
            dt = typedefs.get(
                "HANDLE",
                _dt_parse(dtm, "unsigned short") or _dt_path(dtm, "/undefined2"),
            )
        else:
            dt = _dt_path(dtm, "/undefined2")

    # Apply pointers:
    try:
        from ghidra.program.model.data import Pointer32DataType
    except Exception:
        Pointer32DataType = None

    for _ in range(ptr32_count):
        if Pointer32DataType is not None:
            dt = Pointer32DataType(dt)
        else:
            dt = _pointer_of(dtm, dt, 4)

    for _ in range(star_count - ptr32_count):
        dt = _pointer_of(dtm, dt, FAR_PTR_SIZE)

    return dt


# ------------------------------------------------------------
# Function lookup + application
# ------------------------------------------------------------


def _replace_params(func, params, source):
    """Replace parameters using whichever overload exists."""
    if FunctionUpdateType is not None:
        fut = None
        for attr in (
            "DYNAMIC_STORAGE_ALL_PARAMS",
            "DYNAMIC_STORAGE_FORMAL_PARAMS",
            "CUSTOM_STORAGE",
        ):
            if hasattr(FunctionUpdateType, attr):
                fut = getattr(FunctionUpdateType, attr)
                break
        try:
            func.replaceParameters(fut, True, source, params)
            return True, None
        except TypeError:
            pass
        except Exception as e:
            return False, str(e)
        try:
            func.replaceParameters(params, fut, True, source)
            return True, None
        except TypeError:
            pass
        except Exception as e:
            return False, str(e)

    try:
        func.replaceParameters(params, source)
        return True, None
    except Exception as e:
        return False, str(e)


def _available_calling_conventions(program):
    try:
        cc = program.getCompilerSpec().getCallingConventions()
        return [c.getName() for c in cc]
    except Exception:
        return []


def _name_variants(name):
    """Generate plausible name variants seen in Win16 import/thunk symbols."""
    vars = []
    for n in [name, name.upper(), name.lower()]:
        vars.append(n)
        vars.append("_" + n)
    # de-dupe while preserving order
    out = []
    seen = set()
    for v in vars:
        if v not in seen:
            out.append(v)
            seen.add(v)
    return out


def _find_target_functions(program, name):
    """Return list of Function objects in current program matching `name` (incl externals)."""
    fm = program.getFunctionManager()
    symtab = program.getSymbolTable()
    extmgr = program.getExternalManager()

    found = []
    seen_ids = set()

    def _add_fn(fn):
        if fn is None:
            return
        # de-dupe by entry point address string
        try:
            key = str(fn.getEntryPoint())
        except Exception:
            key = str(id(fn))
        if key in seen_ids:
            return
        seen_ids.add(key)
        found.append(fn)

    # 1) Normal functions by name variants (FunctionManager has a fast lookup)
    for v in _name_variants(name):
        try:
            f = fm.getFunction(v)
            _add_fn(f)
        except Exception:
            pass

    # 2) Symbols (sometimes the function name exists but isn't picked up above, or duplicates exist)
    for v in _name_variants(name):
        try:
            syms = symtab.getSymbols(v)
            if syms is None:
                continue
            it = syms.iterator() if hasattr(syms, "iterator") else syms
            for s in it:
                try:
                    obj = s.getObject()
                except Exception:
                    obj = None
                try:
                    if obj is not None and hasattr(obj, "getEntryPoint"):
                        _add_fn(obj)
                except Exception:
                    pass
        except Exception:
            pass

    # 3) Externals (imports): update/create external functions by name variants
    for v in _name_variants(name):
        try:
            locs = extmgr.getExternalLocations(v)
        except Exception:
            locs = None

        if not locs:
            continue

        for loc in locs:
            fn = None
            try:
                fn = loc.getFunction()
            except Exception:
                fn = None

            if fn is None:
                # Some versions let you create a function from the external location.
                try:
                    fn = loc.createFunction()
                except Exception:
                    fn = None

            _add_fn(fn)

    return found


def _set_varargs(fn, is_varargs):
    """Best-effort toggle of a Function's varargs flag across Ghidra versions."""
    try:
        fn.setVarArgs(is_varargs)
        return True
    except Exception:
        pass

    return False
    try:
        # Some older branches only expose isVarArgs(); if so, we can't set.
        if hasattr(fn, "isVarArgs"):
            # nothing we can do
            return False
    except Exception:
        pass
    return False


def _apply_signature_to_function(
    program, fn, name, ret_dt, param_dts, raw_stmt, is_varargs=False, cc_override=None
):
    ep = fn.getEntryPoint()
    print("[APPLY] %s  %-24s <- %s" % (ep, fn.getName(), raw_stmt))

    ok = True
    try:
        fn.setReturnType(ret_dt, SourceType.USER_DEFINED)
    except Exception as e:
        ok = False
        print("  [ERR] setReturnType failed: %s" % e)

    params = []
    for i, pdt in enumerate(param_dts):
        params.append(ParameterImpl("param_%d" % (i + 1), pdt, program))

    okp, err = _replace_params(fn, params, SourceType.USER_DEFINED)
    if not okp:
        ok = False
        print("  [ERR] replaceParameters failed: %s" % err)

    if is_varargs:
        if not _set_varargs(fn, True):
            # Not fatal; some versions don't allow toggling.
            print("  [WARN] could not mark function as varargs")

    try:
        fn.setCallingConvention(cc_override or PREFERRED_CALLING_CONVENTION)
    except Exception as e:
        # Keep going; not fatal.
        print("  [WARN] calling convention not set: %s" % e)

    return ok


def run():
    print("UpdateWin16WindowsApiSignatures.py> Running...")

    prog = currentProgram
    if prog is None:
        print("[FATAL] No current program")
        return

    # Check for script arguments first (headless mode)
    args = getScriptArgs()
    if args and len(args) > 0:
        header_path = args[0]
        print("UpdateWin16WindowsApiSignatures.py> using argument: %s" % header_path)
    else:
        # Interactive mode - ask user
        header = askFile(WINDOWS_H_PROMPT, "Open")
        if header is None:
            print("[INFO] cancelled")
            return
        header_path = header.getAbsolutePath()

    print("UpdateWin16WindowsApiSignatures.py> reading %s" % header_path)
    try:
        raw = open(header_path, "rb").read()
        try:
            text = raw.decode("utf-8", "ignore")
        except Exception:
            text = raw.decode("latin-1", "ignore")
    except Exception as e:
        print("[FATAL] Could not read header at '%s': %s" % (header_path, e))
        return

    # Ensure typedefs exist so parseDataType has a chance.
    typedefs = _build_win16_typedefs(prog)

    # Check calling convention exists (helps debugging your custom win16fix build).
    avail_cc = _available_calling_conventions(prog)
    if avail_cc and PREFERRED_CALLING_CONVENTION not in avail_cc:
        print(
            "[WARN] preferred calling convention '%s' not in compiler spec. Available: %s"
            % (PREFERRED_CALLING_CONVENTION, ", ".join(avail_cc))
        )

    stmts = _extract_statements(text)
    protos = []
    for st in stmts:
        p = _parse_prototype(st)
        if p is not None:
            protos.append(p)

    # Append hard-coded overrides (applied even if not present in the header).
    for o in API_OVERRIDES:
        nm = o.get("name")
        if not nm:
            continue
        ret_s = o.get("ret", "void")
        args_s = o.get("args", [])
        is_va = bool(o.get("varargs", False))
        protos.append((ret_s, nm, args_s, "override %s" % nm, is_va))

    print(
        "UpdateWin16WindowsApiSignatures.py> preferred calling convention: %s"
        % PREFERRED_CALLING_CONVENTION
    )
    print(
        "UpdateWin16WindowsApiSignatures.py> extracted %d candidate prototypes"
        % len(protos)
    )

    updated = 0
    missing = 0
    parseFail = 0
    applyFail = 0
    multi = 0

    # Map of name -> calling convention override (from API_OVERRIDES)
    cc_overrides = {}
    for o in API_OVERRIDES:
        nm = o.get("name")
        if nm and o.get("cc"):
            cc_overrides[nm] = o.get("cc")

    for ret_str, name, arg_strs, raw_stmt, is_varargs in protos:
        targets = _find_target_functions(prog, name)
        if not targets:
            missing += 1
            continue

        if len(targets) > 1:
            multi += 1

        try:
            ret_dt = _resolve_type(prog, typedefs, ret_str)

            # If prototype is varargs, drop the trailing "..." from the concrete parameter list.
            if is_varargs and arg_strs and arg_strs[-1].strip() == "...":
                arg_strs = arg_strs[:-1]

            param_dts = [_resolve_type(prog, typedefs, a) for a in arg_strs]
        except Exception as e:
            parseFail += 1
            print("[PARSEFAIL] %s <- %s (%s)" % (name, raw_stmt, e))
            continue

        any_ok = False
        for fn in targets:
            ok = _apply_signature_to_function(
                prog,
                fn,
                name,
                ret_dt,
                param_dts,
                raw_stmt,
                is_varargs=is_varargs,
                cc_override=cc_overrides.get(name),
            )
            any_ok = any_ok or ok

        if any_ok:
            updated += 1
        else:
            applyFail += 1

    print("")
    print("UpdateWin16WindowsApiSignatures.py> done")
    print("  updated prototypes: %d" % updated)
    print(
        "  missing:           %d (prototype name not found as function/external)"
        % missing
    )
    print("  parseFail:         %d" % parseFail)
    print("  applyFail:         %d (found target(s) but could not apply)" % applyFail)
    print(
        "  multi-hit:         %d (prototypes that matched >1 function/external)" % multi
    )


# Ghidra runs scripts by executing the file; call run() directly.
run()
