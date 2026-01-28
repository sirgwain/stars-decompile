from dataclasses import dataclass
import re
from symtable import SymbolTable
from typing import Any, Literal, TypeAlias
import json
from collections import deque

# make IDE register built ins
try:
    from ghidra.ghidra_builtins import *
    from ghidra.program.model.listing import *

    currentProgram = currentProgram  # type: Program
except:
    pass

from ghidra.program.model.data import (
    DataTypeManager,
    DataType,
    CategoryPath,
    ArrayDataType,
    BooleanDataType,
    ByteDataType,
    ByteDataType,
    CharDataType,
    DoubleDataType,
    FloatDataType,
    FunctionDefinitionDataType,
    LongDataType,
    LongDoubleDataType,
    ParameterDefinitionImpl,
    Pointer32DataType,
    Pointer16DataType,
    PointerDataType,
    ShortDataType,
    SignedByteDataType,
    TypedefDataType,
    UnsignedLongDataType,
    UnsignedShortDataType,
    VoidDataType,
)
from ghidra.program.model.address import Address

# ----- category paths -----
DEFAULT_CAT_PATH = CategoryPath("/stars")
_WINDOWS_CAT_PATH = CategoryPath("/windows")
_CATEGORY_PATHS = [DEFAULT_CAT_PATH, _WINDOWS_CAT_PATH, CategoryPath("/")]

_RE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_RE_ARRAY = re.compile(r"\[(\d+)\]")
_RE_FUNC_PTR = re.compile(
    r"^\s*(?P<ret>[A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\*\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\)\s*\((?P<args>.*)\)\s*$"
)
_RE_PTR_TO_ARRAY_HEAD = re.compile(
    r"^\s*(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\*\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\)\s*$"
)

# ----- log helpers -----


def log(s):
    print(s)


def warn(s):
    print("[WARN] " + s)


def err(s):
    print("[ERR] " + s)


# ----- common leaf types -----


@dataclass
class CvRef:
    seg: int
    off: int
    typind: int
    rectyp: int
    flags: int
    from_: str  # JSON key "from"
    proc: str  # used by LABELs


@dataclass
class SegMap:
    frame: int
    base_off: int
    iSegName: int
    segname: str
    iClassName: int
    flags: int
    group: int


@dataclass
class GhidraRef:
    selector: int
    off: int
    addr: str
    default_label: str
    frame: int
    base_off: int


@dataclass
class VarInfo:
    name: str
    kind: str  # "param" or "local"
    typind: int
    c_type: str
    c_decl: str
    size: int
    is_far_ptr: bool
    bp_off: int
    # Pre-parsed declaration info from parse_c_decl(c_decl)
    decl: "DeclInfo | None" = None
    # If decl.base maps to a builtin DataType (via c_type_to_data_type), this is the
    # fully wrapped datatype (pointers/arrays applied). Otherwise None.
    base_dt: "DataType | None" = None


@dataclass
class RetInfo:
    c_type: str
    is_far_ptr: bool
    is_32bit: bool
    size: int
    # Pre-parsed declaration info from parse_c_decl(c_type)
    decl: "DeclInfo | None" = None
    # If decl.base maps to a builtin DataType (via c_type_to_data_type), this is the
    # fully wrapped datatype (pointers/arrays applied). Otherwise None.
    base_dt: "DataType | None" = None


@dataclass(frozen=True, slots=True)
class Entry:
    name: str
    cv: CvRef
    segmap: SegMap
    ghidra: GhidraRef


# ----- PROC typing -----


@dataclass
class ProcTypes:
    typind: int
    proto: str
    tags: list[str]
    is_pascal: bool
    ret: RetInfo
    params: list[VarInfo]
    locals: list[VarInfo]


@dataclass(frozen=True, slots=True)
class ProcEntry(Entry):
    types: ProcTypes


# ----- GLOBAL/LABEL/PUBLIC entries (from globals list) -----


@dataclass
class GlobalTypes:
    typind: int
    c_type: str
    c_decl: str
    kind: str
    is_far_ptr: bool
    # Pre-parsed declaration info from parse_c_decl(c_decl)
    decl: "DeclInfo | None" = None
    # If decl.base maps to a builtin DataType (via c_type_to_data_type), this is the
    # fully wrapped datatype (pointers/arrays applied). Otherwise None.
    base_dt: "DataType | None" = None


@dataclass(frozen=True, slots=True)
class GlobalEntry(Entry):
    types: GlobalTypes


@dataclass(frozen=True, slots=True)
class LabelEntry(Entry):
    pass


# ----- Structs -----


@dataclass
class StructField:
    kind: str
    name: str
    offset: int
    typind: int
    bitlen: int
    bitpos: int
    c_type: str
    c_decl: str
    override_c_type: str
    is_far_ptr: bool
    # Pre-parsed declaration info from parse_c_decl(c_decl)
    decl: "DeclInfo | None" = None
    # If decl.base maps to a builtin DataType (via c_type_to_data_type), this is the
    # fully wrapped datatype (pointers/arrays applied). Otherwise None.
    base_dt: "DataType | None" = None


@dataclass
class StructEntry:
    name: str
    typind: int
    kind: str
    raw_name: str
    size: int
    fieldlist: int | None
    fields: list[StructField]


# ----- Root entries -----


@dataclass
class Nb09GhidraGlobals:
    globals: list[GlobalEntry]
    procs: list[ProcEntry]
    labels: list[LabelEntry]


@dataclass
class Nb09GhidraStructs:
    structs: list[StructEntry]


# ----- decoding helpers -----


def _try_parse_c_decl(text: str | None) -> "DeclInfo | None":
    """Best-effort parse of a C decl/type string into DeclInfo.

    This is intentionally tolerant: on any parse failure, returns None.
    """
    if not text:
        return None
    try:
        return parse_c_decl(text)
    except Exception:
        return None


def _try_build_wrapped_builtin_dt(
    decl_info: DeclInfo | None,
    is_far_ptr: bool,
) -> DataType | None:
    """If decl_info.base is a known builtin C type, build a wrapped DataType.

    This is intentionally lightweight and does NOT consult the program DTM.
    It only succeeds for primitives handled by c_type_to_data_type().
    """

    if decl_info is None:
        return None

    # Function pointers require FunctionDefinitionDataType (needs DTM); skip.
    if decl_info.kind != "normal":
        return None

    base_name = decl_info.base
    if not base_name:
        return None

    base_dt = c_type_to_data_type(base_name)
    if base_dt is None:
        return None

    return wrapped_datatype(base_dt, decl_info, is_far_ptr)


def _cv(d: dict[str, Any]) -> CvRef:
    return CvRef(
        seg=d.get("seg"),
        off=d.get("off"),
        typind=d.get("typind"),
        rectyp=d.get("rectyp"),
        flags=d.get("flags"),
        from_=d.get("from"),
        proc=d.get("proc"),
    )


def _segmap(d: dict[str, Any]) -> SegMap:
    return SegMap(
        frame=d["frame"],
        base_off=d["base_off"],
        iSegName=d.get("iSegName"),
        segname=d.get("segname"),
        iClassName=d.get("iClassName"),
        flags=d.get("flags"),
        group=d.get("group"),
    )


def _ghidra(d: dict[str, Any]) -> GhidraRef:
    return GhidraRef(
        selector=d["selector"],
        off=d["off"],
        addr=d["addr"],
        default_label=d["default_label"],
        frame=d["frame"],
        base_off=d.get("base_off", 0),
    )


def _var(d: dict[str, Any]) -> VarInfo:
    c_decl = d.get("c_decl")
    is_far_ptr = bool(d.get("is_far_ptr"))
    decl = _try_parse_c_decl(c_decl)
    return VarInfo(
        name=d["name"],
        kind=d.get("kind") or "",
        typind=d.get("typind"),
        c_type=d.get("c_type"),
        c_decl=c_decl,
        size=d.get("size"),
        is_far_ptr=is_far_ptr,
        bp_off=d.get("bp_off"),
        decl=decl,
        base_dt=_try_build_wrapped_builtin_dt(decl, is_far_ptr),
    )


def _ret(d: dict[str, Any]) -> RetInfo:
    c_type = d.get("c_type")
    is_far_ptr = bool(d.get("is_far_ptr"))
    decl = _try_parse_c_decl(c_type)
    return RetInfo(
        c_type=c_type,
        is_far_ptr=is_far_ptr,
        is_32bit=d.get("is_32bit"),
        size=d.get("size"),
        decl=decl,
        base_dt=_try_build_wrapped_builtin_dt(decl, is_far_ptr),
    )


def _proc_types(d: dict[str, Any]) -> ProcTypes:
    return ProcTypes(
        typind=d.get("typind"),
        proto=d.get("proto"),
        tags=list(d.get("tags") or []),
        is_pascal=d.get("is_pascal"),
        ret=_ret(d.get("ret") or {}),
        params=[_var(x) for x in (d.get("params") or [])],
        locals=[_var(x) for x in (d.get("locals") or [])],
    )


def _global_types(d: dict[str, Any]) -> GlobalTypes:
    c_decl = d.get("c_decl")
    is_far_ptr = bool(d.get("is_far_ptr"))
    decl = _try_parse_c_decl(c_decl)
    return GlobalTypes(
        typind=d.get("typind"),
        c_type=d.get("c_type"),
        c_decl=c_decl,
        kind=d.get("kind"),
        is_far_ptr=is_far_ptr,
        decl=decl,
        base_dt=_try_build_wrapped_builtin_dt(decl, is_far_ptr),
    )


def _struct_field(d: dict[str, Any]) -> StructField:
    c_decl = d.get("c_decl")
    is_far_ptr = bool(d.get("is_far_ptr", False))
    decl = _try_parse_c_decl(c_decl)
    return StructField(
        name=d["name"],
        kind=d.get("kind", ""),
        typind=d.get("typind", 0),
        offset=d.get("offset", 0),
        bitlen=d.get("bitlen", 0),
        bitpos=d.get("bitpos", 0),
        c_type=d.get("c_type"),
        c_decl=c_decl,
        override_c_type=d.get("override_c_type"),
        is_far_ptr=is_far_ptr,
        decl=decl,
        base_dt=_try_build_wrapped_builtin_dt(decl, is_far_ptr),
    )


# convert a c_type like int16_t to a ghidra DataType like ShortDataType
def c_type_to_data_type(c_type: str) -> DataType | None:
    n = c_type.strip()
    if n in ("int8_t", "signed char"):
        return SignedByteDataType.dataType
    if n in ("uint8_t", "byte"):
        return ByteDataType.dataType
    if n == "char":
        return CharDataType.dataType
    if n in ("bool", "_Bool"):
        return BooleanDataType.dataType
    if n in ("int16_t", "short"):
        return ShortDataType.dataType
    if n in ("uint16_t", "unsigned short"):
        return UnsignedShortDataType.dataType
    if n in ("int32_t", "long"):
        return LongDataType.dataType
    if n in ("uint32_t", "unsigned long"):
        return UnsignedLongDataType.dataType
    if n in ("double"):
        return DoubleDataType.dataType
    if n in ("float"):
        return FloatDataType.dataType
    if n in ("long double"):
        return LongDoubleDataType.dataType
    if n == "void":
        return VoidDataType.dataType
    return None


def sanitize_name(name: str, fallback: str) -> str:
    # sanitize a symbol name
    if not name:
        name = fallback or "SYM"

    out = []
    for c in name:
        if c.isalnum() or c == "_":
            out.append(c)
        else:
            out.append("_")
    s = "".join(out)
    if not s:
        s = fallback or "SYM"
    if s[0].isdigit():
        s = "_" + s
    return s


def dedupe_name(symtab: SymbolTable, name: str, addr: Address, max_tries=1000):
    if symtab.getGlobalSymbol(name, addr) is None:
        return name
    for i in range(1, max_tries + 1):
        cand = "%s_%d" % (name, i)
        if symtab.getGlobalSymbol(cand, addr) is None:
            return cand
    return "%s_%d" % (name, max_tries + 1)


def dts_by_name(dtm: DataTypeManager) -> dict[str, DataType]:
    """Build a simple-name -> DataType map for the current program."""
    idx: dict[str, DataType] = {}
    try:
        for dt in dtm.getAllDataTypes():
            dt = dt  # type: DataType
            nm = dt.getName()
            if nm and nm not in idx:
                idx[nm] = dt
    except Exception:
        idx = {}

    return idx


def make_func_def(
    dtm: DataTypeManager, ret_name: str, args_text: str, unique_name: str
) -> FunctionDefinitionDataType:
    # make a FunctionDefinitionDataType for a function pointer
    # Return type
    ret_dt = c_type_to_data_type(ret_name)
    if ret_dt is None:
        ret_dt = VoidDataType.dataType

    # Construct function definition datatype
    fd = FunctionDefinitionDataType(CategoryPath.ROOT, unique_name, dtm)

    fd.setReturnType(ret_dt)

    args_text = args_text.strip()
    if args_text == "" or args_text == "void":
        return fd

    # Parameter details don't matter; keep placeholders
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


def pointer_dt(base_dt: DataType, is_far_ptr: bool) -> DataType:
    # Turn a DataType into a pointer to the DataType
    if is_far_ptr:
        # FAR pointer => 4 bytes
        return Pointer32DataType(base_dt)
    # NEAR pointer => default pointer size (Win16 segments: 2 bytes in your setup)
    return Pointer16DataType(base_dt)


def wrap_pointers(base_dt: DataType, star_count: int, is_far_ptr: bool) -> DataType:
    # For each *, wrap the base DataType as a pointer
    dt = base_dt
    for _ in range(star_count):
        dt = pointer_dt(dt, is_far_ptr)
    return dt


def wrap_arrays(base_dt: DataType, dims: list[int]) -> DataType:
    # For each dimension of an array, wrap the base DataType as an array
    dt = base_dt
    # Build from inner to outer
    for n in reversed(dims):
        # TODO: if this is an array of near pointers, dt.getLength() will return 4 regardless of the pointer
        num_elements = n or 0
        element_length = dt.getLength()
        dt = ArrayDataType(dt, num_elements, element_length)
    return dt


def _unwrap_typedef(dt: DataType) -> DataType:
    if isinstance(dt, TypedefDataType):
        dt = dt  # type: TypedefDataType
        b = dt.getBaseDataType()
        if b is not None:
            return b
    return dt


def lookup_type(dtm: DataTypeManager, name: str, cat_paths=_CATEGORY_PATHS) -> DataType:
    """
    Lookup a DataType by name, from a given list of category paths
    """
    for cat_path in cat_paths:
        dt = dtm.getDataType(cat_path, name)
        if dt is not None:
            return _unwrap_typedef(dt)
    return None


def wrapped_datatype(dt: DataType, decl_info: DeclInfo, is_far_ptr: bool) -> DataType:
    stars = decl_info.stars
    dims = decl_info.dims
    wrapped_dt = dt

    if decl_info.kind == "normal" and decl_info.ptr_to_array:
        # pointer-to-array: build the array first, then apply pointer(s)
        if dims:
            wrapped_dt = wrap_arrays(wrapped_dt, dims)
        if stars > 0:
            wrapped_dt = wrap_pointers(wrapped_dt, stars, is_far_ptr)
    else:
        # normal: pointers bind before arrays (array-of-pointers)
        if stars > 0:
            wrapped_dt = wrap_pointers(wrapped_dt, stars, is_far_ptr or decl_info.array_of_far_ptrs)
        if dims:
            wrapped_dt = wrap_arrays(wrapped_dt, dims)

    return wrapped_dt


def datatype_from_decl_info(
    dtm: DataTypeManager,
    name: str,
    decl_info: DeclInfo,
    is_far_ptr: bool,
    cat_paths=_CATEGORY_PATHS,
) -> tuple[DataType, str]:
    """
    Return a DataType from a c_decl

    ex:
    c_decl: "uint8_t rgPalGray[20]"
    """

    if decl_info.kind == "funcptr":
        fn_name = "fn_%s" % sanitize_name(name, "sym")
        fd = make_func_def(dtm, decl_info.ret, decl_info.args, fn_name)
        return pointer_dt(fd, is_far_ptr), None

    base_name = decl_info.base

    base_dt = c_type_to_data_type(base_name)
    if base_dt is None:
        base_dt = lookup_type(dtm, base_name, cat_paths)
        print(
            f"datatype_from_decl_info: lookup_type {name} - decl_info: {decl_info.base} ptr_to_array={decl_info.ptr_to_array} is_far_ptr={is_far_ptr} base_dt={base_dt.getName()}"
        )
    if base_dt is None:
        return (
            None,
            "could not resolve base type '%s' (from '%s')"
            % (
                base_name,
                decl_info.base,
            ),
        )

    dt = wrapped_datatype(base_dt, decl_info, is_far_ptr)

    return dt, None


# --- typed DeclInfo ---


@dataclass(frozen=True, slots=True)
class NormalDeclInfo:
    kind: Literal["normal"]
    base: str  # e.g. "int16_t", "ENGINE", "char"
    stars: int  # number of '*' after FAR "*32" normalization
    dims: list[int]  # array dimensions, e.g. [10][4] -> [10, 4]
    ptr_to_array: bool = False
    array_of_far_ptrs: bool = False


@dataclass(frozen=True, slots=True)
class FuncPtrDeclInfo:
    kind: Literal["funcptr"]
    ret: str  # return type text (as captured)
    args: str  # argument text inside (...)
    base: str = ""


DeclInfo: TypeAlias = NormalDeclInfo | FuncPtrDeclInfo


def parse_c_decl(c_decl: str) -> DeclInfo:
    """
    Parse a C-style declaration string into a typed DeclInfo.

    Handles primitive and typedef-based types, pointer qualifiers ('*'),
    arrays ([N][M]...), pointer-to-array forms, and function pointers.

    NB09/Ghidra-specific notes:
      - FAR pointer markers encoded as '*32' are normalized away here.
        Pointer size semantics are tracked separately via type metadata.
      - This is a syntactic parser, not a full C grammar implementation.

    Returns:
        DeclInfo:
            - NormalDeclInfo for standard types (base + pointer depth + dims)
            - FuncPtrDeclInfo for function pointer declarations
    """

    s = c_decl.strip()

    # if this is an array of far pointers, we need to record that for future wrapped_datatype calls
    _maybe_array_of_far_ptrs = s.find("*32") != -1

    # NB09 sometimes encodes FAR pointers in the C decl using "*32".
    # The pointer size itself comes from types.is_far_ptr; "32" here is just
    # a marker and must NOT become part of the base type name.
    # we do need to record it, however, in order to track arrays of far pointers
    #
    # Normalize both "*32" and "(*32 name)" forms.
    s = re.sub(r"\(\s*\*\s*32\b", "(*", s)
    s = re.sub(r"\*32\b", "*", s)

    if s.endswith(";"):
        s = s[:-1].strip()

    m = _RE_FUNC_PTR.match(s)
    if m:
        return FuncPtrDeclInfo(
            kind="funcptr",
            ret=m.group("ret").strip(),
            args=m.group("args").strip(),
        )

    # Remove initializer if present
    if "=" in s:
        s = s.split("=", 1)[0].strip()

    # Arrays
    dim_strs = _RE_ARRAY.findall(s)  # usually list[str] like ["10","4"]
    dims = [int(x, 10) for x in dim_strs if x]  # list[int]
    s_no_arr = _RE_ARRAY.sub("", s).strip()

    # Pointer-to-array head: "T (*name)" (after arrays stripped)
    m2 = _RE_PTR_TO_ARRAY_HEAD.match(s_no_arr)
    if m2:
        return NormalDeclInfo(
            kind="normal",
            base=m2.group("base").strip(),
            stars=1,
            dims=dims,
            ptr_to_array=True,
            array_of_far_ptrs=_maybe_array_of_far_ptrs,
        )

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

    return NormalDeclInfo(
        kind="normal",
        base=base,
        stars=stars,
        dims=dims,
        array_of_far_ptrs=(len(dims) > 0 and _maybe_array_of_far_ptrs),
    )


def load_nb09_structs(path: str) -> Nb09GhidraStructs:
    with open(path, "r", encoding="utf-8") as f:
        root = json.load(f)

    structs: list[StructEntry] = []
    for e in root.get("structs", []):
        structs.append(
            StructEntry(
                name=e["name"],
                raw_name=e.get("raw_name", ""),
                typind=int(e.get("typind", 0)),
                kind=e.get("kind", ""),
                size=e.get("size", 0),
                fieldlist=int(e.get("fieldList", 0)),
                fields=([_struct_field(f) for f in e.get("fields", [])]),
            )
        )

    print(f"loaded {path} -> structs={len(structs)}")

    return Nb09GhidraStructs(structs=structs)


def load_nb09_ghidra_globals(path: str) -> Nb09GhidraGlobals:
    with open(path, "r", encoding="utf-8") as f:
        root = json.load(f)

    globals_list: list[GlobalEntry] = []
    for e in root.get("globals", []):
        globals_list.append(
            GlobalEntry(
                name=e["name"],
                cv=_cv(e.get("cv") or {}),
                types=(
                    _global_types(e["types"])
                    if "types" in e and e["types"] is not None
                    else None
                ),
                segmap=_segmap(e["segmap"]),
                ghidra=_ghidra(e["ghidra"]),
            )
        )

    procs_list: list[ProcEntry] = []
    for e in root.get("procs", []):
        procs_list.append(
            ProcEntry(
                name=e["name"],
                cv=_cv(e.get("cv") or {}),
                types=_proc_types(e.get("types") or {}),
                segmap=_segmap(e["segmap"]),
                ghidra=_ghidra(e["ghidra"]),
            )
        )

    labels_list: list[LabelEntry] = []
    for e in root.get("labels", []):
        labels_list.append(
            LabelEntry(
                name=e["name"],
                cv=_cv(e.get("cv") or {}),
                segmap=_segmap(e["segmap"]),
                ghidra=_ghidra(e["ghidra"]),
            )
        )

    print(
        f"loaded {path} -> globals={len(globals_list)}, procs={len(procs_list)}, labels={len(labels_list)}"
    )

    return Nb09GhidraGlobals(
        globals=globals_list,
        procs=procs_list,
        labels=labels_list,
    )
