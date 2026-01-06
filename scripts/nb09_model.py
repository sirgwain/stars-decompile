#!/usr/bin/env python3
"""
nb09_model.py — structured model objects for CodeView NB09 parsing.

These classes are intentionally "data first": they store parsed results in a way that
downstream generator scripts can query without re-implementing CodeView parsing.

Design goals:
- stable field names matching CodeView concepts (seg/off are runtime addresses; symoff is symbol-stream offset)
- keep derived fields (typ, c_type) clearly labeled
- provide .to_dict() for JSON export
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# Minimal CodeView simple/primitive type mapping used by Stars!.
# Keys are typinds (e.g. 0x0072 = T_INT2). Values are (cv_name, c_name, size_bytes).
CV_PRIM_MODE_DIRECT = 0x00
CV_PRIM_MODE_NEAR   = 0x01  # 16-bit near pointer (offset)
CV_PRIM_MODE_FAR    = 0x02  # 16:16 far pointer
CV_PRIM_MODE_HUGE   = 0x03  # 16:16 huge pointer (normalized far)
CV_PRIM_MODE_NEAR32 = 0x04  # 32-bit near pointer (flat offset)
CV_PRIM_MODE_FAR32  = 0x05  # 16:32 far pointer
CV_PRIM_MODE_NEAR64 = 0x06  # 64-bit near pointer
# 0x07 reserved


def cv_prim_ptr_size_bytes(mode: int) -> int:
    """Return pointer size in bytes for a CodeView primitive mode."""
    mode &= 0x07
    if mode == CV_PRIM_MODE_DIRECT:
        return 0
    if mode == CV_PRIM_MODE_NEAR:
        return 2
    if mode in (CV_PRIM_MODE_FAR, CV_PRIM_MODE_HUGE):
        return 4
    if mode in (CV_PRIM_MODE_NEAR32, CV_PRIM_MODE_FAR32):
        return 4
    if mode == CV_PRIM_MODE_NEAR64:
        return 8
    return 0


# Minimal CodeView simple/primitive type mapping used by Stars!.
# Keys are full primitive typinds (e.g. 0x0072 = T_INT2, 0x0170 = near ptr to T_RCHAR).
# Values are (cv_name, c_name, size_bytes). For pointer-encoded primitives, size_bytes is the *pointer* size.
#
# NOTE on "char":
#   - CodeView has both "signed char" (T_CHAR = 0x0010) and "plain char" (T_RCHAR = 0x0070).
#   - Stars!' NB09 uses T_RCHAR for most C "char" arrays (e.g. elemtype 0x0070).
CV_PRIMITIVE_BASE: Dict[int, Tuple[str, str, Optional[int]]] = {
    # --- Special ---
    0x0000: ("T_NOTYPE", "void", 0),
    0x0001: ("T_ABS", "uint16_t", 2),
    0x0002: ("T_SEGMENT", "uint16_t", 2),
    0x0003: ("T_VOID", "void", 0),

    # --- Character ---
    0x0010: ("T_CHAR", "int8_t", 1),      # signed char
    0x0020: ("T_UCHAR", "uint8_t", 1),    # unsigned char / BYTE
    0x0070: ("T_RCHAR", "char", 1),       # plain char
    0x0071: ("T_WCHAR", "uint16_t", 2),   # 16-bit wchar_t (Win16)

    # --- 16-bit short / 32-bit long ("real" forms) ---
    0x0011: ("T_SHORT", "int16_t", 2),
    0x0012: ("T_LONG", "int32_t", 4),
    0x0021: ("T_USHORT", "uint16_t", 2),
    0x0022: ("T_ULONG", "uint32_t", 4),

    # --- Explicit-size ints (CodeView "intN" forms) ---
    0x0072: ("T_INT2", "int16_t", 2),
    0x0073: ("T_UINT2", "uint16_t", 2),
    0x0074: ("T_INT4", "int32_t", 4),
    0x0075: ("T_UINT4", "uint32_t", 4),
    0x0076: ("T_INT8", "int64_t", 8),
    0x0077: ("T_UINT8", "uint64_t", 8),

    # --- Floating point ---
    0x0040: ("T_REAL32", "float", 4),
    0x0041: ("T_REAL64", "double", 8),
    0x0042: ("T_REAL80", "long double", 10),     # x87 80-bit float stored as 10 bytes
    0x0043: ("T_REAL128", "long double", 16),
    0x0044: ("T_REAL48", "double", 6),
}

# Full map including pointer-mode variants for any base types above.
CV_PRIMITIVES: Dict[int, Tuple[str, str, Optional[int]]] = dict(CV_PRIMITIVE_BASE)

for _base_tid, (_cvn, _cn, _sz) in list(CV_PRIMITIVE_BASE.items()):
    # Only synthesize pointer-mode variants for true base types (low byte encoding).
    if _base_tid > 0x00FF:
        continue
    for _mode in (
        CV_PRIM_MODE_NEAR,
        CV_PRIM_MODE_FAR,
        CV_PRIM_MODE_HUGE,
        CV_PRIM_MODE_NEAR32,
        CV_PRIM_MODE_FAR32,
        CV_PRIM_MODE_NEAR64,
    ):
        _tid = _base_tid | (_mode << 8)
        if _tid in CV_PRIMITIVES:
            continue
        _ptr_sz = cv_prim_ptr_size_bytes(_mode)
        # CV name: keep the base CV name and encode mode in a predictable way.
        _mode_name = {
            CV_PRIM_MODE_NEAR: "PN",
            CV_PRIM_MODE_FAR: "PF",
            CV_PRIM_MODE_HUGE: "PH",
            CV_PRIM_MODE_NEAR32: "P32N",
            CV_PRIM_MODE_FAR32: "P32F",
            CV_PRIM_MODE_NEAR64: "P64N",
        }.get(_mode, "P")
        CV_PRIMITIVES[_tid] = (f"{_cvn}_{_mode_name}", f"{_cn} *", _ptr_sz)



def is_far_ptrtype(ptrtype: int) -> bool:
    """True if a CodeView ptrtype encodes a far/huge pointer.

    For our purposes:
      0 = near
      1 = far
      2 = huge
      10 = near32
      11 = far32
    """
    return int(ptrtype) in (1, 2, 11)


def is_pascal_calltype(calltype: Optional[int]) -> bool:
    """True if calltype indicates a PASCAL-like calling convention (best-effort)."""
    return int(calltype or 0) in (2, 3)


# -----------------------------
# Heuristics: string-like names
# -----------------------------

_STRING_PREFIXES = ("sz", "psz", "pch", "lpsz", "lpch", "rgch", "rgsz")
_STRING_EXACT = {"sz", "psz", "pch", "lpsz", "lpch"}


def looks_like_string_name(name: str) -> bool:
    if not name:
        return False
    ln = name.lower()
    if ln in _STRING_EXACT:
        return True
    return ln.startswith(_STRING_PREFIXES)


def maybe_string_decl_from_typind(db: "Nb09Db", typind: int, name: str, *, byte_len_hint: int | None = None) -> str | None:
    """If `name` looks like a string, coerce common mis-decoded types to char buffers.

    This is intentionally shared between dump_nb09_c.py and dump_nb09_ghidra.py so
    that the same globals that print as `char szFoo[...];` in globals.h get the
    same declaration in the Ghidra automation JSON.
    """
    if not looks_like_string_name(name):
        return None
    try:
        rt = db.resolve_typind(int(typind))
    except Exception:
        return None

    # Pointer-to-integer -> char*
    if isinstance(rt, PointerType):
        base = rt.to
        if isinstance(base, PrimitiveType) and (base.size in (1, 2)):
            return f"char *{name}"

    # Integer array -> char[]
    if isinstance(rt, ArrayType):
        elem = rt.elem
        count = rt.count
        if isinstance(elem, PrimitiveType):
            total_bytes = int(rt.size) if isinstance(getattr(rt, "size", None), int) and int(rt.size or 0) > 0 else None

            if byte_len_hint is not None:
                return f"char {name}[{int(byte_len_hint)}]"

            if elem.size == 1:
                if total_bytes is not None:
                    return f"char {name}[{total_bytes}]"
                if isinstance(count, int) and count > 0:
                    return f"char {name}[{count}]"
                return None

            if elem.size == 2:
                if total_bytes is not None:
                    return f"char {name}[{total_bytes}]"
                if isinstance(count, int) and count > 0:
                    return f"char {name}[{count * 2}]"
                return None

    return None


# --------------------------------------------------------------------------------------
# Resolved type model
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ResolvedType:
    """Generator-friendly type shape resolved from a CodeView typind."""

    kind: str
    size: Optional[int] = None

    def to_c(self) -> str:
        raise NotImplementedError

    def to_c_style(self, style: str = "ghidra") -> str:
        """Render this type as a C-ish type expression.

        `style` controls pointer syntax:
          - "ghidra": emit `*32` for FAR/HUGE pointers (Ghidra-friendly)
          - "c":      emit plain `*` so the output compiles in a normal C toolchain.

        For non-pointer types, this is the same as :meth:`to_c`.
        """
        # Default: only pointer types care; they override this.
        return self.to_c()

    def c_decl(self, name: str) -> str:
        t = self.to_c()
        return f"{t} {name}".strip() if name else t

    def c_decl_style(self, name: str, style: str = "ghidra") -> str:
        """Render a declaration for `name` using the given pointer style."""
        t = self.to_c_style(style)
        return f"{t} {name}".strip() if name else t


@dataclass(frozen=True)
class UnknownType(ResolvedType):
    """Fallback type used when the NB09 type graph can't be fully resolved.

    Goal: keep generated C *compilable* while preserving approximate size when known.
    """

    def to_c(self) -> str:
        # Prefer a concrete C type so declarations compile.
        if self.size == 1:
            return "uint8_t"
        if self.size == 2:
            return "uint16_t"
        if self.size == 4:
            return "uint32_t"
        if self.size == 8:
            return "uint64_t"
        # Unknown or odd sizes: represent as bytes (caller may emit an array).
        return "uint8_t"

    def c_decl(self, name: str) -> str:
        # If we know the size and it's not one of the common scalars, emit as a byte array.
        if self.size and self.size not in (1,2,4,8):
            return f"uint8_t {name}[{self.size}]".strip()
        return f"{self.to_c()} {name}".strip()


@dataclass(frozen=True)
class PrimitiveType(ResolvedType):
    cv_name: str = ""
    c_name: str = ""

    def to_c(self) -> str:
        return self.c_name or self.cv_name or "/*primitive*/"


@dataclass(frozen=True)
class StructType(ResolvedType):
    name: str = ""  # tag name in debug info (e.g., _planet, tagRECT)
    typedef_name: str = ""  # cleaned alias (e.g., PLANET, RECT)
    fieldlist: Optional[int] = None

    def to_c(self) -> str:
        return self.typedef_name or self.name or "/*anon_struct*/"


@dataclass(frozen=True)
class UnionType(ResolvedType):
    name: str = ""  # tag name in debug info
    typedef_name: str = ""  # cleaned alias
    fieldlist: Optional[int] = None

    def to_c(self) -> str:
        return self.typedef_name or self.name or "/*anon_union*/"


@dataclass(frozen=True)
class EnumType(ResolvedType):
    name: str = ""  # tag name in debug info
    typedef_name: str = ""  # cleaned alias
    underlying: Optional[ResolvedType] = None

    def to_c(self) -> str:
        return self.typedef_name or self.name or "/*anon_enum*/"


@dataclass(frozen=True)
class BitfieldType(ResolvedType):
    base: ResolvedType = field(default_factory=lambda: UnknownType(kind="unknown", size=None))
    length: int = 0
    position: int = 0

    def to_c(self) -> str:
        # For declarations we typically use the base type.
        return self.base.to_c()


@dataclass(frozen=True)
class PointerType(ResolvedType):
    to: ResolvedType = field(default_factory=lambda: UnknownType(kind="unknown", size=None))
    ptrtype: int = 0  # 0 near,1 far,2 huge,10 near32,11 far32
    ptrmode: int = 0
    isflat32: bool = False

    def _star(self, style: str = "ghidra") -> str:
        """Return pointer declarator for this pointer kind.

        - style="ghidra": Win16 FAR/HUGE (and FAR32) pointers render as `*32`.
        - style="c":      always render as plain `*` (compilable C).
        """
        if style == "c":
            return "*"
        if self.ptrtype in (1, 2, 11):  # far, huge, far32
            return "*32"
        return "*"

    def to_c(self) -> str:
        # Backwards-compatible default: Ghidra pointer style.
        return self.to_c_style("ghidra")

    def to_c_style(self, style: str = "ghidra") -> str:
        star = self._star(style)

        # If pointing to a procedure type, emit a function-pointer type.
        # Not strict C when `*32` is used, but that's OK for the Ghidra path.
        if isinstance(self.to, ProcedureType):
            a = ", ".join(x.to_c_style(style) for x in self.to.args) or "void"
            return f"{self.to.ret.to_c_style(style)} ({star})({a})"

        return f"{self.to.to_c_style(style)} {star}"

    def c_decl(self, name: str) -> str:
        # Backwards-compatible default: Ghidra pointer style.
        return self.c_decl_style(name, "ghidra")

    def c_decl_style(self, name: str, style: str = "ghidra") -> str:
        star = self._star(style)

        # Pointer-to-procedure: `R (* name)(args)` / `R (*32 name)(args)`
        if isinstance(self.to, ProcedureType):
            a = ", ".join(x.to_c_style(style) for x in self.to.args) or "void"
            return f"{self.to.ret.to_c_style(style)} ({star} {name})({a})".strip()

        # Pointer-to-array: emit `T (* name)[N]` / `T (*32 name)[N]`
        if isinstance(self.to, ArrayType):
            base, dims = self.to._flatten()
            dim_s = "".join([f"[{d}]" if d is not None else "[1]" for d in dims])
            return f"{base.to_c_style(style)} ({star} {name}){dim_s}".strip()

        return f"{self.to.to_c_style(style)} {star} {name}".replace("  ", " ").strip()


@dataclass(frozen=True)
class ArrayType(ResolvedType):
    elem: ResolvedType = field(default_factory=lambda: UnknownType(kind="unknown", size=None))
    count: Optional[int] = None

    def _flatten(self) -> tuple[ResolvedType, list[Optional[int]]]:
        """Flatten nested array-of-array into (base_type, dims)."""
        dims: list[Optional[int]] = []
        t: ResolvedType = self
        while isinstance(t, ArrayType):
            dims.append(t.count)
            t = t.elem
        return t, dims

    def to_c(self) -> str:
        # Backwards-compatible default.
        return self.to_c_style("ghidra")

    def to_c_style(self, style: str = "ghidra") -> str:
        base, dims = self._flatten()
        dim_s = "".join([f"[{d}]" if d is not None else "[1]" for d in dims])
        return f"{base.to_c_style(style)}{dim_s}"

    def c_decl(self, name: str) -> str:
        return self.c_decl_style(name, "ghidra")

    def c_decl_style(self, name: str, style: str = "ghidra") -> str:
        base, dims = self._flatten()
        dim_s = "".join([f"[{d}]" if d is not None else "[1]" for d in dims])
        return f"{base.to_c_style(style)} {name}{dim_s}".strip()


@dataclass(frozen=True)
class ProcedureType(ResolvedType):
    ret: ResolvedType = field(default_factory=lambda: UnknownType(kind="unknown", size=None))
    args: Tuple[ResolvedType, ...] = tuple()
    calltype: Optional[int] = None

    def to_c(self) -> str:
        return self.to_c_style("ghidra")

    def to_c_style(self, style: str = "ghidra") -> str:
        a = ", ".join(x.to_c_style(style) for x in self.args) or "void"
        return f"{self.ret.to_c_style(style)} ({a})"

    def c_decl(self, name: str) -> str:
        return self.c_decl_style(name, "ghidra")

    def c_decl_style(self, name: str, style: str = "ghidra") -> str:
        a = ", ".join(x.to_c_style(style) for x in self.args) or "void"
        return f"{self.ret.to_c_style(style)} {name}({a})".strip()


@dataclass(frozen=True)
class DirEntry:
    """One NB09 directory entry describing a subsection stream."""
    subsection: int
    imod: int
    lfo: int
    cb: int

    def to_dict(self) -> Dict[str, Any]:
        return {"subsection": self.subsection, "imod": self.imod, "lfo": self.lfo, "cb": self.cb}


@dataclass
class DataSymbol:
    """A data symbol with a segmented address."""
    name: str
    seg: int
    off: int
    typind: int
    rectyp: int
    # Derived (may be None if unknown/non-primitive)
    typ: Optional[str] = None
    c_type: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "name": self.name,
            "seg": self.seg,
            "off": self.off,
            "typind": self.typind,
            "rectyp": self.rectyp,
            "typind": self.typind,
        }
        if self.typ is not None:
            d["typ"] = self.typ
        if self.c_type is not None:
            d["c_type"] = self.c_type
        return d



@dataclass
class GlobalVarResolved:
    """A global variable symbol resolved from multiple NB09 symbol sources.

    `source` is the chosen symbol origin (e.g. 'static_sym_dataref_symbols').
    `candidates` retains all competing descriptions seen at the same seg:off.
    """
    name: str
    seg: int
    off: int
    typind: Optional[int]
    source: str
    candidates: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "seg": self.seg,
            "off": self.off,
            "typind": self.typind,
            "source": self.source,
            "candidates": self.candidates,
        }


@dataclass
class ProcSymbol:
    """A procedure symbol. seg/off is the entry address; symoff is byte offset in module sstAlignSym."""
    name: str
    imod: int
    symoff: int
    seg: int
    off: int
    typind: int
    procLen: int
    dbgStart: int
    dbgEnd: int
    flags: int
    pParent: int
    pEnd: int
    pNext: int
    rectyp: int
    # best-effort source mapping (from sstSrcModule)
    src_file: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    # source of resolution (PROCREF or direct)
    from_ref: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "imod": self.imod,
            "symoff": self.symoff,
            "name": self.name,
            "seg": self.seg,
            "off": self.off,
            "typind": self.typind,
            "procLen": self.procLen,
            "dbgStart": self.dbgStart,
            "dbgEnd": self.dbgEnd,
            "flags": self.flags,
            "pParent": self.pParent,
            "pEnd": self.pEnd,
            "pNext": self.pNext,
            "rectyp": self.rectyp,
        }
        if self.src_file is not None:
            d["src_file"] = self.src_file
        if self.line_start is not None:
            d["line_start"] = self.line_start
        if self.line_end is not None:
            d["line_end"] = self.line_end
        if self.from_ref:
            d["from"] = self.from_ref
        return d


@dataclass
class LocalSymbol:
    """A local/param symbol within a procedure scope (usually S_BPREL16)."""
    kind: str                # "param" or "local" (best-effort)
    name: str
    rectyp: int
    typind: int
    bp_off: Optional[int] = None
    reg: Optional[int] = None
    reg_off: Optional[int] = None
    typ: Optional[str] = None
    c_type: Optional[str] = None
    block: Optional[int] = None  # index into ProcLocals.blocks

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "kind": self.kind,
            "name": self.name,
            "rectyp": self.rectyp,
            "typind": self.typind,
        }
        if self.bp_off is not None:
            d["bp_off"] = self.bp_off
        if self.reg is not None:
            d["reg"] = self.reg
        if self.reg_off is not None:
            d["reg_off"] = self.reg_off
        if self.typ is not None:
            d["typ"] = self.typ
        if self.c_type is not None:
            d["c_type"] = self.c_type
        if self.block is not None:
            d["block"] = self.block
        return d


@dataclass
class BlockScope:
    """A lexical block scope (S_BLOCK16) inside a procedure."""
    id: int
    symoff: int                # symbol-stream offset of the S_BLOCK16 record
    pEnd: int                  # symbol-stream offset of the matching S_END
    pParent: int               # symbol-stream offset of parent scope opener
    seg: int
    off: int
    length: int
    name: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "id": self.id,
            "symoff": self.symoff,
            "pEnd": self.pEnd,
            "pParent": self.pParent,
            "seg": self.seg,
            "off": self.off,
            "length": self.length,
        }
        if self.name:
            d["name"] = self.name
        return d


@dataclass
class LabelSymbol:
    """A code label inside a procedure scope (S_LABEL16)."""

    name: str
    seg: int
    off: int
    flags: int
    rectyp: int
    block: Optional[int] = None  # index into ProcLocals.blocks

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "name": self.name,
            "seg": self.seg,
            "off": self.off,
            "flags": self.flags,
            "rectyp": self.rectyp,
        }
        if self.block is not None:
            d["block"] = self.block
        return d


@dataclass
class FrameProc:
    """Procedure frame metadata (S_FRAMEPROC)."""

    rectyp: int
    total_frame_bytes: int
    padding_frame_bytes: int
    offset_to_padding: int
    bytes_of_callee_saved_registers: int
    offset_of_exception_handler: int
    section_id_of_exception_handler: int
    flags: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rectyp": self.rectyp,
            "total_frame_bytes": self.total_frame_bytes,
            "padding_frame_bytes": self.padding_frame_bytes,
            "offset_to_padding": self.offset_to_padding,
            "bytes_of_callee_saved_registers": self.bytes_of_callee_saved_registers,
            "offset_of_exception_handler": self.offset_of_exception_handler,
            "section_id_of_exception_handler": self.section_id_of_exception_handler,
            "flags": self.flags,
        }


@dataclass
class ProcLocals:
    """Locals/params (and optional nested block scopes) for a single procedure."""
    proc_name: str
    imod: int
    symoff: int
    seg: int
    off: int
    typind: int
    locals: List[LocalSymbol] = field(default_factory=list)
    blocks: List[BlockScope] = field(default_factory=list)
    labels: List[LabelSymbol] = field(default_factory=list)
    frameproc: Optional[FrameProc] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "name": self.proc_name,
            "imod": self.imod,
            "symoff": self.symoff,
            "seg": self.seg,
            "off": self.off,
            "typind": self.typind,
            "locals": [x.to_dict() for x in self.locals],
        }
        if self.blocks:
            d["blocks"] = [b.to_dict() for b in self.blocks]
        if self.labels:
            d["labels"] = [l.to_dict() for l in self.labels]
        if self.frameproc is not None:
            d["frameproc"] = self.frameproc.to_dict()
        return d


@dataclass
class TypeRecord:
    """One LF_* type record. The 'data' dict is intentionally flexible."""
    typind: int
    leaf: int
    kind: str
    reclen: int
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = {"typind": self.typind, "leaf": self.leaf, "kind": self.kind, "reclen": self.reclen}
        d.update(self.data)
        return d


@dataclass
class TypeTable:
    base_index: int
    records: Dict[int, TypeRecord] = field(default_factory=dict)  # typind -> record
    named: Dict[str, int] = field(default_factory=dict)          # name -> typind

    def get(self, typind: int) -> Optional[TypeRecord]:
        return self.records.get(typind)

    def to_dict(self) -> Dict[str, Any]:
        recs = [self.records[k].to_dict() for k in sorted(self.records)]
        return {
            "base_index": self.base_index,
            "record_count": len(self.records),
            "records": recs,
            "named": self.named,
        }



@dataclass
class CompactedSymHeader:
    """Header for sstGlobalSym / sstGlobalPub / sstStaticSym."""
    symhash: int
    addrhash: int
    cbSymbol: int
    cbSymHash: int
    cbAddrHash: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "symhash": self.symhash,
            "addrhash": self.addrhash,
            "cbSymbol": self.cbSymbol,
            "cbSymHash": self.cbSymHash,
            "cbAddrHash": self.cbAddrHash,
        }


@dataclass
class PubSymbol:
    name: str
    seg: int
    off: int
    typind: int
    rectyp: int
    typ: Optional[str] = None
    c_type: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "name": self.name,
            "seg": self.seg,
            "off": self.off,
            "typind": self.typind,
            "rectyp": self.rectyp,
        }
        if self.typ is not None:
            d["typ"] = self.typ
        if self.c_type is not None:
            d["c_type"] = self.c_type
        return d


@dataclass
class ProcRef:
    imod: int
    symoff: int
    checksum: int
    rectyp: int
    typind: Optional[int] = None
    name: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "imod": self.imod,
            "symoff": self.symoff,
            "checksum": self.checksum,
            "rectyp": self.rectyp,
        }
        if self.name is not None:
            d["name"] = self.name
        return d


@dataclass
class DataRef:
    imod: int
    symoff: int
    checksum: int
    rectyp: int
    typind: Optional[int] = None
    name: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "imod": self.imod,
            "symoff": self.symoff,
            "checksum": self.checksum,
            "rectyp": self.rectyp,
        }
        if self.name is not None:
            d["name"] = self.name
        return d


@dataclass
class AlignSym:
    reclen: int
    rectyp: int

    def to_dict(self) -> Dict[str, Any]:
        return {"reclen": self.reclen, "rectyp": self.rectyp}

@dataclass
class Nb09Db:
    """Parsed NB09 debug blob with query-friendly indexes."""
    summary: Dict[str, Any]
    dir_entries: List[DirEntry]
    modules: List[Dict[str, Any]]
    segname: List[str]
    segmap: List[Dict[str, Any]]
    publics: List[Dict[str, Any]]
    global_data: List[DataSymbol]
    proc_symbols: List[ProcSymbol]
    dataref_symbols: List[Dict[str, Any]]
    global_sym_procref_symbols: Optional[List[Dict[str, Any]]] = None
    global_sym_dataref_symbols: Optional[List[Dict[str, Any]]] = None
    static_sym_procref_symbols: Optional[List[Dict[str, Any]]] = None
    static_sym_dataref_symbols: Optional[List[Dict[str, Any]]] = None
    global_types: Optional[TypeTable] = None
    srcmodules: Optional[Dict[str, Any]] = None
    proc_locals: Optional[List[ProcLocals]] = None
    missing_alignsym_modules: Optional[List[Dict[str, Any]]] = None

    # Raw compacted symbol tables (NB09): headers + decoded records
    global_sym_header: Optional[CompactedSymHeader] = None
    global_pub_header: Optional[CompactedSymHeader] = None
    static_sym_header: Optional[CompactedSymHeader] = None

    global_pub_pubs: List[PubSymbol] = field(default_factory=list)
    global_pub_procrefs: List[ProcRef] = field(default_factory=list)
    global_pub_datarefs: List[DataRef] = field(default_factory=list)
    global_pub_align: List[AlignSym] = field(default_factory=list)

    global_sym_procrefs: List[ProcRef] = field(default_factory=list)
    global_sym_datarefs: List[DataRef] = field(default_factory=list)
    global_sym_align: List[AlignSym] = field(default_factory=list)

    static_sym_procrefs: List[ProcRef] = field(default_factory=list)
    static_sym_datarefs: List[DataRef] = field(default_factory=list)
    static_sym_align: List[AlignSym] = field(default_factory=list)

    # Internal cache for resolved types (not serialized)
    _resolved_type_cache: Dict[int, ResolvedType] = field(default_factory=dict, repr=False)

    def resolve_typind(self, typind: int) -> ResolvedType:
        """Resolve a CodeView typind into a generator-friendly model.

        This walks the LF_* graph in `global_types` and returns a `ResolvedType`.
        Results are memoized per db instance.
        """

        if typind in self._resolved_type_cache:
            return self._resolved_type_cache[typind]

        # Primitive/simple types
        # Derived simple pointer types (e.g. 0x0172 = T_PINT2).
        # These are "simple type" indices, not LF_POINTER records.
        # IMPORTANT: Some emitters also include these in CV_PRIMITIVES; we prefer
        # to model them as PointerType so we can render FAR pointers as `*32`. 
        hi = typind & 0xFF00
        if hi in (0x0100, 0x0200, 0x0300, 0x0400, 0x0500):
            base_tid = typind & 0x00FF
            base = self.resolve_typind(base_tid)
            ptrtype = {0x0100: 0, 0x0200: 1, 0x0300: 2, 0x0400: 10, 0x0500: 11}[hi]
            rt = PointerType(kind="pointer", to=base, ptrtype=ptrtype, ptrmode=0, isflat32=(ptrtype in (10, 11)))
            self._resolved_type_cache[typind] = rt
            return rt

        # Primitive/simple types
        prim = CV_PRIMITIVES.get(typind)
        if prim is not None:
            cv_name, c_name, sz = prim
            rt = PrimitiveType(kind="primitive", size=sz, cv_name=cv_name, c_name=c_name)
            self._resolved_type_cache[typind] = rt
            return rt

        # If we don't have a type table, we can't resolve.
        if self.global_types is None:
            rt = UnknownType(kind="unknown", size=None)
            self._resolved_type_cache[typind] = rt
            return rt

        rec = self.global_types.get(typind)
        if rec is None:
            rt = UnknownType(kind="unknown", size=None)
            self._resolved_type_cache[typind] = rt
            return rt

        # Place a temporary to break cycles (self-referential structs etc.)
        self._resolved_type_cache[typind] = UnknownType(kind="unknown", size=None)

        k = rec.kind
        d = rec.data

        if k in ("struct", "class"):
            tag = d.get("name", "")
            rt = StructType(kind="struct", size=d.get("size"), name=tag, typedef_name=self._clean_typedef_name(tag), fieldlist=d.get("fieldlist"))
        elif k == "union":
            tag = d.get("name", "")
            rt = UnionType(kind="union", size=d.get("size"), name=tag, typedef_name=self._clean_typedef_name(tag), fieldlist=d.get("fieldlist"))
        elif k == "enum":
            tag = d.get("name", "")
            rt = EnumType(kind="enum", size=d.get("size"), name=tag, typedef_name=self._clean_typedef_name(tag), underlying=None)
        elif k == "bitfield":
            base_tid = int(d.get("type", 0) or 0)
            base = self.resolve_typind(base_tid) if base_tid else UnknownType(kind="unknown", size=None)
            rt = BitfieldType(kind="bitfield", size=base.size, base=base, length=int(d.get("length", 0) or 0), position=int(d.get("position", 0) or 0))
        elif k == "pointer":
            # Our pointer decode stores the pointee typind under either `utype` or `attr` depending on CV variant.
            cand_a = d.get("utype")
            cand_b = d.get("attr")
            pointee_tid: Optional[int] = None
            for cand in (cand_a, cand_b):
                if isinstance(cand, int) and (cand in self.global_types.records or cand in CV_PRIMITIVES):
                    pointee_tid = cand
                    break
            to = self.resolve_typind(pointee_tid) if pointee_tid is not None else UnknownType(kind="unknown", size=None)

            # Decode pointer attributes (CV4/TIS). `attr` is a bitfield:
            #   bits 0-4: ptrtype (0 near, 1 far, 2 huge, 10 near32, 11 far32)
            #   bits 5-7: ptrmode
            #   bit 8   : isflat32 (varies by emitter; we also treat near32/far32 as flat32)
            attr_val: int = 0
            cand_attr = d.get("attr")
            cand_utype = d.get("utype")
            # If one of the two fields was used as the pointee typind, prefer the other as attr.
            if pointee_tid is not None:
                if isinstance(cand_attr, int) and cand_attr != pointee_tid:
                    attr_val = cand_attr
                elif isinstance(cand_utype, int) and cand_utype != pointee_tid:
                    attr_val = cand_utype
            elif isinstance(cand_attr, int):
                attr_val = cand_attr

            ptrtype = int(attr_val) & 0x1F
            ptrmode = (int(attr_val) >> 5) & 0x07
            isflat32 = bool(((int(attr_val) >> 8) & 0x01) or (ptrtype in (10, 11)))

            rt = PointerType(kind="pointer", size=None, to=to, ptrtype=ptrtype, ptrmode=ptrmode, isflat32=isflat32)
        elif k == "array":
            elem_tid = d.get("elemtype")
            size = d.get("size")
            elem = self.resolve_typind(int(elem_tid)) if isinstance(elem_tid, int) else UnknownType(kind="unknown", size=None)
            count = None
            if isinstance(size, int) and elem.size and elem.size > 0 and size % elem.size == 0:
                count = size // elem.size
            rt = ArrayType(kind="array", size=size if isinstance(size, int) else None, elem=elem, count=count)
        elif k == "procedure":
            rv_tid = d.get("rvtype")
            arglist_tid = d.get("arglist")
            calltype = d.get("calltype")
            ret = self.resolve_typind(int(rv_tid)) if isinstance(rv_tid, int) else UnknownType(kind="unknown", size=None)
            args: List[ResolvedType] = []
            if isinstance(arglist_tid, int):
                arec = self.global_types.get(arglist_tid)
                if arec and arec.kind == "arglist":
                    for at in (arec.data.get("args") or []):
                        if isinstance(at, int):
                            args.append(self.resolve_typind(at))
            rt = ProcedureType(kind="procedure", size=None, ret=ret, args=tuple(args), calltype=calltype if isinstance(calltype, int) else None)
        else:
            rt = UnknownType(kind="unknown", size=d.get("size") if isinstance(d.get("size"), int) else None)

        self._resolved_type_cache[typind] = rt
        return rt

    def c_type_of(self, typind: int, *, style: str = "ghidra") -> str:
        """Convenience: best-effort C-ish type expression.

        style:
          - "ghidra": emits `*32` for far pointers
          - "c": emits plain `*` for compilable C output
        """
        return self.resolve_typind(typind).to_c_style(style)

    def c_decl_of(self, typind: int, name: str, *, style: str = "ghidra") -> str:
        """Convenience: best-effort C-ish declaration for `name`.

        style:
          - "ghidra": emits `*32` for far pointers
          - "c": emits plain `*` for compilable C output
        """
        return self.resolve_typind(typind).c_decl_style(name, style)


    # ---- Global symbol selection / type resolution helpers ----

    def _normalize_symbol_name(self, name: str) -> str:
        """Normalize names across tables (PUBLICS often have a leading underscore)."""
        if not name:
            return name
        # Strip exactly one leading underscore for C symbol decoration (_foo).
        if name.startswith("_") and len(name) > 1:
            return name[1:]
        return name

    def _is_zero_len_array_typind(self, typind: Optional[int]) -> bool:
        """True if `typind` resolves to an array with any dimension == 0."""
        if typind is None:
            return False
        try:
            rt = self.resolve_typind(int(typind))
        except Exception:
            return False
        if isinstance(rt, ArrayType):
            base, dims = rt._flatten()
            return any((d == 0) for d in dims if d is not None)
        return False

    def iter_globals_resolved(self) -> List[GlobalVarResolved]:
        """Return globals deduped by address, choosing the best type via a Stars!-tuned hierarchy.

        Hierarchy (best to worst) when multiple symbol sources describe the same seg:off:
          1) static_sym_dataref_symbols (DATAREF from SST_STATIC_SYM)
          2) global_sym_dataref_symbols (DATAREF from SST_GLOBAL_SYM)
          3) dataref_symbols (fallback, if you don't have the split lists)
          4) global_data (S_GDATA16 / 'GLOBAL')

        Within the same priority, never choose a zero-length array type if any non-zero alternative exists.
        """
        # Gather candidates by address.
        cand_by_addr: Dict[Tuple[int, int], List[Dict[str, Any]]] = {}

        def _add_candidate(src: str, rec: Dict[str, Any]) -> None:
            seg = int(rec.get("seg", 0) or 0)
            off = int(rec.get("off", 0) or 0)
            if seg == 0 and off == 0:
                return
            name = rec.get("name") or ""
            typind = rec.get("typind")
            if typind is not None:
                try:
                    typind = int(typind)
                except Exception:
                    typind = None
            cand = {
                "source": src,
                "name": name,
                "norm_name": self._normalize_symbol_name(name),
                "seg": seg,
                "off": off,
                "typind": typind,
                "rectyp": rec.get("rectyp"),
                "imod": rec.get("imod"),
                "symoff": rec.get("symoff"),
                "from": rec.get("from"),
            }
            cand_by_addr.setdefault((seg, off), []).append(cand)

        # 1/2/3: DATAREF-resolved symbols
        for rec in (getattr(self, "static_sym_dataref_symbols", None) or []):
            _add_candidate("static_sym_dataref_symbols", rec)
        for rec in (getattr(self, "global_sym_dataref_symbols", None) or []):
            _add_candidate("global_sym_dataref_symbols", rec)
        for rec in (self.dataref_symbols or []):
            _add_candidate("dataref_symbols", rec)

        # 4: Global data (S_GDATA16) parsed as DataSymbol objects
        for s in (self.global_data or []):
            _add_candidate("global_data", {"name": s.name, "seg": s.seg, "off": s.off, "typind": s.typind, "rectyp": s.rectyp})

        # Optionally, PUBLICS can help with decoration/name, but they are *not* a reliable global-variable list.
        # To avoid pulling in every exported procedure as a 'global', we only consult PUBLICS for
        # addresses that already appear in the data symbol tables above.
        for p in (self.publics or []):
            try:
                seg = int(p.get("seg", 0) or 0)
                off = int(p.get("off", 0) or 0)
            except Exception:
                continue
            if (seg, off) not in cand_by_addr:
                continue
            name = p.get("name") or ""
            typind = p.get("typind")
            if typind in (0, None):
                typind = None
            _add_candidate("publics", {"name": name, "seg": seg, "off": off, "typind": typind, "rectyp": p.get("rectyp")})
# Rank sources for type selection (lower is better).
        src_rank = {
            "static_sym_dataref_symbols": 0,
            "global_sym_dataref_symbols": 1,
            "dataref_symbols": 2,
            "global_data": 3,
            "publics": 9,  # name-only last resort
        }

        out: List[GlobalVarResolved] = []
        for (seg, off), cands in sorted(cand_by_addr.items()):
            # Group duplicates by normalized name within each source.
            # If multiple entries are identical except origin, keep them in candidates for debugging,
            # but select a single best record for output.
            def score(c: Dict[str, Any]) -> Tuple[int, int, int, int]:
                rank = src_rank.get(c["source"], 99)
                has_type = 0 if c.get("typind") is not None else 1
                zero_pen = 1 if self._is_zero_len_array_typind(c.get("typind")) else 0
                # Prefer normalized name without leading underscore.
                undecorated_pen = 0 if (c.get("name") == c.get("norm_name")) else 1
                return (rank, has_type, zero_pen, undecorated_pen)

            # First, find the best rank that has any non-zero-length type if possible.
            sorted_cands = sorted(cands, key=score)
            chosen = sorted_cands[0]

            # Within same source priority, avoid zero-length arrays if any alternative exists at same rank+has_type.
            best_rank = src_rank.get(chosen["source"], 99)
            same_rank = [c for c in cands if src_rank.get(c["source"], 99) == best_rank and c.get("typind") is not None]
            if same_rank and self._is_zero_len_array_typind(chosen.get("typind")):
                non_zero = [c for c in same_rank if not self._is_zero_len_array_typind(c.get("typind"))]
                if non_zero:
                    chosen = sorted(non_zero, key=score)[0]

            # Decide output name:
            # Prefer the chosen candidate's normalized name; if empty, fall back to any other normalized name.
            out_name = chosen.get("norm_name") or chosen.get("name") or ""
            if not out_name:
                for c in sorted_cands:
                    nn = c.get("norm_name") or c.get("name")
                    if nn:
                        out_name = nn
                        break

            out.append(
                GlobalVarResolved(
                    name=out_name,
                    seg=seg,
                    off=off,
                    typind=chosen.get("typind"),
                    source=chosen["source"],
                    candidates=cands,
                )
            )
        return out
    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "summary": self.summary,
            "dir_entries": [e.to_dict() for e in self.dir_entries],
            "modules": self.modules,
            "segname": self.segname,
            "segmap": self.segmap,
            "publics": self.publics,
            "global_data": [g.to_dict() for g in self.global_data],
            "proc_symbols": [p.to_dict() for p in self.proc_symbols],
            "dataref_symbols": self.dataref_symbols,
            "global_sym_header": self.global_sym_header.to_dict() if self.global_sym_header else None,
            "global_pub_header": self.global_pub_header.to_dict() if self.global_pub_header else None,
            "static_sym_header": self.static_sym_header.to_dict() if self.static_sym_header else None,
            "global_pub_pubs": [x.to_dict() for x in self.global_pub_pubs],
            "global_pub_procrefs": [x.to_dict() for x in self.global_pub_procrefs],
            "global_pub_datarefs": [x.to_dict() for x in self.global_pub_datarefs],
            "global_pub_align": [x.to_dict() for x in self.global_pub_align],
            "global_sym_procrefs": [x.to_dict() for x in self.global_sym_procrefs],
            "global_sym_datarefs": [x.to_dict() for x in self.global_sym_datarefs],
            "global_sym_align": [x.to_dict() for x in self.global_sym_align],
            "static_sym_procrefs": [x.to_dict() for x in self.static_sym_procrefs],
            "static_sym_datarefs": [x.to_dict() for x in self.static_sym_datarefs],
            "static_sym_align": [x.to_dict() for x in self.static_sym_align],
        }
        if self.global_sym_procref_symbols is not None:
            out["global_sym_procref_symbols"] = self.global_sym_procref_symbols
        if self.global_sym_dataref_symbols is not None:
            out["global_sym_dataref_symbols"] = self.global_sym_dataref_symbols
        if self.static_sym_procref_symbols is not None:
            out["static_sym_procref_symbols"] = self.static_sym_procref_symbols
        if self.static_sym_dataref_symbols is not None:
            out["static_sym_dataref_symbols"] = self.static_sym_dataref_symbols

        if self.global_types is not None:
            out["global_types"] = self.global_types.to_dict()
        if self.srcmodules is not None:
            out["srcmodules"] = self.srcmodules
        if self.proc_locals is not None:
            out["proc_locals"] = [pl.to_dict() for pl in self.proc_locals]
        if self.missing_alignsym_modules is not None:
            out["missing_alignsym_modules"] = self.missing_alignsym_modules
        return out
    
    @staticmethod
    def _clean_typedef_name(tag_name: str) -> str:
        """Best-effort: derive a nicer typedef name from CodeView tag names.

        Examples:
            _planet -> PLANET
            _prod   -> PROD
            tagRECT -> RECT
            tagPOINT -> POINT
        """
        if not tag_name:
            return ""
        if tag_name.startswith("_") and len(tag_name) > 1:
            return tag_name[1:].upper()
        if tag_name.startswith("tag") and len(tag_name) > 3:
            return tag_name[3:]
        return ""

