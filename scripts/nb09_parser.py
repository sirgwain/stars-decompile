"""
nb09_parser.py — minimal CodeView NB09 parser for Stars! extracted debug blob.

This implements the core structures from the TIS "Microsoft Symbol and Type Information"
spec (Tool Interface Standards, Version 1.0), including:

- NB09 signature header + lfoDir
- Subsection directory (DirHeader + DirEntry)
- sstModule (0x0120)
- sstLibraries (0x0128)
- sstFileIndex (0x0133)  (uses length-prefixed names in this file)
- sstSegName (0x012e)
- sstSegMap (0x012d)
- sstGlobalPub (0x012a)  (S_PUB16/S_PUB32)
- sstGlobalSym (0x0129)  (S_GDATA16, S_PROCREF, etc.)
- sstStaticSym (0x0134)  (S_DATAREF)

Also resolves CVPACK PROCREF/DATAREF entries back into per-module sstAlignSym (0x0125)
to recover procedure/data names and addresses.

Usage:
  python3 nb09_parser.py stars26jrc3.codeview.nb09.bin out.json
"""
from __future__ import annotations

import json
import struct
import sys
from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional, Iterable, Any


# ---- Constants (symbol record types) ----
S_UDT       = 0x0004
S_OBJNAME   = 0x0009
S_END       = 0x0006

S_LDATA16   = 0x0101
S_GDATA16   = 0x0102
S_PUB16     = 0x0103
S_LPROC16   = 0x0104
S_GPROC16   = 0x0105
S_THUNK16   = 0x0106
S_BLOCK16   = 0x0107
S_WITH16    = 0x0108
S_LABEL16   = 0x0109
S_ENDARG    = 0x000A


S_LDATA32   = 0x0201
S_GDATA32   = 0x0202
S_PUB32     = 0x0203
S_LPROC32   = 0x0204
S_GPROC32   = 0x0205

S_PROCREF   = 0x0400
S_DATAREF   = 0x0401
S_ALIGN     = 0x0402


# ---- CodeView "primitive" type indices (0x0000..0x0FFF) ----
# These are not type records from $$TYPES; they are built-in encodings.
#
# NOTE: This is a *partial* map covering the ones Stars! appears to use most often.
# You can extend this as we encounter additional primitives in typind fields.
#
# Naming follows the TIS spec ("Real ... Types") convention: T_<...>
T_VOID     = 0x0003
T_CHAR     = 0x0010
T_UCHAR    = 0x0020
T_SHORT    = 0x0011
T_USHORT   = 0x0021
T_LONG     = 0x0012
T_ULONG    = 0x0022
T_REAL32   = 0x0040
T_REAL64   = 0x0041

# "Real 16-bit Integer Types" (commonly used in 16-bit code)
T_INT2     = 0x0072
T_UINT2    = 0x0073

# Some common near/far pointer primitive encodings (still appear as typinds in symbols).
# We treat them as plain pointers in modern C output.
T_PVOID    = 0x0103
T_PCHAR    = 0x0110
T_PUCHAR   = 0x0120
T_PSHORT   = 0x0111
T_PUSHORT  = 0x0121
T_PLONG    = 0x0112
T_PULONG   = 0x0122

# Far pointer variants (seg:off); keep here so we can label them in output.
T_PFVOID   = 0x0203
T_PFCHAR   = 0x0210
T_PFUCHAR  = 0x0220
T_PFSHORT  = 0x0211
T_PFUSHORT = 0x0221
T_PFLONG   = 0x0212
T_PFULONG  = 0x0222
T_PFINT2   = 0x0272
T_PFUINT2  = 0x0273

# typind -> (T_ name, C type string)
CV_PRIMITIVE_TYPES: Dict[int, Tuple[str, str]] = {
    T_VOID:    ("T_VOID", "void"),
    T_CHAR:    ("T_CHAR", "char"),
    T_UCHAR:   ("T_UCHAR", "uint8_t"),
    T_SHORT:   ("T_SHORT", "int16_t"),
    T_USHORT:  ("T_USHORT", "uint16_t"),
    T_LONG:    ("T_LONG", "int32_t"),
    T_ULONG:   ("T_ULONG", "uint32_t"),
    T_REAL32:  ("T_REAL32", "float"),
    T_REAL64:  ("T_REAL64", "double"),
    T_INT2:    ("T_INT2", "int16_t"),
    T_UINT2:   ("T_UINT2", "uint16_t"),

    # pointers (near)
    T_PVOID:   ("T_PVOID", "void*"),
    T_PCHAR:   ("T_PCHAR", "char*"),
    T_PUCHAR:  ("T_PUCHAR", "uint8_t*"),
    T_PSHORT:  ("T_PSHORT", "int16_t*"),
    T_PUSHORT: ("T_PUSHORT", "uint16_t*"),
    T_PLONG:   ("T_PLONG", "int32_t*"),
    T_PULONG:  ("T_PULONG", "uint32_t*"),

    # pointers (far) - still emit plain pointers for modern C, but keep the name.
    T_PFVOID:   ("T_PFVOID", "void*"),
    T_PFCHAR:   ("T_PFCHAR", "char*"),
    T_PFUCHAR:  ("T_PFUCHAR", "uint8_t*"),
    T_PFSHORT:  ("T_PFSHORT", "int16_t*"),
    T_PFUSHORT: ("T_PFUSHORT", "uint16_t*"),
    T_PFLONG:   ("T_PFLONG", "int32_t*"),
    T_PFULONG:  ("T_PFULONG", "uint32_t*"),
    T_PFINT2:   ("T_PFINT2", "int16_t*"),
    T_PFUINT2:  ("T_PFUINT2", "uint16_t*"),
}

def cv_primitive_to_c_type(typind: int) -> Optional[Tuple[str, str]]:
    """Return (T_NAME, c_type) if typind is a known CodeView primitive, else None."""
    return CV_PRIMITIVE_TYPES.get(typind)

# ---- Constants (subsection indices) ----
SST_MODULE      = 0x0120
SST_ALIGN_SYM   = 0x0125
SST_SRC_MODULE  = 0x0127
SST_LIBRARIES   = 0x0128
SST_GLOBAL_SYM  = 0x0129
SST_GLOBAL_PUB  = 0x012A
SST_GLOBAL_TYPES= 0x012B
SST_SEG_MAP     = 0x012D
SST_SEG_NAME    = 0x012E
SST_FILE_INDEX  = 0x0133
SST_STATIC_SYM  = 0x0134

# ---- Constants (type leaf indices) ----
LF_MODIFIER   = 0x0001
LF_POINTER    = 0x0002
LF_ARRAY      = 0x0003
LF_CLASS      = 0x0004
LF_STRUCTURE  = 0x0005
LF_UNION      = 0x0006
LF_ENUM       = 0x0007
LF_PROCEDURE  = 0x0008
LF_MFUNCTION  = 0x0009
LF_VTSHAPE    = 0x000A
LF_COBOL0     = 0x000B
LF_COBOL1     = 0x000C
LF_BARRAY     = 0x000D
LF_LABEL      = 0x000E
LF_NULL       = 0x000F
LF_NOTTRAN    = 0x0010
LF_DIMARRAY   = 0x0011
LF_VFTPATH    = 0x0012
LF_PRECOMP    = 0x0013
LF_ENDPRECOMP = 0x0014
LF_OEM        = 0x0015

LF_SKIP       = 0x0200
LF_ARGLIST    = 0x0201
LF_DEFARG     = 0x0202
LF_LIST       = 0x0203
LF_FIELDLIST  = 0x0204
LF_DERIVED    = 0x0205
LF_BITFIELD   = 0x0206
LF_METHODLIST = 0x0207
LF_DIMCONU    = 0x0208
LF_DIMCONLU   = 0x0209
LF_DIMVARU    = 0x020A
LF_DIMVARLU   = 0x020B
LF_REFSYM     = 0x020C

# sub-leaves inside FIELDLIST etc.
LF_BCLASS     = 0x0400
LF_VBCLASS    = 0x0401
LF_IVBCLASS   = 0x0402
LF_ENUMERATE  = 0x0403
LF_FRIENDFCN  = 0x0404
LF_INDEX      = 0x0405
LF_MEMBER     = 0x0406
LF_STMEMBER   = 0x0407
LF_METHOD     = 0x0408
LF_NESTTYPE   = 0x0409
LF_VFUNCTAB   = 0x040A
LF_FRIENDCLS  = 0x040B
LF_ONEMETHOD  = 0x040C
LF_VFUNCOFF   = 0x040D

# numeric leaves
LF_CHAR       = 0x8000
LF_SHORT      = 0x8001
LF_USHORT     = 0x8002
LF_LONG       = 0x8003
LF_ULONG      = 0x8004
LF_REAL32     = 0x8005
LF_REAL64     = 0x8006
LF_REAL80     = 0x8007
LF_REAL128    = 0x8008
LF_QUADWORD   = 0x8009
LF_UQUADWORD  = 0x800A
LF_REAL48     = 0x800B
LF_COMPLEX32  = 0x800C
LF_COMPLEX64  = 0x800D
LF_COMPLEX80  = 0x800E
LF_COMPLEX128 = 0x800F
LF_VARSTRING  = 0x8010


LEAF_START_SET = {
    LF_MODIFIER, LF_POINTER, LF_ARRAY, LF_CLASS, LF_STRUCTURE, LF_UNION, LF_ENUM,
    LF_PROCEDURE, LF_MFUNCTION, LF_VTSHAPE, LF_COBOL0, LF_COBOL1, LF_BARRAY,
    LF_LABEL, LF_NULL, LF_NOTTRAN, LF_DIMARRAY, LF_VFTPATH, LF_PRECOMP,
    LF_ENDPRECOMP, LF_OEM,
    LF_SKIP, LF_ARGLIST, LF_DEFARG, LF_LIST, LF_FIELDLIST, LF_DERIVED, LF_BITFIELD,
    LF_METHODLIST, LF_DIMCONU, LF_DIMCONLU, LF_DIMVARU, LF_DIMVARLU, LF_REFSYM,
}



def u16(b: bytes, off: int) -> int:
    return struct.unpack_from("<H", b, off)[0]

def u32(b: bytes, off: int) -> int:
    return struct.unpack_from("<I", b, off)[0]

def read_pascal(b: bytes, off: int) -> Tuple[str, int]:
    n = b[off]
    s = b[off+1:off+1+n].decode("latin1", errors="replace")
    return s, off + 1 + n

def read_cstr(b: bytes, off: int) -> Tuple[str, int]:
    end = b.find(b"\x00", off)
    if end < 0:
        end = len(b)
    s = b[off:end].decode("latin1", errors="replace")
    return s, end + 1


@dataclass
class DirEntry:
    subsection: int
    imod: int
    lfo: int
    cb: int


def parse_directory(b: bytes) -> Tuple[int, List[DirEntry]]:
    """
    NB09 header:
      char  sig[4] = "NB09"
      uint32 lfoDir
    Directory header (TIS):
      uint16 cbDirHeader
      uint16 cbDirEntry
      uint32 cDir
      uint32 lfoNextDir
      uint32 flags
    Directory entry:
      uint16 subsection
      uint16 iMod
      uint32 lfo
      uint32 cb
    """
    if b[:4] != b"NB09":
        raise ValueError(f"Not NB09: {b[:4]!r}")
    lfo_dir = u32(b, 4)
    cb_dir_header = u16(b, lfo_dir + 0)
    cb_dir_entry  = u16(b, lfo_dir + 2)
    c_dir          = u32(b, lfo_dir + 4)
    lfo_next_dir   = u32(b, lfo_dir + 8)
    flags          = u32(b, lfo_dir + 12)
    # entries start at lfo_dir + cb_dir_header
    entries: List[DirEntry] = []
    base = lfo_dir + cb_dir_header
    for i in range(c_dir):
        sub, imod, lfo, cb = struct.unpack_from("<HHII", b, base + i*cb_dir_entry)
        entries.append(DirEntry(sub, imod, lfo, cb))
    return lfo_dir, entries


def parse_sst_module(b: bytes, lfo: int, cb: int) -> Dict[str, Any]:
    ovl, iLib, cSeg, style = struct.unpack_from("<HHHH", b, lfo)
    pos = lfo + 8
    seginfo = []
    for _ in range(cSeg):
        seg, pad, off, cbSeg = struct.unpack_from("<HHII", b, pos)
        seginfo.append({"seg": seg, "off": off, "cb": cbSeg})
        pos += 12
    name, _ = read_pascal(b, pos)
    # style is little-endian 'CV' in this file
    return {
        "ovl": ovl,
        "iLib": iLib,
        "cSeg": cSeg,
        "style": style,
        "name": name,
        "seginfo": seginfo,
    }


def parse_sst_libraries(b: bytes, lfo: int, cb: int) -> List[str]:
    libs=[]
    pos=lfo
    end=lfo+cb
    while pos<end:
        n=b[pos]
        pos+=1
        libs.append(b[pos:pos+n].decode("latin1", errors="replace"))
        pos+=n
    return libs


def parse_sst_segname(b: bytes, lfo: int, cb: int) -> Dict[int, str]:
    # strings are NUL-terminated; directory stores offsets into this blob
    blob=b[lfo:lfo+cb]
    out={}
    pos=0
    while pos<cb:
        end=blob.find(b"\x00", pos)
        if end<0:
            break
        out[pos]=blob[pos:end].decode("latin1", errors="replace")
        pos=end+1
    return out


def parse_sst_segmap(b: bytes, lfo: int, cb: int) -> Dict[str, Any]:
    cSeg, cSegLog = struct.unpack_from("<HH", b, lfo)
    pos = lfo + 4
    segdescs=[]
    for i in range(cSeg):
        flags, ovl, group, frame, iSegName, iClassName, off, cbSeg = struct.unpack_from("<HHHHHHII", b, pos + i*20)
        segdescs.append({
            "seg": i+1,
            "flags": flags,
            "ovl": ovl,
            "group": group,
            "frame": frame,
            "iSegName": iSegName,
            "iClassName": iClassName,
            "off": off,
            "cb": cbSeg,
        })
    return {"cSeg": cSeg, "cSegLog": cSegLog, "segs": segdescs}


def parse_sst_fileindex(b: bytes, lfo: int, cb: int) -> Dict[str, Any]:
    """
    TIS describes a zero-terminated string table, but this NB09 blob uses
    length-prefixed (1-byte) strings and NameRef offsets point to the length byte.

      uint16 cMod
      uint16 cRef
      uint16 ModStart[cMod]
      uint16 cRefCnt[cMod]
      uint32 NameRef[cRef]
      uint8  Names[]
    """
    cMod, cRef = struct.unpack_from("<HH", b, lfo)
    pos = lfo + 4
    ModStart = list(struct.unpack_from("<" + "H"*cMod, b, pos)); pos += 2*cMod
    cRefCnt  = list(struct.unpack_from("<" + "H"*cMod, b, pos)); pos += 2*cMod
    NameRef  = list(struct.unpack_from("<" + "I"*cRef, b, pos)); pos += 4*cRef
    names_blob = b[pos:lfo+cb]

    def lp_at(off: int) -> str:
        n = names_blob[off]
        return names_blob[off+1:off+1+n].decode("latin1", errors="replace")

    names = [lp_at(o) for o in NameRef]

    mod_to_files: Dict[int, List[str]] = {}
    for m in range(1, cMod+1):
        start = ModStart[m-1]
        cnt = cRefCnt[m-1]
        mod_to_files[m] = names[start:start+cnt]

    return {
        "cMod": cMod,
        "cRef": cRef,
        "names": names,
        "mod_to_files": mod_to_files,
    }


def iter_symbol_records(blob: bytes) -> Iterable[Tuple[int,int,int,bytes]]:
    """
    Each record:
      uint16 reclen  (length of (rectyp + payload), not including reclen itself)
      uint16 rectyp
      payload[reclen-2]
    """
    pos=0
    n=len(blob)
    while pos+4 <= n:
        reclen = u16(blob, pos)
        rectyp = u16(blob, pos+2)
        # guard against nonsense
        if reclen < 2 or pos + 2 + reclen > n:
            break
        payload = blob[pos+4:pos+2+reclen]
        yield pos, reclen, rectyp, payload
        pos += 2 + reclen


def _is_pad_byte(x: int) -> bool:
    return 0xF0 <= x <= 0xFF


def _skip_type_padding(blob: bytes, pos: int, end: int) -> int:
    # In fieldlists, padding bytes are 0xF0..0xFF where low nibble encodes pad count.
    # Spec: LF_PAD0..LF_PAD15
    while pos < end and _is_pad_byte(blob[pos]):
        pos += (blob[pos] & 0x0F)
    return pos


def parse_numeric_leaf(blob: bytes, pos: int, end: int) -> Tuple[int, int]:
    """Parse a numeric field as described in TIS section 4.

    If the next u16 < 0x8000, it is the value.
    Otherwise it is a numeric leaf index and the value follows.

    Returns (value, new_pos).
    """
    if pos + 2 > end:
        return 0, pos
    tag = u16(blob, pos)
    if tag < 0x8000:
        return tag, pos + 2
    pos += 2
    if tag == LF_CHAR:
        return struct.unpack_from("<b", blob, pos)[0], pos + 1
    if tag == LF_SHORT:
        return struct.unpack_from("<h", blob, pos)[0], pos + 2
    if tag == LF_USHORT:
        return struct.unpack_from("<H", blob, pos)[0], pos + 2
    if tag == LF_LONG:
        return struct.unpack_from("<i", blob, pos)[0], pos + 4
    if tag == LF_ULONG:
        return struct.unpack_from("<I", blob, pos)[0], pos + 4
    if tag == 0x8010:  # LF_VARSTRING
        n = u16(blob, pos)
        pos += 2
        s = blob[pos:pos+n].decode("latin1", errors="replace")
        # Return length as "value"; caller that wants string can separately parse.
        return n, pos + n
    # Unknown numeric leaf: best-effort: treat as 0 and don't advance further.
    return 0, pos


TYPE_LEAF_START = {
    LF_MODIFIER, LF_POINTER, LF_ARRAY, LF_CLASS, LF_STRUCTURE, LF_UNION, LF_ENUM,
    LF_PROCEDURE, LF_MFUNCTION, LF_VTSHAPE, LF_COBOL0, LF_COBOL1, LF_BARRAY,
    LF_LABEL, LF_NULL, LF_NOTTRAN, LF_DIMARRAY, LF_VFTPATH, LF_PRECOMP,
    LF_ENDPRECOMP, LF_OEM,
    LF_SKIP, LF_ARGLIST, LF_DEFARG, LF_LIST, LF_FIELDLIST, LF_DERIVED, LF_BITFIELD,
    LF_METHODLIST, LF_DIMCONU, LF_DIMCONLU, LF_DIMVARU, LF_DIMVARLU, LF_REFSYM,
}


def find_type_record_stream_start(blob: bytes) -> Tuple[int, int]:
    """Heuristic: find an offset where type-record parsing yields a long valid chain.

    Returns (start_off, record_count).
    """
    n = len(blob)

    def chain_len(off: int, max_records: int = 100000) -> int:
        pos = off
        c = 0
        while pos + 4 <= n and c < max_records:
            reclen = u16(blob, pos)
            if reclen < 4 or reclen > 8192:
                break
            leaf = u16(blob, pos + 2)
            if leaf not in TYPE_LEAF_START:
                break
            if pos + 2 + reclen > n:
                break
            pos += 2 + reclen
            c += 1
        return c

    best_off = -1
    best_len = 0
    # scan 2-byte aligned offsets (records are naturally aligned)
    for off in range(0, n - 4, 2):
        reclen = u16(blob, off)
        if reclen < 4 or reclen > 4096:
            continue
        leaf = u16(blob, off + 2)
        if leaf not in TYPE_LEAF_START:
            continue
        c = chain_len(off, max_records=50000)
        if c > best_len:
            best_len = c
            best_off = off
    if best_off < 0:
        return 0, 0
    return best_off, best_len


def iter_type_records(blob: bytes, start_off: int) -> Iterable[Tuple[int, int, int, bytes]]:
    """Iterate type records: (offset, reclen, leaf, payload)."""
    pos = start_off
    n = len(blob)
    while pos + 4 <= n:
        reclen = u16(blob, pos)
        leaf = u16(blob, pos + 2)
        if reclen < 4 or reclen > 8192 or leaf not in TYPE_LEAF_START:
            break
        if pos + 2 + reclen > n:
            break
        payload = blob[pos + 4:pos + 2 + reclen]
        yield pos, reclen, leaf, payload
        pos += 2 + reclen


def parse_type_record(leaf: int, payload: bytes) -> Dict[str, Any]:
    """Best-effort decode of common CV4/TIS v1.0 leaves.

    This is intentionally conservative: it extracts names/sizes and references,
    but does not attempt to fully build C declarations.
    """
    out: Dict[str, Any] = {"leaf": leaf}
    # NOTE: Many leaves begin with type indices (u16) referencing other types.
    # Names are typically trailing length-prefixed strings.

    if leaf == LF_POINTER:
        # CV4/TIS: u16 attr; u16 utype  (some emitters swap these)
        if len(payload) >= 4:
            a, b = struct.unpack_from("<HH", payload, 0)
            # Heuristic: utype is usually a primitive (<0x0200) or a type index (>=0x1000).
            # attr is a bitfield; it is rarely >= 0x1000. If it looks swapped, swap it.
            attr, utype = a, b
            if (attr >= 0x1000) and (utype < 0x1000):
                attr, utype = utype, attr
            out.update({"kind": "pointer", "utype": utype, "attr": attr})
        return out

    if leaf == LF_MODIFIER:
        # u16 utype; u16 mod
        if len(payload) >= 4:
            utype, mod = struct.unpack_from("<HH", payload, 0)
            out.update({"kind": "modifier", "utype": utype, "mod": mod})
        return out

    if leaf == LF_ARRAY:
        # u16 elemtype; u16 idxtype; numeric size; name
        if len(payload) >= 4:
            elem, idx = struct.unpack_from("<HH", payload, 0)
            pos = 4
            size, pos = parse_numeric_leaf(payload, pos, len(payload))
            name = ""
            if pos < len(payload):
                # name is a length-prefixed string
                n = payload[pos]
                name = payload[pos+1:pos+1+n].decode("latin1", errors="replace")
            out.update({"kind": "array", "elemtype": elem, "idxtype": idx, "size": size, "name": name})
        return out

    if leaf in (LF_STRUCTURE, LF_CLASS, LF_UNION):
        # Common prefix (TIS):
        # u16 count; u16 fieldlist; u16 property; u16 dList;
        # u16 vshape (class/struct); numeric size; name; (optional) unique name
        kind = "struct" if leaf in (LF_STRUCTURE, LF_CLASS) else "union"
        out["kind"] = kind
        if len(payload) >= 10:
            count, fieldlist, prop, dlist, vshape = struct.unpack_from("<HHHHH", payload, 0)
            pos = 10
            size, pos = parse_numeric_leaf(payload, pos, len(payload))
            name = ""
            if pos < len(payload):
                n = payload[pos]
                name = payload[pos+1:pos+1+n].decode("latin1", errors="replace")
                pos += 1 + n
            out.update({
                "count": count,
                "fieldlist": fieldlist,
                "prop": prop,
                "dlist": dlist,
                "vshape": vshape,
                "size": size,
                "name": name,
            })
        return out

    if leaf == LF_ENUM:
        # u16 count; u16 utype; u16 fieldlist; u16 property; name
        out["kind"] = "enum"
        if len(payload) >= 8:
            count, utype, fieldlist, prop = struct.unpack_from("<HHHH", payload, 0)
            pos = 8
            name = ""
            if pos < len(payload):
                n = payload[pos]
                name = payload[pos+1:pos+1+n].decode("latin1", errors="replace")
            out.update({"count": count, "utype": utype, "fieldlist": fieldlist, "prop": prop, "name": name})
        return out

    if leaf == LF_PROCEDURE:
        # u16 rvtype; u8 calltype; u8 reserved; u16 parmcount; u16 arglist
        out["kind"] = "procedure"
        if len(payload) >= 8:
            rvtype = u16(payload, 0)
            calltype = payload[2]
            parmcount = u16(payload, 4)
            arglist = u16(payload, 6)
            out.update({"rvtype": rvtype, "calltype": calltype, "parmcount": parmcount, "arglist": arglist})
        return out

    if leaf == LF_ARGLIST:
        # u16 count; u16 args[count]
        out["kind"] = "arglist"
        if len(payload) >= 2:
            count = u16(payload, 0)
            args = []
            pos = 2
            for _ in range(count):
                if pos + 2 > len(payload):
                    break
                args.append(u16(payload, pos))
                pos += 2
            out.update({"count": count, "args": args})
        return out

    if leaf == LF_FIELDLIST:
        # contains sub-leaves (LF_MEMBER / LF_ENUMERATE / etc.)
        out["kind"] = "fieldlist"
        fields: List[Dict[str, Any]] = []
        pos = 0
        end = len(payload)
        while pos + 2 <= end:
            pos = _skip_type_padding(payload, pos, end)
            if pos + 2 > end:
                break
            subleaf = u16(payload, pos)
            pos += 2
            if subleaf == LF_MEMBER:
                # u16 type; u16 attr; numeric offset; name
                if pos + 4 > end:
                    break
                typ = u16(payload, pos); attr = u16(payload, pos+2)
                pos += 4
                offset, pos = parse_numeric_leaf(payload, pos, end)
                name = ""
                if pos < end:
                    n = payload[pos]
                    name = payload[pos+1:pos+1+n].decode("latin1", errors="replace")
                    pos += 1 + n
                fields.append({"kind": "member", "attr": attr, "type": typ, "offset": offset, "name": name})
                continue
            if subleaf == LF_ENUMERATE:
                # u16 attr; numeric value; name
                if pos + 2 > end:
                    break
                attr = u16(payload, pos); pos += 2
                val, pos = parse_numeric_leaf(payload, pos, end)
                name = ""
                if pos < end:
                    n = payload[pos]
                    name = payload[pos+1:pos+1+n].decode("latin1", errors="replace")
                    pos += 1 + n
                fields.append({"kind": "enumerate", "attr": attr, "value": val, "name": name})
                continue
            if subleaf == LF_INDEX:
                # u16 index (continuation)
                if pos + 2 > end:
                    break
                idx = u16(payload, pos); pos += 2
                fields.append({"kind": "index", "index": idx})
                continue
            # Unknown subleaf: stop to avoid desync.
            fields.append({"kind": "unknown", "subleaf": subleaf, "pos": pos})
            break
        out["fields"] = fields
        return out

    if leaf == LF_BITFIELD:
        # Observed in Stars! NB09: u8 length; u8 position; u16 base_type
        out["kind"] = "bitfield"
        if len(payload) >= 4:
            out.update({"type": u16(payload, 2), "length": payload[0], "position": payload[1]})
        return out

    # default: return raw size only
    out["kind"] = "unknown"
    out["payload_len"] = len(payload)
    return out


def parse_sst_globaltypes(b: bytes, lfo: int, cb: int) -> Dict[str, Any]:
    """Parse sstGlobalTypes (aka $$TYPES).

    Note: the CodeView *type indices* (typind) used by symbol records are implied by record
    order plus a base. Different toolchains use different bases (commonly 0x0200 for CV4
    user types, or 0x1000 for later formats). We parse the record stream first and infer
    the base later using the typinds referenced by symbols.
    """
    blob = b[lfo:lfo+cb]
    start_off, _ = find_type_record_stream_start(blob)
    records: List[Dict[str, Any]] = []
    recno = 0
    for _, reclen, leaf, payload in iter_type_records(blob, start_off):
        rec = parse_type_record(leaf, payload)
        rec["_recno"] = recno  # 0-based record number within this type stream
        rec["reclen"] = reclen
        records.append(rec)
        recno += 1
    return {
        "subsection": "sstGlobalTypes",
        "lfo": lfo,
        "cb": cb,
        "stream_start": start_off,
        "record_count": recno,
        "records": records,
        "base_index": None,   # inferred later
        "named": {},          # filled later
    }


def parse_sst_srcmodule(b: bytes, lfo: int, cb: int) -> Dict[str, Any]:
    """Parse sstSrcModule (0x0127) line number / source mapping.

    This implements the format described in the TIS spec:

      Module header:
        uint16 cFile
        uint16 cSeg
        uint32 baseSrcFile[cFile]
        uint32 start_end[2*cSeg]     (start,end per module segment, offsets within segment)
        uint16 seg[cSeg]            (segment indices; pad to 4-byte alignment if needed)

      For each file (at baseSrcFile[i]):
        uint16 cSeg
        uint16 pad
        uint32 baseSrcLn[cSeg]
        uint32 start_end[2*cSeg]
        uint16 cbName
        char   Name[cbName]
        (no required padding beyond natural alignment)

      For each line table (at baseSrcLn[j]):
        uint16 Seg
        uint16 cPair
        uint32 offset[cPair]
        uint16 linenumber[cPair]
        (pad uint16 if cPair odd)

    We return a query-friendly structure:
      {
        cFile, cSeg, segs:[seg...],
        files:[ { name, line_tables: {seg:[(off,line), ...]} } , ...]
      }
    """
    blob = b[lfo:lfo+cb]
    if cb < 4:
        return {"cb": cb}

    cFile, cSeg = struct.unpack_from("<HH", blob, 0)
    pos = 4

    baseSrcFile: List[int] = []
    for _ in range(cFile):
        if pos + 4 > cb:
            break
        baseSrcFile.append(struct.unpack_from("<I", blob, pos)[0])
        pos += 4

    # module-level start/end per seg
    mod_ranges: List[Tuple[int, int]] = []
    for _ in range(cSeg):
        if pos + 8 > cb:
            break
        start = struct.unpack_from("<I", blob, pos)[0]
        end = struct.unpack_from("<I", blob, pos+4)[0]
        mod_ranges.append((start, end))
        pos += 8

    segs: List[int] = []
    for _ in range(cSeg):
        if pos + 2 > cb:
            break
        segs.append(struct.unpack_from("<H", blob, pos)[0])
        pos += 2
    # pad to maintain natural alignment (spec says pad chars if cSeg odd)
    if (cSeg & 1) and pos + 2 <= cb:
        pos += 2

    files: List[Dict[str, Any]] = []
    # We'll parse each file record, then parse its line tables.
    for i, off in enumerate(baseSrcFile):
        if off <= 0 or off + 8 > cb:
            continue
        f_cSeg, _pad = struct.unpack_from("<HH", blob, off)
        p = off + 4

        baseSrcLn: List[int] = []
        for _ in range(f_cSeg):
            if p + 4 > cb:
                break
            baseSrcLn.append(struct.unpack_from("<I", blob, p)[0])
            p += 4

        f_ranges: List[Tuple[int, int]] = []
        for _ in range(f_cSeg):
            if p + 8 > cb:
                break
            start = struct.unpack_from("<I", blob, p)[0]
            end = struct.unpack_from("<I", blob, p+4)[0]
            f_ranges.append((start, end))
            p += 8

        if p + 2 > cb:
            continue
        cbName = struct.unpack_from("<H", blob, p)[0]
        p += 2
        name = ""
        if p + cbName <= cb:
            name = blob[p:p+cbName].decode("latin1", errors="replace")
            p += cbName

        # Parse each line table referenced by baseSrcLn
        line_tables: Dict[int, List[Tuple[int, int]]] = {}
        seg_ranges: Dict[str, Dict[str, int]] = {}
        for idx, ln_off in enumerate(baseSrcLn):
            if ln_off <= 0 or ln_off + 4 > cb:
                continue
            Seg, cPair = struct.unpack_from("<HH", blob, ln_off)
            if idx < len(f_ranges):
                a, b2 = f_ranges[idx]
                seg_ranges[str(Seg)] = {"start": int(a), "end": int(b2)}
            q = ln_off + 4
            offsets: List[int] = []
            for _ in range(cPair):
                if q + 4 > cb:
                    break
                offsets.append(struct.unpack_from("<I", blob, q)[0])
                q += 4
            linenos: List[int] = []
            for _ in range(cPair):
                if q + 2 > cb:
                    break
                linenos.append(struct.unpack_from("<H", blob, q)[0])
                q += 2
            if cPair & 1:
                # pad word for alignment
                if q + 2 <= cb:
                    q += 2
            pairs = list(zip(offsets, linenos))
            # ensure stable ordering
            pairs.sort(key=lambda t: t[0])
            line_tables[Seg] = pairs

        files.append({
            "file_index": i,
            "name": name,
            "cSeg": f_cSeg,
            "segs": segs[:f_cSeg],  # best-effort: file table aligns with module seg ordering
            "ranges": [{"start": a, "end": b} for (a, b) in f_ranges],
            "line_tables": {str(k): [{"off": o, "line": ln} for (o, ln) in v] for k, v in line_tables.items()},
            "seg_ranges": seg_ranges,
            "off": off,
        })

    return {
        "cb": cb,
        "cFile": cFile,
        "cSeg": cSeg,
        "segs": segs,
        "ranges": [{"start": a, "end": b} for (a, b) in mod_ranges],
        "baseSrcFile": baseSrcFile,
        "files": files,
    }


def parse_sst_hashsym(b: bytes, lfo: int, cb: int) -> Tuple[bytes, int, int, int, int, int]:
    """
    GlobalSym/GlobalPub/StaticSym share:
      uint16 symhash
      uint16 addrhash
      uint32 cbSymbol
      uint32 cbSymHash
      uint32 cbAddrHash
      ... symbol bytes ...
    """
    symhash, addrhash, cbSymbol, cbSymHash, cbAddrHash = struct.unpack_from("<HHIII", b, lfo)
    sym_off = lfo + 16
    sym_blob = b[sym_off:sym_off+cbSymbol]
    return sym_blob, symhash, addrhash, cbSymbol, cbSymHash, cbAddrHash


def parse_pub_record(rectyp: int, payload: bytes) -> Optional[Dict[str, Any]]:
    if rectyp == S_PUB16:
        off, seg, typ = struct.unpack_from("<HHH", payload, 0)
        n = payload[6]
        name = payload[7:7+n].decode("latin1", errors="replace")
        out = {"name": name, "seg": seg, "off": off, "typind": typ, "rectyp": rectyp}
        prim = cv_primitive_to_c_type(typ)
        if prim:
            out["typ"] = prim[0]
            out["c_type"] = prim[1]
        return out
    if rectyp == S_PUB32:
        off32, seg, typ = struct.unpack_from("<IHH", payload, 0)
        n = payload[8]
        name = payload[9:9+n].decode("latin1", errors="replace")
        out = {"name": name, "seg": seg, "off": off32, "typind": typ, "rectyp": rectyp}
        prim = cv_primitive_to_c_type(typ)
        if prim:
            out["typ"] = prim[0]
            out["c_type"] = prim[1]
        return out
    return None



def parse_data16_record(rectyp: int, payload: bytes) -> Optional[Dict[str, Any]]:
    if rectyp in (S_LDATA16, S_GDATA16):
        off, seg, typ = struct.unpack_from("<HHH", payload, 0)
        n = payload[6]
        name = payload[7:7+n].decode("latin1", errors="replace")
        out = {"name": name, "seg": seg, "off": off, "typind": typ, "rectyp": rectyp}
        prim = cv_primitive_to_c_type(typ)
        if prim:
            out["typ"] = prim[0]
            out["c_type"] = prim[1]
        return out
    if rectyp in (S_LDATA32, S_GDATA32):
        off32, seg, typ = struct.unpack_from("<IHH", payload, 0)
        n = payload[8]
        name = payload[9:9+n].decode("latin1", errors="replace")
        out = {"name": name, "seg": seg, "off": off32, "typind": typ, "rectyp": rectyp}
        prim = cv_primitive_to_c_type(typ)
        if prim:
            out["typ"] = prim[0]
            out["c_type"] = prim[1]
        return out
    return None


def parse_pub_record(rectyp: int, payload: bytes) -> Optional[Dict[str, Any]]:
    # S_PUB16 and S_PUB32 share the Local Data layout for the address + typind + name.
    if rectyp == S_PUB16:
        off, seg, typ = struct.unpack_from("<HHH", payload, 0)
        n = payload[6]
        name = payload[7:7+n].decode("latin1", errors="replace")
        out = {"name": name, "seg": seg, "off": off, "typind": typ, "rectyp": rectyp}
        prim = cv_primitive_to_c_type(typ)
        if prim:
            out["typ"] = prim[0]
            out["c_type"] = prim[1]
        return out
    if rectyp == S_PUB32:
        off32, seg, typ = struct.unpack_from("<IHH", payload, 0)
        n = payload[8]
        name = payload[9:9+n].decode("latin1", errors="replace")
        out = {"name": name, "seg": seg, "off": off32, "typind": typ, "rectyp": rectyp}
        prim = cv_primitive_to_c_type(typ)
        if prim:
            out["typ"] = prim[0]
            out["c_type"] = prim[1]
        return out
    return None



def parse_proc16_record(rectyp: int, payload: bytes) -> Optional[Dict[str, Any]]:
    if rectyp in (S_LPROC16, S_GPROC16):
        pParent, pEnd, pNext = struct.unpack_from("<III", payload, 0)
        procLen, dbgStart, dbgEnd, off, seg, typ = struct.unpack_from("<HHHHHH", payload, 12)
        flags = payload[24]
        n = payload[25]
        name = payload[26:26+n].decode("latin1", errors="replace")
        return {
            "name": name,
            "seg": seg,
            "off": off,
            "typind": typ,
            "procLen": procLen,
            "dbgStart": dbgStart,
            "dbgEnd": dbgEnd,
            "flags": flags,
            "pParent": pParent,
            "pEnd": pEnd,
            "pNext": pNext,
            "rectyp": rectyp,
        }
    if rectyp in (S_LPROC32, S_GPROC32):
        # From TIS: pParent,pEnd,pNext,procLen,dbgStart,dbgEnd,off32,seg,typind,flags, name
        pParent, pEnd, pNext, procLen, dbgStart, dbgEnd, off32 = struct.unpack_from("<IIIIIII", payload, 0)
        seg, typ = struct.unpack_from("<HH", payload, 28)
        flags = payload[32]
        n = payload[33]
        name = payload[34:34+n].decode("latin1", errors="replace")
        return {
            "name": name,
            "seg": seg,
            "off": off32,
            "typind": typ,
            "procLen": procLen,
            "dbgStart": dbgStart,
            "dbgEnd": dbgEnd,
            "flags": flags,
            "pParent": pParent,
            "pEnd": pEnd,
            "pNext": pNext,
            "rectyp": rectyp,
        }
    return None


def parse_ref_record(rectyp: int, payload: bytes) -> Optional[Dict[str, Any]]:
    if rectyp in (S_PROCREF, S_DATAREF):
        # In this NB09: checksum u32, offset u32, iMod u16, typind u16
        checksum, symoff, imod, typ = struct.unpack_from("<IIHH", payload, 0)
        return {"checksum": checksum, "symoff": symoff, "imod": imod, "typind": typ, "rectyp": rectyp}
    return None


def resolve_ref(ref: Dict[str, Any], alignsym_by_mod: Dict[int, bytes]) -> Optional[Dict[str, Any]]:
    imod = ref["imod"]
    blob = alignsym_by_mod.get(imod)
    if not blob:
        return None
    symoff = ref["symoff"]
    if symoff + 4 > len(blob):
        return None
    reclen = u16(blob, symoff)
    rectyp = u16(blob, symoff+2)
    if symoff + 2 + reclen > len(blob):
        return None
    payload = blob[symoff+4:symoff+2+reclen]
    if ref["rectyp"] == S_PROCREF:
        pr = parse_proc16_record(rectyp, payload)
        if pr:
            return pr
    if ref["rectyp"] == S_DATAREF:
        dr = parse_data16_record(rectyp, payload)
        if dr:
            return dr
    return None



def infer_types_base_index(global_types: Dict[str, Any], referenced_typinds: List[int]) -> int:
    """Infer the base typind for the type record stream.

    We prefer 0x1000 when the referenced typinds suggest it; otherwise fall back to 0x0200.
    """
    rec_count = int(global_types.get("record_count") or 0)
    if rec_count <= 0:
        return 0x1000
    max_ref = max(referenced_typinds) if referenced_typinds else 0
    # Candidate bases in priority order
    candidates = [0x1000, 0x0200]
    for base in candidates:
        if max_ref >= base and (max_ref - base) < rec_count:
            return base
    # Heuristic: if any ref typind is >= 0x1000, it's almost certainly a 0x1000-based stream
    if any(t >= 0x1000 for t in referenced_typinds):
        return 0x1000
    return 0x0200


def finalize_global_types(global_types: Dict[str, Any], referenced_typinds: List[int]) -> Dict[str, Any]:
    """Assign real typinds to parsed type records and build name lookup."""
    if not global_types:
        return {}
    base = infer_types_base_index(global_types, referenced_typinds)
    global_types["base_index"] = base

    named: Dict[str, int] = {}
    for rec in global_types.get("records", []):
        recno = int(rec.get("_recno", 0))
        rec["typind"] = base + recno
        # Build name->typind map for named kinds
        nm = rec.get("name")
        if isinstance(nm, str) and nm:
            kind = rec.get("kind")
            if kind in ("structure", "class", "union", "enum", "udt"):
                named[nm] = rec["typind"]

    global_types["named"] = named
    return global_types



def parse_nb09_blob(b: bytes) -> dict:
    """Internal: parse NB09 blob bytes into a JSON-serializable dict."""
    b = bytes(b)
    _, dirents = parse_directory(b)

    dir_entries = [
        {"subsection": de.subsection, "imod": de.imod, "lfo": de.lfo, "cb": de.cb}
        for de in dirents
    ]

    # Collect subsections
    modules: Dict[int, Dict[str,Any]] = {}
    libraries: List[str] = []
    segname: Dict[int,str] = {}
    segmap: Dict[str,Any] = {}
    fileindex: Dict[str,Any] = {}
    global_types: Dict[str,Any] = {}
    srcmodules: Dict[int, Dict[str,Any]] = {}
    alignsym_by_mod: Dict[int,bytes] = {}

    for de in dirents:
        if de.subsection == SST_MODULE:
            modules[de.imod] = parse_sst_module(b, de.lfo, de.cb)
        elif de.subsection == SST_LIBRARIES:
            libraries = parse_sst_libraries(b, de.lfo, de.cb)
        elif de.subsection == SST_SEG_NAME:
            segname = parse_sst_segname(b, de.lfo, de.cb)
        elif de.subsection == SST_SEG_MAP:
            segmap = parse_sst_segmap(b, de.lfo, de.cb)
        elif de.subsection == SST_FILE_INDEX:
            fileindex = parse_sst_fileindex(b, de.lfo, de.cb)
        elif de.subsection == SST_GLOBAL_TYPES:
            global_types = parse_sst_globaltypes(b, de.lfo, de.cb)
        elif de.subsection == SST_SRC_MODULE:
            # multiple entries, keyed by module
            srcmodules[de.imod] = parse_sst_srcmodule(b, de.lfo, de.cb)
        elif de.subsection == SST_ALIGN_SYM:
            # keep raw blob for ref-resolution
            alignsym_by_mod[de.imod] = b[de.lfo:de.lfo+de.cb]

    # Parse publics
    publics: List[Dict[str,Any]] = []
    global_data: List[Dict[str,Any]] = []
    proc_refs: List[Dict[str,Any]] = []
    data_refs: List[Dict[str,Any]] = []

    # Keep decoded contents of the compacted tables (NB09)
    global_pub_header: Optional[Dict[str,Any]] = None
    global_sym_header: Optional[Dict[str,Any]] = None
    static_sym_header: Optional[Dict[str,Any]] = None
    global_pub_procrefs: List[Dict[str,Any]] = []
    global_pub_datarefs: List[Dict[str,Any]] = []
    global_pub_align: List[Dict[str,Any]] = []
    global_sym_procrefs: List[Dict[str,Any]] = []
    global_sym_datarefs: List[Dict[str,Any]] = []
    global_sym_align: List[Dict[str,Any]] = []
    static_sym_procrefs: List[Dict[str,Any]] = []
    static_sym_datarefs: List[Dict[str,Any]] = []
    static_sym_align: List[Dict[str,Any]] = []

    for de in dirents:
        if de.subsection == SST_GLOBAL_PUB:
            sym_blob, symhash, addrhash, cbSymbol, cbSymHash, cbAddrHash = parse_sst_hashsym(b, de.lfo, de.cb)
            global_pub_header = {"symhash": symhash, "addrhash": addrhash, "cbSymbol": cbSymbol, "cbSymHash": cbSymHash, "cbAddrHash": cbAddrHash}
            for _,_,rt,payload in iter_symbol_records(sym_blob):
                if rt == S_ALIGN:
                    global_pub_align.append({"rectyp": rt, "reclen": len(payload) + 2})
                    continue
                pr = parse_pub_record(rt, payload)
                if pr:
                    publics.append(pr)
                    continue
                rr = parse_ref_record(rt, payload)
                if rr:
                    if rt == S_PROCREF:
                        proc_refs.append(rr)
                        global_pub_procrefs.append(rr)
                    elif rt == S_DATAREF:
                        data_refs.append(rr)
                        global_pub_datarefs.append(rr)
        elif de.subsection == SST_GLOBAL_SYM:
            sym_blob, symhash, addrhash, cbSymbol, cbSymHash, cbAddrHash = parse_sst_hashsym(b, de.lfo, de.cb)
            global_sym_header = {"symhash": symhash, "addrhash": addrhash, "cbSymbol": cbSymbol, "cbSymHash": cbSymHash, "cbAddrHash": cbAddrHash}
            for _,_,rt,payload in iter_symbol_records(sym_blob):
                if rt == S_ALIGN:
                    global_sym_align.append({"rectyp": rt, "reclen": len(payload) + 2})
                    continue
                dr = parse_data16_record(rt, payload)
                if dr:
                    global_data.append(dr)
                    continue
                rr = parse_ref_record(rt, payload)
                if rr:
                    if rt == S_PROCREF:
                        proc_refs.append(rr)
                        global_sym_procrefs.append(rr)
                    elif rt == S_DATAREF:
                        data_refs.append(rr)
                        global_sym_datarefs.append(rr)
        elif de.subsection == SST_STATIC_SYM:
            sym_blob, symhash, addrhash, cbSymbol, cbSymHash, cbAddrHash = parse_sst_hashsym(b, de.lfo, de.cb)
            static_sym_header = {"symhash": symhash, "addrhash": addrhash, "cbSymbol": cbSymbol, "cbSymHash": cbSymHash, "cbAddrHash": cbAddrHash}
            for _,_,rt,payload in iter_symbol_records(sym_blob):
                if rt == S_ALIGN:
                    static_sym_align.append({"rectyp": rt, "reclen": len(payload) + 2})
                    continue
                rr = parse_ref_record(rt, payload)
                if rr:
                    if rt == S_PROCREF:
                        proc_refs.append(rr)
                        static_sym_procrefs.append(rr)
                    elif rt == S_DATAREF:
                        data_refs.append(rr)
                        static_sym_datarefs.append(rr)

    resolved_procs=[]
    for r in proc_refs:
        res = resolve_ref(r, alignsym_by_mod)
        if res:
            resolved_procs.append({"imod": r["imod"], "symoff": r["symoff"], "from": "PROCREF", **res})
    resolved_datas=[]
    for r in data_refs:
        res = resolve_ref(r, alignsym_by_mod)
        if res:
            resolved_datas.append({"imod": r["imod"], "symoff": r["symoff"], "from": "DATAREF", **res})

    # Also resolve compacted-table refs separately so callers can distinguish origins.
    def _resolve_ref_list(refs: List[Dict[str, Any]], from_tag: str) -> List[Dict[str, Any]]:
        outl: List[Dict[str, Any]] = []
        for rr in refs:
            res2 = resolve_ref(rr, alignsym_by_mod)
            if not res2:
                continue
            item = {"imod": rr["imod"], "symoff": rr["symoff"], "from": from_tag, **res2}
            if "checksum" in rr:
                item["checksum"] = rr["checksum"]
            if "typind" in rr and isinstance(rr["typind"], int):
                # keep original ref typind (may be a primitive) for debugging
                item["ref_typind"] = rr["typind"]
            outl.append(item)
        return outl

    global_sym_procref_symbols = _resolve_ref_list(global_sym_procrefs, "PROCREF")
    global_sym_dataref_symbols = _resolve_ref_list(global_sym_datarefs, "DATAREF")
    static_sym_procref_symbols = _resolve_ref_list(static_sym_procrefs, "PROCREF")
    static_sym_dataref_symbols = _resolve_ref_list(static_sym_datarefs, "DATAREF")

    # Finalize (assign real typinds) for the types stream, now that we have symbol-referenced typinds.
    referenced_typinds: List[int] = []
    for it in global_data:
        t = it.get("typind")
        if isinstance(t, int) and t:
            referenced_typinds.append(t)
    for it in resolved_procs:
        t = it.get("typind")
        if isinstance(t, int) and t:
            referenced_typinds.append(t)
    for it in resolved_datas:
        t = it.get("typind")
        if isinstance(t, int) and t:
            referenced_typinds.append(t)
    if global_types:
        global_types = finalize_global_types(global_types, referenced_typinds)

    # Attach module->files if available
    mod_to_files = fileindex.get("mod_to_files", {}) if fileindex else {}
    for imod, m in modules.items():
        m["files"] = mod_to_files.get(str(imod)) or mod_to_files.get(imod) or []


    # Fill missing sstSrcModule file names from sstFileIndex/module file lists.
    # In this Stars! NB09 blob, sstSrcModule file records may have cbName==0.
    for imod, sm in list(srcmodules.items()):
        m = modules.get(imod)
        mf = (m.get("files") if m else None) or []
        for f in sm.get("files") or []:
            if f.get("name"):
                continue
            idx = f.get("file_index")
            if isinstance(idx, int) and 0 <= idx < len(mf):
                f["name"] = mf[idx]


    # ---- Source lines: attach best-effort file + line range to each resolved proc ----
    def _line_at_or_before(pairs: List[Tuple[int, int]], off: int) -> Optional[int]:
        # pairs sorted by off
        lo, hi = 0, len(pairs) - 1
        best = None
        while lo <= hi:
            mid = (lo + hi) // 2
            o, ln = pairs[mid]
            if o <= off:
                best = ln
                lo = mid + 1
            else:
                hi = mid - 1
        return best

    def _find_proc_source(imod: int, seg: int, start_off: int, end_off: int) -> Tuple[Optional[str], Optional[int], Optional[int]]:
        sm = srcmodules.get(imod) or srcmodules.get(str(imod))
        if not sm:
            return (None, None, None)
        files = sm.get("files") or []
        # Try each file; pick the first one that provides a mapping for this segment.
        for f in files:
            lt = f.get("line_tables") or {}
            pairs_raw = lt.get(str(seg))
            if not pairs_raw:
                continue
            pairs = [(int(x["off"]), int(x["line"])) for x in pairs_raw if "off" in x and "line" in x]
            if not pairs:
                continue
            pairs.sort(key=lambda t: t[0])
            sr = (f.get("seg_ranges") or {}).get(str(seg))
            if sr is not None:
                try:
                    if start_off < int(sr.get("start", 0)) or start_off > int(sr.get("end", 0xFFFFFFFF)):
                        continue
                except Exception:
                    pass
            ls = _line_at_or_before(pairs, start_off)
            le = _line_at_or_before(pairs, end_off)
            if ls is None and le is None:
                continue
            return (f.get("name") or None, ls, le)
        return (None, None, None)

    for p in resolved_procs:
        imod = p.get("imod")
        seg = p.get("seg")
        off = p.get("off")
        plen = p.get("procLen")
        if isinstance(imod, int) and isinstance(seg, int) and isinstance(off, int) and isinstance(plen, int):
            end_off = off + max(plen - 1, 0)
            fn, ls, le = _find_proc_source(imod, seg, off, end_off)
            if fn:
                p["src_file"] = fn
            if ls is not None:
                p["line_start"] = ls
            if le is not None:
                p["line_end"] = le


    # ---- Proc locals / params (from module sstAlignSym scopes) ----

    # ---- Proc locals / params (from module sstAlignSym scopes) ----
    # We can only extract locals/params for procedures that were resolved into an sstAlignSym stream.
    def _parse_bprel16(payload: bytes) -> dict:
        # int16 off; uint16 typind; cstring name
        if len(payload) < 4:
            return {}
        bp_off = struct.unpack_from("<h", payload, 0)[0]
        typind = u16(payload, 2)
        name, _ = read_pascal(payload, 4)
        return {"bp_off": bp_off, "typind": typind, "name": name}

    def _parse_regrel16(payload: bytes) -> dict:
        # int16 off; uint16 typind; uint16 reg; cstring name
        if len(payload) < 6:
            return {}
        reg_off = struct.unpack_from("<h", payload, 0)[0]
        typind = u16(payload, 2)
        reg = u16(payload, 4)
        name, _ = read_pascal(payload, 6)
        return {"reg_off": reg_off, "typind": typind, "reg": reg, "name": name}

    def _parse_register(payload: bytes) -> dict:
        # uint16 typind; uint16 reg; cstring name
        if len(payload) < 4:
            return {}
        typind = u16(payload, 0)
        reg = u16(payload, 2)
        name, _ = read_pascal(payload, 4)
        return {"typind": typind, "reg": reg, "name": name}

    def _parse_block16(payload: bytes) -> dict:
        # uint32 pParent; uint32 pEnd; uint16 len; uint16 off; uint16 seg; pascal name
        if len(payload) < 14:
            return {}
        pParent = struct.unpack_from("<I", payload, 0)[0]
        pEnd = struct.unpack_from("<I", payload, 4)[0]
        blen = u16(payload, 8)
        off = u16(payload, 10)
        seg = u16(payload, 12)
        name, _ = read_pascal(payload, 14)
        return {"pParent": pParent, "pEnd": pEnd, "length": blen, "off": off, "seg": seg, "name": name}

    def _parse_label16(payload: bytes) -> dict:
        # uint16 off; uint16 seg; uint8 flags; pascal name
        # (from TIS CodeView spec: S_LABEL16)
        if len(payload) < 5:
            return {}
        off = u16(payload, 0)
        seg = u16(payload, 2)
        flags = payload[4]
        name, _ = read_pascal(payload, 5)
        return {"off": off, "seg": seg, "flags": flags, "name": name}

    def _parse_frameproc(payload: bytes) -> dict:
        # S_FRAMEPROC (0x1012) layout per LLVM CodeView SymbolRecordMapping:
        # u32 TotalFrameBytes, u32 PaddingFrameBytes, u32 OffsetToPadding,
        # u32 BytesOfCalleeSavedRegisters, u32 OffsetOfExceptionHandler,
        # u16 SectionIdOfExceptionHandler, u32 Flags
        if len(payload) < 26:
            return {}
        total, pad, offpad, saveregs, offeh = struct.unpack_from("<IIIII", payload, 0)
        secteh = u16(payload, 20)
        flags = struct.unpack_from("<I", payload, 22)[0]
        return {
            "total_frame_bytes": total,
            "padding_frame_bytes": pad,
            "offset_to_padding": offpad,
            "bytes_of_callee_saved_registers": saveregs,
            "offset_of_exception_handler": offeh,
            "section_id_of_exception_handler": secteh,
            "flags": flags,
        }

    proc_locals: List[Dict[str, Any]] = []

    for p in resolved_procs:
        imod = p.get("imod")
        symoff = p.get("symoff")
        pend = p.get("pEnd")
        if not isinstance(imod, int) or not isinstance(symoff, int) or not isinstance(pend, int):
            continue
        symstream = alignsym_by_mod.get(imod)
        if not symstream:
            continue
        if symoff < 0 or symoff >= len(symstream):
            continue

        recs: List[Dict[str, Any]] = []
        blocks: List[Dict[str, Any]] = []
        labels: List[Dict[str, Any]] = []
        frameproc: Dict[str, Any] | None = None
        block_stack: List[Tuple[int, int]] = []  # [(end_symoff, block_id)]
        saw_endarg = False

        # Determine starting offset right after the proc record itself.
        try:
            reclen = u16(symstream, symoff)
        except Exception:
            continue
        start_off = symoff + 2 + reclen
        cur = start_off

        hard_end = len(symstream)

        while cur < hard_end:
            try:
                rlen = u16(symstream, cur)
            except Exception:
                break
            if rlen == 0:
                break
            rectyp = u16(symstream, cur + 2)
            payload = symstream[cur + 4: cur + 2 + rlen]

            # Pop any blocks that ended at or before this record.
            while block_stack and cur >= block_stack[-1][0]:
                block_stack.pop()

            if rectyp == S_END:
                # If this is the proc's end record, stop.
                if cur >= pend:
                    break

            elif rectyp == S_ENDARG:
                saw_endarg = True

            elif rectyp == 0x1012:  # S_FRAMEPROC (if present)
                # Usually appears right after the proc symbol.
                if frameproc is None:
                    fp = _parse_frameproc(payload)
                    if fp:
                        frameproc = {"rectyp": rectyp, **fp}

            elif rectyp == 0x0109:  # S_LABEL16
                d = _parse_label16(payload)
                if d and d.get("name"):
                    rec: Dict[str, Any] = {
                        "name": d["name"],
                        "seg": d.get("seg"),
                        "off": d.get("off"),
                        "flags": d.get("flags"),
                        "rectyp": rectyp,
                    }
                    if block_stack:
                        rec["block"] = block_stack[-1][1]
                    labels.append(rec)

            elif rectyp == S_BLOCK16:
                d = _parse_block16(payload)
                if d:
                    block_id = len(blocks)
                    blocks.append({
                        "id": block_id,
                        "name": d.get("name", ""),
                        "seg": d.get("seg"),
                        "off": d.get("off"),
                        "length": d.get("length"),
                        "pParent": d.get("pParent"),
                        "pEnd": d.get("pEnd"),
                        "symoff": cur,
                    })
                    if isinstance(d.get("pEnd"), int) and d["pEnd"] > 0:
                        block_stack.append((int(d["pEnd"]), block_id))

            elif rectyp == 0x0100:  # S_BPREL16
                d = _parse_bprel16(payload)
                if d and d.get("name"):
                    kind = "local"
                    if (not saw_endarg) and isinstance(d.get("bp_off"), int) and d["bp_off"] >= 0:
                        kind = "param"
                    typind = int(d.get("typind") or 0)
                    tc = cv_primitive_to_c_type(typind)
                    typ, c_type = tc if tc else (None, None)
                    rec: Dict[str, Any] = {
                        "kind": kind,
                        "name": d["name"],
                        "rectyp": rectyp,
                        "typind": typind,
                        "bp_off": d.get("bp_off"),
                    }
                    if block_stack:
                        rec["block"] = block_stack[-1][1]
                    if typ:
                        rec["typ"] = typ
                    if c_type:
                        rec["c_type"] = c_type
                    recs.append(rec)

            elif rectyp == 0x010C:  # S_REGREL16
                d = _parse_regrel16(payload)
                if d and d.get("name"):
                    typind = int(d.get("typind") or 0)
                    tc = cv_primitive_to_c_type(typind)
                    typ, c_type = tc if tc else (None, None)
                    rec = {
                        "kind": "local",
                        "name": d["name"],
                        "rectyp": rectyp,
                        "typind": typind,
                        "reg": d.get("reg"),
                        "reg_off": d.get("reg_off"),
                    }
                    if block_stack:
                        rec["block"] = block_stack[-1][1]
                    if typ:
                        rec["typ"] = typ
                    if c_type:
                        rec["c_type"] = c_type
                    recs.append(rec)

            elif rectyp == 0x0002:  # S_REGISTER
                d = _parse_register(payload)
                if d and d.get("name"):
                    typind = int(d.get("typind") or 0)
                    tc = cv_primitive_to_c_type(typind)
                    typ, c_type = tc if tc else (None, None)
                    rec = {
                        "kind": "local",
                        "name": d["name"],
                        "rectyp": rectyp,
                        "typind": typind,
                        "reg": d.get("reg"),
                    }
                    if block_stack:
                        rec["block"] = block_stack[-1][1]
                    if typ:
                        rec["typ"] = typ
                    if c_type:
                        rec["c_type"] = c_type
                    recs.append(rec)

            cur += 2 + rlen

        if recs or blocks or labels or frameproc is not None:
            entry = {
                "name": p.get("name"),
                "imod": imod,
                "symoff": symoff,
                "seg": p.get("seg"),
                "off": p.get("off"),
                "typind": p.get("typind"),
                "locals": recs,
            }
            if blocks:
                entry["blocks"] = blocks
            if labels:
                entry["labels"] = labels
            if frameproc is not None:
                entry["frameproc"] = frameproc
            proc_locals.append(entry)



    # Modules that do not have an sstAlignSym subsection (no per-proc locals/params/scopes).
    missing_alignsym_modules: List[Dict[str, Any]] = []

    align_imods = set(alignsym_by_mod.keys())
    for imod in sorted(modules.keys()):
        if imod not in align_imods:
            missing_alignsym_modules.append({"imod": imod, "name": modules[imod].get("name", "")})

    out = {
        "summary": {
            "module_count": len(modules),
            "public_count": len(publics),
            "global_data_count": len(global_data),
            "resolved_proc_count": len(resolved_procs),
            "resolved_dataref_count": len(resolved_datas),
            "proc_locals_count": len(proc_locals),
            "missing_alignsym_module_count": len(missing_alignsym_modules),
            "type_record_count": int(global_types.get("record_count", 0)),
            "libraries": libraries,
        },
        "dir_entries": dir_entries,
        "modules": modules,
        "srcmodules": srcmodules,
        "segname": segname,
        "segmap": segmap,
        "publics": publics,
        "global_data": global_data,
        "proc_symbols": resolved_procs,
        "dataref_symbols": resolved_datas,
        "global_types": global_types,
        "proc_locals": proc_locals,
        "missing_alignsym_modules": missing_alignsym_modules,
        "global_sym_header": global_sym_header,
        "global_pub_header": global_pub_header,
        "static_sym_header": static_sym_header,
        "global_pub_procrefs": global_pub_procrefs,
        "global_pub_datarefs": global_pub_datarefs,
        "global_pub_align": global_pub_align,
        "global_sym_procrefs": global_sym_procrefs,
        "global_sym_datarefs": global_sym_datarefs,
        "global_sym_align": global_sym_align,
        "static_sym_procrefs": static_sym_procrefs,
        "static_sym_datarefs": static_sym_datarefs,
        "global_sym_procref_symbols": global_sym_procref_symbols,
        "global_sym_dataref_symbols": global_sym_dataref_symbols,
        "static_sym_procref_symbols": static_sym_procref_symbols,
        "static_sym_dataref_symbols": static_sym_dataref_symbols,
        "static_sym_align": static_sym_align,
    }

    return out


# ---- Library entrypoints ----

from nb09_model import (
    DirEntry,
    DataSymbol,
    ProcSymbol,
    ProcLocals,
    LocalSymbol,
    BlockScope,
    LabelSymbol,
    FrameProc,
    TypeRecord,
    TypeTable,
    CompactedSymHeader,
    PubSymbol,
    ProcRef,
    DataRef,
    AlignSym,
    Nb09Db,
)

def load_nb09(path: str) -> Nb09Db:
    """
    Parse an extracted CodeView NB09 blob from disk and return a structured Nb09Db.
    This is the single "source of truth" loader intended for reuse by other scripts.
    """
    data = open(path, "rb").read()
    return parse_nb09_bytes(data)

def parse_nb09_bytes(data: bytes) -> Nb09Db:
    """
    Parse NB09 blob bytes and return Nb09Db.
    """
    # Reuse the existing parse pipeline by calling the internal worker and then
    # converting the dicts/lists into structured model objects.
    out = _parse_nb09_to_dict(data)

    # Convert to model objects
    dir_entries = [DirEntry(**e) for e in out.get("dir_entries", [])]

    global_data = [DataSymbol(**g) for g in out.get("global_data", [])]
    proc_symbols = []
    for p in out.get("proc_symbols", []):
        p2 = dict(p)
        from_ref = p2.pop("from", None)
        proc_symbols.append(ProcSymbol(from_ref=from_ref, **p2))

    proc_locals = None
    if "proc_locals" in out:
        proc_locals = []
        

        for pl in out["proc_locals"]:
            locals_list = [LocalSymbol(**x) for x in pl.get("locals", [])]
            blocks_list = [BlockScope(**b) for b in pl.get("blocks", [])] if pl.get("blocks") else []
            labels_list = [LabelSymbol(**l) for l in pl.get("labels", [])] if pl.get("labels") else []
            frameproc_obj = FrameProc(**pl["frameproc"]) if pl.get("frameproc") else None
            proc_locals.append(
                ProcLocals(
                    proc_name=pl["name"],
                    imod=pl["imod"],
                    symoff=pl["symoff"],
                    seg=pl["seg"],
                    off=pl["off"],
                    typind=pl["typind"],
                    locals=locals_list,
                    blocks=blocks_list,
                    labels=labels_list,
                    frameproc=frameproc_obj,
                )
            )

    global_types = None
    gt = out.get("global_types")
    if gt and isinstance(gt, dict) and "records" in gt:
        # records is a list of dicts; create map typind->TypeRecord
        rec_map = {}
        for r in gt.get("records", []):
            r2 = dict(r)
            typind = r2.pop("typind")
            leaf = r2.pop("leaf")
            kind = r2.pop("kind")
            reclen = r2.pop("reclen")
            rec_map[typind] = TypeRecord(typind=typind, leaf=leaf, kind=kind, reclen=reclen, data=r2)
        global_types = TypeTable(base_index=gt.get("base_index", 0x1000), records=rec_map, named=gt.get("named", {}))

    # Decode compacted symbol tables (global/pub/static)
    gsh = out.get("global_sym_header")
    gph = out.get("global_pub_header")
    ssh = out.get("static_sym_header")
    global_sym_header = CompactedSymHeader(**gsh) if isinstance(gsh, dict) else None
    global_pub_header = CompactedSymHeader(**gph) if isinstance(gph, dict) else None
    static_sym_header = CompactedSymHeader(**ssh) if isinstance(ssh, dict) else None

    global_pub_pubs = [PubSymbol(**d) for d in out.get("publics", [])]
    global_pub_procrefs = [ProcRef(**d) for d in out.get("global_pub_procrefs", [])]
    global_pub_datarefs = [DataRef(**d) for d in out.get("global_pub_datarefs", [])]
    global_pub_align = [AlignSym(**d) for d in out.get("global_pub_align", [])]

    global_sym_procrefs = [ProcRef(**d) for d in out.get("global_sym_procrefs", [])]
    global_sym_datarefs = [DataRef(**d) for d in out.get("global_sym_datarefs", [])]
    global_sym_align = [AlignSym(**d) for d in out.get("global_sym_align", [])]

    static_sym_procrefs = [ProcRef(**d) for d in out.get("static_sym_procrefs", [])]
    static_sym_datarefs = [DataRef(**d) for d in out.get("static_sym_datarefs", [])]
    static_sym_align = [AlignSym(**d) for d in out.get("static_sym_align", [])]

    db = Nb09Db(
        summary=out.get("summary", {}),
        dir_entries=dir_entries,
        modules=out.get("modules", []),
        segname=out.get("segname", []),
        segmap=out.get("segmap", []),
        publics=out.get("publics", []),
        global_data=global_data,
        proc_symbols=proc_symbols,
        dataref_symbols=out.get("dataref_symbols", []),
        global_types=global_types,
        srcmodules=out.get("srcmodules"),
        proc_locals=proc_locals,
        missing_alignsym_modules=out.get("missing_alignsym_modules"),
        global_sym_header=global_sym_header,
        global_pub_header=global_pub_header,
        static_sym_header=static_sym_header,
        global_pub_pubs=global_pub_pubs,
        global_pub_procrefs=global_pub_procrefs,
        global_pub_datarefs=global_pub_datarefs,
        global_pub_align=global_pub_align,
        global_sym_procrefs=global_sym_procrefs,
        global_sym_datarefs=global_sym_datarefs,
        global_sym_align=global_sym_align,
        static_sym_procrefs=static_sym_procrefs,
        static_sym_datarefs=static_sym_datarefs,
        global_sym_procref_symbols=out.get("global_sym_procref_symbols"),
        global_sym_dataref_symbols=out.get("global_sym_dataref_symbols"),
        static_sym_procref_symbols=out.get("static_sym_procref_symbols"),
        static_sym_dataref_symbols=out.get("static_sym_dataref_symbols"),
        static_sym_align=static_sym_align,
    )
    return db

def _parse_nb09_to_dict(data: bytes) -> dict:
    """
    Internal: original script-style parse that returns a JSON-serializable dict.
    Kept as a private helper so other tools can build structured views on top.
    """
    return parse_nb09_blob(data)

# Backwards-compatible alias
parse_nb09 = load_nb09
