# -*- coding: utf-8 -*-
# ApplyNb09StructPackingFromJson.py
# @category: Stars.NB09

import json
import re

# NOTE: This is a standard Ghidra Jython script.
# Do NOT instantiate GhidraScript manually; Ghidra provides globals like
# currentProgram, askFile(), println(), etc.

from ghidra.program.model.data import (
    CategoryPath,
    DataTypeConflictHandler,
    StructureDataType,
    UnionDataType,
    TypedefDataType,
    PointerDataType,
    ArrayDataType,
    BitFieldDataType,
    Undefined1DataType,
    CharDataType,
)

# Builtins: use signed forms (size-correct). Avoid UnsignedByteDataType (missing in some 10.3 builds).
try:
    from ghidra.program.model.data import ByteDataType, ShortDataType, IntegerDataType, LongDataType, UnsignedIntegerDataType, UnsignedLongDataType
except Exception:
    ByteDataType = None
    ShortDataType = None
    IntegerDataType = None
    LongDataType = None
    UnsignedIntegerDataType = None
    UnsignedLongDataType = None

_DECL_RE = re.compile(r"^\s*(?P<type>.*?)\s+(?P<name>[A-Za-z_]\w*)(?P<arrays>(\[[0-9]+\])*)\s*$")
_ARRAY_RE = re.compile(r"\[([0-9]+)\]")

# Verbose debug logging (set False to quiet)
_DEBUG = True

_EXCLUDE_STRUCTS = [] # ["RECT", "POINT"]


def _dbg(msg):
    if not _DEBUG:
        return
    try:
        println(msg)
    except Exception:
        pass



def _safe_add_replace(dtm, dt, handler):
    """Add a datatype, and if Ghidra blows up due to a corrupted existing type,
    try to remove the existing type and retry."""
    try:
        return dtm.addDataType(dt, handler)
    except Exception as e:
        msg = str(e)
        # We have observed Ghidra NPEs when replacing composites whose existing
        # components have null datatypes (often from a prior bad import).
        if ('NullPointerException' in msg) or ('java.lang.NullPointerException' in msg):
            try:
                existing = dtm.getDataType(dt.getCategoryPath(), dt.getName())
            except Exception:
                existing = None
            if existing is not None:
                try:
                    _dbg("[SAFE] removing existing corrupted type %s" % existing.getPathName())
                    dtm.remove(existing, monitor)
                except Exception as e2:
                    _dbg("[SAFE] remove failed for %s: %s" % (existing.getPathName(), e2))
            # retry once
            return dtm.addDataType(dt, handler)
        raise
def _norm(s):
    if s is None:
        return ""
    return str(s).strip()


def _unwrap_typedef(dt):
    try:
        if isinstance(dt, TypedefDataType):
            b = dt.getBaseDataType()
            if b is not None:
                return b
    except Exception:
        pass
    return dt


def _index_datatypes(dtm):
    idx = {}
    it = dtm.getAllDataTypes()
    while it.hasNext():
        dt = it.next()
        if dt is None:
            continue
        base = _unwrap_typedef(dt)
        for getter in ("getName", "getPathName"):
            try:
                nm = getattr(dt, getter)()
                if nm:
                    idx.setdefault(nm, base)
            except Exception:
                pass
            try:
                nm2 = getattr(base, getter)()
                if nm2:
                    idx.setdefault(nm2, base)
            except Exception:
                pass
    return idx


def _ensure_len(dt, want_len):
    """Ensure structure has at least want_len bytes."""
    try:
        cur = dt.getLength()
    except Exception:
        return

    if cur >= want_len:
        return

    _dbg("[ENSURE] %s (%s) want_len=%d cur=%d" % (
        getattr(dt, 'getPathName', lambda: '<dt>')(), dt.__class__.__name__, want_len, cur))

    # Prefer growStructure (keeps existing components).
    # IMPORTANT: Some StructureDB variants can return without changing length.
    # Guard against infinite loops by detecting "no progress" and falling back.
    try:
        safety = 0
        while cur < want_len and safety < 32:
            need = want_len - cur
            before = cur
            dt.growStructure(need)
            cur = dt.getLength()
            safety += 1
            if cur == before:
                break
        if cur >= want_len:
            _dbg("[ENSURE] %s after growStructure cur=%d" % (getattr(dt, 'getPathName', lambda: '<dt>')(), cur))
            return
        _dbg("[ENSURE] growStructure made no progress (cur=%d want=%d); falling back" % (cur, want_len))
    except Exception as e:
        _dbg("[ENSURE] growStructure failed: %s" % e)

    # Fallback setLength if available
    try:
        dt.setLength(want_len)
        cur2 = dt.getLength()
        _dbg("[ENSURE] %s after setLength cur=%d" % (getattr(dt, 'getPathName', lambda: '<dt>')(), cur2))
        if cur2 >= want_len:
            return
    except Exception as e:
        _dbg("[ENSURE] setLength failed: %s" % e)

    # Final fallback: append undefined bytes (works reliably across StructureDB variants)
    try:
        undef = Undefined1DataType.dataType
        cur = dt.getLength()
        while cur < want_len:
            dt.add(undef)
            cur = dt.getLength()
        _dbg("[ENSURE] %s after add(undefined) cur=%d" % (getattr(dt, 'getPathName', lambda: '<dt>')(), cur))
    except Exception as e:
        _dbg("[ENSURE] add(undefined) failed: %s" % e)


def _set_struct_packing(struct_dt, pack_value=1, min_align=1):
    """Best-effort: force packed layout (avoid end padding / alignment rounding)."""
    # Enable packing if available.
    try:
        if hasattr(struct_dt, "setPackingEnabled"):
            struct_dt.setPackingEnabled(True)
    except Exception as e:
        _dbg("[PACK] setPackingEnabled failed: %s" % e)

    # Some Ghidra builds expose explicit packing value.
    try:
        if hasattr(struct_dt, "setExplicitPackingValue"):
            struct_dt.setExplicitPackingValue(int(pack_value))
    except Exception as e:
        _dbg("[PACK] setExplicitPackingValue failed: %s" % e)

    # Minimum alignment.
    try:
        if hasattr(struct_dt, "setExplicitMinimumAlignment"):
            struct_dt.setExplicitMinimumAlignment(int(min_align))
    except Exception as e:
        _dbg("[PACK] setExplicitMinimumAlignment failed: %s" % e)

    # Some builds use setAlignment.
    try:
        if hasattr(struct_dt, "setAlignment"):
            struct_dt.setAlignment(int(min_align))
    except Exception:
        pass


def _force_struct_len(struct_dt, want_len):
    """Force a structure length to exactly want_len (can shrink).

    We only shrink if all defined components fit within want_len; otherwise we log and keep.
    """
    try:
        want_len = int(want_len)
    except Exception:
        return
    if want_len <= 0:
        return

    try:
        cur = int(struct_dt.getLength())
    except Exception:
        return

    if cur == want_len:
        return

    if cur < want_len:
        _ensure_len(struct_dt, want_len)
        return

    # cur > want_len: ensure no defined component crosses the boundary.
    bad = []
    try:
        for c in struct_dt.getComponents():
            try:
                co = int(c.getOffset())
                cl = int(c.getLength())
                dtc = c.getDataType()
                nm = dtc.getName() if dtc is not None else ""
            except Exception:
                continue
            if cl <= 0:
                continue
            # treat undefined fillers as safe
            if nm and nm.lower().startswith("undefined"):
                continue
            if co < want_len and (co + cl) > want_len:
                bad.append((co, cl, nm))
    except Exception:
        bad = [(-1, -1, "<error>")]

    if bad:
        _dbg("[SIZE-SKIP] %s cannot shrink %d->%d; component crosses end: %s" % (
            getattr(struct_dt, 'getPathName', lambda: '<dt>')(), cur, want_len, bad))
        return

    # Clear/delete any components that begin at/after want_len.
    try:
        comps = list(struct_dt.getComponents())
    except Exception:
        comps = []
    ords = []
    for c in comps:
        try:
            if int(c.getOffset()) >= want_len:
                ords.append(int(c.getOrdinal()))
        except Exception:
            pass
    for ord_ in sorted(set(ords), reverse=True):
        try:
            if hasattr(struct_dt, "clearComponent"):
                struct_dt.clearComponent(ord_)
            else:
                struct_dt.deleteComponent(ord_)
        except Exception:
            try:
                struct_dt.deleteComponent(ord_)
            except Exception:
                pass

    # Now attempt to set exact length.
    try:
        if hasattr(struct_dt, "setLength"):
            struct_dt.setLength(want_len)
    except Exception as e:
        _dbg("[SIZE] setLength(%d) failed: %s" % (want_len, e))
        # Fallback: delete trailing undefined components until length matches.
        try:
            while int(struct_dt.getLength()) > want_len:
                # find last component
                last = None
                for c in struct_dt.getComponents():
                    last = c
                if last is None:
                    break
                try:
                    struct_dt.deleteComponent(int(last.getOrdinal()))
                except Exception:
                    break
        except Exception:
            pass

    try:
        _dbg("[SIZE] %s forced len=%d (was %d)" % (
            getattr(struct_dt, 'getPathName', lambda: '<dt>')(), int(struct_dt.getLength()), cur))
    except Exception:
        pass


def _delete_overlaps(struct_dt, off, length):
    """Clear (or delete) any *defined* components overlapping [off, off+length).

    Important: do NOT remove undefined filler components, because deleting them can
    shrink the structure length and cause 'not enough undefined bytes' errors later.
    """
    end = off + length
    ords = []
    try:
        for c in struct_dt.getComponents():
            try:
                co = c.getOffset()
                cl = c.getLength()
                dtc = c.getDataType()
            except Exception:
                continue
            if cl <= 0:
                continue
            if dtc is None:
                continue

            # Skip undefined fillers
            try:
                n = dtc.getName()
            except Exception:
                n = ""
            if n and n.lower().startswith("undefined"):
                continue

            # overlap?
            if not (co + cl <= off or co >= end):
                try:
                    ords.append(c.getOrdinal())
                except Exception:
                    pass
    except Exception:
        return

    if ords:
        _dbg("[OVERLAP] %s off=0x%x len=0x%x ords=%s" % (
            getattr(struct_dt, 'getPathName', lambda: '<dt>')(), off, length, sorted(set(ords))))

    for ord_ in sorted(set(ords), reverse=True):
        # Prefer clearing to undefined to preserve structure length
        try:
            if hasattr(struct_dt, "clearComponent"):
                struct_dt.clearComponent(ord_)
                continue
        except Exception:
            pass
        # Fall back to deletion (may shrink; caller should ensure length after)
        try:
            struct_dt.deleteComponent(ord_)
            continue
        except Exception:
            pass
        try:
            struct_dt.delete(ord_)
        except Exception:
            pass


def _dump_struct(struct_dt, max_comps=40):
    """Debug dump of structure components."""
    try:
        _dbg("[DUMP] struct=%s len=%d" % (struct_dt.getPathName(), struct_dt.getLength()))
    except Exception:
        _dbg("[DUMP] struct=<unknown>")
        return

    try:
        comps = list(struct_dt.getComponents())
    except Exception:
        return
    for i, c in enumerate(comps):
        if i >= max_comps:
            _dbg("[DUMP] ... (%d more comps)" % (len(comps) - max_comps))
            break
        try:
            _dbg("[DUMP]  off=0x%x len=0x%x dt=%s name=%s" % (
                c.getOffset(), c.getLength(), c.getDataType().getName(), c.getFieldName()))
        except Exception:
            pass


def _force_struct_len_exact(struct_dt, want_len):
    """Force structure length to exactly want_len.

    Ghidra often rounds struct size up to its computed alignment (e.g., 4),
    which is *wrong* for many 16-bit/packed structs. NB09 already provides the
    canonical byte size, so we clamp the DataType length to match.

    Strategy:
      1) If we need to shrink, clear/delete any components that start at/after
         want_len.
      2) Refuse to shrink if any defined component overlaps the truncation
         boundary (we log and leave length as-is).
      3) Call setLength(want_len) (or equivalent) if possible.
    """
    try:
        want_len = int(want_len)
    except Exception:
        return
    if want_len <= 0:
        return

    try:
        cur_len = struct_dt.getLength()
    except Exception:
        return

    if cur_len == want_len:
        return

    if cur_len < want_len:
        _ensure_len(struct_dt, want_len)
        return

    # If any defined component crosses the boundary, we cannot safely shrink.
    try:
        for c in struct_dt.getComponents():
            try:
                off = c.getOffset()
                ln = c.getLength()
                dtc = c.getDataType()
            except Exception:
                continue
            if ln <= 0 or dtc is None:
                continue
            try:
                n = dtc.getName() or ""
            except Exception:
                n = ""
            # undefined filler can be discarded
            is_undef = bool(n and n.lower().startswith("undefined"))
            if off < want_len and (off + ln) > want_len and not is_undef:
                _dbg("[SIZE-WARN] %s cannot shrink to %d; component crosses boundary: off=0x%x len=0x%x dt=%s" % (
                    getattr(struct_dt, 'getPathName', lambda: '<dt>')(), want_len, off, ln, n))
                return
    except Exception:
        # If we can't enumerate components, don't risk corruption.
        _dbg("[SIZE-WARN] %s cannot enumerate components to shrink; leaving len=%d" % (
            getattr(struct_dt, 'getPathName', lambda: '<dt>')(), cur_len))
        return

    # Clear/delete anything fully beyond new length.
    ords = []
    try:
        for c in struct_dt.getComponents():
            try:
                off = c.getOffset()
                ln = c.getLength()
            except Exception:
                continue
            if ln <= 0:
                continue
            if off >= want_len:
                try:
                    ords.append(c.getOrdinal())
                except Exception:
                    pass
    except Exception:
        ords = []

    for ord_ in sorted(set(ords), reverse=True):
        try:
            if hasattr(struct_dt, "clearComponent"):
                struct_dt.clearComponent(ord_)
                continue
        except Exception:
            pass
        try:
            if hasattr(struct_dt, "deleteComponent"):
                struct_dt.deleteComponent(ord_)
                continue
        except Exception:
            pass
        try:
            struct_dt.delete(ord_)
        except Exception:
            pass

    # Finally clamp length.
    try:
        struct_dt.setLength(want_len)
    except Exception as e:
        _dbg("[SIZE] setLength(%d) failed for %s: %s" % (want_len, getattr(struct_dt, 'getPathName', lambda: '<dt>')(), e))
        return

    try:
        _dbg("[SIZE] %s len %d -> %d" % (
            getattr(struct_dt, 'getPathName', lambda: '<dt>')(), cur_len, struct_dt.getLength()))
    except Exception:
        pass


def _builtin_for_name(dtm, base_name):
    n = base_name.strip()
    # canonicalize
    n = n.replace("signed ", "").replace("unsigned ", "")

    # common spellings
    #
    # IMPORTANT: In CodeView + C, `char` is a distinct "character" type.
    # If we map it to ByteDataType, Ghidra will show char arrays as byte[N].
    # So keep `char` as CharDataType, but still treat uint8_t/byte as ByteDataType.
    if n in ("char",):
        try:
            return CharDataType.dataType
        except Exception:
            # fallback: some builds may not expose CharDataType; best-effort
            return ByteDataType.dataType if ByteDataType is not None else None

    # 8-bit
    if n in ("int8_t", "uint8_t", "byte"):
        if ByteDataType is not None:
            return ByteDataType.dataType

    # 16-bit
    #
    # NOTE: Ghidra's built-in "int" and "long" sizes depend on the language
    # model; for Win16 (x86:16), we still want fixed *byte sizes* that match
    # the C typedefs in types.h / NB09.
    #
    # Use ShortDataType for 2-byte integers, IntegerDataType for 4-byte integers,
    # and LongDataType for 8-byte integers.
    if n in ("short", "int16_t", "uint16_t", "word"):
        if ShortDataType is not None:
            return ShortDataType.dataType

    # 32-bit
    if n in ("long", "int32_t", "uint32_t", "dword"):
        if LongDataType is not None:
            return LongDataType.dataType

    # 64-bit
    if n in ("longlong", "int64_t", "uint64_t"):
        if LongDataType is not None:
            return LongDataType.dataType
    if n in ("void",):
        # Ghidra doesn't like plain void as a field; treat as byte.
        if ByteDataType is not None:
            return ByteDataType.dataType

    return None
_DEFAULT_CAT_PATH = CategoryPath("/stars")

# Populated in main(): name -> size (bytes) for NB09 structs/unions.
_SIZE_BY_NAME = {}



def _resolve_base_type(dtm, name_index, base_name, cat_path=None):
    """
    Resolve a base (non-pointer, non-array) type name to a Ghidra DataType.

    Key points for this project:
      - We frequently encounter forward references (a struct uses POINT before POINT is built).
      - We must NOT create 1-byte typedef placeholders for composite types, because that poisons
        subsequent structure placement (flen becomes 1, and later replacements can leave null components).
      - Keep name_index in sync even as we add types (do a live dtm lookup when missing).
    """
    b = _builtin_for_name(dtm, base_name)
    if b is not None:
        return b

    # Try exact and common aliases
    cand = [base_name, base_name.strip()]
    # tagX -> X heuristic (useful for tagRECT->RECT)
    if base_name.startswith("tag") and len(base_name) > 3:
        cand.append(base_name[3:])
    # _foo -> FOO (typedef alias pattern)
    if base_name.startswith("_") and len(base_name) > 1:
        cand.append(base_name[1:].upper())

    # 1) Try cached index
    for c in cand:
        dt = name_index.get(c)
        if dt is not None:
            return dt

    # 2) Try live lookups in dtm (keeps us correct after we create types)
    for c in cand:
        for cp in (cat_path or _DEFAULT_CAT_PATH, _DEFAULT_CAT_PATH, CategoryPath("/")):
            try:
                dt = dtm.getDataType(cp, c)
            except Exception:
                dt = None
            if dt is not None:
                dt = _unwrap_typedef(dt)
                name_index[c] = dt
                name_index[dt.getName()] = dt
                try:
                    name_index[dt.getPathName()] = dt
                except Exception:
                    pass
                _dbg("[RESOLVE] %s -> %s (dtm lookup)" % (c, dt.getPathName()))
                return dt

    # 3) Forward reference: create a placeholder STRUCT (preferred) if we know its size.
    #    This ensures early uses (e.g. embedding POINT) have the correct length.
    for c in cand:
        sz = _SIZE_BY_NAME.get(c)
        if sz is None and c.startswith("tag"):
            sz = _SIZE_BY_NAME.get(c[3:])
        if sz is None and c.startswith("_"):
            sz = _SIZE_BY_NAME.get(c[1:].upper())
        if sz is not None and int(sz) > 0:
            try:
                sdt = StructureDataType(c, int(sz))
                try:
                    sdt.setCategoryPath(cat_path or _DEFAULT_CAT_PATH)
                except Exception:
                    pass
                sdt = dtm.addDataType(sdt, DataTypeConflictHandler.KEEP_HANDLER)
                base = _unwrap_typedef(sdt)
                name_index[c] = base
                name_index[base.getName()] = base
                try:
                    name_index[base.getPathName()] = base
                except Exception:
                    pass
                _dbg("[FWD-STRUCT] created placeholder struct %s (size=%d) under %s" % (
                    c, int(sz), (cat_path or _DEFAULT_CAT_PATH)))
                return base
            except Exception as e:
                _dbg("[FWD-STRUCT] failed to create placeholder struct %s: %s" % (c, str(e)))

    # 4) Last resort: typedef to char (length 1). This is only safe for truly-unknown scalars.
    try:
        td = TypedefDataType(base_name, _builtin_for_name(dtm, "char") or ByteDataType.dataType)
        try:
            td.setCategoryPath(cat_path or _DEFAULT_CAT_PATH)
        except Exception:
            pass
        _dbg("[FWD-TYPEDEF] created placeholder typedef %s under %s" % (
            base_name, (cat_path or _DEFAULT_CAT_PATH)))
        td = dtm.addDataType(td, DataTypeConflictHandler.KEEP_HANDLER)
        base = _unwrap_typedef(td)
        name_index[base_name] = base
        try:
            name_index[base.getPathName()] = base
        except Exception:
            pass
        return base
    except Exception:
        return _builtin_for_name(dtm, "char") or (ByteDataType.dataType if ByteDataType else None)


def _parse_type_from_cdecl(dtm, name_index, c_decl, cat_path=None):
    """Parse just enough of a C decl to build a DataType.

    Supports:
      - base types by name (including struct typedef names)
      - pointers: * and *32 (size 4)
      - arrays: [N][M]
    """
    s = _norm(c_decl)
    s = s.rstrip(";")

    m = _DECL_RE.match(s)
    if not m:
        return None, None, []

    type_part = m.group("type")
    name = m.group("name")
    arrays = m.group("arrays") or ""

    # Count pointer indirections and whether any are *32
    ptr_tokens = re.findall(r"\*32|\*", type_part)
    is_far32 = any(t == "*32" for t in ptr_tokens)
    ptr_count = len(ptr_tokens)

    base_part = re.sub(r"\*32|\*", " ", type_part)
    base_part = " ".join(base_part.split())

    base_dt = _resolve_base_type(dtm, name_index, base_part, cat_path=cat_path)
    if base_dt is None:
        return None, name, []

    dt = base_dt

    # Apply pointers
    for _ in range(ptr_count):
        if is_far32:
            # Create explicit 4-byte pointer
            try:
                dt = PointerDataType(dt, 4, dtm)
            except Exception:
                # Fallback: at least make it a pointer
                dt = PointerDataType(dt)
        else:
            dt = PointerDataType(dt)

    # Apply arrays (outermost last)
    dims = [int(x) for x in _ARRAY_RE.findall(arrays)]
    for dim in reversed(dims):
        try:
            dt = ArrayDataType(dt, dim, dt.getLength())
        except Exception:
            # If element length unknown, skip array
            break

    return dt, name, dims


def _create_struct_or_union_from_json(dtm, name_index, rec, cat_path):
    name = _norm(rec.get("name"))
    kind = _norm(rec.get("kind"))
    size = rec.get("size")
    if size is None:
        size = 0
    try:
        size = int(size)
    except Exception:
        size = 0

    is_union = (kind == "union")

    if is_union:
        # Populate unions too. If we early-return, any struct embedding this union will
        # see it as a 0/1-byte type and you'll get large undefined gaps (e.g. FLEET's
        # union { DV rgdv[16]; int32_t wtFleet; }).
        dt = UnionDataType(name)
        dt.setCategoryPath(cat_path)
        dt = _safe_add_replace(dtm, dt, DataTypeConflictHandler.REPLACE_HANDLER)
        # Allow forward/self refs to resolve to this union while populating members.
        name_index[name] = dt

        _dbg("[UNION] %s created/replaced size_json=%d ghidra_len=%d" % (dt.getPathName(), size, dt.getLength()))

        fields = rec.get("fields") or []
        for f in fields:
            if not isinstance(f, dict) or _norm(f.get("kind")) != "member":
                continue
            c_decl = _norm(f.get("c_decl"))
            if not c_decl:
                continue

            dt_field, parsed_name, _dims = _parse_type_from_cdecl(dtm, name_index, c_decl, cat_path=cat_path)
            if dt_field is None:
                _dbg("[UNION-MEMBER-SKIP] %s decl='%s' (type parse failed)" % (dt.getPathName(), c_decl))
                continue

            mname = _norm(f.get("name")) or parsed_name or "member_%d" % (dt.getNumComponents() + 1)
            try:
                _dbg("[UNION-MEMBER] %s %s len=%d decl='%s'" % (dt.getPathName(), mname, int(dt_field.getLength()), c_decl))
                dt.add(dt_field, int(dt_field.getLength()), mname, None)
            except Exception as e:
                _dbg("[UNION-MEMBER-FAIL] %s %s err=%s" % (dt.getPathName(), mname, e))
                raise

        # If NB09 provided an explicit union size, ensure the union is at least that
        # large by padding with undefined bytes (Ghidra unions are max(member sizes)).
        if size > 0:
            try:
                cur = int(dt.getLength())
            except Exception:
                cur = 0
            if cur < size:
                try:
                    pad = ArrayDataType(Undefined1DataType.dataType, size - cur, 1)
                    dt.add(pad, int(pad.getLength()), "_pad", None)
                except Exception:
                    pass

        return dt
    # Structures: do NOT allow 0-length, or replaceAtOffset will throw in some builds.
    dt = StructureDataType(name, max(size, 1))
    dt.setCategoryPath(cat_path)
    dt = _safe_add_replace(dtm, dt, DataTypeConflictHandler.REPLACE_HANDLER)

    # Win16 structs are frequently packed (alignment 1 or 2) and many are NOT
    # rounded up to 4-byte multiples. Force packing to avoid Ghidra's end-padding.
    _set_struct_packing(dt, pack_value=1, min_align=1)

    # IMPORTANT: add to name_index immediately so self-referential fields like
    #   struct HB { HB*32 lphbNext; }
    # resolve to /stars/HB (this structure) instead of triggering a placeholder typedef.
    name_index[name] = dt

    _dbg("[STRUCT] %s created/replaced size_json=%d ghidra_len=%d" % (dt.getPathName(), size, dt.getLength()))

    # Ensure target size now (some bindings still keep 0 despite constructor)
    _ensure_len(dt, max(size, 1))

    fields = rec.get("fields") or []
    # Process in offset order to avoid back-filling issues.
    #
    # IMPORTANT: NB09 represents anonymous unions by emitting multiple "member" entries
    # that share the same offset. If we naively place them in sequence, the later entry
    # will delete/overwrite the earlier one, often leaving the smaller alternative plus a
    # tail of undefined1 fillers (e.g. FLEET: union { DV rgdv[16]; int32_t wtFleet; }).
    #
    # Strategy: group members by offset; for each offset, place the *widest* successfully
    # parsed member (this produces the correct packed layout with no undefined gaps).
    # We still keep bitfield containers as a special case.
    members_by_off = {}
    placed_bitfield_offsets = set()  # offsets where we've already placed a flag container
    for f in fields:
        if not isinstance(f, dict) or _norm(f.get('kind')) != 'member':
            continue
        try:
            off = int(f.get('offset'))
        except Exception:
            continue
        members_by_off.setdefault(off, []).append(f)

    for off in sorted(members_by_off.keys()):
        cand_fields = members_by_off.get(off) or []

        # If any candidate is a bitfield member, emit a single container and skip the rest.
        has_bitfield = False
        for cf in cand_fields:
            if isinstance(cf, dict) and cf.get('bitlen') is not None:
                has_bitfield = True
                break
        if has_bitfield:
            if off in placed_bitfield_offsets:
                continue
            placed_bitfield_offsets.add(off)
            # Use 1-based word index for naming: +0 -> flags1, +2 -> flags2, etc.
            fname = "flags%d" % (off // 2 + 1)
            dt_field = _builtin_for_name(dtm, "uint16_t") or _builtin_for_name(dtm, "int16_t")
            if dt_field is None:
                continue
            flen = int(dt_field.getLength())
            _dbg("[FIELD] %s +0x%x len=%d decl='<bitfield-container>'" % (dt.getPathName(), off, flen))
            _ensure_len(dt, off + flen)
            _delete_overlaps(dt, off, flen)
            _ensure_len(dt, off + flen)
            dt.replaceAtOffset(off, dt_field, flen, fname, None)
            continue

        # Non-bitfield: choose the widest parsed candidate at this offset.
        best = None  # (flen, dt_field, fname, c_decl)
        for f in cand_fields:
            c_decl = _norm(f.get('c_decl'))
            if not c_decl:
                continue
            dt_try, parsed_name, _dims = _parse_type_from_cdecl(dtm, name_index, c_decl, cat_path=cat_path)
            if dt_try is None:
                continue
            try:
                flen = int(dt_try.getLength())
            except Exception:
                continue
            if flen <= 0:
                continue
            fname_try = _norm(f.get('name')) or parsed_name or ("field_%x" % off)
            if best is None or flen > best[0]:
                best = (flen, dt_try, fname_try, c_decl)

        if best is None:
            continue

        flen, dt_field, fname, c_decl = best

        # Note: union-like overlaps are resolved by choosing the widest member above.

        _dbg("[FIELD] %s +0x%x len=%d decl='%s'" % (dt.getPathName(), off, flen, c_decl))
        _dbg("[FIELD]   before: ghidra_len=%d" % dt.getLength())

        # Ensure struct is big enough BEFORE replace
        _ensure_len(dt, off + flen)
        _dbg("[FIELD]   after ensure: ghidra_len=%d" % dt.getLength())

        # Clear overlaps then place field
        _delete_overlaps(dt, off, flen)
        # Deleting defined components can shrink the structure; ensure again.
        _ensure_len(dt, off + flen)

        try:
            dt.replaceAtOffset(off, dt_field, flen, fname, None)
            _dbg("[FIELD]   placed ok; ghidra_len=%d" % dt.getLength())
        except Exception as e:
            _dbg("[FIELD-FAIL] %s +0x%x len=%d err=%s" % (dt.getPathName(), off, flen, e))
            # One more try: ensure+clear and retry
            _ensure_len(dt, off + flen)
            _delete_overlaps(dt, off, flen)
            try:
                dt.replaceAtOffset(off, dt_field, flen, fname, None)
                _dbg("[FIELD]   placed ok after retry; ghidra_len=%d" % dt.getLength())
            except Exception as e2:
                _dbg("[FIELD-FAIL2] %s +0x%x len=%d err=%s" % (dt.getPathName(), off, flen, e2))
                _dump_struct(dt)
                raise

    # Finally force to NB09 size (grow OR shrink). This is critical for structs
    # that would otherwise be rounded up to the structure alignment (e.g. 26 -> 28).
    if size > 0:
        _force_struct_len(dt, size)

    return dt


def main():
    # currentProgram and UI helpers are provided by Ghidra at runtime.
    dtm = currentProgram.getDataTypeManager()
    name_index = _index_datatypes(dtm)

    f = askFile("Select nb09_structmeta.json", "Open")
    path = f.getAbsolutePath()

    with open(path, "r") as fp:
        data = json.load(fp)

    # JSON can be either list or dict with key "structs"/"types"
    if isinstance(data, dict):
        recs = data.get("structs") or data.get("types") or []
    else:
        recs = data


    # Pre-index declared sizes so forward references (e.g. POINT before definition) can create
    # correctly-sized placeholder structs instead of 1-byte typedefs.
    global _SIZE_BY_NAME
    _SIZE_BY_NAME = {}
    try:
        for r in recs:
            if not isinstance(r, dict):
                continue
            k = _norm(r.get("kind"))
            if k not in ("struct", "union"):
                continue
            n = _norm(r.get("name"))
            if not n:
                continue
            sz = r.get("size")
            if sz is None:
                continue
            try:
                _SIZE_BY_NAME[n] = int(sz)
            except Exception:
                pass
    except Exception as e:
        _dbg("[WARN] size preindex failed: %s" % str(e))

    cat_path = CategoryPath("/stars")

    created = 0
    for rec in recs:
        if not isinstance(rec, dict):
            continue
        kind = _norm(rec.get("kind"))
        if kind not in ("struct", "union"):
            continue
        nm = _norm(rec.get("name"))
        if not nm:
            continue

        if nm in _EXCLUDE_STRUCTS:
            _dbg("[EXCLUDE] %s is excluded" % nm)
            continue

        if nm in name_index:
            _dbg("[EXISTS] %s already in DataTypeManager; will replace" % nm)

        dt = _create_struct_or_union_from_json(dtm, name_index, rec, cat_path)
        if dt is not None:
            created += 1
            println("[CREATED] %s (%s)" % (nm, kind))
            # refresh index so later types can resolve
            name_index[nm] = dt

    println("ApplyNb09StructPackingFromJson.py> Created: %d" % created)


main()