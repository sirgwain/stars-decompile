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

_EXCLUDE_STRUCTS = ["RECT", "POINT"]


def _dbg(msg):
    if not _DEBUG:
        return
    try:
        println(msg)
    except Exception:
        pass


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

    if n in ("int8_t", "uint8_t", "byte"):
        if ByteDataType is not None:
            return ByteDataType.dataType

    if n in ("short", "uint16_t", "word"):
        if ShortDataType is not None:
            return ShortDataType.dataType
    if n in ("int16_t", "uint32_t", "dword"):
        if IntegerDataType is not None:
            return IntegerDataType.dataType
    if n in ("int", "long", "int32_t", "uint32_t", "longlong"):
        if LongDataType is not None:
            return LongDataType.dataType
    if n in ("void",):
        # Ghidra doesn't like plain void as a field; treat as byte.
        if ByteDataType is not None:
            return ByteDataType.dataType

    return None

_DEFAULT_CAT_PATH = CategoryPath("/stars")


def _resolve_base_type(dtm, name_index, base_name, cat_path=None):
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

    for c in cand:
        dt = name_index.get(c)
        if dt is not None:
            return dt

    # As a last resort, create an empty typedef so fields can at least be placed.
    # IMPORTANT: place it under the same category as our NB09 imports so it will be
    # replaced later (and we don't pollute "/" with conflicting names like "/HB").
    try:
        td = TypedefDataType(base_name, _builtin_for_name(dtm, "char") or ByteDataType.dataType)
        try:
            td.setCategoryPath(cat_path or _DEFAULT_CAT_PATH)
        except Exception:
            pass
        _dbg("[FWD-TYPEDEF] created placeholder typedef %s under %s" % (
            base_name, (cat_path or _DEFAULT_CAT_PATH)))
        return dtm.addDataType(td, DataTypeConflictHandler.KEEP_HANDLER)
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
        dt = UnionDataType(name)
        dt.setCategoryPath(cat_path)
        dt = dtm.addDataType(dt, DataTypeConflictHandler.REPLACE_HANDLER)
        # Allow self-references / forward refs to resolve to this union while populating members.
        name_index[name] = dt
        return dt

    # Structures: do NOT allow 0-length, or replaceAtOffset will throw in some builds.
    dt = StructureDataType(name, max(size, 1))
    dt.setCategoryPath(cat_path)
    dt = dtm.addDataType(dt, DataTypeConflictHandler.REPLACE_HANDLER)

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
    members = []
    placed_bitfield_offsets = set()  # offsets where we've already placed a flag container
    for f in fields:
        try:
            if isinstance(f, dict) and _norm(f.get('kind')) == 'member':
                members.append((int(f.get('offset')), f))
        except Exception:
            continue
    members.sort(key=lambda t: t[0])

    for off, f in members:
        if not isinstance(f, dict):
            continue
        if _norm(f.get("kind")) != "member":
            continue

        c_decl = _norm(f.get("c_decl"))
        if not c_decl:
            continue

        # off already parsed/sorted above

        dt_field, parsed_name, _dims = _parse_type_from_cdecl(dtm, name_index, c_decl, cat_path=cat_path)
        if dt_field is None:
            continue

        fname = _norm(f.get("name")) or parsed_name or "field_%x" % off

        # Bitfields: we don't model individual bits here. We only create a single
        # container field per 16-bit word and give it a stable name (flags1, flags2, ...).
        bitlen = f.get("bitlen")
        bitpos = f.get("bitpos")
        if bitlen is not None:
            # Many bitfield members share the same underlying word. Once we've placed the
            # container for this offset, skip subsequent bitfields at the same offset.
            if off in placed_bitfield_offsets:
                _dbg("[BITFIELD-SKIP] %s +0x%x %s (container already placed)" % (
                    dt.getPathName(), off, _norm(f.get("name")) or "bitfield"
                ))
                continue
            placed_bitfield_offsets.add(off)

            # Use 1-based word index for naming: +0 -> flags1, +2 -> flags2, etc.
            fname = "flags%d" % (off // 2 + 1)

        flen = 0
        try:
            flen = int(dt_field.getLength())
        except Exception:
            flen = 0

        if flen <= 0:
            continue

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
