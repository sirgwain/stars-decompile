#!/usr/bin/env python3
import json
import argparse
from pathlib import Path

# Canonical loader that returns an nb09_model.Nb09Db instance.
from nb09_parser import load_nb09

def typedef_alias(tag: str) -> str:
    """Create a prettier typedef name for common Win16 conventions.

    Examples:
        _btn    -> BTN
        tagRECT -> RECT
    """
    if not tag:
        return tag
    if tag.startswith("_") and len(tag) > 1:
        return tag[1:].upper()
    if tag.startswith("tag") and len(tag) > 3 and tag[3].isalpha():
        return tag[3:]
    return tag

def _clean_name(s: str) -> str:
    return (s or "").strip()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("nb09_bin", type=Path)
    ap.add_argument("-o", "--out", type=Path, default=Path("nb09_structmeta.json"))
    ap.add_argument("--include-anonymous", action="store_true")
    args = ap.parse_args()

    db = load_nb09(str(args.nb09_bin))
    tt = db.global_types
    if tt is None:
        raise SystemExit("NB09 blob has no global type table (global_types is None)")

    out = {
        "source": str(args.nb09_bin),
        "structs": []
    }

    # Iterate all LF_* records; pick structs/unions.
    for typind, trec in tt.records.items():
        kind = trec.kind
        if kind not in ("struct", "union"):
            continue

        name = _clean_name(trec.data.get("name", ""))
        if not name and not args.include_anonymous:
            continue

        size = int(trec.data.get("size") or 0)

        # Fields live in a referenced LF_FIELDLIST record.
        fieldlist_tid = trec.data.get("fieldlist")
        fields = []
        if isinstance(fieldlist_tid, int):
            fl = tt.get(fieldlist_tid)
            if fl and fl.kind == "fieldlist":
                fields = fl.data.get("fields", []) or []

        f_out = []
        for f in fields:
            # Fieldlist entries are dicts like:
            #   {kind:'member', type:<typind>, offset:<n>, name:'x', ...}
            f_kind = f.get("kind")
            if f_kind not in ("member", "enumerate", "method", "nestedtype", "stmember"):
                # Still export unknown kinds for visibility.
                pass

            f_name = _clean_name(f.get("name", ""))
            f_off = int(f.get("offset") or 0)
            f_typind = f.get("type")

            bitlen = None
            bitpos = None
            base_typind = None
            c_decl = None
            try:
                if isinstance(f_typind, int):
                    rt = db.resolve_typind(int(f_typind))
                    if getattr(rt, "kind", None) == "bitfield":
                        bitlen = int(getattr(rt, "length", 0) or 0)
                        bitpos = int(getattr(rt, "position", 0) or 0)
                        base = getattr(rt, "base", None)
                        base_typind = getattr(base, "_typind", None)
                    if hasattr(rt, "c_decl"):
                        c_decl = rt.c_decl(f_name if f_name else "field")
                    elif hasattr(rt, "to_c"):
                        c_decl = rt.to_c()
            except Exception:
                c_decl = None

            f_out.append({
                "kind": f_kind,
                "name": f_name,
                "offset": f_off,
                "typind": int(f_typind) if isinstance(f_typind, int) else None,
                "bitlen": bitlen,
                "bitpos": bitpos,
                "c_decl": c_decl,
            })

        out["structs"].append({
            "typind": int(typind),
            "kind": kind,
            "name": typedef_alias(name),
            "size": size,
            "fieldlist": int(fieldlist_tid) if isinstance(fieldlist_tid, int) else None,
            "fields": f_out,
        })

    out["structs"].sort(key=lambda s: (s["name"] or "", s["typind"]))

    args.out.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print("Wrote %s structs/unions to %s" % (len(out["structs"]), args.out))

if __name__ == "__main__":
    main()
