#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
from typing import Any, Dict, Optional

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


def _load_struct_overrides(path: Optional[Path]) -> Dict[str, Dict[str, Any]]:
    """Load struct member overrides.

    File format (minimal):
        {
          "XFER": { "grobj": "GrobjClass" }
        }

    Keys may also be the raw CodeView tag name (e.g. "_xfer") or the numeric
    typind as a string (e.g. "4910").

    Values may be:
      - string: C type name (used to build c_decl as '<type> <member>')
      - object: {"c_type": "..."} (future extensibility)
    """
    if path is None:
        return {}
    if not path.exists():
        raise SystemExit("struct overrides file not found: %s" % path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        raise SystemExit("failed to parse struct overrides json: %s: %s" % (path, e))
    if not isinstance(data, dict):
        raise SystemExit("struct overrides must be a JSON object at top-level: %s" % path)

    out: Dict[str, Dict[str, Any]] = {}
    for sk, sv in data.items():
        if not isinstance(sv, dict):
            raise SystemExit("override for struct '%s' must be an object of member->type" % sk)
        out[str(sk)] = sv
    return out


def _find_overrides_for_struct(
    overrides: Dict[str, Dict[str, Any]], *, typind: int, raw_name: str, alias_name: str
) -> Optional[Dict[str, Any]]:
    # Prefer explicit typind key, then alias, then raw.
    k1 = str(int(typind))
    if k1 in overrides and isinstance(overrides.get(k1), dict):
        return overrides[k1]
    if alias_name in overrides and isinstance(overrides.get(alias_name), dict):
        return overrides[alias_name]
    if raw_name in overrides and isinstance(overrides.get(raw_name), dict):
        return overrides[raw_name]
    return None


def _override_member_type(members_overrides: Optional[Dict[str, Any]], member_name: str) -> Optional[str]:
    if not members_overrides or not member_name:
        return None
    if member_name not in members_overrides:
        return None
    ov = members_overrides.get(member_name)
    if isinstance(ov, str):
        ov = ov.strip()
        return ov if ov else None
    if isinstance(ov, dict):
        ct = ov.get("c_type")
        if isinstance(ct, str):
            ct = ct.strip()
            return ct if ct else None
    return None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("nb09_bin", type=Path)
    ap.add_argument("-o", "--out", type=Path, default=Path("nb09_structmeta.json"))
    ap.add_argument("--include-anonymous", action="store_true")
    ap.add_argument(
        "--struct-overrides",
        type=Path,
        default=None,
        help="JSON file of struct member type overrides (similar to dump_nb09_ghidra.py)",
    )
    args = ap.parse_args()

    overrides = _load_struct_overrides(args.struct_overrides)

    db = load_nb09(str(args.nb09_bin))
    tt = db.global_types
    if tt is None:
        raise SystemExit("NB09 blob has no global type table (global_types is None)")

    out: Dict[str, Any] = {
        "structs": [],
    }

    # Iterate all LF_* records; pick structs/unions.
    for typind, trec in tt.records.items():
        kind = trec.kind
        if kind not in ("struct", "union"):
            continue

        raw_name = _clean_name(trec.data.get("name", ""))
        if not raw_name and not args.include_anonymous:
            continue

        alias_name = typedef_alias(raw_name)
        size = int(trec.data.get("size") or 0)

        members_overrides = _find_overrides_for_struct(
            overrides, typind=int(typind), raw_name=raw_name, alias_name=alias_name
        )

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
            f_name = _clean_name(f.get("name", ""))
            f_off = int(f.get("offset") or 0)
            f_typind = f.get("type")

            bitlen = None
            bitpos = None
            base_typind = None
            c_decl = None
            c_type = None

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

                    if hasattr(rt, "to_c"):
                        c_type = rt.to_c()
            except Exception:
                c_decl = None
                c_type = None

            # Apply member override (only makes sense for actual named members).
            ov_type = _override_member_type(members_overrides, f_name)
            if ov_type:
                c_type = ov_type
                if f_kind == "member" and f_name:
                    c_decl = "%s %s" % (ov_type, f_name)
                else:
                    c_decl = ov_type

            f_out.append(
                {
                    "kind": f_kind,
                    "name": f_name,
                    "offset": f_off,
                    "typind": int(f_typind) if isinstance(f_typind, int) else None,
                    "bitlen": bitlen,
                    "bitpos": bitpos,
                    "base_typind": int(base_typind) if isinstance(base_typind, int) else None,
                    "c_type": c_type,
                    "c_decl": c_decl,
                    "override_c_type": ov_type,
                }
            )

        out["structs"].append(
            {
                "typind": int(typind),
                "kind": kind,
                "name": alias_name,
                "raw_name": raw_name,
                "size": size,
                "fieldlist": int(fieldlist_tid) if isinstance(fieldlist_tid, int) else None,
                "fields": f_out,
            }
        )

    out["structs"].sort(key=lambda s: ((s.get("name") or ""), s["typind"]))

    args.out.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print("Wrote %s structs/unions to %s" % (len(out["structs"]), args.out))


if __name__ == "__main__":
    main()
