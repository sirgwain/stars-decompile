#!/usr/bin/env python3
"""
Generate C _Static_assert layout checks from nb09_structmeta.json.

- Emits sizeof(TYPE) == expected_size for each struct.
- Emits offsetof(TYPE, member) == expected_offset for each non-bitfield member.
- Skips bitfields (bitlen != null) because offsetof() is invalid for bitfields.

Usage:
  python3 scripts/gen_struct_layout_asserts.py nb09_structmeta.json -o src/struct_layout_asserts.h

Then include the generated header somewhere in your build, e.g.:
  #ifdef STARS_LAYOUT_CHECKS
  #include "struct_layout_asserts.h"
  #endif
"""

from __future__ import annotations

import argparse
import json
from typing import Any, Dict, List, Optional


def is_bitfield(field: Dict[str, Any]) -> bool:
    return field.get("bitlen") is not None


def c_ident(s: str) -> str:
    # Types/names in your meta are already C-ish; keep minimal sanitization.
    # If you have anonymous or weird names, you can extend this.
    return s


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("structmeta_json", help="Path to nb09_structmeta.json")
    ap.add_argument("-o", "--out", required=True, help="Output header path")
    ap.add_argument(
        "--guard",
        default="STARS_LAYOUT_CHECKS",
        help="Preprocessor guard macro for asserts (default: STARS_LAYOUT_CHECKS)",
    )
    ap.add_argument(
        "--only",
        action="append",
        default=[],
        help="Only emit asserts for these struct names (repeatable). Example: --only PLAYER --only PLANET",
    )
    args = ap.parse_args()

    with open(args.structmeta_json, "r", encoding="utf-8") as f:
        meta = json.load(f)

    structs: List[Dict[str, Any]] = meta.get("types", [])
    only_set = set(args.only) if args.only else None

    lines: List[str] = []
    lines.append("/* AUTO-GENERATED. DO NOT EDIT. */")
    lines.append("/* Generated from nb09_structmeta.json */")
    lines.append("")
    lines.append("#pragma once")
    lines.append("")
    lines.append("#include <stddef.h> /* offsetof */")
    lines.append("")
    lines.append(f"#ifdef {args.guard}")
    lines.append("")
    lines.append("/*")
    lines.append(" * NOTE: Bitfields are skipped because offsetof(TYPE, bitfield) is illegal in C.")
    lines.append(" * If you need to validate bitfield containers, assert the offset of the underlying")
    lines.append(" * raw member (e.g., wFlags, wMdPlr) instead.")
    lines.append(" */")
    lines.append("")

    emitted_any = False

    # Sort by name for stable diffs
    for t in sorted(structs, key=lambda x: (x.get("name") or "", x.get("typind") or 0)):
        if t.get("kind") != "struct":
            continue
        name = t.get("name")
        if not name:
            continue
        if only_set is not None and name not in only_set:
            continue

        size = t.get("size")
        fields = t.get("fields", [])

        # Some structs might be placeholders without size/fields; skip if incomplete.
        if size is None:
            continue

        emitted_any = True
        lines.append(f"/* {name} (typind {t.get('typind')}) */")
        lines.append(f"_Static_assert(sizeof({c_ident(name)}) == {int(size)}, \"sizeof({name}) mismatch\");")

        # Emit member offset asserts for non-bitfields
        for fld in fields:
            if fld.get("kind") != "member":
                continue
            member = fld.get("name")
            off = fld.get("offset")
            if member is None or off is None:
                continue
            if is_bitfield(fld):
                continue

            # Avoid nonsense members that aren't real C identifiers
            # (Rare, but could happen if raw debug name is weird.)
            member_c = c_ident(member)

            lines.append(
                f"_Static_assert(offsetof({c_ident(name)}, {member_c}) == {int(off)}, "
                f"\"offsetof({name}, {member}) mismatch\");"
            )

        lines.append("")

    lines.append(f"#endif /* {args.guard} */")
    lines.append("")

    if not emitted_any:
        raise SystemExit("No structs emitted. Check input JSON or --only filters.")

    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())