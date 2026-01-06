#!/usr/bin/env python3
"""
parse_nb09_cli.py — CLI wrapper around nb09_parser.load_nb09.

This keeps command-line / JSON dumping out of the library module so other scripts can import
nb09_parser without side effects.
"""
from __future__ import annotations

import argparse
import json
from nb09_parser import load_nb09


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Parse CodeView NB09 blob into JSON.")
    ap.add_argument("nb09_bin", help="Path to extracted .codeview.nb09.bin")
    ap.add_argument("out_json", nargs="?", default="-", help="Output JSON path or '-' for stdout")
    args = ap.parse_args(argv)

    db = load_nb09(args.nb09_bin)
    js = json.dumps(db.to_dict(), indent=2, sort_keys=False)

    if args.out_json == "-" or args.out_json.lower() == "stdout":
        print(js)
    else:
        with open(args.out_json, "w", encoding="utf-8") as f:
            f.write(js)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
