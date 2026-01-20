# -*- coding: utf-8 -*-
# ApplyNb09GlobalsFromJson.py
# @category Stars

import re
from dataclasses import dataclass
from typing import Literal, TypeAlias

# make IDE register built ins
try:
    from ghidra.ghidra_builtins import *
    from ghidra.program.model.listing import *

    currentProgram = currentProgram  # type: Program
except:
    pass

from ghidra.program.model.address import Address
from ghidra.program.model.data import (
    DataTypeManager,
    DataType,
    DataUtilities,
)


from ghidra_utils import (
    datatype_from_c_decl,
    load_nb09_ghidra_globals,
    sanitize_name,
    dedupe_name,
)


def _force_clear_and_create(listing: Listing, addr: Address, dt: DataType):
    """UI-style overwrite: clear any overlapping code/data, then create dt."""
    dt_len = dt.getLength()
    if dt_len <= 0:
        raise ValueError("datatype length is 0")
    end = addr.add(dt_len - 1)

    # If a conflicting unit starts before addr but overlaps (e.g. a string),
    # we must clear the *entire* containing units.
    try:
        cu0 = listing.getCodeUnitContaining(addr)
        clr_start = cu0.getMinAddress() if cu0 is not None else addr
    except Exception:
        clr_start = addr
    try:
        cu1 = listing.getCodeUnitContaining(end)
        clr_end = cu1.getMaxAddress() if cu1 is not None else end
    except Exception:
        clr_end = end

    try:
        listing.clearCodeUnits(clr_start, clr_end, False)
    except Exception:
        # Fallback to the minimal range
        listing.clearCodeUnits(addr, end, False)

    DataUtilities.createData(
        currentProgram,
        addr,
        dt,
        -1,
        False,
        DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA,
    )


def main():
    print("---- ApplyNb09GlobalsFromJson ----")

    json_file = askFile("Select nb09_ghidra_globals.json", "Open")
    path = json_file.getAbsolutePath()

    root = load_nb09_ghidra_globals(path)

    globals = root.globals
    if not globals:
        popup("No globals found in JSON: %s" % path)
        return

    symtab = currentProgram.getSymbolTable()
    listing = currentProgram.getListing()
    dtm = currentProgram.getDataTypeManager()

    typed = 0
    type_ok = 0
    type_failed = 0

    for rec in globals:
        name = rec.name
        gh = rec.ghidra
        addr_str = gh.addr
        default_label = gh.default_label

        if not addr_str:
            print("[TYPE-FAIL] %s: missing ghidra.addr" % name)
            type_failed += 1
            continue

        try:
            addr: Address = toAddr(addr_str)
        except Exception as e:
            print("[TYPE-FAIL] %s @ %s: bad addr (%s)" % (name, addr_str, str(e)))
            type_failed += 1
            continue

        # ----- Label -----
        sym = symtab.getPrimarySymbol(addr)
        desired = sanitize_name(name, default_label)
        desired = dedupe_name(symtab, desired, addr)

        if sym is None:
            print("[LABEL-FAIL] %s @ %s: no existing symbol" % (desired, addr_str))
            continue

        # ----- Type -----
        dt, decl_info, err = datatype_from_c_decl(
            dtm, rec.name, rec.types.c_decl, rec.types.is_far_ptr
        )
        if dt is None:
            if err and "zero-length array" in str(err):
                print("[TYPE-SKIP] %s @ %s: %s" % (name, addr_str, err))
            elif err and "datatype length is 0" in str(err):
                print("[TYPE-SKIP] %s @ %s: datatype length is 0" % (name, addr_str))
            else:
                print("[TYPE-FAIL] %s @ %s: %s" % (name, addr_str, err))
                type_failed += 1
            continue

        try:
            d = listing.getDataAt(addr)
            if d is None:
                print("[TYPE-SKIP] %s @ %s: no data" % (name, addr_str))
                continue

            cur_dt = d.getDataType()
            if cur_dt.getName() == dt.getName():
                print("[TYPE-OK]   %s @ %s (%s)" % (name, addr_str, dt.getName()))
                type_ok += 1
            else:
                _force_clear_and_create(listing, addr, dt)
                if cur_dt is not None:
                    print(
                        "[TYPE-SET]  %s @ %s := %s (was %s)"
                        % (name, addr_str, dt.getName(), cur_dt.getName())
                    )
                else:
                    print("[TYPE-SET]  %s @ %s := %s" % (name, addr_str, dt.getName()))
                typed += 1
        except Exception as e:
            msg = str(e)
            if "datatype length is 0" in msg:
                print("[TYPE-SKIP] %s @ %s: datatype length is 0" % (name, addr_str))
            else:
                print("[TYPE-FAIL] %s @ %s: apply failed (%s)" % (name, addr_str, msg))
                type_failed += 1

    print("---- ApplyNb09GlobalsFromJson summary ----")
    print("Globals processed : %d" % len(globals))
    print("Types set         : %d" % typed)
    print("Types already ok  : %d" % type_ok)
    print("Types failed      : %d" % type_failed)
    print("----------------------------------------")


if __name__ == "__main__":
    main()
