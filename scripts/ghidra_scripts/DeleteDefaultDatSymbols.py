# @category Stars

"""
Delete analyzer-created default DAT_* labels.

This targets symbols named like:
  DAT_1234_5678
  DAT_0000_57a4
  DAT_1120_57a4
and only deletes those whose SourceType is DEFAULT (i.e., auto-created placeholders).

Headless args (optional):
  --dry-run
  --regex=<python-regex>
  --delete-data    (also clears DEFAULT data at the same address; off by default)

Notes:
- This does NOT touch user/IMPORTED labels.
- Keep this script simple on purpose (no blanket try/except).
"""

import re
from ghidra.program.model.symbol import SourceType, Symbol
from ghidra.program.model.address import Address
from ghidra.program.model.listing import Listing
from ghidra.app.cmd.label import DeleteLabelCmd

# make IDE register built ins
try:
    from ghidra.ghidra_builtins import *
    from ghidra.program.model.listing import *
    from ghidra.util.task import *

    currentProgram = currentProgram  # type: Program
except:
    pass


_DEFAULT_REGEX = r"^DAT_[0-9A-Fa-f]{4}(?:_[0-9A-Fa-f]{4})?$"


def _parse_args(argv):
    # type: (list) -> dict
    """
    Very small arg parser for getScriptArgs().

    Returns dict with:
      dry_run: bool
      regex: str
    """
    out = {
        "dry_run": False,
        "regex": _DEFAULT_REGEX,
    }
    for a in argv:
        if a == "--dry-run":
            out["dry_run"] = True
        elif a.startswith("--regex="):
            out["regex"] = a[len("--regex=") :]
    return out


def _is_default_dat_symbol(sym: Symbol, rx):
    # type: (object, object) -> bool
    name = sym.getName()
    if not rx.match(name):
        return False
    if sym.getSource() != SourceType.DEFAULT:
        return False
    return True


def _clear_default_data_at(listing, addr):
    # type: (Listing, Address) -> int
    """
    If the listing has DEFAULT data at addr, clear it.

    Returns number of cleared code units (0 or 1).
    """
    data = listing.getDataAt(addr)
    if data is None:
        return 0

    # Clear exactly the data's address range.
    start = data.getMinAddress()
    end = data.getMaxAddress()
    listing.clearCodeUnits(start, end, False)
    return 1


def run():
    argv = list(getScriptArgs())
    opts = _parse_args(argv)

    rx = re.compile(opts["regex"])

    symtab = currentProgram.getSymbolTable()
    listing = currentProgram.getListing()
    refman = currentProgram.getReferenceManager()

    deleted_syms = 0
    cleared_data = 0

    for sym in symtab.getAllSymbols(True):
        sym = sym  # type: Symbol
        if not _is_default_dat_symbol(sym, rx):
            continue

        addr = sym.getAddress()
        println("match: %s @ %s" % (sym.getName(True), addr))

        if not opts["dry_run"]:

            refman.removeAllReferencesTo(sym.address)
            cleared_data += _clear_default_data_at(listing, addr)
            deleteLabelCmd = DeleteLabelCmd(
                sym.address, sym.name, currentProgram.getGlobalNamespace()
            )
            ok = deleteLabelCmd.applyTo(currentProgram)
            if ok:
                deleted_syms += 1
            else:
                println("ERROR: failed to delete symbol")

    println("")
    println("Done.")
    println("Deleted DAT_* DEFAULT symbols: %d" % deleted_syms)
    if opts["dry_run"]:
        println("(dry run; no changes made)")


run()
