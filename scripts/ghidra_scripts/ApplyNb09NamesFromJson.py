# ApplyNb09NamesFromJson.py
# @category Stars

import re

# make IDE register built ins
try:
    from ghidra.ghidra_builtins import *
    from ghidra.program.model.listing import *

    currentProgram = currentProgram  # type: Program
except:
    pass

from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.program.model.symbol import SourceType, Symbol, SymbolTable, Namespace
from ghidra.program.model.address import Address

from ghidra_utils import Entry, load_nb09_ghidra_globals, sanitize_name
from typing import Literal


def _strip_memory_prefix(segname: str) -> str:
    # all the segment maps start with MEMORY_*, strip it out
    if not segname:
        return segname
    return segname[len("MEMORY_") :] if segname.startswith("MEMORY_") else segname


def _get_or_create_namespace(symtab: SymbolTable, name: str) -> Namespace | None:
    if not name:
        return None

    gns = currentProgram.getGlobalNamespace()
    name = sanitize_name(name, "NS")
    ns = symtab.getNamespace(name, gns)
    if ns is not None:
        return ns

    # Create
    try:
        ns = symtab.createNameSpace(gns, name, SourceType.USER_DEFINED)
        return ns
    except Exception as e:
        print("[NS-FAIL] could not create namespace '%s': %s" % (name, str(e)))

    return None


def _set_symbol_namespace(sym: Symbol, ns: Namespace):
    if sym is None or ns is None:
        return
    try:
        sym.setNamespace(ns)
    except Exception as e:
        # Not fatal.
        try:
            nm = sym.getName()
        except Exception:
            nm = "<sym>"
        print("[NS-WARN] %s: %s" % (nm, str(e)))


def _pick_namespace_name(rec: Entry) -> str:
    cv = rec.cv
    segmap = rec.segmap

    if cv.from_ == "PUBLIC":
        return "PUBLIC"

    if segmap:
        return _strip_memory_prefix(segmap.segname)

    return cv.from_


def _is_default_name(name: str) -> bool:
    return name.startswith("FUN_") or name.startswith("LAB_") or name.startswith("DAT_")


def _should_rename(existing: str, default_label: str):
    if default_label and existing == default_label:
        return True
    return not existing or _is_default_name(existing)


def _dedupe_tree_name(existing_set, base):
    if base not in existing_set:
        existing_set.add(base)
        return base
    i = 2
    while True:
        cand = "%s_%d" % (base, i)
        if cand not in existing_set:
            existing_set.add(cand)
            return cand
        i += 1


def _rename_program_tree_segments(frame_to_name: dict[int, str]):
    # Rename Program Tree fragments like Code11/Data18 to segment names.
    root: ProgramModule = currentProgram.getListing().getDefaultRootModule()

    existing = set()
    for g in root.getChildren():
        g = g  # type: Group
        try:
            existing.add(g.getName())
        except Exception:
            pass

    for g in root.getChildren():
        g = g  # type: Group
        name = g.getName()

        m = re.match(r"^(Code|CODE|Data|DATA)(\d+)$", name)
        if not m:
            continue

        try:
            frame = int(m.group(2))
        except Exception:
            continue

        new_base = frame_to_name.get(frame)
        if not new_base:
            continue

        new_base = sanitize_name(_strip_memory_prefix(new_base), name)
        if new_base == name:
            continue

        new_name = _dedupe_tree_name(existing, new_base)
        try:
            g.setName(new_name)
            print("[TREE-RENAME] %s -> %s" % (name, new_name))
        except Exception as e:
            print("[TREE-FAIL]   %s -> %s: %s" % (name, new_name, str(e)))


def _name_is_used_elsewhere(symtab: SymbolTable, nm: str, addr: Address):
    # return True if this name is used in the symbol table at a different address
    for s in symtab.getSymbols(nm):
        s = s  # type: Symbol
        if s.getAddress() != addr:
            return True
    return False


def _dedupe_name(symtab: SymbolTable, desired: str, addr: Address):
    # append _2, _3, etc to a name if it's used elsewhere
    if not _name_is_used_elsewhere(symtab, desired, addr):
        return desired
    i = 2
    while True:
        cand = "%s_%d" % (desired, i)
        if not _name_is_used_elsewhere(symtab, cand, addr):
            return cand
        i += 1


def _ensure_code_at(addr, addr_str):
    cmd = DisassembleCommand(addr, None, True)
    ok = cmd.applyTo(currentProgram, monitor)
    if not ok:
        print("[DISASM-FAIL] %s" % addr_str)
    return ok


def _ensure_function_at(
    fm: FunctionManager, addr: Address, addr_str: str, desired_name: str
):
    f = fm.getFunctionAt(addr)
    if f is not None:
        return f, False

    print("[FUN-MISS]    %s @ %s (creating function)" % (desired_name, addr_str))
    _ensure_code_at(addr, addr_str)

    try:
        cmd = CreateFunctionCmd(addr, True)
        ok = cmd.applyTo(currentProgram, monitor)
        f = fm.getFunctionAt(addr)
        if ok and f is not None:
            print("[FUN-CREATE] %s @ %s" % (desired_name, addr_str))
            return f, True

        # Try to extract any status message (varies by build)
        msg = None
        try:
            if hasattr(cmd, "getStatusMsg"):
                msg = cmd.getStatusMsg()
        except Exception:
            msg = None

        if msg:
            print("[FUN-CREATEFAIL] %s @ %s (%s)" % (desired_name, addr_str, msg))
        else:
            print("[FUN-CREATEFAIL] %s @ %s" % (desired_name, addr_str))
        return None, False

    except Exception as e:
        print("[FUN-CREATEEXC]  %s @ %s: %s" % (desired_name, addr_str, str(e)))
        return None, False


def _get_or_create_primary_symbol(
    symtab: SymbolTable,
    addr: Address,
    desired: str,
    addr_str: str,
    ns: Namespace,
    *,
    create_if_missing: bool,
    create_msg: str,
    fail_msg: str,
    missing_msg: str | None = None,
) -> tuple[object | None, tuple[int, int, int] | None]:
    """
    Shared 'front half' for renamers:
      - get primary symbol
      - optionally create label if missing
      - if still missing, emit message and return a terminal (created, renamed, skip/fail) tuple

    Returns:
      (sym, terminal_result)
        - If terminal_result is not None, caller should return it immediately.
        - Otherwise sym is non-None and caller can continue with rename logic.
    """
    sym = symtab.getPrimarySymbol(addr)
    if sym is None:
        if not create_if_missing:
            if missing_msg is not None:
                print(missing_msg % (desired, addr_str))
            return (None, (0, 0, 1))

        try:
            sym = symtab.createLabel(addr, desired, ns, SourceType.USER_DEFINED)
            print(create_msg % (desired, addr_str))
            return (sym, (1, 0, 0))
        except Exception as e:
            print(fail_msg % (desired, addr_str, str(e)))
            return (None, (0, 0, 1))

    return (sym, None)


def _rename_label(
    symtab: SymbolTable, addr: Address, desired: str, addr_str: str, ns, force=False
) -> tuple[int, int, int]:
    sym, terminal = _get_or_create_primary_symbol(
        symtab,
        addr,
        desired,
        addr_str,
        ns,
        create_if_missing=True,
        create_msg="[LABEL-CREATE] %s @ %s",
        fail_msg="[LABEL-FAIL]   %s @ %s: %s",
    )
    if terminal is not None:
        return terminal

    cur = sym.getName()
    if cur == desired:
        sym.setNamespace(ns)
        return (0, 0, 1)

    try:
        if force:
            sym.setName(desired, SourceType.USER_DEFINED)
            sym.setNamespace(ns)
            print("[LABEL-RENAME] %s @ %s (was '%s')" % (desired, addr_str, cur))
            return (0, 1, 0)

        # non-force: only rename if looks auto
        if _should_rename(cur, None):
            sym.setName(desired, SourceType.USER_DEFINED)
            sym.setNamespace(ns)
            print("[LABEL-RENAME] %s @ %s (was '%s')" % (desired, addr_str, cur))
            return (0, 1, 0)

    except Exception as e:
        print("[LABEL-FAIL]   %s @ %s: %s" % (desired, addr_str, str(e)))
        return (0, 0, 1)

    sym.setNamespace(ns)
    return (0, 0, 1)


def _rename_global(
    symtab: SymbolTable,
    addr: Address,
    desired: str,
    addr_str: str,
    default_label: str,
    ns: Namespace,
) -> tuple[int, int, int]:
    sym, terminal = _get_or_create_primary_symbol(
        symtab,
        addr,
        desired,
        addr_str,
        ns,
        create_if_missing=True,
        create_msg="[DATA-CREATE]  %s @ %s",
        fail_msg="[DATA-FAIL]    %s @ %s: %s",
    )
    if terminal is not None:
        return terminal

    cur = sym.getName()
    if cur == desired:
        sym.setNamespace(ns)
        return (0, 0, 1)

    if _should_rename(cur, default_label):
        try:
            sym.setName(desired, SourceType.USER_DEFINED)
            sym.setNamespace(ns)
            print("[DATA-RENAME]  %s @ %s (was '%s')" % (desired, addr_str, cur))
            return (0, 1, 0)
        except Exception as e:
            print("[DATA-FAIL]    %s @ %s: %s" % (desired, addr_str, str(e)))
            return (0, 0, 1)

    sym.setNamespace(ns)
    print("[DATA-SKIP]    %s @ %s (existing='%s')" % (desired, addr_str, cur))
    return (0, 0, 1)


def _rename_proc(
    fm: FunctionManager,
    addr: Address,
    desired: str,
    addr_str: str,
    ns,
) -> tuple[int, int, int]:
    f, created = _ensure_function_at(fm, addr, addr_str, desired)

    if f is None:
        print("[FUNC-FAIL]    %s @ %s: no existing function, will create label" % (desired, addr_str))
        _rename_label(currentProgram.symbolTable, addr, desired, addr_str, ns)
        return (0, 0, 1)

    # Rename function
    cur = f.getName()
    if cur == desired:
        try:
            _set_symbol_namespace(f.getSymbol(), ns)
        except Exception:
            pass
        return (1 if created else 0, 0, 1)

    try:
        f.setName(desired, SourceType.USER_DEFINED)
        _set_symbol_namespace(f.getSymbol(), ns)
        print("[FUNC-RENAME]  %s @ %s (was '%s')" % (desired, addr_str, cur))
        return (1 if created else 0, 1, 0)
    except Exception as e:
        print("[FUNC-FAIL]    %s @ %s: %s" % (desired, addr_str, str(e)))
        return (1 if created else 0, 0, 1)


def _process(
    kind: Literal["GLOBAL", "PROC", "LABEL"],
    items: list[Entry],
    symtab: SymbolTable,
    fm: FunctionManager,
    frame_to_name: dict[int, str],
):
    created = renamed = skipped = failed = 0

    for rec in items:
        g = rec.ghidra
        addr_str = g.addr
        if not addr_str:
            continue

        # Skip nameless PROC/LABEL records; these are usually synthetic entries.

        if kind in ("PROC", "LABEL") and (rec.name == ""):
            print("[%s-NONAME-SKIP] @ %s" % (kind, addr_str))
            skipped += 1
            continue

        try:
            addr = toAddr(addr_str)
        except Exception as e:
            print(
                "[%s-FAIL]  %s @ %s: bad addr (%s)" % (kind, rec.name, addr_str, str(e))
            )
            failed += 1
            continue

        # Build segment name mapping for program tree
        try:
            frame = g.frame
            sm = rec.segmap
            segname = sm.segname
            if frame is not None and segname:
                frame_to_name[int(frame)] = _strip_memory_prefix(segname)
        except Exception:
            pass

        ns_name = _pick_namespace_name(rec)
        ns = _get_or_create_namespace(symtab, ns_name) if ns_name else None

        desired = sanitize_name(rec.name, g.default_label)
        desired = _dedupe_name(symtab, desired, addr)

        if kind == "GLOBAL":
            c, r, s = _rename_global(
                symtab, addr, desired, addr_str, g.default_label, ns
            )
        elif kind == "PROC":
            c, r, s = _rename_proc(fm, addr, desired, addr_str, ns)
        elif kind == "LABEL":
            c, r, s = _rename_label(symtab, addr, desired, addr_str, ns, force=True)
        else:
            skipped += 1
            continue

        created += c
        renamed += r
        skipped += s

    return created, renamed, skipped, failed


def main():
    print("---- ApplyNb09NamesFromJson ----")

    json_file = askFile("Select nb09_ghidra_globals.json", "Open")
    path = json_file.getAbsolutePath()

    root = load_nb09_ghidra_globals(path)

    symtab = currentProgram.getSymbolTable()
    fm = currentProgram.getFunctionManager()

    frame_to_name: dict[int, str] = {}

    g_created, g_renamed, g_skipped, g_failed = _process(
        "GLOBAL", root.globals, symtab, fm, frame_to_name
    )
    p_created, p_renamed, p_skipped, p_failed = _process(
        "PROC", root.procs, symtab, fm, frame_to_name
    )
    l_created, l_renamed, l_skipped, l_failed = _process(
        "LABEL", root.labels, symtab, fm, frame_to_name
    )

    if frame_to_name:
        _rename_program_tree_segments(frame_to_name)

    print("---- Summary ----")
    print(
        "Globals: created=%d renamed=%d skipped=%d failed=%d"
        % (g_created, g_renamed, g_skipped, g_failed)
    )
    print(
        "Procs:   created=%d renamed=%d skipped=%d failed=%d"
        % (p_created, p_renamed, p_skipped, p_failed)
    )
    print(
        "Labels:  created=%d renamed=%d skipped=%d failed=%d"
        % (l_created, l_renamed, l_skipped, l_failed)
    )


if __name__ == "__main__":
    main()
