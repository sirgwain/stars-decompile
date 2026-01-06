# ApplyNb09NamesFromJson.py
# @category: Stars.NB09

import json
import re

from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.program.model.symbol import SourceType


def _sanitize_name(name, fallback):
    if name is None:
        name = ""
    name = str(name)
    if not name:
        name = fallback or "SYM"

    out = []
    for c in name:
        if c.isalnum() or c == "_":
            out.append(c)
        else:
            out.append("_")
    s = "".join(out)
    if not s:
        s = fallback or "SYM"
    if s[0].isdigit():
        s = "_" + s
    return s


def _strip_memory_prefix(segname):
    if not segname:
        return segname
    segname = str(segname)
    return segname[len("MEMORY_"):] if segname.startswith("MEMORY_") else segname


def _get_global_namespace(symtab):
    # API varies across Ghidra forks.
    try:
        if hasattr(symtab, "getGlobalNamespace"):
            return symtab.getGlobalNamespace()
    except Exception:
        pass
    try:
        if hasattr(currentProgram, "getGlobalNamespace"):
            return currentProgram.getGlobalNamespace()
    except Exception:
        pass
    return None


def _get_or_create_namespace(symtab, name):
    if not name:
        return None

    gns = _get_global_namespace(symtab)
    if gns is None:
        return None

    name = _sanitize_name(name, "NS")

    # Lookup
    try:
        if hasattr(symtab, "getNamespace"):
            ns = symtab.getNamespace(name, gns)
            if ns is not None:
                return ns
    except Exception:
        pass

    # Create
    try:
        if hasattr(symtab, "createNameSpace"):
            return symtab.createNameSpace(gns, name, SourceType.USER_DEFINED)
    except Exception as e:
        print("[NS-FAIL] could not create namespace '%s': %s" % (name, str(e)))

    return None


def _set_symbol_namespace(sym, ns):
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


def _pick_namespace_name(rec, kind):
    cv = rec.get("cv") or {}
    segmap = rec.get("segmap") or {}

    cv_from = cv.get("from") or ""
    segname = segmap.get("segname") or ""

    if cv_from == "PUBLIC":
        return "PUBLIC"

    if segname:
        return _strip_memory_prefix(segname)

    if cv_from:
        return str(cv_from)

    return None


def _should_rename(existing, default_label, prefix):
    if existing is None:
        return True
    if default_label and existing == default_label:
        return True
    if prefix and existing.startswith(prefix + "_"):
        return True
    return False


def _iter_children(group):
    """Return python-iterable children for Program Tree groups.

    Different forks return:
      * a Java Iterator (hasNext/next)
      * a Java array
      * a Python list
    """
    ch = group.getChildren()
    if hasattr(ch, "hasNext"):
        out = []
        while ch.hasNext():
            out.append(ch.next())
        return out
    # Java arrays / Python lists should be iterable
    try:
        return list(ch)
    except Exception:
        # Last resort
        out = []
        try:
            for x in ch:
                out.append(x)
        except Exception:
            pass
        return out


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


def _rename_program_tree_segments(frame_to_name):
    # Rename Program Tree fragments like Code11/Data18 to segment names.
    try:
        root = currentProgram.getListing().getDefaultRootModule()
    except Exception as e:
        print("[TREE-WARN] cannot access Program Tree root: %s" % str(e))
        return

    children = _iter_children(root)
    existing = set()
    for g in children:
        try:
            existing.add(g.getName())
        except Exception:
            pass

    for g in children:
        try:
            name = g.getName()
        except Exception:
            continue

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

        new_base = _sanitize_name(_strip_memory_prefix(new_base), name)
        if new_base == name:
            continue

        new_name = _dedupe_tree_name(existing, new_base)
        try:
            g.setName(new_name)
            print("[TREE-RENAME] %s -> %s" % (name, new_name))
        except Exception as e:
            print("[TREE-FAIL]   %s -> %s: %s" % (name, new_name, str(e)))


def _name_is_used_elsewhere(symtab, nm, addr):
    try:
        if hasattr(symtab, "getSymbols"):
            syms = symtab.getSymbols(nm)
            it = syms.iterator() if hasattr(syms, "iterator") else syms
            for s in it:
                try:
                    if s.getAddress() != addr:
                        return True
                except Exception:
                    return True
            return False
    except Exception:
        pass
    # If we can't tell, assume used to be safe.
    return True


def _dedupe_name(symtab, desired, addr):
    if not _name_is_used_elsewhere(symtab, desired, addr):
        return desired
    i = 2
    while True:
        cand = "%s_%d" % (desired, i)
        if not _name_is_used_elsewhere(symtab, cand, addr):
            return cand
        i += 1


def _ensure_code_at(addr, addr_str):
    # Try GhidraScript helper first.
    try:
        disassemble(addr)
        return True
    except Exception:
        pass

    try:
        cmd = DisassembleCommand(addr, None, True)
        ok = cmd.applyTo(currentProgram)
        if not ok:
            print("[DISASM-FAIL] %s" % addr_str)
        return ok
    except Exception as e:
        print("[DISASM-EXC]  %s: %s" % (addr_str, str(e)))
        return False


def _ensure_function_at(fm, addr, addr_str, desired_name):
    f = fm.getFunctionAt(addr)
    if f is not None:
        return f, False

    print("[FUNC-MISS]    %s @ %s (creating function)" % (desired_name, addr_str))
    _ensure_code_at(addr, addr_str)

    try:
        cmd = CreateFunctionCmd(addr, True)
        ok = cmd.applyTo(currentProgram)
        f = fm.getFunctionAt(addr)
        if ok and f is not None:
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


def _rename_label(symtab, addr, desired, addr_str, ns, force=False):
    sym = symtab.getPrimarySymbol(addr)
    if sym is None:
        try:
            sym = symtab.createLabel(addr, desired, ns, SourceType.USER_DEFINED)
            print("[LABEL-CREATE] %s @ %s" % (desired, addr_str))
            return (1, 0, 0)
        except Exception as e:
            print("[LABEL-FAIL]   %s @ %s: %s" % (desired, addr_str, str(e)))
            return (0, 0, 1)

    cur = sym.getName()
    if cur == desired:
        _set_symbol_namespace(sym, ns)
        return (0, 0, 1)

    try:
        if force:
            sym.setName(desired, SourceType.USER_DEFINED)
            _set_symbol_namespace(sym, ns)
            print("[LABEL-RENAME] %s @ %s (was '%s')" % (desired, addr_str, cur))
            return (0, 1, 0)

        # non-force: only rename if looks auto
        if _should_rename(cur, None, "LAB"):
            sym.setName(desired, SourceType.USER_DEFINED)
            _set_symbol_namespace(sym, ns)
            print("[LABEL-RENAME] %s @ %s (was '%s')" % (desired, addr_str, cur))
            return (0, 1, 0)

    except Exception as e:
        print("[LABEL-FAIL]   %s @ %s: %s" % (desired, addr_str, str(e)))
        return (0, 0, 1)

    _set_symbol_namespace(sym, ns)
    return (0, 0, 1)


def _rename_global(symtab, addr, desired, addr_str, default_label, ns):
    sym = symtab.getPrimarySymbol(addr)
    if sym is None:
        try:
            sym = symtab.createLabel(addr, desired, ns, SourceType.USER_DEFINED)
            print("[DATA-CREATE]  %s @ %s" % (desired, addr_str))
            return (1, 0, 0)
        except Exception as e:
            print("[DATA-FAIL]    %s @ %s: %s" % (desired, addr_str, str(e)))
            return (0, 0, 1)

    cur = sym.getName()
    if cur == desired:
        _set_symbol_namespace(sym, ns)
        return (0, 0, 1)

    if _should_rename(cur, default_label, "DAT"):
        try:
            sym.setName(desired, SourceType.USER_DEFINED)
            _set_symbol_namespace(sym, ns)
            print("[DATA-RENAME]  %s @ %s (was '%s')" % (desired, addr_str, cur))
            return (0, 1, 0)
        except Exception as e:
            print("[DATA-FAIL]    %s @ %s: %s" % (desired, addr_str, str(e)))
            return (0, 0, 1)

    _set_symbol_namespace(sym, ns)
    print("[DATA-SKIP]    %s @ %s (existing='%s')" % (desired, addr_str, cur))
    return (0, 0, 1)


def _rename_proc(fm, symtab, addr, desired, addr_str, default_label, ns):
    f, created = _ensure_function_at(fm, addr, addr_str, desired)

    if f is None:
        # fall back: rename primary symbol if it exists and is FUN_*
        sym = symtab.getPrimarySymbol(addr)
        if sym is None:
            print("[FUNC-FAIL]    %s @ %s (no function, no symbol)" % (desired, addr_str))
            return (0, 0, 1)

        cur = sym.getName()
        if cur == desired:
            _set_symbol_namespace(sym, ns)
            return (0, 0, 1)

        if _should_rename(cur, default_label, "FUN"):
            try:
                sym.setName(desired, SourceType.USER_DEFINED)
                _set_symbol_namespace(sym, ns)
                print("[FUNC-SYMREN]  %s @ %s (was '%s')" % (desired, addr_str, cur))
                return (0, 1, 0)
            except Exception as e:
                print("[FUNC-FAIL]    %s @ %s: %s" % (desired, addr_str, str(e)))
                return (0, 0, 1)

        _set_symbol_namespace(sym, ns)
        return (0, 0, 1)

    # Rename function
    cur = f.getName()
    if cur == desired:
        try:
            _set_symbol_namespace(f.getSymbol(), ns)
        except Exception:
            pass
        return (1 if created else 0, 0, 1)

    if _should_rename(cur, default_label, "FUN") or True:
        try:
            f.setName(desired, SourceType.USER_DEFINED)
            try:
                _set_symbol_namespace(f.getSymbol(), ns)
            except Exception:
                pass
            print("[FUNC-RENAME]  %s @ %s (was '%s')" % (desired, addr_str, cur))
            return (1 if created else 0, 1, 0)
        except Exception as e:
            print("[FUNC-FAIL]    %s @ %s: %s" % (desired, addr_str, str(e)))
            return (1 if created else 0, 0, 1)

    return (1 if created else 0, 0, 1)


def _process(kind, items, symtab, fm, frame_to_name):
    created = renamed = skipped = failed = 0

    for rec in items:
        g = rec.get("ghidra") or {}
        addr_str = g.get("addr")
        if not addr_str:
            continue

        # Skip nameless PROC/LABEL records; these are usually synthetic entries.
        raw_name = rec.get("name")
        if kind in ("PROC", "LABEL") and (raw_name is None or str(raw_name) == ""):
            print("[%s-NONAME-SKIP] @ %s" % (kind, addr_str))
            skipped += 1
            continue

        default_label = g.get("default_label") or ""

        try:
            addr = toAddr(addr_str)
        except Exception as e:
            print("[%s-FAIL]  %s @ %s: bad addr (%s)" % (kind, raw_name, addr_str, str(e)))
            failed += 1
            continue

        # Build segment name mapping for program tree
        try:
            frame = g.get("frame")
            sm = rec.get("segmap") or {}
            segname = sm.get("segname")
            if frame is not None and segname:
                frame_to_name[int(frame)] = _strip_memory_prefix(segname)
        except Exception:
            pass

        ns_name = _pick_namespace_name(rec, kind)
        ns = _get_or_create_namespace(symtab, ns_name) if ns_name else None

        desired = _sanitize_name(raw_name, default_label if default_label else kind.lower())
        desired = _dedupe_name(symtab, desired, addr)

        if kind == "GLOBAL":
            c, r, s = _rename_global(symtab, addr, desired, addr_str, default_label, ns)
        elif kind == "PROC":
            c, r, s = _rename_proc(fm, symtab, addr, desired, addr_str, default_label, ns)
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

    json_path = askFile("NB09 ghidra json", "Open").getAbsolutePath()
    print("JSON: %s" % json_path)

    with open(json_path, "r") as f:
        db = json.load(f)

    globals_items = db.get("globals") or []
    procs_items = db.get("procs") or []
    labels_items = db.get("labels") or []

    print("Globals: %d  Procs: %d  Labels: %d" % (len(globals_items), len(procs_items), len(labels_items)))

    symtab = currentProgram.getSymbolTable()
    fm = currentProgram.getFunctionManager()

    frame_to_name = {}

    g_created, g_renamed, g_skipped, g_failed = _process("GLOBAL", globals_items, symtab, fm, frame_to_name)
    p_created, p_renamed, p_skipped, p_failed = _process("PROC", procs_items, symtab, fm, frame_to_name)
    l_created, l_renamed, l_skipped, l_failed = _process("LABEL", labels_items, symtab, fm, frame_to_name)

    if frame_to_name:
        _rename_program_tree_segments(frame_to_name)

    print("---- Summary ----")
    print("Globals: created=%d renamed=%d skipped=%d failed=%d" % (g_created, g_renamed, g_skipped, g_failed))
    print("Procs:   created=%d renamed=%d skipped=%d failed=%d" % (p_created, p_renamed, p_skipped, p_failed))
    print("Labels:  created=%d renamed=%d skipped=%d failed=%d" % (l_created, l_renamed, l_skipped, l_failed))


if __name__ == "__main__":
    main()
