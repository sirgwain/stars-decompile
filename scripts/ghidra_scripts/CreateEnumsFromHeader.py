#@category Stars/Types
#@menupath Tools.Stars!.Create Enums From Header
#@toolbar

"""Create Ghidra enums from a C header (enums.h) using 2-byte storage.

Parses blocks of:
  - typedef enum Name { ... } Name;
  - enum Name { ... };

Members may be:
  - NAME
  - NAME = 123
  - NAME = 0x7B
  - NAME = -1

Non-literal expressions (e.g. 1<<3, A|B) are skipped with a warning.

Place enums.h next to this script (in ghidra_scripts) for no prompt.
Otherwise you'll be asked to pick the header.
"""

import os
import re

from ghidra.program.model.data import CategoryPath, EnumDataType
from ghidra.util import Msg

# ---- config ----
ENUM_SIZE_BYTES = 2
CATEGORY_PATH_STR = "/Stars/Enums"
OVERWRITE_EXISTING = True
VERBOSE = True

# ---- regex ----
_RE_BLOCK = re.compile(
    r"""(?:typedef\s+)?enum\s+(?P<tag>[A-Za-z_]\w*)?\s*\{\s*(?P<body>.*?)\s*\}\s*(?P<alias>[A-Za-z_]\w*)?\s*;""",
    re.DOTALL,
)
_RE_COMMENT_BLOCK = re.compile(r"/\*.*?\*/", re.DOTALL)
_RE_COMMENT_LINE = re.compile(r"//.*?$", re.MULTILINE)
_RE_MEMBER = re.compile(r"^\s*(?P<name>[A-Za-z_]\w*)(?:\s*=\s*(?P<value>.+?))?\s*$")
_RE_INT_LITERAL = re.compile(r"^\s*(?P<sign>[+-])?(?:0x(?P<hex>[0-9A-Fa-f]+)|(?P<dec>\d+))(?:[uUlL]*)\s*$")


def _strip_comments(text):
    text = _RE_COMMENT_BLOCK.sub("", text)
    text = _RE_COMMENT_LINE.sub("", text)
    return text


def _split_members(body):
    # Basic comma-split; good enough for typical enums.h.
    parts = body.replace("\r\n", "\n").split(",")
    out = []
    for p in parts:
        s = p.strip()
        if s:
            out.append(s)
    return out


def _parse_int_literal(expr):
    m = _RE_INT_LITERAL.match(expr)
    if not m:
        raise ValueError("not a simple int literal")
    sign = -1 if m.group("sign") == "-" else 1
    if m.group("hex") is not None:
        v = int(m.group("hex"), 16)
    else:
        v = int(m.group("dec"), 10)
    return sign * v


def parse_enums_from_header(path):
    with open(path, "r") as f:
        text = f.read()

    text = _strip_comments(text)

    enums = []
    for m in _RE_BLOCK.finditer(text):
        tag = (m.group("tag") or "").strip()
        alias = (m.group("alias") or "").strip()
        body = m.group("body") or ""

        enum_name = alias or tag
        if not enum_name:
            # anonymous enum
            continue

        members = []
        next_val = 0

        for chunk in _split_members(body):
            mm = _RE_MEMBER.match(chunk)
            if not mm:
                if VERBOSE:
                    Msg.warn(None, "Could not parse member in %s: %r" % (enum_name, chunk))
                continue

            name = mm.group("name")
            vexpr = mm.group("value")

            if vexpr is None or not vexpr.strip():
                val = next_val
            else:
                try:
                    val = _parse_int_literal(vexpr.strip())
                except Exception:
                    if VERBOSE:
                        Msg.warn(None, "Skipping non-literal value %s.%s = %r" % (enum_name, name, vexpr.strip()))
                    continue

            members.append((name, val))
            next_val = val + 1

        if members:
            enums.append((enum_name, members))

    return enums


def _ensure_category(dtm, cat_path_str):
    cat_path = CategoryPath(cat_path_str)
    cat = dtm.getCategory(cat_path)
    if cat is None:
        cat = dtm.createCategory(cat_path)
    return cat


def _unique_name(dtm, cat_path_str, base):
    cat_path = CategoryPath(cat_path_str)
    if dtm.getDataType(cat_path, base) is None:
        return base
    i = 2
    while True:
        cand = "%s_%d" % (base, i)
        if dtm.getDataType(cat_path, cand) is None:
            return cand
        i += 1


def _remove_existing(dtm, cat_path_str, name):
    cat_path = CategoryPath(cat_path_str)
    existing = dtm.getDataType(cat_path, name)
    if existing is None:
        return True
    try:
        dtm.remove(existing)
        return True
    except Exception as e:
        if VERBOSE:
            Msg.warn(None, "Could not remove existing %s/%s: %s" % (cat_path_str, name, str(e)))
        return False


def create_enums(enums):
    dtm = currentProgram.getDataTypeManager()
    _ensure_category(dtm, CATEGORY_PATH_STR)

    tx = dtm.startTransaction("Create enums from header")
    created = 0
    skipped = 0
    try:
        cat_path = CategoryPath(CATEGORY_PATH_STR)
        for enum_name, members in enums:
            name_to_use = enum_name
            if OVERWRITE_EXISTING:
                if not _remove_existing(dtm, CATEGORY_PATH_STR, enum_name):
                    name_to_use = _unique_name(dtm, CATEGORY_PATH_STR, enum_name)

            e = EnumDataType(cat_path, name_to_use, ENUM_SIZE_BYTES)
            for mem_name, mem_val in members:
                try:
                    e.add(mem_name, mem_val)
                except Exception as ex:
                    if VERBOSE:
                        Msg.warn(None, "Could not add %s.%s=%d: %s" % (name_to_use, mem_name, mem_val, str(ex)))

            try:
                dtm.addDataType(e, None)
                created += 1
                if VERBOSE:
                    Msg.info(None, "Created enum %s (%d members)" % (name_to_use, len(members)))
            except Exception as ex:
                skipped += 1
                Msg.error(None, "Failed to create enum %s: %s" % (name_to_use, str(ex)))
    finally:
        dtm.endTransaction(tx, True)

    Msg.info(None, "Done. created=%d skipped=%d" % (created, skipped))


def _default_header_path():
    try:
        script_dir = getScriptDirectory()
    except Exception:
        script_dir = None

    if script_dir:
        cand = os.path.join(script_dir, "enums.h")
        if os.path.isfile(cand):
            return cand
    return None


def main():
    # Check for script arguments first (headless mode)
    args = getScriptArgs()
    if args and len(args) > 0:
        path = args[0]
        print("CreateEnumsFromHeader.py> using argument: %s" % path)
    else:
        f = askFile("Select enums.h", "Open")
        path = f.getAbsolutePath()

    Msg.info(None, "Parsing header: %s" % path)
    enums = parse_enums_from_header(path)
    if not enums:
        Msg.warn(None, "No enums found.")
        return

    Msg.info(None, "Found %d enums" % len(enums))
    create_enums(enums)


main()
