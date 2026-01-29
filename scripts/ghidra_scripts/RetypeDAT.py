# RetypeDAT.py
# @category Stars
#
# Retype unresolved DAT_1120_xxxx style references in segment 1120:*.
#
# Features:
#   1) Retype & rename 8-byte constants (undefined8) as double (scan entire 1120 segment).
#   2) Retype a provided list of 0x1120xxxx addresses as NUL-terminated C strings
#      if they look "string-like", and rename labels to resemble Ghidra's s_* style.
#
# Safety / behavior:
#   - Mutates program listing (clears + retypes) for matched items.
#   - Conservative string heuristic (printable ASCII + NUL terminator).
#   - Double pass only touches *defined* 8-byte items typed undefined8/double.
#
# Output:
#   - Prints strings created/kept
#   - Prints addresses that were NOT string-like
#   - Prints summary for doubles pass

from ghidra.program.model.data import DoubleDataType, StringDataType
from ghidra.program.model.symbol import SourceType
from java.lang import Double as JDouble
import math
import re
import string

SEG = 0x1120
VERBOSE = True

# --------------------------------------------
# Inputs: flat 0x1120xxxx addresses to consider as C strings
# --------------------------------------------
ADDRESSES = [
    0x112057a4,0x112057a4,0x11200c92,0x11200c99,0x112057a4,0x112057a4,
    0x112057a4,0x11200cc9,0x11200a2e,0x11200a34,0x11200ab8,0x11200abc,
    0x11200adc,0x1120501a,0x11200ae0,0x11200ae4,0x11200aee,0x11200af2,
    0x112005fb,0x11200667,0x11200670,0x11200679,0x11200682,0x1120068b,
    0x11200694,0x1120069d,0x11200726,0x11200731,0x11200738,0x1120073a,
    0x1120073c,0x1120073e,0x11200740,0x11200742,0x11200744,0x11200746,
    0x11200748,0x11200749,0x1120074a,0x1120074b,0x11200752,0x1120075d,
    0x112009fe,0x11200a05,0x11200a0c,0x11200a17,0x112003cb,0x112003ac,
    0x112003b1,0x112003c1,0x112003de,0x112003e9,0x112003ff,0x1120040d,
    0x1120041a,0x11200423,0x11200427,0x112004fa,0x11200507,0x11200b34,
    0x11200b59,0x11200b54,0x11200b63,0x11200b6c,0x112057a4,0x112057a4,
    0x112008b0,0x112008b6,0x112008bb,0x112057a4,0x112008c4,0x11200bee,
    0x11200bf6,0x11200c1c,0x11200c26,0x112057a4,0x11201331,0x11201337,
    0x1120134f,0x11201353,0x11201355,0x1120135e,0x11201365,0x112015e8,
    0x112015ea,0x112015ee,0x112015f0,0x112015f7,0x112015fa,0x11201600,
    0x11201603,0x1120161b,0x11201633,0x1120163a,0x11201647,0x11201655,
    0x11201663,0x11201673,0x1120167a,0x11201686,0x1120167f,0x11200d24,
    0x11200d27,0x11200d2a,0x11200d2c,0x11200d31,0x11200000,0x112005a2,
    0x112005b1,0x112005aa,0x112005b8,0x112005c0,0x112005c6,0x1120098a,
    0x112057a4,0x112057a4,0x112057a4,0x112057a4,0x11200994,0x112057a4,
    0x112057a4,0x112016ba,0x112016a0,0x112009c8,0x112009cf,0x11200518,
    0x1120051c,0x11200520,0x11200524,0x11200532,0x11200564,0x11201385,
    0x11201429,0x11201432,0x1120143b
]

# String heuristic knobs
MAX_LEN = 256
MIN_LEN = 1

# Accept common printable ASCII plus whitespace; reject control chars (except \t, \n, \r)
PRINTABLE = set(string.printable) - set("\x0b\x0c")

# Rename only if the current primary symbol looks auto-generated.
AUTO_DAT_RE = re.compile(r'^DAT_%04x_[0-9A-Fa-f]{4}$' % SEG)
AUTO_STR_RE = re.compile(r'^s_.*_%04x_[0-9A-Fa-f]{4}$' % SEG)

# For doubles, accept:
#   DAT_1120_1d12
#   DOUBLE_1120_1d12
#   DOUBLE_<anything>__1120_1d12
AUTO_DBL_RE = re.compile(r'^(DAT|DOUBLE)_%04x_[0-9A-Fa-f]{4}$|^DOUBLE_.*__%04x_[0-9A-Fa-f]{4}$' % (SEG, SEG))


def log(msg):
    try:
        println(msg)
    except:
        print(msg)


def dbg(msg):
    if VERBOSE:
        log(msg)


def addr(seg, off):
    return toAddr("%04x:%04x" % (seg & 0xffff, off & 0xffff))


def to_addr_flat(flat):
    return addr(SEG, flat & 0xffff)


# --------------------------------------------
# Double helpers
# --------------------------------------------
def read_double_bits(a):
    # getLong reads 8 bytes using the program's endianness (x86 LE here)
    bits = currentProgram.getMemory().getLong(a)
    return JDouble.longBitsToDouble(bits)


def value_token(d):
    if math.isnan(d):
        return "nan"
    if math.isinf(d):
        return "pinf" if d > 0 else "ninf"

    # normalize -0.0
    if d == 0.0:
        d = 0.0

    s = "%.12g" % d
    # force ".0" for integers: 4 -> 4.0
    if ("e" not in s) and ("." not in s):
        s += ".0"

    # make identifier-safe
    s = s.replace("+", "")
    s = s.replace("e-", "em").replace("e+", "e")
    s = s.replace("-", "m")
    s = s.replace(".", "_")
    s = re.sub(r"[^A-Za-z0-9_]", "_", s)
    return s


def process_double_at(a):
    listing = currentProgram.getListing()
    symtab = currentProgram.getSymbolTable()

    data = listing.getDataAt(a)
    if data is None:
        return False, "no-data"
    if data.getLength() != 8:
        return False, "len=%d" % data.getLength()

    dt = data.getDataType()
    dtname = dt.getName().lower() if dt is not None else ""
    if dtname not in ("undefined8", "double"):
        return False, "type=%s" % dtname

    d = read_double_bits(a)
    tok = value_token(d)
    off = a.getOffset() & 0xffff
    new_name = "DOUBLE_%s__%04x_%04x" % (tok, SEG, off)

    # ensure typed as double
    if dtname != "double":
        clearListing(a, a.add(7))
        listing.createData(a, DoubleDataType.dataType)

    # rename label if it looks auto
    sym = symtab.getPrimarySymbol(a)
    if sym is None:
        symtab.createLabel(a, new_name, SourceType.USER_DEFINED)
        return True, "created %s val=%s" % (new_name, d)

    old = sym.getName()
    if not AUTO_DBL_RE.match(old):
        return True, "kept-name %s val=%s" % (old, d)

    if old != new_name:
        sym.setName(new_name, SourceType.USER_DEFINED)
        return True, "renamed %s -> %s val=%s" % (old, new_name, d)

    return True, "ok %s val=%s" % (old, d)


def pass_retype_doubles():
    start = addr(SEG, 0x0000)
    end = addr(SEG, 0xffff)

    listing = currentProgram.getListing()

    seen8 = 0
    changed = 0
    skipped = 0

    dbg("[dbl] scanning defined data in %04x:0000-%04x:ffff" % (SEG, SEG))

    a = start
    while a is not None and a.compareTo(end) <= 0:
        monitor.checkCanceled()

        data = listing.getDataAt(a)
        if data is None:
            a = a.next()
            continue

        if data.getLength() == 8:
            dt = data.getDataType()
            dtname = dt.getName().lower() if dt is not None else ""
            if dtname in ("undefined8", "double"):
                seen8 += 1
                ok, why = process_double_at(a)
                if ok:
                    changed += 1
                    dbg("[dbl-ok] %s %s" % (a, why))
                else:
                    skipped += 1
                    dbg("[dbl-skip] %s %s" % (a, why))

        # step by data size
        try:
            step = data.getLength()
            if step <= 0:
                step = 1
            a = a.add(step)
        except:
            a = a.next()

    log("[dbl-done] seen8=%d changed=%d skipped=%d" % (seen8, changed, skipped))


# --------------------------------------------
# String helpers
# --------------------------------------------
def looks_like_c_string_at(a):
    mem = currentProgram.getMemory()
    chars = []
    for i in range(MAX_LEN):
        b = mem.getByte(a.add(i)) & 0xff
        if b == 0:
            if len(chars) >= MIN_LEN:
                return "".join(chars), i + 1  # include NUL in length
            return None, 0
        c = chr(b)
        if c not in PRINTABLE:
            return None, 0
        chars.append(c)
    return None, 0  # no terminator within MAX_LEN


def sanitize_for_label(s):
    # Approximate Ghidra's s_* labels, but keep it stable and safe.
    s = s.strip()
    if len(s) == 0:
        return "empty"
    # Keep a prefix of the string to avoid absurd symbol names
    s = s[:40]
    s = re.sub(r'[^A-Za-z0-9]', '_', s)
    s = re.sub(r'_+', '_', s).strip('_')
    if len(s) == 0:
        return "str"
    return s


def process_string_at(a):
    listing = currentProgram.getListing()
    symtab = currentProgram.getSymbolTable()

    s, nbytes = looks_like_c_string_at(a)
    if s is None:
        return False, "not-string"

    # Retype as (fixed-size) char[nbytes] so the decompiler can treat it as string data.
    # We include the NUL terminator.
    clearListing(a, a.add(nbytes - 1))
    listing.createData(a, StringDataType.dataType, nbytes)

    off = a.getOffset() & 0xffff
    name = "s_%s_%04x_%04x" % (sanitize_for_label(s), SEG, off)

    sym = symtab.getPrimarySymbol(a)
    if sym is None:
        symtab.createLabel(a, name, SourceType.USER_DEFINED)
        return True, 'created %s "%s"' % (name, s)

    old = sym.getName()
    # Rename if it was auto DAT_... or an auto s_...; keep user-defined custom names.
    if AUTO_DAT_RE.match(old) or AUTO_STR_RE.match(old):
        if old != name:
            sym.setName(name, SourceType.USER_DEFINED)
            return True, 'renamed %s -> %s "%s"' % (old, name, s)
        return True, 'ok %s "%s"' % (old, s)

    return True, 'kept-name %s "%s"' % (old, s)


def pass_retype_strings_from_list():
    seen = set()
    strings = []
    non_strings = []

    for flat in ADDRESSES:
        if flat in seen:
            continue
        seen.add(flat)

        a = to_addr_flat(flat)
        try:
            ok, msg = process_string_at(a)
            if ok and not msg.startswith("not-string"):
                strings.append((a, msg))
            else:
                non_strings.append(a)
        except Exception as e:
            non_strings.append(a)

    log("=== STRING-LIKE (retyped) ===")
    for a, msg in strings:
        log("%s : %s" % (a, msg))

    log("")
    log("=== NOT STRING-LIKE (untouched) ===")
    for a in non_strings:
        log(str(a))

    log("")
    log("[str-done] strings=%d non_strings=%d unique_addrs=%d" % (len(strings), len(non_strings), len(seen)))


def run():
    pass_retype_strings_from_list()
    log("")
    pass_retype_doubles()


run()
