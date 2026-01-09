# RetypeUndefined8Doubles1120.py
# @category Stars
#
# Retype defined 8-byte constants in segment 1120:* to double and rename labels
# so the value is recognizable in disassembly.
#
# Safety:
# - Only touches *defined* data items of length 8.
# - Only processes datatype 'undefined8' or 'double'.
# - Does NOT follow symbols (avoids clobbering undefined2 tables, etc.).
#
# Value decoding:
# Uses Memory.getLong() + java.lang.Double.longBitsToDouble() (reliable in Jython)
# instead of struct.unpack to avoid byte/str conversion pitfalls.

from ghidra.program.model.data import DoubleDataType
from ghidra.program.model.symbol import SourceType
from java.lang import Double as JDouble
import math
import re

SEG = 0x1120
VERBOSE = True

# Rename only if the current primary symbol looks auto-generated.
# Accept:
#   DAT_1120_1d12
#   DOUBLE_1120_1d12
#   DOUBLE_<anything>__1120_1d12   (lets us fix earlier wrong 0.0 renames)
AUTO_RE = re.compile(r'^(DAT|DOUBLE)_%04x_[0-9A-Fa-f]{4}$|^DOUBLE_.*__%04x_[0-9A-Fa-f]{4}$' % (SEG, SEG))


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


def read_double_bits(a):
    # getLong reads 8 bytes using the program's endianness (x86 LE here)
    bits = currentProgram.getMemory().getLong(a)
    # JDouble.longBitsToDouble expects a signed 64-bit; the bit-pattern is preserved.
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


def process_at(a):
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
    if not AUTO_RE.match(old):
        return True, "kept-name %s val=%s" % (old, d)

    if old != new_name:
        sym.setName(new_name, SourceType.USER_DEFINED)
        return True, "renamed %s -> %s val=%s" % (old, new_name, d)

    return True, "ok %s val=%s" % (old, d)


def run():
    start = addr(SEG, 0x0000)
    end = addr(SEG, 0xffff)

    listing = currentProgram.getListing()

    seen8 = 0
    changed = 0
    skipped = 0

    dbg("[info] scanning defined data in %04x:0000-%04x:ffff" % (SEG, SEG))

    a = start
    while a is not None and a.compareTo(end) <= 0:
        monitor.checkCanceled()

        data = listing.getDataAt(a)
        if data is None:
            a = a.next()
            continue

        # Only attempt on defined 8-byte items of type undefined8/double.
        if data.getLength() == 8:
            dt = data.getDataType()
            dtname = dt.getName().lower() if dt is not None else ""
            if dtname in ("undefined8", "double"):
                seen8 += 1
                ok, why = process_at(a)
                if ok:
                    changed += 1
                    dbg("[ok] %s %s" % (a, why))
                else:
                    skipped += 1
                    dbg("[skip] %s %s" % (a, why))

        # step forward by the current data item's size (prevents byte-walking)
        try:
            step = data.getLength()
            if step <= 0:
                step = 1
            a = a.add(step)
        except:
            a = a.next()

    log("[done] seen8=%d changed=%d skipped=%d" % (seen8, changed, skipped))


run()
