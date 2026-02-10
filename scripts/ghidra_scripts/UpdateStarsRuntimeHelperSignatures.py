# @category Stars
#
# UpdateStarsRuntimeHelperSignatures.py
#
# Applies best-effort signatures to Win16 CRT / compiler helper functions inside Stars!.
#
# Calling convention heuristic (per project requirement):
#   - __cdecl16far if return size is 0 or 2 bytes (void/int16/uint16/etc)
#   - __stdcall16far if return size is 4+ bytes (int32/uint32/float/double/pointers/etc)
#
# NOTE:
#   Many of these helpers are runtime internals. For anything not confidently known,
#   this script applies a minimal prototype (usually void(void)) but still ensures
#   the calling convention follows the return-size heuristic.
#
#   At the end, the script prints an [UNSURE] list so you can follow up.

from ghidra.app.script import GhidraScript
from ghidra.program.model.data import (
    VoidDataType,
    CharDataType,
    ShortDataType,
    UnsignedShortDataType,
    IntegerDataType,
    UnsignedIntegerDataType,
    LongDataType,
    UnsignedLongDataType,
    FloatDataType,
    DoubleDataType,
    Pointer16DataType,
    Pointer32DataType,
    StructureDataType,
    CategoryPath,
)
from ghidra.program.model.listing import ParameterImpl
from ghidra.program.model.symbol import SourceType

# FunctionUpdateType import varies by Ghidra version
FunctionUpdateType = None
try:
    from ghidra.program.model.listing import FunctionUpdateType as _FUT

    FunctionUpdateType = _FUT
except Exception:
    try:
        from ghidra.program.model.listing.Function import FunctionUpdateType as _FUT2

        FunctionUpdateType = _FUT2
    except Exception:
        FunctionUpdateType = None

"""Pointer sizing notes

In this Stars! Win16 decompile project:
  * "near" pointers are the default PointerDataType (16-bit)
  * "far" pointers should use Ghidra's dedicated 32-bit pointer type (Pointer32DataType)

Per project rule: only __f* CRT helpers take/return far pointers.
"""

SYMBOLS = r"""
__wflags @ 1118:0010
__astart @ 1118:001a
__cinit @ 1118:00c4
__exit @ 1118:01b1
__cexit @ 1118:01c0
__c_exit @ 1118:01d1
__ctermsub @ 1118:0241
__lseek @ 1118:027e
__itoa @ 1118:0438
__tell @ 1118:0454
__filelength @ 1118:0470
__strdate @ 1118:050a
__strtime @ 1118:056e
__strcmpi @ 1118:05f2
__strnicmp @ 1118:0634
__strlwr @ 1118:06b4
__setjmp @ 1118:09c8
__access @ 1118:0a16
__mkdir @ 1118:0a4c
__chdir @ 1118:0a5a
__rmdir @ 1118:0a7e
__dos_findnext @ 1118:0b0e
__dos_findfirst @ 1118:0b20
__dos_getdiskfree @ 1118:0b9a
__aFldiv @ 1118:0be4
__aFulmul @ 1118:0c7e
__aFlrem @ 1118:0cb0
__aFlshl @ 1118:0d50
__aFlshr @ 1118:0d5c
__aFuldiv @ 1118:0d68
__aFulrem @ 1118:0dc8
__aFulshr @ 1118:0e32
__fmemcmp @ 1118:0e3e
__fmemcpy @ 1118:0e9a
__fstricmp @ 1118:0ef8
__fstrlen @ 1118:0f3e
__fstrcmp @ 1118:0f58
__fstrcpy @ 1118:0f82
__fstrcat @ 1118:0fbe
__fmemset @ 1118:1012
__fmemmove @ 1118:105a
__aFCIsqrt @ 1118:112a
__aFCIpow @ 1118:1146
__aFCIlog @ 1118:114c
__aFCIlog10 @ 1118:1152
__aFCIexp @ 1118:1157
__aFCIsin @ 1118:116c
__aFCIcos @ 1118:1172
__aFCItan @ 1118:1177
__aFCIasin @ 1118:1192
__aFCIacos @ 1118:1198
__aFCIatan @ 1118:119d
__aFCIatan2 @ 1118:11a2
__fcmp @ 1118:11a8
__aFfcompp @ 1118:11d7
__ftol @ 1118:11fc
__stubmain @ 1118:124e
__FF_MSGBANNER @ 1118:127a
__fptrap @ 1118:129e
__aNchkstk @ 1118:12a4
__chkstk @ 1118:12c4
__setargv @ 1118:12f8
__setenvp @ 1118:147a
__cintDIV @ 1118:150a
__amsg_exit @ 1118:150f
__dosreturn @ 1118:155f
__dosretax @ 1118:1571
__maperror @ 1118:1583
__stackavail @ 1118:15b0
__catox @ 1118:15c4
__aFahdiff @ 1118:1618
__cltoasub @ 1118:1638
__cxtoa @ 1118:1644
__fFEXP @ 1118:16ba
__rtinfpopse @ 1118:1757
__fFLN @ 1118:1767
__rtinfpop @ 1118:17c4
__ffexpm1 @ 1118:17e2
__fFCOS @ 1118:182c
__fFSIN @ 1118:183c
__fFATN2 @ 1118:1945
__rtpiby2 @ 1118:19ba
__forcdecpt @ 1118:19f0
__cropzeros @ 1118:1a66
__positive @ 1118:1aea
__fassign @ 1118:1b20
__cftoe @ 1118:1b6a
__cftof @ 1118:1d20
__cftog @ 1118:1ea2
__cfltcvt @ 1118:1f78
__cintrindisp2 @ 1118:201a
__cintrindisp1 @ 1118:204a
__ctrandisp2 @ 1118:2076
__ctrandisp1 @ 1118:2090
__fpsignal @ 1118:21ca
__wcexit @ 1118:21ee
__QWINIsQWINin @ 1118:21f3
__NMSG_TEXT @ 1118:21fa
__NMSG_WRITE @ 1118:2231
__myalloc @ 1118:226e
__GetDGROUP @ 1118:229c
__fptostr @ 1118:22f8
__wrt2err @ 1118:2392
__trandisp1 @ 1118:23e0
__trandisp2 @ 1118:2422
__rttospopde @ 1118:2485
__rtnospopde @ 1118:248f
__rtzeropop @ 1118:2494
__rtonepop @ 1118:249e
__rtbignan @ 1118:24a8
__rtifprojpop @ 1118:24af
__rttosnpopde @ 1118:24c7
__rtifprojnpop @ 1118:24ce
__rtchsifneg @ 1118:24d7
__Init80x87 @ 1118:29ae
__fltout @ 1118:2a34
__matherr @ 1118:2a84
___ExportedStub @ 1118:2a9e
__growseg @ 1118:2ab2
__incseg @ 1118:2b3e
__findlast @ 1118:2ba4
__FASTLDADD @ 1118:2d5e
__FASTLDMULT @ 1118:2ee5
__fltin @ 1118:2fe8
__nmalloc @ 1118:3048
__nfree @ 1118:30a4
__nrealloc @ 1118:30be
__nmsize @ 1118:312c
__STRINGTOD @ 1118:32fa
__STRINGTOLD @ 1118:3362
__LD12MULTTENPOWER @ 1118:3882
__LD12MULT @ 1118:3957
__MANTOLD12 @ 1118:3adc
__FPMATH @ 14f8:0000
__AHSHIFT @ 14f8:0090
__AHINCR @ 14f8:0094
__WINFLAGS @ 14f8:00b0
Draw3dFrame @ 1040:336a
_exit @ 1118:01a3
_strcat @ 1118:0352
_strcpy @ 1118:0392
_strcmp @ 1118:03c4
_strlen @ 1118:03f0
_strncpy @ 1118:040c
_atoi @ 1118:0434
_strchr @ 1118:05c8
_strrchr @ 1118:068c
_memmove @ 1118:06d2
_memcmp @ 1118:071a
_memcpy @ 1118:0742
_memset @ 1118:076e
_abs @ 1118:079c
_bsearch @ 1118:07b0
_labs @ 1118:0848
_qsort @ 1118:0866
_longjmp @ 1118:09ed
_rename @ 1118:0abe
_remove @ 1118:0aea
_sqrt @ 1118:1124
_pow @ 1118:1130
_log @ 1118:1136
_log10 @ 1118:113c
_exp @ 1118:1141
_sin @ 1118:115c
_cos @ 1118:1162
_tan @ 1118:1167
_asin @ 1118:117c
_acos @ 1118:1182
_atan @ 1118:1187
_atan2 @ 1118:118c
_fFYTOX @ 1118:16ae
_atof @ 1118:22ac
_Soft_fFCOS @ 1118:24e0
_Soft_fFSIN @ 1118:24f7
_Soft_fFTAN @ 1118:25f9
_i8_output @ 1118:2c12
_i8_tpwr10 @ 1118:32bc
_lclose @ 14f8:0070
_lread @ 14f8:0074
_lwrite @ 14f8:0078
"""


def _ptr_near(base_dt):
    """Near pointer (16-bit in this project)."""
    return Pointer16DataType(base_dt)


def _ptr_far(base_dt):
    """Far pointer (32-bit segment:offset in this project)."""
    return Pointer32DataType(base_dt)


def _dt_primitive(name):
    # Use explicit builtins (avoid parseDataType ambiguity across versions).
    if name == "void":
        return VoidDataType.dataType
    if name == "char":
        return CharDataType.dataType
    if name == "int16":
        return ShortDataType.dataType
    if name == "uint16":
        return UnsignedShortDataType.dataType
    if name == "int32":
        return IntegerDataType.dataType  # 4 bytes
    if name == "uint32":
        return UnsignedIntegerDataType.dataType
    if name == "long":
        return LongDataType.dataType  # 4 bytes
    if name == "ulong":
        return UnsignedLongDataType.dataType
    if name == "float":
        return FloatDataType.dataType
    if name == "double":
        return DoubleDataType.dataType
    raise ValueError("unknown primitive: %s" % name)


def _ret_cc_for(dt):
    ln = dt.getLength()
    if ln <= 0:
        return "__cdecl16far"
    if ln <= 2:
        return "__cdecl16far"
    return "__stdcall16far"


# Calling convention overrides for known CRT/compiler helpers where the default
# return-size heuristic is insufficient.
#
# IMPORTANT:
#   - __stdcall16far_8: callee cleans up 8 bytes of arguments (RETF 0x8)
#   - __compiler_helper_dxax_cx: register helper (param_1 in DX:AX, param_2 in CX)
CALLING_CONVENTION_OVERRIDES = {
    # 32-bit helpers that end with RETF 0x8 (two 32-bit stack args)
    "__aFldiv": "__stdcall16far_8",
    "__aFulmul": "__stdcall16far_8",
    "__aFuldiv": "__stdcall16far_8",
    "__aFulrem": "__stdcall16far_8",
    "__aFlrem": "__stdcall16far_8",
    # Register-based helpers (no stack args; uses DX:AX and CX)
    "__aFulshr": "__compiler_helper_dxax_cx",
    "__aFlshl": "__compiler_helper_dxax_cx",
    "__aFlshr": "__compiler_helper_dxax_cx",
}


def _cc_for(name, ret_dt):
    cc = CALLING_CONVENTION_OVERRIDES.get(name)
    if cc is not None:
        return cc
    return _ret_cc_for(ret_dt)


def run():
    prog = currentProgram
    dtm = prog.getDataTypeManager()

    # Minimal named structs used only to get pointer types with readable names.
    # (0-sized on purpose: avoids fake confidence in layout.)
    find_t = dtm.getDataType(CategoryPath("/win16"), "find_t")
    if find_t is None:
        find_t = StructureDataType(CategoryPath("/win16"), "find_t", 0)
        dtm.addDataType(find_t, None)

    diskfree_t = dtm.getDataType(CategoryPath("/win16"), "diskfree_t")
    if diskfree_t is None:
        diskfree_t = StructureDataType(CategoryPath("/win16"), "diskfree_t", 0)
        dtm.addDataType(diskfree_t, None)

    # Known-ish prototypes (best effort).
    # Type tokens:
    #   void,char,int16,uint16,int32,uint32,long,ulong,float,double
    # And pointer pseudo-types:
    #   ptr_char, ptr_void, ptr_find_t, ptr_diskfree_t  (near/16-bit)
    #   ptr32_char, ptr32_void                          (far/32-bit)
    proto = {
        # Startup / termination (best effort)
        "__astart": ("void", []),
        "__cinit": ("void", []),
        "__cexit": ("void", []),
        "__c_exit": ("void", []),
        "__exit": ("void", ["int16"]),
        "__ctermsub": ("void", []),
        "__stubmain": ("int16", []),
        # File/dir (MS 16-bit CRT-ish)
        "__lseek": ("long", ["int16", "long", "int16"]),  # fd, offset, origin
        "__tell": ("long", ["int16"]),
        "__filelength": ("long", ["int16"]),
        "__access": ("int16", ["ptr_char", "int16"]),  # const char*, mode
        "__mkdir": ("int16", ["ptr_char"]),
        "__chdir": ("int16", ["ptr_char"]),
        "__rmdir": ("int16", ["ptr_char"]),
        # Strings (best effort; int is 16-bit)
        "__itoa": ("ptr_char", ["int16", "ptr_char", "int16"]),  # value, buf, radix
        "__strdate": ("ptr_char", ["ptr_char"]),  # char* buf
        "__strtime": ("ptr_char", ["ptr_char"]),
        "__strcmpi": ("int16", ["ptr_char", "ptr_char"]),
        "__strnicmp": ("int16", ["ptr_char", "ptr_char", "uint16"]),
        "__strlwr": ("ptr_char", ["ptr_char"]),
        # setjmp (opaque)
        "__setjmp": ("int16", ["ptr_void"]),  # jmp_buf*
        # DOS helpers (opaque structs)
        "__dos_findfirst": (
            "uint16",
            ["ptr_char", "uint16", "ptr_find_t"],
        ),  # path, attr, find_t*
        "__dos_findnext": ("uint16", ["ptr_find_t"]),
        "__dos_getdiskfree": (
            "uint16",
            ["uint16", "ptr_diskfree_t"],
        ),  # drive, diskfree_t*
        # Far memory/string helpers ("__f*" use far pointers)
        "__fmemcmp": ("int16", ["ptr32_void", "ptr32_void", "uint16"]),
        "__fmemcpy": ("ptr32_void", ["ptr32_void", "ptr32_void", "uint16"]),
        "__fmemmove": ("ptr32_void", ["ptr32_void", "ptr32_void", "uint16"]),
        "__fmemset": ("ptr32_void", ["ptr32_void", "int16", "uint16"]),
        "__fstrlen": ("uint16", ["ptr32_char"]),
        "__fstrcmp": ("int16", ["ptr32_char", "ptr32_char"]),
        "__fstricmp": ("int16", ["ptr32_char", "ptr32_char"]),
        "__fstrcpy": ("ptr32_char", ["ptr32_char", "ptr32_char"]),
        "__fstrcat": ("ptr32_char", ["ptr32_char", "ptr32_char"]),
        # 32-bit helpers (you called these out already)
        "__aFldiv": ("long", ["long", "long"]),
        "__aFulmul": ("ulong", ["ulong", "ulong"]),
        "__aFuldiv": ("ulong", ["ulong", "ulong"]),
        "__aFulrem": ("ulong", ["ulong", "ulong"]),
        "__aFulshr": ("ulong", ["ulong", "uint16"]),
        "__aFlshl": ("long", ["long", "uint16"]),
        "__aFlshr": ("long", ["long", "uint16"]),
        "__aFlrem": ("long", ["long", "long"]),
        # Float/double helpers (best effort)
        "__ftol": ("long", ["double"]),
        "__fcmp": ("int16", ["double", "double"]),
        "__aFCIsqrt": ("ptr_double", ["double"]),
        "__aFCIpow": ("ptr_double", ["double", "double"]),
        "__aFCIlog": ("ptr_double", ["double"]),
        "__aFCIlog10": ("ptr_double", ["double"]),
        "__aFCIexp": ("ptr_double", ["double"]),
        "__aFCIsin": ("ptr_double", ["double"]),
        "__aFCIcos": ("ptr_double", ["double"]),
        "__aFCItan": ("ptr_double", ["double"]),
        "__aFCIasin": ("ptr_double", ["double"]),
        "__aFCIacos": ("ptr_double", ["double"]),
        "__aFCIatan": ("ptr_double", ["double"]),
        "__aFCIatan2": ("ptr_double", ["double", "double"]),
    }

    # C runtime / misc (16-bit int, near pointers unless noted)
    proto.update(
        {
            # termination
            "_exit": ("void", ["int16"]),  # status
            # string.h
            "_strcat": ("ptr_char", ["ptr_char", "ptr_char"]),
            "_strcpy": ("ptr_char", ["ptr_char", "ptr_char"]),
            "_strcmp": ("int16", ["ptr_char", "ptr_char"]),
            "_strlen": ("uint16", ["ptr_char"]),
            "_strncpy": ("ptr_char", ["ptr_char", "ptr_char", "uint16"]),
            "_atoi": ("int16", ["ptr_char"]),
            "_strchr": ("ptr_char", ["ptr_char", "int16"]),  # s, c
            "_strrchr": ("ptr_char", ["ptr_char", "int16"]),  # s, c
            # memory.h / string.h
            "_memmove": ("ptr_void", ["ptr_void", "ptr_void", "uint16"]),
            "_memcmp": ("int16", ["ptr_void", "ptr_void", "uint16"]),
            "_memcpy": ("ptr_void", ["ptr_void", "ptr_void", "uint16"]),
            "_memset": ("ptr_void", ["ptr_void", "int16", "uint16"]),
            # stdlib.h
            "_abs": ("int16", ["int16"]),
            "_labs": ("long", ["long"]),
            "_bsearch": (
                "ptr_void",
                ["ptr_void", "ptr_void", "uint16", "uint16", "ptr_void"],
            ),
            "_qsort": ("void", ["ptr_void", "uint16", "uint16", "ptr_void"]),
            "_longjmp": ("void", ["ptr_void", "int16"]),  # jmp_buf*, val
            # stdio/unistd-ish
            "_rename": ("int16", ["ptr_char", "ptr_char"]),
            "_remove": ("int16", ["ptr_char"]),
            # math (Borland-ish CRT names)
            "_sqrt": ("ptr_double", ["double"]),
            "_pow": ("ptr_double", ["double", "double"]),
            "_log": ("ptr_double", ["double"]),
            "_log10": ("ptr_double", ["double"]),
            "_exp": ("ptr_double", ["double"]),
            "_sin": ("ptr_double", ["double"]),
            "_cos": ("ptr_double", ["double"]),
            "_tan": ("ptr_double", ["double"]),
            "_asin": ("ptr_double", ["double"]),
            "_acos": ("ptr_double", ["double"]),
            "_atan": ("ptr_double", ["double"]),
            "_atan2": ("ptr_double", ["double", "double"]),
            "_atof": ("ptr_double", ["ptr_char"]),
            # Win16 KERNEL file APIs (HFILE + far buffer)
            "_lclose": ("int16", ["int16"]),
            "_lread": ("uint16", ["int16", "ptr32_void", "uint16"]),
            "_lwrite": ("uint16", ["int16", "ptr32_void", "uint16"]),
        }
    )

    def resolve_type(tname):
        # Near (16-bit) pointers
        if tname == "ptr_char":
            return _ptr_near(CharDataType.dataType)
        if tname == "ptr_void":
            return _ptr_near(VoidDataType.dataType)
        if tname == "ptr_find_t":
            return _ptr_near(find_t)
        if tname == "ptr_diskfree_t":
            return _ptr_near(diskfree_t)
        if tname == "ptr_double":
            return _ptr_near(DoubleDataType.dataType)

        # Far (32-bit) pointers - ONLY for __f* family
        if tname == "ptr32_char":
            return _ptr_far(CharDataType.dataType)
        if tname == "ptr32_void":
            return _ptr_far(VoidDataType.dataType)

        return _dt_primitive(tname)

    entries = []
    for line in SYMBOLS.splitlines():
        line = line.strip()
        if not line:
            continue
        if " @ " not in line:
            continue
        name, addr_s = [x.strip() for x in line.split("@", 1)]
        entries.append((name.strip(), addr_s.strip()))

    total_expected = len(entries)
    applied = 0
    created = 0
    missing = 0
    unsure = []

    fm = prog.getFunctionManager()

    for name, addr_s in entries:
        addr = toAddr(addr_s)
        fn = fm.getFunctionAt(addr)
        if fn is None:
            # Create if missing.
            try:
                fn = createFunction(addr, name)
                if fn is None:
                    print(
                        "[MISS] %-22s @ %s (no function, could not create)"
                        % (name, addr_s)
                    )
                    missing += 1
                    continue
                created += 1
            except Exception as e:
                print("[MISS] %-22s @ %s (create failed: %s)" % (name, addr_s, e))
                missing += 1
                continue

        spec = proto.get(name)
        if spec is None:
            # Unknown: keep minimal.
            ret_dt = VoidDataType.dataType
            arg_dts = []
            unsure.append(name)
        else:
            ret_dt = resolve_type(spec[0])
            arg_dts = [resolve_type(x) for x in spec[1]]

        cc = _cc_for(name, ret_dt)

        # Apply calling convention
        try:
            fn.setCallingConvention(cc)
        except Exception as e:
            print(
                "[WARN] %-22s %s (setCallingConvention failed: %s)" % (name, addr_s, e)
            )

        # Apply return type + params
        try:
            fn.setReturnType(ret_dt, SourceType.USER_DEFINED)
        except Exception as e:
            print("[WARN] %-22s %s (setReturnType failed: %s)" % (name, addr_s, e))

        params = []
        for i, dt in enumerate(arg_dts):
            params.append(ParameterImpl("param_%d" % (i + 1), dt, prog))

        try:
            fn.replaceParameters(
                FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                True,
                SourceType.USER_DEFINED,
                params,
            )
        except Exception:
            # Some runtimes/thunks need custom storage mode.
            try:
                fn.replaceParameters(
                    FunctionUpdateType.CUSTOM_STORAGE,
                    True,
                    SourceType.USER_DEFINED,
                    params,
                )
            except Exception as e2:
                print(
                    "[ERR] %-22s %s (replaceParameters failed: %s)" % (name, addr_s, e2)
                )

        applied += 1
        print(
            "[APPLY] %-22s @ %s  ret=%-10s cc=%s args=%d"
            % (name, addr_s, ret_dt.getName(), cc, len(arg_dts))
        )

    print(
        "\n[OK] Done. total=%d applied=%d created=%d missing=%d"
        % (total_expected, applied, created, missing)
    )
    if unsure:
        print(
            "\n[UNSURE] %d functions were given minimal/unknown prototypes:"
            % len(unsure)
        )
        for nm in unsure:
            print("  - %s" % nm)
        print("(Add prototypes for these to the proto{} map when you confirm them.)")


run()
