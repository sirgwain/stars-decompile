// ApplyRaceAttributeEquates.java
//
// Ghidra script: Find comparisons of GetRaceStat(&rgplr[iplr], rsMajorAdv)
// against an immediate constant, and apply equates so the constant shows up
// as a RaceAttribute enum name (raStealth, raMacintosh, etc.)
//
// This is intentionally conservative:
// - It only triggers when the second argument to GetRaceStat is the constant
//   rsMajorAdv (which is 14 in this project types.h).
// - It only applies equates to the immediate in the comparison instruction.
//
// Tested API surface: Decompiler + EquateTable.

import java.util.*;

import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.*;
import ghidra.program.model.pcode.*;

public class ApplyRaceAttributeEquates extends GhidraScript {

    // From your types.h: rsMajorAdv = 14
    private static final long RS_MAJOR_ADV = 14;

    private static final String ENUM_NAME = "RaceAttribute";

    @Override
    public void run() throws Exception {
        Program program = currentProgram;
        if (program == null) {
            printerr("No currentProgram");
            return;
        }

        ghidra.program.model.data.Enum raceAttrEnum = getRaceAttributeEnum(program);
        if (raceAttrEnum == null) {
            printerr("Failed to get/create RaceAttribute enum");
            return;
        }

        Function getRaceStat = findFunctionByName(program, "GetRaceStat");
        if (getRaceStat == null) {
            printerr("Could not find function symbol 'GetRaceStat' in this program");
            printerr("(Tip: rename/import symbols first, or change the name in this script)");
            return;
        }

        DecompInterface ifc = new DecompInterface();
        ifc.setOptions(new DecompileOptions());
        ifc.openProgram(program);

        EquateTable eqTable = program.getEquateTable();

        int applied = 0;
        int considered = 0;

        Listing listing = program.getListing();
        FunctionManager fm = program.getFunctionManager();
        FunctionIterator it = fm.getFunctions(true);

        monitor.initialize(fm.getFunctionCount());
        while (it.hasNext()) {
            monitor.checkCanceled();
            Function f = it.next();
            monitor.incrementProgress(1);
            println("checking function " + f.getName());

            DecompileResults res = ifc.decompileFunction(f, 60, monitor);
            if (!res.decompileCompleted()) {
                continue;
            }
            HighFunction hf = res.getHighFunction();
            if (hf == null) {
                continue;
            }

            // Collect CALL ops to GetRaceStat where arg2 == rsMajorAdv
            ArrayList<PcodeOpAST> prtCalls = new ArrayList<>();
            Iterator<PcodeOpAST> ops = hf.getPcodeOps();
            while (ops.hasNext()) {
                PcodeOpAST op = ops.next();
                if (op.getOpcode() != PcodeOp.CALL) {
                    continue;
                }

                if (!isCallToFunction(op, getRaceStat)) {
                    continue;
                }

                // CALL inputs: in0 = function address, in1.. = params
                // We want second arg (RaceStat) -> that is input(2) if signature is (PLAYER*, RaceStat)
                if (op.getNumInputs() < 3) {
                    continue;
                }

                Varnode arg2 = op.getInput(2);
                if (!isConstValue(arg2, RS_MAJOR_ADV)) {
                    continue;
                }

                prtCalls.add(op);
            }

            if (prtCalls.isEmpty()) {
                continue;
            }

            // Walk comparisons and match ones that consume the CALL output.
            Iterator<PcodeOpAST> ops2 = hf.getPcodeOps();
            while (ops2.hasNext()) {
                PcodeOpAST op = ops2.next();
                int opc = op.getOpcode();
                if (!isComparisonOpcode(opc)) {
                    continue;
                }

                // comparisons have 2 inputs
                if (op.getNumInputs() < 2) {
                    continue;
                }

                Varnode a = op.getInput(0);
                Varnode b = op.getInput(1);

                for (PcodeOpAST call : prtCalls) {
                    Varnode callOut = call.getOutput();
                    if (callOut == null) {
                        continue;
                    }

                    boolean aFromCall = isDerivedFrom(a, callOut, 8);
                    boolean bFromCall = isDerivedFrom(b, callOut, 8);

                    Varnode cst = null;
                    if (aFromCall && b.isConstant()) {
                        cst = b;
                    } else if (bFromCall && a.isConstant()) {
                        cst = a;
                    } else {
                        continue;
                    }

                    long val = cst.getOffset();
                    String enumMember = raceAttrEnum.getName(val);
                    if (enumMember == null) {
                        // Not a valid RaceAttribute value.
                        continue;
                    }

                    considered++;
                    Address instrAddr = op.getSeqnum().getTarget();
                    Instruction instr = listing.getInstructionAt(instrAddr);
                    if (instr == null) {
                        continue;
                    }

                    // Apply equate to any scalar operand that matches this value.
                    boolean didOne = applyEquateToMatchingScalars(eqTable, instr, enumMember, val);
                    if (didOne) {
                        applied++;
                    }
                }
            }
        }

        println("RaceAttribute equates applied: " + applied + " (candidates seen: " + considered + ")");
        println("Done.");
    }

    private static boolean isComparisonOpcode(int opc) {
        switch (opc) {
            case PcodeOp.INT_EQUAL:
            case PcodeOp.INT_NOTEQUAL:
            case PcodeOp.INT_SLESS:
            case PcodeOp.INT_SLESSEQUAL:
            case PcodeOp.INT_LESS:
            case PcodeOp.INT_LESSEQUAL:
                return true;
            default:
                return false;
        }
    }

    private static boolean isConstValue(Varnode vn, long value) {
        return vn != null && vn.isConstant() && vn.getOffset() == value;
    }

    private static boolean isCallToFunction(PcodeOp op, Function target) {
        if (op.getOpcode() != PcodeOp.CALL) {
            return false;
        }
        if (op.getNumInputs() < 1) {
            return false;
        }
        Varnode fn = op.getInput(0);
        if (fn == null || !fn.isAddress()) {
            return false;
        }
        Address addr = fn.getAddress();
        return addr != null && target.getEntryPoint().equals(addr);
    }

    private static boolean isDerivedFrom(Varnode start, Varnode target, int maxDepth) {
        if (start == null || target == null) {
            return false;
        }
        if (start == target) {
            return true;
        }
        Varnode cur = start;
        for (int depth = 0; depth < maxDepth; depth++) {
            if (cur == null) {
                return false;
            }
            if (cur == target) {
                return true;
            }
            PcodeOp def = cur.getDef();
            if (def == null) {
                return false;
            }
            int opc = def.getOpcode();

            // Follow simple casts/copies/extends/subpieces.
            if (opc == PcodeOp.COPY || opc == PcodeOp.INT_ZEXT || opc == PcodeOp.INT_SEXT) {
                cur = def.getInput(0);
                continue;
            }
            if (opc == PcodeOp.SUBPIECE) {
                cur = def.getInput(0);
                continue;
            }

            // Anything else: stop.
            return false;
        }
        return false;
    }

    private static boolean applyEquateToMatchingScalars(EquateTable eqTable, Instruction instr,
            String equateName, long value) {

        // Make sure the equate exists.
        Equate eq = eqTable.getEquate(equateName);
        if (eq == null) {
            try {
                eq = eqTable.createEquate(equateName, value);
                System.out.printf(
                    "Applied equate %s to instruction @ %s: %s%n\n",
                    equateName,
                    instr.getAddress(),
                    instr
                );
            }
            catch (DuplicateNameException e) {
                // Benign: equate already exists under same name
                System.err.println("DuplicateName: " + equateName);
                eq = eqTable.getEquate(equateName);
            }
            catch (InvalidInputException e) {
                // Bad name or illegal value (should never happen here)
                System.err.println("Invalid equate: " + equateName + " = " + value);
                return false;
            }
        }

        boolean appliedAny = false;
        int nops = instr.getNumOperands();
        for (int opIndex = 0; opIndex < nops; opIndex++) {
            Object[] objs = instr.getOpObjects(opIndex);
            if (objs == null) {
                continue;
            }
            for (Object o : objs) {
                if (!(o instanceof Scalar)) {
                    continue;
                }
                Scalar sc = (Scalar) o;
                long v = sc.getUnsignedValue();

                // Be tolerant about sign; most of these are tiny positive values.
                if ((v & 0xffffffffL) != (value & 0xffffffffL)) {
                    continue;
                }

                // Add an equate reference on this operand.
                // If there is already an equate reference, addReference will be idempotent.
                eq.addReference(instr.getAddress(), opIndex);
                appliedAny = true;
            }
        }

        return appliedAny;
    }

    private static Function findFunctionByName(Program program, String name) {
        SymbolTable st = program.getSymbolTable();
        SymbolIterator syms = st.getSymbolIterator(name, true);
        while (syms.hasNext()) {
            Symbol s = syms.next();
            Object obj = s.getObject();
            if (obj instanceof Function) {
                return (Function) obj;
            }
        }
        // Fallback: try listing lookup by name
        Listing listing = program.getListing();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (name.equals(f.getName())) {
                return f;
            }
        }
        return null;
    }

    private static ghidra.program.model.data.Enum getRaceAttributeEnum(Program program) {
        DataTypeManager dtm = program.getDataTypeManager();

        DataType dt = dtm.getDataType(new DataTypePath(new CategoryPath("/Stars/Enums"), "RaceAttribute"));
        if (dt == null) {
            System.err.println("RaceAttribute not found at /Stars/Enums");
            return null;
        }

        // If it’s a typedef to an enum, unwrap it.
        if (dt instanceof TypeDef) {
            dt = ((TypeDef) dt).getBaseDataType();
        }

        if (!(dt instanceof ghidra.program.model.data.Enum)) {
            System.err.println("RaceAttribute exists but is not an Enum. Actual type: " + dt.getClass().getName());
            return null;
        }

        return (ghidra.program.model.data.Enum) dt;   // works for EnumDB
    }

}
