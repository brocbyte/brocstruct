import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.pcode.PcodeOp;

public class Node {
    String name = null;
    int opcode;
    List<Node> inputs = new ArrayList<Node>();
    int bytesize = -1;
    Long constant = null;

    Node(int opcode_, List<Node> inputs_) {
        opcode = opcode_;
        inputs.addAll(inputs_);
    }

    Node(int opcode_, List<Node> inputs_, int bytesize_) {
        opcode = opcode_;
        inputs.addAll(inputs_);
        bytesize = bytesize_;
    }

    Node(String name_) {
        name = name_;
    }

    Node(Long constant_) {
        constant = constant_;
    }

    @Override
    public String toString() {
        if (name != null) {
            return name;
        }
        if (constant != null) {
            return Long.toString(constant);
        }
        if (opcode == PcodeOp.LOAD) {
            String cast = switch (bytesize) {
                case 1 -> "(8_t*)";
                case 2 -> "(16_t*)";
                case 4 -> "(32_t*)";
                case 8 -> "(64_t*)";
                default -> "(error*)";
            };
            return "*" + cast + inputs.get(0).toString();
        }
        if (opcode == PcodeOp.STORE) {
            return "*" + inputs.get(0).toString();
        }
        if (opcode == PcodeOp.PTRADD) {
            return "(" + inputs.get(0).toString() + " + " + inputs.get(1).toString() + " * " + inputs.get(2).toString()
                    + ")";
        }
        return switch (opcode) {
            case PcodeOp.INT_SEXT -> "sext(" + inputs.get(0).toString() + ")";
            case PcodeOp.INT_ADD -> "(" + inputs.get(0).toString() + " + " + inputs.get(1).toString() + ")";
            case PcodeOp.INT_MULT -> "(" + inputs.get(0).toString() + " * " + inputs.get(1).toString() + ")";
            default -> "error";
        };
    }
}
