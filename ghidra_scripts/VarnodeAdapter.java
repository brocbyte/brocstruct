import ghidra.program.model.pcode.Varnode;

class VarnodeAdapter {
    static long getConstant(Varnode varnode) {
        return varnode.getAddress().getOffset();
    }
}