// @author brocbyte
// @category BROCSTRUCT

import java.util.*;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.Msg;

import org.jgrapht.*;
import org.jgrapht.alg.shortestpath.DijkstraShortestPath;
import org.jgrapht.graph.*;
import org.jgrapht.traverse.*;

public class ReStructures extends GhidraScript {
  public void run() throws Exception {
    if (currentProgram == null) {
      Msg.showError(monitor, null, "Error", "No program");
      return;
    }

    Listing listing = currentProgram.getListing();
    Function currentFunction = listing.getFunctionContaining(currentAddress);
    if (currentFunction == null) {
      Msg.showError(monitor, null, "Error", "Place cursor inside a function");
      return;
    }
    println("Analyzing function: " + currentFunction.getName());

    DecompInterface ifc = new DecompInterface();
    if (!ifc.openProgram(currentProgram)) {
      Msg.showError(monitor, null, "Error", "Decompilation failed");
      return;
    }
    DecompileResults res = ifc.decompileFunction(currentFunction, 30, monitor);
    HighFunction highFunction = res.getHighFunction();
    List<PcodeOpAST> pcodeOps = new ArrayList<PcodeOpAST>();
    highFunction.getPcodeOps().forEachRemaining(pcodeOps::add);

    // create a data flow graph from instructions
    Graph<Varnode, DefaultEdge> g = new DefaultDirectedGraph<>(DefaultEdge.class);
    for (PcodeOpAST op : pcodeOps) {
      Varnode output = op.getOutput();
      Varnode[] inputs = op.getInputs();
      if (output != null) {
        g.addVertex(output);
        for (int i = 0; i < inputs.length; ++i) {
          g.addVertex(inputs[i]);
          g.addEdge(inputs[i], output);
        }
      }
    }

    // for each varnode construct it's symbolic expression
    TopologicalOrderIterator<Varnode, DefaultEdge> topVIterator = new TopologicalOrderIterator<>(g);
    while (topVIterator.hasNext()) {
      process(topVIterator.next());
    }

    List<Varnode> params = new ArrayList<Varnode>();
    List<String> paramNameStrings = new ArrayList<String>();
    LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
    for (int i = 0; i < localSymbolMap.getNumParams(); ++i) {
      Varnode param = localSymbolMap.getParam(i).getRepresentative();
      params.add(param);
      paramNameStrings.add(param.getHigh().getName());
    }
    if (params.isEmpty()) {
      println("Function has no parameters :(");
      return;
    }
    Map<String, Varnode> paramNames = new HashMap<String, Varnode>();
    for (Varnode param : params) {
      paramNames.put(param.getHigh().getName(), param);
    }
    String choice = askChoice("Param selection", "Choose one", paramNameStrings, paramNameStrings.get(0));

    Varnode paramVarnode = paramNames.get(choice);

    Map<Long, Map<Integer, Integer>> accesses = new HashMap<>();
    // hit READ: PcodeOpAST is LOAD and its output Varnode has paramVarnode as base
    // hit WRITE: PcodeOpAST is STORE and its input[1] Varnode has paramVarnode as base
    for (PcodeOpAST op : pcodeOps) {
      int opcode = op.getOpcode();
      if (opcode == PcodeOp.STORE || opcode == PcodeOp.LOAD) {
        Varnode dst = opcode == PcodeOp.STORE ? op.getInput(1) : op.getOutput();
        if (DijkstraShortestPath.findPathBetween(g, paramVarnode, dst) != null) {
          List<Node> paths = db.get(dst);
          for (Node path : paths) {
            Node input = opcode == PcodeOp.STORE ? path : path.inputs.get(0);
            String baseName = getBaseName(input);
            Long offset = getOffset(input);
            int bytesize = opcode == PcodeOp.STORE ? op.getInput(2).getSize() : path.bytesize;
            if (baseName.isEmpty()) {
              baseName = "error: " + input.toString();
            }
            printf("%s base: %s, offset: %d, size: %d\n", PcodeOp.getMnemonic(opcode), baseName, offset, bytesize);
            Map<Integer, Integer> sizes = accesses.getOrDefault(offset, new TreeMap<Integer, Integer>());
            Integer freq = sizes.getOrDefault(bytesize, 0) + 1;
            sizes.put(bytesize, freq);
            accesses.put(offset, sizes);
          }
        }
      }
    }

    long structureSize = 0;
    for (Long offset : accesses.keySet()) {
      for (Map.Entry<Integer, Integer> entry : accesses.get(offset).entrySet()) {
        printf("base: %s, offset: 0x%x, size: 0x%x, count: %d\n", paramVarnode.getHigh().getName(), offset,
            entry.getKey(),
            entry.getValue());
        structureSize = Math.max(structureSize, offset + entry.getKey());
      }
    }
    String structureString = buildStructure(accesses, (int) structureSize, choice);
    println("\n" + structureString);
  }

  String getBaseName(Node input) {
    String baseName = "";
    while (input.name == null) {
      if (input.opcode != PcodeOp.INT_ADD) {
        println("unsupported node structure");
      }
      input = input.inputs.get(0);
    }
    baseName = input.name;
    return baseName;
  }

  Long getOffset(Node input) {
    long offset = 0;
    while (input.opcode == PcodeOp.INT_ADD) {
      Node offsetNode = input.inputs.get(1);
      offset += offsetNode.constant;
      input = input.inputs.get(0);
    }
    return offset;
  }

  Map<Varnode, List<Node>> db = new HashMap<Varnode, List<Node>>();

  String buildStructure(Map<Long, Map<Integer, Integer>> accesses, int size, String paramName) {
    StructureDataType structureDataType = new StructureDataType(new CategoryPath("/BROCSTRUCT"), "S_" + paramName,
        size);
    DataTypeManager dm = currentProgram.getDataTypeManager();
    BuiltInDataTypeManager bdm = BuiltInDataTypeManager.getDataTypeManager();
    Map<Integer, DataType> size_lookup = new HashMap<>();
    size_lookup.put(1, bdm.getDataType("/byte"));
    size_lookup.put(2, bdm.getDataType("/short"));
    size_lookup.put(4, bdm.getDataType("/int"));
    size_lookup.put(8, bdm.getDataType("/longlong"));
    List<Pair<Integer, Integer>> accessesList = new ArrayList<Pair<Integer, Integer>>();
    for (Long offsetLong : accesses.keySet()) {
      Map<Integer, Integer> sizes = accesses.get(offsetLong);
      Integer size0 = Collections.max(sizes.entrySet(), Map.Entry.comparingByValue()).getKey();
      int offset = (int) offsetLong.longValue();
      accessesList.add(new Pair<Integer, Integer>(offset, size0));
    }
    accessesList = fixOverlaps(accessesList);
    for (Pair<Integer, Integer> p : accessesList) {
      DataType type = size_lookup.get(p.second());
      printf("setting offset %d size %d %s\n", p.first(), p.second(), "field" + p.first());
      structureDataType.replaceAtOffset(p.first(), type, p.second(), "field" + p.first(), "");
    }
    dm.addDataType(structureDataType, DataTypeConflictHandler.REPLACE_HANDLER);
    return structureDataType.toString();
  }

  private boolean intersect(Pair<Integer, Integer> a, Pair<Integer, Integer> b) {
    int aright = a.first() + a.second() - 1;
    int bright = b.first() + b.second() - 1;
    return a.first() <= bright && b.first() <= aright;
  }

  private List<Pair<Integer, Integer>> fixOverlaps(List<Pair<Integer, Integer>> accessesList) {
    List<Pair<Integer, Integer>> result = new ArrayList<Pair<Integer, Integer>>();
    for (Pair<Integer, Integer> newPair : accessesList) {
      List<Pair<Integer, Integer>> conflictedToRemove = new ArrayList<>();
      for (Pair<Integer, Integer> oldPair : result) {
        if (intersect(newPair, oldPair)) {
          conflictedToRemove.add(oldPair);
        }
      }
      result.removeAll(conflictedToRemove);
      if (conflictedToRemove.isEmpty()) {
        result.add(newPair);
      } else {
        conflictedToRemove.sort((a, b) -> a.first() - b.first());
        while (!conflictedToRemove.isEmpty()) {
          Pair<Integer, Integer> old = conflictedToRemove.getFirst();
          conflictedToRemove.remove(0);
          int ol = old.first();
          int or = old.first() + old.second();
          int nl = newPair.first();
          int nr = newPair.first() + newPair.second();
          int minL = Integer.min(ol, nl);
          int maxL = Integer.max(ol, nl);
          int minR = Integer.min(or, nr);
          int maxR = Integer.max(or, nr);
          List<Pair<Integer, Integer>> splitted = new ArrayList<>();
          splitted.add(new Pair<Integer, Integer>(minL, maxL - minL));
          splitted.add(new Pair<Integer, Integer>(maxL, minR - maxL));
          Pair<Integer, Integer> updatedNewPair = new Pair<Integer, Integer>(minR, maxR - minR);
          if (conflictedToRemove.isEmpty()) {
            if (updatedNewPair.second() > 0) {
              splitted.add(updatedNewPair);
            }
          } else {
            newPair = updatedNewPair;
          }
          result.addAll(splitted);
        }
      }
    }
    return result;
  }

  private void process(Varnode varnode) {
    PcodeOp def = varnode.getDef();
    List<Node> nodes = db.getOrDefault(varnode, new ArrayList<Node>());
    if (def == null) {
      if (varnode.isConstant()) {
        nodes.add(new Node(VarnodeAdapter.getConstant(varnode)));
      } else {
        HighVariable hi = varnode.getHigh();
        if (hi != null) {
          nodes.add(new Node(varnode.getHigh().getName()));
        } else {
          nodes.add(new Node(varnode.toString()));
        }
      }
    } else {
      int parentOpcode = def.getOpcode();
      switch (parentOpcode) {
        case PcodeOp.INT_ADD:
        case PcodeOp.INT_MULT:
          for (Node a : db.get(def.getInput(0))) {
            for (Node b : db.get(def.getInput(1))) {
              nodes.add(new Node(parentOpcode, Arrays.asList(a, b)));
            }
          }
          break;
        case PcodeOp.LOAD:
          for (Node a : db.get(def.getInput(1))) {
            nodes.add(new Node(parentOpcode, Arrays.asList(a), def.getOutput().getSize()));
          }
          break;
        case PcodeOp.MULTIEQUAL:
        case PcodeOp.COPY:
        case PcodeOp.CAST:
          for (Varnode input : def.getInputs()) {
            for (Node a : db.get(input)) {
              nodes.add(a);
            }
          }
          break;
        case PcodeOp.INT_SEXT:
          for (Node a : db.get(def.getInput(0))) {
            nodes.add(new Node(parentOpcode, Arrays.asList(a)));
          }
          break;
        case PcodeOp.PTRADD:
          for (Node a : db.get(def.getInput(0))) {
            for (Node b : db.get(def.getInput(1))) {
              for (Node c : db.get(def.getInput(2))) {
                if (b.constant != null && c.constant != null) {
                  // guess we can
                  nodes.add(new Node(PcodeOp.INT_ADD, Arrays.asList(a, new Node(b.constant * c.constant))));
                } else {
                  nodes.add(new Node(parentOpcode, Arrays.asList(a, b, c)));
                }
              }
            }
          }
          break;
        case PcodeOp.PTRSUB:
          for (Node a : db.get(def.getInput(0))) {
            for (Node b : db.get(def.getInput(1))) {
              nodes.add(new Node(PcodeOp.INT_ADD, Arrays.asList(a, b)));
            }
          }
          break;
      }
    }
    db.put(varnode, nodes);
  }
}
