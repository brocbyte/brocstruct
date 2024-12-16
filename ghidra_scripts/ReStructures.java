// @author brocbyte
// @category BROCSTRUCT

import java.util.*;
import java.util.stream.Collectors;

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

import org.jgrapht.*;
import org.jgrapht.graph.*;
import org.jgrapht.traverse.*;

public class ReStructures extends GhidraScript {
  public void run() throws Exception {
    Listing listing = currentProgram.getListing();
    Function currentFunction = listing.getFunctionContaining(currentAddress);
    println("Analyzing function: " + currentFunction.getName());

    DecompInterface ifc = new DecompInterface();
    ifc.openProgram(currentProgram);
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
      }
      for (int i = 0; i < inputs.length; ++i) {
        g.addVertex(inputs[i]);
        if (output != null) {
          g.addEdge(inputs[i], output);
        }
      }
    }

    // for each varnode construct it's symbolic expression
    TopologicalOrderIterator<Varnode, DefaultEdge> topVIterator = new TopologicalOrderIterator<>(g);
    while (topVIterator.hasNext()) {
      process(topVIterator.next());
    }

    // dbg: collect all used opcodes
    Set<Integer> dbgOps = new HashSet<Integer>();
    for (PcodeOpAST op : pcodeOps) {
      dbgOps.add(op.getOpcode());
    }
    println("all ops used: " + dbgOps.stream().map(op -> PcodeOp.getMnemonic(op)).collect(Collectors.joining(", ")));

    List<Varnode> params = new ArrayList<Varnode>();
    LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
    for (int i = 0; i < localSymbolMap.getNumParams(); ++i) {
      params.add(localSymbolMap.getParam(i).getRepresentative());
    }
    if (params.isEmpty()) {
      println("Function has no parameters :(");
      return;
    }
    Map<String, Varnode> paramNames = new HashMap<String, Varnode>();
    for (Varnode param : params) {
      paramNames.put(param.getHigh().getName(), param);
    }
    List<String> paramNameStrings = new ArrayList<String>(paramNames.keySet());
    String choice = askChoice("Param selection", "Choose one", paramNameStrings, paramNameStrings.get(0));

    Varnode param = paramNames.get(choice);
    String paramName = param.getHigh().getName();
    println("digging " + paramName + " aka " + param.toString());
    Iterator<Varnode> dfs = new DepthFirstIterator<>(g, param);

    Map<Long, Map<Integer, Integer>> accesses = new HashMap<>();
    while (dfs.hasNext()) {
      Varnode varnode = dfs.next(); // varnode is a child of param
      List<Node> paths = db.get(varnode);
      for (Node path : paths) {
        if (path.opcode == PcodeOp.LOAD) {
          Node input = path.inputs.get(0);
          String baseName = getBaseName(input);
          Long offset = getOffset(input);
          printf("READ base: %s, offset: %d, size: %d\n", baseName, offset, path.bytesize);
          Map<Integer, Integer> sizes = accesses.getOrDefault(offset, new TreeMap<Integer, Integer>());
          Integer freq = sizes.getOrDefault(path.bytesize, 0) + 1;
          sizes.put(path.bytesize, freq);
          accesses.put(offset, sizes);
        }
      }
    }

    for (PcodeOpAST op : pcodeOps) {
      if (op.getOpcode() == PcodeOp.STORE) {
        Varnode dst = op.getInput(1);
        dfs = new DepthFirstIterator<>(g, param);
        boolean desired = false;

        while (dfs.hasNext()) {
          Varnode varnode = dfs.next();
          if (dst == varnode) {
            desired = true;
            break;
          }
        }
        if (desired) {
          List<Node> paths = db.get(dst);
          for (Node path : paths) {
            Node input = path;
            String baseName = getBaseName(input);
            Long offset = getOffset(input);
            int bytesize = op.getInput(2).getSize();
            if (baseName.isEmpty()) {
              baseName = "errrr -> " + input.toString();
            }
            printf("WRITE base: %s, offset: %d, size: %d\n", baseName, offset, bytesize);
            Map<Integer, Integer> sizes = accesses.getOrDefault(offset, new TreeMap<Integer, Integer>());
            Integer freq = sizes.getOrDefault(bytesize, 0) + 1;
            sizes.put(bytesize, freq);
            accesses.put(offset, sizes);
          }
        }
      }
    }

    println("===========");
    long structureSize = 0;
    for (Long offset : accesses.keySet()) {
      for (Map.Entry<Integer, Integer> entry : accesses.get(offset).entrySet()) {
        printf("base: %s, offset: 0x%x, size: 0x%x, count: %d\n", param.getHigh().getName(), offset, entry.getKey(),
            entry.getValue());
        structureSize = Math.max(structureSize, offset + entry.getKey());
      }
    }
    println("\n" + buildStructure(accesses, (int) structureSize, paramName));

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
    StructureDataType structureDataType = new StructureDataType(new CategoryPath("/struct"), "S_" + paramName, size);
    DataTypeManager dm = currentProgram.getDataTypeManager();
    BuiltInDataTypeManager bdm = BuiltInDataTypeManager.getDataTypeManager();
    Map<Integer, DataType> size_lookup = new HashMap<>();
    size_lookup.put(1, bdm.getDataType("/byte"));
    size_lookup.put(2, bdm.getDataType("/short"));
    size_lookup.put(4, bdm.getDataType("/int"));
    size_lookup.put(8, bdm.getDataType("/longlong"));
    for (Long offset : accesses.keySet()) {
      Map<Integer, Integer> sizes = accesses.get(offset);
      Integer size0 = Collections.max(sizes.entrySet(), Map.Entry.comparingByValue()).getKey();
      structureDataType.replaceAtOffset((int) offset.longValue(), size_lookup.get(size0), size0, "field" + offset, "");
    }
    dm.addDataType(structureDataType, DataTypeConflictHandler.REPLACE_HANDLER);
    return structureDataType.toString();
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
// opengl32.dll: FUN_18003fd34 <=> InternalDescribePixelFormat
// https://blog.grimm-co.com/2020/11/automated-struct-identification-with.html
// https://github.com/kohnakagawa/PracticalPCode
// https://riverloopsecurity.com/blog/2019/05/pcode/
// https://github.com/NationalSecurityAgency/ghidra/discussions/4944
// https://github.com/niconaus/pcode-interpreter
// https://www.ssrg.ece.vt.edu/papers/vstte22.pdf
// https://github.com/ksluckow/awesome-symbolic-execution
// https://www.msreverseengineering.com/blog/2019/8/5/automation-techniques-in-c-reverse-engineering

/*
 * 
 * Structure S_param_5 {
 * 0 int 4 field0 ""
 * 4 int 4 field4 ""
 * 8 char 1 field8 ""
 * 9 char 1 field9 ""
 * 10 int 4 field10 ""
 * 14 short 2 field14 ""
 * 16 char 1 field16 ""
 * 18 char 1 field18 ""
 * 20 char 1 field20 ""
 * 21 char 1 field21 ""
 * 22 char 1 field22 ""
 * 23 char 1 field23 ""
 * 24 int 4 field24 ""
 * 28 longlong 8 field28 ""
 * 36 int 4 field36 ""
 * }
 * 
 * typedef struct PIXELFORMATDESCRIPTOR
 * {
 * 0 WORD nSize;
 * 2 WORD nVersion;
 * 4 DWORD dwFlags;
 * 8 BYTE iPixelType;
 * 9 BYTE cColorBits;
 * 10 BYTE cRedBits;
 * 11 BYTE cRedShift;
 * 12 BYTE cGreenBits;
 * 13 BYTE cGreenShift;
 * 14 BYTE cBlueBits;
 * 15 BYTE cBlueShift;
 * 16 BYTE cAlphaBits;
 * 17 BYTE cAlphaShift;
 * 18 BYTE cAccumBits;
 * 19 BYTE cAccumRedBits;
 * 20 BYTE cAccumGreenBits;
 * 21 BYTE cAccumBlueBits;
 * 22 BYTE cAccumAlphaBits;
 * 23 BYTE cDepthBits;
 * 24 BYTE cStencilBits;
 * 25 BYTE cAuxBuffers;
 * 26 BYTE iLayerType;
 * 27 BYTE bReserved;
 * 28 DWORD dwLayerMask;
 * 32 DWORD dwVisibleMask;
 * 36 DWORD dwDamageMask;
 * }
 * 
 * 
 * 
 * typedef struct _DDSURFACEDESC aka param_
{
    DWORD		dwSize;			// size of the DDSURFACEDESC structure
    DWORD		dwFlags;		// determines what fields are valid
    DWORD		dwHeight;		// height of surface to be created
    DWORD		dwWidth;		// width of input surface
    LONG		lPitch;			// distance to start of next line (return value)
    DWORD		dwBackBufferCount;	// number of back buffers requested
    DWORD		dwZBufferBitDepth;	// depth of Z buffer requested
    DWORD		dwAlphaBitDepth;	// depth of alpha buffer requested
    DWORD		dwCompositionOrder;	// blt order for the surface, 0 is background
    DWORD		hWnd;			// window handle associated with surface
    DWORD		lpSurface;		// pointer to an associated surface memory
    DDCOLORKEY		ddckCKDestOverlay;	// color key for destination overlay use
    DDCOLORKEY		ddckCKDestBlt;		// color key for destination blt use
    DDCOLORKEY		ddckCKSrcOverlay;	// color key for source overlay use
    DDCOLORKEY		ddckCKSrcBlt;		// color key for source blt use
    DWORD		lpClipList;		// clip list (return value)
    DWORD		lpDDSurface;		// pointer to DirectDraw Surface struct (return value)
    DDPIXELFORMAT	ddpfPixelFormat; 	// pixel format description of the surface
    DDSCAPS		ddsCaps;		// direct draw surface capabilities
} DDSURFACEDESC;
 */