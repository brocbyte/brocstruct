# brocstruct

Brocstruct is a work-in-progress Ghidra script for automatic struct definition extraction from executables.

It is based on Ghidra's P-Code analysis and "theoretically" can work for all architectures supported by Ghidra itself.

The main idea is to track all LOAD/STORE accesses of the form *(arg + offset).
For now it works inside functions only (no interprocedural analysis).

There are already more mature plugins/scripts to do the same:
- https://github.com/grimm-co/gearshift
- https://github.com/NationalSecurityAgency/ghidra/blob/8dd0ea698ac8b9bc6a8d973d882c71037714e81e/Ghidra/Features/Decompiler/ghidra_scripts/CreateStructure.java