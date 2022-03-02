# IDA Practical Cheatsheet

A few practical use-cases of IDA scripting.

## IDA Python

### Get minimum and maximum address

```python
import ida_idaapi

ea_inf = ida_idaapi.get_inf_structure()
min_ea = ea_inf.min_ea
max_ea = ea_inf.max_ea
```

### Iterate over segments and print their names

```python
import ida_segment
import idautils

for seg_ea in idautils.Segments():
  seg = ida_segment.getseg(seg_ea)
  seg_name = ida_segment.get_segm_name(seg)
  print(f"Current segment: {seg_name}")
```

### Iterate over all instructions

#### All executable code (scan full memory)

```python
import idautils
import ida_bytes

for ea in idautils.Heads(): # Iterate over all heads
  flags = ida_bytes.get_flags(ea)
  if ida_bytes.is_code(flags): # Check that ea is located in executable zone
    pass # Do stuff
```

#### Instructions in functions (scan all functions)

```python
import idautils

for func_ea in idautils.Functions(): # Iterate over all functions
  for item_ea in idautils.FuncItems(func_ea): # List all instructions in function
    pass # Do stuff
```

### Create function at specific location

```python
import ida_funcs

ida_funcs.add_func(ea) # i.e ea = 0x424242
```

### Decode instruction at specific location

```python
import idautils
import ida_allins

insn = idautils.DecodeInstruction(ea) # i.e ea = 0x424242

# List operands
for op in insn.ops:
  pass # Do stuff

# Check instruction type
if insn.itype == ida_allins.NN_movs:
  print("Instruction is movs")
  if insn.auxpref & 2:
    print("Instruction has rep prefix")
    
# Get instruction mnemonic name
insn_mnemonic = insn.get_canon_mnem()
```

### Add comment at specific location

```python
import ida_bytes

ida_bytes.set_cmt(ea, "Comment", 0)
```
