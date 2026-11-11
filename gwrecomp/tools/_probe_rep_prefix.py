import os as _gw_os
from pathlib import Path as _GwPath
_GW_ROOT=str(_GwPath(__file__).resolve().parents[1])

# probe_rep_prefix.py — discriminating test for the P05/P06 false negative
import sys, re
root = (_GW_ROOT)
sys.path.insert(0, root + r"\src")
sys.path.insert(0, root + r"\third_party\pcrecomp")
from le_loader import load_le
from tools.disasm.disasm32 import Disassembler
from tools.pe.pe_analyze import Section

im  = load_le(root + r"\evidence\genewars-1_1.exe")
obj = im.objects[0]
START = obj.base
END   = START + obj.virtual_size
code  = bytes(im.mem[START - im.mem_base : END - im.mem_base])
print("START=%#x END=%#x len(code)=%d" % (START, END, len(code)))

# Direct byte scan for rep-prefixed string ops in the tool's own code buffer
# scasb=AE, cmpsb=A6, stosw=AB, stosb=AA, scasd=AF
REPNE, REPE = 0xF2, 0xF3
hits = []
i = 0
n = len(code)
while i < n - 1:
    b0 = code[i]
    b1 = code[i+1]
    if b0 in (REPNE, REPE) and b1 in (0xAE, 0xA6, 0xAB, 0xAA, 0xAF):
        va = START + i
        hits.append((va, i, b0, b1))
        i += 2
    else:
        i += 1
# de-dup (a 3-byte rep lock prefix would double count; just keep first per va)
seen=set(); uniq=[]
for va,i,b0,b1 in hits:
    if va in seen: continue
    seen.add(va); uniq.append((va,i,b0,b1))
print("byte-scan rep-prefixed string ops found:", len(uniq))
for va,i,b0,b1 in uniq[:20]:
    print("  va=%#x codeoff=%d b0=%#x b1=%#x  | code[i]=%#x code[i+1]=%#x" % (va,i,b0,b1,code[i],code[i+1]))

# Now take ONE real VA and run it through the tool's Disassembler + rep_prefix
testva = uniq[0][0] if uniq else None
print("\n=== Discriminating test on va=%#x ===" % testva)
sec = Section(".text", obj.base, obj.virtual_size, 0, obj.virtual_size, 0x20000020)
ds  = Disassembler(code, 0, [sec])
# decode at testva with a fresh capstone to see address/mnemonic/bytes
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail=True
off = testva - START
data = code[off:off+16]
for insn in md.disasm(data, testva):
    print("capstone: addr=%#x size=%d mnemonic=%r op=%r bytes=%s prefixes=%s" %
          (insn.address, insn.size, insn.mnemonic, insn.op_str, bytes(insn.bytes).hex(),
           getattr(insn,'prefixes',None) if hasattr(insn,'prefixes') else 'N/A'))
    break
# the tool's rep_prefix
REPB = {0xF2:"REPNE",0xF3:"REPE"}
def rep_prefix(va):
    b0 = code[va - START]
    return REPB.get(b0)
print("tool rep_prefix(testva) ->", rep_prefix(testva))
print("code[testva-START] = %#x ; expected prefix byte = %#x" % (code[testva-START], code[uniq[0][2]]))

# Now decode via the tool's own disassemble_at at testva
print("\n=== tool disassemble_at(%#x) first insn ===" % testva)
gen = ds.disassemble_at(testva, max_bytes=64)
it0 = next(gen, None)
if it0:
    print("addr=%#x size=%d mnem=%r op=%r bytes=%s" % (it0.address, it0.size, it0.mnemonic, it0.op_str, it0.bytes.hex() if it0.bytes else ''))
    print("rep_prefix(it0.address) ->", rep_prefix(it0.address))
    print("MISMATCH?" , (it0.address != testva))
