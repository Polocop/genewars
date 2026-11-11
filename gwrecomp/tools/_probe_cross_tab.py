import os as _gw_os
from pathlib import Path as _GwPath
_GW_ROOT=str(_GwPath(__file__).resolve().parents[1])

# _probe_cross_tab.py — cross-tab bare-mnemonic vs rep_prefix on the REAL closure
import sys, re
from pathlib import Path
root = Path((_GW_ROOT))
sys.path.insert(0, str(root/"src"))
sys.path.insert(0, str(root/"third_party"/"pcrecomp"))
from le_loader import load_le
from tools.disasm.disasm32 import Disassembler
from tools.pe.pe_analyze import Section

im = load_le(root/"evidence"/"genewars-1_1.exe")
obj = im.objects[0]
START = obj.base; END = START + obj.virtual_size
code = bytes(im.mem[START-im.mem_base : END-im.mem_base])
sec = Section(".text", obj.base, obj.virtual_size, 0, obj.virtual_size, 0x20000020)
ds = Disassembler(code, 0, [sec])

# independent control from lifted C
CLOSURE = root/"build"/"entry_path_closure.c"
tx = CLOSURE.read_text(encoding="utf-8", errors="replace")
control = {
  "repne_scasb": len(re.findall(r"\brepne\s+scasb\b", tx, re.I)),
  "repe_cmpsb":  len(re.findall(r"\brepe\s+cmpsb\b", tx, re.I)),
  "rep_stos":    len(re.findall(r"\brepe?ne?\s+stos[wd]\b", tx, re.I)),
  "neg":         len(re.findall(r"\bneg\s", tx, re.I)),
  "sbb":         len(re.findall(r"\bsbb\s", tx, re.I)),
  "adc":         len(re.findall(r"\bADC\s", tx, re.I)),
}
print("INDEPENDENT CONTROL (regex on lifted C):", control)

# Now walk ALL decoded instructions across the whole code range (not just closure
# functions) to see what capstone reports: bare mnemonic vs folded mnemonic.
from collections import Counter
bare = Counter(); folded = Counter(); rep_by_bare = Counter()
STRING_OPS = {"scasb","scasw","scasd","cmpsb","cmpsw","cmpsd",
              "stosb","stosw","stosd","movsb","movsw","movsd"}
REPB = {0xF2:"REPNE",0xF3:"REPE"}
# decode over the whole code buffer in one sweep
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = False
n=0
for insn in md.disasm(code, START):
    n+=1
    mn = insn.mnemonic
    parts = mn.split()
    base = parts[-1] if parts else mn
    if base in STRING_OPS:
        bare[base]+=1
        folded[mn]+=1
        b0 = code[insn.address-START]
        rp = REPB.get(b0)
        if rp:
            rep_by_bare[base]+=1
    if n>2000000: break
print("total decoded:", n)
print("\n=== bare-mnemonic counts (STRING_OPS base) ===")
for k,v in sorted(bare.items()): print(f"  {k:8s} {v}")
print("\n=== full folded mnemonic counts ===")
for k,v in sorted(folded.items()): print(f"  {k:14s} {v}")
print("\n=== rep-prefixed (via code[addr-START]) by base op ===")
for k,v in sorted(rep_by_bare.items()): print(f"  {k:8s} {v}")

print("\n=== DIAGNOSIS ===")
print("Does capstone FOLD the rep prefix into the mnemonic?")
print("  folded keys containing 'rep':", [k for k in folded if "rep" in k])
print("  bare keys containing 'rep':  ", [k for k in bare if "rep" in k])
print("  -> If bare has NO 'rep' keys, the tool's `m in STRING_OPS` (bare) is TRUE")
print("     but rep_prefix() reads code[addr-START]; capstone addr points at prefix so it works,")
print("     UNLESS the rep-prefixed insns are NOT in the decoded closure functions (only in full sweep).")
