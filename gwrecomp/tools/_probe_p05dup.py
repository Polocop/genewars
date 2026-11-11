
import re
from pathlib import Path
root = Path(r"E:\GWRecomp")
tx = (root/"build"/"entry_path_closure.c").read_text(encoding="utf-8",errors="replace")
lines = tx.splitlines()
# Every line that contains literal 'repne scasb'
lit = [(i, ln) for i,ln in enumerate(lines,1) if re.search(r"repne\s+scasb", ln, re.I)]
anch = [(i,ln) for i,ln in enumerate(lines,1) if re.search(r"0x[0-9A-Fa-f]{5,8}\s*:\s*repne\s+scasb", ln, re.I)]
print("literal-text lines:", len(lit))
print("VA-anchored lines :", len(anch))
# Show the lines that are literal-but-not-VA-anchored (the suspected duplicate/extra)
anch_set = set(i for i,_ in anch)
extra = [(i,ln.strip()[:130]) for i,ln in lit if i not in anch_set]
print("literal but NOT va-anchored (the 30th):")
for i,ln in extra: print(f"  L{i}: {ln}")
# and show one normal va-anchored example
print("sample va-anchored:")
for i,ln in anch[:2]: print(f"  L{i}: {ln.strip()[:130]}")
# Count distinct VAs in the va-anchored set
vas = set()
for i,ln in anch:
    m=re.search(r"0x([0-9A-Fa-f]{5,8})\s*:\s*repne\s+scasb", ln, re.I)
    if m: vas.add(int(m.group(1),16))
print("distinct VA-anchored sites:", len(vas))
# literal count
print("literal total:", len(lit))
print("=> literal 30 - anchored 29 = 1 extra literal occurrence; verify it is the SAME instruction's text rendered twice (not a distinct instruction)")
