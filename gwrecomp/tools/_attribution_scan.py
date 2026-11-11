
import sys, re
def find_strings(path, maxs=40):
    out=set()
    try:
        with open(path,"rb") as f:
            data=f.read()
    except Exception as e:
        return f"ERR {e}"
    for m in re.finditer(rb"[\x20-\x7e]{5,}", data):
        s=m.group().decode()
        out.add(s)
    return out

samples_head = {
 "ADDRESS": r"E:\GWRecomp\evidence\space_recovery_20261007\ADDRESS_head.bin",
 "GW.ERR":  r"E:\GWRecomp\evidence\space_recovery_20261007\GW_ERR_head.bin",
}
host_exe = r"E:\GWRecomp\build\dosboxx-heavy\src\dosbox-x.exe"
guest = r"E:\GeneWarsFX\game\MAIN.EXE"  # try common path; will fallback

# locate guest exe
import glob, os
guest_candidates = []
for base in [r"E:\GeneWarsFX"]:
    for root,_,files in os.walk(base):
        for f in files:
            if f.upper() in ("MAIN.EXE","GW.EXE") :
                guest_candidates.append(os.path.join(root,f))
print("guest candidates:", guest_candidates[:6])

def sig_in(path, sigs):
    strs = find_strings(path)
    if isinstance(strs,str): return {s:strs for s in sigs}
    return {s:(s in strs) for s in sigs}

addr_sigs = ["offsetFunction","c:\\address.txt","address.txt","ADDRESS","function offset","could not","ERROR"]
gwerr_sigs = ["GENEWARS ERROR LOG","Could not read config.ini","config.ini","GENEWARS","error log"]

print("\n== ADDRESS head sample signatures ==")
print(sig_in(samples_head["ADDRESS"], addr_sigs))
print("\n== GW.ERR head sample signatures ==")
print(sig_in(samples_head["GW.ERR"], gwerr_sigs))

# first 200 readable strings of each sample (to see header)
def head_strings(path, n=25):
    data=open(path,"rb").read(65536)
    seen=[]
    for m in re.finditer(rb"[\x20-\x7e]{4,}", data):
        seen.append(m.group().decode())
        if len(seen)>=n: break
    return seen
print("\n== ADDRESS first strings ==", head_strings(samples_head["ADDRESS"]))
print("\n== GW.ERR first strings ==", head_strings(samples_head["GW.ERR"]))

# Now check which binary owns the key literals
print("\n== host dosbox-x.exe owns? ==")
if os.path.exists(host_exe):
    print(sig_in(host_exe, ["offsetFunction","GENEWARS ERROR LOG","Could not read config.ini"]))
else:
    print("host exe missing:", host_exe)
for g in guest_candidates[:2]:
    print(f"\n== guest {g} owns? ==")
    print(sig_in(g, ["offsetFunction","GENEWARS ERROR LOG","Could not read config.ini","c:\\address.txt"]))
