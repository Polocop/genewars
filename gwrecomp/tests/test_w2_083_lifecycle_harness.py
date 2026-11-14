"""Compile the undecided W2-083 harness and capture the current measured seam."""
import os as _gw_os
from pathlib import Path as _GwPath
_GW_MSYS2=_gw_os.environ.get("MSYS2_ROOT",r"C:\msys64")
import hashlib, json, os, pathlib, subprocess, sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
GCC=pathlib.Path((_GW_MSYS2 + '\\mingw32\\bin\\gcc.exe'))
EXE=ROOT/"build"/"w2_083_lifecycle_harness.exe"
OUT=ROOT/"evidence"/"w2_083_lifecycle_preflight.json"
ENV={**os.environ,"TEMP":str(ROOT/"cache"),"TMP":str(ROOT/"cache"),"TMPDIR":str(ROOT/"cache"),
     "PATH":(_GW_MSYS2 + '\\mingw32\\bin;' + _GW_MSYS2 + '\\usr\\bin;')+os.environ.get("PATH","")}
cmd=[str(GCC),"-std=gnu11","-m32","-O0","-I",str(ROOT/"runtime"),
     "-I",str(ROOT/"third_party"/"pcrecomp"/"runtime"/"recomp32"),"-o",str(EXE),
     str(ROOT/"tests"/"w2_083_lifecycle_harness.c"),str(ROOT/"runtime"/"gw_segments.c"),
     str(ROOT/"runtime"/"gw_interrupts.c"),str(ROOT/"runtime"/"gw_dos_services.c")]
p=subprocess.run(cmd,cwd=ROOT,env=ENV,text=True,capture_output=True)
if p.returncode: raise SystemExit(p.stdout+p.stderr)
r=subprocess.run([str(EXE)],cwd=ROOT,env=ENV,text=True,capture_output=True)
if r.returncode: raise SystemExit(r.stdout+r.stderr+f"\nexit={r.returncode}")
records=[json.loads(line) for line in r.stdout.splitlines() if line.startswith("{")]
phases={x["phase"]:x for x in records}
assert phases["ah48_state"]["descriptor_count"]==0 and phases["ah48_state"]["dos_block_count"]==0
assert phases["ah48_state"]["measured_value"]=="0x004c" and phases["ah48_state"]["mcb_bytes_available"] is False
assert phases["mov_es"]["accepted"] is False and phases["mov_es"]["fault_selector"]=="0x004c"
assert phases["ah49"]["result"]=="trapped" and phases["ah49"]["measured_active"]==1
OUT.write_text(json.dumps({"task":"W2-083-preflight","status":"preparation_only_contract_undecided",
    "target_sha256":hashlib.sha256((ROOT/"evidence"/"genewars-1_1.exe").read_bytes()).hexdigest(),
    "runtime_sha256":hashlib.sha256((ROOT/"runtime"/"gw_dos_services.c").read_bytes()).hexdigest(),
    "harness_sha256":hashlib.sha256((ROOT/"tests"/"w2_083_lifecycle_harness.c").read_bytes()).hexdigest(),
    "test_sha256":hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
    "command":cmd,"records":records,"stdout":r.stdout,"accepted":False,
    "note":"No selector/segment/base/limit/rights/owner semantics were inferred; no MCB byte buffer exists at this callback seam."},indent=2)+"\n",encoding="utf-8")
print(r.stdout,end="")
print("PASS W2-083 harness preflight: AH=48 observed, descriptor/MCB absence and ES/AH=49 fail-closed state captured; no semantics inferred")

