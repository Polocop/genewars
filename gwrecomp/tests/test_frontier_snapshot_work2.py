"""Capture a native frontier and prove v1 compatibility checks reject drift."""
import os as _gw_os
from pathlib import Path as _GwPath
_GW_MSYS2=_gw_os.environ.get("MSYS2_ROOT",r"C:\msys64")
import json, os, pathlib, shutil, subprocess, sys, tempfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from frontier_snapshot import validate_snapshot

def main():
    env={**os.environ,"PYTHONDONTWRITEBYTECODE":"1","GW_TASK_TEMP":os.environ.get("TEMP",str(ROOT/"cache")),"PATH":(_GW_MSYS2 + '\\mingw32\\bin;' + _GW_MSYS2 + '\\usr\\bin;')+os.environ.get("PATH","")}
    cmd=[sys.executable,str(ROOT/"tests"/"test_native_guest_image.py"),"--command-tail=-k","--evidence-name=frontier_snapshot_v1_native_run.json","--continue-known-services","--continue-selector-query","--continue-time-query","--continue-dpmi-linear-allocation","--continue-dos-ah48","--continue-dos-ah48-retry","--cd-present-fixture","--snapshot-frontier-v1","--reuse-compiled-closure"]
    p=subprocess.run(cmd,cwd=ROOT,env=env,text=True,capture_output=True)
    if p.returncode: raise AssertionError(p.stdout+p.stderr)
    path=ROOT/"evidence"/"frontier_snapshot_v1_work2.json"
    snap=validate_snapshot(path,ROOT,{"eip":"0x000AF93A"})
    assert snap["memory"]["size"]==0x200000 and snap["psp_mcb"]["mcb_bytes_sha256"]
    assert snap["cpu"]["es"]=="0014" and snap["cpu"]["eip"]=="000af93a"
    assert snap["dos_dpmi_allocator"]["state"]["measured_ah48_active"]=="1" and not snap["dos_dpmi_allocator"]["owned_dos_blocks"]
    assert snap["handles"]["availability"]=="not_modeled_by_native_runner_at_this_frontier"
    for expected,message in [({"target_sha256":"0"*64},"incompatible target"),({"runtime_sha256":"f"*64},"incompatible runtime"),({"generated_code_sha256":"1"*64},"incompatible generated"),({"config_sha256":"2"*64},"incompatible config"),({"cue_sha256":"3"*64},"incompatible cue"),({"eip":"0x000C3D42"},"incompatible EIP")]:
        try: validate_snapshot(path,ROOT,expected)
        except ValueError as e:
            if message.split()[1] not in str(e): raise
        else: raise AssertionError("snapshot accepted "+message)
    with tempfile.TemporaryDirectory() as td:
        temp=pathlib.Path(td); bad=json.loads(path.read_text()); bad_mem=temp/"memory.bin"; bad_mem.write_bytes(b"broken"); bad["memory"]["path"]=str(bad_mem); bad_path=temp/"bad.json"; bad_path.write_text(json.dumps(bad))
        try: validate_snapshot(bad_path,ROOT)
        except ValueError as e:
            if "hash/size" not in str(e): raise
        else: raise AssertionError("snapshot accepted changed memory payload")
    print(p.stdout,end="")
    print("PASS frontier snapshot v1: full memory, CPU/descriptors/allocators and fixture fingerprints captured; incompatible identities/EIP/memory rejected")
if __name__=="__main__": main()






