"""Direct AH=43 fail-closed tests plus the native -k continuation replay."""
import json, os, pathlib, subprocess, sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
GCC=pathlib.Path(r"E:\msys64\mingw32\bin\gcc.exe")
EXE=ROOT/"build"/"test_native_dos_ah43_contract.exe"
ENV={**os.environ,"PYTHONDONTWRITEBYTECODE":"1","TEMP":os.environ.get("TEMP",str(ROOT/"cache")),"TMP":os.environ.get("TEMP",str(ROOT/"cache")),"TMPDIR":os.environ.get("TEMP",str(ROOT/"cache")),"GW_TASK_TEMP":os.environ.get("TEMP",str(ROOT/"cache")),"PATH":r"E:\msys64\mingw32\bin;E:\msys64\usr\bin;"+os.environ.get("PATH","")}
cmd=[str(GCC),"-std=gnu11","-m32","-O0","-I",str(ROOT/"runtime"),"-I",str(ROOT/"third_party"/"pcrecomp"/"runtime"/"recomp32"),"-o",str(EXE),str(ROOT/"tests"/"test_native_dos_ah43_contract.c"),str(ROOT/"runtime"/"gw_segments.c"),str(ROOT/"runtime"/"gw_interrupts.c"),str(ROOT/"runtime"/"gw_dos_services.c")]
p=subprocess.run(cmd,cwd=ROOT,env=ENV,text=True,capture_output=True)
if p.returncode: raise AssertionError(p.stdout+p.stderr)
p=subprocess.run([str(EXE)],cwd=ROOT,env=ENV,text=True,capture_output=True)
if p.returncode: raise AssertionError(p.stdout+p.stderr)
args=[sys.executable,str(ROOT/"tests"/"test_native_guest_image.py"),"--command-tail=-k","--evidence-name=native_dos_ah43_frontier_work2.json","--continue-known-services","--continue-selector-query","--continue-time-query","--continue-dpmi-linear-allocation","--continue-dos-ah48","--continue-dos-ah48-retry","--cd-present-fixture","--reuse-compiled-closure"]
p=subprocess.run(args,cwd=ROOT,env=ENV,text=True,capture_output=True)
if p.returncode: raise AssertionError(p.stdout+p.stderr)
data=json.loads((ROOT/"evidence"/"native_dos_ah43_frontier_work2.json").read_text(encoding="utf-8"))
svc=data["native_generated_c_progress"]["dos_ah43"]
assert svc and svc["request_eax"]=="0x00004300" and svc["path"]=="gw.err"
assert svc["response_eax"]=="0x00000003" and svc["cf_out"]==1 and svc["handled"]==1 and svc["all_other_gprs_preserved"]
assert data["native_generated_c_progress"]["next_frontier"]["instruction_va"]!="0x000AF93A"
fixture=data["native_generated_c_progress"]["cd_fixture_preflight"]
assert fixture and fixture["cue_read_only_mount"] and fixture["flat_data_text_alias_present"] is False
print(p.stdout,end="")
print("PASS native AH=43 exact gw.err result and continued to "+data["native_generated_c_progress"]["next_frontier"]["instruction_va"])
