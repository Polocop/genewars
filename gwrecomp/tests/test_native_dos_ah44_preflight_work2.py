"""Compile the fast fail-closed AH=44 frontier harness and save evidence."""
import hashlib,json,os,pathlib,subprocess
ROOT=pathlib.Path(__file__).resolve().parents[1]
GCC=pathlib.Path(r"E:\msys64\mingw32\bin\gcc.exe")
EXE=ROOT/"build"/"test_native_dos_ah44_preflight.exe"
env={**os.environ,"PYTHONDONTWRITEBYTECODE":"1","TEMP":os.environ.get("TEMP",str(ROOT/"cache")),"TMP":os.environ.get("TEMP",str(ROOT/"cache")),"TMPDIR":os.environ.get("TEMP",str(ROOT/"cache")),"PATH":r"E:\msys64\mingw32\bin;E:\msys64\usr\bin;"+os.environ.get("PATH","")}
cmd=[str(GCC),"-std=gnu11","-m32","-O0","-I",str(ROOT/"runtime"),"-I",str(ROOT/"third_party"/"pcrecomp"/"runtime"/"recomp32"),"-o",str(EXE),str(ROOT/"tests"/"test_native_dos_ah44_preflight.c"),str(ROOT/"runtime"/"gw_segments.c"),str(ROOT/"runtime"/"gw_interrupts.c"),str(ROOT/"runtime"/"gw_dos_services.c")]
p=subprocess.run(cmd,cwd=ROOT,env=env,text=True,capture_output=True)
if p.returncode: raise SystemExit(p.stdout+p.stderr)
p=subprocess.run([str(EXE)],cwd=ROOT,env=env,text=True,capture_output=True)
if p.returncode: raise SystemExit(p.stdout+p.stderr)
ev={"task":"W2-087","target_sha256":"2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f","frontier":{"vector":"0x21","eip":"0x000C8973","eax":"0x00004400","ebx":"0x00000002","ecx":"0x00000000","edx":"0x00000001","esi":"0x0010A83C","edi":"0x001A8C44","ebp":"0x00000000","esp":"0x001A8B28","cs":"0x000C","ds":"0x0014","es":"0x0014","ss":"0x0014","cf":0},"contract_status":"unmeasured; fail-closed only","binary_sha256":hashlib.sha256(EXE.read_bytes()).hexdigest(),"pass":True,"stdout":p.stdout.strip()}
(ROOT/"evidence"/"native_dos_ah44_preflight_work2.json").write_text(json.dumps(ev,indent=2)+"\n",encoding="utf-8")
(ROOT/"reports"/"coordination"/"native_dos_ah44_preflight_work2.md").write_text("# W2-087 — AH=44 fail-closed preflight\n\nThe exact native frontier (`0x000C8973`, AH=44/AL=00, EBX=2) and nearby contexts stay trapped without GPR, CF, or segment mutation. This intentionally implements no AH=44 result semantics while the aligned oracle measurement is pending.\n\nTest: `tests/test_native_dos_ah44_preflight_work2.py` — PASS.\n\nEvidence: `evidence/native_dos_ah44_preflight_work2.json`.\n",encoding="utf-8")
print(p.stdout,end="")
