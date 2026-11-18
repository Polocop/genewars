import os as _gw_os
from pathlib import Path as _GwPath
_GW_MSYS2=_gw_os.environ.get("MSYS2_ROOT",r"C:\msys64")
import os
import pathlib
import subprocess

ROOT=pathlib.Path(__file__).resolve().parents[1]
EXE=ROOT/"build"/"test_interrupt_flag_roundtrip.exe"
ENV={**os.environ,
    "TEMP":str(ROOT/"cache"),"TMP":str(ROOT/"cache"),"TMPDIR":str(ROOT/"cache"),
    "PATH":(_GW_MSYS2 + '\\mingw32\\bin;' + _GW_MSYS2 + '\\usr\\bin;')+os.environ.get("PATH","")}

def main():
    (ROOT/"cache").mkdir(exist_ok=True)
    cmd=[(_GW_MSYS2 + '\\mingw32\\bin\\gcc.exe'),"-std=gnu11","-m32","-O0",
        "-I",str(ROOT/"runtime"),
        "-I",str(ROOT/"third_party"/"pcrecomp"/"runtime"/"recomp32"),
        "-o",str(EXE),str(ROOT/"tests"/"test_interrupt_flag_roundtrip.c"),
        str(ROOT/"runtime"/"gw_interrupts.c")]
    p=subprocess.run(cmd,cwd=ROOT,env=ENV,text=True,capture_output=True)
    if p.returncode:
        print(p.stdout,end=""); print(p.stderr,end="")
        raise SystemExit(p.returncode)
    p=subprocess.run([str(EXE)],cwd=ROOT,env=ENV,text=True,capture_output=True)
    print(p.stdout,end=""); print(p.stderr,end="")
    if p.returncode: raise SystemExit(p.returncode)

if __name__=="__main__": main()
