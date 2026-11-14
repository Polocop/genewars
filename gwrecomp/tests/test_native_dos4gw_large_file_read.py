"""Build and run the DOS/4GW extended INT 21h large-read contract test."""
import os as _gw_os
from pathlib import Path as _GwPath
_GW_MSYS2=_gw_os.environ.get("MSYS2_ROOT",r"C:\msys64")
import os
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]
GCC=Path((_GW_MSYS2 + '\\mingw32\\bin\\gcc.exe'))
EXE=ROOT/"build"/"test_native_dos4gw_large_file_read.exe"
ENV={**os.environ,"TEMP":str(ROOT/"cache"),"TMP":str(ROOT/"cache"),
     "PATH":(_GW_MSYS2 + '\\mingw32\\bin;' + _GW_MSYS2 + '\\usr\\bin;')+os.environ.get("PATH","")}

def run(args):
    p=subprocess.run([str(x) for x in args],cwd=ROOT,env=ENV,text=True,capture_output=True)
    print(p.stdout,end=""); print(p.stderr,end="")
    if p.returncode: raise SystemExit(p.returncode)

def main():
    run([GCC,"-std=gnu11","-m32","-O0","-I",ROOT/"runtime",
         "-I",ROOT/"third_party"/"pcrecomp"/"runtime"/"recomp32",
         "-o",EXE,ROOT/"tests"/"test_native_dos4gw_large_file_read.c",
         ROOT/"runtime"/"recomp_context.c",ROOT/"runtime"/"gw_pit8254.c",
         ROOT/"runtime"/"gw_segments.c",ROOT/"runtime"/"gw_interrupts.c",
         ROOT/"runtime"/"gw_dos_services.c"])
    run([EXE])

if __name__=="__main__": main()
