"""Run original GeneWars 1.1 LbFileOpen over the exact-build read-only VFS."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"src"))
from le_loader import load_le

TARGET=ROOT/"evidence"/"genewars-1_1.exe"
EXPECTED_TARGET="2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
INSTALL=Path(r"<GENEWARS_INSTALL_DIR>")
RESOURCES={
    "GW.EXE":"2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f",
    "DATA/IFTITLE.ANB":"c7d2dfc5d774c69337436249ec74e4d0fa6ae1d06bd5ae785f9f73ee2ac0f707",
    "DATA/TITLESCR.DAT":"2548b024fede333b49fc4011541939fc8ce294cb95b48cdb41ed7d0cec54a0b9",
    "DATA/TITLESCR.PAL":"d5ec91e731c2ff7e8d74dbbde6a3fe0410ec602ff0da52eb1e6f6bb1a44307c7",
    "DATA/TEXT.DAT":"17fd1cc1eb502e629765ae7a18251750592871dcb7c76f95ad9a610858808c47",
    "DATA/SPEC/HARCH.ANB":"629a6471e4deabec794f0cffa34b513eea15013ee95927e67b02a4a7e6157b6a",
    "DATA/FONT2.DAT":"2f3d275f88f2ff6671562a819cbc7a791b16ad4510a4020f3b6078c917f60dba",
    "DATA/FONT2.TAB":"f54057e1b19cc1711a1596b6459cfdfb359a170f5ed739df71fd852befba4bab",
}

def digest(path:Path)->str: return hashlib.sha256(path.read_bytes()).hexdigest()

def run(argv:list[str])->subprocess.CompletedProcess[str]:
    p=subprocess.run([str(x) for x in argv],cwd=ROOT,text=True,capture_output=True)
    if p.returncode:
        if p.stdout: print(p.stdout,end="")
        if p.stderr: print(p.stderr,end="")
        raise SystemExit(p.returncode)
    return p

def main()->None:
    if digest(TARGET)!=EXPECTED_TARGET: raise SystemExit("canonical 1.1 LE hash changed")
    resources={}
    for rel,expected in RESOURCES.items():
        path=INSTALL/Path(rel)
        actual=digest(path)
        if actual!=expected: raise SystemExit(f"local 1.1 installation input changed: {rel} {actual}")
        resources[rel]={"path":str(path),"sha256":actual,"size":path.stat().st_size,
                        "provenance":"local installation whose GW.EXE hash equals the canonical 1.1 target"}

    generated=ROOT/"work"/"recompiled_file_open_lift.c"
    report=ROOT/"work"/"recompiled_file_open_lift.json"
    run([ROOT/".venv"/"Scripts"/"python.exe",ROOT/"tools"/"lift_entry_path.py",
         "--object-map","measured-1-3","--partial-root","0x98C70","--partial-root","0x98D70",
         "--partial-root","0xBC1F6","--partial-root","0xC3584","--partial-root","0xC3882",
         "--stack-range","0x3FD000:0x3000","--dynamic-range","0x2DA000:0xA8C50",
         "--dynamic-range","0x390000:0x10000",
         "--output-c",generated,"--report",report])
    lift=json.loads(report.read_text(encoding="utf-8"))
    if lift["missing_or_unsupported"] or lift["partial_rejections"] or lift["unresolved_direct_calls"]:
        raise SystemExit("original LbFileOpen closure is not complete within verified objects")
    lifted={int(row["address"],16) for row in lift["lifted"]}
    required={0x98C70,0x98C50,0x98D70,0xBABF4,0xAFC8D,0xBAB3B,0xBAB48,0xAFF18,0xC896A,0xC8991,0xC89E6}
    if not required.issubset(lifted): raise SystemExit(f"missing original open closure {sorted(required-lifted)}")

    image=load_le(TARGET,object_rebases={1:0x1EB000,3:0x1DA000})
    if image.mem_base!=0xF0000 or len(image.mem)+image.mem_base>0x400000:
        raise SystemExit("the bounded test guest image extent changed")
    guest=ROOT/"work"/"recompiled_file_open_guest.bin"
    guest.write_bytes(image.mem)
    exe=ROOT/"build"/"test_recompiled_file_open.exe"
    env={**os.environ,"PATH":r"E:\msys64\mingw32\bin;E:\msys64\usr\bin;"+os.environ.get("PATH","")}
    command=[r"E:\msys64\mingw32\bin\gcc.exe","-std=gnu11","-m32","-O0",
        "-I",ROOT/"runtime","-I",ROOT/"third_party"/"pcrecomp"/"runtime"/"recomp32",
        "-o",exe,ROOT/"tests"/"test_recompiled_file_open.c",generated,
        ROOT/"runtime"/"recomp_context.c",ROOT/"runtime"/"gw_interrupts.c",
        ROOT/"runtime"/"gw_segments.c",ROOT/"runtime"/"gw_pit8254.c",
        ROOT/"runtime"/"gw_dos_services.c"]
    built=subprocess.run([str(x) for x in command],cwd=ROOT,env=env,text=True,capture_output=True)
    if built.stdout: print(built.stdout,end="")
    if built.stderr: print(built.stderr,end="")
    if built.returncode: raise SystemExit(built.returncode)
    p=subprocess.run([str(exe),str(guest),str(INSTALL)],cwd=ROOT,env=env,text=True,capture_output=True)
    if p.stdout: print(p.stdout,end="")
    if p.stderr: print(p.stderr,end="")
    if p.returncode: raise SystemExit(p.returncode)
    readback=ROOT/"work"/"recompiled_file_open_readback.bin"
    if digest(readback)!=RESOURCES["DATA/IFTITLE.ANB"]:
        raise SystemExit("bytes returned by original recompiled LbFileRead_ differ from the verified installation resource")

    evidence={"schema":"gw-recompiled-original-file-open/v1","target_sha256":EXPECTED_TARGET,
        "map_sha256":"30e06c203154904740c4ff3f1fcc4971fb6c0ef10ace2f4f9dc63367d45b99b3",
        "resource_inputs":resources,"rea":{"provider":"REA 6.4.0 / Ghidra 12.1.4",
            "LbFileOpen":"ev_d71ebcb1f6b9bc80282a5d6ca8531696f176e610494d40c0dc374448efc853e8",
            "sopen":"ev_4f541b06081d964321e4faf0eb5b63cfb151a19e9d993fa13eb70e6d7bf5736a",
        "read":"ev_87d5d0230188234c8d46a669fd3bf8190ae3a81d5514436f20239446896179f1"},
        "execution":{"function":"LbFileOpen","link_va":"0x98C70","instructions":"original 1.1 partial lift",
            "path_source":"titleGfx_files[0], a verified 44-byte TbLoadFiles record at link VA 0x105EE8 / guest linear 0x2DFEE8",
            "read_function":"LbFileRead_","read_link_va":"0x98D70","readback_guest_va":"0x390000",
            "readback_bytes":30050,"readback_sha256":digest(readback),
            "vfs":"allowlisted read-only local exact-build installation","stdout":p.stdout.strip()},
        "dos_open_contract":{"ah":"0x3D","original_al":"0x40","meaning":"read access, DOS compatibility sharing mode",
            "runtime_change":"decode AL access, sharing, inheritance and reserved bits separately; pass read-only access to the VFS"},
        "passed":True}
    out=ROOT/"evidence"/"recompiled_original_file_open.json"
    out.write_text(json.dumps(evidence,indent=2)+"\n",encoding="utf-8")
    print(f"evidence: {out}")

if __name__=="__main__": main()
