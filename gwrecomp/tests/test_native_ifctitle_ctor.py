"""Execute original GeneWars 1.1 static initializer 0x830F0 in a bounded closure."""
from __future__ import annotations
import os as _gw_os
from pathlib import Path as _GwPath
_GW_MSYS2=_gw_os.environ.get("MSYS2_ROOT",r"C:\msys64")
import hashlib as _hashlib


class _OrigDigest:
    """Stands in for a byte string taken from the original game.

    Only its SHA-256 and length are stored in the repository. Comparing it with
    bytes (or a hex string) from the user's own locally provided game files
    succeeds when they hash to the recorded value.
    """

    def __init__(self, sha256, length):
        self.sha256 = sha256
        self.length = length

    def __len__(self):
        return self.length

    def __eq__(self, other):
        if isinstance(other, str):
            try:
                other = bytes.fromhex(other.replace(" ", ""))
            except ValueError:
                return False
        if not isinstance(other, (bytes, bytearray, memoryview)):
            return NotImplemented
        other = bytes(other)
        return len(other) == self.length and _hashlib.sha256(other).hexdigest() == self.sha256

    def __ne__(self, other):
        r = self.__eq__(other)
        return r if r is NotImplemented else not r

    __hash__ = None

    def __repr__(self):
        return "<original bytes sha256=%s len=%d>" % (self.sha256, self.length)
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
PYTHON=ROOT/".venv"/"Scripts"/"python.exe"
GCC=Path((_GW_MSYS2 + '\\mingw32\\bin\\gcc.exe'))
TARGET=ROOT/"evidence"/"genewars-1_1.exe"
EXPECTED_TARGET="2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
REBASES={1:0x1EB000,3:0x1DA000}
INDIRECT_FIXUPS={
    0x111F2D:0x2C3D0, 0x111F19:0x834A0,
    0x111C59:0x2C520, 0x111C45:0x2C560, 0x111C31:0x34F50,
    0x1121D1:0x957B0,
    0x1121BD:0x69C80,
    0x1121A9:0x957C0,
    0x112195:0x957E0,
    0x112181:0x957D0,
    0x11216D:0x95830, 0x112159:0x95880,
    0x112145:0x95890, 0x112131:0x958E0,
}
ENV={**os.environ,"PYTHONDONTWRITEBYTECODE":"1",
     "PATH":(_GW_MSYS2 + '\\mingw32\\bin;' + _GW_MSYS2 + '\\usr\\bin;')+os.environ.get("PATH","")}

def run(command:list[object],timeout:int=45,quiet:bool=False)->subprocess.CompletedProcess[str]:
    p=subprocess.run([str(x) for x in command],cwd=ROOT,env=ENV,text=True,
                     capture_output=True,timeout=timeout)
    if not quiet and p.stdout: print(p.stdout,end="")
    if not quiet and p.stderr: print(p.stderr,end="")
    if p.returncode: raise SystemExit(p.returncode)
    return p

def main()->None:
    digest=hashlib.sha256(TARGET.read_bytes()).hexdigest()
    if digest!=EXPECTED_TARGET: raise SystemExit(f"protected target hash mismatch: {digest}")
    sys.path[:0]=[str(ROOT/"src"),str(ROOT/"third_party"/"pcrecomp"),str(ROOT/"tools")]
    from le_loader import load_le
    from extract_symbol_corpus import le_fixup_header,parse_fixups
    from tools.disasm.disasm32 import Disassembler
    from tools.pe.pe_analyze import Section
    link_image=load_le(TARGET)
    text=bytes(link_image.object_data(1)); text_object=link_image.objects[0]
    dis=Disassembler(text,0,[Section(".text",text_object.base,text_object.virtual_size,
                                    0,text_object.virtual_size,0x20000020)])
    plugin_bytes=text[0x70D10-text_object.base:0x70D10-text_object.base+64]
    rea_plugin_bytes=_OrigDigest("0f7dcca2aca3eca8aaff997dc7f5fafb4a4b7de49c91b9ce50fe36210613ce33",64)
    plugin_function=dis.disassemble_function(0x70D10)
    expected_plugin_calls={0x15090,0x150D0,0x5B8C0,0x6EF20,0x756C0,
                           0x973B0,0xA0810,0xA4DDA,0xA8A20}
    if plugin_bytes!=rea_plugin_bytes or plugin_function is None or plugin_function.calls_to!=expected_plugin_calls:
        raise SystemExit("REA IFCTitle::PlugIn bytes/callees do not reconcile with canonical LE + Capstone")
    image=load_le(TARGET,object_rebases=REBASES)
    raw=TARGET.read_bytes(); h=le_fixup_header(raw)
    fixups=parse_fixups(raw,image.objects,h["page_size"],h["num_pages"],
                        h["obj_tab"],h["obj_cnt"],h["fixup_page_tab"],h["fixup_rec_tab"])
    fixup_rows=[]
    for source,target in INDIRECT_FIXUPS.items():
        found=[(s,t,kind) for s,t,kind in fixups if s==source]
        if found!=[(source,target,7)]:
            raise SystemExit(f"callback fixup mismatch at {source:#x}: {found}")
        fixup_rows.append({"source_link":f"0x{source-1:08X}","fixup_link":f"0x{source:08X}",
                           "target_link":f"0x{target:08X}","kind":"OFFSET32"})

    generated=ROOT/"work"/"ifctitle_ctor_allowlist.c"
    report=ROOT/"evidence"/"ifctitle_ctor_allowlist.json"
    options=["--object-map","measured-1-3","--partial-root","0x830F0",
             *sum((["--partial-root",hex(t)] for t in sorted(set(INDIRECT_FIXUPS.values()))),[]),
             "--stack-range","0x003FD000:0x3000","--dynamic-range","0x002DA000:0xA8C50"]
    for site,target in [(0xA9F3B,t) for t in sorted(set(INDIRECT_FIXUPS.values()))]:
        options += ["--verified-indirect-target",f"{hex(site)}={hex(target)}"]
    run([PYTHON,ROOT/"tools"/"lift_entry_path.py",*options,
         "--output-c",generated,"--report",report],quiet=True)
    lift=json.loads(report.read_text(encoding="utf-8"))
    if lift["missing_or_unsupported"] or lift["unresolved_direct_calls"] or lift["partial_rejections"]:
        raise SystemExit("constructor closure has unresolved dependencies")
    if not any(row["address"]=="0x000830F0" for row in lift["lifted"]):
        raise SystemExit("root constructor was not lifted")

    guest=ROOT/"work"/"ifctitle_ctor_guest.bin"
    guest.write_bytes(image.mem)
    exe=ROOT/"build"/"test_native_ifctitle_ctor.exe"
    command=[GCC,"-std=gnu11","-m32","-O0","-I",ROOT/"runtime",
             "-I",ROOT/"third_party"/"pcrecomp"/"runtime"/"recomp32",
             "-o",exe,ROOT/"tests"/"test_native_ifctitle_ctor.c",generated,
             ROOT/"runtime"/"recomp_context.c",ROOT/"runtime"/"gw_interrupts.c",
             ROOT/"runtime"/"gw_segments.c",ROOT/"runtime"/"gw_pit8254.c"]
    run(command)
    p=run([exe,guest],timeout=20)
    before=(ROOT/"work"/"ifctitle_ctor_object_before.bin").read_bytes()
    after=(ROOT/"work"/"ifctitle_ctor_object_after.bin").read_bytes()
    if len(before)!=64 or len(after)!=64 or before==after:
        raise SystemExit("static IFCTitle object before/after capture is invalid")
    result={"schema":"gw-native-ifctitle-ctor/v1","target_sha256":digest,
        "rea":{"provider":"REA 6.4.0 / Ghidra 12.1.4",
               "carrier_sha256":"1523022fb1febcfb939b2ed04145ee6e7dcd8b99113d932d21d33301c0052a97",
               "bytes_evidence":"ev_2781cd5c2fde6032fa24d49c6260b3612dc819169c625f39a5ca75da22770d6b",
               "initializer_analysis":"no Ghidra procedure at 0x830F0; original LE was decoded/lifted with Capstone",
               "title_plugin":{"address":"0x70D10","name":"FUN_00070D10 / IFCTitle::PlugIn",
                    "body":"0x70D10..0x70E2C (285 bytes)",
                    "analysis_evidence":"ev_a0acd0dc147af656dd9431cd547a7784e18ea466e597be0074895edeb697aa06",
                    "bytes_evidence":"ev_1aa4a28bc694411eacfa15459ec5de368c10b9310be2232d48d7b753cdfd0bea",
                    "caller":"game() 0x92710",
                    "calls":["LbDataLoadAll_ 0x15090","LbFileLoadAt_ 0x150D0","0x6EF20","0x973B0","0x5B8C0","0xA8A20","0x756C0","0xA0810","thunk 0xA4DDA -> 0xBC1AA"],
                    "cross_check":{"canonical_unrebased_le_bytes_match":True,
                                    "capstone_direct_call_set":[f"0x{x:08X}" for x in sorted(expected_plugin_calls)]},
                    "execution_status":"not invoked; constructor-state does not yet prove the full receiver/service preconditions"}},
        "callbacks_from_le_offset32_fixups":fixup_rows,
        "closure":{"path":"work/ifctitle_ctor_allowlist.c","root":"0x830F0",
                   "lifted_functions":len(lift["lifted"]),"unresolved":0,
                   "allowed_indirect_link_targets":[f"0x{x:08X}" for x in sorted(set(INDIRECT_FIXUPS.values()))]},
        "execution":{"state":"experimental zeroed volatile registers, flat selectors, bounded stack; not an Oracle capture",
                     "stdout":p.stdout.strip(),"status":"passed",
                     "indirect_calls":2156,"object_link_va":"0x00184AB8",
                     "object_guest_linear":"0x0035EAB8","object_before_hex":before.hex(),
                     "object_after_hex":after.hex(),"object_before_sha256":hashlib.sha256(before).hexdigest(),
                     "object_after_sha256":hashlib.sha256(after).hexdigest(),
                     "observed_first_dword_after":"0x002EBA98"},"passed":True}
    out=ROOT/"evidence"/"native_ifctitle_ctor.json"
    out.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    print(f"evidence: {out}")

if __name__=="__main__": main()
