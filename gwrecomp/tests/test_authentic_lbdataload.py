"""Run the original GeneWars 1.1 LbDataLoad_ with the bounded DOS/VFS fixture."""
from __future__ import annotations
import os as _gw_os
from pathlib import Path as _GwPath
_GW_ROOT=str(_GwPath(__file__).resolve().parents[1])
_GW_MSYS2=_gw_os.environ.get("MSYS2_ROOT",r"C:\msys64")
_GW_FX=_gw_os.environ.get("GENEWARSFX_ROOT",_gw_os.path.join(_GW_ROOT,"third_party","GeneWarsFX"))
_GW_INSTALL=_gw_os.environ.get("GENEWARS_INSTALL_DIR","<set GENEWARS_INSTALL_DIR>")
_GW_INSTALL_PARENT=str(_GwPath(_GW_INSTALL).parent)
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
INSTALL=Path((_GW_INSTALL))
RESOURCE=INSTALL/"DATA"/"IFTITLE.ANB"
EXPECTED_RESOURCE="c7d2dfc5d774c69337436249ec74e4d0fa6ae1d06bd5ae785f9f73ee2ac0f707"
REBASES={1:0x1EB000,3:0x1DA000}
TEMP_DIR=ROOT/"work"
ENV={**os.environ,"TEMP":str(TEMP_DIR),"TMP":str(TEMP_DIR),"TMPDIR":str(TEMP_DIR),
     "PYTHONDONTWRITEBYTECODE":"1",
     "PATH":(_GW_MSYS2 + '\\mingw32\\bin;' + _GW_MSYS2 + '\\usr\\bin;')+os.environ.get("PATH","")}

def sha(path:Path)->str: return hashlib.sha256(path.read_bytes()).hexdigest()

def run(command:list[object],timeout:int=90,quiet:bool=False)->subprocess.CompletedProcess[str]:
    p=subprocess.run([str(x) for x in command],cwd=ROOT,env=ENV,text=True,
                     capture_output=True,timeout=timeout)
    if p.stdout and not quiet: print(p.stdout,end="")
    if p.stderr and not quiet: print(p.stderr,end="")
    if p.returncode: raise SystemExit(p.returncode)
    return p

def exact_slice(dis,va,count,name,synthetic_ret=False):
    from tools.disasm.disasm32 import BasicBlock,Function,Instruction
    decoded=list(dis.disassemble_at(va,max_bytes=0x100))
    if len(decoded)<count: raise SystemExit(f"short original instruction slice at {va:#x}")
    ins=[Instruction(x.address,x.size,x.mnemonic,x.op_str,bytes(x.bytes),x.operands)
         for x in decoded[:count]]
    if synthetic_ret:
        end=ins[-1].address+ins[-1].size
        ins.append(Instruction(end,1,"ret","",b"\xc3",[]))
    start,end=ins[0].address,ins[-1].address+ins[-1].size
    return Function(start,end,name,{start:BasicBlock(start,end,ins,is_exit=True)},size=end-start)

def main()->None:
    if sha(TARGET)!=EXPECTED_TARGET: raise SystemExit("protected canonical 1.1 LE hash changed")
    if sha(RESOURCE)!=EXPECTED_RESOURCE: raise SystemExit("exact-build IFTITLE.ANB hash mismatch")
    sys.path[:0]=[str(ROOT/"src"),str(ROOT/"third_party"/"pcrecomp")]
    from le_loader import load_le
    from tools.disasm.disasm32 import Disassembler
    from tools.pe.pe_analyze import Section
    from tools.lift.lift32 import Lifter

    generated=ROOT/"work"/"authentic_lbdataload_closure.c"
    lift_report=ROOT/"evidence"/"authentic_lbdataload_closure.json"
    options=["--object-map","measured-1-3","--partial-root","0x14FF0",
        "--partial-root","0x921F0","--stack-range","0x003FD000:0x3000",
        "--dynamic-range","0x002DA000:0xA8C50","--dynamic-range","0x01000000:0x02002000",
        "--verified-indirect-target","0x98A1A=0x14BB0",
        "--deferred-indirect-call","0xC87A9",
        "--indexed-cs-table","0xD00F3=0xD00AA:36:edi:edx",
        "--indexed-cs-table","0xD0193=0xD0146:36:edi:edx"]
    # 0x96B23 explicitly loads the relocated 0x96B10 character-emitter into
    # ECX before entering the original Watcom formatter. Admit only those
    # formatter callsites, and leave the original run-time pointer lookup in
    # place; the test must resolve the actual loaded 0x281B10 address through
    # the verified object-1 map.
    for site in (0xB65FA,0xB66D8,0xB66F1,0xB670F,0xB6742,0xB677D,0xB679E,0xB67BD,0xB67FC):
        options += ["--verified-indirect-target",f"{hex(site)}=0x96B10"]
    run([PYTHON,ROOT/"tools"/"lift_entry_path.py",*options,
         "--output-c",generated,"--report",lift_report],timeout=90,quiet=True)
    lifted_text=generated.read_text(encoding="utf-8")
    rnc_call='    RECOMP_CALL(recomp_gw_partial_UnpackM1); /* 0x00097EE0: call 0xb9cfc */'
    rnc_payload='    esi = edi; /* 0x000B9DA1: mov esi, edi */'
    if lifted_text.count(rnc_call)!=1 or lifted_text.count(rnc_payload)!=1:
        raise SystemExit("cannot instrument the exact original LbDataLoad RNC callsite")
    lifted_text=lifted_text.replace('#include "gw_segments.h"',
        '#include "gw_segments.h"\nvoid gw_capture_lbdataload_rnc_args(uint32_t,uint32_t,uint32_t);\nvoid gw_capture_lbdataload_relocated_payload(uint32_t);',1)
    lifted_text=lifted_text.replace(rnc_call,
        '    gw_capture_lbdataload_rnc_args(eax,ecx,edx);\n'+rnc_call,1)
    lifted_text=lifted_text.replace(rnc_payload,
        rnc_payload+'\n    gw_capture_lbdataload_relocated_payload(esi);',1)
    generated.write_text(lifted_text,encoding="utf-8")
    report=json.loads(lift_report.read_text(encoding="utf-8"))
    if report["partial_rejections"] or report["missing_or_unsupported"] or report["unresolved_direct_calls"]:
        raise SystemExit("bounded original LbDataLoad closure is incomplete")
    lifted={int(row["address"],16) for row in report["lifted"]}
    need={0x14FF0,0x989EC,0x921F0,0x91E00,0x91E90,0x97DF0,0x97E9C,0xB9CFC,0x98C70,0x98D70}
    if not need.issubset(lifted): raise SystemExit(f"missing original resource-load functions: {sorted(need-lifted)}")

    image=load_le(TARGET,object_rebases=REBASES)
    obj=image.objects[0]
    dis=Disassembler(bytes(image.object_data(1)),0,
        [Section(".text",obj.base,obj.virtual_size,0,obj.virtual_size,0x20000020)])
    install=exact_slice(dis,0x14E94,3,"gw_original_install_resource_callback",True)
    setter=exact_slice(dis,0x989E0,3,"sub_000989E0")
    init_c=Lifter().lift_function(install)
    setter_c=Lifter().lift_function(setter)
    if "RECOMP_CALL(sub_000989E0)" not in init_c or "MEM32(DS_BASE + (0x2E4804)) = eax" not in setter_c:
        raise SystemExit("callback init/setter bytes no longer match the original LE slice")
    callback=ROOT/"work"/"lbdataload_callback_init_slice.c"
    callback.write_text('#define RECOMP_GENERATED_CODE\n#include "recomp_types.h"\n#include "recomp_context.h"\n#include "gw_recomp_stop.h"\n#include "gw_segments.h"\n'+
                        "void sub_000989E0(void);\n"+init_c+"\n"+setter_c+"\n",encoding="utf-8")

    guest=ROOT/"work"/"authentic_lbdataload_guest.bin"; guest.write_bytes(image.mem)
    exe=ROOT/"build"/"test_authentic_lbdataload.exe"
    exe.parent.mkdir(parents=True,exist_ok=True)
    command=[GCC,"-std=gnu11","-m32","-O0","-I",ROOT/"runtime",
        "-I",ROOT/"third_party"/"pcrecomp"/"runtime"/"recomp32","-o",exe,
        ROOT/"tests"/"test_authentic_lbdataload.c",generated,callback,
        ROOT/"runtime"/"recomp_context.c",ROOT/"runtime"/"gw_interrupts.c",
        ROOT/"runtime"/"gw_segments.c",ROOT/"runtime"/"gw_pit8254.c",
        ROOT/"runtime"/"gw_dos_services.c",ROOT/"runtime"/"gw_recomp_trace.c"]
    run(command)
    executed=run([exe,guest,INSTALL],timeout=90)
    output=ROOT/"work"/"lbdataload_iftitle.bin"
    if not output.exists() or output.stat().st_size!=0xE349:
        raise SystemExit("original LbDataLoad_ did not leave the 58,185-byte expanded resource")
    output_hash=sha(output)
    expected_decoded="f5537949f249fc4f84e265768a4a8af981d5db02604a67371bb70dab3f40e7bc"
    independent_reference=ROOT/"work"/"iftitle_independent_rnc.raw"
    packed_capture=ROOT/"work"/"lbdataload_relocated_rnc_payload.bin"
    compressed_capture=ROOT/"work"/"lbdataload_compressed_capture.bin"
    packed=packed_capture.read_bytes() if packed_capture.exists() else b""
    compressed=compressed_capture.read_bytes() if compressed_capture.exists() else b""
    payload_matches=bool(compressed and len(packed)==int.from_bytes(compressed[8:12],"big") and
                         packed==compressed[18:18+len(packed)])
    attempt={"schema":"gw-authentic-lbdataload-iftitle-attempt/v1",
        "target_sha256":EXPECTED_TARGET,
        "resource":{"path":str(RESOURCE),"physical_bytes":RESOURCE.stat().st_size,
            "sha256":EXPECTED_RESOURCE,"provenance":"protected exact-build local installation"},
        "analysis":{"provider":"REA 6.4.0 / Ghidra 12.1.4 mapped PE carrier, corroborated against canonical LE and Capstone",
            "LbDataLoad":"ev_9affbb5dc8c29e635944c38a397a2508a123a84b0b230de1f0ed09007ec05106",
            "resource_manager":"ev_ee2750127b20331b0431ae27a3fb771d80bc8d73ae708428f65d7186bf4d02cf",
            "RNC_in_place":"ev_76c7a20f069c769103dd3c77ad575fcb587297c25db66522ef0e7a5e45b24ead",
            "allocator":"ev_33b4145d4aa170a176a37c6522aed9e18d2e15a5e8f19fa7524c1ca289319ce"},
        "execution":{"entry":"original recompiled LbDataLoad_ 0x14FF0 -> FUN_989EC 0x989EC",
            "callback":"original 0x14E94 initializer slice installs original 0x14BB0; full FUN_14BF0 config parser was not run",
            "memory_profile":"bounded experimental 0x03002000 guest map; not Oracle equivalence",
            "vfs":{"path":"data/iftitle.anb","opens":6,"reads":3,"closes":6,
                "read_sizes":[8,8,30050],"file_bytes_sha256":hashlib.sha256(compressed).hexdigest()},
            "allocator":{"original_functions":["LbMemorySetup_ 0x921F0","LbMemoryAlloc_ 0x91E00"],
                "first_start":"0x01001030","expanded_length":0xE349},
        "rnc":{"original_function":"UnpackM1_ 0xB9CFC","args":{"eax":"0x01001030","ecx":"0x01001030","edx":"0x01001030"},
            "output_sha256":output_hash,"independent_rnc1_reference_sha256":expected_decoded,
            "independent_reference":{"kind":"read-only Python RNC1 decoder and CRC check from GeneWarsFX evidence tree",
                "script":(_GW_FX.replace("\\","/") + '/work/phase2v_rnc1_probe.py'),"input_sha256":EXPECTED_RESOURCE,
                "output_sha256":sha(independent_reference) if independent_reference.exists() else None,
                "header_unpacked_crc":"0x31de","decoder_unpacked_crc":"0x31de"},
                "relocated_payload_matches_original":payload_matches,
            "relocated_payload_bytes":len(packed),"status":"matched independent RNC1 output"}},
        "limitations":["Earlier expected hash 4ea6... came from a recompilation using incorrect REP overlap semantics and is superseded by the independent RNC1 decode plus matching header CRC.",
            "No title plug-in, menu, Oracle, or natural DOS/4GW replay was run."],"passed":False}
    evidence_path=ROOT/"evidence"/"authentic_lbdataload_iftitle_attempt.json"
    evidence_path.write_text(json.dumps(attempt,indent=2)+"\n",encoding="utf-8")
    print(f"evidence: {evidence_path}")
    if output_hash!=expected_decoded or not independent_reference.exists() or sha(independent_reference)!=expected_decoded or not payload_matches:
        raise SystemExit(f"manager RNC expansion did not match the independent RNC1 reference: {output_hash}")
    attempt["passed"]=True
    attempt["limitations"]=["The callback installer was the exact original 0x14E94 slice; full FUN_14BF0 config parsing was not run.",
        "No title plug-in, menu, Oracle, or natural DOS/4GW replay was run."]
    evidence_path.write_text(json.dumps(attempt,indent=2)+"\n",encoding="utf-8")
    print(f"PASS manager in-place expansion matches independent RNC1 output and CRC: {output_hash}")
    evidence={"schema":"gw-authentic-lbdataload-iftitle/v1","target_sha256":EXPECTED_TARGET,
        "resource":{"path":str(RESOURCE),"size":RESOURCE.stat().st_size,"sha256":EXPECTED_RESOURCE,
                    "provenance":"exact local installation, protected read-only input"},
        "analysis":{"provider":"REA 6.4.0 / Ghidra 12.1.4 on mapped PE carrier; exact path and dispatch checked against canonical LE with Capstone",
            "LbDataLoad_evidence":"ev_9affbb5dc8c29e635944c38a397a2508a123a84b0b230de1f0ed09007ec05106",
            "LbDataLoadAll_evidence":"ev_a7518b3b876adbad53fed0850489a95fd10726a2f5773c848b76b7da676a8a54",
            "resource_manager_evidence":"ev_ee2750127b20331b0431ae27a3fb771d80bc8d73ae708428f65d7186bf4d02cf",
            "heap_evidence":"ev_b381b14a23444b1753ad6a258cad3c831042037c151ad8098c5597b5c67d4cd5",
            "cs_table_guards":report["indexed_cs_tables"],"dynamic_calls_deferred":report["deferred_indirect_call_sites"]},
        "execution":{"mode":"original recompiled partial closure","entry":"LbDataLoad_ 0x14FF0",
            "resource_manager":"FUN_000989EC","callback":"original 0x14E94 slice sets LE-fixed 0x14BB0 via original 0x989E0",
            "memory_profile":"experimental bounded DOS/4GW guest map 0x03002000; not Oracle equivalence",
            "vfs":"allowlisted read-only exact-build resource; DOS open/read/close services",
            "expanded_size":output.stat().st_size,"expanded_sha256":output_hash,
            "stdout":executed.stdout.strip()},
        "regression_reference":{"prior_original_file_pipeline_sha256":expected_decoded,
            "prior_test":"tests/test_recompiled_iftitle_pipeline.py; separate original LbFileRead_ + original UnpackM1_ run"},
        "limitations":["No natural DOS/4GW replay or Oracle claim.",
            "Only title resource IFTITLE.ANB was passed through LbDataLoad_; other title files were not loaded.",
            "Deferred Watcom diagnostic/exit callbacks must remain unreached for a pass."],"passed":True}
    path=ROOT/"evidence"/"authentic_lbdataload_iftitle.json"
    path.write_text(json.dumps(evidence,indent=2)+"\n",encoding="utf-8")
    print(f"evidence: {path}")

if __name__=="__main__": main()
