"""Version 1 deterministic fixed-link runtime frontier snapshot and validator."""
import os as _gw_os
from pathlib import Path as _GwPath
_GW_ROOT=str(_GwPath(__file__).resolve().parents[1])
_GW_FX=_gw_os.environ.get("GENEWARSFX_ROOT",_gw_os.path.join(_GW_ROOT,"third_party","GeneWarsFX"))
import hashlib, json, pathlib, re

CUE_DEFAULT = pathlib.Path((_GW_FX + '\\evidence\\original_disc\\Genewars (Europe) (En,Fr,De,Es,It,Sv).cue'))

def sha256_bytes(data): return hashlib.sha256(data).hexdigest()
def sha256_file(path): return sha256_bytes(pathlib.Path(path).read_bytes())
def manifest_hash(paths, root):
    h=hashlib.sha256()
    for path in sorted(map(pathlib.Path,paths), key=lambda p:str(p.relative_to(root)).lower()):
        rel=str(path.relative_to(root)).replace("\\","/").encode()
        blob=path.read_bytes()
        h.update(len(rel).to_bytes(4,"little")); h.update(rel)
        h.update(len(blob).to_bytes(8,"little")); h.update(blob)
    return h.hexdigest()
def runtime_hash(root): return manifest_hash(list((root/"runtime").glob("*.c"))+list((root/"runtime").glob("*.h")),root)
def generated_hash(root): return manifest_hash([root/"build"/"entry_path_closure.c",root/"build"/"entry_path_native_lookup.c"],root)
def fingerprints(root, config_path, cue_path, target_path=None):
    return {"target_sha256":sha256_file(target_path or root/"evidence"/"genewars-1_1.exe"),
            "runtime_sha256":runtime_hash(root),"generated_code_sha256":generated_hash(root),
            "config_sha256":sha256_file(config_path),"cue_sha256":sha256_file(cue_path)}
def _records(stdout,prefix):
    out=[]
    for line in stdout.splitlines():
        if line.startswith(prefix+" "):
            out.append(dict(item.split("=",1) for item in line[len(prefix)+1:].split() if "=" in item))
    return out
def create_snapshot(root, evidence, memory_path, snapshot_path):
    root=pathlib.Path(root); memory_path=pathlib.Path(memory_path); snapshot_path=pathlib.Path(snapshot_path)
    progress=evidence["native_generated_c_progress"]
    frontier=progress["next_frontier"]
    if not frontier.get("instruction_va"):
        raise ValueError("snapshot v1 requires a recorded native guest frontier EIP")
    fixture=progress.get("cd_fixture_preflight") or {}
    config_path=pathlib.Path(fixture.get("config_path","")); cue_path=pathlib.Path(fixture.get("cue_path",""))
    if not config_path.is_file() or not cue_path.is_file(): raise ValueError("snapshot fixture config/CUE unavailable")
    if not memory_path.is_file(): raise ValueError("native full-memory payload missing")
    memory=memory_path.read_bytes()
    if len(memory)!=0x200000: raise ValueError(f"unexpected memory payload size {len(memory):#x}")
    psp=int(evidence["psp"]["linear"],16); mcb_begin=max(0,psp-16); mcb=memory[mcb_begin:psp]
    stdout=evidence.get("stdout","")
    cpu_lines=_records(stdout,"NATIVE_FRONTIER_CPU")
    if len(cpu_lines)!=1 or int(cpu_lines[0].get("eip","0"),16)!=int(frontier["instruction_va"],16):
        raise ValueError("captured CPU state does not match the guest trap EIP")
    fp=fingerprints(root,config_path,cue_path)
    if fp["target_sha256"]!=evidence["target_sha256"]: raise ValueError("target fingerprint disagrees with runner evidence")
    snap={"schema":"gwrecomp.frontier_snapshot.v1","created_by":"WORK2","fixture_arguments":{"command_tail":evidence.get("command_tail",{}).get("text"),"cdrom_drives":fixture.get("cdrom_drives",[])},
          "fingerprints":fp,"guest_eip":frontier["instruction_va"],"cpu":cpu_lines[0],
          "memory":{"path":str(memory_path.relative_to(root)).replace("\\","/"),"size":len(memory),"sha256":sha256_bytes(memory),"coverage":"complete guest memory image; dirty pages are included in full image"},
          "psp_mcb":{"psp_linear":evidence["psp"]["linear"],"psp_selector":evidence["psp"]["selector"],"mcb_linear":f"0x{mcb_begin:08X}","mcb_bytes_hex":mcb.hex(),"mcb_bytes_sha256":sha256_bytes(mcb)},
          "descriptors":{"source":"native gw_dos_services registry at frontier","entries":_records(stdout,"NATIVE_FRONTIER_DESCRIPTOR")},
          "dos_dpmi_allocator":{"state":(_records(stdout,"NATIVE_FRONTIER_ALLOC") or [None])[0],"owned_dos_blocks":_records(stdout,"NATIVE_FRONTIER_DOS_BLOCK")},
          "handles":{"availability":"not_modeled_by_native_runner_at_this_frontier","entries":[]},
          "filesystem_positions":{"availability":"not_modeled_by_native_runner_at_this_frontier","entries":[]},
          "cue_state":{"availability":"read_only fixture preflight only","path":str(cue_path),"sha256":fp["cue_sha256"],"native_cue_io_reached":bool(fixture.get("native_cd_request_reached",False))},
          "validation":{"restore_supported":False,"compatible":True}}
    snapshot_path.write_text(json.dumps(snap,indent=2)+"\n",encoding="utf-8")
    return snap

def validate_snapshot(snapshot_path, root, expected=None):
    root=pathlib.Path(root); snapshot_path=pathlib.Path(snapshot_path); snap=json.loads(snapshot_path.read_text(encoding="utf-8"))
    if snap.get("schema")!="gwrecomp.frontier_snapshot.v1": raise ValueError("unsupported snapshot schema")
    fp=snap.get("fingerprints",{}); expected=dict(expected or {})
    for key in ("target_sha256","runtime_sha256","generated_code_sha256","config_sha256","cue_sha256"):
        if key in expected and fp.get(key)!=expected[key]: raise ValueError("incompatible "+key)
    if "eip" in expected and snap.get("guest_eip","").lower()!=str(expected["eip"]).lower(): raise ValueError("incompatible guest EIP")
    mem=snap.get("memory",{}); path=root/mem.get("path","")
    if not path.is_file(): raise ValueError("memory payload missing")
    data=path.read_bytes()
    if len(data)!=mem.get("size") or sha256_bytes(data)!=mem.get("sha256"): raise ValueError("memory payload hash/size mismatch")
    if int(snap.get("cpu",{}).get("eip","0"),16)!=int(snap.get("guest_eip","-1"),16): raise ValueError("CPU EIP disagrees with snapshot frontier")
    return snap

