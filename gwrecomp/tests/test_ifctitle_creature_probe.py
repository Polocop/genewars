"""Run original IFCTitle::PlugIn, Update, and Draw in bounded guest state."""
from __future__ import annotations
import os as _gw_os
from pathlib import Path as _GwPath
_GW_ROOT=str(_GwPath(__file__).resolve().parents[1])
_GW_FX=_gw_os.environ.get("GENEWARSFX_ROOT",_gw_os.path.join(_GW_ROOT,"third_party","GeneWarsFX"))
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
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import struct

ROOT=Path(__file__).resolve().parents[1]
PYTHON=Path(os.environ.get("GWRECOMP_PYTHON") or sys.executable)  # V19.1: explicit interpreter (was ROOT/.venv/Scripts/python.exe)
def _toolchain_config()->dict:
    """Locate the toolchain from the environment (see tools/rebuild/README_BUILD.md).

    GWRECOMP_CLANG_X64  clang used to compile the large lifted C unit (64-bit host)
    GWRECOMP_CLANG_X86  clang used to link (defaults to GWRECOMP_CLANG_X64)
    MSYS2_ROOT          MSYS2 installation providing mingw32 (SDL2, crt, libstdc++)
    """
    import shutil
    def first(*cands):
        for c in cands:
            if c and Path(str(c)).is_file(): return Path(str(c))
        return None
    clang64=first(os.environ.get("GWRECOMP_CLANG_X64"),os.environ.get("GWRECOMP_CLANG"),shutil.which("clang"))
    if clang64 is None:
        for base in (os.environ.get("ProgramFiles(x86)"),os.environ.get("ProgramFiles")):
            if not base: continue
            for edition in ("BuildTools","Community","Professional","Enterprise"):
                cand=first(Path(base)/"Microsoft Visual Studio"/"2022"/edition/"VC"/"Tools"/"Llvm"/"x64"/"bin"/"clang.exe")
                if cand: clang64=cand; break
            if clang64: break
    clang86=first(os.environ.get("GWRECOMP_CLANG_X86"),clang64)
    msys=os.environ.get("MSYS2_ROOT")
    if not msys:
        gcc=shutil.which("gcc")
        if gcc and Path(gcc).parent.name.lower()=="bin" and Path(gcc).parent.parent.name.lower()=="mingw32":
            msys=str(Path(gcc).parent.parent.parent)
    if not msys and Path(r"C:\msys64").is_dir(): msys=r"C:\msys64"
    return {"clang64":clang64,"clang86":clang86,"msys":Path(msys) if msys else None}
_TC=_toolchain_config()
def _need(value,what:str):
    if value is None:
        raise SystemExit(f"{what} not found. Run scripts\\setup.ps1 or set the variable named in tools/rebuild/README_BUILD.md")
    return value
_CLANG64=_TC["clang64"] or Path("clang.exe")
_CLANG86=_TC["clang86"] or Path("clang.exe")
MINGW32=(_TC["msys"]/"mingw32") if _TC["msys"] else Path("<MSYS2_ROOT>")/"mingw32"
MINGW32_BIN=MINGW32/"bin"
MINGW32_LIB=MINGW32/"lib"
MINGW32_INCLUDE=MINGW32/"include"
SDL2_INCLUDE=MINGW32_INCLUDE/"SDL2"
def _cxx_include_dirs()->list[Path]:
    base=MINGW32_INCLUDE/"c++"
    versions=sorted((d for d in base.iterdir() if d.is_dir()),reverse=True) if base.is_dir() else []
    if not versions: return [MINGW32_INCLUDE]
    v=versions[0]
    return [v,v/"i686-w64-mingw32",MINGW32_INCLUDE]
CC=[_CLANG64,"--target=i686-w64-windows-gnu"]
LINK_CC=[_CLANG86,"--target=i686-w64-windows-gnu"]
CLANGXX=[_CLANG64.with_name("clang++.exe"),"--target=i686-w64-windows-gnu"]
TARGET=ROOT/"evidence"/"genewars-1_1.exe"
EXPECTED_TARGET="2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
HARNESS_IMAGE_BASE=0x000F0000
DOS_CONVENTIONAL_TOP=0x0000A000
REA_OPTIONS_TRANSITION={
    "provider":"REA 6.4.0 / Ghidra 12.1.4",
    "carrier_sha256":"1523022fb1febcfb939b2ed04145ee6e7dcd8b99113d932d21d33301c0052a97",
    "evidence_ids":{
        "IFCOptions_code_bytes_0x6A3D0":"ev_6254dc990accdf84bff28c849c77dd326042a702afb4ed490a6997363de70e50",
        "formatter_emitter_0x96B10_bytes":"ev_de89a59aa40241b75a6b16396711c98a5c390fc1b9d561ce48b004687f9d938d",
        "formatter_wrapper_0x96B23":"ev_27b34aeca151f6973eabac14f83c177999f6bc8314a9b5877432e5d4c23469d9",
        "formatter_callback_0xB6534":"ev_4761cafe7c742fab7007a43b7e952dc9a9069503f5cdccf50dd6b0af83d78dc9",
        "setup_game_0x94AC0":"ev_b5cdf5bb4a586ebdaf9611cd9b74a9eee37c3ebc3e2689284cf3f8f01666e484",
        "global_this_xrefs_0x114CA8":"ev_64c53b43f7e67e3810f3a54c03596d5181445093284c52af2cdec8d082fe6e81"},
    "limitation":"Ghidra read_bytes confirms 0x6A3D0 code but has no defined procedure entry there; semantics and boundaries are cross-checked against canonical LE with Capstone and native hooks."}
INSTALL=Path(os.environ.get("GENEWARS_INSTALL_DIR") or "<set GENEWARS_INSTALL_DIR>")
RESOURCE=INSTALL/"DATA"/"IFTITLE.ANB"
EXPECTED_RESOURCE="c7d2dfc5d774c69337436249ec74e4d0fa6ae1d06bd5ae785f9f73ee2ac0f707"
TITLE_SCREEN=INSTALL/"DATA"/"TITLESCR.DAT"
EXPECTED_TITLE_SCREEN="2548b024fede333b49fc4011541939fc8ce294cb95b48cdb41ed7d0cec54a0b9"
CONFIG_INI=INSTALL/"CONFIG.INI"
EXPECTED_CONFIG_INI="e7a4728ff07332c2f04320fda202ac5521818a47453e670f9f2842767ef36798"
BIOINTRO=INSTALL/"INTRO"/"BIOINTRO.SMK"
EXPECTED_BIOINTRO="fcd3dcddb1ace394b882f240f8cec3625a57d471be5cd66f1db75e543688a4ef"
GENEWARS_CUE=Path(os.environ.get("GENEWARS_CUE") or "<set GENEWARS_CUE>")
EXPECTED_GENEWARS_CUE="1d417e3aed625d4f054b51054a1211562a19cd4f712b08e7846613517228a5b5"
TITLE_RESOURCES={
    "DATA/TITLESCR.DAT":"2548b024fede333b49fc4011541939fc8ce294cb95b48cdb41ed7d0cec54a0b9",
    "DATA/IFTITLE.ANB":"c7d2dfc5d774c69337436249ec74e4d0fa6ae1d06bd5ae785f9f73ee2ac0f707",
    "DATA/TITLESCR.PAL":"d5ec91e731c2ff7e8d74dbbde6a3fe0410ec602ff0da52eb1e6f6bb1a44307c7",
    "DATA/FONT2.DAT":"2f3d275f88f2ff6671562a819cbc7a791b16ad4510a4020f3b6078c917f60dba",
    "DATA/FONT2.TAB":"f54057e1b19cc1711a1596b6459cfdfb359a170f5ed739df71fd852befba4bab",
    "DATA/TEXT.DAT":"17fd1cc1eb502e629765ae7a18251750592871dcb7c76f95ad9a610858808c47",
    "DATA/FILEEN.DAT":"98902c34587768832b1c40ddbccf8db8f2982f875c3ea8631170f15347a6cf40",
}
INTERFACE_RESOURCES={
    "DATA/MAIN.GLA":"c5e12a5b4325c8302cab0fb3ba3aaa654e2e044131763298815766d8a6f47a58",
    "DATA/FILESCR.ANB":"33c9c1f394a249209ff20319490393afa844d46dec84455cf43aca5ff24cf957",
    "DATA/FILESCR.GLA":"a312c491d16681660ea42f719c6da39d4b9500b8efed72b68b00b2d5c5b6267b",
    "DATA/FILESCR.PAL":"997a3711fbed107cc0025fd30f15760345139dcdccc842c6433ce8fb2b29a5ec",
}
REBASES={1:0x1EB000,3:0x1DA000}
ENV={**os.environ,"PYTHONDONTWRITEBYTECODE":"1",
     "PATH":str(MINGW32_BIN)+";"+str(MINGW32.parent/"usr"/"bin")+";"+os.environ.get("PATH",""),
     "GW_ENABLE_WIDE_RASTER_PROBES":"1"}

class ReferenceMap:
    """Optional private reference symbol map (evidence/genewars-1_1.map).

    The build never needs it: function boundaries come from explicit roots and closure traversal, and generated identifiers
    are address-based. When the map IS supplied, the cross-checks below compare the reverse-engineering assumptions encoded
    in this driver with it. When it is NOT supplied those cross-checks are SKIPPED (counted and reported), never passed.
    """
    path=ROOT/"evidence"/"genewars-1_1.map"
    available=path.is_file()
    text=path.read_text(encoding="utf-8",errors="replace") if available else ""
    skipped=0
    @classmethod
    def _skip(cls):
        cls.skipped+=1
    @classmethod
    def contains(cls,literal:str)->bool:
        """Presence cross-check: the exact map text must contain `literal`."""
        if not cls.available: cls._skip(); return True
        return literal in cls.text
    @classmethod
    def has_line(cls,prefix:str)->bool:
        """Presence cross-check: some map line must start with `prefix`."""
        if not cls.available: cls._skip(); return True
        return any(line.startswith(prefix) for line in cls.text.splitlines())
    @classmethod
    def has_unexpected_line(cls,prefix:str)->bool:
        """Absence cross-check: True means a line that must NOT exist does exist."""
        if not cls.available: cls._skip(); return False
        return any(line.startswith(prefix) for line in cls.text.splitlines())
    @classmethod
    def line_with(cls,prefix:str,needle:str):
        if not cls.available: cls._skip(); return "(reference map not supplied)"
        return next((line.strip() for line in cls.text.splitlines() if line.startswith(prefix) and needle in line),None)
    @classmethod
    def code_symbols(cls)->dict:
        symbols={}
        for line in cls.text.splitlines():
            fields=line.split()
            if len(fields)>=2 and fields[0].startswith("0001:"):
                try: symbols[int(fields[0].split(":",1)[1],16)]=fields[1]
                except ValueError: pass
        return symbols
import atexit
@atexit.register
def _report_reference_map():
    if ReferenceMap.available: print("TRACE reference_map present cross_checks=active",flush=True)
    else: print(f"TRACE reference_map absent cross_checks_skipped={ReferenceMap.skipped}",flush=True)


def sha(path:Path)->str: return hashlib.sha256(path.read_bytes()).hexdigest()

REFERENCE_SAVE0_SHA256="a174d375b625e1f0016eefade2e639b9366ff68608d3af62f51d971363a0a95e"
def detect_save_profile()->str:
    """Which SAVE-directory profile this installation is in.

    reference-save : SAVE contains exactly SAVE0.SAV with the maintainers' reference content (regression profile)
    no-saves       : SAVE is empty or absent, i.e. a fresh installation (the profile outside contributors can reproduce)
    Anything else (another save, or a SAVE0.SAV with other content) is refused: the replays below validate one of these two
    states and no other."""
    save_dir=INSTALL/"SAVE"
    present=sorted(p.name for p in save_dir.iterdir() if p.is_file()) if save_dir.is_dir() else []
    if not present: return "no-saves"
    if [name.upper() for name in present]==["SAVE0.SAV"]:
        actual=sha(save_dir/present[0])
        if actual==REFERENCE_SAVE0_SHA256: return "reference-save"
        raise SystemExit(f"SAVE0.SAV has SHA-256 {actual}, not the reference save; remove it (profile no-saves) or use the reference file")
    raise SystemExit(f"unsupported SAVE directory content {present}: supported states are an empty SAVE directory (no-saves) or exactly the reference SAVE0.SAV")
def save_evidence(resource_inputs:dict,read_by:str)->dict:
    entry=resource_inputs.get("SAVE/SAVE0.SAV")
    if entry is None:
        return {"SAVE0.SAV":{"present":False,"profile":"no-saves","note":"fresh installation: the SAVE directory is empty"}}
    return {"SAVE0.SAV":{"sha256":entry["sha256"],"read_by":read_by,"bytes":entry["size"],"profile":"reference-save"}}

def cue_matches_profile(cue:Path)->bool:
    """True when every track image of `cue` has the size and SHA-256 recorded in the version profile.

    The text of a cue sheet depends on how the disc was ripped (file names, line endings) and says nothing about the audio
    data; the track images do. This accepts the same disc content under a differently spelled cue sheet and still refuses any
    other content. The layout derived from the cue is separately asserted below."""
    profile=json.loads((ROOT/"tools"/"rebuild"/"profiles"/"gw11-europe.json").read_text(encoding="utf-8"))
    expected=profile["disc"]["tracks"]
    sys.path.insert(0,str(ROOT/"runtime"))
    from dos_cdrom import CueImage
    try: tracks=CueImage.from_cue(cue).tracks
    except Exception: return False
    if len(tracks)!=len(expected): return False
    return all(t.path.stat().st_size==e["size"] and sha(t.path)==e["sha256"] for t,e in zip(tracks,expected))


def create_install_manifest()->tuple[Path,dict]:
    root=INSTALL.resolve(strict=True)
    if not root.is_dir(): raise SystemExit(f"GeneWars 1.1 installation root is unavailable: {root}")
    records=[]
    for path in root.rglob("*"):
        if path.is_symlink() or not path.is_file(): continue
        resolved=path.resolve(strict=True)
        try: relative=resolved.relative_to(root)
        except ValueError: raise SystemExit(f"installation manifest path escaped root: {path}")
        rel=relative.as_posix().lower()
        records.append({"path":rel,"size":resolved.stat().st_size,"sha256":sha(resolved)})
    records.sort(key=lambda row:row["path"])
    if not records: raise SystemExit("GeneWars installation manifest is empty")
    body="".join(f"{row['sha256']}\t{row['path']}\n" for row in records)
    manifest_tsv=ROOT/"work"/"genewars_1_1_install_manifest_creature_probe.tsv"
    manifest_tsv.write_text(body,encoding="ascii",newline="\n")
    manifest={"schema":"gwrecomp-vfs-install-manifest/v1","target_sha256":EXPECTED_TARGET,
        "root":str(root),"read_policy":"only existing regular files with matching SHA-256; writes are overlay-only",
        "file_count":len(records),"files":records,
        "canonical_list_sha256":hashlib.sha256(body.encode("ascii")).hexdigest()}
    manifest_path=ROOT/"evidence"/"genewars_1_1_install_manifest_creature_probe.json"
    manifest_path.write_text(json.dumps(manifest,indent=2)+"\n",encoding="utf-8")
    return manifest_tsv,manifest

def run(command:list[object],timeout:int=90,quiet:bool=False)->subprocess.CompletedProcess[str]:
    try:
        p=subprocess.run([str(x) for x in command],cwd=ROOT,env=ENV,text=True,
                         capture_output=True,timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        if Path(str(command[0])).name.lower()=="test_ifctitle_creature_probe.exe":
            def captured(value):
                if value is None: return ""
                return value.decode("utf-8",errors="replace") if isinstance(value,bytes) else value
            trace=captured(exc.stdout)+"\n"+captured(exc.stderr)
            log_path=ROOT/"evidence"/"native_ifclevel_transition_timeout.log"
            log_path.write_text(trace,encoding="utf-8")
            timeout_json={"schema":"gw-native-ifclevel-transition-timeout/v1",
                "target_sha256":EXPECTED_TARGET,"timeout_seconds":timeout,
                "command":[str(x) for x in command],"log":str(log_path.relative_to(ROOT)),
                "log_sha256":hashlib.sha256(trace.encode("utf-8",errors="replace")).hexdigest(),
                "classification":"native replay exceeded its host timeout; partial output was preserved"}
            (ROOT/"evidence"/"native_ifclevel_transition_timeout.json").write_text(
                json.dumps(timeout_json,indent=2)+"\n",encoding="utf-8")
        raise
    if p.stdout and not quiet: print(p.stdout,end="")
    if p.stderr and not quiet: print(p.stderr,end="")
    if p.returncode:
        if Path(str(command[0])).name.lower()=="test_ifctitle_creature_probe.exe":
            (ROOT/"evidence"/"native_ifctitle_creature_probe_failure.stdout.log").write_text(
                p.stdout or "",encoding="utf-8")
            (ROOT/"evidence"/"native_ifctitle_creature_probe_failure.stderr.log").write_text(
                p.stderr or "",encoding="utf-8")
        if (Path(str(command[0])).name.lower()=="test_ifctitle_creature_probe.exe" and
                (os.environ.get("GWRECOMP_IFCLEVEL_FULL_GAME_ENTRY")=="1" or
                 os.environ.get("GWRECOMP_IFCLEVEL_FRESH_GAME_ENTRY")=="1" or
                 os.environ.get("GWRECOMP_IFCLEVEL_CONTINUOUS_GAME_ROOT")=="1")):
            default_stem=("native_ifclevel_fresh_game_entry" if
                os.environ.get("GWRECOMP_IFCLEVEL_FRESH_GAME_ENTRY")=="1" else
                "native_ifclevel_continuous_game_root" if
                os.environ.get("GWRECOMP_IFCLEVEL_CONTINUOUS_GAME_ROOT")=="1" else
                "native_ifclevel_full_game_entry")
            stem=os.environ.get("GWRECOMP_IFCLEVEL_REPLAY_STEM") or default_stem
            stdout_path=ROOT/"evidence"/f"{stem}.stdout.log"
            stderr_path=ROOT/"evidence"/f"{stem}.stderr.log"
            stdout_path.write_text(p.stdout or "",encoding="utf-8")
            stderr_path.write_text(p.stderr or "",encoding="utf-8")
            result=next((line for line in (p.stderr or "").splitlines()
                if line.startswith("TRACE native_full_game_result ")),None)
            (ROOT/"evidence"/f"{stem}.json").write_text(json.dumps({
                "schema":"gw-native-full-game-entry-failure/v1",
                "target_sha256":EXPECTED_TARGET,"entry_link":"0x00092710",
                "exit_code":p.returncode,"result":result,
                "stdout":str(stdout_path.relative_to(ROOT)),
                "stderr":str(stderr_path.relative_to(ROOT)),
                "prepgadget_records":[line for line in (p.stderr or "").splitlines()
                    if line.startswith(("TRACE prepgadget_entry ","TRACE prepgadget_deref "))],
                "passed":False},indent=2)+"\n",encoding="utf-8")
        if (Path(str(command[0])).name.lower()=="test_ifctitle_creature_probe.exe" and
                p.returncode==121):
            # 121 is a harness status, not a guest DOS/LE exit code. Preserve
            # the actual contract/fault summary separately so a loop-bound or
            # output-validation failure is not mislabeled as an indirect LE
            # frontier.
            native_loop=os.environ.get("GWRECOMP_IFCLEVEL_NATIVE_GAME_LOOP")=="1"
            stem=(os.environ.get("GWRECOMP_IFCLEVEL_REPLAY_STEM") or
                  ("native_ifclevel_game_loop" if native_loop else "native_ifclevel_creature_probe_continue"))
            stdout_path=ROOT/"evidence"/f"{stem}.stdout.log"
            stderr_path=ROOT/"evidence"/f"{stem}.stderr.log"
            stdout_path.write_text(p.stdout or "",encoding="utf-8")
            stderr_path.write_text(p.stderr or "",encoding="utf-8")
            result_path=ROOT/"evidence"/f"{stem}.json"
            trace_lines=(p.stdout or "").splitlines()+(p.stderr or "").splitlines()
            loop_result=next((line for line in trace_lines
                if line.startswith("TRACE native_game_loop_result ")),None)
            harness_failure=next((line for line in trace_lines
                if line.startswith("bounded IFCLevel interaction continuation failed")),None)
            classification=("harness returned 121 after native-loop contract validation; not a guest exit"
                if native_loop else
                "harness returned 121 after bounded replay or artifact validation; not a guest exit")
            (result_path).write_text(
                json.dumps({"schema":"gw-native-ifclevel-harness-validation-failure/v1",
                    "target_sha256":EXPECTED_TARGET,"exit_code":p.returncode,
                    "stdout_log":str(stdout_path.relative_to(ROOT)),
                    "stderr_log":str(stderr_path.relative_to(ROOT)),
                    "native_game_loop_result":loop_result,
                    "harness_failure_line":harness_failure,
                    "guest_exit_observed":False,
                    "classification":classification},
                    indent=2)+"\n",encoding="utf-8")
        if Path(str(command[0])).name.lower()=="test_ifctitle_creature_probe.exe" and p.returncode==133:
            trace=(p.stdout or "")+"\n"+(p.stderr or "")
            log_path=ROOT/"evidence"/"native_setupgame_continuous_fastpath.log"
            log_path.write_text(trace,encoding="utf-8")
            capture={"schema":"gw-native-setupgame-continuous-frontier/v1",
                "target_sha256":EXPECTED_TARGET,"exit_code":p.returncode,
                "log":str(log_path.relative_to(ROOT)),
                "log_sha256":hashlib.sha256(trace.encode("utf-8",errors="replace")).hexdigest(),
                "classification":"full original setup_game was entered with its native Watcom frame and stopped at a bounded runtime frontier"}
            (ROOT/"evidence"/"native_setupgame_continuous_fastpath.json").write_text(
                json.dumps(capture,indent=2)+"\n",encoding="utf-8")
        if (Path(str(command[0])).name.lower()=="test_ifctitle_creature_probe.exe" and
                p.returncode in (0xC00000FD,-1073741571)):
            trace=(p.stdout or "")+"\n"+(p.stderr or "")
            log_path=ROOT/"evidence"/"native_ifclevel_host_stack_overflow.log"
            log_path.write_text(trace,encoding="utf-8")
            exception=next((line for line in trace.splitlines()
                            if line.startswith("HOST_EXCEPTION code=")),None)
            system1=next((line for line in trace.splitlines()
                          if line.startswith("TRACE SYSTEM1 VFS summary ")),None)
            capture={"schema":"gw-native-ifclevel-host-exception/v1",
                "target_sha256":EXPECTED_TARGET,"exit_code":p.returncode,
                "exception_code":"0xC00000FD","log":str(log_path.relative_to(ROOT)),
                "log_sha256":hashlib.sha256(trace.encode("utf-8",errors="replace")).hexdigest(),
                "host_exception":exception,"system1_vfs_summary":system1,
                "classification":"the native process exhausted its stack; the handler retained host and guest instruction context without resuming execution"}
            (ROOT/"evidence"/"native_ifclevel_host_stack_overflow.json").write_text(
                json.dumps(capture,indent=2)+"\n",encoding="utf-8")
        if (Path(str(command[0])).name.lower()=="test_ifctitle_creature_probe.exe" and
                p.returncode in (105,109)):
            full_trace=(p.stdout or "")+"\n"+(p.stderr or "")
            lines=full_trace.splitlines()
            system1_indices=[i for i,line in enumerate(lines)
                if "TRACE original VFS read path='C:\\GENEWARS\\anims\\system1.smk'" in line]
            if len(system1_indices)>64:
                keep=set(system1_indices[:16]+system1_indices[-16:])
                compact=[]; omitted=0
                for i,line in enumerate(lines):
                    if "TRACE original VFS read path='C:\\GENEWARS\\anims\\system1.smk'" in line and i not in keep:
                        omitted+=1
                        if omitted==1:
                            compact.append(f"TRACE SYSTEM1 VFS read trace compacted; retained 32 of {len(system1_indices)} rows")
                        continue
                    compact.append(line)
                trace="\n".join(compact)+"\n"
            else:
                trace=full_trace
            log_path=ROOT/"evidence"/"native_ifclevel_transition_investigation.log"
            log_path.write_text(trace,encoding="utf-8")
            transition=next((line for line in trace.splitlines()
                if line.startswith("TRACE original game() TITLE->IFCLevel transition ")),None)
            mouse=next((line for line in trace.splitlines()
                if line.startswith("TRACE original INT33 registered=")),None)
            budget=next((line for line in trace.splitlines()
                if line.startswith("TRACE bounded IFCLevel replay instruction_budget=")),None)
            smack_callbacks=next((line for line in trace.splitlines()
                if line.startswith("TRACE live Smacker callbacks ")),None)
            system1_summary=next((line for line in trace.splitlines()
                if line.startswith("TRACE SYSTEM1 VFS summary ")),None)
            draw_failure=next((line for line in trace.splitlines()
                if line.startswith("original IFCLevel Draw dispatch failed ")),None)
            capture={"schema":"gw-native-ifclevel-transition-frontier/v1",
                "target_sha256":EXPECTED_TARGET,"exit_code":p.returncode,
                "command":[str(x) for x in command],
                "log":str(log_path.relative_to(ROOT)),
                "log_sha256":hashlib.sha256(trace.encode("utf-8",errors="replace")).hexdigest(),
                "full_trace_sha256":hashlib.sha256(full_trace.encode("utf-8",errors="replace")).hexdigest(),
                "full_trace_bytes":len(full_trace.encode("utf-8",errors="replace")),
                "mouse_registration":mouse,"transition":transition,"instruction_budget_frontier":budget,
                "live_smacker_callbacks":smack_callbacks,"system1_vfs_summary":system1_summary,
                "system1_decode_completion":"not confirmed; VFS recorded EOF reads at the end of SYSTEM1.SMK",
                "ifclevel_draw_failure":draw_failure,
                "classification":("bounded native instruction budget stopped the original call chain; inspect last_eip before extending the closure"
                    if budget else
                    "IFCLevel::PlugIn returned through the original game transition; the post-transition Draw reached its original remap-sprite routine and stopped on the recorded fail-closed guest memory fault"
                    if draw_failure else
                    "native recompiled replay reached its bounded IFCLevel transition check; inspect the recorded first runtime trap before relaxing any closure contract")}
            draw_failure_site=next((line for line in trace.splitlines()
                if line.startswith("TRACE original W_DrawMyRemapSpriteHR enter ")),None)
            bank_init_enter=next((line for line in trace.splitlines()
                if line.startswith("TRACE original InitMyAnimBank enter site=0001588f")),None)
            bank_init_return=next((line for line in trace.splitlines()
                if line.startswith("TRACE original InitMyAnimBank return site=0001588f")),None)
            image_paths={name:ROOT/"evidence"/name for name in (
                "native_ifclevel_draw_investigation_wscreen.raw",
                "native_ifclevel_draw_investigation_palette6.raw",
                "native_ifclevel_draw_investigation.bmp")}
            image_hashes={name:hashlib.sha256(path.read_bytes()).hexdigest()
                for name,path in image_paths.items() if path.exists()}
            capture["draw_investigation"]={
                "first_remap_call":draw_failure_site,
                "init_my_anim_bank_enter":bank_init_enter,
                "init_my_anim_bank_return":bank_init_return,
                "remap_calls_completed_before_fault":0 if draw_failure else None,
                "remap_calls_attempted":1 if draw_failure else None,
                "artifacts":image_hashes,
                "transition_changed_bytes":58315,
                "transition_changed_bytes_classification":"unbacked low guest address range reported by the existing fail-closed transition delta checker; byte deltas are not raw store counts"}
            (ROOT/"evidence"/"native_ifclevel_transition_investigation.json").write_text(
                json.dumps(capture,indent=2)+"\n",encoding="utf-8")
        if any(str(part).lower().endswith("lift_entry_path.py") for part in command):
            refusal=(p.stdout or "")+"\n"+(p.stderr or "")
            refusal_path=ROOT/"evidence"/"ifctitle_setupgame_partial_closure_refusal.log"
            refusal_path.write_text(refusal,encoding="utf-8")
            refusal_json={"schema":"gw-partial-closure-refusal/v1",
                "command":list(map(str,command)),"returncode":p.returncode,
                "log":str(refusal_path.relative_to(ROOT)),"log_sha256":hashlib.sha256(
                    refusal.encode("utf-8",errors="replace")).hexdigest(),
                "classification":"The fail-closed lifter rejected unresolved control-flow, callback, and memory dependencies in the requested partial closure, which now includes IFCLevel methods; compilation and native replay were not started."}
            (ROOT/"evidence"/"ifctitle_setupgame_partial_closure_refusal.json").write_text(
                json.dumps(refusal_json,indent=2)+"\n",encoding="utf-8")
        if (Path(str(command[0])).name.lower()=="test_ifctitle_creature_probe.exe" and
                p.returncode==10 and "LbMemorySetup failed" in p.stderr):
            trace=(p.stdout+"\n"+p.stderr).encode("utf-8",errors="replace")
            log_path=ROOT/"evidence"/"native_rationalalloc_ah48_failure_stack.log"
            log_path.write_bytes(trace)
            capture={"schema":"gw-rationalalloc-ah48-stack-capture/v1",
                "target_sha256":EXPECTED_TARGET,"exit_code":p.returncode,
                "command":[str(x) for x in command],"log":str(log_path.relative_to(ROOT)),
                "log_sha256":hashlib.sha256(trace).hexdigest(),
                "classification":"bounded native replay reached the original AH=48 failure and LbMemorySetup boundary",
                "dos_profile":{"kind":"experimental bounded 640-KiB conventional-memory profile",
                    "top_segment":"0xA000","expected_response":"recomputed from active MCB chain"}}
            (ROOT/"evidence"/"native_rationalalloc_ah48_failure_stack.json").write_text(
                json.dumps(capture,indent=2)+"\n",encoding="utf-8")
        if (Path(str(command[0])).name.lower()=="test_ifctitle_creature_probe.exe" and
                p.returncode==75):
            trace=(p.stdout+"\n"+p.stderr).encode("utf-8",errors="replace")
            log_path=ROOT/"evidence"/"native_ifctitle_watcom_initrtns_failure.log"
            log_path.write_bytes(trace)
            stdout_path=ROOT/"evidence"/"native_ifctitle_watcom_initrtns.stdout.log"
            stderr_path=ROOT/"evidence"/"native_ifctitle_watcom_initrtns.stderr.log"
            stdout_path.write_text(p.stdout,encoding="utf-8")
            stderr_path.write_text(p.stderr,encoding="utf-8")
            capture={"schema":"gw-ifctitle-watcom-init-capture/v1",
                "target_sha256":EXPECTED_TARGET,"exit_code":p.returncode,
                "command":[str(x) for x in command],"log":str(log_path.relative_to(ROOT)),
                "log_sha256":hashlib.sha256(trace).hexdigest(),
                "stdout_log":str(stdout_path.relative_to(ROOT)),"stdout_sha256":sha(stdout_path),
                "stderr_log":str(stderr_path.relative_to(ROOT)),"stderr_sha256":sha(stderr_path),
                "classification":(
                    "bounded original Watcom startup stopped at the guest instruction budget"
                    if "bounded original Watcom startup exceeded guest budget" in p.stderr else
                    "bounded original Watcom __InitRtns returned to its caller but the test's post-call boundary assertion failed"
                    if "last_guest_eip=000afbf4" in p.stderr and "mem=0:" in p.stderr and "int=0:" in p.stderr else
                    "bounded original Watcom startup stopped at a controlled guest memory fault"
                    if re.search(r"mem=1:",p.stderr) else
                    "bounded original Watcom startup stopped at a trapped interrupt or port service"),
                "frontier":{"watcom_dispatcher_link":"0x000C871C",
                    "second_original_init_target":"0x000A38DC",
                    "init_target_name":"j___sys_init_387_emulator",
                    "x87_fninit_expected_control_word":"0x037F",
                    "unsupported_f304_calls":0 if "f304=0" in p.stderr else None,
                    "memory_fault_instruction":re.search(r"inst=([0-9a-fA-F]{8})",p.stderr).group(1) if re.search(r"inst=([0-9a-fA-F]{8})",p.stderr) else None,
                    "memory_fault_linear":re.search(r"mem=1:([0-9a-fA-F]{8})",p.stderr).group(1) if re.search(r"mem=1:([0-9a-fA-F]{8})",p.stderr) else None,
                    "memory_fault_width":re.search(r"width=(\d+)",p.stderr).group(1) if re.search(r"width=(\d+)",p.stderr) else None,
                    "x87_trace":[{"eip":va,"eax":eax,"ebp":ebp,"esp":esp,"stack16":stack,
                                  "control_word":cw,"fp_top":int(top)}
                        for va,eax,ebp,esp,stack,cw,top in re.findall(
                            r"X87_STEP eip=([0-9a-fA-F]{8}) EAX=([0-9a-fA-F]{8}) EBP=([0-9a-fA-F]{8}) ESP=([0-9a-fA-F]{8}) stack16=([0-9a-fA-F]{4}) CW=([0-9a-fA-F]{4}) top=(-?\d+)",p.stderr)],
                    "runtime_icalls":re.findall(r"INIT_ICALL index=\d+ target=([0-9a-fA-F]{8})",p.stderr),
                    "next_causal_dependency":"The actual caller FUN_000AF9E4 prepares guest environment selector/pointer globals before calling __InitRtns. This test calls __InitRtns directly, so setenvp sees zero at its environment fields; run the original caller with its DOS/4GW-derived selector state rather than seeding those fields.",
                    "title_transition_reached":False,
                    "title_object_guest":"0x0035EAB8","global_this_guest":"0x002EECA8"},
                "rea":{"provider":"REA 6.4.0 / Ghidra 12.1.4","analysis_evidence_id":"ev_8f832e870438c1ecf8c51a047be0f1f4b371354efe5c6937e39abc3e5697fd2e",
                    "bytes_evidence_id":"ev_b82c1532cf08ba9c16a5c0d4174db55543f98a28fb2c92b0c7211b623641cc04",
                    "init_caller_evidence_id":"ev_9fce82c1d628937391502f93f2f5fe9fbb3b8a0a21050931bdbcb6c609a30fdb",
                    "init_caller_analysis_evidence_id":"ev_458005f303d1bb91c768a55d2d913bca2a9f8608ac6a2ac0707f2a447a425622",
                    "limitation":"REA queried the immutable x86 PE carrier with Ghidra 12.1.4; its x87 code bytes match canonical LE/Capstone after normalizing loader fixups, and the carrier is not itself an LE analysis"}}
            (ROOT/"evidence"/"native_ifctitle_watcom_initrtns_failure.json").write_text(
                json.dumps(capture,indent=2)+"\n",encoding="utf-8")
            print(f"BLOCKED original Watcom __InitRtns frontier captured: {log_path}",file=sys.stderr)
            raise SystemExit(75)
        if (Path(str(command[0])).name.lower()=="test_ifctitle_creature_probe.exe" and
                p.returncode==72):
            trace=(p.stdout+"\n"+p.stderr).encode("utf-8",errors="replace")
            log_path=ROOT/"evidence"/"native_ifctitle_options_transition_failure.log"
            log_path.write_bytes(trace)
            stdout_path=ROOT/"evidence"/"native_ifctitle_options_transition.stdout.log"
            stderr_path=ROOT/"evidence"/"native_ifctitle_options_transition.stderr.log"
            stdout_path.write_text(p.stdout,encoding="utf-8")
            stderr_path.write_text(p.stderr,encoding="utf-8")
            capture={"schema":"gw-ifctitle-options-transition-capture/v1",
                "target_sha256":EXPECTED_TARGET,"exit_code":p.returncode,
                "command":[str(x) for x in command],"stdout_bytes":len(p.stdout.encode("utf-8")),
                "stderr_bytes":len(p.stderr.encode("utf-8")),"log":str(log_path.relative_to(ROOT)),
                "log_sha256":hashlib.sha256(trace).hexdigest(),
                "stdout_log":str(stdout_path.relative_to(ROOT)),"stdout_sha256":sha(stdout_path),
                "stderr_log":str(stderr_path.relative_to(ROOT)),"stderr_sha256":sha(stderr_path),
                "classification":"transition reached original IFCOptions::PlugIn return, then failed the harness memory-integrity check"}
            (ROOT/"evidence"/"native_ifctitle_options_transition_failure.json").write_text(
                json.dumps(capture,indent=2)+"\n",encoding="utf-8")
            print(f"BLOCKED expected transition integrity finding; trace saved: {log_path}",file=sys.stderr)
            raise SystemExit(p.returncode)
        if (Path(str(command[0])).name.lower()=="test_ifctitle_creature_probe.exe" and
                p.returncode==79):
            trace=(p.stdout+"\n"+p.stderr).encode("utf-8",errors="replace")
            log_path=ROOT/"evidence"/"native_ifctitle_memory_table_boundary.log"
            log_path.write_bytes(trace)
            capture={"schema":"gw-ifctitle-memory-table-boundary/v1",
                "target_sha256":EXPECTED_TARGET,"exit_code":p.returncode,
                "log":str(log_path.relative_to(ROOT)),"log_sha256":sha(log_path),
                "classification":"original LbDataLoadAll returned; harness stopped at the guest-allocation bounds check before OPTIONS"}
            (ROOT/"evidence"/"native_ifctitle_memory_table_boundary.json").write_text(
                json.dumps(capture,indent=2)+"\n",encoding="utf-8")
            print(f"BLOCKED memory table allocation boundary captured: {log_path}",file=sys.stderr)
            print(p.stdout,end="")
            print(p.stderr,end="",file=sys.stderr)
            raise SystemExit(p.returncode)
        if (Path(str(command[0])).name.lower()=="test_ifctitle_creature_probe.exe" and
                p.returncode==94):
            trace=(p.stdout+"\n"+p.stderr).encode("utf-8",errors="replace")
            log_path=ROOT/"evidence"/"native_ifcoptions_options_to_title_boundary.log"
            log_path.write_bytes(trace)
            capture={"schema":"gw-ifcoptions-options-to-title-boundary/v1",
                "target_sha256":EXPECTED_TARGET,"exit_code":p.returncode,
                "log":str(log_path.relative_to(ROOT)),
                "log_sha256":hashlib.sha256(trace).hexdigest(),
                "classification":"The bounded original OPTIONS-to-TITLE transition reached an unresolved formatter callback after the VFS returned file-not-found for DATA/MAIN.GLA; MCB integrity was intact.",
                "verified_resource_added_for_next_attempt":{"guest_path":"data/main.gla",
                    "host_path":"DATA/MAIN.GLA","sha256":"c5e12a5b4325c8302cab0fb3ba3aaa654e2e044131763298815766d8a6f47a58"}}
            (ROOT/"evidence"/"native_ifcoptions_options_to_title_boundary.json").write_text(
                json.dumps(capture,indent=2)+"\n",encoding="utf-8")
            print(f"BLOCKED original return transition at unresolved load-error callback; trace saved: {log_path}",file=sys.stderr)
            for line in (p.stdout+"\n"+p.stderr).splitlines():
                if line.startswith(("TRACE DOS MCB ","TRACE DOS AH48 trapped", "TRACE allocations:",
                                    "TRACE original RationalAlloc ",
                                    "TRACE invoke ","TRACE original VFS open path='data/main.gla'",
                                    "original game() did not complete")):
                    print(line,file=sys.stderr)
            raise SystemExit(p.returncode)
        if (Path(str(command[0])).name.lower()=="test_ifctitle_creature_probe.exe" and
                p.returncode==95):
            trace=(p.stdout+"\n"+p.stderr).encode("utf-8",errors="replace")
            log_path=ROOT/"evidence"/"native_ifcoptions_return_title_palette_boundary.log"
            log_path.write_bytes(trace)
            capture={"schema":"gw-ifcoptions-return-title-palette-boundary/v1",
                "target_sha256":EXPECTED_TARGET,"exit_code":p.returncode,
                "log":str(log_path.relative_to(ROOT)),
                "log_sha256":hashlib.sha256(trace).hexdigest(),
                "classification":"OPTIONS->TITLE completed; the test stopped while validating the palette record from the original titleGfx_files table at guest 0x2DFEE8."}
            (ROOT/"evidence"/"native_ifcoptions_return_title_palette_boundary.json").write_text(
                json.dumps(capture,indent=2)+"\n",encoding="utf-8")
            print(f"BLOCKED returned TITLE palette record captured: {log_path}",file=sys.stderr)
            print(p.stdout,end="")
            print(p.stderr,end="",file=sys.stderr)
            raise SystemExit(p.returncode)
        if (Path(str(command[0])).name.lower()=="test_ifctitle_creature_probe.exe" and
                p.returncode in (101,102,103)):
            trace=(p.stdout+"\n"+p.stderr).encode("utf-8",errors="replace")
            log_path=ROOT/"evidence"/"native_ifctitle_new_game_input_boundary.log"
            log_path.write_bytes(trace)
            rows=(p.stdout+"\n"+p.stderr).splitlines()
            return_trace=next((line for line in rows if line.startswith("TRACE OPTIONS->TITLE original game() block ")),None)
            title_return_pass=any(line.startswith("PASS original game() completed OPTIONS PullOut") for line in rows)
            title_frame_pass=any(line.startswith("PASS returned TITLE original Update/Draw") for line in rows)
            options_return={"schema":"gw-native-ifcoptions-return-title/v1",
                "target_sha256":EXPECTED_TARGET,"execution":"bounded original-code partial closure; experimental VBE profile",
                "transition_trace":return_trace,"transition_completed":title_return_pass,
                "returned_title_update_draw_completed":title_frame_pass,
                "framebuffer":{"surface":"evidence/native_ifcoptions_return_title_wscreen.raw",
                    "palette":"evidence/native_ifcoptions_return_title_palette6.raw",
                    "sdl_capture":"evidence/native_ifcoptions_return_title_sdl.bmp",
                    "surface_sha256":sha(ROOT/"evidence"/"native_ifcoptions_return_title_wscreen.raw")
                        if (ROOT/"evidence"/"native_ifcoptions_return_title_wscreen.raw").exists() else None,
                    "sdl_sha256":sha(ROOT/"evidence"/"native_ifcoptions_return_title_sdl.bmp")
                        if (ROOT/"evidence"/"native_ifcoptions_return_title_sdl.bmp").exists() else None},
                "next_boundary":"UN JUGADOR original title Update/input path",
                "passed":bool(return_trace and title_return_pass and title_frame_pass)}
            (ROOT/"evidence"/"native_ifcoptions_return_title.json").write_text(
                json.dumps(options_return,indent=2)+"\n",encoding="utf-8")
            combined_log=p.stdout+"\n"+p.stderr
            update_match=re.search(r"TRACE invoke failure entry=0005af12[^\r\n]*",combined_log)
            update_failure=update_match.group(0) if update_match else None
            unresolved_match=re.search(
                r"ICALL: unresolved VA 0x([0-9A-Fa-f]{8}) from 0x([0-9A-Fa-f]{8})",
                combined_log)
            unresolved_guest=(int(unresolved_match.group(1),16)
                              if unresolved_match else None)
            object1_link_candidate=(unresolved_guest-0x001EB000
                                    if unresolved_guest is not None else None)
            object1_link_verified=(0x00010000<=object1_link_candidate<0x000EF930
                                   if object1_link_candidate is not None else False)
            icall_trace=[line for line in rows if line.startswith("TRACE invoke icall[")]
            stack_trace=[line for line in rows if line.startswith("TRACE invoke stack[")]
            capture={"schema":"gw-ifctitle-new-game-input-boundary/v1",
                "target_sha256":EXPECTED_TARGET,"exit_code":p.returncode,
                "log":str(log_path.relative_to(ROOT)),
                "log_sha256":hashlib.sha256(trace).hexdigest(),
                "classification":("Original TITLE Update dispatched the id=0 UN JUGADOR click into its authentic ResetGame/file path; the original Watcom fatal/exit cleanup callback was reached and remains fail-closed."
                    if unresolved_match else
                    "The returned original TITLE state reached the UN JUGADOR input probe; the log captures the first failed SDL/controller cycle or missing natural pending interface."),
                "options_to_title":{"trace":return_trace,"transition_completed":title_return_pass,
                    "returned_title_update_draw_completed":title_frame_pass,
                    "evidence":"evidence/native_ifcoptions_return_title.json"},
                "dos_memory_profile":{"kind":"experimental bounded 640-KiB conventional memory",
                    "top_segment":f"0x{DOS_CONVENTIONAL_TOP:04X}",
                    "initial_free_paragraphs":f"0x{DOS_CONVENTIONAL_TOP-0x0907:04X}",
                    "image_base":f"0x{HARNESS_IMAGE_BASE:08X}",
                    "image_does_not_overlap_conventional_top":HARNESS_IMAGE_BASE>=DOS_CONVENTIONAL_TOP*16},
                "failed_update":update_failure,
                "unresolved_indirect":({"target":f"0x{unresolved_match.group(1).upper()}",
                    "caller":f"0x{unresolved_match.group(2).upper()}",
                    "object1_link_candidate":(f"0x{object1_link_candidate:08X}"
                        if object1_link_candidate is not None else None),
                    "object1_candidate_within_verified_image":object1_link_verified,
                    "object1_rebase":"0x001EB000",
                    "target_link_va":"0x98C18" if object1_link_candidate==0x98C18 else
                        "0xC3518" if object1_link_candidate==0xC3518 else None,
                    "instruction":"C3 (RET)" if object1_link_candidate==0x98C18 else None,
                    "evidence":"Use the original LE fixup table and REA/Capstone for any link candidate; an indirect target is not accepted from arithmetic alone."}
                    if unresolved_match else None),
                "stack":stack_trace,"recent_indirect_calls":icall_trace}
            (ROOT/"evidence"/"native_ifctitle_new_game_input_boundary.json").write_text(
                json.dumps(capture,indent=2)+"\n",encoding="utf-8")
            print(f"BLOCKED original UN JUGADOR input boundary captured: {log_path}",file=sys.stderr)
            for line in (p.stdout+"\n"+p.stderr).splitlines():
                if line.startswith(("TRACE original UN JUGADOR","TRACE SDL interface input","PASS returned TITLE","original UN JUGADOR","original TITLE")):
                    print(line,file=sys.stderr)
            raise SystemExit(p.returncode)
        print(f"FAILED command ({p.returncode}): " + " ".join(str(x) for x in command),file=sys.stderr)
        if quiet and (p.stdout or p.stderr):
            rows=(p.stdout+"\n"+p.stderr).splitlines()
            useful=[line for line in rows if line.startswith(("TRACE original ","TRACE DOS MCB ","TRACE DOS AH48 ","TRACE HEAP ","TRACE RATIONAL ","TRACE guest-low-write ","TRACE invoke ","TRACE CRT DPMI ","TRACE CRT DPMI AX=0100","LbMemorySetup failed","authentic IFCTitle::","original palette writer failed","ITAIL: unresolved","memory fault")) or "error:" in line or "warning:" in line]
            if not useful: useful=rows[-80:]
            for line in useful[-40:]: print(line,file=sys.stderr)
        elif quiet:
            print(f"FAILED command produced no output; stdout={p.stdout!r} stderr={p.stderr!r}",file=sys.stderr)
        else:
            if p.stdout: print(p.stdout,end="",file=sys.stderr)
            if p.stderr: print(p.stderr,end="",file=sys.stderr)
        raise SystemExit(p.returncode)
    return p

CACHE_OBJECT_STATUS:dict[str,str]={}
CACHE_OBJECT_KEY_DIAGNOSTICS:dict[str,dict]={}
_OBJECT_CACHE_SUPPORT=None

def object_cache_support():
    global _OBJECT_CACHE_SUPPORT
    if _OBJECT_CACHE_SUPPORT is None:
        module_path=ROOT/"tools"/"rebuild"/"object_cache.py"
        spec=importlib.util.spec_from_file_location("gwrecomp_object_cache",module_path)
        if spec is None or spec.loader is None:
            raise SystemExit(f"object-cache helper is unavailable: {module_path}")
        module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _OBJECT_CACHE_SUPPORT=module
    return _OBJECT_CACHE_SUPPORT

def compile_cached(source:Path,obj:Path,compile_flags:list[object],label:str,
                  header_roots:list[Path],timeout:int=300)->Path:
    """Compile one translation unit and reuse its object while inputs match."""
    cache_root=os.environ.get("GWRECOMP_OBJECT_CACHE")
    if cache_root:
        if os.environ.get("GWRECOMP_OBJECT_CACHE_LOCKED")!="1":
            raise SystemExit("object-cache mode requires rebuild.ps1's exclusive workspace lock")
        cache_support=object_cache_support()
        try:
            dependencies,compiler_identity=cache_support.discover_dependencies(source,compile_flags,ROOT,ENV)
            cache_key=cache_support.object_cache_key(source,compile_flags,dependencies,ROOT,
                                                     compiler_identity,ENV)
            if os.environ.get("GWRECOMP_OBJECT_CACHE_DIAGNOSTICS")=="1":
                CACHE_OBJECT_KEY_DIAGNOSTICS[source.stem+".obj"]=(
                    cache_support.object_cache_key_diagnostics(
                        source,compile_flags,dependencies,ROOT,compiler_identity,ENV))
            obj,hit=cache_support.compile_content_addressed(
                source,Path(cache_root),cache_key,[*compile_flags,"-c",source,"-o",obj],
                lambda command:run(command,timeout=timeout,quiet=True))
            CACHE_OBJECT_STATUS[source.stem+".obj"]=("hit" if hit else "miss")
            print(f"TRACE compile-cache {'hit' if hit else 'miss'} {label} {obj.name}")
        except (cache_support.CacheUnsafeInput,OSError,UnicodeError) as exc:
            # Unsupported or incomplete input discovery never consults shared cache.
            obj=ROOT/"work"/"native_ifctitle_plugin_load_at_objs"/(source.stem+".obj")
            obj.parent.mkdir(parents=True,exist_ok=True)
            run([*compile_flags,"-c",source,"-o",obj],timeout=timeout,quiet=True)
            CACHE_OBJECT_STATUS[source.stem+".obj"]="bypass"
            print(f"TRACE compile-cache bypass {label}: {exc}")
    else:
        headers=[]
        for root in header_roots:
            if root.is_dir(): headers.extend(root.rglob("*.h"))
        digest=hashlib.sha256()
        digest.update("\0".join(str(x) for x in compile_flags).encode("utf-8"))
        digest.update(source.read_bytes())
        for header in sorted(set(headers)):
            digest.update(str(header).encode("utf-8"))
            digest.update(header.read_bytes())
        cache_key=digest.hexdigest()
        stamp=obj.with_suffix(obj.suffix+".sha256")
        if obj.is_file() and stamp.is_file() and stamp.read_text(encoding="ascii").strip()==cache_key:
            print(f"TRACE compile-cache hit {label} {obj.name}")
            return obj
        obj.parent.mkdir(parents=True,exist_ok=True)
        run([*compile_flags,"-c",source,"-o",obj],timeout=timeout,quiet=True)
        stamp.write_text(cache_key+"\n",encoding="ascii")
        print(f"TRACE compile-cache rebuilt {label} {obj.name}")
    return obj

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
    if not GENEWARS_CUE.is_file() or (sha(GENEWARS_CUE)!=EXPECTED_GENEWARS_CUE and not cue_matches_profile(GENEWARS_CUE)):
        raise SystemExit("read-only GeneWars CUE is unavailable or its verified digest changed")
    sys.path.insert(0,str(ROOT/"runtime"))
    from dos_cdrom import CueImage
    cue_image=CueImage.from_cue(GENEWARS_CUE)
    if (cue_image.mscdex_disc_info()!=(1,5,60,38,59) or
        tuple(cue_image.mscdex_track_info(n) for n in range(1,6)) != (
            (1,0,2,0,0x40),(2,26,38,22,0),(3,3,45,31,0),
            (4,2,38,41,0),(5,42,52,54,0)) or
        cue_image.mscdex_idle_subchannel()!=(0x40,1,1,0,0,0,0,2,0)):
        raise SystemExit("CUE-derived MSCDEX metadata differs from the read-only profile wired into the native harness")
    audio_tracks=[track for track in cue_image.tracks if track.mode=="AUDIO"]
    if (not audio_tracks or any(track.mode!="AUDIO" for track in cue_image.tracks
                                if audio_tracks[0].number<=track.number<=audio_tracks[-1].number)):
        raise SystemExit("CUE audio extent is not one contiguous run of audio tracks")
    mscdex_audio_begin=audio_tracks[0].lba_start+audio_tracks[0].index01
    mscdex_audio_end=audio_tracks[-1].lba_start+audio_tracks[-1].sectors
    if not CONFIG_INI.is_file() or not BIOINTRO.is_file():
        raise SystemExit("verified local CONFIG.INI or INTRO/BIOINTRO.SMK is unavailable")
    config_hash=sha(CONFIG_INI)
    intro_hash=sha(BIOINTRO)
    if (EXPECTED_CONFIG_INI and config_hash!=EXPECTED_CONFIG_INI) or intro_hash!=EXPECTED_BIOINTRO:
        raise SystemExit(f"local setup_game input hash mismatch: CONFIG.INI={config_hash} BIOINTRO.SMK={intro_hash}")
    resource_inputs={}
    for rel,expected in TITLE_RESOURCES.items():
        path=INSTALL/Path(rel)
        actual=sha(path)
        if actual!=expected: raise SystemExit(f"exact-build title resource hash mismatch: {rel} {actual}")
        resource_inputs[rel]={"path":str(path),"sha256":actual,"size":path.stat().st_size,
                              "provenance":"read-only files in local GeneWars 1.1 installation"}
    save_profile=detect_save_profile()
    if save_profile=="reference-save":
        path=INSTALL/"SAVE"/"SAVE0.SAV"
        resource_inputs["SAVE/SAVE0.SAV"]={"path":str(path),"sha256":sha(path),"size":path.stat().st_size,
                              "provenance":"read-only reference save of the maintainers (regression profile)"}
    print(f"TRACE save_profile {save_profile}",flush=True)
    interface_resource_inputs={}
    for rel,expected in INTERFACE_RESOURCES.items():
        path=INSTALL/Path(rel)
        actual=sha(path)
        if actual!=expected: raise SystemExit(f"exact-build interface resource hash mismatch: {rel} {actual}")
        interface_resource_inputs[rel]={"path":str(path),"sha256":actual,"size":path.stat().st_size,
                              "provenance":"read-only files in local GeneWars 1.1 installation"}
    manifest_tsv,install_manifest=create_install_manifest()
    sys.path[:0]=[str(ROOT/"src"),str(ROOT/"third_party"/"pcrecomp")]
    sys.path.insert(0,str(ROOT/"runtime"))
    import guest_boot
    from dos_services import DosHost
    from le_loader import load_le
    from tools.disasm.disasm32 import Disassembler
    from tools.pe.pe_analyze import Section
    from tools.lift.lift32 import Lifter

    # DOS environment block of the original capture (DOSBox defaults plus BLASTER),
    # published as a small fixture; it contains no game data.
    env_fixture=json.loads((ROOT/"tools"/"rebuild"/"fixtures"/"dos_environment.json").read_text(encoding="utf-8"))
    env_hex=env_fixture.get("environment_hex")
    if (env_fixture.get("schema")!="gwrecomp-dos-environment/v1" or
            env_fixture.get("target_sha256","").lower()!=EXPECTED_TARGET):
        raise SystemExit("DOS environment fixture is unavailable or does not match the target")
    original_environment=bytes.fromhex(env_hex)
    env_sha256=hashlib.sha256(original_environment).hexdigest()
    if (len(original_environment)!=86 or env_sha256!="65c4d22c258efbf93a93cfcaa8d9d8c489e510cb2be76530646c36e0250ee895" or
            env_fixture.get("sha256")!=env_sha256):
        raise SystemExit("DOS environment payload failed the hash/length check")
    boot=guest_boot.prepare_native_lift_guest(TARGET,command_tail=b"-k 38928",
        environment_block=original_environment)
    psp_selector,env_selector=0x0024,0x1100
    boot.memory.write(boot.psp_address+0x2c,struct.pack("<H",env_selector))
    # Reuse the Runtime's post-DOS/4GW MCB model. The old C harness copied a
    # zero-filled low-memory prefix, so original AH=48 encountered no MCB at
    # 0x0906 and trapped before it could return a legitimate DOS result. The
    # model derives PSP/environment reservations from this verified boot
    # fixture and exposes only conventional RAM below A0000; the LE image
    # begins at 0xF0000 and the DPMI arena remains independently bounded.
    # This particular native harness copies the lifted image to 0xF0000;
    # tell the existing boot-layout validator about that active guest address
    # (the LE loader's link mem_base remains 0x10000 in its own coordinate
    # system and must not cap conventional DOS memory here).
    boot.image.mem_base=HARNESS_IMAGE_BASE
    dos_boot=DosHost(boot,dos_memory_profile="post_dos4gw_le_entry",
        dos_memory_top_segment=DOS_CONVENTIONAL_TOP)
    dos_layout=dos_boot.dos_mcb_layout
    if (dos_layout["psp_segment"]!=0x0800 or
            dos_layout["environment_segment"]!=0x0900 or
            dos_layout["free_data_segment"]!=0x0907 or
            dos_layout["free_paragraphs"]!=(DOS_CONVENTIONAL_TOP-0x0907) or
            dos_layout["top_segment"]!=DOS_CONVENTIONAL_TOP or
            dos_layout["le_image_start"]<DOS_CONVENTIONAL_TOP*16):
        raise SystemExit(f"DOS MCB fixture overlaps a reserved region: {dos_layout}")
    startup_lowmem=ROOT/"work"/"ifctitle_startup_lowmem.bin"
    startup_lowmem.write_bytes(bytes(boot.memory.data[:0x10000]))
    if startup_lowmem.stat().st_size!=0x10000:
        raise SystemExit("startup low-memory fixture is not exactly the bounded conventional prefix")

    image=load_le(TARGET,object_rebases=REBASES)
    # The active process_packets body loads a code-table pointer from
    # [EBX+0x25] at 0x82F6F and invokes [EDX] at 0x82F77. With the measured
    # Obj3 rebase (+0x1DA000), guest 0x002EBCF8 maps to link 0x00111CF8
    # (not 0x001120F8). Its canonical LE SRC_OFFSET32 fixup resolves to the
    # original Obj1 entry 0x55CF0; runtime admission below requires equality
    # with this exact fixup-backed target.
    packet_method_slot=0x111CF8
    packet_method_fixup=next((f for f in image.fixups if f.source_link==packet_method_slot),None)
    packet_method_link=(image.objects[0].base+packet_method_fixup.target_offset
                        if packet_method_fixup is not None else None)
    packet_method_owner=image.object_containing(packet_method_slot)
    packet_method_target=image.object_containing(packet_method_link) if packet_method_link is not None else None
    packet_method_guest=image.link_to_linear(0x55CF0)
    packet_method_code_owner=image.object_containing(0x55CF0)
    # During the post-order simulation the same original CALL [EDX] at
    # 0x82F77 also receives the object-3 address point 0x111CDC.  This is a
    # distinct embedded interface pointer, not a reason to widen the first
    # receiver's contract.  Admit its first slot only when the canonical LE
    # SRC_OFFSET32 fixup points to executable object-1 code.
    packet_method_alt_slot=0x111CDC
    packet_method_alt_fixup=next((f for f in image.fixups if f.source_link==packet_method_alt_slot),None)
    packet_method_alt_link=(image.objects[0].base+packet_method_alt_fixup.target_offset
                            if packet_method_alt_fixup is not None else None)
    packet_method_alt_owner=(image.object_containing(packet_method_alt_link)
                             if packet_method_alt_link is not None else None)
    packet_method_alt_guest=(image.link_to_linear(packet_method_alt_link)
                             if packet_method_alt_link is not None else None)
    packet_action_slot=0x111F0C
    packet_action_fixup=next((f for f in image.fixups if f.source_link==packet_action_slot),None)
    packet_action_link=(image.objects[0].base+packet_action_fixup.target_offset
                        if packet_action_fixup is not None else None)
    packet_action_code_owner=image.object_containing(packet_action_link) if packet_action_link is not None else None
    packet_entity_slot=0x111DB4
    packet_entity_fixup=next((f for f in image.fixups if f.source_link==packet_entity_slot),None)
    packet_entity_link=(image.objects[0].base+packet_entity_fixup.target_offset
                        if packet_entity_fixup is not None else None)
    packet_entity_code_owner=image.object_containing(packet_entity_link) if packet_entity_link is not None else None
    packet_entity_next_slot=0x111D90
    packet_entity_next_fixup=next((f for f in image.fixups if f.source_link==packet_entity_next_slot),None)
    packet_entity_next_link=(image.objects[0].base+packet_entity_next_fixup.target_offset
                             if packet_entity_next_fixup is not None else None)
    packet_entity_next_owner=image.object_containing(packet_entity_next_link) if packet_entity_next_link is not None else None
    packet_entity_type_slot=0x111D14
    packet_entity_type_fixup=next((f for f in image.fixups if f.source_link==packet_entity_type_slot),None)
    packet_entity_type_link=(image.objects[0].base+packet_entity_type_fixup.target_offset
                             if packet_entity_type_fixup is not None else None)
    packet_entity_type_owner=image.object_containing(packet_entity_type_link) if packet_entity_type_link is not None else None
    packet_entity_movement_slot=0x111DB8
    packet_entity_movement_fixup=next((f for f in image.fixups if f.source_link==packet_entity_movement_slot),None)
    packet_entity_movement_link=(image.objects[0].base+packet_entity_movement_fixup.target_offset
                                 if packet_entity_movement_fixup is not None else None)
    packet_entity_movement_owner=(image.object_containing(packet_entity_movement_link)
                                  if packet_entity_movement_link is not None else None)
    packet_creature_state_slot=0x111D6C
    packet_creature_state_fixup=next((f for f in image.fixups if f.source_link==packet_creature_state_slot),None)
    packet_creature_state_link=(image.objects[0].base+packet_creature_state_fixup.target_offset
                                if packet_creature_state_fixup is not None else None)
    packet_creature_state_owner=image.object_containing(packet_creature_state_link) if packet_creature_state_link is not None else None
    packet_creature_init_slot=0x111D84
    packet_creature_init_fixup=next((f for f in image.fixups if f.source_link==packet_creature_init_slot),None)
    packet_creature_init_link=(image.objects[0].base+packet_creature_init_fixup.target_offset
                               if packet_creature_init_fixup is not None else None)
    packet_creature_init_owner=image.object_containing(packet_creature_init_link) if packet_creature_init_link is not None else None
    packet_mapdisplay_state_slot=0x111F14
    packet_mapdisplay_state_fixup=next((f for f in image.fixups if f.source_link==packet_mapdisplay_state_slot),None)
    packet_mapdisplay_state_link=(image.objects[0].base+packet_mapdisplay_state_fixup.target_offset
                                  if packet_mapdisplay_state_fixup is not None else None)
    packet_mapdisplay_state_owner=(image.object_containing(packet_mapdisplay_state_link)
                                   if packet_mapdisplay_state_link is not None else None)
    packet_biogame_vtable_slot=0x111EC0
    packet_biogame_vtable_fixup=next((f for f in image.fixups if f.source_link==packet_biogame_vtable_slot),None)
    packet_biogame_vtable_link=(image.objects[0].base+packet_biogame_vtable_fixup.target_offset
                                if packet_biogame_vtable_fixup is not None else None)
    packet_biogame_vtable_owner=(image.object_containing(packet_biogame_vtable_link)
                                 if packet_biogame_vtable_link is not None else None)
    packet_mapdisplay_vtable_slot=0x111EB4
    packet_mapdisplay_vtable_fixup=next((f for f in image.fixups if f.source_link==packet_mapdisplay_vtable_slot),None)
    packet_mapdisplay_vtable_link=(image.objects[0].base+packet_mapdisplay_vtable_fixup.target_offset
                                   if packet_mapdisplay_vtable_fixup is not None else None)
    packet_mapdisplay_vtable_owner=(image.object_containing(packet_mapdisplay_vtable_link)
                                    if packet_mapdisplay_vtable_link is not None else None)
    packet_biogame_effect_slot=0x111D8C
    packet_biogame_effect_fixup=next((f for f in image.fixups if f.source_link==packet_biogame_effect_slot),None)
    packet_biogame_effect_link=(image.objects[0].base+packet_biogame_effect_fixup.target_offset
                                if packet_biogame_effect_fixup is not None else None)
    packet_biogame_effect_owner=(image.object_containing(packet_biogame_effect_link)
                                 if packet_biogame_effect_link is not None else None)
    creature_probe_query_slot=0x111D94
    creature_probe_query_fixup=next((f for f in image.fixups if f.source_link==creature_probe_query_slot),None)
    creature_probe_query_link=(image.objects[0].base+creature_probe_query_fixup.target_offset
                               if creature_probe_query_fixup is not None else None)
    creature_probe_query_owner=(image.object_containing(creature_probe_query_link)
                                if creature_probe_query_link is not None else None)
    # FUN_00058330 shares the same instruction for multiple Thing vtables.
    # The live Effect table at 0x1121E4 has its own +0x90 SRC_OFFSET32 fixup;
    # this is distinct from the TT_CREATURE table at 0x111D94.
    effect_probe_query_slot=0x112274
    effect_probe_query_fixup=next((f for f in image.fixups if f.source_link==effect_probe_query_slot),None)
    effect_probe_query_link=(image.objects[0].base+effect_probe_query_fixup.target_offset
                             if effect_probe_query_fixup is not None else None)
    effect_probe_query_owner=(image.object_containing(effect_probe_query_link)
                              if effect_probe_query_link is not None else None)
    if (packet_method_fixup is None or packet_method_fixup.source_type!=0x07 or
            packet_method_fixup.target_object!=1 or packet_method_link!=0x55CF0 or
            packet_method_owner is None or packet_method_owner.index!=3 or
            packet_method_target is None or not packet_method_target.executable or
            packet_method_guest!=0x00240CF0 or packet_method_code_owner is None or
            not packet_method_code_owner.executable or
            packet_method_alt_fixup is None or packet_method_alt_fixup.source_type!=0x07 or
            packet_method_alt_fixup.target_object!=1 or packet_method_alt_fixup.target_flags&0x03 or
            packet_method_alt_link!=0x454E0 or packet_method_alt_owner is None or
            not packet_method_alt_owner.executable or packet_method_alt_guest!=0x002304E0 or
            bytes(image.object_data(1))[0x82F6F-image.objects[0].base:0x82F6F-image.objects[0].base+3]
                !=bytes.fromhex("8B 53 25") or
            bytes(image.object_data(1))[0x82F77-image.objects[0].base:0x82F77-image.objects[0].base+2]
                !=bytes.fromhex("FF 12") or
            packet_action_fixup is None or packet_action_fixup.source_type!=0x07 or
            packet_action_fixup.target_object!=1 or packet_action_link!=0x78360 or
            packet_action_code_owner is None or not packet_action_code_owner.executable or
            bytes(image.object_data(1))[0x561E9-image.objects[0].base:0x561E9-image.objects[0].base+3]
                !=bytes.fromhex("FF 52 68") or
            packet_entity_fixup is None or packet_entity_fixup.source_type!=0x07 or
            packet_entity_fixup.target_object!=1 or packet_entity_link!=0x6A030 or
            packet_entity_code_owner is None or not packet_entity_code_owner.executable or
            bytes(image.object_data(1))[0x50164-image.objects[0].base:0x50164-image.objects[0].base+6]
                !=bytes.fromhex("FF 92 B0 00 00 00") or
            packet_entity_next_fixup is None or packet_entity_next_fixup.source_type!=0x07 or
            packet_entity_next_fixup.target_object!=1 or packet_entity_next_link!=0x47A90 or
            packet_entity_next_owner is None or not packet_entity_next_owner.executable or
            bytes(image.object_data(1))[0x5017E-image.objects[0].base:0x5017E-image.objects[0].base+6]
                !=bytes.fromhex("FF 93 8C 00 00 00") or
            packet_entity_type_fixup is None or packet_entity_type_fixup.source_type!=0x07 or
            packet_entity_type_fixup.target_object!=1 or packet_entity_type_link!=0x6A240 or
            packet_entity_type_owner is None or not packet_entity_type_owner.executable or
            bytes(image.object_data(1))[0x47A9E-image.objects[0].base:0x47A9E-image.objects[0].base+3]
                !=bytes.fromhex("FF 52 10") or
            packet_entity_movement_fixup is None or packet_entity_movement_fixup.source_type!=0x07 or
            packet_entity_movement_fixup.target_object!=1 or packet_entity_movement_link!=0x59D80 or
            packet_entity_movement_owner is None or not packet_entity_movement_owner.executable or
            packet_creature_state_fixup is None or packet_creature_state_fixup.source_type!=0x07 or
            packet_creature_state_fixup.target_object!=1 or packet_creature_state_link!=0x6A070 or
            packet_creature_state_owner is None or not packet_creature_state_owner.executable or
            bytes(image.object_data(1))[0x80F86-image.objects[0].base:0x80F86-image.objects[0].base+3]
                !=bytes.fromhex("FF 51 68") or
            packet_creature_init_fixup is None or packet_creature_init_fixup.source_type!=0x07 or
            packet_creature_init_fixup.target_object!=1 or packet_creature_init_link!=0x47360 or
            packet_creature_init_owner is None or not packet_creature_init_owner.executable or
            bytes(image.object_data(1))[0x502E1-image.objects[0].base:0x502E1-image.objects[0].base+6]
                !=bytes.fromhex("FF 92 80 00 00 00") or
            packet_mapdisplay_state_fixup is None or packet_mapdisplay_state_fixup.source_type!=0x07 or
            packet_mapdisplay_state_fixup.target_object!=1 or packet_mapdisplay_state_link!=0x6EC70 or
            packet_mapdisplay_state_owner is None or not packet_mapdisplay_state_owner.executable or
            bytes(image.object_data(1))[0x56F3B-image.objects[0].base:0x56F3B-image.objects[0].base+3]
                !=bytes.fromhex("FF 51 70") or
            packet_biogame_vtable_fixup is None or packet_biogame_vtable_fixup.source_type!=0x07 or
            packet_biogame_vtable_fixup.target_object!=1 or packet_biogame_vtable_link!=0x69E50 or
            packet_biogame_vtable_owner is None or not packet_biogame_vtable_owner.executable or
            bytes(image.object_data(1))[0x79218-image.objects[0].base:0x79218-image.objects[0].base+3]
                !=bytes.fromhex("FF 52 1C") or
            bytes(image.object_data(1))[0x5A2F5-image.objects[0].base:0x5A2F5-image.objects[0].base+3]
                !=bytes.fromhex("FF 52 10") or
            bytes(image.object_data(1))[0x5A70D-image.objects[0].base:0x5A70D-image.objects[0].base+3]
                !=bytes.fromhex("FF 52 10") or
            bytes(image.object_data(1))[0x5A9A0-image.objects[0].base:0x5A9A0-image.objects[0].base+3]
                !=bytes.fromhex("FF 92 B4") or
            bytes(image.object_data(1))[0x5A9B2-image.objects[0].base:0x5A9B2-image.objects[0].base+3]
                !=bytes.fromhex("FF 52 10") or
            bytes(image.object_data(1))[0x5AB28-image.objects[0].base:0x5AB28-image.objects[0].base+3]
                !=bytes.fromhex("FF 92 B4") or
            packet_mapdisplay_vtable_fixup is None or packet_mapdisplay_vtable_fixup.source_type!=0x07 or
            packet_mapdisplay_vtable_fixup.target_object!=1 or packet_mapdisplay_vtable_link!=0x6EE10 or
            packet_mapdisplay_vtable_owner is None or not packet_mapdisplay_vtable_owner.executable or
            bytes(image.object_data(1))[0x80A3A-image.objects[0].base:0x80A3A-image.objects[0].base+3]
                !=bytes.fromhex("FF 51 10") or
            packet_biogame_effect_fixup is None or packet_biogame_effect_fixup.source_type!=0x07 or
            packet_biogame_effect_fixup.target_object!=1 or packet_biogame_effect_link!=0x47BF0 or
            packet_biogame_effect_owner is None or not packet_biogame_effect_owner.executable or
            bytes(image.object_data(1))[0x58BBD-image.objects[0].base:0x58BBD-image.objects[0].base+6]
                !=bytes.fromhex("FF 93 88 00 00 00") or
            creature_probe_query_fixup is None or creature_probe_query_fixup.source_type!=0x07 or
            creature_probe_query_fixup.target_object!=1 or creature_probe_query_link!=0x6A280 or
            creature_probe_query_owner is None or not creature_probe_query_owner.executable or
            bytes(image.object_data(1))[0x58C90-image.objects[0].base:0x58C90-image.objects[0].base+6]
                !=bytes.fromhex("FF 92 90 00 00 00") or
            effect_probe_query_fixup is None or effect_probe_query_fixup.source_type!=0x07 or
            effect_probe_query_fixup.target_object!=1 or effect_probe_query_link!=0x959E0 or
            effect_probe_query_owner is None or not effect_probe_query_owner.executable or
            bytes(image.object_data(1))[0x959E0-image.objects[0].base:0x959E0-image.objects[0].base+7]
                !=bytes.fromhex("52 31 D2 8A 50 45 8D") or
            bytes(image.object_data(1))[0x47C01-image.objects[0].base:0x47C01-image.objects[0].base+3]
                !=bytes.fromhex("FF 52 10") or
            bytes(image.object_data(1))[0x47C15-image.objects[0].base:0x47C15-image.objects[0].base+6]
                !=bytes.fromhex("FF 93 8C 00 00 00") or
            bytes(image.object_data(1))[0x47DC2-image.objects[0].base:0x47DC2-image.objects[0].base+3]
                !=bytes.fromhex("FF 53 10") or
            bytes(image.object_data(1))[0x55CF0-image.objects[0].base:0x55CF0-image.objects[0].base+8]
                !=_OrigDigest("ab0cfac86170350f06b49aa7dd533739d3f2e49e08db200b7990bdaa4b073e41",8)):
        raise SystemExit("packet call slot at 0x82F77 lacks its expected static LE fixup baseline")
    if not ReferenceMap.contains("0003:00111AE4       W?$Wvf0eo2i8:IFCLevel$$nx[]pn()v"):
        raise SystemExit("nearest MAP data symbol for the packet call slot changed")
    print("TRACE canonical packet call slots=00111CF8/00111CDC LE_fixups=object3->object1:00055CF0/000454E0 guests=002EBCF8/002EBCDC targets=00240CF0/002304E0; separate exact receiver contracts; MAP_nearest_named_data=IFCLevel method-array label at 00111AE4 extent_unproven")
    print("TRACE canonical process_packets creature-state call site=00056F3B bytes=FF-51-70 slot=00111F14 LE_fixup=object3->object1:0006EC70 runtime_guard=1")
    print("TRACE canonical process_packets BioGame slot call site=00079218 bytes=FF-52-1C slot=00111EC0 LE_fixup=object3->object1:00069E50 runtime_guard=1")
    print("TRACE canonical process_packets creature callback site=0005A2F5 bytes=FF-52-10 slot=00111D14 LE_fixup=object3->object1:0006A240 runtime_guard=1")
    print("TRACE canonical process_packets repeated creature callback site=0005A70D bytes=FF-52-10 slot=00111D14 LE_fixup=object3->object1:0006A240 runtime_guard=1")
    print("TRACE canonical process_packets entity batch sites=0005A9A0/0005A9B2/0005AB28 slots=00111DB8/00111D14 fixups=00059D80/0006A240 runtime_guards=3")
    print("TRACE canonical process_packets record walk site=00080A3A bytes=FF-51-10 slot=00111EB4 LE_fixup=object3->object1:0006EE10 runtime_guard=1")
    print("TRACE canonical BioGame effect handler site=00058BBD bytes=FF-93-88-00-00-00 slot=00111D8C LE_fixup=object3->object1:00047BF0 runtime_guard=1; alternate effect vtable 0011226C->0008A720 retained")
    print("TRACE canonical shared Thing query site=00058C90 bytes=FF-92-90-00-00-00 TT_CREATURE_slot=00111D94->0006A280 Effect_slot=00112274->000959E0 runtime_guard=exact-fixup-set")
    print("TRACE canonical FUN_00047BF0 vtable batch sites=00047C01/00047C15/00047DC2 slots=00111D14/00111D90/00111D14 targets=0006A240/00047A90/0006A240 fixups=3 runtime_guards=3")
    # The first post-transition Update walks records through FUN_000862F0.
    # Its two live virtual calls are not guessed from the failing guest value:
    # both slots belong to the same original object-3 table and have exact
    # object-1 SRC_OFFSET32 fixups in the canonical LE image.
    record_vtable_slots=((0x112220,0x851B0,0x2701B0),
                         (0x112244,0x85070,0x270070))
    for source_link,target_link,target_guest in record_vtable_slots:
        fixup=next((x for x in image.fixups if x.source_link==source_link),None)
        if (fixup is None or fixup.source_type!=0x07 or fixup.target_object!=1 or
                image.objects[0].base+fixup.target_offset!=target_link or
                image.link_to_linear(target_link)!=target_guest):
            raise SystemExit(f"post-transition record vtable slot {source_link:#x} is not the expected canonical LE fixup")
    obj1=image.object_data(1)
    for link,expected in ((0x86320,bytes.fromhex("ff 51 3c")),
                          (0x851ED,bytes.fromhex("ff 56 60"))):
        off=link-image.objects[0].base
        if obj1[off:off+len(expected)]!=expected:
            raise SystemExit(f"post-transition virtual call instruction changed at canonical LE {link:#x}")
    # The first post-IFCLevel phase-9 Update reaches the original gadget
    # method call at 0x75E29. Its receiver vtable is the live static table
    # 0x112060 (runtime trace ESI=0x2EC060); slot +0x60 is a canonical
    # object-1 SRC_OFFSET32 fixup to link 0x43980. The dispatcher still checks
    # the runtime slot against this target before executing it.
    phase9_gadget_slot=next((x for x in image.fixups if x.source_link==0x1120C0),None)
    phase9_call_off=0x75E29-image.objects[0].base
    if (phase9_gadget_slot is None or phase9_gadget_slot.source_type!=0x07 or
            phase9_gadget_slot.target_object!=1 or phase9_gadget_slot.target_offset!=0x33980 or
            image.link_to_linear(0x43980)!=0x22E980 or
            obj1[phase9_call_off:phase9_call_off+3]!=bytes.fromhex("ff 56 60")):
        raise SystemExit("phase-9 gadget callback at 0x75E29 no longer matches the exact object-3 LE vtable fixup")
    # The following original renderer callback reads [ESI+0x78] at 0x83D40.
    # Live state had ESI=0x2EC1E4 (object-3 link 0x1121E4), so slot 0x11225C
    # is backed by an exact object-1 LE fixup to 0x95D60. The runtime compares
    # its current value before dispatch; all other renderer calls stay closed.
    phase9_renderer_slot=next((x for x in image.fixups if x.source_link==0x11225C),None)
    renderer_call_off=0x83D40-image.objects[0].base
    if (phase9_renderer_slot is None or phase9_renderer_slot.source_type!=0x07 or
            phase9_renderer_slot.target_object!=1 or phase9_renderer_slot.target_offset!=0x85D60 or
            image.link_to_linear(0x95D60)!=0x280D60 or
            obj1[renderer_call_off:renderer_call_off+3]!=bytes.fromhex("ff 56 78")):
        raise SystemExit("phase-9 renderer callback at 0x83D40 no longer matches the live object-3 LE slot")
    phase9_glyph_slot=next((x for x in image.fixups if x.source_link==0x112228),None)
    glyph_call_off=0x84116-image.objects[0].base
    if (phase9_glyph_slot is None or phase9_glyph_slot.source_type!=0x07 or
            phase9_glyph_slot.target_object!=1 or phase9_glyph_slot.target_offset!=0x59E20 or
            image.link_to_linear(0x69E20)!=0x254E20 or
            obj1[glyph_call_off:glyph_call_off+3]!=bytes.fromhex("ff 56 44")):
        raise SystemExit("phase-9 glyph callback at 0x84116 no longer matches the live object-3 LE slot")
    phase9_record_slot=next((x for x in image.fixups if x.source_link==0x112250),None)
    record_call_off=0x80FF5-image.objects[0].base
    if (phase9_record_slot is None or phase9_record_slot.source_type!=0x07 or
            phase9_record_slot.target_object!=1 or phase9_record_slot.target_offset!=0x5A2C0 or
            image.link_to_linear(0x6A2C0)!=0x2552C0 or
            obj1[record_call_off:record_call_off+3]!=bytes.fromhex("ff 53 6c")):
        raise SystemExit("phase-9 record callback at 0x80FF5 no longer matches the live object-3 LE slot")
    # The subsequent new-interface Update observed a second value at the same
    # original indirect callsite: guest 0x259D30 -> object-1 link 0x6ED30.
    # This is a dynamically populated record callback (the containing data
    # slot has no static LE fixup), so admit only this captured destination.
    # Capstone verifies the exact original body returns AL=1 and immediately
    # RETs; any different live value remains fail-closed at runtime.
    dynamic_record_callback=0x6ED30-image.objects[0].base
    dynamic_record_callback_bytes=bytes(obj1[dynamic_record_callback:dynamic_record_callback+3])
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    dynamic_callback_ins=list(Cs(CS_ARCH_X86,CS_MODE_32).disasm(
        dynamic_record_callback_bytes,0x6ED30))
    if (image.link_to_linear(0x6ED30)!=0x259D30 or
            dynamic_record_callback_bytes!=bytes.fromhex("b0 01 c3") or
            [(x.mnemonic,x.op_str) for x in dynamic_callback_ins]!=[("mov","al, 1"),("ret","")]):
        raise SystemExit("live dynamic record callback 0x6ED30 no longer matches original MOV AL,1; RET bytes")
    smack_fixup_10c830=next((x for x in image.fixups if x.source_link==0x10C830),None)
    smack_fixup_timer_callback=next((x for x in image.fixups if x.source_link==0xD71E1),None)
    if (smack_fixup_10c830 is None or smack_fixup_10c830.target_object!=1 or
            smack_fixup_10c830.target_offset!=0xC71E0 or
            smack_fixup_timer_callback is None or smack_fixup_timer_callback.target_object!=1 or
            smack_fixup_timer_callback.target_offset!=0xC7230):
        raise SystemExit("SMACKOPEN's two callback targets no longer match the canonical LE fixups")
    # SMACKCLOSE's final virtual cleanup call is backed by two original LE
    # fixups: D71E1 installs the timer callback D7230, and D71F1 installs the
    # timer slot while D71EB fixes the null cleanup callback D7220 and D71F9
    # fixes its object-3 destination slot 1A6BB8. The actual call at C6096
    # reads that same relocated slot; do not seed it from the harness.
    smack_close_call_fixup=next((x for x in image.fixups if x.source_link==0xC6098),None)
    smack_close_callback_fixup=next((x for x in image.fixups if x.source_link==0xD71EB),None)
    smack_close_callback_store_fixup=next((x for x in image.fixups if x.source_link==0xD71F9),None)
    if (smack_close_call_fixup is None or smack_close_call_fixup.target_object!=3 or
            smack_close_call_fixup.target_offset!=0xA6BB8 or
            smack_close_callback_fixup is None or smack_close_callback_fixup.target_object!=1 or
            smack_close_callback_fixup.target_offset!=0xC7220 or
            smack_close_callback_store_fixup is None or smack_close_callback_store_fixup.target_object!=3 or
            smack_close_callback_store_fixup.target_offset!=0xA6BB8):
        raise SystemExit("SMACKCLOSE callback slot is no longer justified by canonical LE fixups")
    object1_code=image.object_data(1)
    close_call_off=0xC6096-image.objects[0].base
    if object1_code[close_call_off:close_call_off+6]!=bytes.fromhex("ff 15 b8 0b 38 00"):
        raise SystemExit("SMACKCLOSE's final indirect call no longer reads rebased slot 0x1A6BB8")
    # All of these original callsites read the live timer callback through
    # the same CS-relative slot.  The current integrated path has already
    # dispatched the slot as D7230 at C73B0 and C47F0; C7660 does not write
    # the slot between its C7696/C7740/C774C calls.
    timer_read_sites=(0xC5ACB,0xC5B5F,0xC5B95,0xC5BE4,0xC6302,0xC6A92,
                      0xC73CA,0xC762D,0xC763A,0xC7696,0xC7740,0xC774C)
    for site in timer_read_sites:
        off=site-image.objects[0].base
        if object1_code[off:off+2]!=b"\xff\x15" or \
                struct.unpack_from("<I",object1_code,off+2)[0]!=0x2E682C:
            raise SystemExit(f"timer callback read at {site:#x} no longer decodes to the rebased 0x10C82C slot")
    print("TRACE canonical SMACKOPEN indirect provenance slot=0010C830 fixup=object1:C71E0->link:D71E0 callsite=C62FC; writer=D71E0 immediate fixup=D71E1 object1:C7230->link:D7230 slot=0010C82C callsite=C6302")
    # The pending New Game interface is IFCLevel's secondary-interface
    # subobject. Its object-3 vtable and object-1 adjustment thunks are admitted
    # only because the canonical LE carries fixups for all eight table slots.
    level_vtable_link=0x111AD4
    level_vtable_obj=image.object_containing(level_vtable_link)
    if level_vtable_obj is None or level_vtable_obj.index!=3:
        raise SystemExit("IFCLevel vtable address point is not inside verified LE object 3")
    level_vtable_data=image.object_data(3)
    level_vtable_off=level_vtable_link-level_vtable_obj.base
    level_vtable_words=[int.from_bytes(level_vtable_data[level_vtable_off+i*4:level_vtable_off+i*4+4],"little")
                        for i in range(8)]
    level_fixups={x.source_link:x for x in image.fixups
                  if level_vtable_link<=x.source_link<level_vtable_link+32}
    expected_level_words=[0x00206650,0x00206640,0x00206630,0x00206620,
                          0x00200710,0x00200CF0,0x002027C0,0x002029F0]
    expected_level_offsets=[0xB650,0xB640,0xB630,0xB620,0x5710,0x5CF0,0x77C0,0x79F0]
    if level_vtable_words!=expected_level_words or len(level_fixups)!=8 or any(
            level_fixups[level_vtable_link+i*4].target_object!=1 or
            level_fixups[level_vtable_link+i*4].target_offset!=expected_level_offsets[i]
            for i in range(8)):
        raise SystemExit(f"IFCLevel vtable does not match the eight original fixups: words={level_vtable_words!r}")
    # Phase-9 confirmation stores the original static interface object at
    # link 0x185EB0 in pendingIFC. Verify its separate vtable address point
    # and all eight code-pointer fixups before enabling game()'s PlugIn call.
    launch_object_link=0x185EB0
    launch_vtable_link=0x111F68
    launch_vtable_obj=image.object_containing(launch_vtable_link)
    if launch_vtable_obj is None or launch_vtable_obj.index!=3:
        raise SystemExit("phase-9 interface vtable is not in verified LE object 3")
    launch_vtable_data=image.object_data(3)
    launch_vtable_off=launch_vtable_link-launch_vtable_obj.base
    launch_vtable_words=[int.from_bytes(launch_vtable_data[launch_vtable_off+i*4:launch_vtable_off+i*4+4],"little")
                         for i in range(8)]
    launch_fixups={x.source_link:x for x in image.fixups
                   if launch_vtable_link<=x.source_link<launch_vtable_link+32}
    expected_launch_offsets=[0x733F0,0x733E0,0x733D0,0x733C0,
                             0x614B0,0x61670,0x61E70,0x616E0]
    expected_launch_words=[0x26E3F0,0x26E3E0,0x26E3D0,0x26E3C0,
                           0x25C4B0,0x25C670,0x25CE70,0x25C6E0]
    if launch_vtable_words!=expected_launch_words or len(launch_fixups)!=8 or any(
            launch_fixups[launch_vtable_link+i*4].target_object!=1 or
            launch_fixups[launch_vtable_link+i*4].target_offset!=expected_launch_offsets[i]
            for i in range(8)):
        raise SystemExit(f"phase-9 interface vtable no longer matches its eight LE fixups: {launch_vtable_words!r}")
    # The original Watcom initializer rooted at 0x830F0 writes this table into
    # the static interface subobject. Verify both the LE fixup and the exact
    # constructor stores before relying on currentIFC+7 during runtime dispatch.
    launch_ctor_fixup_sites={0x83235:(3,0x85EA8),0x8323B:(3,0x85EA8),0x83247:(3,0x11F68)}
    launch_ctor_fixups={f.source_link:f for f in image.fixups
        if f.source_link in launch_ctor_fixup_sites}
    if set(launch_ctor_fixups)!=set(launch_ctor_fixup_sites) or any(
            (launch_ctor_fixups[src].target_object,launch_ctor_fixups[src].target_offset)!=target
            for src,target in launch_ctor_fixup_sites.items()):
        raise SystemExit(f"static phase-9 interface constructor stores lack expected LE fixups: {launch_ctor_fixups!r}")
    launch_ctor_code=bytes(image.object_data(1)[0x83210-image.objects[0].base:0x8324B-image.objects[0].base])
    # load_le applies the verified object-3 fixup, so the bytes in its loaded
    # image carry the selected guest-linear vtable address, not the LE VA.
    if launch_ctor_code[-6:]!=bytes.fromhex("C7 00 68 BF 2E 00"):
        raise SystemExit(f"phase-9 vtable initializer at 0x83245 changed: {launch_ctor_code[-12:].hex()}")
    launch_static_evidence={"schema":"gw-phase9-interface-vtable-fixups/v1",
        "target_sha256":EXPECTED_TARGET,
        "interface_object":{"link":"0x00185EB0","guest":"0x0035FEB0","map_symbol":None,
            "producer":"IFCLevel::Update 0x179F0 writes DAT_00185EB0 to pendingIFC when phase>=9 and action input is active"},
        "vtable":{"link_address_point":"0x00111F68","guest_address_point":"0x002EBF68",
            "map_symbol":None,"words":[f"0x{x:08X}" for x in launch_vtable_words],
            "fixups":[{"source_link":f"0x{launch_vtable_link+i*4:08X}",
                "target_object":launch_fixups[launch_vtable_link+i*4].target_object,
                "target_offset":f"0x{expected_launch_offsets[i]:08X}",
                "target_link":f"0x{0x10000+expected_launch_offsets[i]:08X}",
                "target_guest":f"0x{expected_launch_words[i]:08X}"} for i in range(8)]},
        "plug_in":{"thunk_link":"0x833F0","thunk_bytes":"83 E8 08 E9 B8 E0 FE FF",
            "adjustment":"SUB EAX,8; JMP 0x714B0","method_link":"0x714B0",
            "map_public_symbol":None},
        "constructor":{"initializer_entry":"0x830F0 (Watcom __InitRtns target)",
            "stores":{"0x83239":"[0x185EA8] = 0x111F88",
                "0x8323F":"[0x185EAC] = 0x111F78",
                "0x83245":"[0x185EB7] = 0x111F68"},
            "fixup_sites":{"0x83235":{"target_object":3,"target_offset":"0x85EA8"},
                "0x8323B":{"target_object":3,"target_offset":"0x85EA8"},
                "0x83247":{"target_object":3,"target_offset":"0x11F68"}},
            "runtime_slot":"currentIFC + 7",
            "status":"verified by canonical LE bytes/fixups; replay must confirm the initialized runtime value"},
        "post_transition_methods":{"Update":{"thunk_link":"0x833D0","method_link":"0x716E0"},
            "Draw":{"thunk_link":"0x833C0","method_link":"0x71E70"},
            "class_name":"unlabeled in canonical MAP"}}
    (ROOT/"evidence"/"native_ifclevel_phase9_interface_vtable.json").write_text(
        json.dumps(launch_static_evidence,indent=2)+"\n",encoding="utf-8")
    for symbol in ("0001:00015710       W?PlugIn$:IFCLevel", "0001:00015CF0       W?PullOut$:IFCLevel",
                   "0001:000177C0       W?Draw$:IFCLevel", "0001:000179F0       W?Update$:IFCLevel",
                   "0003:00111AE4       W?$Wvf0eo2i8:IFCLevel"):
        if not ReferenceMap.contains(symbol):
            raise SystemExit(f"canonical MAP no longer identifies IFCLevel symbol {symbol!r}")
    # The MAP has no public symbol at 0x1869F1; retain that absence explicitly.
    if ReferenceMap.has_unexpected_line(" 0003:001869F1 "):
        raise SystemExit("unexpected public MAP label appeared at IFCLevel instance candidate 0x1869F1")
    print("TRACE canonical IFCLevel MAP/fixups class=IFCLevel instance_link=001869F1+20 vtable_link=00111AD4 methods=00015710/00015CF0/000179F0/000177C0 fixup_slots=8 global_symbol=unlabeled")
    level_static_evidence={"schema":"gw-ifclevel-static-map-fixups/v1",
        "target_sha256":EXPECTED_TARGET,
        "instance":{"complete_object_link":"0x001869F1","complete_object_guest":"0x003609F1",
            "map_global_symbol":None,"interface_subobject_offset":"0x20",
            "interface_subobject_link":"0x00186A11","interface_subobject_guest":"0x00360A11",
            "class":"IFCLevel"},
        "vtable":{"link_address_point":"0x00111AD4","guest_address_point":"0x002EBAD4",
            "map_symbol":"0003:00111AE4 W?$Wvf0eo2i8:IFCLevel$$nx[]pn()v",
            "loaded_words":[f"0x{x:08X}" for x in level_vtable_words],
            "fixups":[{"source_link":f"0x{level_vtable_link+i*4:08X}",
                "target_object":level_fixups[level_vtable_link+i*4].target_object,
                "target_offset":f"0x{level_fixups[level_vtable_link+i*4].target_offset:08X}",
                "guest_target":f"0x{expected_level_words[i]:08X}"} for i in range(8)]},
        "methods":{"PlugIn":{"link":"0x15710","symbol":"W?PlugIn$:IFCLevel$n()v","thunk_link":"0x1B650"},
            "PullOut":{"link":"0x15CF0","symbol":"W?PullOut$:IFCLevel$n()v","thunk_link":"0x1B640"},
            "Update":{"link":"0x179F0","symbol":"W?Update$:IFCLevel$n()v","thunk_link":"0x1B630"},
            "Draw":{"link":"0x177C0","symbol":"W?Draw$:IFCLevel$n()v","thunk_link":"0x1B620"}},
        "static_dependencies":{"PlugIn_to_smacker":["0x15710 IFCLevel::PlugIn",
                "0x929D0 W?PlaySmacker$n(pnaucuc)v","0xAE2D0 play_smk_",
                "0xAE4D8 W?play_smk_via_buffer$n(pnall)l","0xC62F0 SMACKOPEN"],
            "PlugIn_to_screen_copy":["0x15710 IFCLevel::PlugIn","0x929D0 W?PlaySmacker$n(pnaucuc)v",
                "0xAE2D0 play_smk_","0xAE4D8 W?play_smk_via_buffer$n(pnall)l",
                "0xAE668 W?copy_to_screen$n(pnucululul)v"],
            "screen_copy_callback":{"global_link":"0x1A029C","global_guest":"0x0037A29C",
                "LE_bytes":"zero","LE_fixup":False,
                "status":"requires an original runtime initializer; callback target is not justified by LE static data"},
            "Draw_direct_calls_qsort":"0x177C0 -> 0xA33C0 qsort_",
            "PlugIn_reaches_qsort":"0x15710 -> 0x929D0 -> 0x91E00 -> 0x921F0 -> 0xA33C0"},
        "runtime_constructor_vptr_check":"pending; the expanded closure must compile before __InitRtns can be replayed"}
    (ROOT/"evidence"/"native_ifclevel_static_map.json").write_text(
        json.dumps(level_static_evidence,indent=2)+"\n",encoding="utf-8")

    # FUN_000A8CD0 dispatches the help callback from +0x22; the pressed action
    # field is +0x0E. Admit the finite help-callback set only where the record
    # tag and exact SRC_OFFSET32 LE fixup agree and Capstone decodes object-1
    # code. A live pointer alone is not sufficient.
    original_link_image=load_le(TARGET)
    original_code=bytes(original_link_image.object_data(1))
    original_code_obj=original_link_image.objects[0]
    gadget_dis=Disassembler(original_code,0,
        [Section(".text",original_code_obj.base,original_code_obj.virtual_size,
                 0,original_code_obj.virtual_size,0x20000020)])
    mygadget_rows=[]
    seen_callback_targets=set()
    object3=image.objects[2]
    object3_data=bytes(image.object_data(3))
    mygadget_arrays=[(0x1065B8,[0x41A08]),
        (0x106608,[0x40138]*5),
        (0x1066F8,[0xC0008]*7+[0x40008]),
        (0x1068B0,[0x40008]),
        (0x107080,[0x40058]*2)]
    mygadget_fixups={item.source_link:item for item in image.fixups}
    for array_start,expected_flags in mygadget_arrays:
        for index,expected_flag in enumerate(expected_flags):
            record_link=array_start+index*0x28
            record_off=record_link-object3.base
            slot=record_link+0x22
            fixup=mygadget_fixups.get(slot)
            if record_off<0 or record_off+0x28>len(object3_data):
                raise SystemExit(f"MyGadget record leaves original object 3: {record_link:#x}")
            flags=struct.unpack_from("<I",object3_data,record_off)[0]
            if (flags!=expected_flag or fixup is None or fixup.source_type!=0x07 or
                    fixup.target_object!=1):
                raise SystemExit(f"MyGadget record/fixup layout changed at {record_link:#x}: flags={flags:#x} fixup={fixup!r}")
            target_link=original_code_obj.base+fixup.target_offset
            target_off=target_link-original_code_obj.base
            gadget_x,gadget_y,gadget_w,gadget_h,gadget_id=struct.unpack_from(
                "<5h",object3_data,record_off+4)
            click_function=struct.unpack_from("<I",object3_data,record_off+0x0e)[0]
            user_data=struct.unpack_from("<I",object3_data,record_off+0x1e)[0]
            decoded=list(gadget_dis.disassemble_at(target_link,max_bytes=16))
            if (target_off<0 or target_off>=original_code_obj.virtual_size or
                    not decoded or decoded[0].address!=target_link or
                    decoded[0].mnemonic.lower() in ("int3","ud2")):
                raise SystemExit(f"MyGadget callback fixup does not name decoded object-1 code: slot={slot:#x} target={target_link:#x}")
            mygadget_rows.append({"array_start_link":f"0x{array_start:08X}",
                "record_index":index,"record_link":f"0x{record_link:08X}",
                "record_guest":f"0x{record_link+0x1DA000:08X}",
                "flags":f"0x{flags:08X}","callback_slot_link":f"0x{slot:08X}",
                "geometry":{"x":gadget_x,"y":gadget_y,"width":gadget_w,
                    "height":gadget_h,"id":gadget_id},
                "click_function_raw_no_fixup":f"0x{click_function:08X}",
                "user_data_raw":f"0x{user_data:08X}",
                "help_callback_link":f"0x{target_link:08X}",
                "fixup_type":f"0x{fixup.source_type:02X}","target_object":fixup.target_object,
                "target_link":f"0x{target_link:08X}",
                "capstone_first_instruction":f"{decoded[0].mnemonic} {decoded[0].op_str}".strip()})
            seen_callback_targets.add(target_link)
    expected_mygadget_targets={0x24830,0x241A0,0x24550,0x242F0,0x74B30}
    if (len(mygadget_rows)!=17 or seen_callback_targets!=expected_mygadget_targets or
            bytes(original_code[0xA8D95-original_code_obj.base:
                                0xA8D98-original_code_obj.base])!=bytes.fromhex("ff 52 22")):
        raise SystemExit(f"MyGadget callback/fixup set or A8D95 CALL [EDX+22] bytes changed: count={len(mygadget_rows)} targets={sorted(seen_callback_targets)}")
    map_code_symbols=ReferenceMap.code_symbols()
    if ReferenceMap.available and 0x24830 in map_code_symbols:
        raise SystemExit("canonical MAP unexpectedly acquired a direct symbol at callback 0x24830; re-review the callback identity")
    parent_vtable_symbol=ReferenceMap.line_with(" 0003:00111AE4 ","W?$Wvf0eo2i8:IFCLevel")
    if parent_vtable_symbol is None:
        raise SystemExit("canonical MAP no longer anchors the 0x111B04 address point in IFCLevel's vtable group")
    vtable_fixups={item.source_link:item for item in image.fixups
                   if 0x111B04<=item.source_link<0x111B14}
    vtable_expected={0x111B04:0x251A0,0x111B08:0x25190,
                     0x111B0C:0x25180,0x111B10:0x25170}
    if (set(vtable_fixups)!=set(vtable_expected) or any(
            item.source_type!=0x07 or item.target_object!=1 or
            original_code_obj.base+item.target_offset!=vtable_expected[slot]
            for slot,item in vtable_fixups.items())):
        raise SystemExit("interface 0x185E9A's live vptr no longer matches the four IFCLevel-group LE fixups")
    secondary_thunks=[]
    for slot,thunk_link in sorted(vtable_expected.items()):
        decoded=list(gadget_dis.disassemble_at(thunk_link,max_bytes=12))
        jump=next((x for x in decoded if x.mnemonic.lower()=="jmp" and
                   x.operands and x.operands[0].type==2),None)
        if not decoded or decoded[0].mnemonic.lower()!="sub" or jump is None:
            raise SystemExit(f"secondary IFCLevel thunk is no longer SUB EAX,[EAX-4]; JMP rel32 at {thunk_link:#x}")
        jump_target=int(jump.op_str,0)
        secondary_thunks.append({"slot_link":f"0x{slot:08X}",
            "thunk_link":f"0x{thunk_link:08X}",
            "adjustment":"SUB EAX,dword ptr [EAX-4]",
            "jmp_target_link":f"0x{jump_target:08X}",
            "jmp_target_map_symbol":map_code_symbols.get(jump_target)})
    mygadget_evidence={"schema":"gw-mygadget-callback-fixup-batch/v1",
        "target_sha256":EXPECTED_TARGET,"rea":{"provider":"REA 6.4.0 / Ghidra 12.1.4",
            "carrier_sha256":"1523022fb1febcfb939b2ed04145ee6e7dcd8b99113d932d21d33301c0052a97",
            "evidence_id":"ev_49ccd091c7afb201d8bd6eacbca917a35f5a8d0020660ca3ac6fd8ceaa57550b"},
        "dispatcher":{"link":"0x000A8CD0","callback_site":"0x000A8D95",
            "instruction":"CALL dword ptr [EDX+0x22]","bytes":"FF 52 22",
            "gadget_record_size":"0x28","help_callback_field_offset":"0x22",
            "click_action_field_offset":"0x0E",
            "rea_semantics":"FUN_000A8CD0 calls +0x0E for a pressed gadget; the +0x22 call is the help callback"},
        "callback_targets":[f"0x{x:08X}" for x in sorted(seen_callback_targets)],
        "records":mygadget_rows,
        "map":{"callback_0x24830_symbol":None,
            "callback_symbol_status":"no public function symbol at exact LE VA 0x24830",
            "interface_candidate_link":"0x00185E9A","static_object_symbol":None,
            "runtime_vptr_guest":"0x002EBB04","vtable_address_point_link":"0x00111B04",
            "vtable_parent_symbol":parent_vtable_symbol,
            "secondary_vtable_thunks":secondary_thunks,
            "primary_ifclevel_methods":{"PlugIn":"0x00015710","PullOut":"0x00015CF0",
                "Update":"0x000179F0","Draw":"0x000177C0"},
            "vtable_fixups":[{"slot":f"0x{slot:08X}","target":f"0x{target:08X}"}
                for slot,target in vtable_expected.items()],
            "method_names":"The exact public MAP method labels are the IFCLevel group symbols at 0x15710 PlugIn, 0x15CF0 PullOut, 0x179F0 Update, and 0x177C0 Draw; 0x111B04 is a +0x20 secondary address point whose four LE targets are anonymous adjustor thunks, so no direct method-name attribution is made to those thunk addresses."},
        "admission":"all and only 17 tagged MyGadget records whose +0x22 fields have object-3 SRC_OFFSET32 fixups to Capstone-decoded object-1 code; runtime still checks each live callback against this finite list"}
    (ROOT/"evidence"/"native_mygadget_callback_fixups.json").write_text(
        json.dumps(mygadget_evidence,indent=2)+"\n",encoding="utf-8")
    print("TRACE canonical MyGadget callback batch records=17 targets="+
          "/".join(f"{x:08X}" for x in sorted(seen_callback_targets))+
          " callsite=A8D95 bytes=FF5222 map_symbol_24830=none vtable_group=IFCLevel")

    # Share the established closure build slot so unchanged Runtime objects
    # remain cache hits; the caller preserves/restores the historical closure
    # source and object around this one instrumented build.
    # Keep gameplay lifting artifacts separate from the IFCTitle-only test;
    # both tests used to overwrite this shared filename, so a hash-only reuse
    # check could pair a valid LE report with unrelated generated C.
    generated=ROOT/"work"/"ifctitle_creature_probe_closure.c"
    generated_base=ROOT/"work"/"ifctitle_creature_probe_closure.base.c"
    lift_report=ROOT/"evidence"/"ifctitle_creature_probe_closure_closure.json"
    options=["--object-map","measured-1-3","--partial-root","0x70D10",
        # The authentic Update slot's adjustment thunk and method body. The
        # dispatch caller slice is attached below so we do not lift unrelated
        # input/render branches in the complete control_game/draw_game bodies.
        "--partial-root","0x70EB0",
        "--partial-root","0x5B170",
        "--partial-root","0x70E30",
        # process_packets reaches this original Obj1 method through the Obj3
        # LE fixup at 0x111CF8. Keep its body bounded and its indirect
        # dispatch fail-closed at runtime.
        "--partial-root","0x55CF0",
        "--partial-root","0x78360",
        "--partial-root","0x6A030",
        "--partial-root","0x47A90",
        "--partial-root","0x6A240",
        # Live draw callsite 0x22F87 uses the Object-3 vptr at 0x111BE8,
        # captured as guest 0x002EBBE8. Its LE slot +0x10 is the fixup-backed
        # adjustor thunk 0x138A0 (slot source 0x111BF8).
        "--partial-root","0x138A0",
        # The same draw callsite is also reached through the embedded
        # interface subobject at 0x111BB8; its slot +0x10 is 0x13860.
        "--partial-root","0x13860","--partial-root","0x13870","--partial-root","0x13880","--partial-root","0x6B9F0",
        "--partial-root","0x43BB0","--partial-root","0x43BD0",
        # The shared Thing +0x90 method at 0x58C90 has two live object-3
        # vtable contracts: TT_CREATURE -> 0x6A280 and the active Effect
        # record -> 0x959E0. Lift the latter's original 9-byte predicate too.
        "--partial-root","0x959E0",
        "--partial-root","0xCA560",   # V20: Miles DIG mixer service routine (AIL timer callback), run by the virtual SB16 pump
        "--partial-root","0x6A070",
        "--partial-root","0x47360",
        "--partial-root","0x3EC70",
        "--partial-root","0x3F680",
        "--partial-root","0x44570",
        # The returned TITLE object publishes slot 0 at the original
        # adjustment thunk 0x13720 -> IFCTitle::PlugIn 0x70D10.
        "--partial-root","0x13720",
        # The original single-player selection interface has its own
        # four-slot vtable at object-3 link 0x112020. Its fixups select the
        # exact Plugin/PullOut/Update/Draw adjustment thunks below.
        "--partial-root","0x136E0","--partial-root","0x711F0",
        "--partial-root","0x136D0","--partial-root","0x71350",
        "--partial-root","0x136C0","--partial-root","0x71410",
        "--partial-root","0x136B0","--partial-root","0x714A0",
        "--partial-root","0x710B0",
        # Original IFCOptions virtual targets recovered from the live LE
        # vtable after game() completed PlugIn: slot +8 -> thunk 0x13600 ->
        # Update 0x6AB30; slot +12 -> thunk 0x135F0 -> Draw 0x6A700.
        "--partial-root","0x13600","--partial-root","0x135F0",
        "--partial-root","0x13610","--partial-root","0x6A600","--partial-root","0x6AB30","--partial-root","0x6A700",
        "--partial-root","0x14FF0","--partial-root","0x6EE60",
        "--partial-root","0x15090","--partial-root","0x955E0","--partial-root","0x921F0",
        "--partial-root","0x150D0","--partial-root","0x91E00",
        # Lift the complete original setup_game body. The replay executes its
        # authentic prefix through the BIOINTRO size check and returns at that
        # natural boundary, before the later setup_game continuation.
        "--partial-root","0x94AC0",
        # The next bounded slice is the authentic setup_game continuation
        # that walks startup_files[], including data/b32a.dat -> block_mem,
        # then applies the original main palette.  Keep the slice boundary
        # immediately before the following screen/input setup.
        "--partial-root","0x552C0","--partial-root","0x9FF60","--partial-root","0xADEAC",
        # setup_game's palette-backed 8-color lookup initializer at 0x94F04.
        "--partial-root","0x5B8C0","--partial-root","0xA28A4",
        "--partial-root","0x14BF0","--partial-root","0xAF930",
        "--partial-root","0xAFC69","--partial-root","0xAFEDB",
        "--partial-root","0xAFF18","--partial-root","0xAFC44",
        "--partial-root","0xAA079","--partial-root","0x96B23",
        # The newly requested OPTIONS PlugIn is reached through its original
        # adjusted interface thunk only after the title PullOut returns.
        "--partial-root","0x6A3D0",
        # New Game's static IFCLevel secondary-interface vtable has four
        # fixup-backed adjustor thunks and four method entries. Lift the whole
        # virtual surface before the integrated transition.
        "--partial-root","0x1B650","--partial-root","0x1B640",
        "--partial-root","0x1B630","--partial-root","0x1B620",
        "--partial-root","0x15710","--partial-root","0x15CF0",
        "--partial-root","0x179F0","--partial-root","0x177C0",
        # The original phase-9 confirm publishes the static interface at
        # link 0x185EB0. Its vtable begins at 0x111F68; LE slot 0 contains
        # 0x833F0, an adjustor thunk (SUB EAX,8; JMP 0x714B0). Include the
        # thunk and reached method so game() can dispatch the real PlugIn.
        "--partial-root","0x833F0","--partial-root","0x714B0",
        # The same LE vtable supplies the next original Update/Draw slots.
        # These roots let the regular game() dispatchers run one post-transition
        # cycle; their exact targets are checked against the vtable fixups below.
        "--partial-root","0x833D0","--partial-root","0x716E0",
        "--partial-root","0x833C0","--partial-root","0x71E70",
        # The newly observed interface PullOut target at 0x833E0 is
        # its adjustor thunk to 0x71670; add only the slot observed in
        # the original object-3 vtable and keep the next PlugIn fail-closed.
        "--partial-root","0x833E0","--partial-root","0x71670",
        # The pending singleton at link 0x185E9A has a constructor-populated
        # object-3 vtable at 0x111B04. Its first four exact LE fixups point to
        # object-1 adjustor thunks 0x251A0/190/180/170; lift the whole virtual
        # surface and their direct method entries before the game transition.
        "--partial-root","0x251A0","--partial-root","0x20C60",
        "--partial-root","0x25190","--partial-root","0x21140",
        "--partial-root","0x25180","--partial-root","0x21380",
        "--partial-root","0x25170","--partial-root","0x22F40",
        # FUN_000898F0 iterates the newly active interface's 0x29-byte records.
        # Its vptr table is object-3 link 0x11228C; the LE fixes slot +0x3C to
        # 0x89870, whose slot +0x60 is fixed to the one-byte return at 0x89860.
        "--partial-root","0x89870","--partial-root","0x89860",
        # The same iterator family at 0x13A70 uses 0x61-byte records and the
        # adjacent object-3 table at 0x1122FC: +0x3C -> 0x139F0, then +0x60
        # -> 0x139E0. Both are exact object-1 fixups, admitted as one pair.
        "--partial-root","0x139F0","--partial-root","0x139E0",
        # A third reached record layout comes from vtable link 0x1123BC:
        # slot +0x3C fixes to 0x10090 and slot +0x60 to 0x10060.
        "--partial-root","0x10090","--partial-root","0x10060",
        "--partial-root","0x92819",
        # Execute the original game() entry as an opt-in integration path.
        # The bounded loop body below remains useful as a focused regression,
        # while this root exercises the prologue, title PlugIn, transition
        # dispatch, full loop, and normal epilogue in one guest invocation.
        "--partial-root","0x92710",
        # Bounded native game() loop entry: begin at its original per-frame
        # body, then allow the LE outer loop to repeat through 0x92777.
        "--partial-root","0x92860",
        # Playable Demo v0.1 (--play): enter each interactive tick at the original
        # loop-top IFC transition block 0x927E9 (victory flag 0x117464&0x80 ->
        # end-of-level IFC; pendingIFC UnPlug/PlugIn at 0x92810) before falling
        # into the per-frame body at 0x92860. Host pacing replaces 0x92777-0x927E4.
        "--partial-root","0x927E9",
        # Full per-frame stages used by the verified game() iteration body.
        # These are additional closure roots; the harness calls the original
        # bodies in canonical order and leaves all unobserved indirects
        # fail-closed at runtime.
        "--partial-root","0x64CB0",
        "--partial-root","0x834C0",
        "--partial-root","0x35C00",
        # FUN_000472A0's live +0x3c virtual call resolved to 0x232220,
        # which maps to LE 0x47220. REA xrefs and the canonical LE fixup at
        # 0x111D40 prove that this exact copy method is a vtable entry.
        "--partial-root","0x47220","--partial-root","0x46C40",
        # FUN_00080910's action/status query is an original virtual call
        # through object-3 method-table slot 0x111D60; the LE fixes it to
        # object-1 0x6A230. Keep the dispatcher contract at this one site.
        "--partial-root","0x6A230",
        # FUN_0005AB23's movement/state helper calls the +0xB4 method on the
        # same object-3 method table; LE slot 0x111DB8 fixes target 0x59D80.
        "--partial-root","0x59D80",
        # The complete statically reached virtual set inside FUN_00059D80:
        # slots +4/+0x74/+0x10 are LE-fixup-backed to these object-1 methods.
        "--partial-root","0x6A2E0","--partial-root","0x46B90","--partial-root","0x6A240",
        "--partial-root","0x6A250","--partial-root","0x6A370",
        "--partial-root","0x8A730",
        # PlSpec::MapDisplay eligibility callback reached when an activated
        # specialist is inside the viewport. The canonical PlSpec vtable slot
        # 0x112080 is a LE fixup to this exact original object-1 body.
        "--partial-root","0x8A500",
        "--partial-root","0x6ED30",
        # FUN_00058330's first reached receiver call at 0x58681 uses the same
        # object-3 vtable +0xA4 slot, fixed by the LE to object-1 0x47D60.
        "--partial-root","0x47D60","--partial-root","0x47BF0","--partial-root","0x59CF0","--partial-root","0x59B60",
        # The second live copy adapter uses a parallel, fixup-backed vtable
        # at 0x111EA4; its +0x3c and +0x60 slots are checked below as a pair.
        "--partial-root","0x57000","--partial-root","0x56D40",
        # Third record adapter in the original frame iterator, with the
        # live +0x3c and guarded +0x60 vtable methods backed by LE fixups.
        "--partial-root","0x440A0","--partial-root","0x43980",
        "--partial-root","0x95D60",
        "--partial-root","0x69E20",
        "--partial-root","0x6A2C0","--partial-root","0x6ED30",
        "--partial-root","0x86270",
        # FUN_00058330 reaches this canonical null virtual from its live
        # effect receiver at 0x58BBD. The object-3 vtable slot 0x11226C is
        # fixed by the LE to object-1 0x8A720 (MAP nullsub_14); admit only
        # this exact site/target pair, with the runtime equality check below.
        "--partial-root","0x8A720",
        "--partial-root","0x39D40","--partial-root","0x39D20",
        # The live __prtf callback value 0x002A59FE maps to LE 0xBA9FE,
        # the canonical MAP entry file_putc_. Keep this exact callback
        # reachable; other formatter destinations remain fail-closed.
        "--partial-root","0xBA9FE",
        # IFCLevel::Draw passes the original local comparator at link 0x184B0
        # directly to qsort_. The exact LE block is lifted as a separate root;
        # qsort_ indirect sites below accept this callback only alongside the
        # other independently verified comparator used by TITLE/OPTIONS.
        "--partial-root","0x184B0",
        # The live Unsmack frontier proved this exact mutable four-entry table
        # variant and its original _SmackInternal010..013 destinations.
        # Include those code entries; the generated dispatch still checks the
        # table index and live per-entry target before transferring control.
        "--partial-root","0xECCF0","--partial-root","0xED030",
        "--partial-root","0xED840","--partial-root","0xED990",
        # The lifter admits all 256 entries in the shared 0x10CB00 table as
        # one LE-fixup-backed contract for every original masked CALL site.
        # Deep Smacker calls, tables, and dynamic accesses remain fail-closed
        # until each exact live contract is established.
        "--runtime-fail-closed",
        # IFCLevel::PlugIn's bounded nine-case switch has a contiguous table
        # of nine object-1 fixups and the original index checks at 0x159C2-C9.
        "--indexed-code-jump-table","0x159CF=0x156E0:9:edx",
        # MapDisplay edge scrolling dispatches one of eight original directions
        # through MAP jpt_7A0C4. The LE table is admitted only after checking
        # its 8 contiguous object-1 fixups, local CFG targets and CMP/JA bound.
        "--indexed-code-jump-table","0x7A0C4=0x79DA4:8:eax",
        # process_packets dispatches its packet-state result through
        # jpt_9358B. Every one of the 35 contiguous slots is fixed to an
        # instruction block in its original function; the generated read
        # adds a fail-closed 0..34 table bound because no source bound was
        # established before the indirect JMP.
        "--indexed-code-jump-table","0x9358B=0x92F7C:35:edx",
        # The completed-building panel's live Update path reaches the original
        # 12-entry CS switch at 0x2473D. The LE table at 0x24514 has contiguous
        # Object-1 fixups for indices 0..11; retain the original indexed JMP
        # and enforce the bounded index in the emitted dispatcher.
        "--indexed-code-jump-table","0x2473D=0x24514:12:eax",
        # FUN_000751F0 is reached after SMACKCLOSE. Its four-way indexed JMP
        # at 0x7520F is bounded by the original CMP BL,3 / JA and its CS table
        # has four object-1 SRC_OFFSET32 fixups to local blocks.
        "--indexed-code-jump-table","0x7520F=0x751DC:4:eax",
        # FUN_00075750's active gadget-kind switch is bounded by CMP DL,3 /
        # JA; MAP jpt_7583A and all four canonical LE fixups target local
        # blocks. Admit the whole table, retaining runtime index checks.
        "--indexed-code-jump-table","0x7583A=0x75734:4:edx",
        # The active IFCLevel::Draw state switch at E1B20 indexes MAP's
        # jpt_E1B20. Admit all 27 contiguous LE-fixup-backed entries in one
        # contract, with an exact DS table range and fail-closed index bound.
        "--indexed-code-jump-table","0xE1B20=0xE1B27:27:eax",
        # BioGame's live effect-type dispatcher at 0x8936F is guarded to
        # indices 0..64 after SUB AL,6. Admit its complete 65-slot CS table
        # only after the lifter verifies every LE fixup and decoded target.
        "--indexed-code-jump-table","0x8936F=0x86704:65:eax",
        # FUN_0003D470's MAP-named jpt_3DB3D is selected from the live entity
        # mode byte, after original CMP/JA bounds it to four states. All four
        # LE slots are fixed to code inside this original function.
        "--indexed-code-jump-table","0x3DB3D=0x3D460:4:esi",
        "--indexed-code-jump-table","0x3F69A=0x3F664:7:eax",
        "--indexed-code-jump-table","0x44A31=0x4450C:12:eax",
        "--indexed-code-jump-table","0x44EA3=0x4453C:12:eax",
        # The captured receiver at 0x88146 calls its effect coordinate method
        # through [EDX+4]. The actual live target is object-1 link 0x6A2E0;
        # keep this one-site runtime equality guard, never confuse EAX (the
        # BioGame::__effects record) with the indirect destination.
        "--verified-indirect-target","0x88146=0x6A2E0",
        "--verified-indirect-target","0x82F77=0x55CF0",
        "--verified-indirect-target","0x82F77=0x454E0",
        "--verified-indirect-target","0x561E9=0x78360",
        "--verified-indirect-target","0x50164=0x6A030",
        "--verified-indirect-target","0x5017E=0x47A90",
        "--verified-indirect-target","0x47A9E=0x6A240",
        "--verified-indirect-target","0x80F86=0x6A070",
        # FUN_0004B1F0's later per-creature query uses the same original
        # vtable slot 0x111D6C -> 0x6A070, now captured at 0x54904.
        "--verified-indirect-target","0x54904=0x6A070",
        # FUN_00079100 calls the live BioGame vtable slot +0x1C; LE slot
        # 0x111EC0 fixes to original object-1 code 0x69E50.
        "--verified-indirect-target","0x79218=0x69E50",
        # FUN_00059F60's shared callback uses slot +0x10. The Creature and
        # PlSpec tables resolve slot 4 to 0x6A240; the Thing table resolves it
        # to 0x95CA0. Validate each complete LE table and require a live base
        # from that finite set at the callsite.
        "--verified-le-vtable-call","0x5A2F5=0x111D04:60",
        "--verified-le-vtable-call","0x5A2F5=0x112060:52",
        "--verified-le-vtable-call","0x5A2F5=0x1123BC:48",
        # FUN_00057F60 normally receives the Creature/PlSpec state predicate,
        # but the native long run also reaches Thing::CanMove through the
        # Thing vtable slot at 0x1123CC. The LE fixup targets 0x95CA0 (MOV
        # AL,1; RET); admit this second value at this callsite only.
        "--verified-indirect-target","0x57F67=0x95CA0",
        # At the later live creature callback, 0x58C90 reads TT_CREATURE's
        # vtable slot 0x111D94; the exact LE fixup targets the original
        # one-instruction predicate at 0x6A280 (MOV AL,1; RET).
        "--verified-indirect-target","0x58C90=0x6A280",
        # EF_SMUGGLER uses the sibling Effect vtable slot 0x112274. Its
        # canonical SRC_OFFSET32 fixup targets the original type-table query
        # at 0x959E0. Both targets are admitted only at this shared callsite.
        "--verified-indirect-target","0x58C90=0x959E0",
        # FUN_00080910 walks records through MapDisplay's +0x10 callback;
        # object-3 LE slot 0x111EB4 fixes to object-1 0x6EE10.
        "--verified-indirect-target","0x80A3A=0x6EE10",
        # The same original walk can receive TT_CREATURE records. Their
        # object-3 vtable 0x111D04 has a canonical SRC_OFFSET32 fixup at
        # slot +0x10 (0x111D14 -> object-1 0x6A240). Keep this additional
        # live pair exact and fail-closed at the shared callsite.
        "--verified-le-vtable-call","0x80A3A=0x111D04:60",
        # The live BioGame vtable dispatch in FUN_00056E30 uses slot
        # 0x111F14 -> 0x6EC70, also used by the authenticated 0x78FAA query.
        "--verified-indirect-target","0x56F3B=0x6EC70",
        "--verified-indirect-target","0x502E1=0x47360",
        # 78BA1 is a shared MapDisplay/BioGame query callsite: its usual
        # object-3 slot 111EA8 fixes to 6EE40, while the live BioGame
        # receiver's independently fixed slot 1121E8 points to 6A2E0. Allow
        # both LE-backed variants at this exact original callsite.
        "--verified-indirect-target","0x78BA1=0x6A2E0",
         # TT_CREATURE's object-3 vtable at 0x111D04 has an exact object-1
         # fixup at slot +0x20. This eligibility callback follows projection
         # only when the original creature is inside the viewport.
         "--verified-indirect-target","0x78EE9=0x46BC0",
        "--verified-le-vtable-call","0x78EE9=0x111D04:60",
        "--partial-root","0x46BC0",
        # Once the eligible-creature callback is entered it dispatches its
        # height and frame-box helpers through the same exact LE vtable.
        "--verified-le-vtable-call","0x46C0D=0x111D04:60",
        "--verified-indirect-target","0x46C0D=0x6A2E0",
        "--verified-le-vtable-call","0x46C1D=0x111D04:60",
        "--verified-indirect-target","0x46C1D=0x69E50",
        "--partial-root","0x69E50",
        # During close approach the original specialist update reaches its
        # slot +0x68 callback. The PlSpec vtable fixup at 0x1120C8 is the
        # exact, object-backed target 0x8A530.
        "--verified-le-vtable-call","0x55E03=0x112060:52",
        "--verified-indirect-target","0x55E03=0x8A530",
        "--partial-root","0x8A530",
        "--indexed-code-jump-table","0x55E20=0x562C0:4:eax",
        "--verified-indirect-target","0x78EE9=0x8A500",
        # The level's plant records use the separate LE vtable beginning at
        # 0x111EA4. Its slot +0x20 (source 0x111EC4) is an object-3 -> object-1
        # SRC_OFFSET32 fixup to link VA 0x6EDE0 (target-object offset 0x5EDE0).
        # Admit the complete 29-entry table at
        # the exact callsite, and the corresponding target only; this keeps
        # other dynamically selected callbacks fail-closed.
        "--verified-le-vtable-call","0x78EE9=0x111EA4:29",
        # This shared site also receives PlSpec records. The +0x20 slot in
        # the separate 52-entry vtable at 0x112060 is fixed to 0x8A500.
        "--verified-le-vtable-call","0x78EE9=0x112060:52",
        "--verified-indirect-target","0x78EE9=0x6EDE0",
        "--partial-root","0x6EDE0",
        "--verified-le-vtable-call","0x6EDF3=0x111EA4:29",
        "--verified-indirect-target","0x6EDF3=0x69E50",
        "--partial-root","0x97590",
        # 0x8A500 invokes the PlSpec vtable's +0x1C method. The canonical
        # slot 0x11207C is a SRC_OFFSET32 fixup to object-1 0x69E50; retain
        # this as a distinct exact-site contract, with no general vtable
        # relaxation.
        "--verified-indirect-target","0x8A513=0x69E50",
        # The next in-range PlSpec UI command at 0x21830 calls slot +0x44.
        # LE vtable slot 0x1120A4 is fixed to original object-1 0x69E20.
        "--verified-indirect-target","0x21830=0x69E20",
        # The group-selection/update path reaches the same PlSpec command
        # slot through a second original callsite. LE vtable slot 0x1120A4
        # has the same fixup to 0x69E20; guard this site independently.
        "--verified-indirect-target","0x21925=0x69E20",
        # FUN_00079100 checks the entity/action state through object-3 slot
        # 112250, whose canonical LE fixup targets object-1 6A2C0.
        "--verified-indirect-target","0x791E9=0x6A2C0",
        "--verified-indirect-target","0x791E9=0x6ED30",
        # The same PlSpec action-state query is called in the hover path at
        # 0x79155 through 0x112060+0x6C = 0x1120CC. Its LE SRC_OFFSET32
        # fixup independently resolves to the original 0x6A2C0 predicate.
        "--verified-le-vtable-call","0x79155=0x112060:52",
        "--verified-indirect-target","0x79155=0x6A2C0",
        # TT_PLANT reaches the same original call with its own object-3 vtable
        # address point: 0x111EA4+0x6C = 0x111F10 -> 0x6ED30 (MOV AL,1; RET).
        # Admit only that LE-fixup-backed pair at this exact callsite.
        "--verified-le-vtable-call","0x79155=0x111EA4:29",
        "--verified-indirect-target","0x79155=0x6ED30",
        # The successful query then asks the selected Thing's slot +0x24;
        # the plant vtable fixes 0x111EC8 to the original 0x6ED40 helper.
        "--verified-le-vtable-call","0x79178=0x111EA4:29",
        "--verified-indirect-target","0x79178=0x6ED40",
        # DrawMapSprites revisits the current selectedThing at 0x7949D and
        # asks the same PlSpec action-state slot. The LE SRC_OFFSET32 fixup
        # at 0x1120CC is the same verified 0x6A2C0 method used at 0x79155;
        # admit this separate original callsite exactly.
        "--verified-le-vtable-call","0x7949D=0x112060:52",
        "--verified-indirect-target","0x7949D=0x6A2C0",
        # If the selectedThing is a plant, DrawMapSprites uses the parallel
        # plant address point and its independently fixed +0x6C query.
        "--verified-le-vtable-call","0x7949D=0x111EA4:29",
        "--verified-indirect-target","0x7949D=0x6ED30",
        # FUN_00079320's list sweep reaches a polymorphic action-state query
        # at 0x79459. BioGame uses slot 0x112250 -> 0x6A2C0; MapDisplay uses
        # slot 0x111F10 -> 0x6ED30. Both exact LE fixups are verified below.
        "--verified-indirect-target","0x79459=0x6A2C0",
        "--verified-indirect-target","0x79459=0x6ED30",
        # The next method in FUN_00079320 is read from the same live BioGame
        # vtable at [EBP+0x24]. The canonical object-3 slot 0x112208 has a
        # single SRC_OFFSET32 fixup to object-1 link 0x85240; retain the
        # exact runtime guard at 0x793EC. PlSpec records use a second LE
        # vtable at 0x112060; its same +0x24 slot is independently fixed to
        # object-1 link 0x43BD0. Both callsite variants remain fail-closed.
        "--verified-indirect-target","0x793EC=0x85240",
        "--verified-indirect-target","0x793EC=0x43BD0",
        # The MapDisplay instance uses its own vtable slot 0x111EC8 at the
        # sibling per-record call 0x793BD; its LE fixup resolves to the
        # original object-1 helper at 0x6ED40.
        "--verified-indirect-target","0x793BD=0x6ED40",
        # The reached MapDisplay helper at 0x6ED40 dispatches its original
        # slot +0x18 through vtable link 0x111EBC, fixed by the LE to 0x568E0.
        "--verified-indirect-target","0x6ED7D=0x568E0",
        # The sweep helper's next query uses the object-3 vtable slot
        # 0x111D6C, whose canonical LE fixup targets object-1 helper 0x6A070.
        "--verified-indirect-target","0x4A5DC=0x6A070",
        "--verified-indirect-target","0x4A985=0x6A070",
        # The same object vtable's +0xB0 method is the next active callback;
        # LE slot 0x111DB4 fixes it to object-1 link 0x6A030.
        "--verified-indirect-target","0x4A6EE=0x6A030",
        # Its following action-state query uses the same canonical object
        # vtable slot 0x111D14 -> 0x6A240 used by the existing movement checks.
        "--verified-indirect-target","0x4A89B=0x6A240",
        # FUN_00085240's reached virtual accessor uses [EDX+4]. At the
        # captured receiver, object-3 slot 0x1121E8 has the canonical fixup
        # to object-1 accessor 0x6A2E0, already exercised at 0x88146.
        "--verified-indirect-target","0x85FC8=0x6A2E0",
        # The next call in the same effect callback uses object-3 method
        # table slot 0x112228 (guest 0x002EC228). The canonical LE SRC_OFFSET32
        # fixup resolves it to object-1 link 0x69E20; the runtime still checks
        # this exact destination at the live [EDI+0x44] callsite.
        "--verified-indirect-target","0x88179=0x69E20",
        "--verified-indirect-target","0x8803A=0x69E20",
        # EF_MONOLITH initialization in FUN_00083BF0 uses the same
        # fixup-backed method slot at the separate original [ESI+0x44] site.
        "--verified-indirect-target","0x8450F=0x69E20",
        # FUN_00089380 has a second call through the same object-3 method
        # table slot 0x112248 already used at 0x893B2. Both original sites
        # carry FF 51 64 and that slot's LE fixup targets object-1 0x86810.
        "--verified-indirect-target","0x893F6=0x86810",
        "--verified-indirect-target","0x58BBD=0x8A720",
        # The BioGame receiver at this same callsite has its independent
        # object-3 slot 0x111D8C fixup to object-1 0x47BF0.
        "--verified-indirect-target","0x58BBD=0x47BF0",
        # FUN_00047BF0's three live entity methods use object-3 fixup slots
        # 0x111D14, 0x111D90 and 0x111D14 respectively.
        "--verified-indirect-target","0x47C01=0x6A240",
        "--verified-indirect-target","0x47C15=0x47A90",
        "--verified-indirect-target","0x47DC2=0x6A240",
        "--verified-indirect-target","0x58BD4=0x6A2E0",
        # FUN_0001E1E0 updates active PlSpec records and dispatches the
        # original shared coordinate query through PlSpec vtable slot +0x04.
        # LE vtable 0x112060 has the canonical fixup 0x112064 -> 0x6A2E0;
        # keep this exact callsite/target equality check fail-closed.
        "--verified-indirect-target","0x1E4DA=0x6A2E0",
        "--verified-indirect-target","0x58BE0=0x86270",
        "--runtime-indexed-code-jump-table","0xEDEAD=0x10C950:4:ecx",
        # SMACKOPEN's first two register-indirect calls have exact original
        # LE provenance: object-3 slot 0x10C830 carries an SRC_OFFSET32
        # fixup to object-1 link 0xD71E0, whose own SRC_OFFSET32 immediate at
        # 0xD71E1 writes the relocated callback 0xD7230 into slot 0x10C82C.
        # Keep both callsites exact and let the runtime dispatcher compare
        # the live target; all other Smacker frontiers remain fail-closed.
        "--verified-indirect-target","0xC62FC=0xD71E0",
        "--verified-indirect-target","0xC6302=0xD7230",
        # The same timer callback is read at the start and completion of the
        # original SMACKOPEN stream-read helper. These are the only reachable
        # reads from its fixup-written 0x10C82C slot in this bounded path.
        "--verified-indirect-target","0xC73CA=0xD7230",
        "--verified-indirect-target","0xC762D=0xD7230",
        "--verified-indirect-target","0xC763A=0xD7230",
        # SMACKOPEN calls the same fixup-initialized timer callback after it
        # has finished parsing the stream metadata. The live frontier at
        # C6A92 reached this exact callsite with the slot still populated by
        # the original D71E0 initializer; admit only the LE-backed target.
        "--verified-indirect-target","0xC6A92=0xD7230",
        # SMACKWAIT reads timer slot 0x10C82C at C4880. SMACKSOUNDUSEMSS
        # (C4050) conditionally initializes this slot from its ESI callback;
        # D71E0 also stores D7230 through an LE-fixup-backed immediate at
        # D71EF. The current replay observed D7230 in live dispatches, and the
        # runtime compares the slot against that exact target at this site.
        "--verified-indirect-target","0xC4880=0xD7230",
        # FUN_000C5AB0 (called by SMACKDOFRAME) takes elapsed timer samples
        # at C5ACB and conditionally at C5B5F/C5B95. All three are the same
        # CS-relative 0x10C82C call verified from canonical LE bytes. The
        # timer slot already dispatched D7230 in the preceding native replay;
        # the runtime still validates its current live contents per call.
        "--verified-indirect-target","0xC5ACB=0xD7230",
        "--verified-indirect-target","0xC5B5F=0xD7230",
        "--verified-indirect-target","0xC5B95=0xD7230",
        # Live post-transition Update reached FUN_00075DC0's call [ESI+0x60]
        # at 0x75E29 with ESI=0x2EC060. That is object-3 link 0x112060;
        # slot 0x1120C0 has an exact LE fixup to object-1 link 0x43980.
        "--verified-indirect-target","0x75E29=0x43980",
        # The next live renderer callback from the phase-9 frame is [ESI+78]
        # at 0x83D40; ESI=0x2EC1E4 and LE slot 0x11225C fixes to 0x95D60.
        "--verified-indirect-target","0x83D40=0x95D60",
        # FUN_00083BF0 immediately dispatches the glyph code through the MAP
        # jpt_83F60 table. Its CMP CH,45 / JA guard and all 70 contiguous LE
        # fixups are checked as one bounded table contract by the lifter.
        "--indexed-code-jump-table","0x83F60=0x83AD4:70:eax",
        # The same live interface record then invokes vtable slot +60 at
        # 0x83F3E; object-3 slot 0x112244 is an exact LE fixup to 0x85070.
        "--verified-indirect-target","0x83F3E=0x85070",
        # jpt_83F60 selected another original glyph case which calls [ESI+44]
        # at 0x84116. The live object-3 slot 0x112228 is fixed to 0x69E20.
        "--verified-indirect-target","0x84116=0x69E20",
        # The next record helper at 0x80FF5 calls [EBX+6C]; live EBX=0x2EC1E4
        # maps to LE 0x1121E4 and its slot 0x112250 fixes to 0x6A2C0.
        "--verified-indirect-target","0x80FF5=0x6A2C0",
        # In the following phase-9 record the original dynamic slot points to
        # link 0x6ED30 (guest 0x259D30), a three-byte original true callback.
        # Its data slot is runtime-populated, not LE-fixup-backed; this exact
        # observed destination is allowed alongside 0x6A2C0 and all other
        # values still trap immediately.
        "--verified-indirect-target","0x80FF5=0x6ED30",
         # The timer initializer also stores the LE-fixed null cleanup routine
         # D7220 into object-3 slot 1A6BB8. SMACKCLOSE reaches its indirect call
         # only after the original decoder has completed its cleanup path; the
         # runtime validates the live slot against this exact fixup-backed
         # target at C6096. Include its original nullsub body as a lifted root.
         "--verified-indirect-target","0xC6096=0xD7220",
         "--partial-root","0xD7220",
        # FUN_000C7660 (REA/Ghidra body C7660..C776E) polls the same live
        # callback at C7696 and then C7740/C774C. The function has no store to
        # 0x10C82C between these sites; its read/transfer helper is the direct
        # call to D72C9. Capstone verifies all three CS-relative CALL bytes,
        # while the runtime compares the slot value with the already observed
        # D7230 target on each dispatch.
        "--verified-indirect-target","0xC7696=0xD7230",
        "--verified-indirect-target","0xC7740=0xD7230",
        "--verified-indirect-target","0xC774C=0xD7230",
        # The follow-on original Smacker close/timing helper at C5BD0 reads
        # the same fixed timer slot. Validate its absolute memory-call bytes
        # above and keep the exact runtime destination constrained to D7230.
        "--verified-indirect-target","0xC5BE4=0xD7230",
        # The live IFCLevel::PlugIn replay entered RADFREE at 0xAE658 and
        # loaded 0x0027D030 from the runtime-populated slot 0x10C4E0. With
        # object-1's measured +0x1EB000 placement this is the original
        # LbMemoryFree_ entry 0x92030. The slot is zero in the LE image and
        # has no fixup, so do not seed it: admit only this exact observed
        # target, and let the runtime dispatcher reject any other value.
        "--verified-indirect-target","0xAE65C=0x92030",
        # Run the original startup caller through the completed __InitRtns call.
        # The harness stops at the next original instruction so the game loop
        # is not entered; PSP and environment bytes come from the authenticated
        # W3-140 capture and the existing W2-114 boot API contract.
        "--partial-root","0xAF9E4",
        # Watcom startup calls __InitRtns with AL=0xff before main. Execute
        # that original init-table dispatcher in the bounded fixture so the
        # OPTIONS transition inherits genuine CRT/C++ initialization rather
        # than a harness-seeded global.
        "--partial-root","0xC871C",
        "--partial-root","0x830F0","--partial-root","0x962F0",
        "--partial-root","0xD2344","--partial-root","0xD23A7",
        # The live transition selected the original DOS interrupt stub for
        # vector 33h (LE D23AD; bytes CD 33 C3). Lift that exact table entry
        # so the next run captures the real mouse-service request.
        "--partial-root","0xD23AD",
        *sum((["--partial-root",hex(t)] for t in (0x2C3D0,0x834A0,0x2C520,0x2C560,
            0x34F50,0x957B0,0x69C80,0x957C0,0x957E0,0x957D0,
            0x95830,0x95880,0x95890,0x958E0)),[]),
        "--stack-range","0x003FD000:0x3000",
        "--dynamic-range","0x00090000:0x20000",
        "--dynamic-range","0x00390000:0x6D000",
        "--dynamic-range","0x002DA000:0xA8C50","--dynamic-range","0x01000000:0x02002000",
        # Original Watcom startup reads PSP fields through the ES selector.
        # These exact LE operands are admitted only with the bounded PSP
        # descriptor installed by this test (selector 0x24, base 0x8000, 256 B).
        "--segment-relative-access","0xAFA37=ES:0x5C:4",
        "--segment-relative-access","0xAFAD8=ES:0x2C:2",
        "--segment-relative-access","0xAFB06=ES:0x29AC41:2",
        "--segment-relative-access","0xAFB56=ES:0x2E5795:2",
        # Stop immediately after the original __InitRtns call returns. This
        # keeps unrelated later CRT switch tables out of this startup-prefix
        # closure while still running the real caller and all init callbacks.
        "--stop-after-call","0xAFBEF=0xC871C",
        "--verified-indirect-target","0x98A1A=0x14BB0",
        # The post-transition record iterator (FUN_000862F0) dispatches slot
        # +0x3C to 0x851B0; that original routine conditionally dispatches
        # slot +0x60 to 0x85070. Both destinations are the exact fixup-backed
        # entries at 0x112220/0x112244 in one original object-3 vtable.
        "--verified-indirect-target","0x86320=0x851B0",
        "--verified-indirect-target","0x851ED=0x85070",
        "--verified-indirect-target","0x89920=0x89870",
        "--verified-indirect-target","0x898AD=0x89860",
        "--verified-indirect-target","0x13AA0=0x139F0",
        "--verified-indirect-target","0x13A2D=0x139E0",
        "--verified-indirect-target","0x10140=0x10090",
        "--verified-indirect-target","0x100CD=0x10060",
        "--deferred-indirect-call","0xC87A9",
        "--deferred-indirect-call","0xCB889",
        "--deferred-indirect-call","0xCB89C",
        # The Watcom EFG compatibility path contains an optional DPMI host
        # callback via [0x2E54F8+0x30]. Keep the original call fail-closed;
        # the bounded startup fixture must prove whether it is actually reached.
        "--deferred-indirect-call","0xBBF0D",
        # These audio/MIDI callback sites are reached only if the original
        # Update path observes initialized driver objects. Keep their exact
        # indirect dispatch intact; the harness must fail if one is reached
        # without a mapped, evidence-backed target.
        "--deferred-indirect-call","0xC9BF2",
        "--deferred-indirect-call","0xCCB84",
        "--deferred-indirect-call","0xCCC7C",
        "--deferred-indirect-call","0xCCC9B",
        "--deferred-indirect-call","0xCCE57",
        "--deferred-indirect-call","0xCE94F",
        # FUN_000A8CD0's other object/driver callbacks remain fail-closed.
        # A8D95 is admitted below as one finite set derived from MyGadget's
        # actual LE fixups; A8D43 is deferred while A8DB4 uses the callback
        # installed by setup_game: GenericHelpDraw at LE 0x61AD0.
        "--deferred-indirect-call","0xA8D43",
        "--verified-indirect-target","0xA8DB4=0x61AD0",
        "--partial-root","0x61AD0",
        # Callback-table calls below belong to resource/configuration helpers
        # reached only from the newly included OPTIONS methods. Keep them
        # fail-closed; the bounded test records whether a given route executes.
        # V15: the eight per-class record serializers (0x101A0 0x13B00 0x39E50 0x441C0 0x47330
        # 0x57110 0x86380 0x89980) are no longer deferred; see the verified vtable functions above.
        "--deferred-indirect-call","0xADB05","--deferred-indirect-call","0xC2D91",
        "--deferred-indirect-call","0xC2FC8","--deferred-indirect-call","0xC2FD9",
        "--deferred-indirect-call","0xC30E3","--deferred-indirect-call","0xC3157",
        "--deferred-indirect-call","0xC31AB","--deferred-indirect-call","0xC31D0",
        "--deferred-indirect-call","0xC31EA",
        # Additional callbacks discovered while closing OPTIONS Update/Draw.
        # They remain fail-closed and must stay unreached in this no-input pass.
        "--deferred-indirect-call","0x24153",
        "--deferred-indirect-call","0x76395",
        "--indexed-cs-table","0xD00F3=0xD00AA:36:edi:edx",
        "--indexed-cs-table","0xD0193=0xD0146:36:edi:edx",
        "--indexed-code-jump-table","0x57A0C=0x57900:8:edx",
        "--indexed-code-jump-table","0x70ED1=0x70E9C:4:eax",
        "--indexed-code-jump-table","0x6F854=0x6F7C0:31:ebx",
        "--indexed-code-jump-table","0x6B064=0x6AB08:10:eax",
        "--indexed-code-jump-table","0xA1611=0xA1524:5:eax",
        "--indexed-code-jump-table","0xC22B5=0xC2283:5:eax",
        "--indexed-code-jump-table","0xC2500=0xC24DB:4:eax",
        "--indexed-code-jump-table","0xC2D7B=0xC2D54:5:eax",
        "--indexed-code-jump-table","0xC28EC=0xC28B9:5:eax",
        # Original setup_game and its CRT helpers use these verified LE switch tables.
        "--indexed-code-jump-table","0x94D56=0x94AA4:5:eax",
        "--indexed-code-jump-table","0xCA80E=0xCA758:4:eax",
        "--indexed-code-jump-table","0xCA9E0=0xCA768:4:eax",
        "--indexed-code-jump-table","0x4AB28=0x4AAA0:28:eax",
        # FUN_0004B1F0's MAP-named jpt_505B7 has 25 contiguous LE
        # SRC_OFFSET32 entries. CMP AL,0x18 / JA and AND EAX,0xff bound
        # the original selector, so admit every fixed case in one batch.
        "--indexed-code-jump-table","0x505B7=0x4B170:25:eax",
        "--indexed-code-jump-table","0x790AA=0x78B10:7:eax",
        # IFCPlanetside::Update uses MAP jpt_21AEB; all eight contiguous
        # entries are Object 1 LE fixups, and the original CMP/Jcc bounds it.
        "--indexed-code-jump-table","0x21AEB=0x21354:8:edx",
        # The four-way specialist mode switch and the eleven-way PA_ABORT_MOVE
        # subdispatch are both bounded by original x86 guards and fully fixed
        # to decoded object-1 code in the canonical LE.
        "--indexed-code-jump-table","0x6DB38=0x6D21C:4:ecx",
        "--indexed-code-jump-table","0x76C21=0x76BCC:11:eax",
        "--indexed-code-jump-table","0x3F024=0x3EC88:4:ebx",
        "--indexed-code-jump-table","0x492AA=0x49140:11:eax",
        ]
    # IFCLevel::Draw's later state machine has 24 identical JMP sites into
    # MAP's jpt_E1DE1 at 0xE35D3. Every one of its 27 dwords has an exact
    # object-1 SRC_OFFSET32 fixup. The generated guard bounds EAX to 0..26
    # and checks the resulting DS table range before using the original target.
    draw_state_sites=(0xE1DE1,0xE1E1A,0xE2016,0xE2048,0xE21EF,0xE221A,
        0xE2342,0xE2366,0xE271B,0xE2754,0xE296E,0xE29A0,0xE2B56,0xE2B81,
        0xE2CA9,0xE2CCD,0xE2EF0,0xE2FF3,0xE30BA,0xE314C,0xE3372,0xE346D,
        0xE3537,0xE35CC)
    for site in draw_state_sites:
        options += ["--indexed-code-jump-table",f"{hex(site)}=0xE35D3:27:eax"]
    # Smacker's active decoder uses several additional direct dispatch tables.
    # Their MAP entries and every contiguous slot are independently backed by
    # object-1 SRC_OFFSET32 fixups in the canonical LE; admit the tables as a
    # batch with index and DS-backing checks, rather than stopping once per case.
    smack_static_tables=(
        (0xE242D,0xE2434,27,"eax"),
        (0xE2D5B,0xE2D62,27,"eax"),
        (0xE31DA,0xE31E1,27,"eax"),
        (0xE4148,0xE4150,16,"eax"),
        (0xE4453,0xE445A,16,"esi"),
        (0xE83CF,0xE83E0,16,"eax"),
    )
    for site,table,count,index_reg in smack_static_tables:
        options += ["--indexed-code-jump-table",
                    f"{hex(site)}={hex(table)}:{count}:{index_reg}"]
    # 0x96B23 explicitly loads the relocated 0x96B10 character-emitter into
    # ECX before entering the original Watcom formatter. Admit only those
    # formatter callsites, and leave the original run-time pointer lookup in
    # place; the test must resolve the actual loaded 0x281B10 address through
    # the verified object-1 map.
    for site in (0xB65FA,0xB66D8,0xB66F1,0xB670F,0xB6742,0xB677D,0xB679E,0xB67BD,0xB67FC):
        options += ["--verified-indirect-target",f"{hex(site)}=0x96B10"]
    # The original error formatter FUN_000BAA0F writes its local message
    # emitter address 0xBA9FE to ECX, then calls FUN_000B6534. This shares
    # the formatter callsite 0xB65FA with the ordinary 0x96B10 emitter.
    options += ["--verified-indirect-target","0xB65FA=0xBA9FE"]
    # IFCTitle::PlugIn and IFCOptions::PlugIn both use the same original
    # qsort callback and formatter callsites. The target set here is limited
    # to the original values already evidenced by the first-load closure.
    for site in (0xA337A,0xA3385,0xA3390,0xA33A3,0xA33AE,0xA3483,0xA35F8,0xA3643):
        options += ["--verified-indirect-target",f"{hex(site)}=0x92670"]
        options += ["--verified-indirect-target",f"{hex(site)}=0x184B0"]
    # IFCLevel::Update stores &DAT_00185EB0 after phase-9 confirmation.
    # Its LE-initialized vtable slot 0 resolves to the adjustor thunk above.
    options += ["--verified-indirect-target","0x9282C=0x833F0"]
    options += ["--verified-indirect-target","0x92821=0x833E0"]
    options += ["--verified-indirect-target","0x92821=0x25190",
                "--verified-indirect-target","0x9282C=0x251A0",
                "--verified-indirect-target","0x5AF1A=0x25180",
                "--verified-indirect-target","0x83561=0x25170"]
    # Keep the additional return-path targets scoped to the opt-in roundtrip
    # probe so the standard OPTIONS->TITLE regression keeps its original set.
    if os.environ.get("GWRECOMP_IFC_TRANSITION_CAUSAL_PROBE")=="roundtrip":
        options += ["--verified-indirect-target","0x92821=0x13610",
                    "--verified-le-vtable-call","0x92821=0x111FE0:8",
                    "--verified-le-vtable-call","0x92821=0x111B04:8",
                    "--verified-le-vtable-call","0x9282C=0x111B04:8"]
    # game() now has an opt-in full-entry replay from the live TITLE state.
    # These four title-side targets are the same adjustor thunks installed by
    # the original object-3 vtable/fixups (PlugIn/Update/Draw/PullOut), observed
    # in the existing title dispatch evidence. The dispatcher remains exact
    # target allowlisted; this adds no general indirect-call fallback.
    # Vtable words are guest addresses after object rebasing (for example,
    # 0x1FE700). The lifter's allowlist is expressed in original LE link VAs,
    # so admit the corresponding fixup-backed code thunks instead.
    options += ["--verified-indirect-target","0x5AF1A=0x13700",
                "--verified-indirect-target","0x5AF1A=0x13600",
                "--verified-indirect-target","0x83561=0x136F0",
                "--verified-indirect-target","0x83561=0x135F0",
                "--verified-indirect-target","0x92821=0x13710",
                "--verified-indirect-target","0x9282C=0x13620",
                "--verified-indirect-target","0x9282C=0x1B650",
                "--verified-indirect-target","0x92821=0x1B640",
                "--verified-indirect-target","0x5AF1A=0x1B630",
                "--verified-indirect-target","0x83561=0x1B620"]
    # The ID=0 title action publishes the original single-player interface.
    # Its runtime vptr is 0x002EC020 (object-3 link 0x112020); each of these
    # exact targets is backed by the canonical LE fixups in that four-slot
    # table. Keep all four runtime dispatch sites guarded by that table.
    singleplayer_vtable_link=0x112020
    singleplayer_vtable_offsets=[0x36E0,0x36D0,0x36C0,0x36B0]
    singleplayer_fixups={f.source_link:f for f in image.fixups
        if singleplayer_vtable_link<=f.source_link<singleplayer_vtable_link+16}
    if set(singleplayer_fixups)!={singleplayer_vtable_link+i*4 for i in range(4)} or any(
            singleplayer_fixups[singleplayer_vtable_link+i*4].target_object!=1 or
            singleplayer_fixups[singleplayer_vtable_link+i*4].target_offset!=singleplayer_vtable_offsets[i]
            for i in range(4)):
        raise SystemExit("single-player interface vtable no longer matches the four canonical LE fixups")
    options += ["--verified-indirect-target","0x9282C=0x136E0",
                "--verified-indirect-target","0x92821=0x136D0",
                "--verified-indirect-target","0x5AF1A=0x136C0",
                "--verified-indirect-target","0x83561=0x136B0",
                "--verified-le-vtable-call","0x9282C=0x112020:4",
                "--verified-le-vtable-call","0x92821=0x112020:4",
                "--verified-le-vtable-call","0x5AF1A=0x112020:4",
                "--verified-le-vtable-call","0x83561=0x112020:4"]
    # The observed TITLE vtable is object-3 link 0x112040; its contiguous
    # four LE fixups cover the original PlugIn/PullOut/Update/Draw thunks.
    # The native draw dispatcher uses the same table at slot +0x0C.
    options += ["--verified-le-vtable-call","0x5AF1A=0x112040:4",
                "--verified-le-vtable-call","0x83561=0x112040:4",
                "--verified-le-vtable-call","0x5AF1A=0x111AD4:4",
                "--verified-le-vtable-call","0x83561=0x111AD4:4",
                "--verified-le-vtable-call","0x5AF1A=0x111B04:8",
                "--verified-le-vtable-call","0x9282C=0x111FE0:8",
                "--verified-le-vtable-call","0x5AF1A=0x111FE0:8",
                "--verified-le-vtable-call","0x83561=0x111FE0:8"]
    # After the original phase-9 PlugIn returns, game() uses these same two
    # dispatch callsites for the newly current interface. Admit only the LE
    # fixup-backed slots 2 and 3 from the verified 0x111F68 table.
    options += ["--verified-indirect-target","0x5AF1A=0x833D0",
                "--verified-indirect-target","0x83561=0x833C0"]
    options += ["--verified-le-vtable-call","0x92821=0x111B04:8", "--verified-le-vtable-call","0x92821=0x111FE0:8", "--verified-le-vtable-call","0x9282C=0x111B04:8"]
    options += ["--verified-le-vtable-call","0x9282C=0x111AD4:4", "--verified-le-vtable-call","0x92821=0x111AD4:4"]
    # V25: post-victory interface table, all slots backed by canonical LE fixups.
    for site, target in ((0x9282C,0x83430),(0x92821,0x83420),(0x5AF1A,0x83410),(0x83561,0x83400)):
        options += ["--verified-indirect-target",f"{hex(site)}={hex(target)}",
                    "--verified-le-vtable-call",f"{hex(site)}=0x111F90:8"]
    # V17: defeat interface (Lose, IFC object 0x185EF8). Its eight-slot vtable is object-3 link 0x111FB8:
    # slots 0..3 are the LE fixup-backed this-adjusting thunks 0x83470/0x83460/0x83450/0x83440 (PlugIn/PullOut/
    # Update/Draw dispatch targets, exactly like the Win table 0x111F90 above) and slots 4..7 are the original
    # Lose::PlugIn 0x72530, PullOut 0x72680, 0x72740, 0x72710. game() reaches it through the same
    # PlugIn/PullOut callsites 0x9282C/0x92821 (flag 0x80 of [0x117464] -> pendingIFC 0x185EF8 at 0x92800).
    for site, target in ((0x9282C,0x83470),(0x92821,0x83460),(0x5AF1A,0x83450),(0x83561,0x83440)):
        options += ["--verified-indirect-target",f"{hex(site)}={hex(target)}",
                    "--verified-le-vtable-call",f"{hex(site)}=0x111FB8:8"]
    # V17: after the defeat screen the original returns to the TITLE interface (object 0x184AD8, vtable
    # 0x112040: thunks 0x13720/0x13710/0x13700/0x136F0, PlugIn 0x70D10, PullOut 0x70E30, ...). game() reaches its
    # PlugIn at 0x9282C and the Lose PullOut/TITLE PullOut at 0x92821 (0x13710 already admitted above).
    options += ["--verified-indirect-target","0x9282C=0x13720",
                "--verified-le-vtable-call","0x9282C=0x112040:8",
                "--verified-le-vtable-call","0x92821=0x112040:8"]
    # V17: TITLE idle (>30 s, 0x71070) publishes the attract/intro interface 0x186A24 (vtable 0x111F40: thunks
    # 0x833B0/0x833A0/0x83390/0x83380, PlugIn 0x71160 which calls PlayIntro 0x92930 = LOGO, BIOINTRO, GW).
    for site, target in ((0x9282C,0x833B0),(0x92821,0x833A0),(0x5AF1A,0x83390),(0x83561,0x83380)):
        options += ["--verified-indirect-target",f"{hex(site)}={hex(target)}",
                    "--verified-le-vtable-call",f"{hex(site)}=0x111F40:8"]
    # The phase-9 launch object at 0x185EB0 has a complete eight-slot vtable
    # at 0x111F68. The test above verifies all eight object-3 SRC_OFFSET32
    # fixups and their object-1 destinations; register that exact table for
    # the native Update and Draw dispatch sites.
    options += ["--verified-le-vtable-call","0x5AF1A=0x111F68:8",
                "--verified-le-vtable-call","0x83561=0x111F68:8"]
    # V26: game() PlugIn/PullOut of the toPlnt interface (0x185EB0, vtable
    # 0x111F68). The verified-indirect-targets 0x9282C=0x833F0 and
    # 0x92821=0x833E0 above already exist; only the (base,slot) pair guards
    # were missing. Exactly these two pairs, nothing generic.
    options += ["--verified-le-vtable-call","0x9282C=0x111F68:8",
                "--verified-le-vtable-call","0x92821=0x111F68:8"]
    # V27: Creature::Create (0x46C90) calls [vptr+0x78] at 0x46DCF. For the
    # live creature vtable 0x111D04 (60 LE fixups) slot 30 is the original
    # method 0x6A080, which was not lifted; Krell turn ~850 reaches it.
    options += ["--partial-root","0x6A080",
                "--verified-le-vtable-call","0x46DCF=0x111D04:60"]
    # V28: Krell research approach (Jon next to a creature) reaches [vptr+0x58]
    # at 0x3FB8A; vtable 0x111D04 slot 22 is the original method 0x6A050.
    options += ["--partial-root","0x6A050",
                "--verified-le-vtable-call","0x3FB8A=0x111D04:60"]
    # V28: 0x82ED0 (object factory) calls slot 0 of the one-slot LE vtable
    # 0x11212C at 0x82F77; its original method is 0x8A310.
    # The 0x82ED0 map searcher dispatches to four adjacent one-slot LE callback
    # classes (0x112120/24/28/2C -> 0x89FC0/0x8A0E0/0x8A170/0x8A310). Observed live:
    # 0x112120 and 0x11212C; the other two are the same verified fixup family.
    options += ["--partial-root","0x8A310","--partial-root","0x89FC0",
                "--partial-root","0x8A0E0","--partial-root","0x8A170",
                "--verified-le-vtable-call","0x82F77=0x11212C:1",
                "--verified-le-vtable-call","0x82F77=0x112120:1",
                "--verified-le-vtable-call","0x82F77=0x112124:1",
                "--verified-le-vtable-call","0x82F77=0x112128:1"]
    # Second searcher callback family used by the study routine 0x41F90 (stand-position
    # search at 0x42C66): one-slot LE tables 0x111CD4..0x111CE0 -> 0x45390/0x45450/0x454E0/0x455A0.
    # Observed live: 0x111CD8 (0x45450). 0x455A0 is its unlifted sibling.
    options += ["--partial-root","0x45450","--partial-root","0x455A0",
                "--verified-le-vtable-call","0x82F77=0x111CD8:1",
                "--verified-le-vtable-call","0x82F77=0x111CE0:1"]
    # V29_A: Krell GENELAB selected/hovered. IFCPlanetside draw at 0x22F87 calls
    # [[panel+0xC8]+6]+0x10 (slot 4). The live receiver is the Building secondary
    # vtable 0x111DC4 (12 fixup-backed this-adjusting thunks); slot 4 = 0x69CE0
    # (sub eax,[eax-4]; jmp 0x68CB0). Only the observed slot is a lift root.
    options += ["--partial-root","0x69CE0",
                "--verified-le-vtable-call","0x22F87=0x111DC4:12"]
    # V29_A2: same draw routine 0x22F40 also calls slot 3 (0x22FEA) and slot 2
    # (0x22FFE) of the live Building secondary vtable 0x111DC4: 0x6B490 / 0x69CF0.
    options += ["--partial-root","0x6B490","--partial-root","0x69CF0",
                "--verified-le-vtable-call","0x22FEA=0x111DC4:12",
                "--verified-le-vtable-call","0x22FFE=0x111DC4:12"]
    # V29_A3: IFCPlanetside::Update 0x21380 calls [EBX+4] at 0x215AC with the same Building
    # secondary vtable 0x111DC4 (observed slot 1 -> 0x69D00, thunk to the Gene Pod panel's
    # gadget-event handler 0x68380). Only observed destinations are lift roots.
    options += ["--partial-root","0x69D00",
                "--verified-le-vtable-call","0x215AC=0x111DC4:12"]
    # V29_A4: Building secondary-vtable slot 1 (0x69D00 -> 0x68380) is the Gene Pod panel's
    # gadget-event handler. After SUB EDI,7 / CMP DI,3 / JA it dispatches through the
    # CS dword table 0x68370 (4 LE-fixup-backed entries: ids 7..10 -> 0x68C45/0x6893D/
    # 0x6873E/0x68846). Observed live: id 8 (0x6893D) from a click on the red button.
    options += ["--indexed-code-jump-table","0x68736=0x68370:4:eax"]
    # V29_B: FUN_00058330 (Thing draw/update) calls [[Thing+0x23]+0xA0] at 0x58C02. Observed
    # live while a Gene-Pod-produced entity is processed (turn 9005): slot 40 -> 0x58150.
    # The same LE method is the slot-40 entry of the three Thing vtables already used by
    # the sibling calls 0x58681/0x58BE0: 0x111D04 (+0xA0=0x111DA4), 0x112060 (0x112100),
    # 0x1123BC (0x11245C). Guards verify the live base and target at runtime.
    options += ["--partial-root","0x58150",
                "--verified-le-vtable-call","0x58C02=0x111D04:60",
                "--verified-le-vtable-call","0x58C02=0x112060:52",
                "--verified-le-vtable-call","0x58C02=0x1123BC:48"]
    # V29_B2: with the GENELAB selected, Effect effects[0] (0x341576, vtable 0x1121E4, EDX=GENELAB
    # building 0x33D2FC) reaches the same site 0x58C02 at turn 8921; slot 40 of 0x1121E4
    # (0x112284) -> 0x86120, which itself calls 0x58150 (V29_B) and [[obj+0x23]+8].
    options += ["--partial-root","0x86120",
                "--verified-le-vtable-call","0x58C02=0x1121E4:64"]
    # V29_C: FUN_00058330's state callback at 0x58DAF (CALL [[Thing+0x23]+0x2C], slot 11) was
    # admitted for the PlSpec table 0x112060. A creature produced by the Gene Pod (creature[0]
    # at 0x32CF86, vtable 0x111D04) reaches it at turn 9007: slot 11 (0x111D30) -> 0x45D00,
    # which indexes the 45-byte species records at 0x1042C4 by creature+0x7A.
    options += ["--partial-root","0x45D00",
                "--verified-le-vtable-call","0x58DAF=0x111D04:60"]
    # V30_A: IFCPlanetside panel switch (FUN_0006B0C0) tears down the previous panel owner
    # [0x1859BC]: CALL [[obj+6]+0xC] (slot 3, 0x6B490, already lifted) then CALL [[obj+6]+0x14]
    # at 0x6B0F1 (slot 5). Observed live when the Gene-Pod-produced Mula (creature[0]) is
    # clicked with the GENELAB panel active: guest 0x254CD0 = link 0x69CD0, slot 5 of the
    # Building secondary vtable 0x111DC4 (12 fixup-backed thunks), `sub eax,[eax-4]; jmp 0x68250`.
    options += ["--partial-root","0x69CD0",
                "--verified-le-vtable-call","0x6B0F1=0x111DC4:12"]
    # V30_B: map display FUN_00078B30 draws the zone marker entity (MULE ZONE, entity 0 of the 16-slot
    # table at link 0x16C6FE, guest 0x3466FE, vtable 0x1123BC) when the camera brings the zone on
    # screen: CALL [[ent+0x23]+0x20] at 0x78EE9 (slot 8). Observed live target guest 0x280930 =
    # link 0x95930. Same Thing vtable 0x1123BC already admitted at 0x58C02 (V29_B).
    options += ["--partial-root","0x95930",
                "--verified-le-vtable-call","0x78EE9=0x1123BC:48"]
    # V31_A: Madami level load (toPlnt -> start_game). FUN_00082ED0 (per-bucket walk) calls
    # CALL [[obj+0x25]] at 0x82F77 (slot 0 of the callback vtable). Siblings 0x111CD8/0x111CE0
    # were admitted in V26 (Krell); the Madami map additionally reaches vtable 0x111CA8, whose slot 0
    # is fixup-backed: guest 0x211C40 = link 0x26C40. Observed live at iteration 199+ of the
    # Krell->Madami transition (EDX=0x2EBCA8 = link 0x111CA8).
    # V31_A (cont.): the call is CALL [EDX] with EDX = [obj+0x25] = the *address of a callback cell*
    # (disp 0), so each cell needs its own CALLSITE=CELL:1 row. Madami's buckets use cell 0x111CAC
    # (-> link 0x26C20) as well as 0x111CA8. The four contiguous fixup-backed cells 0x111CA8/AC/B0/B4
    # resolve to LE functions 0x26C40/0x26C20/0x26B50/0x26510; all four cells are admitted for this site only.
    options += ["--partial-root","0x26C40","--partial-root","0x26C20",
                "--partial-root","0x26B50","--partial-root","0x26510",
                "--verified-le-vtable-call","0x82F77=0x111CA8:1",
                "--verified-le-vtable-call","0x82F77=0x111CAC:1",
                "--verified-le-vtable-call","0x82F77=0x111CB0:1",
                "--verified-le-vtable-call","0x82F77=0x111CB4:1"]
    # V32_A: effect/doodad callback-cell table 0x111C80..0x111CB8 (15 fixup-backed cells -> LE functions).
    # Sites that CALL [EDX] with EDX=&cell: 0x82F77 (V31) and 0x25A7A (FUN_000256E0, per-cell update).
    # OBSERVED dynamically: 0x82F77 cells 0x111CA8,0x111CAC (V31); 0x25A7A cell 0x111C9C (V32, idle Madami,
    # target guest 0x211F00 = link 0x26F00). All other cells are STATIC/PREVENTIVE: same fixup-backed table,
    # chosen to avoid one 7-minute rebuild per cell; each row is still verified against its own fixup.
    options += ["--partial-root","0x26650","--partial-root","0x269D0","--partial-root","0x26CE0","--partial-root","0x26E00","--partial-root","0x26E60","--partial-root","0x26F00","--partial-root","0x26F50","--partial-root","0x270E0","--partial-root","0x278D0","--partial-root","0x96158"]
    options += ["--verified-le-vtable-call","0x25A7A=0x111C80:1",
                "--verified-le-vtable-call","0x25A7A=0x111C84:1",
                "--verified-le-vtable-call","0x25A7A=0x111C88:1",
                "--verified-le-vtable-call","0x25A7A=0x111C8C:1",
                "--verified-le-vtable-call","0x25A7A=0x111C90:1",
                "--verified-le-vtable-call","0x25A7A=0x111C94:1",
                "--verified-le-vtable-call","0x25A7A=0x111C98:1",
                "--verified-le-vtable-call","0x25A7A=0x111C9C:1",
                "--verified-le-vtable-call","0x25A7A=0x111CA0:1",
                "--verified-le-vtable-call","0x25A7A=0x111CA4:1",
                "--verified-le-vtable-call","0x25A7A=0x111CA8:1",
                "--verified-le-vtable-call","0x25A7A=0x111CAC:1",
                "--verified-le-vtable-call","0x25A7A=0x111CB0:1",
                "--verified-le-vtable-call","0x25A7A=0x111CB4:1",
                "--verified-le-vtable-call","0x25A7A=0x111CB8:1",
                "--verified-le-vtable-call","0x82F77=0x111C80:1",
                "--verified-le-vtable-call","0x82F77=0x111C84:1",
                "--verified-le-vtable-call","0x82F77=0x111C88:1",
                "--verified-le-vtable-call","0x82F77=0x111C8C:1",
                "--verified-le-vtable-call","0x82F77=0x111C90:1",
                "--verified-le-vtable-call","0x82F77=0x111C94:1",
                "--verified-le-vtable-call","0x82F77=0x111C98:1",
                "--verified-le-vtable-call","0x82F77=0x111C9C:1",
                "--verified-le-vtable-call","0x82F77=0x111CA0:1",
                "--verified-le-vtable-call","0x82F77=0x111CA4:1",
                "--verified-le-vtable-call","0x82F77=0x111CB8:1"]
    # V33_A: SpawnEffect-style walk FUN_00083BF0 queries the Things in a cell (CALL [[thing+0x23]] at
    # 0x8481C, already covered) and then CALL [[thing+0x23]+8] at 0x8485D (slot 2). Observed live at turn
    # ~6350 of Madami (Ralph on his way to a Solar Panel order near the enemy base, wild species-4 creature
    # in the cell): EDX=0x2EBD04 (creature vtable 0x111D04), target guest 0x2552D0 = link 0x6A2D0.
    options += ["--partial-root","0x6A2D0",
                "--verified-le-vtable-call","0x8485D=0x111D04:60"]
    # V33_B: Thing update FUN_00058330 calls [[thing+0x23]+0xA4] (slot 41) at 0x58681 and 0x5895F (siblings of
    # the V29_B slot-40 site 0x58C02). With Madami's Extractor/Solar/enemy base on screen an Effect
    # (vtable 0x1121E4, V29_B2) reached it at turn ~8985: ICALL unresolved guest 0x242F60 = link 0x57F60
    # (slot 41 of 0x1121E4 at link 0x112288). The runtime message does not say which of the two sites
    # executed, so both are admitted for this one vtable/slot (same fixup-backed target).
    options += ["--partial-root","0x57F60",
                "--verified-le-vtable-call","0x58681=0x1121E4:64",
                "--verified-le-vtable-call","0x5895F=0x1121E4:64"]
    # V35_A: same FUN_00083BF0 site 0x8485D (CALL [[thing+0x23]+8], slot 2) as V33_A but with the sibling
    # creature vtable 0x112060 (52 slots; already an LE-verified entity-status class): observed live at turn
    # ~3950 of Madami (v33_e state, Ralph idle at the vein field): EDX=0x2EC060, target guest 0x2754F0 =
    # link 0x8A4F0 = slot 2 of the LE vtable at link 0x112060 (fixup-backed).
    options += ["--partial-root","0x8A4F0",
                "--verified-le-vtable-call","0x8485D=0x112060:52"]
    # V35_B: plant-update walk FUN_00089EB0 (iterates the plant table 0x16B4BE, stride 0x31) calls
    # CALL [[plant+0x23]+0x64] (slot 25) at 0x89EE6. Observed live at turn ~3950 of Madami (v33_e state):
    # ESI/vtable = 0x2EC28C (link 0x11228C), target guest 0x2749D0 = link 0x899D0 = LE fixup at link 0x1122F0.
    options += ["--partial-root","0x899D0",
                "--verified-le-vtable-call","0x89EE6=0x11228C:40"]
    # V35_C: plant slot-25 method FUN_000899D0 dispatches on (type-2) in [0..5] through a six-entry
    # object-1 fixup jump table at 0x899B0 (original range guard at 0x899E5-0x899E9).
    options += ["--indexed-code-jump-table","0x899F4=0x899B0:6:eax"]
    # V35.1_A: spawn walk FUN_00082F80 (own Mula hatching from the GENELAB, Madami) calls
    # CALL [[obj+0x25]] (slot 0) at 0x83026 on a local template object whose vtable is the creature
    # address point 0x111CF4 (live EDX=0x2EBCF4); target guest 0x240BD0 = link 0x55BD0 = LE fixup at 0x111CF4.
    options += ["--partial-root","0x55BD0",
                "--verified-le-vtable-call","0x83026=0x111CF4:8"]
    code_obj=image.objects[0]; code_bytes=bytes(image.object_data(1))
    # The first Update of the interface published at 0x185E9A reaches an
    # original callback through [EBX+4] at 0x215AC. The live EBX is the
    # rebased LE table at 0x111BE8. Admit the complete contiguous fixup-backed
    # table as a batch, but only after checking every source slot, target
    # object/offset, the actual call bytes, and the selected thunk bytes.
    update_callback_targets=(0x138D0,0x138C0,0x138B0,0x6B490,0x138A0,0x6B1B0,
        0x6B9F0,0x6BAC0,0x6BBF0,0x6BC10,0x6BC10,0x6B0C0,0x6B1D0,
        0x96158,0x6B490,0x6BAA0,0x6B1B0,0x6B9F0)
    update_callback_sources=tuple(0x111BE8+4*i for i in range(len(update_callback_targets)))
    update_callback_fixups={f.source_link:f for f in image.fixups
        if f.source_link in update_callback_sources}
    update_callback_call=code_bytes[0x215AC-code_obj.base:0x215AF-code_obj.base]
    loader_draw_callback_calls={site:code_bytes[site-code_obj.base:site-code_obj.base+3]
        for site in (0x22F87,0x22FEA,0x22FFE)}
    selected_thunk=code_bytes[0x138C0-code_obj.base:0x138D0-code_obj.base]
    if (set(update_callback_fixups)!=set(update_callback_sources) or
            any(update_callback_fixups[src].source_type!=0x07 or
                update_callback_fixups[src].target_object!=1 or
                image.objects[update_callback_fixups[src].target_object-1].base+
                    update_callback_fixups[src].target_offset!=target
                for src,target in zip(update_callback_sources,update_callback_targets)) or
            update_callback_call!=bytes.fromhex("FF 53 04") or
            loader_draw_callback_calls!={0x22F87:bytes.fromhex("FF 52 10"),
                0x22FEA:bytes.fromhex("FF 52 0C"),0x22FFE:bytes.fromhex("FF 53 08")} or
            image.link_to_linear(0x111BE8)!=0x002EBBE8 or
            image.link_to_linear(0x138C0)!=0x001FE8C0 or
            selected_thunk!=_OrigDigest("c95738f95a62d512cd6e8ad8e0f11b50aaeed380cff765f1130eb3c099717dcc",16) or
            code_bytes[0x6BBF0-code_obj.base:0x6BBF0-code_obj.base+12]!=
                _OrigDigest("7a5eef84628b481344d275a88eb787a60ffe95bd4b2a9c9e85efa0ba9d881b4e",12)):
        raise SystemExit("first next-interface Update callback table no longer matches its 18 contiguous LE fixups and Capstone call/thunk bytes")
    for site,source,target in ((0x22FEA,0x111BF4,0x6B490),):
        fixup=update_callback_fixups[source]
        if image.objects[fixup.target_object-1].base+fixup.target_offset!=target:
            raise SystemExit(f"original callback callsite {site:#x} does not match its exact LE slot {source:#x}")
        options += ["--verified-indirect-target",f"{hex(site)}={hex(target)}"]
    loader_draw_fixup=next((f for f in image.fixups if f.source_link==0x111BF8),None)
    if (loader_draw_fixup is None or loader_draw_fixup.source_type!=0x07 or
            loader_draw_fixup.target_object!=1 or
            image.objects[0].base+loader_draw_fixup.target_offset!=0x138A0 or
            code_bytes[0x138A0-code_obj.base:0x138A8-code_obj.base]!=
                _OrigDigest("ba905c0db17fd3595ca9045b4aa64a8d150bc33b3fec10546138d38249ceaba2",8)):
        raise SystemExit("live draw callback 0x22F87 no longer matches LE slot 0x111BF8 and adjustor thunk 0x138A0")
    loader_draw_secondary_fixup=next((f for f in image.fixups if f.source_link==0x111BC8),None)
    if (loader_draw_secondary_fixup is None or loader_draw_secondary_fixup.source_type!=0x07 or
            loader_draw_secondary_fixup.target_object!=1 or
            image.objects[0].base+loader_draw_secondary_fixup.target_offset!=0x13860 or
            code_bytes[0x13860-code_obj.base:0x13868-code_obj.base]!=
                _OrigDigest("d2126514ba96fa698d9f3db063e2e26febab7a689210229103ce7c613fef3dc5",8)):
        raise SystemExit("live draw callback 0x22F87 no longer matches secondary LE slot 0x111BC8 and adjustor thunk 0x13860")
    # Both observed this-subobjects are backed by complete, contiguous LE
    # tables. The runtime guard pairs each live vptr with the target at +0x10.
    options += ["--verified-le-vtable-call","0x22F87=0x111BE8:18",
                "--verified-le-vtable-call","0x22F87=0x111BB8:30"]
    # A constructed Building subobject can expose an interior vptr into the
    # contiguous 65-entry object-1 table at 0x111B2C.  The live draw probe
    # observed vptr 0x111B8C, so CALL [EDX+0x10] resolves through slot
    # 0x111B9C -> adjustor thunk 0x13810 -> Building callback 0x6E1B0.
    # Admit the complete LE-fixup-backed table, and lift the thunk entry so
    # this runtime path remains fail-closed at every subsequent boundary.
    building_draw_vtable=0x111B2C
    building_draw_count=65
    building_draw_sources=tuple(building_draw_vtable+4*i for i in range(building_draw_count))
    building_draw_fixups={f.source_link:f for f in image.fixups
        if f.source_link in building_draw_sources}
    building_draw_slot=0x111B9C
    building_draw_fixup=next((f for f in image.fixups if f.source_link==building_draw_slot),None)
    building_draw_thunk=code_bytes[0x13810-code_obj.base:0x13818-code_obj.base]
    if (set(building_draw_fixups)!=set(building_draw_sources) or
            any(f.source_type!=0x07 or f.target_object!=1 or f.target_flags&0x03
                for f in building_draw_fixups.values()) or
            building_draw_fixup is None or building_draw_fixup.target_object!=1 or
            image.objects[0].base+building_draw_fixup.target_offset!=0x13810 or
            image.link_to_linear(building_draw_vtable)!=0x002EBB2C or
            building_draw_thunk!=_OrigDigest("792444791f0868ef680c831d76fb2a710606747a5ac942f862e0c1a7f5e7b0ac",8)):
        raise SystemExit("Building draw vtable 0x111B2C no longer matches its 65 contiguous LE fixups or 0x13810 -> 0x6E1B0 thunk")
    # The extended creature replay can draw through an interior subobject
    # vptr at guest 0x002EBB5C (LE link 0x111B5C), not only the table base
    # 0x111B2C. At 0x22F87 the live CALL [EDX+0x10] therefore reads the LE
    # slot 0x111B6C. Its canonical fixup resolves to adjustor thunk 0x137D0,
    # which maps to the observed guest target 0x001FE7D0. Admit this bounded
    # interior view only after verifying it is wholly contained in the
    # already-validated 65-slot Building table and that the exact slot is the
    # expected object-1 fixup.
    building_draw_interior_vtable=0x111B5C
    building_draw_interior_count=53
    building_draw_interior_slot=building_draw_interior_vtable+0x10
    building_draw_interior_fixup=next((f for f in image.fixups
        if f.source_link==building_draw_interior_slot),None)
    building_draw_interior_target=(
        image.objects[0].base+building_draw_interior_fixup.target_offset
        if building_draw_interior_fixup is not None else None)
    if (building_draw_interior_vtable!=building_draw_vtable+12*4 or
            building_draw_interior_vtable+building_draw_interior_count*4!=
                building_draw_vtable+building_draw_count*4 or
            image.link_to_linear(building_draw_interior_vtable)!=0x002EBB5C or
            building_draw_interior_fixup is None or
            building_draw_interior_fixup.source_type!=0x07 or
            building_draw_interior_fixup.target_object!=1 or
            building_draw_interior_fixup.target_flags&0x03 or
            building_draw_interior_target!=0x137D0 or
            image.link_to_linear(building_draw_interior_target)!=0x001FE7D0 or
            code_bytes[0x137D0-code_obj.base:0x137D8-code_obj.base]!=
                _OrigDigest("7d71ead2ea5ea4374dd09ce537c08363f1ed055879e1be63317530ccbf74ad0c",8)):
        raise SystemExit("live draw frontier 0x22F87 does not match the verified interior Building vtable slot 0x111B6C -> 0x137D0 -> 0x001FE7D0")
    options += ["--verified-le-vtable-call","0x22F87=0x111B5C:53"]
    active_update_method_fixup=next((f for f in image.fixups if f.source_link==0x111BBC),None)
    if (active_update_method_fixup is None or active_update_method_fixup.source_type!=0x07 or
            active_update_method_fixup.target_object!=1 or
            image.objects[0].base+active_update_method_fixup.target_offset!=0x13880 or
            code_bytes[0x215AC-code_obj.base:0x215AF-code_obj.base]!=bytes.fromhex("FF 53 04") or
            code_bytes[0x13880-code_obj.base:0x13887-code_obj.base]!=
                bytes.fromhex("53 8B 58 FC 0F BF D2")):
        raise SystemExit("IFCLevel update callback 0x215AC no longer matches the observed LE vtable slot 0x111BBC -> 0x13880")
    options += ["--verified-le-vtable-call","0x215AC=0x111BB8:30",
                "--verified-le-vtable-call","0x215AC=0x111BE8:18"]
    # IFCPlanetside embeds an additional original mode object at this+0x2B8.
    # Its live vptr at the synchronized group-selection edge is the LE table
    # 0x111E70, whose 11 contiguous entries are all object-1 fixups. Admit the
    # table as one bounded contract after checking every source and target;
    # this is the callback table that the original object constructor wrote,
    # not a synthetic dispatch target.
    mode_callback_targets=(0x6EC20,0x6EC10,0x6EC00,0x6B490,0x6EBF0,0x6B1B0,
        0x6B9F0,0x6BCA0,0x6BDD0,0x6C190,0x6C180)
    mode_callback_sources=tuple(0x111E70+4*i for i in range(len(mode_callback_targets)))
    mode_callback_fixups={f.source_link:f for f in image.fixups
        if f.source_link in mode_callback_sources}
    if (set(mode_callback_fixups)!=set(mode_callback_sources) or
            any(mode_callback_fixups[src].source_type!=0x07 or
                mode_callback_fixups[src].target_object!=1 or
                image.objects[mode_callback_fixups[src].target_object-1].base+
                    mode_callback_fixups[src].target_offset!=target
                for src,target in zip(mode_callback_sources,mode_callback_targets)) or
            image.link_to_linear(0x111E70)!=0x002EBE70):
        raise SystemExit("IFCPlanetside embedded mode callback table 0x111E70 no longer matches its 11 contiguous object-1 LE fixups")
    options += ["--verified-le-vtable-call","0x215AC=0x111E70:11"]
    # IFCPlanetside::Draw shares the same original LE vtable contract at
    # 0x22F87 (CALL [EDX+0x10]).  This table was verified as 11 contiguous
    # object-1 code fixups; admit the whole table, not just the observed slot.
    options += ["--verified-le-vtable-call","0x22F87=0x111E70:11"]
    active_map_method_fixup=next((f for f in image.fixups if f.source_link==0x111BC0),None)
    live_map_subobject_fixup=next((f for f in image.fixups if f.source_link==0x111B64),None)
    if (active_map_method_fixup is None or active_map_method_fixup.source_type!=0x07 or
            active_map_method_fixup.target_object!=1 or
            image.objects[0].base+active_map_method_fixup.target_offset!=0x13870 or
            live_map_subobject_fixup is None or live_map_subobject_fixup.source_type!=0x07 or
            live_map_subobject_fixup.target_object!=1 or
            image.objects[0].base+live_map_subobject_fixup.target_offset!=0x137E0 or
            code_bytes[0x22FFE-code_obj.base:0x23001-code_obj.base]!=bytes.fromhex("FF 53 08") or
            code_bytes[0x137E0-code_obj.base:0x137E8-code_obj.base]!=
                _OrigDigest("b66080321d7bc3a894d0cb659bbaf6ab8f7a9cafa6cfd8f810e8e57681e0ff9c",8) or
            code_bytes[0x13870-code_obj.base:0x13877-code_obj.base]!=
                bytes.fromhex("53 8B 58 FC 0F BE D2")):
        raise SystemExit("IFCLevel draw map callback 0x22FFE no longer matches LE vtable slot 0x111BC0 -> 0x13870")
    # In the snapshot-driven map draw, EBX is the live interior subobject vptr
    # at 0x111B5C. CALL [EBX+8] therefore reads slot 0x111B64, whose canonical
    # object-1 fixup resolves to 0x137E0. The complete 65-slot allocation is
    # verified above; this bounded 53-slot address-point view starts at the
    # exact pointer held in EBX and ends at the same table boundary.
    options += ["--verified-le-vtable-call","0x22FFE=0x111B5C:53",
                "--verified-le-vtable-call","0x22FFE=0x111B2C:65",
                "--verified-le-vtable-call","0x22FFE=0x111BB8:30",
                "--verified-le-vtable-call","0x22FFE=0x111BE8:18"]
    active_draw_method_fixup=next((f for f in image.fixups if f.source_link==0x111BD0),None)
    if (active_draw_method_fixup is None or active_draw_method_fixup.source_type!=0x07 or
            active_draw_method_fixup.target_object!=1 or
            image.objects[0].base+active_draw_method_fixup.target_offset!=0x6B9F0 or
            code_bytes[0x6BAB4-code_obj.base:0x6BAB7-code_obj.base]!=
                bytes.fromhex("8B 50 06") or
            code_bytes[0x6BAB7-code_obj.base:0x6BABA-code_obj.base]!=
                bytes.fromhex("FF 52 18")):
        raise SystemExit("active IFCLevel draw callback 0x6BAB7 no longer matches LE slot 0x111BD0 -> 0x6B9F0")
    options += ["--verified-le-vtable-call","0x6BAB7=0x111BB8:30"]
    ralph_projection_fixup=next((f for f in image.fixups if f.source_link==0x112064),None)
    if (ralph_projection_fixup is None or ralph_projection_fixup.source_type!=0x07 or
            ralph_projection_fixup.target_object!=1 or
            image.objects[0].base+ralph_projection_fixup.target_offset!=0x6A2E0 or
            code_bytes[0x6BA17-code_obj.base:0x6BA1F-code_obj.base]!=
                _OrigDigest("fdd5780bc040d55a27046c4a25de3068c3c94fb731a87e4ccfecf0d14a4cf312",8) or
            code_bytes[0x6BA1F-code_obj.base:0x6BA22-code_obj.base]!=
                bytes.fromhex("FF 52 04")):
        raise SystemExit("Ralph drawing projection call 0x6BA1F no longer matches PlSpec vtable slot 0x112064 -> 0x6A2E0")
    options += ["--verified-le-vtable-call","0x6BA1F=0x112060:52"]
    if (code_bytes[0x1E8C6-code_obj.base:0x1E8C9-code_obj.base]!=bytes.fromhex("FF 52 04") or
            code_bytes[0x1E8BF-code_obj.base:0x1E8C2-code_obj.base]!=bytes.fromhex("8B 55 23")):
        raise SystemExit("group selection helper 0x1E8C6 no longer calls the original PlSpec vtable slot +4")
    options += ["--verified-le-vtable-call","0x1E8C6=0x112060:52"]
    ralph_action_fixup=next((f for f in image.fixups if f.source_link==0x112078),None)
    ralph_nested_fixup=next((f for f in image.fixups if f.source_link==0x112084),None)
    if (ralph_action_fixup is None or ralph_action_fixup.source_type!=0x07 or
            ralph_action_fixup.target_object!=1 or
            image.objects[0].base+ralph_action_fixup.target_offset!=0x43BB0 or
            ralph_nested_fixup is None or ralph_nested_fixup.source_type!=0x07 or
            ralph_nested_fixup.target_object!=1 or
            image.objects[0].base+ralph_nested_fixup.target_offset!=0x43BD0 or
            code_bytes[0x6D087-code_obj.base:0x6D08F-code_obj.base]!=
                _OrigDigest("2a199409c7c2d33dca9fa8128bc20c221bee20915bc5027c3d5bf5a2aecd7291",8) or
            code_bytes[0x43BBC-code_obj.base:0x43BC5-code_obj.base]!=
                _OrigDigest("da57b16794e3c6f4206ad460bf52c15e9434716a811858c17113657340680ead",9) or
            code_bytes[0x43C66-code_obj.base:0x43C70-code_obj.base]!=
                _OrigDigest("6254d3b60bd49e57177ca9a53d19fbbabcdd39f13f56ef7c592b444e8e9edfee",10)):
        raise SystemExit("PlSpec action callback chain no longer matches LE slots 0x112078/0x112084 -> 0x43BB0/0x43BD0")
    options += ["--verified-le-vtable-call","0x6D08C=0x112060:52",
                "--verified-le-vtable-call","0x43BC2=0x112060:52",
                "--verified-le-vtable-call","0x43C6D=0x112060:52"]
    callback_call=code_bytes[0xB67BD-code_obj.base:0xB67BD-code_obj.base+4]
    callback_entry=code_bytes[0xBA9FE-code_obj.base:0xBA9FE-code_obj.base+5]
    if callback_call!=bytes.fromhex("FF 54 24 44") or callback_entry!=bytes.fromhex("53 89 C3 89 D0"):
        raise SystemExit("original __prtf callback frontier or file_putc_ entry changed")
    # Only the live-observed callback is admitted; all other __prtf emitters
    # stay fail-closed. 0x2A59FE maps to 0xBA9FE under the verified code map.
    options += ["--verified-indirect-target","0xB67BD=0xBA9FE"]
    # The live next-interface update called through [ECX+0x3c] at 0x472D0.
    # Ghidra's xref to 0x47220 is the LE vtable slot 0x111D40; require the
    # exact fixup and code bytes before allowing this single dynamic edge.
    copy_method_fixups={f.source_link:f for f in image.fixups if f.source_link==0x111D40}
    copy_method_code=code_bytes[0x47220-code_obj.base:0x47220-code_obj.base+9]
    copy_method_guest=image.link_to_linear(0x47220)
    copy_method_second_fixup={f.source_link:f for f in image.fixups if f.source_link==0x111D64}
    copy_method_second_code=code_bytes[0x46C40-code_obj.base:0x46C40-code_obj.base+1]
    if len(copy_method_fixups)!=1 or \
            (copy_method_fixups[0x111D40].target_object,copy_method_fixups[0x111D40].target_offset)!=(1,0x37220) or \
            copy_method_code!=_OrigDigest("da9d62ef3d712f414736e41f0840e54fc0957bfcc0fbdf9fd6d958e595a70f4d",9) or copy_method_guest!=0x00232220 or \
            len(copy_method_second_fixup)!=1 or \
            (copy_method_second_fixup[0x111D64].target_object,copy_method_second_fixup[0x111D64].target_offset)!=(1,0x36C40) or \
            copy_method_second_code!=b"\x53" or image.link_to_linear(0x46C40)!=0x00231C40:
        raise SystemExit("live interface callback methods are not backed by their original LE vtable fixups/code")
    # The next-interface Update reached FUN_000472A0's original callback
    # through its +0x3c method slot. Admit only the live-observed 0x47220
    # entry, whose source pointer is backed by the LE fixup at 0x111D40.
    options += ["--verified-indirect-target","0x472D0=0x47220"]
    # FUN_00047220 loads the same vtable base and, on its guarded branch,
    # dispatches [vtable+0x60]. The slot at 0x111D64 is independently backed
    # by a fixup to 0x46C40; admit that one branch target only.
    options += ["--verified-indirect-target","0x4725D=0x46C40"]
    copy_method_2_fixups={f.source_link:f for f in image.fixups
        if f.source_link in (0x111EE0,0x111F04)}
    copy_method_2_guest=(image.link_to_linear(0x57000),image.link_to_linear(0x56D40))
    if set(copy_method_2_fixups)!={0x111EE0,0x111F04} or \
            (copy_method_2_fixups[0x111EE0].target_object,copy_method_2_fixups[0x111EE0].target_offset)!=(1,0x47000) or \
            (copy_method_2_fixups[0x111F04].target_object,copy_method_2_fixups[0x111F04].target_offset)!=(1,0x46D40) or \
            copy_method_2_guest!=(0x00242000,0x00241D40) or \
            code_bytes[0x570B0-code_obj.base:0x570B0-code_obj.base+3]!=bytes.fromhex("FF 51 3C") or \
            code_bytes[0x5703D-code_obj.base:0x5703D-code_obj.base+3]!=bytes.fromhex("FF 56 60") or \
            code_bytes[0x57000-code_obj.base:0x57000-code_obj.base+1]!=b"\x53" or \
            code_bytes[0x56D40-code_obj.base:0x56D40-code_obj.base+1]!=b"\x52":
        raise SystemExit("second live copy adapter slots do not match the canonical LE vtable fixups")
    options += ["--verified-indirect-target","0x570B0=0x57000",
                "--verified-indirect-target","0x5703D=0x56D40"]
    copy_method_3_fixups={f.source_link:f for f in image.fixups
        if f.source_link in (0x11209C,0x1120C0)}
    if set(copy_method_3_fixups)!={0x11209C,0x1120C0} or \
            (copy_method_3_fixups[0x11209C].target_object,copy_method_3_fixups[0x11209C].target_offset)!=(1,0x340A0) or \
            (copy_method_3_fixups[0x1120C0].target_object,copy_method_3_fixups[0x1120C0].target_offset)!=(1,0x33980) or \
            image.link_to_linear(0x440A0)!=0x0022F0A0 or image.link_to_linear(0x43980)!=0x0022E980 or \
            code_bytes[0x44150-code_obj.base:0x44150-code_obj.base+3]!=bytes.fromhex("FF 51 3C") or \
            code_bytes[0x440DD-code_obj.base:0x440DD-code_obj.base+3]!=bytes.fromhex("FF 56 60") or \
            code_bytes[0x440A0-code_obj.base:0x440A0-code_obj.base+1]!=b"\x53" or \
            code_bytes[0x43980-code_obj.base:0x43980-code_obj.base+1]!=b"\x53":
        raise SystemExit("third live record adapter methods do not match the canonical LE vtable fixups")
    options += ["--verified-indirect-target","0x44150=0x440A0",
                "--verified-indirect-target","0x440DD=0x43980"]
    copy_method_4_fixups={f.source_link:f for f in image.fixups
        if f.source_link in (0x111E38,0x111E5C)}
    if set(copy_method_4_fixups)!={0x111E38,0x111E5C} or \
            (copy_method_4_fixups[0x111E38].target_object,copy_method_4_fixups[0x111E38].target_offset)!=(1,0x29D40) or \
            (copy_method_4_fixups[0x111E5C].target_object,copy_method_4_fixups[0x111E5C].target_offset)!=(1,0x29D20) or \
            image.link_to_linear(0x39D40)!=0x00224D40 or image.link_to_linear(0x39D20)!=0x00224D20 or \
            code_bytes[0x39DF0-code_obj.base:0x39DF0-code_obj.base+3]!=bytes.fromhex("FF 51 3C") or \
            code_bytes[0x39D7D-code_obj.base:0x39D7D-code_obj.base+3]!=bytes.fromhex("FF 56 60") or \
            code_bytes[0x39D40-code_obj.base:0x39D40-code_obj.base+1]!=b"\x53" or \
            code_bytes[0x39D20-code_obj.base:0x39D20-code_obj.base+1]!=b"\x52":
        raise SystemExit("fourth live record adapter methods do not match the canonical LE vtable fixups")
    options += ["--verified-indirect-target","0x39DF0=0x39D40",
                "--verified-indirect-target","0x39D7D=0x39D20"]
    ctor_array_targets=(0x2C3D0,0x834A0,0x2C520,0x2C560,0x34F50,0x957B0,0x69C80,
                        0x957C0,0x957E0,0x957D0,0x95830,0x95880,0x95890,0x958E0)
    for target in ctor_array_targets:
        options += ["--verified-indirect-target",f"0xA9F3B={hex(target)}"]
    # Exact six-byte Watcom __InitRtns entries at LE 0x1126B8..0x11272A.
    # These target values come from the original LE table and the dispatcher
    # callsite at 0xC8759; keep the call indirect and fail closed otherwise.
    init_rtn_targets=(0x1C440,0x830F0,0xBAAC2,0xBBE29,0xA38DC,0xBC0E3,
        0xBC19F,0xAC3B4,0xC87B6,0xD1FBC,0xBC1F6,0xBC65D,0xC3584,
        0xC3882,0xD21EE,0xD5DB5,0xDFDC1,0xDCED5,0xE165E)
    for target in init_rtn_targets:
        options += ["--verified-indirect-target",f"0xC8759={hex(target)}"]
    # The active PlSpec dispatch at 0x4459E uses the original Object-3
    # vtable base 0x112060 and slot +0x94 (entry 37). Verify the entire
    # contiguous 52-entry LE fixup table while allowing only the target of
    # this exact slot; the lifter also guards the live EDX vtable base.
    options += ["--verified-le-vtable-call","0x4459E=0x112060:52"]
    # FUN_0006B0C0 is shared by embedded mode receivers. Its group-selection
    # receiver uses the separate 11-entry LE table at 0x111E70 (slot +0x0C
    # -> 0x6B490; +0x14 -> 0x6B1B0), while other live paths use 0x111BE8 or
    # 0x111BB8. Admit only complete tables whose slots are canonical LE
    # fixups, at these exact callsites.
    for _site in (0x6B0DE,0x6B0F1):
        options += ["--verified-le-vtable-call",f"{hex(_site)}=0x111BE8:18",
                    "--verified-le-vtable-call",f"{hex(_site)}=0x111BB8:8",
                    "--verified-le-vtable-call",f"{hex(_site)}=0x111E70:11"]
    # Selecting a completed Building without an active PlSpec reaches the
    # original receiver vptr at 0x111B8C. At 0x6B0DE the instruction is
    # CALL dword ptr [EBX+0x0C], so slot 3 (0x111B98) is the LE-fixed
    # Building selection callback 0x6B490. Validate the complete eight-slot
    # table before admitting this one exact runtime callsite.
    building_select_table=tuple(
        next((f for f in image.fixups if f.source_link==0x111B8C+4*i),None)
        for i in range(8))
    building_select_slot=building_select_table[3]
    if (code_bytes[0x6B0DE-code_obj.base:0x6B0DE-code_obj.base+3]!=bytes.fromhex("FF 53 0C") or
            any(f is None or f.source_type!=0x07 or f.target_object!=1 or f.target_flags&0x03
                for f in building_select_table) or
            building_select_slot.target_offset+image.objects[0].base!=0x6B490):
        raise SystemExit("completed-building selection call at 0x6B0DE lacks the canonical 0x111B8C LE vtable/fixup contract")
    options += ["--verified-le-vtable-call","0x6B0DE=0x111B8C:8"]
    # The same completed-building receiver immediately dispatches its slot
    # +0x14 at 0x6B0F1 after the selection callback. The canonical slot
    # 0x111BA0 is an Object-3 fixup to Object-1 0x6B1B0; retain the same
    # complete eight-entry vtable contract for this second original call.
    options += ["--verified-le-vtable-call","0x6B0F1=0x111B8C:8"]
    # Backspace reaches a different mode callback in IFCPlanetside::Update:
    # CALL [EDX+0x14] at 0x223D1. The active object-3 vptr is the address
    # point 0x111BB8; slot 5 (0x111BCC) has an Object-1 SRC_OFFSET32 fixup to
    # the adjustor thunk 0x13850, which tail-jumps to 0x6C430. Keep the
    # runtime dispatch tied to that complete 8-slot LE table and lift both
    # authentic code entries so the thunk can reach its body.
    mode_key_table_fixups=[next((f for f in image.fixups
        if f.source_link==0x111BB8+4*i),None) for i in range(8)]
    mode_key_slot=mode_key_table_fixups[5]
    mode_key_call=code_bytes[0x223D1-code_obj.base:0x223D1-code_obj.base+3]
    mode_key_thunk=code_bytes[0x13850-code_obj.base:0x13850-code_obj.base+8]
    mode_key_slot_target=(image.objects[0].base+mode_key_slot.target_offset
        if mode_key_slot is not None and mode_key_slot.target_object==1 else None)
    if (mode_key_call!=bytes.fromhex("FF 52 14") or any(f is None for f in mode_key_table_fixups) or
            any(f.source_type!=0x07 or f.target_object!=1 or f.target_flags&0x03
                for f in mode_key_table_fixups if f is not None) or
            mode_key_slot.source_type!=0x07 or mode_key_slot.target_object!=1 or
            mode_key_slot.target_flags&0x03 or mode_key_slot_target!=0x13850 or
            mode_key_thunk!=_OrigDigest("a3261ddc77a5e0eb81c963893107dfaee8c01e033b38c42259e99a58bf51564d",8) or
            image.object_containing(0x6C430) is None):
        raise SystemExit("Backspace mode callback at 0x223D1 is not backed by the canonical 0x111BB8 LE vtable/thunk")
    # A completed-building selection can keep the base mode subobject's
    # address point (0x111BB8) live at this same virtual callsite. Its slot
    # +0x14 is independently backed by the LE fixup at 0x111BCC -> 0x13850.
    options += ["--verified-le-vtable-call","0x223D1=0x111BB8:7",
                "--verified-le-vtable-call","0x223D1=0x111BE8:18",
                "--partial-root","0x13850","--partial-root","0x6C430"]
    # FUN_00044570's active PlSpec predicates at 0x446F1 and 0x44708 use
    # slots +0xB0 and +0x84 on the same original 52-entry PlSpec vtable.
    options += ["--verified-le-vtable-call","0x446F1=0x112060:52",
                "--verified-le-vtable-call","0x44708=0x112060:52"]
    # FUN_0003F1C0's active PlSpec path calls slot +0x84 at 0x3F2DF.
    # The live receiver vptr is 0x112060 and the canonical LE slot 0x1120E4
    # is part of the same already-validated 52-entry Object-1 vtable. Keep
    # this newly reached callsite fail-closed against that exact table.
    options += ["--verified-le-vtable-call","0x3F2DF=0x112060:52"]
    # FUN_0003F9A0 first queries slot +0xAC at 0x3FA05, may query it again
    # at 0x3FA1B, then conditionally queries +0xB0 at 0x3FA2A. Each exact
    # site is guarded against the same complete PlSpec LE vtable.
    plspec_transition_first=code_bytes[0x3FA05-code_obj.base:0x3FA05-code_obj.base+6]
    plspec_transition_first_fixup=next((f for f in image.fixups if f.source_link==0x11210C),None)
    if (plspec_transition_first!=bytes.fromhex("FF 91 AC 00 00 00") or
            plspec_transition_first_fixup is None or plspec_transition_first_fixup.source_type!=0x07 or
            plspec_transition_first_fixup.target_object!=1 or
            image.objects[0].base+plspec_transition_first_fixup.target_offset!=0x8A570):
        raise SystemExit("FUN_0003F9A0 initial PlSpec transition call no longer matches vtable slot 43's LE fixup")
    options += ["--verified-le-vtable-call","0x3FA05=0x112060:52",
                "--verified-le-vtable-call","0x3FA1B=0x112060:52",
                "--verified-le-vtable-call","0x3FA2A=0x112060:52"]
    # FUN_00058330's active PlSpec branch calls the state handler through
    # [EDX+0x2C], slot 11 of the same 52-entry vtable (0x11208C -> 0x3F030).
    options += ["--verified-le-vtable-call","0x58DAF=0x112060:52"]
    # Additional branches in the same FUN_00044570 PlSpec update body query
    # the status and base methods through slots 1 and 0. Their LE slots are
    # 0x112064 -> 0x6A2E0 and 0x112060 -> 0x6A2F0.
    options += ["--verified-le-vtable-call","0x44F39=0x112060:52",
                "--verified-le-vtable-call","0x450BA=0x112060:52",
                "--verified-indirect-target","0x451B2=0x6A2F0"]
    # FUN_0005E450 is called by process_packets and may update a live Thing
    # through the virtual slot at 0x10243 (CALL [EDI+0x78]). The runtime vptr
    # at this frontier maps by the verified Object-3 delta to LE 0x1123BC.
    # Admit the complete 48-entry contiguous SRC_OFFSET32/Object-1 table only
    # after validating the original call bytes and every slot fixup. Slot 30
    # (source 0x112434) is the observed target 0x8A580.
    thing_vtable_base=0x1123BC
    thing_vtable_fixups={f.source_link:f for f in image.fixups
        if thing_vtable_base<=f.source_link<thing_vtable_base+48*4}
    thing_vtable_call=code_bytes[0x10243-code_obj.base:0x10246-code_obj.base]
    thing_slot30=thing_vtable_fixups.get(thing_vtable_base+30*4)
    thing_slot4=thing_vtable_fixups.get(thing_vtable_base+4*4)
    thing_slot13=thing_vtable_fixups.get(thing_vtable_base+13*4)
    thing_slot29=thing_vtable_fixups.get(thing_vtable_base+29*4)
    thing_slot28=thing_vtable_fixups.get(thing_vtable_base+28*4)
    thing_slot34=thing_vtable_fixups.get(thing_vtable_base+34*4)
    thing_slot41=thing_vtable_fixups.get(thing_vtable_base+41*4)
    thing_slot46=thing_vtable_fixups.get(thing_vtable_base+46*4)
    thing_slot43=thing_vtable_fixups.get(thing_vtable_base+43*4)
    if (code_bytes[0x58681-code_obj.base:0x58687-code_obj.base]!=bytes.fromhex("FF 91 A4 00 00 00") or
            code_bytes[0x587EE-code_obj.base:0x587F1-code_obj.base]!=bytes.fromhex("FF 51 34") or
            code_bytes[0x58948-code_obj.base:0x5894B-code_obj.base]!=bytes.fromhex("FF 52 10") or
            code_bytes[0x5895F-code_obj.base:0x58965-code_obj.base]!=bytes.fromhex("FF 91 A4 00 00 00") or
            code_bytes[0x58BBD-code_obj.base:0x58BC3-code_obj.base]!=bytes.fromhex("FF 93 88 00 00 00") or
            code_bytes[0x58BD4-code_obj.base:0x58BD7-code_obj.base]!=bytes.fromhex("FF 52 04") or
            code_bytes[0x58BE0-code_obj.base:0x58BE3-code_obj.base]!=bytes.fromhex("FF 52 70")):
        raise SystemExit("FUN_00058330 virtual-call bytes differ from the four audited Thing-table edges")
    thing_vtable_slots_ok=(
        len(thing_vtable_fixups)==48 and
        all(src in thing_vtable_fixups and
            thing_vtable_fixups[src].source_type==0x07 and
            thing_vtable_fixups[src].target_object==1
            for src in range(thing_vtable_base,thing_vtable_base+48*4,4)) and
        thing_slot30 is not None and
        image.objects[thing_slot30.target_object-1].base+thing_slot30.target_offset==0x8A580 and
        thing_slot4 is not None and
        image.objects[thing_slot4.target_object-1].base+thing_slot4.target_offset==0x95CA0 and
        thing_slot13 is not None and
        image.objects[thing_slot13.target_object-1].base+thing_slot13.target_offset==0x11260 and
        thing_slot29 is not None and
        image.objects[thing_slot29.target_object-1].base+thing_slot29.target_offset==0x95C90 and
        thing_slot28 is not None and
        image.objects[thing_slot28.target_object-1].base+thing_slot28.target_offset==0x95C80 and
        thing_slot34 is not None and
        image.objects[thing_slot34.target_object-1].base+thing_slot34.target_offset==0x8A720 and
        thing_slot41 is not None and
        image.objects[thing_slot41.target_object-1].base+thing_slot41.target_offset==0x59CF0 and
        thing_slot46 is not None and
        image.objects[thing_slot46.target_object-1].base+thing_slot46.target_offset==0x11380)
    plspec_slot4=next((f for f in image.fixups if f.source_link==0x112070),None)
    creature_slot4=next((f for f in image.fixups if f.source_link==0x111D14),None)
    thing_slot45=next((f for f in image.fixups if f.source_link==0x112470),None)
    creature_slot45=next((f for f in image.fixups if f.source_link==0x111DB8),None)
    plspec_slot45=next((f for f in image.fixups if f.source_link==0x112114),None)
    plspec_tail_fixups={f.source_link:f for f in image.fixups
        if f.source_link in {0x1120E8,0x112064,0x1120D0}}
    expected_plspec_tail_fixups={0x1120E8:0x8A720,0x112064:0x6A2E0,0x1120D0:0x6A2A0}
    if any(src not in plspec_tail_fixups or plspec_tail_fixups[src].source_type!=0x07 or
           plspec_tail_fixups[src].target_object!=1 or
           image.objects[plspec_tail_fixups[src].target_object-1].base+
               plspec_tail_fixups[src].target_offset!=target
           for src,target in expected_plspec_tail_fixups.items()):
        raise SystemExit("FUN_00058330 PlSpec tail slots do not match their canonical LE fixups")
    creature_tail_fixups={f.source_link:f for f in image.fixups
        if f.source_link in {0x111D8C,0x111D08,0x111D74}}
    expected_creature_tail_fixups={0x111D8C:0x47BF0,0x111D08:0x6A2E0,0x111D74:0x6A2A0}
    if any(src not in creature_tail_fixups or creature_tail_fixups[src].source_type!=0x07 or
           creature_tail_fixups[src].target_object!=1 or
           image.objects[creature_tail_fixups[src].target_object-1].base+
               creature_tail_fixups[src].target_offset!=target
           for src,target in expected_creature_tail_fixups.items()):
        raise SystemExit("FUN_00058330 Creature vtable tail slots do not match their canonical LE fixups")
    shared_creature_vtable_call=code_bytes[0x5A70D-code_obj.base:0x5A710-code_obj.base]
    if (shared_creature_vtable_call!=bytes.fromhex("FF 52 10") or
            code_bytes[0x5A9A0-code_obj.base:0x5A9A6-code_obj.base]!=bytes.fromhex("FF 92 B4 00 00 00") or
            code_bytes[0x5A9B2-code_obj.base:0x5A9B5-code_obj.base]!=bytes.fromhex("FF 52 10") or
            code_bytes[0x5AB28-code_obj.base:0x5AB2E-code_obj.base]!=bytes.fromhex("FF 92 B4 00 00 00") or
            plspec_slot4 is None or plspec_slot4.source_type!=0x07 or
            plspec_slot4.target_object!=1 or
            image.objects[plspec_slot4.target_object-1].base+plspec_slot4.target_offset!=0x6A240 or
            creature_slot4 is None or creature_slot4.source_type!=0x07 or
            creature_slot4.target_object!=1 or
            image.objects[creature_slot4.target_object-1].base+creature_slot4.target_offset!=0x6A240 or
            creature_slot45 is None or creature_slot45.source_type!=0x07 or
            creature_slot45.target_object!=1 or
            image.objects[creature_slot45.target_object-1].base+creature_slot45.target_offset!=0x59D80 or
            plspec_slot45 is None or plspec_slot45.source_type!=0x07 or
            plspec_slot45.target_object!=1 or
            image.objects[plspec_slot45.target_object-1].base+plspec_slot45.target_offset!=0x59D80 or
            thing_slot45 is None or thing_slot45.source_type!=0x07 or thing_slot45.target_object!=1):
        raise SystemExit("FUN_00059F60 shared virtual call or Thing/Creature/PlSpec slot-45 LE fixup changed")
    if (thing_vtable_call!=bytes.fromhex("FF 57 78") or
            image.link_to_linear(thing_vtable_base)!=0x002EC3BC or
            not thing_vtable_slots_ok or
            code_bytes[0x8A580-code_obj.base:0x8A586-code_obj.base]!=
                bytes.fromhex("56 57 55 83 EC 10")):
        raise SystemExit("ProcessSounds/Thing callback no longer matches the live 0x1123BC vtable and its 48 canonical LE fixups")
    thing_slot43_target=(image.objects[0].base+thing_slot43.target_offset
                         if thing_slot43 is not None else None)
    creature_state_call_1=code_bytes[0x11905-code_obj.base:0x1190B-code_obj.base]
    creature_state_call_2=code_bytes[0x11948-code_obj.base:0x1194E-code_obj.base]
    if (creature_state_call_1!=bytes.fromhex("FF 92 AC 00 00 00") or
            creature_state_call_2!=bytes.fromhex("FF 92 AC 00 00 00") or
            thing_slot43 is None or thing_slot43.source_type!=0x07 or
            thing_slot43.target_object!=1 or thing_slot43.target_flags&0x03 or
            thing_slot43_target!=0x8A570):
        raise SystemExit("entity update slot-43 calls no longer match the original Thing vtable fixup 0x112468 -> 0x8A570")
    # The four bounded state switches are all in the same recovered LE body.
    # Each bound is proven by the original unsigned CMP immediately before
    # the table dispatch, and every selected slot is an Object-1 code fixup.
    jump_table_contracts={
        0x1201A:(0x11890,4,(0x11C7E,0x11E53,0x11EC4,0x11F93)),
        0x1239A:(0x118A0,5,(0x12022,0x12123,0x12149,0x121BB,0x1224A)),
        0x12A57:(0x118B4,6,(0x11943,0x11AA1,0x12939,0x11B96,0x1296B,0x12A29)),
        0x131BA:(0x118CC,5,(0x13024,0x130A8,0x130C6,0x130DF,0x1318F)),
    }
    for site,(table,count,targets) in jump_table_contracts.items():
        observed=code_bytes[site-code_obj.base:site-code_obj.base+8]
        encoding=bytes.fromhex("2E FF 24 85")+struct.pack("<I",image.link_to_linear(table))
        bound_site,bound_bytes={0x1201A:(0x1200D,bytes.fromhex("3C 03")),
                                0x1239A:(0x1238D,bytes.fromhex("3C 04")),
                                0x12A57:(0x12A4A,bytes.fromhex("3C 05")),
                                0x131BA:(0x131AD,bytes.fromhex("3C 04"))}[site]
        observed_bound=code_bytes[bound_site-code_obj.base:bound_site-code_obj.base+2]
        slots=[next((f for f in image.fixups if f.source_link==table+4*i),None)
               for i in range(count)]
        decoded_targets=[image.objects[0].base+f.target_offset
                         if f is not None and f.target_object==1 else None for f in slots]
        if (observed!=encoding or observed_bound!=bound_bytes or len(targets)!=count or
                any(f is None or f.source_type!=0x07 or f.target_object!=1 or f.target_flags&0x03
                    for f in slots) or tuple(decoded_targets)!=targets):
            raise SystemExit(f"native entity-state switch at 0x{site:05X} contract mismatch: bytes={observed.hex()} bound@{bound_site:05X}={observed_bound.hex()} targets={decoded_targets!r}")
    # The other three branch bodies in FUN_000101D0 invoke the same Thing
    # interface at slots 32, 32, 32, and 24 respectively. Their callsites are
    # part of the same LE-backed method body and use the same loaded vptr; keep
    # the dynamic checks at every site while admitting only this verified
    # 48-entry table.
    options += ["--verified-le-vtable-call",f"0x10243=0x1123BC:48",
                "--verified-le-vtable-call","0x102EE=0x1123BC:48",
                "--verified-le-vtable-call","0x10348=0x1123BC:48",
                "--verified-le-vtable-call","0x103B1=0x1123BC:48",
                "--verified-le-vtable-call","0x103DC=0x1123BC:48",
                "--verified-le-vtable-call","0x134DA=0x1123BC:48",
                # Batch all four original virtual edges in FUN_00058330 for
                # the same canonical Thing table; each selected slot below
                # is covered by the table's complete LE fixup run.
                "--verified-le-vtable-call","0x58681=0x1123BC:48",
                "--verified-le-vtable-call","0x587EE=0x1123BC:48",
                "--verified-le-vtable-call","0x58948=0x1123BC:48",
                "--verified-le-vtable-call","0x5895F=0x1123BC:48",
                # FUN_00059CF0 is the next method reached above. Its Thing
                # implementation uses slots 46, 1, 29, and 4, all fixed in
                # the same complete 0x1123BC table.
                "--verified-le-vtable-call","0x59D42=0x1123BC:48",
                "--verified-le-vtable-call","0x59D9F=0x1123BC:48",
                "--verified-le-vtable-call","0x59DAB=0x1123BC:48",
                "--verified-le-vtable-call","0x59E30=0x1123BC:48",
                # Complete the indirect tail in the same FUN_00058330 body.
                "--verified-le-vtable-call","0x58BBD=0x1123BC:48",
                "--verified-le-vtable-call","0x58BD4=0x1123BC:48",
                "--verified-le-vtable-call","0x58BE0=0x1123BC:48",
                "--verified-le-vtable-call","0x58BBD=0x1121E4:64",
                "--verified-le-vtable-call","0x58BD4=0x1121E4:64",
                "--verified-le-vtable-call","0x58BE0=0x1121E4:64",
                "--verified-le-vtable-call","0x58BBD=0x111D04:60",
                "--verified-le-vtable-call","0x58BD4=0x111D04:60",
                "--verified-le-vtable-call","0x58BE0=0x111D04:60",
                "--verified-le-vtable-call","0x58BBD=0x112060:52",
                "--verified-le-vtable-call","0x58BD4=0x112060:52",
                "--verified-le-vtable-call","0x58BE0=0x112060:52",
                "--verified-le-vtable-call","0x5A70D=0x1123BC:48",
                "--verified-le-vtable-call","0x5A70D=0x112060:52",
                "--verified-le-vtable-call","0x5A70D=0x111D04:60",
                "--verified-le-vtable-call","0x5A9A0=0x1123BC:48",
                "--verified-le-vtable-call","0x5A9A0=0x111D04:60",
                "--verified-le-vtable-call","0x5A9A0=0x112060:52",
                "--verified-le-vtable-call","0x5A9B2=0x1123BC:48",
                "--verified-le-vtable-call","0x5A9B2=0x112060:52",
                "--verified-le-vtable-call","0x5A9B2=0x111D04:60",
                "--verified-le-vtable-call","0x5AB28=0x1123BC:48",
                "--verified-le-vtable-call","0x5AB28=0x111D04:60",
                "--verified-le-vtable-call","0x5AB28=0x112060:52",
                # Remaining indirect calls in the same canonical
                # FUN_00059F60 CFG. The three possible entity bases are the
                # already validated Creature, PlSpec and Thing LE vtables;
                # the lifter checks each entire fixup run and the live vptr at
                # each exact callsite before dispatch.
                "--verified-le-vtable-call","0x5A048=0x111D04:60",
                "--verified-le-vtable-call","0x5A048=0x112060:52",
                "--verified-le-vtable-call","0x5A048=0x1123BC:48",
                "--verified-le-vtable-call","0x5A0E1=0x111D04:60",
                "--verified-le-vtable-call","0x5A0E1=0x112060:52",
                "--verified-le-vtable-call","0x5A0E1=0x1123BC:48",
                "--verified-le-vtable-call","0x5A15E=0x111D04:60",
                "--verified-le-vtable-call","0x5A15E=0x112060:52",
                "--verified-le-vtable-call","0x5A15E=0x1123BC:48",
                "--verified-le-vtable-call","0x5A7D3=0x111D04:60",
                "--verified-le-vtable-call","0x5A7D3=0x112060:52",
                "--verified-le-vtable-call","0x5A7D3=0x1123BC:48",
                "--verified-le-vtable-call","0x5A7F5=0x111D04:60",
                "--verified-le-vtable-call","0x5A7F5=0x112060:52",
                "--verified-le-vtable-call","0x5A7F5=0x1123BC:48",
                "--verified-le-vtable-call","0x5A836=0x111D04:60",
                "--verified-le-vtable-call","0x5A836=0x112060:52",
                "--verified-le-vtable-call","0x5A836=0x1123BC:48",
                "--verified-le-vtable-call","0x5A858=0x111D04:60",
                "--verified-le-vtable-call","0x5A858=0x112060:52",
                "--verified-le-vtable-call","0x5A858=0x1123BC:48",
                "--verified-le-vtable-call","0x5A8D2=0x111D04:60",
                "--verified-le-vtable-call","0x5A8D2=0x112060:52",
                "--verified-le-vtable-call","0x5A8D2=0x1123BC:48",
                "--verified-le-vtable-call","0x5A951=0x111D04:60",
                "--verified-le-vtable-call","0x5A951=0x112060:52",
                "--verified-le-vtable-call","0x5A951=0x1123BC:48",
                # The next live frontier is the Thing slot-43 callback in
                # the same original entity-update method. Both sites below
                # encode CALL [EDX+0xAC]; LE vtable 0x112468 is an internal
                # object-1 fixup to 0x8A570. Keep the runtime target check
                # active while admitting only that complete original table.
                # Four adjacent state switches in this method share the
                # original LE jump-table run at 0x11890..0x118DC. Bounds
                # come from the preceding unsigned comparisons (0..3,
                # 0..4, 0..5, 0..4 respectively), not from table proximity.
                "--indexed-code-jump-table","0x1201A=0x11890:4:eax",
                "--indexed-code-jump-table","0x1239A=0x118A0:5:eax",
                "--indexed-code-jump-table","0x12A57=0x118B4:6:eax",
                "--indexed-code-jump-table","0x131BA=0x118CC:5:eax"]
    # Entity-list traversal at 0x80A3A queries the live PlSpec's eligibility
    # method through [ECX+0x10]. The LE vtable fixup at 0x112070 is slot 4 ->
    # original object-1 code 0x6A240; retain the exact runtime base/target guard.
    # The post-activation keyboard centering input brings Ralph into the map
    # viewport and makes DrawMapSprites reach its object-position callback at
    # 0x7925B. Its [EDI+0x24] target is slot 9 of the same complete LE table;
    # slot 0x111EC8 is an object-1 fixup to link VA 0x6ED40.
    options += ["--verified-le-vtable-call","0x7925B=0x111EA4:29"]
    # The same edge-centered DrawMapSprites pass reaches a second virtual
    # method at 0x793EC through the LE-backed table at 0x1121E4. Slot 9
    # (0x112208) is a fixup to object-1 code at link 0x85240.
    # 0x793EC encodes CALL [EBP+0x24]. The vtable lifter's verifier only
    # accepts ordinary GPR base registers, so this EBP-based site is guarded
    # by the exact live targets above and table/fixup assertions below.
    options += ["--verified-le-vtable-call","0x80A3A=0x111EA4:29",
                "--verified-le-vtable-call","0x80A3A=0x112060:52",
                "--verified-le-vtable-call","0x80A3A=0x1121E4:64",
                "--verified-indirect-target","0x80A3A=0x6A240"]
    # The continued landing-effect path in FUN_00086810 uses the same
    # complete 64-slot effect vtable at 0x1121E4: its coordinate callback at
    # 0x88563 reads slot +4 (0x1121E8 -> 0x6A2E0), then its render callback at
    # 0x88596 reads slot +0x44 (0x112228 -> 0x69E20). Both are canonical
    # object-3 SRC_OFFSET32 fixups already verified as one contiguous table.
    options += ["--verified-le-vtable-call","0x88563=0x1121E4:64",
                "--verified-le-vtable-call","0x88596=0x1121E4:64"]
    # The bounded PlSpec state case at 0x44EA3 invokes its state method via
    # [EDX+0x7C]. EDX is the PlSpec subobject vtable (0x112060), and slot 31
    # is an original object-1 LE fixup to FUN_0006A290.
    options += ["--verified-le-vtable-call","0x44EB4=0x112060:52"]
    # FUN_00059F60 is shared by creature and PlSpec vtables. At +0x68,
    # object-1 fixups select different methods for the two verified LE tables.
    options += ["--verified-le-vtable-call","0x59F91=0x111D04:60",
                "--verified-le-vtable-call","0x46030=0x111D04:60",
                "--verified-le-vtable-call","0x59F91=0x112060:52",
                "--verified-le-vtable-call","0x59F91=0x1123BC:48"]
    # Thing::Update's live type-2 path reaches CALL [EDX+0x80] in FUN_000114B0.
    # Its receiver carries the canonical Thing vtable at 0x1123BC; slot 32
    # (0x11243C) is fixed by the LE to the original predicate 0x95C60.
    options += ["--verified-le-vtable-call","0x11548=0x1123BC:48"]
    # The original Thing sprite/state path at 0x1044A calls virtual slot 18
    # through the receiver's +0x23 vptr. The canonical Thing fixup at
    # 0x112404 resolves that slot to original code 0x69E10.
    options += ["--verified-le-vtable-call","0x1044A=0x1123BC:48"]
    # FUN_00056B60 iterates records with the verified 0x111EA4 table. Its
    # two reached methods use slot 10 (0x111ECC -> 0x6A300) and slot 24
    # (0x111F04 -> 0x56D40); keep both callsites constrained to that table.
    options += ["--verified-le-vtable-call","0x56C72=0x111EA4:29",
                "--verified-le-vtable-call","0x56CD8=0x111EA4:29"]
    # Other branches in FUN_000103F0 use the same runtime Thing/Creature/
    # PlSpec receiver layout but select virtual slots 20 and 18. Keep each
    # branch tied to its own decoded callsite and complete canonical vtable.
    for site in (0x10421,0x1042E,0x1043B):
        for table,count in ((0x111D04,60),(0x112060,52),(0x1123BC,48)):
            options += ["--verified-le-vtable-call",f"{hex(site)}={hex(table)}:{count}"]
    # FUN_00059F60 is a shared creature/PlSpec method. The same CALL [ECX+0x98]
    # therefore has two legitimate receivers in the LE: creature vtable
    # 0x111D04 (slot 0x111D9C) and PlSpec vtable 0x112060 (slot 0x1120F8).
    # Both slots carry exact object-3 SRC_OFFSET32 fixups to object-1 0x58DE0.
    # Its nested +0x88 callback is likewise backed by the PlSpec table.
    movement_update_vtables=(0x111D04,0x112060)
    movement_update_call=code_bytes[0x5AACC-code_obj.base:0x5AACC-code_obj.base+6]
    movement_update_fixups={slot:next((f for f in image.fixups if f.source_link==slot+0x98),None)
                            for slot in movement_update_vtables}
    movement_method=code_bytes[0x58DE0-code_obj.base:0x58DE0-code_obj.base+19]
    movement_nested_call=code_bytes[0x58E86-code_obj.base:0x58E86-code_obj.base+13]
    movement_nested_fixup=next((f for f in image.fixups if f.source_link==0x1120E8),None)
    if (movement_update_call!=bytes.fromhex("FF 91 98 00 00 00") or
            any(f is None or f.source_type!=0x07 or f.target_object!=1 or f.target_flags&0x03 or
                image.objects[0].base+f.target_offset!=0x58DE0
                for f in movement_update_fixups.values()) or
            movement_method!=_OrigDigest("cf0667daa039ed38e53b810bce7cab42126ff65611c60b3136db858cd65c0e55",19) or
            movement_nested_call!=_OrigDigest("a0bd3c6d3ad78c6e73f9b383b72a4714eb0699e7d6de93a170dfb6f26620c37f",13) or
            movement_nested_fixup is None or movement_nested_fixup.source_type!=0x07 or
            movement_nested_fixup.target_object!=1 or movement_nested_fixup.target_flags&0x03 or
            image.objects[0].base+movement_nested_fixup.target_offset!=0x8A720):
        raise SystemExit("the PlSpec post-order movement method no longer matches the exact original LE vtable/fixup contracts")
    if (image.link_to_linear(0x111D04)!=0x2EBD04 or
            image.link_to_linear(0x112060)!=0x2EC060):
        raise SystemExit("the original creature/PlSpec vtable mappings changed")
    options += ["--verified-le-vtable-call","0x5AACC=0x111D04:60",
                "--verified-le-vtable-call","0x5AACC=0x112060:52",
                "--verified-le-vtable-call","0x58E8D=0x112060:52"]
    # FUN_00058330 dispatches PlSpec's movement/status method at slot +0xA4.
    options += ["--verified-le-vtable-call","0x58681=0x111D04:60",
                "--verified-le-vtable-call","0x58681=0x112060:52"]
    # FUN_00059CF0 has the shared [EBX+0xB8] method slot too: TT uses
    # 0x47700, while the PlSpec table fixes it to 0x59B60.
    options += ["--verified-le-vtable-call","0x59D42=0x111D04:60",
                "--verified-le-vtable-call","0x59D42=0x112060:52"]
    options += ["--verified-le-vtable-call","0x59BA6=0x111D04:60",
                "--verified-le-vtable-call","0x59BA6=0x112060:52"]
    # FUN_00059D80 is shared by creature and PlSpec records. Close its three
    # virtual calls against both original vtables; the PlSpec +0x74 method is
    # a distinct LE fixup to 0x8A730 and becomes live during the native loop.
    options += ["--verified-le-vtable-call","0x59D9F=0x111D04:60",
                "--verified-le-vtable-call","0x59D9F=0x112060:52",
                "--verified-le-vtable-call","0x59DAB=0x111D04:60",
                "--verified-le-vtable-call","0x59DAB=0x112060:52",
                "--verified-le-vtable-call","0x59E30=0x111D04:60",
                "--verified-le-vtable-call","0x59E30=0x112060:52"]
    options += ["--verified-le-vtable-call","0x44932=0x111D04:60",
                "--verified-le-vtable-call","0x44932=0x112060:52"]
    # The full native game() loop reaches another PlSpec virtual call from
    # the active map entity. At 0x451DF the LE bytes are CALL [ESI+0x44],
    # with ESI=0x112060 at runtime; slot 0x1120A4 is an object-3 LE fixup to
    # the already lifted original object-1 callback at 0x69E20.
    options += ["--verified-le-vtable-call","0x451DF=0x112060:52"]
    native_loop_call=code_bytes[0x451DF-code_obj.base:0x451DF-code_obj.base+3]
    native_loop_fixup=next((f for f in image.fixups if f.source_link==0x1120A4),None)
    if (native_loop_call!=bytes.fromhex("FF 56 44") or native_loop_fixup is None or
            native_loop_fixup.source_type!=0x07 or native_loop_fixup.target_object!=1 or
            native_loop_fixup.target_flags&0x03 or
            image.objects[0].base+native_loop_fixup.target_offset!=0x69E20):
        raise SystemExit("native game() PlSpec callback at 0x451DF no longer matches the exact 0x1120A4 LE fixup to 0x69E20")
    # This continuation dispatches through IFCPlanetside's secondary
    # subobject: live vptr 0x002EBB04, link address point 0x111B04. Its
    # +0x0C Draw slot and the seven adjacent entries are LE-fixup backed.
    options += ["--verified-le-vtable-call","0x83561=0x111B04:8"]
    # The longer native game loop reaches a Thing virtual call at 0x47EFC.
    # Its live vtable base is the LE address point 0x111EA4; all 29 adjacent
    # slots have object-1 fixups, so admit this finite table with the normal
    # runtime base, selected-slot, and target checks.
    # The same callsite is shared by PlSpec records: canonical LE slot
    # 0x112070 is independently fixed to 0x6A240, so retain the paired
    # vtable/target contract rather than broadening the callsite globally.
    options += ["--verified-le-vtable-call","0x47EFC=0x111EA4:29",
                "--verified-le-vtable-call","0x47EFC=0x112060:52"]
    # FUN_00047EE0 compares the live creature with a virtual query result;
    # this path now reaches two separate calls at the same basic block: the
    # selected PlSpec's slot 0 at 0x477F4 and the creature's slot 0 at
    # 0x477FD. Both slot-0 targets are confirmed by contiguous LE fixups.
    options += ["--verified-le-vtable-call","0x477F4=0x112060:52",
                "--verified-le-vtable-call","0x477FD=0x111D04:60"]
    # The creature state-reset path reached at turn 820 dispatches slot
    # 0x84 through the creature's verified 60-entry vtable. LE slot
    # 0x111D88 is an SRC_OFFSET32 fixup to 0x6A250.
    options += ["--verified-le-vtable-call","0x48DA3=0x111D04:60"]
    # The same creature update routine performs its sound/event callback via
    # slot +0x44 at 0x48E1A; the canonical 0x111D48 fixup targets 0x69E20.
    options += ["--verified-le-vtable-call","0x48E1A=0x111D04:60"]
    # The creature's next action predicate is reached in the shared entity
    # ranking path at 0x45559. Slot +0x68 (0x111D6C) is LE-fixed to 0x6A070.
    options += ["--verified-le-vtable-call","0x45559=0x111D04:60"]
    # The active PlSpec phase transition invokes slot +0x80 at 0x3FC0C;
    # the PlSpec LE vtable fixes 0x1120E0 to the original helper 0x6A370.
    options += ["--verified-le-vtable-call","0x3FC0C=0x112060:52"]
    options += ["--verified-le-vtable-call","0x480D8=0x111D04:60"]
    options += ["--verified-le-vtable-call","0x50A02=0x111EA4:29"]
    options += ["--verified-le-vtable-call","0x50ADC=0x111D04:60"]
    options += ["--verified-le-vtable-call","0x50AEB=0x111D04:60"]
    options += ["--verified-le-vtable-call","0x50ACC=0x111D04:60",
                "--verified-le-vtable-call","0x50B29=0x111D04:60",
                "--verified-le-vtable-call","0x50C76=0x111EA4:29",
                "--verified-le-vtable-call","0x50C7F=0x111EA4:29",
                "--indexed-code-jump-table","0x50B18=0x4B1D4:4:eax"]
    # The same native lifecycle helper has a four-way, LE-fixed Thing-type
    # switch at 0x47F63 (MAP jpt_47F63 at 0x47ECC), bounded by the original
    # SUB/CMP/JA sequence. Admit all four fixed cases as one contract.
    options += ["--indexed-code-jump-table","0x47F63=0x47ECC:4:eax"]
    # FUN_000118E0 is the original state-driven entity updater now reached
    # on every native game() tick. Admit its complete bounded set of virtual
    # call edges against the four already validated entity vtables. The LE
    # fixups determine each selected target; Runtime still checks the actual
    # live vptr and slot target at every call. This closes only this function,
    # not the general virtual-call mechanism.
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    from capstone.x86_const import X86_OP_MEM, X86_REG_EAX, X86_REG_EBX, X86_REG_ECX, X86_REG_EDX, X86_REG_ESI, X86_REG_EDI, X86_REG_EBP
    entity_update_dis=Cs(CS_ARCH_X86,CS_MODE_32)
    entity_update_dis.detail=True
    entity_update_vtables=((0x1123BC,48),(0x111D04,60),(0x112060,52),(0x1121E4,64))
    gpr_bases={X86_REG_EAX,X86_REG_EBX,X86_REG_ECX,X86_REG_EDX,
               X86_REG_ESI,X86_REG_EDI,X86_REG_EBP}
    entity_update_sites=[]
    for insn in entity_update_dis.disasm(original_code[0x118E0-original_code_obj.base:
                                                        0x13240-original_code_obj.base],0x118E0):
        if insn.mnemonic.lower()!="call" or len(insn.operands)!=1:
            continue
        operand=insn.operands[0]
        if (operand.type!=X86_OP_MEM or operand.mem.base not in gpr_bases or
                operand.mem.index or operand.mem.disp<0 or operand.mem.disp%4):
            continue
        slot_index=operand.mem.disp//4
        matched=[]
        for vtable_link,slot_count in entity_update_vtables:
            if slot_index>=slot_count:
                continue
            fixup=next((f for f in image.fixups if f.source_link==vtable_link+4*slot_index),None)
            if (fixup is None or fixup.source_type!=0x07 or fixup.target_object!=1 or
                    fixup.target_flags&0x03):
                raise SystemExit(f"entity updater vtable slot 0x{vtable_link+4*slot_index:06X} lacks an object-1 LE code fixup")
            matched.append((vtable_link,slot_count))
        if not matched:
            continue
        entity_update_sites.append({"site":insn.address,"bytes":bytes(insn.bytes).hex(),
                                    "slot":slot_index,"vtable_pairs":matched})
        for vtable_link,slot_count in matched:
            options += ["--verified-le-vtable-call",
                        f"0x{insn.address:X}=0x{vtable_link:X}:{slot_count}"]
    if not entity_update_sites:
        raise SystemExit("no original entity-update virtual calls were decoded in 0x118E0..0x13240")
    (ROOT/"evidence"/"native_entity_update_le_closure.json").write_text(
        json.dumps({"schema":"gw-le-entity-update-closure/v1",
            "target_sha256":EXPECTED_TARGET,"function_link":"0x000118E0",
            "callsite_count":len(entity_update_sites),"sites":entity_update_sites,
            "vtable_fixup_contracts":[{"link":f"0x{link:08X}","slots":count,
                "evidence":"contiguous object-1 SRC_OFFSET32 fixups; verified in prior live entity callbacks"}
                for link,count in entity_update_vtables]},indent=2)+"\n",encoding="utf-8")
    # DrawMapSprites uses an EBP-based virtual call at 0x793EC, which the
    # vtable-call syntax intentionally does not accept as a base register.
    # Resolve the exact finite receiver set from slot 9 of the four already
    # verified entity vtables, then keep the per-site runtime target guard.
    map_pick_dispatch=original_code[0x793EC-original_code_obj.base:
                                   0x793EC-original_code_obj.base+3]
    map_pick_tables=((0x1123BC,48,0x10EA0),(0x111D04,60,0x45EF0),
                     (0x112060,52,0x43BD0),(0x1121E4,64,0x85240))
    if map_pick_dispatch!=bytes.fromhex("FF 55 24"):
        raise SystemExit(f"MapDisplay list-sweep dispatch bytes changed at 0x793EC: {map_pick_dispatch.hex()}")
    for vtable_link,slot_count,expected_target in map_pick_tables:
        fixup=next((f for f in image.fixups if f.source_link==vtable_link+9*4),None)
        target=(image.objects[0].base+fixup.target_offset
                if fixup is not None and fixup.target_object==1 else None)
        if (slot_count<=9 or fixup is None or fixup.source_type!=0x07 or
                fixup.target_object!=1 or fixup.target_flags&0x03 or
                target!=expected_target):
            raise SystemExit(f"MapDisplay slot-9 callback lacks exact LE fixup at 0x{vtable_link+36:06X}")
        target_contract=f"--verified-indirect-target"
        target_row=f"0x793EC=0x{expected_target:X}"
        if target_row not in options:
            options += [target_contract,target_row]
        partial_root=f"0x{expected_target:X}"
        if partial_root not in options:
            options += ["--partial-root",partial_root]
    # The original Thing slot-9 method 0x10EA0 subsequently queries the
    # Thing vtable at 0x10EFA (CALL [EDX+4], slot 1). Keep this nested callback
    # fail-closed and admit only the exact Thing table whose slot-1 LE fixup
    # resolves to the original accessor 0x6A2E0.
    thing_property_site=0x10EFA
    thing_property_fixup=next((f for f in image.fixups if f.source_link==0x1123C0),None)
    thing_property_target=(image.objects[0].base+thing_property_fixup.target_offset
        if thing_property_fixup is not None and thing_property_fixup.target_object==1 else None)
    thing_property_call=original_code[thing_property_site-original_code_obj.base:
                                      thing_property_site-original_code_obj.base+3]
    if (thing_property_call!=bytes.fromhex("FF 52 04") or thing_property_fixup is None or
            thing_property_fixup.source_type!=0x07 or thing_property_fixup.target_object!=1 or
            thing_property_fixup.target_flags&0x03 or thing_property_target!=0x6A2E0):
        raise SystemExit(f"Thing sprite-property callback lacks its exact LE-vtable contract: bytes={thing_property_call.hex()} fixup={thing_property_fixup!r} target={thing_property_target!r}")
    thing_property_contract=("--verified-le-vtable-call", "0x10EFA=0x1123BC:48")
    if thing_property_contract[1] not in options:
        options += list(thing_property_contract)
    thing_property_root="0x6A2E0"
    if thing_property_root not in options:
        options += ["--partial-root",thing_property_root]
    (ROOT/"evidence"/"native_map_pick_vtable_slot9.json").write_text(
        json.dumps({"schema":"gw-le-map-pick-vtable-slot9/v1",
            "target_sha256":EXPECTED_TARGET,"callsite_link":"0x000793EC",
            "instruction":"CALL [EBP+0x24]","instruction_bytes":"FF 55 24",
            "slot_index":9,"vtable_targets":[{"vtable_link":f"0x{link:08X}",
                "slot_link":f"0x{link+36:08X}","slot_count":count,
                "target_link":f"0x{target:08X}","fixup":"Object-3 SRC_OFFSET32 -> Object-1 code"}
                for link,count,target in map_pick_tables],
            "nested_thing_property_callback":{"callsite_link":"0x00010EFA",
                "instruction":"CALL [EDX+4]","instruction_bytes":thing_property_call.hex(" ").upper(),
                "receiver_vtable_link":"0x001123BC","slot_index":1,"slot_link":"0x001123C0",
                "slot_count":48,"target_link":"0x0006A2E0",
                "fixup":"Object-3 SRC_OFFSET32 -> Object-1 code",
                "runtime_guard":"exact callsite, receiver vtable and destination"}},indent=2)+"\n",encoding="utf-8")
    # Batch the exact virtual calls throughout FUN_0004B1F0. Every candidate
    # table is checked slot-for-slot for Object-1 LE fixups by the lifter, and
    # every dynamic call remains guarded against the actual vptr and target.
    options += ["--verified-le-vtable-function",
                "0x4B1F0=0x111D04:60,0x112060:52,0x111EA4:29"]
    # BioGame effect lifecycle has a separate contiguous 128-slot LE vtable
    # region; its active callback slot 0x112228 fixes to 0x69E20.
    options += ["--verified-le-vtable-function","0x86810=0x1121E4:128"]
    options += ["--verified-le-vtable-function","0x85240=0x1121E4:128"]
    options += ["--verified-le-vtable-function","0x80B20=0x111EA4:29"]
    options += ["--verified-le-vtable-function",
                "0x47D60=0x111D04:60,0x112060:52"]
    # V15 (savegame): FUN_00047300 serializes the 0x7C-byte Thing records through the virtual
    # method at vptr+0x40 (record+0x23). Same LE-fixup-backed Thing class tables as the other
    # per-Thing loops (0x4B1F0, 0x47D60, 0x80B20, effect lifecycle 0x1121E4).
    for ser in ("0x10170","0x13AD0","0x39E20","0x44190","0x47300","0x570E0","0x86350","0x89950"):
        options += ["--verified-le-vtable-function",
                    ser+"=0x111D04:17,0x111DFC:17,0x111EA4:17,0x112060:17,0x1121E4:17,0x11228C:17,0x1122FC:17,0x1123BC:17"]
    options += ["--verified-le-vtable-call","0x47E66=0x111EA4:29",
                "--verified-le-vtable-call","0x47E6F=0x111EA4:29"]
    options += ["--verified-le-vtable-function","0x56FB0=0x111EA4:29"]
    # An adjacent original vtable address point at 0x111D00 (one fixed method
    # before the 0x111D04 interface) is used by the reached 0x25A7A call.
    # Its 61 contiguous slots are all object-1 LE fixups; keep this callsite
    # explicit because its address point differs by one dword.
    options += ["--verified-le-vtable-call","0x25A7A=0x111D00:61"]
    # FUN_000256E0 is also reached in the long simulation while resolving
    # frame/callback geometry. Its original CALL [EDX] uses the same exact
    # 0x111D00 address point; admit the full contiguous LE-fixup-backed table
    # for that function, retaining per-call live base/slot guards.
    options += ["--verified-le-vtable-function","0x256E0=0x111D00:61"]
    # The 672-turn run reaches this original PlSpec callback dispatch after
    # the rectangle helper returns true. Slot 0x111DAC is the exact
    # object-3 -> object-1 SRC_OFFSET32 fixup used by CALL [EBX+0xA8].
    options += ["--verified-le-vtable-call","0x5A048=0x111D04:60"]
    # Lifecycle mode callback reached after the validated six-state switch;
    # PlSpec slot 43 is an Object-1 LE fixup to 0x8A570.
    # Batch the fixup-backed jump tables in the full draw/sound subtree.
    # Dynamic object callbacks and formatter callbacks remain fail-closed.
    options += ["--indexed-code-jump-table","0x3DBDD=0x3DB60:4:eax",
                "--indexed-code-jump-table","0x4103A=0x40390:6:eax",
                "--indexed-code-jump-table","0x3C6A8=0x39EE4:12:eax",
                "--indexed-code-jump-table","0xCBC93=0xCBC48:10:eax",
                "--verified-indirect-target","0xB6B45=0xD0134",
                "--partial-root","0xC41C0",
                "--verified-indirect-target","0xC62FC=0xC41C0",
                "--partial-root","0xC4270",
                "--verified-indirect-target","0xC4880=0xC4270",
                "--verified-indirect-target","0xC5ACB=0xC4270",
                "--verified-indirect-target","0xC5B5F=0xC4270",
                "--verified-indirect-target","0xC5B95=0xC4270",
                "--verified-indirect-target","0xC5BE4=0xC4270",
                "--verified-indirect-target","0xC6302=0xC4270",
                "--verified-indirect-target","0xC6A92=0xC4270",
                "--verified-indirect-target","0xC73CA=0xC4270",
                "--verified-indirect-target","0xC762D=0xC4270",
                "--verified-indirect-target","0xC763A=0xC4270",
                "--verified-indirect-target","0xC7696=0xC4270",
                "--verified-indirect-target","0xC7740=0xC4270",
                "--verified-indirect-target","0xC774C=0xC4270",
                "--partial-root","0xC4180",
                "--verified-indirect-target","0xC6096=0xC4180",
                "--verified-indirect-target","0xC631E=0xC4180",
                "--verified-indirect-target","0xC63F6=0xC4180",
                "--partial-root","0xC43B0",
                "--verified-indirect-target","0xC6D26=0xC43B0",
                "--partial-root","0xC42F0",
                "--verified-indirect-target","0xC5F98=0xC42F0",
                "--partial-root","0xC4600",
                "--verified-indirect-target","0xC483E=0xC4600",
                "--verified-indirect-target","0xC5CE9=0xC4600",
                "--partial-root","0xC4370",
                "--verified-indirect-target","0xC71A4=0xC4370",
                "--partial-root","0xC4640",
                "--batch-le-fixup-vtables"]
    for target in sorted(seen_callback_targets):
        options += ["--verified-indirect-target",f"0xA8D95={hex(target)}",
                    "--partial-root",hex(target)]
    if os.environ.get("GWRECOMP_REUSE_EXISTING_LIFT") == "1":
        if not generated_base.is_file() or not lift_report.is_file():
            raise SystemExit("requested incremental lift reuse but the pristine generated closure/report is missing")
        cached_lift=json.loads(lift_report.read_text(encoding="utf-8"))
        if cached_lift.get("target_sha256","").lower()!=EXPECTED_TARGET:
            raise SystemExit("refusing to reuse lifted closure for a different LE target hash")
        # The harness adds C probes to its generated translation unit below.
        # Always start from the pristine lifter output; reusing the previously
        # instrumented file duplicates generated wrapper definitions.
        generated.write_bytes(generated_base.read_bytes())
        print("TRACE lift-cache reused existing hash-matched LE closure")
    else:
        # These shared list/query sites also dispatch the LE-backed Thing
        # vtable at 0x1123BC for __unkarr01 records. Keep both contracts
        # exact without pushing the Windows subprocess command line past 32 KiB.
        ENV["GWRECOMP_LIFT_VTABLE_CALLS"] = ";".join((
            "0x78BA1=0x1123BC:48", "0x80A3A=0x1123BC:48",
            "0x7925B=0x111DFC:40", "0x38F78=0x111DFC:40"))
        ENV["GWRECOMP_LIFT_PARTIAL_ROOTS"] = ";".join(("0x95CA0", "0x6ED40", "0x69E20"))
        # Building-state switch at 0x39083: the original CMP/JA bounds EAX
        # to 0..11 and the canonical LE fixes all 12 table slots to Object-1
        # code. Keep this bounded batch out of CreateProcess' long argv.
        ENV["GWRECOMP_LIFT_INDEXED_CODE_JUMP_TABLES"] = (
            "0x39083=0x38EC4:12:eax;0x3A18E=0x39EAC:14:eax;"
            "0x3F5AC=0x3F1A4:4:eax;0x1160D=0x11478:12:edx;"
            "0x1086F=0x104B0:6:eax;0x266C0=0x26628:4:eax;"
            "0x267F1=0x26638:4:eax;0x298CA=0x28FFC:4:eax;"
            "0x2B1F7=0x2B100:5:ebx;0x3248D=0x31680:7:edx;"
            "0x32D18=0x32CE0:7:ecx;0x33AE8=0x33AA4:4:eax;"
            "0x37873=0x37454:8:eax;0x39390=0x392E8:12:eax;"
            "0x39705=0x39614:11:edx;0x3972F=0x39640:10:eax;"
            "0x3A077=0x39E80:11:edx;0x3DE6D=0x3DB50:4:eax;"
            "0x64BCB=0x64990:7:eax;0x71424=0x713EC:6:ecx;"
            "0x72EEA=0x72D40:27:eax;0x84674=0x83AA0:6:eax;"
            "0x84B26=0x83AB8:7:eax;0x85BEC=0x85230:4:eax;"
            "0x85CEB=0x85230:4:eax;0x873A0=0x866C0:7:eax;"
            "0x87F30=0x866DC:10:eax;0xD5B90=0xD5B58:9:ebx;"
            "0x2D696=0x2CF40:7:eax;0x2F1BF=0x2E0F0:4:eax;"
            "0x2F48F=0x2F1D4:14:eax;0x32DCA=0x32CC4:7:ebx;"
            "0xAC965=0xAC942:4:eax;0xD6868=0xD6818:10:esi")
        # The verified-LE closure has grown beyond Windows' CreateProcess
        # command-line limit. Keep the same exact argv as a one-argument-per-
        # line response file; argparse expands it without changing contracts.
        lift_args=[*options,"--output-c",generated,"--report",lift_report]
        if any("\n" in str(arg) or "\r" in str(arg) for arg in lift_args):
            raise SystemExit("lift response-file argument unexpectedly contains a newline")
        lift_response=ROOT/"work"/"ifctitle_creature_probe_lift_args.txt"
        lift_response.write_text("\n".join(str(arg) for arg in lift_args)+"\n",encoding="utf-8")
        run([PYTHON,ROOT/"tools"/"lift_entry_path.py",f"@{lift_response}"],timeout=300,quiet=True)
        generated_base.write_bytes(generated.read_bytes())
    lift_evidence=json.loads(lift_report.read_text(encoding="utf-8"))
    drawmap_vtable=next((row for row in lift_evidence.get("verified_le_vtable_calls",[])
                         if row.get("callsite")=="0x0007925B" and
                            row.get("vtable_link")=="0x00111EA4"),None)
    if (drawmap_vtable is None or drawmap_vtable.get("slot_count")!=29 or
            not any(entry.get("source_link")=="0x00111EC8" and
                    entry.get("target_link")=="0x0006ED40"
                    for entry in drawmap_vtable.get("entries",[]))):
        raise SystemExit(f"DrawMapSprites object-position callback lacks its canonical LE vtable fixup: {drawmap_vtable!r}")
    building_update_vtable=next((row for row in lift_evidence.get("verified_le_vtable_calls",[])
                         if row.get("callsite")=="0x00038F78" and
                            row.get("vtable_link")=="0x00111DFC"),None)
    if (building_update_vtable is None or building_update_vtable.get("slot_count")!=40 or
            not any(entry.get("source_link")=="0x00111E40" and
                    entry.get("target_link")=="0x00069E20"
                    for entry in building_update_vtable.get("entries",[]))):
        raise SystemExit(f"building update slot lacks its canonical LE vtable fixup: {building_update_vtable!r}")
    fixups_by_source={f.source_link:f for f in image.fixups}
    for vtable_link,slot_count,dispatch_slot,target_link,label in (
            (0x1121E4,64,0x112208,0x85240,"BioGame"),
            (0x112060,52,0x112084,0x43BD0,"PlSpec")):
        slots=[fixups_by_source.get(vtable_link+4*i) for i in range(slot_count)]
        if (any(f is None or f.source_type!=0x07 or f.target_object!=1 for f in slots) or
                fixups_by_source[dispatch_slot].target_offset+image.objects[0].base!=target_link):
            raise SystemExit(f"FUN_00079320 {label} dispatch table is not a complete {slot_count}-slot LE fixup table")
    packet_switch=next((row for row in lift_evidence.get("indexed_code_jump_tables",[])
                        if row.get("instruction")=="0x0009358B"),None)
    if (packet_switch is None or packet_switch.get("table_link")!="0x00092F7C" or
            packet_switch.get("count")!=35 or packet_switch.get("segment")!="CS" or
            len(packet_switch.get("fixup_slots",[]))!=35 or
            any(slot.get("target_object")!=1 for slot in packet_switch["fixup_slots"])):
        raise SystemExit(f"process_packets dispatch table was not admitted from all 35 original LE fixups: {packet_switch!r}")
    print("TRACE canonical process_packets jump table link=00092f7c site=0009358b slots=35 object1_fixups=35 runtime_index=0..34 fail_closed=1")
    packet_kind_switch=next((row for row in lift_evidence.get("indexed_code_jump_tables",[])
                             if row.get("instruction")=="0x000505B7"),None)
    if (packet_kind_switch is None or packet_kind_switch.get("table_link")!="0x0004B170" or
            packet_kind_switch.get("count")!=25 or packet_kind_switch.get("segment")!="CS" or
            len(packet_kind_switch.get("fixup_slots",[]))!=25 or
            any(slot.get("target_object")!=1 for slot in packet_kind_switch["fixup_slots"])):
        raise SystemExit(f"process_packets packet-kind dispatch was not admitted from all 25 original LE fixups: {packet_kind_switch!r}")
    print("TRACE canonical packet-kind dispatch MAP=jpt_505B7 link=0004b170 site=000505b7 slots=25 object1_fixups=25 index=0..24 fail_closed=1")
    landing_state_switch=next((row for row in lift_evidence.get("indexed_code_jump_tables",[])
                               if row.get("instruction")=="0x0003F69A"),None)
    expected_landing_targets=["0x0003F6A2","0x0003F6FE","0x0003F93C","0x0003F93C",
                              "0x0003F8F1","0x0003F75A","0x0003F7EE"]
    landing_fixups=sorted((fixup for fixup in image.fixups
                           if 0x3F664<=fixup.source_link<0x3F680),key=lambda fixup:fixup.source_link)
    if (landing_state_switch is None or landing_state_switch.get("table_link")!="0x0003F664" or
            landing_state_switch.get("count")!=7 or landing_state_switch.get("segment")!="CS" or
            landing_state_switch.get("targets_link")!=expected_landing_targets or
            len(landing_state_switch.get("fixup_slots",[]))!=7 or len(landing_fixups)!=7 or
            any(fixup.source_type!=0x07 or fixup.target_object!=1 for fixup in landing_fixups)):
        raise SystemExit(f"PlSpec lifecycle switch at 0x3F69A lacks its seven original LE fixups: {landing_state_switch!r}")
    print("TRACE canonical PlSpec lifecycle switch site=0003F69A table=0003F664 entries=7 object1_fixups=7 bounds=0..6 fail_closed=1")
    mode_state_switch=next((row for row in lift_evidence.get("indexed_code_jump_tables",[])
                            if row.get("instruction")=="0x0003DB3D"),None)
    mode_state_fixups=sorted((fixup for fixup in image.fixups
                              if 0x3D460<=fixup.source_link<0x3D470),
                             key=lambda fixup:fixup.source_link)
    expected_mode_state_targets=[f"0x{target:08X}" for target in
                                 (0x3D651,0x3D8B2,0x3D99B,0x3D925)]
    if (original_code[0x3DB3D-original_code_obj.base:0x3DB45-original_code_obj.base]!=
            _OrigDigest("f8532e03f0d1fea6b2c2689e1ba88da4f13d812370b84dd96ce493dc9832fc9d",8) or
            mode_state_switch is None or mode_state_switch.get("table_link")!="0x0003D460" or
            mode_state_switch.get("count")!=4 or
            mode_state_switch.get("targets_link")!=expected_mode_state_targets or
            len(mode_state_switch.get("fixup_slots",[]))!=4 or len(mode_state_fixups)!=4 or
            any(fixup.source_type!=0x07 or fixup.target_object!=1 for fixup in mode_state_fixups)):
        raise SystemExit(f"FUN_0003D470 jpt_3DB3D lacks its four original LE code fixups: {mode_state_switch!r}")
    print("TRACE canonical FUN_0003D470 MAP=jpt_3DB3D site=0003DB3D table=0003D460 targets=0003D651/0003D8B2/0003D99B/0003D925 object1_fixups=4 bounds=0..3 fail_closed=1")
    planside_state_switch=next((row for row in lift_evidence.get("indexed_code_jump_tables",[])
                                if row.get("instruction")=="0x00044A31"),None)
    planside_state_fixups=sorted((fixup for fixup in image.fixups
                                  if 0x4450C<=fixup.source_link<0x4453C),key=lambda fixup:fixup.source_link)
    expected_planside_targets=[f"0x{target:08X}" for target in
        (0x44A39,0x44D5E,0x44A46,0x44A60,0x44C75,0x44D5E,
         0x44A53,0x44D5E,0x44CF6,0x44D00,0x44D20,0x44D2A)]
    if (planside_state_switch is None or planside_state_switch.get("table_link")!="0x0004450C" or
            planside_state_switch.get("count")!=12 or planside_state_switch.get("segment")!="CS" or
            planside_state_switch.get("targets_link")!=expected_planside_targets or
            len(planside_state_switch.get("fixup_slots",[]))!=12 or len(planside_state_fixups)!=12 or
            any(fixup.source_type!=0x07 or fixup.target_object!=1 for fixup in planside_state_fixups)):
        raise SystemExit(f"FUN_00044570 state switch lacks its twelve original LE fixups: {planside_state_switch!r}")
    print("TRACE canonical PlSpec update switch site=00044A31 table=0004450C entries=12 object1_fixups=12 bounds=0..11 fail_closed=1")
    planside_secondary_switch=next((row for row in lift_evidence.get("indexed_code_jump_tables",[])
                                    if row.get("instruction")=="0x00044EA3"),None)
    planside_secondary_fixups=sorted((fixup for fixup in image.fixups
                                      if 0x4453C<=fixup.source_link<0x4456C),key=lambda fixup:fixup.source_link)
    expected_secondary_targets=[f"0x{target:08X}" for target in
        (0x45054,0x44F30,0x45030,0x44F0E,0x44EEC,0x45030,
         0x45030,0x44EAB,0x45030,0x45030,0x45030,0x44F84)]
    if (planside_secondary_switch is None or planside_secondary_switch.get("table_link")!="0x0004453C" or
            planside_secondary_switch.get("count")!=12 or planside_secondary_switch.get("segment")!="CS" or
            planside_secondary_switch.get("targets_link")!=expected_secondary_targets or
            len(planside_secondary_switch.get("fixup_slots",[]))!=12 or len(planside_secondary_fixups)!=12 or
            any(fixup.source_type!=0x07 or fixup.target_object!=1 for fixup in planside_secondary_fixups)):
        raise SystemExit(f"FUN_00044570 secondary state switch lacks its twelve original LE fixups: {planside_secondary_switch!r}")
    print("TRACE canonical PlSpec secondary switch site=00044EA3 table=0004453C entries=12 object1_fixups=12 bounds=0..11 fail_closed=1")
    plspec_state_method=next((row for row in lift_evidence.get("verified_le_vtable_calls",[])
                              if row.get("callsite")=="0x00044EB4"),None)
    plspec_state_method_fixup=next((fixup for fixup in image.fixups
                                    if fixup.source_link==0x1120DC),None)
    if (plspec_state_method is None or plspec_state_method.get("vtable_link")!="0x00112060" or
            plspec_state_method.get("vtable_guest")!="0x002EC060" or
            plspec_state_method.get("slot_count")!=52 or
            plspec_state_method.get("selected_slot_index")!=31 or
            plspec_state_method.get("selected_slot_link")!="0x001120DC" or
            plspec_state_method.get("selected_target_link")!="0x0006A290" or
            len(plspec_state_method.get("entries",[]))!=52 or plspec_state_method_fixup is None or
            plspec_state_method_fixup.source_type!=0x07 or plspec_state_method_fixup.target_object!=1 or
            plspec_state_method_fixup.target_offset!=0x6A290-image.objects[0].base):
        raise SystemExit(f"PlSpec state-method call at 0x44EB4 is not backed by vtable slot 31's LE fixup: {plspec_state_method!r}")
    print("TRACE canonical PlSpec state method site=00044EB4 operand=[EDX+7C] base=00112060 slot=31/001120DC target=0006A290 LE_fixup=object1 runtime_guard=exact")
    planside_eligibility_rows=[row for row in lift_evidence.get("verified_le_vtable_calls",[])
                               if row.get("callsite")=="0x00080A3A"]
    planside_eligibility_fixup=next((fixup for fixup in image.fixups
                                     if fixup.source_link==0x112070),None)
    creature_eligibility_fixup=next((fixup for fixup in image.fixups
                                     if fixup.source_link==0x111D14),None)
    expected_eligibility_pairs={
        ("0x00111EA4",29,4,"0x00111EB4","0x0006EE10"),
        ("0x00112060",52,4,"0x00112070","0x0006A240"),
        ("0x001121E4",64,4,"0x001121F4","0x0006EE10"),
        ("0x00111D04",60,4,"0x00111D14","0x0006A240"),
        ("0x00111DFC",40,4,"0x00111E0C","0x0006EE10"),
        ("0x001123BC",48,4,"0x001123CC","0x00095CA0")}
    actual_eligibility_pairs={(row.get("vtable_link"),row.get("slot_count"),
        row.get("selected_slot_index"),row.get("selected_slot_link"),row.get("selected_target_link"))
        for row in planside_eligibility_rows}
    if (actual_eligibility_pairs!=expected_eligibility_pairs or
            any(len(row.get("entries",[]))!=row.get("slot_count") for row in planside_eligibility_rows) or
            planside_eligibility_fixup is None or
            planside_eligibility_fixup.source_type!=0x07 or planside_eligibility_fixup.target_object!=1 or
            planside_eligibility_fixup.target_offset!=0x6A240-image.objects[0].base or
            creature_eligibility_fixup is None or creature_eligibility_fixup.source_type!=0x07 or
            creature_eligibility_fixup.target_object!=1 or
            creature_eligibility_fixup.target_offset!=0x6A240-image.objects[0].base):
        raise SystemExit(f"shared entity-list callback at 0x80A3A lacks its original LE vtable contracts: {planside_eligibility_rows!r}")
    print("TRACE canonical entity-list callbacks site=00080A3A operand=[ECX+10] vtables=00111EA4[29]=>0006EE10/00112060[52]=>0006A240/001121E4[64]=>0006EE10/00111D04[60]=>0006A240/00111DFC[40]=>0006EE10/001123BC[48]=>00095CA0 slot=4 LE_fixups=6 runtime_guard=exact-pairs")
    plspec_vtable_call=next((row for row in lift_evidence.get("verified_le_vtable_calls",[])
                             if row.get("callsite")=="0x0004459E"),None)
    if (plspec_vtable_call is None or plspec_vtable_call.get("vtable_link")!="0x00112060" or
            plspec_vtable_call.get("vtable_guest")!="0x002EC060" or
            plspec_vtable_call.get("slot_count")!=52 or
            plspec_vtable_call.get("selected_slot_index")!=37 or
            plspec_vtable_call.get("selected_slot_link")!="0x001120F4" or
            plspec_vtable_call.get("selected_target_link")!="0x00059F60" or
            len(plspec_vtable_call.get("entries",[]))!=52 or
            any(not str(entry.get("target_link","")).startswith("0x") for entry in plspec_vtable_call["entries"])):
        raise SystemExit(f"PlSpec vtable 0x112060 was not verified as 52 contiguous LE code fixups: {plspec_vtable_call!r}")
    print("TRACE canonical PlSpec vtable site=0004459E base=00112060 entries=52 fixup_targets=object1 slot=37/001120F4 target=00059F60 base_guard=1 target_guard=1")
    plspec_followup_calls=[row for row in lift_evidence.get("verified_le_vtable_calls",[])
                           if row.get("callsite") in ("0x000446F1","0x00044708")]
    expected_plspec_followups={
        ("0x000446F1",44,"0x00112110","0x0008A560"),
        ("0x00044708",33,"0x001120E4","0x0006A250")}
    actual_plspec_followups={(row.get("callsite"),row.get("selected_slot_index"),
        row.get("selected_slot_link"),row.get("selected_target_link")) for row in plspec_followup_calls}
    if (actual_plspec_followups!=expected_plspec_followups or
            any(row.get("vtable_link")!="0x00112060" or row.get("slot_count")!=52 or
                len(row.get("entries",[]))!=52 for row in plspec_followup_calls)):
        raise SystemExit(f"FUN_00044570 PlSpec predicate calls lack their exact LE vtable slots: {plspec_followup_calls!r}")
    print("TRACE canonical FUN_00044570 PlSpec predicates sites=000446F1/00044708 slots=44/00112110->0008A560,33/001120E4->0006A250 fixup_guard=1")
    plspec_transition_calls=[row for row in lift_evidence.get("verified_le_vtable_calls",[])
                             if row.get("callsite") in ("0x0003FA05","0x0003FA1B","0x0003FA2A")]
    expected_plspec_transition={
        ("0x0003FA05",43,"0x0011210C","0x0008A570"),
        ("0x0003FA1B",43,"0x0011210C","0x0008A570"),
        ("0x0003FA2A",44,"0x00112110","0x0008A560")}
    actual_plspec_transition={(row.get("callsite"),row.get("selected_slot_index"),
        row.get("selected_slot_link"),row.get("selected_target_link")) for row in plspec_transition_calls}
    if (actual_plspec_transition!=expected_plspec_transition or
            any(row.get("vtable_link")!="0x00112060" or row.get("slot_count")!=52 or
                len(row.get("entries",[]))!=52 for row in plspec_transition_calls)):
        raise SystemExit(f"PlSpec state-transition predicates lack their exact LE vtable slots: {plspec_transition_calls!r}")
    print("TRACE canonical FUN_0003F9A0 PlSpec transition sites=0003FA05/0003FA1B/0003FA2A slots=43/0011210C->0008A570,44/00112110->0008A560 fixup_guard=1")
    plspec_state_handler=next((row for row in lift_evidence.get("verified_le_vtable_calls",[])
                               if row.get("callsite")=="0x00058DAF" and row.get("vtable_link")=="0x00112060"),None)
    if (plspec_state_handler is None or plspec_state_handler.get("vtable_link")!="0x00112060" or
            plspec_state_handler.get("slot_count")!=52 or
            plspec_state_handler.get("selected_slot_index")!=11 or
            plspec_state_handler.get("selected_slot_link")!="0x0011208C" or
            plspec_state_handler.get("selected_target_link")!="0x0003F030" or
            len(plspec_state_handler.get("entries",[]))!=52):
        raise SystemExit(f"FUN_00058330 PlSpec state callback is not backed by vtable slot 11: {plspec_state_handler!r}")
    print("TRACE canonical FUN_00058330 PlSpec state callback site=00058DAF slot=11/0011208C->0003F030 fixup_guard=1")
    plspec_common_calls=[row for row in lift_evidence.get("verified_le_vtable_calls",[])
                         if row.get("callsite") in ("0x00044F39","0x000450BA","0x000451B2")]
    expected_plspec_common={
        ("0x00044F39",1,"0x00112064","0x0006A2E0"),
        ("0x000450BA",1,"0x00112064","0x0006A2E0")}
    actual_plspec_common={(row.get("callsite"),row.get("selected_slot_index"),
        row.get("selected_slot_link"),row.get("selected_target_link")) for row in plspec_common_calls}
    if (actual_plspec_common!=expected_plspec_common or
            any(row.get("vtable_link")!="0x00112060" or row.get("slot_count")!=52 or
                len(row.get("entries",[]))!=52 for row in plspec_common_calls)):
        raise SystemExit(f"FUN_00044570 PlSpec common method calls lack their exact LE vtable slots: {plspec_common_calls!r}")
    plspec_base_method=next((row for row in lift_evidence.get("verified_indirect_targets",[])
                             if row.get("callsite")=="0x000451B2" and row.get("link_target")=="0x0006A2F0"),None)
    if plspec_base_method is None:
        raise SystemExit("FUN_00044570 zero-displacement CALL [EDX] lacks the exact LE fixup target guard")
    print("TRACE canonical FUN_00044570 PlSpec common methods sites=00044F39/000450BA slot=1/00112064->0006A2E0; zero-displacement site=000451B2 target=0006A2F0 fixup_guard=1")
    team_callback_rows=[row for row in lift_evidence.get("verified_indirect_targets",[])
                        if row.get("callsite")=="0x00045228"]
    expected_team_callback=("0x00044570",f"0x{image.link_to_linear(0x44570):08X}")
    if {(row.get("link_target"),row.get("guest_target")) for row in team_callback_rows} != {expected_team_callback}:
        raise SystemExit(f"process_packets team callback is not guarded by its LE fixup target: {team_callback_rows!r}")
    print("TRACE canonical process_packets team callback site=00045228 slot=001120C4 fixup=object1:00044570 live_target_guard=1")
    creature_callback_rows=[row for row in lift_evidence.get("verified_indirect_targets",[])
                            if row.get("callsite") in ("0x00054C19","0x00054C50")]
    expected_creature_callbacks={
        ("0x0006A070",f"0x{image.link_to_linear(0x6A070):08X}"),
        ("0x0004B1F0",f"0x{image.link_to_linear(0x4B1F0):08X}"),
    }
    if {(row.get("link_target"),row.get("guest_target")) for row in creature_callback_rows} != expected_creature_callbacks:
        raise SystemExit(f"BioGame creature method calls lack their complete LE fixup-backed target set: {creature_callback_rows!r}")
    print("TRACE canonical BioGame creature callbacks sites=00054C19/00054C50 slots=00111D6C/00111D68 targets=0006A070/0004B1F0 fixup_guard=1")
    creature_entity_rows=[row for row in lift_evidence.get("verified_indirect_targets",[])
                          if row.get("callsite")=="0x0004B2EF"]
    expected_entity_callback=("0x00059F60",f"0x{image.link_to_linear(0x59F60):08X}")
    if {(row.get("link_target"),row.get("guest_target")) for row in creature_entity_rows} != {expected_entity_callback}:
        raise SystemExit(f"BioGame creature entity callback lacks its LE fixup-backed target: {creature_entity_rows!r}")
    print("TRACE canonical BioGame creature entity callback site=0004B2EF slot=00111D98 target=00059F60 fixup_guard=1")
    creature_action_contracts=[row for row in lift_evidence.get("verified_le_vtable_calls",[])
                               if row.get("callsite")=="0x00059F91"]
    expected_creature_action_contracts={
        ("0x00111D04",60,26,"0x00111D6C","0x0006A070"),
        ("0x00112060",52,26,"0x001120C8","0x0008A530"),
        ("0x001123BC",48,26,"0x00112424","0x00095CB0")}
    actual_creature_action_contracts={(row.get("vtable_link"),row.get("slot_count"),
        row.get("selected_slot_index"),row.get("selected_slot_link"),row.get("selected_target_link"))
        for row in creature_action_contracts}
    if actual_creature_action_contracts != expected_creature_action_contracts or any(
            len(row.get("entries",[]))!=row.get("slot_count") for row in creature_action_contracts):
        raise SystemExit(f"shared PlSpec/creature action dispatch lacks both complete LE vtable contracts: {creature_action_contracts!r}")
    print("TRACE canonical entity action site=00059F91 vtables=00111D04[60]=>0006A070,00112060[52]=>0008A530,001123BC[48]=>00095CB0 slot=26 fixup_pairs=3")
    packet_entity_action_contracts=[row for row in lift_evidence.get("verified_le_vtable_calls",[])
                                   if row.get("callsite")=="0x0005A2F5"]
    expected_packet_entity_action_contracts={
        ("0x00111D04",60,4,"0x00111D14","0x0006A240"),
        ("0x00112060",52,4,"0x00112070","0x0006A240"),
        ("0x001123BC",48,4,"0x001123CC","0x00095CA0")}
    actual_packet_entity_action_contracts={(row.get("vtable_link"),row.get("slot_count"),
        row.get("selected_slot_index"),row.get("selected_slot_link"),row.get("selected_target_link"))
        for row in packet_entity_action_contracts}
    if (actual_packet_entity_action_contracts!=expected_packet_entity_action_contracts or
            any(len(row.get("entries",[]))!=row.get("slot_count") for row in packet_entity_action_contracts)):
        raise SystemExit(f"FUN_00059F60 entity action call lacks its three exact LE vtable contracts: {packet_entity_action_contracts!r}")
    print("TRACE canonical FUN_00059F60 entity action site=0005A2F5 tables=00111D04[60]/00112060[52]/001123BC[48] slot=4 targets=0006A240/0006A240/00095CA0 complete_fixups=1")
    thing_update_contracts=[row for row in lift_evidence.get("verified_le_vtable_calls",[])
                            if row.get("callsite")=="0x00011548"]
    expected_thing_update_contract={
        ("0x001123BC",48,32,"0x0011243C","0x00095C60")}
    actual_thing_update_contract={(row.get("vtable_link"),row.get("slot_count"),
        row.get("selected_slot_index"),row.get("selected_slot_link"),row.get("selected_target_link"))
        for row in thing_update_contracts}
    if (actual_thing_update_contract!=expected_thing_update_contract or
            any(len(row.get("entries",[]))!=row.get("slot_count") for row in thing_update_contracts)):
        raise SystemExit(f"FUN_000114B0 Thing update lacks its full LE vtable contract: {thing_update_contracts!r}")
    print("TRACE canonical Thing update site=00011548 table=001123BC[48] slot=32/0011243C target=00095C60 fixup_guard=1")
    thing_sprite_method=[row for row in lift_evidence.get("verified_le_vtable_calls",[])
                         if row.get("callsite")=="0x0001044A"]
    expected_thing_sprite_method={
        ("0x001123BC",48,18,"0x00112404","0x00069E10")}
    actual_thing_sprite_method={(row.get("vtable_link"),row.get("slot_count"),
        row.get("selected_slot_index"),row.get("selected_slot_link"),row.get("selected_target_link"))
        for row in thing_sprite_method}
    if (actual_thing_sprite_method!=expected_thing_sprite_method or
            any(len(row.get("entries",[]))!=row.get("slot_count") for row in thing_sprite_method)):
        raise SystemExit(f"Thing sprite/state callback lacks its LE-backed slot-18 contract: {thing_sprite_method!r}")
    print("TRACE canonical Thing sprite/state site=0001044A table=001123BC[48] slot=18/00112404 target=00069E10 fixup_guard=1")
    record_method_contracts=[row for row in lift_evidence.get("verified_le_vtable_calls",[])
                             if row.get("callsite") in {"0x00056C72","0x00056CD8"}]
    expected_record_methods={
        ("0x00056C72",10,"0x00111ECC","0x0006A300"),
        ("0x00056CD8",24,"0x00111F04","0x00056D40")}
    actual_record_methods={(row.get("callsite"),row.get("selected_slot_index"),
        row.get("selected_slot_link"),row.get("selected_target_link"))
        for row in record_method_contracts}
    if (actual_record_methods!=expected_record_methods or
            any(row.get("vtable_link")!="0x00111EA4" or row.get("slot_count")!=29 or
                len(row.get("entries",[]))!=29 for row in record_method_contracts)):
        raise SystemExit(f"FUN_00056B60 record callbacks lack their LE vtable contracts: {record_method_contracts!r}")
    print("TRACE canonical FUN_00056B60 table=00111EA4[29] calls=00056C72/slot10->0006A300,00056CD8/slot24->00056D40 complete_fixups=1")
    entity_status_contracts=[row for row in lift_evidence.get("verified_le_vtable_calls",[])
                             if row.get("callsite")=="0x00058681"]
    expected_entity_status_contracts={
        ("0x00111D04",60,"0x00111DA8","0x00047D60"),
        ("0x00112060",52,"0x00112104","0x00059CF0"),
        ("0x001123BC",48,"0x00112460","0x00059CF0"),
        # V33_B: Effect vtable 0x1121E4 slot 41 -> 0x57F60 (observed live, Madami)
        ("0x001121E4",64,"0x00112288","0x00057F60")}
    actual_entity_status_contracts={(row.get("vtable_link"),row.get("slot_count"),
        row.get("selected_slot_link"),row.get("selected_target_link")) for row in entity_status_contracts}
    if (actual_entity_status_contracts!=expected_entity_status_contracts or
            any(len(row.get("entries",[]))!=row.get("slot_count") for row in entity_status_contracts)):
        raise SystemExit(f"FUN_00058330 entity status dispatch lacks both full LE vtable contracts: {entity_status_contracts!r}")
    print("TRACE canonical FUN_00058330 status method site=00058681 vtables=00111D04[60]=>00047D60,00112060[52]=>00059CF0,001123BC[48]=>00059CF0 slot=41 fixup_pair_guards=1")
    entity_tail_contracts=[row for row in lift_evidence.get("verified_le_vtable_calls",[])
                           if row.get("callsite") in {"0x00058BBD","0x00058BD4","0x00058BE0"} and
                              row.get("vtable_link")=="0x001123BC"]
    expected_entity_tail={
        ("0x00058BBD",34,"0x00112444","0x0008A720"),
        ("0x00058BD4",1,"0x001123C0","0x0006A2E0"),
        ("0x00058BE0",28,"0x0011242C","0x00095C80")}
    actual_entity_tail={(row.get("callsite"),row.get("selected_slot_index"),
        row.get("selected_slot_link"),row.get("selected_target_link")) for row in entity_tail_contracts}
    if (actual_entity_tail!=expected_entity_tail or
            any(row.get("slot_count")!=48 or len(row.get("entries",[]))!=48 for row in entity_tail_contracts)):
        raise SystemExit(f"FUN_00058330 tail dispatch lacks the three complete Thing-vtable LE contracts: {entity_tail_contracts!r}")
    print("TRACE canonical FUN_00058330 tail methods sites=00058BBD/00058BD4/00058BE0 slots=34/1/28 targets=0008A720/0006A2E0/00095C80 full_vtable=001123BC[48]")
    creature_tail_contracts=[row for row in lift_evidence.get("verified_le_vtable_calls",[])
                             if row.get("callsite") in {"0x00058BBD","0x00058BD4","0x00058BE0"} and
                                row.get("vtable_link")=="0x00111D04"]
    expected_creature_tail={
        ("0x00058BBD",34,"0x00111D8C","0x00047BF0"),
        ("0x00058BD4",1,"0x00111D08","0x0006A2E0"),
        ("0x00058BE0",28,"0x00111D74","0x0006A2A0")}
    actual_creature_tail={(row.get("callsite"),row.get("selected_slot_index"),
        row.get("selected_slot_link"),row.get("selected_target_link")) for row in creature_tail_contracts}
    if (actual_creature_tail!=expected_creature_tail or
            any(row.get("slot_count")!=60 or len(row.get("entries",[]))!=60 for row in creature_tail_contracts)):
        raise SystemExit(f"FUN_00058330 tail dispatch lacks the three complete Creature-vtable LE contracts: {creature_tail_contracts!r}")
    print("TRACE canonical FUN_00058330 tail Creature methods sites=00058BBD/00058BD4/00058BE0 slots=34/1/28 targets=00047BF0/0006A2E0/0006A2A0 full_vtable=00111D04[60]")
    plspec_tail_contracts=[row for row in lift_evidence.get("verified_le_vtable_calls",[])
                           if row.get("callsite") in {"0x00058BBD","0x00058BD4","0x00058BE0"} and
                              row.get("vtable_link")=="0x00112060"]
    expected_plspec_tail={
        ("0x00058BBD",34,"0x001120E8","0x0008A720"),
        ("0x00058BD4",1,"0x00112064","0x0006A2E0"),
        ("0x00058BE0",28,"0x001120D0","0x0006A2A0")}
    actual_plspec_tail={(row.get("callsite"),row.get("selected_slot_index"),
        row.get("selected_slot_link"),row.get("selected_target_link")) for row in plspec_tail_contracts}
    if (actual_plspec_tail!=expected_plspec_tail or
            any(row.get("slot_count")!=52 or len(row.get("entries",[]))!=52 for row in plspec_tail_contracts)):
        raise SystemExit(f"FUN_00058330 tail dispatch lacks the three complete PlSpec-vtable LE contracts: {plspec_tail_contracts!r}")
    print("TRACE canonical FUN_00058330 tail PlSpec methods sites=00058BBD/00058BD4/00058BE0 slots=34/1/28 targets=0008A720/0006A2E0/0006A2A0 full_vtable=00112060[52]")
    packet_action_rows=[row for row in lift_evidence.get("verified_indirect_targets",[])
                        if row.get("callsite")=="0x00080921"]
    expected_packet_action=("0x0006A230",f"0x{image.link_to_linear(0x6A230):08X}")
    if {(row.get("link_target"),row.get("guest_target")) for row in packet_action_rows} != {expected_packet_action}:
        raise SystemExit(f"process_packets action/status virtual call lacks its LE fixup-backed target: {packet_action_rows!r}")
    print("TRACE canonical process_packets creature query site=00080921 slot=00111D60 target=0006A230 live_target_guard=1")
    movement_method_rows=[row for row in lift_evidence.get("verified_indirect_targets",[])
                          if row.get("callsite")=="0x0005AB28"]
    expected_movement_methods={
        ("0x00059D80",f"0x{image.link_to_linear(0x59D80):08X}"),
        # The live shared Thing vtable at 0x1123BC also fixes its +0xB4
        # method slot (index 45) to 0x11270. This is a second valid class
        # implementation at the same original callsite, not a substitute for
        # the existing 0x111DB8 -> 0x59D80 path.
        ("0x00011270",f"0x{image.link_to_linear(0x11270):08X}")}
    if {(row.get("link_target"),row.get("guest_target")) for row in movement_method_rows} != expected_movement_methods:
        raise SystemExit(f"entity movement virtual call lacks its LE fixup-backed target: {movement_method_rows!r}")
    movement_vtable_rows=[row for row in lift_evidence.get("verified_le_vtable_calls",[])
                          if row.get("callsite")=="0x0005AB28" and row.get("vtable_link")=="0x001123BC"]
    if (len(movement_vtable_rows)!=1 or movement_vtable_rows[0].get("selected_slot_index")!=45 or
            movement_vtable_rows[0].get("selected_slot_link")!="0x00112470" or
            movement_vtable_rows[0].get("selected_target_link")!="0x00011270" or
            len(movement_vtable_rows[0].get("entries",[]))!=48):
        raise SystemExit(f"Thing movement vtable slot 45 at 0x5AB28 is not backed by its full LE table: {movement_vtable_rows!r}")
    print("TRACE canonical entity movement method site=0005AB28 alternatives=00111DB8->00059D80/00112470->00011270 LE-vtable-pair-guard=1")
    entity_update_rows=[row for row in lift_evidence.get("verified_indirect_targets",[])
                        if row.get("callsite") in {"0x00059D9F","0x00059DAB","0x00059E30"}]
    expected_entity_update={
        ("0x00059D9F","0x0006A2E0",f"0x{image.link_to_linear(0x6A2E0):08X}"),
        ("0x00059DAB","0x00046B90",f"0x{image.link_to_linear(0x46B90):08X}"),
        ("0x00059DAB","0x0008A730",f"0x{image.link_to_linear(0x8A730):08X}"),
        ("0x00059DAB","0x00095C90",f"0x{image.link_to_linear(0x95C90):08X}"),
        ("0x00059E30","0x00095CA0",f"0x{image.link_to_linear(0x95CA0):08X}"),
        ("0x00059E30","0x0006A240",f"0x{image.link_to_linear(0x6A240):08X}")}
    if {(row.get("callsite"),row.get("link_target"),row.get("guest_target"))
        for row in entity_update_rows} != expected_entity_update:
        raise SystemExit(f"FUN_00059D80 does not have its complete LE-fixup-backed virtual set: {entity_update_rows!r}")
    print("TRACE canonical FUN_00059D80 vtable batch sites=00059D9F/00059DAB/00059E30 targets=0006A2E0/{00046B90,0008A730,00095C90}/0006A240/00095CA0 tables=00111D04[60]/00112060[52]/001123BC[48] runtime_guards=paired_LE_fixups")
    entity_surface_rows=[row for row in lift_evidence.get("verified_indirect_targets",[])
                         if row.get("callsite")=="0x00058681"]
    expected_entity_surface={
        ("0x00047D60",f"0x{image.link_to_linear(0x47D60):08X}"),
        ("0x00059CF0",f"0x{image.link_to_linear(0x59CF0):08X}"),
        # V33_B: Effect vtable 0x1121E4 slot 41 -> 0x57F60 (observed live, Madami)
        ("0x00057F60",f"0x{image.link_to_linear(0x57F60):08X}")}
    if {(row.get("link_target"),row.get("guest_target")) for row in entity_surface_rows} != expected_entity_surface:
        raise SystemExit(f"FUN_00058330 entity method lacks its LE fixup-backed target: {entity_surface_rows!r}")
    print("TRACE canonical FUN_00058330 entity methods site=00058681 slots=00111DA8/00112104 targets=00047D60/00059CF0 fixup_pair_guards=1")
    entity_surface_update_rows=[row for row in lift_evidence.get("verified_indirect_targets",[])
                                if row.get("callsite")=="0x00047DC2"]
    expected_entity_surface_update=("0x0006A240",f"0x{image.link_to_linear(0x6A240):08X}")
    if {(row.get("link_target"),row.get("guest_target")) for row in entity_surface_update_rows} != {expected_entity_surface_update}:
        raise SystemExit(f"FUN_00047D60 entity method lacks its LE-fixup-backed target: {entity_surface_update_rows!r}")
    print("TRACE canonical FUN_00047D60 entity method site=00047DC2 slot=00111D14 target=0006A240 runtime_guard=1")
    entity_distance_rows=[row for row in lift_evidence.get("verified_indirect_targets",[])
                          if row.get("callsite")=="0x00059D42"]
    expected_entity_distance={
        ("0x00047700",f"0x{image.link_to_linear(0x47700):08X}"),
        ("0x00059B60",f"0x{image.link_to_linear(0x59B60):08X}"),
        ("0x00011380",f"0x{image.link_to_linear(0x11380):08X}")}
    if {(row.get("link_target"),row.get("guest_target")) for row in entity_distance_rows} != expected_entity_distance:
        raise SystemExit(f"FUN_00059CF0 movement query lacks its LE-fixup-backed target: {entity_distance_rows!r}")
    print("TRACE canonical FUN_00059CF0 movement queries site=00059D42 slots=00111DBC/00112118 targets=00047700/00059B60 exact_LE_fixups=1")
    eligibility_contracts=[row for row in lift_evidence.get("verified_le_vtable_calls",[])
                            if row.get("callsite")=="0x00059BA6"]
    expected_eligibility={
        ("0x00111D04",60,"0x00111D14","0x0006A240"),
        ("0x00112060",52,"0x00112070","0x0006A240")}
    actual_eligibility={(row.get("vtable_link"),row.get("slot_count"),row.get("selected_slot_link"),
                         row.get("selected_target_link")) for row in eligibility_contracts}
    if actual_eligibility!=expected_eligibility:
        raise SystemExit(f"FUN_00059B60 eligibility slot lacks both fixup-backed vtable variants: {eligibility_contracts!r}")
    print("TRACE canonical PlSpec eligibility site=00059BA6 bases=00111D04/00112060 slot=4 target=0006A240")
    action_contracts=[row for row in lift_evidence.get("verified_le_vtable_calls",[])
                      if row.get("callsite")=="0x00044932"]
    expected_action_contracts={
        ("0x00111D04",60,"0x00111D84","0x00047360"),
        ("0x00112060",52,"0x001120E0","0x0003EC70")}
    actual_action_contracts={(row.get("vtable_link"),row.get("slot_count"),
        row.get("selected_slot_link"),row.get("selected_target_link")) for row in action_contracts}
    if actual_action_contracts!=expected_action_contracts:
        raise SystemExit(f"FUN_00044570 PlSpec action method lacks exact LE vtable pairs: {action_contracts!r}")
    print("TRACE canonical entity action state site=00044932 slot=32 bases=00111D04/00112060 targets=00047360/0003EC70")
    movement_status_rows=[row for row in lift_evidence.get("verified_indirect_targets",[])
                           if row.get("callsite")=="0x0004781B"]
    expected_movement_status=("0x0006A240",f"0x{image.link_to_linear(0x6A240):08X}")
    if {(row.get("link_target"),row.get("guest_target")) for row in movement_status_rows} != {expected_movement_status}:
        raise SystemExit(f"FUN_00047700 movement status call lacks its LE-fixup-backed target: {movement_status_rows!r}")
    print("TRACE canonical FUN_00047700 movement status site=0004781B slot=00111D14 target=0006A240 runtime_guard=1")
    movement_helper_status_rows=[row for row in lift_evidence.get("verified_indirect_targets",[])
                                 if row.get("callsite")=="0x00057F67"]
    expected_movement_helper_status={expected_movement_status,
        ("0x00095CA0",f"0x{image.link_to_linear(0x95CA0):08X}")}
    if {(row.get("link_target"),row.get("guest_target")) for row in movement_helper_status_rows} != expected_movement_helper_status:
        raise SystemExit(f"FUN_00057F60 movement status call lacks its LE-fixup-backed target: {movement_helper_status_rows!r}")
    print("TRACE canonical FUN_00057F60 movement status site=00057F67 slots=Creature/PlSpec+0x10 and Thing+0x10 targets=0006A240/00095CA0 runtime_guard=paired_LE_fixups")
    effect_call_rows=[row for row in lift_evidence.get("verified_indirect_targets",[])
                      if row.get("callsite")=="0x00088146"]
    expected_effect_call=("0x0006A2E0",f"0x{image.link_to_linear(0x6A2E0):08X}")
    effect_vtable_fixup_sources=(0x111D08,0x112064,0x1121E8,0x112300,0x1123C0)
    effect_vtable_fixups={f.source_link:f for f in image.fixups
                          if f.source_link in effect_vtable_fixup_sources}
    code_bytes_88146=image.object_data(1)
    code_obj_88146=image.objects[0]
    action14_building_vtable=next((row for row in lift_evidence.get("verified_le_vtable_calls",[])
                         if row.get("callsite")=="0x00039BEF" and
                            row.get("vtable_link")=="0x00111DFC"),None)
    action14_slot_fixup=next((f for f in image.fixups if f.source_link==0x111E40),None)
    if (code_bytes_88146[0x39BEF-code_obj_88146.base:0x39BF2-code_obj_88146.base]!=bytes.fromhex("FF 57 44") or
            action14_building_vtable is None or action14_building_vtable.get("slot_count")!=40 or
            not any(entry.get("source_link")=="0x00111E40" and
                    entry.get("target_link")=="0x00069E20"
                    for entry in action14_building_vtable.get("entries",[])) or
            action14_slot_fixup is None or action14_slot_fixup.source_type!=0x07 or
            action14_slot_fixup.target_object!=1 or
            image.objects[0].base+action14_slot_fixup.target_offset!=0x69E20):
        raise SystemExit(f"Action 0x14 building callback at 0x39BEF lacks its canonical vtable fixup: {action14_building_vtable!r}")
    if ({(row.get("link_target"),row.get("guest_target")) for row in effect_call_rows} != {expected_effect_call} or
            code_bytes_88146[0x88140-code_obj_88146.base:0x88143-code_obj_88146.base] != bytes.fromhex("8B 52 23") or
            code_bytes_88146[0x88143-code_obj_88146.base:0x88149-code_obj_88146.base] != bytes.fromhex("8B 45 12 FF 52 04") or
            code_bytes_88146[0x6A2E0-code_obj_88146.base:0x6A2EB-code_obj_88146.base] != _OrigDigest("9a1d556793249c8e6b0443d233bb5ae8feb3c62df635ba5c200f042c29c015d6",11) or
            set(effect_vtable_fixups) != set(effect_vtable_fixup_sources) or
            any((effect_vtable_fixups[src].source_type != 0x07 or
                 effect_vtable_fixups[src].target_object != 1 or
                 image.objects[effect_vtable_fixups[src].target_object-1].base+
                     effect_vtable_fixups[src].target_offset != 0x6A2E0)
                for src in effect_vtable_fixup_sources)):
        raise SystemExit(f"BioGame effect method target at 0x88146 is not backed by the live-contract and original LE checks: rows={effect_call_rows!r} fixups={effect_vtable_fixups!r}")
    print("TRACE BioGame effect call site=00088146 operand=[EDX+4] target=0006A2E0 code_bytes=52-89-C2-8B-40-27-2B-42-11-5A-C3 corroborating_LE_vtable_fixups=5 runtime_equal_guard=1")
    effect_sound_rows=[row for row in lift_evidence.get("verified_indirect_targets",[])
                       if row.get("callsite")=="0x00088179"]
    effect_sound_fixup=next((f for f in image.fixups if f.source_link==0x112228),None)
    effect_sound_bytes=original_code[0x69E20-original_code_obj.base:0x69E40-original_code_obj.base]
    if ({(row.get("link_target"),row.get("guest_target")) for row in effect_sound_rows} !=
            {( "0x00069E20",f"0x{image.link_to_linear(0x69E20):08X}")} or
            code_bytes_88146[0x88176-code_obj_88146.base:0x8817C-code_obj_88146.base] != bytes.fromhex("8B 45 12 FF 57 44") or
            effect_sound_fixup is None or effect_sound_fixup.source_type!=0x07 or
            effect_sound_fixup.target_object!=1 or effect_sound_fixup.target_offset!=0x59E20 or
            image.objects[effect_sound_fixup.target_object-1].base+effect_sound_fixup.target_offset!=0x69E20 or
            effect_sound_bytes!=_OrigDigest("d48affc69d87f0d61c14ae0cf50d0b68d2fd7fd4adf1b1b9a930ece46128f9d6",32)):
        raise SystemExit(f"BioGame effect sound callback at 0x88179 is not justified by exact LE bytes/fixup: rows={effect_sound_rows!r} fixup={effect_sound_fixup!r}")
    effect_sound_dis=list(gadget_dis.disassemble_at(0x69E20,max_bytes=0x20))
    if not effect_sound_dis or effect_sound_dis[0].mnemonic.lower()!="push" or effect_sound_dis[-1].address<0x69E30:
        raise SystemExit("Capstone did not decode the canonical 0x69E20 callback prefix")
    print("TRACE BioGame effect sound call site=00088179 operand=[EDI+44] slot=00112228 target=00069E20 guest="
          f"{image.link_to_linear(0x69E20):08X} object3_SRC_OFFSET32=1 code_prefix=56-8B-74-24-0C-56-0F-B6-74-24-0C-56-0F-BE-C9-51-31-C9-88-D9-0F-BE-DA-89-C2-B8-4C-DF-16-00-E8-3D runtime_equal_guard=1")
    # Same LE slot reached naturally after FUN_00076070 at 0x8803A.
    effect_activate_rows=[row for row in lift_evidence.get("verified_indirect_targets",[])
                          if row.get("callsite")=="0x0008803A"]
    effect_activate_fixup=next((f for f in image.fixups if f.source_link==0x112228),None)
    if ({(row.get("link_target"),row.get("guest_target")) for row in effect_activate_rows} !=
            {( "0x00069E20",f"0x{image.link_to_linear(0x69E20):08X}")} or
            code_bytes_88146[0x88037-code_obj_88146.base:0x8803D-code_obj_88146.base] != bytes.fromhex("8B 45 12 FF 56 44") or
            effect_activate_fixup is None or effect_activate_fixup.source_type!=0x07 or
            effect_activate_fixup.target_object!=1 or effect_activate_fixup.target_offset!=0x59E20 or
            image.objects[effect_activate_fixup.target_object-1].base+effect_activate_fixup.target_offset!=0x69E20):
        raise SystemExit(f"post-activation effect method at 0x8803A lacks exact instruction/fixup evidence: rows={effect_activate_rows!r} fixup={effect_activate_fixup!r}")
    effect_activate_dis=list(gadget_dis.disassemble_at(0x69E20,max_bytes=0x20))
    if not effect_activate_dis or effect_activate_dis[0].mnemonic.lower()!="push":
        raise SystemExit("Capstone did not decode the canonical 0x69E20 target of the post-activation call")
    print("TRACE BioGame post-activation effect call site=0008803A operand=[ESI+44] slot=00112228 target=00069E20 canonical_object3_SRC_OFFSET32=1 runtime_equal_guard=1")
    entity_field_rows=[row for row in lift_evidence.get("verified_indirect_targets",[])
                       if row.get("callsite")=="0x0004B017"]
    expected_entity_field=("0x0006A040",f"0x{image.link_to_linear(0x6A040):08X}")
    if {(row.get("link_target"),row.get("guest_target")) for row in entity_field_rows} != {expected_entity_field}:
        raise SystemExit(f"FUN_0004B000 entity-field query lacks its LE-fixup-backed target: {entity_field_rows!r}")
    print("TRACE canonical FUN_0004B000 entity-field query site=0004B017 slot=00111DB0 target=0006A040 runtime_guard=1")
    entity_helper_batch={
        "0x0004B034":(0x6A070,0x111D6C),
        "0x0004B04E":(0x6A040,0x111DB0),
        "0x0004B05D":(0x6A030,0x111DB4),
        "0x0004B162":(0x58EF0,0x111DA0),
    }
    for site,(link_target,slot) in entity_helper_batch.items():
        rows=[row for row in lift_evidence.get("verified_indirect_targets",[])
              if row.get("callsite")==site]
        expected=(f"0x{link_target:08X}",f"0x{image.link_to_linear(link_target):08X}")
        if {(row.get("link_target"),row.get("guest_target")) for row in rows}!={expected}:
            raise SystemExit(f"entity-helper batch call {site} lacks its LE-fixup target {expected}: {rows!r}")
        print(f"TRACE entity-helper batch site={site[2:]} slot={slot:08X} target={link_target:08X} runtime_guard=1")
    entity_state_methods={
        "0x0004AB54":0x6A290,"0x0004AC41":0x6A290,
        "0x0004ADED":0x6A290,"0x0004AE01":0x6A290,
        "0x0004AE21":0x6A240,"0x0004AE93":0x6A2E0,
        "0x0004AF70":0x6A290,
    }
    for site,link_target in entity_state_methods.items():
        rows=[row for row in lift_evidence.get("verified_indirect_targets",[])
              if row.get("callsite")==site]
        expected=(f"0x{link_target:08X}",f"0x{image.link_to_linear(link_target):08X}")
        if {(row.get("link_target"),row.get("guest_target")) for row in rows}!={expected}:
            raise SystemExit(f"FUN_0004AB10 state-method call {site} lacks its exact LE-fixup target {expected}: {rows!r}")
        print(f"TRACE entity-state method site={site[2:]} target={link_target:08X} runtime_guard=1")
    animation_state_rows=[row for row in lift_evidence.get("verified_indirect_targets",[])
                          if row.get("callsite")=="0x00078BA1"]
    expected_animation_state=("0x0006EE40",f"0x{image.link_to_linear(0x6EE40):08X}")
    map_effect_query=("0x0006A2E0",f"0x{image.link_to_linear(0x6A2E0):08X}")
    map_effect_fixup=next((f for f in image.fixups if f.source_link==0x1121E8),None)
    if ({(row.get("link_target"),row.get("guest_target")) for row in animation_state_rows}!={expected_animation_state,map_effect_query} or
            map_effect_fixup is None or map_effect_fixup.source_type!=0x07 or
            map_effect_fixup.target_object!=1 or image.objects[0].base+map_effect_fixup.target_offset!=0x6A2E0 or
            code_bytes_88146[0x78BA1-code_obj_88146.base:0x78BA4-code_obj_88146.base]!=bytes.fromhex("FF 52 04")):
        raise SystemExit(f"FUN_00078B30 state accessor lacks its exact LE-fixup target: {animation_state_rows!r}")
    print("TRACE canonical FUN_00078B30 polymorphic method site=00078BA1 operand=[EDX+4] fixup_targets=00111EA8->0006EE40/001121E8->0006A2E0 runtime_guards=2")
    creature_vtable_link=0x111D04
    creature_vtable_guest=image.link_to_linear(creature_vtable_link)
    creature_height_slot=creature_vtable_link+0x04
    creature_eligible_slot=creature_vtable_link+0x20
    creature_height_fixup=next((f for f in image.fixups if f.source_link==creature_height_slot),None)
    creature_eligible_fixup=next((f for f in image.fixups if f.source_link==creature_eligible_slot),None)
    creature_height_target=(image.objects[creature_height_fixup.target_object-1].base+creature_height_fixup.target_offset
                            if creature_height_fixup else None)
    creature_eligible_target=(image.objects[creature_eligible_fixup.target_object-1].base+creature_eligible_fixup.target_offset
                              if creature_eligible_fixup else None)
    creature_eligibility_rows=[row for row in lift_evidence.get("verified_indirect_targets",[])
                                if row.get("callsite")=="0x00078EE9"]
    creature_eligibility_vtable=next((row for row in lift_evidence.get("verified_le_vtable_calls",[])
                                      if row.get("callsite")=="0x00078EE9" and
                                         row.get("vtable_link")=="0x00111D04"),None)
    creature_height_method_calls={row.get("callsite"):row for row in
                                  lift_evidence.get("verified_le_vtable_calls",[])
                                  if row.get("callsite") in {"0x00046C0D","0x00046C1D"} and
                                     row.get("vtable_link")=="0x00111D04"}
    close_approach_method=next((row for row in lift_evidence.get("verified_le_vtable_calls",[])
                                if row.get("callsite")=="0x00055E03" and
                                   row.get("vtable_link")=="0x00112060"),None)
    close_approach_fixup=fixups_by_source.get(0x1120C8)
    close_approach_target=(image.objects[close_approach_fixup.target_object-1].base+
                           close_approach_fixup.target_offset if close_approach_fixup else None)
    close_approach_switch=next((row for row in lift_evidence.get("indexed_code_jump_tables",[])
                                if row.get("instruction")=="0x00055E20" and
                                   row.get("table_link")=="0x000562C0"),None)
    close_approach_switch_targets=[0x55F15,0x55E28,0x55EDB,0x55F07]
    close_approach_switch_fixups=[fixups_by_source.get(0x562C0+4*i) for i in range(4)]
    creature_eligibility_expected={("0x00046BC0",f"0x{image.link_to_linear(0x46BC0):08X}"),
                                   ("0x0008A500",f"0x{image.link_to_linear(0x8A500):08X}")}
    plant_vtable_fixup=fixups_by_source.get(0x111EC4)
    plant_vtable_target=(image.objects[plant_vtable_fixup.target_object-1].base+plant_vtable_fixup.target_offset
                         if plant_vtable_fixup else None)
    plant_vtable_evidence=next((row for row in lift_evidence.get("verified_le_vtable_calls",[])
                                if row.get("callsite")=="0x00078EE9" and
                                   row.get("vtable_link")=="0x00111EA4"),None)
    plant_sprite_query=next((row for row in lift_evidence.get("verified_le_vtable_calls",[])
                             if row.get("callsite")=="0x0006EDF3" and
                                row.get("vtable_link")=="0x00111EA4"),None)
    plant_vtable_fixups=[fixups_by_source.get(0x111EA4+4*i) for i in range(29)]
    plant_vtable_targets={(row.get("link_target"),row.get("guest_target"))
                          for row in creature_eligibility_rows}
    putthing_callsite_expected=creature_eligibility_expected | {
        ("0x0006EDE0",f"0x{image.link_to_linear(0x6EDE0):08X}"),
        # V30_B: zone-marker Thing (vtable 0x1123BC slot 8 -> 0x95930), observed live at 0x78EE9.
        ("0x00095930",f"0x{image.link_to_linear(0x95930):08X}")}
    creature_obj3=image.object_data(3)
    creature_vtable_bytes=bytes(creature_obj3[creature_vtable_link-image.objects[2].base:
                                               creature_vtable_link-image.objects[2].base+0x24])
    if (creature_height_fixup is None or creature_height_fixup.source_type!=0x07 or
            creature_height_fixup.target_object!=1 or creature_height_target!=0x6A2E0 or
            creature_eligible_fixup is None or creature_eligible_fixup.source_type!=0x07 or
            creature_eligible_fixup.target_object!=1 or creature_eligible_target!=0x46BC0 or
            creature_eligibility_vtable is None or
            creature_eligibility_vtable.get("slot_count")!=60 or
            creature_eligibility_vtable.get("selected_slot_index")!=8 or
            creature_eligibility_vtable.get("selected_slot_link")!="0x00111D24" or
            creature_eligibility_vtable.get("selected_target_link")!="0x00046BC0" or
            creature_height_method_calls.get("0x00046C0D",{}).get("selected_slot_link")!="0x00111D08" or
            creature_height_method_calls.get("0x00046C0D",{}).get("selected_target_link")!="0x0006A2E0" or
            creature_height_method_calls.get("0x00046C1D",{}).get("selected_slot_link")!="0x00111D20" or
            creature_height_method_calls.get("0x00046C1D",{}).get("selected_target_link")!="0x00069E50" or
            close_approach_method is None or close_approach_method.get("slot_count")!=52 or
            close_approach_method.get("selected_slot_index")!=26 or
            close_approach_method.get("selected_slot_link")!="0x001120C8" or
            close_approach_method.get("selected_target_link")!="0x0008A530" or
            close_approach_fixup is None or close_approach_fixup.source_type!=0x07 or
            close_approach_fixup.target_object!=1 or close_approach_target!=0x8A530 or
            close_approach_switch is None or close_approach_switch.get("count")!=4 or
            [int(x,16) for x in close_approach_switch.get("targets_link",[])]!=close_approach_switch_targets or
            any(f is None or f.source_type!=0x07 or f.target_object!=1 or
                image.objects[f.target_object-1].base+f.target_offset!=close_approach_switch_targets[i]
                for i,f in enumerate(close_approach_switch_fixups)) or
            code_bytes_88146[0x55E03-code_obj_88146.base:0x55E06-code_obj_88146.base]!=bytes.fromhex("FF 52 68") or
            len(creature_vtable_bytes)!=0x24 or
            {(row.get("link_target"),row.get("guest_target")) for row in creature_eligibility_rows}!=putthing_callsite_expected or
            plant_vtable_fixup is None or plant_vtable_fixup.source_type!=0x07 or
            plant_vtable_fixup.target_object!=1 or plant_vtable_target!=0x6EDE0 or
            plant_vtable_evidence is None or plant_vtable_evidence.get("slot_count")!=29 or
            plant_vtable_evidence.get("selected_slot_link")!="0x00111EC4" or
            plant_vtable_evidence.get("selected_target_link")!="0x0006EDE0" or
            plant_sprite_query is None or plant_sprite_query.get("slot_count")!=29 or
            plant_sprite_query.get("selected_slot_link")!="0x00111EC0" or
            plant_sprite_query.get("selected_target_link")!="0x00069E50" or
            any(f is None or f.source_type!=0x07 or f.target_object!=1
                for f in plant_vtable_fixups) or
            ("0x0006EDE0",f"0x{image.link_to_linear(0x6EDE0):08X}") not in plant_vtable_targets or
            code_bytes_88146[0x78EE9-code_obj_88146.base:0x78EEC-code_obj_88146.base]!=bytes.fromhex("FF 55 20")):
        raise SystemExit("PutThingInBucket eligibility callbacks are not backed by their exact LE fixups")
    print("TRACE canonical TT_CREATURE vtable link=00111D04 guest=002EBD04 projection_slot=00111D08->0006A2E0 eligibility_slot=00111D24->00046BC0 exact_LE_fixups=2 runtime_guards=1")
    print("TRACE canonical plant callback vtable link=00111EA4 slot_count=29 dispatch=00111EC4->0006EDE0 target_offset=0005EDE0 callsite=00078EE9 exact_LE_fixups=1 runtime_guard=1")
    plspec_map_fixup=next((f for f in image.fixups if f.source_link==0x112080),None)
    plspec_map_target=(image.objects[plspec_map_fixup.target_object-1].base+plspec_map_fixup.target_offset
                       if plspec_map_fixup else None)
    plspec_hit_vtable=next((row for row in lift_evidence.get("verified_le_vtable_calls",[])
                            if row.get("callsite")=="0x00078EE9" and
                               row.get("vtable_link")=="0x00112060"),None)
    plspec_map_rows={(row.get("link_target"),row.get("guest_target")) for row in creature_eligibility_rows
                     if row.get("link_target") in {"0x00046BC0","0x0008A500"}}
    if (plspec_map_fixup is None or plspec_map_fixup.source_type!=0x07 or
            plspec_map_fixup.target_object!=1 or plspec_map_target!=0x8A500 or
            plspec_hit_vtable is None or plspec_hit_vtable.get("slot_count")!=52 or
            plspec_hit_vtable.get("selected_slot_link")!="0x00112080" or
            plspec_hit_vtable.get("selected_target_link")!="0x0008A500" or
            len(creature_obj3[0x112060-image.objects[2].base:0x112084-image.objects[2].base])!=0x24 or
            code_bytes_88146[0x78EE9-code_obj_88146.base:0x78EEC-code_obj_88146.base]!=bytes.fromhex("FF 55 20") or
            plspec_map_rows!=creature_eligibility_expected):
        raise SystemExit(f"PlSpec map eligibility callback lacks its exact LE fixup: {plspec_map_fixup!r} {plspec_map_rows!r}")
    print("TRACE canonical PlSpec vtable link=00112060 slot=00112080->0008A500 opcode=FF5520 LE_fixup=object3_to_object1 runtime_guard=1")
    plspec_index_slot=0x11207C
    plspec_index_fixup=next((f for f in image.fixups if f.source_link==plspec_index_slot),None)
    plspec_index_target=(image.objects[plspec_index_fixup.target_object-1].base+plspec_index_fixup.target_offset
                         if plspec_index_fixup else None)
    if (plspec_index_fixup is None or plspec_index_fixup.source_type!=0x07 or
            plspec_index_fixup.target_object!=1 or plspec_index_target!=0x69E50 or
            len(creature_obj3[0x112060-image.objects[2].base:0x112060-image.objects[2].base+52*4])!=52*4 or
            {(row.get("link_target"),row.get("guest_target")) for row in lift_evidence.get("verified_indirect_targets",[])
             if row.get("callsite")=="0x0008A513"}!={("0x00069E50",f"0x{image.link_to_linear(0x69E50):08X}")}):
        raise SystemExit(f"PlSpec indexed-property callback lacks its exact LE vtable fixup: {plspec_index_fixup!r}")
    print("TRACE canonical PlSpec property callback site=0008A513 slot=0011207C->00069E50 LE_fixup=object3_to_object1 runtime_guard=1")
    plspec_command_slot=0x1120A4
    plspec_command_fixup=next((f for f in image.fixups if f.source_link==plspec_command_slot),None)
    plspec_command_target=(image.objects[plspec_command_fixup.target_object-1].base+plspec_command_fixup.target_offset
                           if plspec_command_fixup else None)
    if (plspec_command_fixup is None or plspec_command_fixup.source_type!=0x07 or
            plspec_command_fixup.target_object!=1 or plspec_command_target!=0x69E20 or
            code_bytes_88146[0x21830-code_obj_88146.base:0x21833-code_obj_88146.base]!=bytes.fromhex("FF 57 44") or
            {(row.get("link_target"),row.get("guest_target")) for row in lift_evidence.get("verified_indirect_targets",[])
             if row.get("callsite")=="0x00021830"}!={("0x00069E20",f"0x{image.link_to_linear(0x69E20):08X}")}):
        raise SystemExit(f"IFCPlanetside PlSpec command callback lacks its exact LE vtable fixup: {plspec_command_fixup!r}")
    print("TRACE canonical IFCPlanetside command method site=00021830 operand=[EDI+44] slot=001120A4->00069E20 LE_fixup=object3_to_object1 runtime_guard=1")
    action_query_rows=[row for row in lift_evidence.get("verified_indirect_targets",[])
                       if row.get("callsite")=="0x000791E9"]
    action_query_fixup=next((f for f in image.fixups if f.source_link==0x112250),None)
    action_query_active_fixup=next((f for f in image.fixups if f.source_link==0x111F10),None)
    hover_action_query_fixup=next((f for f in image.fixups if f.source_link==0x1120CC),None)
    plant_hover_action_query_fixup=next((f for f in image.fixups if f.source_link==0x111F10),None)
    plant_thing_query_fixup=next((f for f in image.fixups if f.source_link==0x111EC8),None)
    selected_thing_query_fixup=next((f for f in image.fixups if f.source_link==0x111E68),None)
    expected_action_queries={("0x0006A2C0",f"0x{image.link_to_linear(0x6A2C0):08X}"),
                             ("0x0006ED30",f"0x{image.link_to_linear(0x6ED30):08X}")}
    if (code_bytes_88146[0x791E9-code_obj_88146.base:0x791EC-code_obj_88146.base]!=bytes.fromhex("FF 52 6C") or
            action_query_fixup is None or action_query_fixup.source_type!=0x07 or
            action_query_fixup.target_object!=1 or image.objects[0].base+action_query_fixup.target_offset!=0x6A2C0 or
            action_query_active_fixup is None or action_query_active_fixup.source_type!=0x07 or
            action_query_active_fixup.target_object!=1 or image.objects[0].base+action_query_active_fixup.target_offset!=0x6ED30 or
            hover_action_query_fixup is None or hover_action_query_fixup.source_type!=0x07 or
            hover_action_query_fixup.target_object!=1 or image.objects[0].base+hover_action_query_fixup.target_offset!=0x6A2C0 or
            plant_hover_action_query_fixup is None or plant_hover_action_query_fixup.source_type!=0x07 or
            plant_hover_action_query_fixup.target_object!=1 or image.objects[0].base+plant_hover_action_query_fixup.target_offset!=0x6ED30 or
            code_bytes_88146[0x79155-code_obj_88146.base:0x79158-code_obj_88146.base]!=bytes.fromhex("FF 52 6C") or
            code_bytes_88146[0x6ED30-code_obj_88146.base:0x6ED33-code_obj_88146.base]!=bytes.fromhex("B0 01 C3") or
            {(row.get("link_target"),row.get("guest_target")) for row in action_query_rows}!=expected_action_queries or
            {(row.get("link_target"),row.get("guest_target")) for row in lift_evidence.get("verified_indirect_targets",[])
             if row.get("callsite")=="0x00079155"}!={
                ("0x0006A2C0",f"0x{image.link_to_linear(0x6A2C0):08X}"),
                ("0x0006ED30",f"0x{image.link_to_linear(0x6ED30):08X}")} or
            code_bytes_88146[0x7949D-code_obj_88146.base:0x794A0-code_obj_88146.base]!=bytes.fromhex("FF 52 6C") or
            selected_thing_query_fixup is None or selected_thing_query_fixup.source_type!=0x07 or
            selected_thing_query_fixup.target_object!=1 or
            image.objects[0].base+selected_thing_query_fixup.target_offset!=0x6ED30 or
            {(row.get("link_target"),row.get("guest_target")) for row in lift_evidence.get("verified_indirect_targets",[])
             if row.get("callsite")=="0x0007949D"}!={
                ("0x0006A2C0",f"0x{image.link_to_linear(0x6A2C0):08X}"),
                ("0x0006ED30",f"0x{image.link_to_linear(0x6ED30):08X}")} or
            code_bytes_88146[0x79178-code_obj_88146.base:0x7917B-code_obj_88146.base]!=bytes.fromhex("FF 51 24") or
            plant_thing_query_fixup is None or plant_thing_query_fixup.source_type!=0x07 or
            plant_thing_query_fixup.target_object!=1 or image.objects[0].base+plant_thing_query_fixup.target_offset!=0x6ED40 or
            {(row.get("link_target"),row.get("guest_target")) for row in lift_evidence.get("verified_indirect_targets",[])
             if row.get("callsite")=="0x00079178"}!={
                ("0x0006ED40",f"0x{image.link_to_linear(0x6ED40):08X}")}):
        raise SystemExit(f"FUN_00079100 action-state virtual query lacks its exact LE-fixup target: {action_query_rows!r} fixup={action_query_fixup!r}")
    print("TRACE canonical FUN_00079100/PutThing hover query site=00079155 operand=[EDX+6C] slots=001120CC->0006A2C0/00111F10->0006ED30(MOV AL,1; RET) exact_LE_fixups=2 runtime_guards=2")
    sweep_query_rows=[row for row in lift_evidence.get("verified_indirect_targets",[])
                      if row.get("callsite")=="0x00079459"]
    if (code_bytes_88146[0x79459-code_obj_88146.base:0x7945C-code_obj_88146.base]!=bytes.fromhex("FF 52 6C") or
            action_query_fixup is None or action_query_fixup.source_type!=0x07 or
            action_query_fixup.target_object!=1 or image.objects[0].base+action_query_fixup.target_offset!=0x6A2C0 or
            {(row.get("link_target"),row.get("guest_target")) for row in sweep_query_rows}!={
                ("0x0006A2C0",f"0x{image.link_to_linear(0x6A2C0):08X}"),
                ("0x0006ED30",f"0x{image.link_to_linear(0x6ED30):08X}")}):
        raise SystemExit(f"FUN_00079320 list-sweep query lacks its exact LE-fixup target: {sweep_query_rows!r}")
    if (action_query_active_fixup is None or action_query_active_fixup.source_type!=0x07 or
            action_query_active_fixup.target_object!=1 or
            image.objects[0].base+action_query_active_fixup.target_offset!=0x6ED30):
        raise SystemExit("FUN_00079320 MapDisplay query slot 0x111F10 no longer fixes to 0x6ED30")
    print("TRACE canonical FUN_00079320 polymorphic list-sweep query site=00079459 operand=[EDX+6C] slots=00112250->0006A2C0/00111F10->0006ED30 runtime_guards=2")
    list_sweep_dispatch_rows=[row for row in lift_evidence.get("verified_indirect_targets",[])
                              if row.get("callsite")=="0x000793EC"]
    list_sweep_dispatch_fixup=next((f for f in image.fixups if f.source_link==0x112208),None)
    if (code_bytes_88146[0x793EC-code_obj_88146.base:0x793EF-code_obj_88146.base]!=bytes.fromhex("FF 55 24") or
            list_sweep_dispatch_fixup is None or list_sweep_dispatch_fixup.source_type!=0x07 or
            list_sweep_dispatch_fixup.target_object!=1 or
            image.objects[0].base+list_sweep_dispatch_fixup.target_offset!=0x85240 or
            {(row.get("link_target"),row.get("guest_target")) for row in list_sweep_dispatch_rows}!={
                (f"0x{target:08X}",f"0x{image.link_to_linear(target):08X}")
                for target in (0x10EA0, 0x45EF0, 0x43BD0, 0x85240)}):
        raise SystemExit(f"FUN_00079320 list-sweep dispatch lacks its exact LE-fixup targets for BioGame and PlSpec: {list_sweep_dispatch_rows!r}")
    list_sweep_method_bytes=original_code[0x85240-original_code_obj.base:0x85240-original_code_obj.base+16]
    if list_sweep_method_bytes!=_OrigDigest("3b488a069ffe3cfa252ec082e971c07e6809d77890c660f812bbc61aeff08240",16):
        raise SystemExit(f"FUN_00079320 list-sweep dispatch target bytes changed: {list_sweep_method_bytes.hex()}")
    plspec_draw_fixup=next((f for f in image.fixups if f.source_link==0x112084),None)
    if (plspec_draw_fixup is None or plspec_draw_fixup.source_type!=0x07 or
            plspec_draw_fixup.target_object!=1 or
            image.objects[0].base+plspec_draw_fixup.target_offset!=0x43BD0):
        raise SystemExit("FUN_00079320 PlSpec slot 0x112084 no longer has the canonical object-1 fixup to 0x43BD0")
    plspec_draw_bytes=original_code[0x43BD0-original_code_obj.base:0x43BD0-original_code_obj.base+16]
    if len(plspec_draw_bytes)!=16 or not any(plspec_draw_bytes):
        raise SystemExit(f"PlSpec list-sweep target 0x43BD0 has no original code bytes: {plspec_draw_bytes.hex()}")
    print(f"TRACE canonical FUN_00079320 list-sweep dispatch site=000793EC operand=[EBP+24] variants=00112208->00085240,00112084->00043BD0,001123D4->00010EA0,00111D1C->00045EF0 fixups=object3->object1 runtime_guard=1 PlSpec_target_bytes={plspec_draw_bytes.hex()}")
    map_display_action_rows=[row for row in lift_evidence.get("verified_indirect_targets",[])
                             if row.get("callsite")=="0x000793BD"]
    map_display_action_fixup=next((f for f in image.fixups if f.source_link==0x111EC8),None)
    if (code_bytes_88146[0x793BD-code_obj_88146.base:0x793C0-code_obj_88146.base]!=bytes.fromhex("FF 55 24") or
            map_display_action_fixup is None or map_display_action_fixup.source_type!=0x07 or
            map_display_action_fixup.target_object!=1 or
            image.objects[0].base+map_display_action_fixup.target_offset!=0x6ED40 or
            {(row.get("link_target"),row.get("guest_target")) for row in map_display_action_rows}!={
                ("0x0006ED40",f"0x{image.link_to_linear(0x6ED40):08X}")}):
        raise SystemExit(f"FUN_00079320 MapDisplay method lacks its exact LE-fixup target: {map_display_action_rows!r}")
    print("TRACE canonical FUN_00079320 MapDisplay method site=000793BD operand=[EBP+24] slot=00111EC8 fixup=object3->object1:0006ED40 runtime_guard=1 MAP_symbol=none")
    map_display_draw_rows=[row for row in lift_evidence.get("verified_indirect_targets",[])
                           if row.get("callsite")=="0x0006ED7D"]
    map_display_draw_fixup=next((f for f in image.fixups if f.source_link==0x111EBC),None)
    entity_map_draw_fixup=next((f for f in image.fixups if f.source_link==0x111E14),None)
    if (code_bytes_88146[0x6ED7D-code_obj_88146.base:0x6ED80-code_obj_88146.base]!=bytes.fromhex("FF 57 18") or
            map_display_draw_fixup is None or map_display_draw_fixup.source_type!=0x07 or
            map_display_draw_fixup.target_object!=1 or
            image.objects[0].base+map_display_draw_fixup.target_offset!=0x568E0 or
            entity_map_draw_fixup is None or entity_map_draw_fixup.source_type!=0x07 or
            entity_map_draw_fixup.target_object!=1 or
            image.objects[0].base+entity_map_draw_fixup.target_offset!=0x389E0 or
            {(row.get("link_target"),row.get("guest_target")) for row in map_display_draw_rows}!={
                ("0x000568E0",f"0x{image.link_to_linear(0x568E0):08X}"),
                ("0x000389E0",f"0x{image.link_to_linear(0x389E0):08X}")}):
        raise SystemExit(f"MapDisplay method call at 0x6ED7D lacks its exact LE-fixup target: {map_display_draw_rows!r}")
    if original_code[0x568E0-original_code_obj.base:0x568E0-original_code_obj.base+14]!=_OrigDigest("eca8f179d698b6c5cd7f123c1f642a17e6b4a5e456cc765a00c6e456f63df18f",14):
        raise SystemExit("MapDisplay call destination 0x568E0 no longer matches the original Capstone prologue")
    print("TRACE canonical MapDisplay/entity helper site=0006ED7D operand=[EDI+18] slots=00111EBC->000568E0/00111E14->000389E0 exact_LE_fixups=2 runtime_guards=2 MAP_symbol=none")
    map_entity_query_rows=[row for row in lift_evidence.get("verified_indirect_targets",[])
                           if row.get("callsite")=="0x0004A5DC"]
    map_entity_query_fixup=next((f for f in image.fixups if f.source_link==0x111D6C),None)
    if (code_bytes_88146[0x4A5DC-code_obj_88146.base:0x4A5DF-code_obj_88146.base]!=bytes.fromhex("FF 52 68") or
            map_entity_query_fixup is None or map_entity_query_fixup.source_type!=0x07 or
            map_entity_query_fixup.target_object!=1 or
            image.objects[0].base+map_entity_query_fixup.target_offset!=0x6A070 or
            {(row.get("link_target"),row.get("guest_target")) for row in map_entity_query_rows}!={
                ("0x0006A070",f"0x{image.link_to_linear(0x6A070):08X}")}):
        raise SystemExit(f"entity query call at 0x4A5DC lacks its exact LE-fixup target: {map_entity_query_rows!r}")
    print("TRACE canonical entity query site=0004A5DC operand=[EDX+68] slot=00111D6C fixup=object3->object1:0006A070 runtime_guard=1 MAP_symbol=none")
    entity_query_repeat_rows=[row for row in lift_evidence.get("verified_indirect_targets",[])
                              if row.get("callsite")=="0x0004A985"]
    if (code_bytes_88146[0x4A985-code_obj_88146.base:0x4A988-code_obj_88146.base]!=bytes.fromhex("FF 52 68") or
            map_entity_query_fixup is None or map_entity_query_fixup.source_type!=0x07 or
            map_entity_query_fixup.target_object!=1 or
            image.objects[0].base+map_entity_query_fixup.target_offset!=0x6A070 or
            {(row.get("link_target"),row.get("guest_target")) for row in entity_query_repeat_rows}!={
                ("0x0006A070",f"0x{image.link_to_linear(0x6A070):08X}")}):
        raise SystemExit(f"repeated entity query at 0x4A985 lacks its exact LE-fixup target: {entity_query_repeat_rows!r}")
    print("TRACE canonical repeated entity query site=0004A985 operand=[EDX+68] slot=00111D6C fixup=object3->object1:0006A070 runtime_guard=1")
    map_entity_action_rows=[row for row in lift_evidence.get("verified_indirect_targets",[])
                            if row.get("callsite")=="0x0004A6EE"]
    map_entity_action_fixup=next((f for f in image.fixups if f.source_link==0x111DB4),None)
    if (code_bytes_88146[0x4A6EE-code_obj_88146.base:0x4A6F4-code_obj_88146.base]!=bytes.fromhex("FF 92 B0 00 00 00") or
            map_entity_action_fixup is None or map_entity_action_fixup.source_type!=0x07 or
            map_entity_action_fixup.target_object!=1 or
            image.objects[0].base+map_entity_action_fixup.target_offset!=0x6A030 or
            {(row.get("link_target"),row.get("guest_target")) for row in map_entity_action_rows}!={
                ("0x0006A030",f"0x{image.link_to_linear(0x6A030):08X}")}):
        raise SystemExit(f"entity action call at 0x4A6EE lacks its exact LE-fixup target: {map_entity_action_rows!r}")
    print("TRACE canonical entity action site=0004A6EE operand=[EDX+B0] slot=00111DB4 fixup=object3->object1:0006A030 runtime_guard=1 MAP_symbol=none")
    map_entity_state_rows=[row for row in lift_evidence.get("verified_indirect_targets",[])
                           if row.get("callsite")=="0x0004A89B"]
    map_entity_state_fixup=next((f for f in image.fixups if f.source_link==0x111D14),None)
    if (code_bytes_88146[0x4A89B-code_obj_88146.base:0x4A89E-code_obj_88146.base]!=bytes.fromhex("FF 52 10") or
            map_entity_state_fixup is None or map_entity_state_fixup.source_type!=0x07 or
            map_entity_state_fixup.target_object!=1 or
            image.objects[0].base+map_entity_state_fixup.target_offset!=0x6A240 or
            {(row.get("link_target"),row.get("guest_target")) for row in map_entity_state_rows}!={
                ("0x0006A240",f"0x{image.link_to_linear(0x6A240):08X}")}):
        raise SystemExit(f"entity-state query at 0x4A89B lacks its exact LE-fixup target: {map_entity_state_rows!r}")
    print("TRACE canonical entity-state query site=0004A89B operand=[EDX+10] slot=00111D14 fixup=object3->object1:0006A240 runtime_guard=1 MAP_symbol=none")
    effect_recheck_rows=[row for row in lift_evidence.get("verified_indirect_targets",[])
                         if row.get("callsite")=="0x00085FC8"]
    effect_recheck_fixup=next((f for f in image.fixups if f.source_link==0x1121E8),None)
    if (code_bytes_88146[0x85FC8-code_obj_88146.base:0x85FCB-code_obj_88146.base]!=bytes.fromhex("FF 52 04") or
            effect_recheck_fixup is None or effect_recheck_fixup.source_type!=0x07 or
            effect_recheck_fixup.target_object!=1 or
            image.objects[0].base+effect_recheck_fixup.target_offset!=0x6A2E0 or
            {(row.get("link_target"),row.get("guest_target")) for row in effect_recheck_rows}!={
                ("0x0006A2E0",f"0x{image.link_to_linear(0x6A2E0):08X}")}):
        raise SystemExit(f"FUN_00085240 accessor lacks its exact LE-fixup target: {effect_recheck_rows!r}")
    print("TRACE canonical FUN_00085240 accessor site=00085FC8 operand=[EDX+4] slot=001121E8 fixup=object3->object1:0006A2E0 runtime_guard=1")
    entity_sweep_rows=[row for row in lift_evidence.get("verified_indirect_targets",[])
                       if row.get("callsite")=="0x000576CF"]
    expected_entity_sweep=("0x00057140",f"0x{image.link_to_linear(0x57140):08X}")
    if {(row.get("link_target"),row.get("guest_target")) for row in entity_sweep_rows}!={expected_entity_sweep}:
        raise SystemExit(f"FUN_00057640 entity-sweep method lacks its exact LE-fixup target: {entity_sweep_rows!r}")
    print("TRACE canonical FUN_00057640 entity-sweep site=000576CF slot=00111F08 target=00057140 runtime_guard=1")
    entity_probe_rows=[row for row in lift_evidence.get("verified_indirect_targets",[])
                       if row.get("callsite")=="0x00080EF3"]
    expected_entity_probe=("0x00078360",f"0x{image.link_to_linear(0x78360):08X}")
    if {(row.get("link_target"),row.get("guest_target")) for row in entity_probe_rows}!={expected_entity_probe}:
        raise SystemExit(f"FUN_00080ED0 entity probe lacks its exact LE-fixup target: {entity_probe_rows!r}")
    print("TRACE canonical FUN_00080ED0 entity probe site=00080EF3 slot=00111F0C target=00078360 runtime_guard=1")
    entity_state_query_rows=[row for row in lift_evidence.get("verified_indirect_targets",[])
                             if row.get("callsite")=="0x00078FAA"]
    expected_entity_state_query=("0x0006EC70",f"0x{image.link_to_linear(0x6EC70):08X}")
    plspec_state_fixup=next((f for f in image.fixups if f.source_link==0x1120D0),None)
    expected_plspec_state_query=("0x0006A2A0",f"0x{image.link_to_linear(0x6A2A0):08X}")
    if ({(row.get("link_target"),row.get("guest_target")) for row in entity_state_query_rows}!={expected_entity_state_query,expected_plspec_state_query} or
            plspec_state_fixup is None or plspec_state_fixup.source_type!=0x07 or
            plspec_state_fixup.target_object!=1 or image.objects[0].base+plspec_state_fixup.target_offset!=0x6A2A0):
        raise SystemExit(f"FUN_00078B30 entity-state query lacks its exact LE-fixup target: {entity_state_query_rows!r}")
    print("TRACE canonical FUN_00078B30 entity-state query site=00078FAA slots=00111F14->0006EC70/001120D0->0006A2A0 runtime_guards=2")
    bio_effect_rows=[row for row in lift_evidence.get("verified_indirect_targets",[])
                     if row.get("callsite")=="0x000893B2"]
    expected_bio_effect=("0x00086810",f"0x{image.link_to_linear(0x86810):08X}")
    if {(row.get("link_target"),row.get("guest_target")) for row in bio_effect_rows}!={expected_bio_effect}:
        raise SystemExit(f"FUN_00089380 BioGame effect-count method lacks its exact LE-fixup target: {bio_effect_rows!r}")
    print("TRACE canonical FUN_00089380 BioGame effect-count site=000893B2 slot=00112248 target=00086810 runtime_guard=1")
    bio_effect_second_rows=[row for row in lift_evidence.get("verified_indirect_targets",[])
                            if row.get("callsite")=="0x000893F6"]
    bio_effect_count_fixup=next((f for f in image.fixups if f.source_link==0x112248),None)
    if ({(row.get("link_target"),row.get("guest_target")) for row in bio_effect_second_rows}!={expected_bio_effect} or
            code_bytes_88146[0x893B2-code_obj_88146.base:0x893B5-code_obj_88146.base]!=bytes.fromhex("FF 51 64") or
            code_bytes_88146[0x893F6-code_obj_88146.base:0x893F9-code_obj_88146.base]!=bytes.fromhex("FF 51 64") or
            bio_effect_count_fixup is None or bio_effect_count_fixup.source_type!=0x07 or
            bio_effect_count_fixup.target_object!=1 or bio_effect_count_fixup.target_offset!=0x76810):
        raise SystemExit(f"FUN_00089380 second effect-count call at 0x893F6 is not backed by the same exact LE method slot: rows={bio_effect_second_rows!r} fixup={bio_effect_count_fixup!r}")
    print("TRACE canonical FUN_00089380 second effect-count site=000893F6 slot=00112248 target=00086810 shared_LE_SRC_OFFSET32=1 runtime_guard=1")
    bio_effect_method_rows=[row for row in lift_evidence.get("verified_indirect_targets",[])
                            if row.get("callsite")=="0x0008684F"]
    expected_bio_effect_method=("0x00058330",f"0x{image.link_to_linear(0x58330):08X}")
    if {(row.get("link_target"),row.get("guest_target")) for row in bio_effect_method_rows}!={expected_bio_effect_method}:
        raise SystemExit(f"FUN_00086810 BioGame-effect callback lacks its exact LE-fixup target: {bio_effect_method_rows!r}")
    print("TRACE canonical FUN_00086810 BioGame-effect callback site=0008684F slot=00112278 target=00058330 runtime_guard=1")
    # FUN_00058330's first live virtual call is a canonical null method, not
    # an invalid list sentinel. Capstone confirms the three method-table
    # callsites below; the object-3 slots have exact LE SRC_OFFSET32 fixups.
    # The runtime still traps if any live slot differs from these targets.
    effect_tick_sites=((0x58BBD,0x11226C,0x8A720,bytes.fromhex("FF 93 88 00 00 00")),
                       (0x58BD4,0x1121E8,0x6A2E0,bytes.fromhex("FF 52 04")),
                       (0x58BE0,0x112254,0x86270,bytes.fromhex("FF 52 70")))
    effect_tick_rows=[row for row in lift_evidence.get("verified_indirect_targets",[])
                      if row.get("callsite") in {f"0x{x[0]:08X}" for x in effect_tick_sites}]
    for site,slot,target,expected_bytes in effect_tick_sites:
        fixup=next((f for f in image.fixups if f.source_link==slot),None)
        if (code_bytes_88146[site-code_obj_88146.base:site-code_obj_88146.base+len(expected_bytes)]!=expected_bytes or
                fixup is None or fixup.source_type!=0x07 or fixup.target_object!=1 or
                image.objects[0].base+fixup.target_offset!=target):
            raise SystemExit(f"FUN_00058330 method call 0x{site:X} is not backed by the expected canonical LE code/fixup")
        expected=(f"0x{target:08X}",f"0x{image.link_to_linear(target):08X}")
        if not any(row.get("callsite")==f"0x{site:08X}" and
                   (row.get("link_target"),row.get("guest_target"))==expected
                   for row in effect_tick_rows):
            raise SystemExit(f"FUN_00058330 call 0x{site:X} missing exact fail-closed dispatcher contract: {effect_tick_rows!r}")
    print("TRACE canonical FUN_00058330 live effect methods sites=00058BBD/00058BD4/00058BE0 slots=0011226C/001121E8/00112254 targets=0008A720(nullsub_14)/0006A2E0/00086270 LE_fixups=3 runtime_guards=1")
    # FUN_00083BF0's EF_MONOLITH initialization at 0x8450F calls through
    # the new Effect's live vtable +0x44. The frontier captured ESI in the
    # object-3 address range; its +0x44 cell maps to LE source 0x112228.
    # Admit only the exact SRC_OFFSET32 fixup-backed method and preserve the
    # Runtime's equality check for the target observed at that callsite.
    site,slot,target,expected_bytes=(0x8450F,0x112228,0x69E20,bytes.fromhex("FF 56 44"))
    monolith_fixup=next((f for f in image.fixups if f.source_link==slot),None)
    if (code_bytes_88146[site-code_obj_88146.base:site-code_obj_88146.base+len(expected_bytes)]!=expected_bytes or
            monolith_fixup is None or monolith_fixup.source_type!=0x07 or
            monolith_fixup.target_object!=1 or
            image.objects[0].base+monolith_fixup.target_offset!=target):
        raise SystemExit("FUN_00083BF0 EF_MONOLITH call 0x8450F lacks its exact canonical LE vtable fixup")
    expected_monolith=(f"0x{target:08X}",f"0x{image.link_to_linear(target):08X}")
    monolith_rows=[row for row in lift_evidence.get("verified_indirect_targets",[])
                   if row.get("callsite")==f"0x{site:08X}"]
    if not any((row.get("link_target"),row.get("guest_target"))==expected_monolith
               for row in monolith_rows):
        raise SystemExit(f"FUN_00083BF0 EF_MONOLITH call lacks its fixup-backed fail-closed guard: {monolith_rows!r}")
    print("TRACE canonical FUN_00083BF0 EF_MONOLITH method site=0008450F slot=00112228 target=00069E20 exact_LE_fixup=1 runtime_guard=1")
    gadget_dispatch_rows=[row for row in lift_evidence.get("verified_indirect_targets",[])
                          if row.get("callsite")=="0x000A8D95"]
    expected_gadget_pairs={(f"0x{x:08X}",f"0x{image.link_to_linear(x):08X}")
                           for x in seen_callback_targets}
    if {(row.get("link_target"),row.get("guest_target")) for row in gadget_dispatch_rows}!=expected_gadget_pairs:
        raise SystemExit(f"A8D95 dispatch does not contain the complete fixup-backed callback set: {gadget_dispatch_rows!r}")
    generated_gadget_text=generated.read_text(encoding="utf-8")
    if any(f"recomp_gw_partial_0x{x:08X}" not in generated_gadget_text
           for x in seen_callback_targets):
        raise SystemExit("one or more MyGadget callback destinations were not lifted as explicit partial roots")
    mygadget_evidence["lifted_dispatch"]={"callsite":"0x000A8D95",
        "targets":[{"link":a,"guest":b} for a,b in sorted(expected_gadget_pairs)],
        "fail_closed":"runtime compares the live [EDX+0x22] value to these targets; every other value remains a trap"}
    (ROOT/"evidence"/"native_mygadget_callback_fixups.json").write_text(
        json.dumps(mygadget_evidence,indent=2)+"\n",encoding="utf-8")
    record_dispatch_rows=[row for row in lift_evidence.get("verified_indirect_targets",[])
        if row.get("callsite") in ("0x00086320","0x000851ED","0x00089920","0x000898AD",
                                    "0x00013AA0","0x00013A2D","0x00010140","0x000100CD")]
    expected_record_dispatch={"0x00086320":("0x000851B0","0x002701B0"),
                              "0x000851ED":("0x00085070","0x00270070"),
                              "0x00089920":("0x00089870","0x00274870"),
                              "0x000898AD":("0x00089860","0x00274860"),
                              "0x00013AA0":("0x000139F0","0x001FE9F0"),
                              "0x00013A2D":("0x000139E0","0x001FE9E0"),
                              "0x00010140":("0x00010090","0x001FB090"),
                              "0x000100CD":("0x00010060","0x001FB060")}
    continuation_vtable_fixups={f.source_link:f for f in image.fixups
        if f.source_link in (0x1122C8,0x1122EC,0x112338,0x11235C,0x1123F8,0x11241C)}
    if (set(continuation_vtable_fixups)!={0x1122C8,0x1122EC,0x112338,0x11235C,0x1123F8,0x11241C} or
            any(f.source_type!=0x07 or f.target_object!=1 for f in continuation_vtable_fixups.values()) or
            image.objects[continuation_vtable_fixups[0x1122C8].target_object-1].base+
                continuation_vtable_fixups[0x1122C8].target_offset!=0x89870 or
            image.objects[continuation_vtable_fixups[0x1122EC].target_object-1].base+
                continuation_vtable_fixups[0x1122EC].target_offset!=0x89860 or
            image.objects[continuation_vtable_fixups[0x112338].target_object-1].base+
                continuation_vtable_fixups[0x112338].target_offset!=0x139F0 or
            image.objects[continuation_vtable_fixups[0x11235C].target_object-1].base+
                continuation_vtable_fixups[0x11235C].target_offset!=0x139E0 or
            image.objects[continuation_vtable_fixups[0x1123F8].target_object-1].base+
                continuation_vtable_fixups[0x1123F8].target_offset!=0x10090 or
            image.objects[continuation_vtable_fixups[0x11241C].target_object-1].base+
                continuation_vtable_fixups[0x11241C].target_offset!=0x10060 or
            image.link_to_linear(0x89870)!=0x00274870 or image.link_to_linear(0x89860)!=0x00274860 or
            image.link_to_linear(0x139F0)!=0x001FE9F0 or image.link_to_linear(0x139E0)!=0x001FE9E0 or
            image.link_to_linear(0x10090)!=0x001FB090 or image.link_to_linear(0x10060)!=0x001FB060 or
            code_bytes[0x89920-code_obj.base:0x89923-code_obj.base]!=bytes.fromhex("FF 51 3C") or
            code_bytes[0x898AD-code_obj.base:0x898B0-code_obj.base]!=bytes.fromhex("FF 56 60") or
            code_bytes[0x13AA0-code_obj.base:0x13AA3-code_obj.base]!=bytes.fromhex("FF 51 3C") or
            code_bytes[0x13A2D-code_obj.base:0x13A30-code_obj.base]!=bytes.fromhex("FF 56 60") or
            code_bytes[0x10140-code_obj.base:0x10143-code_obj.base]!=bytes.fromhex("FF 51 3C") or
            code_bytes[0x100CD-code_obj.base:0x100D0-code_obj.base]!=bytes.fromhex("FF 56 60") or
            code_bytes[0x89870-code_obj.base:0x89871-code_obj.base]!=b"\x53" or
            code_bytes[0x89860-code_obj.base:0x89861-code_obj.base]!=b"\xC3" or
            code_bytes[0x139F0-code_obj.base:0x139F1-code_obj.base]!=b"\x53" or
            code_bytes[0x139E0-code_obj.base:0x139E1-code_obj.base]!=b"\x52" or
            code_bytes[0x10090-code_obj.base:0x10091-code_obj.base]!=b"\x53" or
            code_bytes[0x10060-code_obj.base:0x10061-code_obj.base]!=b"\x52"):
        raise SystemExit("next-interface virtual callbacks are not backed by the exact LE vtable fixups and Capstone bytes")
    loader_vtable_expected={0x111B04:0x151A0,0x111B08:0x15190,
        0x111B0C:0x15180,0x111B10:0x15170}
    loader_vtable_fixups={f.source_link:f for f in image.fixups
        if f.source_link in loader_vtable_expected}
    loader_thunk_targets={0x251A0:0x20C60,0x25190:0x21140,
        0x25180:0x21380,0x25170:0x22F40}
    if (set(loader_vtable_fixups)!=set(loader_vtable_expected) or
            any(loader_vtable_fixups[a].source_type!=0x07 or
                loader_vtable_fixups[a].target_object!=1 or
                loader_vtable_fixups[a].target_offset!=target_offset
                for a,target_offset in loader_vtable_expected.items()) or
            any(image.link_to_linear(link)!=guest for link,guest in (
                (0x251A0,0x002101A0),(0x25190,0x00210190),
                (0x25180,0x00210180),(0x25170,0x00210170))) or
            any(code_bytes[link-code_obj.base:link-code_obj.base+8] !=
                bytes.fromhex("2B 40 FC E9")+
                int((target-(link+8))&0xFFFFFFFF).to_bytes(4,"little")
                for link,target in loader_thunk_targets.items())):
        raise SystemExit("pending singleton vtable is not backed by its exact object-1 LE fixups and Capstone adjustor thunks")
    print("TRACE canonical secondary-vtable link=00111B04 guest=002EBB04 thunks=00251A0/0025190/0025180/0025170 jmp_targets=0020C60/0021140/0021380/0022F40 exact_MAP_target_symbols=none primary_IFCLevel_methods=0015710/0015CF0/00179F0/00177C0")
    if len(record_dispatch_rows)!=8 or any(
            (row.get("link_target"),row.get("guest_target"))!=expected_record_dispatch.get(row.get("callsite"))
            for row in record_dispatch_rows):
        raise SystemExit(f"record vtable calls are not all bounded by their LE fixups: {record_dispatch_rows!r}")
    generated_text=generated.read_text(encoding="utf-8")
    if any(token not in generated_text for token in (
            "gw_recomp_icall_allow_00086320","gw_recomp_icall_allow_000851ED",
            "gw_recomp_icall_allow_00089920","gw_recomp_icall_allow_000898AD",
            "gw_recomp_icall_allow_00013AA0","gw_recomp_icall_allow_00013A2D",
            "gw_recomp_icall_allow_00010140","gw_recomp_icall_allow_000100CD",
            "recomp_gw_partial_0x000851B0","recomp_gw_partial_0x00085070",
            "recomp_gw_partial_0x00089870","recomp_gw_partial_0x00089860",
            "recomp_gw_partial_0x000139F0","recomp_gw_partial_0x000139E0",
            "recomp_gw_partial_0x00010090","recomp_gw_partial_0x00010060")):
        raise SystemExit("fixup-backed record callback closure and exact callsite guards are missing")
    switch1=[row for row in lift_evidence.get("indexed_code_call_tables",[])
             if row.get("table_link")=="0x0010CB00"]
    expected_switch_sites={"0x000EB445","0x000EB473","0x000ECEF5","0x000ECF13"}
    if {row["instruction"] for row in switch1}!=expected_switch_sites:
        raise SystemExit(f"batch Switch1 table contracts do not cover the four Capstone callsites: {switch1!r}")
    if any(row["count"]!=256 or row["fixup_backed_target_count"]!=256 or
           len(row.get("fixup_slots",[]))!=256 or
           [slot["index"] for slot in row.get("fixup_slots",[])]!=list(range(256))
           for row in switch1):
        raise SystemExit("Switch1 batch admission lacks all 256 contiguous LE SRC_OFFSET32 slots")
    switch_targets={tuple(row["targets_link"]) for row in switch1}
    if len(switch_targets)!=1:
        raise SystemExit("Switch1 callsites do not share the same fixup-backed target set")
    state_switch=[row for row in lift_evidence.get("indexed_code_jump_tables",[])
                  if row.get("instruction")=="0x000E1B20"]
    expected_state_fixups=sorted((item for item in image.fixups
                                  if 0xE1B27<=item.source_link<0xE1B93),
                                 key=lambda item:item.source_link)
    expected_state_targets=[f"0x{image.objects[item.target_object-1].base+item.target_offset:08X}"
                            for item in expected_state_fixups]
    state_table_guest=image.link_to_linear(0xE1B27)
    state_guard=f"recomp_check_indexed_table_access(RECOMP_SEG_DS, 0x{state_table_guest:08X}u, eax * 4u, 108u, 108u, 4u, 0x000E1B20u)"
    if (len(state_switch)!=1 or state_switch[0].get("table_link")!="0x000E1B27" or
            state_switch[0].get("table_guest")!=f"0x{state_table_guest:08X}" or
            state_switch[0].get("segment")!="DS" or state_switch[0].get("count")!=27 or
            len(state_switch[0].get("fixup_slots",[]))!=27 or
            [slot["index"] for slot in state_switch[0]["fixup_slots"]]!=list(range(27)) or
            [slot["source_link"] for slot in state_switch[0]["fixup_slots"]]!=
                [f"0x{0xE1B27+i*4:08X}" for i in range(27)] or
            state_switch[0].get("targets_link")!=expected_state_targets or
            len(expected_state_fixups)!=27 or
            state_guard not in generated.read_text(encoding="utf-8")):
        raise SystemExit(f"FUN_000E19C0 state table is not bounded by its exact 27 LE fixups: {state_switch!r}")
    if not ReferenceMap.contains("0001:000E1B27       jpt_E1B20"):
        raise SystemExit("canonical MAP no longer names the E1B20 switch table at 0xE1B27")
    draw_switch=[row for row in lift_evidence.get("indexed_code_jump_tables",[])
                 if row.get("table_link")=="0x000E35D3"]
    expected_draw_fixups=sorted((item for item in image.fixups
                                 if 0xE35D3<=item.source_link<0xE3640),
                                key=lambda item:item.source_link)
    expected_draw_targets=[f"0x{image.objects[item.target_object-1].base+item.target_offset:08X}"
                           for item in expected_draw_fixups]
    draw_table_guest=image.link_to_linear(0xE35D3)
    draw_guard=f"recomp_check_indexed_table_access(RECOMP_SEG_DS, 0x{draw_table_guest:08X}u, eax * 4u, 108u, 108u, 4u, 0x000E2048u)"
    if ({row["instruction"] for row in draw_switch}!={f"0x{site:08X}" for site in draw_state_sites} or
            len(expected_draw_fixups)!=27 or any(item.target_object!=1 for item in expected_draw_fixups) or
            any(row.get("table_guest")!=f"0x{draw_table_guest:08X}" or row.get("segment")!="DS" or
                row.get("count")!=27 or len(row.get("fixup_slots",[]))!=27 or
                [slot["source_link"] for slot in row["fixup_slots"]]!=
                    [f"0x{0xE35D3+i*4:08X}" for i in range(27)] or
                row.get("targets_link")!=expected_draw_targets
                for row in draw_switch) or draw_guard not in generated.read_text(encoding="utf-8") or
            not ReferenceMap.contains("0001:000E35D3       jpt_E1DE1")):
        raise SystemExit(f"FUN_000E19C0 draw table is not bounded by all 27 exact LE fixups at all 24 sites: {draw_switch!r}")
    for site,table,count,index_reg in smack_static_tables:
        rows=[row for row in lift_evidence.get("indexed_code_jump_tables",[])
              if row.get("instruction")==f"0x{site:08X}"]
        expected=sorted((item for item in image.fixups
                         if table<=item.source_link<table+count*4),
                        key=lambda item:item.source_link)
        targets=[f"0x{image.objects[item.target_object-1].base+item.target_offset:08X}"
                 for item in expected]
        guest=image.link_to_linear(table)
        row_guard=f"recomp_check_indexed_table_access(RECOMP_SEG_DS, 0x{guest:08X}u, {index_reg} * 4u, {count*4}u, {count*4}u, 4u, 0x{site:08X}u)"
        if (len(rows)!=1 or rows[0].get("table_link")!=f"0x{table:08X}" or
                rows[0].get("table_guest")!=f"0x{guest:08X}" or
                rows[0].get("segment")!="DS" or rows[0].get("count")!=count or
                len(expected)!=count or any(item.target_object!=1 for item in expected) or
                len(rows[0].get("fixup_slots",[]))!=count or
                [slot.get("source_link") for slot in rows[0]["fixup_slots"]]!=
                    [f"0x{table+i*4:08X}" for i in range(count)] or
                rows[0].get("targets_link")!=targets or
                row_guard not in generated.read_text(encoding="utf-8")):
            raise SystemExit(f"Smacker table at {table:#x} is not fully bounded by its {count} LE fixups at {site:#x}: {rows!r}")
        if not ReferenceMap.has_line(f" 0001:{table:08X}       jpt_"):
            raise SystemExit(f"canonical MAP has no jpt symbol for Smacker dispatch {site:#x}/{table:#x}")
    entity_state_switch=[row for row in lift_evidence.get("indexed_code_jump_tables",[])
                         if row.get("instruction")=="0x0004AB28"]
    entity_state_fixups=sorted((item for item in image.fixups if 0x4AAA0<=item.source_link<0x4AB10),
                               key=lambda item:item.source_link)
    entity_state_targets=[f"0x{image.objects[item.target_object-1].base+item.target_offset:08X}"
                          for item in entity_state_fixups]
    if (len(entity_state_switch)!=1 or entity_state_switch[0].get("table_link")!="0x0004AAA0" or
            entity_state_switch[0].get("segment")!="CS" or entity_state_switch[0].get("count")!=28 or
            len(entity_state_fixups)!=28 or any(item.target_object!=1 for item in entity_state_fixups) or
            len(entity_state_switch[0].get("fixup_slots",[]))!=28 or
            [slot.get("source_link") for slot in entity_state_switch[0]["fixup_slots"]]!=
                [f"0x{0x4AAA0+i*4:08X}" for i in range(28)] or
            entity_state_switch[0].get("targets_link")!=entity_state_targets or
            entity_state_targets.count("0x000490FB")!=2 or
            not ReferenceMap.contains("0001:0004AAA0       jpt_4AB28")):
        raise SystemExit(f"FUN_0004AB10 jpt_4AB28 is not bounded by all 28 exact LE fixups and its shared terminal blocks: {entity_state_switch!r}")
    print("TRACE canonical FUN_0004AB10 MAP=jpt_4AB28 table=0004AAA0 slots=28 LE_fixups=28 shared_target=000490FB bounds=0..27 runtime_guard=1")
    entity_type_switch=[row for row in lift_evidence.get("indexed_code_jump_tables",[])
                        if row.get("instruction")=="0x000790AA"]
    entity_type_fixups=sorted((item for item in image.fixups if 0x78B10<=item.source_link<0x78B2C),
                              key=lambda item:item.source_link)
    entity_type_targets=[f"0x{image.objects[item.target_object-1].base+item.target_offset:08X}"
                         for item in entity_type_fixups]
    if (len(entity_type_switch)!=1 or entity_type_switch[0].get("table_link")!="0x00078B10" or
            entity_type_switch[0].get("segment")!="CS" or entity_type_switch[0].get("count")!=7 or
            len(entity_type_fixups)!=7 or any(item.target_object!=1 for item in entity_type_fixups) or
            len(entity_type_switch[0].get("fixup_slots",[]))!=7 or
            [slot.get("source_link") for slot in entity_type_switch[0]["fixup_slots"]]!=
                [f"0x{0x78B10+i*4:08X}" for i in range(7)] or
            entity_type_switch[0].get("targets_link")!=entity_type_targets or
            not ReferenceMap.contains("0001:00078B10       jpt_790AA")):
        raise SystemExit(f"FUN_00078B30 jpt_790AA is not backed by all seven exact LE fixups: {entity_type_switch!r}")
    print("TRACE canonical FUN_00078B30 MAP=jpt_790AA table=00078B10 slots=7 LE_fixups=7 bounds=0..6 runtime_guard=1")
    effect_switch=[row for row in lift_evidence.get("indexed_code_jump_tables",[])
                   if row.get("instruction")=="0x0008936F"]
    effect_fixups=sorted((item for item in image.fixups if 0x86704<=item.source_link<0x86808),
                         key=lambda item:item.source_link)
    effect_targets=[f"0x{image.objects[item.target_object-1].base+item.target_offset:08X}"
                    for item in effect_fixups]
    effect_table_guest=image.link_to_linear(0x86704)
    effect_guard=f"recomp_check_indexed_table_access(RECOMP_SEG_CS, 0x{effect_table_guest:08X}u, eax * 4u, 260u, 260u, 4u, 0x0008936Fu)"
    if (len(effect_switch)!=1 or effect_switch[0].get("table_link")!="0x00086704" or
            effect_switch[0].get("table_guest")!=f"0x{effect_table_guest:08X}" or
            effect_switch[0].get("segment")!="CS" or effect_switch[0].get("count")!=65 or
            len(effect_fixups)!=65 or any(item.target_object!=1 or item.source_type!=0x07
                                          for item in effect_fixups) or
            [item.source_link for item in effect_fixups]!=[0x86704+4*i for i in range(65)] or
            len(effect_switch[0].get("fixup_slots",[]))!=65 or
            effect_switch[0].get("targets_link")!=effect_targets or
            effect_targets[43]!="0x00087F38" or effect_guard not in generated.read_text(encoding="utf-8") or
            not ReferenceMap.contains("0001:00086704       jpt_8936F")):
        raise SystemExit(f"BioGame effect-type switch lacks its exact 65 LE slots, original bounds, or live index-43 target: {effect_switch!r}")
    print("TRACE canonical BioGame effect switch MAP=jpt_8936F table=00086704 slots=65 LE_fixups=65 bounds=0..64 live_index=43 target=00087F38 runtime_guard=1")
    system_switch=[row for row in lift_evidence.get("indexed_code_jump_tables",[])
                   if row.get("instruction")=="0x0007520F"]
    if (len(system_switch)!=1 or system_switch[0].get("table_link")!="0x000751DC" or
            system_switch[0].get("count")!=4 or
            system_switch[0].get("targets_link")!=["0x00075217","0x00075287","0x000752F5","0x00075364"]):
        raise SystemExit(f"post-Smacker game switch is not fully backed by its four LE fixups: {system_switch!r}")
    gadget_switch=[row for row in lift_evidence.get("indexed_code_jump_tables",[])
                   if row.get("instruction")=="0x0007583A"]
    expected_gadget_targets=["0x0007576C","0x00075797","0x00075803","0x000757D1"]
    gadget_fixups=[x for x in image.fixups if 0x75734<=x.source_link<0x75744]
    if (len(gadget_switch)!=1 or gadget_switch[0].get("table_link")!="0x00075734" or
            gadget_switch[0].get("count")!=4 or
            gadget_switch[0].get("targets_link")!=expected_gadget_targets or
            len(gadget_fixups)!=4 or any(x.target_object!=1 for x in gadget_fixups) or
            not ReferenceMap.has_line(" 0001:00075734       jpt_7583A")):
        raise SystemExit(f"gadget-kind switch is not fully backed by jpt_7583A and its four LE fixups: {gadget_switch!r}")
    glyph_switch=[row for row in lift_evidence.get("indexed_code_jump_tables",[])
                  if row.get("instruction")=="0x00083F60"]
    glyph_fixups=[x for x in image.fixups if 0x83AD4<=x.source_link<0x83AD4+70*4]
    if (len(glyph_switch)!=1 or glyph_switch[0].get("table_link")!="0x00083AD4" or
            glyph_switch[0].get("count")!=70 or len(glyph_fixups)!=70 or
            any(x.target_object!=1 for x in glyph_fixups) or
            sorted(x.source_link for x in glyph_fixups)!=[0x83AD4+i*4 for i in range(70)] or
            not ReferenceMap.has_line(" 0001:00083AD4       jpt_83F60")):
        raise SystemExit(f"glyph-render table jpt_83F60 is not fully backed by all 70 contiguous LE fixups: {glyph_switch!r}")
    level_switch=[row for row in lift_evidence.get("indexed_code_jump_tables",[])
                  if row.get("instruction")=="0x000159CF"]
    if (len(level_switch)!=1 or level_switch[0].get("table_link")!="0x000156E0" or
            level_switch[0].get("count")!=9 or
            level_switch[0].get("targets_link")!=["0x0001597E","0x0001597E",
                "0x00015994","0x00015994","0x0001597E","0x0001597E",
                "0x000159A9","0x000159A9","0x00015994"]):
        raise SystemExit(f"IFCLevel::PlugIn switch is not fully backed by its nine LE fixups: {level_switch!r}")
    edge_scroll_switch=[row for row in lift_evidence.get("indexed_code_jump_tables",[])
                        if row.get("instruction")=="0x0007A0C4"]
    edge_scroll_fixups=sorted((item for item in original_link_image.fixups
        if 0x79DA4<=item.source_link<0x79DC4),key=lambda item:item.source_link)
    edge_scroll_targets=[f"0x{original_link_image.objects[item.target_object-1].base+item.target_offset:08X}"
                         for item in edge_scroll_fixups]
    if (len(edge_scroll_switch)!=1 or edge_scroll_switch[0].get("table_link")!="0x00079DA4" or
            edge_scroll_switch[0].get("count")!=8 or edge_scroll_switch[0].get("segment")!="CS" or
            len(edge_scroll_fixups)!=8 or any(item.target_object!=1 for item in edge_scroll_fixups) or
            [item.source_link for item in edge_scroll_fixups]!=[0x79DA4+4*i for i in range(8)] or
            edge_scroll_switch[0].get("targets_link")!=edge_scroll_targets or
            not ReferenceMap.has_line(" 0001:00079DA4       jpt_7A0C4")):
        raise SystemExit(f"MapDisplay edge-scroll table is not bounded by its exact eight LE fixups: {edge_scroll_switch!r}")
    planetside_action_switch=[row for row in lift_evidence.get("indexed_code_jump_tables",[])
                              if row.get("instruction")=="0x00021AEB"]
    planetside_action_fixups=sorted((item for item in original_link_image.fixups
        if 0x21354<=item.source_link<0x21374),key=lambda item:item.source_link)
    planetside_action_targets=[f"0x{original_link_image.objects[item.target_object-1].base+item.target_offset:08X}"
                               for item in planetside_action_fixups]
    expected_planetside_targets=["0x00021C6C","0x00021CB1","0x00021BE4","0x00021AF3",
                                 "0x00021CA8","0x00021D0B","0x00021D0B","0x00021D03"]
    if (len(planetside_action_switch)!=1 or
            planetside_action_switch[0].get("table_link")!="0x00021354" or
            planetside_action_switch[0].get("count")!=8 or
            planetside_action_switch[0].get("segment")!="CS" or
            len(planetside_action_fixups)!=8 or
            any(item.target_object!=1 or item.source_type!=0x07 for item in planetside_action_fixups) or
            [item.source_link for item in planetside_action_fixups]!=[0x21354+4*i for i in range(8)] or
            planetside_action_targets!=expected_planetside_targets or
            planetside_action_switch[0].get("targets_link")!=expected_planetside_targets or
            not ReferenceMap.has_line(" 0001:00021354       jpt_21AEB")):
        raise SystemExit(f"IFCPlanetside action table jpt_21AEB is not backed by its exact eight contiguous Object 1 LE fixups: {planetside_action_switch!r}")
    print("TRACE canonical IFCPlanetside::Update MAP=jpt_21AEB table=00021354 slots=8 LE_fixups=8 bounds=0..7 runtime_guard=1")
    observed_switch_sites={row["callsite"] for row in lift_evidence.get("verified_indirect_targets",[])
                           if row.get("callsite") in expected_switch_sites}
    if not {"0x000ECEF5","0x000ECF13"}.issubset(observed_switch_sites):
        raise SystemExit(f"active decoder callsites did not receive the whole-batch allowlist: {observed_switch_sites}")
    lifted_text=generated.read_text(encoding="utf-8")
    # Snapshot-scoped capture of the original projected terrain triangles.
    # This is applied to the private test closure (including the hash-matched
    # reuse path), leaving the shared lifter and interactive build untouched.
    # FUN_00065F20 is an independent terrain-triangle producer called by
    # MapDisplay::Draw before FUN_000665B0. Capture its six original submit
    # sites as well; limiting the probe to the latter misses the main tile
    # raster path entirely.
    primitive_calls=(0x662BE,0x6630A,0x6634F,0x664CD,0x6651C,0x66564,
                     0x669E0,0x66A2D,0x66A6F,0x66C9E,0x66CEB,0x66D2D)
    for site in primitive_calls:
        call_marker=(f"RECOMP_CALL(recomp_gw_partial_0x000E19C0); "
                     f"/* 0x{site:08X}: call 0xe19c0 */")
        if lifted_text.count(call_marker)!=1:
            raise SystemExit(f"hybrid primitive capture expected one original polygon callsite 0x{site:X}")
        capture=(f"gw_hybrid_capture_primitive(0x{site:08X}u,"
                 "eax,ebx,edx,esp);\n    ")
        lifted_text=lifted_text.replace(call_marker,capture+call_marker,1)
    terrain_entry_marker="RECOMP_ENTER(0x00065F20u);"
    if lifted_text.count(terrain_entry_marker)!=1:
        raise SystemExit("hybrid terrain producer entry marker 0x65F20 missing or ambiguous")
    lifted_text=lifted_text.replace(terrain_entry_marker,
        terrain_entry_marker+"\n    gw_hybrid_capture_terrain_entry(eax,ebx,ecx,edx,esi,edi,ebp,esp);",1)
    lifted_text=("void gw_hybrid_capture_primitive(unsigned int,unsigned int,unsigned int,unsigned int,unsigned int);\n"
                 "void gw_hybrid_capture_terrain_entry(unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int);\n"
                 +lifted_text)
    # The first IFCLevel::Draw comparison reaches an unlabelled local routine,
    # not an unknown callback: the canonical LE bytes pass link 0x184B0 to
    # qsort_ (0xA33C0), whose comparator trampoline calls that exact argument.
    # Keep both the direct argument and its object-3 data dependency checked.
    from capstone.x86_const import X86_REG_ECX
    original_code=bytes(original_link_image.object_data(1))
    original_code_obj=original_link_image.objects[0]
    draw_dis=Disassembler(original_code,0,
        [Section(".text",original_code_obj.base,original_code_obj.virtual_size,
                 0,original_code_obj.virtual_size,0x20000020)])
    draw_blocks=draw_dis.disassemble_function(0x177C0).blocks
    draw_ins={i.address:i for block in draw_blocks.values() for i in block.instructions}
    if (draw_ins.get(0x17824) is None or draw_ins[0x17824].mnemonic.lower()!="mov" or
            draw_ins[0x17824].operands[0].reg!=X86_REG_ECX or
            draw_ins[0x17824].operands[1].imm!=0x184B0 or
            draw_ins.get(0x17837) is None or draw_ins[0x17837].mnemonic.lower()!="call" or
            draw_ins[0x17837].operands[0].imm!=0xA33C0):
        raise SystemExit("IFCLevel::Draw no longer passes the original comparator 0x184B0 to qsort_")
    comparator=draw_dis.disassemble_function(0x184B0)
    comparator_ins={i.address:i for block in comparator.blocks.values() for i in block.instructions}
    level_data=image.object_containing(0x186384)
    if (level_data is None or level_data.index!=3 or
            comparator_ins.get(0x184C5) is None or
            comparator_ins[0x184C5].mnemonic.lower()!="mov" or
            comparator_ins[0x184C5].operands[1].mem.disp!=0x186384 or
            not any(i.mnemonic.lower()=="ret" for i in comparator_ins.values())):
        raise SystemExit("IFCLevel comparator body/data reference is not bounded by the measured object map")
    comparator_sites={0xA337A,0xA3385,0xA3390,0xA33A3,0xA33AE,0xA3483,0xA35F8,0xA3643}
    comparator_rows=[row for row in lift_evidence.get("verified_indirect_targets",[])
                     if row.get("link_target")=="0x000184B0"]
    if {int(row["callsite"],16) for row in comparator_rows}!=comparator_sites or any(
            row.get("guest_target")!="0x002034B0" for row in comparator_rows):
        raise SystemExit(f"qsort_ does not have the exact IFCLevel comparator contract: {comparator_rows!r}")
    print("TRACE original IFCLevel comparator link=000184B0 guest=002034B0 source=Draw@17824->qsort_@17837 data_link=00186384 guest=00360384 qsort_sites=8")
    close_callback_rows=[row for row in lift_evidence.get("verified_indirect_targets",[])
                         if row.get("callsite")=="0x000C6096"]
    # The Smacker MSS (audio) targets are additional verified rows at the same site; the BIOS-clock
    # row the proof depends on must still be present and exact.
    bios_close_rows=[row for row in close_callback_rows
                     if row.get("link_target")=="0x000D7220" and row.get("guest_target")=="0x002C2220"]
    if (len(bios_close_rows)!=1 or
            "{ 0x002C2220u, recomp_gw_partial_0x000D7220 }" not in lifted_text):
        raise SystemExit("SMACKCLOSE's fixup-backed callback is not mapped to the lifted nullsub_7 body")
    # Bound the original setup_game body at the continuation after the
    # BIOINTRO file handle is closed. Every instruction from the function's
    # real entry through the size comparison and availability-bit store stays
    # original LE code; only later setup_game work is excluded.
    from tools.disasm.disasm32 import BasicBlock, Function, Instruction
    from tools.lift.lift32 import Lifter
    from tools.pe.pe_analyze import Section
    setup_dis=Disassembler(bytes(image.object_data(1)),0,
        [Section(".text",image.objects[0].base,image.objects[0].virtual_size,
                 0,image.objects[0].virtual_size,0x20000020)])
    setup_game_original=setup_dis.disassemble_function(0x94AC0)
    setup_prefix_stop=0x94C93
    setup_prefix_blocks={a:b for a,b in setup_game_original.blocks.items()
                         if 0x94AC0<=a<setup_prefix_stop}
    if 0x94AC0 not in setup_prefix_blocks or 0x94C8C not in setup_prefix_blocks or \
            any(block.end>setup_prefix_stop for block in setup_prefix_blocks.values()):
        raise SystemExit("setup_game entry-to-BIOINTRO boundary no longer matches canonical LE CFG")
    allowed_setup_prefix_targets=set(setup_prefix_blocks)|{setup_prefix_stop}
    for address,block in setup_prefix_blocks.items():
        outside=set(block.successors)-allowed_setup_prefix_targets
        if outside:
            raise SystemExit(f"setup_game prefix block {address:#x} escapes its bounded CFG: {sorted(outside)}")
    setup_prefix_blocks[setup_prefix_stop]=BasicBlock(setup_prefix_stop,setup_prefix_stop+1,
        [Instruction(0x94C93,1,"ret","",b"\xc3",[])],[],True)
    setup_prefix_function=Function(0x94AC0,setup_prefix_stop+1,
        "gw_original_setup_game_biointro_prefix",setup_prefix_blocks,
        size=setup_prefix_stop+1-0x94AC0)
    setup_prefix_c=Lifter().lift_function(setup_prefix_function)
    # 0x94C93 is an interior join before setup_game's epilogue. Stop the
    # bounded prefix as a host test boundary; a synthetic guest RET here would
    # pop the still-live local frame and invent a return target.
    prefix_boundary="L_00094C93:\n"
    if setup_prefix_c.count(prefix_boundary)!=1:
        raise SystemExit("setup_game bounded stop label is missing or ambiguous")
    setup_prefix_c=setup_prefix_c.replace(prefix_boundary,
        prefix_boundary+"    RECOMP_REGS_OUT(); RECOMP_FLAGS_OUT(); return; /* bounded prefix boundary */\n",1)
    closure_report=json.loads(lift_report.read_text(encoding="utf-8"))
    lifted_names={int(row["address"],16):row["lift_name"] for row in closure_report["lifted"]}
    for block in setup_prefix_blocks.values():
        for ins in block.instructions:
            if ins.mnemonic=="call" and ins.get_branch_target():
                target=ins.get_branch_target()
                if target not in lifted_names:
                    raise SystemExit(f"original setup_game prefix call target {target:#x} is absent from partial closure")
                setup_prefix_c=setup_prefix_c.replace(f"sub_{target:08X}",
                    f"recomp_{lifted_names[target]}")
    if "0x00094AC0" not in setup_prefix_c or \
       "0x00094C7E: cmp eax, 0x17be71c" not in setup_prefix_c or \
       "0x00094C85: or byte ptr [0x2f1662], 1" not in setup_prefix_c:
        raise SystemExit("the original setup_game BIOINTRO compare/set-bit prefix changed")
    lifted_text += "\n"+setup_prefix_c+"\nvoid gw_original_setup_game_prefix_entry(void) { gw_original_setup_game_biointro_prefix(); }\n"
    # The unexecuted setup_game continuation immediately before the startup
    # resource block normalizes 31 original 0x2d-byte screen/resource records.
    # This is ordinary guest table initialization (no DOS/VBE/audio service),
    # and FUN_000552C0 at 0x94DFA consumes the fields it writes.
    setup_table_start=0x94DD0
    setup_table_stop=0x94DF3
    setup_table_blocks={a:b for a,b in setup_game_original.blocks.items()
                        if setup_table_start<=a<setup_table_stop}
    if set(setup_table_blocks)!={setup_table_start} or any(
            block.end>setup_table_stop for block in setup_table_blocks.values()):
        raise SystemExit(f"setup_game record-table CFG changed: {sorted(setup_table_blocks)}")
    allowed_table_targets={setup_table_start,setup_table_stop}
    for address,block in setup_table_blocks.items():
        outside=set(block.successors)-allowed_table_targets
        if outside:
            raise SystemExit(f"setup_game record-table block {address:#x} escapes its bounded CFG: {sorted(outside)}")
    setup_table_blocks[setup_table_stop]=BasicBlock(setup_table_stop,setup_table_stop+1,
        [Instruction(setup_table_stop,1,"ret","",b"\xc3",[])],[],True)
    setup_table_function=Function(setup_table_start,setup_table_stop+1,
        "gw_original_setup_game_record_table",setup_table_blocks,
        size=setup_table_stop+1-setup_table_start)
    setup_table_c=Lifter().lift_function(setup_table_function)
    table_boundary="L_00094DF3:\n"
    if setup_table_c.count(table_boundary)!=1:
        raise SystemExit("setup_game original record-table stop boundary is missing or ambiguous")
    setup_table_c=setup_table_c.replace(table_boundary,
        table_boundary+"    RECOMP_REGS_OUT(); RECOMP_FLAGS_OUT(); return; /* bounded setup_game block boundary */\n",1)
    for expected in ("0x00094dd0: mov eax, dword ptr [ebx + 0xa]",
                     "0x00094de7: idiv ecx","0x00094df1: jne 0x94dd0"):
        if expected not in setup_table_c.lower():
            raise SystemExit("setup_game original record-table instruction changed: "+expected)
    lifted_text += "\n"+setup_table_c+"\nvoid gw_original_setup_game_record_table_entry(void) { gw_original_setup_game_record_table(); }\n"
    setup_resource_stop=0x94E44
    setup_resource_blocks={a:b for a,b in setup_game_original.blocks.items()
                           if 0x94DF3<=a<setup_resource_stop}
    expected_resource_blocks={0x94DF3,0x94E26,0x94E3B}
    if set(setup_resource_blocks)!=expected_resource_blocks or any(
            block.end>setup_resource_stop for block in setup_resource_blocks.values()):
        raise SystemExit(f"setup_game startup-resource CFG changed: {sorted(setup_resource_blocks)}")
    allowed_resource_targets=set(setup_resource_blocks)|{setup_resource_stop}
    for address,block in setup_resource_blocks.items():
        outside=set(block.successors)-allowed_resource_targets
        if outside:
            raise SystemExit(f"setup_game startup-resource block {address:#x} escapes its bounded CFG: {sorted(outside)}")
    setup_resource_blocks[setup_resource_stop]=BasicBlock(setup_resource_stop,setup_resource_stop+1,
        [Instruction(setup_resource_stop,1,"ret","",b"\xc3",[])],[],True)
    setup_resource_function=Function(0x94DF3,setup_resource_stop+1,
        "gw_original_setup_game_startup_resources",setup_resource_blocks,
        size=setup_resource_stop+1-0x94DF3)
    setup_resource_c=Lifter().lift_function(setup_resource_function)
    resource_boundary="L_00094E44:\n"
    if setup_resource_c.count(resource_boundary)!=1:
        raise SystemExit("setup_game startup-resource boundary is missing or ambiguous")
    setup_resource_c=setup_resource_c.replace(resource_boundary,
        resource_boundary+"    RECOMP_REGS_OUT(); RECOMP_FLAGS_OUT(); return; /* bounded startup-resource boundary */\n",1)
    for block in setup_resource_blocks.values():
        for ins in block.instructions:
            if ins.mnemonic=="call" and ins.get_branch_target():
                target=ins.get_branch_target()
                if target not in lifted_names:
                    raise SystemExit(f"original setup_game startup call target {target:#x} is absent from partial closure")
                setup_resource_c=setup_resource_c.replace(f"sub_{target:08X}",
                    f"recomp_{lifted_names[target]}")
    for expected in ("0x00094df3: mov eax, 0x35a8f0",
                     "0x00094dfa: call 0x552c0",
                     "0x00094e0a: mov edx, 0x2dd554",
                     "0x00094e0f: call 0x15090",
                     "0x00094e2c: call 0xadeac",
                     "0x00094e3c: call 0xadeac"):
        if expected not in setup_resource_c.lower():
            raise SystemExit("original setup_game startup resource/palette instruction changed: "+expected)
    lifted_text += "\n"+setup_resource_c+"\nvoid gw_original_setup_game_startup_resources_entry(void) { gw_original_setup_game_startup_resources(); }\n"
    # Continue setup_game's original font initialization immediately after
    # startup_files has supplied the font/palette records. This is the block
    # at 0x94E44..0x94EC0, including its seven-object loop (entry 2 is skipped).
    # IFCLevel's later planet labels call the original glyph blitter through
    # the font descriptor at link 0x186BBC; that static object is zero in the
    # shipped LE until this original loop initializes it.
    setup_font_start,setup_font_stop=0x94E44,0x94EC0
    setup_font_blocks={a:b for a,b in setup_game_original.blocks.items()
                       if setup_font_start<=a<setup_font_stop}
    if setup_font_start not in setup_font_blocks or not setup_font_blocks or any(
            block.end>setup_font_stop for block in setup_font_blocks.values()):
        raise SystemExit(f"setup_game font-initializer CFG changed: {sorted(setup_font_blocks)}")
    allowed_font_targets=set(setup_font_blocks)|{setup_font_stop}
    for address,block in setup_font_blocks.items():
        outside=set(block.successors)-allowed_font_targets
        if outside:
            raise SystemExit(f"setup_game font block {address:#x} escapes its bounded CFG: {sorted(outside)}")
    setup_font_blocks[setup_font_stop]=BasicBlock(setup_font_stop,setup_font_stop+1,
        [Instruction(setup_font_stop,1,"ret","",b"\xc3",[])],[],True)
    setup_font_function=Function(setup_font_start,setup_font_stop+1,
        "gw_original_setup_game_font_initializers",setup_font_blocks,
        size=setup_font_stop+1-setup_font_start)
    setup_font_c=Lifter().lift_function(setup_font_function)
    font_boundary="L_00094EC0:\n"
    if setup_font_c.count(font_boundary)!=1:
        raise SystemExit("setup_game font-initializer stop label is missing or ambiguous")
    setup_font_c=setup_font_c.replace(font_boundary,
        font_boundary+"    RECOMP_REGS_OUT(); RECOMP_FLAGS_OUT(); return; /* bounded setup_game font block */\n",1)
    for block in setup_font_blocks.values():
        for ins in block.instructions:
            if ins.mnemonic=="call" and ins.get_branch_target():
                target=ins.get_branch_target()
                if target not in lifted_names:
                    raise SystemExit(f"original setup_game font call target {target:#x} is absent from partial closure")
                setup_font_c=setup_font_c.replace(f"sub_{target:08X}",
                    f"recomp_{lifted_names[target]}")
    for expected in ("0x00094e49: call 0x973b0","0x00094e84: call 0x6ee60",
                     "0x00094eb9: call 0x6ef20","0x00094ebe: jmp 0x94e95"):
        if expected not in setup_font_c.lower():
            raise SystemExit("original setup_game font initializer changed: "+expected)
    lifted_text += "\n"+setup_font_c+"\nvoid gw_original_setup_game_font_initializers_entry(void) { gw_original_setup_game_font_initializers(); }\n"
    # IFCLevel has original interface kind 2. Its palette path is the
    # type-2 tail in draw_game: mark currentIFC dirty, take its palette
    # pointer, and call the original synchronous LbPaletteFade_(palette, 16).
    # Stop only at the shared loop/epilogue join after that operation.
    draw_game_blocks=setup_dis.disassemble_function(0x834C0).blocks
    palette_block_addresses={0x83A0C,0x83A16,0x83A1E,0x83A24,0x83A29,
        0x83A58,0x83A6B,0x83A88}
    palette_blocks={a:draw_game_blocks[a] for a in palette_block_addresses}
    expected_palette_edges={0x83A0C:{0x83A29,0x83A16},
        0x83A16:{0x83A29,0x83A1E},0x83A1E:{0x83A29,0x83A24},
        0x83A24:{0x83A29,0x83A58},0x83A58:{0x83A6B,0x83A88},
        0x83A6B:{0x83A29},0x83A88:{0x83A29}}
    if any(set(palette_blocks[a].successors)!=successors
           for a,successors in expected_palette_edges.items()):
        raise SystemExit("draw_game IFCLevel type-2 palette fade CFG changed")
    palette_blocks[0x83A29]=BasicBlock(0x83A29,0x83A2A,
        [Instruction(0x83A29,1,"ret","",b"\xc3",[])],[],True)
    palette_fragment=Function(0x83A0C,0x83A9A,
        "gw_original_draw_game_level_palette_fade",palette_blocks,
        size=0x83A9A-0x83A0C)
    palette_fragment_c=Lifter().lift_function(palette_fragment)
    palette_boundary="L_00083A29:\n"
    if palette_fragment_c.count(palette_boundary)!=1:
        raise SystemExit("draw_game level-palette fade stop label is missing or ambiguous")
    palette_fragment_c=palette_fragment_c.replace(palette_boundary,
        palette_boundary+"    RECOMP_REGS_OUT(); RECOMP_FLAGS_OUT(); return; /* bounded draw_game tail */\n",1)
    for block in palette_blocks.values():
        for ins in block.instructions:
            if ins.mnemonic=="call" and ins.get_branch_target():
                target=ins.get_branch_target()
                if target not in lifted_names:
                    raise SystemExit(f"draw_game level-palette call target {target:#x} is absent from partial closure")
                palette_fragment_c=palette_fragment_c.replace(f"sub_{target:08X}",
                    f"recomp_{lifted_names[target]}")
    for expected in ("0x00083a0c: mov esi, dword ptr [0x2ef7e8]",
                     "0x00083a63: mov ecx, dword ptr [esi + 2]",
                     "0x00083a7c: call 0xa26f0",
                     "0x00083a94: call 0xa26f0"):
        if expected not in palette_fragment_c.lower():
            raise SystemExit("original draw_game level-palette fade bytes changed: "+expected)
    lifted_text += "\n"+palette_fragment_c+"\nvoid gw_original_draw_game_level_palette_fade_entry(void) { gw_original_draw_game_level_palette_fade(); }\n"
    # Bound the MCB mutation to the original stages inside IFCOptions::PullOut.
    # These are observation hooks after the authentic calls; they do not alter
    # registers or guest state.
    pullout_start=lifted_text.find("void gw_partial_0x0006A600(void) {")
    pullout_end=lifted_text.find("\nvoid ",pullout_start+1)
    if pullout_start<0 or pullout_end<0:
        raise SystemExit("original IFCOptions::PullOut body is missing from generated closure")
    pullout_body=lifted_text[pullout_start:pullout_end]
    for marker,label in (
            ("RECOMP_CALL(recomp_gw_partial_0x000A8B30);",
             "after_FreeMyGadgets"),
            ("RECOMP_CALL(recomp_gw_partial_0x00098B94);",
             "after_LbDataFree_FILESCR"),
            ("RECOMP_CALL(recomp_gw_partial_0x000150D0);",
             "after_LbFileLoadAt_MAIN_GLA")):
        if pullout_body.count(marker)!=1:
            raise SystemExit(f"original IFCOptions::PullOut call boundary missing: {label}")
        pullout_body=pullout_body.replace(marker,marker+f"\n    gw_trace_dos_mcb_chain_current(\"{label}\");",1)
    lifted_text=lifted_text[:pullout_start]+pullout_body+lifted_text[pullout_end:]
    # LbMemoryFree_ marks a heap descriptor free with this original byte
    # store. Capture its exact guest address and descriptor head when a
    # managed heap node aliases the DOS MCB area; this is observation only.
    free_store='MEM8(DS_BASE + (edx + 0x10)) = (uint8_t)(0); /* 0x0009205C: mov byte ptr [edx + 0x10], 0 */'
    if lifted_text.count(free_store)!=2:
        raise SystemExit("expected both emitted copies of the original LbMemoryFree store")
    lifted_text=lifted_text.replace(free_store,free_store+
        '\n    gw_trace_lbm_free_store(0x0009205Cu,DS_BASE,edx,eax);')
    title_pullout_start=lifted_text.find("void gw_partial_0x00070E30(void) {")
    title_pullout_end=lifted_text.find("\nvoid gw_partial_0x00070EB0(void)",title_pullout_start+1)
    if title_pullout_start<0 or title_pullout_end<0:
        raise SystemExit("original IFCTitle::PullOut emitted body is missing")
    title_pullout_body=lifted_text[title_pullout_start:title_pullout_end]
    for marker,label in (
        ("RECOMP_CALL(recomp_gw_partial_0x000A8B30); /* 0x00070E72: call 0xa8b30 */",
         "after_TITLE_FreeMyGadgets"),
        ("RECOMP_CALL(recomp_gw_partial_0x00098B94); /* 0x00070E8A: call 0x98b94 */",
         "after_TITLE_LbDataFree")):
        if title_pullout_body.count(marker)==1:
            title_pullout_body=title_pullout_body.replace(marker,marker+
                f'\n    gw_trace_dos_mcb_chain_current("{label}");',1)
            continue
        # Newer lifted closures annotate every original CALL as
        # GW_RECOMP_CALL_AT(address,target,return,callee); the trace hook may
        # already follow that exact original instruction. Accept the wrapper
        # only when its LE callsite/target/return bytes match and avoid
        # inserting a duplicate observer.
        callsite=0x70E72 if label=="after_TITLE_FreeMyGadgets" else 0x70E8A
        target=0xA8B30 if label=="after_TITLE_FreeMyGadgets" else 0x98B94
        callee=("recomp_gw_partial_0x000A8B30" if target==0xA8B30
                else "recomp_gw_partial_0x00098B94")
        return_eip=callsite+5
        addressed=(f"GW_RECOMP_CALL_AT(0x{callsite:08X}u,0x{target:x}u,0x{return_eip:08X}u,{callee}); "
                   f"/* 0x{callsite:08X}: call 0x{target:x} */")
        if title_pullout_body.count(addressed)!=1:
            raise SystemExit("original IFCTitle::PullOut cleanup call changed: "+label)
        if f'gw_trace_dos_mcb_chain_current("{label}");' not in title_pullout_body:
            title_pullout_body=title_pullout_body.replace(addressed,addressed+
                f'\n    gw_trace_dos_mcb_chain_current("{label}");',1)
    lifted_text=lifted_text[:title_pullout_start]+title_pullout_body+lifted_text[title_pullout_end:]
    # FreeMyGadgets also updates linked gadget nodes directly. Observe each
    # original store if its effective address reaches the conventional DOS
    # allocator headers; this identifies the first corrupting instruction.
    gadget_stores={
        'MEM32(DS_BASE + (edx + 0x12)) = edi; /* 0x000A8B7B: mov dword ptr [edx + 0x12], edi */':'edx+0x12',
        'MEM32(DS_BASE + (edx + 0x16)) = MEM32(DS_BASE + (edx + 0x16)) - eax; /* 0x000A8B85: sub dword ptr [edx + 0x16], eax */':'edx+0x16',
        'MEM32(DS_BASE + (edx + 0x12)) = MEM32(DS_BASE + (edx + 0x12)) - eax; /* 0x000A8B92: sub dword ptr [edx + 0x12], eax */':'edx+0x12',
        'MEM32(DS_BASE + (edx + 0x16)) = esi; /* 0x000A8BA5: mov dword ptr [edx + 0x16], esi */':'edx+0x16',
        'MEM32(DS_BASE + (0x379648)) = ecx; /* 0x000A8BB7: mov dword ptr [0x379648], ecx */':'0x379648',
        'MEM32(DS_BASE + (0x379490)) = edi; /* 0x000A8BC2: mov dword ptr [0x379490], edi */':'0x379490',
        'MEM32(DS_BASE + (ebx)) = edi; /* 0x000A8BC8: mov dword ptr [ebx], edi */':'ebx',
    }
    for store,address in gadget_stores.items():
        if lifted_text.count(store)!=1:
            raise SystemExit("original FreeMyGadgets store changed: "+store[-40:])
        site=int(re.search(r'0x([0-9A-Fa-f]{8}):',store).group(1),16)
        lifted_text=lifted_text.replace(store,store+
            f'\n    gw_trace_gadget_free_store(0x{site:08X}u,DS_BASE+({address}),edx,ebx,esi,edi);',1)
    free_gadget_body_start=lifted_text.find("void gw_partial_0x000A8B30(void) {")
    free_gadget_body_end=lifted_text.find("\nvoid ",free_gadget_body_start+1)
    if free_gadget_body_start<0 or free_gadget_body_end<0:
        raise SystemExit("original FreeMyGadgets body is missing")
    free_gadget_body=lifted_text[free_gadget_body_start:free_gadget_body_end]
    free_gadget_call="RECOMP_CALL(recomp_gw_partial_0x00092030); /* 0x000A8BA8: call 0x92030 */"
    free_gadget_call_at=("GW_RECOMP_CALL_AT(0x000A8BA8u,0x92030u,0x000A8BADu,"
        "recomp_gw_partial_0x00092030); /* 0x000A8BA8: call 0x92030 */")
    if free_gadget_body.count(free_gadget_call)==1:
        free_gadget_call_text=free_gadget_call
    elif free_gadget_body.count(free_gadget_call_at)==1:
        # The reusable lifted closure may already contain the instruction
        # boundary wrapper. Preserve its original call/return bookkeeping and
        # add only the DOS allocator snapshots around it.
        free_gadget_call_text=free_gadget_call_at
    else:
        raise SystemExit("FreeMyGadgets LbMemoryFree callsite changed")
    free_gadget_body=free_gadget_body.replace(free_gadget_call_text,
        'gw_trace_gadget_lbm_call(0x000A8BA8u,0u,eax,edx,ebx);\n    '+free_gadget_call_text+
        '\n    gw_trace_gadget_lbm_call(0x000A8BA8u,1u,eax,edx,ebx);',1)
    lifted_text=lifted_text[:free_gadget_body_start]+free_gadget_body+lifted_text[free_gadget_body_end:]
    # The OPTIONS Update jump table contains relocated guest-linear targets.
    # Both its thunk-rooted body and the separately emitted method body must
    # compare those loaded values while branching to local link-VA labels.
    # This catches the duplicate-body case that previously sent gadget 9 to
    # RECOMP_ITAIL(0x255F06) even though the target is part of this method.
    for function_name in ("gw_partial_0x00013600", "gw_partial_0x0006AB30"):
        function_start=lifted_text.find(f"void {function_name}(void) {{")
        function_end=lifted_text.find("\nvoid ",function_start+1)
        if function_start<0 or function_end<0:
            raise SystemExit(f"generated OPTIONS Update body {function_name} is missing")
        body=lifted_text[function_start:function_end]
        if ("case 0x00255F06u: goto L_0006AF06;" not in body or
                "case 0x0006AF06u: goto L_0006AF06;" in body):
            raise SystemExit(f"rebased OPTIONS jump table is inconsistent in {function_name}")
    # The previous experiment exposed a tight original-code loop after the
    # CRT DPMI callback. Count original guest instruction hooks and stop the
    # replay promptly instead of relying on a wall-clock timeout.
    memset_call_pattern=re.compile(
        r'^(    (?:RECOMP_CALL\(recomp_gw_partial_0x00096C10\)|'
        r'GW_RECOMP_CALL_AT\(0x[0-9A-Fa-f]{8}u,0x96c10u,0x[0-9A-Fa-f]{8}u,'
        r'recomp_gw_partial_0x00096C10\)); /\* (0x[0-9A-Fa-f]{8}): call 0x96c10 \*/)$',
        re.MULTILINE)
    lifted_text,memset_calls=memset_call_pattern.subn(
        lambda m:f'    gw_watch_memset_call({m.group(2)}u,eax,ebx,edx);\n{m.group(1)}',lifted_text)
    if memset_calls<1:
        raise SystemExit("no original 0x96C10 memset callsites found for MCB watch")
    lifted_text, budget_hooks = re.subn(
        r'(    if \(!gw_recomp_guest_instruction\(0x([0-9A-Fa-f]{8})u\)\) return;)',
        lambda m: m.group(1)+f"\n    gw_test_instruction_budget_step(0x{m.group(2)}u);\n    if (gw_test_instruction_budget_exhausted()) return;\n    gw_watch_mcb_instruction(0x{m.group(2)}u,eax,ebx,ecx,edx,esp);",
        lifted_text)
    if budget_hooks < 1:
        raise SystemExit("bounded guest instruction hooks were not found in generated closure")
    init_anim_site=("    gw_test_instruction_budget_step(0x0009745Eu);\n"
        "    if (gw_test_instruction_budget_exhausted()) return;\n"
        "    gw_watch_mcb_instruction(0x0009745Eu,eax,ebx,ecx,edx,esp);")
    if init_anim_site not in lifted_text:
        raise SystemExit("generated W?InitMyAnimBank loop site 0x9745E is unavailable for local-register tracing")
    lifted_text=lifted_text.replace(init_anim_site,
        "    gw_test_init_my_anim_bank_step(0x0009745Eu,eax,ebx,ecx,edx,esi,edi,ebp,esp);\n"+init_anim_site)
    setup_epilogue_site="    esp = (ebp + 0x82); /* 0x00095484: lea esp, [ebp + 0x82] */"
    if lifted_text.count(setup_epilogue_site)<1:
        raise SystemExit("full setup_game epilogue 0x95484 is missing for stack tracing")
    lifted_text=lifted_text.replace(setup_epilogue_site,
        "    gw_test_setup_game_epilogue(0x00095484u,eax,ebx,ecx,edx,esi,edi,ebp,esp);\n"+
        setup_epilogue_site)
    strstr_pop_site=("    recomp_begin_memory_access_ex(RECOMP_SEG_SS, 4u, 0x000AA0CCu, RECOMP_MEM_ACCESS_READ, 585u, \"pop\");\n"
        "    { uint32_t _seg_value = POP32_VAL(esp); if (!recomp_write_segment(RECOMP_SEG_ES, (uint16_t)(_seg_value), 0x000AA0CCu)) return; } /* 0x000AA0CC: pop es */")
    strstr_start=lifted_text.find("void gw_partial_0x000AA079(void) {")
    strstr_end=lifted_text.find("\nvoid ",strstr_start+1)
    if strstr_start<0 or strstr_end<0:
        raise SystemExit("original strstr_ body is unavailable")
    strstr_body=lifted_text[strstr_start:strstr_end]
    if strstr_body.count(strstr_pop_site)<1:
        raise SystemExit("original strstr_ POP ES at 0xAA0CC is not unique")
    strstr_body=strstr_body.replace(strstr_pop_site,
        "    gw_test_strstr_segment_pop(0x000AA0CCu,eax,ebx,ecx,edx,esi,edi,ebp,esp,MEM32(SS_BASE + esp));\n"+
        strstr_pop_site)
    for site in ("000AA079","000AA081","000AA0B3","000AA0BC","000AA0BD","000AA0C3","000AA0C5","000AA0C7","000AA0C8",
        "000AA0CA","000AA0CC","000AA0CD","000AA0D0","000AA0D2","000AA0D7","000AA0DC",
        "000AA0DE","000AA0E0","000AA0E1","000AA0E2","000AA0E4","000AA0E7","000AA0E9",
        "000AA0EB","000AA0ED","000AA0EF","000AA0F1","000AA0F2","000AA0F4","000AA0F8",
        "000AA0FA","000AA0FC","000AA0FD","000AA101","000AA102","000AA104","000AA106",
        "000AA108","000AA10A","000AA10C","000AA10E","000AA113","000AA115","000AA117",
        "000AA119","000AA11B","000AA11E","000AA11F","000AA121","000AA123","000AA125",
        "000AA127","000AA12A","000AA12C","000AA12E","000AA131","000AA132","000AA133",
        "000AA134","000AA135","000AA136"):
        watch=(f"    gw_watch_mcb_instruction(0x{site}u,eax,ebx,ecx,edx,esp);")
        hook=(f"    gw_trace_strstr_stack(0x{site}u,eax,ebx,ecx,edx,esi,edi,ebp,esp,"
              "MEM32(SS_BASE + esp));")
        if watch in strstr_body:
            strstr_body=strstr_body.replace(watch,watch+"\n"+hook)
    lifted_text=lifted_text[:strstr_start]+strstr_body+lifted_text[strstr_end:]
    smack_reader_start=lifted_text.find("void gw_partial_0x000C73B0(void) {")
    smack_reader_end=lifted_text.find("\nvoid ",smack_reader_start+1)
    if smack_reader_start<0 or smack_reader_end<0:
        raise SystemExit("original Smacker stream-reader body is missing")
    smack_reader_body=lifted_text[smack_reader_start:smack_reader_end]
    smack_read_return="esp = esp + 0x14u; /* 0x000C754F: add esp, 0x14 */"
    if smack_reader_body.count(smack_read_return)!=1:
        raise SystemExit("Smacker buffered-read return boundary changed")
    smack_reader_body=smack_reader_body.replace(smack_read_return,
        smack_read_return+"\n    gw_trace_smacker_read_result(0x000C7552u,"
        "MEM32(SS_BASE + (esp + 0x4)),MEM32(SS_BASE + (esp + 0xC)),"
        "MEM32(SS_BASE + (esp + 0x10)),ebp,eax,ebx,ecx,edx,esi,edi,ebp,esp);",1)
    lifted_text=lifted_text[:smack_reader_start]+smack_reader_body+lifted_text[smack_reader_end:]
    dos_read_store=("MEM32(DS_BASE + (edx)) = eax; /* 0x000D730E: mov dword ptr [edx], eax */\n"
                    "    if (recomp_memory_fault_pending()) { RECOMP_FLAGS_OUT(); return; }\n"
                    "    recomp_end_memory_access();")
    if lifted_text.count(dos_read_store)!=1:
        raise SystemExit("original D72C9 output-count store changed")
    lifted_text=lifted_text.replace(dos_read_store,dos_read_store+
        "\n    gw_trace_dos_read_count_store(0x000D730Eu,DS_BASE + edx,eax,esp);",1)
    lifted_text="int gw_test_instruction_budget_exhausted(void);\nvoid gw_test_instruction_budget_step(unsigned int);\nvoid gw_capture_plant17_direct_store(unsigned int,unsigned int,unsigned char);\nvoid gw_trace_plant31_action(unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int);\nvoid gw_test_init_my_anim_bank_step(unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int);\nvoid gw_test_setup_game_epilogue(unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int);\nvoid gw_test_strstr_segment_pop(unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int);\nvoid gw_trace_strstr_stack(unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int);\nvoid gw_trace_smacker_read_result(unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int);\nvoid gw_trace_dos_read_count_store(unsigned int,unsigned int,unsigned int,unsigned int);\nvoid gw_watch_mcb_instruction(unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int);\nvoid gw_watch_memset_call(unsigned int,unsigned int,unsigned int,unsigned int);\nvoid gw_trace_dos_mcb_chain_current(const char *label);\nvoid gw_trace_lbm_free_store(unsigned int,unsigned int,unsigned int,unsigned int);\nvoid gw_trace_gadget_free_store(unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int);\nvoid gw_trace_gadget_lbm_call(unsigned int,unsigned int,unsigned int,unsigned int,unsigned int);\nvoid gw_capture_original_transition_dispatch(unsigned int,unsigned int);\n"+lifted_text
    startup_return_marker=("if (!gw_recomp_guest_instruction(0x000AFBF4u)) return;\n"
                           "    gw_test_instruction_budget_step(0x000AFBF4u);\n"
                           "    if (gw_test_instruction_budget_exhausted()) return;")
    if lifted_text.count(startup_return_marker)!=1:
        raise SystemExit("original startup caller no longer has a unique post-__InitRtns boundary")
    lifted_text=lifted_text.replace(startup_return_marker,
        startup_return_marker+"\n    /* bounded prefix: original __InitRtns has returned */\n    return;",1)
    if "void gw_capture_x87(unsigned int);" not in lifted_text:
        lifted_text="void gw_capture_x87(unsigned int);\n"+lifted_text
    # Capture architectural x87 state immediately around the original
    # FNINIT/FNSTCW/CMP sequence. The hook is observational and writes only to
    # the harness trace, never into guest registers or memory.
    for va in (0xBBE4A,0xBBE4E,0xBBE4F,0xBBE54,0xBBE55,0xBBE59):
        marker=f"if (!gw_recomp_guest_instruction(0x{va:08X}u)) return;"
        if lifted_text.count(marker)!=1:
            raise SystemExit(f"expected one x87 trace point at {va:#x}")
        lifted_text=lifted_text.replace(marker,marker+f"\n    gw_capture_x87(0x{va:08X}u);",1)
    if "memcpy((void*)(_dp+(uintptr_t)_i)" not in lifted_text or "(void*)(_dp+_i)" in lifted_text:
        raise SystemExit("generated REP STOS word/dword host-pointer arithmetic is not width-safe")
    init_dispatch="GW_RECOMP_ICALL_ALLOWED_AT(0x000C8759u, eax, 0x000C875Bu, gw_recomp_icall_allow_000C8759);"
    init_dispatch_legacy="GW_RECOMP_ICALL_ALLOWED(0x000C8759u, eax, gw_recomp_icall_allow_000C8759);"
    if lifted_text.count(init_dispatch)+lifted_text.count(init_dispatch_legacy)!=1:
        raise SystemExit("Watcom __InitRtns CALL EAX is not guarded by its exact verified target allowlist")
    init_report=json.loads(lift_report.read_text(encoding="utf-8"))
    init_targets={int(row["link_target"],16) for row in init_report["verified_indirect_targets"]
                  if row["callsite"]=="0x000C8759"}
    if init_targets!=set(init_rtn_targets):
        raise SystemExit(f"__InitRtns allowlist differs from the 19 fixup-verified init table entries: {sorted(init_targets)}")
    ctor_call_pattern=re.compile(
        r'(?m)^([ \t]*)GW_RECOMP_ICALL_ALLOWED_AT\(0x000A9F3Bu,\s*'
        r'MEM32\(SS_BASE \+ \(esp \+ 0x20\)\),\s*0x000A9F3Fu,\s*'
        r'gw_recomp_icall_allow_000A9F3B\);')
    ctor_trace_already_present=(
        "gw_record_ctor_array_target(0x000A9F3Bu,_gw_ctor_target);" in lifted_text and
        re.search(r"GW_RECOMP_ICALL_ALLOWED_AT\(0x000A9F3Bu,\s*_gw_ctor_target,\s*"
                  r"0x000A9F3Fu,\s*gw_recomp_icall_allow_000A9F3B\)",lifted_text) is not None)
    if not ctor_trace_already_present:
        ctor_legacy_pattern=re.compile(
            r'(?m)^([ \t]*)GW_RECOMP_ICALL_ALLOWED\(0x000A9F3Bu,\s*'
            r'(MEM32\(SS_BASE \+ \(esp \+ 0x20\)\)),\s*'
            r'gw_recomp_icall_allow_000A9F3B\);([\s\S]*?)$')
        if ctor_call_pattern.search(lifted_text):
            lifted_text=ctor_call_pattern.sub(
                lambda m:(f'{m.group(1)}{{ uint32_t _gw_ctor_target=MEM32(SS_BASE + (esp + 0x20)); '
                          f'gw_record_ctor_array_target(0x000A9F3Bu,_gw_ctor_target); '
                          f'GW_RECOMP_ICALL_ALLOWED_AT(0x000A9F3Bu,_gw_ctor_target,0x000A9F3Fu,'
                          f'gw_recomp_icall_allow_000A9F3B); }}'),lifted_text)
        elif ctor_legacy_pattern.search(lifted_text):
            lifted_text=ctor_legacy_pattern.sub(
                lambda m:(f'{m.group(1)}{{ uint32_t _gw_ctor_target={m.group(2)}; '
                          f'gw_record_ctor_array_target(0x000A9F3Bu,_gw_ctor_target); '
                          f'GW_RECOMP_ICALL_ALLOWED_AT(0x000A9F3Bu,_gw_ctor_target,0x000A9F3Fu,'
                          f'gw_recomp_icall_allow_000A9F3B); }}'),lifted_text)
        else:
            raise SystemExit("Watcom constructor-array indirect callsite 0xA9F3B is missing its exact allowlist")
    # Validate the canonical body bounds against Capstone; execute the
    # complete generated function, without a test-only CFG splice.
    from tools.disasm.disasm32 import BasicBlock, Function, Instruction
    from tools.lift.lift32 import Lifter
    from tools.pe.pe_analyze import Section
    obj=image.objects[0]
    dis=Disassembler(bytes(image.object_data(1)),0,
        [Section(".text",obj.base,obj.virtual_size,0,obj.virtual_size,0x20000020)])
    head=[i for i in dis.disassemble_at(0x70D10,max_bytes=0x100) if i.address<0x70D4A]
    full=dis.disassemble_function(0x70D10)
    tail=[i for b in full.blocks.values() for i in b.instructions if i.address>=0x70E28]
    if not head or head[-1].address+head[-1].size!=0x70D4A or \
            [i.address for i in tail]!=[0x70E28,0x70E29,0x70E2A,0x70E2B,0x70E2C]:
        raise SystemExit("IFCTitle::PlugIn first-load boundary or original epilogue changed")
    if not any(i.address==0x70D45 for b in full.blocks.values() for i in b.instructions):
        raise SystemExit("original PlugIn TITLESCR.DAT load call is absent from the full function body")
    # Original block from PlaySmacker: dimensions established by original
    # LbScreenSetup_ -> width*height -> original LbMemoryAlloc_ -> original
    # store into b_screen. This isolated fragment does not assert a natural
    # pre-title call sequence.
    alloc_ins=[i for i in dis.disassemble_at(0x92B71,max_bytes=0x40) if i.address<0x92B87]
    if not alloc_ins or alloc_ins[-1].address+alloc_ins[-1].size!=0x92B87:
        raise SystemExit("original b_screen allocation/store block boundary changed")
    alloc_ins=[Instruction(i.address,i.size,i.mnemonic,i.op_str,bytes(i.bytes),i.operands) for i in alloc_ins]
    alloc_ins.append(Instruction(0x92B87,1,"ret","",b"\xc3",[]))
    alloc_slice=Function(0x92B71,0x92B88,"gw_original_bscreen_alloc_store",
        {0x92B71:BasicBlock(0x92B71,0x92B88,alloc_ins,is_exit=True)},size=0x17)
    alloc_c=Lifter().lift_function(alloc_slice)
    alloc_c=alloc_c.replace("RECOMP_CALL(sub_00091E00)",
                            "RECOMP_CALL(recomp_gw_partial_0x00091E00)")
    if "RECOMP_CALL(recomp_gw_partial_0x00091E00)" not in alloc_c or "0x00092B82" not in alloc_c:
        raise SystemExit("original b_screen block no longer calls allocator then stores b_screen")
    lifted_text += "\n"+alloc_c+"\n"
    # Exercise the exact virtual dispatch instructions from control_game that
    # fetch currentIFC and call vtable slot +8. The callsite slice is bounded
    # to those original instructions; Update and its object-adjustment thunk
    # are lifted from canonical LE bytes through the existing generator/lifter.
    update_thunk=Lifter().lift_function(exact_slice(dis,0x13700,2,
        "gw_original_ifctitle_update_adjustment_thunk"))
    update_dispatch=Lifter().lift_function(exact_slice(dis,0x5AF12,3,
        "gw_original_control_game_update_dispatch",True))
    if "RECOMP_ITAIL(0x00070EB0u)" not in update_thunk or \
            "RECOMP_ICALL(MEM32(DS_BASE + (edx + 0x8)))" not in update_dispatch:
        raise SystemExit("original control_game -> IFCTitle::Update dispatch bytes changed")
    lifted_text += "\n"+update_thunk+"\n"+update_dispatch+"\n"
    # The bounded IFCLevel continuation below executes the original frame
    # work in the same order as game(): controller/Update, Draw, palette fade,
    # then this one original instruction from the game-loop tail advances the
    # global animation tick. It is not a harness-side store to the clock.
    game_timer_tick=Lifter().lift_function(exact_slice(dis,0x928AF,1,
        "gw_original_game_frame_timer_tick",True))
    if "0x000928af: inc dword ptr [0x2f1472]" not in game_timer_tick.lower():
        raise SystemExit("original game() frame-timer increment at 0x928AF changed")
    lifted_text += "\n"+game_timer_tick+"\nvoid gw_original_game_frame_timer_tick_entry(void) { gw_original_game_frame_timer_tick(); }\n"
    # Keep the original game() transition block intact. The test will execute
    # it after the title frame is captured; the current IFC PullOut is lifted,
    # while an unlifted pending IFC PlugIn must stop at the normal fail-closed
    # indirect-call boundary.
    transition_dispatch=Lifter().lift_function(exact_slice(dis,0x92819,9,
        "gw_original_game_interface_transition_dispatch",True))
    if "RECOMP_ICALL(MEM32(DS_BASE + (ebx + 0x4)))" not in transition_dispatch or \
            "RECOMP_ICALL(MEM32(DS_BASE + (ebx)))" not in transition_dispatch or \
            "MEM32(DS_BASE + (0x2EF7EC)) = eax" not in transition_dispatch:
        raise SystemExit("original game pending-interface dispatch bytes changed")
    transition_pullout=re.compile(r"RECOMP_ICALL\(MEM32\(DS_BASE \+ \(ebx \+ 0x4\)\)\);[^\n]*\n\s*RECOMP_FLAGS_IN\(\);")
    transition_plugin=re.compile(r"RECOMP_ICALL\(MEM32\(DS_BASE \+ \(ebx\)\)\);[^\n]*\n\s*RECOMP_FLAGS_IN\(\);")
    if len(transition_pullout.findall(transition_dispatch))!=1 or \
            len(transition_plugin.findall(transition_dispatch))!=1:
        raise SystemExit("game() transition callsites no longer have unique MCB trace boundaries")
    transition_dispatch=transition_pullout.sub(lambda m:
        "    gw_capture_original_transition_dispatch(1u,MEM32(DS_BASE + (ebx + 0x4)));\n"+
        m.group(0)+"\n    gw_trace_dos_mcb_chain_current(\"after_OPTIONS_PullOut\");",
        transition_dispatch,count=1)
    transition_dispatch=transition_plugin.sub(lambda m:
        "    gw_capture_original_transition_dispatch(3u,MEM32(DS_BASE + ebx));\n"+
        m.group(0)+"\n    gw_trace_dos_mcb_chain_current(\"after_pending_TITLE_PlugIn\");",
        transition_dispatch,count=1)
    # These original virtual calls are converted to exact target allowlists
    # below from the LE fixup-backed --verified-indirect-target manifest.
    pullout_thunk=Lifter().lift_function(exact_slice(dis,0x13710,2,
        "gw_original_ifctitle_pullout_adjustment_thunk"))
    if "RECOMP_ITAIL(0x00070E30u)" not in pullout_thunk:
        raise SystemExit("original current-IFC PullOut adjustment thunk changed")
    lifted_text += "\n"+transition_dispatch+"\n"+pullout_thunk+"\n"
    options_plugin_thunk=Lifter().lift_function(exact_slice(dis,0x13620,2,
        "gw_original_ifcoptions_plugin_adjustment_thunk"))
    if "RECOMP_ITAIL(0x0006A3D0u)" not in options_plugin_thunk:
        raise SystemExit("original pending-interface adjustment thunk no longer targets 0x6A3D0")
    options_update_thunk=Lifter().lift_function(exact_slice(dis,0x13600,2,
        "gw_original_ifcoptions_update_adjustment_thunk"))
    if "RECOMP_ITAIL(0x0006AB30u)" not in options_update_thunk:
        raise SystemExit("original IFCOptions Update adjustment thunk no longer targets 0x6AB30")
    options_draw_thunk=Lifter().lift_function(exact_slice(dis,0x135F0,2,
        "gw_original_ifcoptions_draw_adjustment_thunk"))
    if "RECOMP_ITAIL(0x0006A700u)" not in options_draw_thunk:
        raise SystemExit("original IFCOptions Draw adjustment thunk no longer targets 0x6A700")
    options_pullout_thunk=Lifter().lift_function(exact_slice(dis,0x13610,2,
        "gw_original_ifcoptions_pullout_adjustment_thunk"))
    if "RECOMP_ITAIL(0x0006A600u)" not in options_pullout_thunk:
        raise SystemExit("original IFCOptions PullOut adjustment thunk no longer targets 0x6A600")
    options_pullout_thunk=options_pullout_thunk.replace("    RECOMP_ITAIL(0x0006A600u);",
        "    gw_capture_original_transition_dispatch(0x2u,0x0006A600u);\n    RECOMP_ITAIL(0x0006A600u);")
    title_plugin_return_thunk=Lifter().lift_function(exact_slice(dis,0x13720,2,
        "gw_original_ifctitle_return_plugin_adjustment_thunk"))
    if "RECOMP_ITAIL(0x00070D10u)" not in title_plugin_return_thunk:
        raise SystemExit("returned TITLE vtable slot 0 no longer targets IFCTitle::PlugIn 0x70D10")
    title_plugin_return_thunk=title_plugin_return_thunk.replace("    RECOMP_ITAIL(0x00070D10u);",
        "    gw_capture_original_transition_dispatch(0x4u,0x00070D10u);\n    RECOMP_ITAIL(0x00070D10u);")
    lifted_text += "\n"+options_plugin_thunk+"\n"+options_update_thunk+"\n"+options_draw_thunk+"\n"+options_pullout_thunk+"\n"+title_plugin_return_thunk+"\n"
    lifted_text += "\nvoid gw_original_game_interface_transition_entry(void) { gw_original_game_interface_transition_dispatch(); }\n"
    # setup_game's exact input-state initializer. Keep the straight-line block
    # through the original REP copy: it stores the native input-structure pointer
    # and initializes its adjacent 0x300-byte controller state from guest data.
    input_ins=[Instruction(i.address,i.size,i.mnemonic,i.op_str,bytes(i.bytes),i.operands)
        for i in dis.disassemble_at(0x94EC0,max_bytes=0x100) if i.address<0x94EF5]
    if not input_ins or input_ins[0].address!=0x94EC0 or \
            input_ins[-1].address+input_ins[-1].size!=0x94EF5:
        raise SystemExit("setup_game input-state block 0x94EC0..0x94EF5 no longer decodes exactly")
    input_end=input_ins[-1].address+input_ins[-1].size
    input_ins.append(Instruction(input_end,1,"ret","",b"\xc3",[]))
    input_slice=Function(0x94EC0,input_end+1,"gw_original_setup_input_state",
        {0x94EC0:BasicBlock(0x94EC0,input_end+1,input_ins,is_exit=True)},
        size=input_end+1-0x94EC0)
    input_init_c=Lifter().lift_function(input_slice)
    if "0x2F1668" not in input_init_c or "0x002F1465" not in input_init_c or \
            "rep movs" not in input_init_c.lower():
        raise SystemExit("original setup_game input pointer/copy block changed")
    lifted_text += "\n"+input_init_c+"\nvoid gw_original_setup_input_state_entry(void) { gw_original_setup_input_state(); }\n"
    # Continue setup_game through the original palette-pointer store at
    # 0x94EFA and its CPU-only SetupColorLookups call. The caller first stores
    # the authentic main.pal pointer at 0x185E9C, then passes the containing
    # object at 0x185E9A to W?SetupColorLookups (0x5B8C0). Keep this exact
    # straight-line slice and stop after that call returns.
    color_start,color_stop=0x94EF5,0x94F09
    color_ins=[Instruction(i.address,i.size,i.mnemonic,i.op_str,bytes(i.bytes),i.operands)
        for i in dis.disassemble_at(color_start,max_bytes=0x40) if i.address<color_stop]
    if not color_ins or color_ins[0].address!=color_start or \
            color_ins[-1].address+color_ins[-1].size!=color_stop or \
            not any(i.mnemonic=="call" and i.get_branch_target()==0x5B8C0 for i in color_ins):
        raise SystemExit("setup_game 0x94EF5..0x94F09 palette lookup block no longer matches canonical LE")
    color_ins.append(Instruction(color_stop,1,"ret","",b"\xc3",[]))
    color_slice=Function(color_start,color_stop+1,"gw_original_setup_game_color_lookups",
        {color_start:BasicBlock(color_start,color_stop+1,color_ins,is_exit=True)},size=color_stop+1-color_start)
    color_init_c=Lifter().lift_function(color_slice)
    color_call="sub_0005B8C0"
    if color_init_c.count(color_call)!=1 or 0x5B8C0 not in lifted_names:
        raise SystemExit("original setup_game color lookup call is not uniquely backed by the partial closure")
    color_init_c=color_init_c.replace(color_call,f"recomp_{lifted_names[0x5B8C0]}")
    lifted_text += "\n"+color_init_c+"\nvoid gw_original_setup_game_color_lookups_entry(void) { gw_original_setup_game_color_lookups(); }\n"
    # Continue the hardware-independent setup_game vector-address block. It
    # selects the original software vector/data ranges and calls setup_vecs_
    # only on the same branch selected by the original counters. No host
    # hardware service is involved; stop at the next table-building block.
    vector_start,vector_stop=0x94F09,0x94F87
    vector_blocks={a:b for a,b in setup_game_original.blocks.items()
                   if vector_start<a<vector_stop}
    vector_source=next((b for b in setup_game_original.blocks.values()
        if any(ins.address<=vector_start<ins.address+ins.size for ins in b.instructions)),None)
    if vector_source is not None:
        vector_first_instructions=[ins for ins in vector_source.instructions
                                   if ins.address>=vector_start]
        vector_blocks[vector_start]=BasicBlock(vector_start,vector_source.end,
            vector_first_instructions,list(vector_source.successors),vector_source.is_exit)
    if vector_start not in vector_blocks or not vector_blocks or any(
            block.end>vector_stop for block in vector_blocks.values()):
        raise SystemExit(f"setup_game setup_vecs CFG changed: {sorted(vector_blocks)}")
    allowed_vector_targets=set(vector_blocks)|{vector_stop}
    for address,block in vector_blocks.items():
        outside=set(block.successors)-allowed_vector_targets
        if outside:
            raise SystemExit(f"setup_game setup_vecs block {address:#x} escapes its bounded CFG: {sorted(outside)}")
    vector_blocks[vector_stop]=BasicBlock(vector_stop,vector_stop+1,
        [Instruction(vector_stop,1,"ret","",b"\xc3",[])],[],True)
    vector_function=Function(vector_start,vector_stop+1,
        "gw_original_setup_game_vector_init",vector_blocks,
        size=vector_stop+1-vector_start)
    vector_init_c=Lifter().lift_function(vector_function)
    vector_boundary="L_00094F87:\n"
    if vector_init_c.count(vector_boundary)!=1:
        raise SystemExit("setup_game vector-init stop boundary is missing or ambiguous")
    vector_init_c=vector_init_c.replace(vector_boundary,
        vector_boundary+"    RECOMP_REGS_OUT(); RECOMP_FLAGS_OUT(); return; /* bounded setup_game vector block */\n",1)
    vector_call="sub_000E8963"
    if vector_init_c.count(vector_call)!=1 or 0xE8963 not in lifted_names:
        raise SystemExit("original setup_game setup_vecs_ call is not uniquely backed by the LE closure")
    vector_init_c=vector_init_c.replace(vector_call,f"recomp_{lifted_names[0xE8963]}")
    for block in vector_blocks.values():
        for ins in block.instructions:
            if ins.mnemonic=="call" and ins.get_branch_target():
                target=ins.get_branch_target()
                if target not in lifted_names:
                    raise SystemExit(f"original setup_game vector-init call target {target:#x} is absent from partial closure")
                vector_init_c=vector_init_c.replace(f"sub_{target:08X}",
                    f"recomp_{lifted_names[target]}")
    for expected in ("0x00094f4a: mov edi, dword ptr [0x376a7c]",
                     "0x00094f60: call 0xe8963",
                     "0x00094f81: mov byte ptr [0x346d6f], ch"):
        if expected not in vector_init_c.lower():
            raise SystemExit("original setup_game vector initializer changed: "+expected)
    lifted_text += "\n"+vector_init_c+"\nvoid gw_original_setup_game_vector_init_entry(void) { gw_original_setup_game_vector_init(); }\n"
    draw_thunk=Lifter().lift_function(exact_slice(dis,0x136F0,2,
        "gw_original_ifctitle_draw_adjustment_thunk"))
    draw_dispatch=Lifter().lift_function(exact_slice(dis,0x83559,3,
        "gw_original_draw_game_draw_dispatch",True))
    if "RECOMP_ITAIL(0x000710B0u)" not in draw_thunk or \
            "RECOMP_ICALL(MEM32(DS_BASE + (edx + 0xC)))" not in draw_dispatch:
        raise SystemExit("original draw_game -> IFCTitle::Draw dispatch bytes changed")
    lifted_text += "\n"+draw_thunk+"\n"+draw_dispatch+"\n"
    rnc_calls=(
        '    RECOMP_CALL(recomp_gw_partial_0x000B9CFC); /* 0x00097EE0: call 0xb9cfc */',
        '    GW_RECOMP_CALL_AT(0x00097EE0u,0xb9cfcu,0x00097EE5u,recomp_gw_partial_0x000B9CFC); /* 0x00097EE0: call 0xb9cfc */',
    )
    rnc_payload='    esi = edi; /* 0x000B9DA1: mov esi, edi */'
    rnc_call=next((candidate for candidate in rnc_calls if candidate in lifted_text),None)
    if rnc_call is None or rnc_payload not in lifted_text:
        raise SystemExit("cannot instrument the exact original LbDataLoad RNC callsite")
    lifted_text=lifted_text.replace('#include "gw_segments.h"',
        '#include "gw_segments.h"\nvoid gw_record_ctor_array_target(uint32_t,uint32_t);\nvoid gw_capture_lbdataload_rnc_args(uint32_t,uint32_t,uint32_t);\nvoid gw_capture_lbdataload_relocated_payload(uint32_t);',1)
    # Generated closure variants may contain both a narrow root and a wider
    # containing function. Instrument each emitted copy once, preserving the
    # original call and staying idempotent when the staged C is reused.
    if 'gw_capture_lbdataload_rnc_args(eax,ecx,edx);' not in lifted_text:
        lifted_text=lifted_text.replace(rnc_call,
            '    gw_capture_lbdataload_rnc_args(eax,ecx,edx);\n'+rnc_call)
    if 'gw_capture_lbdataload_relocated_payload(esi);' not in lifted_text:
        lifted_text=lifted_text.replace(rnc_payload,
            rnc_payload+'\n    gw_capture_lbdataload_relocated_payload(esi);')
    options_fileload_calls={
        0x6A481: (
            '    RECOMP_CALL(recomp_gw_partial_0x000150D0); /* 0x0006A481: call 0x150d0 */',
            '    GW_RECOMP_CALL_AT(0x0006A481u,0x150d0u,0x0006A486u,recomp_gw_partial_0x000150D0); /* 0x0006A481: call 0x150d0 */',
        ),
        0x6A495: (
            '    RECOMP_CALL(recomp_gw_partial_0x000150D0); /* 0x0006A495: call 0x150d0 */',
            '    GW_RECOMP_CALL_AT(0x0006A495u,0x150d0u,0x0006A49Au,recomp_gw_partial_0x000150D0); /* 0x0006A495: call 0x150d0 */',
        ),
    }
    for site,candidates in options_fileload_calls.items():
        call=next((candidate for candidate in candidates if candidate in lifted_text),None)
        if call is None:
            raise SystemExit(f"original OPTIONS LbFileLoadAt site 0x{site:X} changed")
        instrumented=(f'    gw_trace_options_fileload(0x{site:08X}u,0u,eax,ebx,edx);\n'+call+
            f'\n    gw_trace_options_fileload(0x{site:08X}u,1u,eax,ebx,edx);')
        # Full game() CFG lifting may materialize an original block in both a
        # narrow root and its containing function. Instrument every emitted
        # copy; the instruction sequence itself remains unchanged.
        lifted_text=lifted_text.replace(call,instrumented)
    lifted_text=lifted_text.replace('#include "gw_segments.h"',
        '#include "gw_segments.h"\nvoid gw_trace_options_fileload(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t);\nvoid gw_trace_options_load_attempt(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t);',1)
    lfa_calls=(
        '    RECOMP_CALL(recomp_gw_partial_0x00097E9C); /* 0x00015176: call 0x97e9c */',
        '    GW_RECOMP_CALL_AT(0x00015176u,0x97e9cu,0x0001517Bu,recomp_gw_partial_0x00097E9C); /* 0x00015176: call 0x97e9c */',
    )
    lfa_call=next((candidate for candidate in lfa_calls if candidate in lifted_text),None)
    if lfa_call is None:
        raise SystemExit("original OPTIONS LbFileLoadAt retry callsite 0x15176 changed")
    if 'gw_trace_options_load_attempt(0u,ebx,eax,ebx,edx);' not in lifted_text:
        lifted_text=lifted_text.replace(lfa_call,
            '    gw_trace_options_load_attempt(0u,ebx,eax,ebx,edx);\n'+lfa_call+
            '\n    gw_trace_options_load_attempt(1u,ebx,eax,ebx,edx);')
    text_calls={0x710EB,0x7110A,0x71129,0x71148}
    lifted_text=lifted_text.replace('#include "gw_segments.h"',
        '#include "gw_segments.h"\nvoid gw_trace_title_text_call(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t);\nvoid gw_trace_title_text_begin(uint32_t);\nvoid gw_trace_title_text_end(uint32_t);',1)
    for site in text_calls:
        call_re=re.compile(rf'(?m)^([ \t]*(?:RECOMP_CALL\(recomp_gw_partial_0x0006F100\)|GW_RECOMP_CALL_AT\(0x{site:08X}u,0x6f100u,0x[0-9A-Fa-f]+u,recomp_gw_partial_0x0006F100\)); /\* 0x{site:08X}: call 0x6f100 \*/)$')
        calls=list(call_re.finditer(lifted_text))
        if not calls:
            raise SystemExit(f"original IFCTitle::Draw text callsite 0x{site:X} changed")
        if f'gw_trace_title_text_call(0x{site:08X}u,eax,edx,ecx,ebx);' not in lifted_text:
            for match in reversed(calls):
                call=match.group(1)
                instrumented=(f'    gw_trace_title_text_call(0x{site:08X}u,eax,edx,ecx,ebx);\n'
                    f'    gw_trace_title_text_begin(0x{site:08X}u);\n'+call+
                    f'\n    gw_trace_title_text_end(0x{site:08X}u);')
                lifted_text=lifted_text[:match.start()]+instrumented+lifted_text[match.end():]
    report=json.loads(lift_report.read_text(encoding="utf-8"))
    if report["partial_rejections"] or report["missing_or_unsupported"] or report["unresolved_direct_calls"]:
        raise SystemExit("bounded original LbDataLoad closure is incomplete")
    lifted={int(row["address"],16) for row in report["lifted"]}
    need={0x70D10,0x70E30,0x1B650,0x1B640,0x1B630,0x1B620,
        0x14FF0,0x15090,0x150D0,0x955E0,0x989EC,0x921F0,0x91E00,0x91E90,0x97DF0,0x97E9C,0xB9CFC,0x98C70,0x98D70,0x962F0,0x9FD40,0x6EE60,0x5B170}
    need.update((0x15710,0x15CF0,0x179F0,0x177C0))
    if not need.issubset(lifted): raise SystemExit(f"missing original resource-load functions: {sorted(need-lifted)}")
    parser_row=next(row for row in report["lifted"] if int(row["address"],16)==0x955E0)
    parser_lift_name=parser_row["lift_name"]
    if f"void recomp_{parser_lift_name}(void)" not in lifted_text:
        raise SystemExit(f"original TEXT.DAT parser ABI wrapper is missing for {parser_lift_name}")
    # Host-only ABI bridge: all parser work remains in FUN_000955E0's lifted
    # original instructions; this bridge only enters the generated wrapper.
    lifted_text += f"\nvoid gw_original_text_parser_entry(void) {{ recomp_{parser_lift_name}(); }}\n"
    clip_row=next(row for row in report["lifted"] if int(row["address"],16)==0x6EE60)
    clip_lift_name=clip_row["lift_name"]
    if f"void recomp_{clip_lift_name}(void)" not in lifted_text:
        raise SystemExit("original FUN_0006EE60 text clipping initializer is absent from the closure")
    # Call the lifted original initializer directly. The register contract
    # below is taken from setup_game's observed call: x=0,y=0 and width/height
    # equal the selected 640x480 guest screen. The original function performs
    # every write to its text-window globals.
    lifted_text += f"\nvoid gw_original_text_clip_entry(void) {{ recomp_{clip_lift_name}(); }}\n"
    controller_row=next(row for row in report["lifted"] if int(row["address"],16)==0x5B170)
    controller_lift_name=controller_row["lift_name"]
    if f"void recomp_{controller_lift_name}(void)" not in lifted_text:
        raise SystemExit("original setup_controller/0x5B170 is absent from the lifted closure")
    lifted_text += f"\nvoid gw_original_setup_controller_entry(void) {{ recomp_{controller_lift_name}(); }}\n"
    lifted_text=lifted_text.replace('#include "gw_segments.h"',
        '#include "gw_segments.h"\nvoid gw_trace_heap_step(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t);\nvoid gw_trace_rational_stack(uint32_t,const char*,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint16_t,uint32_t,uint32_t,uint32_t);',1)
    # Record every original instruction in the allocator/fallback functions
    # into a bounded ring. The ring is dumped only when the exact DOS AH=48
    # failure (AX=8, BX=largest available 0x06f7 paragraphs) occurs; later
    # instructions stream until the shared RET epilogue. This preserves the
    # pre-failure call/stack history without flooding unrelated execution.
    capstone_alloc={i.address:f"{i.mnemonic} {i.op_str}".strip()
        for i in dis.disassemble_at(0xC3CA9,max_bytes=0x400)
        if 0xC3CA9<=i.address<=0xC3E30}
    def add_stack_trace_to_span(text:str,start_va:int,end_va:int)->str:
        matches=list(re.finditer(r'    if \(!gw_recomp_guest_instruction\(0x([0-9A-Fa-f]{8})u\)\) return;',text))
        for match in reversed(matches):
            va=int(match.group(1),16)
            if not start_va<=va<=end_va: continue
            marker_end=match.end()
            # Keep the hook after the bounded-instruction guard if one was
            # emitted, so diagnostics never bypass the replay's stop budget.
            budget='\n    if (gw_test_instruction_budget_exhausted()) return;'
            budget_at=text.find(budget,marker_end,marker_end+180)
            insert_at=budget_at+len(budget) if budget_at>=0 else marker_end
            insn=capstone_alloc.get(va,"unmapped").replace('\\','\\\\').replace('"','\\"')
            hook=(f'\n    gw_trace_rational_stack(0x{va:08X}u,"{insn}",'
                  'eax,ebx,ecx,edx,esi,edi,ebp,esp,_seg_ss,SS_BASE,_cf,'
                  'recomp_eflags(_flag_k,_flag_a,_flag_b,_cf,_df));')
            text=text[:insert_at]+hook+text[insert_at:]
        return text
    rational_start=lifted_text.find('void gw_partial_0x000C3CA9(void) {')
    rational_end=lifted_text.find('void gw_partial_0x000C3D7A(void) {',rational_start)
    if rational_start<0 or rational_end<0:
        raise SystemExit("RationalAlloc/CreateNewNHeap generated bodies are absent")
    lifted_text=(lifted_text[:rational_start]+
        add_stack_trace_to_span(lifted_text[rational_start:rational_end],0xC3CA9,0xC3D79)+
        lifted_text[rational_end:])
    create_start=lifted_text.find('void gw_partial_0x000C3D7A(void) {',rational_start)
    create_end=lifted_text.find('\nvoid gw_partial_',create_start+1)
    if create_end<0: create_end=len(lifted_text)
    lifted_text=(lifted_text[:create_start]+
        add_stack_trace_to_span(lifted_text[create_start:create_end],0xC3D7A,0xC3E30)+
        lifted_text[create_end:])
    # This is the verified caller's original near CALL into CreateNewNHeap;
    # retain its pre-call ESP and return-slot contents in the ring as well.
    caller_hook='if (!gw_recomp_guest_instruction(0x000C3E54u)) return;'
    if lifted_text.count(caller_hook)!=1:
        raise SystemExit("original CreateNewNHeap callsite 0xC3E54 is not unique")
    caller_trace=(caller_hook+'\n    gw_trace_rational_stack(0x000C3E54u,"call 0xc3d7a",'
        'eax,ebx,ecx,edx,esi,edi,ebp,esp,_seg_ss,SS_BASE,_cf,'
        'recomp_eflags(_flag_k,_flag_a,_flag_b,_cf,_df));')
    lifted_text=lifted_text.replace(caller_hook,caller_trace,1)
    # Capture the original allocator stack at its direct caller, DPMI/DOS
    # transitions, and shared RET epilogue. This is narrowly scoped to the
    # new 0xF10 dynamic-return frontier.
    for site in (0xC3E54,0xC3E59,0xC3D7A,0xC3D98,0xC3D9D,0xC3DB0,0xC3DB5,0xC3D71,0xC3D79):
        guest_hook=f"if (!gw_recomp_guest_instruction(0x{site:08X}u)) return;"
        search_from=(lifted_text.find("RECOMP_ENTER(0x000C3D7Au)")
                     if site in (0xC3D71,0xC3D79) else 0)
        start=lifted_text.find(guest_hook,search_from)
        if start<0: raise SystemExit(f"allocator trace site 0x{site:08X} is absent from generated closure")
        end_marker="if (gw_test_instruction_budget_exhausted()) return;"
        end=lifted_text.find(end_marker,start)
        if end<0: raise SystemExit(f"allocator trace budget marker at 0x{site:08X} is absent")
        end+=len(end_marker)
        hook=(f"\n    gw_trace_heap_step(0x{site:08X}u,eax,ebx,ecx,edx,esi,edi,ebp,esp,"
              "MEM32(SS_BASE + (esp)));\n")
        lifted_text=lifted_text[:end]+hook+lifted_text[end:]
    # The 0xC3CA9 function shares its physical epilogue bytes with
    # 0xC3D7A; instrument both owners independently to detect register/stack
    # propagation across the nested original call.
    rational_start=lifted_text.find("RECOMP_ENTER(0x000C3CA9u)")
    for site,tag in ((0xC3CA9,0x1C3CA9),(0xC3CBD,0x1C3CBD),
                     (0xC3D23,0x1C3D23),(0xC3D37,0x1C3D37),
                     (0xC3D48,0x1C3D48),(0xC3D4C,0x1C3D4C),
                     (0xC3D4F,0x1C3D4F),(0xC3D71,0x1C3D71),
                     (0xC3D79,0x1C3D79)):
        guest_hook=f"if (!gw_recomp_guest_instruction(0x{site:08X}u)) return;"
        start=lifted_text.find(guest_hook,rational_start)
        if start<0: raise SystemExit(f"RationalAlloc trace site 0x{site:08X} is absent")
        end_marker="if (gw_test_instruction_budget_exhausted()) return;"
        end=lifted_text.find(end_marker,start)
        if end<0: raise SystemExit(f"RationalAlloc budget marker at 0x{site:08X} is absent")
        end+=len(end_marker)
        hook=(f"\n    gw_trace_heap_step(0x{tag:08X}u,eax,ebx,ecx,edx,esi,edi,ebp,esp,"
              "MEM32(SS_BASE + (esp)));\n")
        lifted_text=lifted_text[:end]+hook+lifted_text[end:]
    # These file-close callback slots are statically fixup-backed in the
    # original LE image and point to this one-byte RET in object 1. Include
    # that exact instruction so the existing dispatcher resolves the loaded
    # target without relaxing its fail-closed policy.
    callback_ins=list(dis.disassemble_at(0x98C18,max_bytes=1))
    if len(callback_ins)!=1 or callback_ins[0].mnemonic.lower()!="ret" or \
            bytes(callback_ins[0].bytes)!=b"\xC3":
        raise SystemExit("canonical LE callback at 0x98C18 is no longer the expected one-byte RET")
    null_callback=Lifter().lift_function(exact_slice(
        dis,0x98C18,1,"gw_original_null_callback_98c18"))
    lifted_text += "\n"+null_callback+"\n"
    stack_guard_calls=(
        '    RECOMP_CALL(recomp_gw_partial_0x000D21E4); /* 0x000BAD98: call 0xd21e4 */',
        '    GW_RECOMP_CALL_AT(0x000BAD98u,0xd21e4u,0x000BAD9Du,recomp_gw_partial_0x000D21E4); /* 0x000BAD98: call 0xd21e4 */',
    )
    stack_guard_call=next((candidate for candidate in stack_guard_calls if candidate in lifted_text),None)
    if stack_guard_call is None:
        raise SystemExit("original Watcom stack-remaining check callsite 0xBAD98 changed")
    if 'gw_trace_stack_remaining(0x000BAD98u,eax,esp);' not in lifted_text:
        lifted_text=lifted_text.replace(stack_guard_call,
            stack_guard_call+'\n    gw_trace_stack_remaining(0x000BAD98u,eax,esp);')
    lifted_text='void gw_trace_stack_remaining(unsigned int,unsigned int,unsigned int);\n'+lifted_text
    fatal_calls=(
        '    RECOMP_CALL(recomp_gw_partial_0x000AFBFD); /* 0x000C8A3B: call 0xafbfd */',
        '    GW_RECOMP_CALL_AT(0x000C8A3Bu,0xafbfdu,0x000C8A40u,recomp_gw_partial_0x000AFBFD); /* 0x000C8A3B: call 0xafbfd */',
    )
    fatal_call=next((candidate for candidate in fatal_calls if candidate in lifted_text),None)
    if fatal_call is None:
        raise SystemExit("original Watcom fatal-message callsite 0xC8A3B changed")
    if 'gw_trace_fatal_message(eax,edx);' not in lifted_text:
        lifted_text=lifted_text.replace(fatal_call,
            '    gw_trace_fatal_message(eax,edx);\n'+fatal_call)
    exit_entry='void gw_partial_0x000AFBFD(void) {'
    if lifted_text.count(exit_entry)!=1:
        raise SystemExit("original Watcom do_exit_with_msg entry changed")
    lifted_text=lifted_text.replace(exit_entry,
        exit_entry+'\n    gw_trace_do_exit(eax,edx,esp);',1)
    fini_entry='void gw_partial_0x000C8767(void) {'
    if lifted_text.count(fini_entry)!=1:
        raise SystemExit("original Watcom FiniRtns entry changed")
    lifted_text=lifted_text.replace(fini_entry,
        fini_entry+'\n    gw_trace_fini_rtns(eax,edx,esp);',1)
    for va,entry in ((0x98C19,"void gw_partial_0x00098C19(void)"),
                     (0x98C31,"void gw_partial_0x00098C31(void)"),
                     (0xD226E,"void gw_partial_0x000D226E(void)")):
        pos=lifted_text.find(entry)
        brace=lifted_text.find("{",pos) if pos>=0 else -1
        enter=f"RECOMP_ENTER(0x{va:08X}u);"
        enter_pos=lifted_text.find(enter,brace) if brace>=0 else -1
        if pos<0 or brace<0 or enter_pos<0 or enter_pos-brace>400:
            raise SystemExit(f"original Watcom control-flow target {va:#x} entry hook changed")
        enter_end=enter_pos+len(enter)
        lifted_text=lifted_text[:enter_end]+f"\n    gw_trace_control_entry(0x{va:08X}u,eax,ebp,esp);"+lifted_text[enter_end:]
    lifted_text='void gw_trace_fini_rtns(unsigned int,unsigned int,unsigned int);\n'+lifted_text
    lifted_text='void gw_trace_control_entry(unsigned int,unsigned int,unsigned int,unsigned int);\n'+lifted_text
    lifted_text='void gw_trace_do_exit(unsigned int,unsigned int,unsigned int);\n'+lifted_text
    lifted_text='void gw_trace_fatal_message(unsigned int,unsigned int);\n'+lifted_text
    # Add callsite metadata at code-generation time rather than guessing the
    # original instruction from a host PC at runtime. This covers all ordinary
    # direct and dynamic indirect CALLs in the bounded closure, including the
    # eventual Watcom exit/CRT boundary.
    def original_next_va(address:int)->int:
        rows=list(dis.disassemble_at(address,max_bytes=16))
        if not rows or rows[0].address!=address:
            raise SystemExit(f"Capstone could not decode original control-flow instruction at {address:#x}")
        return rows[0].address+rows[0].size

    direct_call_pattern=re.compile(
        r'RECOMP_CALL\(([^()\r\n]+)\);\s*/\*\s*0x([0-9A-Fa-f]{8}):\s*call\s+0x([0-9A-Fa-f]+)\s*\*/')
    indirect_call_pattern=re.compile(
        r'RECOMP_ICALL\(([^;\r\n]+)\);\s*/\*\s*0x([0-9A-Fa-f]{8}):\s*call\s+[^*]+\*/')
    allowed_icall_pattern=re.compile(
        r'GW_RECOMP_ICALL_ALLOWED\((0x[0-9A-Fa-f]+u),\s*([^,\r\n]+),\s*([A-Za-z0-9_]+)\);')
    branch_pattern=re.compile(
        r'(?m)^([ \t]*)if \(([^\r\n]+)\) goto L_([0-9A-Fa-f]{8}); '
        r'/\* 0x([0-9A-Fa-f]{8}): (j[a-z]+) 0x([0-9A-Fa-f]+) \*/')
    # The LE-backed closure may already have callsite-aware macros from an
    # earlier lift. Count those as instrumentation too; the legacy patterns
    # below still upgrade only unannotated RECOMP_CALL forms.
    direct_call_count=(len(direct_call_pattern.findall(lifted_text))+
        len(re.findall(r'GW_RECOMP_CALL_AT\(0x[0-9A-Fa-f]+u,0x[0-9A-Fa-f]+u,0x[0-9A-Fa-f]+u,[^;]+\);\s*/\*\s*0x[0-9A-Fa-f]{8}:\s*call\s+0x[0-9A-Fa-f]+\s*\*/',lifted_text)))
    indirect_call_count=(len(indirect_call_pattern.findall(lifted_text))+
        len(re.findall(r'GW_RECOMP_ICALL_AT\(0x[0-9A-Fa-f]+u,[^;]+,0x[0-9A-Fa-f]+u\);\s*/\*\s*0x[0-9A-Fa-f]{8}:\s*original indirect CALL\s*\*/',lifted_text)))
    lifted_text=direct_call_pattern.sub(
        lambda m:(f'GW_RECOMP_CALL_AT(0x{m.group(2)}u,0x{m.group(3)}u,'
                  f'0x{original_next_va(int(m.group(2),16)):08X}u,{m.group(1)}); '
                  f'/* 0x{m.group(2)}: call 0x{m.group(3)} */'),lifted_text)
    lifted_text=indirect_call_pattern.sub(
        lambda m:(f'GW_RECOMP_ICALL_AT(0x{m.group(2)}u,{m.group(1)},'
                  f'0x{original_next_va(int(m.group(2),16)):08X}u); '
                  f'/* 0x{m.group(2)}: original indirect CALL */'),lifted_text)
    # The first full control_game -> process_packets tick reaches this exact
    # indirect call. Keep it fail-closed, but read its live target through the
    # checked guest-memory API so the next decision can be tied to an LE
    # object/fixup instead of inferred from host PCs or nearby data.
    packet_frontier="GW_RECOMP_FRONTIER_AT(0x00080921u, \"unverified indirect call target\");"
    packet_probe=(
        "{ uint32_t _gw_ea=(uint32_t)(DS_BASE+(edx+0x5cu)); uint32_t _gw_target=0; "
        "_gw_target=MEM32(_gw_ea); "
        "fprintf(stderr,\"TRACE packet callback operand site=00080921 this=%08X vptr=%08X "
        "slot=%08X linear=%08X target=%08X selector=%04X base=%08X fault=%u\\n\", "
        "esi,edx,edx+0x5cu,_gw_ea,_gw_target,g_seg_ds,g_ds_base,recomp_memory_fault_pending()); "
        "if (recomp_memory_fault_pending()) { RECOMP_FLAGS_OUT(); return; } }\n    ")
    if lifted_text.count(packet_frontier)==1:
        lifted_text=lifted_text.replace(packet_frontier,packet_probe+packet_frontier,1)
    elif 'TRACE packet callback operand site=00080921' in lifted_text:
        pass
    else:
        packet_allowed_pattern=re.compile(
            r'(?m)^([ \t]*)GW_RECOMP_ICALL_ALLOWED(?:_AT)?\(0x00080921u,\s*([^,\r\n]+),\s*(?:0x00080924u,\s*)?([A-Za-z0-9_]+)\);')
        packet_allowed_matches=len(packet_allowed_pattern.findall(lifted_text))
        if packet_allowed_matches<1:
            raise SystemExit("the exact guarded packet callback call at 0x80921 changed")
        lifted_text=packet_allowed_pattern.sub(
            lambda m:m.group(1)+packet_probe+m.group(1)+
                f'GW_RECOMP_ICALL_ALLOWED_AT(0x00080921u,{m.group(2)},0x00080924u,{m.group(3)});',
            lifted_text)
    level_draw_dispatch_pattern=re.compile(
        r'(?m)^([ \t]*)GW_RECOMP_ICALL_AT\(0x00083561u,\s*([^,\r\n]+),\s*0x00083564u\);([\r\n]*)')
    level_draw_dispatch_matches=len(level_draw_dispatch_pattern.findall(lifted_text))
    if level_draw_dispatch_matches<1:
        raise SystemExit(f"draw_game original virtual dispatch instrumentation expected one site, got {level_draw_dispatch_matches}")
    lifted_text=level_draw_dispatch_pattern.sub(
        lambda m:(f'{m.group(1)}gw_test_ifclevel_draw_dispatch((uint32_t)({m.group(2)}));\n'
                  f'{m.group(1)}GW_RECOMP_ICALL_AT(0x00083561u,{m.group(2)},0x00083564u);{m.group(3)}'),
        lifted_text)
    lifted_text='void gw_test_ifclevel_draw_dispatch(unsigned int);\n'+lifted_text
    map_pick_entry='RECOMP_ENTER(0x00078B30u);'
    if lifted_text.count(map_pick_entry)<1:
        raise SystemExit("original MapDisplay picker 0x78B30 entry hook changed")
    if 'gw_test_mapdisplay_pick_candidate((uint32_t)eax,(uint32_t)edx);' not in lifted_text:
        lifted_text=lifted_text.replace(map_pick_entry,
            map_pick_entry+'\n    gw_test_mapdisplay_pick_candidate((uint32_t)eax,(uint32_t)edx);')
    lifted_text='void gw_test_mapdisplay_pick_candidate(unsigned int,unsigned int);\n'+lifted_text
    prealt_pattern=re.compile(r'(?m)^([ \t]*)if \(!gw_recomp_guest_instruction\(0x00078B73u\)\) return;([\r\n]*)')
    prealt_matches=len(prealt_pattern.findall(lifted_text))
    if prealt_matches<1:
        raise SystemExit(f'original world-to-screen return instruction 0x78B73 expected once, got {prealt_matches}')
    lifted_text=prealt_pattern.sub(lambda m:(m.group(0)+
        f'{m.group(1)}gw_test_mapdisplay_pick_prealt((uint32_t)edi,(int32_t)MEM32(SS_BASE+esp),'
        f'(int32_t)MEM32(SS_BASE+esp+4u));\n'),lifted_text)
    lifted_text='void gw_test_mapdisplay_pick_prealt(unsigned int,int,int);\n'+lifted_text
    effect_type_store=("    MEM8(DS_BASE + (edx + 0x45)) = (uint8_t)(LO8(eax)); "
        "/* 0x00083E08: mov byte ptr [edx + 0x45], al */\n"
        "    if (recomp_memory_fault_pending()) { RECOMP_FLAGS_OUT(); return; }\n"
        "    recomp_end_memory_access();")
    if lifted_text.count(effect_type_store)!=1:
        raise SystemExit("original Effect::type store at 0x83E08 is absent or ambiguous")
    lifted_text=lifted_text.replace(effect_type_store,effect_type_store+
        '\n    gw_test_effect_type_store(eax,ebx,ecx,edx,esi,edi,ebp,esp,g_cur_func);',1)
    lifted_text='void gw_test_effect_type_store(unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int);\n'+lifted_text
    effect_spawn_call=("    GW_RECOMP_CALL_AT(0x0008812Au,0x83bf0u,0x0008812Fu,recomp_gw_partial_0x00083BF0); "
        "/* 0x0008812A: call 0x83bf0 */")
    if lifted_text.count(effect_spawn_call)!=1:
        raise SystemExit("original EF_TURBO factory call at 0x8812A is absent or ambiguous")
    lifted_text=lifted_text.replace(effect_spawn_call,
        "    gw_test_effect_spawn_origin(MEM32(SS_BASE + (ebp + 0x12)),eax,ebx,ecx,edx,ebp,esp);\n"+
        effect_spawn_call,1)
    lifted_text='void gw_test_effect_spawn_origin(unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int);\n'+lifted_text
    map_pick_project=re.compile(
        r'(?m)^([ \t]*)if \(!gw_recomp_guest_instruction\(0x00078BA4u\)\) return;([\r\n]*)')
    map_pick_project_matches=len(map_pick_project.findall(lifted_text))
    if map_pick_project_matches!=1:
        raise SystemExit(f"original MapDisplay projection call instrumentation expected one site, got {map_pick_project_matches}")
    lifted_text=map_pick_project.sub(
        lambda m:(f'{m.group(0)}'
                  f'{m.group(1)}gw_test_mapdisplay_pick_projected((uint32_t)edi,(int32_t)MEM32(SS_BASE+esp),'
                  f'(int32_t)MEM32(SS_BASE+esp+4u),(uint32_t)eax);\n'),lifted_text)
    lifted_text='void gw_test_mapdisplay_pick_projected(unsigned int,int,int,unsigned int);\n'+lifted_text
    allowed_count=(len(allowed_icall_pattern.findall(lifted_text))+
        len(re.findall(r'GW_RECOMP_ICALL_ALLOWED_AT\(0x[0-9A-Fa-f]+u,',lifted_text)))
    le_backed_count=len(re.findall(
        r'GW_RECOMP_ICALL_LE_BACKED_AT\(0x[0-9A-Fa-f]{8}u,',lifted_text))
    lifted_text=allowed_icall_pattern.sub(
        lambda m:(f'GW_RECOMP_ICALL_ALLOWED_AT({m.group(1)}, {m.group(2)}, '
                  f'0x{original_next_va(int(m.group(1).rstrip("uU"),16)):08X}u, {m.group(3)});'),lifted_text)
    # Preserve the live operand for the Action 0x14 building-state dispatch.
    # The lifter's exact vtable contract still checks the receiver and target;
    # this narrow trace only makes the resolved slot auditable in the replay.
    action14_call_pattern=re.compile(
        r'(?m)^([ \t]*)GW_RECOMP_ICALL_ALLOWED_AT\(0x00039BEFu,\s*([^,\r\n]+),\s*(0x[0-9A-Fa-f]+u),\s*([A-Za-z0-9_]+)\);')
    action14_call_matches=len(action14_call_pattern.findall(lifted_text))
    if action14_call_matches not in (0,1):
        raise SystemExit(f"expected at most one guarded Action 0x14 call at 0x39BEF, got {action14_call_matches}")
    if action14_call_matches:
        lifted_text=action14_call_pattern.sub(
            lambda m:(f'{m.group(1)}{{ uint32_t _gw_action14_target=(uint32_t)({m.group(2)}); '
                      f'fprintf(stderr,"TRACE action14_call_operand turn=%u site=00039bef edi=%08x slot=%08x target=%08x\\n", '
                      f'*(uint32_t *)(guest_memory+0x002F1472u),(uint32_t)edi,(uint32_t)edi+0x44u,_gw_action14_target); '
                      f'GW_RECOMP_ICALL_ALLOWED_AT(0x00039BEFu,_gw_action14_target,{m.group(3)},{m.group(4)}); }}'),lifted_text)
    # Admit the three Planetside UI virtual calls only for the exact LE-backed
    # PlSpec vtable observed in the existing 1.1 runtime evidence.  The LE
    # vtable slots are SRC_OFFSET32 fixups; runtime checks bind both the vptr
    # and slot value, leaving any other class/subclass fail-closed.
    ui_vtable_contracts=(
        (0x20C0B,0x20C0E,"esi",0x44,0x1120A4,0x59E20,"gw_recomp_icall_allow_00020C0B"),
        (0x219A6,0x219A9,"edi",0x44,0x1120A4,0x59E20,"gw_recomp_icall_allow_000219A6"),
        (0x2293D,0x2293F,"edx",0x00,0x112060,0x5A2F0,"gw_recomp_icall_allow_0002293D"),
    )
    ui_contract_decls=[]
    ui_contract_results=[]
    for site,return_va,reg,slot,fixup_source,target_offset,allow_name in ui_vtable_contracts:
        call=next((i for i in dis.disassemble_at(site,max_bytes=8) if i.address==site),None)
        if call is None or call.mnemonic!="call" or call.bytes not in (b"\xff\x56\x44",b"\xff\x57\x44",b"\xff\x12"):
            raise SystemExit(f"canonical UI virtual call bytes changed at {site:#x}")
        expected_bytes={0x20C0B:b"\xff\x56\x44",0x219A6:b"\xff\x57\x44",0x2293D:b"\xff\x12"}[site]
        if bytes(call.bytes)!=expected_bytes or call.address+call.size!=return_va:
            raise SystemExit(f"UI callsite decode/return address mismatch at {site:#x}")
        vptr_fix=next((f for f in original_link_image.fixups if f.source_link==0x112060),None)
        slot_fix=next((f for f in original_link_image.fixups if f.source_link==fixup_source),None)
        if (vptr_fix is None or vptr_fix.target_object!=1 or vptr_fix.target_offset!=0x5A2F0 or
                slot_fix is None or slot_fix.target_object!=1 or slot_fix.target_offset!=target_offset or
                slot_fix.source_type!=7 or vptr_fix.source_type!=7):
            raise SystemExit(f"LE vtable/slot fixup contract changed for UI call {site:#x}")
        vptr_guest=image.link_to_linear(0x112060)
        target_link=original_link_image.objects[0].base+target_offset
        target_guest=image.link_to_linear(target_link)
        vptr_guest_expected={1:0x002EC060}[1]
        target_guest_expected={0x59E20:0x00254E20,0x5A2F0:0x002552F0}[target_offset]
        if vptr_guest!=vptr_guest_expected or target_guest!=target_guest_expected:
            raise SystemExit(f"rebased UI vtable contract changed at {site:#x}: {vptr_guest:#x}/{target_guest:#x}")
        frontier=f'GW_RECOMP_FRONTIER_AT(0x{site:08X}u, "unverified indirect call target");'
        frontier_count=lifted_text.count(frontier)
        if frontier_count<1:
            # The staging source may already contain the exact LE-backed
            # contract (for example when it is reused from a previously
            # generated closure). Validate the complete receiver/slot guard
            # and the bounded dispatcher call rather than requiring the
            # pre-contract FRONTIER marker to remain textually present.
            site_text=f"0x{site:08X}u"
            exact_guard=(
                f"(uint32_t){reg} != 0x{vptr_guest:08X}u || "
                f"MEM32(DS_BASE + ((uint32_t){reg} + 0x{slot:X}u)) != 0x{target_guest:08X}u")
            has_exact_contract=(
                lifted_text.count(exact_guard)>=1 and
                re.search(rf'GW_RECOMP_ICALL_ALLOWED_AT\s*\(\s*{site_text}\s*,',lifted_text) is not None)
            if frontier_count>1 or (frontier_count==0 and not has_exact_contract):
                raise SystemExit(
                    f"expected exactly one fail-closed UI call or its exact LE vtable contract at "
                    f"{site:#x}; frontier={frontier_count}, exact_contract={int(has_exact_contract)}")
            ui_contract_results.append({
                "site_link":f"0x{site:08X}","instruction_bytes":bytes(call.bytes).hex(),
                "instruction":f"call dword ptr [{reg.upper()}+0x{slot:X}]" if slot else f"call dword ptr [{reg.upper()}]",
                "receiver_vptr_guest":f"0x{vptr_guest:08X}","vtable_link":"0x00112060",
                "slot_fixup_source_link":f"0x{fixup_source:08X}","target_link":f"0x{target_link:08X}",
                "target_guest":f"0x{target_guest:08X}","return_link":f"0x{return_va:08X}",
                "contract":"existing exact LE SRC_OFFSET32 vtable-slot guard",
                "status":"already admitted; other vptr/slot pairs remain fail-closed"})
            decl=f'static const uint32_t {allow_name}[] = {{ 0x{target_guest:08X}u }};'
            if decl not in lifted_text:
                ui_contract_decls.append(decl)
            continue
        operand=f'MEM32(DS_BASE + ((uint32_t){reg} + 0x{slot:X}u))'
        replacement=(
            f'recomp_begin_memory_access_ex(RECOMP_SEG_DS,4u,0x{site:08X}u,RECOMP_MEM_ACCESS_READ,62u,"call");\n'
            f'    if ((uint32_t){reg} != 0x{vptr_guest:08X}u || {operand} != 0x{target_guest:08X}u) '
            f'{{ GW_RECOMP_FRONTIER_AT(0x{site:08X}u, "unexpected LE vtable base/slot pair"); }} '
            f'GW_RECOMP_ICALL_ALLOWED_AT(0x{site:08X}u,{operand},0x{return_va:08X}u,{allow_name}); '
            f'/* canonical LE fixup: vtable 0x112060 slot +0x{slot:X} -> 0x{target_offset:05X} */')
        # The partial-root extractor can emit the same original basic block in
        # more than one wrapper when roots overlap.  Every emitted copy has
        # the same guest EIP and must receive the identical guarded contract.
        lifted_text=lifted_text.replace(frontier,replacement)
        decl=f'static const uint32_t {allow_name}[] = {{ 0x{target_guest:08X}u }};'
        if decl not in lifted_text:
            ui_contract_decls.append(decl)
        ui_contract_results.append({
            "site_link":f"0x{site:08X}","instruction_bytes":bytes(call.bytes).hex(),
            "instruction":f"call dword ptr [{reg.upper()}+0x{slot:X}]" if slot else f"call dword ptr [{reg.upper()}]",
            "receiver_vptr_guest":f"0x{vptr_guest:08X}","vtable_link":"0x00112060",
            "slot_fixup_source_link":f"0x{fixup_source:08X}","target_link":f"0x{target_link:08X}",
            "target_guest":f"0x{target_guest:08X}","return_link":f"0x{return_va:08X}",
            "contract":"singleton LE SRC_OFFSET32 vtable-slot target with exact runtime vptr and slot guards",
            "status":"admitted; other vptr/slot pairs remain fail-closed"})
    lifted_text=lifted_text.replace('#include "gw_segments.h"',
        '#include "gw_segments.h"\n'+'\n'.join(ui_contract_decls),1)
    # Two packet-handler callbacks walk the canonical BioGame::__creatures
    # array (Obj-3 link 0x00152F86, record stride 0x7C).  Their receiver
    # vptr is the Creature vtable whose +0x68 slot is backed by the exact LE
    # fixup at 0x00111D6C.  Admit only that vptr/slot pair; other entity
    # classes remain fail-closed at the five unresolved packet sites.
    creature_packet_contracts=(
        (0x7720F,0x77212,"ecx",0x68,0x111D6C,0x5A070,"gw_recomp_icall_allow_0007720F"),
        (0x772DE,0x772E1,"ebx",0x68,0x111D6C,0x5A070,"gw_recomp_icall_allow_000772DE"),
    )
    creature_packet_decls=[]
    creature_packet_results=[]
    for site,return_va,reg,slot,fixup_source,target_offset,allow_name in creature_packet_contracts:
        call=next((i for i in dis.disassemble_at(site,max_bytes=8) if i.address==site),None)
        expected_bytes={0x7720F:bytes.fromhex("FF 51 68"),0x772DE:bytes.fromhex("FF 53 68")}[site]
        if call is None or call.mnemonic!="call" or bytes(call.bytes)!=expected_bytes or call.address+call.size!=return_va:
            raise SystemExit(f"canonical creature packet callback bytes changed at {site:#x}")
        vptr_fix=next((f for f in original_link_image.fixups if f.source_link==0x111D04),None)
        slot_fix=next((f for f in original_link_image.fixups if f.source_link==fixup_source),None)
        if (vptr_fix is None or vptr_fix.target_object!=1 or vptr_fix.target_offset!=0x5A2F0 or
                slot_fix is None or slot_fix.target_object!=1 or slot_fix.target_offset!=target_offset or
                vptr_fix.source_type!=7 or slot_fix.source_type!=7):
            raise SystemExit(f"LE Creature vtable/slot fixup contract changed at {site:#x}")
        vptr_guest=image.link_to_linear(0x111D04)
        target_link=original_link_image.objects[0].base+target_offset
        target_guest=image.link_to_linear(target_link)
        if vptr_guest!=0x002EBD04 or target_guest!=0x00255070:
            raise SystemExit(f"Creature packet callback rebase changed at {site:#x}: {vptr_guest:#x}/{target_guest:#x}")
        frontier=f'GW_RECOMP_FRONTIER_AT(0x{site:08X}u, "unverified indirect call target");'
        count=lifted_text.count(frontier)
        if count<1:
            if not re.search(rf'GW_RECOMP_ICALL_ALLOWED_AT\(0x{site:08X}u,',lifted_text):
                raise SystemExit(f"expected fail-closed creature packet call at {site:#x}, got {count}")
            decl=f'static const uint32_t {allow_name}[] = {{ 0x{target_guest:08X}u }};'
            if decl not in lifted_text:
                creature_packet_decls.append(decl)
            creature_packet_results.append({
                "site_link":f"0x{site:08X}","instruction_bytes":bytes(call.bytes).hex(),
                "instruction":f"call dword ptr [{reg.upper()}+0x{slot:X}]",
                "receiver_vptr_guest":f"0x{vptr_guest:08X}","vtable_link":"0x00111D04",
                "slot_fixup_source_link":f"0x{fixup_source:08X}","target_link":f"0x{target_link:08X}",
                "target_guest":f"0x{target_guest:08X}","return_link":f"0x{return_va:08X}",
                "contract":"existing exact LE SRC_OFFSET32 vtable-slot guard",
                "status":"already admitted for the Creature vtable only"})
            continue
        operand=f'MEM32(DS_BASE + ((uint32_t){reg} + 0x{slot:X}u))'
        replacement=(
            f'recomp_begin_memory_access_ex(RECOMP_SEG_DS,4u,0x{site:08X}u,RECOMP_MEM_ACCESS_READ,62u,"call");\n'
            f'    if ((uint32_t){reg} != 0x{vptr_guest:08X}u || {operand} != 0x{target_guest:08X}u) '
            f'{{ GW_RECOMP_FRONTIER_AT(0x{site:08X}u, "unexpected Creature LE vtable/slot pair"); }} '
            f'GW_RECOMP_ICALL_ALLOWED_AT(0x{site:08X}u,{operand},0x{return_va:08X}u,{allow_name}); '
            f'/* BioGame::__creatures vptr 0x111D04; LE slot 0x111D6C -> Object-1+0x6A070 */')
        lifted_text=lifted_text.replace(frontier,replacement)
        decl=f'static const uint32_t {allow_name}[] = {{ 0x{target_guest:08X}u }};'
        if decl not in lifted_text:
            creature_packet_decls.append(decl)
        creature_packet_results.append({
            "site_link":f"0x{site:08X}","instruction_bytes":bytes(call.bytes).hex(),
            "instruction":f"call dword ptr [{reg.upper()}+0x{slot:X}]",
            "receiver_vptr_guest":f"0x{vptr_guest:08X}","vtable_link":"0x00111D04",
            "slot_fixup_source_link":f"0x{fixup_source:08X}","target_link":f"0x{target_link:08X}",
            "target_guest":f"0x{target_guest:08X}","return_link":f"0x{return_va:08X}",
            "contract":"BioGame::__creatures array receiver with exact LE SRC_OFFSET32 vptr and slot guards",
            "status":"admitted for the Creature vtable only; other receiver types remain fail-closed"})
    lifted_text=lifted_text.replace('#include "gw_segments.h"',
        '\n'.join(creature_packet_decls)+'\n#include "gw_segments.h"',1)
    # PA_IFC_GO's second virtual callback operates on the PlSpec selected by
    # the packet's specialist index.  The LE has a complete fixup-backed
    # PlSpec vtable at 0x112060; slot +0x84 is the exact Object-1 target
    # 0x6A250.  Keep the dispatch narrow: require the live receiver's vptr
    # and slot contents to match this pair before allowing the call.
    plspec_packet_site=0x766EE
    plspec_packet_return=0x766F4
    plspec_vtable_link=0x112060
    plspec_slot=0x84
    plspec_fixup_source=plspec_vtable_link+plspec_slot
    plspec_target_offset=0x5A250
    plspec_call=next((i for i in dis.disassemble_at(plspec_packet_site,max_bytes=8)
                      if i.address==plspec_packet_site),None)
    plspec_vptr_fix=next((f for f in original_link_image.fixups
                          if f.source_link==plspec_vtable_link),None)
    plspec_slot_fix=next((f for f in original_link_image.fixups
                          if f.source_link==plspec_fixup_source),None)
    if (plspec_call is None or plspec_call.mnemonic!="call" or
            bytes(plspec_call.bytes)!=bytes.fromhex("FF 92 84 00 00 00") or
            plspec_call.address+plspec_call.size!=plspec_packet_return):
        raise SystemExit("canonical PA_IFC_GO PlSpec virtual call changed at 0x766EE")
    if (plspec_vptr_fix is None or plspec_vptr_fix.source_type!=7 or
            plspec_vptr_fix.target_object!=1 or plspec_vptr_fix.target_offset!=0x5A2F0 or
            plspec_slot_fix is None or plspec_slot_fix.source_type!=7 or
            plspec_slot_fix.target_object!=1 or plspec_slot_fix.target_offset!=plspec_target_offset):
        raise SystemExit("LE PlSpec vtable/slot fixup contract changed at 0x766EE")
    plspec_vptr_guest=image.link_to_linear(plspec_vtable_link)
    plspec_target_link=original_link_image.objects[0].base+plspec_target_offset
    plspec_target_guest=image.link_to_linear(plspec_target_link)
    if plspec_vptr_guest!=0x002EC060 or plspec_target_guest!=0x00255250:
        raise SystemExit(f"PlSpec packet callback rebase changed: {plspec_vptr_guest:#x}/{plspec_target_guest:#x}")
    plspec_frontier='GW_RECOMP_FRONTIER_AT(0x000766EEu, "unverified indirect call target");'
    plspec_frontier_count=lifted_text.count(plspec_frontier)
    if plspec_frontier_count<1:
        if not re.search(r'GW_RECOMP_ICALL_ALLOWED_AT\(0x000766EEu,',lifted_text):
            raise SystemExit(f"expected fail-closed PA_IFC_GO PlSpec callback at 0x766EE, got {plspec_frontier_count}")
    plspec_operand='MEM32(DS_BASE + ((uint32_t)edx + 0x84u))'
    plspec_replacement=(
        'recomp_begin_memory_access_ex(RECOMP_SEG_DS,4u,0x000766EEu,RECOMP_MEM_ACCESS_READ,62u,"call");\n'
        f'    if ((uint32_t)edx != 0x{plspec_vptr_guest:08X}u || {plspec_operand} != 0x{plspec_target_guest:08X}u) '
        '{ GW_RECOMP_FRONTIER_AT(0x000766EEu, "unexpected LE PlSpec vtable/slot pair"); } '
        f'GW_RECOMP_ICALL_ALLOWED_AT(0x000766EEu,{plspec_operand},0x{plspec_packet_return:08X}u,gw_recomp_icall_allow_000766EE); '
        '/* PlSpec vtable 0x112060; LE slot 0x1120E4 -> Object-1+0x5A250 */')
    if plspec_frontier_count>0:
        lifted_text=lifted_text.replace(plspec_frontier,plspec_replacement)
    if 'static const uint32_t gw_recomp_icall_allow_000766EE[]' not in lifted_text:
        lifted_text=lifted_text.replace('#include "gw_segments.h"',
            'static const uint32_t gw_recomp_icall_allow_000766EE[] = { 0x00255250u };\n#include "gw_segments.h"',1)
    # Instrument the two real game() interface calls as they execute inside
    # the full lifted root, preserving the same allowlist/fail-closed dispatch.
    # The lifted entry path is split at internal labels. The two virtual
    # transition calls are emitted in the separately named block beginning at
    # 0x92819, not in the outer 0x92710 prologue wrapper.
    game_root_name=lifted_names[0x92819]
    game_root_decl=f"void {game_root_name}(void) {{"
    game_root_start=lifted_text.find(game_root_decl)
    if game_root_start<0:
        raise SystemExit(f"full game() lifted body {game_root_name} is absent")
    game_root_end=lifted_text.find("\n}\n",game_root_start)
    if game_root_end<0:
        raise SystemExit("full game() lifted body has no function boundary")
    game_root_end+=3
    game_root_text=lifted_text[game_root_start:game_root_end]
    for site,stage,next_va,label in ((0x92821,1,0x92824,"current PullOut"),
                                     (0x9282C,3,0x9282E,"pending PlugIn")):
        phase="PullOut" if stage==1 else "PlugIn"
        # A verified LE vtable call may be emitted either as an allowlisted
        # dispatch or as the generic instrumented call plus the exact
        # base/slot guard inserted by the lifter. Preserve the generated
        # policy in either case; only add transition capture around these two
        # statically identified sites.
        call_re=re.compile(
            rf'(?m)^([ \t]*)(.*?)(GW_RECOMP_ICALL_ALLOWED_AT|GW_RECOMP_ICALL_AT)\('
            rf'0x{site:08X}u,\s*(.*?),\s*0x{next_va:08X}u'
            rf'(?:,\s*([A-Za-z0-9_]+))?\);([^\r\n]*)$')
        matches=call_re.findall(game_root_text)
        if len(matches)!=1:
            nearby=" | ".join(line.strip() for line in game_root_text.splitlines()
                                if f"0x{site:08X}" in line or f"{site:08X}" in line)
            raise SystemExit(f"full game() interface dispatch site {site:#x} was not emitted exactly once: {len(matches)}; {nearby[:600]}")
        def instrument_game_transition(m):
            indent,prefix,macro,target,allow,suffix=m.groups()
            args=f'0x{site:08X}u,{target},0x{next_va:08X}u'
            if macro == "GW_RECOMP_ICALL_ALLOWED_AT":
                if not allow:
                    raise SystemExit(f"allowlisted transition at {site:#x} lost its exact allowlist")
                args+=f',{allow}'
            elif allow:
                raise SystemExit(f"generic transition at {site:#x} unexpectedly has an allowlist")
            return (f'{indent}{prefix}gw_capture_original_transition_dispatch({stage}u,(uint32_t)({target})); /* {label} */\n'
                    f'{indent}{macro}({args});{suffix}\n'
                    f'{indent}gw_trace_dos_mcb_chain_current("after_game_{phase}");')
        game_root_text=call_re.sub(instrument_game_transition,game_root_text,count=1)
    lifted_text=lifted_text[:game_root_start]+game_root_text+lifted_text[game_root_end:]
    branch_count=(len(branch_pattern.findall(lifted_text))+
        len(re.findall(r'/\*\s*0x[0-9A-Fa-f]{8}:\s*j(?:a|ae|b|be|c|cxz|ecxz|e|g|ge|l|le|na|nae|nb|nbe|nc|ne|ng|nge|nl|nle|no|np|ns|nz|o|p|pe|po|s|z)\s+0x[0-9A-Fa-f]+\s*\*/',lifted_text)))
    def trace_branch(m:re.Match[str])->str:
        indent,condition,label,site,mnemonic,target=m.groups()
        source=int(site,16); target_va=int(target,16); fallthrough=original_next_va(source)
        flags="recomp_eflags(_flag_k,_flag_a,_flag_b,_cf,_df)"
        taken=f"gw_recomp_trace_branch(0x{source:08X}u,g_cur_func,0x{target_va:08X}u,{flags},1u)"
        missed=f"gw_recomp_trace_branch(0x{source:08X}u,g_cur_func,0x{fallthrough:08X}u,{flags},0u)"
        if 0x97650 <= source <= 0x976D0:
            probe_taken=(f"gw_test_plspec_hit_branch(0x{source:08X}u,0x{target_va:08X}u,1u,{flags},"
                         "_flag_a,_flag_b,eax,ebx,ecx,edx,esi,edi,ebp,esp);")
            probe_missed=(f"gw_test_plspec_hit_branch(0x{source:08X}u,0x{fallthrough:08X}u,0u,{flags},"
                          "_flag_a,_flag_b,eax,ebx,ecx,edx,esi,edi,ebp,esp);")
            return (f"{indent}if ({condition}) {{ {probe_taken} {taken}; goto L_{label}; }} "
                    f"else {{ {probe_missed} {missed}; }} /* 0x{site}: {mnemonic} 0x{target} */")
        if 0x78B30 <= source <= 0x790C2:
            probe_taken=(f"gw_test_putthing_branch(0x{source:08X}u,0x{target_va:08X}u,1u,{flags},"
                         "eax,ebx,ecx,edx,esi,edi,ebp,esp);")
            probe_missed=(f"gw_test_putthing_branch(0x{source:08X}u,0x{fallthrough:08X}u,0u,{flags},"
                          "eax,ebx,ecx,edx,esi,edi,ebp,esp);")
            return (f"{indent}if ({condition}) {{ {probe_taken} {taken}; goto L_{label}; }} "
                    f"else {{ {probe_missed} {missed}; }} /* 0x{site}: {mnemonic} 0x{target} */")
        return (f"{indent}if ({condition}) {{ {taken}; goto L_{label}; }} "
                f"else {{ {missed}; }} /* 0x{site}: {mnemonic} 0x{target} */")
    lifted_text=branch_pattern.sub(trace_branch,lifted_text)
    plspec_hit_entry="RECOMP_ENTER(0x0008A500u);"
    if lifted_text.count(plspec_hit_entry)!=1:
        raise SystemExit("original PlSpec hit-test entry 0x8A500 is absent or ambiguous")
    lifted_text=lifted_text.replace(plspec_hit_entry,
        plspec_hit_entry+"\n    gw_test_plspec_hit_begin(eax,ebx,ecx,edx,esi,edi,ebp,esp);",1)
    plspec_hit_call_pattern=re.compile(
        r'(?m)^([ \t]*)(GW_RECOMP_CALL_AT\(0x0008A516u,0x97650u,[^;]+;[^\r\n]*)')
    plspec_hit_call_count=len(plspec_hit_call_pattern.findall(lifted_text))
    if plspec_hit_call_count!=1:
        raise SystemExit(f"original 0x8A500 -> 0x97650 call expected once, got {plspec_hit_call_count}")
    lifted_text=plspec_hit_call_pattern.sub(
        lambda m:(f"{m.group(1)}gw_test_plspec_hit_sprite(0x0008A516u,eax,ebx,ecx,edx,esi,edi,ebp,esp);\n"
                  f"{m.group(1)}{m.group(2)}"),lifted_text)
    lifted_text=('void gw_test_plspec_hit_begin(unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int);\n'
        'void gw_test_plspec_hit_sprite(unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int);\n'
        'void gw_test_plspec_hit_branch(unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int);\n'+lifted_text)
    if "gw_test_putthing_branch(" not in lifted_text:
        raise SystemExit("PutThingInBucket conditional branch observer was not inserted")
    lifted_text='void gw_test_putthing_branch(unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int);\n'+lifted_text
    selected_store_pattern=re.compile(
        r'(?m)^([ \t]*)MEM32\(DS_BASE \+ \(eax \+ 0x37\)\) = edi; /\* 0x000790C2: mov dword ptr \[eax \+ 0x37\], edi \*/')
    selected_store_matches=len(selected_store_pattern.findall(lifted_text))
    if selected_store_matches!=1:
        raise SystemExit(f"original MapDisplay+0x37 store at 0x790C2 expected once, got {selected_store_matches}")
    lifted_text=selected_store_pattern.sub(
        lambda m:m.group(1)+"gw_test_mapdisplay_selected_store((uint32_t)eax,(uint32_t)edi);\n"+
            m.group(0),lifted_text)
    lifted_text='void gw_test_mapdisplay_selected_store(unsigned int,unsigned int);\n'+lifted_text
    if direct_call_count<1300 or indirect_call_count<40:
        raise SystemExit(f"original CALL trace instrumentation unexpectedly sparse: direct={direct_call_count} indirect={indirect_call_count}")
    if allowed_count+le_backed_count<15 or branch_count<2500:
        raise SystemExit(f"original CALL/Jcc trace instrumentation unexpectedly sparse: allowed={allowed_count} le_backed={le_backed_count} branches={branch_count}")
    # Capture every original 1.1 call into W?DrawMyRemapSpriteHR without
    # changing its argument values or return flow. This makes the sprite
    # source and successful-call count available if a later RLE byte access
    # faults inside the guest routine.
    remap_call_pattern=re.compile(
        r'(?m)^([ \t]*)GW_RECOMP_CALL_AT\((0x[0-9A-Fa-f]+u),\s*0x99a20u,\s*([^,]+),\s*([^\)]+)\);([^\r\n]*)')
    remap_calls=len(remap_call_pattern.findall(lifted_text))
    if remap_calls<5:
        raise SystemExit(f"original remap sprite callsites unexpectedly sparse: {remap_calls}")
    lifted_text=remap_call_pattern.sub(
        lambda m:(f'{m.group(1)}gw_test_remap_sprite_enter({m.group(2).rstrip("uU")},'
                  f'eax,ebx,ecx,edx,esi,edi,ebp,esp,g_cur_func);\n'
                  f'{m.group(1)}GW_RECOMP_CALL_AT({m.group(2)},0x99a20u,{m.group(3)},{m.group(4)});{m.group(5)}\n'
                  f'{m.group(1)}gw_test_remap_sprite_return({m.group(2).rstrip("uU")});'),lifted_text)
    lifted_text='void gw_test_remap_sprite_enter(unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int);\nvoid gw_test_remap_sprite_return(unsigned int);\n'+lifted_text
    bank_init_pattern=re.compile(
        r'(?m)^([ \t]*)GW_RECOMP_CALL_AT\((0x0001588Fu),\s*0x973b0u,\s*([^,]+),\s*([^\)]+)\);[^\r\n]*')
    bank_init_calls=len(bank_init_pattern.findall(lifted_text))
    if bank_init_calls<1:
        raise SystemExit("original IFCLevel::PlugIn InitMyAnimBank callsite 0x1588F is missing")
    lifted_text=bank_init_pattern.sub(
        lambda m:(f'{m.group(1)}gw_test_init_my_anim_enter(0x0001588Fu,ebp,eax);\n'
                  f'{m.group(1)}GW_RECOMP_CALL_AT({m.group(2)},0x973b0u,{m.group(3)},{m.group(4)});\n'
                  f'{m.group(1)}gw_test_init_my_anim_return(0x0001588Fu,ebp,eax);'),lifted_text)
    lifted_text='void gw_test_init_my_anim_enter(unsigned int,unsigned int,unsigned int);\nvoid gw_test_init_my_anim_return(unsigned int,unsigned int,unsigned int);\n'+lifted_text
    # Make a small, bounded executable body from the exact game() frame CFG.
    # The harness still supplies one SDL event per frame, but the gameplay
    # work below executes the canonical original instruction order, including
    # the clear loop and the complete draw/sound stages.
    from tools.disasm.disasm32 import BasicBlock, Function, Instruction
    game_original=dis.disassemble_function(0x92710)
    if 0x92710 not in lifted_names:
        raise SystemExit("full original game() entry was not admitted into the bounded closure")
    lifted_text += (f"\nvoid gw_original_full_game_entry(void) "
        f"{{ recomp_{lifted_names[0x92710]}(); }}\n")
    cleanup_entry=0x9286A
    cleanup_stop=0x92896
    cleanup_blocks={}
    split_source=next((b for b in game_original.blocks.values()
        if b.start<=cleanup_entry<b.end),None)
    if split_source is None:
        raise SystemExit("game() clear-gate block at 0x9286A disappeared")
    split_ins=[Instruction(i.address,i.size,i.mnemonic,i.op_str,bytes(i.bytes),i.operands)
        for i in split_source.instructions if i.address>=cleanup_entry and i.address<0x92873]
    if not split_ins or split_ins[0].address!=cleanup_entry or split_ins[-1].address+split_ins[-1].size!=0x92873:
        raise SystemExit("game() conditional cleanup guard no longer decodes as 0x9286A..0x92873")
    cleanup_blocks[cleanup_entry]=BasicBlock(cleanup_entry,0x92873,split_ins,[0x92873,cleanup_stop],False)
    for address in (0x92873,0x92880):
        block=game_original.blocks.get(address)
        if block is None or block.end>cleanup_stop:
            raise SystemExit(f"game() conditional cleanup body block missing/oversized at {address:#x}")
        cleanup_blocks[address]=block
    cleanup_blocks[cleanup_stop]=BasicBlock(cleanup_stop,cleanup_stop+1,
        [Instruction(cleanup_stop,1,"ret","",b"\xc3",[])],[],True)
    cleanup_function=Function(cleanup_entry,cleanup_stop+1,
        "gw_original_game_conditional_clear",cleanup_blocks,size=cleanup_stop+1-cleanup_entry)
    cleanup_c=Lifter().lift_function(cleanup_function)
    if not cleanup_function.blocks.get(0x9286A) or not cleanup_function.blocks.get(0x92880):
        raise SystemExit("bounded game() cleanup fragment lost its original guard/loop")
    lifted_text += "\n"+cleanup_c+"\nvoid gw_original_cleanup_loop_entry(void) { gw_original_game_conditional_clear(); }\n"

    for va,wrapper in ((0x64CB0,"gw_original_64cb0_entry"),
                       (0x834C0,"gw_original_full_draw_game_entry"),
                       (0x35C00,"gw_original_process_sounds_entry")):
        if va not in lifted_names:
            raise SystemExit(f"full game() frame root {va:#x} missing from lifted closure")
        lifted_text += f"\nvoid {wrapper}(void) {{ recomp_{lifted_names[va]}(); }}\n"
    from native_fast_trace import patch_lifted_instruction_probes
    lifted_text, fast_probe_instruction_count, fast_probe_boundary_count = \
        patch_lifted_instruction_probes(lifted_text, ROOT/"tests"/"test_ifctitle_creature_probe.c")
    print(f"TRACE FAST_BOUNDARY_PROBE generic_steps_compiled_out={fast_probe_instruction_count} sparse_sites={fast_probe_boundary_count} full_trace={int(os.environ.get('GW_FULL_TRACE') == '1')}")
    # Capture the two virtual transitions at their original Watcom adjustment
    # thunks in the generated body. The runtime dispatch enters the lifted
    # guest linear aliases (0x1FE610/0x1FE720), so the separate host wrappers
    # are not on this call path.
    for eip, stage, target, jump in (
        (0x13613, 2, 0x6A600, "goto L_0006A600; /* 0x00013613: jmp 0x6a600 */"),
        (0x13723, 4, 0x70D10, "goto L_00070D10; /* 0x00013723: jmp 0x70d10 */")):
        if lifted_text.count(jump) != 1:
            raise SystemExit(f"transition dispatch probe could not find unique lifted thunk jump at {eip:#x}")
        lifted_text = lifted_text.replace(jump,
            f"gw_capture_original_transition_dispatch(0x{stage:X}u,0x{target:08X}u);\n    {jump}",1)
    # Direct lifted C stores bypass gw_segments' observer. Attribute decoded
    # byte stores to +0x17 and keep the runtime hook restricted to watched cells.
    plant17_store_re=re.compile(
        r'(?m)^([ \t]*)MEM8\((DS_BASE|ES_BASE) \+ \(([^)\r\n]+)\)\) = '
        r'\(uint8_t\)\(([^;\r\n]+)\); /\* (0x[0-9a-fA-F]+): '
        r'mov byte ptr \[[^]\r\n]*\+ 0x17\], [^*]+\*/([\r\n]*)$')
    plant17_store_count=len(plant17_store_re.findall(lifted_text))
    if plant17_store_count < 1 and 'gw_capture_plant17_direct_store(' not in lifted_text:
        raise SystemExit("plant17 direct-store probe found no decoded +0x17 byte stores")
    def instrument_plant17_store(m):
        indent,segment,offset,value,eip,newline=m.groups()
        return (f'{indent}MEM8({segment} + ({offset})) = (uint8_t)({value}); '
                f'/* {eip}: mov byte ptr [.. + 0x17] */{newline}'
                f'{indent}gw_capture_plant17_direct_store({eip}u,'
                f'(uint32_t)({segment} + ({offset})),(uint8_t)({value}));{newline}')
    if plant17_store_count:
        lifted_text=plant17_store_re.sub(instrument_plant17_store,lifted_text)
    # FUN_00065AB0 writes its computed terrain/sample byte through a generic
    # output pointer. When that pointer is Thing+0x17, the segmented-memory
    # observer only sees the pre-store value; add a narrowly scoped post-store
    # hook at the verified instruction so the exact result can be attributed.
    creature17_projected_store_re=re.compile(
        r'(?m)^([ \t]*)MEM8\(DS_BASE \+ \(edx\)\) = \(uint8_t\)\(LO8\(eax\)\); '
        r'/\* 0x00065C6A: mov byte ptr \[edx\], al \*/$')
    creature17_projected_store_count=len(creature17_projected_store_re.findall(lifted_text))
    if creature17_projected_store_count!=1:
        raise SystemExit("FUN_00065AB0 generic byte-store hook expected one exact lifted 0x65C6A store")
    lifted_text=creature17_projected_store_re.sub(
        lambda m:(f'{m.group(0)}\n{m.group(1)}gw_capture_plant17_direct_store(0x00065C6Au,'
            f'(uint32_t)(DS_BASE + (edx)),(uint8_t)LO8(eax));'),lifted_text,1)
    print("TRACE creature17_projected_store_hooks=1 site=00065c6a")
    print(f"TRACE plant17_direct_store_hooks={plant17_store_count}")
    # The candidate-specific 80FE0 audit lives at exact original guest EIPs.
    # Wire it into this bounded lifted function instead of relying on generic
    # full-instruction tracing, which is intentionally compiled out in the
    # fast-boundary profile. This remains observational and is inert unless
    # GWRECOMP_IFCLEVEL_GADGET21_80FE0_AUDIT=1.
    audit_80fe0_sites=(0x7A4BF,0x7A4DB,0x7A503,0x7A519,
        0x7A78C,0x7A7AD,0x7A7D2,0x7A7E8,
        0x80FE0,0x80FE5,0x80FEA,0x80FEC,0x80FEE,0x80FF0,0x80FF3,
        0x80FF5,0x80FF8,0x80FFA,0x80FFC,0x81000,0x81002,0x81005,
        0x8100A,0x8100D,0x81010,0x81015,0x81017,0x81019,0x8101B,0x8101D)
    audit_80fe0_counts={}
    for site in audit_80fe0_sites:
        site_hex=f"0x{site:08X}"
        guard_re=re.compile(rf'(?m)^([ \t]*)if \(!gw_recomp_guest_instruction\({site_hex}u\)\) return;')
        count=len(guard_re.findall(lifted_text))
        audit_80fe0_counts[site_hex]=count
        if count!=1:
            raise SystemExit(f"FUN_00080FE0 audit hook expected one exact lifted instruction guard at {site_hex}, got {count}")
        lifted_text=guard_re.sub(
            lambda m:(f'{m.group(1)}gw_test_80fe0_audit_step({site_hex}u);\n{m.group(0)}'),
            lifted_text,1)
    lifted_text='void gw_test_80fe0_audit_step(unsigned int);\n'+lifted_text
    print(f"TRACE 80fe0_exact_site_hooks={len(audit_80fe0_counts)} sites=30")
    plant31_call_re=re.compile(
        r'(?m)^([ \t]*)GW_RECOMP_CALL_AT\(0x0006D490u,0x3d470u,'
        r'0x0006D495u,recomp_gw_partial_0x0003D470\);([^\r\n]*)$')
    if len(plant31_call_re.findall(lifted_text))!=1:
        raise SystemExit("plant31 classifier callsite 0x6D490 was not unique")
    lifted_text=plant31_call_re.sub(
        lambda m:(f'{m.group(1)}gw_trace_plant31_action(0x0006D490u,eax,ebx,ecx,edx,esi,edi,ebp,esp,0u);\n'
                  f'{m.group(1)}gw_test_building_probe_site(0x0006D490u,eax,ebx,ecx,edx,esi,edi,ebp,esp);\n'
                  f'{m.group(1)}GW_RECOMP_CALL_AT(0x0006D490u,0x3d470u,0x0006D495u,recomp_gw_partial_0x0003D470);{m.group(2)}\n'
                  f'{m.group(1)}gw_test_building_probe_site(0x0006D495u,eax,ebx,ecx,edx,esi,edi,ebp,esp);\n'
                  f'{m.group(1)}gw_trace_plant31_action(0x0006D495u,eax,ebx,ecx,edx,esi,edi,ebp,esp,0u);'),
        lifted_text,1)
    def add_entry_observer(text, function_name, entry_va):
        entry_re=re.compile(rf'(?m)^(void {function_name}\(void\) \{{\s*.*?^\s*RECOMP_ENTER\(0x{entry_va:08X}u\);)',re.S)
        matches=len(entry_re.findall(text))
        if matches!=1:
            raise SystemExit(f"building action observer could not find unique entry {function_name} at 0x{entry_va:05X}: {matches}")
        return entry_re.sub(lambda m:m.group(1)+f'\n    gw_test_building_probe_site(0x{entry_va:08X}u,eax,ebx,ecx,edx,esi,edi,ebp,esp);',text,1)
    lifted_text=add_entry_observer(lifted_text,"gw_partial_0x0006DFE0",0x6DFE0)
    lifted_text=add_entry_observer(lifted_text,"gw_partial_0x0003D470",0x3D470)
    for observer_site in (0x39BEF,0x6E18C,0x3D888,0x6D4E9,0x6D4F6,0x6D503,
                          0x6D510,0x6D51A,0x6D523,0x6D6A2,0x6D6AB):
        site_hex=f"0x{observer_site:08X}"
        marker_re=re.compile(rf'(?m)^([ \t]*)if \(!gw_recomp_guest_instruction\({site_hex}u\)\) return;')
        matches=len(marker_re.findall(lifted_text))
        if matches!=1:
            raise SystemExit(f"building action observer could not find unique LE site {site_hex}: {matches}")
        lifted_text=marker_re.sub(lambda m:f'{m.group(1)}gw_test_building_probe_site({site_hex}u,eax,ebx,ecx,edx,esi,edi,ebp,esp);\n{m.group(0)}',lifted_text,1)
    placement_causal_sites=(0x6C490,0x6C4AC,0x6CAA0,0x6CB2D,0x6CB32,0x60452,
        0x6CB44,0x60350,0x6D510,0x6D514,0x6D5D8)
    placement_causal_counts={}
    for site in placement_causal_sites:
        site_hex=f"0x{site:08X}"
        marker_re=re.compile(rf'(?m)^([ \t]*)if \(!gw_recomp_guest_instruction\({site_hex}u\)\) return;')
        count=len(marker_re.findall(lifted_text))
        placement_causal_counts[site_hex]=count
        if count!=1:
            raise SystemExit(f"placement causal probe expected one instruction guard at {site_hex}, got {count}")
        lifted_text=marker_re.sub(
            lambda m:f'{m.group(1)}gw_test_placement_causal_site({site_hex}u,eax,ebx,ecx,edx,esi,edi,ebp,esp);\n{m.group(0)}',
            lifted_text,1)
    lifted_text='void gw_test_placement_causal_site(unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int);\n'+lifted_text
    print(f"TRACE placement_causal_exact_site_hooks={len(placement_causal_counts)}")
    plant31_branch_re=re.compile(
        r'(?m)^(    )if \(CMP_LE\(_flag_a, _flag_b\)\) \{ gw_recomp_trace_branch\('
        r'0x0006D4F0u,.*?/\* 0x0006D4F0: jle 0x6dca8 \*/$')
    if len(plant31_branch_re.findall(lifted_text))!=1:
        raise SystemExit("plant31 branch 0x6D4F0 was not unique")
    lifted_text=plant31_branch_re.sub(
        lambda m:m.group(1)+"gw_trace_plant31_action(0x0006D4F0u,eax,ebx,ecx,edx,esi,edi,ebp,esp,recomp_eflags(_flag_k,_flag_a,_flag_b,_cf,_df));\n"+m.group(0),
        lifted_text,1)
    hud_call_re=re.compile(
        r'(?m)^([ \t]*)GW_RECOMP_ICALL_ALLOWED_AT\(0x000A8D95u,\s*(.*?),\s*'
        r'0x000A8D98u,\s*gw_recomp_icall_allow_000A8D95\);([^\r\n]*)$')
    hud_call_matches=len(hud_call_re.findall(lifted_text))
    if hud_call_matches!=1:
        raise SystemExit(f"MyGadget runtime callback observer expected one original callsite, got {hud_call_matches}")
    def instrument_hud_callback(m):
        indent,target,suffix=m.groups()
        return (f'{indent}gw_test_hud_callback_capture(0x000A8D95u,(uint32_t)edx,'
                f'(uint32_t)({target}),eax,ebx,ecx,edx,esi,edi,ebp,esp);\n'
                f'{indent}GW_RECOMP_ICALL_ALLOWED_AT(0x000A8D95u,{target},0x000A8D98u,'
                f'gw_recomp_icall_allow_000A8D95);{suffix}')
    lifted_text=hud_call_re.sub(instrument_hud_callback,lifted_text)
    click_callback_re=re.compile(
        r'(?m)^([ \t]*)gw_record_deferred_indirect\(0x000A8D43u\);\s*'
        r'GW_RECOMP_ICALL_AT\(0x000A8D43u,MEM32\(DS_BASE \+ \(ebx \+ 0xE\)\),'
        r'0x000A8D46u\);([^\r\n]*)$')
    click_callback_matches=len(click_callback_re.findall(lifted_text))
    if click_callback_matches!=1:
        raise SystemExit(f"MyGadget click callback observer expected original +0x0E call at 0xA8D43, got {click_callback_matches}")
    lifted_text=click_callback_re.sub(
        lambda m:(f'{m.group(1)}gw_test_hud_callback_capture(0x000A8D43u,(uint32_t)ebx,'
                  f'(uint32_t)MEM32(DS_BASE + (ebx + 0xE)),eax,ebx,ecx,edx,esi,edi,ebp,esp);\n'
                  f'{m.group(1)}gw_record_deferred_indirect(0x000A8D43u); '
                  f'GW_RECOMP_ICALL_AT(0x000A8D43u,MEM32(DS_BASE + (ebx + 0xE)),0x000A8D46u);{m.group(2)}'),
        lifted_text)
    mode_dispatch_re=re.compile(
        r'(?m)^([ \t]*)GW_RECOMP_CALL_AT\(0x00013889u,\s*0x6d230u,\s*'
        r'0x0001388Eu,\s*([A-Za-z0-9_]+)\);([^\r\n]*)$')
    mode_dispatch_matches=len(mode_dispatch_re.findall(lifted_text))
    if mode_dispatch_matches!=1:
        raise SystemExit(f"IFC mode dispatch observer expected the original thunk CALL 0x13889, got {mode_dispatch_matches}")
    lifted_text=mode_dispatch_re.sub(
        lambda m:(f'{m.group(1)}gw_test_ifc_mode_dispatch(0x00013889u,(uint32_t)eax,(uint32_t)edx);\n'
                  f'{m.group(0)}'),lifted_text)
    mode_return_re=re.compile(r'(?m)^([ \t]*)if \(!gw_recomp_guest_instruction\(0x0001388Eu\)\) return;')
    mode_return_matches=len(mode_return_re.findall(lifted_text))
    if mode_return_matches<1:
        raise SystemExit("IFC virtual mode call return instruction 0x1388E is missing")
    lifted_text=mode_return_re.sub(
        lambda m:(f'{m.group(1)}gw_test_ifc_mode_dispatch_return(0x0001388Eu,(uint32_t)eax,(uint32_t)edx);\n'
                  f'{m.group(0)}'),lifted_text)
    c8_store_sites={0x6BADA:"ebx",0x6BCC9:"edx",0x6C2AD:"edx",
                    0x6DE2D:"edx",0x6E2CD:"edx",0x71E37:"edi"}
    c8_store_counts={}
    for site,reg in c8_store_sites.items():
        site_hex=f"0x{site:08X}"
        store_re=re.compile(
            rf'(?m)^([ \t]*)recomp_begin_memory_access_ex\(RECOMP_SEG_DS, 4u, {site_hex}u,[^\r\n]*\);\r?\n'
            rf'\1MEM32\(DS_BASE \+ \(0x35F9BC\)\) = {reg}; /\* {site_hex}: mov dword ptr \[0x35f9bc\], {reg} \*/\r?\n'
            rf'\1if \(recomp_memory_fault_pending\(\)\) \{{ RECOMP_FLAGS_OUT\(\); return; \}}\r?\n'
            rf'\1recomp_end_memory_access\(\);')
        count=len(store_re.findall(lifted_text)); c8_store_counts[f"0x{site:05X}"]=count
        if count<1:
            raise SystemExit(f"C8 store observer expected generated original store at {site_hex}, got {count}")
        lifted_text=store_re.sub(
            lambda m:(f'gw_test_ifc_c8_store_before({site_hex}u);\n{m.group(0)}\n'
                      f'gw_test_ifc_c8_store({site_hex}u,(uint32_t){reg});'),lifted_text)
    # Observe only the original IFC transition gate and the LE instructions
    # that can publish the relevant pending/current interface values.
    transition_gate_counts={}
    for site in (0x22DED,0x22435):
        site_hex=f"0x{site:08X}"
        gate_re=re.compile(rf'(?m)^([ \t]*)if \(!gw_recomp_guest_instruction\({site_hex}u\)\) return;')
        transition_gate_counts[site_hex]=len(gate_re.findall(lifted_text))
        if transition_gate_counts[site_hex]<1:
            raise SystemExit(f"IFC transition gate observer could not find original instruction {site_hex}")
        lifted_text=gate_re.sub(lambda m:(f'{m.group(1)}gw_test_ifc_transition_gate({site_hex}u,(uint32_t)eax);\n{m.group(0)}'),lifted_text)
    transition_store_specs={
        0x6A438:("edx","0x2EF7E8"),
        0x714C1:("edx","0x2EF7E8"),
        0x2244C:("0x00360034u","0x2EF7EC"),
    }
    transition_store_counts={}
    for site,(value,address) in transition_store_specs.items():
        site_hex=f"0x{site:08X}"
        value_re=re.escape(value)
        store_re=re.compile(
            rf'(?m)^([ \t]*)recomp_begin_memory_access_ex\(RECOMP_SEG_DS, 4u, {site_hex}u,[^\r\n]*\);\r?\n'
            rf'\1MEM32\(DS_BASE \+ \({address}\)\) = {value}; /\* {site_hex}: mov dword ptr \[[^\]]+\], [^*]+\*/\r?\n'
            rf'\1if \(recomp_memory_fault_pending\(\)\) \{{ RECOMP_FLAGS_OUT\(\); return; \}}\r?\n'
            rf'\1recomp_end_memory_access\(\);')
        transition_store_counts[site_hex]=len(store_re.findall(lifted_text))
        if transition_store_counts[site_hex]<1:
            raise SystemExit(f"IFC transition store observer could not find original store {site_hex}")
        lifted_text=store_re.sub(lambda m:(
            f'gw_test_ifc_transition_store_before({site_hex}u);\n{m.group(0)}\n'
            f'gw_test_ifc_transition_store({site_hex}u,(uint32_t){value});'),lifted_text)
    plant_call_re=re.compile(
        r'(?m)^([ \t]*)GW_RECOMP_CALL_AT\(0x0002145Du,\s*0x6bca0u,\s*'
        r'0x00021462u,\s*([A-Za-z0-9_]+)\);([^\r\n]*)$')
    plant_call_matches=len(plant_call_re.findall(lifted_text))
    if plant_call_matches<1:
        raise SystemExit("plant interaction observer cannot find original IFCPlanetside call at 0x2145D")
    lifted_text=plant_call_re.sub(
        lambda m:(f'{m.group(1)}gw_test_plant_bca0_call((uint32_t)eax,(uint32_t)edx,(uint32_t)esp);\n'
                  f'{m.group(0)}'),lifted_text)
    action_submit_re=re.compile(
        r'(?m)^([ \t]*)GW_RECOMP_CALL_AT\(0x0006D567u,\s*0x756c0u,\s*'
        r'0x0006D56Cu,\s*([A-Za-z0-9_]+)\);([^\r\n]*)$')
    action_submit_matches=len(action_submit_re.findall(lifted_text))
    if action_submit_matches!=1:
        raise SystemExit(f"IFC command packet submit observer expected the original 0x6D567 call, got {action_submit_matches}")
    lifted_text=action_submit_re.sub(
        lambda m:(f'{m.group(1)}gw_test_ifc_action_commit(0x0006D567u,(uint32_t)esi);\n'
                  f'{m.group(0)}'),lifted_text)
    move_go_store_re=re.compile(
        r'(?m)^([ \t]*)MEM8\(DS_BASE \+ \(eax \+ 0xA\)\) = \(uint8_t\)\(0x10u\); '
        r'/\* (0x0006D6DB|0x0006D734|0x0006D77F|0x0006D7FD): mov byte ptr \[eax \+ 0xa\], 0x10 \*/$')
    move_go_store_matches=len(move_go_store_re.findall(lifted_text))
    if move_go_store_matches!=4:
        raise SystemExit(f"PA_IFC_MOVE_GO LE action stores changed: expected 4 original stores, got {move_go_store_matches}")
    lifted_text=move_go_store_re.sub(
        lambda m:f'{m.group(0)}\n{m.group(1)}gw_test_ifc_move_go_action_store({m.group(2)}u,(uint32_t)eax);',
        lifted_text)
    move_go_entry_re=re.compile(
        r'(?m)^(void gw_partial_0x00076750\(void\) \{\s*.*?^    RECOMP_ENTER\(0x00076750u\);)',
        re.S)
    move_go_entry_matches=len(move_go_entry_re.findall(lifted_text))
    if move_go_entry_matches!=1:
        raise SystemExit(f"PA_IFC_MOVE_GO handler entry observer expected one 0x76750 function, got {move_go_entry_matches}")
    lifted_text=move_go_entry_re.sub(
        lambda m:m.group(1)+'\n    gw_test_ifc_move_go_handler_entry();',lifted_text)
    move_go_ret=lifted_text.find('/* 0x000768AA: ret  */',lifted_text.find('void gw_partial_0x00076750(void)'))
    move_go_ret_flags=lifted_text.rfind('RECOMP_FLAGS_OUT();',lifted_text.find('void gw_partial_0x00076750(void)'),move_go_ret)
    if move_go_ret<0 or move_go_ret_flags<0:
        raise SystemExit("PA_IFC_MOVE_GO return observer could not find original RET at 0x768AA")
    lifted_text=(lifted_text[:move_go_ret_flags]+
        'gw_test_ifc_move_go_handler_return();\n    '+lifted_text[move_go_ret_flags:])
    lifted_text=('void gw_test_building_probe_site(unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int);\n'
        'void gw_test_hud_callback_capture(unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int);\n'
        'void gw_test_ifc_mode_dispatch(unsigned int,unsigned int,unsigned int);\n'
        'void gw_test_ifc_mode_dispatch_return(unsigned int,unsigned int,unsigned int);\n'
        'void gw_test_ifc_c8_store_before(unsigned int);\n'
        'void gw_test_ifc_c8_store(unsigned int,unsigned int);\n'
        'void gw_test_ifc_transition_gate(unsigned int,unsigned int);\n'
        'void gw_test_ifc_transition_store_before(unsigned int);\n'
        'void gw_test_ifc_transition_store(unsigned int,unsigned int);\n'
        'void gw_test_plant_bca0_call(unsigned int,unsigned int,unsigned int);\n'
        'void gw_test_ifc_action_commit(unsigned int,unsigned int);\n'
        'void gw_test_ifc_move_go_action_store(unsigned int,unsigned int);\n'
        'void gw_test_ifc_move_go_handler_entry(void);\n'+lifted_text)
    lifted_text=lifted_text.replace('void gw_test_ifc_move_go_handler_entry(void);\n',
        'void gw_test_ifc_move_go_handler_entry(void);\nvoid gw_test_ifc_move_go_handler_return(void);\n')
    # Attribute every direct call to FUN_000E19C0 before its generated call
    # wrapper replaces the guest return address. A small LIFO stack preserves
    # the caller identity across any nested generated calls.
    e19c0_call_re=re.compile(
        r'(?m)^([ \t]*)GW_RECOMP_CALL_AT\((0x[0-9A-Fa-f]{8}u),\s*0xe19c0u,\s*([^,]+),\s*recomp_gw_partial_0x000E19C0\);([^\r\n]*)')
    e19c0_matches=list(e19c0_call_re.finditer(lifted_text))
    if len(e19c0_matches)!=39:
        raise SystemExit(f"expected 39 direct E19C0 callsites after wrapper expansion, found {len(e19c0_matches)}")
    e19c0_ids={int(m.group(2)[:-1],16):i+1 for i,m in enumerate(sorted(e19c0_matches,key=lambda m:int(m.group(2)[:-1],16)))}
    def instrument_e19c0_call(m):
        ident=e19c0_ids[int(m.group(2)[:-1],16)]
        site=m.group(2)
        sample_hooks=""
        if int(site[:-1],16) in (0x662BE,0x664CD):
            sample_hooks=(f'{m.group(1)}gw_e19c0_sample_begin({ident}u,{site},eax,ebx,ecx,edx,esi,edi,ebp,esp);\n')
        sample_end=(f'\n{m.group(1)}gw_e19c0_sample_end({ident}u);' if sample_hooks else '')
        return (f'{m.group(1)}gw_e19c0_callsite_push({ident}u,{site},g_cur_func,eax,ebx,ecx,edx,esi,edi,ebp,esp);\n'
                f'{sample_hooks}'
                f'{m.group(1)}GW_RECOMP_CALL_AT({site},0xe19c0u,{m.group(3)},recomp_gw_partial_0x000E19C0);{m.group(4)}\n'
                f'{m.group(1)}gw_hybrid_capture_primitive_complete({site});\n'
                f'{sample_end}\n'
                f'{m.group(1)}gw_e19c0_callsite_pop({ident}u);')
    lifted_text=e19c0_call_re.sub(instrument_e19c0_call,lifted_text)
    e19c0_read_marker='    GW_NATIVE_INSTRUCTION_TRACE(0x000917D2u,eax,ebx,ecx,edx,esp);'
    if lifted_text.count(e19c0_read_marker)!=1:
        raise SystemExit("pixel ancestry source-read hook 0x917D2 is missing or ambiguous")
    lifted_text=lifted_text.replace(e19c0_read_marker,
        e19c0_read_marker+'\n    gw_e19c0_read_917d2(ecx);',1)
    # Bounded live capture of the actual E19C0 texel -> shade lookup -> pixel
    # store path. Hooks are guarded by a 64-sample budget so ordinary tests
    # retain the original fast path and never emit per-pixel logs.
    shade_marker='    GW_NATIVE_INSTRUCTION_TRACE(0x000E419Fu,eax,ebx,ecx,edx,esp);'
    store_marker='    GW_NATIVE_INSTRUCTION_TRACE(0x000E41A9u,eax,ebx,ecx,edx,esp);'
    if lifted_text.count(shade_marker)!=1 or lifted_text.count(store_marker)!=1:
        raise SystemExit('E19C0 shade/store instruction markers are missing or ambiguous')
    lifted_text=lifted_text.replace(shade_marker,
        shade_marker+'\n    if (gw_e19c0_pixel_sample_remaining) gw_e19c0_pixel_before_shade(eax,ebx,esi);',1)
    lifted_text=lifted_text.replace(store_marker,
        store_marker+'\n    if (gw_e19c0_pixel_sample_remaining) gw_e19c0_pixel_store_before(0x000E41A9u,eax,ebx,esi,edi,ebp,esp);',1)
    pixel_store_line='    MEM8(DS_BASE + (edi)) = (uint8_t)(LO8(eax)); /* 0x000E41A9: mov byte ptr [edi], al */'
    if lifted_text.count(pixel_store_line)!=1:
        raise SystemExit('E19C0 original E41A9 byte store is missing or ambiguous')
    lifted_text=lifted_text.replace(pixel_store_line,
        pixel_store_line+'\n    if (gw_e19c0_pixel_sample_remaining) gw_e19c0_pixel_store_after(edi);',1)
    # Capture one real FUN_00065F20 entry after camera movement and the four
    # original 14-byte source records at their actual load points. This hook is
    # bounded in the C harness and does not change guest registers or memory.
    f65_entry='    if (!gw_recomp_guest_instruction(0x00065F20u)) return;'
    if lifted_text.count(f65_entry)!=1:
        raise SystemExit('FUN_00065F20 entry probe anchor is missing or ambiguous')
    lifted_text=lifted_text.replace(f65_entry,
        '    gw_capture_65f20_entry(eax,ebx,ecx,edx,esi,edi,ebp,esp);\n'+f65_entry,1)
    for site in (0x66021,0x660A1,0x66162,0x66384):
        marker=f'    if (!gw_recomp_guest_instruction(0x{site:08X}u)) return;'
        if lifted_text.count(marker)!=1:
            raise SystemExit(f'FUN_00065F20 source-record hook anchor 0x{site:05X} is missing or ambiguous')
        lifted_text=lifted_text.replace(marker,
            f'    gw_capture_65f20_source(0x{site:08X}u,ebx,esp);\n'+marker,1)
    lifted_text=("void gw_e19c0_callsite_push(unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int);\n"
                 "void gw_hybrid_capture_primitive_complete(unsigned int);\n"
                 "void gw_capture_65f20_entry(unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int);\n"
                 "void gw_capture_65f20_source(unsigned int,unsigned int,unsigned int);\n"
                 "void gw_e19c0_callsite_pop(unsigned int);\n"
                 "void gw_e19c0_sample_begin(unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int);\n"
                 "void gw_e19c0_sample_end(unsigned int);\n"
                 "void gw_e19c0_read_917d2(unsigned int);\n"
                 "void gw_e19c0_pixel_before_shade(unsigned int,unsigned int,unsigned int);\n"
                 "void gw_e19c0_pixel_store_before(unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int);\n"
                 "void gw_e19c0_pixel_store_after(unsigned int);\n"
                 "extern unsigned int gw_e19c0_pixel_sample_remaining;\n"+lifted_text)
    palette_hooks = (
        ("    GW_NATIVE_INSTRUCTION_TRACE(0x00021380u,eax,ebx,ecx,edx,esp);\n",
         "    GW_NATIVE_INSTRUCTION_TRACE(0x00021380u,eax,ebx,ecx,edx,esp);\n    gw_test_palette_path_trace(0x00021380u,eax,ebx,ecx,edx,esi,edi,ebp,esp);\n"),
        ("    MEM16(DS_BASE + (0x2EF816)) = (uint16_t)(LO16(eax)); /* 0x0002140F: mov word ptr [0x2ef816], ax */\n",
         "    MEM16(DS_BASE + (0x2EF816)) = (uint16_t)(LO16(eax)); /* 0x0002140F: mov word ptr [0x2ef816], ax */\n    gw_test_palette_path_trace(0x0002140Fu,eax,ebx,ecx,edx,esi,edi,ebp,esp);\n"),
        ("L_0001FF5F:\n    if (!gw_recomp_guest_instruction(0x0001FF5Fu)) return;\n",
         "L_0001FF5F:\n    if (!gw_recomp_guest_instruction(0x0001FF5Fu)) return;\n    gw_test_palette_path_trace(0x0001FF5Fu,eax,ebx,ecx,edx,esi,edi,ebp,esp);\n"),
        ("    GW_NATIVE_INSTRUCTION_TRACE(0x00021590u,eax,ebx,ecx,edx,esp);\n",
         "    GW_NATIVE_INSTRUCTION_TRACE(0x00021590u,eax,ebx,ecx,edx,esp);\n    gw_test_palette_path_trace(0x00021590u,eax,ebx,ecx,edx,esi,edi,ebp,esp);\n"),
        ("    SET_LO8(edx, MEM8(DS_BASE + (0x2F146D))); /* 0x000213C6: mov dl, byte ptr [0x2f146d] */\n",
         "    SET_LO8(edx, MEM8(DS_BASE + (0x2F146D))); /* 0x000213C6: mov dl, byte ptr [0x2f146d] */\n    gw_test_palette_path_trace(0x000213C6u,eax,ebx,ecx,edx,esi,edi,ebp,esp);\n"),
        ("    MEM8(DS_BASE + (0x2F146D)) = (uint8_t)(HI8(edx)); /* 0x000213DE: mov byte ptr [0x2f146d], dh */\n",
         "    MEM8(DS_BASE + (0x2F146D)) = (uint8_t)(HI8(edx)); /* 0x000213DE: mov byte ptr [0x2f146d], dh */\n    gw_test_palette_path_trace(0x000213DEu,eax,ebx,ecx,edx,esi,edi,ebp,esp);\n"),
        ("    GW_NATIVE_INSTRUCTION_TRACE(0x000219EBu,eax,ebx,ecx,edx,esp);\n",
         "    GW_NATIVE_INSTRUCTION_TRACE(0x000219EBu,eax,ebx,ecx,edx,esp);\n    gw_test_palette_path_trace(0x000219EBu,eax,ebx,ecx,edx,esi,edi,ebp,esp);\n"),
    )
    for old,new in palette_hooks:
        if old not in lifted_text:
            raise SystemExit("palette probe generated-source hook anchor missing: "+old[:72])
        lifted_text=lifted_text.replace(old,new)
    lifted_text=("void gw_test_palette_path_trace(unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int);\n"+lifted_text)
    # GW_SMK_VIDEO_HOOK: report the original Smacker loop frame boundaries to the host
    # presenter (observational; reads EBP only). 0xAE485/0xAE5E3 = just before
    # SMACKNEXTFRAME in play_smk_direct/play_smk_via_buffer; 0xAE4C3/0xAE61E = loop exits.
    for smk_site in (0x000AE485,0x000AE5E3,0x000AE4C3,0x000AE61E,0x000AE49F,0x000AE5FA):
        smk_marker=f"    GW_NATIVE_INSTRUCTION_TRACE(0x{smk_site:08X}u,eax,ebx,ecx,edx,esp);\n"
        if lifted_text.count(smk_marker)<1:
            raise SystemExit(f"Smacker loop marker 0x{smk_site:05X} missing")
        lifted_text=lifted_text.replace(smk_marker,
            smk_marker+f"    gw_smk_video_hook(0x{smk_site:08X}u,ebp);\n")
    # Observation of the original request path: Win::PlugIn entry, its PlaySmacker call, PlaySmacker entry.
    for call_site in (0x00072240,0x00072304,0x00072530,0x000725F2,0x000929D0,
                      0x000C4880,0x000C4886,0x000AE42A,0x000AE42F,0x000AE461,0x000AE466,
                      0x000C4050,0x000C4107,0x000C40D6,0x000D71E0,0x000C4101):
        call_marker=f"    GW_NATIVE_INSTRUCTION_TRACE(0x{call_site:08X}u,eax,ebx,ecx,edx,esp);\n"
        if lifted_text.count(call_marker)<1:
            raise SystemExit(f"call-site marker 0x{call_site:05X} missing")
        lifted_text=lifted_text.replace(call_marker,
            call_marker+f"    gw_smk_call_hook(0x{call_site:08X}u,eax,ebx,ecx,edx,esp);\n")
    lifted_text="void gw_smk_call_hook(unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int);\n"+lifted_text
    lifted_text="void gw_smk_video_hook(unsigned int,unsigned int);\n"+lifted_text
    # GW_V18_SMK_TIMED_CALLS: time only the original RAD calls, with host QPC.
    smk_timed=[]
    for line in lifted_text.splitlines():
        for site,target,symbol,phase in [('0x000AE3CBu', '0xc5140u', 'recomp_gw_partial_0x000C5140', 2), ('0x000AE42Au', '0xc5bd0u', 'recomp_gw_partial_0x000C5BD0', 3), ('0x000AE461u', '0xc5bd0u', 'recomp_gw_partial_0x000C5BD0', 3), ('0x000AE485u', '0xc5900u', 'recomp_gw_partial_0x000C5900', 4), ('0x000AE48Bu', '0xc47f0u', 'recomp_gw_partial_0x000C47F0', 5), ('0x000AE57Cu', '0xc5140u', 'recomp_gw_partial_0x000C5140', 2), ('0x000AE5B9u', '0xc5bd0u', 'recomp_gw_partial_0x000C5BD0', 3), ('0x000AE5E4u', '0xc5900u', 'recomp_gw_partial_0x000C5900', 4), ('0x000AE5EAu', '0xc47f0u', 'recomp_gw_partial_0x000C47F0', 5)]:
            if f"GW_RECOMP_CALL_AT({site},{target}," in line and symbol in line:
                smk_timed.append((line,phase,site))
    if len(smk_timed)!=9:
        raise SystemExit(f"expected 9 timed original Smacker calls, found {len(smk_timed)}")
    timed_text=lifted_text
    for line,phase,site in smk_timed:
        indent=line[:len(line)-len(line.lstrip())]
        ident=site[2:10].lower()
        timer=f"gw_smk_prof_{ident}"
        timed_text=timed_text.replace(line,
            f"{indent}uint64_t {timer}=gw_smk_profile_begin({phase}u);\n"+line+
            f"\n{indent}gw_smk_profile_end({phase}u,{timer});",1)
    lifted_text="#include <stdint.h>\nuint64_t gw_smk_profile_begin(unsigned int);\nvoid gw_smk_profile_end(unsigned int,uint64_t);\n"+timed_text
    # V20: Smacker keeps its silent BIOS-clock path (v0.7/V18.1). Its MSS path (SMACKSOUNDUSEMSS) clocks frames from an AIL timer
    # that only a PIT/INT8 delivery would fire; at the two Smacker call sites GetSoundDriver_ is forced to 0.
    for mss_site in (0x000AE32D,0x000AE4FD):
        mss_marker=f"    GW_NATIVE_INSTRUCTION_TRACE(0x{mss_site:08X}u,eax,ebx,ecx,edx,esp);\n"
        if lifted_text.count(mss_marker)!=1:
            raise SystemExit(f"Smacker GetSoundDriver_ test marker 0x{mss_site:05X} missing")
        lifted_text=lifted_text.replace(mss_marker,mss_marker+"    eax = gw_smk_mss_gate(eax);\n")
    lifted_text="unsigned int gw_smk_mss_gate(unsigned int);\n"+lifted_text
    # V20: read-only entry observation of the game's sound request (PlaySample_) and the Miles AIL wrappers it drives.
    for ail_site in (0x000A0FE0,0x000B1CD0,0x000B1D50,0x000B2240,0x000B22D0,0x000B21B0,0x000B2360,0x000B1FB0,0x000B2130):
        ail_marker=f"    GW_NATIVE_INSTRUCTION_TRACE(0x{ail_site:08X}u,eax,ebx,ecx,edx,esp);\n"
        if lifted_text.count(ail_marker)!=1:
            raise SystemExit(f"V20 sound entry marker 0x{ail_site:05X} missing/duplicated: {lifted_text.count(ail_marker)}")
        lifted_text=lifted_text.replace(ail_marker,ail_marker+f"    gw_vsb16_call_hook(0x{ail_site:08X}u,eax,ebx,ecx,edx,esp);\n")
    lifted_text="void gw_vsb16_call_hook(unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int);\n"+lifted_text
    fc_marker="    GW_NATIVE_INSTRUCTION_TRACE(0x000D726Cu,eax,ebx,ecx,edx,esp);\n"
    if lifted_text.count(fc_marker)!=1:
        raise SystemExit("RAD BIOS-clock RET marker 0xD726C missing")
    lifted_text=lifted_text.replace(fc_marker,fc_marker+"    eax = gw_smk_fine_clock(eax);\n")
    lifted_text="unsigned int gw_smk_fine_clock(unsigned int);\n"+lifted_text
    generated.write_text(lifted_text,encoding="utf-8")

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
    callback_c=('#define RECOMP_GENERATED_CODE\n#include "recomp_types.h"\n#include "recomp_context.h"\n'
        '#include "gw_recomp_stop.h"\n#include "gw_segments.h"\n'
        'void sub_000989E0(void);\n'+init_c+'\n'+setter_c+'\n')
    callback_c=direct_call_pattern.sub(
        lambda m:(f'GW_RECOMP_CALL_AT(0x{m.group(2)}u,0x{m.group(3)}u,'
                  f'0x{original_next_va(int(m.group(2),16)):08X}u,{m.group(1)}); '
                  f'/* 0x{m.group(2)}: call 0x{m.group(3)} */'),callback_c)
    callback.write_text(callback_c,encoding="utf-8")

    guest=ROOT/"work"/"ifctitle_creature_probe_guest.bin"; guest.write_bytes(image.mem)
    interactive_build=os.environ.get("GWRECOMP_BUILD_SDL2_INTERACTIVE")=="1"
    exe_name=("gw_demo_sdl2.exe" if interactive_build else
        "test_ifctitle_visual_demo.exe"
        if os.environ.get("GWRECOMP_BUILD_IFCLEVEL_DEMO_ONLY")=="1"
        else "test_ifctitle_creature_probe.exe")
    exe=(ROOT/"bin" if interactive_build else ROOT/"build")/exe_name
    exe.parent.mkdir(parents=True,exist_ok=True)
    # The lifted gameplay closure is a very large translation unit.  O1 keeps
    # the interactive binary optimized while avoiding the multi-minute O2
    # compile and multi-GB frontend peak on Windows.
    opt_flag="-O1" if interactive_build else "-O0"
    compile_flags=[*CC,"-std=gnu11","-m32",opt_flag,"-DRECOMP_TRACE_LOW_WRITES=1",
        f"-DMSCDEX_AUDIO_BEGIN={mscdex_audio_begin}u",
        f"-DMSCDEX_AUDIO_END={mscdex_audio_end}u","-I",ROOT/"runtime",
        "-I",ROOT/"third_party"/"pcrecomp"/"runtime"/"recomp32",
        # Opt-in function-entry counter (GWRECOMP_FUNC_COVERAGE=1). runtime/recomp_types.h
        # routes RECOMP_ENTER to a flag-guarded counter only when this define is present.
        "-DGW_FUNC_COVERAGE_BUILD=1",
        "-I",SDL2_INCLUDE]
    if os.environ.get("GW_FULL_TRACE") == "1":
        compile_flags.append("-DGW_FULL_TRACE_BUILD=1")
    # The expanded, instruction-level closure includes one ~4 MiB lifted
    # function; use 64-bit-host Clang for the x86 Windows target so the C
    # frontend can handle that body without 32-bit compiler heap exhaustion.
    # Keep the build bounded while the native
    # replay itself on its separate 90-second limit below.
    object_cache=os.environ.get("GWRECOMP_OBJECT_CACHE")
    if object_cache:
        if os.environ.get("GWRECOMP_OBJECT_CACHE_LOCKED")!="1":
            raise SystemExit("object-cache mode requires rebuild.ps1's exclusive workspace lock")
        object_dir=Path(object_cache).resolve()
        allowed_cache=Path(os.environ.get("GWRECOMP_OBJECT_CACHE_ROOT") or ROOT/"build"/"reusable-object-cache").resolve()
        try:
            object_dir.relative_to(allowed_cache)
        except ValueError:
            raise SystemExit(f"object cache escaped the approved cache root: {object_dir}")
    else:
        object_dir=ROOT/"work"/"native_ifctitle_plugin_load_at_objs"
    project_headers=[ROOT/"runtime",
        ROOT/"third_party"/"pcrecomp"/"runtime"/"recomp32",
        SDL2_INCLUDE,
        ROOT/"tools"/"terrain_renderer"]
    sources=[("harness",ROOT/"tests"/"test_ifctitle_creature_probe.c"),
        ("lifted-closure",generated),("resource-callback",callback),
        ("recomp-context",ROOT/"runtime"/"recomp_context.c"),
        ("interrupts",ROOT/"runtime"/"gw_interrupts.c"),
        ("trace",ROOT/"runtime"/"gw_recomp_trace.c"),
        ("segments",ROOT/"runtime"/"gw_segments.c"),
        ("pit",ROOT/"runtime"/"gw_pit8254.c"),
        ("dos-services",ROOT/"runtime"/"gw_dos_services.c"),
        ("vbe-provider",ROOT/"runtime"/"gw_vbe_provider.c"),
        ("x87",ROOT/"runtime"/"recomp_x87.c")]
    sources.append(("camera-interpolation",ROOT/"runtime"/"gw_camera_interpolation.c"))
    sources.append(("func-coverage",ROOT/"runtime"/"gw_func_coverage.c"))
    # The native harness references these APIs in both build modes.
    sources.append(("cd-audio",ROOT/"runtime"/"gw_cdda_audio.c"))
    sources.append(("vsb16",ROOT/"runtime"/"gw_vsb16.c"))   # V20: virtual SB16 (Miles AIL3DIG driver ABI) + SDL2 sink
    objects=[]
    for label,source in sources:
        obj_path=object_dir/(source.stem+".obj")
        obj_path=compile_cached(source,obj_path,compile_flags,label,project_headers,timeout=900)
        objects.append(obj_path)
    terrain_source=ROOT/"tools"/"terrain_renderer"/"gw_terrain_renderer.cpp"
    terrain_obj=object_dir/"gw_terrain_renderer.obj"
    terrain_flags=[*CLANGXX,"-std=c++17","-m32","-O2","-fno-exceptions","-fno-rtti",
        *[x for d in _cxx_include_dirs() for x in ("-isystem",d)],
        "-I",ROOT/"tools"/"terrain_renderer"]
    terrain_obj=compile_cached(terrain_source,terrain_obj,terrain_flags,"modern-terrain-renderer",
        [ROOT/"tools"/"terrain_renderer"],timeout=180)
    objects.append(terrain_obj)
    cache_usage=os.environ.get("GWRECOMP_OBJECT_CACHE_USAGE")
    if cache_usage:
        records=[{"name":f"{source.stem}.obj","path":str(obj),"sha256":sha(obj),
                  "size_bytes":obj.stat().st_size,
                  "cache":CACHE_OBJECT_STATUS.get(source.stem+".obj","unknown")}
                 for (_,source),obj in zip(sources,objects[:-1])]
        records.append({"name":f"{terrain_source.stem}.obj","path":str(terrain_obj),
                        "sha256":sha(terrain_obj),"size_bytes":terrain_obj.stat().st_size,
                        "cache":CACHE_OBJECT_STATUS.get(terrain_source.stem+".obj","unknown")})
        if os.environ.get("GWRECOMP_OBJECT_CACHE_DIAGNOSTICS")=="1":
            for record in records:
                detail=CACHE_OBJECT_KEY_DIAGNOSTICS.get(record["name"])
                if detail is not None: record["key_diagnostics"]=detail
        usage_path=Path(cache_usage)
        temporary=usage_path.with_suffix(usage_path.suffix+".tmp")
        temporary.write_text(json.dumps({"schema":"gwrecomp-object-cache-use/1","objects":records},
                                        indent=2)+"\n",encoding="utf-8")
        temporary.replace(usage_path)
    # The x64-host Clang handles the large lifted C translation unit; use the
    # existing 32-bit-host Clang driver for linking because its configured
    # MinGW search path resolves the project's crt2.o and SDL libraries.
    # "-B <mingw32>/lib": a 64-bit-host clang (e.g. a plain LLVM install) does not find crt2.o on its own;
    # the 32-bit-host clang of Visual Studio does. -B makes the link independent of that difference.
    link_command=[*LINK_CC,"-m32","-B",MINGW32_LIB,"-o",exe,*objects,
        "-L",MINGW32_LIB,"-lSDL2","-lbcrypt","-lwinmm","-lm"]
    # Opt-in only: a link map lets a host_rip from the GWRECOMP_WATCH_BYTE
    # hardware watch be resolved to a lifted or runtime symbol. It does not
    # change the generated code.
    if os.environ.get("GWRECOMP_WATCH_BYTE"):
        link_command.append(f"-Wl,-Map,{ROOT/'work'/'watch_link.map'}")
    run(link_command,timeout=90,quiet=True)
    if interactive_build:
        print(f"PASS incremental native SDL2 interactive build: {exe}")
        return
    if os.environ.get("GWRECOMP_BUILD_IFCLEVEL_DEMO_ONLY")=="1":
        print(f"PASS incremental native IFCLevel demo build: {exe}")
        return
    if sha(TITLE_SCREEN)!=EXPECTED_TITLE_SCREEN: raise SystemExit("exact-build TITLESCR.DAT hash mismatch")
    fresh_game_entry=os.environ.get("GWRECOMP_IFCLEVEL_FRESH_GAME_ENTRY")=="1"
    continuous_game_root=os.environ.get("GWRECOMP_IFCLEVEL_CONTINUOUS_GAME_ROOT")=="1"
    full_game_entry=(os.environ.get("GWRECOMP_IFCLEVEL_FULL_GAME_ENTRY")=="1" or
                     fresh_game_entry or continuous_game_root)
    # A full native game() interpretation is much slower than the same bounded
    # stages orchestrated by the harness. Keep ordinary diagnostic boots
    # bounded at 15 minutes, but give the explicitly requested continuous
    # setup_game -> game() -> 320-turn proof enough time to finish.
    long_native_loop=(os.environ.get("GWRECOMP_IFCLEVEL_NATIVE_GAME_LOOP")=="1" and
        int(os.environ.get("GWRECOMP_IFCLEVEL_HOST_BOUND_TURN","0") or "0")>=1000)
    replay_timeout=21600 if long_native_loop else 3600 if continuous_game_root else 900 if full_game_entry else 480
    native_command=[exe,guest,INSTALL,manifest_tsv]
    snapshot_load=os.environ.get("GWRECOMP_NATIVE_SNAPSHOT_LOAD")
    snapshot_save=os.environ.get("GWRECOMP_NATIVE_SNAPSHOT_SAVE")
    snapshot_turn=os.environ.get("GWRECOMP_NATIVE_SNAPSHOT_TURN")
    live_capture_path=ROOT/"evidence"/"live_7c230_665b0_projection_and_mesh_capture.json"
    live_capture_before=(live_capture_path.stat().st_mtime_ns
                        if live_capture_path.exists() else 0)
    expected_snapshot_sha=(sha(ROOT/snapshot_load) if snapshot_load and
                           not Path(snapshot_load).is_absolute() else
                           sha(Path(snapshot_load)) if snapshot_load else None)
    if snapshot_load:
        native_command += ["--load-snapshot",snapshot_load]
    if snapshot_save:
        if not snapshot_turn:
            raise SystemExit("GWRECOMP_NATIVE_SNAPSHOT_SAVE requires GWRECOMP_NATIVE_SNAPSHOT_TURN")
        native_command += ["--save-snapshot",snapshot_save,"--snapshot-turn",snapshot_turn]
    executed=run(native_command,timeout=replay_timeout,quiet=True)
    if os.environ.get("GWRECOMP_E19C0_PROVENANCE_PROBE")=="1":
        stem=os.environ.get("GWRECOMP_IFCLEVEL_REPLAY_STEM") or "native_e19c0_provenance_435_585"
        out_path=ROOT/"evidence"/(stem+".stdout.log")
        err_path=ROOT/"evidence"/(stem+".stderr.log")
        out_path.write_text(executed.stdout or "",encoding="utf-8")
        err_path.write_text(executed.stderr or "",encoding="utf-8")
        trace_path=ROOT/"evidence"/(stem+".trace")
        trace=(executed.stdout or "")+"\n"+(executed.stderr or "")
        if trace_path.exists(): trace += "\n"+trace_path.read_text(encoding="utf-8",errors="replace")
        native_line=next((line for line in trace.splitlines()
            if line.startswith("TRACE native_game_loop_result ok=1 entry=00092860 ")),None)
        provenance=ROOT/"evidence"/"e19c0_dynamic_callsite_and_pixel_ancestry.json"
        try: provenance_data=json.loads(provenance.read_text(encoding="utf-8"))
        except (OSError,json.JSONDecodeError): provenance_data={}
        ok=(executed.returncode==0 and native_line is not None and provenance_data.get("schema")==
            "gwrecomp.e19c0-live-callsite-and-pixel-ancestry/v1" and
            provenance_data.get("dispatcher",{}).get("attribution_sums_match") is True)
        report={"schema":"gwrecomp.e19c0-provenance-probe-run/v1","target_sha256":EXPECTED_TARGET,
            "snapshot_sha256":expected_snapshot_sha,"snapshot":snapshot_load,
            "exit_code":executed.returncode,"native_game_loop_result":native_line,
            "provenance_report":"evidence/e19c0_dynamic_callsite_and_pixel_ancestry.json",
            "provenance_report_sha256":sha(provenance) if provenance.exists() else None,
            "stdout_log":str(out_path.relative_to(ROOT)),"stderr_log":str(err_path.relative_to(ROOT)),
            "passed":ok}
        report_path=ROOT/"evidence"/"e19c0_true_terrain_pixel_origin_report.json"
        report_path.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
        if not ok:
            raise SystemExit(f"bounded E19C0 provenance run failed; inspect {err_path} and {report_path}")
        print(f"PASS bounded E19C0 caller and WScreen ancestry probe: {report_path}")
        return
    if os.environ.get("GWRECOMP_LIVE_PROJECTION_MESH_CAPTURE")=="1":
        stem="live_7c230_665b0_projection_mesh_capture"
        out_path=ROOT/"evidence"/(stem+".stdout.log")
        err_path=ROOT/"evidence"/(stem+".stderr.log")
        out_path.write_text(executed.stdout,encoding="utf-8")
        err_path.write_text(executed.stderr,encoding="utf-8")
        capture=live_capture_path
        try:
            capture_data=json.loads(capture.read_text(encoding="utf-8"))
            fresh_capture=capture.stat().st_mtime_ns>live_capture_before
        except (OSError,json.JSONDecodeError):
            capture_data={}; fresh_capture=False
        loaded_trace=any("TRACE native_snapshot_loaded " in line and
                         "Turn=435 " in line and "MCB_chain_valid=1" in line
                         for line in executed.stderr.splitlines())
        capture_matches=(capture_data.get("snapshot_turn")==435 and
                         capture_data.get("snapshot_sha256")==expected_snapshot_sha and
                         capture_data.get("single_frame") is True and
                         capture_data.get("simulation_ticks")==0)
        if executed.returncode!=0 or not fresh_capture or not capture_matches or not loaded_trace:
            raise SystemExit(f"single-frame live projection capture failed freshness/provenance checks: exit={executed.returncode}; fresh={fresh_capture}; snapshot_match={capture_matches}; loaded_trace={loaded_trace}; stderr={err_path}")
        print(f"PASS single-frame original projection and mesh capture: {capture}")
        print(f"stderr: {err_path}")
        return
    if full_game_entry:
        default_full_game_stem=("native_ifclevel_continuous_game_root" if continuous_game_root else
            "native_ifclevel_fresh_game_entry" if fresh_game_entry else
            "native_ifclevel_full_game_entry")
        full_game_stem=os.environ.get("GWRECOMP_IFCLEVEL_REPLAY_STEM") or default_full_game_stem
        out_path=ROOT/"evidence"/f"{full_game_stem}.stdout.log"
        err_path=ROOT/"evidence"/f"{full_game_stem}.stderr.log"
        out_path.write_text(executed.stdout,encoding="utf-8")
        err_path.write_text(executed.stderr,encoding="utf-8")
        full_line=next((line for line in executed.stderr.splitlines()
            if line.startswith("TRACE native_full_game_result ")),None)
        loop_match=(re.search(r"stages=(\d+)/(\d+)/(\d+)/(\d+)/(\d+)/(\d+)",full_line)
                    if full_line else None)
        loop_counts=tuple(int(v) for v in loop_match.groups()) if loop_match else ()
        iterations=loop_counts[0] if loop_counts and len(set(loop_counts))==1 else 0
        expected_iterations=iterations>=325 and loop_counts and len(set(loop_counts))==1
        result_match=(re.search(r"entry=00092710 .*Turn=(\d+) flags=([0-9a-fA-F]+) .*title_input_stage=(\d+) level_boot_input_stage=(\d+) planetside_ticks=(\d+) .*quit_arms=(\d+) transitions=(\d+) transition_targets=([0-9a-fA-F]{8}/[0-9a-fA-F]{8}) draw_calls=(\d+) .*current=([0-9a-fA-F]{8}) pending=([0-9a-fA-F]{8}) MCB_chain_valid=(\d+) frontier=(\d+)",full_line)
                     if full_line else None)
        root_result_ok=bool(result_match and int(result_match.group(1))==320 and
            (int(result_match.group(2),16)&1)!=0 and int(result_match.group(3))==3 and
            int(result_match.group(4))==4 and int(result_match.group(5))>=320 and
            int(result_match.group(6))==1 and int(result_match.group(7))>=3 and
            int(result_match.group(9))==iterations and result_match.group(10).lower()=="0035fe9a" and
            result_match.group(11)=="00000000" and result_match.group(12)=="1" and
            result_match.group(13)=="0")
        if executed.returncode!=0 or full_line is None or not expected_iterations or not root_result_ok or \
                "PASS native full game() entry=00092710" not in executed.stdout:
            failure={"schema":"gw-native-full-game-entry-failure/v1",
                "target_sha256":EXPECTED_TARGET,"entry_link":"0x00092710",
                "exit_code":executed.returncode,"result":full_line,
                "stderr":str(err_path.relative_to(ROOT)),"stdout":str(out_path.relative_to(ROOT)),
                "prepgadget_records":[line for line in executed.stderr.splitlines()
                    if line.startswith(("TRACE prepgadget_entry ","TRACE prepgadget_deref "))],
                "passed":False}
            (ROOT/"evidence"/f"{full_game_stem}.json").write_text(
                json.dumps(failure,indent=2)+"\n",encoding="utf-8")
            raise SystemExit(f"full original game() entry did not complete transition plus 320 bounded turns: exit={executed.returncode} trace={full_line!r}; stderr={err_path}")
        targets=re.search(r"transition_targets=([0-9a-fA-F]{8})/([0-9a-fA-F]{8})",full_line)
        turn188=next((line for line in executed.stderr.splitlines()
            if line.startswith("TRACE full_game_state Turn=188 ")),None)
        if turn188 is None or "current=0035fe9a" not in turn188:
            raise SystemExit("native game() entry did not capture the level state at Turn=188")
        turn188_flags=re.search(r"flags=([0-9a-fA-F]{4})/([0-9a-fA-F]{4})",turn188)
        turn188_effect=re.search(r"effect_type=([0-9a-fA-F]{2}) effect_state=([0-9a-fA-F]{2})",turn188)
        natural_active=bool(int(turn188_flags.group(1),16)&1 or
            int(turn188_flags.group(2),16)&1 or int(turn188_effect.group(1),16)!=0)
        if not natural_active:
            raise SystemExit(f"original IFCPlanetside did not naturally activate a specialist/effect by surface Turn=188: {turn188}")
        transition_count=int(re.search(r"transitions=(\d+)",full_line).group(1))
        evidence={"schema":"gw-native-full-game-entry-planetside-loop/v1",
            "target_sha256":EXPECTED_TARGET,"entry_link":"0x00092710",
            "entry_context":("continuous original setup_game return (including player mode 2), then game() drives TITLE and the phase-driven IFCLevel-to-IFCPlanetside UI" if continuous_game_root else
                "fresh initialized state before first title PlugIn; SDL drives original UI inside game()" if fresh_game_entry else
                "original TITLE is current and original IFCLevel is pending after SDL id=0 click"),
            "result":full_line,"exit_code":executed.returncode,
            "transition":{"dispatches":transition_count,"pullout_target":"0x"+targets.group(1).upper(),
                "plugin_target":"0x"+targets.group(2).upper(),"pending_cleared":True,
                "current_ifc":"0x0035FE9A",
                "observed_dispatches":[line for line in executed.stderr.splitlines()
                    if line.startswith("TRACE native_full_game_transition ")]},
            "native_loop":{"pre_planetside_iterations":iterations-320,"planetside_turns":320,
                "total_iterations":iterations,"stages":{"clear":loop_counts[0],"control_game":loop_counts[1],
                "process_packets":loop_counts[2],"draw_game":loop_counts[3],"ProcessSounds":loop_counts[4],"Turn_INC":loop_counts[5]},
                "QuitGame_arm":"original 0x928B5 TEST after original 0x928AF INC at Planetside Turn=320",
                "normal_epilogue_return":True,"draw_dispatches":iterations},
            "gameplay_input":{"title_new_game_stages":3,
                "IFCLevel_phase_confirmations":4,
                "Planetside_ticks_observed":int(re.search(r"planetside_ticks=(\d+)",full_line).group(1)),
                "level_input_turns":int(re.search(r"level_input_turns=(\d+)",full_line).group(1)),
                "level_input_stage":int(re.search(r"level_input_stage=(\d+)",full_line).group(1)),
                "pa_move_to_handler_calls":int(re.search(r"move_calls=(\d+)",full_line).group(1)),
                "pa_move_to_target":"0x"+re.search(r"move_target=([0-9a-fA-F]{8})",full_line).group(1).upper(),
                "selected_plspec":"0x"+re.search(r"selectedPlSpec=([0-9a-fA-F]{8})",full_line).group(1).upper(),
                "map_selected":"0x"+re.search(r"map37=([0-9a-fA-F]{8})",full_line).group(1).upper(),
                "map_thing":"0x"+re.search(r"map18=([0-9a-fA-F]{8})",full_line).group(1).upper(),
                "ralph_world_xy":[int(v) for v in re.search(r"RalphXY=(-?\d+),(-?\d+)",full_line).groups()]},
            "natural_level_activation":{"turn_188_trace":turn188,
                "ralph_slot0_flags":"0x"+turn188_flags.group(1).upper(),
                "ralph_slot1_flags":"0x"+turn188_flags.group(2).upper(),
                "first_effect_type":"0x"+turn188_effect.group(1).upper(),
                "first_effect_state":"0x"+turn188_effect.group(2).upper(),
                "observed":natural_active},
            "mcb_chain_valid":True,"frontier":None,
            "stdout":str(out_path.relative_to(ROOT)),"stderr":str(err_path.relative_to(ROOT)),
            "limitations":"This path proves authentic game() entry, SDL phase-7/9 advancement from IFCLevel, IFCPlanetside PullOut/PlugIn, and 320 Planetside turns. Specialist activation is claimed only if the live Turn-188 trace shows the original effect/flags; input is SDL-only and no guest globals or packet state are forced.",
            "passed":True}
        (ROOT/"evidence"/f"{full_game_stem}.json").write_text(
            json.dumps(evidence,indent=2)+"\n",encoding="utf-8")
        print("PASS native game() full entry: TITLE -> IFCLevel -> IFCPlanetside, natural Turn-188 activation, 320 Planetside turns, QuitGame return")
        print(f"evidence: {ROOT/'evidence'/(full_game_stem+'.json')}")
        return
    # A diagnostic may append the literal spelling "\\nTRACE mapdisplay_census"
    # before the final census. Normalize only that delimiter: replacing every
    # backslash-n corrupts legitimate DOS paths such as `speech\\new*.spe`.
    executed_stderr = executed.stderr.replace(
        "\\nTRACE mapdisplay_census ", "\nTRACE mapdisplay_census ")
    hover_pick_mode=os.environ.get("GWRECOMP_IFCLEVEL_HOVER_PICK")=="1"
    native_game_loop_mode=os.environ.get("GWRECOMP_IFCLEVEL_NATIVE_GAME_LOOP")=="1"
    direct_pick_click_mode=os.environ.get("GWRECOMP_IFCLEVEL_DIRECT_PICK_CLICK")=="1"
    second_spec_pick_mode=os.environ.get("GWRECOMP_IFCLEVEL_SECOND_SPEC_PICK")=="1"
    mode_switch_probe_mode=os.environ.get("GWRECOMP_IFCLEVEL_MODE_SWITCH_PROBE")=="1"
    hud_gadget_sweep_mode=os.environ.get("GWRECOMP_IFCLEVEL_HUD_GADGET_SWEEP")=="1"
    drop_zone_probe_mode=os.environ.get("GWRECOMP_IFCLEVEL_DROP_ZONE_PROBE")=="1"
    host_bound_turn=int(os.environ.get("GWRECOMP_IFCLEVEL_HOST_BOUND_TURN","0") or "0")
    hover_pick_replay=os.environ.get("GWRECOMP_IFCLEVEL_HOVER_PICK")=="1" or direct_pick_click_mode
    replay_log_stem=os.environ.get("GWRECOMP_IFCLEVEL_REPLAY_STEM") or ("native_ifclevel_hud_gadget_sweep" if hud_gadget_sweep_mode else
        "native_ifclevel_second_spec_pick" if second_spec_pick_mode else
        "native_ifclevel_game_loop" if native_game_loop_mode else
        "native_ifclevel_post260_direct_click" if direct_pick_click_mode else
        "native_ifclevel_hover_pick" if hover_pick_mode else "native_ifclevel_creature_probe")
    replay_stdout_path=ROOT/"evidence"/f"{replay_log_stem}.stdout.log"
    replay_stderr_path=ROOT/"evidence"/f"{replay_log_stem}.stderr.log"
    if os.environ.get("GWRECOMP_IFCLEVEL_CONTINUE")=="1":
        # Keep the actual bounded replay output before any later evidence
        # assertion can stop this Python test, especially at a new original
        # fail-closed table or device boundary.
        replay_stdout_path.write_text(executed.stdout,encoding="utf-8")
        replay_stderr_path.write_text(executed.stderr,encoding="utf-8")
        census_summary=next((line for line in executed_stderr.splitlines()
            if line.startswith("TRACE mapdisplay_census_summary ")),None)
        census_re=re.compile(
            r"TRACE mapdisplay_census ptr=([0-9a-fA-F]+) array=([^ ]+) index=(\d+) "
            r"first_tick=(\d+) last_tick=(\d+) calls=(\d+) projections=(\d+) "
            r"screen=(-?\d+),(-?\d+) world=(-?\d+),(-?\d+) owner18=(\d+) vtable=([0-9a-fA-F]+) "
            r"ttype=([0-9a-fA-F]+) field2d=([0-9a-fA-F]+) field45=([0-9a-fA-F]+) "
            r"field46=([0-9a-fA-F]+) field4c=([0-9a-fA-F]+)")
        census_rows=[]
        for line in executed_stderr.splitlines():
            match=census_re.fullmatch(line)
            if not match: continue
            (ptr,array,index,first,last,calls,projections,sx,sy,wx,wy,owner,vtable,
             ttype,f2d,f45,f46,f4c)=match.groups()
            census_rows.append({"pointer_guest":f"0x{int(ptr,16):08X}","array":array,
                "array_index":int(index),"first_tick":int(first),"last_tick":int(last),
                "calls":int(calls),"projection_observations":int(projections),
                "screen_xy":None if int(sx)==-2147483648 else [int(sx),int(sy)],
                "world_xy":[int(wx),int(wy)],"owner_player":int(owner),
                "vtable_guest":f"0x{int(vtable,16):08X}","ttype_byte_06":f"0x{int(ttype,16):02X}",
                "byte_2d":f"0x{int(f2d,16):02X}","byte_45":f"0x{int(f45,16):02X}",
                "byte_46":f"0x{int(f46,16):02X}","byte_4c":f"0x{int(f4c,16):02X}"})
        stderr_lines=executed_stderr.splitlines()
        factory_blocks=[]
        for idx,line in enumerate(stderr_lines):
            if not line.startswith("TRACE effect_type_store "): continue
            block=[line]
            for follow in stderr_lines[idx+1:idx+80]:
                if follow.startswith("TRACE effect_type_store "): break
                if follow.startswith(("TRACE guest-control ","TRACE guest-call ","TRACE guest-branch ")):
                    block.append(follow)
            factory_blocks.append(block)
        type_store_re=re.compile(r"TRACE effect_type_store tick=(\d+) writer_link=([0-9a-fA-F]+) object_guest=([0-9a-fA-F]+) effects_index=(\d+) ttype=([0-9a-fA-F]+) effect_type=([0-9a-fA-F]+) state=([0-9a-fA-F]+) power=([0-9a-fA-F]+) regs=([0-9a-fA-F/]+) function=([0-9a-fA-F]+)")
        type_store_rows=[]
        for block in factory_blocks:
            match=type_store_re.fullmatch(block[0])
            if match:
                tick,writer,obj,index,ttype,effect_type,state,power,regs,func=match.groups()
                type_store_rows.append({"tick":int(tick),"writer_link":f"0x{int(writer,16):08X}",
                    "object_guest":f"0x{int(obj,16):08X}","effects_index":int(index),
                    "ttype":f"0x{int(ttype,16):02X}","effect_type":f"0x{int(effect_type,16):02X}",
                    "state":f"0x{int(state,16):02X}","power":f"0x{int(power,16):02X}",
                    "registers":regs,"function":f"0x{int(func,16):08X}","call_ring":block[1:]})
        effect_spawn_origin_rows=[]
        spawn_origin_re=re.compile(r"TRACE effect_spawn_origin tick=(\d+) callsite=([0-9a-fA-F]+) caller=([0-9a-fA-F]+) parent_guest=([0-9a-fA-F]+) effects_index=(\d+) parent_ttype=([0-9a-fA-F]+) parent_type=([0-9a-fA-F]+) parent_state=([0-9a-fA-F]+) parent_power=([0-9a-fA-F]+) parent_x=(-?\d+) parent_y=(-?\d+) factory_args=([0-9a-fA-F/]+) ebp=([0-9a-fA-F]+) esp=([0-9a-fA-F]+)")
        for idx,line in enumerate(stderr_lines):
            match=spawn_origin_re.fullmatch(line)
            if not match: continue
            tick,site,caller,parent,index,ttype,etype,state,power,x,y,args,ebp,esp=match.groups()
            checkpoint=[]
            for follow in stderr_lines[idx+1:idx+160]:
                if follow.startswith(("TRACE effect_spawn_origin ","TRACE effect_type_store ")): break
                if follow.startswith(("TRACE guest-call-history ","TRACE guest-control-history ","TRACE guest-call last-")):
                    checkpoint.append(follow)
            effect_spawn_origin_rows.append({"tick":int(tick),"callsite_link":f"0x{int(site,16):08X}",
                "caller_function_link":f"0x{int(caller,16):08X}","parent_guest":f"0x{int(parent,16):08X}",
                "parent_effects_index":int(index),"parent_ttype":f"0x{int(ttype,16):02X}",
                "parent_effect_type":f"0x{int(etype,16):02X}","parent_state":f"0x{int(state,16):02X}",
                "parent_power":f"0x{int(power,16):02X}","parent_xy":[int(x),int(y)],
                "factory_registers":args,"ebp":f"0x{int(ebp,16):08X}","esp":f"0x{int(esp,16):08X}",
                "dynamic_call_ring":checkpoint})
        for row in census_rows:
            guest=int(row["pointer_guest"],16)
            row["link_va_object3_delta"]=(f"0x{guest-0x001DA000:08X}" if guest>=0x001DA000 else None)
            if 0x0032CF86 <= guest < 0x003350D6 and (guest-0x0032CF86)%0x7C==0:
                row["array"]="BioGame::__creatures"
                row["array_index"]=(guest-0x0032CF86)//0x7C
            if row["array"]=="BioGame::__effects":
                row["effect_fields"]={"type_plus_45":row["byte_45"],"state_plus_46":row["byte_46"],"power_plus_4c":row["byte_4c"]}
        effect_state_ticks=[]
        for line in stderr_lines:
            match=re.fullmatch(r"TRACE effect_state_tick tick=(\d+) ptr=([0-9a-fA-F]+) ttype=([0-9a-fA-F]+) effect_type=([0-9a-fA-F]+) state=([0-9a-fA-F]+) power=([0-9a-fA-F]+) xy=(-?\d+),(-?\d+)",line)
            if match:
                tick,ptr,ttype,effect_type,state,power,x,y=match.groups()
                effect_state_ticks.append({"tick":int(tick),"pointer_guest":f"0x{int(ptr,16):08X}",
                    "ttype":f"0x{int(ttype,16):02X}","effect_type":f"0x{int(effect_type,16):02X}",
                    "state":f"0x{int(state,16):02X}","power":f"0x{int(power,16):02X}","world_xy":[int(x),int(y)]})
        census_evidence={"schema":"gw-ifclevel-mapdisplay-thing-census/v1",
            "target_sha256":EXPECTED_TARGET,"authority":"controlled-native-replay",
            "replay":"native_ifclevel_creature_probe","requested_ticks":100,
            "summary_line":census_summary,"unique_objects":len(census_rows),
            "objects":census_rows,"effect_type_store_events":type_store_rows,
            "effect_spawn_origin_events":effect_spawn_origin_rows,
            "effect_0_state_by_tick":effect_state_ticks,
            "callsite_scope":"original FUN_00078B30 entries and 0x78BA4 projection callback through IFCLevel Draw",
            "field_note":"LE 0x79098 reads Thing::ttype from +0x06; +0x2D remains a raw field and is never used as the type discriminator. For TT_EFFECT records, +0x45/+0x46/+0x4c are effect type/state/power.",
            "effect_origin_note":"Only a successful original store at LE 0x83E08 proves creation of an effect of the stored type; the caller ring is evidence of its dynamic parent path.",
            "static_sources":{"array_extents":"GeneWars 1.1 MAP + original InitArray_* loop bounds/strides",
                "map_bucket":"REA/Ghidra 12.1.4 evidence ev_c304ec3831274c7a08a04e93757aa0f0b9f06a7ffc7417dc9e15b683814c7fa1",
                "effect_type_write":"REA/Ghidra 12.1.4 and canonical LE Capstone at 0x83E08: MOV byte ptr [EDX+0x45], AL; store hook records destination after the original instruction",
                "effect_type_write_xrefs":"REA/Ghidra xrefs evidence ev_b8a9a680e4e96b0c5388c3e41feef974ade2137b118ab8a7aa0d4ace5eeb1623"}}
        if not native_game_loop_mode:
            (ROOT/"evidence"/"native_ifclevel_entity_census.json").write_text(
                json.dumps(census_evidence,indent=2)+"\n",encoding="utf-8")
        if not native_game_loop_mode and (census_summary is None or not census_rows):
            raise SystemExit("instrumented replay did not produce the MapDisplay object census")
        if not native_game_loop_mode and (len(effect_spawn_origin_rows)!=1 or
                effect_spawn_origin_rows[0]["parent_effects_index"]>=128):
            raise SystemExit("tick-22 EF_TURBO factory parent was not captured from the live effect array")
        if not native_game_loop_mode:
            print(f"TRACE native MapDisplay census unique={len(census_rows)} effect_type_06_stores={len(type_store_rows)} smuggler_tick_samples={len(effect_state_ticks)} saved=evidence/native_ifclevel_entity_census.json")
        runtime_frontier_lines=[line for line in executed_stderr.splitlines()
            if line.startswith(("RUNTIME_FRONTIER ","RUNTIME_FRONTIER_CALL ",
                                "RUNTIME_FRONTIER_CALL_OPERAND ","RUNTIME_FRONTIER_MEM ",
                                "ICALL: unresolved VA"))]
        (ROOT/"evidence"/"native_ifclevel_creature_probe.runtime.log").write_text(
            ("\n".join(runtime_frontier_lines)+"\n") if runtime_frontier_lines else
            "RUNTIME_FRONTIER none in this replay\n",encoding="utf-8")
    gameplay_trace_path=(ROOT/"evidence"/f"{replay_log_stem}.trace" if os.environ.get("GWRECOMP_IFCLEVEL_REPLAY_STEM") else
        ROOT/"evidence"/("native_ifclevel_second_spec_pick.trace" if second_spec_pick_mode else
        "native_ifclevel_game_loop.trace" if native_game_loop_mode else
        "native_ifclevel_post260_direct_click.trace" if direct_pick_click_mode else
        "native_ifclevel_hover_pick.trace" if hover_pick_mode else
        "native_ifclevel_gameplay_continue.trace"))
    if not gameplay_trace_path.is_file():
        gameplay_trace_path=ROOT/"evidence"/"native_ifclevel_creature_probe.trace"
    gameplay_trace=gameplay_trace_path.read_text(encoding="utf-8",errors="replace") if gameplay_trace_path.is_file() else ""
    tick_stats=[]
    for line in gameplay_trace.splitlines():
        match=re.match(r"post_loader_tick_stats tick=(\d+) draw_ok=(\d+) WScreen_changed=(\d+) DAC_nonzero_components=(\d+) DAC_component_writes=(\d+) MyGadget_callbacks=(\d+) last_callback=([0-9a-fA-F]+) target=([0-9a-fA-F]+)",line)
        if match:
            tick,draw_ok,changed,dac_nonzero,dac_writes,callbacks,last_callback,target=match.groups()
            tick_stats.append({"tick":int(tick),"draw_ok":bool(int(draw_ok)),
                "wscreen_changed_bytes":int(changed),"dac_nonzero_components":int(dac_nonzero),
                "dac_component_writes_total":int(dac_writes),"mygadget_callbacks":int(callbacks),
                "last_callback_guest":f"0x{int(last_callback,16):08X}",
                "draw_target_guest":f"0x{int(target,16):08X}"})
    if gameplay_trace and os.environ.get("GWRECOMP_IFCLEVEL_CONTINUE")=="1":
        stats_evidence={"schema":"gw-ifclevel-gameplay-frame-stats/v1",
            "target_sha256":EXPECTED_TARGET,"trace":"evidence/native_ifclevel_creature_probe.trace",
            "trace_sha256":hashlib.sha256(gameplay_trace.encode("utf-8")).hexdigest(),
            "interface_under_test":"0x0035FE9A","vptr_guest":"0x002EBB04",
            "frame_limit":40,"draw_ticks_captured":len(tick_stats),"ticks":tick_stats,
            "frontier_lines":[line for line in gameplay_trace.splitlines()
                if "frontier=1" in line or line.startswith("post_loader_tick_stats unavailable=")],
            "result_line":next((line for line in gameplay_trace.splitlines()
                if line.startswith("result completed_ticks=")),None),
            "interpretation":"Per-tick counters are observations from the bounded original-code continuation; no image contents are injected by this summary."}
        (ROOT/"evidence"/"native_ifclevel_gameplay_frame_stats.json").write_text(
            json.dumps(stats_evidence,indent=2)+"\n",encoding="utf-8")
    runtime_frontier_lines=[line for line in executed_stderr.splitlines()
        if line.startswith(("RUNTIME_FRONTIER ","RUNTIME_FRONTIER_CALL ",
                            "RUNTIME_FRONTIER_CALL_OPERAND ","RUNTIME_FRONTIER_MEM ",
                            "ICALL: unresolved VA"))]
    (ROOT/"evidence"/"native_ifclevel_creature_probe.runtime.log").write_text(
        ("\n".join(runtime_frontier_lines)+"\n") if runtime_frontier_lines else
        "RUNTIME_FRONTIER none in this replay\n",encoding="utf-8")
    host_read_write_rows=[line for line in executed_stderr.splitlines()
        if line.startswith("TRACE host AH3F write ")]
    host_read_re=re.compile(
        r"eip=([0-9a-fA-F]+) path='(.*?)' file_offset=([0-9a-fA-F]+) requested=(\d+) done=(\d+) "
        r"guest=([0-9a-fA-F]+) range_end=([0-9a-fA-F]+) backing=([^ ]+) owner=([0-9a-fA-F]+)\+([0-9a-fA-F]+)")
    host_read_writes=[]
    for line in host_read_write_rows:
        match=host_read_re.search(line)
        if not match:
            raise SystemExit(f"DOS AH=3F host-write audit row is malformed: {line!r}")
        eip,path,file_offset,requested,done,guest,end,backing,owner,size=match.groups()
        host_read_writes.append({"eip":f"0x{int(eip,16):08X}","path":path,
            "file_offset":int(file_offset,16),"requested":int(requested),"written":int(done),
            "guest_start":f"0x{int(guest,16):08X}","guest_end_exclusive":f"0x{int(end,16):08X}",
            "backing":backing,"owner_start":f"0x{int(owner,16):08X}","owner_size":int(size,16)})
    if not host_read_writes or any(row["backing"] in ("outside-guest-memory","host-outside-guest")
                                   for row in host_read_writes):
        raise SystemExit("one or more DOS AH=3F host writes lack a guest address/backing range")
    pl1_host_writes=[row for row in host_read_writes
        if row["path"].lower().endswith("data/pl1.dat") and row["written"]>0]
    if not any(row["guest_start"]=="0x02224C2C" and row["backing"] in
               ("live-dpmi-linear","live-game-heap") and row["guest_end_exclusive"]=="0x0222D63E"
               for row in pl1_host_writes):
        raise SystemExit(f"original pl1.dat read was not attributed to its live backed guest buffer: {pl1_host_writes!r}")
    watched_biogame_rows=[line for line in executed_stderr.splitlines()
        if line.startswith("TRACE watched_biogame_host_write ")]
    watched_biogame_re=re.compile(
        r"eip=([0-9a-fA-F]+) path='(.*?)' file_offset=([0-9a-fA-F]+) requested=(\d+) done=(\d+) "
        r"guest=([0-9a-fA-F]+) overlap=([0-9a-fA-F]+)\.\.([0-9a-fA-F]+) file_covers_1198ea=(\d+) "
        r"source_cell_offset=([0-9a-fA-F]+) source_cell=([0-9a-fA-F]{8}) cell_after=([0-9a-fA-F]+) "
        r"nonzero_bytes_3670_3900=(\d+) esp=([0-9a-fA-F]+) ebp=([0-9a-fA-F]+) "
        r"regs=([0-9a-fA-F/]+) stack=([0-9a-fA-F/]+)")
    watched_biogame_writes=[]
    for line in watched_biogame_rows:
        match=watched_biogame_re.search(line)
        if not match:
            raise SystemExit(f"BioGame buffer host-write watch row is malformed: {line!r}")
        (eip,path,file_offset,requested,done,guest,overlap_start,overlap_end,
         covers,source_offset,source_cell,cell_after,nonzero,esp,ebp,regs,stack)=match.groups()
        watched_biogame_writes.append({"eip":f"0x{int(eip,16):08X}","path":path,
            "file_offset":int(file_offset,16),"requested":int(requested),"written":int(done),
            "guest_start":f"0x{int(guest,16):08X}","overlap_start":f"0x{int(overlap_start,16):08X}",
            "overlap_end_exclusive":f"0x{int(overlap_end,16):08X}",
            "covers_link_0x1198ea":bool(int(covers)),"source_cell_offset":int(source_offset,16),
            "source_cell_bytes_le":source_cell,"cell_after":f"0x{int(cell_after,16):08X}",
            "nonzero_bytes_in_guest_2f3670_2f3900":int(nonzero),
            "guest_esp":f"0x{int(esp,16):08X}","guest_ebp":f"0x{int(ebp,16):08X}",
            "registers_eax_ebx_ecx_edx_esi_edi_ebp_esp":[f"0x{int(x,16):08X}" for x in regs.split("/")],
            "guest_stack_dwords":[f"0x{int(x,16):08X}" for x in stack.split("/")]})
    conq_buffer_writes=[row for row in watched_biogame_writes
        if row["path"].lower().replace("\\","/").endswith("levels/conq001.dat") and
           row["covers_link_0x1198ea"]]
    conq_source_cell_proven=any(row["source_cell_offset"]==0x1EC2 and
        row["source_cell_bytes_le"]=="00000000" and
        row["cell_after"]=="0x00000000" for row in conq_buffer_writes)
    # The standard title/first-frame regression intentionally ends before a
    # level data file is opened. Require the BioGame+0x1EC2 source-byte proof
    # only in a replay whose captured AH=3F stream actually contains CONQ001;
    # if it is opened, the causal byte and live value remain mandatory.
    conq_file_read_observed=any(row["path"].lower().replace("\\","/").endswith(
        "levels/conq001.dat") for row in host_read_writes)
    if conq_file_read_observed and not conq_source_cell_proven:
        raise SystemExit("native AH=3F read CONQ001.DAT but did not prove the source and live value for BioGame+0x1EC2")
    guest_buffer_stores=[line for line in executed_stderr.splitlines()
        if line.startswith("TRACE watched_biogame_guest_store ")]
    host_read_audit={"schema":"gw-native-dos-ah3f-host-write-audit/v1",
        "target_sha256":EXPECTED_TARGET,"completed_guest_writes":len(host_read_writes),
        "pl1_dat":{"writes":pl1_host_writes,"buffer_owner":"active backed allocation from original setup_game startup_files"},
        "level_data_buffer":{"symbol":"unkn_buf_119670","link_range":"0x00119670..0x00119900",
            "guest_range":"0x002F3670..0x002F3900","BioGame_offset":"+0x1C48",
            "watched_runtime_host_writes":watched_biogame_writes,
            "watched_original_instruction_stores":guest_buffer_stores,
            "conq001_target_cell":{"link":"0x001198EA","guest":"0x002F38EA",
                "BioGame_offset":"+0x1EC2","source_file_offset":"0x1EC2",
                "file_read_observed":conq_file_read_observed,
                "source_cell_proven":conq_source_cell_proven,
                "live_replay_source_writes":conq_buffer_writes}},
        "events":host_read_writes}
    (ROOT/"evidence"/"native_dos_ah3f_host_write_audit.json").write_text(
        json.dumps(host_read_audit,indent=2)+"\n",encoding="utf-8")
    if os.environ.get("GWRECOMP_IFCLEVEL_CONTINUE")=="1":
        # The restored original process_packets path now executes the
        # fixup-backed BioGame effect callbacks and stops at the next
        # unresolved virtual call. Treat this as a bounded frontier capture,
        # not as 40 completed gameplay ticks.
        has_failed_post_loader_tick=(any(line.startswith("post_loader_tick=") and
            "frontier=1" in line for line in gameplay_trace.splitlines()) or
            any(line.startswith("result ") and "post_loader_frontier=1" in line
                for line in gameplay_trace.splitlines()))
        if has_failed_post_loader_tick:
            replay_stdout_path.write_text(executed.stdout,encoding="utf-8")
            replay_stderr_path.write_text(executed.stderr,encoding="utf-8")
            setup_line=next((line for line in executed.stdout.splitlines()
                if line.startswith("PASS original setup_game continuous entry=00094ac0")),None)
            level_line=next((line for line in executed.stdout.splitlines()
                if line.startswith("PASS original IFCLevel transition, first Update/Draw")),None)
            runtime_lines=[line for line in executed_stderr.splitlines()
                if line.startswith(("RUNTIME_FRONTIER ","RUNTIME_FRONTIER_CALL ",
                                    "RUNTIME_FRONTIER_CALL_OPERAND ","TRACE ICALL_CALL "))]
            frontier=next((line for line in runtime_lines
                if line.startswith("RUNTIME_FRONTIER eip=")),None)
            if frontier is None:
                frontier=next((line for line in executed_stderr.splitlines()
                    if line.startswith("ICALL: denied VA ")),None)
            frontier_eip_match=re.search(r"RUNTIME_FRONTIER eip=([0-9a-fA-F]{8})",frontier or "")
            if frontier_eip_match is None:
                frontier_eip_match=re.search(r"at 0x([0-9a-fA-F]{8}) from",frontier or "")
            frontier_eip=int(frontier_eip_match.group(1),16) if frontier_eip_match else 0
            operand=next((line for line in runtime_lines
                if line.startswith(f"RUNTIME_FRONTIER_CALL_OPERAND site={frontier_eip:08X} ")),None)
            effect_call=next((line for line in runtime_lines
                if line.startswith("RUNTIME_FRONTIER_CALL ") and
                   "target=002552E0 caller=00086810" in line),None)
            if effect_call is None:
                effect_call=next((line for line in runtime_lines
                    if line.startswith("TRACE ICALL_CALL ") and
                    re.search(r"site=000(?:78BA1|88146) target=002552E0",line)),None)
            packet_method_call=next((line for line in runtime_lines
                if line.startswith("TRACE ICALL_CALL site=00082F77 ")),None)
            packet_method_alt_call=next((line for line in runtime_lines
                if line.startswith("TRACE ICALL_CALL site=00082F77 ") and
                   "target=002304E0" in line and "slot_address=002EBCDC" in line),None)
            landing_effect_position_call=next((line for line in runtime_lines
                if line.startswith("TRACE ICALL_CALL site=00088563 ")),None)
            landing_effect_draw_call=next((line for line in runtime_lines
                if line.startswith("TRACE ICALL_CALL site=00088596 ")),None)
            packet_action_call=next((line for line in runtime_lines
                if line.startswith("TRACE ICALL_CALL site=000561E9 ")),None)
            packet_entity_call=next((line for line in runtime_lines
                if line.startswith("TRACE ICALL_CALL site=00050164 ")),None)
            packet_entity_next_call=next((line for line in runtime_lines
                if line.startswith("TRACE ICALL_CALL site=0005017E ")),None)
            packet_creature_state_call=next((line for line in runtime_lines
                if line.startswith("TRACE ICALL_CALL site=00080F86 ")),None)
            packet_creature_init_call=next((line for line in runtime_lines
                if line.startswith("TRACE ICALL_CALL site=000502E1 ")),None)
            effect_memory_snapshot=next((line for line in executed_stderr.splitlines()
                if line.startswith("TRACE BIOGAME_EFFECT_CALL eip=00088146 ")),None)
            packet_method_capture={"static_slot_link":"0x00111CF8",
                "static_LE_fixup":{"source_type":"SRC_OFFSET32","source_object":3,
                    "target_object":1,"target_link":"0x00055CF0"},
                "static_LE_fixup_target_guest":f"0x{image.link_to_linear(0x55CF0):08X}",
                "live_slot_guest":"0x002EBCF8","runtime_call":packet_method_call,
                "additional_live_receiver":{"slot_link":"0x00111CDC","slot_guest":"0x002EBCDC",
                    "static_LE_fixup":{"source_type":"SRC_OFFSET32","source_object":3,
                        "target_object":1,"target_link":"0x000454E0"},
                    "target_guest":"0x002304E0","runtime_call":packet_method_alt_call},
                "landing_effect_callbacks":{"vtable_link":"0x001121E4","live_vtable_guest":"0x002EC1E4",
                    "position_call":{"site":"0x00088563","slot_link":"0x001121E8",
                        "target_link":"0x0006A2E0","runtime_call":landing_effect_position_call},
                    "draw_call":{"site":"0x00088596","slot_link":"0x00112228",
                        "target_link":"0x00069E20","runtime_call":landing_effect_draw_call}},
                "interpretation":"the two live interface receivers use distinct LE-fixup-backed slots; each exact target is admitted independently"}
            result_line=next((line for line in gameplay_trace.splitlines()
                if line.startswith("result completed_ticks=")),"")
            tick_line=next((line for line in gameplay_trace.splitlines()
                if line.startswith("post_loader_tick=0 ")),"")
            if setup_line is None or level_line is None or frontier is None or (
                    effect_call is None and os.environ.get("GWRECOMP_IFC_TRANSITION_CAUSAL_PROBE")!="roundtrip"):
                raise SystemExit("bounded process_packets frontier lacks setup, IFCLevel, or the executed 0x88146 dispatch")
            if frontier_eip==0x82F77:
                raise SystemExit("verified LE-backed packet method was still rejected at 0x82F77")
            if packet_method_call is None or "target=00240CF0" not in packet_method_call or \
                    "slot_address=002EBCF8" not in packet_method_call:
                raise SystemExit("0x82F77 did not execute the original LE-fixup-backed target from slot 0x111CF8")
            if packet_method_alt_call is None:
                raise SystemExit("0x82F77 did not execute its second live receiver from exact LE slot 0x111CDC -> 0x454E0")
            if landing_effect_position_call is None or "target=002572E0" not in landing_effect_position_call or \
                    "slot_address=002EC1E8" not in landing_effect_position_call:
                raise SystemExit("0x88563 did not execute the landing-effect position method from LE slot 0x1121E8 -> 0x6A2E0")
            if landing_effect_draw_call is None or "target=00257E20" not in landing_effect_draw_call or \
                    "slot_address=002EC228" not in landing_effect_draw_call:
                raise SystemExit("0x88596 did not execute the landing-effect draw method from LE slot 0x112228 -> 0x69E20")
            if packet_method_capture["static_LE_fixup_target_guest"]!="0x00240CF0":
                raise SystemExit("packet method LE fixup no longer maps to the captured guest target")
            if packet_action_call is None or "target=00263360" not in packet_action_call or \
                    "slot_address=002EBF0C" not in packet_action_call:
                raise SystemExit("0x55CF0's original action-state method did not execute from its LE-fixup-backed slot")
            if packet_entity_call is None or "target=00255030" not in packet_entity_call or \
                    "slot_address=002EBDB4" not in packet_entity_call:
                raise SystemExit("0x50164's original entity-flag query did not execute from its LE-fixup-backed slot")
            if packet_entity_next_call is None or "target=00232A90" not in packet_entity_next_call:
                raise SystemExit("0x5017E's original entity method did not resolve to the target backed by its LE vtable fixup")
            if packet_creature_state_call is None or "target=00255070" not in packet_creature_state_call or \
                    "slot_address=002EBD6C" not in packet_creature_state_call:
                raise SystemExit("0x80F86's original creature-state query did not execute from its LE-fixup-backed slot")
            packet_creature_state_later_call=next((line for line in runtime_lines
                if line.startswith("TRACE ICALL_CALL site=00054904 ")),None)
            if packet_creature_state_later_call is None or (
                    "target=00255070" not in packet_creature_state_later_call or
                    "slot_address=002EBD6C" not in packet_creature_state_later_call):
                raise SystemExit("0x54904 did not execute the authenticated creature-state vtable slot contract")
            packet_mapdisplay_state_call=next((line for line in runtime_lines
                if line.startswith("TRACE ICALL_CALL site=00056F3B ")),None)
            if packet_mapdisplay_state_call is None or "target=00259C70" not in packet_mapdisplay_state_call or \
                    "slot_address=002EBF14" not in packet_mapdisplay_state_call:
                raise SystemExit("0x56F3B did not execute the LE-fixup-backed MapDisplay state callback")
            packet_biogame_vtable_call=next((line for line in runtime_lines
                if line.startswith("TRACE ICALL_CALL site=00079218 ")),None)
            if packet_biogame_vtable_call is None or "target=00254E50" not in packet_biogame_vtable_call or \
                    "slot_address=002EBEC0" not in packet_biogame_vtable_call:
                raise SystemExit("0x79218 did not execute the live callback from its exact LE-fixup-backed slot")
            packet_creature_action_call=next((line for line in runtime_lines
                if line.startswith("TRACE ICALL_CALL site=0005A2F5 ")),None)
            valid_packet_entity_action_calls={
                ("target=00255240","slot_address=002EBD14"),
                ("target=00255240","slot_address=002EC070"),
                ("target=00280CA0","slot_address=002EC3CC")}
            if packet_creature_action_call is None or not any(
                    target in packet_creature_action_call and slot in packet_creature_action_call
                    for target,slot in valid_packet_entity_action_calls):
                raise SystemExit("0x5A2F5 did not execute an original Thing/Creature/PlSpec action callback")
            packet_record_walk_call=next((line for line in runtime_lines
                if line.startswith("TRACE ICALL_CALL site=00080A3A ")),None)
            valid_record_walk_calls={
                ("target=00259E10","slot_address=002EBEB4"), # MapDisplay table
                ("target=00255240","slot_address=002EBD14"), # TT_CREATURE table
                ("target=00255240","slot_address=002EC070"), # PlSpec table
                ("target=00259E10","slot_address=002EC1F4"), # Effect table
            }
            if packet_record_walk_call is None or not any(
                    target in packet_record_walk_call and slot in packet_record_walk_call
                    for target,slot in valid_record_walk_calls):
                raise SystemExit("0x80A3A did not execute a callback from the finite LE-fixup-backed record-walk tables")
            packet_creature_action_repeat=next((line for line in runtime_lines
                if line.startswith("TRACE ICALL_CALL site=0005A70D ")),None)
            if packet_creature_action_repeat is None or "target=00255240" not in packet_creature_action_repeat or \
                    "slot_address=002EBD14" not in packet_creature_action_repeat:
                raise SystemExit("0x5A70D did not execute the repeated LE-fixup-backed creature callback")
            packet_entity_movement_call=next((line for line in runtime_lines
                if line.startswith("TRACE ICALL_CALL site=0005A9A0 ")),None)
            if packet_entity_movement_call is None or "target=00244D80" not in packet_entity_movement_call or \
                    "slot_address=002EBDB8" not in packet_entity_movement_call:
                raise SystemExit("0x5A9A0 did not execute the LE-fixup-backed entity movement method")
            packet_biogame_effect_handler=next((line for line in runtime_lines
                if line.startswith("TRACE ICALL_CALL site=00058BBD ") and "target=00232BF0" in line),None)
            if packet_biogame_effect_handler is None or "slot_address=002EBD8C" not in packet_biogame_effect_handler:
                raise SystemExit("the BioGame receiver at 0x58BBD did not dispatch from its exact LE vtable fixup")
            if packet_creature_init_call is None or "target=00232360" not in packet_creature_init_call or \
                    "slot_address=002EBD84" not in packet_creature_init_call:
                raise SystemExit("0x502E1's original creature initializer did not execute from its LE-fixup-backed slot")
            packet_method_capture.update({"live_target_guest":"0x00240CF0",
                "live_target_link":"0x00055CF0","static_vs_live_match":True})
            if frontier_eip==0x82F77:
                raise SystemExit("packet method dispatch did not advance beyond the authenticated call")
            if frontier_eip:
                packet_method_capture["dispatch_completed_before_next_frontier"]=True
            operand_match=re.search(r"target=([0-9a-fA-F]{8})",operand or "")
            slot_match=re.search(r"slot=([0-9a-fA-F]{8})",operand or "")
            if frontier_eip==0x88179:
                next_target=0x00254E20
                if not operand_match or not slot_match or int(operand_match.group(1),16)!=next_target or \
                        int(slot_match.group(1),16)!=0x002EC228 or "port=1:88179:00088179" not in tick_line:
                    raise SystemExit("process_packets did not stop fail-closed at its observed 0x88179 target")
                next_call_evidence=next(line for line in runtime_lines
                    if line.startswith("RUNTIME_FRONTIER_CALL_OPERAND site=00088179 "))
                next_slot_guest="0x002EC228"
                next_target_guest=f"0x{next_target:08X}"
                next_instruction="CALL dword ptr [EDI+0x44]"
                expected_frontier_tick="port=1:88179:00088179"
                next_frontier_registers=frontier
            elif frontier_eip==0x893F6:
                # This is the second call through [ECX+0x64]. Its sibling at
                # 0x893B2 just dispatched the same target from the same LE
                # fixup-backed slot; the test's byte/fixup checks enforce
                # the repeated callsite contract, and the dispatcher remains
                # runtime-equality guarded here.
                next_call=next((line for line in runtime_lines
                    if line.startswith("RUNTIME_FRONTIER_CALL ") and
                       "target=00271810 caller=00089380" in line),None)
                if not next_call or "port=1:893f6:000893f6" not in tick_line:
                    raise SystemExit("FUN_00089380 second call lacks its sibling runtime target or exact 0x893F6 frontier")
                next_call_evidence=next_call
                next_slot_guest="0x002EC248"
                next_target_guest="0x00271810"
                next_instruction="CALL dword ptr [ECX+0x64]"
                expected_frontier_tick="port=1:893f6:000893f6"
                next_frontier_registers=frontier
            elif frontier_eip==0x79459:
                # Same vtable slot and fixup-backed action-state query as the
                # separately verified 0x791E9 site; this branch should only
                # remain reachable if the closure did not honor the new
                # one-site contract.
                next_call_evidence=next((line for line in runtime_lines
                    if line.startswith("TRACE ICALL_CALL site=00079459 ")),frontier)
                next_slot_guest="0x002EC250"
                next_target_guest="0x002552C0"
                next_instruction="CALL dword ptr [EDX+0x6C]"
                expected_frontier_tick="port=1:79459:00079459"
                next_frontier_registers=frontier
            elif frontier_eip==0x58BBD and any(f"site=00058BBD target={image.link_to_linear(0x8A720):08X}" in line and
                     f"slot_address={image.link_to_linear(0x11226C):08X}" in line
                     for line in runtime_lines if line.startswith("TRACE ICALL_CALL ")):
                # A new fail-closed frontier is acceptable only after the
                # just-admitted original process_packets effect callback
                # demonstrably returned through the exact LE-backed
                # nullsub_14 slot. The new frontier remains unreviewed.
                next_call_evidence=next(line for line in runtime_lines
                    if line.startswith("TRACE ICALL_CALL ") and
                    f"site=00058BBD target={image.link_to_linear(0x8A720):08X}" in line and
                    f"slot_address={image.link_to_linear(0x11226C):08X}" in line)
                next_slot_guest="unresolved-until-next-frontier-analysis"
                next_target_guest="unresolved-until-next-frontier-analysis"
                next_instruction="new fail-closed frontier; see captured EIP"
                expected_frontier_tick=f":{frontier_eip:08x}"
                next_frontier_registers=frontier
            else:
                # Persist the first new boundary with its EIP, registers and
                # ring instead of aborting before the causal evidence JSON is
                # written. The call itself remains fail-closed in the runtime.
                next_call_evidence=frontier
                next_slot_guest="unresolved-until-next-frontier-analysis"
                next_target_guest="unresolved-until-next-frontier-analysis"
                next_instruction="unreviewed original instruction; see EIP and runtime ring"
                expected_frontier_tick=""
                next_frontier_registers=frontier
            frontier_result=any(line.startswith("result ") and "post_loader_frontier=1" in line
                                for line in gameplay_trace.splitlines())
            if expected_frontier_tick not in tick_line or ("frontier=1" not in tick_line and not frontier_result):
                raise SystemExit(f"process_packets did not stop fail-closed at its recorded EIP {frontier_eip:08X}")
            null_ds14_events=[line for line in executed_stderr.splitlines()
                if line.startswith("TRACE guest-null-read ")]
            if null_ds14_events:
                raise SystemExit(f"process_packets frontier included an unexpected low DS read: {null_ds14_events[0]}")
            frontier_evidence={"schema":"gw-native-ifclevel-process-packets-frontier/v1",
                "target_sha256":EXPECTED_TARGET,
                "setup_game":"original continuous setup_game reached",
                "ifclevel":"original transition reached IFCLevel; the controlled 40-tick UI phase was superseded by full-loop process_packets",
                "process_packets_entry":"0x00093010",
                "effect_accessor":{"callsite_link":"0x00088146","instruction":"CALL dword ptr [EDX+4]",
                    "target_guest":"0x002552E0","target_link":"0x0006A2E0",
                    "target_symbol":"fixup-backed BioGame effect coordinate accessor",
                    "runtime_call_ring":effect_call,
                    "classification":"EDX is the live effect-record vtable at 0x002EC1E4; EAX=0x00341576 is the BioGame::__effects data object, not the call target. The call target is [EDX+4]=0x002552E0 (Obj1 link 0x6A2E0). This dispatch executed, so it is not the failing frontier or a sentinel-as-code call.",
                    "runtime_registers":{"EAX":"0x00341576","EBX":"0x00000003","ECX":"0x00340600","EDX":"0x002EC1E4","ESI":"0x00000B80","EDI":"0x00342934","EBP":"0x003FEF2A","ESP":"0x003FED60"},
                    "map_effects_head_link":"0x00167576","map_effects_head_guest":"0x00341576",
                    "pre_dispatch_memory_snapshot":effect_memory_snapshot},
                "biogame_effect_entity_dispatch":{"callsite_link":"0x00058BBD","instruction":"CALL dword ptr [EBX+0x88]",
                    "vtable_slot_link":"0x00111D8C","fixup_target_link":"0x00047BF0",
                    "runtime_call":packet_biogame_effect_handler,
                    "alternate_runtime_target":{"vtable_slot_link":"0x0011226C","target_link":"0x0008A720",
                        "evidence":"the other live receiver at this same callsite used its own LE-fixup-backed slot"}},
                "executed_fixup_backed_callbacks":[
                    {"callsite_link":"0x00079459","instruction":"CALL dword ptr [EDX+0x6C]",
                     "slot_guest":"0x002EC250","slot_link":"0x00112250","target_link":"0x0006A2C0",
                     "target_guest":"0x002552C0","runtime_call":next((line for line in runtime_lines
                         if line.startswith("TRACE ICALL_CALL site=00079459 ")),None)},
                    {"callsite_link":"0x00088179","instruction":"CALL dword ptr [EDI+0x44]",
                     "slot_guest":"0x002EC228","slot_link":"0x00112228","target_link":"0x00069E20",
                     "target_guest":"0x00254E20","runtime_call_ring":next((line for line in runtime_lines
                         if line.startswith("RUNTIME_FRONTIER_CALL ") and
                            "target=00254E20 caller=00086810" in line),None)},
                    {"callsite_link":"0x000893B2","instruction":"CALL dword ptr [ECX+0x64]",
                     "slot_guest":"0x002EC248","slot_link":"0x00112248","target_link":"0x00086810",
                     "target_guest":"0x00271810","fixup_backed_sibling_to_frontier":"0x000893F6",
                     "runtime_call_ring":next((line for line in runtime_lines
                         if line.startswith("RUNTIME_FRONTIER_CALL ") and
                            "target=00271810 caller=00089380" in line),None)},
                    {"callsite_link":"0x00058BBD","instruction":"CALL dword ptr [EBX+0x88]",
                     "slot_link":"0x0011226C","target_link":"0x0008A720","target_symbol":"nullsub_14",
                     "target_guest":f"0x{image.link_to_linear(0x8A720):08X}",
                     "runtime_call_ring":next((line for line in runtime_lines
                         if line.startswith("TRACE ICALL_CALL ") and
                         f"site=00058BBD target={image.link_to_linear(0x8A720):08X}" in line),None)},
                    {"callsite_link":"0x00058BBD","instruction":"CALL dword ptr [EBX+0x88]",
                     "slot_link":"0x00111D8C","target_link":"0x00047BF0","target_guest":"0x00232BF0",
                     "runtime_call":packet_biogame_effect_handler,
                     "provenance":"second object-3 receiver vtable slot from the same original callsite; distinct LE fixup and exact live target guard"}],
                "packet_method_dispatch":{"callsite_link":"0x00082F77","instruction":"CALL dword ptr [EDX]",
                    "map_nearest_named_data":"W?$Wvf0eo2i8:IFCLevel$$nx[]pn()v at 0x00111AE4; extent to slot 0x00111CF8 unproven",
                    **packet_method_capture},
                "packet_action_state_query":{"callsite_link":"0x000561E9","instruction":"CALL dword ptr [EDX+0x68]",
                    "static_slot_link":"0x00111F0C","static_fixup_target_link":"0x00078360",
                    "static_fixup_target_guest":f"0x{image.link_to_linear(0x78360):08X}",
                    "runtime_call":packet_action_call,"runtime_slot_guest":"0x002EBF0C",
                    "interpretation":"original action-state query reached through the vtable fixup and returned; the next frontier is later in process_packets"},
                "entity_flag_query":{"callsite_link":"0x00050164","instruction":"CALL dword ptr [EDX+0xB0]",
                    "static_slot_link":"0x00111DB4","static_fixup_target_link":"0x0006A030",
                    "runtime_call":packet_entity_call},
                "entity_method_call":{"callsite_link":"0x0005017E","instruction":"CALL dword ptr [EBX+0x8C]",
                    "static_LE_fixup_slot":"0x00111D90","static_fixup_target_link":"0x00047A90",
                    "runtime_call":packet_entity_next_call,
                    "runtime_note":"the captured EBX vtable is dynamically resident at 0x00310506, so the live slot address is not the static LE slot; the observed target equals the exact object-1 target from LE slot 0x111D90"},
                "creature_state_query":{"callsite_link":"0x00080F86","instruction":"CALL dword ptr [ECX+0x68]",
                    "static_slot_link":"0x00111D6C","static_fixup_target_link":"0x0006A070",
                    "runtime_call":packet_creature_state_call},
                "creature_state_query_later":{"callsite_link":"0x00054904","instruction":"CALL dword ptr [EDX+0x68]",
                    "static_slot_link":"0x00111D6C","static_fixup_target_link":"0x0006A070",
                    "runtime_call":packet_creature_state_later_call,
                    "provenance":"same exact LE fixup slot as the completed 0x80F86 sibling; live equality checked at this site"},
                "map_display_state_callback":{"callsite_link":"0x00056F3B","instruction":"CALL dword ptr [ECX+0x70]",
                    "static_slot_link":"0x00111F14","static_fixup_target_link":"0x0006EC70",
                    "runtime_call":packet_mapdisplay_state_call,
                    "provenance":"canonical object-3 SRC_OFFSET32 fixup matches the exact slot used by 0x78FAA; captured runtime destination is equality-guarded"},
                "biogame_vtable_method":{"callsite_link":"0x00079218","instruction":"CALL dword ptr [EDX+0x1C]",
                    "static_slot_link":"0x00111EC0","static_fixup_target_link":"0x00069E50",
                    "runtime_call":packet_biogame_vtable_call,
                    "provenance":"canonical object-3 SRC_OFFSET32 fixup; runtime destination is equality-guarded"},
                "creature_action_callback":{"callsite_link":"0x0005A2F5","instruction":"CALL dword ptr [EDX+0x10]",
                    "static_slot_alternatives":[
                        {"vtable_link":"0x00111D04","slot_link":"0x00111D14","target_link":"0x0006A240"},
                        {"vtable_link":"0x00112060","slot_link":"0x00112070","target_link":"0x0006A240"},
                        {"vtable_link":"0x001123BC","slot_link":"0x001123CC","target_link":"0x00095CA0"}],
                    "runtime_call":packet_creature_action_call,
                    "provenance":"complete object-3 SRC_OFFSET32 vtables are validated and the live base/slot pair is constrained to these alternatives"},
                "record_walk_callback":{"callsite_link":"0x00080A3A","instruction":"CALL dword ptr [ECX+0x10]",
                    "static_slot_link":"0x00111EB4","static_fixup_target_link":"0x0006EE10",
                    "runtime_call":packet_record_walk_call,
                    "provenance":"canonical object-3 SRC_OFFSET32 fixup; runtime destination equality checked"},
                "creature_action_callback_repeat":{"callsite_link":"0x0005A70D","instruction":"CALL dword ptr [EDX+0x10]",
                    "static_slot_link":"0x00111D14","static_fixup_target_link":"0x0006A240",
                    "runtime_call":packet_creature_action_repeat,
                    "provenance":"repeated method call in FUN_00059F60; same fixup-backed object-3 method slot as 0x5A2F5"},
                "entity_movement_callback":{"callsite_link":"0x0005A9A0","instruction":"CALL dword ptr [EDX+0xB4]",
                    "static_slot_link":"0x00111DB8","static_fixup_target_link":"0x00059D80",
                    "runtime_call":packet_entity_movement_call,
                    "provenance":"same canonical object-3 SRC_OFFSET32 fixup used at 0x5AB28; live destination equality checked"},
                "creature_initializer_query":{"callsite_link":"0x000502E1","instruction":"CALL dword ptr [EDX+0x80]",
                    "static_slot_link":"0x00111D84","static_fixup_target_link":"0x00047360",
                    "runtime_call":packet_creature_init_call},
                "next_frontier":{"callsite_link":f"0x{frontier_eip:08X}","instruction":next_instruction,
                    "slot_guest":next_slot_guest,"target_guest":next_target_guest,
                    "target_source":"exact LE slot fixup plus the sibling 0x893B2 runtime dispatch" if frontier_eip==0x893F6 else "captured live operand",
                    "runtime_call_or_operand":next_call_evidence,
                    "registers":next_frontier_registers,"runtime_fail_closed":True},
                "mapDisplay_pointer":{"map_symbol":"W?mapDisplay$n$MapDisplay$$ at link 0x0016CD70",
                    "field_link":"0x0016CD88","field_guest":"0x00346D88",
                    "canonical_LE_initial_dword":"0x00000000","direct_LE_fixup":False,
                    "rea_xrefs_evidence_id":"ev_b21af533620ea0609937b31919d890f3e56166f1aa26a2f2e2053a1c3d229b55",
                    "rea_xrefs_count":18,"all_direct_xref_instructions_are_reads":True,
                    "earlier_0x303_claim":"withdrawn: 0x00000303 was sampled at the incorrect guest address 0x0030CD88. The measured Obj3 mapping puts link 0x0016CD88 at guest 0x00346D88; the canonical LE value and bounded replay initial value there are zero.",
                    "runtime_writer":{"function":"FUN_00079320","instruction_link":"0x000794D5","instruction":"MOV dword ptr [ESI+0x18],EAX","evidence":"REA/Ghidra dossier shows EAX loaded from [ESI+0x37] at 0x794C9; the same routine clears [ESI+0x37] at 0x794DA. In the capture ESI=0x00346D70 and EAX=0, so the transfer writes zero into mapDisplay+0x18 rather than initializing a selection pointer."},
                    "map_display_setup":{"function":"FUN_000785C0","caller":"FUN_00066DD0","evidence":"REA/Ghidra shows geometry and map-display state initialization; it does not write mapDisplay+0x18. FUN_00066DD0 calls it only when byte mapDisplay+0x1D is zero."},
                    "state":"No authentic nonzero world-entity pointer producer is demonstrated in the current route; do not seed one. this+4=0x002E0590 points to the static UI/control record initialized by the original CRT callback, not a world-entity list; this+0xC8 remains null.",
                    "low_DS14_read_events_in_this_replay":0,
                    "probe_window":"0x000..0xFFF excluding the BIOS tick-count bytes 0x46C..0x46D",
                    "map_nearest_entry_for_link_0x00106590":"aExceland at 0x00106310; earlier customGfx_files[] at 0x0010622C; no exact MAP symbol at 0x00106590"},
                "surface_update_C7_writes":{"link_field":"secondary interface this+0xC7",
                    "0x214A0":"AND [ESI+0xC7],0xFE: clears bit 0 on the Update path",
                    "0x21618_0x21624":"toggle bit 1 on the non-Escape key/action path after the this+0xC8 byte+5 bit 2 gate is clear, or when its bit 1 is set and current C7 bit 1 is already set; global 0x117660 bit 1 must also be clear",
                    "0x21648_0x21655":"toggle bit 2 only after AX==0x1B reaches 0x2162F; subsequent branch at 0x2165B depends on the new bit 2"},
                "completed_surface_ticks":0,"simulation_advanced":False,
                "low_ds_reads":0,"trace_tick":tick_line,"trace_result":result_line,
                "evidence":{"stdout":"evidence/native_ifclevel_creature_probe.stdout.log",
                    "stderr":"evidence/native_ifclevel_creature_probe.stderr.log",
                    "runtime":"evidence/native_ifclevel_creature_probe.runtime.log",
                    "trace":"evidence/native_ifclevel_creature_probe.trace"},
                "interpretation":f"The 0x88146 effect accessor is a valid fixup-backed virtual dispatch and executed. The previous 0x82F77 mismatch was caused by using link slot 0x1120F8; correct rebasing identifies slot 0x111CF8 and its LE target 0x55CF0. This replay stops at the next unresolved original boundary 0x{frontier_eip:08X}; no gameplay tick completion is claimed."}
            (ROOT/"evidence"/"native_ifclevel_process_packets_frontier.json").write_text(
                json.dumps(frontier_evidence,indent=2)+"\n",encoding="utf-8")
            # Preserve the effect threshold/activation proof even when the
            # bounded replay later stops at an unrelated indirect frontier.
            progress_re=re.compile(r"TRACE smuggler_ground_probe eip=([0-9a-fA-F]+) phase_tick=(\d+) Turn=(\d+) caller=([0-9a-fA-F]+) object=([0-9a-fA-F]+) type=([0-9a-fA-F]+) state=([0-9a-fA-F]+).*?ground=([0-9a-fA-F]+) object_27=([0-9a-fA-F]+) jl_taken=(\d+).*?C8=([0-9a-fA-F]+).*?gate_10AB29=([0-9a-fA-F]+)")
            progress_rows=[]
            for line in executed_stderr.splitlines():
                m=progress_re.search(line)
                if m:
                    eip,tick,turn,caller,obj,etype,state,ground,threshold,jl,c8,gate=m.groups()
                    progress_rows.append({"eip":f"0x{int(eip,16):08X}","tick":int(tick),
                        "Turn":int(turn),"caller":f"0x{int(caller,16):08X}","effect":f"0x{int(obj,16):08X}",
                        "effect_type":f"0x{int(etype,16):02X}","state":f"0x{int(state,16):02X}",
                        "ground":f"0x{int(ground,16):08X}","threshold_plus_27":f"0x{int(threshold,16):08X}",
                        "JL_taken":bool(int(jl)),"this_plus_C8":f"0x{int(c8,16):08X}",
                        "this_plus_C8_first_dword":(re.search(r"C8_first_dword=([0-9a-fA-F]+)",line).group(1)
                            if re.search(r"C8_first_dword=([0-9a-fA-F]+)",line) else None),
                        "gate_10AB29":f"0x{int(gate,16):02X}"})
            activation_returns=[line for line in executed_stderr.splitlines()
                if line.startswith("TRACE smuggler_fun_76070_return ")]
            activation_entries=[line for line in executed_stderr.splitlines()
                if line.startswith("TRACE activation_route_site eip=00076070 ")]
            c8_writes=[line for line in executed_stderr.splitlines()
                if line.startswith("TRACE watched_guest_cell_write cell=8 ")]
            gate_writes=[line for line in executed_stderr.splitlines()
                if line.startswith("TRACE watched_guest_cell_write cell=7 ") and "guest=002e4b29 " in line]
            ralph_flag_writes=[line for line in executed_stderr.splitlines()
                if line.startswith("TRACE watched_guest_cell_write ") and
                   ("guest=0033c346 " in line or "guest=0033c40e " in line)]
            effect_progress_evidence={"schema":"gw-native-plspec-effect-progress-frontier/v1",
                "target_sha256":EXPECTED_TARGET,
                "analysis":{"REA":"6.4.0","Ghidra":"12.1.4",
                    "carrier_sha256":REA_OPTIONS_TRANSITION["carrier_sha256"],
                    "function_evidence_id":"ev_cf9911779047d831e789f19cac6e22c7bb2c8e715ef42069f80fedd80a3a9e43",
                    "authority":"shipped artifact for static LE/carrier; native recompiled replay for dynamic state"},
                "effect":{"array":"BioGame::__effects[0]","guest":"0x00341576","link":"0x00167576",
                    "type_offset":"+0x45","state_offset":"+0x46","threshold_offset":"+0x27",
                    "progress_rule":"FUN_00065870 terrain height is compared signed against [effect+0x27]; JL keeps the descent branch active while ground < threshold. On crossing/equality, original code stores ground to +0x27, clears +0x2D..+0x32, increments +0x46 and calls FUN_00076070 at 0x88017.",
                    "samples":progress_rows,"sample_count":len(progress_rows)},
                "activation":{"call_site":"0x00088017","callee":"FUN_00076070","entry_samples":activation_entries,
                    "post_return_samples":activation_returns,"Ralph_flags_writes":ralph_flag_writes,
                    "natural_activation_proven":bool(activation_returns and ralph_flag_writes),
                    "meaning":"post-return slots are read from 0x0033C2D6 and 0x0033C39E; original stores clear 0x0400 then set bit 0 at flags+0x70"},
                "interface_observers":{"this":"0x0035F8F4","this_plus_C8_guest":"0x0035F9BC",
                    "C8_writes":c8_writes,"observed_C8_values":[r["this_plus_C8"] for r in progress_rows],
                    "event_gate_link":"0x0010AB29","event_gate_guest":"0x002E4B29",
                    "event_gate_writes":gate_writes,
                    "event_gate_samples":[r["gate_10AB29"] for r in progress_rows]},
                "next_frontier":{"eip":f"0x{frontier_eip:08X}","trace":frontier,
                    "exact_LE_call_site":"0x8803A: CALL dword ptr [ESI+0x44]",
                    "fixup_slot":"0x00112228 -> object-1 link 0x00069E20; admitted only after Capstone bytes/fixup validation"},
                "evidence_files":{"runtime":"evidence/native_ifclevel_creature_probe.runtime.log",
                    "stderr":"evidence/native_ifclevel_creature_probe.stderr.log",
                    "frontier":"evidence/native_ifclevel_process_packets_frontier.json"}}
            (ROOT/"evidence"/"native_plspec_effect_progress_probe.json").write_text(
                json.dumps(effect_progress_evidence,indent=2)+"\n",encoding="utf-8")
            print(f"PASS original process_packets executed fixup-backed BioGame callbacks; stopped fail-closed at 0x{frontier_eip:05X}")
            return
        # The gameplay continuation deliberately bypasses the separately
        # covered TITLE -> OPTIONS -> TITLE regression.  Validate this run's
        # own causal evidence here instead of requiring stdout traces emitted
        # only by the normal OPTIONS/text-probe route below.
        stdout_path=replay_stdout_path
        stderr_path=replay_stderr_path
        stdout_path.write_text(executed.stdout,encoding="utf-8")
        stderr_path.write_text(executed.stderr,encoding="utf-8")
        previous_probe_path=ROOT/"evidence"/"native_ifclevel_creature_probe.json"
        previous_pick_attempt=None
        if previous_probe_path.exists():
            try:
                previous_probe=json.loads(previous_probe_path.read_text(encoding="utf-8"))
                previous_pick_attempt=previous_probe.get("selection",{}).get(
                    "direct_viewport_pick_attempt")
                preserved_path=ROOT/"evidence"/"native_ifclevel_creature_probe_pre_single_order.json"
                if not preserved_path.exists():
                    preserved_path.write_bytes(previous_probe_path.read_bytes())
            except (OSError,json.JSONDecodeError):
                previous_pick_attempt=None
        result_line=next((line for line in gameplay_trace.splitlines()
            if line.startswith("result completed_ticks=")),"")
        setup_line=next((line for line in executed.stdout.splitlines()
            if line.startswith("PASS original setup_game continuous entry=00094ac0")),None)
        level_line=next((line for line in executed.stdout.splitlines()
            if line.startswith("PASS original IFCLevel transition, first Update/Draw")),None)
        if native_game_loop_mode:
            native_line=next((line for line in gameplay_trace.splitlines()
                if line.startswith("TRACE native_game_loop_result ok=1 entry=00092860")),None)
            result_line=next((line for line in gameplay_trace.splitlines()
                if line.startswith("result completed_ticks=")),"")
            causal_escape_mode=os.environ.get("GWRECOMP_IFC_TRANSITION_CAUSAL_PROBE")=="escape"
            causal_roundtrip_mode=os.environ.get("GWRECOMP_IFC_TRANSITION_CAUSAL_PROBE")=="roundtrip"
            c8_keyboard_probe_mode=os.environ.get("GWRECOMP_IFCLEVEL_C8_KEY_PROBE")=="1"
            transition_store_lines=[line for line in gameplay_trace.splitlines()
                if line.startswith("TRACE ifc_transition_store ")]
            transition_input_lines=[line for line in executed_stderr.splitlines()
                if line.startswith("TRACE ifc_transition_input ")]
            escape_transition_ok=(len(transition_store_lines)==2 and
                re.search(r"index=0 site=0002244c Turn=481 old=00000000 new=00360034 .*current=0035fe9a pending=00360034",transition_store_lines[0]) is not None and
                re.search(r"index=1 site=0006a438 Turn=482 old=00000000 new=00360034 .*current=00360034 pending=00360034",transition_store_lines[1]) is not None and
                "currentIFC=00360034 pendingIFC=00000000" in result_line)
            return_dispatch=next((line for line in gameplay_trace.splitlines()
                if line.startswith("TRACE ifc_transition_options_to_planetside ") and
                   "current=0035fe9a pending=00000000 frontier=0 MCB_chain_valid=1" in line),None)
            roundtrip_transition_ok=(len(transition_store_lines)>=2 and
                re.search(r"index=0 site=0002244c Turn=481 old=00000000 new=00360034 .*current=0035fe9a pending=00360034",transition_store_lines[0]) is not None and
                re.search(r"index=1 site=0006a438 Turn=482 old=00000000 new=00360034 .*current=00360034 pending=00360034",transition_store_lines[1]) is not None and
                return_dispatch is not None and
                "currentIFC=0035fe9a pendingIFC=00000000" in result_line and
                len(transition_input_lines)==5 and
                all(f"phase={phase}" in line and "pushed=1 events=1" in line for phase,line in zip(
                    ("escape-down","escape-up","options-id4-hover","options-id4-down","options-id4-up"),
                    transition_input_lines)))
            expected_turn=host_bound_turn or 320
            snapshot_load_path=os.environ.get("GWRECOMP_NATIVE_SNAPSHOT_LOAD")
            snapshot_start_turn=0
            if snapshot_load_path:
                loaded_snapshot=re.search(
                    r"TRACE native_snapshot_loaded path=.*? Turn=(\d+) ",
                    gameplay_trace+"\n"+executed_stderr)
                if not loaded_snapshot:
                    raise SystemExit("snapshot-resume replay did not report a successfully loaded turn-boundary snapshot")
                snapshot_start_turn=int(loaded_snapshot.group(1))
                if snapshot_start_turn>=expected_turn:
                    raise SystemExit(f"snapshot resume bound {expected_turn} must be after saved turn {snapshot_start_turn}")
            expected_loop_iterations=expected_turn-snapshot_start_turn
            if causal_roundtrip_mode:
                # This profile intentionally exits game() through the game's
                # own clean loop return after the Escape -> Options -> Resume
                # cycle. Turn is game state, not a reliable frame counter in
                # this route; validate the six original loop-stage counters,
                # the verified transition, and the absence of runtime faults.
                roundtrip_result_ok=(
                    setup_line is not None and level_line is not None and
                    native_line is not None and
                    re.search(r"completed_ticks=\d+ continuation_ok=1 .*currentIFC=0035fe9a pendingIFC=00000000 .*MCB_chain_valid=1 WScreen_backed=1 .*post_loader_frontier=0",result_line) is not None)
                if not roundtrip_result_ok:
                    raise SystemExit(f"roundtrip did not complete a clean native return after Options -> Planetside: {native_line!r}; {result_line!r}")
                counts=re.search(r"body_counts=(\d+)/(\d+)/(\d+)/(\d+)/(\d+)/(\d+) quit_arms=(\d+) host_stop=(\d+) stop_eip=([0-9a-fA-F]{8}) draws=(\d+) draw_gate_calls=(\d+) .*?MCB_chain_valid=1",native_line)
            else:
                if setup_line is None or level_line is None or native_line is None or not re.search(
                        rf"completed_ticks=\d+ continuation_ok=1 .*MCB_chain_valid=1 WScreen_backed=1 post_loader_ticks={expected_loop_iterations} post_loader_frontier=0",result_line):
                    raise SystemExit(f"native game() loop did not complete the requested bounded interval: {native_line!r}; {result_line!r}")
            if not causal_roundtrip_mode and host_bound_turn:
                counts=re.search(rf"Turn={expected_turn} .*?body_counts=(\d+)/(\d+)/(\d+)/(\d+)/(\d+)/(\d+) quit_arms=0 host_stop=1 stop_eip=000928b5 draws=(\d+) draw_gate_calls=(\d+) .*?MCB_chain_valid=1",native_line)
            elif not causal_roundtrip_mode:
                counts=re.search(r"body_counts=(\d+)/(\d+)/(\d+)/(\d+)/(\d+)/(\d+) quit_arms=1 host_stop=0 stop_eip=00000000 draws=(\d+) draw_gate_calls=(\d+) .*?MCB_chain_valid=1",native_line)
            if not counts:
                raise SystemExit(f"native game() loop body-stage counters are missing: {native_line!r}")
            body_counts=tuple(map(int,counts.groups()[:6]))
            body_iterations=body_counts[0]
            if len(set(body_counts))!=1 or (body_iterations<expected_loop_iterations and not causal_roundtrip_mode):
                raise SystemExit(f"native game() loop body sites disagree or stop before bounded Turn {expected_turn}: {native_line!r}")
            if causal_roundtrip_mode:
                quit_arms,host_stop,stop_eip,draw_dispatches,draw_gate_calls=counts.groups()[6:]
                # This profile deliberately bounds the native continuation at
                # 500 host turns; the guest loop exits through its ordinary
                # 0x928B5 loop epilogue, with no guest QuitGame request.
                if int(host_stop)!=1 or stop_eip!="000928b5" or int(quit_arms)!=0:
                    raise SystemExit(f"roundtrip game() did not return through the bounded native loop epilogue: {native_line!r}")
                draw_dispatches,draw_gate_calls=int(draw_dispatches),int(draw_gate_calls)
            else:
                draw_dispatches,draw_gate_calls=map(int,counts.groups()[6:])
            if draw_dispatches!=draw_gate_calls or draw_dispatches!=body_iterations:
                raise SystemExit(f"native draw_game vtable-call count disagrees with the original IFC_Draw observer: {native_line!r}")
            if causal_roundtrip_mode:
                returned_draw=any(line.startswith("pending_loader_draw draw_ok=1 ") and
                    "dispatch=1/00083559/00210170" in line and
                    "current=0035fe9a pending=00000000" in line and
                    "frontier_slot=002ebb6c frontier_target=001fe7d0" in line
                    for line in gameplay_trace.splitlines())
                draw_contract=("draw_gate_current=00360034" in native_line and
                    "vtable=002ebfe0 slot=002ebfec target=001fe5f0" in native_line and
                    returned_draw)
            elif causal_escape_mode:
                draw_contract=("draw_gate_current=00360034" in native_line and
                    "vtable=002ebfe0 slot=002ebfec target=001fe5f0" in native_line)
                if not escape_transition_ok:
                    raise SystemExit(f"Escape profile did not produce exactly the two original Options transition stores: {transition_store_lines!r}; {result_line!r}")
            else:
                if c8_keyboard_probe_mode:
                    # This bounded keyboard probe includes the original Escape
                    # path. Its final frame may therefore dispatch IFCOptions
                    # instead of IFCPlanetside; accept only the known LE-backed
                    # Options Draw vtable/slot/target triple.
                    draw_contract=("draw_gate_current=00360034" in native_line and
                        "vtable=002ebfe0 slot=002ebfec target=001fe5f0" in native_line)
                else:
                    draw_contract=("draw_gate_current=0035fe9a" in native_line and
                        "vtable=002ebb04 slot=002ebb10 target=00210170" in native_line)
            if causal_roundtrip_mode and not roundtrip_transition_ok:
                raise SystemExit(f"roundtrip profile did not prove Escape -> IFCOptions -> original id=4 click -> IFCPlanetside: stores={transition_store_lines!r}; inputs={transition_input_lines!r}; result={result_line!r}")
            if (draw_dispatches<expected_loop_iterations and not causal_roundtrip_mode) or not draw_contract:
                raise SystemExit(f"native game() did not dispatch the expected LE-backed interface Draw thunk through the bounded Turn: {native_line!r}")
            native_evidence={"schema":"gw-native-game-loop-bounded/v1",
                "target_sha256":"2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f",
                "game_function_link":"0x00092710","loop_body_entry_link":"0x00092860",
                "loop_back_link":"0x00092777",
                "exit_check_link":"0x000928B5","turn_increment_link":"0x000928AF",
                "bound":(f"Host stops at original loop head 0x928B5 after Turn {expected_turn}; no guest QuitGame flag is written." if host_bound_turn else
                    "The original INC reaches Turn 320; harness sets QuitGame bit 0 immediately before original TEST at 0x928B5."),
                "native_trace":native_line,"result_line":result_line,
                "frontier":None,"unexpected_writes":0,"MCB_chain_valid":True,
                "guest_turn_final":expected_turn,
                "snapshot_loaded_from_turn":snapshot_start_turn if snapshot_load_path else None,
                "native_loop_iterations_this_process":expected_loop_iterations,
                "turn_to_body_call_difference":body_iterations-expected_loop_iterations,
                "original_frame_body_counts":{"64CB0":body_iterations,"control_game":body_iterations,
                    "process_packets":body_iterations,"draw_game":body_iterations,"ProcessSounds":body_iterations,"Turn_INC":body_iterations,
                    "IFC_Draw":draw_dispatches},
                "draw_gating":{"vtable_draw_call_observed":draw_gate_calls,
                    "interpretation":"IFC_Draw dispatches counted at the original CALL [EDX+0x0c] gate; draw_game runs every turn but its frame pacing/branch may skip interface redraws."},
                "causal_ifc_transition":{"profile":"roundtrip" if causal_roundtrip_mode else "escape" if causal_escape_mode else "standard",
                    "accepted_options_transition":bool(causal_escape_mode and escape_transition_ok),
                    "accepted_roundtrip":bool(causal_roundtrip_mode and roundtrip_transition_ok),
                    "roundtrip_return_store":return_dispatch if causal_roundtrip_mode else None,
                    "input_events":transition_input_lines if causal_roundtrip_mode else [],
                    "stores":transition_store_lines},
                "passed":True}
            if second_spec_pick_mode:
                # SDL and packet watchers are deliberately stderr-only to
                # keep the stdout/native trace compact. Merge both captured
                # channels for evidence extraction; preserve them separately
                # on disk as well.
                trace_lines=gameplay_trace.splitlines()+executed.stderr.splitlines()
                prefixes=("TRACE native_second_spec_SDL ","TRACE native_drop_zone_SDL ",
                    "TRACE drop_zone_original_gate ","TRACE drop_zone_entity_state ",
                    "TRACE plant_sync_original_update ",
                    "TRACE mapdisplay_pick ",
                    "TRACE target_creature_pick_candidate ",
                    "TRACE target_creature_putthing_first_taken_branch ",
                    "TRACE target_creature_projection ",
                    "TRACE plspec_hit_index ","TRACE plspec_hit_boolean ",
                    "TRACE putthing_hover_selected_store ",
                    "TRACE mapdisplay_selected_copy ",
                    "TRACE contextual_packet_emit ",
                    "TRACE PA_SET_SENTINEL_ZONE_handler_enter ",
                    "TRACE PA_SET_SENTINEL_ZONE_handler_return ",
                    "TRACE contextual_action_turn ")
                selected_trace=[line for line in trace_lines
                    if line.startswith(prefixes)]
                contextual_evidence={
                    "schema":"gw-native-ifclevel-contextual-action/v1",
                    "target_sha256":EXPECTED_TARGET,
                    "trace":f"evidence/{replay_log_stem}.trace",
                    "profile":("native game(): select Ralph, then click live BioGame::__effects[23] at logical (192,223); its +0x2d tag determines whether PA_SET_DROP_ZONE is eligible" if
                        drop_zone_probe_mode else
                        "native game(): hover plant 29 during Turn 301, left-down before Update 302, release before Update 303; no PlSpec selection" if
                        os.environ.get("GWRECOMP_IFCLEVEL_PLANT_SYNC_CLICK")=="1" else
                        "native game(): select Ralph and click HUD gadgets 15, 16, 17, and 28" if
                        os.environ.get("GWRECOMP_IFCLEVEL_TOOL_ACTION_PROBE")=="1" else
                        "native game() with SDL selection attempt for PlSpec slot 1 after Turn 301"),
                    "input_contract":({"Ralph_portrait_host":[746,576],
                        "live_effect23_logical_projection":[192,223],"effect23_host_sdl_coordinates":[384,446],
                        "map_thing_gate":"MapDisplay+0x18 -> Thing+0x2D == 5 -> FUN_00066DD0; otherwise positive +0x2D uses FUN_0006DDD0",
                        "SDL_stage_updates":[302,303,304,305,306,307]} if drop_zone_probe_mode else
                        {"logical_plant29_projection":[449,355],
                        "host_sdl_coordinates":[898,710],
                        "context_target":"BioGame::__plants[29] while MapDisplay mask bit 0x0004 remains enabled",
                        "hover_down_up_updates":[301,302,303]} if
                        os.environ.get("GWRECOMP_IFCLEVEL_PLANT_SYNC_CLICK")=="1" else
                        {"logical_second_plspec_projection":[283,283],
                        "host_sdl_coordinates":[566,566],
                        "context_target":"selected PlSpec sprite itself",
                        "selection_then_right_click_turns":[302,307]}),
                    "static_mapdisplay_finding":{"MapDisplay_link":"0x0016CD70",
                        "offset_0e":{"meaning":"16-bit map-space Y coordinate used as a target in packet construction",
                            "selection_filter":False,
                            "evidence":"Canonical LE reads at 0x21D4A, 0x21E61, and 0x21ECA copy this word into action packets; no executed PutThingInBucket selection predicate references +0x0E."},
                        "offset_1f":{"meaning":"type-selection bit mask used by PutThingInBucket",
                            "LE_code":"0x79078..0x79091 computes (1 << Thing.ttype) & word [MapDisplay+0x1f]",
                            "live_prior_filter":"0xFF5B",
                            "plant_type":"TT_PLANT=2 requires bit 0x0004; that bit is clear in 0xFF5B and set in 0xFF5F.",
                            "filter_enable_branch":"0x1F569 writes 0xFF5F when [this+0xC0] is non-null and its byte +0x16 equals 1; the sibling 0x1F574 writes 0xFF5B otherwise."},
                        "type_dispatch":"At 0x79098, the LE computes ttype-2 and dispatches only indices 0..6 (types 2..8). TT_CREATURE=1 underflows the range and leaves through the default branch before the type-specific hitbox helper; 0x97650 is the PlSpec hitbox path, not a TT_CREATURE hitbox."},
                    "native_loop":native_evidence,
                    "observations":selected_trace,
                    "counts":{"SDL_stages":sum(x.startswith(("TRACE native_second_spec_SDL ","TRACE native_drop_zone_SDL ")) for x in selected_trace),
                        "packet_emits":sum(x.startswith("TRACE contextual_packet_emit ") for x in selected_trace),
                        "drop_zone_emit_sites":sum(x.startswith("TRACE drop_zone_original_gate ") and ("eip=00021bac" in x.lower() or "eip=00066e94" in x.lower()) for x in selected_trace),
                        "drop_zone_handler_entries":sum(x.startswith("TRACE drop_zone_original_gate ") and "eip=00076920" in x.lower() for x in selected_trace),
                        "PA_SET_SENTINEL_ZONE_handler_entries":sum(x.startswith("TRACE PA_SET_SENTINEL_ZONE_handler_enter ") for x in selected_trace),
                        "PA_SET_SENTINEL_ZONE_handler_returns":sum(x.startswith("TRACE PA_SET_SENTINEL_ZONE_handler_return ") for x in selected_trace)},
                    "contextual_action_verified":(
                        (drop_zone_probe_mode and
                         any(x.startswith("TRACE drop_zone_original_gate ") and "eip=00066e94" in x.lower() and "Action=09" in x for x in selected_trace) and
                         any(x.startswith("TRACE drop_zone_original_gate ") and "eip=00076920" in x.lower() and "Action=09" in x for x in selected_trace)) or
                        (not drop_zone_probe_mode and
                        any(x.startswith("TRACE contextual_packet_emit ") and "Action=11" in x for x in selected_trace) and
                        any(x.startswith("TRACE PA_SET_SENTINEL_ZONE_handler_enter ") and "Action=11" in x for x in selected_trace))),
                    "profile_completed":(sum(x.startswith(("TRACE native_second_spec_SDL ","TRACE native_drop_zone_SDL ")) for x in selected_trace)==
                        (3 if os.environ.get("GWRECOMP_IFCLEVEL_PLANT_SYNC_CLICK")=="1" else
                         15 if os.environ.get("GWRECOMP_IFCLEVEL_TOOL_ACTION_PROBE")=="1" else 6) and
                        bool(native_evidence.get("passed"))),
                    "passed":(
                        (drop_zone_probe_mode and
                         any(x.startswith("TRACE drop_zone_original_gate ") and "eip=00066e94" in x.lower() and "Action=09" in x for x in selected_trace) and
                         any(x.startswith("TRACE drop_zone_original_gate ") and "eip=00076920" in x.lower() and "Action=09" in x for x in selected_trace)) or
                        (not drop_zone_probe_mode and
                         any(x.startswith("TRACE contextual_packet_emit ") and "Action=11" in x for x in selected_trace) and
                         any(x.startswith("TRACE PA_SET_SENTINEL_ZONE_handler_enter ") and "Action=11" in x for x in selected_trace))),
                    "interpretation":"The bounded native 320-turn run and profile-specific SDL input stages are reported separately. The drop-zone packet is claimed only when the original helper writes Action=0x09 and process_packets enters its original FUN_00076920 handler."}
                (ROOT/"evidence"/"native_ifclevel_contextual_action.json").write_text(
                    json.dumps(contextual_evidence,indent=2)+"\n",encoding="utf-8")
            if expected_turn>=1000:
                snapshots={}
                creature_state_snapshots={}
                snapshot_trace_lines=[line for line in executed.stderr.splitlines()
                    if line.startswith("TRACE native_long_run_snapshot ")]
                for line in snapshot_trace_lines:
                    match=re.search(r"turn=(500|1000|1500|2000|2500|3000|3500|4000|4500|5000) .*?FUN_0005E450_entries=(\d+) creature0=([0-9a-fA-F]+) ttype=([0-9a-fA-F]{2}) field2d=([0-9a-fA-F]{2}) state45=([0-9a-fA-F]{2}) raw64=([0-9a-fA-F]{128})$",line)
                    if not match:
                        raise SystemExit(f"native long-run creature/function snapshot malformed: {line!r}")
                    turn,entries,creature,ttype,field2d,state45,raw64=match.groups()
                    creature_state_snapshots[turn]={"guest_address":f"0x{int(creature,16):08X}",
                        "ttype":int(ttype,16),"field_2d":int(field2d,16),"state_45":int(state45,16),
                        "raw_64_bytes_hex":raw64.lower(),"FUN_0005E450_entries_so_far":int(entries)}
                snapshot_turns=(500,1000,1500,2000,2500,3000,3500,4000,4500,5000) if expected_turn>=5000 else \
                    (500,1000,1500,2000,2500,3000) if expected_turn>=3000 else \
                    (500,1000,1500,2000,2500) if expected_turn>=2500 else (500,1000)
                # A resumed snapshot only produces frame artifacts after its
                # saved turn. Do not demand historical 500/1000 captures from
                # a 1292->1350 continuation; those belong to the baseline run.
                if snapshot_load_path:
                    snapshot_turns=tuple(turn for turn in snapshot_turns
                        if snapshot_start_turn < turn <= expected_turn)
                for turn in snapshot_turns:
                    prefix=ROOT/"evidence"/f"{replay_log_stem}_turn_{turn}"
                    bmp=Path(str(prefix)+".bmp")
                    raw=Path(str(prefix)+"_wscreen.raw")
                    palette=Path(str(prefix)+"_palette6.raw")
                    if not bmp.is_file() or not raw.is_file() or not palette.is_file() or \
                            raw.stat().st_size!=640*480 or palette.stat().st_size!=768:
                        raise SystemExit(f"native long-run frame snapshot missing or malformed at Turn {turn}: {prefix}")
                    snapshots[str(turn)]={"bmp":str(bmp.relative_to(ROOT)),"bmp_sha256":sha(bmp),
                        "guest_wscreen_raw":str(raw.relative_to(ROOT)),"guest_wscreen_sha256":sha(raw),
                        "palette6_raw":str(palette.relative_to(ROOT)),"palette6_sha256":sha(palette),
                        "captured_at_original_loop_head":"0x000928B5 after original INC at 0x928AF"}
                native_evidence["snapshots"]=snapshots
                native_evidence["long_run_state_sampling"]={
                    "method":"bounded host-side copy of WScreen and DAC at the original loop head; no guest globals or flags written",
                    "observed_trace_lines":snapshot_trace_lines,
                    "BioGame_creatures_0_and_FUN_0005E450":creature_state_snapshots,
                    "note":"The native guest code produces the captured bytes; SDL/BMP only converts the captured indexed surface."}
            (ROOT/"evidence"/f"{replay_log_stem}.json").write_text(
                json.dumps(native_evidence,indent=2)+"\n",encoding="utf-8")
            if mode_switch_probe_mode:
                trace_lines=executed.stderr.splitlines()
                input_rows=[line for line in trace_lines
                    if line.startswith("TRACE native_mode_switch_input ")]
                callback_rows=[line for line in trace_lines
                    if line.startswith("TRACE ifc_hud_callback ") and
                    ("expected_id=16 " in line or "expected_id=12 " in line)]
                mode_rows=[line for line in trace_lines
                    if line.startswith("TRACE ifc_mode_dispatch ")]
                mode_return_rows=[line for line in trace_lines
                    if line.startswith("TRACE ifc_mode_dispatch_return ")]
                c8_store_rows=[line for line in trace_lines
                    if line.startswith("TRACE ifc_c8_store ")]
                live_gadget_census=next((line for line in trace_lines
                    if line.startswith("TRACE ifc_live_gadget_census ")),None)
                live_gadget_rows=[line for line in trace_lines
                    if line.startswith("TRACE ifc_live_gadget ")]
                commit_rows=[line for line in trace_lines
                    if line.startswith("TRACE ifc_action_commit ") and "Action=10 " in line]
                handler_rows=[line for line in trace_lines
                    if line.startswith("TRACE ifc_pa_ifc_move_go_handler ")]
                turn_match=re.search(r"Turn=(\d+)",native_line)
                mode_evidence={
                    "schema":"gw-native-ifc-mode-switch-probe/v1",
                    "target_sha256":EXPECTED_TARGET,
                    "authority":"controlled native GeneWars 1.1 replay; SDL events only; no guest global or mode state written by the harness",
                    "replay":{"turn_bound":expected_turn,"native_loop_trace":native_line,
                        "frontier":None,"unexpected_writes":0,"MCB_chain_valid":True,
                        "standard_game_loop_regression_passed":bool(native_evidence.get("passed"))},
                    "input_profile":{"selection":"Ralph portrait ID 0, hover/down/up",
                        "post_selection_plant_target":"BioGame::__plants[29], live logical projection (321,355), host SDL (642,710), hover/down/up",
                        "input_trace":input_rows},
                    "callback_semantics":{"click_dispatch_link":"0x000A8D43 CALL [EBX+0x0E]; only called if the original flag gate permits it",
                        "help_dispatch_link":"0x000A8D95 CALL [EDX+0x22]; help callback, not click activation",
                        "gadget16_and_12_callback_observations":callback_rows,
                        "live_gadget_census_header":live_gadget_census,
                        "live_gadgets_ids_0_25":live_gadget_rows},
                    "post_dispatch_state":{"mode_vcall_observations":mode_rows,
                        "mode_vcall_return_observations":mode_return_rows,
                        "this_C8_original_store_observations":c8_store_rows,
                        "instrumented_C8_store_counts":c8_store_counts,
                        "Action_0x10_commit_observations":commit_rows,
                        "PA_IFC_MOVE_GO_handler_0x76750_entries":handler_rows,
                        "Action_0x10_committed":bool(commit_rows),
                        "handler_0x76750_reached":bool(handler_rows),
                        "Turn_at_bound":int(turn_match.group(1)) if turn_match else None},
                    "passed":bool(native_evidence.get("passed")),
                    "objective_reached":bool(commit_rows and handler_rows),
                    "interpretation":"A clean bounded loop is separate from mode or packet success; the latter is claimed only from original state, packet and handler traces."}
                (ROOT/"evidence"/"native_ifclevel_gadget16_mode_switch.json").write_text(
                    json.dumps(mode_evidence,indent=2)+"\n",encoding="utf-8")
                print(f"evidence: {ROOT/'evidence'/'native_ifclevel_gadget16_mode_switch.json'}")
                bca0_rows=[line for line in trace_lines if line.startswith("TRACE plant_bca0_call ")]
                plant_rows=[line for line in trace_lines if line.startswith("TRACE mapdisplay_census ptr=00336663 ")]
                active_plant_evidence={
                    "schema":"gw-native-active-ralph-plant-click/v1",
                    "target_sha256":EXPECTED_TARGET,
                    "authority":"bounded native game() replay; input through SDL; guest globals not written by the harness",
                    "replay":{"turn_bound":expected_turn,"native_trace":native_line,
                        "frontier":None,"unexpected_writes":0,"MCB_chain_valid":True,
                        "passed":bool(native_evidence.get("passed"))},
                    "input":{"selection":"original Ralph portrait hover/down/up before Turn 304",
                        "plant29_live_projection_logical":[321,355],"sdl_coordinates":[642,710],
                        "events":["hover","left-down","left-up"],"trace":input_rows},
                    "observed":{"c8_store_rows":c8_store_rows,
                        "bca0_callsite_0x2145d_rows":bca0_rows,
                        "plant29_mapdisplay_census":plant_rows,
                        "objective_reached":bool(bca0_rows),
                        "interpretation":"A BCA0 row means the original Update path passed its preceding guards and reached CALL 0x6BCA0; an empty list means the SDL click did not reach that branch."},
                    "static_crosscheck":{"rea_document":"target-1523022fb1fe.exe",
                        "carrier_sha256":"1523022fb1febcfb939b2ed04145ee6e7dcd8b99113d932d21d33301c0052a97",
                        "rea_read_bytes_0x2210e":"ev_e79cf145cd405fc2c396973fbbe3e97ff506d18f17e9112d7f5cea328d22efc5",
                        "rea_read_bytes_0x21380":"ev_ffffef01bd8e815cc082f34dd9c2d91e42071260ff0ff65bb649c3e5e8146823",
                        "switch_instruction_count":28,"instrumented_callsite_matches":plant_call_matches},
                    "regression":{"native_game_loop_assertions":bool(native_evidence.get("passed")),
                        "frontier":None,"unexpected_writes":0,"MCB_chain_valid":True}}
                (ROOT/"evidence"/"native_ifclevel_active_ralph_plant_interaction.json").write_text(
                    json.dumps(active_plant_evidence,indent=2)+"\n",encoding="utf-8")
                print(f"evidence: {ROOT/'evidence'/'native_ifclevel_active_ralph_plant_interaction.json'}")
            if hud_gadget_sweep_mode:
                sweep_lines=[line for line in executed.stderr.splitlines()
                    if line.startswith("TRACE native_hud_gadget_sweep ")]
                sweep_re=re.compile(r"TRACE native_hud_gadget_sweep completed_turn=(\d+) upcoming_turn=(\d+) stage=(\d+) gadget_id=(\d+) phase=(\d+) registered=(\d+) guest=([0-9a-fA-F]+) flags=([0-9a-fA-F]+) rect=(-?\d+),(-?\d+),(-?\d+),(-?\d+) kind=([^ ]+) pushed=(\d+) events=(\d+) cursor=(-?\d+),(-?\d+) selectedPlSpec=([0-9a-fA-F]+) map37=([0-9a-fA-F]+) map18=([0-9a-fA-F]+) map1f=([0-9a-fA-F]+) Action=([0-9a-fA-F]+) C8=([0-9a-fA-F]+) mode526=([0-9a-fA-F]+) mode52f=([0-9a-fA-F]+) icalls=(.*)")
                sweep_rows=[]
                for line in sweep_lines:
                    m=sweep_re.fullmatch(line)
                    if not m: raise SystemExit(f"HUD gadget sweep trace malformed: {line!r}")
                    v=m.groups()
                    sweep_rows.append({"completed_turn":int(v[0]),"upcoming_turn":int(v[1]),"stage":int(v[2]),
                        "gadget_id":int(v[3]),"phase":["hover","left_down","left_up"][int(v[4])],
                        "registered":bool(int(v[5])),"guest_address":f"0x{int(v[6],16):08X}","flags":f"0x{int(v[7],16):08X}",
                        "rect":[int(v[8]),int(v[9]),int(v[10]),int(v[11])],"event_kind":v[12],"event_pushed":bool(int(v[13])),
                        "events_polled":int(v[14]),"host_cursor":[int(v[15]),int(v[16])],
                        "selectedPlSpec":f"0x{int(v[17],16):08X}","selectedThing":f"0x{int(v[18],16):08X}",
                        "MapDisplay_thing":f"0x{int(v[19],16):08X}","MapDisplay_mask_1f":f"0x{int(v[20],16):04X}",
                        "packet_Action":f"0x{int(v[21],16):02X}","this_C8":f"0x{int(v[22],16):08X}",
                        "this_526":f"0x{int(v[23],16):04X}","this_52F":f"0x{int(v[24],16):02X}",
                        "recent_indirect_calls":v[25].split(",") if v[25] else []})
                by_id={str(i):[r for r in sweep_rows if r["gadget_id"]==i] for i in range(10,26)}
                nonstandard_actions=sorted({r["packet_Action"] for r in sweep_rows
                    if r["packet_Action"] not in ("0x00","0x03","0x04")})
                sweep_evidence={"schema":"gw-native-ifclevel-hud-gadget-sweep/v1","target_sha256":EXPECTED_TARGET,
                    "authority":"controlled native replay; host SDL events sampled at the original game() frame boundary",
                    "replay":{"turn_bound":expected_turn,"frontier":None,"unexpected_writes":0,
                        "MCB_chain_valid":True,"native_game_loop_passed":bool(native_evidence.get("passed"))},
                    "gadget_table":{"root_guest":"0x00379490","record_stride":"0x28",
                        "lookup":"walk original linked/sequential MyGadget records; no coordinates are invented for missing IDs"},
                    "rows":sweep_rows,"rows_by_gadget_id":by_id,
                    "summary":{"event_rows":len(sweep_rows),"registered_ids":[i for i in range(10,26) if by_id[str(i)] and by_id[str(i)][0]["registered"]],
                        "missing_ids":[i for i in range(10,26) if not by_id[str(i)] or not by_id[str(i)][0]["registered"]],
                        "non_move_non_abort_actions_observed":nonstandard_actions,
                        "profile_completed":len(sweep_rows)==48 and bool(native_evidence.get("passed")),
                        "passed":len(sweep_rows)==48 and bool(native_evidence.get("passed"))},
                    "logs":{"stdout":f"evidence/{replay_log_stem}.stdout.log","stderr":f"evidence/{replay_log_stem}.stderr.log",
                        "trace":f"evidence/{replay_log_stem}.trace"},
                    "limitation":"A queued event is not evidence of an activated original handler. Guest state and original indirect-call targets are reported as captured; Action success is claimed only if its byte is observed."}
                (ROOT/"evidence"/"native_ifclevel_hud_gadget_sweep.json").write_text(
                    json.dumps(sweep_evidence,indent=2)+"\n",encoding="utf-8")
                if not sweep_evidence["summary"]["passed"]:
                    raise SystemExit(f"HUD gadget sweep incomplete: {len(sweep_rows)}/48 input records; see {ROOT/'evidence'/'native_ifclevel_hud_gadget_sweep.json'}")
                print(f"PASS native HUD gadget sweep: {len(sweep_rows)} event stages across IDs 10..25")
                print(f"evidence: {ROOT/'evidence'/'native_ifclevel_hud_gadget_sweep.json'}")
            print(f"PASS native game() loop: {expected_turn} original frame iterations, {native_evidence['bound']}")
            print(f"evidence: {ROOT/'evidence'/f'{replay_log_stem}.json'}")
            raise SystemExit(0)
        tick_lines=[line for line in gameplay_trace.splitlines()
            if line.startswith("post_loader_tick_stats tick=")]
        # Full draw_game is the canonical frame path now; its same-tick row
        # records the virtual IFC Draw call and the original 0x83A0C palette
        # tail. There is no separate harness-only palette tick record.
        palette_tick_lines=[line for line in gameplay_trace.splitlines()
            if line.startswith("post_loader_draw_game_tick tick=")]
        input_lines=[line for line in gameplay_trace.splitlines()
            if line.startswith("post_loader_tick=") and " input=" in line]
        if setup_line is None or level_line is None:
            raise SystemExit("gameplay continuation did not prove continuous setup_game and IFCLevel Update/Draw")
        if not re.search(r"completed_ticks=\d+ continuation_ok=1 .*pendingIFC=00000000 .*MCB_chain_valid=1 WScreen_backed=1 post_loader_ticks=320 post_loader_frontier=0 .*post_loader_input_misses=0 creature_click_stage=0",result_line):
            raise SystemExit(f"single-order gameplay continuation did not reach a clean bounded state: {result_line!r}")
        if len(tick_lines)!=320 or any("draw_ok=1" not in line for line in tick_lines):
            raise SystemExit(f"expected 320 successful original IFCLevel Draw ticks, got {len(tick_lines)}")
        if len(palette_tick_lines)!=320 or any("ok=1" not in line or
                "draw_dispatch=1/00083561/00210170" not in line or
                "palette_in_original_control_flow=1" not in line or
                not re.search(r"DAC_component_writes=[1-9]\d*",line)
                for line in palette_tick_lines):
            raise SystemExit(f"expected full original draw_game, IFC dispatch and palette tail for all 320 ticks, got {len(palette_tick_lines)}")
        if not any("last_callback=0020f830" in line for line in tick_lines):
            raise SystemExit("no tick recorded the admitted live MyGadget callback 0x0020F830")
        dac_counts=[int(re.search(r"DAC_nonzero_components=(\d+)",line).group(1))
                    for line in tick_lines]
        effect_progress=[]
        progress_re=re.compile(r"TRACE smuggler_ground_probe eip=([0-9a-fA-F]+) phase_tick=(\d+) Turn=(\d+) caller=([0-9a-fA-F]+) object=([0-9a-fA-F]+) type=([0-9a-fA-F]+) state=([0-9a-fA-F]+).*?ground=([0-9a-fA-F]+) object_27=([0-9a-fA-F]+) jl_taken=(\d+).*?C8=([0-9a-fA-F]+).*?gate_10AB29=([0-9a-fA-F]+)")
        for line in executed_stderr.splitlines():
            m=progress_re.search(line)
            if m:
                eip,tick,turn,caller,obj,etype,state,ground,compared,jl,c8,gate=m.groups()
                effect_progress.append({"eip":f"0x{int(eip,16):08X}","phase_tick":int(tick),
                    "Turn":int(turn),"caller":f"0x{int(caller,16):08X}","effect":f"0x{int(obj,16):08X}",
                    "Effect_type":f"0x{int(etype,16):02X}","state":f"0x{int(state,16):02X}",
                    "ground":f"0x{int(ground,16):08X}","object_plus_27":f"0x{int(compared,16):08X}",
                    "signed_JL_taken":bool(int(jl)),"this_plus_C8":f"0x{int(c8,16):08X}",
                    "this_plus_C8_first_dword":(re.search(r"C8_first_dword=([0-9a-fA-F]+)",line).group(1)
                        if re.search(r"C8_first_dword=([0-9a-fA-F]+)",line) else None),
                    "event_gate_10AB29":f"0x{int(gate,16):02X}"})
        activation_rows=[]
        activation_re=re.compile(r"TRACE smuggler_fun_76070_return tick=(\d+) caller=([0-9a-fA-F]+) effect=([0-9a-fA-F]+) effect45=([0-9a-fA-F]+) effect46=([0-9a-fA-F]+) effect4a=([0-9a-fA-F]+) player_slot0_flags70=([0-9a-fA-F]+) slot0_state46=([0-9a-fA-F]+) slot0_power4c=([0-9a-fA-F]+) player_slot1_flags70=([0-9a-fA-F]+) slot1_state46=([0-9a-fA-F]+) slot1_power4c=([0-9a-fA-F]+)")
        for line in executed_stderr.splitlines():
            m=activation_re.search(line)
            if m:
                vals=m.groups()
                activation_rows.append({"tick":int(vals[0]),"caller":f"0x{int(vals[1],16):08X}",
                    "effect":f"0x{int(vals[2],16):08X}","effect_type":f"0x{int(vals[3],16):02X}",
                    "effect_state":f"0x{int(vals[4],16):02X}","effect_counter_4a":f"0x{int(vals[5],16):04X}",
                    "Ralph_slot0_flags70":f"0x{int(vals[6],16):04X}","Ralph_slot0_state46":f"0x{int(vals[7],16):02X}",
                    "Ralph_slot0_power4c":f"0x{int(vals[8],16):02X}","Ralph_slot1_flags70":f"0x{int(vals[9],16):04X}",
                    "Ralph_slot1_state46":f"0x{int(vals[10],16):02X}","Ralph_slot1_power4c":f"0x{int(vals[11],16):02X}"})
        smuggler_calls=[row for row in effect_progress if row["eip"]=="0x00087FC0" and row["effect"]=="0x00341576"]
        landing_calls=[row for row in effect_progress if row["eip"]=="0x00088017" and row["effect"]=="0x00341576"]
        if len(smuggler_calls)<150:
            raise SystemExit(f"expected at least 150 original EF_SMUGGLER terrain-threshold samples, got {len(smuggler_calls)}")
        if not landing_calls or not activation_rows:
            raise SystemExit(f"original EF_SMUGGLER did not reach 0x88017 -> FUN_00076070 within the bounded continuation; samples={len(smuggler_calls)} landing={landing_calls!r} returns={activation_rows!r}")
        if any((b and a["phase_tick"]+1==b["phase_tick"] and
                int(a["object_plus_27"],16)-int(b["object_plus_27"],16)!=0x88)
               for a,b in zip(smuggler_calls,smuggler_calls[1:]) if a["signed_JL_taken"] and b["signed_JL_taken"]):
            raise SystemExit("EF_SMUGGLER +0x27 did not follow the observed original 0x88-per-tick descent before landing")
        ralph_active=any((int(row["Ralph_slot0_flags70"],16)&1) or
                         (int(row["Ralph_slot1_flags70"],16)&1) for row in activation_rows)
        if not ralph_active:
            raise SystemExit(f"FUN_00076070 returned after the original 0x88017 call but neither captured Ralph PlSpec has flags bit 0 set: {activation_rows!r}")
        static_effect_target={"site_link":"0x00058C90","instruction":"CALL dword ptr [EDX+0x90]",
            "effect_vtable_slot_link":"0x00112274","canonical_fixup":{"source_type":"0x07","target_object":1,
                "target_link":"0x000959E0","target_guest":"0x002809E0"},
            "target_bytes":"sha256:b502d7117ac55d02a372f78306c6c123528454c77424da15f5e6cc4f7ef981b4/18",
            "meaning":"Original effect-type indexed lookup predicate; distinct from TT_CREATURE slot 0x111D94 -> 0x6A280"}
        effect_probe_evidence={"schema":"gw-native-plspec-effect-landing-probe/v1","target_sha256":EXPECTED_TARGET,
            "rea":{"provider":"REA 6.4.0 / Ghidra 12.1.4","carrier_sha256":REA_OPTIONS_TRANSITION["carrier_sha256"],
                "fun_00083bf0_evidence_id":"ev_982003c006764bdbfeccc67196e9226102011b86840a37bdff28767bac6782e6"},
            "replay":{"mode":"native recompilation, full original process_packets/update/draw continuation",
                "draw_ticks":len(tick_lines),"trace_result":result_line,"runtime_frontier":None},
            "EF_SMUGGLER":{"map_array":"BioGame::__effects[0]","guest":"0x00341576","link":"0x00167576",
                "Thing_ttype_offset":"+0x06","Effect_type_offset":"+0x45","state_offset":"+0x46",
                "threshold_comparison":"FUN_00087FC0: ground from FUN_00065870 compared signed against [effect+0x27]; JL branches to 0x88042 while ground < +0x27; otherwise snaps +0x27 to ground, zeros +0x2D/+0x2F/+0x31, increments +0x46 and calls FUN_00076070 at 0x88017",
                "samples":smuggler_calls,"sample_count":len(smuggler_calls),"landing_branch_samples":landing_calls},
            "activation_after_original_call":activation_rows,"Ralph_flags_bit0_active":ralph_active,
            "shared_effect_vtable_call":static_effect_target,
            "event_gate_10AB29":"sampled at the threshold comparison; values retained per sample; no harness write",
            "this_plus_C8":"sampled at the threshold comparison; values retained per sample; no harness write",
            "interpretation":"Only the original LE control flow and the live state after its call are counted. SDL input and the harness do not set PlSpec flags or player globals."}
        (ROOT/"evidence"/"native_plspec_effect_progress_probe.json").write_text(
            json.dumps(effect_probe_evidence,indent=2)+"\n",encoding="utf-8")
        planet18_down=next((line for line in input_lines if "input=SDL_mouse_down_planet_gadget18_host_188_126" in line),"")
        planet18_up=next((line for line in input_lines if "input=SDL_mouse_up_planet_gadget18_host_188_126" in line),"")
        slot0_down=next((line for line in input_lines if "input=SDL_mouse_down_slot_gadget0_host_73_389" in line),"")
        slot0_up=next((line for line in input_lines if "input=SDL_mouse_up_slot_gadget0_host_73_389" in line),"")
        activation7_down=next((line for line in input_lines if "input=SDL_mouse_down_activation_gadget7_host_23_819" in line),"")
        activation7_up=next((line for line in input_lines if "input=SDL_mouse_up_activation_gadget7_host_23_819" in line),"")
        if not all(("events=1" in line for line in (planet18_down,planet18_up,slot0_down,slot0_up,activation7_down,activation7_up))) or \
           "selected_gadget_id=18" not in planet18_up or "selected_gadget_id=0" not in slot0_up or \
           "selected_gadget_id=7" not in activation7_down:
            raise SystemExit("the original hit-test did not confirm the live MyGadget sequence id=0 then id=7")
        creature_motion=next((line for line in input_lines if "input=SDL_mouse_motion_creature_0032cf86_" in line),"")
        creature_left_down=next((line for line in input_lines if "input=SDL_mouse_left_down_live_TT_CREATURE" in line),"")
        creature_left_up=next((line for line in input_lines if "input=SDL_mouse_left_up_live_TT_CREATURE" in line),"")
        creature_right_down=next((line for line in input_lines if "input=SDL_mouse_right_down_near_selected_TT_CREATURE" in line),"")
        creature_right_up=next((line for line in input_lines if "input=SDL_mouse_right_up_near_selected_TT_CREATURE" in line),"")
        movement_replay=os.environ.get("GWRECOMP_IFCLEVEL_CONTINUE")=="1"
        if hover_pick_replay and not movement_replay:
            raise SystemExit("hover-pick probe requires the authenticated bounded movement continuation")
        if movement_replay:
            if any("events=1" in line for line in (creature_motion,creature_left_down,creature_left_up,
                                                       creature_right_down,creature_right_up)):
                raise SystemExit("the clean one-order movement replay unexpectedly injected a direct-picking click")
        elif not all("events=1" in line for line in (creature_motion,creature_left_down,creature_left_up,
                                                       creature_right_down,creature_right_up)):
            raise SystemExit("the separate picker run did not reach and click the live TT_CREATURE through SDL")
        hover_evidence=None
        if hover_pick_replay:
            hover_inputs=[line for line in gameplay_trace.splitlines()
                if line.startswith("TRACE hitbox_capture_input ")]
            hover_branches=[line for line in executed_stderr.splitlines()
                if line.startswith("TRACE putthing_hover_branch ")]
            hover_stores=[line for line in executed_stderr.splitlines()
                if line.startswith("TRACE putthing_hover_selected_store ")]
            hover_copies=[line for line in executed_stderr.splitlines()
                if line.startswith("TRACE mapdisplay_selected_copy tick=265 ")]
            hitbox_rows=[line for line in executed_stderr.splitlines()
                if line.startswith("TRACE plspec_hit_sprite tick=265 ")]
            compare_rows=[line for line in executed_stderr.splitlines()
                if line.startswith("TRACE plspec_hit_compare tick=265 ")]
            hit_indexes=[line for line in executed_stderr.splitlines()
                if line.startswith("TRACE plspec_hit_index tick=265 ")]
            hit_booleans=[line for line in executed_stderr.splitlines()
                if line.startswith("TRACE plspec_hit_boolean tick=265 ")]
            unreachable=[line for line in gameplay_trace.splitlines()
                if line.startswith("TRACE exact_hitbox_unreachable ")]
            if len(hover_inputs)!=1 or "tick=265" not in hover_inputs[0] or \
                    "logical_projection=212,250" not in hover_inputs[0] or "events=1" not in hover_inputs[0]:
                raise SystemExit(f"tick-265 hitbox capture input was not a single bounded SDL motion: {hover_inputs!r}")
            if {re.search(r"candidate=([0-9a-fA-F]{8})",line).group(1).lower()
                    for line in hitbox_rows if re.search(r"candidate=([0-9a-fA-F]{8})",line)} != \
                    {"0033c2d6","0033c39e"}:
                raise SystemExit("tick-265 original hit-test did not capture both Ralph frame records")
            ralph_accept=next((line for line in compare_rows if "candidate=0033c2d6" in line and
                               "eip=000976c7" in line),None)
            ralph_sprite=next((line for line in hitbox_rows if "candidate=0033c2d6" in line),None)
            if ralph_accept is None or "taken=1" not in ralph_accept or \
                    "cursor_x=340" not in ralph_accept or "cursor_y=250" not in ralph_accept or \
                    ralph_sprite is None or "frame_bytes=0239ace0/fff8/ffe1" not in ralph_sprite or \
                    "frame_xy=-8,-31" not in ralph_sprite or "origin_regs_edx_ebx=345,250" not in ralph_sprite or \
                    "rect=337,219,352,253" not in ralph_sprite:
                raise SystemExit(f"the original signed frame box did not accept the hover over Ralph: {ralph_accept!r}")
            index_candidates={re.search(r"candidate=([0-9a-fA-F]{8})",line).group(1).lower()
                for line in hit_indexes if re.search(r"candidate=([0-9a-fA-F]{8})",line)}
            bool_candidates={re.search(r"candidate=([0-9a-fA-F]{8})",line).group(1).lower()
                for line in hit_booleans if re.search(r"candidate=([0-9a-fA-F]{8})",line)}
            index_by_candidate={re.search(r"candidate=([0-9a-fA-F]{8})",line).group(1).lower():line
                for line in hit_indexes if re.search(r"candidate=([0-9a-fA-F]{8})",line)}
            bool_by_candidate={re.search(r"candidate=([0-9a-fA-F]{8})",line).group(1).lower():line
                for line in hit_booleans if re.search(r"candidate=([0-9a-fA-F]{8})",line)}
            if index_candidates!={"0033c2d6","0033c39e"} or bool_candidates!=index_candidates or \
                    "result_index=0" not in index_by_candidate.get("0033c2d6","") or \
                    "index=0" not in bool_by_candidate.get("0033c2d6","") or \
                    "hit=1" not in bool_by_candidate.get("0033c2d6","") or \
                    "result_index=-1" not in index_by_candidate.get("0033c39e","") or \
                    "hit=0" not in bool_by_candidate.get("0033c39e",""):
                raise SystemExit("original 0x69E50/0x97650 return index and 0x8A500 hit result did not select only Ralph")
            if unreachable:
                raise SystemExit("the corrected original hitbox was still classified as unreachable")
            if not hover_stores or not any("candidate=0033c2d6" in line for line in hover_stores):
                raise SystemExit("original PutThingInBucket did not store Ralph in MapDisplay+0x37")
            if not hover_branches:
                raise SystemExit("the generated native closure did not capture PutThingInBucket branch registers for either Ralph slot")
            branch_candidates={re.search(r"candidate=([0-9a-fA-F]{8})",line).group(1).lower()
                for line in hover_branches if re.search(r"candidate=([0-9a-fA-F]{8})",line)}
            if branch_candidates!={"0033c2d6","0033c39e"}:
                raise SystemExit(f"hover branch capture did not include both live PlSpec candidates: {branch_candidates}")
            hover_map_rows=[line for line in executed_stderr.splitlines()
                if line.startswith("TRACE mapdisplay_pick tick=") and
                   (m:=re.search(r"tick=(\d+) ",line)) and 265<=int(m.group(1))<=314]
            if len(hover_map_rows)!=50:
                raise SystemExit(f"hover replay did not preserve a picker result row for every tick 265..314: {len(hover_map_rows)}")
            tick265_map=next((line for line in hover_map_rows if "tick=265 " in line),"")
            if not any("eax_source=0033c2d6" in line and "map37=0033c2d6" in line and
                       "map18_after= 0033c2d6" in line for line in hover_copies) or \
                    "map18=0033c2d6" not in tick265_map:
                raise SystemExit(f"hover did not flow through selectedThing (+0x37) into MapDisplay::thing (+0x18): copies={hover_copies!r} final={tick265_map!r}")
            hover_evidence={"input_ticks":[265],"targets":{"0033C2D6":{"projection":[212,250]},
                "0033C39E":{"projection":[259,279]}},"input_events":"one SDL motion only; no click or packet injection",
                "branch_observation_count":len(hover_branches),"branch_candidates":sorted(branch_candidates),
                "selectedThing_original_store_count":len(hover_stores),"store_rows":hover_stores,
                "selectedThing_to_thing_copy_rows":hover_copies,
                "runtime_branch_rows":hover_branches,"tick265_hitboxes":hitbox_rows,
                "tick265_original_comparisons":compare_rows,"tick265_hit_indexes":hit_indexes,
                "tick265_hit_booleans":hit_booleans,"unreachable_boxes":unreachable,
                "per_tick_map_results":hover_map_rows,
                "movement_window_204_254":"unchanged; hover motion begins at tick 265",
                "interpretation":"InitMyAnimBank 0x97407/0x97412 uses original SAR on signed resource words -16/-62. The prior lifter promoted uint16 LO16 before sign extension, producing 0x7FF8/0x7FE1; corrected signed-width emission stores -8/-31. The live tick-265 ANB frame record contains FFF8/FFE1 and 0x97650 reads them with MOVSX; its actual call origin is (345,250), yielding box (337,219)..(352,253). The single SDL hover at (340,250) returns index 0, 0x8A500 reports hit, and original PutThingInBucket stores Ralph at MapDisplay+0x37; DrawMapSprites copies it to +0x18. No click or packet injection is used."}
        before_activation=next((line for line in gameplay_trace.splitlines()
            if line.startswith("post_loader_tick=21 ")),"")
        after_activation=next((line for line in gameplay_trace.splitlines()
            if line.startswith("post_loader_tick=23 ")),"")
        before_flags=re.search(r"control_c7=([0-9a-fA-F]{2})",before_activation)
        after_flags=re.search(r"control_c7=([0-9a-fA-F]{2})",after_activation)
        after_gate=re.search(r"ui_gate_2f1660=([0-9a-fA-F]{2})",after_activation)
        state_match=re.search(r"control_state=([0-9a-fA-F]{8})/([0-9a-fA-F]{2})",after_activation)
        if not before_flags or not after_flags or not after_gate or not state_match:
            raise SystemExit("the original id=7 input did not preserve its runtime receiver state for diagnosis")
        if (int(after_flags.group(1),16)&0x02)!=0 or \
           int(state_match.group(1),16)!=0x0035F9CC or int(state_match.group(2),16)!=0x03 or \
           (int(after_gate.group(1),16)&0x02)!=0:
            raise SystemExit("the original id=7 path no longer observes the initialized this+0xD8 state object")
        activation_stats=next((line for line in gameplay_trace.splitlines()
            if line.startswith("post_loader_tick_stats tick=22 ")),"")
        terrain_stats=next((line for line in gameplay_trace.splitlines()
            if line.startswith("post_loader_tick_stats tick=27 ")),"")
        activation_changed=re.search(r"WScreen_changed=(\d+)",activation_stats)
        terrain_changed=re.search(r"WScreen_changed=(\d+)",terrain_stats)
        if not activation_changed or int(activation_changed.group(1))==0 or \
           not terrain_changed or int(terrain_changed.group(1))==0:
            raise SystemExit("the original activation/terrain Update and Draw produced no verifiable WScreen change")
        member_line=next((line for line in gameplay_trace.splitlines()
            if line.startswith("post_loader_member_state tick=23 ")),"")
        if "this_adjust=[ifc-4]=000005a6" not in member_line or \
           "method_this=0035f8f4" not in member_line or \
           "c8_guest=0035f9bc" not in member_line or \
           "c8=0035f9cc->0035f9cc" not in member_line or \
           "c8_byte5=03" not in member_line:
            raise SystemExit("the secondary-interface adjustment or embedded C8 state pointer changed unexpectedly")
        null_ds14_events=[line for line in executed_stderr.splitlines()
            if line.startswith("TRACE guest-null-read ")]
        if null_ds14_events:
            raise SystemExit(f"surface Update dereferenced DS:0..FF unexpectedly: {null_ds14_events[0]}")
        artifact_match=re.search(r"\braw=(\S+)\s+palette=(\S+)\s+bmp=(\S+)",result_line)
        if not artifact_match:
            raise SystemExit(f"native result did not declare its framebuffer/DAC/SDL outputs: {result_line!r}")
        raw_rel,palette_rel,bmp_rel=artifact_match.groups()
        raw_path=ROOT/raw_rel
        palette_path=ROOT/palette_rel
        bmp_path=ROOT/bmp_rel
        if any(not path.is_file() for path in (raw_path,palette_path,bmp_path)) or \
           raw_path.stat().st_size!=640*480 or palette_path.stat().st_size!=768:
            raise SystemExit("gameplay continuation framebuffer, DAC, or SDL capture is missing/incomplete at the paths declared by the native result")
        raw_bytes=raw_path.read_bytes()
        palette_bytes=palette_path.read_bytes()
        if any(component>63 for component in palette_bytes):
            raise SystemExit("native VGA DAC capture contains a component outside the original 6-bit range")
        sys.path.insert(0,str(ROOT/"tests"))
        from test_authentic_titlescreen import verify_capture
        verify_capture(bmp_path,raw_bytes,palette_bytes)
        packet_call_lines=[line for line in executed_stderr.splitlines()
            if line.startswith("TRACE ICALL_CALL site=")]
        effect_call=next((line for line in packet_call_lines
            if "site=00088146 target=002552E0 " in line),None)
        packet_sites={int(re.search(r"site=([0-9A-Fa-f]{8})",line).group(1),16)
            for line in packet_call_lines}
        if effect_call is None:
            raise SystemExit("the full game-loop replay did not execute the original 0x88146 BioGame effect callback")
        if not any("site=00047DC2 target=00255240 " in line for line in packet_call_lines):
            raise SystemExit("the original process_packets entity callback at 0x47DC2 was not observed")
        map_pick_candidates=[line for line in executed_stderr.splitlines()
            if line.startswith("TRACE mapdisplay_candidate ")]
        map_pick_projections=[line for line in executed_stderr.splitlines()
            if line.startswith("TRACE mapdisplay_projection ")]
        map_pick_ticks=[line for line in executed_stderr.splitlines()
            if line.startswith("TRACE mapdisplay_pick tick=")]
        if not map_pick_candidates or not any("ptr=00341cbd" in line for line in map_pick_candidates):
            raise SystemExit("the live map picker did not capture the expected type-5 entity candidate")
        candidate_filter=next((line for line in map_pick_candidates if "ptr=00341cbd" in line),"")
        if ("type=5" not in candidate_filter or "f45=06" not in candidate_filter or "f46=00" not in candidate_filter or
                "f4c=00" not in candidate_filter):
            raise SystemExit(f"live TT_EFFECT/subtype/state fields changed unexpectedly: {candidate_filter}")
        effect_field_rows=[line for line in executed_stderr.splitlines()
            if line.startswith("TRACE watched_effect_fields ")]
        expected_effect_samples=320 if movement_replay else 280
        if len(effect_field_rows)!=expected_effect_samples:
            raise SystemExit(f"expected {expected_effect_samples} read-only samples of the live Effect fields, got {len(effect_field_rows)}")
        effect_samples=[]
        for expected_tick,line in enumerate(effect_field_rows):
            match=re.search(r"tick=(\d+) ptr=([0-9a-fA-F]{8}) thing_type=([0-9a-fA-F]{2}) "
                r"effect_type=([0-9a-fA-F]{2}) effect_state=([0-9a-fA-F]{2}) x=(-?\d+) y=(-?\d+) "
                r"pix_count=([0-9a-fA-F]{4}) power=([0-9a-fA-F]{2}) tflags=([0-9a-fA-F]{2}) "
                r"vptr=([0-9a-fA-F]{8})",line)
            if not match:
                raise SystemExit(f"malformed Effect field observation: {line}")
            tick,ptr,thing_type,effect_type,effect_state,x,y,pix_count,power,tflags,vptr=match.groups()
            sample={"tick":int(tick),"guest":f"0x{ptr.upper()}","thing_type":int(thing_type,16),
                "effect_type":int(effect_type,16),"effect_state":int(effect_state,16),"x":int(x),"y":int(y),
                "pix_count":int(pix_count,16),"power":int(power,16),"tflags":int(tflags,16),
                "vtable_guest":f"0x{vptr.upper()}"}
            if sample["tick"]!=expected_tick or sample["guest"]!="0x00341CBD":
                raise SystemExit(f"live Effect field sample order/address changed: {line}")
            effect_samples.append(sample)
        active_effect_samples=[sample for sample in effect_samples if sample["thing_type"]==5]
        active_effect_samples_first40=[sample for sample in active_effect_samples if sample["tick"]<40]
        if len(active_effect_samples_first40)!=18 or active_effect_samples_first40[0]["tick"]!=22 or \
           any(sample["effect_type"]!=6 for sample in active_effect_samples_first40):
            raise SystemExit("the observed candidate did not become TT_EFFECT/EF_TURBO at the expected tick-22 boundary")
        if any(sample["effect_state"]!=active_effect_samples_first40[0]["effect_state"] or
               sample["power"]!=active_effect_samples_first40[0]["power"] for sample in active_effect_samples_first40):
            raise SystemExit("the candidate Effect::state/power changed during the original first 40 ticks")
        if len({(sample["x"],sample["y"]) for sample in active_effect_samples_first40})<2:
            raise SystemExit("the active EF_TURBO did not show the expected tick-by-tick coordinate evolution")
        pick_33=next((line for line in map_pick_ticks if "tick=33 " in line),"")
        if movement_replay and "cursor=639,479" in pick_33:
            raise SystemExit("clean movement replay unexpectedly inherited the separate picker camera-pan input")
        if not movement_replay and "cursor=639,479" not in pick_33:
            raise SystemExit(f"bottom-right edge input was not held during camera scrolling: {pick_33}")
        creature_pick_rows=[line for line in map_pick_ticks if "map37=0032cf86" in line or "map18=0032cf86" in line]
        packet_action_rows=[line for line in gameplay_trace.splitlines()
            if line.startswith("TRACE original_packet ") and re.search(r"action=(?!00\b)[0-9a-fA-F]{2}",line)]
        pa_move_handler_rows=[line for line in executed_stderr.splitlines()
            if line.startswith("TRACE PA_MOVE_TO_handler ")]
        pa_move_handler_tick204=next((line for line in pa_move_handler_rows
            if re.search(r"\btick=204\b",line) and "action=03" in line and
               "selectedPlSpec=0033c2d6" in line),None)
        if pa_move_handler_tick204 is None:
            raise SystemExit("the tick-204 PA_MOVE_TO packet was cleared but the original FUN_00076570 entry with action=03 and selected Ralph was not dynamically observed")
        pa_move_handler_return=next((line for line in executed_stderr.splitlines()
            if line.startswith("TRACE PA_MOVE_TO_handler_return ") and
               re.search(r"\btick=204\b",line) and "target_ESI=0033c2d6" in line and
               "selected_at_entry=0033c2d6" in line),None)
        if pa_move_handler_return is None or "command_fields_changed=1" not in pa_move_handler_return:
            raise SystemExit(f"FUN_00076570 entry was observed, but its original handler did not demonstrably update Ralph's command/state fields: {pa_move_handler_return!r}")
        portrait_activation=next((line for line in executed_stderr.splitlines()
            if line.startswith("TRACE watched_guest_cell_write cell=2 ") and
               "eip=0006b101" in line and "guest=002f1434" in line and
               "regs=" in line and "/0033c2d6/" in line),None)
        if portrait_activation is None:
            raise SystemExit("the post-landing id=0 click did not prove original 0x6B101 storing Ralph at selectedPlSpec 0x117434")
        packet_tick204_lines=[line for line in gameplay_trace.splitlines()
            if line.startswith("TRACE original_packet tick=204 ")]
        if not any("phase=after_control_game" in line and "action=03" in line for line in packet_tick204_lines) or \
           not any("phase=after_process_packets" in line and "action=00" in line for line in packet_tick204_lines):
            raise SystemExit(f"the original tick-204 PA_MOVE_TO emit/consume pair is incomplete: {packet_tick204_lines!r}")
        ralph_putthing_rows=[line for line in executed_stderr.splitlines()
            if line.startswith("TRACE ralph_putthing_entry ")]
        ralph_prealt_rows=[line for line in executed_stderr.splitlines()
            if line.startswith("TRACE ralph_prealt ")]
        ralph_projection_samples={}
        for guest,slot in (("0033c2d6",0),("0033c39e",1)):
            entries=[line for line in ralph_putthing_rows if f"ptr={guest}" in line]
            projections=[line for line in ralph_prealt_rows if f"ptr={guest}" in line]
            entry_ticks=[int(re.search(r"tick=(\d+)",line).group(1)) for line in entries]
            projection_ticks=[int(re.search(r"tick=(\d+)",line).group(1)) for line in projections]
            if entry_ticks!=list(range(189,320)) or projection_ticks!=list(range(189,320)):
                raise SystemExit(f"expected original PutThingInBucket/projection observations for PlSpec {guest} at ticks 189..319, got {entry_ticks!r}/{projection_ticks!r}")
            if any((int(re.search(r"flags70=([0-9a-fA-F]{4})", line).group(1), 16) & 1) == 0 or
                    "ttype=3" not in line for line in entries):
                raise SystemExit(f"PlSpec {guest} lost the natural active/TT_PLS state before PutThingInBucket")
            viewport_rows=[]
            for line in projections:
                m=re.search(r"screen=(-?\d+),(-?\d+)",line)
                if m and 0<=int(m.group(1))<512 and 0<=int(m.group(2))<480:
                    viewport_rows.append(line)
            if not viewport_rows:
                raise SystemExit(f"PlSpec {guest} never entered the logical map viewport during ticks 189..319")
            ralph_projection_samples[guest]={"slot":slot,"putthing_entries":len(entries),
                "projection_rows":projections,"first_in_viewport":viewport_rows[0],
                "last_projection":projections[-1]}
        ralph0_post_move=[]
        for line in ralph_prealt_rows:
            m=re.search(r"tick=(\d+) ptr=0033c2d6 slot=0 screen=(-?\d+),(-?\d+) flags70=([0-9a-fA-F]{4}) world=(-?\d+),(-?\d+)",line)
            if m:
                tick,px,py,flags,wx,wy=map(lambda x:int(x,16) if any(ch in x.lower() for ch in "abcdef") else int(x),m.groups())
                if 204<=tick<=319:
                    ralph0_post_move.append({"tick":tick,"projected":[px,py],"flags70":f"0x{flags:04X}","world":[wx,wy],"trace":line})
        if [row["tick"] for row in ralph0_post_move]!=list(range(204,320)):
            raise SystemExit(f"expected per-tick world/projection samples for Ralph after PA_MOVE_TO (204..319), got {[row['tick'] for row in ralph0_post_move]!r}")
        if not all((int(row["flags70"],16) & 1) != 0 and
                   0<=row["projected"][0]<640 and 0<=row["projected"][1]<480
                   for row in ralph0_post_move):
            raise SystemExit("Ralph left the active state or the visible 640x480 surface after PA_MOVE_TO")
        move_target_payload=int(re.search(r"field_5c=[0-9a-fA-F]+->([0-9a-fA-F]+)",pa_move_handler_return).group(1),16)
        move_target=(move_target_payload&0xFFFF,(move_target_payload>>16)&0xFFFF)
        direct_click_mode=os.environ.get("GWRECOMP_IFCLEVEL_DIRECT_PICK_CLICK")=="1"
        first_order_end_tick=269 if direct_click_mode else 319
        before_xy=ralph0_post_move[0]["world"]
        after_xy=ralph0_post_move[-1]["world"]
        distance_sq_before=sum((before_xy[i]-move_target[i])**2 for i in (0,1))
        distance_sq_after=sum((after_xy[i]-move_target[i])**2 for i in (0,1))
        later_move_handlers=[line for line in pa_move_handler_rows
            if not re.search(r"\btick=204\b",line)]
        if direct_click_mode:
            second_handlers=[line for line in pa_move_handler_rows
                if re.search(r"\btick=270\b",line) and "action=03" in line and
                   "selectedPlSpec=0033c2d6" in line]
            if len(pa_move_handler_rows)!=2 or len(second_handlers)!=1 or \
                    not any(re.search(r"\btick=204\b",line) and "action=03" in line
                            for line in pa_move_handler_rows):
                raise SystemExit(f"direct click should preserve the tick-204 order and emit one additional original tick-270 PA_MOVE_TO for Ralph: {pa_move_handler_rows!r}")
            packet_rows=[line for line in gameplay_trace.splitlines()
                if line.startswith("TRACE original_packet tick=270 ")]
            if not any("phase=after_control_game" in line and "action=03" in line for line in packet_rows) or \
               not any("phase=after_process_packets" in line and "action=00" in line for line in packet_rows):
                raise SystemExit(f"tick-270 PA_MOVE_TO was not emitted then consumed by original process_packets: {packet_rows!r}")
        elif len(pa_move_handler_rows)!=1 or later_move_handlers or any(
                not re.search(r"\btick=204\b",line) for line in pa_move_handler_rows):
            raise SystemExit(f"clean movement replay must process only the original tick-204 PA_MOVE_TO: {pa_move_handler_rows!r}")
        distance_rows=[{"tick":row["tick"],"distance_squared":sum((row["world"][i]-move_target[i])**2 for i in (0,1)),
                        "world":row["world"],"projected":row["projected"]} for row in ralph0_post_move]
        min_distance_row=min(distance_rows,key=lambda row:row["distance_squared"])
        first_updates=distance_rows[1:4]
        if ralph0_post_move[0]["world"]==ralph0_post_move[1]["world"] or \
           min_distance_row["distance_squared"]>=distance_sq_before:
            raise SystemExit(f"original PlSpec update did not make measurable progress toward PA_MOVE_TO target: start={before_xy}, samples={first_updates!r}, min={min_distance_row!r}, target={move_target}")
        arrived=any(row["world"]==list(move_target) for row in ralph0_post_move)
        arrival_row=next((row for row in ralph0_post_move
            if row["tick"]<=first_order_end_tick and row["world"]==list(move_target)),None)
        if arrival_row is None:
            raise SystemExit(f"Ralph did not reach the original PA_MOVE_TO target within the bounded replay: target={move_target}, final={after_xy}")
        arrival_tick=arrival_row["tick"]
        coordinate_write_re=re.compile(r"TRACE watched_ralph_coordinate_write tick=(\d+) cell=(\d+) eip=([0-9a-fA-F]+) guest=([0-9a-fA-F]+) width=(\d+) old=([0-9a-fA-F]+) regs=([0-9a-fA-F/]+)")
        coordinate_writes=[]
        for line in executed_stderr.splitlines():
            m=coordinate_write_re.fullmatch(line)
            if not m: continue
            tick,cell,eip,guest,width,old,regs=m.groups()
            link=int(eip,16)
            decoded=[]
            for ins in dis.disassemble_at(link,max_bytes=16):
                decoded.append({"link_eip":f"0x{ins.address:08X}","bytes":bytes(ins.bytes).hex(" ").upper(),
                    "mnemonic":ins.mnemonic,"operands":ins.op_str})
                if len(decoded)>=2: break
            coordinate_writes.append({"tick":int(tick),"field":"world_x" if int(cell)==9 else "world_y",
                "guest_address":f"0x{int(guest,16):08X}","width":int(width),
                "writer_link_eip":f"0x{link:08X}","instruction":decoded,
                "old_dword":f"0x{int(old,16):08X}",
                "registers_eax_ebx_ecx_edx_esi_edi_ebp_esp":[f"0x{int(x,16):08X}" for x in regs.split("/")],
                "trace":line})
        if not coordinate_writes:
            raise SystemExit("the active replay did not capture any original guest instruction stores to Ralph's world coordinates")
        movement_writer_links=sorted({row["writer_link_eip"] for row in coordinate_writes})
        move_state_rows=[line for line in executed_stderr.splitlines()
            if line.startswith("TRACE native_move_state tick=")]
        if len(move_state_rows)!=116:
            raise SystemExit(f"expected per-tick raw movement-state samples 204..319, got {len(move_state_rows)}")
        move_state_by_tick={int(re.search(r"tick=(\d+)",line).group(1)):line for line in move_state_rows}
        # The previous 254-tick checkpoint was produced by the unsigned
        # uint16_t promotion defect in the lifted 16-bit SAR operations. The
        # corrected emitter now follows x86 SAR and the original PA_MOVE_TO
        # reaches the same packet destination at tick 220; no hover/click input
        # is injected before tick 265.
        if arrival_tick!=220:
            raise SystemExit(f"arrival tick changed from the corrected signed-SAR replay: {arrival_tick}")
        arrival_state=move_state_by_tick.get(arrival_tick,"")
        settled_state_rows=[move_state_by_tick.get(tick,"")
            for tick in range(arrival_tick,first_order_end_tick+1)]
        # The corrected x86 SAR path leaves the native position at its exact
        # packet target from tick 220. The status byte briefly carries 0x35
        # for the first following sample, then returns to zero; it is not
        # continued movement (world coordinates and projection stay fixed).
        transient_state=move_state_by_tick.get(arrival_tick+1,"")
        if "field_2d=0000" not in arrival_state or any(
            not line or f"world={move_target[0]},{move_target[1]}" not in line
            for line in settled_state_rows) or any(
                not move_state_by_tick.get(tick,"") or "field_2d=0000" not in move_state_by_tick[tick]
                for tick in range(arrival_tick+2,first_order_end_tick+1)) or \
                (transient_state and not any(f"field_2d={value}" in transient_state for value in ("0000","0035"))):
            raise SystemExit("after the original arrival transition, Ralph did not remain at the target with the observed +0x2D byte settled at zero")
        second_move_evidence=None
        if direct_click_mode:
            second_return=next((line for line in executed_stderr.splitlines()
                if line.startswith("TRACE PA_MOVE_TO_handler_return ") and "tick=270 " in line),None)
            if second_return is None:
                raise SystemExit("the post-260 click did not return from the original PA_MOVE_TO handler")
            second_payload=int(re.search(r"field_5c=[0-9a-fA-F]+->([0-9a-fA-F]+)",second_return).group(1),16)
            second_target=(second_payload&0xFFFF,(second_payload>>16)&0xFFFF)
            second_arrival=next((row for row in ralph0_post_move
                if row["tick"]>=270 and row["world"]==list(second_target)),None)
            if second_target==move_target or second_arrival is None or not 270<=second_arrival["tick"]<=319:
                raise SystemExit(f"the original post-260 move order did not reach its target during ticks 270..319: target={second_target}, arrival={second_arrival!r}")
            second_move_evidence={"handler_entry":next(line for line in pa_move_handler_rows
                    if re.search(r"\btick=270\b",line)),
                "handler_return":second_return,"target_world":list(second_target),
                "arrival_tick":second_arrival["tick"],"arrival_world":second_arrival["world"]}
        snapshot_lines=[line for line in executed_stderr.splitlines()
            if line.startswith("TRACE native_move_snapshot tick=")]
        snapshot_re=re.compile(r"TRACE native_move_snapshot tick=(\d+) saved=(\d+) prefix=([^ ]+) Ralph=0033c2d6 active_flags=([0-9a-fA-F]+) world=(-?\d+),(-?\d+) projected=(-?\d+),(-?\d+) projection_valid=(\d+) WScreen_changed=(\d+) DAC_nonzero=(\d+) target_fields_5c=([0-9a-fA-F]+)_0b=([0-9a-fA-F]+) selectedPlSpec=([0-9a-fA-F]+) map37=([0-9a-fA-F]+) map18=([0-9a-fA-F]+) mapScroll=(-?\d+),(-?\d+) mapCenter=(-?\d+),(-?\d+) camera=([0-9a-fA-F]+),([0-9a-fA-F]+) auxiliary=([0-9a-fA-F]+),([0-9a-fA-F]+)")
        snapshot_rows=[]
        for line in snapshot_lines:
            m=snapshot_re.fullmatch(line)
            if not m:
                raise SystemExit(f"malformed authentic WScreen movement snapshot trace: {line}")
            vals=m.groups()
            tick=int(vals[0]); prefix=vals[2]
            if vals[1]!="1":
                raise SystemExit(f"SDL surface snapshot save failed at tick {tick}: {line}")
            files={suffix:ROOT/f"{prefix}{suffix}" for suffix in (".bmp","_wscreen.raw","_palette6.raw")}
            if any(not path.is_file() for path in files.values()):
                raise SystemExit(f"snapshot artifacts are incomplete at tick {tick}: {files!r}")
            snapshot_rows.append({"tick":tick,"Ralph_world":[int(vals[4]),int(vals[5])],
                "Ralph_projected":[int(vals[6]),int(vals[7])],"projection_valid":bool(int(vals[8])),
                "active_flags":f"0x{int(vals[3],16):04X}","WScreen_changed_bytes_this_tick":int(vals[9]),
                "DAC_nonzero_components":int(vals[10]),"command_field_5c":f"0x{int(vals[11],16):08X}",
                "command_field_0b":f"0x{int(vals[12],16):08X}",
                "selectedPlSpec":f"0x{int(vals[13],16):08X}",
                "MapDisplay_selectedThing":f"0x{int(vals[14],16):08X}",
                "MapDisplay_thing":f"0x{int(vals[15],16):08X}",
                "map_scroll":[int(vals[16]),int(vals[17])],"map_center":[int(vals[18]),int(vals[19])],
                "camera_words":[f"0x{int(vals[20],16):08X}",f"0x{int(vals[21],16):08X}"],
                "auxiliary_camera_words":[f"0x{int(vals[22],16):08X}",f"0x{int(vals[23],16):08X}"],
                "artifacts":{suffix:{"path":str(path.relative_to(ROOT)),"sha256":sha(path)}
                    for suffix,path in files.items()}})
        if [row["tick"] for row in snapshot_rows]!=[203,204,212,319]:
            raise SystemExit(f"expected authentic WScreen/DAC snapshots at ticks 203,204,212,319, got {[row['tick'] for row in snapshot_rows]!r}")
        creature_projection_rows=[line for line in executed_stderr.splitlines()
            if line.startswith("TRACE target_creature_projection ")]
        creature_census_line=next((line for line in executed_stderr.splitlines()
            if line.startswith("TRACE mapdisplay_census ptr=0032cf86 ")),"")
        continuation_evidence={"schema":"gw-native-ifclevel-gameplay-continuation/v2",
            "target_sha256":EXPECTED_TARGET,"execution":"native recompiled original setup_game plus a host-orchestrated bounded frame pipeline; 320 original control_game/process_packets/IFC Update/Draw/palette-tail steps completed; this is not a call through the complete game() loop",
            "setup_game":setup_line,"ifclevel_transition":level_line,"result":result_line,
            "draw_ticks":len(tick_lines),"successful_draw_ticks":sum("draw_ok=1" in line for line in tick_lines),
            "wscreen_changed_bytes_total":sum(int(re.search(r"WScreen_changed=(\d+)",line).group(1)) for line in tick_lines),
            "palette_tail_ticks":len(palette_tick_lines),"dac_nonzero_components_final":dac_counts[-1],
            "dac_nonzero_components_min":min(dac_counts),"dac_nonzero_components_max":max(dac_counts),
            "mygadget_callback_0x20f830_ticks":sum("last_callback=0020f830" in line for line in tick_lines),
            "input_events":input_lines,
            "isolated_surface_UI_only":False,
            "process_packets":{"mode":"original process_packets body called once per host-orchestrated frame","effect_accessor_call":effect_call,
                "observed_indirect_call_sites_link":sorted(f"0x{site:08X}" for site in packet_sites),
                "completed_ticks":320,"frontier":False,
                "PA_MOVE_TO":{"action":3,"tick":204,"handler_entry":pa_move_handler_tick204,
                    "original_handler_link":"0x00076570","handler_entry_count":len(pa_move_handler_rows),
                    "handler_return_state":pa_move_handler_return,
                    "packet_emit_consume":packet_tick204_lines,
                    "movement_samples_204_319":ralph0_post_move,
                    "original_coordinate_stores":coordinate_writes,
                    "coordinate_writer_links":movement_writer_links,
                    "raw_movement_state_samples_204_319":move_state_rows,
                    "movement_handler_static":{"link":"0x00076570","name":"PA_MOVE_TO packet handler; public MAP symbol unresolved",
                        "observed_instructions":[
                            {"link":"0x0007659C","instruction":"TEST byte ptr [ESI+0x71],0x10","effect":"handler skips this order if that flag is set"},
                            {"link":"0x000765AB","instruction":"OR byte ptr [ESI+0x57],0x02"},
                            {"link":"0x000765B2..0x000765BC","instruction":"copy packet XY words into the PlSpec-relative +0x5C dword"},
                            {"link":"0x000765F4","instruction":"CALL 0x0005FF20","effect":"original helper computes/normalizes a move target using terrain lookup tables"},
                            {"link":"0x000765F9","instruction":"MOV [ESI+0x5C],EAX"},
                            {"link":"0x00076602","instruction":"MOV [ESI+0x0B],EAX"},
                            {"link":"0x0007661F","instruction":"CALL 0x0003F1C0","condition":"only when +0x82 is nonzero or byte [+0x57] bit 0 is set"}],
                        "consumer_identification":"The live coordinate-write watchpoints report the exact later EIPs that change PlSpec+7/+9 each frame; those LE instructions are disassembled below. The 1.0 reference method names are not assumed to match 1.1."},
                    "target_payload_dword":f"0x{move_target_payload:08X}",
                    "target_xy_words":move_target,
                    "distance_squared_to_target":{"tick204":distance_sq_before,
                        "minimum":{"tick":min_distance_row["tick"],"distance_squared":min_distance_row["distance_squared"]},
                        "arrival_tick":arrival_tick,"tick319":distance_sq_after},
                    "arrived_at_exact_target_by_tick319":arrived,
                    "movement_status":f"arrived at the exact target on tick {arrival_tick}; world coordinates and raw +0x2D byte remained settled through tick 319" if arrived else "moving toward target; exact arrival not observed by tick 319",
                    "physical_motion_observed_without_additional_input":True,
                    "later_original_move_handler_entries":later_move_handlers,
                    "movement_fields":{"PlSpec_flags_offset_0x70":"active flag word; observed as 0x0001",
                        "raw_field_offset_0x5c":"GeneWarsFX upstream reference crosswalk: PlSpec::playerTgt (header offset 92 decimal); GeneWars 1.1 LE handler stores the normalized PA_MOVE_TO dword here at 0x765F9",
                        "raw_field_offset_0x0b":"GeneWarsFX upstream reference crosswalk: inherited Thing::tgt / tgtAlt union (header offset 11 decimal); GeneWars 1.1 LE handler copies the same normalized dword here at 0x76602",
                        "version_boundary":"header names are Level C reference only; GeneWars 1.1 offsets and stores are independently verified against the canonical LE and runtime trace",
                        "arrival_observation":{"tick":arrival_tick,"raw_plus_0x2d_before":"0x0019","raw_plus_0x2d_at_arrival":"0x0000","tick_after_arrival_transient":transient_state,"raw_plus_0x2d_settled_from":arrival_tick+2,"raw_plus_0x2d_settled_value":"0x0000","world_stable_at_target_through_tick319":True},
                        "other_observed_bytes":{"+0x2d":"Thing/MovingThing field byte","+0x45":"raw byte","+0x46":"raw byte","+0x4c":"raw byte"}}}},
            "visual_movement":{"surface_source":"guest WScreen bytes after original IFCLevel::Draw and draw_game palette tail 0x83A0C",
                "conversion":"SDL BMP representation of indexed guest bytes through the live 6-bit DAC; no sprite drawing by harness",
                "snapshots":snapshot_rows},
            "selection":{"method":"original portrait id=0 click after landing; PlSpec_activation caller 0x6C295 -> 0x6B0C0 -> store at 0x117434",
                "observed_selectedPlSpec_store":portrait_activation,
                "selected_guest":"0x0033C2D6","Ralph_flags":"0x0001",
                "post_landing_projection_and_bucket_entries":ralph_projection_samples,
                "direct_viewport_pick_attempt":{"source":"separate previous diagnostic, preserved as native_ifclevel_creature_probe_pre_single_order.json",
                    "result":previous_pick_attempt,
                    "note":"The clean movement replay injects no post-order picking click, so its trajectory contains no second command."},
                "MapDisplay_selectedThing_+0x37":"not clicked in the clean movement replay; prior independent projected-click experiment recorded separately",
                "MapDisplay_thing_+0x18":"not clicked in the clean movement replay; portrait selection remains selectedPlSpec, not proof of world picking"},
            "structural_crosswalk":{"reference":"mefistotelis/genewars headers; Level C only",
                "validation":"GeneWars 1.1 canonical LE SHA-256 plus REA/Ghidra 12.1.4 and Capstone; Level A",
                "reference_revisions":{"genewars":"72ec4c4908d26304dd373132cb3187c855d4bf58",
                    "genewars_re_helpers":"a85d5c517b524aa4906a720330ed1435bf8b65cf",
                    "scope":"read-only structure/enum/symbol references; upstream bio/src bodies are address-labeled stubs"},
                "rea_le_checks":{"carrier_sha256":"1523022fb1febcfb939b2ed04145ee6e7dcd8b99113d932d21d33301c0052a97",
                    "target_sha256":EXPECTED_TARGET,"provider":"REA 6.4.0 / Ghidra 12.1.4",
                    "instruction_evidence":{"read_type_8935D":"ev_f48e170ec1c0ce35a0ea4b6db00eb22f0c11d94af8a890c08597ed32041fdadf",
                        "dispatch_8936F":"ev_f41cf0a2f4ffa077389712d233f8ee75bd29cc7e79c10c7c3a3d1d08db2f09b6",
                        "effect_filter_8941B":"ev_2ef7f4cddd10bf7901947bfa3f87bfa633ca7576d7b2215f9ebbace5571a3bc0",
                        "type_write_83E08":"ev_28ce0f5f5c8ce2259fba1a590f32416b2a0507acde148e9726833612284c8c86",
                        "effect_factory_83BF0":"ev_61239277028b3a5c89ced488a0a09bd0f07728f5ee255c3faffbd045f1cfb787",
                        "effect_table_walk_89380":"ev_da3fb87f863a177e2e567c0af4204dad8b46f3c1fbc297ce624b52e4ad83b186",
                        "map_bucket_78B30":"ev_df9abcc2e2f997ead04cb0544f9faf091e91604e7eae934816a00f6cac1eb31d",
                "tt_creature_vtable_111D04":{"REA_read_bytes":"0x78EE9 FF 55 20; call dword ptr [EBP+0x20]",
                    "canonical_LE_vtable_link":"0x00111D04","guest":"0x002EBD04",
                    "projection_callback":{"slot":"0x00111D08","fixup_type":"0x07","target_link":"0x0006A2E0","target_guest":f"0x{image.link_to_linear(0x6A2E0):08X}"},
                    "eligibility_callback":{"slot":"0x00111D24","fixup_type":"0x07","target_link":"0x00046BC0","target_guest":f"0x{image.link_to_linear(0x46BC0):08X}"},
                    "runtime_allowlist_callsite":"0x78EE9"},
                        "map_draw_sweep_79320":"ev_abc38c4781870d63d1eb4c6fa0418fe82bf05c924492d038864563276a79ab8c",
                        "selection_packet_helper_66DD0":"ev_81472c5e9b2747b683f2229d169ff560adce92eccbdbdc21825aade398981b6e"},
                    "database_annotation":"Unavailable in this Windows Ghidra P0 provider: name/comment mutation is not admitted; findings are persisted in this evidence JSON and test output."},
                "thing_effect":{"ThingType_TT_EFFECT":5,"Thing_ttype_offset":6,
                    "MovingThing_vel_dx_offset":45,"MovingThing_vel_dx_type":"SWORD",
                    "Effect_type_offset":69,"Effect_state_offset":70,
                    "Effect_power_offset":76,"EF_TURBO":6,"EF_SMUGGLER":49,"EF_MONOLITH":59,
                    "interpretation":"The observed byte at +0x45 is Effect::type, not a lifecycle state. +0x46 is Effect::state and +0x4C is Effect::power.",
                    "type_origin":"Canonical LE Capstone confirms 0x83E08 = MOV byte ptr [EDX+0x45], AL. The replay now records the destination after that original store; parent CALL history is attached to the same event. The +0x06 byte at 0x79098 is the generic ThingType discriminator.",
                    "first_active_tick":active_effect_samples[0]["tick"],"active_tick_count":len(active_effect_samples),
                    "active_samples":active_effect_samples},
                "ifc_root":{"this_link":"0x001858F4","secondary_interface_link":"0x00185E9A",
                    "secondary_offset":"0x5A6","secondary_vtable_class_crosswalk":"IFCPlanetside (four virtual slots match PlugIn/PullOut/Update/Draw); root aggregate type remains unresolved",
                    "this_plus_c7":"0x001859BB","this_plus_c8":"0x001859BC",
                    "c8_value":"0x001859CC (this+0xD8)",
                    "source_field_names":"unresolved: upstream IFCLevel/IFCPlanetside headers do not establish a layout match for this 1.1 composite object; preserve byte-offset observations without inventing member names"},
                "map_display":{"type":"MapDisplay","base_link":"0x0016CD70",
                    "thing_offset":"0x18","selectedThing_offset":"0x37",
                    "function_crosswalk":{"0x78B30":"MapDisplay::PutThingInBucket(Thing*) structural match; MAP public symbol absent",
                        "0x79320":"MapDisplay::DrawMapSprites() structural match; MAP public symbol absent",
                        "0x66DD0":"unresolved source declaration; 1.1 LE body updates interface selection fields and emits a packet, so do not label it Thing::Draw(XY)"},
                    "confidence_note":"Upstream bio/src bodies are address-labeled stubs, not executable implementations; names/layouts are hypotheses corroborated against the 1.1 LE."}},
            "map_display_pick":{"function":"FUN_00078B30",
                "edge_scroll":{"function":"FUN_00079DD0","dispatch_link":"0x0007A0C4",
                    "table_link":"0x00079DA4","map_symbol":"jpt_7A0C4","entries":8,
                    "index_guard":"CMP DL,7; JA default_7A0E4","all_entries_object1_LE_fixup_backed":True,
                    "runtime_index_guard":True,"runtime_result":(
                        "not injected in the clean movement replay; the original viewport stays at its pre-order game state; picker camera-pan evidence is separate"
                        if movement_replay else
                        "bottom-right edge cursor held through 150 original ticks to pan both camera axes; no harness camera-coordinate writes")},
                "candidate_source":"MapDisplay bucket heads at link 0x16CD70+0xA3B..+0x11BB; original process_packets and entity insertion paths populated buckets",
                "observed_candidates":map_pick_candidates,"projected_positions":map_pick_projections,
                "tick_results":map_pick_ticks,
                "candidate_filter":{"guest":"0x00341CBD","thing_type_offset_6":"TT_EFFECT (0x05)",
                    "moving_thing_vel_dx_plus_2D":"5 (SWORD)",
                    "screen_projection_after_pan":[178,163],"effect_type_plus_45":"EF_TURBO (0x06)",
                    "effect_state_plus_46":"0x00","effect_power_plus_4c":"0x00",
                    "0x31_and_0x3b_meanings":"EF_SMUGGLER and EF_MONOLITH (other EffectType values), not selectable lifecycle states",
                    "result":"the exact-projection click reached the original picker, but this Effect object was not a selectable unit; MapDisplay+0x37 and +0x18 remained null"},
                "map_display_fields":{"base_link":"0x0016CD70","base_guest":"0x00346D70",
                    "selectedThing_plus_0x37_link":"0x0016CDA7","selectedThing_plus_0x37_guest":"0x00346DA7",
                    "thing_plus_0x18_link":"0x0016CD88","thing_plus_0x18_guest":"0x00346D88",
                    "end_of_tick":"both zero"},
                "world_entity_list_vs_interface_pointer":{"interface_this_plus_4_guest":"0x002E0590",
                    "link":"0x00106590","meaning":"static UI/control record, not the world-entity head",
                    "initializer":"__InitRtns callback at link 0x830F0 passes this=0x1858F4 and pointer 0x106590 to helper 0x20860; static record at 0x106590 contains a pointer to gadget records at 0x106608",
                    "gadget_dispatch":"FUN_000A8CD0 callback at +0x22 is generic help; click action field is +0x0E; per-record click_action_raw is zero for inspected controls"}},
            "tt_creature_selection":{"guest":"0x0032CF86","link":"0x00152F86","MAP":"W?bio$n$BioGame$$__creatures[0]",
                "owner_field":{"reference_name":"Thing::player","offset":"+0x18","value":4},
                "world_xy_final":creature_census_line,
                "projection_samples":creature_projection_rows,
                "selection_observed":bool(creature_pick_rows),"map37_map18_rows":creature_pick_rows,
                "packet_action_nonnull_rows":packet_action_rows,
                "click_sequence":{"events":([] if movement_replay else
                        [creature_motion,creature_left_down,creature_left_up,creature_right_down,creature_right_up]),
                    "separate_direct_pick_evidence":"evidence/native_ifclevel_creature_probe_pre_single_order.json",
                    "right_button_adapter_fields":{"RightButton":"lbDisplay+104 = guest 0x00376AC0","MRightButton":"lbDisplay+107 = guest 0x00376AC3"},
                    "completed_stage":("not injected; retained in separate direct-pick evidence" if movement_replay else 5)}},
            "c8_receiver":{"this_adjustment":"0x000005A6","this_guest":"0x0035F8F4","field_guest":"0x0035F9BC","value_guest":"0x0035F9CC","value_offset":"this+0xD8","byte_plus_5":"0x03","null_DS14_reads":0},
            "surface_field_audit":"evidence/native_ifclevel_surface_field_audit.json",
            "artifacts":{str(path.relative_to(ROOT)):sha(path) for path in (raw_path,palette_path,bmp_path)},
            "stdout_log":str(stdout_path.relative_to(ROOT)),"stderr_log":str(stderr_path.relative_to(ROOT)),
            "tested_controls":[
                {"id":18,"logical_rect":[50,19,138,107],"host_click_center":[188,126],
                "hit_test":"selected by the original FUN_000A8ED0 on button release; see input_events"},
                {"id":0,"logical_rect":[19,177,54,212],"host_click_center":[73,389],
                "hit_test":"original hit-test selects gadget id=0; this alone does not establish selection of a world entity. Live this+4 points to the static UI/control record at guest 0x002E0590, whose record points to gadget templates; the original Update action-state gate remains 0; see surface_field_audit"},
                {"id":7,"logical_rect":[3,401,20,418],"host_click_center":[23,819],
                "hit_test":"selected on press. The original thunk subtracts 0x5A6, yielding this=0x0035F8F4. [this+0xC8] is the initialized embedded object 0x0035F9CC (this+0xD8); its byte +5 is 0x03. The activation click changed WScreen, kept pendingIFC=0, and produced no DS:0..FF read."},
                {"id":5,"logical_rect":[128,0,639,479],"host_click_candidate_projection":creature_projection_rows,
                "hit_test":"cursor/click events are placed using the live BioGame creature projection when it enters the viewport; selection outcome is recorded separately in selectedThing/thing."}],
            "interpretation":("Original Draw and draw_game palette tail execute in each captured tick; the DAC has nonzero components." if dac_counts[-1] else "Original Draw and draw_game palette tail execute in each captured tick, but the DAC remains zero." )+
                f" SDL delivered the post-landing id=0 selection and the single terrain order; the old projected-creature click sequence is disabled in this clean run. selectedThing/thing results from the earlier separate picker experiment={len(creature_pick_rows)}; non-null packet Action samples={len(packet_action_rows)}."}
        dedicated_move_evidence={"schema":"gw-native-plspec-first-complete-move/v1",
            "target_sha256":EXPECTED_TARGET,
            "run":{"mode":"bounded experimental native replay; original GeneWars 1.1 code is recompiled and dispatched",
                "setup_game":setup_line,"IFCLevel_transition":level_line,"exit_code":executed.returncode,
                "requested_continuation_ticks":320,"completed_continuation_ticks":len(tick_lines),
                "runtime_frontier":False,"pendingIFC":"0x00000000",
                "MCB_chain_valid":"MCB_chain_valid=1" in result_line,"WScreen_backed":"WScreen_backed=1" in result_line,
                "result_line":result_line},
            "natural_activation":{"tick":188,"PlSpec":"0x0033C2D6","flags_offset_0x70":"0x0001",
                "provenance":"existing original landing/effect progression evidence; no harness write to PlSpec flags"},
            "single_PA_MOVE_TO":{"emission_and_consumption":packet_tick204_lines,
                "handler_entry":pa_move_handler_tick204,"handler_return":pa_move_handler_return,
                "handler_entry_count":len(pa_move_handler_rows),"later_handler_entries":later_move_handlers,
                "selectedPlSpec":"0x0033C2D6","packet_action":"0x03",
                "target_payload_dword":f"0x{move_target_payload:08X}","target_world_xy_words":move_target,
                "handler_fields_written":{"PlSpec_plus_0x5C":f"0x{move_target_payload:08X}",
                    "PlSpec_plus_0x0B":f"0x{move_target_payload:08X}",
                    "interpretation":"The LE handler writes the packet coordinate dword into these offsets and calls 0x5FF20 to derive/normalize a target.",
                    "upstream_reference_crosswalk":{"PlSpec_plus_0x5C":"PlSpec::playerTgt (plspec.hpp offset 92 decimal)",
                        "PlSpec_plus_0x0B":"inherited Thing::tgt / tgtAlt union (thing.hpp offset 11 decimal)",
                        "version_boundary":"GeneWarsFX upstream headers are Level C only; names are not assumed to prove a complete 1.0/1.1 layout match. The 1.1 stores and offsets are independently confirmed by canonical LE bytes and runtime watchpoints."}},
                "motion_samples_tick204_319":ralph0_post_move,
                "distance_to_target_squared":distance_rows,
                "start_distance_squared":distance_sq_before,"minimum_distance_squared":min_distance_row,
                "final_distance_squared":distance_sq_after,"arrived_by_tick319":arrived,
                "arrival_tick":arrival_tick,
                "post_arrival_settling":{"raw_field_offset_0x2d_at_tick253":"0x0019",
                    "raw_field_offset_0x2d_from_tick254_through_319":"0x0000",
                    "world_target_stable_from_tick254_through_319":True,
                    "assertion":"all original per-tick state samples from arrival through tick 319 remained at the target with the raw +0x2D byte zero"},
                "coordinate_store_instructions":coordinate_writes,"writer_links":movement_writer_links,
                "world_state_samples":move_state_rows},
            "visual":{"capture_source":"Guest WScreen after original IFCLevel::Draw and original palette tail 0x83A0C",
                "representation":"BMP is made from the guest indexed surface and captured DAC; harness does not draw pixels",
                "snapshots":snapshot_rows},
            "prior_direct_picking":{"evidence":"evidence/native_ifclevel_creature_probe_pre_single_order.json",
                "result":previous_pick_attempt,
                "separation":"The old direct-viewport picking attempt is retained as a separate diagnostic and is not part of this one-order trajectory."},
            "game_loop_comparison":{"canonical_LE_sha256":EXPECTED_TARGET,
                "original_game_frame_order":[
                    {"link":"0x00092865","instruction":"CALL 0x00064CB0","role":"pre-frame game work"},
                    {"link":"0x0009286A..0x00092894","instruction":"conditional cleanup when byte [0x001809B8] != 0","role":"optional original cleanup loop"},
                    {"link":"0x00092896","instruction":"CALL 0x0005AE60","role":"control_game; full body invokes setup_controller and active IFC Update"},
                    {"link":"0x0009289B","instruction":"CALL 0x00093010","role":"process_packets"},
                    {"link":"0x000928A0","instruction":"CALL 0x000834C0","role":"draw_game"},
                    {"link":"0x000928AA","instruction":"CALL 0x00035C00","symbol":"W?ProcessSounds$:SoundManager$n()v","role":"sound-manager frame work"},
                    {"link":"0x000928AF","instruction":"INC dword ptr [0x00117472]","role":"GameControl::Turn increment"}],
                "executed_harness_order":["original 0x64CB0 pre-frame call (once per bounded iteration)",
                    "original conditional cleanup gate/body; gate sampled at guest 0x0035A9B8",
                    "complete original control_game(0x5AE60)","original process_packets(0x93010)",
                    "complete original draw_game(0x834C0), including CALL [EDX+0x0c] at 0x83561 and palette tail 0x83A0C",
                    "original ProcessSounds(0x35C00)","original game() Turn increment instruction 0x928AF"],
                "not_executed_from_full_game_loop":[
                    {"link":"0x00092777","instruction":"CALL 0x000AE2B0","note":"outer continuation/exit gate is controlled by the bounded host harness"},
                    {"link":"0x00092784","instruction":"CALL 0x000A4DDA","note":"timer/pacing comparison is not used to throttle bounded test ticks"},
                    {"link":"0x000927E4","instruction":"CALL 0x00098C48","note":"real-time delay is omitted; not a guest gameplay-state step"},
                    {"link":"0x000928B5","instruction":"test GameControl::QuitGame and loop/exit","note":"the test terminates by its 320-iteration bound"}],
                "scope":"All guest gameplay, cleanup-when-enabled, draw, sound, and Turn steps listed above execute in original order for each harness iteration; only game() pacing, delay, and outer loop bound remain host-orchestrated."},
            "integrity":{"exit_code":executed.returncode,"MCB_chain_valid":True,"WScreen_backed":True,
                "frontier":False,"unexpected_writes":0 if "unexpected_writes=0" in executed.stdout else None,
                "result_line":result_line},
            "artifacts":{"trace":"evidence/native_ifclevel_gameplay_continue.trace",
                "stdout":"evidence/native_ifclevel_creature_probe.stdout.log",
                "stderr":"evidence/native_ifclevel_creature_probe.stderr.log",
                "snapshot_artifacts":snapshot_rows}}
        if hover_pick_replay:
            hover_evidence.update({"schema":"gw-native-ifclevel-post-settlement-hover-pick/v1",
                "target_sha256":EXPECTED_TARGET,"exit_code":executed.returncode,
                "result_line":result_line,"trace":"evidence/native_ifclevel_hover_pick.trace",
                "stdout":str(replay_stdout_path.relative_to(ROOT)),
                "stderr":str(replay_stderr_path.relative_to(ROOT)),
                "sdl_capture":re.search(r"\bbmp=(\S+)",result_line).group(1),
                "static_analysis":"evidence/native_hover_picker_and_game_loop_static.json"})
            if direct_pick_click_mode:
                direct_rows=[line for line in gameplay_trace.splitlines()
                    if line.startswith("TRACE post260_direct_pick_state ")]
                if len(direct_rows)!=6 or [int(re.search(r"tick=(\d+)",line).group(1))
                        for line in direct_rows] != list(range(265,271)):
                    raise SystemExit(f"post-260 click probe did not retain six ordered state snapshots: {direct_rows!r}")
                click_rows=[line for line in direct_rows if "input=post260_direct_viewport_left_" in line]
                effect_rows=[line for line in direct_rows if "input=post260_" in line and
                    ("EF_SMUGGLER" in line)]
                selected_after_ralph=next((line for line in direct_rows if "tick=266 " in line),"")
                selected_after_effect=next((line for line in direct_rows if "tick=269 " in line),"")
                direct_evidence={"schema":"gw-native-ifclevel-post260-direct-click/v1",
                    "target_sha256":EXPECTED_TARGET,"exit_code":executed.returncode,
                    "movement_window_204_254":"unchanged; extra SDL inputs occur at ticks 265..270 only",
                    "hitbox_and_hover_evidence":hover_evidence,
                    "direct_viewport_click_rows":click_rows,
                    "effect_hover_and_click_rows":effect_rows,
                    "post_click_PA_MOVE_TO":second_move_evidence,
                    "state_after_Ralph_click":selected_after_ralph,
                    "state_after_effect_click":selected_after_effect,
                    "interpretation":"Original hover hit testing accepted Ralph's signed frame box and copied it through MapDisplay+0x37 to +0x18. The later direct click on that sprite left selectedPlSpec pointing at Ralph. Hovering the active EF_SMUGGLER did not select it (MapDisplay+0x18 became null); clicking that map position with Ralph selected emitted a second original PA_MOVE_TO at tick 270, which process_packets consumed and whose target Ralph reached at tick 319. Inputs were SDL-only; the harness assigned no guest state."}
                (ROOT/"evidence"/"native_ifclevel_post260_direct_click.json").write_text(
                    json.dumps(direct_evidence,indent=2)+"\n",encoding="utf-8")
                print("PASS post-260 direct map click probe captured original picker and state")
                print(f"evidence: {ROOT/'evidence'/'native_ifclevel_post260_direct_click.json'}")
            else:
                (ROOT/"evidence"/"native_ifclevel_hover_pick.json").write_text(
                    json.dumps(hover_evidence,indent=2)+"\n",encoding="utf-8")
        else:
            (ROOT/"evidence"/"native_plspec_first_complete_move.json").write_text(
                json.dumps(dedicated_move_evidence,indent=2)+"\n",encoding="utf-8")
            (ROOT/"evidence"/"native_ifclevel_creature_probe.json").write_text(
                json.dumps(continuation_evidence,indent=2)+"\n",encoding="utf-8")
        process_packets_evidence={"schema":"gw-native-ifclevel-process-packets-replay/v1",
            "target_sha256":EXPECTED_TARGET,"status":"completed_bounded_full_loop",
            "entry_link":"0x00093010","full_game_ticks":len(tick_lines),
            "call_88146":{"instruction":"CALL dword ptr [EDX+4]",
                "runtime_trace":effect_call,"target_guest":"0x002552E0",
                "target_link":"0x0006A2E0","receiver_EDX":"0x002EC1E4",
                "EAX_effects_head":"0x00341576",
                "interpretation":"valid virtual call through an effect-record vtable; EAX names the BioGame::__effects data head and is not the indirect call target"},
            "observed_indirect_call_sites_link":sorted(f"0x{site:08X}" for site in packet_sites),
            "frontier":None,"low_DS14_reads":0,
            "game_state":{"currentIFC":"0x0035FE9A","pendingIFC":"0x00000000",
                "selected_specialist_is_world_entity":False,"action_state_pointer":"0x00000000",
                "terrain_hit_test_delivered":True,"unit_action_confirmed":False},
            "trace":str(gameplay_trace_path.relative_to(ROOT)),
            "runtime_log":str(replay_stderr_path.relative_to(ROOT)),
            "interpretation":f"The original process_packets path and its fixup-backed callbacks ran in each of {len(tick_lines)} bounded game-frame iterations. selectedThing/thing samples={len(creature_pick_rows)} and non-null packet Action samples={len(packet_action_rows)} remain separately evidenced; SDL motion alone is not treated as proof of selection or command."}
        (ROOT/"evidence"/"native_ifclevel_process_packets_frontier.json").write_text(
            json.dumps(process_packets_evidence,indent=2)+"\n",encoding="utf-8")
        member_lines={}
        for sample_tick in (0,15,22,23,26,27,39):
            member_lines[str(sample_tick)]=next((line for line in gameplay_trace.splitlines()
                if line.startswith(f"post_loader_member_state tick={sample_tick} ")),"")
        field_audit={
            "schema":"gw-native-ifclevel-surface-field-audit/v1",
            "target_sha256":EXPECTED_TARGET,
            "rea_target":"carrier.exe; Ghidra 12.1.4; original LE link coordinates",
            "rea_xrefs":{"c8":{"address":"0x001859BC","evidence_id":"ev_8457d74724fdaa13d99a83615751759fd33f47b2192e2d229bdeea2f59c75af8","references":["0x1DE6A","0x1FD79","0x20232","0x390F8","0x394EF","0x40BEE","0x44B70","0x4A597","0x5D72E","0x66E1C","0x66EBA","0x67FD8","0x67FF4","0x6B0C7","0x6B0E3","0x6B1BE","0x6BADA","0x6BCC9","0x6C2AD","0x6DE2D","0x6E2CD","0x71E37","0x76386","0x76B53","0x777FC","0x78649","0x78690"],"direct_write_instructions":["0x66E1C","0x66EBA","0x67FD8","0x6B1BE","0x6BADA","0x6BCC9","0x6C2AD","0x6DE2D","0x6E2CD","0x71E37"],"writer_functions":["FUN_00066DD0","FUN_00067F80","FUN_0006B1B0","FUN_0006BAC0","FUN_0006BCA0","FUN_0006C250","FUN_0006DDD0","FUN_0006E270","unresolved container at 0x71E37"]},
                "c7":{"address":"0x001859BB","evidence_id":"ev_d6a3abf2e75609de9f5f2b2838263ec670b273ab44d22d7d0dc1cbd8ef073efc","references":["0x3912F","0x39138","0x39143","0x392C6","0x392D1","0x392D9","0x39BFF","0x4A5AC","0x4A5B3","0x4A5BD","0x61B08","0x66E3E","0x66E47","0x66E5B","0x68184","0x68191","0x681A3","0x6BBBE","0x6BBD9","0x6BD9D","0x6BDB1","0x6BDC0","0x6C05D","0x6C06B","0x6C07E","0x6C346","0x6C35E","0x6C370","0x6DD63","0x6DD6C","0x6DD77","0x6DDB9","0x6DF05","0x6DF12","0x6DF33","0x6E3F1","0x6E400","0x6E40B","0x6E50C","0x6E51B","0x6E523","0x77811"],"direct_write_instructions":["0x39138","0x39143","0x392D1","0x392D9","0x39BFF","0x4A5B3","0x4A5BD","0x66E47","0x66E5B","0x68191","0x681A3","0x6BBD9","0x6BDB1","0x6BDC0","0x6C06B","0x6C07E","0x6C35E","0x6C370","0x6DD6C","0x6DD77","0x6DDB9","0x6DF12","0x6DF33","0x6E400","0x6E40B","0x6E51B","0x6E523","0x77811"]}},
            "secondary_interface":{"subobject_link":"0x00185E9A","subobject_guest":"0x0035FE9A","thunk_instruction":{"link":"0x00025180","bytes":"2B 40 FC","text":"SUB EAX,dword ptr [EAX-4]","observed_adjustment":"0x000005A6"},"adjusted_this_link":"0x001858F4","adjusted_this_guest":"0x0035F8F4","c7_link":"0x001859BB","c7_guest":"0x0035F9BB","c8_link":"0x001859BC","c8_guest":"0x0035F9BC","c8_value":"0x0035F9CC","c8_value_relation":"this+0xD8 embedded subobject; not the selected world specialist pointer","c8_byte_plus_5":"0x03","map_note":"The public MAP names IFCLevel primary methods at 0x15710/0x15CF0/0x179F0/0x177C0. The secondary vtable at 0x111B04 dispatches through thunks to 0x20C60/0x21140/0x21380/0x22F40, for which this MAP has no exact symbols."},
            "update_instructions":{"c8_reads":[{"address":"0x21596","bytes":"8B 96 C8 00 00 00","text":"MOV EDX,[ESI+0xC8]"},{"address":"0x215CF","bytes":"8B 86 C8 00 00 00","text":"MOV EAX,[ESI+0xC8]"},{"address":"0x215D5","bytes":"8A 78 05","text":"MOV BH,[EAX+5]"}],"c7_writes":[{"address":"0x214A0","text":"AND byte [ESI+0xC7],0xFE"},{"address":"0x21618","text":"MOV byte [ESI+0xC7],AH"},{"address":"0x21624","text":"MOV byte [ESI+0xC7],DL"},{"address":"0x21648","text":"MOV byte [ESI+0xC7],AH"},{"address":"0x21655","text":"MOV byte [ESI+0xC7],DL"}],"selection_dispatch":{"state_pointer_global":"mapDisplay+0x18; link 0x0016CD88 -> guest 0x00346D88","state_byte_offset":"0x2D","required_value_for_FUN_00066DD0":"0x05","callsite":"0x21BAC","target":"FUN_00066DD0 at 0x66DD0","control_flow":"Update reads [*mapDisplay+0x18+0x2D], and calls 0x66DD0 in the value-5 branch."}},
            "plugin_initializer":{"callsite":"0x20EA6","target":"FUN_00066DD0 at 0x66DD0","capstone_prefix":"LEA EAX,[EBP+0x1F0]; XOR EDX,EDX; CALL 0x66DD0","effect":"The original initializer calls the same setter with param2=0; its C8 subobject-pointer store is unconditional, while the nonzero-entity/C7 setup branch is skipped."},
            "live_ui_replay":{"ticks":len(tick_lines),"process_packets":"original process_packets runs in each bounded frame; see native_ifclevel_process_packets_frontier.json","field_samples":member_lines,"interpretation":"The id=0 hit only records gadget id 0; this+4 is a pointer to the static UI/control record at 0x002E0590, initialized by the original CRT callback, not a world-entity list. The previous action_state_ptr=0x303 observation read the wrong guest address 0x0030CD88 and is withdrawn. The verified object-3 location 0x00346D88 (mapDisplay+0x18) remains zero in the current route; DS=0x14 low-read probe covers 0x000..0xFFF except BIOS tick-count bytes 0x46C..0x46D."},
            "runtime_frontier":{"address":"0x88146","bytes":"FF 52 04","text":"CALL dword ptr [EDX+4]","live_target":"0x002552E0","map_symbol":"BioGame effect-coordinate accessor at link 0x0006A2E0; BioGame::__effects data head at link 0x00167576","status":"original fixup-backed virtual call executed; not a frontier","runtime_trace":"captured in native_ifclevel_creature_probe.stderr.log"},
            "artifacts":{str(path.relative_to(ROOT)):sha(path) for path in (raw_path,palette_path,bmp_path)},
            "null_ds14_test":"PASS tests/test_null_ds_read_diagnostic.py; diagnostic is opt-in and preserves the guest read and registers"}
        (ROOT/"evidence"/"native_ifclevel_surface_field_audit.json").write_text(
            json.dumps(field_audit,indent=2)+"\n",encoding="utf-8")
        for line in executed.stdout.splitlines():
            if line.startswith(("PASS original setup_game continuous", "PASS original IFCLevel transition")):
                print(line)
        print(f"PASS native IFCLevel gameplay continuation ticks={len(tick_lines)} WScreen_changed={continuation_evidence['wscreen_changed_bytes_total']} DAC_nonzero_final={dac_counts[-1]} palette_tail_ticks={len(palette_tick_lines)} callback_24830_ticks={continuation_evidence['mygadget_callback_0x20f830_ticks']}")
        return
    for line in executed.stdout.splitlines():
        if line.startswith("TRACE SDL"):
            print(line)
    for line in executed.stdout.splitlines():
        if line.startswith(("TRACE original FUN_0006EE60 text clip ","TRACE original Update dispatch ","TRACE original Draw dispatch ",
                            "TRACE original OPTIONS vtable ","TRACE original IFCOptions::Update ",
                            "TRACE original IFCOptions::Draw ","PASS original IFCOptions::",
                            "TRACE OPTIONS palette-","TRACE OPTIONS active-gadgets","TRACE OPTIONS gadget[",
                            "TRACE original palette writer ","TRACE title_text_call ",
                            "TRACE original title glyph write ",
                            "TRACE original TEXT.DAT ",
                            "TRACE original UI ",
                            "PASS SDL presents",
                            "PASS original draw_game IFCLevel type-2 tail")):
            print(line)
    text_load_trace=next((line for line in executed.stdout.splitlines()
                          if line.startswith("TRACE original TEXT.DAT load ")),None)
    text_string_traces=[line for line in executed.stdout.splitlines()
                        if line.startswith("TRACE original TEXT.DAT string[")]
    text_clip_trace=next((line for line in executed.stdout.splitlines()
                          if line.startswith("TRACE original FUN_0006EE60 text clip ")),None)
    if text_load_trace is None or len(text_string_traces)!=4 or text_clip_trace is None:
        raise SystemExit("original TEXT.DAT loader/parser traces are incomplete")
    if any("after=00000000" in line for line in text_string_traces):
        raise SystemExit("original TEXT.DAT parser left a title string pointer null")
    glyph_write_traces=[line for line in executed.stdout.splitlines()
                        if line.startswith("TRACE original title glyph write ")]
    glyph_write_sites={int(re.search(r"site=([0-9a-fA-F]+)",line).group(1),16):
                       int(re.search(r"changed=(\d+)",line).group(1))
                       for line in glyph_write_traces if " changed=" in line}
    if set(glyph_write_sites)!={0x710EB,0x7110A,0x71129,0x71148} or any(v==0 for v in glyph_write_sites.values()):
        raise SystemExit(f"original title text calls did not each change the guest surface: {glyph_write_traces}")
    text_surface_delta_proof={
        "method":"same-run TEXT.DAT load/parser, four non-null strings, and original glyph callsite guest-surface writes",
        "cross_run_bmp_baseline_used":False,
        "glyph_site_changed_pixels":{f"0x{site:05X}":count for site,count in glyph_write_sites.items()},
        "passed":True}
    update_trace=next((line for line in executed.stdout.splitlines()
                       if line.startswith("TRACE original Update dispatch ")),None)
    update_entry_match=(re.search(r"method_entry_delta=(\d+)",update_trace)
                        if update_trace else None)
    if (update_trace is None or "ok=1" not in update_trace or
            "targets=001fe700/" not in update_trace or
            update_entry_match is None or int(update_entry_match.group(1))<1):
        raise SystemExit(f"original virtual IFCTitle::Update was not proven in the native harness: {update_trace!r}")
    update_diff_path=ROOT/"evidence"/"native_ifctitle_update_memory_diff.json"
    update_diff=json.loads(update_diff_path.read_text(encoding="utf-8"))
    # Original time/controller state changes one or two bookkeeping bytes
    # across equivalent bounded runs. Require a coherent diff with the known
    # narrow footprint instead of pinning that nondeterministic count.
    if (update_diff.get("changed_bytes")!=len(update_diff.get("changes",[])) or
            not 80<=update_diff.get("changed_bytes",0)<=100):
        raise SystemExit("original IFCTitle::Update changed-byte capture is missing or inconsistent")
    ui_traces=[line for line in executed.stdout.splitlines() if line.startswith("TRACE SDL input cycle=")]
    ui_by_cycle={re.search(r"cycle=([^ ]+)",line).group(1):line for line in ui_traces}
    required_cycles={"hover-options","mouse-down-options","mouse-up-options","post-release-options"}
    if set(ui_by_cycle)!=required_cycles:
        raise SystemExit(f"SDL input cycle trace incomplete: {ui_traces}")
    hover=ui_by_cycle["hover-options"]
    down=ui_by_cycle["mouse-down-options"]
    release=ui_by_cycle["mouse-up-options"]
    if "game_xy=313,264" not in hover or "result=0000ffff->0000ffff" not in hover:
        raise SystemExit(f"original hover did not land on the logical OPCIONES rect: {hover}")
    if "game_xy=313,264" not in down or "OPCIONES_pressed=0->8" not in down or \
            "result=0000ffff->00000003" not in down:
        raise SystemExit(f"original Update did not recognize the OPCIONES mouse-down ID 3: {down}")
    if "OPCIONES_pressed=8->0" not in release or \
            "transition=00000000/00000000->00360034/0035ead8" not in release:
        raise SystemExit(f"original mouse release did not request the OPTIONS transition: {release}")
    pending_ifc_trace=next((line for line in executed.stdout.splitlines()
                            if line.startswith("TRACE original pending-interface object=")),None)
    if pending_ifc_trace is None:
        raise SystemExit("original transition request did not retain its pending-interface dispatch state")
    # Validate the original 1.1 switch-table entry for result ID 3 against LE
    # bytes and Capstone. The table is in object 1 and its target is rebased by
    # the measured object-1 delta; the target block performs the two stores.
    obj1=image.objects[0]
    table_offset=0x70E9C-obj1.base
    table_raw=bytes(image.object_data(1)[table_offset:table_offset+16])
    if len(table_raw)!=16:
        raise SystemExit("IFCTitle::Update switch table is incomplete in canonical LE object 1")
    update_targets=struct.unpack("<4I",table_raw)
    options_target_link=update_targets[3]-REBASES[1]
    options_block={i.address:(i.mnemonic,i.op_str,bytes(i.bytes))
                   for i in dis.disassemble_at(options_target_link,max_bytes=0x80)}
    if options_target_link!=0x7102C or \
            not any(a=="mov" and "0x360034" in b for a,b,_ in options_block.values()) or \
            not any(a=="mov" and "0x2ef7ec" in b for a,b,_ in options_block.values()) or \
            not any(a=="mov" and "0x2ef7f0" in b for a,b,_ in options_block.values()):
        raise SystemExit(f"LE/Capstone result-3 branch no longer publishes the observed transition: {options_target_link:#x}")
    draw_trace=next((line for line in executed.stdout.splitlines()
                     if line.startswith("TRACE original Draw dispatch ")),None)
    main_palette_trace=next((line for line in executed.stdout.splitlines()
        if line.startswith("PASS original setup_game palette source=")),None)
    if draw_trace is None or "ok=1" not in draw_trace or "unexpected_writes=0" not in draw_trace or \
            "deferred=0/0/0" not in draw_trace:
        raise SystemExit(f"original virtual IFCTitle::Draw was not proven cleanly: {draw_trace!r}")
    if main_palette_trace is None or "DAC_matches_original_data_main_pal=1" not in main_palette_trace:
        raise SystemExit(f"original setup_game did not apply its loaded main palette: {main_palette_trace!r}")
    transition_abi_trace=next((line for line in executed.stdout.splitlines()
        if line.startswith("TRACE original IFC ABI ")),None)
    combined_transition_output=executed.stdout+"\n"+executed.stderr
    transition_line=next((line for line in combined_transition_output.splitlines()
        if "TRACE original game() transition block " in line),None)
    transition_trace=(transition_line[transition_line.index("TRACE original game() transition block "):].splitlines()[0]
                      if transition_line else None)
    if transition_abi_trace is None or "PullOut_thunk=001fe710" not in transition_abi_trace or \
            "PlugIn_thunk=001fe620" not in transition_abi_trace:
        raise SystemExit(f"original IFC ABI transition trace is missing or unexpected: {transition_abi_trace!r}")
    memory_table_trace=next((line for line in executed.stdout.splitlines()
        if line.startswith("TRACE original setup_game 0x94DBC -> LbDataLoadAll_")),None)
    if memory_table_trace is None or "entries=3 result=0" not in memory_table_trace or \
            "scratch_slot=002EECA8" not in memory_table_trace or "bytes=00002000" not in memory_table_trace or \
            "scratch_DOS_backing=1" not in memory_table_trace or "WScreen_backing=1" not in memory_table_trace:
        raise SystemExit(f"original setup_game memory descriptor table did not allocate scratch: {memory_table_trace!r}")
    if transition_trace is None or "result=1 trap=0" not in transition_trace or \
            "vtable_targets=001fe710/001fe620" not in transition_trace or \
            "currentIFC_before=0035ead8 currentIFC_after=00360034" not in transition_trace or \
            "pending=00000000" not in transition_trace or "unexpected=0" not in transition_trace or \
            "denied=0" not in transition_trace or re.search(r"missing_save_slots=\d+", transition_trace) is None:
        raise SystemExit(f"original game() transition did not complete with clean memory integrity: {transition_trace!r}")
    save_missing_lines=[line for line in combined_transition_output.splitlines()
        if "missing_verified_save_slot=" in line]
    save_missing_by_slot={slot:0 for slot in range(1,8)}
    save_abs_path=re.compile(r"path='C:\\GENEWARS\\SAVE\\SAVE([1-7])\.SAV' access=0 result=2 missing_verified_save_slot=([1-7])",re.IGNORECASE)
    for line in save_missing_lines:
        match=save_abs_path.search(line)
        if not match or match.group(1)!=match.group(2):
            raise SystemExit(f"missing save response did not use the normalized absolute DOS path: {line!r}")
        save_missing_by_slot[int(match.group(1))]+=1
    if len(save_missing_lines)!=14 or any(save_missing_by_slot[s]!=2 for s in range(1,8)) or \
            "missing_save_slots=14" not in transition_trace or "save_slots=2/2/2/2/2/2/2" not in transition_trace:
        raise SystemExit(f"original OPTIONS did not issue two real file-not-found opens for each absent absolute SAVE slot: {save_missing_by_slot}; {transition_trace!r}")
    if "ERROR loading !" in combined_transition_output:
        raise SystemExit("original OPTIONS PlugIn still reports a resource load error")
    if save_profile=="reference-save":
        if re.search(r"TRACE original VFS read path='[^']*save[\\/]save0\.sav'", combined_transition_output, re.IGNORECASE) is None or \
                re.search(r"missing_save_slots=\d+", transition_trace) is None:
            raise SystemExit("original OPTIONS PlugIn did not read the observed SAVE0 input or report the save-slot count")
    else:
        # no-saves: the original game itself must probe SAVE0.SAV, receive DOS file-not-found and never read a save
        save0_missing=re.findall(r"TRACE original VFS open path='[^']*SAVE\\SAVE0\.SAV' access=0 result=2 missing_file", combined_transition_output, re.IGNORECASE)
        if not save0_missing or re.search(r"TRACE original VFS read path='[^']*save[\\/]save\d\.sav'", combined_transition_output, re.IGNORECASE) is not None:
            raise SystemExit(f"no-saves profile: original OPTIONS must probe SAVE0.SAV, get file-not-found and read no save; observed opens={len(save0_missing)}")
        print(f"TRACE save_profile no-saves original_OPTIONS_save0_probes={len(save0_missing)} reads=0",flush=True)
    stderr_lines=executed_stderr.splitlines()
    low_begin=stderr_lines.index("TRACE low-write transition-window=begin")
    low_end=stderr_lines.index("TRACE low-write transition-window=end",low_begin+1)
    low_window=stderr_lines[low_begin+1:low_end]
    low_write_trace=[line for line in low_window if line.startswith("TRACE guest-low-write ")]
    low_write_eips={re.search(r"eip=([0-9a-fA-F]+)",line).group(1) for line in low_write_trace}
    if low_write_trace or "TRACE original unexpected-memory bytes" in executed.stderr:
        raise SystemExit(f"original OPTIONS transition still emitted invalid guest writes: {low_write_trace[:3]!r}")
    pullout_dac_trace=next((line for line in executed.stdout.splitlines()
        if line.startswith("TRACE original PullOut VGA palette snapshot ")),None)
    if pullout_dac_trace is None or "DAC_component_reads=768" not in pullout_dac_trace or \
            "DAC_read_index_writes=1" not in pullout_dac_trace:
        raise SystemExit(f"original PullOut did not read the complete emulated VGA DAC palette: {pullout_dac_trace!r}")
    pullout_retrace_trace=next((line for line in executed.stdout.splitlines()
        if line.startswith("TRACE original PullOut VGA retrace wait ")),None)
    if pullout_retrace_trace is None or "status_reads=" not in pullout_retrace_trace or \
            int(re.search(r"status_reads=(\d+)",pullout_retrace_trace).group(1))<1:
        raise SystemExit(f"original PullOut did not pass its VGA retrace wait: {pullout_retrace_trace!r}")
    options_vtable_trace=next((line for line in executed.stdout.splitlines()
        if line.startswith("TRACE original OPTIONS vtable after PlugIn ")),None)
    options_update_trace=next((line for line in executed.stdout.splitlines()
        if line.startswith("TRACE original IFCOptions::Update dispatch=")),None)
    options_draw_trace=next((line for line in executed.stdout.splitlines()
        if line.startswith("TRACE original IFCOptions::Draw dispatch=")),None)
    if options_vtable_trace is None or "vptr=002ebfe0" not in options_vtable_trace or \
            "slots=001fe620/001fe610/001fe600/001fe5f0/" not in options_vtable_trace:
        raise SystemExit(f"original OPTIONS vtable did not expose the expected 1.1 method thunks: {options_vtable_trace!r}")
    if options_update_trace is None or "ok=1" not in options_update_trace or \
            "eip=0005af12" not in options_update_trace or "esp=003ff004" not in options_update_trace or \
            "icalls=1" not in options_update_trace or "targets=001fe600/" not in options_update_trace or \
            "unexpected=0" not in options_update_trace or "current=00360034 pending=00000000" not in options_update_trace:
        raise SystemExit(f"original IFCOptions::Update dispatch did not return cleanly: {options_update_trace!r}")
    options_campaign=os.environ.get("GWRECOMP_IFCOPTIONS_CAMPAIGN")=="1"
    options_draw_return="eip=000834c0" if options_campaign else "eip=00083559"
    if options_draw_trace is None or "ok=1" not in options_draw_trace or \
            options_draw_return not in options_draw_trace or "esp=003ff004" not in options_draw_trace or \
            "icalls=2" not in options_draw_trace or "targets=001fe5f0/" not in options_draw_trace or \
            "WScreen_writes=" not in options_draw_trace or "unexpected=0" not in options_draw_trace:
        raise SystemExit(f"original IFCOptions::Draw dispatch did not return cleanly: {options_draw_trace!r}")
    options_surface=ROOT/"evidence"/"native_ifcoptions_draw_wscreen.raw"
    options_sdl=ROOT/"evidence"/"native_ifcoptions_draw_sdl.bmp"
    title_surface=ROOT/"evidence"/"native_ifctitle_draw_wscreen.raw"
    if not options_surface.exists() or options_surface.stat().st_size!=640*480 or \
            not options_sdl.exists() or not title_surface.exists():
        raise SystemExit("original IFCOptions Draw surface/capture is missing or has an invalid size")
    options_surface_bytes=options_surface.read_bytes()
    if len(set(options_surface_bytes))<2 or options_surface_bytes==title_surface.read_bytes():
        raise SystemExit("original IFCOptions Draw did not produce distinct, non-uniform WScreen bytes")
    options_palette_path=ROOT/"evidence"/"native_ifcoptions_draw_palette6.raw"
    if not options_palette_path.exists() or options_palette_path.stat().st_size!=768:
        raise SystemExit("original VGA DAC palette capture is missing before OPTIONS presentation validation")
    palette_bytes=options_palette_path.read_bytes()
    sys.path.insert(0,str(ROOT/"tests"))
    from test_authentic_titlescreen import verify_capture
    verify_capture(options_sdl,options_surface_bytes,palette_bytes)
    options_cycle_evidence={"schema":"gw-native-ifcoptions-cycle/v1","target_sha256":EXPECTED_TARGET,
        "execution":"original recompilation partial closure; bounded experimental guest/VBE profile",
        "state_source":"currentIFC and vtable published by the original game() pending-interface block and IFCOptions::PlugIn",
        "vtable_trace":options_vtable_trace,
        "methods":{"Update":{"link":"0x6AB30","original_adjustment_thunk":"0x13600",
                    "dispatch":"original control_game virtual slot +8","trace":options_update_trace},
                   "Draw":{"link":"0x6A700","original_adjustment_thunk":"0x135F0",
                    "dispatch":"original draw_game virtual slot +12","trace":options_draw_trace}},
        "surface":{"guest_pointer":f"0x{int(re.search(r'surface=([0-9A-Fa-f]+)',options_draw_trace).group(1),16):08X}" if re.search(r'surface=([0-9A-Fa-f]+)',options_draw_trace) else "unresolved",
                    "width":640,"height":480,"pitch":640,"format":"8-bit indexed",
                    "bytes":len(options_surface_bytes),"sha256":sha(options_surface),
                    "non_uniform_values":len(set(options_surface_bytes)),
                    "distinct_from_title":True},
        "presentation":{"path":str(options_sdl.relative_to(ROOT)),"sha256":sha(options_sdl),
            "verified_against_guest_surface_and_palette":True},
        "limitations":["The run begins from the bounded initialized title state and transitions through the original game() interface switch; it is not a natural DOS/4GW boot.",
            "VBE profile remains experimental. The image is produced by original IFCOptions::Draw and shown from its WScreen bytes; no claim of interactive controls or natural framebuffer is made."],
        "passed":True}
    options_cycle_path=ROOT/"evidence"/"native_ifcoptions_cycle.json"
    options_cycle_path.write_text(json.dumps(options_cycle_evidence,indent=2)+"\n",encoding="utf-8")
    draw_diff_path=ROOT/"evidence"/"native_ifctitle_draw_memory_diff.json"
    draw_diff=json.loads(draw_diff_path.read_text(encoding="utf-8"))
    if (draw_diff.get("changed_bytes",0)!=len(draw_diff.get("changes",[])) or
            draw_diff.get("changed_bytes",0)==0):
        raise SystemExit("original IFCTitle::Draw memory-diff capture is missing or inconsistent")
    wscreen_guest=int(re.search(r"WScreen=([0-9a-fA-F]+)",memory_table_trace).group(1),16)
    draw_wscreen_changed=sum(1 for row in draw_diff["changes"]
        if wscreen_guest<=int(row["guest"],16)<wscreen_guest+0x4B000)
    trace_wscreen=re.search(r"wscreen_writes=(\d+)",draw_trace)
    if not trace_wscreen or int(trace_wscreen.group(1))!=draw_wscreen_changed or draw_wscreen_changed==0:
        raise SystemExit("Draw WScreen writes disagree with the byte-level memory diff")
    draw_surface=ROOT/"evidence"/"native_ifctitle_draw_wscreen.raw"
    draw_palette=ROOT/"evidence"/"native_ifctitle_draw_palette6.raw"
    draw_palette_source=ROOT/"evidence"/"native_ifctitle_draw_palette_source.raw"
    draw_sdl=ROOT/"evidence"/"native_ifctitle_draw_sdl.bmp"
    surface_bytes=draw_surface.read_bytes()
    palette_bytes=draw_palette.read_bytes()
    palette_source_bytes=draw_palette_source.read_bytes()
    known_palette=ROOT/"evidence"/"genewars_11_titlescreen_dac6.raw"
    if (len(surface_bytes)!=640*480 or len(palette_bytes)!=768 or any(x>63 for x in palette_bytes) or
            len(palette_source_bytes)!=768):
        raise SystemExit("captured original Draw surface or 6-bit DAC palette has invalid dimensions/data")
    if bytes(x&0x3F for x in palette_source_bytes)!=palette_bytes:
        raise SystemExit("captured VGA DAC does not match the loaded original data/main.pal resource")
    if len(set(surface_bytes))<2:
        raise SystemExit("original Draw WScreen surface is uniform")
    sys.path.insert(0,str(ROOT/"tests"))
    from test_authentic_titlescreen import verify_capture
    verify_capture(draw_sdl,surface_bytes,palette_bytes)
    baseline_diff_pixels=None
    palette_reference=known_palette.read_bytes()
    palette_reference_differences=sum(a!=b for a,b in zip(palette_bytes,palette_reference))
    observed_ctor_dispatches=[json.loads(line.removeprefix("TRACE ctor_array "))
        for line in executed.stdout.splitlines() if line.startswith("TRACE ctor_array {")]
    if (sum(row["count"] for row in observed_ctor_dispatches)!=2156 or
            {int(row["target_link"],16) for row in observed_ctor_dispatches}!=set(ctor_array_targets) or
            any(not row["mapped_code"] for row in observed_ctor_dispatches)):
        raise SystemExit(f"constructor-array runtime destinations disagree with verified executable fixups: {observed_ctor_dispatches}")
    manager_record=ROOT/"work"/"lbdataload_iftitle.bin"
    output=ROOT/"work"/"lbdataload_rnc_out_of_place.bin"
    screen_input=ROOT/"work"/"ifctitle_plugin_titlescr_input.bin"
    screen_output=ROOT/"work"/"ifctitle_plugin_bscreen.raw"
    if not manager_record.exists() or manager_record.stat().st_size!=0xE349:
        raise SystemExit("original LbDataLoad_ did not leave the 58,185-byte expanded resource")
    if not output.exists() or output.stat().st_size!=0xE349:
        raise SystemExit("original UnpackM1 differential did not leave the 58,185-byte IFTITLE output")
    if (not screen_input.exists() or screen_input.stat().st_size!=139405 or
            sha(screen_input)!=EXPECTED_TITLE_SCREEN or not screen_output.exists() or
            screen_output.stat().st_size!=0x4B000):
        raise SystemExit("full original PlugIn did not preserve the exact TITLESCR input and 307,200-byte b_screen output")
    output_hash=sha(output)
    manager_record_hash=sha(manager_record)
    expected_decoded="f5537949f249fc4f84e265768a4a8af981d5db02604a67371bb70dab3f40e7bc"
    independent_reference=ROOT/"work"/"iftitle_independent_rnc.raw"
    packed_capture=ROOT/"work"/"lbdataload_relocated_rnc_payload.bin"
    compressed_capture=ROOT/"work"/"lbdataload_compressed_capture.bin"
    packed=packed_capture.read_bytes() if packed_capture.exists() else b""
    compressed=compressed_capture.read_bytes() if compressed_capture.exists() else b""
    payload_matches=bool(compressed and len(packed)==int.from_bytes(compressed[8:12],"big") and
                         packed==compressed[18:18+len(packed)])
    attempt={"schema":"gw-authentic-lbdataload-iftitle-attempt/v2",
        "target_sha256":EXPECTED_TARGET,
        "resource":{"path":str(RESOURCE),"physical_bytes":RESOURCE.stat().st_size,
            "sha256":EXPECTED_RESOURCE,"provenance":"protected exact-build local installation"},
        "analysis":{"provider":"REA 6.4.0 / Ghidra 12.1.4 mapped PE carrier, corroborated against canonical LE and Capstone",
            "mygadgets_manager_FUN_A8ED0_REA":"ev_91a5692f5df581c6c87e02ac8196f6a3f63cdb34986ab3a5bdd96b6f8455db5c",
            "mygadgets_hit_test_FUN_A8DD0_REA":"ev_38e658535b9f58c3420a0ad42427213af18983650ed4ca6f139d8d817d604c91",
            "vga_retrace_wait_REA":"ev_2dc55b7af08c4e5d3f9747abd984c7d44733623e3cb3068d59a358764404688c",
            "LbDataLoad":"ev_9affbb5dc8c29e635944c38a397a2508a123a84b0b230de1f0ed09007ec05106",
            "resource_manager":"ev_ee2750127b20331b0431ae27a3fb771d80bc8d73ae708428f65d7186bf4d02cf",
            "RNC_in_place":"ev_76c7a20f069c769103dd3c77ad575fcb587297c25db66522ef0e7a5e45b24ead",
            "allocator":"ev_33b4145d4aa170a176a37c6522aed9e18d2e15a5e8f19fa7524c1ca289319ce"},
        "execution":{"entry":"original init 0x830F0 -> IFCTitle::PlugIn 0x70D10..0x70E2C -> LbDataLoadAll_ 0x15090 -> LbDataLoad_ 0x14FF0 -> FUN_989EC 0x989EC",
            "callback":"original 0x14E94 initializer slice installs original 0x14BB0; full FUN_14BF0 config parser was not run",
            "memory_profile":"bounded experimental 0x03002000 guest map; not Oracle equivalence",
            "vfs":{"requested_records":["data/iftitle.anb","data/titlescr.pal","data/font2.dat","data/font2.tab"],
                "return_code":"LbDataLoadAll_ returned zero resource errors","file_bytes_sha256":hashlib.sha256(compressed).hexdigest()},
            "loaded_records":[
                {"path":"data/iftitle.anb","guest":"0x01001030","bytes":58185},
                {"path":"data/titlescr.pal","guest":"0x03001038","bytes":768},
                {"path":"data/font2.dat","guest":"0x0100F57C","bytes":44647},
                {"path":"data/font2.tab","guest":"0x03001538","bytes":1170}],
            "allocator":{"original_functions":["LbMemorySetup_ 0x921F0","LbMemoryAlloc_ 0x91E00"],
                "first_start":"0x01001030","expanded_length":0xE349},
        "rnc":{"original_function":"UnpackM1_ 0xB9CFC","args":{"eax":"0x01001030","ecx":"0x01001030","edx":"0x01001030"},
            "output_sha256":output_hash,"independent_rnc1_reference_sha256":expected_decoded,
            "manager_loaded_iftitle_sha256":manager_record_hash,
            "independent_reference":{"kind":"read-only Python RNC1 decoder and CRC check from GeneWarsFX evidence tree",
                "script":(_GW_FX.replace("\\","/") + '/work/phase2v_rnc1_probe.py'),"input_sha256":EXPECTED_RESOURCE,
                "output_sha256":sha(independent_reference) if independent_reference.exists() else None,
                "header_unpacked_crc":"0x31de","decoder_unpacked_crc":"0x31de"},
                "relocated_payload_matches_original":payload_matches,
            "relocated_payload_bytes":len(packed),"status":"matched independent RNC1 output"}},
        "limitations":["Earlier expected hash 4ea6... came from a recompilation using incorrect REP overlap semantics and is superseded by the independent RNC1 decode plus matching header CRC.",
            "Full PlugIn body is run in an experimental VBE/allocator state; Update/Draw, menu, Oracle and natural DOS/4GW replay are not run."],"passed":False}
    evidence_path=ROOT/"evidence"/"native_ifctitle_creature_probe_attempt.json"
    evidence_path.write_text(json.dumps(attempt,indent=2)+"\n",encoding="utf-8")
    print(f"evidence: {evidence_path}")
    if output_hash!=expected_decoded or not independent_reference.exists() or sha(independent_reference)!=expected_decoded or not payload_matches:
        raise SystemExit(f"original UnpackM1 output did not match the independent RNC1 reference: {output_hash}")
    attempt["passed"]=True
    attempt["execution"]["original_text_initialization"]={
        "resource_record":"0x002DE104 (LE 0x00104104, object 3 delta +0x001DA000)",
        "loader":"original LbDataLoadAll_ 0x15090 -> LbDataLoad_ 0x14FF0 -> DOS/VFS reads",
        "path":"data/text.dat","bytes":38632,"sha256":resource_inputs["DATA/TEXT.DAT"]["sha256"],
        "payload_guest":"0x01001030","pointer_table_guest":"0x002EECAC",
        "parser":"original FUN_000955E0, EBX=626","strings":text_string_traces,
        "text_clip_initializer":"original FUN_0006EE60; setup_game caller 0x94E84",
        "text_clip_trace":text_clip_trace,
        "text_clip_guest_fields":"0x002EE8E4..0x002EE8F8 = (0,0)-(640,480), extent 640x480",
        "draw_callsite_guest_surface_changed_bytes":{f"0x{k:08X}":v for k,v in glyph_write_sites.items()},
        "state":"original resource load, string pointer construction and clip-window writes executed; no text pointers or bounds seeded by the harness"}
    attempt["execution"]["original_ifctitle_update"]={"trace":update_trace,"memory_diff":str(update_diff_path),
        "changed_bytes":update_diff["changed_bytes"],"dispatch":"0x5AF12 -> thunk 0x13700 -> Update 0x70EB0",
        "draw_executed":True,"input_injected":True}
    attempt["execution"]["original_menu_mouse_input"]={
        "events":"SDL motion, left down, left up at host (626,528), scaled to guest (313,264)",
        "device_boundary":"lbDisplay MMouseX/Y and LeftButton/MLeftButton only; original setup_controller 0x5B170 translated them",
        "cycles":ui_traces,
        "gadget":"MyGadget[2], id=3 (OPCIONES), verified 40-byte records and hit-tested by original FUN_000A8ED0/FUN_000A8DD0",
        "activation":"original IFCTitle::Update 0x70EB0 switched on result ID 3 at LE block 0x7102C after release",
        "switch_table_object1_link":"0x70E9C",
        "case3_target_guest":f"0x{update_targets[3]:08X}",
        "case3_target_link":f"0x{options_target_link:08X}",
        "transition_request":{"pending_interface":"0x00360034","pullout_interface":"0x0035EAD8","current_interface":"0x0035EAD8"},
        "pending_interface_dispatch":pending_ifc_trace,
        "opened_options":True,"plugin_returned":True,
        "blocked_by":None,"next":"verify OPTIONS Update/Draw prerequisites; the authenticated memory-table state leaves the optional VESA pointer null in this experimental profile"}
    run_output=executed.stdout+"\n"+executed.stderr
    # Preserve the bounded replay and verify both causal stages: setup_game sets
    # its own BIOINTRO gate, then original TITLE::Update takes the set-bit route
    # and publishes a pending interface without reaching exit_.
    diagnostic_stdout=ROOT/"evidence"/"native_setupgame_biointro_new_game.stdout.log"
    diagnostic_stderr=ROOT/"evidence"/"native_setupgame_biointro_new_game.stderr.log"
    diagnostic_stdout.write_text(executed.stdout,encoding="utf-8")
    diagnostic_stderr.write_text(executed.stderr,encoding="utf-8")
    trace_rows=run_output.splitlines()
    setup_pass=next((line for line in trace_rows if line.startswith(
        "PASS original setup_game 0x94AC0 prefix checked INTRO/BIOINTRO.SMK:")),None)
    click_pass=next((line for line in trace_rows if line.startswith(
        "PASS original TITLE::Update accepted UN JUGADOR through SDL and published constructor-initialized IFCLevel subobject")),None)
    level_ctor_trace=next((line for line in trace_rows if line.startswith(
        "TRACE original IFCLevel constructor state ")),None)
    level_object_trace=next((line for line in trace_rows if line.startswith(
        "TRACE original IFCLevel object ")),None)
    level_transition_trace=next((line for line in trace_rows if line.startswith(
        "TRACE original game() TITLE->IFCLevel transition ")),None)
    level_update_trace=next((line for line in trace_rows if line.startswith(
        "TRACE original IFCLevel::Update dispatch=")),None)
    level_draw_trace=next((line for line in trace_rows if line.startswith(
        "TRACE original IFCLevel::Draw dispatch=")),None)
    level_palette_fade_trace=next((line for line in trace_rows if line.startswith(
        "PASS original draw_game IFCLevel type-2 tail 0x83A0C -> LbPaletteFade_ 0xA26F0")),None)
    level_palette_load_trace=next((line for line in trace_rows if line.startswith(
        "TRACE original IFCLevel palette file=data/levscr01.pal ")),None)
    branch_taken=next((line for line in trace_rows if line.startswith("TRACE guest-branch-watch ") and
        "kind=jcc-taken" in line and "site=00070eed" in line and "target=00070f0f" in line),None)
    exit_call=[line for line in trace_rows if line.startswith("TRACE guest-call-history ") and
        "site=00070f05" in line]
    if (executed.returncode!=0 or setup_pass is None or click_pass is None or
            branch_taken is None or exit_call or any(line.startswith(
                "TRACE guest-exit-boundary ") for line in trace_rows)):
        diagnostic={"schema":"gw-setupgame-biointro-new-game-replay/v1",
            "target_sha256":EXPECTED_TARGET,"exit_code":executed.returncode,
            "setupgame_pass":setup_pass,"new_game_pass":click_pass,
            "availability_branch_taken":branch_taken,"unexpected_exit_call_history":exit_call,
            "stdout_log":str(diagnostic_stdout.relative_to(ROOT)),"stdout_sha256":sha(diagnostic_stdout),
            "stderr_log":str(diagnostic_stderr.relative_to(ROOT)),"stderr_sha256":sha(diagnostic_stderr),
            "classification":"bounded replay did not prove both the original BIOINTRO producer and New Game availability branch"}
        (ROOT/"evidence"/"native_setupgame_biointro_new_game_diagnostic.json").write_text(
            json.dumps(diagnostic,indent=2)+"\n",encoding="utf-8")
        raise SystemExit("setup_game BIOINTRO/New Game replay proof incomplete; bounded logs saved")
    if (level_ctor_trace is None or level_object_trace is None or level_transition_trace is None or
            "current=00360a11 pending=00000000 unexpected_writes=0" not in level_transition_trace.lower() or
            level_update_trace is None or level_draw_trace is None or level_palette_fade_trace is None or
            "changed_WScreen=" not in level_draw_trace or "unexpected_writes=0" not in level_draw_trace):
        raise SystemExit("the original IFCLevel constructor/transition/first Update+Draw cycle was not all proven")
    if "type=2 dirty=0->1" not in level_palette_fade_trace or \
            "DAC_components=13056 final_palette_matches_source=1" not in level_palette_fade_trace:
        raise SystemExit(f"original IFCLevel palette fade did not apply its current palette: {level_palette_fade_trace!r}")
    if (level_palette_load_trace is None or
            "source=010000f0" not in level_palette_load_trace.lower() or
            "guest=002eec9c current=010000f0" not in level_palette_load_trace.lower()):
        raise SystemExit(f"the original level palette record did not publish its decoded buffer through W?palette$npnuc: {level_palette_load_trace!r}")
    palette_source_match=re.search(r"source=([0-9a-fA-F]+)",level_palette_fade_trace)
    if palette_source_match is None:
        raise SystemExit(f"original draw_game palette source is absent from its trace: {level_palette_fade_trace!r}")
    dpmi_0300_sb16=next((line for line in trace_rows if line.startswith(
        "TRACE setup_game DPMI 0300 frame vector=66 ") and "AX=00000303" in line),None)
    sb16_0303_result=next((line for line in trace_rows if line.startswith(
        "TRACE native SB16.DIG INT66 AX0303 executed-verified-entry ")),None)
    if (dpmi_0300_sb16 is None or "frame=valid" not in dpmi_0300_sb16 or
            sb16_0303_result is None or "table[3]=07ed" not in sb16_0303_result.lower() or
            "result_ax=0220" not in sb16_0303_result.lower()):
        raise SystemExit("the original AX=0300/vector-66 bridge did not complete the verified SB16.DIG AX=0303 request")
    startup_files_trace=next((line for line in trace_rows if line.startswith(
        "PASS original setup_game startup_files block=002dd554 data/b32a.dat->block_mem")),None)
    pl1_read_trace=next((line for line in trace_rows if line.startswith(
        "TRACE original VFS read path='C:\\GENEWARS\\data/pl1.dat'") and "guest=02224c2c" in line),None)
    mcb_audit_path=ROOT/"evidence"/"native_ifclevel_low_write_audit.json"
    mcb_audit=json.loads(mcb_audit_path.read_text(encoding="utf-8"))
    initial_mcb_trace=next((line for line in trace_rows if line.startswith(
        "PASS DOS MCB chain valid at setup_game entry")),None)
    if (startup_files_trace is None or pl1_read_trace is None or
            initial_mcb_trace is None or not mcb_audit.get("initial_mcb_chain_valid") or
            not mcb_audit.get("final_mcb_chain_valid") or
            mcb_audit.get("unexpected_writes")!=0 or
            mcb_audit.get("expected_host_BDA_timer_bytes")!=2 or
            mcb_audit.get("bytes_without_guest_store_site")!=2 or
            mcb_audit.get("changed_bytes_below_0x90000")!=2):
        raise SystemExit("startup block backing, pl1.dat destination, or final MCB audit did not validate")
    trace_path=ROOT/"evidence"/"native_setupgame_biointro_new_game.log"
    trace_path.write_text("\n".join(trace_rows)+"\n",encoding="utf-8")
    setupgame_evidence={"schema":"gw-native-setupgame-biointro-new-game/v1",
        "target_sha256":EXPECTED_TARGET,
        "execution":"bounded native recompilation with experimental DOS/VBE profile",
        "setupgame_prefix":{"entry":"0x94AC0","last_original_call":"0x94C8E CALL 0xAFF18",
            "stop_boundary":"0x94C93; synthetic RET after original file close",
            "biointro":{"path":"INTRO/BIOINTRO.SMK","size":24897308,"sha256":EXPECTED_BIOINTRO,
                "size_compare":"0x94C7E CMP EAX,0x017BE71C",
                "availability_store":"0x94C85 OR byte ptr [0x117662],1"},
            "trace":setup_pass,"availability_bit_before":"0x00","availability_bit_after":"0x01",
            "state_source":"the original LbMemorySetup_ created the tracked *SCRATCH backing before this call; the harness did not seed the gate"},
        "new_game":{"input":"SDL mouse click on original TITLE gadget id=0","update":"0x70EB0",
            "availability_branch":"0x70EED JNE 0x70F0F","taken_trace":branch_taken,
            "exit_callsite":"0x70F05","exit_call_observed":False,"trace_ifc":click_pass},
        "ifclevel":{"constructor_state":level_ctor_trace,"pending_object":level_object_trace,
            "game_transition":level_transition_trace,"update":level_update_trace,"draw":level_draw_trace,
            "level_palette_fade":level_palette_fade_trace,
            "level_palette_load":level_palette_load_trace,
            "palette_path":{"original_draw_game_tail_link":"0x83A0C",
                "resource":"data/levscr01.pal","decoded_buffer":"0x010000F0",
                "global_symbol":"W?palette$npnuc","global_link":"0x00114C9C",
                "global_guest":"0x002EEC9C","global_value":"0x010000F0",
                "fade_source_guest":"0x"+palette_source_match.group(1).lower(),
                "fade_source_bytes_match_decoded_resource":True,
                "interface_type":2,"dirty_byte":"0x00360A12","palette_pointer":"currentIFC+2",
                "original_fade":"LbPaletteFade_ 0xA26F0 -> LbPaletteSet_ 0xADEAC",
                "dac_component_writes":13056,"final_DAC_matches_interface_palette":True},
            "identity":{"class":"IFCLevel","object_link":"0x1869F1 (MAP has no public object label)",
                "interface_subobject_link":"0x186A11 = object +0x20","vtable_link":"0x111AD4",
                "map_symbol":"0x111AE4 W?$Wvf0eo2i8:IFCLevel$$nx[]pn()v",
                "methods":{"PlugIn":"0x15710","PullOut":"0x15CF0","Draw":"0x177C0","Update":"0x179F0"},
                "fixup_backed_thunks":{"PlugIn":"0x1B650","PullOut":"0x1B640","Update":"0x1B630","Draw":"0x1B620"}},
            "screen":{"raw":"evidence/native_ifclevel_new_game_wscreen.raw",
                "raw_sha256":sha(ROOT/"evidence"/"native_ifclevel_new_game_wscreen.raw"),
                "palette_dac6":"evidence/native_ifclevel_new_game_palette6.raw",
                "palette_sha256":sha(ROOT/"evidence"/"native_ifclevel_new_game_palette6.raw"),
                "sdl_capture":"evidence/native_ifclevel_new_game_sdl.bmp",
                "sdl_capture_sha256":sha(ROOT/"evidence"/"native_ifclevel_new_game_sdl.bmp"),
                "provenance":"first IFCLevel::Draw WScreen in experimental VBE profile; not a natural boot frame"}},
        "replay":{"instruction_budget":110000000,
            "process_exit_code":executed.returncode,
            "setup_game_startup_files":startup_files_trace,
            "pl1_dat_read":pl1_read_trace,
            "dos_ah3f_host_write_audit":"evidence/native_dos_ah3f_host_write_audit.json",
            "low_memory_audit":"evidence/native_ifclevel_low_write_audit.json",
            "stdout_log":str(diagnostic_stdout.relative_to(ROOT)),"stdout_sha256":sha(diagnostic_stdout),
            "stderr_log":str(diagnostic_stderr.relative_to(ROOT)),"stderr_sha256":sha(diagnostic_stderr),
            "trace":"evidence/native_setupgame_biointro_new_game.log","trace_sha256":sha(trace_path),
            "audio_bridge":{"outer_service":"INT 31h AX=0300 simulate real-mode interrupt",
                "outer_vector":"0x66","driver_request":"INT 66h AX=0303",
                "driver_entry":"SB16.DIG dispatch table[3] -> 0x07ED",
                "driver_result_AX":"0x0220","outer_frame_trace":dpmi_0300_sb16,
                "driver_result_trace":sb16_0303_result,
                "DPMI_AX0303_service_added":False}},
        "natural_boot_claimed":False,"passed":True}
    (ROOT/"evidence"/"native_setupgame_biointro_new_game.json").write_text(
        json.dumps(setupgame_evidence,indent=2)+"\n",encoding="utf-8")
    attempt["execution"]["setup_game_biointro_prefix"]=setupgame_evidence["setupgame_prefix"]
    attempt["execution"]["new_game_availability_branch"]=setupgame_evidence["new_game"]
    attempt["execution"]["original_ifctitle_draw"]={"trace":draw_trace,"memory_diff":str(draw_diff_path),
        "changed_bytes":draw_diff["changed_bytes"],"dispatch":"0x83559 -> thunk 0x136F0 -> Draw 0x710B0",
        "input_injected":True,"deferred_A8CD0_callbacks_reached":False,
        "surface":{"guest":f"0x{wscreen_guest:08X}","dimensions":[640,480],"pitch_bytes":640,
            "format":"8-bit palette indices","changed_surface_bytes":draw_wscreen_changed,
            "sha256":sha(draw_surface),"palette_source_sha256":sha(draw_palette_source),
            "palette_dac6_sha256":sha(draw_palette),"reference_dac6_sha256":sha(known_palette),
            "dac_components_differing_from_prior_title_pipeline":palette_reference_differences,
            "sdl_capture":str(draw_sdl.relative_to(ROOT)),"sdl_capture_sha256":sha(draw_sdl),
            "same_run_text_surface_proof":text_surface_delta_proof,
            "presented_buffer":"WScreen bytes produced by original Draw; no harness pixel writes"}}
    attempt["execution"]["original_game_interface_transition"]={
        "block_link":"0x92819..0x9283B","abi_trace":transition_abi_trace,"trace":transition_trace,
        "current_ifc_pullout_target":"0x001FE710 (original adjustment thunk to IFCTitle::PullOut 0x70E30)",
        "pending_ifc_plugin_target":"0x001FE620 (verified IFCOptions adjustment thunk to PlugIn 0x6A3D0)",
        "pullout_vga_palette_snapshot":pullout_dac_trace,
        "pullout_vga_retrace_wait":pullout_retrace_trace,
        "result":"The original setup_game prefix ran its BIOINTRO size check and set the availability bit. The original OPTIONS->TITLE game() transition completed with zero unexpected writes. An SDL click on the original TITLE id=0 gadget executed IFCTitle::Update and published pending interface 0x00360A11; the watched JNE at 0x70EED bypassed the exit_ call at 0x70F05. This is a bounded experimental VBE profile, not a natural DOS/4GW boot.",
        "resources":{**save_evidence(resource_inputs,"original OPTIONS PlugIn/DOS VFS"),
            "missing_save_slots":{"count":14,"paths":"C:\\GENEWARS\\SAVE\\SAVE1.SAV..SAVE7.SAV","per_slot":2,"result":"DOS file-not-found (AX=2); absent slots verified in read-only install"}},
        "scratch_allocation":{"guest_global":"0x002EECA8 (LE 0x00114CA8)","pre_table_value":"0x00000000",
            "guest_pointer":"0x000090C8","descriptor":"*SCRATCH at LE 0x1040AC","size_bytes":0x2000,
            "allocation_trace":memory_table_trace,"backing":"live DOS MCB ledger","invalid_writes":0},
        "memory_profile":{"WScreen":"0x0200B920, 640x480x8 backed by the live DPMI region","VESA":"null in this experimental state; not needed to complete PlugIn; do not infer authentic VESA setup"},
        "pending_cleared":True,"plugin_returned":True,"options_opened":True,
        "options_update_draw_attempted":False,"unexpected_guest_writes":0,
        "low_write_count":0,"low_write_eips":[],
        "transition_capture":"evidence/native_ifctitle_creature_probe.json",
        "rea":REA_OPTIONS_TRANSITION}
    attempt["limitations"]=["The callback installer was the exact original 0x14E94 slice; full FUN_14BF0 config parsing was not run.",
        "This bounded replay executes the original setup_game prefix through the BIOINTRO availability store, then follows the TITLE id=0 input route. It proves the branch around exit_ but does not enter a natural full game boot or the Watcom destructor chain.",
        "The bounded SDL sequence reached TITLE-to-OPTIONS, OPTIONS Update/Draw, OPTIONS-to-TITLE, and the UN JUGADOR pending-interface request. The setup_game memory table allocated formatter scratch in a tracked DOS MCB block; the interface transition reported zero unexpected writes. VESA remains null in this profile.",
        "SAVE0.SAV was read-only through the original loader/VFS. The run reported zero missing save slots; it makes no claim that other save slots are absent.",
        "b_screen came from the original size calculation, allocator call, and store block using dimensions initialized by LbScreenSetup_ under the explicit experimental VBE profile.",
        "The full game loop, OPTIONS interface rendering, Oracle, and natural DOS/4GW replay were not run."]
    evidence_path.write_text(json.dumps(attempt,indent=2)+"\n",encoding="utf-8")
    print(f"PASS original UnpackM1 output matches independent RNC1 output and CRC: {output_hash}")
    evidence={"schema":"gw-native-ifctitle-plugin-load-at/v1","target_sha256":EXPECTED_TARGET,
        "resource":{"path":str(RESOURCE),"size":RESOURCE.stat().st_size,"sha256":EXPECTED_RESOURCE,
                    "provenance":"exact local installation, protected read-only input"},
        "title_resource_inputs":resource_inputs,
        "analysis":{"provider":"REA 6.4.0 / Ghidra 12.1.4 on mapped PE carrier; original LE path/calls checked independently with Capstone",
            "rea_options_transition_this_turn":REA_OPTIONS_TRANSITION,
            "game":"ev_2e9c4630d062076a3ec424c279a67f7da7afb6de2731bd5d0df204775f0341da",
            "game_transition_assembly":"ev_e36e24b40abe599d5b031c8ac8eb62e97be6759628dc5b5479928a0c36c4d7a5",
            "game_caller_setup_path":"ev_725122251197e6c6dff6eb9258558454446450156f4183a749936607b72f56d0",
            "pre_game_interface_stage":"ev_bc390af3abc26a924b723e144a286ac23813d6a6e7eb07541b03fc4b92b87b8d",
            "pre_game_current_ifc_helper":"ev_f73e0a028e6cd6a11cea72a4551f845b2d1653c9933c17566c0ba9044e357ef4",
            "control_game":"ev_40e9b4555f2fbb3736e308c31523cfdc19d2ff340ebacccf5228113536654818",
            "draw_game":"ev_706b73c9e74c826f592f232d93b55663f1efa7eadb5262361088d8b64b553e7b",
            "IFCTitle::PlugIn":"ev_a0acd0dc147af656dd9431cd547a7784e18ea466e597be0074895edeb697aa06",
            "LbFileLoadAt_":"ev_92df8018eb097f62da1cd84467c9266999089adf0e5abc7838e33f9f4ffae759",
            "FUN_00097E9C":"ev_06b42f7d2a33885520d059ddd58f390df2d6280c12226d3abfe78c147f93f8ec",
            "FUN_00097DF0":"ev_1b23154aa51434b65e036acb092aa4fd367d66735a6b5e312a37fe7cd7fa415e",
            "LbDataLoad_evidence":"ev_9affbb5dc8c29e635944c38a397a2508a123a84b0b230de1f0ed09007ec05106",
            "LbDataLoadAll_evidence":"ev_a7518b3b876adbad53fed0850489a95fd10726a2f5773c848b76b7da676a8a54",
            "setup_game_text_load_and_clip":"ev_b5cdf5bb4a586ebdaf9611cd9b74a9eee37c3ebc3e2689284cf3f8f01666e484",
            "FUN_00093BD0_parser_call":"ev_3b77e5d64b8a9a9ad231c1c76f3609bcfd514b93f621f795d2c4a563c994b951",
            "FUN_000955E0_text_parser":"ev_8f3f7bc0c0dabd434680d11fd71b5de570cf3820d53adb51b53348e1b32bac4f",
            "FUN_0006EE60_text_clip":"ev_3def114cc06f4fea18a52014033378870ad632a670cc092ace336ad8619243b5",
            "FUN_0006F120_glyph_draw":"ev_87ed2b5b377ca1eade4a44950f70104d09f3c177f5b7297dcdad55a28e2d9741",
            "FUN_0006F900_glyph_blitter":"ev_821e11184aedb1e16b916e5cc3ad8afba241cc0d34a8d9c77d28ef9cdfb29d01",
            "resource_manager_evidence":"ev_ee2750127b20331b0431ae27a3fb771d80bc8d73ae708428f65d7186bf4d02cf",
            "MyGadgets_manager_FUN_A8ED0":"ev_fa23348782ebe7697b1af405ca971d7329b1f3223d17d59096d1e842d3cd654b",
            "MyGadgets_hit_test_FUN_A8DD0":"ev_9652b331ba2bde278cdd92c9cd36a5bf4146cb6580f02c2995575dea668731f6",
            "MyGadgets_manager_FUN_A8ED0_this_turn":"ev_91a5692f5df581c6c87e02ac8196f6a3f63cdb34986ab3a5bdd96b6f8455db5c",
            "MyGadgets_hit_test_FUN_A8DD0_this_turn":"ev_38e658535b9f58c3420a0ad42427213af18983650ed4ca6f139d8d817d604c91",
            "vga_retrace_wait_this_turn":"ev_2dc55b7af08c4e5d3f9747abd984c7d44733623e3cb3068d59a358764404688c",
            "setup_controller_0x5B170":"ev_00799b6126aa4b11a8a32ff09a3fe21034cfe31debe51386348586caf8ed1324",
            "IFCTitle_Update_static":"canonical LE + Capstone; REA carrier has no procedure entry at 0x70EB0",
            "heap_evidence":"ev_b381b14a23444b1753ad6a258cad3c831042037c151ad8098c5597b5c67d4cd5",
            "cs_table_guards":report["indexed_cs_tables"],
            "justify_parse_switch_REA":"ev_f67a109d3450af0ee56f369c939937eaa9ff1ec75a7e3b7b1233e28e5a8fc984",
            "justify_parse_dispatch_REA":"ev_e85458303dc92ae99a90ab039d678e4e7292714c29af4edb10f2bc3efc3a907d",
            "justify_parse_table_REA":"ev_96cb2ea0062b33a0b77fb11b1df0d47274609aabb652a4bdf29bf9bb9afad878",
            "A8CD0_REA":"ev_4c6c9c89dccd81f3fd46cc0dcc87e64ffc24756dbac231e67b40e4fef26a4d8a",
            "A8CD0_indirect_sites_REA":["ev_c15c8273847272f6efb0b5cfe91724548b0acec2490f207e247b07b0f6b55b23",
                "ev_f55e084612d4a0ae478d8001184c527d3365b57de7862215db0f7e216f958f21",
                "ev_6251f04b9330bc6a72fa19c4666947b53869dbb3a25b8f2ec538cbc434af9bc4"],
            "indexed_code_jump_tables":report["indexed_code_jump_tables"],
            "dynamic_calls_deferred":report["deferred_indirect_call_sites"]},
        "execution":{"mode":"original recompiled partial closure","entry":"Watcom initializer 0x830F0 -> LbScreenSetup_ 0x962F0 -> setup_game memory table 0x94DBC -> LbDataLoadAll_ 0x15090 -> original b_screen allocation/store block 0x92B71 -> IFCTitle::PlugIn 0x70D10 -> LbDataLoadAll_ 0x15090 -> LbFileLoadAt_ 0x150D0",
            "original_game_interface_transition":{"block_link":"0x92819..0x9283B","abi_trace":transition_abi_trace,"trace":transition_trace,
                "pullout_target":"0x001FE710 -> IFCTitle::PullOut 0x70E30","pending_plugin_target":"0x001FE620",
            "pending_interface_identity":"IFCOptions (1.1 object/vtable/constructor-byte correspondence; see object_pointer_analysis)",
                "pullout_vga_palette_snapshot":pullout_dac_trace,
                "pullout_vga_retrace_wait":pullout_retrace_trace,
        "result":"setup_game's original LbDataLoadAll_ processed the LE *W_SCREEN/*VESA/*SCRATCH records and its bounded prefix validated BIOINTRO.SMK, setting the availability bit. The native-recompiled interface transition completed PullOut and IFCOptions::PlugIn, returned to TITLE, then an SDL click on id=0 ran IFCTitle::Update through the availability branch and published pending interface 0x00360A11. The observed transitions had zero unexpected writes.",
            "resources":{**save_evidence(resource_inputs,"verified local installation, original OPTIONS PlugIn read"),
                "missing_save_slots":{"count":14,"paths":"C:\\GENEWARS\\SAVE\\SAVE1.SAV..SAVE7.SAV","per_slot":2,"dos_result":"AX=2 file-not-found; each absolute path was requested twice"}},
            "scratch_allocation":{"global_link":"0x00114CA8","global_guest":"0x002EECA8","pre_table_value":"0x00000000","guest_pointer":"0x000090C8","descriptor":"*SCRATCH at LE 0x001040AC","size_bytes":8192,"backing":"live DOS MCB ledger","allocation_trace":memory_table_trace,"unexpected_guest_writes":0},
            "memory_profile":{"WScreen":"0x0200B920; 640x480x8, backed by live DPMI allocation","VESA":"null in this experimental profile; not needed to complete PlugIn"}},
            "original_ifctitle_update":{"dispatch_slice_link":"0x5AF12","control_game_callsite":"0x5AF1A call [EDX+8]",
                "this_adjustment_thunk_link":"0x13700","method_link":"0x70EB0",
                "runtime_guest_targets":["0x001FE700","0x00070EB0"],"trace":update_trace,
                "changed_bytes":update_diff["changed_bytes"],"memory_diff":str(update_diff_path),
                "state":"returned cleanly in bounded experimental PlugIn/VBE state; original mouse-input cycles include the OPCIONES transition request",
                "mouse_input":attempt["execution"]["original_menu_mouse_input"],
                "unexpected_guest_writes":0,
                "draw_executed":True,"full_control_game_executed":False},
            "original_ifctitle_draw":{"dispatch_slice_link":"0x83559","draw_game_callsite":"0x83561 call [EDX+0xC]",
                "this_adjustment_thunk_link":"0x136F0","method_link":"0x710B0",
                "runtime_guest_targets":["0x001FE6F0","0x000710B0"],"trace":draw_trace,
            "palette_application_trace":main_palette_trace,
                "text_call_traces":[line for line in executed.stdout.splitlines()
                    if line.startswith("TRACE title_text_call ")],
                "text_call_finding":"Original setup_game loads DATA/TEXT.DAT; FUN_000955E0 builds the 626-entry string-pointer table and initializes globals 0x2EF0A8/0x2EF0B0/0x2EF0B4/0x2EF0B8. The original setup_game clip call invokes FUN_0006EE60 after screen setup. With those original writes, IFCTitle::Draw's four callsites consume non-null guest strings and produce visible glyph pixels.",
                "text_initialization_trace":text_clip_trace,"text_string_traces":text_string_traces,
                "per_call_guest_surface_writes":glyph_write_traces,
                "changed_bytes":draw_diff["changed_bytes"],"memory_diff":str(draw_diff_path),
                "surface":{"guest":f"0x{wscreen_guest:08X}","width":640,"height":480,"pitch":640,
                    "format":"8-bit indexed; bounded experimental VBE profile","changed_pixel_bytes":draw_wscreen_changed,
                    "sha256":sha(draw_surface),"palette_source_sha256":sha(draw_palette_source),
                    "palette_dac6_sha256":sha(draw_palette),
                    "prior_pipeline_dac6_component_differences":palette_reference_differences,
                    "SDL_capture":str(draw_sdl.relative_to(ROOT)),"SDL_capture_sha256":sha(draw_sdl),
                    "same_run_text_surface_proof":text_surface_delta_proof},
                "A8CD0_deferred_calls_reached":[],"input_injected":True,
                "menu_mouse_input":attempt["execution"]["original_menu_mouse_input"],
                "unexpected_guest_writes":0,"full_control_game_executed":False},
            "constructor_array_dispatches":observed_ctor_dispatches,
            "interface_state_after_plugin":[line for line in executed.stdout.splitlines()
                if line.startswith("TRACE interface globals after PlugIn ")],
            "function_extent":"complete original IFCTitle::PlugIn body 0x70D10..0x70E2C from the generated partial closure; no CFG splice",
            "constructor":{"object_link":"0x00184AB8","object_guest":"0x0035EAB8","first_pointer_after_original_init":"0x002EBA98",
                           "plugin_byte_this_plus_0x20":2,"experimental_runtime_not_Oracle":True},
            "next_original_dispatch":{"game":"0x92710 calls PlugIn then enters a loop gated by GameControl.Flags bit 0",
                "current_interface_global_link":"0x001157E8","pending_interface_global_link":"0x001157EC",
                "control_game":"0x5AE60 indirect call through current IFC slot +0x8",
                "draw_game":"0x834C0 indirect call through current IFC slot +0xC",
                "interface_change":"game() calls current IFC slot +0x4 and pending IFC slot +0x0 when pending interface is set",
                "caller_sequence":"REA at 0x93F30 shows setup_game(0x94AC0) -> 0x92930 -> game(0x92710); 0x92930 plays three Smacker entries then calls 0x756C0, which reads currentIFC",
            "status":"currentIFC was published by original PlugIn; original Update and Draw ran, setup_game's BIOINTRO prefix ran, and the later id=0 Update published a pending interface; the complete game loop remains unexecuted"},
            "object_pointer_analysis":{"first_dword_guest":"0x002EBA98","object3_delta":"0x001DA000",
                "resolved_link_address":"0x00111A98","ghidra_bytes_64":"sha256:8e61714e15489803cb0918704cd5bb1045b323ebfd96ab57e0d8eada5556a965/64",
                "address_name":"none","ghidra_read_bytes_evidence":"ev_178c2f4ad299816d03d303c9e4bde6608293fc7e340c9f7a807ea9688b68b642",
                "nearby_ifclevel_vtable":{"link_address":"0x00111AE4","map_symbol":"W?$Wvf0eo2i8:IFCLevel$$nx[]pn()v",
                    "methods":["0x00015710","0x00015CF0","0x000177C0","0x000179F0"],
                    "ghidra_bytes_evidence":"ev_4d22c7e8c6dd13d39e122d88a7ef26df146f01f9a55552d1d2674fe18f240357"},
                "conclusion":"0x111A98 is 0x4C before the MAP-identified IFCLevel method table; the first IFCTitle object pointer is not labeled a vtable without further layout evidence."},
            "resource_manager":"FUN_000989EC","callback":"original 0x14E94 slice sets LE-fixed 0x14BB0 via original 0x989E0",
            "memory_profile":"experimental bounded DOS/4GW guest map 0x03002000; not Oracle equivalence",
            "vfs":"allowlisted read-only exact-build resource; DOS open/read/close services",
            "title_screen":{"input":"DATA/TITLESCR.DAT","input_bytes":screen_input.stat().st_size,
                "input_sha256":sha(screen_input),"destination":"b_screen guest 0x01001030",
                "destination_bytes":screen_output.stat().st_size,"destination_sha256":sha(screen_output),
                "producer":"original LbFileLoadAt_ and original UnpackM1_ during complete IFCTitle::PlugIn"},
            "expanded_size":output.stat().st_size,"expanded_sha256":output_hash,
            "stdout":executed.stdout.strip()},
        "regression_reference":{"prior_original_file_pipeline_sha256":expected_decoded,
            "prior_test":"tests/test_recompiled_iftitle_pipeline.py; separate original LbFileRead_ + original UnpackM1_ run"},
        "limitations":["No natural DOS/4GW replay or Oracle claim; VBE used the explicit host-emulated 0x101 profile.",
            "SDL mouse events were adapted at lbDisplay and processed by original setup_controller and IFCTitle::Update. The run completed original TITLE/OPTIONS Update/Draw and OPTIONS->TITLE PullOut/PlugIn; the later id=0 click bypassed exit_ and published the next pending interface. The VESA pointer remains null in this experimental state.",
            "SAVE0.SAV was read-only through the original VFS; this run reports zero missing save slots and makes no claim about other save files.",
            "The b_screen block is authentic original code isolated from its PlaySmacker caller; natural call-order provenance is not claimed.",
            "REA's PE carrier and the original LE serve different address/byte authorities; function-body claims above were cross-checked with canonical LE/Capstone rather than treating the carrier as an LE loader.",
            "The closure report lists deferred indirect callsites; this test does not attribute the 165 runtime indirect dispatches to those static sites."],"passed":True}
    path=ROOT/"evidence"/"native_ifctitle_creature_probe.json"
    path.write_text(json.dumps(evidence,indent=2)+"\n",encoding="utf-8")
    print(f"evidence: {path}")

if __name__=="__main__": main()
