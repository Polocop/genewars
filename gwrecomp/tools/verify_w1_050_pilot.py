"""Fail-closed validator for W1-050's native startup evidence (read-only)."""
import argparse
import json
import hashlib
import pathlib
import re
import sys

HEX64 = re.compile(r"^[0-9a-f]{64}$")
ROOT = pathlib.Path(__file__).resolve().parents[1]


def validate(data, target_sha256=None, project_root=None):
    errors=[]
    if data.get("schema") != "gwrecomp.native-setup-replay/v1": errors.append("schema must be gwrecomp.native-setup-replay/v1")
    if data.get("execution_mode") != "native_recompiled_guest": errors.append("execution_mode must identify the native recompiled guest")
    if data.get("evidence_level") != "DIFF_VERIFIED": errors.append("evidence_level must be DIFF_VERIFIED")
    for key in ("target_sha256",):
        if not HEX64.fullmatch(str(data.get(key,""))): errors.append(f"{key} must be a SHA-256")
    if target_sha256 and data.get("target_sha256") != target_sha256: errors.append("capture target hash is stale for the current GeneWars 1.1 target")
    for key in ("build_id","fixture_id","capture_id","captured_at"):
        if not data.get(key): errors.append(f"{key} is required")
    build=data.get("build_artifact",{})
    if not build.get("path") or not HEX64.fullmatch(str(build.get("sha256",""))) or data.get("build_id")!=build.get("sha256"):
        errors.append("build_id must be the SHA-256 fingerprint of a recorded native build artifact")
    runtime=data.get("runtime_fingerprint",{})
    for key in ("c_h_sha256","python_sha256"):
        if not HEX64.fullmatch(str(runtime.get(key,""))): errors.append(f"runtime_fingerprint.{key} must be a SHA-256")
    build_runtime=build.get("runtime_fingerprint",{})
    if any(build_runtime.get(k)!=runtime.get(k) for k in ("c_h_sha256","python_sha256")):
        errors.append("native build must record the same C/H and Python Runtime fingerprints as the capture")
    ref=data.get("original_contract",{})
    if not ref.get("path") or not HEX64.fullmatch(str(ref.get("sha256",""))): errors.append("original CONFIG.INI contract path and SHA-256 are required")
    elif project_root:
        ref_path=(project_root/ref["path"]).resolve()
        try: ref_path.relative_to(project_root.resolve())
        except ValueError: errors.append("original contract path escapes the project root")
        else:
            if not ref_path.is_file(): errors.append("referenced original contract evidence is missing")
            elif hashlib.sha256(ref_path.read_bytes()).hexdigest()!=ref["sha256"]: errors.append("referenced original contract hash does not match")
    fx=data.get("fixtures",{}); original=fx.get("original",{}); native=fx.get("native",{})
    seed=original.get("authentic_seed_evidence",{})
    seed_file=original.get("address_txt_path")
    if not seed_file: errors.append("original fixture ADDRESS.TXT path is required")
    elif project_root:
        rel_seed=pathlib.PurePosixPath(str(seed_file).replace("\\","/"))
        if rel_seed.is_absolute() or ".." in rel_seed.parts:
            errors.append("original fixture ADDRESS.TXT path must be a contained relative path")
        else:
            # Keep the lexical in-project path. The canonical fixture directory
            # is a junction to its mounted VHDX volume, so resolve() would make
            # this verified path appear outside the project tree.
            seed_file_path=project_root.joinpath(*rel_seed.parts)
            if not seed_file_path.is_file(): errors.append("original fixture ADDRESS.TXT file is missing")
            elif hashlib.sha256(seed_file_path.read_bytes()).hexdigest()!=original.get("address_txt_sha256"):
                errors.append("original fixture ADDRESS.TXT bytes do not match its recorded SHA-256")
    if not seed.get("path") or not HEX64.fullmatch(str(seed.get("sha256",""))):
        errors.append("authentic original ADDRESS.TXT seed evidence path and hash are required")
    elif project_root:
        seed_path=(project_root/seed["path"]).resolve()
        try: seed_path.relative_to(project_root.resolve())
        except ValueError: errors.append("ADDRESS.TXT seed evidence path escapes the project root")
        else:
            if not seed_path.is_file(): errors.append("authentic ADDRESS.TXT seed evidence is missing")
            elif hashlib.sha256(seed_path.read_bytes()).hexdigest()!=seed["sha256"]:
                errors.append("authentic ADDRESS.TXT seed evidence hash does not match")
            else:
                try:
                    seed_data=json.loads(seed_path.read_text(encoding="utf-8"))
                    authentic=seed_data.get("runtime",{}).get("guest_errors",{})
                    if authentic.get("ADDRESS_TXT_matches_functional_source") is not True or authentic.get("ADDRESS_TXT_sha256")!=original.get("address_txt_sha256"):
                        errors.append("original ADDRESS.TXT fixture does not match the verified authentic functional-source seed")
                except Exception: errors.append("authentic ADDRESS.TXT seed evidence is invalid JSON")
    crt=data.get("crt",{})
    destinations=crt.get("destinations",[])
    if crt.get("callback_count") != 19 or len(set(destinations)) != 19 or len(destinations) != 19:
        errors.append("CRT evidence must contain exactly 19 callbacks to 19 unique destinations")
    if data.get("argv",{}).get("argc") != 3: errors.append("argc must be 3")
    gate=data.get("gate",{})
    if gate.get("local_64") != "01" or gate.get("local_68") != "01": errors.append("setup gate locals must both be 01")
    setup=data.get("roots",{}).get("setup_game",{})
    if str(setup.get("link_va","")).lower() not in ("0x94ac0","0x00094ac0"): errors.append("setup_game link VA 0x94AC0 must be observed")
    callee=data.get("roots",{}).get("first_callee_14bf0",{})
    if str(callee.get("link_va","")).lower() not in ("0x14bf0","0x00014bf0") or callee.get("observed") is not True:
        errors.append("first setup_game callee 0x14BF0 must be observed dynamically")
    cfg=data.get("config_ini",{})
    if str(cfg.get("path","")).replace("/","\\").casefold().split("\\")[-1] != "config.ini": errors.append("CONFIG.INI path must be recorded")
    if cfg.get("opened") is not True or cfg.get("bytes_read") != 130 or cfg.get("eof_observed") is not True:
        errors.append("CONFIG.INI must be opened, read for 130 bytes, and reach EOF")
    ioctl=data.get("ax4400",[])
    if not any(str(x.get("path","")).replace("/","\\").casefold().endswith("config.ini") and x.get("regular_file") is True and x.get("ax") == 2 and x.get("dx") == 2 and x.get("carry") is False for x in ioctl):
        errors.append("regular-file CONFIG.INI AX=4400 must show AX=DX=2 and CF=0")
    if fx.get("comparable") is not True or not original.get("fingerprint") or original.get("fingerprint") != native.get("fingerprint"):
        errors.append("original/native fixture fingerprints must be present and equal")
    if not HEX64.fullmatch(str(original.get("address_txt_sha256",""))) or original.get("address_txt_sha256") != native.get("address_txt_sha256"):
        errors.append("original and native ADDRESS.TXT seed hashes must match")
    if native.get("address_provider_initial_visibility") != "present" or not native.get("address_provider_open"):
        errors.append("authentic ADDRESS.TXT must be visible and opened in the native virtual provider")
    physical=native.get("physical_host_path_observation",{})
    if physical and physical.get("guest_provider_source") is not False:
        errors.append("physical ADDRESS.TXT presence must remain distinct from native virtual-provider visibility")
    if data.get("ax4400_comparison",{}).get("same_dynamic_invocation_claimed") is not False:
        errors.append("AX=4400 comparison must not claim different dynamic handles/events are the same invocation")
    frontier=data.get("frontier",{})
    if frontier.get("newly_observed") is not True or not frontier.get("stop_reason") or not frontier.get("guest_eip"):
        errors.append("a new native frontier with reason and guest EIP must be observed")
    if data.get("prior_ax4300_checkpoint_reused") is not False:
        errors.append("the historical AX=4300 boundary cannot stand in for a new checkpoint")
    if project_root:
        build_path=(project_root/build.get("path","")).resolve()
        try: build_path.relative_to(project_root.resolve())
        except ValueError: errors.append("native build artifact path escapes the project root")
        else:
            if not build_path.is_file(): errors.append("fingerprinted native build artifact is missing")
            elif hashlib.sha256(build_path.read_bytes()).hexdigest()!=build.get("sha256"):
                errors.append("native build artifact fingerprint is stale")
        try:
            sys.path.insert(0,str(project_root/"tools"))
            import frontier_snapshot
            live_runtime=frontier_snapshot.runtime_hash(project_root)
            py_files=list((project_root/"runtime").glob("*.py"))
            live_python=frontier_snapshot.manifest_hash(py_files,project_root)
            if runtime.get("c_h_sha256")!=live_runtime: errors.append("Runtime C/H fingerprint is stale")
            if runtime.get("python_sha256")!=live_python: errors.append("Runtime Python fingerprint is stale")
        except Exception as e: errors.append(f"current Runtime fingerprint could not be verified: {e}")
    return errors


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("evidence",type=pathlib.Path)
    a=p.parse_args(argv)
    if not a.evidence.is_file():
        print(f"INCONCLUSIVE: required capture evidence is not present: {a.evidence}",file=sys.stderr)
        return 2
    try: data=json.loads(a.evidence.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"INVALID evidence JSON: {e}",file=sys.stderr); return 2
    target=ROOT/"evidence"/"genewars-1_1.exe"
    current_sha=hashlib.sha256(target.read_bytes()).hexdigest() if target.is_file() else None
    errors=validate(data,target_sha256=current_sha,project_root=ROOT)
    if errors:
        print("FAIL W1-050 acceptance gate:")
        for e in errors: print("- "+e)
        return 1
    print("PASS W1-050 evidence contract; no execution was performed by this verifier")
    return 0


if __name__=="__main__":
    raise SystemExit(main())
