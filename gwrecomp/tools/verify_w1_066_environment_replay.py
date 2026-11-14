"""Validate fresh native evidence using the authenticated W3-140 DOS environment."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGET_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
ENVIRONMENT_SHA256 = "65c4d22c258efbf93a93cfcaa8d9d8c489e510cb2be76530646c36e0250ee895"
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def validate(data: dict, *, project_root: pathlib.Path | None = None,
             target_sha256: str | None = None) -> list[str]:
    errors: list[str] = []
    if data.get("schema") != "gwrecomp.native-setup-replay/v1":
        errors.append("native setup replay schema is missing")
    if data.get("execution_mode") != "native_recompiled_guest":
        errors.append("capture must identify the native recompiled guest")
    if data.get("task_schema") != "gwrecomp.native-setenvp-aligned-replay/v1":
        errors.append("W1-066 task schema is missing")
    if data.get("evidence_level") != "NATIVE_REACHED":
        errors.append("W1-066 evidence level must be NATIVE_REACHED")
    if data.get("target_sha256") != TARGET_SHA256 or (target_sha256 and target_sha256 != TARGET_SHA256):
        errors.append("target hash does not match the pinned GeneWars 1.1 image")
    env = data.get("authenticated_environment", {})
    if env.get("size_bytes") != 86 or env.get("sha256") != ENVIRONMENT_SHA256:
        errors.append("authenticated environment size/hash does not match W3-140")
    if env.get("guest_boot_environment_bytes") != 86 or env.get("guest_boot_environment_sha256") != ENVIRONMENT_SHA256:
        errors.append("native boot fixture did not record the authenticated 86-byte payload")
    if env.get("exact_bytes_loaded") is not True:
        errors.append("authenticated environment bytes were not confirmed at native boot input")
    if env.get("same_dynamic_invocation_claimed") is not False:
        errors.append("cross-run environment comparison must not claim dynamic invocation identity")
    if env.get("original_comparison", {}).get("same_dynamic_invocation_claimed") is not False:
        errors.append("original comparison must remain explicitly cross-run")
    events = env.get("native_setenvp_events", [])
    if not any(line.startswith("NATIVE_ADF95_BRANCH ") and "site=000dfe04" in line.lower() for line in events):
        errors.append("native __setenvp_ DFE04 branch checkpoint is missing")
    if not any(line.startswith("NATIVE_ALLOC_CALLSITE ") and "site=000dfe0d" in line.lower() for line in events):
        errors.append("native __setenvp_ callsite DFE0D is missing")
    if not any(line.startswith("NATIVE_ALLOC_ENTRY ") and "va=000adf95" in line.lower() for line in events):
        errors.append("native ADF95 entry is missing")
    return_seen = any(line.startswith("NATIVE_ADF95_RETURN ") and "link_va=000dfe12" in line.lower()
                       for line in events)
    if return_seen != (env.get("return_to_dfe12_observed") is True):
        errors.append("DFE12 return observation flag does not match the captured events")
    if not return_seen and env.get("return_to_dfe12_status") != "not_reached_before_strict_AX0501_stop":
        errors.append("unreached DFE12 must be explained by the strict no-response AX=0501 stop")
    for key in ("source_evidence_sha256", "runtime_contract_evidence_sha256", "runtime_source_sha256"):
        if not HEX64.fullmatch(str(env.get(key, ""))):
            errors.append(f"authenticated_environment.{key} must be a SHA-256")
    if env.get("source_evidence") != "evidence/w3_140_original_setenvp_environment.json":
        errors.append("W3-140 environment source evidence is not identified")
    if env.get("runtime_contract_evidence") != "evidence/w2_114_authenticated_environment_fixture.json":
        errors.append("W2-114 fixture API contract evidence is not identified")

    callbacks = data.get("crt", {})
    if not isinstance(callbacks.get("callback_count"), int):
        errors.append("CRT callback count was not recorded")
    argv = data.get("argv", {})
    if not isinstance(argv.get("argc"), int) or not isinstance(argv.get("values"), list):
        errors.append("native argc/argv capture is incomplete")
    if not isinstance(data.get("gate"), dict) or not isinstance(data.get("roots"), dict):
        errors.append("main gate/setup reachability fields are missing")
    frontier = data.get("frontier", {})
    if not frontier.get("fresh_replay") or not frontier.get("stop_reason"):
        errors.append("fresh native frontier or exact stop reason is missing")
    if data.get("prior_ax4300_checkpoint_reused") is not False:
        errors.append("historical AX=4300 evidence cannot substitute for this replay")
    if data.get("native_response_forced") is not False or frontier.get("response_count") != 0:
        errors.append("W1-066 strict frontier must record zero forced/service responses")

    if project_root is not None:
        root = project_root.resolve()
        for path_key, hash_key in (("source_evidence", "source_evidence_sha256"),
                                   ("runtime_contract_evidence", "runtime_contract_evidence_sha256")):
            rel = env.get(path_key, "")
            path = (root / rel).resolve()
            try:
                path.relative_to(root)
            except ValueError:
                errors.append(f"{path_key} escapes the project")
                continue
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != env.get(hash_key):
                errors.append(f"{path_key} is missing or its fingerprint changed")
        original_ref = data.get("original_contract", {})
        original_path = (root / original_ref.get("path", "")).resolve()
        try:
            original_path.relative_to(root)
        except ValueError:
            errors.append("original contract path escapes the project")
        else:
            if not original_path.is_file() or hashlib.sha256(original_path.read_bytes()).hexdigest() != original_ref.get("sha256"):
                errors.append("original contract evidence is missing or stale")
        build = data.get("build_artifact", {})
        build_path = (root / build.get("path", "")).resolve()
        try:
            build_path.relative_to(root)
        except ValueError:
            errors.append("native build path escapes the project")
        else:
            if not build_path.is_file() or hashlib.sha256(build_path.read_bytes()).hexdigest() != build.get("sha256"):
                errors.append("native build artifact is missing or stale")
        source_fingerprints = data.get("build_fingerprints", {})
        for field, relative in (("replay_driver_sha256", "tests/test_native_guest_image.py"),
                                ("native_harness_source_sha256", "tests/test_native_guest_image.c")):
            path = root / relative
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != source_fingerprints.get(field):
                errors.append(f"{relative} fingerprint is missing or stale")
        recovery = data.get("recovery", {})
        for key in ("manifest", "verification"):
            rel = recovery.get(key, "")
            path = (root / rel).resolve()
            try:
                path.relative_to(root)
            except ValueError:
                errors.append(f"recovery {key} path escapes the project")
            else:
                if not path.is_file():
                    errors.append(f"recovery {key} file is missing")

    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=pathlib.Path)
    args = parser.parse_args(argv)
    if not args.evidence.is_file():
        print(f"INCONCLUSIVE: missing capture evidence: {args.evidence}", file=sys.stderr)
        return 2
    try:
        data = json.loads(args.evidence.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"INVALID evidence JSON: {exc}", file=sys.stderr)
        return 2
    target = ROOT / "evidence" / "genewars-1_1.exe"
    live_target_hash = hashlib.sha256(target.read_bytes()).hexdigest() if target.is_file() else None
    errors = validate(data, project_root=ROOT, target_sha256=live_target_hash)
    if errors:
        print("FAIL W1-066 evidence contract:")
        for error in errors:
            print("- " + error)
        return 1
    print("PASS W1-066 fresh native environment-replay evidence; no guest execution was performed by this validator")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
