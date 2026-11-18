#!/usr/bin/env python3
"""Offline W3-298 activation audit; reads only source and existing evidence."""
from __future__ import annotations

import ast
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAGING = ROOT / "third_party/dosbox-staging-w3-059-instrumented"
CORE = STAGING / "src/cpu/core_dyn_x86.cpp"
GUARD_SOURCE = ROOT / "tools/oracle_guard.py"
RUNNER = ROOT / "tools/w3_298_capture_runner.py"
BINARY = ROOT / "build/staging-w3-059-exec/Debug/dosbox.exe"
RECOVERY = ROOT / "evidence/recovery/w3_298/core_dyn_x86.cpp.prechange"
RESTORE = ROOT / "build/w3_298_restore_check/core_dyn_x86.cpp"
TRACE = ROOT / "build/dosboxx_oracle/C/W3_298_SOUND_PIT_20261010_01.jsonl"
CAPTURE = ROOT / "evidence/w3_298_smacker_pit_capture.json"
GUARD_RUN = ROOT / "evidence/oracle_runs/oracle_runs_w3-298-natural-sound-pit-20261010-01.json"
RESULT = ROOT / "evidence/w3_299_sound_hook_audit.json"
REPORT = ROOT / "reports/coordination/w3_299_sound_hook_audit.md"
REVISION = "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f"
CORE_SHA = "a7f18e500abf889c6235bea7808ec930bd0d84d3916aa7e72024c71718ce16cd"
BINARY_SHA = "263898db71d32bf19e04b9886a8a660f27faa197e01dffc71c3b7ab73d8db0a0"
TRACE_SHA = "3f53238e4f43d5d266ebce36aa6335a67233af660d70ea40b212aaf3365a7820"
TARGET_SITES = {
    0x000ae308, 0x000ae326, 0x000ae32d, 0x000ae32f, 0x000ae331,
    0x000ae339, 0x000ae4d8, 0x000ae4f6, 0x000ae4fd, 0x000ae4ff,
    0x000ae501, 0x000ae509, 0x000c4050, 0x000c40d0, 0x000c460a,
    0x000c4270, 0x000c427a, 0x000c427e, 0x000c4282, 0x000c4293,
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def child_inherits_parent_environment(source: str) -> bool:
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and \
                isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess" and \
                node.func.attr == "Popen":
            return not any(keyword.arg == "env" for keyword in node.keywords)
    return False


def analyze(source: str, runner: str, guard_source: str, binary: bytes,
            rows: list[dict], capture_evidence: dict, guard_record: dict,
            hashes: dict) -> dict:
    checkpoints = [row for row in rows if row.get("event") == "target_runtime_checkpoint"]
    anchors = [row for row in rows if row.get("event") == "target_code_anchor" and
               row.get("anchor") == "MAIN_ENTRY"]
    selected = [row for row in rows if str(row.get("event", "")).startswith("W3_298_")]
    observed_links = {int(row.get("link_va", -1)) for row in checkpoints}
    observed_target_links = sorted(observed_links & TARGET_SITES)
    last_checkpoint = checkpoints[-1] if checkpoints else None
    last_api = [row for row in rows if row.get("event") == "setup_dos_api"]
    last_api = last_api[-1] if last_api else None
    env_requested = '"GWRECOMP_W3_298_CAPTURE": "1"' in runner
    env_read = 'string_from_env("GWRECOMP_W3_298_CAPTURE") == "1"' in source
    marker_compiled = b"W3_298_SOUND_PIT_CHECKPOINT" in binary
    guard_inherits = child_inherits_parent_environment(guard_source)
    runtime_marker_present = any(row.get("event") == "W3_298_CAPTURE_ARMED" for row in rows)
    if selected:
        activation = "W3-298 observer emitted selected runtime rows"
    elif not env_requested or not env_read or not marker_compiled or not guard_inherits:
        activation = "static activation chain has a missing link"
    else:
        activation = "activation configured/compiled, but runtime activation is unproven"
    return {
        "source_revision": hashes["revision"],
        "source_sha256": hashes["source"],
        "binary_sha256": hashes["binary"],
        "recovery_sha256": hashes["recovery"],
        "restored_copy_sha256": hashes["restored"],
        "trace_sha256": hashes["trace"],
        "hashes_match_pinned_inputs": hashes["revision"] == REVISION and
            hashes["source"] == CORE_SHA and hashes["binary"] == BINARY_SHA and
            hashes["trace"] == TRACE_SHA,
        "recovery_restore_identical": hashes["recovery"] == hashes["restored"],
        "runner_sets_capture_env": env_requested,
        "source_reads_capture_env": env_read,
        "compiled_binary_contains_probe_marker": marker_compiled,
        "oracle_guard_child_inherits_environment": guard_inherits,
        "runtime_activation_marker_present": runtime_marker_present,
        "runtime_activation_assessment": activation,
        "main_anchor_count": len(anchors),
        "main_code_rebase": anchors[0].get("candidate_rebase") if anchors else None,
        "generic_checkpoint_count": len(checkpoints),
        "observed_target_sound_site_links": [hex(x) for x in observed_target_links],
        "selected_w3_298_event_count": len(selected),
        "last_generic_checkpoint": ({"sequence": last_checkpoint.get("sequence"),
            "name": last_checkpoint.get("checkpoint"),
            "link_va": hex(int(last_checkpoint.get("link_va", 0))),
            "runtime_eip": hex(int(last_checkpoint.get("eip", 0))),
            "data_rebase": hex(int(last_checkpoint.get("data_rebase", 0)))}
            if last_checkpoint else None),
        "last_dos_api": ({"sequence": last_api.get("sequence"),
            "ordinal": last_api.get("ordinal"), "operation": last_api.get("operation"),
            "requested_path": last_api.get("requested_path"), "cwd": last_api.get("cwd"),
            "cf": last_api.get("cf"), "result": last_api.get("result"),
            "dos_error_field": last_api.get("dos_error")}
            if last_api else None),
        "dos_api_hook_cap": 128,
        "guard_cause": guard_record.get("cause"),
        "guard_duration_seconds": guard_record.get("duration_s"),
        "guard_killed_processes": guard_record.get("killed_processes"),
        "classification": "INCONCLUSIVE",
        "reason": "The runner requests capture, the guard inherits its environment, and the binary contains the probe; however, no W3-298 runtime activation marker exists. Zero selected rows cannot distinguish sound-path non-reachability from a runtime hook/candidate-coverage gap.",
        "supported_next_measurement": "Add a single opt-in activation marker at the fresh MAIN mapping and a per-site dispatch-hit marker before interpreting absence of the sound gates. If those markers prove active and sound sites remain absent, classify the path as not reached within this bounded replay; do not synthesize a gate or extend the old trace.",
        "original_visual_claims": {"vesa_mode_log": "101h observed in Staging log",
            "framebuffer_pixels": "not measured", "menu": "not reached/verified",
            "gameplay": "not reached/verified"},
        "capture_evidence_level": capture_evidence.get("evidence_level"),
        "guard_sandbox_verified": guard_record.get("sandbox_verified"),
    }


def main() -> int:
    for path in (CORE, RUNNER, GUARD_SOURCE, BINARY, RECOVERY, RESTORE, TRACE,
                 CAPTURE, GUARD_RUN):
        if not path.is_file():
            raise FileNotFoundError(path)
    if RESULT.exists() or REPORT.exists():
        raise FileExistsError("refusing to overwrite W3-299 artifacts")
    revision = subprocess.run(["git", "-C", str(STAGING), "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=10,
                              check=True).stdout.strip()
    raw = TRACE.read_bytes()
    rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    capture = json.loads(CAPTURE.read_text(encoding="utf-8"))
    guard_record = json.loads(GUARD_RUN.read_text(encoding="utf-8"))
    hashes = {"revision": revision, "source": sha(CORE), "binary": sha(BINARY),
              "recovery": sha(RECOVERY), "restored": sha(RESTORE),
              "trace": hashlib.sha256(raw).hexdigest()}
    result = analyze(CORE.read_text(encoding="utf-8"), RUNNER.read_text(encoding="utf-8"),
                     GUARD_SOURCE.read_text(encoding="utf-8"), BINARY.read_bytes(),
                     rows, capture, guard_record, hashes)
    RESULT.write_text(json.dumps({"schema": "w3-299-sound-hook-audit/v1",
                                  "task": "W3-299", "evidence_level": "INCONCLUSIVE",
                                  "inputs": {str(p.relative_to(ROOT)).replace("\\", "/"): sha(p)
                                             for p in (CORE, RUNNER, GUARD_SOURCE, BINARY,
                                                       RECOVERY, RESTORE, TRACE, CAPTURE,
                                                       GUARD_RUN)},
                                  "analysis": result}, indent=2) + "\n", encoding="utf-8")
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(
        "# W3-299 — W3-298 sound-hook activation audit\n\n"
        "Conclusion: **INCONCLUSIVE** for sound-path reachability; the static activation chain is present, but runtime activation has no explicit marker.\n\n"
        f"- Pinned revision/hash checks: `{result['hashes_match_pinned_inputs']}`; recovery restore identical: `{result['recovery_restore_identical']}`.\n"
        f"- Runner sets opt-in: `{result['runner_sets_capture_env']}`; source reads it: `{result['source_reads_capture_env']}`; binary includes probe string: `{result['compiled_binary_contains_probe_marker']}`; guard child inherits environment: `{result['oracle_guard_child_inherits_environment']}`.\n"
        f"- MAIN mapping anchors: {result['main_anchor_count']}; code rebase `{result['main_code_rebase']}`. Generic checkpoints: {result['generic_checkpoint_count']}; sound-site overlaps: `{result['observed_target_sound_site_links']}`. W3-298 rows: {result['selected_w3_298_event_count']}.\n"
        f"- Last checkpoint: `{result['last_generic_checkpoint']}`. Last DOS API: `{result['last_dos_api']}`. Guard: `{result['guard_cause']}` after {result['guard_duration_seconds']} s.\n"
        "- Staging logged VESA mode 101h; no framebuffer pixels, menu, or gameplay were measured.\n"
        f"- Interpretation: {result['reason']}\n"
        f"- Minimal next measurement: {result['supported_next_measurement']}\n",
        encoding="utf-8")
    print(json.dumps({"result": str(RESULT), "activation": result["runtime_activation_assessment"],
                      "classification": result["classification"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
