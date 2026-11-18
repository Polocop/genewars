#!/usr/bin/env python3
"""One bounded guarded original capture of the DPMI 0300/INT 21h 6300 frame."""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.w3_100_capture_runner import sha, verify_sandbox
from tools.w3_143_postopen_branch import MAX_TRACE_BYTES, parse_jsonl

MOUNT = ROOT / "build/dosboxx_oracle/C"
FIXTURE = MOUNT / "GENEWARS/GW.EXE"
CONFIG = ROOT / "build/dosboxx_oracle/dosbox-staging.w3-067-functional.conf"
CUE = ROOT.parent / "GeneWarsFX/evidence/original_disc/Genewars (Europe) (En,Fr,De,Es,It,Sv).cue"
DOSBOX = ROOT / "build/staging-w3-059-exec/Debug/dosbox.exe"
GUARD = ROOT / "tools/oracle_guard.py"
SOURCE = ROOT / "third_party/dosbox-staging-w3-059-instrumented"
CORE = SOURCE / "src/cpu/core_dyn_x86.cpp"
W1_EVIDENCE = ROOT / "evidence/native_ax0300_frame_audit_w1_069.json"
W3_140_EVIDENCE = ROOT / "evidence/w3_140_original_setenvp_environment.json"
W3_140_TRACE = MOUNT / "W3_140_SETENVP_ENV_20261009_01.jsonl"
RUN_ID = "w3-182-original-ax0300-20261009-01"
TRACE = MOUNT / "W3_182_ORIGINAL_AX0300_20261009_01.jsonl"
RESULT = ROOT / "evidence/w3_182_original_ax0300_capture.json"
GUARD_JSON = ROOT / "evidence/oracle_runs/oracle_runs_w3-182-original-ax0300-20261009-01.json"
GUARD_STDOUT = GUARD_JSON.with_name(GUARD_JSON.stem + ".stdout.json")
GUARD_STDERR = GUARD_JSON.with_name(GUARD_JSON.stem + ".stderr.txt")
REVISION = "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f"
GW_SIZE = 1_251_658
GW_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
CONFIG_SHA256 = "b2bac63096aa97a808abb8ea09486db79559b12a25a1410ea930be0e5eeffff1"
CUE_SHA256 = "1d417e3aed625d4f054b51054a1211562a19cd4f712b08e7846613517228a5b5"
W1_NATIVE_TAIL = " -k 38928"
FRAME_BYTES = 48


def _w1_context() -> dict[str, Any]:
    data = json.loads(W1_EVIDENCE.read_text(encoding="utf-8"))
    output = data.get("stdout", "")
    marker = next((line for line in output.splitlines()
                   if line.startswith("W1_CRT_DPMI0300_CHECK ")), None)
    if data.get("target_sha256") != GW_SHA256 or data.get("command_tail") != W1_NATIVE_TAIL or not marker:
        raise RuntimeError("W1-069 evidence identity or DPMI marker mismatch")
    fields = dict(re.findall(r"([a-zA-Z0-9_]+)=([^ ]+)", marker))
    if fields.get("eip") != "000bc765" or fields.get("eax", "")[-4:].lower() != "0300" or fields.get("inner_eax") != "00006300":
        raise RuntimeError("W1-069 marker is not the expected AX=0300 / inner AX=6300 call")
    return {"target_sha256": data["target_sha256"], "command_tail": data["command_tail"],
            "entry": fields}


def _w3_140_context() -> dict[str, Any]:
    data = json.loads(W3_140_EVIDENCE.read_text(encoding="utf-8"))
    env = data.get("capture", {}).get("environment", {})
    rows = parse_jsonl(W3_140_TRACE.read_bytes()) if W3_140_TRACE.is_file() else []
    main = next((row for row in rows if row.get("checkpoint") == "MAIN_ENTRY_CHECKPOINT"), None)
    if data.get("source", {}).get("target_sha256") != GW_SHA256:
        raise RuntimeError("W3-140 target hash mismatch")
    if not env.get("valid") or env.get("sample_bytes") != 86 or not env.get("double_nul_found"):
        raise RuntimeError("W3-140 authenticated environment is not validated")
    if main is None:
        raise RuntimeError("W3-140 raw trace lacks MAIN/PSP-tail checkpoint")
    if main.get("psp_tail_text") != W1_NATIVE_TAIL:
        raise RuntimeError("W3-140 original PSP tail differs from W1-069 native context")
    return {"environment_sample_bytes": env["sample_bytes"],
            "environment_sha256": hashlib.sha256(bytes.fromhex(env["sample_hex"])).hexdigest(),
            "environment_hex": env["sample_hex"], "environment_valid": env["valid"],
            "original_psp_tail": main.get("psp_tail_text"),
            "psp_tail_source": "W3-140 raw MAIN checkpoint",
            "trace_sha256": sha(W3_140_TRACE)}


def _preflight() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    sandbox = verify_sandbox()
    if not sandbox.get("verified") or sandbox.get("label") != "GWORACLE":
        raise RuntimeError(f"GWORACLE verification failed: {sandbox}")
    for path in (FIXTURE, CONFIG, CUE, DOSBOX, GUARD, CORE, W1_EVIDENCE,
                 W3_140_EVIDENCE, W3_140_TRACE):
        if not path.is_file():
            raise FileNotFoundError(path)
    if FIXTURE.stat().st_size != GW_SIZE or sha(FIXTURE) != GW_SHA256:
        raise RuntimeError("authentic W3-067 fixture identity mismatch")
    if sha(CONFIG) != CONFIG_SHA256 or sha(CUE) != CUE_SHA256:
        raise RuntimeError("functional config or original CUE hash mismatch")
    if not re.search(r"(?im)^\s*imgmount\s+d\s+.*\.cue.*-ro\b", CONFIG.read_text(encoding="utf-8")):
        raise RuntimeError("original CUE is not mounted read-only")
    revision = subprocess.run(["git", "-C", str(SOURCE), "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    if revision != REVISION:
        raise RuntimeError(f"pinned Staging revision mismatch: {revision}")
    core = CORE.read_text(encoding="utf-8", errors="replace")
    for token in ("W3_182_DPMI0300_ENTRY", "W3_182_DPMI0300_RETURN",
                  "candidate_link_va == 0x000bc765", "w3_182_frame_hex",
                  "w3_182_dpmi0300_return_runtime"):
        if token not in core:
            raise RuntimeError(f"W3-182 instrumentation missing {token}")
    w1 = _w1_context()
    w3_140 = _w3_140_context()
    for path in (TRACE, RESULT, GUARD_JSON, GUARD_STDOUT, GUARD_STDERR):
        if path.exists():
            raise FileExistsError(f"refusing to overwrite W3-182 artifact: {path}")
    return sandbox, w1, w3_140


def classify(rows: list[dict[str, Any]]) -> dict[str, Any]:
    main = next((r for r in rows if r.get("checkpoint") == "MAIN_ENTRY_CHECKPOINT"), None)
    entries = [r for r in rows if r.get("checkpoint") == "W3_182_DPMI0300_ENTRY"]
    returns = [r for r in rows if r.get("checkpoint") == "W3_182_DPMI0300_RETURN"]
    last = rows[-1] if rows else None
    if len(entries) > 1 or len(returns) > 1:
        return {"classification": "INCONCLUSIVE", "reason": "unexpected duplicate target events",
                "entry_count": len(entries), "return_count": len(returns)}
    if not entries:
        return {"classification": "NOT_OBSERVED", "reason": "natural original AX=0300 checkpoint not captured",
                "main": main, "last_event": last}
    entry = entries[0]
    mapping_valid = bool(main) and int(entry.get("link_va", -1)) == 0xBC765 and \
            int(entry.get("eip", -1)) - (int(main["eip"]) - int(main["link_va"])) == 0xBC765 and \
            int(entry.get("process_psp", -1)) == int(main["process_psp"])
    opcode = str(entry.get("bytes", "")).lower()
    service_valid = (int(entry.get("eax", 0)) & 0xFFFF) == 0x0300
    frame_hex = str(entry.get("w3_182_frame_hex", ""))
    frame_valid = entry.get("w3_182_frame_valid") is True and \
            int(entry.get("w3_182_frame_bytes", 0)) == FRAME_BYTES and \
            len(bytes.fromhex(frame_hex)) == FRAME_BYTES
    returned = returns[0] if returns else None
    return_valid = bool(returned) and int(returned.get("eip", -1)) == int(entry["eip"]) + 2 and \
            int(returned.get("process_psp", -1)) == int(entry.get("process_psp", -2)) and \
            int(returned.get("sequence", -1)) > int(entry.get("sequence", 0))
    return {"classification": "ORIGINAL_AX0300_OBSERVED", "reason": "natural target checkpoint captured",
            "mapping_valid": mapping_valid, "service_valid": service_valid,
            "int31_opcode_verified": opcode.startswith("cd31"),
            "entry": entry, "frame_valid": frame_valid,
            "frame_hex": frame_hex if frame_valid else None,
            "return_observed": bool(returned), "return_valid": return_valid,
            "return": returned, "last_event": last}


def main() -> int:
    if any(arg in ("-h", "--help") for arg in sys.argv[1:]):
        print("Usage: w3_182_original_ax0300_capture_runner.py [--help]")
        print("Running without --help performs one fixed guarded original replay.")
        return 0
    if Path(sys.executable).name.lower() != "python.exe":
        raise RuntimeError(f"explicit console Python required, got {sys.executable}")
    sandbox, w1, w3_140 = _preflight()
    evidence_dir = ROOT / "evidence/oracle_runs"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    binary_sha = sha(DOSBOX)
    env = dict(os.environ)
    for key in tuple(env):
        if key.startswith("GWRECOMP_ANCHOR_") or key.startswith("GWRECOMP_EXEC_TRACE_"):
            env.pop(key, None)
    env.update({"GWRECOMP_GW_FILE_SIZE": str(GW_SIZE),
                "GWRECOMP_GW_LE_HEADER_OFFSET": "0x8f50",
                "GWRECOMP_GW_LE_OBJECT_TABLE_OFFSET": "0x9014",
                "GWRECOMP_EXEC_TRACE_PATH": str(TRACE),
                "GWRECOMP_EXEC_TRACE_MAX_BYTES": str(MAX_TRACE_BYTES),
                "GWRECOMP_EXEC_TRACE_FILE_IO": "0",
                "GWRECOMP_ANCHOR_MAIN_ENTRY_LINK": "0x000af96c",
                "GWRECOMP_ANCHOR_MAIN_ENTRY_BYTES": "eb765741",
                "GWRECOMP_ANCHOR_CRT_ARGV_LOAD_LINK": "0x000c8702",
                "GWRECOMP_ANCHOR_GAME_MAIN_ENTRY_LINK": "0x00093f30",
                "GWRECOMP_W3_171_ENABLE_SAMPLES": "0"})
    command = [sys.executable, str(GUARD), "run", "--exe", str(DOSBOX), "--config", str(CONFIG),
               "--staging-dir", str(MOUNT), "--host-drive", "E:", "--run-id", RUN_ID,
               "--operation", "W3-182 original DPMI 0300 frame capture", "--commit-sha", REVISION,
               "--target-sha", GW_SHA256, "--runtime-sha", binary_sha, "--fixture-sha", GW_SHA256,
               "--evidence-dir", str(evidence_dir), "--max-file-text-mib", "1", "--max-file-bin-mib", "64",
               "--max-run-gib", "1", "--host-floor-gib", "100", "--timeout-s", "30",
               "--growth-text-mibs", "8", "--growth-bin-mibs", "24", "--poll-hz", "1"]
    with GUARD_STDOUT.open("xb") as out, GUARD_STDERR.open("xb") as err:
        subprocess.run(command, cwd=ROOT, env=env, stdout=out, stderr=err, timeout=40, check=False)
    guard = json.loads(GUARD_STDOUT.read_text(encoding="utf-8"))
    raw = TRACE.read_bytes() if TRACE.exists() else b""
    if len(raw) > MAX_TRACE_BYTES:
        raise RuntimeError("trace exceeded configured 1 MiB cap")
    rows = parse_jsonl(raw)
    outcome = classify(rows)
    result = {**outcome, "schema": "w3-182-original-ax0300-capture/v1", "task": "W3-182",
              "run_id": RUN_ID,
              "source": {"target_sha256": GW_SHA256, "fixture_bytes": FIXTURE.stat().st_size,
                         "config_sha256": sha(CONFIG), "cue_sha256": sha(CUE),
                         "staging_revision": REVISION, "instrumented_core_sha256": sha(CORE),
                         "staging_binary_sha256": binary_sha},
              "contexts": {"w1_069_native": w1, "w3_140_original_environment": w3_140,
                           "same_context_claim": False},
              "preflight": {"sandbox": sandbox, "cue_read_only_mount": True,
                            "timeout_seconds": 30, "trace_cap_bytes": MAX_TRACE_BYTES,
                            "target_link_va": "0xBC765", "frame_sample_cap_bytes": FRAME_BYTES,
                            "global_trace": False, "guest_state_modified": False},
              "guard": {k: guard.get(k) for k in ("run_id", "operation", "sandbox_verified",
                         "sandbox_capacity", "host_free_before", "host_free_after", "limits",
                         "exit_reason", "cause", "detail", "exit_code", "killed_processes",
                         "duration_s", "evidence_path", "ok")},
              "trace": {"path": str(TRACE.relative_to(ROOT)), "bytes": len(raw),
                        "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
                        "event_count": len(rows)},
              "limitations": ["AX=0300 return is reported only if the derived post-INT instruction checkpoint is captured.",
                              "ES:EDI bytes are raw and are not assigned DPMI frame semantics unless the caller contract is independently confirmed.",
                              "The native command-tail/context is not treated as equivalent to the original run."]}
    RESULT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"result": str(RESULT), "classification": result["classification"],
                      "entry": bool(result.get("entry")), "return_observed": result.get("return_observed"),
                      "guard_cause": guard.get("cause")}, indent=2))
    return 0 if guard.get("sandbox_verified") else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"PREFLIGHT/REPLAY FAILED CLOSED: {exc}", file=sys.stderr)
        raise SystemExit(2)
