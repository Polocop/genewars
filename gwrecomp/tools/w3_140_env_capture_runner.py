#!/usr/bin/env python3
"""One bounded original __setenvp_ capture, launched only by oracle_guard."""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.w3_100_capture_runner import sha, verify_sandbox
from tools.w3_140_env_capture import MAX_TRACE_BYTES, parse_jsonl, summarize

MOUNT = ROOT / "build/dosboxx_oracle/C"
FIXTURE = MOUNT / "GENEWARS/GW.EXE"
CONFIG = ROOT / "build/dosboxx_oracle/dosbox-staging.w3-067-functional.conf"
CUE = ROOT.parent / "GeneWarsFX/evidence/original_disc/Genewars (Europe) (En,Fr,De,Es,It,Sv).cue"
DOSBOX = ROOT / "build/staging-w3-059-exec/Debug/dosbox.exe"
GUARD = ROOT / "tools/oracle_guard.py"
SOURCE = ROOT / "third_party/dosbox-staging-w3-059-instrumented"
CORE = SOURCE / "src/cpu/core_dyn_x86.cpp"
DISASM = ROOT / "evidence/genewars-1_1-le_disasm.s"
W3_068 = ROOT / "evidence/w3_068_heap_alignment_original_20261008.json"
REVISION = "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f"
GW_SIZE = 1_251_658
GW_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
CONFIG_SHA256 = "b2bac63096aa97a808abb8ea09486db79559b12a25a1410ea930be0e5eeffff1"
CUE_SHA256 = "1d417e3aed625d4f054b51054a1211562a19cd4f712b08e7846613517228a5b5"
RUN_ID = "w3-140-setenvp-env-20261009-01"
TRACE = MOUNT / "W3_140_SETENVP_ENV_20261009_01.jsonl"
RESULT = ROOT / "evidence/w3_140_original_setenvp_environment.json"
MAX_TARGETS = 4
HOST_FLOOR = 100 * 1024**3


def main() -> int:
    if Path(sys.executable).name.lower() != "python.exe":
        raise RuntimeError(f"explicit console Python required, got {sys.executable}")
    sandbox = verify_sandbox()
    for path in (FIXTURE, CONFIG, CUE, DOSBOX, GUARD, CORE, DISASM, W3_068):
        if not path.is_file():
            raise FileNotFoundError(path)
    if FIXTURE.stat().st_size != GW_SIZE or sha(FIXTURE) != GW_SHA256:
        raise RuntimeError("authentic GW.EXE identity mismatch")
    if sha(CONFIG) != CONFIG_SHA256 or sha(CUE) != CUE_SHA256:
        raise RuntimeError("functional config or original CUE hash mismatch")
    if not re.search(r"(?im)^\s*imgmount\s+d\s+.*\.cue.*-ro\b", CONFIG.read_text(encoding="utf-8")):
        raise RuntimeError("original CUE is not mounted read-only")
    revision = subprocess.run(["git", "-C", str(SOURCE), "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    if revision != REVISION:
        raise RuntimeError(f"pinned Staging revision mismatch: {revision}")
    disasm = DISASM.read_text(encoding="utf-8", errors="replace")
    # This listing labels DFE04/DFE0D but not the intervening MOV at DFE08;
    # validate the instruction and branch/call sequence instead. W3-068
    # dynamically proves the return link DFE12 for the same static call.
    required_disasm = ("0xdfdc1", "jump_dfe04", "jne    jump_dfe0d",
                       "mov    $0x1,%eax", "call   _nmalloc_")
    if not all(x in disasm.lower() for x in required_disasm):
        raise RuntimeError("exact-target disassembly lacks one or more __setenvp_ checkpoints")
    prior = json.loads(W3_068.read_text(encoding="utf-8"))
    prior_call = prior.get("original_adf95", {})
    if prior_call.get("callsite_link_va") != "0x000DFE0D" or prior_call.get("return_link_va") != "0x000DFE12":
        raise RuntimeError("prior original DFE0D->DFE12 dynamic call proof is missing")
    source = CORE.read_text(encoding="utf-8", errors="replace")
    required_source = (
        '"W3_140_SETENVP_DFE04"', '"W3_140_SETENVP_DFE08"',
        '"W3_140_SETENVP_DFE0D"', '"W3_140_SETENVP_DFE12"',
        "w3_140_env_capture_armed", "n < 4096",
        "cpu.gdt.GetDescriptor(SegValue(es), w3_140_es_descriptor)",
    )
    if not all(token in source for token in required_source):
        raise RuntimeError("bounded first-invocation instrumentation gate failed")
    evidence_dir = ROOT / "evidence/oracle_runs"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    stdout = evidence_dir / f"{RUN_ID}.stdout.json"
    stderr = evidence_dir / f"{RUN_ID}.stderr.txt"
    if any(p.exists() for p in (TRACE, RESULT, stdout, stderr)):
        raise FileExistsError("refusing to overwrite W3-140 capture artifacts")
    binary_hash = sha(DOSBOX)
    source_hash = sha(CORE)
    env = dict(os.environ)
    for key in tuple(env):
        if key.startswith("GWRECOMP_ANCHOR_") or key.startswith("GWRECOMP_EXEC_TRACE_"):
            env.pop(key, None)
    env.update({
        "GWRECOMP_GW_FILE_SIZE": str(GW_SIZE),
        "GWRECOMP_GW_LE_HEADER_OFFSET": "0x8f50",
        "GWRECOMP_GW_LE_OBJECT_TABLE_OFFSET": "0x9014",
        "GWRECOMP_EXEC_TRACE_PATH": str(TRACE),
        "GWRECOMP_EXEC_TRACE_MAX_BYTES": str(MAX_TRACE_BYTES),
        "GWRECOMP_EXEC_TRACE_FILE_IO": "0",
        "GWRECOMP_ANCHOR_MAIN_ENTRY_LINK": "0x000af96c",
        "GWRECOMP_ANCHOR_MAIN_ENTRY_BYTES": "eb765741",
        "GWRECOMP_ANCHOR_CRT_ARGV_LOAD_LINK": "0x000c8702",
        "GWRECOMP_ANCHOR_GAME_MAIN_ENTRY_LINK": "0x00093f30",
    })
    command = [sys.executable, str(GUARD), "run", "--exe", str(DOSBOX), "--config", str(CONFIG),
               "--staging-dir", str(MOUNT), "--host-drive", "E:", "--run-id", RUN_ID,
               "--operation", "W3-140 first original __setenvp_ environment block capture",
               "--commit-sha", REVISION, "--target-sha", GW_SHA256, "--runtime-sha", binary_hash,
               "--fixture-sha", GW_SHA256, "--evidence-dir", str(evidence_dir),
               "--max-file-text-mib", "1", "--max-file-bin-mib", "64", "--max-run-gib", "1",
               "--host-floor-gib", "100", "--timeout-s", "30", "--growth-text-mibs", "8",
               "--growth-bin-mibs", "24", "--poll-hz", "1"]
    with stdout.open("xb") as out, stderr.open("xb") as err:
        subprocess.run(command, cwd=ROOT, env=env, stdout=out, stderr=err, timeout=40, check=False)
    guard = json.loads(stdout.read_text(encoding="utf-8"))
    raw = TRACE.read_bytes() if TRACE.exists() else b""
    rows = parse_jsonl(raw)
    capture = summarize(rows)
    guard_fields = ("run_id", "operation", "sandbox_verified", "sandbox_capacity", "host_free_before",
                    "host_free_after", "limits", "exit_reason", "cause", "detail", "exit_code",
                    "killed_processes", "duration_s", "evidence_path", "ok")
    result = {
        "schema": "w3-140-setenvp-environment/v1", "task": "W3-140", "run_id": RUN_ID,
        "source": {"target_sha256": GW_SHA256, "fixture_bytes": FIXTURE.stat().st_size,
                   "config_sha256": sha(CONFIG), "cue_sha256": sha(CUE),
                   "staging_revision": revision, "instrumented_core_sha256": source_hash,
                   "staging_binary_sha256": binary_hash},
        "preflight": {"sandbox": sandbox, "cue_read_only_mount": True,
                      "timeout_seconds": 30, "trace_cap_bytes": MAX_TRACE_BYTES,
                      "target_event_cap": MAX_TARGETS, "global_trace": False,
                      "fixture_or_original_modified": False},
        "guard": {key: guard.get(key) for key in guard_fields},
        "guard_output": {"stdout_path": str(stdout.relative_to(ROOT)), "stdout_sha256": sha(stdout),
                         "stderr_path": str(stderr.relative_to(ROOT)), "stderr_bytes": stderr.stat().st_size},
        "trace": {"path": str(TRACE.relative_to(ROOT)), "bytes": len(raw),
                  "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
                  "event_count": len(rows), "target_event_cap": MAX_TARGETS},
        "capture": capture,
        "cross_run_correlation": {"w3_068_original_first_adf95": "DFE0D, EAX=0x40, ECX=3 per W3-068 evidence; separate replay, not same invocation"},
    }
    RESULT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"result": str(RESULT), "classification": capture["classification"],
                      "target_event_count": capture["target_event_count"], "guard_cause": guard.get("cause"),
                      "guard_exit": guard.get("exit_reason"), "duration_s": guard.get("duration_s")}, indent=2))
    return 0 if guard.get("sandbox_verified") and guard.get("ok") else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"PREFLIGHT/REPLAY FAILED CLOSED: {exc}", file=sys.stderr)
        raise SystemExit(2)
