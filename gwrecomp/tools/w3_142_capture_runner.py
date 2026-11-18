#!/usr/bin/env python3
"""One bounded guarded capture of GeneWars' original direct Smacker route."""
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
from tools.w3_142_direct_smacker import MAX_TRACE_BYTES, parse_jsonl, summarize

MOUNT = ROOT / "build/dosboxx_oracle/C"
FIXTURE = MOUNT / "GENEWARS/GW.EXE"
CONFIG = ROOT / "build/dosboxx_oracle/dosbox-staging.w3-067-functional.conf"
CUE = ROOT.parent / "GeneWarsFX/evidence/original_disc/Genewars (Europe) (En,Fr,De,Es,It,Sv).cue"
DOSBOX = ROOT / "build/staging-w3-059-exec/Debug/dosbox.exe"
GUARD = ROOT / "tools/oracle_guard.py"
SOURCE = ROOT / "third_party/dosbox-staging-w3-059-instrumented"
CORE = SOURCE / "src/cpu/core_dyn_x86.cpp"
DISASM = ROOT / "evidence/genewars-1_1-le_disasm.s"
REVISION = "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f"
GW_SIZE = 1_251_658
GW_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
CONFIG_SHA256 = "b2bac63096aa97a808abb8ea09486db79559b12a25a1410ea930be0e5eeffff1"
CUE_SHA256 = "1d417e3aed625d4f054b51054a1211562a19cd4f712b08e7846613517228a5b5"
RUN_ID = "w3-142-direct-smacker-20261009-01"
TRACE = MOUNT / "W3_142_DIRECT_SMACKER_20261009_01.jsonl"
RESULT = ROOT / "evidence/w3_142_direct_smacker_transfer.json"
HOST_FLOOR = 100 * 1024**3


def main() -> int:
    if Path(sys.executable).name.lower() != "python.exe":
        raise RuntimeError(f"explicit console Python required, got {sys.executable}")
    sandbox = verify_sandbox()
    for path in (FIXTURE, CONFIG, CUE, DOSBOX, GUARD, CORE, DISASM):
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
    for token in ("play_smk_:\t/* 0xae2d0 */", "play_smk_direct:\t/* 0xae308 */",
                  "SMACKTOBUFFER:\t/* 0xc5140 */", "SMACKDOFRAME:\t/* 0xc5bd0 */",
                  "LbScreenSwap_:\t/* 0x9ffe0 */", "jump_ae47f:"):
        if token.lower() not in disasm.lower():
            raise RuntimeError(f"exact-target direct-route disassembly missing {token}")
    source = CORE.read_text(encoding="utf-8", errors="replace")
    for token in ("w3_142_direct_capture_armed", '"W3_142_SMACKTOBUFFER_ENTRY"',
                  '"W3_142_SMACKDOFRAME_ENTRY"', '"W3_142_LBSCREENSWAP_CALLSITE"',
                  '"W3_142_LBSCREENSWAP_ENTRY"'):
        if token not in source:
            raise RuntimeError(f"one-shot source gate missing {token}")
    evidence_dir = ROOT / "evidence/oracle_runs"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    stdout = evidence_dir / f"{RUN_ID}.stdout.json"
    stderr = evidence_dir / f"{RUN_ID}.stderr.txt"
    if any(path.exists() for path in (TRACE, RESULT, stdout, stderr)):
        raise FileExistsError("refusing to overwrite W3-142 artifacts")
    binary_hash = sha(DOSBOX)
    core_hash = sha(CORE)
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
               "--operation", "W3-142 first direct Smacker transfer/screen-swap capture",
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
    result = {
        "schema": "w3-142-direct-smacker-transfer/v1", "task": "W3-142", "run_id": RUN_ID,
        "source": {"target_sha256": GW_SHA256, "fixture_bytes": FIXTURE.stat().st_size,
                   "config_sha256": sha(CONFIG), "cue_sha256": sha(CUE),
                   "staging_revision": revision, "instrumented_core_sha256": core_hash,
                   "staging_binary_sha256": binary_hash},
        "preflight": {"sandbox": sandbox, "cue_read_only_mount": True,
                      "timeout_seconds": 30, "trace_cap_bytes": MAX_TRACE_BYTES,
                      "target_event_cap": 4, "global_trace": False,
                      "fixture_or_original_modified": False},
        "guard": {key: guard.get(key) for key in (
            "run_id", "operation", "sandbox_verified", "sandbox_capacity", "host_free_before",
            "host_free_after", "limits", "exit_reason", "cause", "detail", "exit_code",
            "killed_processes", "duration_s", "evidence_path", "ok")},
        "guard_output": {"stdout_path": str(stdout.relative_to(ROOT)), "stdout_sha256": sha(stdout),
                         "stderr_path": str(stderr.relative_to(ROOT)), "stderr_bytes": stderr.stat().st_size},
        "trace": {"path": str(TRACE.relative_to(ROOT)), "bytes": len(raw),
                  "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
                  "event_count": len(rows)},
        "capture": capture,
    }
    RESULT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"result": str(RESULT), "classification": capture["classification"],
                      "target_event_count": capture["target_event_count"],
                      "guard_cause": guard.get("cause"), "duration_s": guard.get("duration_s")}, indent=2))
    return 0 if guard.get("sandbox_verified") and guard.get("ok") else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"PREFLIGHT/REPLAY FAILED CLOSED: {exc}", file=sys.stderr)
        raise SystemExit(2)
