#!/usr/bin/env python3
"""One guarded, bounded Smacker allocator-return/draw capture."""
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
from tools.w3_136_smacker_restart_coverage import inspect_source
from tools.w3_138_smacker_trace import parse_jsonl

MOUNT = ROOT / "build/dosboxx_oracle/C"
FIXTURE = MOUNT / "GENEWARS/GW.EXE"
CONFIG = ROOT / "build/dosboxx_oracle/dosbox-staging.w3-067-functional.conf"
CUE = ROOT.parent / "GeneWarsFX/evidence/original_disc/Genewars (Europe) (En,Fr,De,Es,It,Sv).cue"
DOSBOX = ROOT / "build/staging-w3-059-exec/Debug/dosbox.exe"
GUARD = ROOT / "tools/oracle_guard.py"
CORE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
REVISION = "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f"
GW_SIZE = 1_251_658
GW_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
CONFIG_SHA256 = "b2bac63096aa97a808abb8ea09486db79559b12a25a1410ea930be0e5eeffff1"
CUE_SHA256 = "1d417e3aed625d4f054b51054a1211562a19cd4f712b08e7846613517228a5b5"
RUN_ID = "w3-139-smacker-return-draw-20261009-01"
TRACE = MOUNT / "W3_139_SMACKER_RETURN_DRAW_20261009_01.jsonl"
RESULT = ROOT / "evidence/w3_139_smacker_return_draw.json"
MAX_TRACE = 1_048_576
CAP_EVENTS = 12


def main() -> int:
    if Path(sys.executable).name.lower() != "python.exe":
        raise RuntimeError(f"explicit console Python required, got {sys.executable}")
    sandbox = verify_sandbox()
    for path in (FIXTURE, CONFIG, CUE, DOSBOX, GUARD, CORE):
        if not path.is_file():
            raise FileNotFoundError(path)
    if FIXTURE.stat().st_size != GW_SIZE or sha(FIXTURE) != GW_SHA256:
        raise RuntimeError("authentic fixture identity mismatch")
    if sha(CONFIG) != CONFIG_SHA256 or sha(CUE) != CUE_SHA256:
        raise RuntimeError("functional config or original CUE hash mismatch")
    if not re.search(r"(?im)^\s*imgmount\s+d\s+.*\.cue.*-ro\b", CONFIG.read_text(encoding="utf-8")):
        raise RuntimeError("original CUE is not mounted read-only")
    source_root = CORE.parents[2]
    revision = subprocess.run(["git", "-C", str(source_root), "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    if revision != REVISION:
        raise RuntimeError(f"pinned Staging revision mismatch: {revision}")
    source = CORE.read_text(encoding="utf-8", errors="replace")
    if not all(inspect_source(source).values()):
        raise RuntimeError("W3-136 selected restart coverage failed")
    if not re.search(r"w3_134_alloc_return_pending\s*&&\s*"
                     r"candidate_link_va\s*==\s*w3_134_alloc_return_link_va", source):
        raise RuntimeError("stack-derived allocator return is not in selected capture gate")

    evidence_dir = ROOT / "evidence/oracle_runs"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    stdout = evidence_dir / f"{RUN_ID}.stdout.json"
    stderr = evidence_dir / f"{RUN_ID}.stderr.txt"
    guard_record = evidence_dir / f"oracle_runs_{RUN_ID}.json"
    if any(path.exists() for path in (TRACE, RESULT, stdout, stderr, guard_record)):
        raise FileExistsError("refusing to overwrite W3-139 artifacts")
    runtime_hash = sha(DOSBOX)
    env = dict(os.environ)
    for key in tuple(env):
        if key.startswith("GWRECOMP_ANCHOR_") or key.startswith("GWRECOMP_EXEC_TRACE_"):
            env.pop(key, None)
    env.update({
        "GWRECOMP_GW_FILE_SIZE": str(GW_SIZE),
        "GWRECOMP_GW_LE_HEADER_OFFSET": "0x8f50",
        "GWRECOMP_GW_LE_OBJECT_TABLE_OFFSET": "0x9014",
        "GWRECOMP_EXEC_TRACE_PATH": str(TRACE),
        "GWRECOMP_EXEC_TRACE_MAX_BYTES": str(MAX_TRACE),
        "GWRECOMP_EXEC_TRACE_FILE_IO": "0",
        "GWRECOMP_ANCHOR_MAIN_ENTRY_LINK": "0x000af96c",
        "GWRECOMP_ANCHOR_MAIN_ENTRY_BYTES": "eb765741",
        "GWRECOMP_ANCHOR_CRT_ARGV_LOAD_LINK": "0x000c8702",
        "GWRECOMP_ANCHOR_GAME_MAIN_ENTRY_LINK": "0x00093f30",
    })
    command = [sys.executable, str(GUARD), "run", "--exe", str(DOSBOX), "--config", str(CONFIG),
               "--staging-dir", str(MOUNT), "--host-drive", "E:", "--run-id", RUN_ID,
               "--operation", "W3-139 bounded Smacker return/draw capture", "--commit-sha", REVISION,
               "--target-sha", GW_SHA256, "--runtime-sha", runtime_hash, "--fixture-sha", GW_SHA256,
               "--evidence-dir", str(evidence_dir), "--max-file-text-mib", "1",
               "--max-file-bin-mib", "64", "--max-run-gib", "1", "--host-floor-gib", "100",
               "--timeout-s", "30", "--growth-text-mibs", "8", "--growth-bin-mibs", "24", "--poll-hz", "1"]
    with stdout.open("xb") as out, stderr.open("xb") as err:
        subprocess.run(command, cwd=ROOT, env=env, stdout=out, stderr=err,
                       timeout=40, check=False)
    guard = json.loads(stdout.read_text(encoding="utf-8"))
    raw = TRACE.read_bytes() if TRACE.exists() else b""
    rows = parse_jsonl(raw)
    targets = []
    seen = set()
    for row in rows:
        if row.get("event") != "target_runtime_checkpoint":
            continue
        checkpoint = row.get("checkpoint")
        if checkpoint not in ("W3_134_LBMEMORYALLOC_RETURN", "W3_133_COPY_TO_SCREEN_ENTRY"):
            continue
        identity = (checkpoint, row.get("link_va"))
        if identity in seen:
            continue
        seen.add(identity)
        targets.append(row)
        if len(targets) >= CAP_EVENTS:
            break
    rebases = sorted({row["eip"] - row["link_va"] for row in targets
                      if isinstance(row.get("eip"), int) and isinstance(row.get("link_va"), int)})
    alloc_return = next((row for row in targets
                         if row.get("checkpoint") == "W3_134_LBMEMORYALLOC_RETURN" and
                         row.get("link_va") == 0xAE64F), None)
    copy = next((row for row in targets
                 if row.get("checkpoint") == "W3_133_COPY_TO_SCREEN_ENTRY" and
                 row.get("link_va") == 0xAE668), None)
    result = {
        "schema": "w3-139-smacker-return-draw/v1", "task": "W3-139", "run_id": RUN_ID,
        "target_sha256": GW_SHA256,
        "source": {"revision": revision, "core_sha256": sha(CORE), "runtime_sha256": runtime_hash},
        "preflight": {"sandbox": sandbox, "fixture_sha256": sha(FIXTURE),
                      "config_sha256": sha(CONFIG), "cue_sha256": sha(CUE),
                      "cue_read_only_mount": True, "selected_return_gate": True,
                      "timeout_seconds": 30, "trace_cap_bytes": MAX_TRACE,
                      "target_event_cap": CAP_EVENTS},
        "guard": {key: guard.get(key) for key in (
            "sandbox_verified", "sandbox_capacity", "host_free_before", "host_free_after", "limits",
            "exit_reason", "cause", "detail", "duration_s", "killed_processes", "evidence_path", "ok")},
        "trace": {"path": str(TRACE.relative_to(ROOT)), "bytes": len(raw),
                  "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
                  "event_count": len(rows), "runtime_rebases": [f"0x{x:08X}" for x in rebases],
                  "target_events": targets,
                  "allocator_return_value": alloc_return.get("eax") if alloc_return else None,
                  "allocator_return_observed": bool(alloc_return),
                  "copy_to_screen_entry_observed": bool(copy),
                  "framebuffer_write_observed": False,
                  "visible_frame_observed": False, "menu_observed": False},
    }
    RESULT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"result": str(RESULT), "allocator_return_observed": bool(alloc_return),
                      "copy_to_screen_entry_observed": bool(copy), "guard_cause": guard.get("cause")}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"PREFLIGHT/REPLAY FAILED CLOSED: {exc}", file=sys.stderr)
        raise SystemExit(2)
