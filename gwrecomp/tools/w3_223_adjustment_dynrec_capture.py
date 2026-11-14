"""Parser/runner for one bounded original AdjustAmount capture."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MOUNT = ROOT / "build/dosboxx_oracle/C"
FIXTURE = MOUNT / "GENEWARS/GW.EXE"
CONFIG = ROOT / "build/dosboxx_oracle/dosbox-staging.w3-067-functional.conf"
CUE = ROOT.parent / "GeneWarsFX/evidence/original_disc/Genewars (Europe) (En,Fr,De,Es,It,Sv).cue"
DOSBOX = ROOT / "build/staging-w3-059-exec/Debug/dosbox.exe"
GUARD = ROOT / "tools/oracle_guard.py"
SOURCE = ROOT / "third_party/dosbox-staging-w3-059-instrumented"
CORE = SOURCE / "src/cpu/core_dyn_x86.cpp"
REVISION = "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f"
GW_SIZE = 1_251_658
GW_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
CONFIG_SHA256 = "b2bac63096aa97a808abb8ea09486db79559b12a25a1410ea930be0e5eeffff1"
CUE_SHA256 = "1d417e3aed625d4f054b51054a1211562a19cd4f712b08e7846613517228a5b5"
MAX_TRACE_BYTES = 1_048_576
TARGET_LINKS = {
    "W3_213_ADJUST_CALLSITE": 0xC3D98,
    "W3_213_ADJUST_ENTRY": 0xC3F76,
    "W3_213_ADJUST_RETURN": 0xC3D9D,
}
RUN_ID = "w3-223-adjustment-20261009-01"
TRACE = MOUNT / "W3_223_ADJUSTMENT_20261009_01.jsonl"
RESULT = ROOT / "evidence/w3_223_adjustment_dynrec_capture.json"


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def parse_jsonl(raw: bytes) -> list[dict[str, Any]]:
    if len(raw) > MAX_TRACE_BYTES:
        raise ValueError("trace exceeds 1 MiB cap")
    rows = []
    for line in raw.splitlines():
        if line.strip():
            obj = json.loads(line)
            if isinstance(obj, dict):
                rows.append(obj)
    return rows


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    anchors = [r for r in rows if r.get("event") == "target_code_anchor"
               and r.get("anchor") == "CREATE_NEW_NHEAP_ENTRY"
               and r.get("link_va") == 0xC3D7A]
    anchor = anchors[0] if len(anchors) == 1 else None
    main_anchors = [r for r in rows if r.get("event") == "target_code_anchor"
                    and r.get("anchor") == "MAIN_ENTRY"
                    and r.get("link_va") == 0xAF96C
                    and r.get("byte_signature_matches") is True]
    main_anchor = main_anchors[0] if len(main_anchors) == 1 else None
    picked: dict[str, dict[str, Any]] = {}
    for row in rows:
        name = row.get("checkpoint")
        if row.get("event") != "target_runtime_checkpoint" or name not in TARGET_LINKS:
            continue
        if row.get("link_va") != TARGET_LINKS[name] or name in picked:
            continue
        picked[name] = row
    ordered_names = ["W3_213_ADJUST_CALLSITE", "W3_213_ADJUST_ENTRY", "W3_213_ADJUST_RETURN"]
    events = [picked[name] for name in ordered_names if name in picked]
    psp_set = {e.get("process_psp") for e in events}
    cs_set = {e.get("cs") for e in events}
    rebase_set = {e.get("w3_213_data_rebase") for e in events}
    complete = all(name in picked for name in ordered_names)
    temporal_order_ok = complete and all(
        int(picked[earlier].get("checkpoint_ordinal", 0)) <
        int(picked[later].get("checkpoint_ordinal", 0))
        for earlier, later in zip(ordered_names, ordered_names[1:]))
    mapping_ok = bool(anchor and anchor.get("measured_address_matches")
                      and anchor.get("data_rebase", 0) > 0
                      and rebase_set == {anchor.get("data_rebase")})
    same_process = len(psp_set) == 1 and len(cs_set) == 1
    samples_ok = all(picked[name].get("w3_213_globals_valid") is True
                     and len(picked[name].get("w3_213_mode_bytes_10b78e_10b790_hex", "")) == 6
                     for name in ("W3_213_ADJUST_ENTRY", "W3_213_ADJUST_RETURN") if name in picked)
    classification = ("ORIGINAL_ADJUSTAMOUNT_CAPTURED" if complete and temporal_order_ok and mapping_ok
                      and same_process and samples_ok else "INCONCLUSIVE")
    return {
        "classification": classification,
        "target_count": len(events),
        "target_event_cap": 3,
        "main_mapping": {
            "runtime_rebase": anchor.get("candidate_rebase") if anchor and
                              anchor.get("measured_address_matches") else None,
            "main_anchor": main_anchor,
            "main_entry_candidate_matches_verified_rebase": bool(
                main_anchor and anchor and
                main_anchor.get("candidate_rebase") == anchor.get("candidate_rebase")),
            "code_mapping_verified_by": "CREATE_NEW_NHEAP_ENTRY byte signature and measured runtime address"
                if anchor and anchor.get("measured_address_matches") else None,
            "data_rebase": anchor.get("data_rebase") if anchor else None,
            "anchor": anchor,
            "verified_for_all_checkpoints": mapping_ok,
        },
        "same_process": same_process,
        "temporal_order_verified": temporal_order_ok,
        "events": events,
        "missing": [name for name in ordered_names if name not in picked],
        "limitations": [
            "A captured callsite/entry/return sequence establishes observed values only; source-level meaning beyond the named stack slot/global remains unclaimed.",
            "A guard timeout after the target events is a bounded stop, not a failed guest operation.",
        ],
    }


def verify_sandbox() -> dict[str, Any]:
    proc = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                           str(ROOT / "tools/verify_oracle_sandbox.ps1"), "-Json"],
                          cwd=ROOT, capture_output=True, text=True, timeout=30, check=False)
    if proc.returncode:
        raise RuntimeError("GWORACLE verification failed: " + proc.stderr[-1000:])
    data = json.loads(proc.stdout)
    if data.get("verified") is not True or data.get("label") != "GWORACLE":
        raise RuntimeError(f"GWORACLE verification failed closed: {data}")
    return data


def preflight() -> dict[str, Any]:
    sandbox = verify_sandbox()
    for path in (FIXTURE, CONFIG, CUE, DOSBOX, GUARD, CORE):
        if not path.is_file():
            raise FileNotFoundError(path)
    if FIXTURE.stat().st_size != GW_SIZE or sha(FIXTURE) != GW_SHA256:
        raise ValueError("authentic original fixture fingerprint mismatch")
    if sha(CONFIG) != CONFIG_SHA256 or sha(CUE) != CUE_SHA256:
        raise ValueError("functional config or read-only original CUE fingerprint mismatch")
    conf = CONFIG.read_text(encoding="utf-8")
    if "GENEWARS.EXE" not in conf.upper() or "-RO" not in conf.upper():
        raise ValueError("functional launch or read-only CUE mount not verified")
    revision = subprocess.run(["git", "-C", str(SOURCE), "rev-parse", "HEAD"],
                             capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    if revision != REVISION:
        raise ValueError(f"pinned Staging source revision mismatch: {revision}")
    if TRACE.exists() or RESULT.exists():
        raise FileExistsError("refusing to overwrite W3-223 evidence")
    return {"sandbox": sandbox, "fixture_sha256": sha(FIXTURE),
            "fixture_bytes": FIXTURE.stat().st_size, "config_sha256": sha(CONFIG),
            "cue_sha256": sha(CUE), "source_revision": revision,
            "source_core_sha256": sha(CORE), "runtime_sha256": sha(DOSBOX),
            "trace_path": str(TRACE), "trace_max_bytes": MAX_TRACE_BYTES,
            "target_event_cap": 3, "timeout_seconds": 30}


def run_capture() -> dict[str, Any]:
    check = preflight()
    evidence_dir = ROOT / "evidence/oracle_runs"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    stdout = evidence_dir / f"{RUN_ID}.stdout.json"
    stderr = evidence_dir / f"{RUN_ID}.stderr.txt"
    if stdout.exists() or stderr.exists():
        raise FileExistsError("refusing to overwrite guard logs")
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
        "GWRECOMP_W3_213_CAPTURE_ONLY": "1",
        "GWRECOMP_W3_223_ADJUST_CAPTURE_ONLY": "1",
        "GWRECOMP_ANCHOR_MAIN_ENTRY_LINK": "0x000af96c",
        "GWRECOMP_ANCHOR_MAIN_ENTRY_BYTES": "eb765741",
        "GWRECOMP_ANCHOR_CREATE_NEW_NHEAP_ENTRY_LINK": "0x000c3d7a",
        "GWRECOMP_ANCHOR_CREATE_NEW_NHEAP_ENTRY_BYTES": "535152565750833d",
    })
    cmd = [sys.executable, str(GUARD), "run", "--exe", str(DOSBOX), "--config", str(CONFIG),
           "--staging-dir", str(MOUNT), "--host-drive", "E:", "--run-id", RUN_ID,
           "--operation", "W3-223 bounded original AdjustAmount dynrec split capture",
           "--commit-sha", REVISION, "--target-sha", GW_SHA256,
           "--runtime-sha", check["runtime_sha256"], "--fixture-sha", GW_SHA256,
           "--evidence-dir", str(evidence_dir), "--max-file-text-mib", "1",
           "--max-file-bin-mib", "64", "--max-run-gib", "1", "--host-floor-gib", "100",
           "--timeout-s", "30", "--growth-text-mibs", "8", "--growth-bin-mibs", "24",
           "--poll-hz", "1"]
    with stdout.open("xb") as out, stderr.open("xb") as err:
        proc = subprocess.run(cmd, cwd=ROOT, env=env, stdout=out, stderr=err,
                              timeout=45, check=False)
    guard = json.loads(stdout.read_text(encoding="utf-8"))
    raw = TRACE.read_bytes() if TRACE.exists() else b""
    rows = parse_jsonl(raw)
    capture = summarize(rows)
    retained = {
        key: guard.get(key) for key in (
            "run_id", "sandbox_verified", "sandbox", "limits", "exit_reason",
            "cause", "duration_s", "killed_processes", "host_free_before",
            "host_free_after", "max_staging_seen", "ok", "evidence_path")
        if key in guard
    }
    result = {
        "schema": "gwrecomp.w3-223-adjustment-dynrec-capture/v1", "task": "W3-223", "run_id": RUN_ID,
        "source": check, "guard": retained, "guard_process_returncode": proc.returncode,
        "trace": {"path": str(TRACE.relative_to(ROOT)), "bytes": len(raw),
                  "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
                  "event_count": len(rows), "max_bytes": MAX_TRACE_BYTES},
        "capture": capture,
    }
    RESULT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()
    result = preflight() if args.preflight_only else run_capture()
    if args.preflight_only:
        print(json.dumps(result, indent=2))
    else:
        print(json.dumps({"task": result["task"], "run_id": result["run_id"],
                          "guard": result["guard"], "trace": result["trace"],
                          "capture": result["capture"]}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"W3-223 FAIL CLOSED: {exc}", file=sys.stderr)
        raise SystemExit(2)

