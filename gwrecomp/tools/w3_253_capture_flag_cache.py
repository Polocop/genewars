"""One bounded protected replay after caching the W3-237 capture gate."""
from __future__ import annotations
import os as _gw_os
from pathlib import Path as _GwPath
_GW_ROOT=str(_GwPath(__file__).resolve().parents[1])
_GW_FX=_gw_os.environ.get("GENEWARSFX_ROOT",_gw_os.path.join(_GW_ROOT,"third_party","GeneWarsFX"))
_GW_INSTALL=_gw_os.environ.get("GENEWARS_INSTALL_DIR","<set GENEWARS_INSTALL_DIR>")
_GW_INSTALL_PARENT=str(_GwPath(_GW_INSTALL).parent)

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.w3_251_pairing import pair_events

MOUNT = ROOT / "build/dosboxx_oracle/C"
FIXTURE = MOUNT / "GENEWARS/GW.EXE"
CONFIG = ROOT / "build/dosboxx_oracle/dosbox-staging.w3-067-functional.conf"
DOSBOX = ROOT / "build/staging-w3-253-exec/Debug/dosbox.exe"
SOURCE = ROOT / "third_party/dosbox-staging-w3-059-instrumented"
GUARD = ROOT / "tools/oracle_guard.py"
CUE = Path((_GW_FX + '\\evidence\\original_disc\\Genewars (Europe) (En,Fr,De,Es,It,Sv).cue'))
ADDRESS = MOUNT / "ADDRESS.TXT"
SOURCE_ADDRESS = Path((_GW_INSTALL_PARENT + '\\ADDRESS.TXT'))
TRACE = MOUNT / "W3_253_ENTRY_RETURN_20261009_01.jsonl"
OUTPUT = ROOT / "evidence/w3_253_capture_flag_cache.json"
RUN_ID = "w3-253-cached-capture-gate-20261009-01"
REVISION = "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f"
GW_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
GW_SIZE = 1_251_658
CONFIG_SHA256 = "b2bac63096aa97a808abb8ea09486db79559b12a25a1410ea930be0e5eeffff1"
CUE_SHA256 = "1d417e3aed625d4f054b51054a1211562a19cd4f712b08e7846613517228a5b5"
ADDRESS_SHA256 = "7b1c5391160e1d95393d3abe980dde978b8a79ecb2814e144ee032d9710ba6ee"
TRACE_CAP = 1_048_576


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_sandbox() -> dict:
    proc = subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                           "-File", str(ROOT / "tools/verify_oracle_sandbox.ps1"),
                           "-Path", str(MOUNT), "-Json"], cwd=ROOT,
                          capture_output=True, text=True, timeout=30, check=False)
    if proc.returncode:
        raise RuntimeError(f"GWORACLE verification failed: {proc.stderr[-1000:]}")
    result = json.loads(proc.stdout.strip().splitlines()[-1])
    if result.get("verified") is not True or result.get("volume", result.get("label")) != "GWORACLE":
        raise RuntimeError(f"GWORACLE is not verified: {result}")
    if result.get("capacity_bytes", 0) < 15 * 1024**3:
        raise RuntimeError("GWORACLE is below required capacity")
    if result.get("host_free_bytes", 0) < result.get("host_floor_bytes", 0):
        raise RuntimeError("host free-space floor is not satisfied")
    return result


def preflight() -> dict:
    sandbox = verify_sandbox()
    for path in (FIXTURE, CONFIG, DOSBOX, GUARD, CUE, ADDRESS, SOURCE_ADDRESS):
        if not path.is_file():
            raise FileNotFoundError(path)
    if TRACE.exists() or OUTPUT.exists():
        raise FileExistsError("refusing to overwrite W3-253 capture")
    if (FIXTURE.stat().st_size, sha256(FIXTURE)) != (GW_SIZE, GW_SHA256):
        raise ValueError("GW.EXE size/hash mismatch")
    if sha256(CONFIG) != CONFIG_SHA256:
        raise ValueError("functional Staging config hash mismatch")
    if sha256(CUE) != CUE_SHA256:
        raise ValueError("original CUE hash mismatch")
    if sha256(ADDRESS) != ADDRESS_SHA256 or sha256(SOURCE_ADDRESS) != ADDRESS_SHA256:
        raise ValueError("ADDRESS.TXT provenance/hash mismatch")
    revision = subprocess.run(["git", "-C", str(SOURCE), "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=10,
                              check=True).stdout.strip()
    if revision != REVISION:
        raise ValueError(f"pinned source revision mismatch: {revision}")
    binary = DOSBOX.read_bytes()
    if b"0.83.0-RC1 (81835)" not in binary:
        raise ValueError("instrumented executable version marker mismatch")
    return {"sandbox": sandbox, "target_sha256": sha256(FIXTURE),
            "target_size": FIXTURE.stat().st_size, "config_sha256": sha256(CONFIG),
            "cue_sha256_before": sha256(CUE), "address_sha256": sha256(ADDRESS),
            "address_size": ADDRESS.stat().st_size, "staging_revision": revision,
            "runtime_sha256": sha256(DOSBOX), "runtime_size": DOSBOX.stat().st_size,
            "runtime_version_marker": "0.83.0-RC1 (81835)",
            "source_sha256": sha256(SOURCE / "src/cpu/core_dyn_x86.cpp"),
            "trace_cap_bytes": TRACE_CAP,
            "expected_dos_exec_tail_chain": ["/c gw  -k 38928", " -k 38928",
                "/c DOS4GW C:\\GENEWARS\\GW.EXE -k 38928 ",
                " C:\\GENEWARS\\GW.EXE -k 38928"]}


def compact_guard(guard: dict) -> dict:
    keep = ("run_id", "start_time", "operation", "argv", "staging", "host_drive",
            "host_free_before", "host_free_after", "sandbox_verified", "sandbox_capacity",
            "provenance", "limits", "exit_reason", "cause", "detail", "exit_code",
            "duration_s", "ticks", "max_staging_seen", "max_file_seen", "killed_processes")
    return {key: guard.get(key) for key in keep if key in guard}


def main() -> int:
    pre = preflight()
    env = dict(os.environ)
    for key in tuple(env):
        if key.startswith(("GWRECOMP_ANCHOR_", "GWRECOMP_EXEC_TRACE_", "GWRECOMP_W3_237_",
                           "GWRECOMP_W3_249_", "GWRECOMP_W3_251_")):
            env.pop(key, None)
    env.update({
        "GWRECOMP_GW_FILE_SIZE": str(GW_SIZE),
        "GWRECOMP_GW_LE_HEADER_OFFSET": "0x8f50",
        "GWRECOMP_GW_LE_OBJECT_TABLE_OFFSET": "0x9014",
        "GWRECOMP_EXEC_TRACE_PATH": str(TRACE),
        "GWRECOMP_EXEC_TRACE_MAX_BYTES": str(TRACE_CAP),
        "GWRECOMP_EXEC_TRACE_FILE_IO": "0",
        "GWRECOMP_W3_237_CAPTURE_ONLY": "1",
        "GWRECOMP_W3_251_CAPTURE_ONLY": "1",
        "GWRECOMP_ANCHOR_MAIN_ENTRY_LINK": "0x000af96c",
        "GWRECOMP_ANCHOR_MAIN_ENTRY_BYTES": "eb765741",
        "GWRECOMP_ANCHOR_CRT_ARGV_LOAD_LINK": "0x000c8702",
        "GWRECOMP_ANCHOR_GAME_MAIN_ENTRY_LINK": "0x00093f30",
    })
    evidence_dir = ROOT / "evidence/oracle_runs"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    command = [sys.executable, str(GUARD), "run", "--exe", str(DOSBOX),
               "--config", str(CONFIG), "--staging-dir", str(MOUNT), "--host-drive", "E:",
               "--run-id", RUN_ID, "--operation", "W3-253 cached isatty capture gate",
               "--commit-sha", REVISION, "--target-sha", GW_SHA256,
               "--runtime-sha", pre["runtime_sha256"], "--fixture-sha", GW_SHA256,
               "--evidence-dir", str(evidence_dir), "--max-file-text-mib", "1",
               "--max-file-bin-mib", "64", "--max-run-gib", "1", "--host-floor-gib", "100",
               "--timeout-s", "30", "--growth-text-mibs", "8", "--growth-bin-mibs", "24",
               "--poll-hz", "1"]
    proc = subprocess.run(command, cwd=ROOT, env=env, capture_output=True,
                          timeout=45, check=False)
    try:
        guard_raw = json.loads(proc.stdout.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        guard_raw = {"exit_reason": "guard_output_invalid", "exit_code": proc.returncode,
                     "stdout_tail": proc.stdout[-1000:].decode("utf-8", errors="replace"),
                     "stderr_tail": proc.stderr[-1000:].decode("utf-8", errors="replace")}
    raw = TRACE.read_bytes() if TRACE.is_file() else b""
    if len(raw) > TRACE_CAP:
        raise ValueError("guard did not enforce trace cap")
    events = [json.loads(line) for line in raw.decode("utf-8", errors="replace").splitlines()
              if line.strip()]
    paired = pair_events(events)
    tails = [event.get("command_tail", "") for event in events if event.get("event") == "dos_execute"]
    launch_chain_observed = all(any(tail == expected for tail in tails)
                                for expected in pre["expected_dos_exec_tail_chain"])
    cue_after = sha256(CUE) if CUE.is_file() else None
    elapsed = [event for event in events if event.get("link_va") in ("0x000c896a", 0x000c896a)
               or event.get("link_va") in ("0x000c8973", 0x000c8973)]
    classification = ("ORIGINAL_CALLER_PAIRED" if paired["pairs"] and paired["pairs"][-1]["status"] == "PAIRED"
                      else "ORIGINAL_BX1_REQUEST_CALLER_UNKNOWN" if paired["bx1_requests"]
                      else "INCONCLUSIVE_TIMEOUT_BEFORE_BX1" if guard_raw.get("cause") == "TIMEOUT"
                      else "INCONCLUSIVE_NO_BX1")
    result = {
        "schema": "gwrecomp-w3-253-capture-flag-cache/v1", "task": "W3-253",
        "classification": classification,
        "evidence_level": "ORIGINAL_OBSERVED" if events else "INCONCLUSIVE",
        "hypothesis": "A dispatcher-local environment read for W3-237 is cached once; one replay tests whether this changes time to shared isatty entry. This is not causal proof by itself.",
        "preflight": pre, "guard": compact_guard(guard_raw),
        "guard_returncode": proc.returncode,
        "guard_stderr_tail": proc.stderr[-1000:].decode("utf-8", errors="replace"),
        "trace": {"path": str(TRACE), "bytes": len(raw),
                  "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
                  "event_count": len(events), "max_bytes": TRACE_CAP},
        "dos_execute_tails": tails, "launch_chain_observed": launch_chain_observed,
        "caller_pairing": paired, "isatty_timeline_events": elapsed,
        "first_target_checkpoint": next((event for event in events
            if event.get("event") == "target_runtime_checkpoint"), None),
        "cue_sha256_after": cue_after, "cue_unchanged": cue_after == pre["cue_sha256_before"],
        "menu_reached": False, "framebuffer_reached": False, "gameplay_reached": False,
    }
    OUTPUT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(OUTPUT), "classification": classification,
                      "guard": guard_raw.get("exit_reason"),
                      "launch_chain_observed": launch_chain_observed,
                      "isatty_entries": len(paired["isatty_entries"]),
                      "bx1_requests": len(paired["bx1_requests"]),
                      "caller": paired["dynamic_caller"], "trace_bytes": len(raw)}, indent=2))
    return 0 if classification == "ORIGINAL_CALLER_PAIRED" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"PREFLIGHT/REPLAY FAILED CLOSED: {exc}", file=sys.stderr)
        raise SystemExit(2)
