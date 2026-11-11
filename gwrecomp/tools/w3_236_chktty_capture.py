#!/usr/bin/env python3
"""One guarded, bounded original __chktty_/AX=4400 BX=1 capture."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.w3_081_original_ah44_caller import summarize
from tools.w3_085_handle5_lineage import summarize_handle_lineage

MOUNT = ROOT / "build/dosboxx_oracle/C"
FIXTURE = MOUNT / "GENEWARS/GW.EXE"
CONFIG = ROOT / "build/dosboxx_oracle/dosbox-staging.w3-067-functional.conf"
DOSBOX = ROOT / "build/staging-w3-059-exec/Debug/dosbox.exe"
SOURCE = ROOT / "third_party/dosbox-staging-w3-059-instrumented"
GUARD = ROOT / "tools/oracle_guard.py"
TRACE = MOUNT / "W3_236_CHKTTY_AX4400.jsonl"
RESULT = ROOT / "evidence/w3_236_chktty_original_capture.json"
REVISION = "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f"
GW_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
GW_SIZE = 1_251_658
CONFIG_SHA256 = "b2bac63096aa97a808abb8ea09486db79559b12a25a1410ea930be0e5eeffff1"
CUE = Path(r"E:\GeneWarsFX\evidence\original_disc\Genewars (Europe) (En,Fr,De,Es,It,Sv).cue")
SOURCE_ADDRESS = Path(r"<GENEWARS_HDD_ROOT>\ADDRESS.TXT")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def verify_sandbox() -> dict:
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
         str(ROOT / "tools/verify_oracle_sandbox.ps1"), "-Json"],
        cwd=ROOT, capture_output=True, text=True, timeout=30, check=False)
    if proc.returncode:
        raise RuntimeError(f"GWORACLE verification failed: {proc.stderr[-1000:]}")
    value = json.loads(proc.stdout)
    if value.get("verified") is not True or value.get("label", value.get("volume")) != "GWORACLE":
        raise RuntimeError(f"GWORACLE not verified: {value}")
    if value.get("host_free_bytes", 0) < value.get("host_floor_bytes", 0):
        raise RuntimeError("host free-space floor is not satisfied")
    return value


def extract_capture(events: list[dict]) -> dict:
    checkpoints = [e for e in events if e.get("event") == "target_runtime_checkpoint"]
    caller = [e for e in checkpoints if e.get("checkpoint") in {
        "AH44_CHKTTY_ENTRY", "AH44_CHKTTY_HANDLE_LOAD", "AH44_CHKTTY_ISATTY_CALL",
        "AH44_ISATTY_ENTRY"}]
    bx1 = [e for e in checkpoints if e.get("checkpoint") == "DOS_AH44_BX1_CALLSITE"]
    returns = [e for e in checkpoints if e.get("checkpoint") == "DOS_AH44_BX1_RETURN"]
    # Keep both serializer forms: some bounded captures also carry the CPU hook row.
    bx1.extend(e for e in events if e.get("event") == "original_cpu_int21_ah44_bx1_entry"
               and e.get("mapping_valid") is True
               and e.get("int_instruction_link_va") == 0x000c8973)
    file_events = [e for e in events if e.get("event") in {
        "dos_handle_open", "dos_file_create", "dos_address_txt_write", "dos_handle_close"}
        and "ADDRESS.TXT" in (str(e.get("path", "")) + str(e.get("requested_path", ""))).upper()]
    return {"chktty_checkpoints": caller[:32], "bx1_callsites": bx1[:8],
            "bx1_returns": returns[:8], "address_file_events": file_events[:32]}


def main() -> int:
    sandbox = verify_sandbox()
    for p in (FIXTURE, CONFIG, DOSBOX, GUARD, CUE, SOURCE_ADDRESS):
        if not p.is_file():
            raise FileNotFoundError(p)
    if TRACE.exists() or RESULT.exists():
        raise FileExistsError("refusing to overwrite W3-236 artifacts")
    if (FIXTURE.stat().st_size, sha256(FIXTURE)) != (GW_SIZE, GW_SHA256):
        raise ValueError("target GW.EXE size/hash mismatch")
    if sha256(CONFIG) != CONFIG_SHA256:
        raise ValueError("W3-067 functional configuration hash mismatch")
    revision = subprocess.run(["git", "-C", str(SOURCE), "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    if revision != REVISION:
        raise ValueError(f"pinned Staging revision mismatch: {revision}")
    guest_address = MOUNT / "ADDRESS.TXT"
    if not guest_address.is_file():
        raise FileNotFoundError("expected authenticated source ADDRESS.TXT is absent in the sandbox")
    source_hash, guest_hash = sha256(SOURCE_ADDRESS), sha256(guest_address)
    if source_hash != guest_hash:
        raise ValueError("sandbox ADDRESS.TXT differs from the read-only functional source")
    address_snapshot = guest_address.read_bytes()
    if len(address_snapshot) > 4096:
        raise ValueError("ADDRESS.TXT snapshot exceeds the small-file bound")
    runtime_hash = sha256(DOSBOX)
    cue_hash = sha256(CUE)

    env = dict(os.environ)
    for key in tuple(env):
        if key.startswith("GWRECOMP_ANCHOR_") or key.startswith("GWRECOMP_EXEC_TRACE_"):
            env.pop(key, None)
    env.update({
        "GWRECOMP_GW_FILE_SIZE": str(GW_SIZE),
        "GWRECOMP_GW_LE_HEADER_OFFSET": "0x8f50",
        "GWRECOMP_GW_LE_OBJECT_TABLE_OFFSET": "0x9014",
        "GWRECOMP_EXEC_TRACE_PATH": str(TRACE),
        "GWRECOMP_EXEC_TRACE_MAX_BYTES": "1048576",
        "GWRECOMP_EXEC_TRACE_FILE_IO": "0",
        "GWRECOMP_ANCHOR_MAIN_ENTRY_LINK": "0x000af96c",
        "GWRECOMP_ANCHOR_MAIN_ENTRY_BYTES": "eb765741",
        "GWRECOMP_ANCHOR_CRT_ARGV_LOAD_LINK": "0x000c8702",
        "GWRECOMP_ANCHOR_GAME_MAIN_ENTRY_LINK": "0x00093f30",
    })
    evidence_dir = ROOT / "evidence/oracle_runs"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    command = [sys.executable, str(GUARD), "run", "--exe", str(DOSBOX),
               "--config", str(CONFIG), "--staging-dir", str(MOUNT), "--host-drive", "E:",
               "--run-id", "w3-236-chktty-ax4400-20261009-01",
               "--operation", "W3-236 original chktty caller and AX=4400 BX=1",
               "--commit-sha", REVISION, "--target-sha", GW_SHA256,
               "--runtime-sha", runtime_hash, "--fixture-sha", GW_SHA256,
               "--evidence-dir", str(evidence_dir), "--max-file-text-mib", "1",
               "--max-file-bin-mib", "64", "--max-run-gib", "1",
               "--host-floor-gib", "100", "--timeout-s", "30",
               "--growth-text-mibs", "8", "--growth-bin-mibs", "24", "--poll-hz", "1"]
    proc = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True,
                          timeout=45, check=False)
    try:
        guard = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"oracle_guard returned invalid JSON: {proc.stdout[-1000:]}") from exc
    if not TRACE.is_file() or TRACE.stat().st_size > 1_048_576:
        raise RuntimeError("guarded trace missing or over 1 MiB cap")
    raw = TRACE.read_bytes()
    events = [json.loads(line) for line in raw.decode("utf-8", errors="replace").splitlines()
              if line.strip()]
    summary = summarize(events)
    captures = extract_capture(events)
    callsite = next((e for e in captures["chktty_checkpoints"]
                     if e.get("checkpoint") == "AH44_CHKTTY_ISATTY_CALL"), None)
    psp = (summary.get("main_entry") or {}).get("process_psp")
    lineage = summarize_handle_lineage(events, psp,
                                       as_of_sequence=callsite.get("sequence") if callsite else None)
    result = {
        "schema": "gwrecomp-w3-236-original-chktty-caller-capture/v1",
        "task": "W3-236",
        "captured_utc": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        "classification": "ORIGINAL_OBSERVED" if captures["bx1_callsites"] else "INCONCLUSIVE_NO_BX1",
        "provenance": {"original_observations": True, "native_comparison_source": "evidence/native_setup_replay_w1_085.json"},
        "preflight": {"sandbox": sandbox, "target_sha256": GW_SHA256,
                      "cue_sha256": cue_hash, "config_sha256": sha256(CONFIG),
                      "runtime_sha256": runtime_hash, "staging_revision": revision,
                      "command_tail_expected": "-k 38928", "timeout_s": 30,
                      "trace_cap_bytes": 1048576},
        "address_txt_initial": {"guest_path": "C:\\ADDRESS.TXT", "source_path": str(SOURCE_ADDRESS),
                                "size": len(address_snapshot), "sha256": guest_hash,
                                "source_size": SOURCE_ADDRESS.stat().st_size,
                                "source_sha256": source_hash,
                                "source_provenance": "present in the read-only HDD root of the user's known-functional package; creation history unknown",
                                "matches_read_only_functional_source": True,
                                "snapshot_hex": address_snapshot.hex()},
        "guard": guard,
        "guard_returncode": proc.returncode,
        "guard_stderr_tail": proc.stderr[-4000:],
        "trace": {"path": str(TRACE), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                  "event_count": len(events)},
        "mapping": summary.get("main_mapping"),
        "effective_child_argv": summary.get("effective_child_argv"),
        "effective_psp_tail": summary.get("psp_command_tail"),
        "chktty_and_bx1": captures,
        "handle_lineage_at_callsite": lineage,
        "last_checkpoint": (summary.get("last_target_checkpoint") or {}).get("checkpoint"),
        "native_comparison": {"task": "W1-085", "evidence_level": "NATIVE_REACHED",
                              "caller": "__chktty_ 0xBA4D6 -> isatty_ callsite 0xBA4E4",
                              "helper_ordinal": 11, "eax": "0x1", "request": "AX=4400 BX=1 at 0xC8973"},
        "limitations": [] if captures["bx1_callsites"] else [
            "No mapped original BX=1 request was captured in this bounded run.",
            "No retry is authorized without a new measured hypothesis."],
    }
    RESULT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"result": str(RESULT), "classification": result["classification"],
                      "guard_exit": guard.get("exit_reason"), "trace": result["trace"],
                      "chktty_events": len(captures["chktty_checkpoints"]),
                      "bx1_calls": len(captures["bx1_callsites"]),
                      "address_initial_sha256": guest_hash}, indent=2))
    return 0 if captures["bx1_callsites"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"PREFLIGHT/REPLAY FAILED CLOSED: {exc}", file=sys.stderr)
        raise SystemExit(2)
