from __future__ import annotations

import hashlib
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(r"E:\GWRecomp")
sys.path.insert(0, str(ROOT))
from tests.test_w3_221_original_ax4400_bx1_alignment import parse_trace

MOUNT = ROOT / "build/dosboxx_oracle/C"
CONFIG = ROOT / "build/dosboxx_oracle/dosbox-staging.w3-067-functional.conf"
CUE = Path(r"E:\GeneWarsFX\evidence\original_disc\Genewars (Europe) (En,Fr,De,Es,It,Sv).cue")
SOURCE = ROOT / "third_party/dosbox-staging-w3-059-instrumented"
DOSBOX = ROOT / "build/staging-w3-059-exec/Debug/dosbox.exe"
GUARD = ROOT / "tools/oracle_guard.py"
TRACE = MOUNT / "W3_224_AH4400_ORDINAL6_20261009_01.jsonl"
RUN_ID = "w3-224-ah4400-ordinal6-20261009-01"
ORACLE_DIR = ROOT / "evidence/oracle_runs"
GUARD_JSON = ORACLE_DIR / f"oracle_runs_{RUN_ID}.json"
GUARD_STDOUT = GUARD_JSON.with_name(GUARD_JSON.stem + ".stdout.json")
GUARD_STDERR = GUARD_JSON.with_name(GUARD_JSON.stem + ".stderr.txt")
RESULT = ROOT / "evidence/w3_224_ah4400_ordinal6_caller.json"
REVISION = "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f"
TARGET_SHA = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
CUE_SHA = "1d417e3aed625d4f054b51054a1211562a19cd4f712b08e7846613517228a5b5"
CONFIG_SHA = "b2bac63096aa97a808abb8ea09486db79559b12a25a1410ea930be0e5eeffff1"
MAX_TRACE_BYTES = 1_048_576
HOST_FLOOR_BYTES = 100 * 1024**3


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def pair_ordinal6_context(capture: dict) -> dict:
    """Pair only the sixth AH=4400 callback with same-register checkpoints."""
    callbacks = capture.get("ax4400_callbacks", [])
    service = next((row for row in callbacks if row.get("ordinal") == 6), None)
    if service is None:
        return {"observed": False, "reason": "ordinal_6_not_in_bounded_window"}
    selected = capture.get("selected_events", [])
    checkpoints = [row for row in selected
                   if row.get("event") == "target_runtime_checkpoint"
                   and row.get("process_psp") == service.get("process_psp")]
    matched_call = next((row for row in reversed(checkpoints)
                         if row.get("sequence", 0) < service.get("sequence", 0)
                         and row.get("link_va") == 0xC8973
                         and all((row.get(reg, -1) & 0xFFFF) == service.get(field)
                                 for reg, field in (("eax", "in_ax"), ("ebx", "in_bx"),
                                                    ("ecx", "in_cx"), ("edx", "in_dx")))), None)
    call_sequence = (matched_call or service).get("sequence", 0)
    isatty = next((row for row in reversed(checkpoints)
                   if 0 < call_sequence - row.get("sequence", 0) <= 2
                   and row.get("checkpoint") == "AH44_ISATTY_ENTRY"), None)
    chktty_call = next((row for row in reversed(checkpoints)
                        if isatty is not None
                        and 0 < isatty.get("sequence", 0) - row.get("sequence", 0) <= 2
                        and row.get("checkpoint") == "AH44_CHKTTY_ISATTY_CALL"), None)
    return {
        "observed": True,
        "ordinal": service.get("ordinal"),
        "service": service,
        "same_register_callsite": matched_call,
        "isatty_entry": isatty,
        "chktty_isatty_callsite": chktty_call,
        "same_process": all(row is None or row.get("process_psp") == service.get("process_psp")
                            for row in (matched_call, isatty, chktty_call)),
        "has_same_register_int21_site": matched_call is not None,
        "has_isatty_entry": isatty is not None,
        "has_chktty_caller": chktty_call is not None,
        "has_caller_chain": matched_call is not None and isatty is not None and chktty_call is not None,
    }


def verify_sandbox() -> dict:
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
         str(ROOT / "tools/verify_oracle_sandbox.ps1"), "-Json"],
        cwd=ROOT, capture_output=True, text=True, timeout=30, check=False)
    if proc.returncode:
        raise RuntimeError(f"GWORACLE verification failed: {proc.stderr[-1000:]}")
    result = json.loads(proc.stdout)
    if result.get("verified") is not True or result.get("label") != "GWORACLE":
        raise RuntimeError(f"GWORACLE not verified: {result}")
    if result.get("capacity_bytes", 0) > 16 * 1024**3:
        raise RuntimeError("GWORACLE capacity exceeds 16 GiB")
    if result.get("host_free_bytes", 0) < HOST_FLOOR_BYTES:
        raise RuntimeError("E: free space fell below the 100 GiB floor")
    return result


def preflight() -> dict:
    check = subprocess.run(
        [str(ROOT / "coordination/autopilot.cmd"), "check", "W3-224", "--worker", "WORK3"],
        cwd=ROOT, capture_output=True, text=True, timeout=15, check=False)
    if check.returncode:
        raise RuntimeError(f"W3-224 lease invalid: {check.stdout} {check.stderr}")
    sandbox = verify_sandbox()
    required = [
        MOUNT / "GENEWARS/GW.EXE", MOUNT / "GENEWARS/GENEWARS.EXE",
        MOUNT / "GENEWARS/DOS4GW.EXE", MOUNT / "GENEWARS/MAIN.EXE",
        MOUNT / "GENEWARS/CONFIG.INI", MOUNT / "ADDRESS.TXT",
        MOUNT / "GENEWARS/DATA/TEXT.DAT", CONFIG, CUE, DOSBOX, GUARD,
        SOURCE / "src/cpu/core_dyn_x86.cpp", SOURCE / "src/cpu/cpu.cpp",
        SOURCE / "src/dos/dos.cpp",
    ]
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise FileNotFoundError("required fixture/tool missing: " + ", ".join(missing))
    target = MOUNT / "GENEWARS/GW.EXE"
    if target.stat().st_size != 1_251_658 or sha256(target) != TARGET_SHA:
        raise RuntimeError("guest GW.EXE is not the authenticated target")
    if sha256(CUE) != CUE_SHA or sha256(CONFIG) != CONFIG_SHA:
        raise RuntimeError("read-only original CUE or functional config fingerprint changed")
    revision = subprocess.run(
        ["git", "-C", str(SOURCE), "rev-parse", "HEAD"],
        capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    if revision != REVISION:
        raise RuntimeError(f"pinned Staging revision changed: {revision}")
    runtime_sha = sha256(DOSBOX)
    if any(path.exists() for path in (TRACE, GUARD_JSON, GUARD_STDOUT, GUARD_STDERR, RESULT)):
        raise FileExistsError("refusing to overwrite prior W3-224 artifacts")
    config_text = CONFIG.read_text(encoding="utf-8")
    if "GENEWARS.EXE" not in config_text.upper() or "-RO" not in config_text.upper():
        raise RuntimeError("functional launcher or read-only CUE mount not verified")
    guest_paths = ["GW.EXE", "GENEWARS.EXE", "DOS4GW.EXE", "MAIN.EXE",
                   "CONFIG.INI", "DATA/TEXT.DAT"]
    guest = MOUNT / "GENEWARS"
    guest_fingerprint = {rel: {"bytes": (guest / rel).stat().st_size,
                               "sha256": sha256(guest / rel)} for rel in guest_paths}
    address_txt = MOUNT / "ADDRESS.TXT"
    if address_txt.is_file():
        guest_fingerprint["../ADDRESS.TXT"] = {
            "bytes": address_txt.stat().st_size, "sha256": sha256(address_txt)}
    return {
        "sandbox": sandbox,
        "task_lease_check": check.stdout.strip(),
        "fixture": guest_fingerprint,
        "cue": {"path": str(CUE), "sha256": CUE_SHA, "read_only_mount": True},
        "config": {"path": str(CONFIG), "sha256": CONFIG_SHA,
                   "content_unchanged": True},
        "runtime": {"path": str(DOSBOX), "sha256": runtime_sha,
                    "staging_revision": revision},
        "trace": {"path": str(TRACE), "max_bytes": MAX_TRACE_BYTES},
        "launch": {"autoexec": ["C:", "CD \\GENEWARS", "GENEWARS.EXE"],
                   "launcher_arguments": "none; child tail must be observed in DOS EXEC events",
                   "guard_timeout_s": 30},
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()
    pre = preflight()
    if args.preflight_only:
        print(json.dumps(pre, indent=2))
        return 0
    env = dict(os.environ)
    for key in tuple(env):
        if (key.startswith("GWRECOMP_ANCHOR_") or
                key.startswith("GWRECOMP_EXEC_TRACE_") or
                key in ("GWRECOMP_W3_213_CAPTURE_ONLY",
                        "GWRECOMP_W3_214_CAPTURE_ONLY",
                        "GWRECOMP_W3_223_ADJUST_CAPTURE_ONLY",
                        "GWRECOMP_W3_224_AH44_CAPTURE_ONLY")):
            env.pop(key, None)
    env.update({
        "GWRECOMP_GW_FILE_SIZE": "1251658",
        "GWRECOMP_GW_LE_HEADER_OFFSET": "0x8f50",
        "GWRECOMP_GW_LE_OBJECT_TABLE_OFFSET": "0x9014",
        "GWRECOMP_EXEC_TRACE_PATH": str(TRACE),
        "GWRECOMP_EXEC_TRACE_MAX_BYTES": str(MAX_TRACE_BYTES),
        "GWRECOMP_EXEC_TRACE_FILE_IO": "0",
        "GWRECOMP_W3_224_AH44_CAPTURE_ONLY": "1",
        "GWRECOMP_ANCHOR_MAIN_ENTRY_LINK": "0x000af96c",
        "GWRECOMP_ANCHOR_MAIN_ENTRY_BYTES": "eb765741",
        "GWRECOMP_ANCHOR_CRT_ARGV_LOAD_LINK": "0x000c8702",
        "GWRECOMP_ANCHOR_GAME_MAIN_ENTRY_LINK": "0x00093f30",
    })
    ORACLE_DIR.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable, str(GUARD), "run", "--exe", str(DOSBOX), "--config", str(CONFIG),
        "--staging-dir", str(MOUNT), "--host-drive", "E:", "--run-id", RUN_ID,
        "--operation", "W3-224 original AX=4400 caller and seed alignment",
        "--commit-sha", REVISION, "--target-sha", TARGET_SHA,
        "--runtime-sha", pre["runtime"]["sha256"], "--fixture-sha", TARGET_SHA,
        "--evidence-dir", str(ORACLE_DIR), "--max-file-text-mib", "1",
        "--max-file-bin-mib", "64", "--max-run-gib", "1",
        "--host-floor-gib", "100", "--timeout-s", "30",
        "--growth-text-mibs", "8", "--growth-bin-mibs", "24", "--poll-hz", "1",
    ]
    with GUARD_STDOUT.open("xb") as stdout, GUARD_STDERR.open("xb") as stderr:
        proc = subprocess.run(command, cwd=ROOT, env=env, stdout=stdout,
                              stderr=stderr, timeout=40, check=False)
    guard = json.loads(GUARD_STDOUT.read_text(encoding="utf-8"))
    raw = TRACE.read_bytes() if TRACE.is_file() else b""
    capture = parse_trace(raw) if raw else {
        "selected_events": [], "ax4400_callbacks": [], "setup_ax4400_callbacks": [],
        "caller_entries_at_target": [], "pairs": [], "dos_exec_chain": [],
        "tail_minus_k_38928_observed": False,
        "classification": "NO_TARGETED_TRACE_EVENTS",
    }
    target_anchors = [row for row in capture["selected_events"]
                      if row.get("event") == "target_code_anchor"]
    main_map = [row for row in target_anchors
                if row.get("link_va") == 0xAF96C or row.get("anchor") == "MAIN_ENTRY"]
    callbacks = capture["ax4400_callbacks"]
    ordinal6_context = pair_ordinal6_context(capture)
    result = {
        "schema": "gwrecomp.original-ax4400-bx1-alignment-w3-221/v1",
        "task": "W3-224",
        "run_id": RUN_ID,
        "captured_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "preflight": pre,
        "guard": guard,
        "guard_returncode": proc.returncode,
        "trace": {"path": str(TRACE), "exists": TRACE.is_file(),
                  "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
                  "raw_event_count": sum(bool(line.strip()) for line in raw.splitlines()),
                  "filtered_event_count": len(capture["selected_events"])},
        "dos_launch_tail": [row for row in capture["dos_exec_chain"]
                            if row.get("executable", "").upper().endswith(("GW.EXE", "DOS4GW.EXE"))],
        "tail_minus_k_38928_observed": capture["tail_minus_k_38928_observed"],
        "main_mapping_anchors": main_map,
        "all_code_mapping_anchors": target_anchors,
        "ax4400_callbacks": callbacks,
        "setup_ax4400_callbacks": capture["setup_ax4400_callbacks"],
        "caller_entries_at_C8973": capture["caller_entries_at_target"],
        "paired_events": capture["pairs"],
        "ordinal6_context": ordinal6_context,
        "handle_table_snapshots": [row for row in capture["selected_events"]
                                    if row.get("event") == "dos_handle_table_snapshot"],
        "classification": capture["classification"],
        "scope": {"oracle_guard_used": True, "guard_sandbox_verified": guard.get("sandbox_verified") is True,
                  "guest_executable_modified": False, "config_modified": False,
                  "personal_source_modified": False, "global_instruction_trace": False,
                  "memory_dump": False, "injected_dos_response": False},
        "limitations": [
            "AX=4400 callback events are kept separately from protected caller entries; only entries with verified mapping and INT 21 bytes are attributed to link VA 0xC8973.",
            "A bounded timeout with no BX=1 caller means not observed in this window, not absent from all executions.",
            "DOS EXEC chain and -k 38928 tail are reported only when present in the captured trace.",
        ],
    }
    RESULT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"result": str(RESULT), "classification": result["classification"],
                      "tail_observed": result["tail_minus_k_38928_observed"],
                      "bx1_caller_count": len(result["caller_entries_at_C8973"]),
                      "ax4400_count": len(callbacks), "trace_bytes": len(raw),
                      "guard_exit_reason": guard.get("exit_reason")}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"PREFLIGHT/REPLAY FAILED CLOSED: {exc}", file=sys.stderr)
        raise SystemExit(2)
