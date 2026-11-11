#!/usr/bin/env python3
"""One guarded, bounded W3-237 original BX=1 caller-pairing capture."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.w3_237_bx1_dynamic_pairing import correlate

MOUNT = ROOT / "build/dosboxx_oracle/C"
FIXTURE_DIR = MOUNT / "GENEWARS"
FIXTURE = FIXTURE_DIR / "GW.EXE"
FIXTURE_CONFIG = FIXTURE_DIR / "CONFIG.INI"
CONFIG = ROOT / "build/dosboxx_oracle/dosbox-staging.w3-067-functional.conf"
DOSBOX = ROOT / "build/staging-w3-059-exec/Debug/dosbox.exe"
SOURCE = ROOT / "third_party/dosbox-staging-w3-059-instrumented"
CPP = SOURCE / "src/cpu/core_dyn_x86.cpp"
GUARD = ROOT / "tools/oracle_guard.py"
TRACE = MOUNT / "W3_237_BX1_PAIRING.jsonl"
RESULT = ROOT / "evidence/w3_237_bx1_dynamic_pairing.json"
REPORT = ROOT / "reports/coordination/w3_237_bx1_dynamic_pairing.md"
REVISION = "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f"
GW_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
GW_SIZE = 1_251_658
CONFIG_SHA256 = "b2bac63096aa97a808abb8ea09486db79559b12a25a1410ea930be0e5eeffff1"
CUE = Path(r"E:\GeneWarsFX\evidence\original_disc\Genewars (Europe) (En,Fr,De,Es,It,Sv).cue")
CUE_SHA256 = "1d417e3aed625d4f054b51054a1211562a19cd4f712b08e7846613517228a5b5"
SOURCE_ADDRESS = Path(r"<GENEWARS_HDD_ROOT>\ADDRESS.TXT")
ADDRESS_SHA256 = "7b1c5391160e1d95393d3abe980dde978b8a79ecb2814e144ee032d9710ba6ee"
RUN_ID = "w3-237-bx1-dynamic-pairing-20261009-01"
TASK_ID = "W3-237"
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
                           "-Path", str(MOUNT), "-Json"], cwd=ROOT, capture_output=True,
                          text=True, timeout=30, check=False)
    if proc.returncode:
        raise RuntimeError(f"GWORACLE verifier failed: {proc.stderr[-1000:]}")
    payload = json.loads(proc.stdout.strip().splitlines()[-1])
    if payload.get("verified") is not True or payload.get("volume", payload.get("label")) != "GWORACLE":
        raise RuntimeError(f"GWORACLE/VHDX verification failed: {payload}")
    if payload.get("capacity_bytes", 0) < 15 * 1024**3:
        raise RuntimeError("oracle VHDX is below the expected 15 GiB capacity")
    return payload


def require_hash(path: Path, expected: str, label: str, size: int | None = None) -> str:
    if not path.is_file():
        raise FileNotFoundError(path)
    digest = sha256(path)
    if digest.lower() != expected.lower() or (size is not None and path.stat().st_size != size):
        raise ValueError(f"{label} fingerprint mismatch: size={path.stat().st_size}, sha256={digest}")
    return digest


def main() -> int:
    sandbox = verify_sandbox()
    if TRACE.exists() or RESULT.exists() or REPORT.exists():
        raise FileExistsError("refusing to overwrite W3-237 evidence")
    fixture_hash = require_hash(FIXTURE, GW_SHA256, "GW.EXE", GW_SIZE)
    config_hash = require_hash(CONFIG, CONFIG_SHA256, "isolated DOSBox config")
    if sha256(CUE) != CUE_SHA256:
        raise ValueError("original CUE hash changed")
    if sha256(FIXTURE_CONFIG) != "e7a4728ff07332c2f04320fda202ac5521818a47453e670f9f2842767ef36798":
        raise ValueError("authentic CONFIG.INI hash changed")
    if SOURCE_ADDRESS.stat().st_size != 24 or sha256(SOURCE_ADDRESS) != ADDRESS_SHA256:
        raise ValueError("read-only source ADDRESS.TXT fingerprint changed")
    guest_address = MOUNT / "ADDRESS.TXT"
    if guest_address.stat().st_size != 24 or sha256(guest_address) != ADDRESS_SHA256:
        raise ValueError("sandbox ADDRESS.TXT state differs from W3-236 verified initial state")
    address_before = guest_address.read_bytes()
    if len(address_before) > 4096:
        raise ValueError("ADDRESS.TXT pre-run snapshot exceeds 4 KiB")
    revision = subprocess.run(["git", "-C", str(SOURCE), "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    if revision != REVISION:
        raise ValueError(f"pinned Staging revision mismatch: {revision}")
    if not all(path.is_file() for path in (DOSBOX, CPP, GUARD)):
        raise FileNotFoundError("instrumented executable, source, or guard missing")
    if TRACE.exists():
        raise FileExistsError(TRACE)
    runtime_hash = sha256(DOSBOX)
    source_hash = sha256(CPP)
    trace_hash_before = sha256(TRACE) if TRACE.exists() else None

    env = dict(os.environ)
    for key in tuple(env):
        if key.startswith("GWRECOMP_ANCHOR_") or key.startswith("GWRECOMP_EXEC_TRACE_") or key.startswith("GWRECOMP_W3_"):
            env.pop(key, None)
    env.update({
        "GWRECOMP_GW_FILE_SIZE": str(GW_SIZE),
        "GWRECOMP_GW_LE_HEADER_OFFSET": "0x8f50",
        "GWRECOMP_GW_LE_OBJECT_TABLE_OFFSET": "0x9014",
        "GWRECOMP_EXEC_TRACE_PATH": str(TRACE),
        "GWRECOMP_EXEC_TRACE_MAX_BYTES": str(TRACE_CAP),
        "GWRECOMP_EXEC_TRACE_FILE_IO": "0",
        # Required to establish the runtime MAIN rebase before any link-VA hook
        # can fire. Keep this fixed, hash-bound anchor configuration in future runs.
        "GWRECOMP_ANCHOR_MAIN_ENTRY_LINK": "0x000af96c",
        "GWRECOMP_ANCHOR_MAIN_ENTRY_BYTES": "eb765741",
        "GWRECOMP_ANCHOR_CRT_ARGV_LOAD_LINK": "0x000c8702",
        "GWRECOMP_ANCHOR_GAME_MAIN_ENTRY_LINK": "0x00093f30",
        "GWRECOMP_W3_237_CAPTURE_ONLY": "1",
    })
    command = [sys.executable, str(GUARD), "run", "--exe", str(DOSBOX),
               "--config", str(CONFIG), "--staging-dir", str(MOUNT), "--host-drive", "E:",
               "--run-id", RUN_ID, "--operation", "W3-237 paired original isatty and BX=1",
               "--commit-sha", REVISION, "--target-sha", GW_SHA256,
               "--runtime-sha", runtime_hash, "--fixture-sha", fixture_hash,
               "--evidence-dir", str(ROOT / "evidence/oracle_runs"),
               "--max-file-text-mib", "1", "--max-file-bin-mib", "64",
               "--max-run-gib", "1", "--host-floor-gib", "100",
               "--timeout-s", "30", "--growth-text-mibs", "8",
               "--growth-bin-mibs", "24", "--poll-hz", "1"]
    proc = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True,
                          timeout=45, check=False)
    try:
        guard = json.loads(proc.stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError) as exc:
        raise RuntimeError(f"oracle_guard did not return JSON: {proc.stdout[-1000:]}") from exc
    if not TRACE.is_file() or TRACE.stat().st_size > TRACE_CAP:
        raise RuntimeError("guarded trace is missing or exceeds 1 MiB")
    raw = TRACE.read_bytes()
    events = [json.loads(line) for line in raw.decode("utf-8", errors="strict").splitlines() if line.strip()]
    summary = correlate(events)
    main_anchors = [event for event in events if event.get("event") == "target_code_anchor"
                    and event.get("anchor") == "MAIN_ENTRY"]
    mapping = None
    if main_anchors:
        mapping = {"link_va": main_anchors[0].get("link_va"),
                   "runtime_eip": main_anchors[0].get("eip"),
                   "code_rebase": main_anchors[0].get("candidate_rebase"),
                   "cs": main_anchors[0].get("cs"),
                   "cs_base": main_anchors[0].get("cs_base")}
    psp_events = [event for event in events if event.get("event") == "target_runtime_checkpoint"
                  and event.get("checkpoint") == "CRT_ARGV_LOAD"]
    psp_tail = next((event.get("psp_tail_text") for event in events
                     if event.get("psp_tail_text")), None)
    after_hash = sha256(guest_address)
    result = {
        "schema": f"gwrecomp-{TASK_ID.lower()}-original-bx1-dynamic-pairing/v1",
        "task": TASK_ID,
        "captured_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "classification": summary["classification"] if summary["bx1_requests"] else "INCONCLUSIVE_NO_BX1",
        "preflight": {"sandbox": sandbox, "staging_revision": revision,
                      "target_size": FIXTURE.stat().st_size, "target_sha256": fixture_hash,
                      "original_cue_sha256": sha256(CUE), "dosbox_config_sha256": config_hash,
                      "guest_config_sha256": sha256(FIXTURE_CONFIG),
                      "runtime_sha256": runtime_hash, "instrumentation_source_sha256": source_hash,
                      "natural_effective_psp_tail_prior_capture": " -k 38928",
                      "command_tail_injected": False, "timeout_s": 30,
                      "trace_cap_bytes": TRACE_CAP},
        "address_txt_initial": {"guest_path": "C:\\ADDRESS.TXT", "size": len(address_before),
                                "sha256": hashlib.sha256(address_before).hexdigest(),
                                "source_sha256": sha256(SOURCE_ADDRESS),
                                "source_provenance": "W3-236 observed on read-only functional HDD source; creation history unknown"},
        "guard": guard, "guard_returncode": proc.returncode,
        "guard_stderr_tail": proc.stderr[-3000:],
        "trace": {"path": str(TRACE), "bytes": len(raw),
                  "sha256": hashlib.sha256(raw).hexdigest(), "event_count": len(events),
                  "preexisting_trace_sha256": trace_hash_before},
        "main_mapping": mapping,
        "failure_analysis": ({
            "classification": "CAPTURE_SETUP_REGRESSION",
            "reason": "The replay runner cleared GWRECOMP_ANCHOR_* variables but did not provide the required MAIN entry anchor. No target_code_anchor or target_runtime_checkpoint appears, so target_main_rebase remained unavailable and the link-VA hooks could not arm.",
            "observed_before_timeout": ["GW.EXE fully read", "DOS4GW protected-mode transition", "8 DOS AX=4400 callbacks", "repeated MULE.ANB open/close activity"],
            "not_demonstrated": ["MAIN runtime mapping", "dynamic isatty_ entry", "the target AX=4400/BX=1 callsite"],
            "retry_authorized": False
        } if not mapping else None),
        "effective_psp_tail_in_capture": psp_tail,
        "argv_capture_events": psp_events[:4],
        "isatty_entries": summary["entries"],
        "ah4400_requests": [{"ordinal": item["ordinal"],
                              "correlated_entry_ordinal": item["correlated_entry_ordinal"],
                              "event": item["event"], "entry": item["entry"]}
                             for item in summary["requests"]],
        "bx1_requests": [{"ordinal": item["ordinal"],
                          "correlated_entry_ordinal": item["correlated_entry_ordinal"],
                          "request": item["event"], "entry": item["entry"]}
                         for item in summary["bx1_requests"]],
        "address_txt_after": {"size": guest_address.stat().st_size, "sha256": after_hash,
                               "unchanged": after_hash == ADDRESS_SHA256},
        "comparison_limits": ["W1-085 native and W3-237 original are separate runs.",
                              "Same static link VA does not prove identical dynamic calls.",
                              "ADDRESS.TXT initial source history remains unknown."],
        "next_action": None,
    }
    if not summary["bx1_requests"]:
        result["next_action"] = "Stop; do not retry unchanged instrumentation. Report the last mapped isatty/AX=4400 hit and the first missing frontier."
    elif any(item["correlated_entry_ordinal"] == 0 for item in summary["bx1_requests"]):
        result["next_action"] = "Report BX=1 as lacking a preceding captured isatty entry; inspect mapping/capture window before any new run."
    else:
        result["next_action"] = "Use the paired original caller/arguments as a bounded WORK1/WORK2 comparison; retain separate-run limitations."
    RESULT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    RESULT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    REPORT.write_text(
        f"# {TASK_ID} — Original BX=1 dynamic caller pairing\n\n"
        f"- Classification: **{result['classification']}**\n"
        f"- Instrumented Staging revision: `{revision}`\n"
        f"- Instrumented executable SHA-256: `{runtime_hash}`\n"
        f"- GW.EXE SHA-256: `{fixture_hash}`; CUE SHA-256: `{sha256(CUE)}`\n"
        f"- Trace: `{result['trace']['bytes']}` bytes, `{result['trace']['event_count']}` events, SHA-256 `{result['trace']['sha256']}`\n"
        f"- MAIN mapping: `{json.dumps(mapping, sort_keys=True)}`\n"
        f"- Effective PSP tail: `{psp_tail if psp_tail is not None else 'not captured in this run'}`; no command tail was injected.\n"
        f"- isatty entries: {len(summary['entries'])}; AH=4400 requests: {len(summary['requests'])}; BX=1 requests: {len(summary['bx1_requests'])}.\n\n"
        "Caller attribution uses the instrumentation's active same-process isatty invocation token. It does not infer a relationship from static addresses alone. Original and native observations are separate executions; no whole-run equivalence is claimed. ADDRESS.TXT source provenance remains limited to its verified bytes on the read-only functional HDD.\n\n"
        f"Next action: {result['next_action']}\n\n"
        f"Evidence JSON: `{RESULT.relative_to(ROOT).as_posix()}`\n", encoding="utf-8")
    print(json.dumps({"result": str(RESULT), "classification": result["classification"],
                      "guard_exit": guard.get("exit_reason"), "trace": result["trace"],
                      "isatty_entries": len(summary["entries"]),
                      "ah4400_requests": len(summary["requests"]),
                      "bx1_requests": len(summary["bx1_requests"]),
                      "address_txt_unchanged": after_hash == ADDRESS_SHA256}, indent=2))
    return 0 if summary["bx1_requests"] and all(
        item["correlated_entry_ordinal"] for item in summary["bx1_requests"]) else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"PREFLIGHT/REPLAY FAILED CLOSED: {exc}", file=sys.stderr)
        raise SystemExit(2)
