"""One bounded original caller capture, launched only by oracle_guard."""
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
from tools.w3_249_isatty_caller_pairing import pair_events
from tools.w3_081_original_ah44_caller import summarize

MOUNT = ROOT / "build/dosboxx_oracle/C"
FIXTURE = MOUNT / "GENEWARS/GW.EXE"
CONFIG = ROOT / "build/dosboxx_oracle/dosbox-staging.w3-067-functional.conf"
DOSBOX = ROOT / "build/staging-w3-249-exec/Debug/dosbox.exe"
SOURCE = ROOT / "third_party/dosbox-staging-w3-059-instrumented"
GUARD = ROOT / "tools/oracle_guard.py"
CUE = Path((_GW_FX + '\\evidence\\original_disc\\Genewars (Europe) (En,Fr,De,Es,It,Sv).cue'))
ADDRESS = MOUNT / "ADDRESS.TXT"
SOURCE_ADDRESS = Path((_GW_INSTALL_PARENT + '\\ADDRESS.TXT'))
TRACE = MOUNT / "W3_249_ISATTY_CALLERS_20261009_01.jsonl"
OUTPUT = ROOT / "evidence/w3_249_original_bx1_caller_capture.json"
RUN_ID = "w3-249-original-isatty-caller-20261009-01"
REVISION = "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f"
GW_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
GW_SIZE = 1_251_658
CONFIG_SHA256 = "b2bac63096aa97a808abb8ea09486db79559b12a25a1410ea930be0e5eeffff1"
CUE_SHA256 = "1d417e3aed625d4f054b51054a1211562a19cd4f712b08e7846613517228a5b5"
ADDRESS_SHA256 = "7b1c5391160e1d95393d3abe980dde978b8a79ecb2814e144ee032d9710ba6ee"
TRACE_CAP = 1_048_576


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def verify_sandbox() -> dict:
    proc = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
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


def preflight() -> dict:
    sandbox = verify_sandbox()
    for path in (FIXTURE, CONFIG, DOSBOX, GUARD, CUE, ADDRESS, SOURCE_ADDRESS):
        if not path.is_file():
            raise FileNotFoundError(path)
    if TRACE.exists() or OUTPUT.exists():
        raise FileExistsError("refusing to overwrite W3-249 capture")
    if (FIXTURE.stat().st_size, sha256(FIXTURE)) != (GW_SIZE, GW_SHA256):
        raise ValueError("target executable size/hash mismatch")
    if sha256(CONFIG) != CONFIG_SHA256:
        raise ValueError("W3-067 configuration hash mismatch")
    if sha256(CUE) != CUE_SHA256:
        raise ValueError("original CUE hash mismatch")
    if sha256(ADDRESS) != ADDRESS_SHA256 or sha256(SOURCE_ADDRESS) != ADDRESS_SHA256:
        raise ValueError("ADDRESS.TXT differs from the recorded known-functional source")
    revision = subprocess.run(["git", "-C", str(SOURCE), "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    if revision != REVISION:
        raise ValueError(f"pinned Staging revision mismatch: {revision}")
    return {"sandbox": sandbox, "target_sha256": sha256(FIXTURE), "target_size": FIXTURE.stat().st_size,
            "config_sha256": sha256(CONFIG), "cue_sha256_before": sha256(CUE),
            "address_txt_guest_sha256": sha256(ADDRESS), "address_txt_source_sha256": sha256(SOURCE_ADDRESS),
            "address_txt_size": ADDRESS.stat().st_size, "staging_revision": revision,
            "instrumented_executable_sha256": sha256(DOSBOX), "trace_cap_bytes": TRACE_CAP,
            "working_directory": "C:\\GENEWARS per pinned W3-067 functional configuration",
            "expected_effective_command_tail": " -k 38928"}


def main() -> int:
    pre = preflight()
    env = dict(os.environ)
    for key in tuple(env):
        if key.startswith("GWRECOMP_ANCHOR_") or key.startswith("GWRECOMP_EXEC_TRACE_") or key.startswith("GWRECOMP_W3_237_") or key.startswith("GWRECOMP_W3_249_"):
            env.pop(key, None)
    env.update({
        "GWRECOMP_GW_FILE_SIZE": str(GW_SIZE),
        "GWRECOMP_GW_LE_HEADER_OFFSET": "0x8f50",
        "GWRECOMP_GW_LE_OBJECT_TABLE_OFFSET": "0x9014",
        "GWRECOMP_EXEC_TRACE_PATH": str(TRACE),
        "GWRECOMP_EXEC_TRACE_MAX_BYTES": str(TRACE_CAP),
        "GWRECOMP_EXEC_TRACE_FILE_IO": "0",
        "GWRECOMP_W3_237_CAPTURE_ONLY": "1",
        "GWRECOMP_W3_249_CAPTURE_ONLY": "1",
        "GWRECOMP_ANCHOR_MAIN_ENTRY_LINK": "0x000af96c",
        "GWRECOMP_ANCHOR_MAIN_ENTRY_BYTES": "eb765741",
        "GWRECOMP_ANCHOR_CRT_ARGV_LOAD_LINK": "0x000c8702",
        "GWRECOMP_ANCHOR_GAME_MAIN_ENTRY_LINK": "0x00093f30",
    })
    evidence_dir = ROOT / "evidence/oracle_runs"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    command = [sys.executable, str(GUARD), "run", "--exe", str(DOSBOX),
               "--config", str(CONFIG), "--staging-dir", str(MOUNT), "--host-drive", "E:",
               "--run-id", RUN_ID, "--operation", "W3-249 original isatty caller token capture",
               "--commit-sha", REVISION, "--target-sha", GW_SHA256,
               "--runtime-sha", pre["instrumented_executable_sha256"], "--fixture-sha", GW_SHA256,
               "--evidence-dir", str(evidence_dir), "--max-file-text-mib", "1",
               "--max-file-bin-mib", "64", "--max-run-gib", "1", "--host-floor-gib", "100",
               "--timeout-s", "30", "--growth-text-mibs", "8", "--growth-bin-mibs", "24", "--poll-hz", "1"]
    proc = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True,
                          timeout=45, check=False)
    try:
        guard = json.loads(proc.stdout)
    except json.JSONDecodeError:
        guard = {"exit_reason": "guard_output_invalid", "stdout_tail": proc.stdout[-2000:],
                 "stderr_tail": proc.stderr[-2000:], "exit_code": proc.returncode}
    raw = TRACE.read_bytes() if TRACE.is_file() else b""
    if len(raw) > TRACE_CAP:
        raise ValueError("guard failed to enforce the 1 MiB trace cap")
    events = [json.loads(line) for line in raw.decode("utf-8", errors="replace").splitlines() if line.strip()]
    pairing = pair_events(events)
    trace_summary = summarize(events) if events else {}
    cue_after = sha256(CUE) if CUE.is_file() else None
    passed = bool(guard.get("exit_reason") == "PASS" and pre["cue_sha256_before"] == cue_after and
                  trace_summary.get("psp_command_tail") == pre["expected_effective_command_tail"])
    classification = "ORIGINAL_CALLER_PAIRED" if passed and pairing["dynamic_caller"] != "UNKNOWN" else (
        "INCONCLUSIVE_CAPTURE" if not passed else "ORIGINAL_BX1_CALLER_UNKNOWN")
    result = {
        "schema": "gwrecomp-w3-249-original-bx1-caller-capture/v1", "task": "W3-249",
        "classification": classification, "evidence_level": "ORIGINAL_OBSERVED" if events else "INCONCLUSIVE",
        "preflight": pre, "guard": guard, "guard_returncode": proc.returncode,
        "guard_stderr_tail": proc.stderr[-2000:],
        "trace": {"path": str(TRACE), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
                  "event_count": len(events), "max_bytes": TRACE_CAP},
        "effective_child_argv": trace_summary.get("effective_child_argv"),
        "effective_psp_tail": trace_summary.get("psp_command_tail"),
        "checkpoints": pairing,
        "target_checkpoint_events": [e for e in events if e.get("event") == "target_runtime_checkpoint" and
                                      (str(e.get("checkpoint", "")).startswith("W3_249_") or
                                       str(e.get("checkpoint", "")).startswith("W3_237_"))],
        "bx1_cpu_events": [e for e in events if e.get("event") == "original_cpu_int21_ah44_bx1_entry"],
        "cue_sha256_after": cue_after, "read_only_reference_unchanged": cue_after == pre["cue_sha256_before"],
        "native_comparison_scope": "W1-085 is separate native evidence; no same-invocation claim unless same-run callsite-entry-request pairing validates.",
        "menu_reached": False, "framebuffer_reached": False, "gameplay_reached": False,
    }
    OUTPUT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(OUTPUT), "classification": classification,
                      "guard": guard.get("exit_reason"), "trace_bytes": len(raw),
                      "caller": pairing["dynamic_caller"], "tail": result["effective_psp_tail"]}, indent=2))
    return 0 if classification == "ORIGINAL_CALLER_PAIRED" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"PREFLIGHT/REPLAY FAILED CLOSED: {exc}", file=sys.stderr)
        raise SystemExit(2)
