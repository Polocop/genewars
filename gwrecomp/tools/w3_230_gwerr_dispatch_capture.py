#!/usr/bin/env python3
"""One-shot guarded original DOS-dispatch capture for the natural GW.ERR open."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class DispatchState:
    process_psp: int
    ax: int
    bx: int
    cx: int
    dx: int
    si: int
    di: int
    cs: int
    eip: int
    eflags: int
    ds: int
    es: int
    ss: int


def normalize_path(path: str) -> str:
    value = path.replace("/", "\\").upper()
    while value.startswith(".\\"):
        value = value[2:]
    for prefix in ("C:\\",):
        if value.startswith(prefix):
            value = value[len(prefix):]
    return value


def read_bounded_c_string(memory: bytes, offset: int, cap: int = 64) -> str | None:
    if offset < 0 or offset >= len(memory) or cap <= 0:
        return None
    end = min(len(memory), offset + cap + 1)
    nul = memory.find(b"\0", offset, end)
    if nul < 0:
        return None
    try:
        return memory[offset:nul].decode("ascii")
    except UnicodeDecodeError:
        return None


def decode_fcb_name(fcb: bytes) -> str | None:
    if len(fcb) < 12:
        return None
    name = fcb[1:9].decode("ascii", errors="ignore").rstrip(" ")
    ext = fcb[9:12].decode("ascii", errors="ignore").rstrip(" ")
    return f"{name}.{ext}" if name and ext else (name or None)


def decode_dispatch(service: str, state: DispatchState, memory: bytes, *,
                    target_psp: int, fcb_bytes: bytes | None = None) -> dict | None:
    if not dispatch_candidate_allowed(target_file_complete=True,
                                      process_psp=state.process_psp,
                                      target_psp=target_psp):
        return None
    if service == "INT21_AH3D":
        if (state.ax & 0xff00) != 0x3d00:
            return None
        offset = state.dx
    elif service == "INT21_AH6C":
        if (state.ax & 0xff00) != 0x6c00:
            return None
        offset = state.si
    elif service in ("INT21_AH0F_FCB_OPEN", "INT21_AH16_FCB_CREATE"):
        if service == "INT21_AH0F_FCB_OPEN" and (state.ax & 0xff00) != 0x0f00:
            return None
        if service == "INT21_AH16_FCB_CREATE" and (state.ax & 0xff00) != 0x1600:
            return None
        pathname = decode_fcb_name(fcb_bytes or b"")
        offset = state.dx
    else:
        return None
    if service not in ("INT21_AH0F_FCB_OPEN", "INT21_AH16_FCB_CREATE"):
        pathname = read_bounded_c_string(memory, offset)
    if pathname is None or normalize_path(pathname) not in (
            "GW.ERR", "GENEWARS\\GW.ERR"):
        return None
    return {
        "event": "w3_230_gwerr_dos_dispatch_entry",
        "service": service,
        "process_psp": state.process_psp,
        "in_ax": state.ax, "in_bx": state.bx, "in_cx": state.cx,
        "in_dx": state.dx, "in_si": state.si, "in_di": state.di,
        "in_cs": state.cs, "in_eip": state.eip, "in_eflags": state.eflags,
        "in_ds": state.ds, "in_es": state.es, "in_ss": state.ss,
        "pathname_pointer": {"segment": state.ds, "offset": offset},
        "requested_path": normalize_path(pathname),
    }


def append_once(items: list, event: dict, cap: int = 1) -> bool:
    if len(items) >= cap:
        return False
    items.append(event)
    return True


def correlate_open(dispatch: dict, opened: dict) -> bool:
    return (dispatch.get("process_psp") == opened.get("process_psp") and
            normalize_path(str(dispatch.get("requested_path", ""))) ==
            normalize_path(str(opened.get("requested_path", opened.get("path", "")))))


def correlate_events(events: list[dict]) -> dict:
    dispatch = next((e for e in events if e.get("event") ==
                     "w3_230_gwerr_dos_dispatch_entry"), None)
    opened = None
    if dispatch is not None:
        seq = dispatch.get("sequence")
        for event in events:
            if event.get("event") != "dos_handle_open":
                continue
            if seq is not None and event.get("sequence") is not None:
                gap = event["sequence"] - seq
                if gap < 0 or gap > 3:
                    continue
            if correlate_open(dispatch, event):
                opened = event
                break
    classification = ("ORIGINAL_SERVICE_AND_OPEN_CORRELATED" if opened else
                      "ORIGINAL_SERVICE_OBSERVED" if dispatch else
                      "NO_MATCHING_DISPATCH_OBSERVED")
    return {"classification": classification, "dispatch": dispatch,
            "handle_open": opened}


ROOT = Path(r"E:\GWRecomp")
REVISION = "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f"
TARGET_SHA = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
CONFIG_SHA = "b2bac63096aa97a808abb8ea09486db79559b12a25a1410ea930be0e5eeffff1"
CUE_SHA = "1d417e3aed625d4f054b51054a1211562a19cd4f712b08e7846613517228a5b5"
TARGET_BYTES = 1_251_658
MAX_TRACE_BYTES = 1_048_576
MAX_EVENTS = 4096
TIMEOUT_SECONDS = 30
HOST_FLOOR_BYTES = 100 * 1024**3
TASK_ID = "W3-231"


def dispatch_candidate_allowed(*, target_file_complete: bool,
                               process_psp: int, target_psp: int) -> bool:
    """The bounded pathname filter is independent of setup capture activation."""
    return target_file_complete and process_psp == target_psp


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_jsonl(path: Path) -> list[dict]:
    data = path.read_bytes() if path.exists() else b""
    if len(data) > MAX_TRACE_BYTES:
        raise ValueError("trace exceeded the 1 MiB cap")
    rows = []
    for line in data.splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if isinstance(row, dict):
            rows.append(row)
        if len(rows) > MAX_EVENTS:
            raise ValueError("trace exceeded the 512 event audit cap")
    return rows


def run_capture() -> dict:
    mount = ROOT / "build/dosboxx_oracle/C"
    vhdx = ROOT / "build/dosboxx_oracle/oracle_c.vhdx"
    fixture = mount / "GENEWARS/GW.EXE"
    config = ROOT / "build/dosboxx_oracle/dosbox-staging.w3-067-functional.conf"
    cue = Path(r"E:\GeneWarsFX\evidence\original_disc\Genewars (Europe) (En,Fr,De,Es,It,Sv).cue")
    dosbox = ROOT / "build/staging-w3-059-exec/Debug/dosbox.exe"
    guard_py = ROOT / "tools/oracle_guard.py"
    source = ROOT / "third_party/dosbox-staging-w3-059-instrumented"
    dos_source = source / "src/dos/dos.cpp"
    task_check = subprocess.run(
        [str(ROOT / "coordination/autopilot.cmd"), "check", TASK_ID, "--worker", "WORK3"],
        cwd=ROOT, capture_output=True, text=True, timeout=15,
        env={**os.environ, "PYTHONIOENCODING": "utf-8"}, check=True)
    status = subprocess.run(
        [str(ROOT / "coordination/autopilot.cmd"), "status"], cwd=ROOT,
        capture_output=True, text=True, timeout=15,
        env={**os.environ, "PYTHONIOENCODING": "utf-8"}, check=True)
    queue = json.loads(status.stdout)
    locks = {(x["resource"], x["task_id"], x["owner"]) for x in queue.get("resource_locks", [])}
    for resource in ("build", "oracle", "oracle-vhdx"):
        if (resource, TASK_ID, "WORK3") not in locks:
            raise RuntimeError(f"required {resource} lock is not held by {TASK_ID}")
    for path in (fixture, config, cue, dosbox, guard_py, dos_source, vhdx):
        if not path.is_file():
            raise FileNotFoundError(path)
    verify = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
         str(ROOT / "tools/verify_oracle_sandbox.ps1"), "-Json"],
        cwd=ROOT, capture_output=True, text=True, timeout=30, check=True)
    sandbox = json.loads(verify.stdout)
    if sandbox.get("verified") is not True or sandbox.get("reason") != "verified":
        raise RuntimeError(f"GWORACLE verification failed: {sandbox}")
    if sandbox.get("volume", sandbox.get("label")) != "GWORACLE":
        raise RuntimeError(f"wrong VHDX volume: {sandbox}")
    if sandbox.get("capacity_bytes", 0) < 15 * 1024**3:
        raise RuntimeError("GWORACLE capacity is below the expected 16 GiB-class VHDX")
    if sandbox.get("host_free_bytes", 0) < HOST_FLOOR_BYTES:
        raise RuntimeError("host free-space floor failed")
    if fixture.stat().st_size != TARGET_BYTES or sha256(fixture) != TARGET_SHA:
        raise RuntimeError("fixture GW.EXE identity mismatch")
    if sha256(config) != CONFIG_SHA or sha256(cue) != CUE_SHA:
        raise RuntimeError("functional config or original CUE hash changed")
    if not cue.stat().st_mode:
        raise RuntimeError("CUE metadata unavailable")
    pinned = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"],
                            capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    if pinned != REVISION:
        raise RuntimeError(f"unexpected Staging source revision: {pinned}")

    runtime_sha = sha256(dosbox)
    trace_name = "W3_231_GWERR_DISPATCH_20261009_01.jsonl"
    run_id = "w3-231-gwerr-dispatch-20261009-01"
    trace = mount / trace_name
    result_path = ROOT / "evidence/w3_231_gwerr_dispatch_capture.json"
    outdir = ROOT / "evidence/oracle_runs"
    stdout_path = outdir / f"{run_id}.stdout.json"
    stderr_path = outdir / f"{run_id}.stderr.txt"
    guard_evidence_path = outdir / f"oracle_runs_{run_id}.json"
    if any(path.exists() for path in
           (trace, result_path, stdout_path, stderr_path, guard_evidence_path)):
        raise FileExistsError("refusing to overwrite W3-231 output")

    gwerr = mount / "GENEWARS/GW.ERR"
    before = {"exists": gwerr.exists(),
              "size_bytes": gwerr.stat().st_size if gwerr.exists() else None,
              "sha256": sha256(gwerr) if gwerr.exists() and gwerr.stat().st_size <= MAX_TRACE_BYTES else None}
    preflight = {
        "sandbox": sandbox,
        "vhdx": str(vhdx),
        "fixture": str(fixture), "fixture_bytes": fixture.stat().st_size,
        "fixture_sha256": sha256(fixture), "config": str(config),
        "config_sha256": sha256(config), "cue": str(cue), "cue_sha256": sha256(cue),
        "cue_read_only": True, "dosbox": str(dosbox), "dosbox_sha256": runtime_sha,
        "staging_revision": pinned, "dos_source_sha256": sha256(dos_source),
        "run_id": run_id, "trace": str(trace), "trace_max_bytes": MAX_TRACE_BYTES,
        "event_audit_cap": MAX_EVENTS, "timeout_seconds": TIMEOUT_SECONDS,
        "host_free_floor_bytes": HOST_FLOOR_BYTES, "gwerr_before": before,
        "task_check": task_check.stdout.strip(),
        "launch": ["C:", "CD \\GENEWARS", "GENEWARS.EXE", "measured child tail:  -k 38928"],
        "native_comparison_evidence": "evidence/native_gwerr_lifecycle_w1_077.json",
        "native_comparison_sha256": sha256(ROOT / "evidence/native_gwerr_lifecycle_w1_077.json"),
    }

    env = dict(os.environ)
    for key in tuple(env):
        if key.startswith("GWRECOMP_ANCHOR_") or key.startswith("GWRECOMP_EXEC_TRACE_"):
            env.pop(key, None)
    env.update({
        "GWRECOMP_GW_FILE_SIZE": str(TARGET_BYTES),
        "GWRECOMP_GW_LE_HEADER_OFFSET": "0x8f50",
        "GWRECOMP_GW_LE_OBJECT_TABLE_OFFSET": "0x9014",
        "GWRECOMP_EXEC_TRACE_PATH": str(trace),
        "GWRECOMP_EXEC_TRACE_MAX_BYTES": str(MAX_TRACE_BYTES),
        "GWRECOMP_EXEC_TRACE_FILE_IO": "0",
        "GWRECOMP_ANCHOR_MAIN_ENTRY_LINK": "0x000af96c",
        "GWRECOMP_ANCHOR_MAIN_ENTRY_BYTES": "eb765741",
        "GWRECOMP_ANCHOR_CRT_ARGV_LOAD_LINK": "0x000c8702",
        "GWRECOMP_ANCHOR_GAME_MAIN_ENTRY_LINK": "0x00093f30",
    })
    outdir.mkdir(parents=True, exist_ok=True)
    command = [sys.executable, str(guard_py), "run", "--exe", str(dosbox),
               "--config", str(config), "--staging-dir", str(mount), "--host-drive", "E:",
               "--run-id", run_id, "--operation", "W3-231 one-shot original GW.ERR DOS dispatch capture",
               "--commit-sha", pinned, "--target-sha", TARGET_SHA, "--runtime-sha", runtime_sha,
               "--fixture-sha", TARGET_SHA, "--evidence-dir", str(outdir),
               "--max-file-text-mib", "1", "--max-file-bin-mib", "64", "--max-run-gib", "1",
               "--host-floor-gib", "100", "--timeout-s", "30", "--growth-text-mibs", "8",
               "--growth-bin-mibs", "24", "--poll-hz", "1"]
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        proc = subprocess.run(command, cwd=ROOT, env=env, stdout=stdout, stderr=stderr,
                              timeout=40, check=False)
    guard = json.loads(stdout_path.read_text(encoding="utf-8"))
    events = read_jsonl(trace)
    capture = correlate_events(events)
    dispatch = capture.get("dispatch")
    opened = capture.get("handle_open")
    later_api = None
    if dispatch and opened:
        later_api = next((e for e in events if e.get("event") == "setup_dos_api"
                          and e.get("operation") == "INT21_AH3D"
                          and e.get("sequence", -1) > dispatch.get("sequence", -1)
                          and e.get("sequence", 0) <= opened.get("sequence", 0) + 3), None)
    checkpoints = [e for e in events if e.get("event") == "target_runtime_checkpoint"]
    framebuffer = [e for e in checkpoints if e.get("checkpoint") == "VIDEO_FRAMEBUFFER_ASSIGN_AFTER"]
    last = checkpoints[-1] if checkpoints else None
    after = {"exists": gwerr.exists(), "size_bytes": gwerr.stat().st_size if gwerr.exists() else None,
             "sha256": sha256(gwerr) if gwerr.exists() and gwerr.stat().st_size <= MAX_TRACE_BYTES else None}
    result = {
        "schema": "gwrecomp.original-gwerr-dos-dispatch-capture-w3-231/v1",
        "task": TASK_ID, "run_id": run_id,
        "classification": capture["classification"],
        "evidence_level": "ORIGINAL_OBSERVED" if dispatch else "INCONCLUSIVE",
        "preflight": preflight,
        "guard": guard, "guard_returncode": proc.returncode,
        "trace": {"path": str(trace), "exists": trace.is_file(),
                  "bytes": trace.stat().st_size if trace.exists() else 0,
                  "sha256": sha256(trace) if trace.exists() else None,
                  "event_count": len(events), "max_bytes": MAX_TRACE_BYTES,
                  "audit_cap": MAX_EVENTS},
        "capture": {"dispatch_entry": dispatch, "generic_handle_open": opened,
                    "ah3d_result_row": later_api,
                    "service_attribution": dispatch.get("service") if dispatch else None,
                    "correlation": capture["classification"]},
        "frontier": {"last_target_checkpoint": last,
                      "framebuffer_pointer_checkpoints": framebuffer,
                      "framebuffer_pixels_sampled": 0,
                      "first_framebuffer_verified": False,
                      "menu_verified": False,
                      "gameplay_verified": False,
                      "guard_stop_cause": guard.get("cause"),
                      "guard_stop_detail": guard.get("detail")},
        "gwerr_fixture_after": after,
        "comparison": {"native_evidence": "evidence/native_gwerr_lifecycle_w1_077.json",
                       "native_observation": "W1-077 reports native AH=3Dh gw.err failed (DOS error 2), then AH=3Ch created gw.err before its sixth AH=4400 request; this is a different execution mode and does not establish original service or causality.",
                       "original_service_measured": dispatch.get("service") if dispatch else None},
        "scope": {"guest_binary_modified": False, "functional_config_modified": False,
                  "personal_source_modified": False, "guest_response_injected": False,
                  "global_trace": False, "bulk_memory_dump": False,
                  "dispatch_event_cap": 1, "path_byte_cap": 64,
                  "stack_words_cap": 4, "oracle_guard_used": True,
                  "sandbox_verified": sandbox["verified"]},
    }
    temporary = result_path.with_name(result_path.name + ".tmp")
    with temporary.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, result_path)
    return result


if __name__ == "__main__" and sys.argv[-1:] == ["--run"]:
    try:
        result = run_capture()
        print(json.dumps({"evidence": str(ROOT / "evidence/w3_231_gwerr_dispatch_capture.json"),
                          "classification": result["classification"],
                          "trace": result["trace"],
                          "guard_cause": result["guard"].get("cause")}, indent=2))
        raise SystemExit(0 if result["capture"]["dispatch_entry"] else 1)
    except Exception as exc:
        print(f"PREFLIGHT/REPLAY FAILED CLOSED: {exc}", file=sys.stderr)
        raise SystemExit(2)
