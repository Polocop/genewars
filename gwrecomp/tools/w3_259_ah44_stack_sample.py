"""Reducer and one-run protected capture for W3-259."""
from __future__ import annotations

import hashlib
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

ROOT = Path(r"E:\GWRecomp")
REVISION = "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f"
TARGET_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
TARGET_SIZE = 1_251_658
CONFIG_SHA256 = "b2bac63096aa97a808abb8ea09486db79559b12a25a1410ea930be0e5eeffff1"
CUE_SHA256 = "1d417e3aed625d4f054b51054a1211562a19cd4f712b08e7846613517228a5b5"
ADDRESS_SHA256 = "7b1c5391160e1d95393d3abe980dde978b8a79ecb2814e144ee032d9710ba6ee"
MOUNT = ROOT / "build/dosboxx_oracle/C"
CONFIG = ROOT / "build/dosboxx_oracle/dosbox-staging.w3-067-functional.conf"
EXE = ROOT / "build/staging-w3-059-ah44-stack-20261009/Debug/dosbox.exe"
SOURCE = ROOT / "third_party/dosbox-staging-w3-059-instrumented"
GUARD = ROOT / "tools/oracle_guard.py"
TRACE = MOUNT / "W3_259_AH44_STACK_20261009_01.jsonl"
OUT = ROOT / "evidence/w3_259_ah44_stack_sample.json"
GUARD_EVIDENCE = ROOT / "evidence/w3_259_guard_run.json"
REPORT = ROOT / "reports/coordination/w3_259_ah44_stack_sample.md"
TRACE_CAP = 1_048_576
MAX_EVENTS = 256


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def reduce_trace(raw: bytes, max_bytes: int = TRACE_CAP) -> dict[str, Any]:
    if len(raw) > max_bytes:
        raise ValueError(f"trace exceeds cap: {len(raw)} > {max_bytes}")
    rows = []
    for line_number, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON at line {line_number}: {exc}") from exc
        if not isinstance(row, dict):
            raise ValueError(f"event at line {line_number} is not an object")
        rows.append(row)
        if len(rows) > MAX_EVENTS:
            raise ValueError(f"event count exceeds cap: {len(rows)} > {MAX_EVENTS}")
    candidates = [r for r in rows if r.get("event") == "original_cpu_int21_ah44_bx1_entry"
                  and r.get("w3_259_stack_sample_target") is True]
    valid = [r for r in candidates if r.get("mapping_valid") is True
             and r.get("int21_bytes_verified") is True
             and r.get("int_instruction_link_va") == 0xC8973
             and (int(r.get("eax", -1)) & 0xFFFF) == 0x4400
             and (int(r.get("ebx", -1)) & 0xFFFF) == 1]
    first = valid[0] if valid else None
    words = first.get("stack_words_u32", []) if first else []
    checkpoints = [{
        key: row.get(key) for key in ("sequence", "checkpoint", "checkpoint_ordinal",
                                      "link_va", "eip", "linear", "main_code_rebase",
                                      "mapping_valid", "cs", "eax", "ebx", "edx", "esp",
                                      "ss", "return_address", "phase")
        if key in row
    } for row in rows if row.get("event") == "target_runtime_checkpoint"]
    callbacks = [{
        key: row.get(key) for key in ("sequence", "ordinal", "in_ax", "in_bx",
                                      "in_cx", "in_dx", "out_ax", "out_bx",
                                      "out_dx", "cf", "ioctl_ok", "dos_error",
                                      "default_drive", "cwd_valid", "cwd")
        if key in row
    } for row in rows if row.get("event") == "original_int21_ah44"]
    last = rows[-1] if rows else None
    last_summary = ({key: last.get(key) for key in ("sequence", "event", "path",
                                                    "requested_path", "checkpoint",
                                                    "link_va", "eip", "process_psp")
                    if key in last} if last else None)
    return {
        "trace_bytes": len(raw),
        "trace_sha256": hashlib.sha256(raw).hexdigest(),
        "event_count": len(rows),
        "bx1_stack_target_count": len(candidates),
        "verified_bx1_count": int(bool(valid)),
        "valid_bx1_event_count": len(valid),
        "duplicate_target_count": max(0, len(candidates) - 1) if valid else 0,
        "suppressed_or_duplicate_target_count": max(0, len(candidates) - 1) if valid else 0,
        "first_verified_event": first,
        "target_checkpoints": checkpoints,
        "original_ah44_callbacks": callbacks,
        "last_trace_event": last_summary,
        "raw_stack_words_u32": words,
        "return_candidate": words[0] if words else None,
        "caller_identification": "UNKNOWN; a stack word alone is only a candidate",
    }


def compact_guard(guard: dict[str, Any]) -> dict[str, Any]:
    keys = ("run_id", "start_time", "operation", "argv", "staging_path", "host_drive",
            "host_free_before", "host_free_after", "sandbox_verified", "sandbox_capacity",
            "provenance", "limits", "exit_reason", "cause", "detail", "exit_code",
            "duration_s", "ticks", "max_staging_seen", "max_file_seen", "killed_processes",
            "evidence_path", "ok")
    compact = {key: guard.get(key) for key in keys if key in guard}
    samples = guard.get("samples_preserved", [])
    if samples:
        compact["samples_preserved"] = [{
            key: sample.get(key) for key in ("path", "size", "head_sha256", "tail_sha256")
            if key in sample
        } for sample in samples]
    return compact


def build_manifest() -> dict[str, Any]:
    cache = ROOT / "build/staging-w3-059-ah44-stack-20261009/CMakeCache.txt"
    cache_values = {}
    for line in cache.read_text(encoding="utf-8", errors="replace").splitlines():
        if ":" in line and "=" in line and not line.startswith(("#", "//")):
            key, value = line.split("=", 1)
            cache_values[key.split(":", 1)[0]] = value
    exe = EXE
    native_exe = ROOT / "build/staging-w3-059-ah44-stack-20261009/native_test_build/Debug/w3_059_exec_trace_native_test.exe"
    native_trace = ROOT / "build/staging-w3-059-ah44-stack-20261009/native_test/capture.jsonl"
    source_file = SOURCE / "src/cpu/cpu.cpp"
    preimage = ROOT / "build/staging-w3-059-ah44-stack-20261009/source_preimage/cpu.cpp.preimage"
    try:
        revision = subprocess.run(["git", "-C", str(SOURCE), "rev-parse", "HEAD"],
                                  capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    except Exception as exc:
        revision = f"unavailable:{type(exc).__name__}"
    return {
        "source_revision": revision,
        "pinned_revision_match": revision == REVISION,
        "source_cpu_cpp_sha256": sha256(source_file),
        "source_preimage_sha256": sha256(preimage),
        "source_cpu_cpp_bytes": source_file.stat().st_size,
        "cmake": {
            "generator": cache_values.get("CMAKE_GENERATOR"),
            "toolset": cache_values.get("CMAKE_GENERATOR_TOOLSET"),
            "source_directory": cache_values.get("CMAKE_HOME_DIRECTORY"),
            "c_compiler": r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\Llvm\x64\bin\clang-cl.exe",
            "cxx_compiler": r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\Llvm\x64\bin\clang-cl.exe",
            "compiler_version": "Clang 19.1.5 with MSVC-like command-line",
            "debugger": cache_values.get("OPT_DEBUGGER"),
            "heavy_debugger": cache_values.get("OPT_HEAVY_DEBUGGER"),
            "tests": cache_values.get("OPT_TESTS"),
        },
        "build_exit_code": 0,
        "binary": {
            "path": str(exe), "exists": exe.is_file(),
            "bytes": exe.stat().st_size if exe.is_file() else None,
            "sha256": sha256(exe) if exe.is_file() else None,
            "version_marker_present": b"0.83.0-RC1 (81835)" in exe.read_bytes() if exe.is_file() else False,
        },
        "native_trace_test": {
            "build_exit_code": 0, "run_exit_code": 0,
            "binary": str(native_exe),
            "binary_sha256": sha256(native_exe) if native_exe.is_file() else None,
            "trace": str(native_trace),
            "trace_sha256": sha256(native_trace) if native_trace.is_file() else None,
        },
    }


def write_report(data: dict[str, Any]) -> None:
    capture = data["run"]["capture"]
    calls = capture["original_ah44_callbacks"]
    at_callsite = [event for event in capture["target_checkpoints"]
                   if event.get("link_va") == 0xC8973]
    first = at_callsite[0] if at_callsite else None
    guard = data["run"]["guard"]
    REPORT.write_text(
        "# W3-259 — muestra de pila en INT 21h AX=4400/BX=1\n\n"
        f"Clasificación: **{data['classification']}**. La compilación y las pruebas sintéticas pasaron; "
        "el único replay se ejecutó con oracle_guard y terminó por el timeout de 30 s.\n\n"
        f"El replay siguió la cadena natural hasta MAIN. Capturó el checkpoint "
        f"{first.get('checkpoint') if first else 'UNKNOWN'} en link VA "
        f"{(first.get('link_va') or 0):#08x} con runtime EIP "
        f"{first.get('linear') if first else 'UNKNOWN'}, rebase verificado "
        f"{first.get('main_code_rebase') if first else 'UNKNOWN'}, "
        f"AX={first.get('eax') if first else 'UNKNOWN'} y BX={first.get('ebx') if first else 'UNKNOWN'}. "
        f"Su callback DOS devolvió AX={calls[0].get('out_ax') if calls else 'UNKNOWN'}, "
        f"CF={calls[0].get('cf') if calls else 'UNKNOWN'}, CWD="
        f"{calls[0].get('cwd') if calls else 'UNKNOWN'}. Esa llamada fue BX=5, no el BX=1 objetivo.\n\n"
        f"Eventos de traza: {capture['event_count']} ({capture['trace_bytes']} bytes); "
        f"último evento: {capture['last_trace_event']}. BX=1 verificado en este replay: "
        f"{capture['verified_bx1_count']}. Por ello no hay muestra de pila ni caller nuevo. "
        "El caller permanece UNKNOWN. La captura anterior W3-236/W3-255 sí emparejó un BX=1 "
        "en la secuencia 104 y callback 107; este run no llegó a esa invocación antes del timeout.\n\n"
        f"Guard: {guard.get('exit_reason')} / {guard.get('cause')}; "
        f"duración {guard.get('duration_s')} s. Evidencia: {OUT}; metadata compacta: "
        f"{GUARD_EVIDENCE}. Metadata original del guard: "
        f"{data['run'].get('guard_original_metadata')}.\n\n"
        "Siguiente acción: no repetir este replay sin una nueva hipótesis medida. Reutilizar "
        "W3-236/W3-255 como evidencia del contrato BX=1 ya observado; si hace falta caller, "
        "crear una tarea distinta solo cuando exista una forma nueva y bounded de alcanzar o "
        "reducir la invocación tardía.\n",
        encoding="utf-8")


def run_checked(argv: list[str], timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, cwd=ROOT, capture_output=True, text=True,
                          timeout=timeout, check=False)


def verify_sandbox() -> dict[str, Any]:
    proc = run_checked(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                        "-File", str(ROOT / "tools/verify_oracle_sandbox.ps1"),
                        "-Path", str(MOUNT), "-Json"], timeout=30)
    if proc.returncode != 0:
        raise RuntimeError(f"sandbox verification failed ({proc.returncode}): {proc.stderr[-1000:]}")
    result = json.loads(proc.stdout.strip().splitlines()[-1])
    if result.get("verified") is not True or result.get("volume", result.get("label")) != "GWORACLE":
        raise RuntimeError(f"GWORACLE not verified: {result}")
    if result.get("capacity_bytes", 0) < 15 * 1024**3:
        raise RuntimeError("GWORACLE capacity below required 15 GiB")
    if result.get("host_free_bytes", 0) < result.get("host_floor_bytes", 0):
        raise RuntimeError("host free-space floor not satisfied")
    return result


def fixture_preflight() -> dict[str, Any]:
    target = MOUNT / "GENEWARS/GW.EXE"
    cue = Path(r"E:\GeneWarsFX\evidence\original_disc\Genewars (Europe) (En,Fr,De,Es,It,Sv).cue")
    address = MOUNT / "ADDRESS.TXT"
    source_address = Path(r"<GENEWARS_HDD_ROOT>\ADDRESS.TXT")
    if not target.is_file() or target.stat().st_size != TARGET_SIZE or sha256(target) != TARGET_SHA256:
        raise RuntimeError("GW.EXE fixture identity mismatch")
    if not CONFIG.is_file() or sha256(CONFIG) != CONFIG_SHA256:
        raise RuntimeError("functional W3-067 config mismatch")
    if not cue.is_file() or sha256(cue) != CUE_SHA256:
        raise RuntimeError("original CUE identity mismatch")
    if not address.is_file() or not source_address.is_file():
        raise RuntimeError("ADDRESS.TXT source or fixture is missing")
    if sha256(address) != ADDRESS_SHA256 or sha256(source_address) != ADDRESS_SHA256:
        raise RuntimeError("ADDRESS.TXT source/fixture provenance mismatch")
    if TRACE.exists():
        raise RuntimeError(f"refusing to overwrite prior trace: {TRACE}")
    if not EXE.is_file():
        raise RuntimeError("fresh instrumented DOSBox binary missing")
    revision = subprocess.run(["git", "-C", str(SOURCE), "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    if revision != REVISION:
        raise RuntimeError(f"pinned source revision mismatch: {revision}")
    if b"0.83.0-RC1 (81835)" not in EXE.read_bytes():
        raise RuntimeError("instrumented executable version marker mismatch")
    return {
        "target_path": str(target), "target_bytes": target.stat().st_size,
        "target_sha256": sha256(target), "functional_config": str(CONFIG),
        "config_sha256": sha256(CONFIG), "cue_path": str(cue),
        "cue_sha256": sha256(cue), "address_path": str(address),
        "address_sha256": sha256(address), "source_address_path": str(source_address),
        "source_address_sha256": sha256(source_address), "instrumented_exe": str(EXE),
        "instrumented_exe_sha256": sha256(EXE), "trace_path": str(TRACE),
        "trace_cap_bytes": TRACE_CAP,
    }


def invoke_guard() -> dict[str, Any]:
    evidence_dir = ROOT / "evidence/oracle_runs"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    for key in tuple(env):
        if key.startswith(("GWRECOMP_ANCHOR_", "GWRECOMP_EXEC_TRACE_", "GWRECOMP_W3_237_",
                           "GWRECOMP_W3_249_", "GWRECOMP_W3_251_")):
            env.pop(key, None)
    env.update({
        "GWRECOMP_GW_FILE_SIZE": str(TARGET_SIZE),
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
    args = [sys.executable, str(GUARD), "run", "--exe", str(EXE), "--config", str(CONFIG),
            "--staging-dir", str(MOUNT), "--host-drive", "E:",
            "--run-id", "w3-259-ah44-bx1-stack-20261009-01",
            "--operation", "W3-259 first verified MAIN BX1 stack sample",
            "--commit-sha", REVISION, "--target-sha", TARGET_SHA256,
            "--runtime-sha", sha256(EXE), "--fixture-sha", TARGET_SHA256,
            "--evidence-dir", str(evidence_dir),
            "--max-file-text-mib", "1", "--max-file-bin-mib", "64",
            "--max-run-gib", "1", "--host-floor-gib", "100", "--timeout-s", "30",
            "--growth-text-mibs", "8", "--growth-bin-mibs", "24", "--poll-hz", "1"]
    proc = subprocess.run(args, cwd=ROOT, env=env, capture_output=True, text=True,
                          timeout=60, check=False)
    if not TRACE.is_file():
        raise RuntimeError(f"guard returned {proc.returncode} but trace is absent: {proc.stderr[-2000:]}")
    raw = TRACE.read_bytes()
    reduced = reduce_trace(raw)
    try:
        guard = json.loads(proc.stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError):
        guard = {"stdout_tail": proc.stdout[-3000:], "stderr_tail": proc.stderr[-3000:],
                 "returncode": proc.returncode}
    raw_guard_path = guard.get("evidence_path") or str(
        evidence_dir / "oracle_runs_w3-259-ah44-bx1-stack-20261009-01.json")
    GUARD_EVIDENCE.write_text(json.dumps(compact_guard(guard), indent=2) + "\n", encoding="utf-8")
    return {"argv": args, "returncode": proc.returncode, "stdout_tail": proc.stdout[-3000:],
            "stderr_tail": proc.stderr[-3000:], "guard_metadata": str(GUARD_EVIDENCE),
            "guard_original_metadata": raw_guard_path, "guard": compact_guard(guard),
            "capture": reduced}


def main() -> int:
    check = run_checked([str(ROOT / "coordination/autopilot.cmd"), "check",
                         "W3-259", "--worker", "WORK3"])
    if check.returncode != 0:
        print(check.stdout + check.stderr, file=sys.stderr)
        return check.returncode
    sandbox = verify_sandbox()
    fixture = fixture_preflight()
    outcome = invoke_guard()
    cue = Path(fixture["cue_path"])
    source_address = Path(fixture["source_address_path"])
    game_source = Path(r"<GENEWARS_INSTALL_DIR>\GW.EXE")
    postrun_integrity = {
        "cue_sha256_after": sha256(cue),
        "cue_unchanged": sha256(cue) == fixture["cue_sha256"],
        "source_address_sha256_after": sha256(source_address),
        "source_address_unchanged": sha256(source_address) == fixture["source_address_sha256"],
        "user_source_gw_exe_sha256": sha256(game_source),
        "user_source_gw_exe_unchanged": sha256(game_source) == TARGET_SHA256,
        "guest_fixture_gw_exe_sha256": sha256(MOUNT / "GENEWARS/GW.EXE"),
        "guest_fixture_gw_exe_unchanged": sha256(MOUNT / "GENEWARS/GW.EXE") == TARGET_SHA256,
    }
    data = {"schema": "gwrecomp.w3-259-ah44-stack-sample/v1", "task": "W3-259",
            "classification": "ORIGINAL_CAPTURED" if outcome["capture"]["verified_bx1_count"] else "INCONCLUSIVE_NO_VERIFIED_BX1",
            "evidence_level": "ORIGINAL_OBSERVED", "source_revision": REVISION,
            "preflight": {"sandbox": sandbox, "fixture": fixture},
            "postrun_integrity": postrun_integrity, "build": build_manifest(), "run": outcome,
            "limits": {"timeout_s": 30, "trace_bytes_max": TRACE_CAP, "trace_events_max": MAX_EVENTS,
                       "stack_sample_bytes_max": 24, "max_file_text_mib": 1,
                       "max_file_bin_mib": 64, "max_run_gib": 1, "host_floor_gib": 100},
            "interpretation": {"caller": outcome["capture"]["caller_identification"],
                               "menu_reached": False, "framebuffer_reached": False}}
    OUT.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    write_report(data)
    print(json.dumps({"evidence": str(OUT), "classification": data["classification"],
                      "events": outcome["capture"]["event_count"],
                      "bx1_verified": outcome["capture"]["verified_bx1_count"]}, indent=2))
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--reduce-existing", action="store_true")
    args = parser.parse_args()
    if args.reduce_existing:
        data = json.loads(OUT.read_text(encoding="utf-8"))
        fixture = data["preflight"]["fixture"]
        trace_path = Path(fixture["trace_path"])
        trace = reduce_trace(trace_path.read_bytes())
        data["run"]["capture"] = trace
        data["run"]["guard"] = compact_guard(data["run"]["guard"])
        if "postrun_integrity" not in data:
            cue = Path(fixture["cue_path"])
            source_address = Path(fixture["source_address_path"])
            game_source = Path(r"<GENEWARS_INSTALL_DIR>\GW.EXE")
            data["postrun_integrity"] = {
                "cue_sha256_after": sha256(cue),
                "cue_unchanged": sha256(cue) == fixture["cue_sha256"],
                "source_address_sha256_after": sha256(source_address),
                "source_address_unchanged": sha256(source_address) == fixture["source_address_sha256"],
                "user_source_gw_exe_sha256": sha256(game_source),
                "user_source_gw_exe_unchanged": sha256(game_source) == TARGET_SHA256,
                "guest_fixture_gw_exe_sha256": sha256(MOUNT / "GENEWARS/GW.EXE"),
                "guest_fixture_gw_exe_unchanged": sha256(MOUNT / "GENEWARS/GW.EXE") == TARGET_SHA256,
            }
        data["build"] = build_manifest()
        data["run"]["guard_original_metadata"] = (
            data["run"].get("guard_original_metadata") or
            str(ROOT / "evidence/oracle_runs/oracle_runs_w3-259-ah44-bx1-stack-20261009-01.json"))
        GUARD_EVIDENCE.write_text(json.dumps(compact_guard(data["run"]["guard"]), indent=2) + "\n",
                                  encoding="utf-8")
        data["run"]["guard"] = compact_guard(data["run"]["guard"])
        OUT.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        write_report(data)
        print(json.dumps({"evidence": str(OUT), "events": trace["event_count"],
                          "checkpoints": trace["target_checkpoints"],
                          "callbacks": trace["original_ah44_callbacks"],
                          "last": trace["last_trace_event"]}, indent=2))
        raise SystemExit(0)
    raise SystemExit(main())
