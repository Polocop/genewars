#!/usr/bin/env python3
"""Fail-closed preflight and one guarded, focused original startup replay."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
MOUNT = ROOT / "build/dosboxx_oracle/C"
FIXTURE = MOUNT / "GENEWARS/GW.EXE"
CONFIG = ROOT / "build/dosboxx_oracle/dosbox-staging.w3-067-functional.conf"
DOSBOX = ROOT / "build/staging-w3-059-exec/Debug/dosbox.exe"
TRACE = MOUNT / "W3_MAIN_FOCUSED_20261008_01.jsonl"
CONFIG_SHA256 = "b2bac63096aa97a808abb8ea09486db79559b12a25a1410ea930be0e5eeffff1"
GW_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
GW_SIZE = 1_251_658
STAGING_REVISION = "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f"
STAGING_SOURCE = ROOT / "third_party/dosbox-staging-w3-059-instrumented"
GUARD_SCRIPT = ROOT / "tools/oracle_guard.py"
STAGING = ROOT / "build/dosboxx_oracle/C"
RUN_ID = "w3-main-focused-20261008-01"
MAIN_LINK = 0x000AF96C
MAIN_SIGNATURE = "eb765741"
CAPTURE_SITES = frozenset({
    0x000C3E59, 0x000C3F75, 0x000AE03D, 0x000AE28C,
    0x000DFDC1, 0x000DFE12, 0x000C871C, 0x000C87B6,
    0x000C86CD, 0x000C8702, 0x00093F30,
})

CAPTURE_ENV = {
    "GWRECOMP_GW_FILE_SIZE": str(GW_SIZE),
    "GWRECOMP_GW_LE_HEADER_OFFSET": "0x8f50",
    "GWRECOMP_GW_LE_OBJECT_TABLE_OFFSET": "0x9014",
    "GWRECOMP_EXEC_TRACE_PATH": str(TRACE),
    "GWRECOMP_EXEC_TRACE_MAX_BYTES": str(512 * 1024),
    "GWRECOMP_ANCHOR_MAIN_ENTRY_LINK": "0x000af96c",
    "GWRECOMP_ANCHOR_MAIN_ENTRY_BYTES": "eb765741",
    "GWRECOMP_ANCHOR_CRT_ARGV_LOAD_LINK": "0x000c8702",
    "GWRECOMP_ANCHOR_GAME_MAIN_ENTRY_LINK": "0x00093f30",
}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def capture_environment(base: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(os.environ if base is None else base)
    # Prevent stale per-anchor overrides from an earlier capture changing this run.
    for key in tuple(env):
        if key.startswith("GWRECOMP_ANCHOR_") or key.startswith("GWRECOMP_EXEC_TRACE_"):
            env.pop(key, None)
    env.update(CAPTURE_ENV)
    return env


def validate_capture_environment(env: dict[str, str]) -> None:
    missing = [key for key, expected in CAPTURE_ENV.items()
               if not str(env.get(key, "")).strip()]
    if missing:
        raise ValueError("missing required capture environment: " + ", ".join(missing))
    if env["GWRECOMP_GW_FILE_SIZE"] != str(GW_SIZE):
        raise ValueError(f"GWRECOMP_GW_FILE_SIZE must be {GW_SIZE}; hook would remain unarmed")
    if int(env["GWRECOMP_EXEC_TRACE_MAX_BYTES"], 0) != 512 * 1024:
        raise ValueError("trace cap must remain 524288 bytes")


def main_signature_candidate(runtime_linear: int) -> bool:
    return runtime_linear >= MAIN_LINK and (runtime_linear & 0xFFF) == (MAIN_LINK & 0xFFF)


def main_signature_matches(runtime_linear: int, signature_hex: str) -> bool:
    return main_signature_candidate(runtime_linear) and signature_hex.lower() == MAIN_SIGNATURE


def main_anchor_matches(runtime_linear: int, rebase: int, cs: int, expected_cs: int) -> bool:
    return rebase > 0 and cs == expected_cs and runtime_linear == rebase + MAIN_LINK


def capture_site_matches(runtime_linear: int, link_va: int, rebase: int,
                         cs: int, expected_cs: int) -> bool:
    return (link_va in CAPTURE_SITES and cs == expected_cs and rebase > 0
            and runtime_linear == rebase + link_va)


def guest_range_valid(offset: int, length: int, descriptor_limit: int) -> bool:
    return offset >= 0 and length > 0 and offset + length - 1 <= descriptor_limit


def verify_file_inputs() -> dict[str, str | int]:
    for path in (FIXTURE, CONFIG, DOSBOX):
        if not path.is_file():
            raise FileNotFoundError(f"required input missing: {path}")
    fixture_size = FIXTURE.stat().st_size
    fixture_sha = sha256(FIXTURE)
    config_sha = sha256(CONFIG)
    if fixture_size != GW_SIZE or fixture_sha != GW_SHA256:
        raise ValueError(f"GW.EXE mismatch: size={fixture_size}, sha256={fixture_sha}")
    if config_sha != CONFIG_SHA256:
        raise ValueError(f"functional config hash mismatch: {config_sha}")
    if not str(TRACE).startswith(str(MOUNT) + os.sep):
        raise ValueError("trace path is outside the verified VHDX mount")
    TRACE.parent.mkdir(parents=True, exist_ok=True)
    probe = TRACE.with_name(TRACE.name + ".preflight")
    try:
        probe.write_text("preflight", encoding="ascii")
        probe.unlink()
    except OSError as exc:
        raise OSError(f"trace path is not writable: {TRACE}: {exc}") from exc
    return {"fixture_size": fixture_size, "fixture_sha256": fixture_sha,
            "config_sha256": config_sha, "runtime_sha256": sha256(DOSBOX)}


def verify_sandbox() -> dict:
    cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
           str(ROOT / "tools/verify_oracle_sandbox.ps1"), "-Json"]
    result = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError(f"sandbox verification failed: {result.stderr[-1500:]}")
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"sandbox verifier returned invalid JSON: {result.stdout[-1000:]}") from exc
    if data.get("verified") is not True or data.get("label", data.get("volume")) != "GWORACLE":
        raise RuntimeError(f"sandbox is not verified GWORACLE: {data}")
    return data


def verify_tooling() -> dict[str, str]:
    if not GUARD_SCRIPT.is_file():
        raise FileNotFoundError(f"oracle_guard is missing: {GUARD_SCRIPT}")
    revision = subprocess.run(
        ["git", "-C", str(STAGING_SOURCE), "rev-parse", "HEAD"],
        cwd=ROOT, capture_output=True, text=True, timeout=10, check=True,
    ).stdout.strip()
    if revision != STAGING_REVISION:
        raise RuntimeError(f"Staging source revision mismatch: {revision}")
    help_result = subprocess.run(
        [sys.executable, str(GUARD_SCRIPT), "run", "--help"],
        cwd=ROOT, capture_output=True, text=True, timeout=10,
    )
    if help_result.returncode != 0 or "oracle_guard run" not in help_result.stdout:
        raise RuntimeError("oracle_guard CLI validation failed")
    return {"staging_revision": revision, "oracle_guard_sha256": sha256(GUARD_SCRIPT)}


def run_guarded(env: dict[str, str], hashes: dict[str, str | int]) -> dict:
    verify = verify_sandbox()
    stdout_path = ROOT / "evidence/oracle_runs" / f"{RUN_ID}.stdout.json"
    stderr_path = ROOT / "evidence/oracle_runs" / f"{RUN_ID}.stderr.txt"
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    guard = [sys.executable, str(GUARD_SCRIPT), "run",
             "--exe", str(DOSBOX), "--config", str(CONFIG),
             "--staging-dir", str(STAGING), "--host-drive", "E:",
             "--run-id", RUN_ID, "--operation", "W3 focused MAIN/CRT startup capture",
             "--commit-sha", STAGING_REVISION,
             "--target-sha", GW_SHA256, "--runtime-sha", str(hashes["runtime_sha256"]),
             "--fixture-sha", GW_SHA256, "--evidence-dir", str(ROOT / "evidence/oracle_runs"),
             "--max-file-text-mib", "1", "--max-file-bin-mib", "64",
             "--max-run-gib", "1", "--host-floor-gib", "100", "--timeout-s", "120",
             "--growth-text-mibs", "8", "--growth-bin-mibs", "24", "--poll-hz", "1"]
    with stdout_path.open("wb") as out, stderr_path.open("wb") as err:
        proc = subprocess.run(guard, cwd=ROOT, env=env, stdout=out, stderr=err,
                              timeout=135, check=False)
    if stdout_path.stat().st_size > 16 * 1024 * 1024:
        raise RuntimeError("guard stdout exceeded the 16 MiB post-run cap")
    try:
        guard_data = json.loads(stdout_path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        guard_data = {"parse_error": "guard output was not a single JSON object"}
    return {"preflight_sandbox": verify, "guard_returncode": proc.returncode,
            "guard": guard_data, "trace_path": str(TRACE),
            "trace_bytes": TRACE.stat().st_size if TRACE.exists() else 0,
            "guard_stdout_path": str(stdout_path), "guard_stderr_path": str(stderr_path)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()
    env = capture_environment()
    validate_capture_environment(env)
    sandbox = verify_sandbox()
    tooling = verify_tooling()
    hashes = verify_file_inputs()
    summary = {"preflight": "PASS", "fixture": hashes,
               "sandbox": sandbox, "tooling": tooling, "config": str(CONFIG),
               "runtime": str(DOSBOX), "trace": str(TRACE)}
    if args.preflight_only:
        print(json.dumps(summary, indent=2))
        return 0
    result = run_guarded(env, hashes)
    summary["replay"] = result
    result_path = ROOT / "evidence/w3_main_focused_replay_20261008.json"
    result_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    guard = result.get("guard", {})
    print(json.dumps({"preflight": "PASS", "guard_returncode": result["guard_returncode"],
                      "guard_exit_reason": guard.get("exit_reason", "UNKNOWN"),
                      "guard_cause": guard.get("cause", "UNKNOWN"),
                      "trace_bytes": result["trace_bytes"],
                      "trace_path": result["trace_path"],
                      "result_path": str(result_path)}, indent=2))
    return 0 if result["guard_returncode"] == 0 else result["guard_returncode"]


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"PREFLIGHT/REPLAY FAILED CLOSED: {exc}", file=sys.stderr)
        raise SystemExit(2)
