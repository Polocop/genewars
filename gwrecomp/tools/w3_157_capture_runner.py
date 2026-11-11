#!/usr/bin/env python3
"""One guarded natural W_SCREEN loader-to-copy sparse sample comparison."""
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
from tools.w3_143_postopen_branch import MAX_TRACE_BYTES, parse_jsonl

MOUNT = ROOT / "build/dosboxx_oracle/C"
FIXTURE = MOUNT / "GENEWARS/GW.EXE"
CONFIG = ROOT / "build/dosboxx_oracle/dosbox-staging.w3-067-functional.conf"
CUE = ROOT.parent / "GeneWarsFX/evidence/original_disc/Genewars (Europe) (En,Fr,De,Es,It,Sv).cue"
DOSBOX = ROOT / "build/staging-w3-059-exec/Debug/dosbox.exe"
GUARD = ROOT / "tools/oracle_guard.py"
SOURCE = ROOT / "third_party/dosbox-staging-w3-059-instrumented"
CORE = SOURCE / "src/cpu/core_dyn_x86.cpp"
DISASM = ROOT / "evidence/genewars-1_1-le_disasm.s"
FRONTIER = ROOT / "evidence/w3_150_screen_write_frontier.json"
REVISION = "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f"
GW_SIZE = 1_251_658
GW_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
CONFIG_SHA256 = "b2bac63096aa97a808abb8ea09486db79559b12a25a1410ea930be0e5eeffff1"
CUE_SHA256 = "1d417e3aed625d4f054b51054a1211562a19cd4f712b08e7846613517228a5b5"
RUN_ID = "w3-157-wscreen-load-copy-20261009-01"
TRACE = MOUNT / "W3_157_WSCREEN_LOAD_COPY_20261009_01.jsonl"
RESULT = ROOT / "evidence/w3_157_wscreen_load_to_copy.json"


def bounded_rep_slice(dwords: int, cap: int = 0x40000) -> int | None:
    """Budget that lets normal-core REP finish without executing the next opcode."""
    if dwords < 2 or dwords > cap:
        return None
    return dwords - 1


def sample_offsets(copy_bytes: int, sample_bytes: int = 16) -> list[int]:
    if copy_bytes < sample_bytes:
        return []
    result = []
    for offset in (0, copy_bytes // 2, copy_bytes - sample_bytes):
        if all(offset + sample_bytes <= prior or prior + sample_bytes <= offset
               for prior in result):
            result.append(offset)
    return result


def sample_bounds_valid(start: int, offset: int, size: int, limit: int, physical: int) -> bool:
    if min(start, offset, size, limit, physical) < 0 or size == 0:
        return False
    end = start + offset + size
    return end >= start and start + offset >= start and end <= limit + 1 and end <= physical


def summarize_pairs(windows: list[dict]) -> dict:
    valid = [w for w in windows if w.get("valid") is True]
    return {"bytes_total": len(valid) * 32, "max_bytes": 96,
            "all_pairs_equal": all(w.get("source_hex") == w.get("destination_hex")
                                    for w in valid) if valid else None}


def loader_entry_matches(entry: dict | None, code_rebase: int, data_rebase: int) -> bool:
    return bool(entry and entry.get("link_va") == 0x15090 and
                entry.get("return_address") == code_rebase + 0x94DC1 and
                entry.get("edx") == data_rebase + 0x104054 and
                entry.get("w3_157_descriptor_name") == "*W_SCREEN")


def windows_bounded(rows: list[dict], expected_offsets=(0, 32000, 63984)) -> bool:
    return (len(rows) == 3 and [x.get("offset") for x in rows] == list(expected_offsets) and
            all(x.get("valid") is True and len(x.get("hex", "")) == 32 for x in rows))


def parse_capture_rows(raw: bytes) -> tuple[list[dict], list[int]]:
    """Parse JSONL, repairing only the known missing '[' prefix in W3-154 windows."""
    rows, recovered_lines = [], []
    marker = b'"w3_154_source_destination_windows":[]'
    replacement = b'"w3_154_source_destination_windows":['
    for line_number, line in enumerate(raw.splitlines(), 1):
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            if marker not in line:
                raise
            repaired = line.replace(marker, replacement, 1)
            rows.append(json.loads(repaired))
            recovered_lines.append(line_number)
    return rows, recovered_lines


def find(rows, name, va):
    return next((r for r in rows if r.get("event") == "target_runtime_checkpoint" and
                 r.get("checkpoint") == name and r.get("link_va") == va), None)


def main() -> int:
    if Path(sys.executable).name.lower() != "python.exe":
        raise RuntimeError(f"explicit console Python required, got {sys.executable}")
    sandbox = verify_sandbox()
    for path in (FIXTURE, CONFIG, CUE, DOSBOX, GUARD, CORE, DISASM, FRONTIER):
        if not path.is_file():
            raise FileNotFoundError(path)
    if FIXTURE.stat().st_size != GW_SIZE or sha(FIXTURE) != GW_SHA256:
        raise RuntimeError("authentic GW.EXE identity mismatch")
    if sha(CONFIG) != CONFIG_SHA256 or sha(CUE) != CUE_SHA256:
        raise RuntimeError("functional config or original CUE hash mismatch")
    if not re.search(r"(?im)^\s*imgmount\s+d\s+.*\.cue.*-ro\b", CONFIG.read_text(encoding="utf-8")):
        raise RuntimeError("original CUE is not mounted read-only")
    frontier = json.loads(FRONTIER.read_text(encoding="utf-8"))
    if frontier["provenance"]["target_sha256"] != GW_SHA256:
        raise RuntimeError("static write frontier is not bound to target")
    revision = subprocess.run(["git", "-C", str(SOURCE), "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    if revision != REVISION:
        raise RuntimeError(f"pinned Staging revision mismatch: {revision}")
    source = CORE.read_text(encoding="utf-8", errors="replace")
    tokens = ("W3_157_WSCREEN_LOADER_ENTRY", "W3_157_WSCREEN_LOADER_RETURN",
              "W3_157_WSCREEN_COPY_PRE", "w3_157_loader_pending",
              "w3_157_expected_return_runtime", "w3_157_sample_windows",
              "w3_157_total_sample_bytes + w3_157_sample_bytes + 16 <= 96",
              "w3_151_copy_probe_armed", "MEM_TotalPages()")
    for token in tokens:
        if token not in source:
            raise RuntimeError(f"bounded screen-write probe missing {token}")
    evidence_dir = ROOT / "evidence/oracle_runs"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    stdout = evidence_dir / f"{RUN_ID}.stdout.json"
    stderr = evidence_dir / f"{RUN_ID}.stderr.txt"
    if any(path.exists() for path in (TRACE, RESULT, stdout, stderr)):
        raise FileExistsError("refusing to overwrite W3-157 artifacts")
    binary_hash = sha(DOSBOX)
    core_hash = sha(CORE)
    env = dict(os.environ)
    for key in tuple(env):
        if key.startswith("GWRECOMP_ANCHOR_") or key.startswith("GWRECOMP_EXEC_TRACE_"):
            env.pop(key, None)
    env.update({"GWRECOMP_GW_FILE_SIZE": str(GW_SIZE),
                "GWRECOMP_GW_LE_HEADER_OFFSET": "0x8f50",
                "GWRECOMP_GW_LE_OBJECT_TABLE_OFFSET": "0x9014",
                "GWRECOMP_EXEC_TRACE_PATH": str(TRACE),
                "GWRECOMP_EXEC_TRACE_MAX_BYTES": str(MAX_TRACE_BYTES),
                "GWRECOMP_EXEC_TRACE_FILE_IO": "0",
                "GWRECOMP_ANCHOR_MAIN_ENTRY_LINK": "0x000af96c",
                "GWRECOMP_ANCHOR_MAIN_ENTRY_BYTES": "eb765741",
                "GWRECOMP_ANCHOR_CRT_ARGV_LOAD_LINK": "0x000c8702",
                "GWRECOMP_ANCHOR_GAME_MAIN_ENTRY_LINK": "0x00093f30"})
    command = [sys.executable, str(GUARD), "run", "--exe", str(DOSBOX), "--config", str(CONFIG),
               "--staging-dir", str(MOUNT), "--host-drive", "E:", "--run-id", RUN_ID,
               "--operation", "W3-157 original W_SCREEN loader-to-copy bounded samples",
               "--commit-sha", REVISION, "--target-sha", GW_SHA256, "--runtime-sha", binary_hash,
               "--fixture-sha", GW_SHA256, "--evidence-dir", str(evidence_dir),
               "--max-file-text-mib", "1", "--max-file-bin-mib", "64", "--max-run-gib", "1",
               "--host-floor-gib", "100", "--timeout-s", "30", "--growth-text-mibs", "8",
               "--growth-bin-mibs", "24", "--poll-hz", "1"]
    with stdout.open("xb") as out, stderr.open("xb") as err:
        subprocess.run(command, cwd=ROOT, env=env, stdout=out, stderr=err, timeout=40, check=False)
    guard = json.loads(stdout.read_text(encoding="utf-8"))
    raw = TRACE.read_bytes() if TRACE.exists() else b""
    rows = parse_jsonl(raw)
    targets = {
        "loader_entry": find(rows, "W3_157_WSCREEN_LOADER_ENTRY", 0x15090),
        "loader_return": find(rows, "W3_157_WSCREEN_LOADER_RETURN", 0x94DC1),
        "copy_pre": find(rows, "W3_157_WSCREEN_COPY_PRE", 0xA0013),
        "vesa_branch": find(rows, "W3_151_VESA_BRANCH", 0xA0000),
    }
    branch = targets["vesa_branch"]
    mapping = None
    if branch:
        mapping = {"code_rebase": branch["eip"] - branch["link_va"],
                   "data_rebase": branch.get("data_rebase"),
                   "data_rebase_freshly_observed": bool(branch.get("data_rebase"))}
    same_rebase = True
    for row in targets.values():
        if row and mapping:
            same_rebase = same_rebase and row["eip"] - row["link_va"] == mapping["code_rebase"]
    entry = targets["loader_entry"]
    loaded = targets["loader_return"]
    copied = targets["copy_pre"]
    code_rebase = mapping["code_rebase"] if mapping else 0
    data_rebase = mapping["data_rebase"] if mapping else 0
    entry_matches = loader_entry_matches(entry, code_rebase, data_rebase)
    loader_windows = loaded.get("w3_157_sample_windows", []) if loaded else []
    copy_windows = copied.get("w3_157_sample_windows", []) if copied else []
    sample_bytes_total = ((loaded.get("w3_157_sample_bytes", 0) if loaded else 0) +
                          (copied.get("w3_157_sample_bytes", 0) if copied else 0))
    samples_valid = (windows_bounded(loader_windows) and windows_bounded(copy_windows) and
                     sample_bytes_total == 96)
    source_pointer = loaded.get("w3_157_wscreen_pointer") if loaded else None
    copy_source_pointer = copied.get("esi") if copied else None
    pointer_consistent = bool(loaded and copied and
        loaded.get("w3_157_wscreen_pointer_valid") is True and
        copied.get("w3_157_wscreen_pointer_valid") is True and
        source_pointer == copy_source_pointer == copied.get("w3_157_wscreen_pointer"))
    same_samples = bool(samples_valid and
        [w.get("hex") for w in loader_windows] == [w.get("hex") for w in copy_windows])
    result = {
        "schema": "w3-157-wscreen-load-to-copy/v1", "task": "W3-157", "run_id": RUN_ID,
        "source": {"target_sha256": GW_SHA256, "fixture_bytes": FIXTURE.stat().st_size,
                   "config_sha256": sha(CONFIG), "cue_sha256": sha(CUE),
                   "staging_revision": revision, "instrumented_core_sha256": core_hash,
                   "staging_binary_sha256": binary_hash},
        "preflight": {"sandbox": sandbox, "cue_read_only_mount": True,
                      "timeout_seconds": 30, "trace_cap_bytes": MAX_TRACE_BYTES,
                      "global_trace": False, "fixture_or_original_modified": False},
        "guard": {key: guard.get(key) for key in ("run_id", "operation", "sandbox_verified",
                   "sandbox_capacity", "host_free_before", "host_free_after", "limits",
                   "exit_reason", "cause", "detail", "exit_code", "killed_processes",
                   "duration_s", "evidence_path", "ok")},
        "trace": {"path": str(TRACE.relative_to(ROOT)), "bytes": len(raw),
                  "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
                  "event_count": len(rows)},
        "mapping": mapping, "mapping_consistent": same_rebase,
        "checkpoints": targets,
        "loader_entry_matches_wscreen_call": entry_matches,
        "loader_entry": {"link_va": entry.get("link_va") if entry else None,
                         "edx": entry.get("edx") if entry else None,
                         "expected_edx": data_rebase + 0x104054 if mapping else None,
                         "descriptor_name": entry.get("w3_157_descriptor_name") if entry else None,
                         "return_address": entry.get("return_address") if entry else None,
                         "expected_return_address": code_rebase + 0x94DC1 if mapping else None,
                         "call_ordinal": entry.get("w3_157_loader_call_ordinal") if entry else None,
                         "registers": {k: entry.get(k) for k in
                           ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eflags", "ds", "es", "ss")} if entry else None},
        "loader_return": {"link_va": loaded.get("link_va") if loaded else None,
                           "eip": loaded.get("eip") if loaded else None,
                           "eax_result": loaded.get("eax") if loaded else None,
                           "w_screen_pointer_valid": loaded.get("w3_157_wscreen_pointer_valid") if loaded else False,
                           "w_screen_pointer": loaded.get("w3_157_wscreen_pointer") if loaded else None,
                           "sample_bytes": loaded.get("w3_157_sample_bytes") if loaded else 0,
                           "sample_windows": loader_windows},
        "first_copy_source": {"link_va": copied.get("link_va") if copied else None,
                               "eip": copied.get("eip") if copied else None,
                               "source_pointer_esi": copied.get("esi") if copied else None,
                               "w_screen_pointer_valid": copied.get("w3_157_wscreen_pointer_valid") if copied else False,
                               "sample_bytes": copied.get("w3_157_sample_bytes") if copied else 0,
                               "sample_windows": copy_windows},
        "sample_validation": {"valid_windows_at_both_checkpoints": samples_valid,
                               "bytes_total": sample_bytes_total, "max_bytes": 96,
                               "source_pointer_consistent": pointer_consistent,
                               "source_windows_unchanged": same_samples,
                               "max_windows_each": 3, "each_window_bytes": 16},
        "capture_complete": bool(entry_matches and loaded and copied and samples_valid and
                                  pointer_consistent and
                                  sample_bytes_total <= 96 and same_rebase),
        "framebuffer_or_visible_output_proven": False,
        "limitations": ["Only three 16-byte windows were read at each checkpoint.",
                        "This capture does not establish pixel format or visible presentation."]
    }
    RESULT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"result": str(RESULT), "entry_matches": entry_matches,
                      "loader_return": bool(loaded), "copy_pre": bool(copied),
                      "samples_valid": samples_valid, "sample_bytes": sample_bytes_total,
                      "capture_complete": result["capture_complete"],
                      "guard_cause": guard.get("cause")}, indent=2))
    return 0 if guard.get("sandbox_verified") and guard.get("ok") else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"PREFLIGHT/REPLAY FAILED CLOSED: {exc}", file=sys.stderr)
        raise SystemExit(2)
