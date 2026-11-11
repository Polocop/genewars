#!/usr/bin/env python3
"""One guarded, bounded original LbScreenSwap sparse screen-sample capture."""
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
RUN_ID = "w3-153-screen-samples-20261009-01"
TRACE = MOUNT / "W3_153_SCREEN_SAMPLES_20261009_01.jsonl"
RESULT = ROOT / "evidence/w3_153_screen_samples.json"


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
    tokens = ("w3_151_copy_probe_window", "w3_151_copy_probe_armed = true;",
              "w3_151_copy_pre_seen", "reg_ecx <= 0x00040000",
              "W3_151_VESA_BRANCH", "W3_151_COPY_NONVESA_PRE",
              "W3_151_COPY_NONVESA_POST", "W3_151_COPY_VESA_PRE",
              "W3_151_COPY_VESA_POST", "w3_151_copy_sample_bytes", "w3_153_screen_width",
              "w3_153_sample_windows", "sample_offsets", "MEM_TotalPages()")
    for token in tokens:
        if token not in source:
            raise RuntimeError(f"bounded screen-write probe missing {token}")
    evidence_dir = ROOT / "evidence/oracle_runs"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    stdout = evidence_dir / f"{RUN_ID}.stdout.json"
    stderr = evidence_dir / f"{RUN_ID}.stderr.txt"
    if any(path.exists() for path in (TRACE, RESULT, stdout, stderr)):
        raise FileExistsError("refusing to overwrite W3-153 artifacts")
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
               "--operation", "W3-153 original LbScreenSwap sparse screen samples",
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
        "screen_swap_entry": find(rows, "W3_142_LBSCREENSWAP_ENTRY", 0x9FFE0),
        "vesa_branch": find(rows, "W3_151_VESA_BRANCH", 0xA0000),
        "nonvesa_pre": find(rows, "W3_151_COPY_NONVESA_PRE", 0xA0013),
        "nonvesa_post": find(rows, "W3_151_COPY_NONVESA_POST", 0xA0015),
        "vesa_pre": find(rows, "W3_151_COPY_VESA_PRE", 0xA005D),
        "vesa_post": find(rows, "W3_151_COPY_VESA_POST", 0xA005F),
        "screen_swap_return": find(rows, "W3_149_LBSCREENSWAP_RETURN", 0xAE484),
    }
    post = targets["nonvesa_post"] or targets["vesa_post"]
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
    result = {
        "schema": "w3-153-lbscreenswap-sparse-samples/v1", "task": "W3-153", "run_id": RUN_ID,
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
        "observed_copy": {"path": "non-VESA" if targets["nonvesa_post"] else
                           "VESA" if targets["vesa_post"] else None,
                           "copy_completed": post is not None,
                           "branch_taken": branch.get("branch_taken") if branch else None,
                           "branch_target": branch.get("branch_destination_link") if branch else None,
                           "vesa_global_valid": branch.get("w3_151_vesa_global_valid") if branch else None,
                           "vesa_global_u8": branch.get("w3_151_vesa_global_u8") if branch else None,
                           "source_start": post.get("w3_151_copy_source_start") if post else None,
                           "destination_start": post.get("w3_151_copy_destination_start") if post else None,
                           "dword_count": post.get("w3_151_copy_dword_count") if post else None,
                           "ds_valid": post.get("w3_151_copy_ds_valid") if post else None,
                           "ds_base": post.get("w3_151_copy_ds_base") if post else None,
                           "ds_limit": post.get("w3_151_copy_ds_limit") if post else None,
                           "es_valid": post.get("w3_151_copy_es_valid") if post else None,
                           "es_base": post.get("w3_151_copy_es_base") if post else None,
                           "es_limit": post.get("w3_151_copy_es_limit") if post else None,
                           "source_bounds_valid": post.get("w3_151_copy_source_bounds_valid") if post else None,
                           "destination_bounds_valid": post.get("w3_151_copy_destination_bounds_valid") if post else None,
                           "sample_valid": post.get("w3_151_copy_sample_valid") if post else False,
                           "sample_bytes": post.get("w3_151_copy_sample_bytes") if post else 0,
                           "sample_hex": post.get("w3_151_copy_sample_hex") if post else "",
                           "sample_max_bytes": 16},
        "screen_geometry": {key: post.get(key) if post else None for key in (
            "w3_153_globals_valid", "w3_153_screen_width", "w3_153_screen_height",
            "w3_153_wscreen", "w3_153_display", "w3_153_vesa_setup",
            "w3_153_geometry_matches_eax", "w3_153_globals_match_copy")},
        "sparse_samples": {"windows": post.get("w3_153_sample_windows", []) if post else [],
                            "bytes_total": post.get("w3_153_sample_bytes_total", 0) if post else 0,
                            "max_bytes": 48},
    }
    result["copy_confirmed"] = bool(post and post.get("w3_151_copy_inputs_valid") and same_rebase)
    result["framebuffer_or_visible_output_proven"] = False
    RESULT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"result": str(RESULT), "branch": result["observed_copy"]["branch_taken"],
                      "copy_confirmed": result["copy_confirmed"],
                      "sample_valid": result["observed_copy"]["sample_valid"],
                      "sparse_sample_bytes": result["sparse_samples"]["bytes_total"],
                      "guard_cause": guard.get("cause")}, indent=2))
    return 0 if guard.get("sandbox_verified") and guard.get("ok") else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"PREFLIGHT/REPLAY FAILED CLOSED: {exc}", file=sys.stderr)
        raise SystemExit(2)
