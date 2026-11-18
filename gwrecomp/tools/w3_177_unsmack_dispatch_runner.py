#!/usr/bin/env python3
"""One guarded replay for the first _Unsmack indirect dispatch and re-entry."""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

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
RUN_ID = "w3-177-unsmack-dispatch-20261009-01"
TRACE = MOUNT / "W3_177_UNSMACK_DISPATCH_20261009_01.jsonl"
RESULT = ROOT / "evidence/w3_177_unsmack_dispatch.json"
REVISION = "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f"
GW_SIZE = 1_251_658
GW_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
CONFIG_SHA256 = "b2bac63096aa97a808abb8ea09486db79559b12a25a1410ea930be0e5eeffff1"
CUE_SHA256 = "1d417e3aed625d4f054b51054a1211562a19cd4f712b08e7846613517228a5b5"
WINDOWS = (0, 32000, 63984)


def allowed_callback_links() -> set[int]:
    asm = DISASM.read_text(encoding="utf-8")
    start = asm.index("_Unsmack:\t/* 0xedb20 */")
    end = asm.index("j_SmackDoPCM:", start)
    body = asm[start:end]
    labels = set(re.findall(r"movl\s+\$([A-Za-z_][\w]*),data_10c95[0-9a-f]+", body))
    definitions = {}
    for match in re.finditer(r"(?m)^\s*([A-Za-z_][\w]*):\s*(?:/\*\s*0x([0-9a-fA-F]+)\s*\*/)?", asm):
        name, comment = match.group(1), match.group(2)
        value = int(comment, 16) if comment else None
        if value is None:
            for prefix in ("jump_", "func_"):
                if name.startswith(prefix):
                    try:
                        value = int(name[len(prefix):], 16)
                    except ValueError:
                        pass
        if value is not None:
            definitions[name] = value
    missing = labels - definitions.keys()
    if missing:
        raise ValueError(f"callback candidate labels lack address definitions: {sorted(missing)}")
    return {definitions[name] for name in labels}


def _sample_valid(row: dict[str, Any] | None, *, psp: int, data_rebase: int,
                  point: str, link: int) -> tuple[bool, str]:
    if row is None or row.get("w3_177_target_sample_point") != point:
        return False, "sample_checkpoint_missing"
    if int(row.get("link_va", -1)) != link or int(row.get("process_psp", -1)) != psp:
        return False, "address_or_psp_mismatch"
    if int(row.get("data_rebase", -1)) != data_rebase:
        return False, "data_rebase_mismatch"
    if not row.get("ds_descriptor_valid") or not row.get("w3_177_wscreen_pointer_valid"):
        return False, "descriptor_or_pointer_invalid"
    if not row.get("w3_177_sample_bounds_valid") or not row.get("w3_177_sample_valid"):
        return False, "sample_bounds_invalid"
    if int(row.get("w3_177_sample_bytes", -1)) != 48:
        return False, "sample_size_invalid"
    windows = row.get("w3_177_sample_windows")
    if not isinstance(windows, list) or [int(w.get("offset", -1)) for w in windows] != list(WINDOWS):
        return False, "window_offsets_invalid"
    try:
        if any(int(w.get("bytes", -1)) != 16 or len(bytes.fromhex(w.get("hex", ""))) != 16
               for w in windows):
            return False, "window_length_invalid"
    except ValueError:
        return False, "window_hex_invalid"
    return True, "valid"


def classify(rows: list[dict[str, Any]], allowed_links: set[int]) -> dict[str, Any]:
    main = next((r for r in rows if r.get("checkpoint") == "MAIN_ENTRY_CHECKPOINT"), None)
    first = next((r for r in rows if r.get("checkpoint") == "W3_177_UNSMACK_DISPATCH_FIRST"), None)
    handler = next((r for r in rows if r.get("checkpoint") == "W3_177_UNSMACK_HANDLER_ENTRY"), None)
    reentry = next((r for r in rows if r.get("checkpoint") == "W3_177_UNSMACK_DISPATCH_REENTRY"), None)
    if not main:
        return {"classification": "UNKNOWN", "reason": "MAIN anchor missing",
                "first_dispatch": first, "handler_entry": handler, "dispatcher_reentry": reentry}
    code_rebase = int(main["eip"]) - int(main["link_va"])
    psp = int(main["process_psp"])
    data_rebase = int(first.get("data_rebase", 0)) if first else int(main.get("data_rebase", 0))
    if not first:
        return {"classification": "NOT_OBSERVED", "reason": "indirect dispatch checkpoint missing",
                "code_rebase": hex(code_rebase), "data_rebase": hex(data_rebase), "psp": psp,
                "first_dispatch": None, "handler_entry": handler, "dispatcher_reentry": reentry}
    first_ok = (int(first.get("link_va", -1)) == 0xEDE94 and
                int(first.get("eip", -1)) - code_rebase == 0xEDE94 and
                int(first.get("process_psp", -1)) == psp and
                first.get("w3_177_table_valid") is True and
                0 <= int(first.get("w3_177_table_index", -1)) < 4 and
                int(first.get("w3_177_table_address", -1)) ==
                    data_rebase + 0x10C950 + 4 * int(first.get("w3_177_table_index", -1)) and
                first.get("w3_177_selected_target_valid") is True)
    target_link = int(first.get("w3_177_selected_target_link_va", -1))
    target_ok = first_ok and target_link in allowed_links
    handler_ok = (handler is not None and target_ok and
                  int(handler.get("link_va", -1)) == target_link and
                  int(handler.get("eip", -1)) - code_rebase == target_link and
                  int(handler.get("process_psp", -1)) == psp and
                  int(handler.get("sequence", -1)) > int(first.get("sequence", 0)))
    if not handler_ok:
        return {"classification": "DISPATCH_TARGET_UNKNOWN", "reason": "selected target lacks a matching exact-target handler entry",
                "first_dispatch_valid": first_ok, "target_symbol_valid": target_ok,
                "code_rebase": hex(code_rebase), "data_rebase": hex(data_rebase), "psp": psp,
                "selected_target_link_va": hex(target_link) if target_link >= 0 else None,
                "first_dispatch": first, "handler_entry": handler, "dispatcher_reentry": reentry}
    if not reentry:
        return {"classification": "HANDLER_ENTRY_ONLY", "reason": "first subsequent dispatcher re-entry not captured",
                "first_dispatch_valid": True, "target_symbol_valid": True, "handler_entry_valid": True,
                "code_rebase": hex(code_rebase), "data_rebase": hex(data_rebase), "psp": psp,
                "selected_target_link_va": hex(target_link),
                "first_dispatch": first, "handler_entry": handler, "dispatcher_reentry": None}
    reentry_ok = (int(reentry.get("link_va", -1)) == 0xEDE94 and
                  int(reentry.get("eip", -1)) - code_rebase == 0xEDE94 and
                  int(reentry.get("process_psp", -1)) == psp and
                  int(reentry.get("sequence", -1)) > int(handler.get("sequence", 0)))
    first_sample_ok, first_reason = _sample_valid(first, psp=psp, data_rebase=data_rebase,
                                                  point="first_dispatch", link=0xEDE94)
    reentry_sample_ok, reentry_reason = _sample_valid(reentry, psp=psp, data_rebase=data_rebase,
                                                       point="dispatcher_reentry", link=0xEDE94)
    same_pointer = int(first.get("w3_177_wscreen_pointer", -1)) == int(reentry.get("w3_177_wscreen_pointer", -2))
    if not (reentry_ok and first_sample_ok and reentry_sample_ok and same_pointer):
        return {"classification": "UNKNOWN", "reason": "dispatcher re-entry/sample validation failed",
                "reentry_valid": reentry_ok, "first_sample_reason": first_reason,
                "reentry_sample_reason": reentry_reason, "same_pointer": same_pointer,
                "first_dispatch_valid": True, "handler_entry_valid": True,
                "code_rebase": hex(code_rebase), "data_rebase": hex(data_rebase), "psp": psp,
                "selected_target_link_va": hex(target_link),
                "first_dispatch": first, "handler_entry": handler, "dispatcher_reentry": reentry}
    changed = [int(a["offset"]) for a, b in zip(first["w3_177_sample_windows"], reentry["w3_177_sample_windows"])
               if bytes.fromhex(a["hex"]) != bytes.fromhex(b["hex"])]
    return {"classification": "SAMPLED_BYTES_CHANGED" if changed else "SAMPLED_BYTES_STABLE",
            "reason": "valid natural dispatch, selected handler, and subsequent dispatcher re-entry",
            "code_rebase": hex(code_rebase), "data_rebase": hex(data_rebase), "psp": psp,
            "first_dispatch_valid": True, "target_symbol_valid": True, "handler_entry_valid": True,
            "reentry_valid": True, "same_pointer": True,
            "selected_target_link_va": hex(target_link),
            "sequence_order": [first["sequence"], handler["sequence"], reentry["sequence"]],
            "sample_bytes_total": int(first["w3_177_sample_bytes"]) + int(reentry["w3_177_sample_bytes"]),
            "sampled_offsets_changed": changed,
            "first_dispatch": first, "handler_entry": handler, "dispatcher_reentry": reentry}


def _preflight() -> dict[str, Any]:
    sandbox = verify_sandbox()
    if not sandbox.get("verified") or sandbox.get("label") != "GWORACLE":
        raise RuntimeError(f"GWORACLE verification failed: {sandbox}")
    for path in (FIXTURE, CONFIG, CUE, DOSBOX, GUARD, CORE, DISASM):
        if not path.is_file():
            raise FileNotFoundError(path)
    if FIXTURE.stat().st_size != GW_SIZE or sha(FIXTURE) != GW_SHA256:
        raise RuntimeError("authentic W3-067 fixture identity mismatch")
    if sha(CONFIG) != CONFIG_SHA256 or sha(CUE) != CUE_SHA256:
        raise RuntimeError("functional config or original CUE hash mismatch")
    if not re.search(r"(?im)^\s*imgmount\s+d\s+.*\.cue.*-ro\b", CONFIG.read_text(encoding="utf-8")):
        raise RuntimeError("original CUE is not mounted read-only")
    revision = subprocess.run(["git", "-C", str(SOURCE), "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    if revision != REVISION:
        raise RuntimeError(f"pinned Staging revision mismatch: {revision}")
    core = CORE.read_text(encoding="utf-8", errors="replace")
    for token in ("W3_177_UNSMACK_DISPATCH_FIRST", "W3_177_UNSMACK_HANDLER_ENTRY",
                  "W3_177_UNSMACK_DISPATCH_REENTRY", "w3_177_total_sample_bytes + 48 <= 96",
                  "0x0010c950"):
        if token not in core:
            raise RuntimeError(f"W3-177 instrumentation missing {token}")
    if TRACE.exists() or RESULT.exists():
        raise FileExistsError("refusing to overwrite W3-177 artifacts")
    return sandbox


def main() -> int:
    if Path(sys.executable).name.lower() != "python.exe":
        raise RuntimeError(f"explicit console Python required, got {sys.executable}")
    sandbox = _preflight()
    evidence_dir = ROOT / "evidence/oracle_runs"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    stdout = evidence_dir / f"{RUN_ID}.stdout.json"
    stderr = evidence_dir / f"{RUN_ID}.stderr.txt"
    if stdout.exists() or stderr.exists():
        raise FileExistsError("refusing to overwrite W3-177 guard output")
    binary_sha = sha(DOSBOX)
    env = dict(os.environ)
    for key in tuple(env):
        if key.startswith("GWRECOMP_ANCHOR_") or key.startswith("GWRECOMP_EXEC_TRACE_"):
            env.pop(key, None)
    env.update({
        "GWRECOMP_GW_FILE_SIZE": str(GW_SIZE), "GWRECOMP_GW_LE_HEADER_OFFSET": "0x8f50",
        "GWRECOMP_GW_LE_OBJECT_TABLE_OFFSET": "0x9014", "GWRECOMP_EXEC_TRACE_PATH": str(TRACE),
        "GWRECOMP_EXEC_TRACE_MAX_BYTES": str(MAX_TRACE_BYTES), "GWRECOMP_EXEC_TRACE_FILE_IO": "0",
        "GWRECOMP_ANCHOR_MAIN_ENTRY_LINK": "0x000af96c", "GWRECOMP_ANCHOR_MAIN_ENTRY_BYTES": "eb765741",
        "GWRECOMP_ANCHOR_CRT_ARGV_LOAD_LINK": "0x000c8702", "GWRECOMP_ANCHOR_GAME_MAIN_ENTRY_LINK": "0x00093f30",
        "GWRECOMP_W3_171_ENABLE_SAMPLES": "0",
    })
    command = [sys.executable, str(GUARD), "run", "--exe", str(DOSBOX), "--config", str(CONFIG),
               "--staging-dir", str(MOUNT), "--host-drive", "E:", "--run-id", RUN_ID,
               "--operation", "W3-177 first _Unsmack indirect dispatch", "--commit-sha", REVISION,
               "--target-sha", GW_SHA256, "--runtime-sha", binary_sha, "--fixture-sha", GW_SHA256,
               "--evidence-dir", str(evidence_dir), "--max-file-text-mib", "1", "--max-file-bin-mib", "64",
               "--max-run-gib", "1", "--host-floor-gib", "100", "--timeout-s", "30",
               "--growth-text-mibs", "8", "--growth-bin-mibs", "24", "--poll-hz", "1"]
    with stdout.open("xb") as out, stderr.open("xb") as err:
        subprocess.run(command, cwd=ROOT, env=env, stdout=out, stderr=err, timeout=40, check=False)
    guard = json.loads(stdout.read_text(encoding="utf-8"))
    raw = TRACE.read_bytes() if TRACE.exists() else b""
    if len(raw) > MAX_TRACE_BYTES:
        raise RuntimeError("trace exceeded configured 1 MiB cap")
    rows = parse_jsonl(raw)
    classification = classify(rows, allowed_callback_links())
    result = {
        **classification, "schema": "w3-177-unsmack-dispatch/v1", "task": "W3-177", "run_id": RUN_ID,
        "source": {"target_sha256": GW_SHA256, "fixture_bytes": FIXTURE.stat().st_size,
                   "config_sha256": sha(CONFIG), "cue_sha256": sha(CUE), "staging_revision": REVISION,
                   "instrumented_core_sha256": sha(CORE), "staging_binary_sha256": binary_sha,
                   "disassembly_sha256": sha(DISASM)},
        "preflight": {"sandbox": sandbox, "cue_read_only_mount": True, "timeout_seconds": 30,
                      "trace_cap_bytes": MAX_TRACE_BYTES, "sample_offsets": list(WINDOWS),
                      "sample_window_bytes": 16, "max_new_sample_bytes": 96,
                      "legacy_w3_171_sampling_disabled": True, "global_trace": False,
                      "guest_state_modified": False},
        "guard": {key: guard.get(key) for key in ("run_id", "operation", "sandbox_verified",
                 "sandbox_capacity", "host_free_before", "host_free_after", "limits", "exit_reason",
                 "cause", "detail", "exit_code", "killed_processes", "duration_s", "evidence_path", "ok")},
        "trace": {"path": str(TRACE.relative_to(ROOT)), "bytes": len(raw),
                  "sha256": hashlib.sha256(raw).hexdigest() if raw else None, "event_count": len(rows)},
        "limitations": ["Only three 16-byte WScreen windows were sampled at the first dispatch and first re-entry.",
                        "The dispatch uses JMP; no callback stack return address is inferred.",
                        "Sparse samples do not characterize the full buffer, visible output, menu, or gameplay."]
    }
    RESULT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"result": str(RESULT), "classification": result.get("classification"),
                      "selected_target": result.get("selected_target_link_va"),
                      "sample_bytes_total": result.get("sample_bytes_total"),
                      "guard_cause": guard.get("cause")}, indent=2))
    return 0 if guard.get("sandbox_verified") and guard.get("ok") else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"PREFLIGHT/REPLAY FAILED CLOSED: {exc}", file=sys.stderr)
        raise SystemExit(2)
