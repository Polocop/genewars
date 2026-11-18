"""Preserve and refresh the current post-MSCDEX gate evidence pointer."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CURRENT = ROOT / "evidence/startup_ah48_current_work3.json"
ARCHIVE = ROOT / "evidence/startup_ah48_current_work3_w3_047_preserved.json"
W3244 = ROOT / "evidence/w3_244_current_runtime_no_cd_replay.json"
REFRESH = ROOT / "evidence/w3_245_current_gate_refresh.json"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def build_current_record() -> tuple[dict, dict]:
    old = json.loads(CURRENT.read_text(encoding="utf-8-sig"))
    source = json.loads(W3244.read_text(encoding="utf-8-sig"))
    capture = source["current_capture"]
    runtime_files = [
        {"path": item["path"], "sha256": item["current_sha256"]}
        for item in source["runtime_comparison"]["files"]
    ]
    record = {
        "task": "W3-244",
        "oracle": "Original GeneWars target bytes under repository Unicorn DOS/DPMI host; current-runtime empty-config no-CD -k control",
        "target_sha256": capture["target_sha256"],
        "command_tail": "-k",
        "fixture": capture["empty_config"],
        "fixture_matches_gate": True,
        "runtime_sha256": source["runtime_comparison"]["current_runtime_bundle_sha256"],
        "runtime_files": runtime_files,
        "source_capture": "evidence/w3_244_current_runtime_no_cd_replay.json",
        "source_capture_sha256": hashlib.sha256(W3244.read_bytes()).hexdigest(),
        "raw_capture": capture["raw_path"],
        "raw_capture_sha256": capture["raw_sha256"],
        "instruction_limit": capture["instruction_limit"],
        "stop_reason": capture["stop_reason"],
        "executed_instruction_count": capture["executed_instruction_count"],
        "last_guest_eip": capture["last_guest_eip"],
        "first_unsupported": None,
        "process_exit": capture["process_exit"],
        "int2f_services": capture["int2f_services"],
        "ah48_event_count": source["current_gate_projection"]["ah48_event_count"],
        "cdrom_inventory": [],
        "menu_reached": False,
        "menu_claimed": False,
        "read_only_reference_unchanged": True,
        "source_previous_current_pointer_sha256": sha(CURRENT.read_bytes()),
    }
    return record, old


def refresh() -> dict:
    if ARCHIVE.exists():
        raise FileExistsError(f"preservation archive already exists: {ARCHIVE}")
    before = CURRENT.read_bytes()
    before_sha = sha(before)
    atomic_write(ARCHIVE, before)
    if sha(ARCHIVE.read_bytes()) != before_sha:
        raise OSError("preserved current-pointer archive failed SHA verification")

    record, _ = build_current_record()
    current_bytes = (json.dumps(record, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    atomic_write(CURRENT, current_bytes)
    after_sha = sha(CURRENT.read_bytes())
    refresh_record = {
        "schema": "gwrecomp-w3-245-current-gate-refresh/v1",
        "task": "W3-245",
        "previous_current_sha256": before_sha,
        "preserved_archive": str(ARCHIVE.relative_to(ROOT)).replace("\\", "/"),
        "preserved_archive_sha256": sha(ARCHIVE.read_bytes()),
        "new_current_sha256": after_sha,
        "source_capture_sha256": record["source_capture_sha256"],
        "runtime_sha256": record["runtime_sha256"],
        "menu_reached": False,
    }
    atomic_write(REFRESH, (json.dumps(refresh_record, indent=2) + "\n").encode("utf-8"))
    return refresh_record
