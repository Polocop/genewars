"""Bounded parser for the first original __setenvp_ environment checkpoint."""
from __future__ import annotations

import json
from typing import Any

MAX_TRACE_BYTES = 1_048_576
MAX_ENV_BYTES = 4_096
TARGETS = {
    "W3_140_SETENVP_DFE04": 0xDFE04,
    "W3_140_SETENVP_DFE08": 0xDFE08,
    "W3_140_SETENVP_DFE0D": 0xDFE0D,
    "W3_140_SETENVP_DFE12": 0xDFE12,
}


def parse_jsonl(raw: bytes) -> list[dict[str, Any]]:
    if len(raw) > MAX_TRACE_BYTES:
        raise ValueError("trace byte cap exceeded")
    rows = []
    for line in raw.splitlines():
        if line.strip():
            value = json.loads(line)
            if isinstance(value, dict):
                rows.append(value)
    return rows


def decode_environment_event(event: dict[str, Any]) -> dict[str, Any]:
    if not event.get("w3_140_env_descriptor_valid"):
        return {"valid": False, "reason": "ES descriptor invalid", "sample_bytes": 0}
    hex_sample = event.get("w3_140_env_sample_hex", "")
    if not isinstance(hex_sample, str) or len(hex_sample) % 2:
        raise ValueError("environment sample is not even-length hex")
    raw = bytes.fromhex(hex_sample)
    if len(raw) > MAX_ENV_BYTES or event.get("w3_140_env_sample_bytes") != len(raw):
        raise ValueError("environment sample exceeds or disagrees with the 4 KiB cap")
    terminator = raw.find(b"\0\0")
    if terminator < 0:
        return {"valid": True, "double_nul_found": False, "sample_bytes": len(raw),
                "sample_hex": raw.hex(), "dos_count": None, "executable_path": None}
    trailer = terminator + 2
    if trailer + 2 > len(raw):
        raise ValueError("truncated DOS environment trailer")
    dos_count = int.from_bytes(raw[trailer:trailer + 2], "little")
    path_start = trailer + 2
    path_end = raw.find(b"\0", path_start)
    if path_end < 0:
        raise ValueError("truncated executable path in DOS environment trailer")
    strings = raw[:terminator].split(b"\0") if terminator else []
    return {
        "valid": True,
        "double_nul_found": True,
        "terminator_offset": terminator,
        "sample_bytes": len(raw),
        "sample_hex": raw.hex(),
        "environment_strings": [item.decode("cp437", errors="replace") for item in strings if item],
        "dos_count": dos_count,
        "executable_path": raw[path_start:path_end].decode("cp437", errors="replace"),
        "trailer_path_terminated": bool(event.get("w3_140_env_trailer_path_complete")),
    }


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    targets = []
    seen = set()
    for row in rows:
        checkpoint = row.get("checkpoint")
        if row.get("event") != "target_runtime_checkpoint" or checkpoint not in TARGETS:
            continue
        if row.get("link_va") != TARGETS[checkpoint]:
            continue
        identity = (checkpoint, row.get("process_psp"), row.get("cs"), row.get("link_va"))
        if identity in seen:
            continue
        seen.add(identity)
        targets.append(row)
        if len(targets) == 4:
            break
    by_name = {row["checkpoint"]: row for row in targets}
    dfe04 = by_name.get("W3_140_SETENVP_DFE04")
    environment = decode_environment_event(dfe04) if dfe04 else {
        "valid": False, "reason": "DFE04 not observed", "sample_bytes": 0
    }
    rebases = sorted({row["eip"] - row["link_va"] for row in targets
                      if isinstance(row.get("eip"), int) and isinstance(row.get("link_va"), int)})
    return {
        "classification": (
            "ORIGINAL_SETENVP_ENVIRONMENT_CAPTURED"
            if dfe04 and environment.get("valid") and environment.get("double_nul_found")
            and environment.get("trailer_path_terminated") else
            "ORIGINAL_SETENVP_ENVIRONMENT_PARTIAL" if dfe04 else
            "ORIGINAL_SETENVP_DFE04_NOT_CAPTURED"),
        "target_event_count": len(targets),
        "runtime_rebases": [f"0x{x:08X}" for x in rebases],
        "dfe04": dfe04,
        "dfe08": by_name.get("W3_140_SETENVP_DFE08"),
        "dfe0d": by_name.get("W3_140_SETENVP_DFE0D"),
        "dfe12": by_name.get("W3_140_SETENVP_DFE12"),
        "environment": environment,
        "same_run_dfe0d_dfe12": bool(
            by_name.get("W3_140_SETENVP_DFE0D") and by_name.get("W3_140_SETENVP_DFE12") and
            by_name["W3_140_SETENVP_DFE0D"].get("process_psp") ==
            by_name["W3_140_SETENVP_DFE12"].get("process_psp") and
            by_name["W3_140_SETENVP_DFE0D"].get("cs") ==
            by_name["W3_140_SETENVP_DFE12"].get("cs")),
    }
