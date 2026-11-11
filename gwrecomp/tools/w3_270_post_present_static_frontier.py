from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path
from typing import Any

import capstone

ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT / "build/dosboxx_oracle/C/GENEWARS/GW.EXE"
MAP = ROOT / "evidence/genewars-1_1.map"
TRACE = ROOT / "build/dosboxx_oracle/C/W3_269_POST_PRESENT_20261009_01.jsonl"
PRIOR = ROOT / "evidence/w3_269_post_present_checkpoint.json"
OUTPUT = ROOT / "evidence/w3_270_post_present_static_frontier.json"
REPORT = ROOT / "reports/coordination/w3_270_post_present_static_frontier.md"
TARGET_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
TRACE_SHA256 = "2c02e497d26971c1b04a0781154b221c340ca893eb2f1ada58196af86f07ad09"
LINK_VA = 0xC427E
MAX_TRACE_BYTES = 1024 * 1024
MAX_TRACE_ROWS = 2048


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def map_le_link_va(data: bytes, va: int) -> dict[str, int]:
    """Translate an LE link VA through its object and 3-byte page map."""
    if len(data) < 0x40:
        raise ValueError("image is too short for MZ header")
    le = struct.unpack_from("<I", data, 0x3C)[0]
    if le + 0x84 > len(data) or data[le:le + 2] != b"LE":
        raise ValueError("missing or truncated LE header")
    rd = lambda off, fmt: struct.unpack_from("<" + fmt, data, le + off)[0]
    page_size = rd(0x28, "I")
    object_table = rd(0x40, "I")
    object_count = rd(0x44, "I")
    page_map = rd(0x48, "I")
    data_pages = rd(0x80, "I")
    if page_size <= 0 or object_count <= 0:
        raise ValueError("invalid LE page size or object count")
    for index in range(object_count):
        size, base, flags, map_index, page_count, _ = struct.unpack_from(
            "<IIIIII", data, le + object_table + index * 24
        )
        if not base <= va < base + size:
            continue
        object_offset = va - base
        page_index, page_offset = divmod(object_offset, page_size)
        if page_index >= page_count:
            raise ValueError("VA falls outside mapped pages")
        entry_index = map_index - 1 + page_index
        entry_at = le + page_map + entry_index * 4
        if entry_at + 4 > len(data):
            raise ValueError("LE page-map entry is out of file bounds")
        page_number = int.from_bytes(data[entry_at:entry_at + 3], "big")
        page_flags = data[entry_at + 3]
        if page_number == 0:
            raise ValueError("LE page is not backed by file data")
        file_offset = data_pages + (page_number - 1) * page_size + page_offset
        if file_offset >= len(data):
            raise ValueError("mapped page extends beyond file")
        return {
            "object": index + 1, "object_base": base, "object_size": size,
            "object_flags": flags, "object_offset": object_offset,
            "page_size": page_size, "page_index_zero_based": page_index,
            "page_map_entry_zero_based": entry_index,
            "page_number_one_based": page_number, "page_flags": page_flags,
            "page_offset": page_offset, "data_pages_file_offset": data_pages,
            "file_offset": file_offset,
        }
    raise ValueError(f"link VA 0x{va:08X} is outside all LE objects")


def disassemble_local_block(data: bytes) -> list[dict[str, str]]:
    start, target, end = 0xC4270, 0xC427E, 0xC4295
    mapping = map_le_link_va(data, start)
    raw = data[mapping["file_offset"]:mapping["file_offset"] + end - start]
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    rows = [{
        "link_va": f"0x{ins.address:08X}", "bytes": ins.bytes.hex(),
        "mnemonic": ins.mnemonic, "operands": ins.op_str,
    } for ins in decoder.disasm(raw, start)]
    if not any(row["link_va"] == f"0x{target:08X}" for row in rows):
        raise ValueError("bounded decode did not contain measured link VA")
    branch = next((row for row in rows if row["link_va"] == "0x000C4293"), None)
    if not branch or branch["mnemonic"] != "jne" or "0xc4272" not in branch["operands"].lower():
        raise ValueError("bounded decode did not verify the backward branch")
    return rows


def read_symbols(path: Path, target: int) -> dict[str, Any]:
    symbols = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0].startswith("0001:"):
            try:
                symbols.append((int(fields[0].split(":", 1)[1], 16), fields[1]))
            except ValueError:
                pass
    below = [item for item in symbols if item[0] <= target]
    above = [item for item in symbols if item[0] > target]
    return {
        "map_sha256": sha256(path.read_bytes()),
        "nearest_lower_public": {"link_va": f"0x{below[-1][0]:08X}", "name": below[-1][1]} if below else None,
        "nearest_upper_public": {"link_va": f"0x{above[0][0]:08X}", "name": above[0][1]} if above else None,
        "function_boundary_proven": False,
    }


def build_evidence() -> dict[str, Any]:
    exe = EXE.read_bytes()
    if sha256(exe) != TARGET_SHA256:
        raise ValueError("guest executable hash mismatch")
    raw = TRACE.read_bytes()
    if len(raw) > MAX_TRACE_BYTES or len(raw.splitlines()) > MAX_TRACE_ROWS:
        raise ValueError("trace exceeds the W3-270 bounded limits")
    if sha256(raw) != TRACE_SHA256:
        raise ValueError("original trace hash mismatch")
    rows = [json.loads(line) for line in raw.splitlines()]
    if not all(isinstance(row, dict) for row in rows):
        raise ValueError("trace contains a non-object row")
    prior = json.loads(PRIOR.read_text(encoding="utf-8"))
    if prior.get("trace", {}).get("sha256") != TRACE_SHA256:
        raise ValueError("W3-269 evidence does not bind retained trace")
    if prior.get("provenance", {}).get("target_sha256") != TARGET_SHA256:
        raise ValueError("W3-269 evidence does not bind exact target")

    marker_i = next(i for i, row in enumerate(rows) if row.get("event") == "w3_269_post_present_marker_set")
    present_i = next(i for i, row in enumerate(rows) if row.get("event") == "backend_present_return")
    checkpoint_i = next(i for i, row in enumerate(rows) if row.get("event") == "w3_269_first_guest_checkpoint_after_present")
    checkpoint = rows[checkpoint_i]
    if checkpoint.get("link_va") != LINK_VA:
        raise ValueError("captured link VA differs from static target")
    if checkpoint["runtime_linear"] - checkpoint["code_rebase"] != LINK_VA:
        raise ValueError("captured runtime mapping does not resolve to the target")

    tail = []
    interesting = {
        "W3_167_CACHE_SPAN_HIT", "W3_193_ECD40_STEP_RESULT",
        "W3_198_ECD40_CONTINUATION_STEP", "W3_198_ECD40_CONTINUATION_STOP",
    }
    for i, row in enumerate(rows):
        if i <= checkpoint_i or row.get("event") not in interesting:
            continue
        item = {"trace_row_index": i, "event": row["event"]}
        for key in ("sequence", "target_link_va", "current_link_va",
                    "target_after_current", "target_seen", "before_link_va",
                    "after_link_va", "ordinal", "steps", "reason",
                    "normal_core_return"):
            if key in row:
                value = row[key]
                if key.endswith("_link_va") and isinstance(value, int):
                    value = f"0x{value:08X}"
                item[key] = value
        tail.append(item)
    map_info = map_le_link_va(exe, LINK_VA)
    decoder_rows = disassemble_local_block(exe)
    transition_targets = ["0x00092996", "0x000929A9", "0x000929C8", "0x00094347", "0x00092710"]
    return {
        "schema": "w3-270-post-present-static-frontier/v1",
        "task": "W3-270",
        "evidence_level": "ORIGINAL_OBSERVED_AND_STATIC_ONLY",
        "original_observed": {
            "source_evidence": "evidence/w3_269_post_present_checkpoint.json",
            "run_id": prior["run_id"], "target_sha256": TARGET_SHA256,
            "trace_path": str(TRACE.relative_to(ROOT)), "trace_sha256": TRACE_SHA256,
            "trace_bytes": len(raw), "trace_rows": len(rows),
            "marker_row": marker_i, "present_return_row": present_i,
            "next_guest_checkpoint_row": checkpoint_i,
            "marker_present_checkpoint_order_valid": marker_i < present_i < checkpoint_i,
            "fresh_main_mapping": prior["analysis"]["fresh_main_mapping"],
            "next_guest_checkpoint": {
                "runtime_linear": f"0x{checkpoint['runtime_linear']:08X}",
                "code_rebase": f"0x{checkpoint['code_rebase']:08X}",
                "link_va": f"0x{checkpoint['link_va']:08X}",
                "cs": f"0x{checkpoint['cs']:04X}",
                "eflags": f"0x{checkpoint['eflags']:08X}",
                "marker_consumption_ordinal": checkpoint["marker_consumption_ordinal"],
            },
            "same_run_post_checkpoint_media_events": tail,
            "game_transition_targets_checked": transition_targets,
            "game_transition_target_rows": sum(
                row.get("event") == "w3_269_game_transition_checkpoint" for row in rows
            ),
            "guard_cause": prior["guard"]["cause"],
            "guard_timeout_seconds": prior["preflight"]["timeout_seconds"],
            "menu_verified": False, "gameplay_verified": False,
        },
        "static_only": {
            "target_sha256": sha256(exe), "link_va": f"0x{LINK_VA:08X}",
            "le_mapping": map_info,
            "file_bytes_at_link_va": exe[map_info["file_offset"]:map_info["file_offset"] + 32].hex(),
            "disassembly_from_0xC4270": decoder_rows,
            "public_symbol_context": read_symbols(MAP, LINK_VA),
            "interpretation": (
                "IN AL,0x40 at 0xC427E is followed by the bounded local read/compare "
                "loop; JNE at 0xC4293 targets 0xC4272. This is static control flow only."
            ),
            "limitations": [
                "The nearest MAP public symbols do not prove containing function extent or caller.",
                "Static bytes do not prove why execution remained before the game-transition checkpoints.",
            ],
        },
        "conclusion": {
            "first_game_transition_after_present": "UNKNOWN",
            "next_action": (
                "A future capture needs a distinct hypothesis centered on the post-media "
                "return/transition; do not repeat the same 45-second replay."
            ),
            "menu_verified": False, "gameplay_verified": False,
        },
    }


def main() -> None:
    evidence = build_evidence()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    original, static = evidence["original_observed"], evidence["static_only"]
    lines = [
        "# W3-270 — static resolution of the post-present frontier",
        "",
        "Status: DONE for this bounded static frontier task. No menu or gameplay claim is made.",
        "",
        "## Original-observed",
        "",
        f"- Run {original['run_id']} used exact target SHA-256 {original['target_sha256']}.",
        f"- Trace: {original['trace_path']}, {original['trace_rows']} rows / {original['trace_bytes']} bytes, SHA-256 {original['trace_sha256']}.",
        f"- Marker, backend present return, and next guest checkpoint occurred in rows {original['marker_row']}, {original['present_return_row']}, and {original['next_guest_checkpoint_row']}.",
        f"- Fresh mapping computes {original['next_guest_checkpoint']['runtime_linear']} - {original['next_guest_checkpoint']['code_rebase']} = {original['next_guest_checkpoint']['link_va']}; CS {original['next_guest_checkpoint']['cs']}, EFLAGS {original['next_guest_checkpoint']['eflags']}.",
        "- Later same-run bounded normal-core instrumentation reaches link VA 0x000ECD40. These events follow the immediate post-present checkpoint and are kept separate.",
        "- No bounded PlayIntro/game-entry target fired before the explicit oracle_guard timeout. Menu and gameplay remain unverified.",
        "",
        "## Static-only",
        "",
        f"- Hash-verified GW.EXE link VA 0x{LINK_VA:08X} maps to LE object {static['le_mapping']['object']}, page {static['le_mapping']['page_number_one_based']}, file offset 0x{static['le_mapping']['file_offset']:X}.",
        f"- Raw bytes: {static['file_bytes_at_link_va']}.",
        "- Bounded decode: IN AL,0x40 at 0xC427E; JNE 0xC4272 at 0xC4293.",
        "- Adjacent MAP publics are naming context only; containing function boundary and caller are UNKNOWN.",
        "",
        "## Next action",
        "",
        "A later capture should test a distinct post-media return/transition hypothesis. Do not repeat the same 45-second replay.",
        "",
        "## Validation",
        "",
        "The registered synthetic suite validates LE page-map translation and fail-closed cases. It does not execute DOSBox or alter the original executable.",
        "",
    ]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({
        "evidence": str(OUTPUT.relative_to(ROOT)),
        "report": str(REPORT.relative_to(ROOT)),
        "link_va": f"0x{LINK_VA:08X}",
        "file_offset": f"0x{static['le_mapping']['file_offset']:X}",
        "post_checkpoint_events": len(original["same_run_post_checkpoint_media_events"]),
    }, indent=2))


if __name__ == "__main__":
    main()
