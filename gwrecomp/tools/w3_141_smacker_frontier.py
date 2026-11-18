"""Bounded reconciliation of original Smacker dispatch and screen route."""
from __future__ import annotations

import json
import re
from pathlib import Path
import sys
from typing import Any

TARGET_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
CODE_REBASE = 0x001EB000
DATA_REBASE = 0x001DA000
MAX_TRACE_BYTES = 1_048_576


def _function_block(disassembly: str, symbol: str) -> str:
    lines = disassembly.splitlines()
    start = next((i for i, line in enumerate(lines)
                  if re.match(rf"^{re.escape(symbol)}:\s*/\*", line)), None)
    if start is None:
        raise ValueError(f"missing exact-target function label: {symbol}")
    end = next((i for i in range(start + 1, len(lines))
                if re.match(r"^[A-Za-z_.$][\w.$@]*:\s*/\*\s*0x[0-9a-fA-F]+\s*\*/", lines[i])), len(lines))
    return "\n".join(lines[start:end])


def parse_jsonl(raw: bytes) -> list[dict[str, Any]]:
    if len(raw) > MAX_TRACE_BYTES:
        raise ValueError("trace exceeds 1 MiB cap")
    rows = []
    for index, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        row = json.loads(line)
        if not isinstance(row, dict):
            raise ValueError(f"non-object JSONL event at line {index}")
        rows.append(row)
    return rows


def audit(disassembly: str, rows: list[dict[str, Any]], w3_139: dict[str, Any],
          w3_140: dict[str, Any]) -> dict[str, Any]:
    if w3_139.get("target_sha256") != TARGET_SHA256 or w3_140.get("source", {}).get("target_sha256") != TARGET_SHA256:
        raise ValueError("target executable identity mismatch")
    entry = next((r for r in rows if r.get("checkpoint") == "W3_133_PLAY_SMK_ENTRY"), None)
    direct = next((r for r in rows if r.get("checkpoint") == "W3_133_PLAY_SMK_DIRECT_ENTRY"), None)
    buffered = next((r for r in rows if r.get("checkpoint") == "W3_133_PLAY_SMK_BUFFER_ENTRY"), None)
    copy = next((r for r in rows if r.get("checkpoint") == "W3_133_COPY_TO_SCREEN_ENTRY"), None)
    if not entry or not direct:
        raise ValueError("same-run original entry and direct-route checkpoints are required")
    code_rebase = entry["eip"] - entry["link_va"]
    if code_rebase != CODE_REBASE or direct["eip"] - direct["link_va"] != code_rebase:
        raise ValueError("runtime code mapping not verified for the observed route")
    if entry.get("data_rebase") != DATA_REBASE or not entry.get("w3_133_draw_callback_valid"):
        raise ValueError("relocated draw-callback global lacks a valid data mapping/sample")
    callback = entry.get("w3_133_draw_callback_value")
    ebx = entry.get("ebx")
    if not isinstance(callback, int) or not isinstance(ebx, int):
        raise ValueError("dispatch inputs were not captured")
    if direct.get("link_va") != 0xAE308:
        raise ValueError("direct successor is not exact target play_smk_direct")
    play_smk = _function_block(disassembly, "play_smk_")
    direct_fn = _function_block(disassembly, "play_smk_direct")
    buffered_fn = _function_block(disassembly, "play_smk_via_buffer")
    normalized_play = re.sub(r"\s+", " ", play_smk)
    normalized_direct = re.sub(r"\s+", " ", direct_fn)
    normalized_buffered = re.sub(r"\s+", " ", buffered_fn)
    if "mov _smack_draw_callback,%ecx" not in normalized_play or "test $0x84,%bl" not in normalized_play:
        raise ValueError("exact-target dispatch predicates not found")
    if "call play_smk_via_buffer" not in normalized_play or "call play_smk_direct" not in normalized_play:
        raise ValueError("exact-target dispatch destinations not found")
    if "call copy_to_screen" not in normalized_buffered or "call SMACKTOBUFFER" not in normalized_direct:
        raise ValueError("route-specific transfer functions not found")
    direct_selected = callback == 0 and (ebx & 0x84) == 0 and "call play_smk_direct" in normalized_play
    if not direct_selected:
        raise ValueError("captured registers do not satisfy direct-route predicate")
    screen_swap_static = "call LbScreenSwap_" in normalized_direct
    return {
        "target_sha256": TARGET_SHA256,
        "runtime_mapping": {"code_rebase": f"0x{code_rebase:08X}",
                            "data_rebase": f"0x{DATA_REBASE:08X}",
                            "main_entry_link_va": f"0x{entry['link_va']:08X}",
                            "main_entry_runtime_eip": f"0x{entry['eip']:08X}"},
        "same_run_original": {
            "play_smk_entry": entry,
            "direct_successor": direct,
            "buffered_entry_observed": bool(buffered),
            "copy_to_screen_entry_observed": bool(copy),
            "data_global_offset": f"0x{entry['w3_133_draw_callback_offset']:08X}",
            "draw_callback_value": f"0x{callback:08X}",
            "ebx": f"0x{ebx:08X}",
            "dispatch_result": "DIRECT_PLAY_SMK_DIRECT",
        },
        "static_route": {
            "play_smk_link_va": "0x000AE2D0",
            "buffered_target": "0x000AE4D8",
            "buffered_copy_to_screen": True,
            "direct_target": "0x000AE308",
            "direct_smack_to_buffer_link_va": "0x000C5140",
            "direct_smack_do_frame_link_va": "0x000C5BD0",
            "direct_lb_screen_swap_call_present": screen_swap_static,
            "direct_route_contains_copy_to_screen": "call copy_to_screen" in normalized_direct,
        },
        "interpretation": {
            "why_ae668_absent": "The original selected play_smk_direct; 0xAE668 is called by play_smk_via_buffer, a different route.",
            "dynamic_vs_static": "Entry registers and the following direct-entry checkpoint are same-run original observations. Route predicates and callee graph are exact-target static evidence.",
            "framebuffer_claim": False,
            "next_capture_hypothesis": "Target the direct route's SMACKTOBUFFER (0xC5140) entry/return and LbScreenSwap_ call at 0x9FFE0 with a fresh measured mapping; do not rely on the buffered 0xAE668 hook.",
        },
        "other_run_comparator": {
            "w3_139_copy_to_screen_entry_observed": w3_139.get("trace", {}).get("copy_to_screen_entry_observed"),
            "same_invocation_claimed": False,
        },
    }


def load_and_audit(root: Path) -> dict[str, Any]:
    disassembly = (root / "evidence/genewars-1_1-le_disasm.s").read_text(encoding="utf-8")
    w3_139 = json.loads((root / "evidence/w3_139_smacker_return_draw.json").read_text(encoding="utf-8"))
    w3_140 = json.loads((root / "evidence/w3_140_original_setenvp_environment.json").read_text(encoding="utf-8"))
    raw = (root / "build/dosboxx_oracle/C/W3_140_SETENVP_ENV_20261009_01.jsonl").read_bytes()
    rows = parse_jsonl(raw)
    result = audit(disassembly, rows, w3_139, w3_140)
    result["trace"] = {"path": "build/dosboxx_oracle/C/W3_140_SETENVP_ENV_20261009_01.jsonl",
                       "bytes": len(raw), "event_count": len(rows),
                       "target_checkpoint_count": sum(r.get("event") == "target_runtime_checkpoint" for r in rows)}
    return result


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    result_path = root / "evidence/w3_141_smacker_frontier_audit.json"
    if result_path.exists():
        raise FileExistsError(f"refusing to overwrite {result_path}")
    result = load_and_audit(root)
    result_path.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"result": str(result_path),
                      "dispatch": result["same_run_original"]["dispatch_result"],
                      "callback": result["same_run_original"]["draw_callback_value"],
                      "ebx": result["same_run_original"]["ebx"],
                      "framebuffer_claim": result["interpretation"]["framebuffer_claim"]}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"AUDIT FAILED: {exc}", file=sys.stderr)
        raise SystemExit(2)
