"""Bounded parser for exact-target generated callsite comments."""

from __future__ import annotations

import re
import hashlib
import json
from pathlib import Path


CALL_RE = re.compile(r"/\*\s*(0x[0-9a-fA-F]+):\s*call\s+0xa3a5c\s*\*/")
FUNCTION_RE = re.compile(
    r"^(?:static\s+)?(?:[\w* ]+)\s+(sub_[0-9A-Fa-f]+|[A-Za-z_][\w]*)\s*\([^;]*\)\s*\{$"
)


def parse_page_calls(text: str) -> list[dict[str, str | int]]:
    """Return ordered callsite, caller, and source-line records for target 0xA3A5C."""
    caller = "(file scope)"
    records: list[dict[str, str | int]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        function = FUNCTION_RE.match(line)
        if function:
            caller = function.group(1)
        call = CALL_RE.search(line)
        if call:
            records.append(
                {
                    "callsite_link_va": f"0x{int(call.group(1), 16):08X}",
                    "caller": caller,
                    "source_line": line_number,
                }
            )
    return records


def parse_disassembly_call_count(text: str) -> int:
    """Count textual direct calls in the immutable disassembly as a cross-check."""
    return sum(
        1
        for line in text.splitlines()
        if re.search(r"\bcall\s+LbVesaSetPage_\b", line)
    )


def validate_records(records: list[dict[str, str | int]], expected_count: int) -> None:
    if len(records) != expected_count:
        raise ValueError(f"expected {expected_count} direct calls, got {len(records)}")
    callsites = [str(record["callsite_link_va"]) for record in records]
    if len(callsites) != len(set(callsites)):
        raise ValueError("duplicate direct-call address")
    if any(record["caller"] == "(file scope)" for record in records):
        raise ValueError("callsite without an owning function")


def load_records(generated_c: Path, disassembly: Path) -> list[dict[str, str | int]]:
    records = parse_page_calls(generated_c.read_text(encoding="utf-8", errors="replace"))
    disasm_count = parse_disassembly_call_count(
        disassembly.read_text(encoding="utf-8", errors="replace")
    )
    validate_records(records, disasm_count)
    return records


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_evidence(root: Path) -> dict[str, object]:
    disassembly = root / "evidence/genewars-1_1-le_disasm.s"
    symbol_map = root / "evidence/genewars-1_1.map"
    closure = root / "build/entry_path_closure.c"
    recomp = root / "build/recomp_282.c"
    w3_100 = root / "evidence/w3_100_targeted_vesa_capture.json"
    w3_103 = root / "evidence/w3_103_vesa_page_capture.json"
    disasm_text = disassembly.read_text(encoding="utf-8", errors="replace")
    recomp_text = recomp.read_text(encoding="utf-8", errors="replace")
    closure_text = closure.read_text(encoding="utf-8", errors="replace")
    records = parse_page_calls(recomp_text)
    closure_records = parse_page_calls(closure_text)
    disasm_count = parse_disassembly_call_count(disasm_text)
    validate_records(records, disasm_count)

    def direct_call_records(text: str, target: str) -> list[dict[str, str | int]]:
        target_re = re.compile(rf"/\*\s*(0x[0-9a-fA-F]+):\s*call\s+{re.escape(target)}\s*\*/")
        function_re = re.compile(
            r"^(?:static\s+)?(?:[\w* ]+)\s+(sub_[0-9A-Fa-f]+|[A-Za-z_][\w]*)\s*\([^;]*\)\s*\{$"
        )
        caller = "(file scope)"
        found: list[dict[str, str | int]] = []
        for line_number, line in enumerate(text.splitlines(), start=1):
            function = function_re.match(line)
            if function:
                caller = function.group(1)
            match = target_re.search(line)
            if match:
                found.append({"callsite_link_va": f"0x{int(match.group(1), 16):08X}", "caller": caller, "source_line": line_number})
        return found

    game_to_draw = direct_call_records(closure_text, "0x834c0")
    draw_to_swap = direct_call_records(closure_text, "0x9ffe0")
    mode_capture = json.loads(w3_100.read_text(encoding="utf-8"))
    page_capture = json.loads(w3_103.read_text(encoding="utf-8"))
    grouped: dict[str, list[str]] = {}
    for record in records:
        grouped.setdefault(str(record["caller"]), []).append(str(record["callsite_link_va"]))
    return {
        "schema": "w3-104-vesa-page-callers/v1",
        "task": "W3-104",
        "target_sha256": "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f",
        "inputs": {
            str(path.relative_to(root)).replace("\\", "/"): sha256(path)
            for path in (disassembly, symbol_map, closure, recomp, w3_100, w3_103)
        },
        "inventory": {
            "disassembly_text_call_count": disasm_count,
            "generated_closure_call_count": len(closure_records),
            "all_generated_call_count": len(records),
            "unique_callsite_count": len({str(r["callsite_link_va"]) for r in records}),
            "callers": grouped,
            "call_sites": records,
        },
        "static_path_candidate": {
            "game_entry_link_va": "0x00092710",
            "game_symbol": "W?game$n()v",
            "game_to_draw_game": game_to_draw,
            "draw_game_entry_link_va": "0x000834C0",
            "draw_game_symbol": "W?draw_game$n()v",
            "draw_game_to_screen_swap": draw_to_swap,
            "screen_swap_entry_link_va": "0x0009FFE0",
            "screen_swap_to_page_callsite_link_va": "0x000A0049",
            "page_function_entry_link_va": "0x000A3A5C",
            "interpretation": "Static call-path candidate only: game calls draw_game at 0x928A0; draw_game can call LbScreenSwap_ at 0x83985 or 0x839A2; LbScreenSwap_ calls LbVesaSetPage_ at 0xA0049. The W3-100/W3-103 original captures do not dynamically prove this chain."
        },
        "capture_reconciliation": {
            "w3_100_last_target_checkpoint": "0x9FDF9",
            "w3_100_mode_callsite": mode_capture["trace"]["target_events"][0]["link_va"],
            "w3_103_page_entry_observed": page_capture["capture"]["page_mapping_observed"],
            "w3_103_int10_checkpoints": page_capture["capture"]["int10_checkpoints"],
            "w3_103_guard_cause": page_capture["guard"]["cause"],
            "meaning": "No A3A5C event was observed in the one bounded replay after a natural 0x101/0x180 mode call. This is bounded non-observation, not proof that the function is unreachable or never called."
        },
        "next_checkpoint": {
            "candidate": "game entry 0x92710, callsite 0x928A0 to draw_game 0x834C0, then first taken draw_game call to LbScreenSwap_ at 0x83985/0x839A2, then page callsite 0xA0049",
            "basis": "Exact-target static callsites in the checked-in entry closure and symbol map.",
            "dynamic_status": "unobserved"
        },
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = build_evidence(args.root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
