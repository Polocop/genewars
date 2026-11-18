"""Hash-bound static and bounded dynamic checks for LbMemoryAlloc_ call."""
from __future__ import annotations

import hashlib as _hashlib


class _OrigDigest:
    """Stands in for a byte string taken from the original game.

    Only its SHA-256 and length are stored in the repository. Comparing it with
    bytes (or a hex string) from the user's own locally provided game files
    succeeds when they hash to the recorded value.
    """

    def __init__(self, sha256, length):
        self.sha256 = sha256
        self.length = length

    def __len__(self):
        return self.length

    def __eq__(self, other):
        if isinstance(other, str):
            try:
                other = bytes.fromhex(other.replace(" ", ""))
            except ValueError:
                return False
        if not isinstance(other, (bytes, bytearray, memoryview)):
            return NotImplemented
        other = bytes(other)
        return len(other) == self.length and _hashlib.sha256(other).hexdigest() == self.sha256

    def __ne__(self, other):
        r = self.__eq__(other)
        return r if r is NotImplemented else not r

    __hash__ = None

    def __repr__(self):
        return "<original bytes sha256=%s len=%d>" % (self.sha256, self.length)
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
MAP = ROOT / "evidence/genewars-1_1.map"
DISASM = ROOT / "evidence/genewars-1_1-le_disasm.s"
PRIOR = ROOT / "evidence/w3_124_post_join_continuation.json"
TRACE_PRIOR = ROOT / "build/dosboxx_oracle/C/W3_124_POST_JOIN_CONTINUATION_20261009_01.jsonl"
ANCHOR, CALLSITE, CALLEE, RETURN = 0x92B71, 0x92B7D, 0x91E00, 0x92B82
FALLTHROUGH = 0x92B71
TARGETS = (ANCHOR, CALLSITE, CALLEE, RETURN)
CAP = 4


def rel32_call(ip: int, encoded: bytes) -> tuple[int, int]:
    if len(encoded) < 5 or encoded[0] != 0xE8:
        raise ValueError("expected CALL rel32")
    fallthrough = (ip + 5) & 0xFFFFFFFF
    displacement = int.from_bytes(encoded[1:5], "little", signed=True)
    return (fallthrough + displacement) & 0xFFFFFFFF, fallthrough


def prior_call() -> dict[str, Any]:
    result = json.loads(PRIOR.read_text(encoding="utf-8"))
    raw = TRACE_PRIOR.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != result["trace"]["sha256"]:
        raise ValueError("W3-124 trace hash mismatch")
    rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    row = next((r for r in rows if r.get("event") == "target_runtime_checkpoint" and
                r.get("link_va") == ANCHOR), None)
    if row is None or _hashlib.sha256(bytes.fromhex(str(row.get("bytes", ""))[:32])).hexdigest() != "dd5608a38937557c04ab6c5f67dd754caa3d005f0ef8687592db2cbd4e76c69a":
        raise ValueError("W3-124 lacks the original 0x92B71 call bytes")
    call_prefix = row["bytes"][(CALLSITE - ANCHOR) * 2:(CALLSITE - ANCHOR + 4) * 2]
    if call_prefix != "e87ef2ff":
        raise ValueError("measured instruction-byte window lacks the expected CALL prefix")
    map_text = MAP.read_text(encoding="utf-8")
    if "0001:00091E00       LbMemoryAlloc_" not in map_text:
        raise ValueError("exact target map lacks LbMemoryAlloc_ at 0x91E00")
    disasm_text = DISASM.read_text(encoding="utf-8")
    call_sequence = ("jump_92b6b:\n\t\tcmpb   $ser_start_,-do_ser_start_(%ebp)\n"
                     "\t\tjne    jump_92b87\n\t\tmov    lbDisplay__GraphicsScreenWidth,%eax\n"
                     "\t\timul   lbDisplay__GraphicsScreenHeight,%eax\n"
                     "\t\tcall   LbMemoryAlloc_\n\t\tmov    %eax,b_screen\n\tjump_92b87:")
    if call_sequence not in disasm_text:
        raise ValueError("exact disassembly lacks the PlayIntro call sequence")
    target, ret = rel32_call(CALLSITE, bytes.fromhex("e87ef2ffff"))
    if (target, ret) != (CALLEE, RETURN):
        raise ValueError("static target/return calculation mismatch")
    return {"target_sha256": result["target_sha256"], "trace_sha256": digest,
            "anchor_sequence": row["sequence"], "anchor_link_va": ANCHOR,
            "anchor_bytes": row["bytes"], "runtime_call_byte_prefix": call_prefix,
            "runtime_call_bytes_complete": False, "callsite_link_va": CALLSITE,
            "static_disassembly_sha256": hashlib.sha256(DISASM.read_bytes()).hexdigest(),
            "callee_link_va": target, "callee_symbol": "LbMemoryAlloc_",
            "return_link_va": ret,
            "target_source": "exact-target disassembly symbol plus rel32 implied by the mapped CALL; last displacement byte is not present in the prior 16-byte runtime sample"}


def parse_jsonl(raw: bytes, cap_bytes: int = 1_048_576) -> list[dict[str, Any]]:
    if len(raw) > cap_bytes:
        raise ValueError("trace exceeds configured byte cap")
    return [json.loads(line) for line in raw.splitlines() if line.strip()]


def capture_events(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    names = {"W3_125_CALLSITE", "W3_125_CALLEE_ENTRY", "W3_125_CALL_RETURN"}
    events, seen = [], set()
    for row in rows:
        if row.get("w3_125_lbmemoryalloc_boundary") is not True and row.get("checkpoint") not in names:
            continue
        link = row.get("link_va")
        if link not in TARGETS or link in seen:
            continue
        events.append(row)
        seen.add(link)
        if len(events) >= CAP:
            break
    return events


def branch_context(rows: list[dict[str, Any]]) -> dict[str, Any]:
    wanted = (0x92B6B, 0x92B6F, 0x92B71, 0x92B87)
    selected = [row for row in rows if row.get("event") == "target_runtime_checkpoint" and
                row.get("link_va") in wanted and row.get("w3_124_post_join_continuation") is True]
    branch = next((row for row in selected if row.get("link_va") == 0x92B6F), None)
    summary = None
    if branch:
        zf = bool(int(branch.get("eflags", 0)) & 0x40)
        taken = not zf
        expected = 0x92B87 if taken else 0x92B71
        links = [row.get("link_va") for row in selected]
        index = links.index(0x92B6F)
        next_link = links[index + 1] if index + 1 < len(links) else None
        summary = {"eflags": branch.get("eflags"), "zf": zf, "jne_taken": taken,
                   "expected_next_link_va": expected, "next_captured_link_va": next_link,
                   "path_matches_flags": expected == next_link}
    keep = ("sequence", "link_va", "eip", "eflags", "ebp", "esp", "bytes",
            "w3_124_post_join_continuation", "elapsed_ms")
    return {"events": [{key: row.get(key) for key in keep} for row in selected],
            "branch": summary}


def summarize(events: list[dict[str, Any]]) -> dict[str, Any]:
    links = [event.get("link_va") for event in events]
    return {"link_vas": [f"0x{link:08X}" for link in links],
            "ordered": links == [link for link in TARGETS if link in links],
            "callee_entry_observed": CALLEE in links,
            "caller_return_observed": RETURN in links,
            "callee_registers": next((event for event in events if event.get("link_va") == CALLEE), None)}


def source_coverage(source: str) -> dict[str, bool]:
    start = source.index("const bool selected_capture_site")
    end = source.index("// Before MAIN's runtime mapping is known", start)
    selected = source[start:end]
    return {
        "sites_selected_after_mapping": all(f"0x{link:08x}" in selected for link in TARGETS),
        "four_event_cap": "w3_125_checkpoint_count < 4" in source,
        "anchor_arms_capture": "if (link_va == 0x00092b71)\n\t\t\t\t\t\tw3_125_capture_armed = true;" in source,
        "call_boundary_flag_serialized": "w3_125_lbmemoryalloc_boundary" in source,
    }
