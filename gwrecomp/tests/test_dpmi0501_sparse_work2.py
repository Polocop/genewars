"""Verify bounded original-byte AX=0501 memory allocations use sparse backing."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
e = json.loads((ROOT / "evidence" / "dpmi_0300_frame_work2.json").read_text(encoding="utf-8"))
assert e["target_sha256"] == "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
assert e["first_unsupported"] is None
first = e["linear_allocation_calls"][0]
assert first["eip"] == "0x001c3cc1"
assert first["registers"]["eax"] == "0x00000501"
assert first["registers"]["ebx"] == "0x00000000"
assert first["registers"]["ecx"] == "0x00001000"
assert first["registers_after"]["ebx"] == "0x0000003c"
assert first["registers_after"]["ecx"] == "0x00002000"
assert first["registers_after"]["esi"] == "0x00000000"
assert first["registers_after"]["edi"] == "0x00000001"
failed = e["first_linear_allocation_failures"][0]
assert failed["eip"] == "0x001c3cc1"
assert failed["service"] == "dpmi31.allocate_memory.unavailable"
assert failed["registers_after"]["eax"] == "0x00008012"
assert int(failed["registers_after"]["eflags"], 16) & 1
assert len(e["guest_allocations"]) == 129
assert 0 < e["guest_allocation_page_count"] < 4096
assert all(x["match"] for x in e["allocation_backing_checks"])
assert all(x["materialized"] for x in e["allocation_backing_checks"])
assert e["guest_allocations"][-1]["base"] == "0x7e449000"
assert e["last_guest_instruction"]["eip"] != "0x001d23a7"
assert e["stop_reason"] == "instruction_limit"
assert e["executed_instruction_count"] == 1_000_000
assert e["read_only_reference_unchanged"] is True
print("PASS: AX=0501 original-byte allocations continue sparsely to the configured 2GiB ceiling")
