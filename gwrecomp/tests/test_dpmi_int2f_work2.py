"""Check original-byte DPMI 0300 / INT 2Fh 1500 dispatch and guest continuation."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
e = json.loads((ROOT / "evidence" / "dpmi_0300_frame_work2.json").read_text(encoding="utf-8"))
assert e["target_sha256"] == "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
assert e["read_only_reference_unchanged"] is True
assert e["first_unsupported"] is None
query = next(x for x in e["interrupts"] if x.get("real_mode_interrupt", {}).get("vector") == 0x2F)
assert query["eip_int_opcode_assumption"] == "0x001d23a7"
assert query["handled"] is True
rm = query["real_mode_interrupt"]
assert rm["registers_before"]["eax"] == "0x00001500"
assert rm["registers_before"]["ebx"] == "0x00000000"
assert rm["registers_before"]["ecx"] == "0x00000000"
assert rm["service"] == "int2f.mscdex_install_check"
assert rm["registers_after"]["eax"] == "0x00001500"
assert rm["registers_after"]["ebx"] == "0x00000000"
assert rm["registers_after"]["ecx"] == "0x00000000"
assert query["registers_after"]["eip"] == "0x001d23a9"
assert e["post_query_services"], "guest did not reach a later service after INT 2Fh"
assert any(x["service"] == "dpmi31.allocate_dos_memory" and x["handled"]
           for x in e["post_query_services"])
assert e["last_guest_instruction"]["eip"] != "0x001d23a7"
print("PASS: original-byte guest handled INT 2Fh AX=1500, resumed after 0x001d23a7, then issued further DPMI work")
