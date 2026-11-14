"""Synthetic bound, callback, and recovery checks for W1-084."""
from __future__ import annotations
import hashlib, json, shutil, tempfile, unittest
from pathlib import Path
from tools.verify_w1_084_native_ah40_continuation import validate_capture
ROOT=Path(__file__).resolve().parents[1]

def event(ordinal: int, count: int) -> str:
    sample=bytes(range(count)).hex()
    return (f"W1_081_AH40_ACTIVE_FILE ordinal={ordinal} caller=000d214f eip=000d219c slot=0 mapping_active=1 owner=gwerr callback_invoked=1 "
        f"eax_in=00004002 ebx_in=00000002 ecx_in={count:08x} edx_in=00201038 esi_in=00000002 edi_in={count:08x} ebp_in=00201038 esp_in=001a8b8c "
        f"flags_k_in=00000001 flags_a_in=02000000 flags_b_in=80000000 cf_in=0 cs=000c ds=0014 es=0014 ss=0014 sample_valid=1 sample_length={count} sample_hex={sample} "
        f"eax_out={count:08x} ebx_out=00000002 ecx_out={count:08x} edx_out=00201038 esi_out=00000002 edi_out={count:08x} ebp_out=00201038 esp_out=001a8b8c "
        "flags_k_out=00000001 flags_a_out=02000000 flags_b_out=80000000 cf_out=0 callback_handled=1")

def capture() -> dict:
    return {"task":"W1-084","fresh_replay":True,"original_equivalence_claimed":False,
        "target_sha256":"2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f",
        "w1_081_ah40_active_file":{"observer_enabled":True,"event_cap":2,"max_sample_bytes":64,"event_count":2,
            "events":[event(0,20),event(1,26)],"only_active_virtual_file_handle":True,"host_write":False,"guest_state_injected":False},
        "frontier":{"newly_observed":True,"fresh_replay":True,"guest_eip":"0x000c8973","stop_reason":"fresh DOS trap",
            "request_registers":{"eip":"000c8973","eax":"00004400"}}}

class W1084AH40Tests(unittest.TestCase):
    def test_accepts_two_measured_callback_events(self): self.assertEqual(validate_capture(capture()),[])
    def test_rejects_third_oversized_or_unmapped_event(self):
        data=capture(); obs=data["w1_081_ah40_active_file"]
        obs["event_cap"]=3; obs["events"].append(event(2,65)); obs["event_count"]=3
        obs["events"][0]=obs["events"][0].replace("mapping_active=1","mapping_active=0")
        errors=validate_capture(data)
        self.assertTrue(any("two-event count" in x for x in errors)); self.assertTrue(any("request bound" in x for x in errors))
        self.assertTrue(any("active mapped" in x for x in errors))
    def test_source_traps_oversized_and_excess_matching_calls(self):
        source=(ROOT/"tests/test_native_guest_image.c").read_text(encoding="utf-8")
        block=source[source.index("#ifdef GW_NATIVE_CAPTURE_W1_081_AH40_ACTIVE_FILE"):]
        block=block[:block.index("#ifdef GW_NATIVE_STOP_AT_FIRST_AX0501")]
        self.assertIn("w1_081_event_count<2u",block)
        self.assertIn("g_ecx<=64u",block)
        self.assertIn("return GW_INTERRUPT_TRAPPED;",block)
    def test_recovery_copies_restore_isolated(self):
        manifest=json.loads((ROOT/"work/recovery/W1-084/manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["task"],"W1-084"); self.assertTrue(manifest["verification"]["all_hashes_match"])
        with tempfile.TemporaryDirectory(prefix="w1_084_restore_",dir=ROOT/"cache") as td:
            for record in manifest["files"]:
                backup=Path(record["backup"]); restored=Path(td)/(backup.stem+backup.suffix)
                shutil.copyfile(backup,restored)
                self.assertEqual(hashlib.sha256(restored.read_bytes()).hexdigest(),record["source_sha256"])

if __name__=="__main__": unittest.main()
