"""Synthetic provenance and recovery checks for W1-085."""
from __future__ import annotations
import hashlib,json,shutil,tempfile,unittest
from pathlib import Path
from tools.verify_w1_085_ah4400_caller_provenance import build_provenance,validate_capture
ROOT=Path(__file__).resolve().parents[1]

def sample_lines():
    return [
      "W1_AH44_CALLSITE ordinal=0 caller=000ba4d6 target=000c896a site=000ba4e4 cs=000c eax=00000001 ebx=00000000 ecx=00000000 edx=00000000 esi=00000000 edi=00000000 ebp=001a8b00 esp=001a8af0 flags_k=00000001 flags_a=00000000 flags_b=00000000 cf=0 ds=0014 ds_base=00000000 es=0014 ss=0014 stack0=00000000 stack1=00000000 stack2=00000000",
      "W1_AH44_HELPER_ENTRY ordinal=0 cs=000c eip=000c896a caller_func=000c896a return_address=dead0000 callsite=00000000 eax=00000001 ebx=00000000 ecx=00000000 edx=00000000 esi=00000000 edi=00000000 ebp=001a8b00 esp=001a8af0 flags_k=00000001 flags_a=00000000 flags_b=00000000 cf=0 ds=0014 ds_base=00000000 es=0014 ss=0014 stack0=dead0000 stack1=00000000 stack2=00000000",
      "W1_AH44_REQUEST ordinal=0 cs=000c eip=000c8973 caller_func=000c896a eax=00004400 ebx=00000001 ecx=00000000 edx=0010a822 esi=00000000 edi=00000000 ebp=001a8b00 esp=001a8ae4 flags_k=00000001 flags_a=00000000 flags_b=00000000 cf=0 ds=0014 ds_base=00000000 es=0014 ss=0014 stack0=00000000 stack1=00000000 stack2=00000000 stack3=00000000 helper_ordinal=0 sample_address=0010a822 sample_valid=1 sample_length=32 sample_hex=" + "00"*32,
      "NATIVE_NEXT_TRAP vector=21 eip=000c8973 eax=00004400 ebx=00000001 ecx=00000000 edx=0010a822"
    ]

def sample_capture():
    return {"task":"W1-085","fresh_replay":True,"original_equivalence_claimed":False,
      "target_sha256":"2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f",
      "frontier":{"newly_observed":True,"guest_eip":"0x000c8973"},
      "native_ah4400_origin":build_provenance(sample_lines(),[])}

class W1085CallerProvenance(unittest.TestCase):
    def test_correlates_bx1_request_to_callsite_and_entry_eax(self):
        data=sample_capture(); self.assertEqual(validate_capture(data),[])
        event=data["native_ah4400_origin"]["bx1_requests"][0]
        self.assertEqual(event["native_dynamic_caller_link_va"],"000ba4d6")
        self.assertEqual(event["native_direct_callsite_link_va"],"000ba4e4")
        self.assertEqual(event["helper_entry_eax"],"00000001")
    def test_preserves_unresolved_instead_of_guessing(self):
        origin=build_provenance(sample_lines()[1:],[])
        self.assertEqual(origin["bx1_caller_attribution"],"UNRESOLVED")
        self.assertIsNone(origin["bx1_requests"][0]["native_dynamic_caller_link_va"])
    def test_recovery_copies_restore_isolated(self):
        manifest=json.loads((ROOT/"work/recovery/W1-085/manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["task"],"W1-085"); self.assertTrue(manifest["verification"]["all_hashes_match"])
        with tempfile.TemporaryDirectory(prefix="w1_085_restore_",dir=ROOT/"cache") as td:
            for item in manifest["files"]:
                backup=Path(item["backup"]); restored=Path(td)/backup.name; shutil.copyfile(backup,restored)
                self.assertEqual(hashlib.sha256(restored.read_bytes()).hexdigest(),item["source_sha256"])

if __name__=="__main__": unittest.main()
