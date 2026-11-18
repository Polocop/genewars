import json
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
class OriginalAH44Handle2EvidenceTests(unittest.TestCase):
 def test_no_matching_original_site_record_is_overclaimed(self):
  d=json.loads((ROOT/"evidence/original_ah44_handle2_frontier_work3.json").read_text(encoding="utf-8"))
  self.assertEqual(d["requested_original_site"]["ebx"],2)
  self.assertFalse(d["site_observation"]["matching_service_record_in_persisted_service_tail"])
  self.assertEqual(d["stop"]["eip"],"0x00194b5a")
  self.assertFalse(d["available_historical_ah44"]["same_fixture_fingerprint"])
 def test_no_contract_is_invented(self):
  d=json.loads((ROOT/"evidence/original_ah44_handle2_frontier_work3.json").read_text(encoding="utf-8"))
  self.assertEqual(d["status"],"BLOCKED")
  self.assertIn("no service result",d["classification"])
if __name__=="__main__": unittest.main()
