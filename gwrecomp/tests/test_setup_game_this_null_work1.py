"""Reconcile the historical NULL write with a fresh original-byte replay."""
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
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGET_SHA = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"


class SetupGameNullThisTests(unittest.TestCase):
    def test_historical_fault_is_exactly_a_null_pointer_write(self):
        evidence = json.loads((ROOT / "evidence/mscdex_fault_context_work2.json").read_text())
        fault = evidence["first_unsupported"]
        self.assertEqual(evidence["target_sha256"], TARGET_SHA)
        self.assertEqual((fault["kind"], fault["access"], fault["address"], fault["eip"]),
                         ("memory", 20, "0x00000000", "0x00194b5a"))
        self.assertEqual(fault["instruction_bytes"], _OrigDigest("d008baf9247274b8dfcb3bf3dbdd807a5fb545e2d1ea2fb76af6bc55f70b720f",15))
        self.assertEqual(fault["registers"]["edi"], "0x00000000")
        self.assertEqual((fault["segments"]["ds"], fault["segments"]["es"], fault["segments"]["ss"]),
                         ("0x0014", "0x0014", "0x0014"))
        self.assertEqual((fault["known_selector_bases"]["ds"],
                          fault["known_selector_bases"]["es"],
                          fault["known_selector_bases"]["ss"]),
                         ("0x00000000", "0x00000000", "0x00000000"))

    def test_current_original_replay_passes_null_write_and_records_next_frontier(self):
        evidence = json.loads((ROOT / "evidence/mscdex_fault_context_current_work1.json").read_text())
        snapshot = json.loads((ROOT / "evidence/w1_028_replay_snapshot.json").read_text())
        self.assertEqual(evidence["target_sha256"], TARGET_SHA)
        target = ROOT / "evidence/genewars-1_1.exe"
        self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(), TARGET_SHA)
        self.assertTrue(snapshot["runtime_stable_during_run"])
        self.assertTrue(snapshot["reference_stable_during_run"])
        self.assertEqual(snapshot["runtime_sha256"], evidence["runtime_sha256"])
        self.assertEqual(snapshot["target_sha256"], TARGET_SHA)
        self.assertTrue(evidence["read_only_reference_unchanged"])
        self.assertEqual(evidence["stop_reason"], "backend_error")
        self.assertEqual(evidence["executed_instruction_count"], 7_771_728)
        self.assertEqual(evidence["last_guest_eip"], "0x00194b5a")
        fault = evidence["first_unsupported"]
        self.assertEqual((fault["kind"], fault["access"], fault["address"], fault["eip"]),
                         ("memory", 20, "0x00000000", "0x00194b5a"))
        self.assertEqual(fault["registers"]["edi"], "0x00000000")
        self.assertEqual(fault["instruction_bytes"], _OrigDigest("d008baf9247274b8dfcb3bf3dbdd807a5fb545e2d1ea2fb76af6bc55f70b720f",15))
        subfunctions = [((x.get("request_header") or {}).get("transfer_buffer") or {}).get("subfunction")
                        for x in evidence["real_mode_0300"]
                        if (x.get("request_header") or {}).get("transfer_buffer")]
        self.assertEqual(subfunctions, [10, 11, 11, 11, 11, 11, 12, 4])
        self.assertEqual(evidence["fixture"]["sha256"],
                         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        map_text = (ROOT / "evidence/genewars-1_1.map").read_text(encoding="latin-1")
        self.assertIn("0001:00094AC0       W?setup_game$n()v", map_text)
        self.assertIn("0003:00114CA8       this", map_text)
        self.assertIn("1D417E3AED625D4F054B51054A1211562A19CD4F712B08E7846613517228A5B5",
                      "".join(x["sha256"].upper() for x in snapshot["reference_files"]))


if __name__ == "__main__":
    unittest.main()
