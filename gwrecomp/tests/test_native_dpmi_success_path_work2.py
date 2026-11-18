"""Replay the native RationalAlloc success branch with a labeled synthetic arena."""
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
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence" / "native_dpmi_success_path_work2.json"


class NativeDpmi0501SuccessTests(unittest.TestCase):
    def test_original_success_observation_is_separate_from_native_fixture(self):
        checkpoint = json.loads((ROOT / "evidence" / "w3_059_main_runtime_mapping_checkpoint_20261008.json").read_text())
        trace = checkpoint["rationalalloc"]["DPMI_AX0501"]
        self.assertEqual(trace["before"]["EAX"], "0x00000501")
        self.assertEqual(trace["registers"]["EBX"], "0x0000001A")
        self.assertEqual(trace["registers"]["ECX"], "0x00000000")
        self.assertFalse(trace["registers"]["CF"])
        self.assertEqual((int(trace["registers"]["EBX"], 16) << 16) | int(trace["registers"]["ECX"], 16), 0x001A0000)
        raw_trace = ROOT / "evidence" / "w3_059_rationalalloc_trace_20261008_03.jsonl"
        returned = None
        for line in raw_trace.read_text(encoding="utf-8").splitlines():
            event = json.loads(line)
            if event.get("event") == "rationalalloc_instruction" and event.get("eip") == 0x2AECC3:
                returned = event
                break
        self.assertIsNotNone(returned, "W3 trace must preserve the post-INT register state")
        original_handle = (returned["esi"] << 16) | returned["edi"]
        self.assertEqual(original_handle, 0x00019896)
        self.assertEqual(returned["eflags"] & 1, 0)
        self.assertFalse(checkpoint["AH48_AH49"]["ah48_observed"])
        self.assertFalse(checkpoint["AH48_AH49"]["ah49_observed"])

    def test_original_ah3c_measured_create_result(self):
        trace = json.loads((ROOT / "evidence" / "runtime_ah3c_create_trace.json").read_text())
        create = next(x for x in trace["target"]["interrupts"] if x.get("service") == "dos21.create_file")
        self.assertEqual(create["eip_int_opcode_assumption"], "0x001afda7")
        self.assertEqual(create["registers"]["eax"], "0x00003c80")
        self.assertEqual(create["registers"]["ebx"], "0x00000002")
        self.assertEqual(create["registers"]["ecx"], "0x00000000")
        self.assertEqual(create["dos_filename"]["path"], r"c:\address.txt")
        self.assertEqual(create["dos_filename"]["attributes"], 0)
        self.assertEqual(create["registers_after"]["eax"], "0x00000005")
        self.assertEqual(int(create["registers_after"]["eflags"], 16) & 1, 0)
        following = trace["target"]["interrupts"][trace["target"]["interrupts"].index(create)+1]
        self.assertEqual(following["eip_int_opcode_assumption"], "0x001c8973")
        self.assertEqual(following["registers"]["eax"], "0x00004400")

    def test_native_replay_passes_0501_and_records_first_following_frontier(self):
        command = [
            sys.executable, str(ROOT / "tests" / "test_native_guest_image.py"),
            "--command-tail=-k",
            "--evidence-name=native_dpmi_success_path_work2.json",
            "--continue-known-services", "--continue-selector-query",
            "--continue-time-query", "--continue-dpmi-linear-success",
            "--continue-dos-ah3d", "--continue-dos-ah3c", "--continue-dos-ax4400",
            "--continue-dos-ah40",
            "--cd-present-fixture", "--reuse-compiled-closure",
        ]
        completed = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
        service = evidence["native_generated_c_progress"]["dpmi_linear_allocation"]
        self.assertEqual(service["contract_class"], "synthetic bounded success path; not an original-address/handle comparison")
        self.assertEqual(service["carry"], 0)
        self.assertEqual(service["handled"], 1)
        self.assertEqual(service["synthetic_size"], "0x00008000")
        self.assertTrue(service["synthetic_handle"])
        self.assertTrue(evidence["native_generated_c_progress"]["next_frontier"])
        ah3d = evidence["native_generated_c_progress"]["dos_ah3d"]
        self.assertEqual(ah3d["path"], r"c:\address.txt")
        self.assertEqual(ah3d["resolved_path"], r"c:\address.txt")
        self.assertTrue(ah3d["raw_path_matches_w3_bytes"])
        self.assertTrue(ah3d["normalized_path_matches_w3_dos_path"])
        self.assertEqual(ah3d["request_eax"], "0x00003D01")
        self.assertEqual(ah3d["response_eax"], "0x00000002")
        self.assertEqual(ah3d["cf_out"], 1)
        self.assertTrue(ah3d["all_non_ax_registers_preserved"])
        ah3c = evidence["native_generated_c_progress"]["dos_ah3c"]
        self.assertEqual(ah3c["path"], r"c:\address.txt")
        self.assertEqual(ah3c["attributes"], 0)
        self.assertEqual(ah3c["response_eax"], "0x00000005")
        self.assertEqual(ah3c["cf_out"], 0)
        self.assertEqual(ah3c["fixture_kind"], "bounded_memory_only")
        ioctl = evidence["native_generated_c_progress"]["dos_ax4400"]
        self.assertEqual(ioctl["request_eax"], "0x00004400")
        self.assertEqual(ioctl["request_ebx"], "0x00000005")
        self.assertEqual(ioctl["response_edx"], "0x00000042")
        self.assertEqual(ioctl["cf_out"], 0)
        self.assertEqual(ioctl["classification"], "synthetic DOS file on drive C, not written")
        self.assertEqual(ioctl["w3_historical_exact_request"]["response"]["edx"], "0x00000002")
        self.assertFalse(ioctl["matches_w3_historical_response"])
        self.assertFalse(ioctl["w3_historical_exact_request"]["same_fixture_sequence_as_current_native"])
        self.assertEqual(ioctl["second_request"]["request_ecx"], "0x00000000")
        self.assertEqual(ioctl["second_request"]["request_edx"], "0x00004000")
        self.assertEqual(ioctl["third_request"]["request_ecx"], "0x0010A88A")
        self.assertEqual(ioctl["third_request"]["request_edx"], "0x0010A88A")
        self.assertEqual(ioctl["fourth_request"]["request_ecx"], "0x00000000")
        self.assertEqual(ioctl["fourth_request"]["request_edx"], "0x0010A88A")
        stdout = evidence["native_generated_c_progress"]["dos_ah40_stdout"]
        self.assertEqual(len(stdout["calls"]), 2)
        self.assertEqual(stdout["calls"][0]["effective_linear"], "0x002000D0")
        self.assertEqual(stdout["calls"][0]["sample_hex"], "0d0a")
        self.assertEqual(stdout["captured_bytes_hex"], _OrigDigest("fe89b1a9ba908b103b94071511cd2d229e8e8e1fc40fcde919939f75cca8fa04",28))
        self.assertEqual(stdout["calls"][0]["response_eax"], "0x00000002")
        self.assertEqual(stdout["calls"][0]["cf_out"], 0)
        self.assertEqual(stdout["calls"][1]["request_ecx"], "0x0000001A")
        self.assertEqual(stdout["calls"][1]["sample_hex"], _OrigDigest("ccc375f7139cdd93dd78a0ed5736d746782f68a52f25c664496af7e046d79909",26))
        self.assertEqual(stdout["fixture_handle_type"], "standard output character device; no fixture redirection configured")
        self.assertEqual(stdout["result_class"], "synthetic bounded replay; original AH=40 stdout response not measured for this call")
        self.assertIsNotNone(stdout["original_same_site_comparison"])
        self.assertFalse(stdout["original_same_site_comparison"]["matches_current_stdout_request"])
        self.assertEqual(stdout["next_frontier"]["instruction_va"], "0x000AFC33")
        self.assertEqual(stdout["next_frontier"]["eax"], "0x00004C00")
        self.assertEqual(stdout["next_frontier"]["event"], "interrupt_trap")
        next_frontier = evidence["native_generated_c_progress"]["next_frontier"]
        ah42 = evidence["native_generated_c_progress"]["dos_ah42"]
        self.assertEqual(ah42["request_eax"], "0x00004201")
        self.assertEqual(ah42["response_eax"], "0x00000000")
        self.assertEqual(ah42["cf_out"], 0)
        self.assertEqual(ah42["second_request"]["request_eax"], "0x00004200")
        self.assertEqual(ah42["second_request"]["response_eax"], "0x00000000")
        ah3e = evidence["native_generated_c_progress"]["dos_ah3e"]
        self.assertEqual(ah3e["request_eax"], "0x00003E05")
        self.assertEqual(ah3e["cf_out"], 0)
        standard_ioctl = evidence["native_generated_c_progress"]["dos_standard_ioctl"]
        self.assertEqual(len(standard_ioctl), 3)
        self.assertEqual(standard_ioctl[0]["request_ebx"], "0x00000002")
        self.assertEqual(standard_ioctl[0]["response_edx"], "0x00100082")
        self.assertEqual(standard_ioctl[1]["request_ebx"], "0x00000001")
        self.assertEqual(standard_ioctl[2]["request_ebx"], "0x00000001")
        next_frontier = evidence["native_generated_c_progress"]["next_frontier"]
        self.assertNotEqual(next_frontier["instruction_va"], "0x000C8973")
        self.assertIn("NATIVE_NEXT_TRAP", evidence["stdout"])
        original = 0x001A0000
        self.assertNotEqual(int(service["synthetic_base"], 16), original)
        self.assertNotEqual(int(service["synthetic_handle"], 16), 0x00019896)


if __name__ == "__main__":
    unittest.main()
