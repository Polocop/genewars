import hashlib
import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class AddressWriterEvidenceTests(unittest.TestCase):
    def test_static_writer_and_bounded_runtime_correlation(self):
        evidence = json.loads((ROOT / "evidence/w3_088_address_writer.json").read_text(encoding="utf-8"))
        for rel, expected in evidence["source_sha256"].items():
            self.assertEqual(hashlib.sha256((ROOT / rel).read_bytes()).hexdigest(), expected, rel)

        target = ROOT / evidence["target"]["path"]
        target_bytes = target.read_bytes()
        self.assertEqual(hashlib.sha256(target_bytes).hexdigest(), evidence["target"]["sha256"])
        self.assertIn(b"c:\\address.txt\0", target_bytes.lower())

        disasm = (ROOT / "evidence/genewars-1_1-le_disasm.s").read_text(encoding="utf-8")
        self.assertIn('aCAddressTxt:\t/* 0x10d9d5 */\n\t\t.string "c:\\\\address.txt"', disasm)
        self.assertIn('aW_4:\t/* 0x10d9d3 */\n\t\t.ascii  "\\x77\\x00"', disasm)
        self.assertEqual(disasm.count("call   func_27d70"), 1)
        self.assertIn("mov    $aW_4,%edx\n\t\tmov    $aCAddressTxt,%eax\n\t\tcall   fopen_", disasm)
        self.assertIn("push   $func_27d70\n\t\tpush   $aOffsetfunction\n\t\tpush   %eax\n\t\tcall   fprintf_", disasm)
        self.assertIn("call   fclose_", disasm)

        self.assertEqual(evidence["original_replay"]["main_entry"]["sequence"], 29)
        self.assertEqual(evidence["original_replay"]["next_recorded_handle_open"]["sequence"], 30)
        self.assertFalse(evidence["original_replay"]["runtime_eip_inside_func_27d70_captured"])
        self.assertEqual(evidence["provenance"]["earlier_persisted_vhdx_bytes_first_creator"], "UNKNOWN")
        self.assertFalse(evidence["provenance"]["authentic_game_inventory_contains_address_txt"])


if __name__ == "__main__":
    unittest.main()
