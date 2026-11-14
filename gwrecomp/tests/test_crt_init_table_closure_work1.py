"""Evidence-backed checks for the exact LE CRT init table and its closure roots."""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))
from le_loader import load_le
from extract_symbol_corpus import le_fixup_header, parse_fixups


class CrtInitTableClosureWork1(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.exe = ROOT / "evidence" / "genewars-1_1.exe"
        cls.raw = cls.exe.read_bytes()
        cls.image = load_le(cls.exe)
        hdr = le_fixup_header(cls.raw)
        cls.fixups = parse_fixups(
            cls.raw, cls.image.objects, hdr["page_size"], hdr["num_pages"],
            hdr["obj_tab"], hdr["obj_cnt"], hdr["fixup_page_tab"], hdr["fixup_rec_tab"],
        )
        cls.report = json.loads((ROOT / "evidence" / "entry_path_closure.json").read_text())
        cls.table = cls.report["crt_init_table"]

    def test_table_fields_are_loaded_from_code_references(self):
        self.assertEqual(self.table["start"], "0x001126B8")
        self.assertEqual(self.table["end_exclusive"], "0x0011272A")
        self.assertEqual(self.table["record_size"], 6)
        self.assertEqual(len(self.table["records"]), 19)
        obj = self.image.object_containing(int(self.table["start"], 16))
        self.assertIsNotNone(obj)
        self.assertTrue(obj.writable)
        self.assertFalse(obj.executable)

    def test_every_function_pointer_matches_applied_offset32_fixup(self):
        table = int(self.table["start"], 16)
        mem = self.image.mem
        for record in self.table["records"]:
            i = record["index"]
            slot = table + i * self.table["record_size"] + 2
            matches = [(target, kind) for source, target, kind in self.fixups if source == slot]
            self.assertIn((record["target"], 7), matches)
            loaded = int.from_bytes(mem[slot - self.image.mem_base:slot - self.image.mem_base + 4], "little")
            self.assertEqual(loaded, record["target"])
            target_obj = self.image.object_containing(loaded)
            self.assertIsNotNone(target_obj)
            self.assertTrue(target_obj.executable)

    def test_dispatch_order_and_indirect_roots_are_preserved(self):
        records = self.table["records"]
        expected = [r["target_va"] for r in sorted(records, key=lambda r: (r["priority"], -r["index"]))]
        self.assertEqual(self.table["dispatch_order"], expected)
        closure = (ROOT / "build" / "entry_path_closure.c").read_text(encoding="utf-8")
        for record in records:
            address = int(record["target_va"], 16)
            self.assertIn(f"RECOMP_ENTER(0x{address:08X}u)", closure)

    def test_direct_jump_thunk_and_target_are_one_recovered_cfg(self):
        closure = (ROOT / "build" / "entry_path_closure.c").read_text(encoding="utf-8")
        start = closure.index("void sub_000A38DC(void)")
        body = closure[start:closure.index("\n}", start) + 2]
        self.assertIn("RECOMP_ENTER(0x000A38DCu)", body)
        self.assertIn("goto L_000BBE44", body)
        self.assertIn("L_000BBE44:", body)
        self.assertIn("push es", body)

    def test_table_roots_have_no_unresolved_or_invalid_targets(self):
        self.assertEqual(self.table["unresolved_table_targets"], [])
        self.assertTrue(all(r["target_object"] == 1 and r["fixup_type"] == 7 for r in self.table["records"]))

    def test_verified_indirect_callback_arguments_extend_the_closure(self):
        edges = self.report["indirect_callback_edges"]
        edge = next(e for e in edges if e["caller"] == "0x00096B23" and e["callee"] == "0x000B6534")
        self.assertEqual(edge["register"], "ecx")
        self.assertEqual(edge["target_va"], "0x00096B10")
        self.assertFalse(edge["already_in_closure"])
        closure = (ROOT / "build" / "entry_path_closure.c").read_text(encoding="utf-8")
        start = closure.index("void sub_00096B10(void) {")
        self.assertIn("RECOMP_ENTER(0x00096B10u)", closure[start:start + 500])
        self.assertEqual(self.report["unresolved_indirect_callback_targets"], [])

    def test_generated_block_probe_is_optional_and_observational(self):
        closure = (ROOT / "build" / "entry_path_closure.c").read_text(encoding="utf-8")
        self.assertIn("#ifdef GW_NATIVE_CAPTURE_CRT_STARTUP", closure[:600])
        self.assertIn("GW_NATIVE_CAPTURE_BLOCK(0x0009432Fu)", closure)


if __name__ == "__main__":
    unittest.main()
