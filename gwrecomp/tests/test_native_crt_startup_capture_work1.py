"""Regression for dynamic CRT initializer execution and main argument startup."""
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class NativeCrtStartupCaptureWork1(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads((ROOT / "evidence" / "native_crt_startup_work1_20261008.json").read_text(encoding="utf-8"))
        cls.stdout = cls.data["stdout"]

    def test_all_crt_initializers_execute_in_table_dispatch_order(self):
        dynamic = re.findall(r"W1_CRT_CALLBACK_DYNAMIC ordinal=(\d+).*?target=([0-9a-f]{8})", self.stdout)
        self.assertEqual([int(i) for i, _ in dynamic], list(range(19)))
        self.assertEqual([f"0x{target.upper()}" for _, target in dynamic], [
            "0x000DCED5", "0x000A38DC", "0x000BC0E3", "0x000E165E",
            "0x000D5DB5", "0x000C3882", "0x000C3584", "0x000BC1F6",
            "0x000DFDC1", "0x000D21EE", "0x000BC65D", "0x000D1FBC",
            "0x000C87B6", "0x000BC19F", "0x000BBE29", "0x000BAAC2",
            "0x000AC3B4", "0x000830F0", "0x0001C440",
        ])
        self.assertIn("W1_MAIN_ARG index=0", self.stdout)
        self.assertIn("text=C:\\GENEWARS\\GENEWARS.EXE", self.stdout)
        self.assertIn("W1_MAIN_ARG index=1", self.stdout)
        self.assertIn("text=-k", self.stdout)
        self.assertIn("W1_MAIN_ARG index=2", self.stdout)
        self.assertIn("text=38928", self.stdout)

    def test_main_parser_sets_locals_and_reaches_game_callsite(self):
        main = re.search(r"W1_MAIN_BLOCK va=000941d2 .*?local64=(\d+) local68=(\d+) global188a4c=([0-9a-f]+)", self.stdout)
        self.assertIsNotNone(main)
        self.assertEqual(main.groups(), ("1", "0", "00000000"))
        parsed = re.search(r"W1_MAIN_BLOCK va=000940c0 .*?local64=(\d+) local68=(\d+) global188a4c=([0-9a-f]+)", self.stdout)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.groups(), ("1", "1", "00009810"))
        self.assertIn("W1_MAIN_BLOCK va=0009432f", self.stdout)
        self.assertIn("W1_MAIN_BLOCK va=0009433d", self.stdout)
        self.assertIn("W1_CRT_SUMMARY", self.stdout)
        self.assertIn("trap_va=000c8973", self.stdout)


if __name__ == "__main__":
    unittest.main()
