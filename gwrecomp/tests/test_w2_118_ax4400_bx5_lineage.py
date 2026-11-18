import hashlib
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read_json(path):
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def sha256(path):
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


class Ax4400Bx5LineageTests(unittest.TestCase):
    def test_w3_079_bounded_callbacks_and_missing_caller(self):
        data = read_json("evidence/w3_079_original_ah44_bx1.json")
        events = data["ah44_events"]
        self.assertEqual([e["in_bx"] for e in events], [5, 5, 5, 5, 5, 2, 2, 2])
        for event in events:
            self.assertEqual(event["in_ax"], 0x4400)
            self.assertEqual(event["out_ax"], 2)
            self.assertEqual(event["out_dx"], 2)
            self.assertFalse(event["cf"])
            self.assertIsNone(event["caller_link_va"])
        self.assertEqual(data["callsite_count"], 0)
        self.assertEqual(data["trace"]["sha256"], "08b039d9df3c3ab89ea91e8f01fefd7399c90c8aef2a05cafa0f72c8f2aa04b1")
        main = data["runtime_mapping"]["main_entry"]
        self.assertEqual(main["psp_tail_text"], " -k 38928")
        setup = data["runtime_mapping"]["setup_game"]
        self.assertEqual(setup["link_va"], 0x94AC0)
        self.assertLess(max(e["sequence"] for e in events), setup["sequence"])

    def test_w3_085_identifies_original_address_file_handle(self):
        data = read_json("evidence/w3_085_handle5_lineage.json")
        rec = data["caller_reconciliation"]
        opened = rec["handle5_open_event"]
        self.assertEqual(opened["requested_path"].lower(), "c:\\address.txt")
        self.assertEqual(opened["entry"], 5)
        self.assertEqual(opened["internal_handle"], 3)
        self.assertEqual(rec["psp_entry_5_maps_to"]["path"], "ADDRESS.TXT")
        self.assertEqual([x["bx"] for x in rec["following_ah44_callbacks"]], [5, 5])
        self.assertTrue(all(x["out_ax"] == 2 and x["out_dx"] == 2 and not x["cf"]
                            for x in rec["following_ah44_callbacks"]))
        self.assertEqual(rec["original_checkpoint"]["link_va"], 0xBA4E4)
        self.assertEqual(data["psp_command_tail"], " -k 38928")

    def test_w3_218_same_tail_calls_remain_unattributed(self):
        data = read_json("evidence/w3_218_ah4400_tail_audit.json")
        self.assertEqual(data["w3_214_run"]["recorded_dos_launch_tail"], " -k 38928")
        self.assertEqual(data["observed_bx_sequence"], [5, 5, 5, 5, 5, 2, 2, 2])
        self.assertTrue(all(x["caller_link_va"] is None for x in data["ax4400_callbacks"]))
        self.assertEqual(data["ax4400_callbacks"][0]["output"], {"ax": 2, "dx": 2, "cf": False})

    def test_native_runs_are_distinct_at_setup_gate(self):
        w1_072 = read_json("evidence/native_address_open_w1_072.json")
        self.assertEqual(w1_072["command_tail"], "-k 38928")
        self.assertEqual(w1_072["address_txt"]["size"], 24)
        self.assertIn("handle=5", w1_072["address_txt"]["open_event"])
        self.assertIn("C:\\ADDRESS.TXT", w1_072["address_txt"]["open_event"])
        self.assertIn("eax=00004400 ebx=00000005", w1_072["next_frontier"]["event"])
        self.assertFalse(w1_072["game_gate"]["setup_game_entry_observed"])

        w1_051 = read_json("evidence/native_sound_ini_replay_w1_051.json")
        self.assertEqual(w1_051["command_tail"], " -k 38928")
        self.assertEqual(w1_051["gate"]["local_64"], "01")
        self.assertEqual(w1_051["gate"]["local_68"], "01")
        self.assertTrue(w1_051["sound_ini_continuation"]["setup_game_entered"])
        self.assertEqual(w1_051["sound_ini_continuation"]["fresh_native_request"]["eip"], "000af93a")
        self.assertEqual(w1_051["sound_ini_continuation"]["fresh_native_request"]["request_eax"], "00004300")
        self.assertEqual(w1_051["ax4400"][0]["path"], "C:\\GENEWARS\\CONFIG.INI")
        self.assertEqual(w1_051["ax4400"][0]["handle"], 6)
        frontier = w1_051["frontier"]
        self.assertEqual(frontier["guest_eip"], "0x000c8973")
        self.assertEqual(frontier["request_registers"]["ebx"], "00000001")
        self.assertFalse(w1_051["sound_ini_continuation"]["original_equivalence_claimed"])

    def test_runtime_is_generic_provider_backed_file_ioctl(self):
        c = (ROOT / "runtime/gw_dos_services.c").read_text(encoding="utf-8")
        dosbox = (ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/dos/dos_ioctl.cpp").read_text(encoding="utf-8")
        self.assertIn("static uint16_t dos_ioctl_get_device_info", c)
        self.assertIn("services->file_ioctl_info(services->file_user", c)
        self.assertIn("services->files[handle-5u].active", c)
        self.assertIn("if (info & 0x0080u) return 0xffffu", c)
        self.assertIn("g_eax=(g_eax&0xffff0000u)|info", c)
        self.assertIn("g_edx=(g_edx&0xffff0000u)|info", c)
        self.assertIn("reg_ax=reg_dx; //Destroyed officially", dosbox)
        self.assertEqual(sha256("runtime/gw_dos_services.c"),
                         read_json("evidence/w2_118_ax4400_bx5_lineage.json")["runtime"]["c_sha256"])
