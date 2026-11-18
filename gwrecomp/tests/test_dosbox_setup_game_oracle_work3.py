import hashlib
import json
import socket
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class DosboxSetupGameOracleManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads((ROOT / "tools/dosboxx_oracle/probe_manifest.json").read_text(encoding="utf-8"))
        cls.readme = (ROOT / "tools/dosboxx_oracle/README.md").read_text(encoding="utf-8")
        cls.source_evidence = json.loads((ROOT / "evidence/setup_game_this_provenance_work3.json").read_text(encoding="utf-8"))

    def test_exact_pinned_fixture_and_source_commit(self):
        self.assertEqual(self.manifest["source"]["debug_mode"], "--enable-debug=heavy")
        self.assertEqual(self.manifest["source"]["commit"], "bd0f21e4becb263b2add0e160451f3c87a38c1b6")
        fixture = self.manifest["fixture"]
        self.assertEqual(fixture["target_sha256"], "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f")
        self.assertEqual(fixture["cue_sha256"], "1d417e3aed625d4f054b51054a1211562a19cd4f712b08e7846613517228a5b5")
        self.assertEqual(fixture["profile_sha256"], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    def test_live_selector_resolution_precedes_any_data_watch(self):
        setup = self.manifest["setup_game"]
        self.assertEqual(setup["map_link_va"], "0x114CA8")
        self.assertEqual(setup["map_object_offset"], "0x14CA8")
        policy = setup["breakpoint_policy"]
        self.assertIn("Resolve guest CS/DS/LDT/GDT", policy)
        self.assertIn("BPPM", policy)
        self.assertIn("Never reuse Unicorn 0x214CA8", policy)
        self.assertIn("does not assume Unicorn's `0x214CA8`", self.readme)

    def test_all_gate_breakpoints_and_capture_fields_are_present(self):
        setup = self.manifest["setup_game"]
        self.assertEqual(setup["code_link_vas"], {"entry": "0x194AC0", "this_read": "0x194B51", "null_write": "0x194B5A"})
        capture = " ".join(self.manifest["capture_at_each_stop"])
        for required in ("CPU", "GDT", "LDT", "EFLAGS", "caller return chain", "descriptor selector/base/limit/access/present"):
            self.assertIn(required, capture)

    def test_video_probe_covers_return_through_first_visible_work(self):
        video = self.manifest["video_frontier"]
        self.assertEqual(video["int10_sites"], ["0xA3A91", "0xA3AB7"])
        for event in ("first mode set", "first guest write into framebuffer memory", "first palette update", "first blit/callback"):
            self.assertIn(event, video["required_first_events"])
        self.assertEqual(video["framebuffer_assignment"]["site"], "0x9FDEF")
        self.assertEqual(video["framebuffer_assignment"]["global_link_va"], "0x19CA58")
        for va in ("0x94342", "0x94347", "0x9FD40", "0x9FDCC", "0xA3A5C"):
            self.assertIn(va, " ".join(video["control_flow"]))

    def test_no_cd_code_zero_is_not_menu(self):
        self.assertEqual(self.source_evidence["last_guest_eip"], "0x00194b5a")
        self.assertIsNone(self.source_evidence["process_exit"])
        process_exit = self.manifest["process_exit"]
        self.assertEqual(process_exit["no_cd_eip"], "0x1AFC33")
        self.assertTrue(process_exit["expected_no_cd_control"])
        self.assertFalse(process_exit["menu_proven"])

    def test_portable_game_staging_preserves_main_and_empty_profile(self):
        main_path = ROOT / "build/dosboxx_oracle/C/GENEWARS/MAIN.EXE"
        config_path = ROOT / "build/dosboxx_oracle/C/GENEWARS/config.ini"
        self.assertEqual(hashlib.sha256(main_path.read_bytes()).hexdigest(), self.manifest["fixture"]["target_sha256"])
        self.assertEqual(hashlib.sha256(config_path.read_bytes()).hexdigest(), self.manifest["fixture"]["profile_sha256"])
        emulator_config = (ROOT / "build/dosboxx_oracle/dosbox-x.debug.conf").read_text(encoding="ascii")
        self.assertIn("mcp_server=58991", emulator_config)
        self.assertIn("DEBUGBOX MAIN.EXE -k", emulator_config)
        self.assertIn("-t cdrom -ro", emulator_config)

    def test_mcp_capture_uses_documented_request_framing(self):
        from tools.dosboxx_oracle.mcp_capture import execute
        client, server = socket.socketpair()
        def peer():
            request = server.recv(256)
            self.assertEqual(request, b"REQ 17 EXEC CPU\n")
            server.sendall(b"BEGIN 17 OK\nCPU snapshot\nEND 17\n")
        thread = threading.Thread(target=peer)
        thread.start()
        try:
            response = execute(client, 17, "CPU")
        finally:
            client.close()
            server.close()
            thread.join()
        self.assertIn("CPU snapshot", response)
        self.assertIn("END 17", response)

    def test_mcp_break_uses_break_verb_and_ignores_stale_capture(self):
        from tools.dosboxx_oracle.mcp_capture import execute
        client, server = socket.socketpair()
        def peer():
            request = server.recv(256)
            self.assertEqual(request, b"REQ 19 BREAK\n")
            server.sendall(b"BEGIN 18 OK\nold capture\nEND 18\nBEGIN 19 OK\npaused\nEND 19\n")
        thread = threading.Thread(target=peer)
        thread.start()
        try:
            response = execute(client, 19, "BREAK")
        finally:
            client.close()
            server.close()
            thread.join()
        self.assertIn("BEGIN 19 OK", response)
        self.assertIn("paused", response)
        self.assertNotIn("old capture", response)


    def test_first_palette_io_probe_is_observational_and_persisted(self):
        patch = (ROOT / "tools/dosboxx_oracle/patches/first_vga_palette_event.patch").read_text(encoding="ascii")
        source = (ROOT / "third_party/dosbox-x/src/hardware/iohandler.cpp").read_text(encoding="utf-8")
        hook = self.manifest["video_frontier"]["palette_observation_hook"]
        self.assertEqual(hook["marker"], "W3_FIRST_VGA_PALETTE_WRITE")
        self.assertIn(hook["marker"], patch)
        self.assertIn(hook["marker"], source)
        self.assertIn("the regular I/O handler receives the same port/value", self.readme)
        for register in ("reg_eax", "reg_ebx", "reg_ecx", "reg_edx", "reg_esi", "reg_edi", "reg_ebp", "reg_esp", "reg_flags"):
            self.assertIn(register, patch)

    def test_first_observed_palette_write_is_classified_as_bios_only(self):
        video = json.loads((ROOT / "evidence/dosbox_video_frontier_work3.json").read_text(encoding="utf-8"))
        event = video["early_palette_io_observation"]
        # DOSBox-X's debug log can contain host-codepage bytes emitted by the
        # emulated DOS guest.  The marker and metadata we assert are ASCII.
        log = (ROOT / event["log"]).read_text(encoding="utf-8", errors="replace")
        self.assertIn(event["marker"], log)
        self.assertEqual(event["cs_eip"], "F000:0000C9B4")
        self.assertIn("BIOS initialization", event["classification"])
        self.assertIsNone(video["first_video_event"])
        self.assertFalse(video["menu_proven"])

    def test_observed_system_int10_is_not_misreported_as_game_vesa(self):
        video = json.loads((ROOT / "evidence/dosbox_video_frontier_work3.json").read_text(encoding="utf-8"))
        event = video["observed_system_int10"]
        self.assertEqual(event["instruction_bytes"], "CD10")
        self.assertEqual(event["ah"], "0x0E")
        self.assertEqual(event["cs_eip"], "F000:DA60")
        self.assertIn("not a GeneWars/VESA", event["classification"])
        self.assertIsNone(event["first_game_vbe_request"])
        self.assertIsNone(event["first_mode_set"])

    def test_cd_dosbox_ah4c_is_not_equated_with_unicorn_no_cd_branch(self):
        oracle = json.loads((ROOT / "evidence/dosbox_setup_game_oracle_work3.json").read_text(encoding="utf-8"))
        event = oracle["process_exit"]["dosbox_cd_guest_exit_capture"]
        self.assertEqual(event["registers"]["ax"], "0x4C00")
        self.assertEqual(event["registers"]["cs"], "0x0812")
        self.assertEqual(event["cr0"], "0x10 (real mode)")
        self.assertIsNone(event["host_process_exit_code"])
        self.assertFalse(event["menu_proven"])
        self.assertIn("do not equate", oracle["process_exit"]["dosbox_comparison"])

if __name__ == "__main__":
    unittest.main()
