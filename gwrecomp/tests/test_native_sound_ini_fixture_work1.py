"""Provenance and bounded-provider regression for W1-051."""
import hashlib
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
EXPECTED = "339a99f3fac46182dc52bec753c7122a7fcb1e3cf762e79d6693a9461c8cb9c3"


class SoundIniFixtureTests(unittest.TestCase):
    def test_fixture_matches_authenticated_source_and_original_contract(self):
        fixture = ROOT / "tests/fixtures/w3_069_sound_ini_work1.bin"
        source = ROOT / "build/dosboxx_oracle/C/GENEWARS/SOUND.INI"
        w2 = json.loads((ROOT / "evidence/native_dos_ah43_sound_ini_work2.json").read_text())
        w3 = json.loads((ROOT / "evidence/w3_069_original_ah43_sound_ini.json").read_text())
        self.assertEqual(fixture.read_bytes(), source.read_bytes())
        self.assertEqual(len(fixture.read_bytes()), 11)
        self.assertEqual(hashlib.sha256(fixture.read_bytes()).hexdigest(), EXPECTED)
        self.assertEqual(w2["fixture"]["sha256"], EXPECTED)
        self.assertEqual(w2["original"]["response_ax"], "0x0020")
        self.assertEqual(w2["original"]["response_cx"], "0x0020")
        self.assertEqual(w2["original"]["caller_link_va"], "UNKNOWN")
        self.assertEqual(w3["schema"], "w3-069-original-ah43/v1")
        caller = json.loads((ROOT / "evidence/w3_077_int21_caller_capture.json").read_text())
        self.assertTrue(any(x.get("int_instruction_link_va_candidate", "").lower()=="0xaf93a"
                            and x.get("matches_w1_frontier") for x in caller["sound_ini_callers"]))

    def test_fixture_is_read_only_exact_allowlist_not_host_fallback(self):
        source = (ROOT / "tests/test_native_guest_image.c").read_text()
        self.assertIn('sound.ini")==0', source)
        self.assertIn('if (access_mode!=0u) return 5u;\n        owner=&native_w3_sound_ini_file;', source)
        self.assertIn('provider=bounded-memory fixture=tests/fixtures/w3_069_sound_ini_work1.bin', source)

    def test_evidence_validator_accepts_only_actual_runtime_contract(self):
        from tools.verify_native_sound_ini_w1_051 import verify
        path = ROOT / "evidence/native_sound_ini_replay_w1_051.json"
        self.assertTrue(path.exists(), "fresh W1-051 replay evidence is required")
        self.assertTrue(verify(path)["passed"])


if __name__ == "__main__":
    unittest.main()
