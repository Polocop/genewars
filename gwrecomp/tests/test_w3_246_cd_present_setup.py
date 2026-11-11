import hashlib
import unittest
from pathlib import Path

from tools.w3_243_profile import resolve_profile_root


ROOT = Path(__file__).resolve().parents[1]
CUE = Path(r"E:\GeneWarsFX\evidence\original_disc\Genewars (Europe) (En,Fr,De,Es,It,Sv).cue")
EXPECTED_CUE = "1d417e3aed625d4f054b51054a1211562a19cd4f712b08e7846613517228a5b5"


class W3246CdPresentSetupTests(unittest.TestCase):
    def test_original_cue_fingerprint_is_exact(self):
        self.assertTrue(CUE.is_file())
        self.assertEqual(hashlib.sha256(CUE.read_bytes()).hexdigest(), EXPECTED_CUE)

    def test_profile_override_is_required_to_stay_under_vhdx(self):
        source = (ROOT / "tests/probe_cd_present_gate_work3.py").read_text(encoding="utf-8")
        self.assertIn("GWRECOMP_W3_246_PROFILE_ROOT", source)
        self.assertIn("resolve_profile_root", source)
        with self.assertRaises(ValueError):
            resolve_profile_root(ROOT, str(ROOT / "build/dos_user_profile_w2_036"), ROOT / "build/dosboxx_oracle/C")


if __name__ == "__main__":
    unittest.main()
