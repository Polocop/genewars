"""Regression for native CONFIG.INI dispatch through DOS handle table mappings."""
import hashlib
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

class ConfigReadMappingTests(unittest.TestCase):
    def test_handler_resolves_guest_handle_by_dos_handle_and_owner(self):
        source = (ROOT / "tests/test_native_guest_image.c").read_text(encoding="utf-8")
        self.assertIn("entry->dos_handle==handle", source)
        self.assertIn("entry->active && entry->dos_handle==handle && entry->file", source)
        self.assertIn("((native_virtual_open *)entry->file)->owner==&native_w3_config_file", source)
        self.assertIn("if (vector==0x21u && (uint8_t)(g_eax>>8)==0x3Fu)", source)
        self.assertNotIn("if (saw_native_w3_config_open && vector==0x21u", source)
        self.assertIn("native_w3_config_handle_active(services,req_ebx)", source)
        runner = (ROOT / "tests/test_native_guest_image.py").read_text(encoding="utf-8")
        self.assertIn("args.w1_077_native_handle_lifecycle and args.w1_080_native_ax4400_active_file", runner)
        self.assertIn("args.w1_081_native_ah40_active_file", runner)
        self.assertIn('"schema":"gwrecomp.native-setup-replay/v1" if w1_083_setup_capture', runner)
        self.assertIn('"evidence_level":"DIFF_VERIFIED" if w1_083_setup_capture', runner)
        self.assertIn("services->files[i].dos_handle!=req_ebx", source)

    def test_recovery_manifest_proves_isolated_restoration(self):
        manifest = json.loads((ROOT / "work/recovery/W1-083/manifest.json").read_text(encoding="utf-8"))
        verification = json.loads((ROOT / "work/recovery/W1-083/verification.json").read_text(encoding="utf-8"))
        self.assertTrue(manifest["verification"]["all_hashes_match"])
        self.assertTrue(manifest["verification"]["restore_was_isolated"])
        self.assertTrue(verification["production_files_modified_during_recovery_check"] is False)
        for item in manifest["files"]:
            self.assertEqual(item["source_sha256"], item["backup_sha256"])
            self.assertEqual(item["source_sha256"], item["restored_sha256"])

if __name__ == "__main__":
    unittest.main()
