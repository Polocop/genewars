"""SAVE-directory profiles of the build driver and of tools/rebuild/check_inputs.py.

Self-contained: uses synthetic directories and synthetic file content only (no game files, no saves).

The driver supports exactly two installation states:
  no-saves        SAVE is empty or absent (a fresh installation)
  reference-save  SAVE holds exactly SAVE0.SAV with the maintainers' reference content (regression profile)
and refuses everything else. check_inputs.py must agree with the driver on every case below.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_driver():
    spec = importlib.util.spec_from_file_location("gw_driver", ROOT / "tests" / "test_ifctitle_creature_probe.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_checker():
    spec = importlib.util.spec_from_file_location("gw_check_inputs", ROOT / "tools" / "rebuild" / "check_inputs.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SaveProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.driver = load_driver()
        cls.checker = load_checker()

    def install(self, files):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = pathlib.Path(tmp.name)
        if files is not None:
            (root / "SAVE").mkdir()
            for name, data in files.items():
                (root / "SAVE" / name).write_bytes(data)
        return root

    def driver_profile(self, root, reference_sha=None):
        old_install, old_ref = self.driver.INSTALL, self.driver.REFERENCE_SAVE0_SHA256
        self.driver.INSTALL = root
        if reference_sha: self.driver.REFERENCE_SAVE0_SHA256 = reference_sha
        try:
            return self.driver.detect_save_profile()
        finally:
            self.driver.INSTALL, self.driver.REFERENCE_SAVE0_SHA256 = old_install, old_ref

    def checker_profile(self, root, reference_sha=None):
        return self.checker.save_profile(root, reference_sha or next(f["sha256"] for f in json.loads((ROOT / "tools/rebuild/inputs.json").read_text())["install_files"] if f["path"] == "SAVE/SAVE0.SAV"))

    # ---- accepted states
    def test_empty_save_directory_is_no_saves(self):
        root = self.install({})
        self.assertEqual(self.driver_profile(root), "no-saves")
        self.assertEqual(self.checker_profile(root), "no-saves")

    def test_missing_save_directory_is_no_saves(self):
        root = self.install(None)
        self.assertEqual(self.driver_profile(root), "no-saves")
        self.assertEqual(self.checker_profile(root), "no-saves")

    def test_reference_content_is_reference_save(self):
        data = b"synthetic stand-in for a reference save"
        sha = hashlib.sha256(data).hexdigest()
        root = self.install({"SAVE0.SAV": data})
        self.assertEqual(self.driver_profile(root, sha), "reference-save")
        self.assertEqual(self.checker_profile(root, sha), "reference-save")

    # ---- refused states (must not be silently treated as no-saves)
    def refuse(self, files, reference_sha="0" * 64):
        root = self.install(files)
        with self.assertRaises(SystemExit):
            self.driver_profile(root, reference_sha)
        with self.assertRaises(SystemExit):
            self.checker_profile(root, reference_sha)

    def test_other_content_in_save0_is_refused(self):
        self.refuse({"SAVE0.SAV": b"someone else's save"})

    def test_additional_save_slot_is_refused(self):
        data = b"x"
        self.refuse({"SAVE0.SAV": data, "SAVE1.SAV": b"y"}, hashlib.sha256(data).hexdigest())

    def test_only_a_different_slot_is_refused(self):
        self.refuse({"SAVE3.SAV": b"z"})

    # ---- evidence
    def test_evidence_states_the_profile(self):
        none = self.driver.save_evidence({}, "x")["SAVE0.SAV"]
        self.assertEqual((none["present"], none["profile"]), (False, "no-saves"))
        ref = self.driver.save_evidence({"SAVE/SAVE0.SAV": {"sha256": "ab", "size": 7}}, "reader")["SAVE0.SAV"]
        self.assertEqual((ref["sha256"], ref["bytes"], ref["profile"]), ("ab", 7, "reference-save"))

    def test_reference_save_is_not_a_mandatory_resource(self):
        self.assertNotIn("SAVE/SAVE0.SAV", self.driver.TITLE_RESOURCES)

    def test_no_other_resource_check_was_removed(self):
        spec = json.loads((ROOT / "tools/rebuild/inputs.json").read_text())
        paths = {f["path"] for f in spec["install_files"]}
        for rel in list(self.driver.TITLE_RESOURCES) + list(self.driver.INTERFACE_RESOURCES):
            self.assertIn(rel, paths)
            self.assertEqual({f["path"]: f["sha256"] for f in spec["install_files"]}[rel], {**self.driver.TITLE_RESOURCES, **self.driver.INTERFACE_RESOURCES}[rel])


if __name__ == "__main__":
    unittest.main()
