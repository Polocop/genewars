import tempfile
import unittest
from pathlib import Path

from tools.w3_243_profile import resolve_profile_root


class W3243ProfileTests(unittest.TestCase):
    def test_accepts_new_overlay_inside_vhdx(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mount = root / "GWORACLE"
            mount.mkdir()
            result = resolve_profile_root(root, str(mount / "W3_243_PROFILE"), mount)
            self.assertEqual(result, (mount / "W3_243_PROFILE").resolve())

    def test_rejects_overlay_outside_vhdx(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mount = root / "GWORACLE"
            mount.mkdir()
            with self.assertRaises(ValueError):
                resolve_profile_root(root, str(root / "outside"), mount)

    def test_rejects_existing_overlay(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mount = root / "GWORACLE"
            existing = mount / "W3_243_PROFILE"
            existing.mkdir(parents=True)
            with self.assertRaises(FileExistsError):
                resolve_profile_root(root, str(existing), mount)


if __name__ == "__main__":
    unittest.main()
