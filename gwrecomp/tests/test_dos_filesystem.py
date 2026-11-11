import io
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime"))
from dos_filesystem import DosFileSystem, DosFsError  # noqa: E402


class DosFileSystemTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / "build", prefix="dosfs_")
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        (self.root / "GENEWARS" / "DATA").mkdir(parents=True)
        (self.root / "GENEWARS" / "DATA" / "Text.DAT").write_bytes(b"alpha\nbeta")
        self.stdout = io.BytesIO()
        self.stderr = io.BytesIO()
        self.fs = DosFileSystem(self.root, stdout=self.stdout, stderr=self.stderr)

    def test_dos_absolute_relative_and_case_insensitive_paths(self):
        self.assertTrue(self.fs.access(r"c:\genewars\data\text.dat"))
        self.assertEqual(self.fs.resolve(r"DATA\TEXT.dat"), self.root / "GENEWARS" / "DATA" / "Text.DAT")

    def test_traversal_and_other_drive_are_rejected(self):
        with self.assertRaises(DosFsError) as ctx:
            self.fs.resolve(r"C:\..\outside.txt")
        self.assertEqual(ctx.exception.dos_code, DosFileSystem.ERR_ACCESS_DENIED)
        with self.assertRaises(DosFsError) as ctx:
            self.fs.resolve(r"D:\GENEWARS\DATA\TEXT.DAT")
        self.assertEqual(ctx.exception.dos_code, DosFileSystem.ERR_INVALID_DRIVE)

    def test_symlink_cannot_escape_virtual_root(self):
        outside = self.root.parent / (self.root.name + "_outside")
        outside.write_bytes(b"secret")
        self.addCleanup(lambda: outside.unlink(missing_ok=True))
        link = self.root / "GENEWARS" / "escape.txt"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation unavailable")
        self.assertFalse(self.fs.access(r"C:\GENEWARS\escape.txt"))

    def test_open_read_seek_and_close(self):
        h = self.fs.open(r"C:\GENEWARS\DATA\TEXT.DAT")
        self.assertEqual(self.fs.read(h, 5), b"alpha")
        self.assertEqual(self.fs.seek(h, 6), 6)
        self.assertEqual(self.fs.read(h, 4), b"beta")
        self.fs.close(h)
        with self.assertRaises(DosFsError) as ctx:
            self.fs.read(h, 1)
        self.assertEqual(ctx.exception.dos_code, DosFileSystem.ERR_INVALID_HANDLE)

    def test_create_write_read_and_access_trace(self):
        h = self.fs.open(r"slot1.dat", access="w", create=True)
        self.assertEqual(self.fs.write(h, b"save"), 4)
        self.fs.close(h)
        self.assertTrue((self.root / "GENEWARS" / "slot1.dat").exists())
        self.assertTrue(self.fs.access(r"SLOT1.DAT"))
        self.assertGreaterEqual(len(self.fs.attempts), 4)


    def test_user_overlay_seeds_empty_config_and_shadows_reference_writes(self):
        overlay = self.root / "user-profile"
        fs = DosFileSystem(self.root, overlay_root=overlay)
        config = fs.seed_empty_file(r"C:\GENEWARS\config.ini")
        self.assertEqual(config, overlay / "GENEWARS" / "config.ini")
        self.assertTrue(config.exists())
        self.assertEqual(config.read_bytes(), b"")
        self.assertFalse((self.root / "GENEWARS" / "config.ini").exists())
        again = fs.seed_empty_file(r"config.ini")
        self.assertEqual(again, config)
        h = fs.open(r"DATA\TEXT.DAT", access="w")
        self.assertEqual(fs.write(h, b"GAMMA"), 5)
        fs.close(h)
        self.assertEqual((self.root / "GENEWARS" / "DATA" / "Text.DAT").read_bytes(), b"alpha\nbeta")
        self.assertEqual((overlay / "GENEWARS" / "DATA" / "Text.DAT").read_bytes(), b"GAMMA\nbeta")

    def test_standard_handles_are_explicit(self):
        self.assertEqual(set((0, 1, 2)).intersection(self.fs.handles), {0, 1, 2})
        self.assertEqual(self.fs.write(1, b"out"), 3)
        self.assertEqual(self.stdout.getvalue(), b"out")
        self.fs.write(2, b"err")
        self.assertEqual(self.stderr.getvalue(), b"err")
        self.fs.handles[0].stream = io.BytesIO(b"in")
        self.assertEqual(self.fs.read(0, 2), b"in")

    def test_missing_file_has_dos_error_and_trace(self):
        with self.assertRaises(DosFsError) as ctx:
            self.fs.open(r"C:\GENEWARS\missing.dat")
        self.assertEqual(ctx.exception.dos_code, DosFileSystem.ERR_FILE_NOT_FOUND)
        self.assertEqual(self.fs.attempts[-1]["error"], DosFileSystem.ERR_FILE_NOT_FOUND)


if __name__ == "__main__":
    unittest.main()




