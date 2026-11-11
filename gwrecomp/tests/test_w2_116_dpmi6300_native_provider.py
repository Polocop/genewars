"""Compile and execute the bounded native DPMI AX=0300 / DOS AX=6300 test."""
import os
import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
GCC = pathlib.Path(r"E:\msys64\mingw32\bin\gcc.exe")
EXE = ROOT / "build" / "test_w2_116_dpmi6300_native_provider.exe"


class NativeDbcsProviderTests(unittest.TestCase):
    def test_native_real_mode_dbcs_table_provider(self):
        self.assertTrue(GCC.is_file(), f"missing bounded C compiler: {GCC}")
        env = {
            **os.environ,
            "TEMP": str(ROOT / "cache"),
            "TMP": str(ROOT / "cache"),
            "TMPDIR": str(ROOT / "cache"),
            "PATH": str(GCC.parent) + ";E:\\msys64\\usr\\bin;" + os.environ.get("PATH", ""),
        }
        command = [
            str(GCC), "-std=gnu11", "-m32", "-O0",
            "-I", str(ROOT / "runtime"),
            "-I", str(ROOT / "third_party" / "pcrecomp" / "runtime" / "recomp32"),
            "-o", str(EXE),
            str(ROOT / "tests" / "test_w2_116_dpmi6300_native_provider.c"),
            str(ROOT / "runtime" / "gw_segments.c"),
            str(ROOT / "runtime" / "gw_interrupts.c"),
            str(ROOT / "runtime" / "gw_dos_services.c"),
        ]
        built = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True)
        self.assertEqual(built.returncode, 0, built.stdout + "\n" + built.stderr)
        ran = subprocess.run([str(EXE)], cwd=ROOT, env=env, text=True, capture_output=True)
        self.assertEqual(ran.returncode, 0, ran.stdout + "\n" + ran.stderr)
        self.assertIn("PASS bounded native DPMI AX=0300 / INT 21h AX=6300 DBCS provider", ran.stdout)


if __name__ == "__main__":
    unittest.main()
