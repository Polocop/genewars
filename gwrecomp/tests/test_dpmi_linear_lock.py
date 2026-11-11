"""Focused C-provider regression for DPMI linear lock/unlock calls."""
import os
import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class DpmiLinearLockTests(unittest.TestCase):
    def test_no_paging_host_lock_contract(self):
        compiler = pathlib.Path(r"E:\msys64\mingw32\bin\gcc.exe")
        executable = ROOT / "build" / "test_dpmi_linear_lock.exe"
        env = {
            **os.environ,
            "TEMP": str(ROOT / "cache"), "TMP": str(ROOT / "cache"),
            "TMPDIR": str(ROOT / "cache"),
            "PATH": r"E:\msys64\mingw32\bin;E:\msys64\usr\bin;" + os.environ.get("PATH", ""),
        }
        command = [str(compiler), "-std=gnu11", "-m32", "-O0",
                   "-I", str(ROOT / "runtime"),
                   "-I", str(ROOT / "third_party" / "pcrecomp" / "runtime" / "recomp32"),
                   "-o", str(executable), str(ROOT / "tests" / "test_dpmi_linear_lock.c"),
                   str(ROOT / "runtime" / "gw_segments.c"),
                   str(ROOT / "runtime" / "gw_interrupts.c"),
                   str(ROOT / "runtime" / "gw_dos_services.c")]
        compiled = subprocess.run(command, cwd=ROOT, env=env, text=True,
                                  capture_output=True, check=False)
        self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
        executed = subprocess.run([str(executable)], cwd=ROOT, env=env, text=True,
                                  capture_output=True, check=False)
        self.assertEqual(executed.returncode, 0, executed.stdout + executed.stderr)
        self.assertIn("PASS DPMI AX=0600/0601", executed.stdout)


if __name__ == "__main__":
    unittest.main()
