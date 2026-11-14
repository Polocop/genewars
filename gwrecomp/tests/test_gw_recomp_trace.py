"""Check call history survives branch-heavy guest cleanup paths."""
import os as _gw_os
from pathlib import Path as _GwPath
_GW_MSYS2=_gw_os.environ.get("MSYS2_ROOT",r"C:\msys64")
from pathlib import Path
import os
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
GCC = Path((_GW_MSYS2 + '\\mingw32\\bin\\gcc.exe'))
ENV = {**os.environ,
       "PATH": (_GW_MSYS2 + '\\mingw32\\bin;' + _GW_MSYS2 + '\\usr\\bin;') + os.environ.get("PATH", "")}


class RecompTraceTests(unittest.TestCase):
    def test_calls_branches_and_last_dos_dpmi_are_separate(self):
        with tempfile.TemporaryDirectory(prefix="gwtrace-") as tmp:
            exe = Path(tmp) / "trace.exe"
            subprocess.run([str(GCC), "-std=c11", "-Wall", "-Wextra", "-Werror",
                "-I", str(ROOT / "runtime"), "-o", str(exe),
                str(ROOT / "tests" / "test_gw_recomp_trace.c"),
                str(ROOT / "runtime" / "gw_recomp_trace.c")],
                check=True, env=ENV, timeout=30)
            result = subprocess.run([str(exe)], check=True, capture_output=True,
                text=True, env=ENV, timeout=10)
        calls = [x for x in result.stderr.splitlines()
                 if x.startswith("TRACE guest-call-history ")]
        branches = [x for x in result.stderr.splitlines()
                    if x.startswith("TRACE guest-branch-history ")]
        controls = [x for x in result.stderr.splitlines()
                    if x.startswith("TRACE guest-control-history ")]
        self.assertEqual(len(calls), 32)
        self.assertIn("seq=9 kind=call-indirect", calls[0])
        self.assertIn("site=00070f05 caller=00070eb0 target=00098c19 return=00070f0a", calls[-1])
        self.assertEqual(len(branches), 32)
        self.assertIn("seq=68", branches[0])
        self.assertIn("seq=99", branches[-1])
        self.assertEqual(len(controls), 32)
        self.assertIn("kind=call-direct site=00070f05 caller=00070eb0 target=00098c19", controls[-1])
        self.assertRegex(result.stderr, r"last-dos .*int=21 site=00001234 .*req=00003d00/00000001")
        self.assertRegex(result.stderr, r"last-dpmi .*int=31 site=00005678 .*req=00000501/00000000/00000000/01000000 .*cf=1")


if __name__ == "__main__":
    unittest.main()
