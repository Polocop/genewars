"""Synthetic parity vectors for the standalone C PIT8254 provider."""
import os as _gw_os
from pathlib import Path as _GwPath
_GW_MSYS2=_gw_os.environ.get("MSYS2_ROOT",r"C:\msys64")
import hashlib
import json
import os
import pathlib
import subprocess
import unittest

from runtime.host_devices import PIT8254

ROOT = pathlib.Path(__file__).resolve().parents[1]
RECOVERY = ROOT / "work/recovery/W2-122-20261009"
BUILD = RECOVERY / "test_build"
EXE = BUILD / "test_w2_122_pit8254_runtime.exe"
SOURCE_C = ROOT / "tests/test_w2_122_pit8254_runtime.c"
RUNTIME_C = ROOT / "runtime/gw_pit8254.c"
RUNTIME_H = ROOT / "runtime/gw_pit8254.h"
PYTHON_REFERENCE = ROOT / "runtime/host_devices.py"
RECOVERY_MANIFEST = RECOVERY / "recovery_manifest.json"
EVIDENCE = ROOT / "evidence/w2_122_pit8254_runtime.json"
REPORT = ROOT / "reports/coordination/w2_122_pit8254_runtime.md"
GCC = pathlib.Path((_GW_MSYS2 + '\\mingw32\\bin\\gcc.exe'))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reference_vectors():
    pit = PIT8254()
    assert pit.write(0x43, 0x00)
    poll = (pit.read(0x40), pit.read(0x40))

    assert pit.write(0x43, 0x34)
    assert pit.write(0x40, 0x34) and pit.write(0x40, 0x12)
    pit.advance(1)
    assert pit.write(0x43, 0x00)
    latched = (pit.read(0x40), pit.read(0x40))

    # Channel 1 low-byte-only reload with periodic mode and two elapsed cycles.
    assert pit.write(0x43, 0x56)
    assert pit.write(0x41, 9)
    pit.advance(2)
    channel1 = pit.read(0x41)

    # Channel 2 low/high periodic reload exercises the second byte lane.
    assert pit.write(0x43, 0xB4)
    assert pit.write(0x42, 100) and pit.write(0x42, 0)
    pit.advance(3)
    channel2 = (pit.read(0x42), pit.read(0x42))
    return {
        "poll": poll,
        "latched": latched,
        "channel1": (channel1,),
        "channel2": channel2,
    }


def runtime_env():
    cache = ROOT / "cache"
    cache.mkdir(exist_ok=True)
    return {
        **os.environ,
        "TEMP": str(cache),
        "TMP": str(cache),
        "TMPDIR": str(cache),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PATH": (_GW_MSYS2 + '\\mingw32\\bin;' + _GW_MSYS2 + '\\usr\\bin;') + os.environ.get("PATH", ""),
    }


class Pit8254RuntimeTests(unittest.TestCase):
    def test_c_provider_matches_python_reference_vectors(self):
        self.assertTrue(RECOVERY_MANIFEST.is_file())
        self.assertTrue(GCC.is_file(), f"C compiler not found: {GCC}")
        BUILD.mkdir(parents=True, exist_ok=True)
        command = [
            str(GCC), "-std=c11", "-Wall", "-Wextra", "-Werror", "-O0",
            "-o", str(EXE), str(SOURCE_C), str(RUNTIME_C),
        ]
        built = subprocess.run(command, cwd=ROOT, env=runtime_env(), text=True,
                               capture_output=True)
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        ran = subprocess.run([str(EXE)], cwd=ROOT, env=runtime_env(), text=True,
                             capture_output=True)
        self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
        actual = {}
        for line in ran.stdout.splitlines():
            if "=" not in line:
                continue
            key, values = line.split("=", 1)
            actual[key] = tuple(int(value, 16) for value in values.split(","))
        expected = reference_vectors()
        self.assertEqual(actual, expected)
        self.assertIn("PASS synthetic C PIT8254", ran.stdout)

        EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
        REPORT.parent.mkdir(parents=True, exist_ok=True)
        evidence = {
            "schema": "gwrecomp.w2-122-pit8254-runtime/v1",
            "task": "W2-122",
            "execution_kind": "SYNTHETIC_PASS",
            "command": command,
            "compile_exit": built.returncode,
            "run_exit": ran.returncode,
            "output": ran.stdout.strip(),
            "synthetic_c_values": {key: list(value) for key, value in actual.items()},
            "python_reference_values": {key: list(value) for key, value in expected.items()},
            "original_evidence": {
                "path": "evidence/w3_270_post_present_static_frontier.json",
                "classification": "STATIC_ONLY instruction bytes after an ORIGINAL_OBSERVED post-present checkpoint",
                "link_va": "0x000C427E",
                "bytes": "e44088c4e44086c425ffff000089c63b1574b9000075ddb9e80300008b1d1048",
                "port_sequence": ["OUT 0x43, AL", "IN AL, 0x40", "IN AL, 0x40"],
                "original_port_values_observed": False,
                "function_boundary_proven": False,
                "native_reachability_proven": False,
            },
            "fingerprints": {
                "runtime_c_sha256": sha(RUNTIME_C),
                "runtime_h_sha256": sha(RUNTIME_H),
                "python_reference_sha256": sha(PYTHON_REFERENCE),
                "test_c_sha256": sha(SOURCE_C),
                "test_py_sha256": sha(pathlib.Path(__file__)),
                "test_exe_sha256": sha(EXE),
                "recovery_manifest_sha256": sha(RECOVERY_MANIFEST),
            },
            "claims": {
                "python_contract_vectors_match": True,
                "original_timer_values_match": False,
                "native_replay_reached_post_present_poll": False,
                "menu_verified": False,
                "gameplay_verified": False,
            },
        }
        EVIDENCE.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
        report = (
            "# W2-122 — deterministic C PIT8254 provider\n\n"
            "Status: synthetic provider vectors pass. The new C provider matches the existing "
            "Python PIT model for the registered channel/latch/reload vectors and keeps state "
            "per instance with explicit virtual cycles.\n\n"
            "W3-270 identifies `OUT 0x43, AL` and two reads from `0x40` at link VA `0xC427E` "
            "in static-only bytes following an original post-present checkpoint. Original port "
            "values, containing function boundary, and native reachability remain unknown. The "
            "synthetic zero/default poll values are not presented as original responses.\n\n"
            "WORK1 must connect generated IN/OUT instructions to this provider and supply guest "
            "cycle advancement before a native replay can exercise it. No replay was run; this "
            "task does not claim menu or gameplay.\n"
        )
        REPORT.write_text(report, encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
