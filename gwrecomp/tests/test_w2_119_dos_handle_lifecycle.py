"""Synthetic DOS standard-handle close/reuse regression for W2-119."""
import os as _gw_os
from pathlib import Path as _GwPath
_GW_MSYS2=_gw_os.environ.get("MSYS2_ROOT",r"C:\msys64")

import hashlib
import json
import os
import pathlib
import re
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
BUILD = ROOT / "build"
SOURCE = ROOT / "tests" / "test_w2_119_dos_handle_lifecycle.c"
EXE = BUILD / "test_w2_119_dos_handle_lifecycle.exe"
LEGACY_SOURCE = ROOT / "tests" / "test_dos_ax4400_runtime_work2.c"
FIXTURE = ROOT / "tests" / "fixtures" / "w3_067_functional_config.ini"
RUNTIME_C = ROOT / "runtime" / "gw_dos_services.c"
RUNTIME_H = ROOT / "runtime" / "gw_dos_services.h"
RECOVERY = ROOT / "evidence" / "w2_119_runtime_recovery_manifest.json"
NATIVE = ROOT / "evidence" / "native_gwerr_lifecycle_w1_077.json"
ORIGINAL = ROOT / "evidence" / "w3_227_ah44_divergence_chronology.json"
EVIDENCE = ROOT / "evidence" / "w2_119_dos_handle_lifecycle.json"
GCC = pathlib.Path((_GW_MSYS2 + '\\mingw32\\bin\\gcc.exe'))


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compiler_env():
    cache = ROOT / "cache"
    cache.mkdir(exist_ok=True)
    return {
        **os.environ,
        "PYTHONDONTWRITEBYTECODE": "1",
        "TEMP": str(cache),
        "TMP": str(cache),
        "TMPDIR": str(cache),
        "PATH": (_GW_MSYS2 + '\\mingw32\\bin;' + _GW_MSYS2 + '\\usr\\bin;') + os.environ.get("PATH", ""),
    }


def validate_recovery_manifest():
    manifest = json.loads(RECOVERY.read_text(encoding="utf-8-sig"))
    if manifest["task"] != "W2-119" or not manifest["verification"]["all_hashes_match"]:
        raise AssertionError("W2-119 recovery manifest is not verified")
    for item in manifest["files"]:
        backup = pathlib.Path(item["backup"])
        restored = pathlib.Path(item["restore_test"])
        if not item["hashes_match"]:
            raise AssertionError("Recovery manifest contains an unverified file")
        if sha256(pathlib.Path(item["source"])) != item["current_sha256_after_change"]:
            raise AssertionError("Runtime source changed since the manifest fingerprint")
        if sha256(backup) != item["backup_sha256"] or sha256(backup) != item["source_sha256"]:
            raise AssertionError(f"Runtime recovery copy mismatch: {backup}")
        if sha256(restored) != item["restored_sha256"] or sha256(restored) != item["source_sha256"]:
            raise AssertionError(f"Isolated restore mismatch: {restored}")
    return manifest


def compile_c(source, exe):
    command = [
        str(GCC), "-std=gnu11", "-m32", "-O0",
        "-I", str(ROOT / "runtime"),
        "-I", str(ROOT / "third_party" / "pcrecomp" / "runtime" / "recomp32"),
        str(source), str(RUNTIME_C), str(ROOT / "runtime" / "gw_segments.c"),
        str(ROOT / "runtime" / "gw_interrupts.c"), "-o", str(exe),
    ]
    result = subprocess.run(command, cwd=ROOT, env=compiler_env(), text=True,
                            capture_output=True)
    if result.returncode:
        raise AssertionError(f"C Runtime compile failed:\n{result.stdout}\n{result.stderr}")


def run_harness(exe, *args):
    result = subprocess.run([str(exe), *map(str, args)], cwd=ROOT, env=compiler_env(), text=True,
                            capture_output=True)
    if result.returncode:
        raise AssertionError(f"C Runtime harness failed ({result.returncode}):\n"
                             f"{result.stdout}\n{result.stderr}")
    return result.stdout.strip()


class DosHandleLifecycle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.recovery = validate_recovery_manifest()
        BUILD.mkdir(exist_ok=True)
        compile_c(SOURCE, EXE)
        cls.output = run_harness(EXE)
        # Keep the earlier regular-file IOCTL lifecycle regression in the loop.
        with tempfile.TemporaryDirectory(prefix="w2_119_legacy_", dir=ROOT / "cache") as td:
            legacy_exe = pathlib.Path(td) / "test_dos_ax4400_runtime_work2.exe"
            compile_c(LEGACY_SOURCE, legacy_exe)
            cls.legacy_output = run_harness(legacy_exe, FIXTURE)

        native = json.loads(NATIVE.read_text(encoding="utf-8"))
        original = json.loads(ORIGINAL.read_text(encoding="utf-8"))
        assert original["provenance"]["target_hashes_match"] is True
        assert original["provenance"]["original_target_sha256"] == native["target_sha256"]
        native_lines = native["stdout"]["selected_lines"]
        close_line = next(line for line in native_lines
                          if line.startswith("W1_CRT_DOS_AH3E_FILE eax_in=00003e02"))
        open_line = next(line for line in native_lines
                         if "kind=open" in line and "path_hex=67772e657272" in line)
        assert re.search(r"eax_out=00000006 .*carry=1 handled=1", close_line)
        original_lifecycle = original["original_sequence"]["lifecycle_before_ordinal6"]
        original_close = next(event for event in original_lifecycle
                              if event["event"] == "dos_handle_close" and event["entry"] == 2)
        original_open = next(event for event in original_lifecycle
                             if event["event"] == "dos_handle_open" and event["entry"] == 2)
        assert original_close["path"] == "CON"
        assert original_open["path"] == "GENEWARS\\GW.ERR"
        assert original["original_sequence"]["GW_ERR_open_precedes_ordinal6"] is True
        assert "PASS DOS handle lifecycle" in cls.output

        evidence = {
            "schema": "gwrecomp.w2-119-dos-handle-lifecycle/v1",
            "task": "W2-119",
            "classification": "SYNTHETIC_PASS",
            "original_observation": {
                "evidence": "evidence/w3_227_ah44_divergence_chronology.json",
                "target_sha256": original["provenance"]["original_target_sha256"],
                "process_psp": original_close["process_psp"],
                "close": original_close,
                "subsequent_open": original_open,
                "ax4400_ordinal6_bx": original["original_sequence"]["ordinal6"]["BX"],
            },
            "native_runtime_observation": {
                "evidence": "evidence/native_gwerr_lifecycle_w1_077.json",
                "close_request_response": close_line,
                "gwerr_open_request": open_line,
                "target_sha256": native["target_sha256"],
                "command_tail": native["command_tail"],
            },
            "synthetic_runtime": {
                "output": cls.output,
                "legacy_ax4400_regression": cls.legacy_output,
                "runtime_c_sha256": sha256(RUNTIME_C),
                "runtime_h_sha256": sha256(RUNTIME_H),
                "test_c_sha256": sha256(SOURCE),
                "test_exe_sha256": sha256(EXE),
            },
            "recovery_manifest": "evidence/w2_119_runtime_recovery_manifest.json",
            "causality_claimed": False,
            "same_invocation_equivalence_claimed": False,
            "qualification": (
                "W3-227 original and W1-077 native are separate captures. The original closes JFT entry 2/CON "
                "then opens GW.ERR into entry 2; the native Runtime returns AX=6/CF=1 for AH=3E/BX=2. "
                "The synthetic C test verifies generic close and reuse semantics, not why the later AX=4400 "
                "handle sequence differs."
            ),
        }
        EVIDENCE.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")

    def test_standard_handle_close_and_low_handle_reuse(self):
        self.assertIn("close std handle", self.output)
        self.assertIn("reuse low handle", self.output)

    def test_virtual_file_operations_route_by_active_handle(self):
        self.assertIn("read/write/seek/IOCTL/create/close", self.output)

    def test_prior_regular_file_ioctl_regression_remains_green(self):
        self.assertIn("DOS_AX4400_C_RUNTIME_TEST pass=1", self.legacy_output)

    def test_evidence_keeps_original_native_and_synthetic_separate(self):
        evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
        self.assertEqual(evidence["classification"], "SYNTHETIC_PASS")
        self.assertFalse(evidence["causality_claimed"])
        self.assertFalse(evidence["same_invocation_equivalence_claimed"])
        self.assertEqual(evidence["original_observation"]["subsequent_open"]["entry"], 2)
        self.assertIn("carry=1", evidence["native_runtime_observation"]["close_request_response"])


if __name__ == "__main__":
    unittest.main()
