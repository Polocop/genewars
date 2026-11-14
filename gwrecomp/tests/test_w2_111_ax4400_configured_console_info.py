"""Synthetic regression for provider-backed standard-stream AX=4400 metadata."""
import os as _gw_os
from pathlib import Path as _GwPath
_GW_MSYS2=_gw_os.environ.get("MSYS2_ROOT",r"C:\msys64")

import hashlib
import json
import os
import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
BUILD = ROOT / "build"
SOURCE = ROOT / "tests" / "test_w2_111_ax4400_configured_console_info.c"
EXE = BUILD / "test_w2_111_ax4400_configured_console_info.exe"
LEGACY_SOURCE = ROOT / "tests" / "test_dos_ax4400_runtime_work2.c"
FIXTURE = ROOT / "tests" / "fixtures" / "w3_067_functional_config.ini"
RUNTIME_C = ROOT / "runtime" / "gw_dos_services.c"
RUNTIME_H = ROOT / "runtime" / "gw_dos_services.h"
W3_091 = ROOT / "evidence" / "w3_091_ah4400_bx1_caller.json"
W3_093 = ROOT / "evidence" / "w3_093_ds_edx_sample.json"
W1_055 = ROOT / "evidence" / "native_stream_object_sample_work1.json"
W2_110 = ROOT / "evidence" / "w2_110_ax4400_stream_classification.json"
EVIDENCE = ROOT / "evidence" / "w2_111_ax4400_stream_metadata.json"
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
    result = subprocess.run([str(exe), *map(str, args)], cwd=ROOT, env=compiler_env(),
                            text=True, capture_output=True)
    if result.returncode:
        raise AssertionError(f"C Runtime harness failed ({result.returncode}):\n"
                             f"{result.stdout}\n{result.stderr}")
    return result.stdout.strip()


class Ax4400ConfiguredConsoleInfo(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        BUILD.mkdir(exist_ok=True)
        compile_c(SOURCE, EXE)
        cls.stdout = run_harness(EXE)
        # Re-run the existing regular-file AX=4400 lifecycle harness from an
        # isolated temporary output path; it verifies file metadata is unchanged.
        with tempfile.TemporaryDirectory(prefix="w2_111_file_test_", dir=ROOT / "cache") as td:
            file_exe = pathlib.Path(td) / "test_dos_ax4400_runtime_work2.exe"
            compile_c(LEGACY_SOURCE, file_exe)
            cls.file_stdout = run_harness(file_exe, FIXTURE)

        original = json.loads(W3_091.read_text(encoding="utf-8"))
        sample = json.loads(W3_093.read_text(encoding="utf-8"))
        native = json.loads(W1_055.read_text(encoding="utf-8"))
        prior = json.loads(W2_110.read_text(encoding="utf-8"))
        contract = original["verified_contract"]
        assert contract["native_site_match"] is True
        assert contract["caller"]["link_va_of_int_instruction"] == "0xc8973"
        assert contract["request"] == {"ax": "0x4400", "bx": "0x1", "cx": "0x0",
                                        "dx": "0x4822", "eflags": "0x246"}
        assert contract["response"]["ax"] == "0x80d3"
        assert contract["response"]["dx"] == "0x80d3"
        assert contract["response"]["cf"] is False
        assert sample["contract"]["sample"]["dword_at_plus_0x10"] == "0x1"
        assert prior["configured_character_stream"]["ax_out"] == "0x0082"
        assert prior["original_comparison"]["original_equivalence_claimed"] is False

        evidence = {
            "schema": "gwrecomp.w2-111-ax4400-stream-metadata/v1",
            "task": "W2-111",
            "classification": "SYNTHETIC_PASS",
            "runtime_changed": True,
            "replay_run": False,
            "original_observation": {
                "evidence": "evidence/w3_091_ah4400_bx1_caller.json",
                "link_va": contract["caller"]["link_va_of_int_instruction"],
                "request": contract["request"],
                "response": contract["response"],
                "handle_type": contract["dos_context"]["resolved_path"],
                "cwd": contract["dos_context"]["cwd"],
                "native_site_match": contract["native_site_match"],
            },
            "context_sample": {
                "evidence": "evidence/w3_093_ds_edx_sample.json",
                "dword_at_plus_0x10": sample["contract"]["sample"]["dword_at_plus_0x10"],
                "object_identity_across_runs": sample["contract"]["comparison"]["same_dynamic_stream_object"],
                "launch_seed_equivalence": sample["contract"]["comparison"]["launch_and_seed_equivalence"],
            },
            "synthetic_callback": {
                "output": cls.stdout,
                "configured_info_word": "0x80D3",
                "legacy_regular_file_regression": cls.file_stdout,
                "original_equivalence_claimed": False,
            },
            "prior_synthetic_default": {
                "evidence": "evidence/w2_110_ax4400_stream_classification.json",
                "output_word": prior["configured_character_stream"]["ax_out"],
                "classification": "SYNTHETIC_PASS",
            },
            "fingerprints": {
                "runtime_c_sha256": sha256(RUNTIME_C),
                "runtime_h_sha256": sha256(RUNTIME_H),
                "test_c_sha256": sha256(SOURCE),
                "test_exe_sha256": sha256(EXE),
                "w3_091_sha256": sha256(W3_091),
                "w3_093_sha256": sha256(W3_093),
                "w1_055_sha256": sha256(W1_055),
                "w2_110_sha256": sha256(W2_110),
            },
            "qualification": (
                "Original response is measured at the same exact link VA and handle 1/CON. "
                "The Runtime test injects the measured info word through a generic stream-provider "
                "API; no replay, same-object identity, launch-seed equivalence, or whole-run parity is claimed."
            ),
        }
        EVIDENCE.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")

    def test_measured_console_word_is_provider_backed_and_register_safe(self):
        self.assertIn("AX/DX=0x80D3 CF=0", self.stdout)
        self.assertIn("invalid metadata rejected", self.stdout)
        self.assertIn("redirected stream trapped unchanged", self.stdout)

    def test_regular_virtual_file_metadata_regression_remains_green(self):
        self.assertIn("DOS_AX4400_C_RUNTIME_TEST pass=1", self.file_stdout)
        self.assertIn("created_empty_ax_dx=0002", self.file_stdout)
        self.assertIn("host_fs_provider_calls=0", self.file_stdout)

    def test_evidence_keeps_original_and_synthetic_results_separate(self):
        evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
        self.assertEqual(evidence["original_observation"]["response"]["dx"], "0x80d3")
        self.assertEqual(evidence["synthetic_callback"]["configured_info_word"], "0x80D3")
        self.assertFalse(evidence["synthetic_callback"]["original_equivalence_claimed"])
        self.assertIsNone(evidence["context_sample"]["object_identity_across_runs"])


if __name__ == "__main__":
    unittest.main()
