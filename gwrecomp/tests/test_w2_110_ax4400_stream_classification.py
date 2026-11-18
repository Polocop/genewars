"""Synthetic C Runtime regression for configured DOS standard-stream IOCTLs."""
import os as _gw_os
from pathlib import Path as _GwPath
_GW_MSYS2=_gw_os.environ.get("MSYS2_ROOT",r"C:\msys64")

import hashlib
import json
import os
import pathlib
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
BUILD = ROOT / "build"
EXE = BUILD / "test_w2_110_ax4400_stream_classification.exe"
SOURCE = ROOT / "tests" / "test_w2_110_ax4400_stream_classification.c"
RUNTIME_C = ROOT / "runtime" / "gw_dos_services.c"
RUNTIME_H = ROOT / "runtime" / "gw_dos_services.h"
EVIDENCE = ROOT / "evidence" / "w2_110_ax4400_stream_classification.json"
GCC = pathlib.Path((_GW_MSYS2 + '\\mingw32\\bin\\gcc.exe'))


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_harness():
    BUILD.mkdir(exist_ok=True)
    cache = ROOT / "cache"
    cache.mkdir(exist_ok=True)
    env = {
        **os.environ,
        "PYTHONDONTWRITEBYTECODE": "1",
        "TEMP": str(cache),
        "TMP": str(cache),
        "TMPDIR": str(cache),
        "PATH": (_GW_MSYS2 + '\\mingw32\\bin;' + _GW_MSYS2 + '\\usr\\bin;') + os.environ.get("PATH", ""),
    }
    command = [
        str(GCC), "-std=gnu11", "-m32", "-O0",
        "-I", str(ROOT / "runtime"),
        "-I", str(ROOT / "third_party" / "pcrecomp" / "runtime" / "recomp32"),
        "-o", str(EXE), str(SOURCE),
        str(ROOT / "runtime" / "gw_dos_services.c"),
        str(ROOT / "runtime" / "gw_segments.c"),
        str(ROOT / "runtime" / "gw_interrupts.c"),
    ]
    compiled = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True)
    if compiled.returncode:
        raise AssertionError(f"C harness compile failed:\n{compiled.stdout}\n{compiled.stderr}")
    executed = subprocess.run([str(EXE)], cwd=ROOT, env=env, text=True, capture_output=True)
    if executed.returncode:
        raise AssertionError(
            f"C harness failed ({executed.returncode}):\n{executed.stdout}\n{executed.stderr}"
        )
    return executed.stdout.strip(), sha256(EXE)


class Ax4400ConfiguredStreamTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stdout, cls.exe_sha256 = run_harness()
        w3_079 = ROOT / "evidence" / "w3_079_original_ah44_bx1.json"
        w3_080 = ROOT / "evidence" / "w3_080_ah44_provenance_reconciliation.json"
        w1_051 = ROOT / "evidence" / "native_sound_ini_replay_w1_051.json"
        w2_104 = ROOT / "evidence" / "native_dos_ax4400_runtime_work2.json"
        w2_087 = ROOT / "evidence" / "native_dos_ah44_preflight_work2.json"
        a = json.loads(w3_079.read_text(encoding="utf-8"))
        b = json.loads(w3_080.read_text(encoding="utf-8"))
        c = json.loads(w1_051.read_text(encoding="utf-8"))
        evidence = {
            "schema": "gwrecomp.w2-110-ax4400-stream-classification/v1",
            "task": "W2-110",
            "classification": "SYNTHETIC_PASS",
            "execution": "direct C Runtime callback harness; no game replay or oracle",
            "request": {
                "vector": "INT 21h",
                "ax": "0x4400",
                "bx": "0x0001",
                "instruction_link_va_in_harness": "0x000C8973",
            },
            "configured_character_stream": {
                "result": "GW_INTERRUPT_HANDLED",
                "ax_out": "0x0082",
                "dx_out": "0x0082",
                "cf_out": 0,
                "unrelated_registers_and_segments_preserved": True,
            },
            "configured_redirected_stream_without_ioctl_metadata": {
                "result": "GW_INTERRUPT_TRAPPED",
                "registers_segments_and_cf_unchanged": True,
            },
            "synthetic_output": cls.stdout,
            "fingerprints": {
                "runtime_c_sha256": sha256(RUNTIME_C),
                "runtime_h_sha256": sha256(RUNTIME_H),
                "test_c_sha256": sha256(SOURCE),
                "test_exe_sha256": cls.exe_sha256,
            },
            "source_evidence": {
                str(p.relative_to(ROOT)).replace("\\", "/"): sha256(p)
                for p in (w3_079, w3_080, w1_051, w2_104, w2_087)
            },
            "original_comparison": {
                "w3_079_original_bx1_call_count": a["bx1_contract"]["original_call_count"],
                "w3_079_classification": a["classification"],
                "w3_080_classification": b["classification"],
                "historical_original_dx": b["historical_original_bx1"]["registers_after"]["edx"],
                "historical_command_tail": b["historical_original_bx1"]["command_tail"],
                "historical_cue_sha256": b["historical_original_bx1"]["cue_sha256"],
                "fresh_original_bx1_call_count": b["fresh_original_w3_079"]["bx1_call_count"],
                "w1_native_frontier": c["sound_ini_continuation"]["next_frontier_cpu"],
                "original_equivalence_claimed": False,
                "native_response_applied": False,
                "qualification": (
                    "Synthetic service behavior only. Historical DX=0x82 has no command-tail/CUE "
                    "fingerprint; the fresh W3 run had no BX=1 callback; W1-051 is a separate "
                    "native trap. This does not authorize resuming the native replay with DX=0x82."
                ),
            },
            "runtime_changed": False,
            "replay_run": False,
        }
        EVIDENCE.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")

    def test_character_device_result_and_preservation(self):
        self.assertIn("configured device AX/DX=0x82 CF=0", self.stdout)

    def test_redirected_stream_without_metadata_traps_unchanged(self):
        self.assertIn("redirected stream traps unchanged", self.stdout)

    def test_new_original_evidence_remains_unaligned(self):
        evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
        comparison = evidence["original_comparison"]
        self.assertEqual(comparison["w3_079_original_bx1_call_count"], 0)
        self.assertEqual(comparison["historical_original_dx"], "0x00000082")
        self.assertIsNone(comparison["historical_command_tail"])
        self.assertIsNone(comparison["historical_cue_sha256"])
        self.assertEqual(comparison["fresh_original_bx1_call_count"], 0)
        self.assertEqual(comparison["w1_native_frontier"]["ebx"], "00000001")
        self.assertFalse(comparison["original_equivalence_claimed"])
        self.assertFalse(comparison["native_response_applied"])
        self.assertFalse(evidence["runtime_changed"])


if __name__ == "__main__":
    unittest.main()
