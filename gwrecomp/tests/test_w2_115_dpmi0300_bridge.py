"""Synthetic C regression for provider-backed DPMI AX=0300 frames."""
import hashlib
import json
import os
import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
BUILD = ROOT / "build"
EXE = BUILD / "test_w2_115_dpmi0300_bridge.exe"
SOURCE = ROOT / "tests" / "test_w2_115_dpmi0300_bridge.c"
RUNTIME_C = ROOT / "runtime" / "gw_dos_services.c"
RUNTIME_H = ROOT / "runtime" / "gw_dos_services.h"
W3_EVIDENCE = ROOT / "evidence" / "w3_187_post_dpmi_screen_path.json"
TRACE = ROOT / "build" / "dosboxx_oracle" / "C" / "W3_184_ORIGINAL_AX0300_WINDOW_20261009_01.jsonl"
EVIDENCE = ROOT / "evidence" / "w2_115_dpmi0300_bridge.json"
GCC = pathlib.Path(r"E:\msys64\mingw32\bin\gcc.exe")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def env():
    cache = ROOT / "cache"
    cache.mkdir(exist_ok=True)
    return {**os.environ, "TEMP": str(cache), "TMP": str(cache),
            "TMPDIR": str(cache), "PYTHONDONTWRITEBYTECODE": "1",
            "PATH": r"E:\msys64\mingw32\bin;E:\msys64\usr\bin;" + os.environ.get("PATH", "")}


class Dpmi0300BridgeTests(unittest.TestCase):
    def test_original_frame_and_synthetic_bridge_are_separate(self):
        original_meta = json.loads(W3_EVIDENCE.read_text(encoding="utf-8"))
        original = {}
        for line in TRACE.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            if row.get("checkpoint") in ("W3_182_DPMI0300_ENTRY", "W3_182_DPMI0300_RETURN"):
                original[row["checkpoint"]] = row
        self.assertEqual(set(original), {"W3_182_DPMI0300_ENTRY", "W3_182_DPMI0300_RETURN"})
        before, after = (original["W3_182_DPMI0300_ENTRY"], original["W3_182_DPMI0300_RETURN"])
        self.assertEqual(original_meta["trace"]["sha256"], sha(TRACE))
        self.assertEqual((before["eax"] & 0xffff, before["ebx"], before["ecx"]),
                         (0x0300, 0x21, 0))
        self.assertEqual((before["ds"], before["es"], before["edi"]),
                         (0x168, 0x168, before["w3_182_frame_linear"]))
        self.assertEqual(before["w3_182_frame_bytes"], 48)  # bounded observation only
        self.assertEqual(after["w3_182_frame_bytes"], 48)
        ib, ob = bytes.fromhex(before["w3_182_frame_hex"]), bytes.fromhex(after["w3_182_frame_hex"])
        self.assertEqual(int.from_bytes(ib[28:32], "little") & 0xffff, 0x6300)
        self.assertEqual(int.from_bytes(ob[28:32], "little") & 0xffff, 0x6300)
        self.assertEqual(int.from_bytes(ob[32:34], "little") & 1, 0)
        self.assertEqual(int.from_bytes(ob[36:38], "little"), 0xC808)
        self.assertEqual(int.from_bytes(ob[4:6], "little"), 0)
        self.assertEqual(after["eflags"] & 1, 0)

        BUILD.mkdir(exist_ok=True)
        command = [str(GCC), "-std=gnu11", "-m32", "-O0",
                   "-I", str(ROOT / "runtime"),
                   "-I", str(ROOT / "third_party" / "pcrecomp" / "runtime" / "recomp32"),
                   "-o", str(EXE), str(SOURCE), str(RUNTIME_C),
                   str(ROOT / "runtime" / "gw_segments.c"),
                   str(ROOT / "runtime" / "gw_interrupts.c")]
        built = subprocess.run(command, cwd=ROOT, env=env(), text=True, capture_output=True)
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        ran = subprocess.run([str(EXE)], cwd=ROOT, env=env(), text=True, capture_output=True)
        self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
        self.assertIn("PASS native DPMI AX=0300", ran.stdout)

        evidence = {
            "schema": "gwrecomp.w2-115-dpmi0300-bridge/v1",
            "task": "W2-115",
            "execution_kind": "SYNTHETIC_PASS",
            "original_observation": {
                "evidence": "evidence/w3_187_post_dpmi_screen_path.json",
                "trace": "build/dosboxx_oracle/C/W3_184_ORIGINAL_AX0300_WINDOW_20261009_01.jsonl",
                "trace_sha256": sha(TRACE),
                "outer_entry": {"EAX": "0x00380300", "EBX": "0x00000021", "ECX": "0",
                                "DS": "0x0168", "ES": "0x0168", "EDI": hex(before["edi"])},
                "inner_input_ax": "0x6300", "inner_return_ax": "0x6300",
                "inner_return_ds_si": "0xC808:0x0000", "inner_return_cf": 0,
                "bounded_frame_bytes_observed": 48,
                "stack_segment_field_observed": False,
                "equivalence_claimed": False,
            },
            "synthetic": {"output": ran.stdout.strip(), "compile_exit": built.returncode,
                          "run_exit": ran.returncode,
                          "provider_output_ds_si": "0x4567:0x1234",
                          "provider_pointer_is_fixture_only": True},
            "runtime_fingerprints": {"c": sha(RUNTIME_C), "h": sha(RUNTIME_H),
                                     "test_c": sha(SOURCE), "test_exe": sha(EXE)},
            "qualification": "The bridge forwards a validated frame to an explicit provider and never hardcodes the original DS:SI. WORK1 still must wire/configure the provider before native replay. The original trace captured 48 bytes of the documented 50-byte frame; SS was not observed.",
        }
        EVIDENCE.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
