"""Build and run the bounded C callback regression for DPMI AX=0200."""
import json
import os
import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
BUILD = ROOT / "build"
EXE = BUILD / "test_w2_112_native_dpmi_0200.exe"
GCC = pathlib.Path(r"E:\msys64\mingw32\bin\gcc.exe")


class NativeDpmi0200Tests(unittest.TestCase):
    def test_native_dpmi_0200_callback(self):
        BUILD.mkdir(exist_ok=True)
        env = {
            **os.environ,
            "TEMP": str(ROOT / "cache"),
            "TMP": str(ROOT / "cache"),
            "TMPDIR": str(ROOT / "cache"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PATH": r"E:\msys64\mingw32\bin;E:\msys64\usr\bin;" + os.environ.get("PATH", ""),
        }
        command = [
            str(GCC), "-std=gnu11", "-m32", "-O0",
            "-I", str(ROOT / "runtime"),
            "-I", str(ROOT / "third_party" / "pcrecomp" / "runtime" / "recomp32"),
            "-o", str(EXE), str(ROOT / "tests" / "test_w2_112_native_dpmi_0200.c"),
            str(ROOT / "runtime" / "recomp_context.c"),
            str(ROOT / "runtime" / "gw_segments.c"),
            str(ROOT / "runtime" / "gw_interrupts.c"),
            str(ROOT / "runtime" / "gw_dos_services.c"),
        ]
        built = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True)
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        ran = subprocess.run([str(EXE)], cwd=ROOT, env=env, text=True, capture_output=True)
        self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
        self.assertIn("PASS native DPMI AX=0200", ran.stdout)
        result = {
            "test": "synthetic C callback DPMI INT 31h AX=0200 real-mode vector",
            "execution_kind": "SYNTHETIC_CALLBACK",
            "documented_contract": "DPMI 1.0 AX=0200 gets the real-mode interrupt vector; BL is the vector number, CX:DX is segment:offset, and CF is clear.",
            "specification": "https://www.sudleyplace.com/dpmione/dpmispec1.0.pdf#page=75",
            "original_observation": {
                "source": "evidence/empty_config_overlay_work2.json",
                "execution_kind": "ORIGINAL_OBSERVED",
                "link_va": "0x001C8CD2",
                "input": {"EAX": "0x00000200", "EBX": "0x00000008", "ECX": "0x00000000", "EDX": "0x00000000"},
                "response": {"ECX": "0x00000000", "EDX": "0x00000000", "CF": 0},
                "note": "Trace labels this service protected_interrupt_vector, but measured inputs and returned words are recorded without relying on that label.",
            },
            "native_request": {
                "source": "evidence/native_ax4400_console_replay_w1_056.json",
                "execution_kind": "NATIVE_REACHED_REQUEST_ONLY",
                "link_va": "0x000C8CD2",
                "input": {"EAX": "0x00000200", "EBX": "0x00000008", "ECX": "0x00000000", "EDX": "0x000C0014"},
                "response": "UNKNOWN; native replay stopped at the callback frontier",
            },
            "compile_exit": built.returncode,
            "run_exit": ran.returncode,
            "output": ran.stdout.strip(),
            "configured_vector": {"BL": "0x08", "CX_segment": "0x1234", "DX_offset": "0x5678"},
            "unconfigured_vector": {"BL": "0x09", "CX_segment": "0x0000", "DX_offset": "0x0000"},
            "passed": True,
        }
        (ROOT / "evidence" / "native_dpmi_0200_c_work2.json").write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8"
        )
