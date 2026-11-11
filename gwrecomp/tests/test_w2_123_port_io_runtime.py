"""Synthetic native callback-to-PIT ABI and fail-closed regressions for W2-123."""
import hashlib
import json
import os
import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
TASK = ROOT / "coordination/task_W2-123.json"
ABI_EVIDENCE = ROOT / "evidence/native_port_io_codegen_w1_087.json"
RECOVERY = ROOT / "work/recovery/W2-123/recovery_manifest.json"
BUILD = ROOT / "work/recovery/W2-123/test_build"
EXE = BUILD / "test_w2_123_port_io_runtime.exe"
SOURCE_C = ROOT / "tests/test_w2_123_port_io_runtime.c"
RUNTIME_C = ROOT / "runtime/recomp_context.c"
RUNTIME_H = ROOT / "runtime/recomp_context.h"
PIT_C = ROOT / "runtime/gw_pit8254.c"
PIT_H = ROOT / "runtime/gw_pit8254.h"
EVIDENCE = ROOT / "evidence/native_port_io_runtime_w2_123.json"
REPORT = ROOT / "reports/coordination/native_port_io_runtime_w2_123.md"
GCC = pathlib.Path(r"E:\msys64\mingw32\bin\gcc.exe")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def runtime_env():
    cache = ROOT / "cache"
    cache.mkdir(exist_ok=True)
    return {
        **os.environ,
        "TEMP": str(cache), "TMP": str(cache), "TMPDIR": str(cache),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PATH": r"E:\msys64\mingw32\bin;E:\msys64\usr\bin;" + os.environ.get("PATH", ""),
    }


class NativePortIoRuntimeTests(unittest.TestCase):
    def test_generated_callback_abi_binds_instance_pit_and_traps_unsupported_io(self):
        self.assertTrue(TASK.is_file())
        self.assertTrue(ABI_EVIDENCE.is_file())
        self.assertTrue(RECOVERY.is_file())
        self.assertTrue(GCC.is_file(), f"C compiler not found: {GCC}")
        manifest = json.loads(RECOVERY.read_text(encoding="utf-8"))
        self.assertEqual(manifest["task"], "W2-123")
        for item in manifest["files"]:
            self.assertTrue(item["match"])
            self.assertEqual(item["original_sha256"], item["backup_sha256"])
            self.assertEqual(item["original_sha256"], item["isolated_restore_sha256"])
            self.assertTrue(pathlib.Path(item["backup"]).is_file())
            self.assertTrue(pathlib.Path(item["isolated_restore"]).is_file())

        BUILD.mkdir(parents=True, exist_ok=True)
        command = [
            str(GCC), "-std=c11", "-Wall", "-Wextra", "-Werror", "-O0",
            "-I", str(ROOT / "runtime"),
            "-I", str(ROOT / "third_party/pcrecomp/runtime/recomp32"),
            "-o", str(EXE), str(SOURCE_C), str(RUNTIME_C), str(PIT_C),
            str(ROOT / "runtime/gw_interrupts.c"),
            str(ROOT / "runtime/gw_segments.c"),
        ]
        built = subprocess.run(command, cwd=ROOT, env=runtime_env(), text=True,
                               capture_output=True)
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        ran = subprocess.run([str(EXE)], cwd=ROOT, env=runtime_env(), text=True,
                             capture_output=True)
        self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
        self.assertIn("PASS W2-123 synthetic callback ABI", ran.stdout)

        abi = json.loads(ABI_EVIDENCE.read_text(encoding="utf-8"))["runtime_contract"]
        self.assertEqual(abi["guest_instruction_tick"], "gw_recomp_guest_instruction(guest_va)")
        self.assertEqual(abi["port_dispatch"],
                         "gw_recomp_port_io(operation, port, width, value, guest_va, value_out)")
        EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
        REPORT.parent.mkdir(parents=True, exist_ok=True)
        evidence = {
            "schema": "gwrecomp.w2-123-native-port-io-runtime/v1",
            "task": "W2-123",
            "execution_kind": "SYNTHETIC_PASS",
            "command": command,
            "compile_exit": built.returncode,
            "run_exit": ran.returncode,
            "output": ran.stdout.strip(),
            "callback_abi": {
                "guest_instruction": "int gw_recomp_guest_instruction(unsigned int guest_va)",
                "port_io": "int gw_recomp_port_io(unsigned int operation, unsigned int port, unsigned int width, unsigned int value, unsigned int guest_va, unsigned int *value_out)",
                "source_contract_evidence": "evidence/native_port_io_codegen_w1_087.json",
                "source_contract_match": True,
            },
            "synthetic_checks": {
                "supported_ports": ["OUT 0x43 byte", "OUT 0x40 byte low/high", "IN 0x40 byte"],
                "virtual_ticks_after_sequences": [4, 5, 1],
                "synthetic_read_value_hex": "0x33",
                "instance_state_isolated": True,
                "unsupported_string_io_trapped": True,
                "unsupported_width_trapped": True,
                "unsupported_port_trapped": True,
                "invalid_operation_trapped": True,
                "missing_read_output_trapped": True,
                "tick_overflow_trapped": True,
                "no_active_context_trapped": True,
                "nested_guest_path_fails_closed": True,
            },
            "recovery": {
                "manifest": "work/recovery/W2-123/recovery_manifest.json",
                "verified_isolated_restore": True,
            },
            "original_evidence": {
                "path": "evidence/w3_270_post_present_static_frontier.json",
                "classification": "STATIC_ONLY port instruction sequence; original port values not measured",
                "link_va": "0x000C427E",
                "original_port_values_measured": False,
                "native_frontier_reached": False,
            },
            "claims": {
                "synthetic_callback_contract_pass": True,
                "original_pit_values_match": False,
                "native_replay_run": False,
                "framebuffer_verified": False,
                "menu_verified": False,
            },
            "fingerprints": {
                "runtime_c_sha256": sha(RUNTIME_C),
                "runtime_h_sha256": sha(RUNTIME_H),
                "pit_c_sha256": sha(PIT_C),
                "pit_h_sha256": sha(PIT_H),
                "test_c_sha256": sha(SOURCE_C),
                "test_py_sha256": sha(pathlib.Path(__file__)),
                "abi_evidence_sha256": sha(ABI_EVIDENCE),
                "recovery_manifest_sha256": sha(RECOVERY),
                "test_exe_sha256": sha(EXE),
            },
        }
        EVIDENCE.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
        REPORT.write_text(
            "# W2-123 — generated port-I/O callback to Runtime PIT\n\n"
            "Status: synthetic callback ABI and per-context PIT tests pass. The Runtime binds the PIT "
            "to the active `gw_recomp_context`, advances one virtual tick before each lifted guest "
            "instruction, and unbinds after invocation. Supported byte I/O at PIT ports 0x40–0x43 "
            "uses the W2-122 provider; unsupported operations latch a traceable trap and stop lifted "
            "execution through the generated callback return path.\n\n"
            "The tests use synthetic vectors only. W3-270's port sequence at 0xC427E remains "
            "STATIC_ONLY for device values and native reachability. No native replay, original-value "
            "parity, menu, or framebuffer is claimed.\n",
            encoding="utf-8",
        )


if __name__ == "__main__":
    unittest.main()
