"""Independent native-C regressions for the DOS virtual-file/AX=4400 path."""
import hashlib
import json
import os
import pathlib
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "evidence" / "runtime_fixture_manifest_ax4400_work2_20261008.json"
W2_CAPTURE = ROOT / "evidence" / "native_w3_config_frontier_work2.json"
W1_CAPTURE = ROOT / "evidence" / "native_setup_config_reconciled_work1_20261008.json"
FIXTURE = ROOT / "tests" / "fixtures" / "w3_067_functional_config.ini"
TEST_SOURCE = ROOT / "tests" / "test_dos_ax4400_runtime_work2.c"
TEST_EXE = ROOT / "build" / "test_dos_ax4400_runtime_work2.exe"
COMPILER = pathlib.Path(r"E:\msys64\mingw32\bin\gcc.exe")


def compile_and_run_c_runtime():
    cache = ROOT / "cache"
    cache.mkdir(exist_ok=True)
    env = {
        **os.environ,
        "PYTHONDONTWRITEBYTECODE": "1",
        "TEMP": str(cache),
        "TMP": str(cache),
        "TMPDIR": str(cache),
        "PATH": r"E:\msys64\mingw32\bin;E:\msys64\usr\bin;" + os.environ.get("PATH", ""),
    }
    command = [
        str(COMPILER), "-std=gnu11", "-m32", "-O0",
        "-I", str(ROOT / "runtime"),
        "-I", str(ROOT / "third_party" / "pcrecomp" / "runtime" / "recomp32"),
        str(TEST_SOURCE), str(ROOT / "runtime" / "gw_dos_services.c"),
        str(ROOT / "runtime" / "gw_segments.c"), str(ROOT / "runtime" / "gw_interrupts.c"),
        "-o", str(TEST_EXE),
    ]
    compiled = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True)
    if compiled.returncode:
        raise AssertionError(f"C Runtime test compile failed:\n{compiled.stdout}\n{compiled.stderr}")
    executed = subprocess.run([str(TEST_EXE), str(FIXTURE)], cwd=ROOT, env=env,
                              text=True, capture_output=True)
    if executed.returncode:
        raise AssertionError(f"C Runtime test failed ({executed.returncode}):\n{executed.stdout}\n{executed.stderr}")
    return executed.stdout, hashlib.sha256(TEST_EXE.read_bytes()).hexdigest()


class DosAx4400RuntimeWork2(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.w2 = json.loads(W2_CAPTURE.read_text(encoding="utf-8"))
        cls.w1 = json.loads(W1_CAPTURE.read_text(encoding="utf-8"))
        cls.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        cls.stdout, cls.test_exe_sha256 = compile_and_run_c_runtime()

    def test_independent_c_runtime_services_and_handle_lifecycle(self):
        self.assertIn("DOS_AX4400_C_RUNTIME_TEST pass=1", self.stdout)
        self.assertIn(f"config_size={FIXTURE.stat().st_size}", self.stdout)
        self.assertIn("created_handle=5 created_empty_ax_dx=0002", self.stdout)
        self.assertIn("invalid_ax=0006 closed_ax=0006 wrote=2 attrs=0020", self.stdout)
        self.assertIn("invalid_path=dos_error host_fs_provider_calls=0 unconfigured=trapped", self.stdout)
        self.assertRegex(self.test_exe_sha256, r"^[0-9a-f]{64}$")

    def test_manifest_describes_the_exact_prior_w2_capture(self):
        m = self.manifest
        self.assertEqual(m["capture"]["target_sha256"], self.w2["target_sha256"])
        self.assertEqual(m["capture"]["build_fingerprints"], self.w2["build_fingerprints"])
        self.assertEqual(m["startup"]["psp_segment"], "0x0800")
        self.assertEqual(m["capture"]["command_tail"], self.w2["command_tail"])
        self.assertEqual(m["runtime_state"]["address_txt"]["initial_exists"], False)
        self.assertEqual(m["runtime_state"]["address_txt"]["after_create_at_trap"], {
            "exists": True, "size": 0, "written": False, "dos_handle": 5})
        self.assertEqual(m["runtime_state"]["dos_file_handles_initial"], [])
        self.assertEqual(m["old_w2_ax4400"]["response"], "trapped; registers unchanged")
        self.assertEqual(m["configured_w1_ax4400"]["response_dx"], "0x0042")
        self.assertFalse(m["equivalence_claimed"])

    def test_original_ax4400_measurement_and_old_w1_provider_mismatch(self):
        original = json.loads((ROOT / "evidence" / "w3_setup_original_contract_20261008.json").read_text(encoding="utf-8"))
        events = original["config_ini"]["subsequent_operations"]
        ioctl = [e for e in events if e["operation"] == "INT21_AH44"]
        self.assertEqual(len(ioctl), 3)
        for event in ioctl:
            self.assertEqual(event["in_bx"], 5)
            self.assertEqual(event["before_position"], 0)
            self.assertEqual(event["out_ax"], 2)
            self.assertEqual(event["out_dx"], 2)
            self.assertFalse(event["cf"])
        old_stdout = self.w1["stdout"]
        old_line = next(x for x in old_stdout.splitlines()
                        if x.startswith("W1_CRT_DOS_AX4400_FILE ") and "ebx_in=00000006" in x)
        self.assertIn("edx_out=00000042 carry=0 handled=1", old_line)
        self.assertIn("path=config.ini", old_stdout)
        self.assertEqual(self.w1["w3_functional_config"]["replay_status"], "CONFIG_OPENED_AND_READ")
        self.assertEqual(self.w1["w3_functional_config"]["next_frontier"]["trap_va"], "000af93a")
        self.assertFalse(self.w1["w3_functional_config"]["original_equivalence_claimed"])
        # The W1 capture predates this Runtime fix; its fingerprints are intentionally stale.
        source_hash = hashlib.sha256((ROOT / "runtime" / "gw_dos_services.c").read_bytes()).hexdigest()
        self.assertNotEqual(self.w1["build_fingerprints"]["dos_services_source_sha256"], source_hash)


if __name__ == "__main__":
    unittest.main()
