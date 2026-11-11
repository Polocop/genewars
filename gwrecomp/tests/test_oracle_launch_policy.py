"""Anti-bypass guardrails for supported local DOSBox oracle launch paths."""
from pathlib import Path
import json
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence" / "oracle_runs"
GUARD = ROOT / "tools" / "oracle_guard.py"
ALLOWED_DIRECT = {GUARD.resolve()}
SKIP_DIRS = {"third_party", ".git", "__pycache__"}
LAUNCH = re.compile(r"(?:subprocess\.)?(?:Popen|run|call|check_call|check_output)\s*\([^\n]*(?:dosbox|debugbox)|(?:dosbox-x|dosbox|debugbox)[^\n]*(?:Popen|subprocess)", re.I)


class OracleLaunchPolicy(unittest.TestCase):
    def test_guard_preserves_the_configured_mountpoint_path(self):
        import sys
        sys.path.insert(0, str(ROOT / "tools"))
        import oracle_guard
        configured = ROOT / "build" / "dosboxx_oracle" / "C"
        self.assertEqual(oracle_guard.lexical_path(configured), configured)

    def test_no_direct_emulator_process_creation_outside_guard(self):
        violations = []
        for base in (ROOT / "tools", ROOT / "tests"):
            for p in base.rglob("*"):
                if not p.is_file() or p.suffix.lower() not in {".py", ".ps1", ".bat", ".cmd"}:
                    continue
                if any(part in SKIP_DIRS for part in p.parts):
                    continue
                if p.resolve() in ALLOWED_DIRECT or p.resolve() == Path(__file__).resolve():
                    continue
                for n, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                    if LAUNCH.search(line):
                        violations.append(f"{p.relative_to(ROOT)}:{n}: {line.strip()}")
        self.assertEqual(violations, [], "Direct oracle launch bypasses:\n" + "\n".join(violations))
        EVIDENCE.mkdir(parents=True, exist_ok=True)
        (EVIDENCE / "disk_guard_launch_policy.json").write_text(
            json.dumps({"test": "direct-oracle-bypass", "status": "PASS",
                        "scanned_roots": ["tools", "tests"], "violations": []}, indent=2),
            encoding="utf-8")

    def test_official_oracle_configs_use_only_legacy_guest_c_mount_path(self):
        expected = r"E:\GWRecomp\build\dosboxx_oracle\C"
        disabled = r"E:\GWRecomp\build\dosboxx_oracle\__VHDX_REQUIRED__"
        confs = list((ROOT / "build" / "dosboxx_oracle").glob("*.conf"))
        self.assertTrue(confs, "No official oracle configs found")
        violations = []
        for conf in confs:
            lines = [line for line in conf.read_text(encoding="utf-8", errors="replace").splitlines()
                     if re.match(r"\s*mount\s+C\b", line, re.I)]
            safe_target = (expected.lower() in lines[0].lower() or disabled.lower() in lines[0].lower()) if lines else False
            if len(lines) != 1 or not safe_target:
                violations.append(f"{conf.name}: {lines}")
        sentinel = ROOT / "build" / "dosboxx_oracle" / "__VHDX_REQUIRED__"
        mount_state = "disabled-sentinel"
        if sentinel.is_file():
            if any(expected.lower() not in line.lower() and disabled.lower() not in line.lower()
                   for conf in confs for line in conf.read_text(encoding="utf-8", errors="replace").splitlines()
                   if re.match(r"\s*mount\s+C\b", line, re.I)):
                violations.append("disabled configs must target the sentinel or verified C mount")
        else:
            # The sentinel is removed only after the verified VHDX has been
            # mounted at this exact staging path. Physical containment remains
            # active for direct launches that bypass the software watchdog.
            if not (ROOT / "build" / "dosboxx_oracle" / "oracle_c.vhdx").is_file():
                violations.append("active configs require the physical VHDX backing file")
            if any(expected.lower() not in line.lower() for conf in confs
                   for line in conf.read_text(encoding="utf-8", errors="replace").splitlines()
                   if re.match(r"\s*mount\s+C\b", line, re.I)):
                violations.append("active configs must mount the verified VHDX staging path")
            mount_state = "active-vhdx-staging"
        self.assertEqual(violations, [], "Unexpected guest C mounts:\n" + "\n".join(violations))
        (EVIDENCE / "disk_guard_config_mounts.json").write_text(
            json.dumps({"test": "official-config-mounts", "status": "PASS",
                        "configs": [p.name for p in confs],
                        "mount_state": mount_state}, indent=2),
            encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
