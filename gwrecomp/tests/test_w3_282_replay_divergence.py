from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tools.w3_282_replay_divergence import compare_runs, read_trace


class ReplayDivergenceTests(unittest.TestCase):
    def write_run(self, folder: Path, name: str, suffix: list[dict], binary: str) -> tuple[dict, list[dict]]:
        base = 0x1EB000
        rows = [
            {"sequence": 1, "event": "main_mapping", "mapping_matches": True,
             "code_rebase": base},
            {"sequence": 10, "event": "w3_275_second_smacker_entry", "link_va": 0x929D0,
             "eax": 0x1000, "ebx": 0, "ecx": 0, "edx": 1, "esi": 2,
             "edi": 3, "ebp": 4, "esp": 5, "eflags": 0x246},
        ]
        rows.extend(suffix)
        raw = b"\n".join(json.dumps(row).encode() for row in rows) + b"\n"
        trace = folder / f"{name}.jsonl"
        trace.write_bytes(raw)
        manifest = {
            "task": name, "run_id": name,
            "provenance": {
                "target_sha256": "target", "fixture_bytes": 1251658,
                "config_sha256": "config", "cue_sha256": "cue",
                "cue_read_only": True, "staging_revision": "rev",
                "binary_sha256": binary, "source_sha256": {"src/cpu/core_dyn_x86.cpp": binary},
            },
            "analysis": {"code_rebase": "0x001EB000"},
            "trace": {"path": str(trace), "bytes": len(raw), "rows": len(rows),
                      "sha256": hashlib.sha256(raw).hexdigest()},
            "guard": {"cause": "TIMEOUT", "duration_s": 123.0,
                      "host_free_before": 1000, "host_free_after": 1000},
        }
        return manifest, rows

    def test_finds_shared_prefix_without_claiming_cause(self) -> None:
        base = 0x1EB000
        def checkpoint(seq: int, link: int) -> dict:
            return {"sequence": seq, "event": "target_runtime_checkpoint",
                    "link_va": link, "runtime_linear": base + link, "code_rebase": base}
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            a, rows_a = self.write_run(folder, "A", [
                checkpoint(11, 0x92030), checkpoint(12, 0x92A16),
                checkpoint(13, 0x92A24),
                {"sequence": 14, "event": "w3_275_second_smacker_callsite", "link_va": 0x92ADD},
            ], "binary-a")
            b, rows_b = self.write_run(folder, "B", [
                checkpoint(11, 0x92030), checkpoint(12, 0x92A16),
                checkpoint(13, 0x92A24),
            ], "binary-b")
            a["_trace_path"] = a["trace"]["path"]
            b["_trace_path"] = b["trace"]["path"]
            result = compare_runs(a, rows_a, b, rows_b)
            self.assertEqual(result["common_post_entry_checkpoint_prefix_length"], 3)
            self.assertEqual(result["first_observed_difference"]["run_a_next"]["link_va"], "0x00092ADD")
            self.assertIsNone(result["first_observed_difference"]["run_b_next"])
            self.assertEqual(result["cause_classification"], "UNKNOWN")
            self.assertTrue(all(v for v in result["identity_equal"].values()))

    def test_trace_hash_mismatch_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "trace.jsonl"
            p.write_bytes(b"{}\n")
            with self.assertRaisesRegex(ValueError, "trace hash mismatch"):
                read_trace(p, 3, 1, "bad")

    def test_fixture_identity_mismatch_rejected(self) -> None:
        base = 0x1EB000
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            row = {"sequence": 11, "event": "target_runtime_checkpoint", "link_va": 0x92030,
                   "runtime_linear": base + 0x92030, "code_rebase": base}
            a, rows_a = self.write_run(folder, "A", [row], "binary-a")
            b, rows_b = self.write_run(folder, "B", [row], "binary-b")
            a["_trace_path"] = a["trace"]["path"]; b["_trace_path"] = b["trace"]["path"]
            b["provenance"]["cue_sha256"] = "different"
            with self.assertRaisesRegex(ValueError, "identity differs"):
                compare_runs(a, rows_a, b, rows_b)


if __name__ == "__main__":
    unittest.main()
