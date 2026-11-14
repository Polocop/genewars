import unittest

from tools.w3_287_smacker_timeout_audit import audit_runs, select_callsite_occurrence, select_ordinal


def run(label, later=False, binary=None, core=None, callsites=0):
    rows = [{"sequence": i + 1, "event": "target_runtime_checkpoint", "link_va": 0x92ADD}
            for i in range(callsites)]
    if later:
        rows.extend([
            {"sequence": 90, "event": "w3_278_later_play_smk_entry", "link_va": 0xAE2D0},
            {"sequence": 91, "event": "w3_278_branch_target", "link_va": 0xAE2E3},
        ])
    return {
        "run_id": label,
        "trace": {"path": label + ".jsonl", "bytes": 100, "sha256": label, "rows": len(rows)},
        "provenance": {"binary_sha256": binary or label,
                       "source_sha256": {"src/cpu/core_dyn_x86.cpp": core or label}},
        "analysis": {"fallthrough_latch_seen": False},
        "guard": {"cause": "TIMEOUT", "duration_s": 120},
        "last_elapsed_ms": 75_000,
        "target_checkpoint_rows": len(rows),
        "smacker_relevant_rows": [],
        "rows": rows,
    }


class SmackerTimeoutAuditTests(unittest.TestCase):
    def test_missing_event_under_timeout_is_unknown_not_branch_divergence(self):
        runs = {"W3-280": run("280", True), "W3-281": run("281", False), "W3-285": run("285", False)}
        result = audit_runs(runs, {"correlation": {"causality": "UNKNOWN"}})
        self.assertEqual(result["reason_classification"]["status"], "UNKNOWN")
        self.assertIn("does not establish", result["reason_classification"]["causality"])

    def test_ordinal_selector_ignores_first_callsite(self):
        events = [{"link_va": 0x92ADD, "ordinal": 1}, {"link_va": 0x92ADD, "ordinal": 2}]
        self.assertEqual(select_ordinal(events, 0x92ADD, 2)["ordinal"], 2)
        self.assertIsNone(select_ordinal(events, 0x92ADD, 3))

    def test_named_callsite_ordinal_ignores_duplicate_custom_row(self):
        events = [
            {"event": "target_runtime_checkpoint", "checkpoint": "W3_117_PLAYSMACKER_CALLSITE", "link_va": 600797, "sequence": 328},
            {"event": "w3_275_second_smacker_callsite", "link_va": 600797, "sequence": 393},
            {"event": "target_runtime_checkpoint", "checkpoint": "W3_117_PLAYSMACKER_CALLSITE", "link_va": 600797, "sequence": 394},
        ]
        self.assertEqual(select_callsite_occurrence(events, 2)["sequence"], 394)

    def test_same_build_does_not_claim_cause_from_missing_gate_alone(self):
        runs = {"W3-280": run("280", True, "same", "same"),
                "W3-281": run("281", False, "same", "same"),
                "W3-285": run("285", False, "same", "same")}
        result = audit_runs(runs, {"correlation": {"causality": "UNKNOWN"}})
        self.assertEqual(result["reason_classification"]["status"], "UNKNOWN")

    def test_capture_design_is_ordinal_and_bounded(self):
        runs = {k: run(k, later=(k == "W3-280")) for k in ("W3-280", "W3-281", "W3-285")}
        result = audit_runs(runs, {"correlation": {"causality": "UNKNOWN"}})
        design = result["minimal_next_capture_design"]
        self.assertIn("occurrence 2", design["trigger"])
        self.assertEqual(design["caps"]["selected_events"], 6)
        self.assertEqual(design["caps"]["wall_timeout_s"], 120)


if __name__ == "__main__":
    unittest.main()
