import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
TARGETS = {"W3_213_ADJUST_CALLSITE": 0xC3D98,
           "W3_213_ADJUST_ENTRY": 0xC3F76,
           "W3_213_ADJUST_RETURN": 0xC3D9D}
ORDER = tuple(TARGETS)
MAX_CAPTURE_EVENTS = len(ORDER)


def runtime_address(link_va, rebase):
    if link_va < 0 or rebase <= 0:
        raise ValueError("a measured positive rebase is required")
    return link_va + rebase


def probe_window_enabled(*, opted_in, target_context, mapping_verified, link_va):
    return bool(opted_in and target_context and mapping_verified and
                (0xC3D58 <= link_va <= 0xC3DB0 or 0xC3F58 <= link_va <= 0xC3F8C))


class BoundedCapture:
    def __init__(self, rebase, process_id, max_events=MAX_CAPTURE_EVENTS):
        if rebase <= 0 or process_id <= 0 or max_events <= 0:
            raise ValueError("positive mapping, process id, and event cap required")
        self.rebase = rebase
        self.process_id = process_id
        self.max_events = min(max_events, MAX_CAPTURE_EVENTS)
        self.events = []

    @property
    def complete(self):
        return len(self.events) == MAX_CAPTURE_EVENTS

    @property
    def stopped(self):
        return len(self.events) >= self.max_events

    def observe(self, name, *, link_va, runtime, process_id, state):
        if self.stopped or name not in TARGETS or process_id != self.process_id:
            return False
        if link_va != TARGETS[name] or runtime != runtime_address(link_va, self.rebase):
            return False
        if self.events and name != ORDER[len(self.events)]:
            return False
        if any(event["checkpoint"] == name for event in self.events):
            return False
        self.events.append({"event": "synthetic_checkpoint", "checkpoint": name,
                            "ordinal": len(self.events) + 1, "link_va": link_va,
                            "runtime": runtime, "rebase": self.rebase,
                            "process_id": process_id, "state": dict(state)})
        return True

    def to_json(self):
        return json.dumps({"events": self.events, "complete": self.complete,
                           "stopped": self.stopped}, sort_keys=True)


def source_validation():
    source = CORE.read_text(encoding="utf-8", errors="replace")
    checks = [
        'string_from_env("GWRECOMP_W3_223_ADJUST_CAPTURE_ONLY") == "1"',
        "linked_candidate_link_va == 0x000c3d98",
        "linked_candidate_link_va == 0x000c3f76",
        "linked_candidate_link_va == 0x000c3d9d",
        "w3_223_adjust_capture_only &&",
        "candidate_link_va >= 0x000c3d58 && candidate_link_va <= 0x000c3db0",
        "candidate_link_va >= 0x000c3f58 && candidate_link_va <= 0x000c3f8c",
    ]
    return {"all_source_markers_found": all(marker in source for marker in checks),
            "missing": [marker for marker in checks if marker not in source]}


class AdjustmentDynrecSplitTests(unittest.TestCase):
    def test_runtime_translation_uses_measured_rebase(self):
        self.assertEqual(runtime_address(0xC3F76, 0x1EB000), 0x2AEF76)
        with self.assertRaises(ValueError):
            runtime_address(0xC3F76, 0)

    def test_probe_requires_opt_in_target_and_verified_mapping(self):
        self.assertTrue(probe_window_enabled(
            opted_in=True, target_context=True, mapping_verified=True, link_va=0xC3F76))
        for args in (
            dict(opted_in=False, target_context=True, mapping_verified=True),
            dict(opted_in=True, target_context=False, mapping_verified=True),
            dict(opted_in=True, target_context=True, mapping_verified=False),
        ):
            self.assertFalse(probe_window_enabled(**args, link_va=0xC3F76))
        self.assertFalse(probe_window_enabled(
            opted_in=True, target_context=True, mapping_verified=True, link_va=0xC4000))

    def test_capture_orders_deduplicates_and_stops_at_cap(self):
        cap = BoundedCapture(0x1EB000, 7811)
        for name in ORDER:
            link = TARGETS[name]
            self.assertTrue(cap.observe(name, link_va=link,
                                        runtime=runtime_address(link, 0x1EB000),
                                        process_id=7811, state={"eax": 0x40}))
            self.assertFalse(cap.observe(name, link_va=link,
                                         runtime=runtime_address(link, 0x1EB000),
                                         process_id=7811, state={"eax": 0x40}))
        self.assertTrue(cap.complete)
        self.assertEqual(len(cap.events), MAX_CAPTURE_EVENTS)
        data = json.loads(cap.to_json())
        self.assertEqual([row["checkpoint"] for row in data["events"]], list(ORDER))
        self.assertTrue(data["complete"])
        self.assertFalse(cap.observe(ORDER[0], link_va=TARGETS[ORDER[0]],
                                     runtime=runtime_address(TARGETS[ORDER[0]], 0x1EB000),
                                     process_id=7811, state={}))

    def test_rejects_wrong_mapping_process_or_order_and_respects_timeout_cap(self):
        cap = BoundedCapture(0x1EB000, 7811, max_events=1)
        name = ORDER[0]
        link = TARGETS[name]
        self.assertFalse(cap.observe(name, link_va=link, runtime=link + 1,
                                     process_id=7811, state={}))
        self.assertFalse(cap.observe(name, link_va=link,
                                     runtime=runtime_address(link, 0x1EB000),
                                     process_id=7812, state={}))
        self.assertTrue(cap.observe(name, link_va=link,
                                    runtime=runtime_address(link, 0x1EB000),
                                    process_id=7811, state={}))
        self.assertTrue(cap.stopped)
        self.assertFalse(cap.observe(ORDER[1], link_va=TARGETS[ORDER[1]],
                                     runtime=runtime_address(TARGETS[ORDER[1]], 0x1EB000),
                                     process_id=7811, state={}))

    def test_cpp_opt_in_and_exact_targets_are_present(self):
        validation = source_validation()
        self.assertTrue(validation["all_source_markers_found"], validation)


if __name__ == "__main__":
    unittest.main()
