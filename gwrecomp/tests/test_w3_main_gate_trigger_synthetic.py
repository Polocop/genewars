import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
DOS_FILES = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/dos/dos_files.cpp"

LINK_MAIN_ENTRY = 0xAF96C
RUNTIME_MAIN_ENTRY = 0x29A96C
LINK_MAIN_C = 0x93F30
LINK_GATE_1 = 0x94334
LINK_GATE_2 = 0x9433B
LINK_GATE_MESSAGE = 0x94365


def branch_decision(link_va, eflags):
    zf = bool(eflags & 0x40)
    if link_va in (LINK_GATE_1, LINK_GATE_2):
        taken = zf
        target = 0x94360 if taken else link_va + 2
    elif link_va == LINK_GATE_MESSAGE:
        taken = not zf
        target = 0x94376 if taken else 0x94367
    else:
        raise ValueError("not a main gate branch")
    return taken, target


def anchor_match(runtime_linear, link_va, rebase):
    return runtime_linear == rebase + link_va


class MainGateSyntheticTests(unittest.TestCase):
    def test_measured_rebase_and_runtime_translation(self):
        rebase = RUNTIME_MAIN_ENTRY - LINK_MAIN_ENTRY
        self.assertEqual(rebase, 0x1EB000)
        gate_runtime = rebase + LINK_GATE_1
        self.assertTrue(anchor_match(gate_runtime, LINK_GATE_1, rebase))
        self.assertFalse(anchor_match(gate_runtime + 1, LINK_GATE_1, rebase))

    def test_selector_is_observation_not_hardcoded_gate(self):
        cs = 0x160
        descriptor_base = 0
        eip = LINK_MAIN_ENTRY + 0x1EB000
        linear = descriptor_base + eip
        self.assertEqual(cs, 0x160)
        self.assertEqual(linear - LINK_MAIN_ENTRY, 0x1EB000)
        self.assertIn("std::to_string(SegValue(cs))", SOURCE.read_text())

    def test_gate_branch_truth_tables(self):
        self.assertEqual(branch_decision(LINK_GATE_1, 0x40), (True, 0x94360))
        self.assertEqual(branch_decision(LINK_GATE_1, 0x00), (False, 0x94336))
        self.assertEqual(branch_decision(LINK_GATE_2, 0x40), (True, 0x94360))
        self.assertEqual(branch_decision(LINK_GATE_2, 0x00), (False, 0x9433D))
        self.assertEqual(branch_decision(LINK_GATE_MESSAGE, 0x00), (True, 0x94376))
        self.assertEqual(branch_decision(LINK_GATE_MESSAGE, 0x40), (False, 0x94367))

    def test_hook_requires_target_file_complete_precondition(self):
        cpu_source = SOURCE.read_text(encoding="utf-8")
        dos_source = DOS_FILES.read_text(encoding="utf-8")
        self.assertIn("exec_trace::target_file_complete()", cpu_source)
        self.assertIn('"GWRECOMP_GW_FILE_SIZE"', dos_source)
        self.assertIn("static_cast<uint64_t>(pos) + toread >= expected_size", dos_source)

    def test_event_json_roundtrip_and_bounded_capture(self):
        event = {"event": "target_runtime_checkpoint", "checkpoint": "MAIN_GATE_CHECKPOINT",
                 "cs": 0x160, "link_va": LINK_GATE_1, "branch_taken": True,
                 "text": 'quote " slash \\ café'}
        encoded = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
        self.assertEqual(json.loads(encoded), event)
        max_bytes = 524288
        self.assertLessEqual(len((encoded + "\n").encode("utf-8")), max_bytes)
        self.assertIn("MAIN_GATE_CHECKPOINT", cpu_source_text())
        trace_api = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/dos/exec_trace.h"
        self.assertIn("bytes_written > max_bytes - record_size", trace_api.read_text())
        used = 0
        events = 0
        for _ in range(20000):
            size = len((encoded + "\n").encode("utf-8"))
            if size > max_bytes or used > max_bytes - size:
                break
            used += size
            events += 1
        self.assertLessEqual(used, max_bytes)
        self.assertGreater(events, 0)

    def test_duplicate_anchor_limit(self):
        source = cpu_source_text()
        self.assertIn("anchor_counts[i] >= 1u", source)
        emitted = []
        for _ in range(5):
            if len(emitted) < 1:
                emitted.append("GAME_MAIN_ENTRY")
        self.assertEqual(emitted, ["GAME_MAIN_ENTRY"])


def cpu_source_text():
    return SOURCE.read_text(encoding="utf-8")


if __name__ == "__main__":
    unittest.main(verbosity=2)
