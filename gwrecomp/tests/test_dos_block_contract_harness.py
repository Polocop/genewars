"""Synthetic checks for the injectable DOS block lifecycle harness only."""
import unittest

from tests.dos_block_contract_harness import (
    DosBlockContractInputs, LifecycleEvent, run_lifecycle,
)


def make_inputs(**changes):
    values = dict(
        requested_paragraphs=7,
        raw_ah48_return=0xA12B,
        real_mode_segment=0x9421,
        protected_mode_selector=0x0037,
        descriptor_base=0x12345000,
        descriptor_limit=0x6FFF,
        descriptor_table="LDT",
        access_rights=0x0092,
        allocation_lifetime="until_explicit_free",
        mapping_lifetime="adapter_defined",
        allocation_owner=0x1357,
        psp_segment=0x2468,
        mov_es_operand=0xA12B,
        ah49_es_input=0x0037,
        ah48_registers_before={"eax": 0x4800, "ebx": 7, "esp": 0x1000},
        ah48_registers_after={"eax": 0xA12B, "ebx": 7, "esp": 0x1000},
        ah48_eflags_before=0x202,
        ah48_eflags_after=0x202,
        segments_before={"cs": 0x000C, "ds": 0x0014, "es": 0x0014, "ss": 0x0014},
        segments_after_ah48={"cs": 0x000C, "ds": 0x0014, "es": 0x0014, "ss": 0x0014},
    )
    values.update(changes)
    return DosBlockContractInputs(**values)


class SyntheticAdapter:
    """Test double with explicit scenario switches; never represents GeneWars."""
    def __init__(self, descriptor_mode, allocation_succeeds, es_valid,
                 free_succeeds, invalidate_after_free, initial_allocation_live):
        self.descriptor_mode = descriptor_mode
        self.allocation_succeeds = allocation_succeeds
        self.es_valid = es_valid
        self.free_succeeds = free_succeeds
        self.invalidate_after_free = invalidate_after_free
        self.allocation_live = initial_allocation_live
        self.descriptor_live = descriptor_mode in {"created", "reused"}
        self.ah49_calls = 0

    @staticmethod
    def event(phase, outcome, inputs, *, descriptor_before, descriptor_after,
              allocation_before, allocation_after, result_ax=None, carry=None,
              detail="synthetic adapter"):
        return LifecycleEvent(
            phase=phase, outcome=outcome,
            registers_before=dict(inputs.ah48_registers_before),
            registers_after=dict(inputs.ah48_registers_after),
            eflags_before=inputs.ah48_eflags_before,
            eflags_after=inputs.ah48_eflags_after,
            segments_before=dict(inputs.segments_before),
            segments_after=dict(inputs.segments_after_ah48),
            descriptor_state_before=descriptor_before,
            descriptor_state_after=descriptor_after,
            allocation_state_before=allocation_before,
            allocation_state_after=allocation_after,
            result_ax=result_ax, carry=carry, detail=detail,
        )

    def ah48(self, inputs):
        before = "live" if self.allocation_live else "absent"
        if not self.allocation_succeeds:
            return self.event("ah48", "failure", inputs,
                descriptor_before="live" if self.descriptor_live else "absent",
                descriptor_after="live" if self.descriptor_live else "absent",
                allocation_before=before, allocation_after=before,
                result_ax=inputs.raw_ah48_return & 0xffff, carry=True)
        self.allocation_live = True
        if self.descriptor_mode == "created":
            self.descriptor_live = True
        return self.event("ah48", "success", inputs,
            descriptor_before="absent" if self.descriptor_mode == "created" else "live",
            descriptor_after="live" if self.descriptor_live else "invalid",
            allocation_before=before, allocation_after="live",
            result_ax=inputs.raw_ah48_return & 0xffff, carry=False)

    def mov_es(self, inputs):
        before = "live" if self.descriptor_live else "invalid"
        accepted = self.es_valid and self.descriptor_live and self.descriptor_mode != "invalid"
        return self.event("mov_es", "success" if accepted else "failure", inputs,
            descriptor_before=before, descriptor_after=before,
            allocation_before="live" if self.allocation_live else "absent",
            allocation_after="live" if self.allocation_live else "absent",
            detail=f"synthetic ES operand 0x{inputs.mov_es_operand:04x}")

    def ah49(self, inputs, es_event):
        self.ah49_calls += 1
        before_alloc = "live" if self.allocation_live else "freed"
        before_desc = "live" if self.descriptor_live else "invalid"
        succeeds = (self.free_succeeds and self.allocation_live and
                    es_event.outcome == "success")
        if succeeds:
            self.allocation_live = False
            if self.invalidate_after_free:
                self.descriptor_live = False
        return self.event("ah49", "success" if succeeds else "failure", inputs,
            descriptor_before=before_desc,
            descriptor_after="live" if self.descriptor_live else "invalid",
            allocation_before=before_alloc,
            allocation_after="live" if self.allocation_live else "freed",
            result_ax=inputs.raw_ah48_return & 0xffff,
            carry=not succeeds,
            detail=f"synthetic ES input 0x{inputs.ah49_es_input:04x}; call {self.ah49_calls}")


class DosBlockContractHarnessTests(unittest.TestCase):
    def test_every_contract_field_is_required_and_no_mapping_defaults_are_injected(self):
        values = vars(make_inputs())
        del values["protected_mode_selector"]
        with self.assertRaises(TypeError):
            DosBlockContractInputs(**values)
        case = make_inputs()
        report = run_lifecycle(case, SyntheticAdapter(
            "created", True, True, True, True, False))
        self.assertEqual(report["classification"], "SYNTHETIC_ADAPTER_RUN")
        self.assertEqual(report["inputs"]["raw_ah48_return"], 0xA12B)
        self.assertEqual(report["inputs"]["real_mode_segment"], 0x9421)
        self.assertEqual(report["inputs"]["protected_mode_selector"], 0x0037)
        self.assertNotEqual(report["inputs"]["raw_ah48_return"],
                            report["inputs"]["protected_mode_selector"])

    def test_created_descriptor_can_be_invalidated_after_configured_free(self):
        report = run_lifecycle(make_inputs(), SyntheticAdapter(
            "created", True, True, True, True, False))
        self.assertEqual([event["phase"] for event in report["events"]],
                         ["ah48", "mov_es", "ah49"])
        self.assertEqual(report["events"][0]["descriptor_state_before"], "absent")
        self.assertEqual(report["events"][0]["descriptor_state_after"], "live")
        self.assertEqual(report["events"][2]["allocation_state_after"], "freed")
        self.assertEqual(report["events"][2]["descriptor_state_after"], "invalid")
        self.assertEqual(report["stop"], "complete")

    def test_reused_descriptor_can_remain_live_when_adapter_says_so(self):
        adapter = SyntheticAdapter("reused", True, True, True, False, False)
        report = run_lifecycle(make_inputs(), adapter)
        self.assertEqual(report["events"][0]["descriptor_state_before"], "live")
        self.assertEqual(report["events"][2]["descriptor_state_after"], "live")
        self.assertEqual(report["events"][2]["allocation_state_after"], "freed")

    def test_invalid_descriptor_and_invalid_es_stop_before_ah49(self):
        for mode, es_valid in (("invalid", True), ("created", False)):
            with self.subTest(mode=mode, es_valid=es_valid):
                adapter = SyntheticAdapter(mode, True, es_valid, True, True, False)
                report = run_lifecycle(make_inputs(), adapter)
                self.assertEqual(report["stop"], "mov_es_failed")
                self.assertEqual([event["phase"] for event in report["events"]],
                                 ["ah48", "mov_es"])

    def test_allocation_failure_stops_without_loading_es_or_freeing(self):
        report = run_lifecycle(make_inputs(), SyntheticAdapter(
            "created", False, True, True, True, False))
        self.assertEqual(report["stop"], "ah48_failed")
        self.assertEqual([event["phase"] for event in report["events"]], ["ah48"])
        self.assertTrue(report["events"][0]["carry"])

    def test_free_failure_and_double_free_are_visible_as_adapter_outcomes(self):
        inputs = make_inputs()
        failed_free = run_lifecycle(inputs, SyntheticAdapter(
            "created", True, True, False, True, False))
        self.assertEqual(failed_free["stop"], "ah49_failed")
        self.assertEqual(failed_free["events"][-1]["allocation_state_after"], "live")

        adapter = SyntheticAdapter("created", True, True, True, True, False)
        report = run_lifecycle(inputs, adapter)
        self.assertEqual(report["stop"], "complete")
        self.assertEqual(report["events"][-1]["allocation_state_after"], "freed")
        second = adapter.ah49(inputs, report_event(report["events"][1]))
        self.assertEqual(second.outcome, "failure")
        self.assertEqual(adapter.ah49_calls, 2)


def report_event(event):
    return LifecycleEvent(**event)


if __name__ == "__main__":
    unittest.main()
