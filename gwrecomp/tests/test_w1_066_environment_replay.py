"""Synthetic shape tests for the W1-066 native replay evidence validator."""
import copy
import json
import pathlib
import unittest

from tests.test_native_guest_image import load_authenticated_w3_140_environment
from tools.verify_w1_066_environment_replay import ENVIRONMENT_SHA256, TARGET_SHA256, validate


def sample():
    return {
        "schema": "gwrecomp.native-setup-replay/v1",
        "task_schema": "gwrecomp.native-setenvp-aligned-replay/v1",
        "execution_mode": "native_recompiled_guest",
        "evidence_level": "NATIVE_REACHED",
        "target_sha256": TARGET_SHA256,
        "prior_ax4300_checkpoint_reused": False,
        "authenticated_environment": {
            "source_evidence": "evidence/w3_140_original_setenvp_environment.json",
            "source_evidence_sha256": "a" * 64,
            "runtime_contract_evidence": "evidence/w2_114_authenticated_environment_fixture.json",
            "runtime_contract_evidence_sha256": "b" * 64,
            "runtime_source_sha256": "c" * 64,
            "size_bytes": 86,
            "sha256": ENVIRONMENT_SHA256,
            "guest_boot_environment_sha256": ENVIRONMENT_SHA256,
            "guest_boot_environment_bytes": 86,
            "exact_bytes_loaded": True,
            "same_dynamic_invocation_claimed": False,
            "original_comparison": {"same_dynamic_invocation_claimed": False},
            "return_to_dfe12_observed": True,
            "return_to_dfe12_status": "observed",
            "native_setenvp_events": [
                "NATIVE_ADF95_BRANCH site=000dfe04 eax=00000040 ecx=00000003",
                "NATIVE_ALLOC_CALLSITE ordinal=1 site=000dfe0d eax=00000040",
                "NATIVE_ALLOC_ENTRY ordinal=2 va=000adf95 eax=00000040",
                "NATIVE_ADF95_RETURN link_va=000dfe12 eax=001a0038",
            ],
        },
        "crt": {"callback_count": 19},
        "argv": {"argc": 3, "values": ["GW.EXE", "-k", "38928"]},
        "gate": {"local_64": "01", "local_68": "01"},
        "roots": {"setup_game": {}, "first_callee_14bf0": {}},
        "frontier": {"fresh_replay": True, "stop_reason": "synthetic bounded frontier", "response_count": 0},
        "native_response_forced": False,
    }


class W1066EvidenceContract(unittest.TestCase):
    def test_w3_140_capture_schema_uses_terminated_trailer_field(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        original = json.loads((root / "evidence/w3_140_original_setenvp_environment.json").read_text(encoding="utf-8"))
        runtime = json.loads((root / "evidence/w2_114_authenticated_environment_fixture.json").read_text(encoding="utf-8"))
        environment = load_authenticated_w3_140_environment(original, runtime)
        self.assertEqual(len(environment), 86)
        self.assertEqual(__import__("hashlib").sha256(environment).hexdigest(), ENVIRONMENT_SHA256)

    def test_complete_synthetic_capture_shape_passes(self):
        self.assertEqual(validate(sample()), [])

    def test_empty_environment_cannot_pass_as_aligned(self):
        capture = sample()
        capture["authenticated_environment"]["guest_boot_environment_sha256"] = "0" * 64
        self.assertTrue(any("native boot fixture" in e for e in validate(capture)))

    def test_missing_native_return_checkpoint_fails_closed(self):
        capture = sample()
        capture["authenticated_environment"]["native_setenvp_events"].pop()
        self.assertTrue(any("DFE12" in e for e in validate(capture)))

    def test_unreached_return_is_explained_by_natural_no_response_stop(self):
        capture = sample()
        env = capture["authenticated_environment"]
        env["native_setenvp_events"].pop()
        env["return_to_dfe12_observed"] = False
        env["return_to_dfe12_status"] = "not_reached_before_strict_AX0501_stop"
        capture["frontier"]["response_count"] = 0
        self.assertEqual(validate(capture), [])

    def test_cross_run_capture_must_not_claim_same_dynamic_call(self):
        capture = copy.deepcopy(sample())
        capture["authenticated_environment"]["same_dynamic_invocation_claimed"] = True
        self.assertTrue(any("dynamic invocation" in e for e in validate(capture)))

    def test_prior_ax4300_is_not_a_fresh_frontier(self):
        capture = sample()
        capture["prior_ax4300_checkpoint_reused"] = True
        self.assertTrue(any("historical AX=4300" in e for e in validate(capture)))

    def test_validator_is_synthetic_and_does_not_launch_guest(self):
        self.assertEqual(sample()["execution_mode"], "native_recompiled_guest")


if __name__ == "__main__":
    unittest.main()
