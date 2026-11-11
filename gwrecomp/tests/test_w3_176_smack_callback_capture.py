"""No-oracle validation for the corrected W3-176 indirect-JMP contract."""
import hashlib
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def validate_contract(dispatch, handler, reentry, sample_a, sample_b, mapping):
    if mapping.get("fresh") is not True:
        return False
    if mapping.get("code_rebase") != 0x1EB000 or mapping.get("data_rebase") != 0x1DA000:
        return False
    if dispatch.get("link_va") != 0xEDE94 or dispatch.get("psp") != 7811:
        return False
    if handler.get("link_va") != 0xECCF0 or handler.get("psp") != 7811:
        return False
    if handler.get("sequence", 0) <= dispatch.get("sequence", 0):
        return False
    if handler.get("runtime_eip") != handler.get("link_va", 0) + mapping["code_rebase"]:
        return False
    if reentry.get("link_va") != 0xEDE94 or reentry.get("psp") != 7811:
        return False
    if reentry.get("sequence", 0) <= handler.get("sequence", 0):
        return False
    if reentry.get("sample_bytes") + sample_a.get("sample_bytes", 0) > 96:
        return False
    for sample in (sample_a, sample_b):
        windows = sample.get("windows", [])
        if [w.get("offset") for w in windows] != [0, 32000, 63984]:
            return False
        if any(w.get("bytes") != 16 or len(w.get("hex", "")) != 32 for w in windows):
            return False
        if sum(w["bytes"] for w in windows) != 48:
            return False
    return True


def actual_contract():
    doc181 = json.loads((ROOT / "evidence/w3_181_smackinternal010_progress.json").read_text(encoding="utf-8"))
    doc189 = json.loads((ROOT / "evidence/w3_189_wscreen_temporal_reconciliation.json").read_text(encoding="utf-8"))
    same = doc189["w3_181_same_run"]
    trace_path = ROOT / doc181["trace"]["path"]
    trace_hash = hashlib.sha256(trace_path.read_bytes()).hexdigest()
    if trace_hash != doc181["trace"]["sha256"]:
        raise AssertionError("W3-181 trace hash mismatch")
    if trace_path.stat().st_size != doc181["trace"]["bytes"]:
        raise AssertionError("W3-181 trace size mismatch")
    first = doc181["first_dispatch"]
    handler = doc181["handler_entry"]
    reentry = doc181["dispatcher_reentry"]
    mapping = {"fresh": True, "code_rebase": int(doc181["code_rebase"], 16), "data_rebase": int(doc181["data_rebase"], 16)}
    dispatch = {"link_va": first["link_va"], "psp": doc181["psp"], "sequence": first["sequence"]}
    handler_row = {"link_va": handler["link_va"], "psp": handler["process_psp"], "sequence": handler["sequence"], "runtime_eip": handler["eip"]}
    reentry_row = {"link_va": reentry["link_va"], "psp": reentry["process_psp"], "sequence": reentry["sequence"], "sample_bytes": sum(x["bytes"] for x in same["dispatcher_reentry"])}
    sample_a = {"windows": same["first_dispatch"], "sample_bytes": sum(x["bytes"] for x in same["first_dispatch"])}
    sample_b = {"windows": same["dispatcher_reentry"], "sample_bytes": sum(x["bytes"] for x in same["dispatcher_reentry"])}
    return doc181, doc189, trace_hash, dispatch, handler_row, reentry_row, sample_a, sample_b, mapping


def build_result():
    doc181, doc189, trace_hash, dispatch, handler, reentry, sample_a, sample_b, mapping = actual_contract()
    if not validate_contract(dispatch, handler, reentry, sample_a, sample_b, mapping):
        raise ValueError("stored W3-181/189 evidence does not satisfy corrected W3-176 criteria")
    return {
        "schema": "gwrecomp-w3-176-indirect-dispatch-reconciliation/v1",
        "task": "W3-176",
        "status": "DONE",
        "classification": "ORIGINAL_OBSERVED_DISPATCH_TARGET_AND_REENTRY",
        "evidence_level": "ORIGINAL_OBSERVED",
        "source_tasks": ["W3-181", "W3-189"],
        "run": {
            "run_id": doc181["run_id"],
            "trace_path": doc181["trace"]["path"],
            "trace_bytes": doc181["trace"]["bytes"],
            "trace_sha256": trace_hash,
            "event_count": doc181["trace"]["event_count"],
            "target_sha256": doc181["source"]["target_sha256"],
            "config_sha256": doc181["source"]["config_sha256"],
            "cue_sha256": doc181["source"]["cue_sha256"],
            "staging_revision": doc181["source"]["staging_revision"],
            "staging_binary_sha256": doc181["source"]["staging_binary_sha256"],
            "code_rebase": doc181["code_rebase"],
            "data_rebase": doc181["data_rebase"],
            "psp": doc181["psp"],
            "guard_sandbox_verified": doc181["guard"]["sandbox_verified"],
            "guard_stop": doc181["guard"]["cause"],
        },
        "dispatch": {
            "link_va": "0x000EDE94",
            "sequence": dispatch["sequence"],
            "eax": doc181["first_dispatch"]["eax"],
            "selected_index": 0,
            "selected_target_link_va": doc181["selected_target_link_va"],
            "target_verified": doc181["target_symbol_valid"],
        },
        "handler": {
            "link_va": "0x000ECCF0",
            "sequence": handler["sequence"],
            "runtime_eip": "0x002D7CF0",
            "edx": doc181["handler_entry"]["edx"],
            "target_matches_dispatch": True,
        },
        "dispatcher_reentry": {
            "link_va": "0x000EDE94",
            "sequence": reentry["sequence"],
            "same_psp": True,
            "same_mapping": True,
        },
        "mapping": {
            "freshly_verified": True,
            "code_rebase": doc181["code_rebase"],
            "data_rebase": doc181["data_rebase"],
            "cs_selector": "0x0160",
            "ds_selector": "0x0168",
        },
        "wscreen_samples": {
            "pointer": doc189["w3_181_same_run"]["wscreen_pointer"],
            "descriptor_checks": doc189["w3_181_same_run"]["descriptor_checks"],
            "bytes_per_checkpoint": 48,
            "total_bytes": 96,
            "dispatch": sample_a["windows"],
            "reentry": sample_b["windows"],
            "changed_windows": doc189["w3_181_same_run"]["changed_windows"],
        },
        "control_transfer": {
            "instruction": "indirect JMP",
            "callback_stack_return": "NOT_APPLICABLE; no CALL return is inferred",
        },
        "limitations": [
            "The separate 0xECD40 progress checkpoint was not observed in W3-181; it is outside this task's corrected dispatch/target/re-entry acceptance.",
            "Sparse byte changes are raw WScreen memory observations, not pixel decoding or a complete frame.",
            "No host VGA mapping, visible framebuffer, menu, or gameplay is verified.",
            "The original guarded run ended at its 30-second timeout after these checkpoints; it did not exit naturally.",
        ],
        "first_framebuffer_verified": False,
        "menu_verified": False,
        "gameplay_verified": False,
    }


class SmackDispatchCaptureTests(unittest.TestCase):
    def test_original_evidence_meets_corrected_dispatch_and_reentry_scope(self):
        doc181, doc189, trace_hash, dispatch, handler, reentry, a, b, mapping = actual_contract()
        self.assertEqual(trace_hash, "c077feb9302e90a912a331df5c3752b0bc681783b891e2e38d4d13ccac9daba6")
        self.assertEqual(doc181["selected_target_link_va"], "0xeccf0")
        self.assertEqual(doc189["w3_181_same_run"]["dispatcher_link_va"], "0x000EDE94")
        self.assertTrue(validate_contract(dispatch, handler, reentry, a, b, mapping))

    def test_no_callback_stack_return_is_required_for_indirect_jmp(self):
        _, _, _, dispatch, handler, reentry, a, b, mapping = actual_contract()
        self.assertTrue(validate_contract(dispatch, handler, reentry, a, b, mapping))

    def test_rejects_wrong_mapping_target_or_event_order(self):
        _, _, _, dispatch, handler, reentry, a, b, mapping = actual_contract()
        self.assertFalse(validate_contract(dispatch, handler, reentry, a, b, {**mapping, "code_rebase": 0}))
        self.assertFalse(validate_contract(dispatch, {**handler, "link_va": 0xED030}, reentry, a, b, mapping))
        self.assertFalse(validate_contract(dispatch, handler, {**reentry, "sequence": handler["sequence"]}, a, b, mapping))

    def test_rejects_missing_or_oversized_sparse_samples(self):
        _, _, _, dispatch, handler, reentry, a, b, mapping = actual_contract()
        self.assertFalse(validate_contract(dispatch, handler, reentry, {"windows": [], "sample_bytes": 0}, b, mapping))
        oversized = {"windows": a["windows"] + a["windows"], "sample_bytes": 96}
        self.assertFalse(validate_contract(dispatch, handler, reentry, oversized, b, mapping))


if __name__ == "__main__":
    unittest.main()
