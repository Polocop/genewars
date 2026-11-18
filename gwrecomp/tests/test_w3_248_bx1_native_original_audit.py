import unittest

from tools.w3_248_bx1_native_original_audit import reconcile


def fixture(native_tail=" -k 38928", original_tail=" -k 38928", original_call_eax="5"):
    native = {
        "frontier": {
            "guest_eip": "0x000c8973",
            "function_entry": "0x000c896a",
            "request_ax": "0x00004400",
            "stop_reason": "fresh native DOS interrupt trap",
            "request_registers": {"vector": "21", "function": "000c896a", "eax": "00004400",
                                  "ebx": "00000001", "ecx": "00000000", "edx": "0010a822", "esp": "001a89d0"},
        },
        "argv": {"values": [r"C:\GENEWARS\GW.EXE", "-k", "38928"]},
        "caller_provenance": {"dynamic_caller": "__chktty_ -> isatty_"},
        "fixtures": {"native": {"address_txt_sha256": "abc"}},
    }
    original = {
        "effective_psp_tail": original_tail,
        "preflight": {"target_sha256": "target", "staging_revision": "pinned", "cue_sha256": "cue", "config_sha256": "config"},
        "mapping": {"process_psp": 7811, "code_rebase": 0x1EB000, "data_rebase": 0x1DA000},
        "chktty_callpoints": [{"sequence": 43, "checkpoint": "AH44_CHKTTY_ISATTY_CALL", "eax": original_call_eax}],
        "bx1": {"sequence": 104, "link_va": "0x000c8973", "eax_hex": "0x00004400", "ebx_hex": "0x00000001",
                "ecx_hex": "0x00000000", "edx_hex": "0x002e41a2", "esp_hex": "0x00382470", "eflags_hex": "0x246",
                "cs_hex": "0x0160", "ds_hex": "0x0168", "es_hex": "0x0168", "ss_hex": "0x0168", "process_psp": 7811},
        "address_txt_initial": {"size": 24, "sha256": "abc", "source_provenance": "read-only source"},
    }
    old = {"same_run_response_contracts": [
        {"source": "W3-236", "pre_dispatch_sequence": 104, "callback_sequence": 107,
         "request": {"ax": "0x4400", "bx": "0x1"}, "response": {"ax": "0x80d3", "dx": "0x80d3", "cf": False},
         "dos_context": {"handle": 1, "resolved_path": "CON", "default_drive": "C", "cwd": "GENEWARS"}},
        {"source": "W3-091", "pre_dispatch_sequence": 99, "callback_sequence": 101,
         "request": {"ax": "0x4400", "bx": "0x1"}, "response": {"ax": "0x80d3", "dx": "0x80d3", "cf": False},
         "dos_context": {"handle": 1, "resolved_path": "CON", "default_drive": "C", "cwd": "GENEWARS"}},
    ]}
    hashes = {"native": {"sha256": "n"}, "original_run": {"sha256": "o"}}
    return native, original, old, hashes


class W3248Bx1AuditTests(unittest.TestCase):
    def test_same_tail_and_ax_bx_cx_are_compared(self):
        n, o, old, hashes = fixture()
        result = reconcile(n, o, {}, old, hashes)
        self.assertTrue(result["request_comparison"]["command_tail_equal"])
        self.assertEqual(result["classification"], "SAME_SERVICE_AND_TAIL_CROSS_RUN_CORROBORATION_CALLER_UNRESOLVED")
        self.assertTrue(result["request_comparison"]["fields"]["AX"]["equal"])
        self.assertTrue(result["request_comparison"]["fields"]["BX"]["equal"])
        self.assertTrue(result["request_comparison"]["fields"]["CX"]["equal"])

    def test_address_registers_do_not_become_a_semantic_mismatch(self):
        n, o, old, hashes = fixture()
        result = reconcile(n, o, {}, old, hashes)
        self.assertFalse(result["request_comparison"]["fields"]["DX_EDX_address_value"]["equal"])
        self.assertIn("not compared as semantic input", result["request_comparison"]["fields"]["DX_EDX_address_value"]["interpretation"])
        self.assertIsNone(result["request_comparison"]["fields"]["EFLAGS_CS_DS_ES_SS"]["equal"])

    def test_eax5_call_does_not_get_attributed_to_later_bx1(self):
        n, o, old, hashes = fixture(original_call_eax="5")
        result = reconcile(n, o, {}, old, hashes)
        self.assertEqual(result["original_call_chain"]["dynamic_caller_for_bx1"], "UNKNOWN")
        self.assertEqual(result["original_call_chain"]["matching_eax1_chktty_callpoint_before_bx1"], [])
        self.assertFalse(result["request_comparison"]["same_dynamic_invocation"])

    def test_tail_mismatch_is_explicit_and_response_remains_original_only(self):
        n, o, old, hashes = fixture(original_tail="")
        result = reconcile(n, o, {}, old, hashes)
        self.assertFalse(result["request_comparison"]["command_tail_equal"])
        self.assertFalse(result["original_response_contract"]["native_response_observed"])
        self.assertEqual(result["original_response_contract"]["W3_236_same_run"]["response"]["ax"], "0x80d3")


if __name__ == "__main__":
    unittest.main()
