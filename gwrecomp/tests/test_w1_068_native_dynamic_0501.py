"""Synthetic evidence-contract tests for the dynamic-size AX=0501 replay."""
import copy, hashlib, unittest
from tools.verify_w1_068_native_dynamic_0501 import ENV_SHA, TARGET_SHA, validate

def sample():
    request=0x400
    return {
        "task":"W1-068","task_schema":"gwrecomp.native-setenvp-dpmi-continue/v1","target_sha256":TARGET_SHA,"evidence_level":"NATIVE_REACHED",
        "authenticated_environment":{"size_bytes":86,"sha256":ENV_SHA,"exact_bytes_loaded":True},
        "prior_capture":{"path":"evidence/native_setenvp_aligned_replay_w1_066.json","sha256":"a"*64,"observed_request_size_bytes":f"0x{request:08X}","separate_dynamic_run":True},
        "native_generated_c_progress":{"dpmi_linear_allocation":{"vector":"0x31","instruction_va":"0x000C3CC1","request_eax":"0x00000501","request_ebx":"0x00000000","request_ecx":f"0x{request:08X}","response_eax":"0x00000501","response_ebx":"0x00000020","response_ecx":"0x00000000","response_esi":"0x00000000","response_edi":"0x00000001","carry":0,"handled":1,"synthetic_base":"0x00200000","synthetic_size":f"0x{request:08X}","synthetic_handle":"0x00000001"}},
        "allocator_service":{"request_matches_prior_capture":True,"arena_kind":"synthetic_test_arena","response_is_guest_state_injection":False,"original_base_or_handle_reused":False,"response_source":"existing gw_dos_services_callback bounded linear allocator"},
        "next_frontier":{"vector":"0x31","eip":"0x000C3CC1"},"menu_reached":False,"framebuffer_reached":False,
        "crt_startup":{"callback_count_before_stop":9,"argc":0,"argv":[]},"setenvp_return":{"observed":False,"event":None}}

class Dynamic0501EvidenceTests(unittest.TestCase):
    def test_dynamic_nonzero_request_can_validate(self): self.assertEqual(validate(sample()),[])
    def test_zero_request_fails(self):
        data=sample();data["native_generated_c_progress"]["dpmi_linear_allocation"]["request_ecx"]="0x00000000";self.assertTrue(any("measured request" in e for e in validate(data)))
    def test_wrong_dynamic_size_fails(self):
        data=sample();data["native_generated_c_progress"]["dpmi_linear_allocation"]["synthetic_size"]="0x00000800";self.assertTrue(any("allocation record" in e for e in validate(data)))
    def test_original_base_or_handle_reuse_is_rejected(self):
        data=sample();data["allocator_service"]["original_base_or_handle_reused"]=True;self.assertTrue(any("provenance" in e for e in validate(data)))
    def test_dynamic_invocation_identity_must_remain_unclaimed(self):
        data=sample();data["prior_capture"]["separate_dynamic_run"]=False;self.assertTrue(any("invocation identity" in e for e in validate(data)))
    def test_menu_and_framebuffer_are_not_inferred(self):
        data=sample();data["menu_reached"]=True;self.assertTrue(any("overclaims" in e for e in validate(data)))

if __name__=="__main__": unittest.main()
