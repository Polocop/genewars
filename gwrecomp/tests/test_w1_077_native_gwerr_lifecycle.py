import unittest
from tools.verify_w1_077_native_gwerr_lifecycle import validate_capture

def sample():
    return {"task":"W1-077","schema":"gwrecomp.native-gwerr-handle-lifecycle-w1-077/v1",
      "fresh_replay":True,"target_sha256":"2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f",
      "w1_077_lifecycle":{"observer_enabled":True,"event_cap":32,"request_event_count":1,
        "events":[{"ordinal":"0","kind":"open","path_valid":"1","path_length":"3",
                   "path_terminated":"1","path_hex":"414243"}],
        "process_context":{"model":"single-native-guest","harness_psp_selector":"0010","harness_psp_linear":"00100000"},
        "ah4400_observations":["W1_CRT_DOS_AX4400_FILE eip=000c8973 eax_in=00004400"],
        "ah4400_observation_count":1,"lifecycle_coverage":"bounded callback requests; no PSP JFT is inferred",
        "same_dynamic_invocation_claimed":False,"causality_claimed":False}}

class W1077LifecycleValidator(unittest.TestCase):
    def test_valid_bounded_capture(self):
        self.assertEqual(validate_capture(sample()),[])
    def test_unknown_gwerr_is_not_required_or_inferred(self):
        capture=sample(); capture["w1_077_lifecycle"]["events"]=[]; capture["w1_077_lifecycle"]["request_event_count"]=0
        self.assertEqual(validate_capture(capture),[])
    def test_rejects_over_cap_and_unterminated_path(self):
        capture=sample(); capture["w1_077_lifecycle"]["event_cap"]=33
        capture["w1_077_lifecycle"]["events"][0]["path_terminated"]="0"
        errors=validate_capture(capture)
        self.assertTrue(any("bounded observer" in x for x in errors))
        self.assertTrue(any("path bounds" in x for x in errors))

if __name__=="__main__": unittest.main()
