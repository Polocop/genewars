import json
import unittest

from tools.w3_230_gwerr_dispatch_capture import (
    DispatchState, append_once, correlate_events, correlate_open, decode_dispatch,
    decode_fcb_name, dispatch_candidate_allowed, normalize_path, read_bounded_c_string,
)


def state(ax, *, psp=7811, dx=0, si=0):
    return DispatchState(psp, ax, 1, 0x1234, dx, si, 0x55, 0x160, 0x123456,
                         0x202, 0x168, 0x168, 0x2000)


class W3230DispatchCaptureTests(unittest.TestCase):
    def test_3d_6c_are_decoded_from_their_distinct_path_registers(self):
        memory = bytearray(256)
        memory[20:27] = b"GW.ERR\0"
        memory[40:47] = b"GW.ERR\0"
        ah3d = decode_dispatch("INT21_AH3D", state(0x3D00, dx=20), bytes(memory), target_psp=7811)
        ah6c = decode_dispatch("INT21_AH6C", state(0x6C00, si=40), bytes(memory), target_psp=7811)
        self.assertEqual(ah3d["requested_path"], "GW.ERR")
        self.assertEqual(ah3d["pathname_pointer"]["offset"], 20)
        self.assertEqual(ah6c["pathname_pointer"]["offset"], 40)
        self.assertEqual(ah6c["service"], "INT21_AH6C")

    def test_exact_path_psp_service_and_pointer_bounds_are_required(self):
        memory = b"x" * 64 + b"OTHER.DAT\0"
        self.assertIsNone(decode_dispatch("INT21_AH3D", state(0x3D00, psp=123, dx=64), memory, target_psp=7811))
        self.assertIsNone(decode_dispatch("INT21_AH3D", state(0x3D00, dx=64), memory, target_psp=7811))
        self.assertIsNone(decode_dispatch("INT21_AH3D", state(0x4000, dx=64), memory, target_psp=7811))
        self.assertIsNone(read_bounded_c_string(memory, -1))
        self.assertIsNone(read_bounded_c_string(b"GW.ERR", 0))
        self.assertEqual(normalize_path("c:/GENEWARS/GW.ERR"), "GENEWARS\\GW.ERR")
        self.assertFalse(decode_dispatch("INT21_AH3D", state(0x3D00, dx=64), b"x" * 64 + b"GENEWARS\\GW.ERR\0", target_psp=7811) is None)

    def test_target_gwerr_can_be_filtered_before_setup_capture_activation(self):
        self.assertTrue(dispatch_candidate_allowed(target_file_complete=True,
                                                   process_psp=7811, target_psp=7811))
        self.assertIsNotNone(decode_dispatch("INT21_AH3D", state(0x3D00, dx=0),
                                             b"GW.ERR\0", target_psp=7811))
        self.assertFalse(dispatch_candidate_allowed(target_file_complete=False,
                                                    process_psp=7811, target_psp=7811))
        self.assertFalse(dispatch_candidate_allowed(target_file_complete=True,
                                                    process_psp=9, target_psp=7811))

    def test_fcb_standard_83_name_and_open_create_service_tags(self):
        fcb = bytes([0]) + b"GW      ERR" + bytes(25)
        self.assertEqual(decode_fcb_name(fcb), "GW.ERR")
        opened = decode_dispatch("INT21_AH0F_FCB_OPEN", state(0x0F00, dx=5), b"", target_psp=7811, fcb_bytes=fcb)
        created = decode_dispatch("INT21_AH16_FCB_CREATE", state(0x1600, dx=5), b"", target_psp=7811, fcb_bytes=fcb)
        self.assertEqual(opened["service"], "INT21_AH0F_FCB_OPEN")
        self.assertEqual(created["service"], "INT21_AH16_FCB_CREATE")

    def test_one_event_cap_json_bound_and_correlation(self):
        event = {"process_psp": 7811, "requested_path": "GW.ERR", "service": "INT21_AH6C"}
        items = []
        self.assertTrue(append_once(items, event))
        self.assertFalse(append_once(items, event))
        self.assertTrue(correlate_open(event, {"process_psp": 7811, "requested_path": "gw.err"}))
        self.assertFalse(correlate_open(event, {"process_psp": 9, "requested_path": "gw.err"}))
        self.assertLess(len(json.dumps(items).encode()), 16 * 1024)

    def test_trace_event_correlation_requires_order_psp_and_bounded_gap(self):
        dispatch = {"event": "w3_230_gwerr_dos_dispatch_entry", "sequence": 10,
                    "service": "INT21_AH6C", "process_psp": 7811, "requested_path": "GW.ERR"}
        opened = {"event": "dos_handle_open", "sequence": 11, "process_psp": 7811,
                  "requested_path": "gw.err", "path": "GENEWARS\\GW.ERR", "flags": 1}
        result = correlate_events([dispatch, opened])
        self.assertEqual(result["classification"], "ORIGINAL_SERVICE_AND_OPEN_CORRELATED")
        self.assertEqual(result["dispatch"]["service"], "INT21_AH6C")
        self.assertEqual(correlate_events([dispatch, {**opened, "process_psp": 9}])["handle_open"], None)
        self.assertEqual(correlate_events([dispatch, {**opened, "sequence": 19}])["handle_open"], None)


if __name__ == "__main__":
    unittest.main()
