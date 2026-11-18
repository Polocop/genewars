import unittest

from tools.w3_105_trace_frontier import link_address, parse_events


class TraceFrontierTests(unittest.TestCase):
    def test_parses_int_string_and_hex_link_addresses(self):
        events = parse_events(
            '{"sequence":1,"link_va":"0x92710"}\n'
            '{"sequence":2,"link_va":336080}\n'
            '{"sequence":3,"link_va":"000A3A5C"}\n'
        )
        self.assertEqual(link_address(events[0]), 0x92710)
        self.assertEqual(link_address(events[1]), 336080)
        self.assertEqual(link_address(events[2]), 0xA3A5C)

    def test_ignores_malformed_and_unrelated_records(self):
        events = parse_events('{bad json}\n{"event":"noise","eip":123}\n')
        self.assertEqual(len(events), 1)
        self.assertIsNone(link_address(events[0]))

    def test_does_not_infer_link_va_from_runtime_eip(self):
        self.assertIsNone(link_address({"eip": 0x28A5C, "code_rebase": 0x1EB000}))


if __name__ == "__main__":
    unittest.main()
