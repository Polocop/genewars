"""Synthetic-only checks for the W3-293 PIT instrumentation scope audit."""

import unittest

from tools.w3_293_pit_port_capture import inspect_scope


class W3293PitCaptureScopeTests(unittest.TestCase):
    def test_actual_byte_io_callbacks_and_ownership_gap_are_explicit(self):
        result = inspect_scope()
        self.assertTrue(all(result["source_checks"].values()))
        self.assertFalse(result["decoder_owned_by_task"])
        self.assertIn("BLOCKED_SCOPE", result["resolution"])


if __name__ == "__main__":
    unittest.main()
