from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"


def capture_enabled(value: str) -> bool:
    return value == "1"


class W3237CaptureFlagCacheTests(unittest.TestCase):
    def test_dispatcher_flag_is_cached_and_opt_in_expression_is_preserved(self):
        source = SOURCE.read_text(encoding="utf-8")
        declaration = ('static const bool w3_237_capture_only =\n'
                       '\t        exec_trace::string_from_env("GWRECOMP_W3_237_CAPTURE_ONLY") == "1";')
        self.assertIn(declaration, source)
        self.assertEqual(source.count('string_from_env("GWRECOMP_W3_237_CAPTURE_ONLY")'), 1)
        self.assertNotRegex(source, r"(?m)^\s*const bool w3_237_capture_only =")

    def test_opt_in_gate_enabled_and_disabled(self):
        self.assertFalse(capture_enabled(""))
        self.assertFalse(capture_enabled("0"))
        self.assertFalse(capture_enabled("true"))
        self.assertTrue(capture_enabled("1"))

    def test_target_selection_stays_scoped_to_isatty_sites(self):
        source = SOURCE.read_text(encoding="utf-8")
        for site in ("0x000c896a", "0x000c8973", "0x000c8975"):
            self.assertIn(site, source)
        self.assertIn("w3_237_probe_window", source)


if __name__ == "__main__":
    unittest.main()
