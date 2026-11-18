import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class NativeAx0501SequenceSourceTests(unittest.TestCase):
    def test_sequence_mode_uses_runtime_and_is_bounded(self):
        source = (ROOT / "tests" / "test_native_guest_image.c").read_text(encoding="utf-8")
        self.assertIn("native_dos_ah25_count==0u", source)
        start = source.rindex("#ifdef GW_NATIVE_CONTINUE_DPMI_LINEAR_SEQUENCE")
        end = source.index("#ifdef GW_NATIVE_CONTINUE_DOS_AH48", start)
        block = source[start:end]
        self.assertIn("gw_dos_services_callback(vector,va,services)", block)
        self.assertIn("w1_090_dpmi_sequence_count>=16u", block)
        self.assertIn("w1_090_dpmi_sequence_failed", block)
        self.assertIn("native_dos_ah25_count>0u", block)
        self.assertIn("provider=gw_dos_services_callback arena=synthetic", block)
        self.assertIn("cursor_before", block)
        self.assertIn("cursor_after", block)
        self.assertIn("0x8012u", block)
        self.assertNotIn("0x01001000u", block)

    def test_cli_requires_authenticated_post_ah25_replay(self):
        source = (ROOT / "tests" / "test_native_guest_image.py").read_text(encoding="utf-8")
        self.assertIn("--continue-dpmi-linear-sequence", source)
        self.assertIn("args.continue_dos_ah25", source)
        self.assertIn("args.serve_w3_functional_config", source)
        self.assertIn("NATIVE_DPMI_AX0501_SEQUENCE ", source)
        self.assertIn("NATIVE_W1_090_AX0501_DISPATCH_PROBE ", source)
        self.assertIn("w1_090_ax0501_sequence", source)
        self.assertIn("NATIVE_DPMI_AX0501_SEQUENCE ", source)


if __name__ == "__main__":
    unittest.main()
