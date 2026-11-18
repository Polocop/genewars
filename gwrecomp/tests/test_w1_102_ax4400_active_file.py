import unittest
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ActiveHandleIoctlRoutingTests(unittest.TestCase):
    def test_console_replay_routes_redirected_handle_two_to_runtime_file_provider(self):
        source = (ROOT / "tests" / "test_native_guest_image.c").read_text(encoding="utf-8")
        start = source.index("#ifdef GW_NATIVE_CONTINUE_DOS_AX4400_CONSOLE\n    /* The original CRT")
        end = source.index("#ifdef GW_NATIVE_CONTINUE_DPMI_AX0200", start)
        dispatch = source[start:end]
        self.assertIn("va==0x000C8973u", dispatch)
        self.assertIn("g_ebx==2u", dispatch)
        self.assertIn("services->files[i].active", dispatch)
        self.assertIn("services->files[i].dos_handle==2u", dispatch)
        self.assertIn("gw_dos_services_callback(vector,va,services)", dispatch)
        self.assertIn("provider=file_ioctl_info", dispatch)
        self.assertIsNone(re.search(r"\bg_edx\s*=(?!=)", dispatch))

    def test_console_replay_routes_ah40_write_to_same_active_guest_file(self):
        source = (ROOT / "tests" / "test_native_guest_image.c").read_text(encoding="utf-8")
        start = source.index("#ifdef GW_NATIVE_CONTINUE_DOS_AX4400_CONSOLE\n    /* The original CRT")
        end = source.index("#ifdef GW_NATIVE_CONTINUE_DPMI_AX0200", start)
        dispatch = source[start:end]
        self.assertIn("va==0x000D219Cu", dispatch)
        self.assertIn("(uint16_t)g_eax==0x4002u && g_ebx==2u", dispatch)
        self.assertIn("services->files[i].active", dispatch)
        self.assertIn("services->files[i].dos_handle==2u", dispatch)
        self.assertIn("gw_dos_services_callback(vector,va,services)", dispatch)
        self.assertIn("host_write=0 provider=virtual_file_write", dispatch)
        self.assertIsNone(re.search(r"\bg_eax\s*=(?!=)", dispatch))


if __name__ == "__main__":
    unittest.main()
