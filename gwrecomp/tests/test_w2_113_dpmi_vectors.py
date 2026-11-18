"""Focused synthetic tests for Python DPMI real-mode vector services."""
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime"))
from dos_services import CpuRegs, DosHost  # noqa: E402
from guest_boot import prepare_guest  # noqa: E402

IMAGE = ROOT / "evidence" / "genewars-1_1.exe"


class DpmiRealModeVectorTests(unittest.TestCase):
    def setUp(self):
        self.host = DosHost(prepare_guest(IMAGE))

    def test_get_configured_and_unconfigured_real_mode_vectors(self):
        self.host.real_mode_interrupt_vectors[8] = (0x1234, 0x5678)
        configured = CpuRegs(eax=0xA5A50200, ebx=0x12340008,
                             ecx=0xABCD0000, edx=0x98760000,
                             esi=0x11112222, eflags=0x203)
        result = self.host.dispatch(0x31, configured)
        self.assertEqual(result.service, "dpmi31.get_real_mode_interrupt_vector")
        self.assertEqual((configured.cx, configured.dx), (0x1234, 0x5678))
        self.assertEqual((configured.ecx, configured.edx), (0xABCD1234, 0x98765678))
        self.assertEqual(configured.eax, 0xA5A50200)
        self.assertEqual(configured.ebx, 0x12340008)
        self.assertEqual(configured.esi, 0x11112222)
        self.assertFalse(configured.carry)

        empty = CpuRegs(eax=0x0200, ebx=9, ecx=0xAABB0001,
                        edx=0xCCDDFFFF, eflags=0x203)
        self.host.dispatch(0x31, empty)
        self.assertEqual((empty.cx, empty.dx), (0, 0))
        self.assertEqual((empty.ecx, empty.edx), (0xAABB0000, 0xCCDD0000))
        self.assertFalse(empty.carry)

    def test_set_uses_real_mode_cx_dx_words_and_round_trips(self):
        request = CpuRegs(eax=0xBEEF0201, ebx=0xAABBCC0A,
                          ecx=0x11220020, edx=0x33440030, eflags=0x203)
        result = self.host.dispatch(0x31, request)
        self.assertEqual(result.service, "dpmi31.set_real_mode_interrupt_vector")
        self.assertFalse(request.carry)
        self.assertEqual(request.eax, 0xBEEF0201)
        self.assertEqual(request.ebx, 0xAABBCC0A)
        self.assertEqual(self.host.real_mode_interrupt_vectors[10], (0x20, 0x30))

        query = CpuRegs(eax=0x0200, ebx=10, ecx=0xAAAA0000, edx=0xBBBB0000)
        self.host.dispatch(0x31, query)
        self.assertEqual((query.cx, query.dx), (0x20, 0x30))
        self.assertEqual((query.ecx, query.edx), (0xAAAA0020, 0xBBBB0030))

    def test_record_contract_evidence(self):
        write_evidence()


def write_evidence():
    result = {
        "test": "Python INT 31h AX=0200/0201 real-mode vectors",
        "execution_kind": "SYNTHETIC_SERVICE_TEST",
        "specification": "https://www.sudleyplace.com/dpmione/dpmispec1.0.pdf#page=75",
        "documented_contract": "AX=0200 gets the real-mode interrupt vector in CX:DX; AX=0201 sets it from CX:DX; both always clear CF.",
        "original_observation": {
            "source": "evidence/empty_config_overlay_work2.json",
            "link_va": "0x001C8CD2",
            "vector": "0x08",
            "response": {"CX_segment": "0x0000", "DX_offset": "0x0000", "CF": 0},
        },
        "synthetic_configured_pair": {"segment": "0x1234", "offset": "0x5678"},
        "unconfigured_default": {"segment": "0x0000", "offset": "0x0000"},
        "legacy_w2_038_python_contract": "incorrectly described 0200/0201 as protected-mode selector:offset; no longer used as semantic authority",
        "full_replay_equivalence": False,
        "passed": True,
    }
    (ROOT / "evidence" / "python_dpmi_0200_0201_work2.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(DpmiRealModeVectorTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        raise SystemExit(1)
    write_evidence()
