import hashlib as _hashlib


class _OrigDigest:
    """Stands in for a byte string taken from the original game.

    Only its SHA-256 and length are stored in the repository. Comparing it with
    bytes (or a hex string) from the user's own locally provided game files
    succeeds when they hash to the recorded value.
    """

    def __init__(self, sha256, length):
        self.sha256 = sha256
        self.length = length

    def __len__(self):
        return self.length

    def __eq__(self, other):
        if isinstance(other, str):
            try:
                other = bytes.fromhex(other.replace(" ", ""))
            except ValueError:
                return False
        if not isinstance(other, (bytes, bytearray, memoryview)):
            return NotImplemented
        other = bytes(other)
        return len(other) == self.length and _hashlib.sha256(other).hexdigest() == self.sha256

    def __ne__(self, other):
        r = self.__eq__(other)
        return r if r is NotImplemented else not r

    __hash__ = None

    def __repr__(self):
        return "<original bytes sha256=%s len=%d>" % (self.sha256, self.length)
import hashlib
import json
import pathlib
import sys
import unittest
from types import SimpleNamespace

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools' / 'probes'))
import unicorn_int21 as probe  # noqa: E402

class FakeUC:
    def __init__(self):
        self.values = {
            probe.UC_X86_REG_EAX: 0x11, probe.UC_X86_REG_EBX: 0x22,
            probe.UC_X86_REG_ECX: 0x33, probe.UC_X86_REG_EDX: 0x44,
            probe.UC_X86_REG_ESP: 0x55, probe.UC_X86_REG_ESI: 0x66,
            probe.UC_X86_REG_EDI: 0, probe.UC_X86_REG_EBP: 0x88,
            probe.UC_X86_REG_EIP: 0x194b5a, probe.UC_X86_REG_EFLAGS: 0x202,
            probe.UC_X86_REG_CS: 0x08, probe.UC_X86_REG_DS: 0x14,
            probe.UC_X86_REG_ES: 0x14, probe.UC_X86_REG_SS: 0x14,
            probe.UC_X86_REG_FS: 0, probe.UC_X86_REG_GS: 0,
        }
    def reg_read(self, reg):
        return self.values[reg]
    def mem_read(self, address, size):
        self.assert_address = address
        return bytes.fromhex('88070000') + bytes(max(0, size - 4))

class FaultContextTests(unittest.TestCase):
    def test_captures_registers_segments_bases_and_instruction(self):
        uc = FakeUC()
        ctx = probe.memory_fault_context(uc, SimpleNamespace(selectors={0x14: 0x2a0000}), 20, 0, 1, 0)
        self.assertEqual(ctx['eip'], '0x00194b5a')
        self.assertEqual(ctx['registers']['edi'], '0x00000000')
        self.assertEqual(ctx['segments']['ds'], '0x0014')
        self.assertEqual(ctx['known_selector_bases']['ds'], '0x002a0000')
        self.assertEqual(ctx['instruction_bytes'][:8], '88070000')
        self.assertEqual(uc.assert_address, 0x194b5a)

    def test_original_replay_has_current_fault_context_without_changing_stop(self):
        e = json.loads((ROOT / 'evidence/mscdex_fault_context_work2.json').read_text(encoding='utf-8'))
        self.assertEqual(e['target_sha256'], '2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f')
        for item in e['runtime_files']:
            self.assertTrue((ROOT / item['path']).is_file())
            self.assertEqual(len(item['sha256']), 64)
        combined = hashlib.sha256(''.join(x['path'] + ':' + x['sha256'] + '\n' for x in e['runtime_files']).encode()).hexdigest()
        self.assertEqual(combined, e['runtime_sha256'])
        fault = e['first_unsupported']
        self.assertEqual((fault['access'], fault['address'], fault['eip']), (20, '0x00000000', '0x00194b5a'))
        self.assertEqual(fault['registers']['edi'], '0x00000000')
        self.assertEqual(fault['segments']['ds'], '0x0014')
        self.assertEqual(fault['known_selector_bases']['ds'], '0x00000000')
        self.assertEqual(fault['instruction_bytes'], _OrigDigest("d008baf9247274b8dfcb3bf3dbdd807a5fb545e2d1ea2fb76af6bc55f70b720f",15))
        self.assertEqual(e['executed_instruction_count'], 7_771_728)
        self.assertEqual(e['stop_reason'], 'backend_error')

if __name__ == '__main__':
    unittest.main()
