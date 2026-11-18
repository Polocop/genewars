import json, pathlib, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
class DosAh48OriginalByteTests(unittest.TestCase):
    def test_measured_request_and_followup_are_served(self):
        result=json.loads((ROOT/'evidence'/'dos_ah48_work2.json').read_text())
        self.assertEqual(result['target_sha256'],'2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f')
        calls=[i for i in result['interrupt_tail'] if i.get('vector')==0x21 and i.get('service','').startswith('dos21.allocate_memory')]
        self.assertGreaterEqual(len(calls),2)
        first=calls[-2]
        self.assertEqual(first['eip_int_opcode_assumption'],'0x001c3d21')
        self.assertEqual(first['registers']['ebx'],'0x00000001')
        self.assertEqual(first['registers_after']['eax'], '0x00009fca')
        self.assertFalse(int(first['registers_after']['eflags'],16)&1)
        second=calls[-1]
        self.assertEqual(second['registers']['ebx'],'0x00001000')
        self.assertEqual(second['registers_after']['eax'],'0x00000008')
        self.assertEqual(second['registers_after']['ebx'],'0x00000034')
        self.assertTrue(int(second['registers_after']['eflags'],16)&1)
        self.assertEqual(result['first_unsupported']['kind'],'cpu_exception')
        self.assertEqual(result['first_unsupported']['vector'],13)
        self.assertEqual(result['first_unsupported']['eip'],'0x001c3d42')
        memory=result['dos_memory_state']
        self.assertEqual(memory['dos_ah48_allocations']['40906'],[40905,1])
        self.assertEqual(memory['dos_free_blocks']['40907'],52)
if __name__=='__main__': unittest.main()
