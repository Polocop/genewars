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
import hashlib, json, pathlib, re, unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
PROVENANCE=ROOT/'evidence'/'setup_game_this_provenance_work3.json'
GATE=ROOT/'evidence'/'cd_present_gate_work3.json'
FAULT=ROOT/'evidence'/'mscdex_fault_context_current_work1.json'
CONTROL=ROOT/'evidence'/'dos_ah48_current_gate_work2.json'
EXIT_CLASS=ROOT/'evidence'/'local_process_exit_classification.json'
OPTION=ROOT/'evidence'/'startup_option_gate_work3.json'
MAP=ROOT/'evidence'/'genewars-1_1.map'
CLOSURE=ROOT/'build'/'entry_path_closure.c'
CUE=pathlib.Path(r'E:\GeneWarsFX\evidence\original_disc\Genewars (Europe) (En,Fr,De,Es,It,Sv).cue')
TARGET_SHA='2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f'
CUE_SHA='1d417e3aed625d4f054b51054a1211562a19cd4f712b08e7846613517228a5b5'

class SetupGameThisProvenance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=json.loads(PROVENANCE.read_text(encoding='utf-8-sig'))
        cls.gate=json.loads(GATE.read_text(encoding='utf-8-sig'))
        cls.fault=json.loads(FAULT.read_text(encoding='utf-8-sig'))
        cls.control=json.loads(CONTROL.read_text(encoding='utf-8-sig'))
        cls.option=json.loads(OPTION.read_text(encoding='utf-8-sig'))
        cls.exit_class=json.loads(EXIT_CLASS.read_text(encoding='utf-8-sig'))

    def test_target_fixture_cue_and_runtime_fingerprint(self):
        d=self.data
        self.assertEqual(d['target_sha256'],TARGET_SHA)
        self.assertEqual(d['fixture']['size'],0)
        self.assertEqual(d['fixture']['sha256'],hashlib.sha256(b'').hexdigest())
        self.assertEqual(d['cue_sha256_before'],CUE_SHA)
        self.assertEqual(d['cue_sha256_after'],CUE_SHA)
        self.assertEqual(hashlib.sha256(CUE.read_bytes()).hexdigest(),CUE_SHA)
        files=d['target_probe_runtime_files']
        for f in files:
            self.assertEqual(hashlib.sha256((ROOT/f['path']).read_bytes()).hexdigest(),f['sha256'],f['path'])
        agg=hashlib.sha256(''.join(x['path']+':'+x['sha256']+'\n' for x in files).encode()).hexdigest()
        self.assertEqual(d['runtime_fingerprint_sha256'],agg)

    def test_rebased_slot_has_no_prior_dynamic_writer(self):
        d=self.data; slot=d['this_global']
        self.assertEqual(slot['map_link_va'],'0x00114ca8')
        self.assertEqual(slot['rebase'],'0x00100000')
        self.assertEqual(slot['runtime_address'],'0x00214ca8')
        self.assertEqual(slot['initial_bytes_before_guest'],'00000000')
        self.assertEqual(slot['object']['index'],3)
        self.assertEqual(slot['object']['base'],0x200000)
        self.assertEqual(d['events_total'],1)
        ev=d['first_events']
        self.assertEqual([(x['kind'],x['eip'],x['slot_bytes_at_event']) for x in ev], [('read','0x00194b51','00000000')])
        self.assertEqual(ev[0]['registers']['edi'],'0x00217484')
        self.assertEqual(ev[0]['registers']['esp'],'0x002a8a44')
        self.assertEqual(ev[0]['registers']['ebp'],'0x002a8b22')
        self.assertEqual(ev[0]['segments'],{'cs':'0x000c','ds':'0x0014','es':'0x0014','ss':'0x0014','fs':'0x0000','gs':'0x0000'})
        self.assertEqual(ev[0]['eflags'],'0x00000246')
        self.assertEqual(ev[0]['gdtr'],'(0, 16384, 4359, 0)')
        self.assertEqual(ev[0]['ldtr'],'(8, 32768, 4095, 0)')
        self.assertTrue(set(ev[0]['stack_0x80'])=={'0'})

    def test_original_fault_and_static_reader_inventory(self):
        fault=self.data['first_unsupported']
        self.assertEqual((fault['address'],fault['eip'],fault['value']),('0x00000000','0x00194b5a',0))
        self.assertEqual(self.data['executed_instruction_count'],7771728)
        self.assertFalse(self.data.get('menu_reached',False))
        text=CLOSURE.read_text(encoding='utf-8')
        writes=re.findall(r'MEM(?:8|16|32)\([^\n]*0x114CA8[^\n]*\)\s*=',text,re.I)
        self.assertEqual(writes,[])
        reads=re.findall(r'MEM(?:8|16|32)\([^\n]*0x114CA8',text,re.I)
        self.assertGreaterEqual(len(reads),30)
        self.assertIn('0x0009433D: call 0x94ac0',text)
        map_text=MAP.read_text(encoding='utf-8',errors='replace')
        self.assertIn('0001:00093F30       main_',map_text)
        self.assertIn('0001:00094AC0       W?setup_game',map_text)
        self.assertIn('0003:00114CA8       this',map_text)
        roots=self.option['root_hits']
        self.assertIn('main_',roots); self.assertIn('setup_game',roots)

    def test_exit_zero_is_expected_no_cd_resource_exit(self):
        p=self.control['process_exit']
        self.assertEqual((p['code'],p['eip'],p['registers']['eax']&0xffff),(0,'0x001afc33',0x4c00))
        msg=[x for x in self.control['runtime_service_tail'] if (x.get('dos_filename') or {}).get('bytes','').startswith('2a2a2a47656e6577617273')]
        self.assertTrue(msg)
        self.assertEqual(msg[-1]['dos_filename']['bytes'],_OrigDigest('49ecb5290ebe8e42fd52b60b777fd82f2c5d9438037ab851eb762c5e73208f0f',44))
        self.assertEqual(self.data['stop_reason'],'backend_error')
        self.assertEqual(self.data['process_exit'],None)
        self.assertEqual(self.fault['last_guest_eip'],'0x00194b5a')

if __name__=='__main__': unittest.main()


