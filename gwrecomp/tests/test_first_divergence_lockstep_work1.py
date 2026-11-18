import importlib.util
import json
import sys
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
_spec=importlib.util.spec_from_file_location("gwrecomp_first_divergence", ROOT/"tools"/"first_divergence_lockstep.py")
_module=importlib.util.module_from_spec(_spec)
sys.modules[_spec.name]=_module
_spec.loader.exec_module(_module)
first_difference, compare_runs, rationalalloc_corpus = (_module.first_difference,
    _module.compare_runs, _module.rationalalloc_corpus)
class FirstDivergenceLockstepTests(unittest.TestCase):
    def pair(self, backend, **changes):
        x={'backend':backend,'checkpoint':'fn:block:1','function':'f','va':'0x1010','eip':'0x1010',
           'registers':{'eax':'0x1','ebx':'0x2','ecx':'0x3','edx':'0x4','esi':'0x5','edi':'0x6','ebp':'0x2010','esp':'0x3010'},
           'flags':{'eflags':'0x202','cf':False},'segments':{'cs':'0xc','ds':'0x14','es':'0x24','ss':'0x14','fs':None,'gs':None},
           'descriptors':None,'event':{'kind':'int','vector':49},'dirty_memory':None,'call_context':None}
        x.update(changes);return x
    def test_backend_neutral_rebase_and_deterministic_first_field(self):
        o=self.pair('unicorn',eip='0x101010',va='0x101010',registers={'eax':'1','ebx':'2','ecx':'3','edx':'4','esi':'0x55','edi':'6','ebp':'0x102010','esp':'0x103010'})
        n=self.pair('native',eip='0x1010',va='0x1010',registers={'eax':'1','ebx':'2','ecx':'3','edx':'4','esi':'0x56','edi':'6','ebp':'0x2010','esp':'0x3010'})
        d=first_difference(o,n,original_eip_delta=-0x100000,original_stack_delta=-0x100000)
        self.assertEqual((d['status'],d['field'],d['original'],d['native']),('FIRST_DIVERGENCE','esi',0x55,0x56))
    def test_unknown_is_not_misreported_as_equal_and_descriptor_diff(self):
        o=self.pair('dosbox',descriptors=None,flags={'eflags':None,'cf':None});n=self.pair('unicorn',descriptors={'es':{'base':4}})
        self.assertEqual(first_difference(o,n)['status'],'COMPARABLE_FIELDS_EQUAL')
        o['descriptors']={'es':{'base':5}}
        self.assertEqual(first_difference(o,n)['field'],'descriptors')
    def test_run_alignment_stops_at_first_differing_checkpoint_and_rebases_memory(self):
        o1=self.pair('dosbox',eip='0x101010',va='0x101010',registers={'eax':'1','ebx':'2','ecx':'3','edx':'4','esi':'5','edi':'6','ebp':'0x102010','esp':'0x103010'}); n1=self.pair('unicorn')
        o2=self.pair('dosbox',checkpoint='fn:block:2',eip='0x101010',va='0x101010',registers={'eax':'1','ebx':'2','ecx':'3','edx':'4','esi':'5','edi':'6','ebp':'0x102010','esp':'0x103010'},dirty_memory=[{'start':'0x101000','bytes':'aa'}])
        n2=self.pair('native',checkpoint='fn:block:2',dirty_memory=[{'start':'0x1000','bytes':'aa'}])
        d=compare_runs({'checkpoints':[o1,o2]},{'checkpoints':[n1,n2]},original_eip_delta=-0x100000,original_stack_delta=-0x100000,original_memory_delta=-0x100000)
        self.assertEqual(d['status'],'COMPARABLE_FIELDS_EQUAL')
        n2['registers']['ebx']='0x99'
        d=compare_runs({'checkpoints':[o1,o2]},{'checkpoints':[n1,n2]},original_eip_delta=-0x100000,original_stack_delta=-0x100000,original_memory_delta=-0x100000)
        self.assertEqual((d['checkpoint_index'],d['field']),(1,'ebx'))
    def test_dirty_memory_and_guest_trap_differences(self):
        o=self.pair('original',dirty_memory=[{'start':'0x2000','bytes':'0102'}]);n=self.pair('native',dirty_memory=[{'start':'0x2000','bytes':'0103'}])
        self.assertEqual(first_difference(o,n)['field'],'dirty_memory')
        o=self.pair('original',event={'kind':'fault','vector':13});n=self.pair('native',event={'kind':'int','vector':49})
        self.assertEqual(first_difference(o,n)['field'],'event')
    def test_candidate_report_includes_nearest_match_and_measured_deltas(self):
        o1=self.pair('original',checkpoint='before',call_context={'caller':'caller_a'})
        n1=self.pair('native',checkpoint='before',call_context={'caller':'caller_a'})
        o2=self.pair('original',checkpoint='after',call_context={'caller':'caller_b'})
        n2=self.pair('native',checkpoint='after',call_context={'caller':'caller_b'},
                     registers={**self.pair('native')['registers'],'eax':'0x9'},
                     flags={'eflags':'0x246','cf':False},
                     segments={'cs':'0xc','ds':'0x14','es':'0x28','ss':'0x14','fs':None,'gs':None})
        d=compare_runs({'checkpoints':[o1,o2]},{'checkpoints':[n1,n2]})
        self.assertEqual(d['status'],'FIRST_DIVERGENCE')
        self.assertEqual(d['FIRST_DIVERGENCE_CANDIDATE']['checkpoint'],'after')
        self.assertEqual(d['PREVIOUS_MATCH']['checkpoint'],'before')
        self.assertEqual((d['FUNCTION'],d['VA'],d['FIELD']),('f',0x1010,'eax'))
        self.assertEqual((d['register_deltas']['eax']['original'],d['register_deltas']['eax']['native']),(1,9))
        self.assertEqual(d['segment_deltas']['es'],{'original':0x24,'native':0x28})
        self.assertEqual(d['flags_deltas']['eflags'],{'original':0x202,'native':0x246})
        self.assertIn('not established',d['CONFIDENCE'])
    def test_unknown_only_checkpoints_are_not_previous_matches(self):
        def unknown(checkpoint):
            x=self.pair('unknown',checkpoint=checkpoint,va=None,eip=None,registers={},flags={},segments={},event=None)
            x['dirty_memory']=None
            return x
        o0,n0=unknown('unknown'),unknown('unknown')
        o1=self.pair('original',checkpoint='match');n1=self.pair('native',checkpoint='match')
        o2=self.pair('original',checkpoint='mismatch');n2=self.pair('native',checkpoint='mismatch',registers={**self.pair('native')['registers'],'ebx':'0x99'})
        d=compare_runs({'checkpoints':[o0,o1,o2]},{'checkpoints':[n0,n1,n2]})
        self.assertEqual(d['PREVIOUS_MATCH']['checkpoint'],'match')
        self.assertEqual(d['PREVIOUS_MATCH']['checkpoint_index'],1)
        self.assertEqual(compare_runs({'checkpoints':[o0]},{'checkpoints':[n0]})['status'],'INSUFFICIENT_DATA')
    def test_real_rationalalloc_checkpoint_reports_measured_difference_only(self):
        d=rationalalloc_corpus(ROOT)
        self.assertEqual(d['first_checkpoint_comparison']['status'],'FIRST_DIVERGENCE')
        self.assertEqual(d['first_checkpoint_comparison']['function'],'RationalAlloc_')
        self.assertEqual(d['first_checkpoint_comparison']['field'],'esi')
        self.assertEqual(d['first_checkpoint_comparison']['original'],0x160)
        self.assertEqual(d['first_checkpoint_comparison']['native'],8)
        self.assertFalse(d['fixture_parity']['full_cpu_runtime_seed_parity'])
        self.assertIn('not reached',d['additional_RationalAlloc_frontiers']['native']['ah49'])
if __name__=='__main__':unittest.main()
