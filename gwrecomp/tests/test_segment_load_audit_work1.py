import json,re,unittest
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT / "third_party" / "pcrecomp"))
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from tools.disasm.disasm32 import Instruction, BasicBlock, Function
from tools.lift.lift32 import Lifter
class SegmentLoadAuditTests(unittest.TestCase):
 def test_inventory_is_complete_and_raw_bypasses_are_gone(self):
  d=json.loads((ROOT/"evidence/segment_load_audit_work1.json").read_text()); self.assertTrue(d["passed"]); self.assertFalse(d["raw_segment_write_bypasses"]); self.assertTrue(d["segment_load_sites"]); self.assertEqual(d["dynamic_route"]["frontier"],"0x000C3D42 MOV ES,EAX selector 0x004C rejected")
 def test_far_load_lifter_uses_bridge_before_offset_commit(self):
  s=(ROOT/"third_party/pcrecomp/tools/lift/lift32.py").read_text(); a=s.index("elif m in ('les', 'lds', 'lfs', 'lgs', 'lss'):"); b=s.index("elif m == 'out'",a); block=s[a:b]; self.assertIn("recomp_write_segment(RECOMP_SEG_{segment}",block); self.assertLess(block.index("if (!recomp_write_segment"),block.index("{dst}")); self.assertNotRegex(block,r"_seg_\w+\s*=")
 def test_mov_es_ds_ss_and_les_emit_checked_bridge(self):
  md=Cs(CS_ARCH_X86,CS_MODE_32); md.detail=True
  cases=[("8ec0","RECOMP_SEG_ES"),("8e18","RECOMP_SEG_DS"),("8ed0","RECOMP_SEG_SS"),("c400","RECOMP_SEG_ES")]
  for raw,seg in cases:
   decoded=list(md.disasm(bytes.fromhex(raw+"c3"),0x12340000))
   ins=[Instruction(i.address,i.size,i.mnemonic,i.op_str,bytes(i.bytes),i.operands) for i in decoded]
   body=Lifter().lift_function(Function(0x12340000,0x12340003,"probe",{0x12340000:BasicBlock(0x12340000,0x12340003,ins,is_exit=True)},size=3))
   self.assertIn("recomp_write_segment("+seg,body,raw)
  les=Lifter().lift_function(Function(0x12340000,0x12340003,"probe",{0x12340000:BasicBlock(0x12340000,0x12340003,[Instruction(i.address,i.size,i.mnemonic,i.op_str,bytes(i.bytes),i.operands) for i in md.disasm(bytes.fromhex("c400c3"),0x12340000)],is_exit=True)},size=3))
  self.assertIn("recomp_write_segment(RECOMP_SEG_ES",les)
  self.assertIn("if (!recomp_write_segment",les)
 def test_current_and_future_candidate_sites_do_not_claim_mapping(self):
  d=json.loads((ROOT/"evidence/segment_load_audit_work1.json").read_text()); self.assertEqual(d["selector_mapping_changes"],[]); self.assertTrue(d["dynamic_route"]["unknown_is_not_false"]); self.assertEqual(d["post_frontier_rank"][0]["va"],"0x000C3D4C")
if __name__=="__main__": unittest.main()
