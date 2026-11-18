import pathlib,sys,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'runtime'))
from recomp_bridge import CpuState,GuestTrap,RecompBridge

class RecompBridgeTests(unittest.TestCase):
 def test_dispatch_preserves_and_returns_explicit_register_state(self):
  def fn(s): s.eax=(s.eax+7)&0xffffffff; s.esp-=4; s.eflags=0x246
  b=RecompBridge({0x12345678:fn}); s=CpuState(eax=5,esp=0x2000,ebx=0xabcdef01)
  self.assertIs(b.call(0x12345678,s),s); self.assertEqual((s.eax,s.ebx,s.esp,s.eflags),(12,0xabcdef01,0x1ffc,0x246))
  self.assertEqual(b.trace[0]['before']['ebx'],0xabcdef01)
 def test_unresolved_address_reports_current_eip_and_full_guest_va(self):
  with self.assertRaises(GuestTrap) as e: RecompBridge({}).call(0xf1234567,CpuState(eip=0x88))
  self.assertEqual((e.exception.eip,e.exception.address),(0x88,0xf1234567)); self.assertIn('0xf1234567',str(e.exception))
 def test_host_exception_becomes_guest_trap(self):
  def fn(s): raise RuntimeError('boom')
  with self.assertRaises(GuestTrap) as e: RecompBridge({0x1000:fn}).call(0x1000,CpuState())
  self.assertEqual(e.exception.kind,'host_function_trap')
 def test_state_rejects_truncated_or_negative_registers(self):
  with self.assertRaises(ValueError): CpuState(eax=-1).validate()

if __name__=='__main__': unittest.main()
