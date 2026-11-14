import json, pathlib, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
class MscdexResponseTests(unittest.TestCase):
 def test_drive_parameters_and_version_register_contract(self):
  import sys
  sys.path.insert(0,str(ROOT/'runtime'))
  from dos_services import CpuRegs, DosHost
  from guest_boot import prepare_guest
  host=DosHost(prepare_guest(ROOT/'evidence'/'genewars-1_1.exe'),cdrom_drives=('D',),mscdex_version=(2,23))
  drive=CpuRegs(eax=0x1500,ebx=0)
  self.assertEqual(host.dispatch(0x2f,drive).service,'int2f.mscdex_install_check')
  self.assertEqual((drive.bx,drive.cx),(1,3))
  version=CpuRegs(eax=0x150c,ebx=0,ecx=3)
  self.assertEqual(host.dispatch(0x2f,version).service,'int2f.mscdex_get_version')
  self.assertEqual((version.bx,version.cx),(0x0217,3))
 def test_drive_enabled_oracle_reaches_real_driver_request_command_03(self):
  evidence=json.loads((ROOT/'evidence'/'mscdex_packet_work2.json').read_text())
  self.assertEqual(evidence['target_sha256'],'2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f')
  frames=evidence['real_mode_0300']
  version=next(x for x in frames if x['frame']['registers']['eax']==0x150c)
  self.assertEqual(version['real_mode_vector'],0x2f)
  request=next(x for x in frames if x['frame']['registers']['eax']==0x1510)
  self.assertEqual(request['frame']['registers']['ecx'],3)
  self.assertEqual(request['request_header']['decoded']['command'],3)
  self.assertEqual(request['request_header']['decoded']['status'],0)
  self.assertEqual(evidence['first_unsupported']['vector'],0x2f)
  self.assertEqual(evidence['first_unsupported']['eip'],'0x001d23a7')
if __name__=='__main__': unittest.main()


