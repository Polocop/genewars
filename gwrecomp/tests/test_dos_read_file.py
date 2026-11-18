import json, pathlib, tempfile, unittest, sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"runtime"))
from guest_boot import prepare_guest
from dos_filesystem import DosFileSystem
from dos_services import CpuRegs, DosHost
IMAGE=ROOT/'evidence'/'genewars-1_1.exe'
class DosReadTests(unittest.TestCase):
    def setUp(self):
        self.boot=prepare_guest(IMAGE)
        self.boot.memory.ensure_size(0x3c403c+0x1000)
        self.host=DosHost(self.boot)
        self.temp=tempfile.TemporaryDirectory(dir=ROOT/'build')
        root=pathlib.Path(self.temp.name); (root/'GENEWARS').mkdir()
        (root/'GENEWARS'/'config.ini').write_bytes(b'Language=English\r\nCd=C:\\GENEWARS\r\n')
        self.host.filesystem=DosFileSystem(root)
        self.handle=self.host.filesystem.open(r'C:\GENEWARS\config.ini')
    def tearDown(self):
        if self.handle in self.host.filesystem.handles:
            self.host.filesystem.close(self.handle)
        self.temp.cleanup()
    def test_read_partial_and_eof_copies_bytes_and_preserves_registers(self):
        regs=CpuRegs(eax=0xabcd3f00,ebx=self.handle,ecx=0x1000,edx=0x3c403c,eflags=0x203,ds=0x14)
        result=self.host.dispatch(0x21,regs,read_buffer_address=0x3c403c)
        expected=b'Language=English\r\nCd=C:\\GENEWARS\r\n'
        self.assertTrue(result.handled); self.assertEqual(result.service,'dos21.read_file')
        self.assertEqual(regs.ax,len(expected)); self.assertEqual(regs.eax>>16,0xabcd)
        self.assertEqual(regs.ebx,self.handle); self.assertEqual(regs.edx,0x3c403c); self.assertFalse(regs.carry)
        self.assertEqual(self.boot.memory.read(0x3c403c,len(expected)),expected)
        self.assertEqual(result.guest_writes,((0x3c403c,expected),))
        eof=CpuRegs(eax=0x3f00,ebx=self.handle,ecx=0x1000,edx=0x100,ds=0x14,eflags=0x203)
        end=self.host.dispatch(0x21,eof,read_buffer_address=0x100)
        self.assertTrue(end.handled); self.assertEqual(end.service,'dos21.read_file')
        self.assertEqual(eof.ax,0); self.assertFalse(eof.carry)
    def test_invalid_handle_maps_dos_error_6(self):
        regs=CpuRegs(eax=0xabcd3f00,ebx=0x7777,ecx=4,edx=0x100,ds=0x14,eflags=0x202)
        result=self.host.dispatch(0x21,regs,read_buffer_address=0x100)
        self.assertTrue(result.handled); self.assertEqual(result.service,'dos21.read_file.error')
        self.assertEqual(regs.ax,DosFileSystem.ERR_INVALID_HANDLE); self.assertTrue(regs.carry)
    def test_unmapped_buffer_traps_before_file_pointer_moves(self):
        regs=CpuRegs(eax=0x3f00,ebx=self.handle,ecx=8,edx=self.boot.memory.size-4,ds=0x14)
        result=self.host.dispatch(0x21,regs,read_buffer_address=self.boot.memory.size-4)
        self.assertFalse(result.handled); self.assertIn('outside mapped guest memory',result.trap.reason)
        self.assertEqual(self.host.filesystem.seek(self.handle,0,1),0)
        good=CpuRegs(eax=0x3f00,ebx=self.handle,ecx=8,edx=0x100,ds=0x14)
        self.host.dispatch(0x21,good,read_buffer_address=0x100)
        self.assertEqual(good.ax,8)
    def test_unmapped_selector_does_not_fabricate_buffer(self):
        regs=CpuRegs(eax=0x3f00,ebx=self.handle,ecx=1,edx=0x100,ds=0x3333)
        result=self.host.dispatch(0x21,regs)
        self.assertFalse(result.handled); self.assertIn('requires a validated DS:EDX',result.trap.reason)
if __name__=='__main__': unittest.main(verbosity=2)

