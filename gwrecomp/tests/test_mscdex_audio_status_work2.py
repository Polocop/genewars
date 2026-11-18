import pathlib
import hashlib
import json
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'runtime'))
from dos_cdrom import CueImage
from dos_services import CpuRegs, DosHost
from guest_boot import prepare_guest

class MscdexAudioStatusTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); p=pathlib.Path(self.temp.name)
        (p/'data.bin').write_bytes(bytes(2*2352)); (p/'audio.bin').write_bytes(bytes(4*2352))
        (p/'disc.cue').write_text('FILE "data.bin" BINARY\n TRACK 01 MODE1/2352\n  INDEX 01 00:00:00\nFILE "audio.bin" BINARY\n TRACK 02 AUDIO\n  INDEX 01 00:00:00\n',encoding='ascii')
        image=CueImage.from_cue(p/'disc.cue')
        self.host=DosHost(prepare_guest(ROOT/'evidence/genewars-1_1.exe'),cdrom_drives=('D',),cdrom_images=(image,))

    def tearDown(self): self.temp.cleanup()

    def driver(self, command, start=2, count=2, mode=0):
        packet=bytearray(26); packet[0]=0x1a; packet[2]=command; packet[0x0d]=mode
        struct.pack_into('<II',packet,0x0e,start,count)
        return self.host.dispatch(0x2f,CpuRegs(eax=0x1510,ecx=3),device_request_address=0x21040,device_request=bytes(packet))

    def ioctl_input(self, sub, length=11):
        packet=bytearray(26); packet[0]=0x1a; packet[2]=3
        struct.pack_into('<HHH',packet,0x0e,0x70,0x2100,length)
        data=bytearray(length); data[0]=sub
        return self.host.dispatch(0x2f,CpuRegs(eax=0x1510,ecx=3,es=0x2104),device_request_address=0x21040,
            device_request=bytes(packet),device_transfer_address=0x21070,device_transfer=bytes(data))

    def test_0f_returns_idle_playing_paused_and_stopped_state(self):
        idle=self.ioctl_input(0x0f)
        self.assertTrue(idle.handled)
        self.assertEqual(dict(idle.guest_writes)[0x21070],bytes.fromhex('0f00000000000000000000'))
        self.driver(0x84)
        playing=self.ioctl_input(0x0f)
        self.assertEqual(dict(playing.guest_writes)[0x21070],bytes.fromhex('0f00000002020000020200'))
        self.driver(0x85)
        paused=self.ioctl_input(0x0f)
        self.assertEqual(dict(paused.guest_writes)[0x21070],bytes.fromhex('0f01000002020000020200'))
        self.driver(0x85)
        stopped=self.ioctl_input(0x0f)
        self.assertEqual(dict(stopped.guest_writes)[0x21070],bytes.fromhex('0f00000000000000000000'))

    def test_output_03_sets_four_pairs_and_input_04_reads_them_back(self):
        data=bytes.fromhex('0301ff008001400000')
        packet=bytearray(26); packet[0]=0x1a; packet[2]=0x0c
        struct.pack_into('<HHH',packet,0x0e,0x70,0x2100,len(data))
        set_result=self.host.dispatch(0x2f,CpuRegs(eax=0x1510,ecx=3,es=0x2104),device_request_address=0x21040,
            device_request=bytes(packet),device_transfer_address=0x21070,device_transfer=data)
        self.assertTrue(set_result.handled)
        get_result=self.ioctl_input(0x04,length=9)
        self.assertEqual(dict(get_result.guest_writes)[0x21070],bytes.fromhex('0401ff008001400000'))

    def test_wrong_io_lengths_and_unrecognized_output_function_trap(self):
        self.assertFalse(self.ioctl_input(0x0f,length=9).handled)
        data=bytes.fromhex('020000000000000000')
        packet=bytearray(26); packet[0]=0x1a; packet[2]=0x0c
        struct.pack_into('<HHH',packet,0x0e,0x70,0x2100,len(data))
        result=self.host.dispatch(0x2f,CpuRegs(eax=0x1510,ecx=3),device_request_address=0x21040,
            device_request=bytes(packet),device_transfer_address=0x21070,device_transfer=data)
        self.assertFalse(result.handled)

    def test_evidence_is_self_consistent_and_does_not_claim_gate(self):
        evidence=json.loads((ROOT/'evidence/mscdex_audio_status_work2.json').read_text(encoding='utf-8'))
        self.assertFalse(evidence['original_byte_audio_status_seen'])
        self.assertFalse(evidence['menu_reached'])
        self.assertEqual(evidence['cue_sha256'],'1d417e3aed625d4f054b51054a1211562a19cd4f712b08e7846613517228a5b5')
        for item in evidence['runtime_files']:
            self.assertTrue((ROOT/item['path']).is_file())
        combined=hashlib.sha256(''.join(x['path']+':'+x['sha256']+'\n' for x in evidence['runtime_files']).encode()).hexdigest()
        self.assertEqual(combined,evidence['runtime_sha256'])

if __name__=='__main__': unittest.main()
