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
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from src.le_loader import load_le
e=json.loads((ROOT/'evidence'/'mscdex_return_context_work3.json').read_text(encoding='utf-8'))
assert e['target_sha256']=='2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f'
for x in e['runtime_files']:
 assert hashlib.sha256((ROOT/x['path']).read_bytes()).hexdigest()==x['sha256'],x['path']
assert e['fixture']['size']==0 and e['fixture']['sha256']=='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
assert e['stop_reason']=='emulation_returned_or_stopped_by_hook'
assert e['first_unsupported']['eip']=='0x001d23a7' and 'audio-disc metadata' in e['first_unsupported']['reason']
ctx=e['dpmi_stub_call_context']
assert ctx['eip']=='0x001d23a7' and ctx['instruction_bytes']=='cd31'
assert ctx['registers']['eax']==0x0300 and ctx['registers']['ebx']==0x2f
assert ctx['ret_target']=='0x001d2240'
assert bytes.fromhex(ctx['stack_bytes_hex'])[:4]==(0x001d2240).to_bytes(4,'little')
packet=e['cdrom_request_events']
assert len(packet)==1
rm=packet[0]['real_mode_interrupt']; assert rm['registers_before']['eax']=='0x00001510'
req=rm['device_request']; assert req['packet_length']==26 and req['command']==3 and req['transfer_length']==7 and req['transfer_before_hex'].startswith('0a')
image=load_le(ROOT/'evidence'/'genewars-1_1.exe',rebase=0x100000)
for va,expect in ((0x001d23a7,'cd31c3'),(0x001d2240,ctx['ret_target_bytes_hex'])):
 obj=image.object_containing(va); assert obj and obj.index==1
 raw=bytes(image.mem[va-image.mem_base:va-image.mem_base+len(bytes.fromhex(expect))]).hex()
 assert raw==expect,(hex(va),raw,expect)
assert _hashlib.sha256(bytes.fromhex(ctx['ret_target_bytes_hex'][:24])).hexdigest()=='662060e32362af3681e36e4268b22fa7d9804216641e9dc42f21d6ecd03ddc99'
print('PASS W3-043: the original CD31 stub returns to __int386x_ at 0x001D2240; stack, packet, hashes and target bytes agree')
