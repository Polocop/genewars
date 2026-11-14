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
import json
j=json.load(open('evidence/startup_gate_classification_work3.json'))
g=j['game_gate_snapshot']
assert j['target_sha256']=='2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f'
assert j['main_instruction_count']==122
assert g['guest_eip']=='0x0019432f' and _hashlib.sha256(bytes.fromhex(g['bytes'][:28])).hexdigest()=='8d9d64a4fa48cfc5769bb170a232e3def47ee37ebaf0c9594d18a978e38e3a27'
assert g['local_64']=='01' and g['local_68']=='00'
assert j['termination']['code']==0 and set(j['root_hits'])=={'main_'}
assert 'no-option' in j['classification']
print('PASS: original-byte gate snapshot shows local64=1 proceeds, local68=0 skips, clean exit 0, no later roots')
