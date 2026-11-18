import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
e=json.loads((ROOT/'evidence/ah48_selector_reconciliation_work3.json').read_text(encoding='utf-8'))
assert e['target_sha256']=='2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f'
assert e['command_tail']=='-k' and e['empty_fixture_sha256']=='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
d=e['dpmi_ax0100']; assert d['request_paragraphs']==4096 and d['returned_real_segment']=='0x1103' and d['returned_protected_selector']=='0x24'
h=e['dos_ah48']; assert h['request_bx']=='0x00000001' and h['returned_ax_segment']=='0x00009fca'
assert h['guest_use_eip']=='0x001c3d42' and h['guest_use_bytes']=='8ec0' and h['exception_vector']==13
assert 'does not measure which mapping' in e['conclusion']
assert e['runtime_sha256_at_AH48_capture']
print('PASS W3-035: distinguishes measured AX=0100 segment/selector outputs from AH=48 raw return and leaves conversion unresolved')
