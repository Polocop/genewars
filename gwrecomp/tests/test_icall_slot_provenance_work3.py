import hashlib,json,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'src'))
from le_loader import load_le
e=json.loads((ROOT/'evidence/icall_slot_provenance_work3.json').read_text(encoding='utf-8'))
assert e['slot_va']=='0x001A029C'
assert hashlib.sha256((ROOT/'evidence/genewars-1_1.exe').read_bytes()).hexdigest()==e['target_sha256']
assert hashlib.sha256((ROOT/'evidence/genewars-1_1.map').read_bytes()).hexdigest()==e['map_sha256']
assert e['map_symbols']==[{'line':2209,'segment_offset':'0003:001A029C','name':'_smack_draw_callback'}]
img=load_le(ROOT/'evidence/genewars-1_1.exe'); obj=img.objects[0]; lo=obj.base; hi=lo+obj.virtual_size; code=bytes(img.mem[lo-img.mem_base:hi-img.mem_base]); needle=struct.pack('<I',0x001A029C); occ=[]; at=0
while True:
 at=code.find(needle,at)
 if at<0: break
 occ.append(f'0x{lo+at:08X}'); at+=1
assert occ==e['raw_absolute_address_occurrences']==['0x000AE2DB','0x000AE689','0x000AE8BA','0x000AE8C4','0x000AE8E2','0x000AE900']
assert e['all_occurrences_have_matching_read_site'] and not e['direct_store_found']
assert len(e['lifted_closure_refs'])==6
assert not any(x['instruction'].startswith('mov dword ptr [0x1a029c],') for x in e['lifted_closure_refs'])
assert not e['dynamic_gate']['reaches_copy_to_screen']
print('PASS W3-SLOT029C: MAP symbol, raw executable xrefs, lifted read sites, direct-store absence and gate reachability')
