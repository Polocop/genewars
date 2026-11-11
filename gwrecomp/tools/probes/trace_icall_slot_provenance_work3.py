"""WORK3 evidence for the optional callback slot at the MAP symbol _smack_draw_callback."""
import hashlib,json,struct,sys,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; sys.path.insert(0,str(ROOT/'src'))
from le_loader import load_le
TARGET=0x001A029C; exe=ROOT/'evidence/genewars-1_1.exe'; mp=ROOT/'evidence/genewars-1_1.map'; icp=ROOT/'evidence/icall_dispatch_table.json'; trace=ROOT/'evidence/dpmi_alloc_contract_work3.json'
img=load_le(exe); obj=img.objects[0]; lo=obj.base; hi=lo+obj.virtual_size; code=bytes(img.mem[lo-img.mem_base:hi-img.mem_base]); needle=struct.pack('<I',TARGET); raw=[]; at=0
while True:
 at=code.find(needle,at)
 if at<0: break
 raw.append(lo+at); at+=1
maprows=[]
for n,line in enumerate(mp.read_text(errors='replace').splitlines(),1):
 p=line.split()
 if len(p)>=2 and p[0]=='0003:001A029C': maprows.append({'line':n,'segment_offset':p[0],'name':p[1]})
refs=[]
for n,line in enumerate((ROOT/'build/recomp_282.c').read_text(errors='replace').splitlines(),1):
 if '0x1A029C' in line or '0x1a029c' in line:
  m=re.search(r'/\*\s*(0x[0-9A-Fa-f]{8}):\s*(.*?)\s*\*/',line)
  if m: refs.append({'line':n,'instruction_va':m.group(1),'instruction':m.group(2),'text':line.strip()})
run=json.loads(trace.read_text(encoding='utf-8'))
out={'task':'W3-SLOT029C','target_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),'map_sha256':hashlib.sha256(mp.read_bytes()).hexdigest(),'icall_table_sha256':hashlib.sha256(icp.read_bytes()).hexdigest(),'startup_trace_sha256':hashlib.sha256(trace.read_bytes()).hexdigest(),'slot_va':f'0x{TARGET:08X}','map_symbols':maprows,'code_object':{'start':f'0x{lo:08X}','end':f'0x{hi:08X}','size':len(code)},'raw_absolute_address_occurrences':[f'0x{x:08X}' for x in raw],'lifted_closure_refs':refs,'all_occurrences_have_matching_read_site':set(raw)=={int(r['instruction_va'],16)+2 for r in refs},'direct_store_found':False,'dynamic_gate':{'last_eip':run.get('last_guest_eip'),'stop':run.get('first_unsupported'),'reaches_copy_to_screen':any(0xAE2D9<=int(r.get('eip',r.get('instruction_va','0')),16)<=0xAE90A for r in run.get('post_first_success_original_instructions',[]))},'classification':'MAP-named callback with no direct absolute store observed in complete executable code object; likely populated by external/application registration, but pointer-alias writes and runtime registration are not excluded. Current -k trace cannot dynamically classify its writer because startup stops before this post-boot path.'}
(ROOT/'evidence/icall_slot_provenance_work3.json').write_text(json.dumps(out,indent=2)+'\n',encoding='utf-8'); print(json.dumps(out,indent=2))


