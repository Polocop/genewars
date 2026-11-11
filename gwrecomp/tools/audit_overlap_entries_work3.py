"""Red-team incoming direct control-flow refs for disputed CFG/MAP labels."""
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'));sys.path.insert(0,str(ROOT/'third_party'/'pcrecomp'))
from le_loader import load_le
from tools.disasm.disasm32 import Disassembler
from tools.pe.pe_analyze import Section
img=ROOT/'evidence/genewars-1_1.exe'; mp=ROOT/'evidence/genewars-1_1.map'
le=load_le(img); obj=le.objects[0]; lo=obj.base; hi=obj.end
code=bytes(le.mem[lo-le.mem_base:hi-le.mem_base])
rows={}
for line in mp.read_text(errors='replace').splitlines():
 p=line.split()
 if len(p)>=2 and p[0].startswith('0001:'):
  try: rows[int(p[0].split(':')[1],16)]=p[1]
  except ValueError:pass
seeds=sorted(a for a,n in rows.items() if lo<=a<hi and (n.startswith(('W?','Lb')) or n.endswith('_') and not n.startswith(('jpt_','def_'))))
sec=Section('.text',lo,obj.virtual_size,0,obj.virtual_size,0x20000020)
funcs=Disassembler(code,0,[sec]).find_functions(lo,hi,seeds=seeds)
delta=json.loads((ROOT/'evidence/overlap_delta_work3.json').read_text(encoding='utf-8'))
over=json.loads((ROOT/'evidence/nonmap_overlap_edges_work3.json').read_text(encoding='utf-8'))
targets={int(e['candidate'],16) for e in over['edges'] if e['classification']=='MAP_control_flow_label'}
bounded=delta['bounded_ambiguous_edge'][0]['candidate_pool']; targets|={int(a,16) for a in bounded}
refs={a:[] for a in targets}; coverage={a:{'instruction_start_in_cfgs':0,'cfg_entries':0} for a in targets}
for fva,f in funcs.items():
 if fva in targets: coverage[fva]['cfg_entries']+=1
 for b in f.blocks.values():
  for i in b.instructions:
   if i.address in targets: coverage[i.address]['instruction_start_in_cfgs']+=1
   if i.mnemonic in ('call','jmp','je','jne','jz','jnz','ja','jae','jb','jbe','jg','jge','jl','jle','js','jns','jo','jno','jp','jnp','jecxz','loop','loope','loopne','loopz','loopnz'):
    t=i.get_branch_target()
    if t in targets:
     refs[t].append({'source':f'0x{i.address:08X}','source_map_name':rows.get(fva),'source_cfg':f'0x{fva:08X}','mnemonic':i.mnemonic,'target':f'0x{t:08X}','bytes':i.bytes.hex()})

def raw_at(a,n=16):return bytes(le.mem[a-le.mem_base:min(a-le.mem_base+n,len(le.mem))]).hex()
entries=[]
for a in sorted(targets):
 name=rows.get(a); label='def_/jpt_ map control-flow label' if name and name.startswith(('def_','jpt_')) else 'unnamed instruction candidate inside seed CFG'
 owners=sorted({e['owner_seed'] for e in over['edges'] if int(e['candidate'],16)==a})
 entries.append({'address':f'0x{a:08X}','map_name':name,'classification':label,'owner_seed_addresses':owners,'instruction_start_in_cfg_count':coverage[a]['instruction_start_in_cfgs'],'recovered_cfg_entry':bool(coverage[a]['cfg_entries']),'raw_bytes':raw_at(a),'incoming_direct_control_flow':refs[a]})
out={'target_sha256':hashlib.sha256(img.read_bytes()).hexdigest(),'map_sha256':hashlib.sha256(mp.read_bytes()).hexdigest(),'decoder_sha256':hashlib.sha256((ROOT/'third_party/pcrecomp/tools/disasm/disasm32.py').read_bytes()).hexdigest(),'recovered_cfg_count':len(funcs),'target_count':len(entries),'disputed_flow_label_count':sum(bool(e['map_name'] and e['map_name'].startswith(('def_','jpt_'))) for e in entries),'disputed_94ac0_pool_count':len(bounded),'entries':entries,'function_count_adjustment':0,'interpretation':'Direct CALL/JMP target evidence is reported separately from CFG entry recovery. A flow label, internal jump target, or instruction entry reachable from an existing seed does not establish an independent function boundary. No native byte invocation was attempted for these interior labels because entry register/stack contracts are unknown.'}
(ROOT/'evidence/overlap_entry_redteam_work3.json').write_text(json.dumps(out,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'recovered_cfg_count':len(funcs),'target_count':len(entries),'flow_labels':out['disputed_flow_label_count'],'anonymous_94ac0':len(bounded),'with_incoming_control_flow':sum(bool(e['incoming_direct_control_flow']) for e in entries),'function_count_adjustment':0},indent=2))
