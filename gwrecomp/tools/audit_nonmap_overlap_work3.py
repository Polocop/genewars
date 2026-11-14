"""Recompute exact non-MAP candidate-to-MAIN.MAP seed overlap edges."""
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'));sys.path.insert(0,str(ROOT/'third_party'/'pcrecomp'))
from le_loader import load_le
from tools.disasm.disasm32 import Disassembler
from tools.pe.pe_analyze import Section
img=ROOT/'evidence'/'genewars-1_1.exe'; raw=img.read_bytes(); target_hash=hashlib.sha256(raw).hexdigest()
map_path=ROOT/'evidence'/'genewars-1_1.map'; map_hash=hashlib.sha256(map_path.read_bytes()).hexdigest()
le=load_le(img); obj=le.objects[0]; lo=obj.base; hi=obj.end
code=bytes(le.mem[lo-le.mem_base:hi-le.mem_base])
rows={}
for line in map_path.read_text(errors='replace').splitlines():
 p=line.split()
 if len(p)>=2 and p[0].startswith('0001:'):
  try: rows[int(p[0].split(':')[1],16)]=p[1]
  except ValueError: pass
seeds=sorted(a for a,n in rows.items() if lo<=a<hi and (n.startswith(('W?','Lb')) or n.endswith('_') and not n.startswith(('jpt_','def_'))))
seedset=set(seeds)
sec=Section('.text',obj.base,obj.virtual_size,0,obj.virtual_size,0x20000020)
funcs=Disassembler(code,0,[sec]).find_functions(lo,hi,seeds=seeds)
def insts(f): return {i.address:i for b in f.blocks.values() for i in b.instructions}
by_addr={a:insts(f) for a,f in funcs.items()}
seed_insts={s:by_addr.get(s,{}) for s in seeds}
edges=[]; partner_owners={}
candidate_set=set(funcs)|{a for a in rows if lo<=a<hi}
for candidate in sorted(candidate_set):
 if candidate in seedset: continue
 ci=by_addr.get(candidate,{candidate:next((ins[candidate] for ins in seed_insts.values() if candidate in ins),None)})
 ci={a:i for a,i in ci.items() if i is not None}
 name=rows.get(candidate)
 for owner in seeds:
  oi=seed_insts[owner]
  common=sorted(ci.keys() & oi.keys())
  if not common: continue
  if name and name.startswith(('jpt_','def_')): cls='MAP_control_flow_label'
  elif candidate in oi: cls='reachable_instruction_entry_boundary_uncertain'
  else: cls='shared_tail_or_CFG_overreach'
  edges.append({'owner_seed':f'0x{owner:08X}','owner_name':rows[owner],'candidate':f'0x{candidate:08X}','candidate_map_name':name,
    'candidate_instruction_count':len(ci),'shared_instruction_count':len(common),'classification':cls,
    'candidate_entry_is_instruction_in_owner':candidate in oi,
    'shared_instruction_sample':[{'address':f'0x{x:08X}','mnemonic':oi[x].mnemonic,'op_str':oi[x].op_str} for x in common[:8]]})
  partner_owners.setdefault(candidate,set()).add(owner)
profiles={}
for owner in seeds:
 owned=[e for e in edges if int(e['owner_seed'],16)==owner]
 if owned: profiles[f'0x{owner:08X}']={'map_name':rows[owner],'nonseed_partner_edges':len(owned),'nonseed_partners':[e['candidate'] for e in owned]}
classes={}
for e in edges: classes[e['classification']]=classes.get(e['classification'],0)+1
prior=json.loads((ROOT/'evidence'/'boundary_revalidation_work3.json').read_text())['overlap']
out={'target_sha256':target_hash,'map_sha256':map_hash,'code_range':[f'0x{lo:08X}',f'0x{hi:08X}'],
 'map_function_like_seed_count':len(seeds),'seed_addresses':[f'0x{x:08X}' for x in seeds],'recovered_cfg_candidate_count':len(funcs),'map_public_candidate_count':sum(lo<=a<hi for a in rows),'candidate_universe_count':len(candidate_set),
 'edge_count':len(edges),'unique_nonseed_candidate_count':len(partner_owners),'seed_owners_involved':len(profiles),
 'owner_filter':'owner must be one of the 651 function-like MAIN.MAP seed addresses; candidate self-ownership is impossible',
 'classes':classes,'edges':edges,'per_seed_profiles':profiles,
 'previous_w3_004_counts':{'seed_any_candidate_pairs':prior['current_seed_any_candidate_pairs'],'unique_nonseed_partners':prior['current_unique_nonseed_partners'],'seeds_involved':prior['current_seed_candidates_involved']},
 'policy':'CFG overlap and exact instruction-entry reachability are boundary/ownership evidence only. MAP control-flow labels are not functions; no candidate is added to the confirmed function count without independent extent and semantic evidence.'}
outpath=ROOT/'evidence'/'nonmap_overlap_edges_work3.json'; outpath.write_text(json.dumps(out,indent=2)+'\n',encoding='utf-8')
print(json.dumps({k:v for k,v in out.items() if k not in ('edges','per_seed_profiles')},indent=2))
