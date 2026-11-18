"""Rebuild corrected CFG ownership around all conflicting MAIN.MAP roots."""
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'src')); sys.path.insert(0,str(ROOT/'third_party'/'pcrecomp'))
from le_loader import load_le
from tools.disasm.disasm32 import Disassembler
from tools.pe.pe_analyze import Section
img=ROOT/'evidence'/'genewars-1_1.exe'; raw=img.read_bytes(); h=hashlib.sha256(raw).hexdigest()
le=load_le(img); obj=le.objects[0]; lo=obj.base; hi=lo+obj.virtual_size; code=bytes(le.mem[lo-le.mem_base:hi-le.mem_base])
rows={}
for line in (ROOT/'evidence'/'genewars-1_1.map').read_text(errors='replace').splitlines():
 p=line.split()
 if len(p)>=2 and p[0].startswith('0001:'):
  try: rows[int(p[0].split(':')[1],16)]=p[1]
  except ValueError: pass
seeds=sorted(a for a,n in rows.items() if lo<=a<hi and (n.startswith(('W?','Lb')) or n.endswith('_') and not n.startswith(('jpt_','def_'))))
prior=json.loads((ROOT/'evidence'/'boundary_revalidation_work3.json').read_text())['overlap']
prior_pairs=prior['seed_to_seed_pairs']; seedset=set(seeds)
sec=Section('.text',obj.base,obj.virtual_size,0,obj.virtual_size,0x20000020)
funcs=Disassembler(code,0,[sec]).find_functions(lo,hi,seeds=seeds)
def insts(f): return {i.address:i for b in f.blocks.values() for i in b.instructions}
by_addr={a:insts(f) for a,f in funcs.items()}
pairs=[]; candidate_owner={}
for old in prior_pairs:
 a=int(old['a'],16); b=int(old['b'],16); fa=by_addr.get(a,{}); fb=by_addr.get(b,{})
 common=sorted(fa.keys()&fb.keys()); a_inside=a in fb; b_inside=b in fa
 if a_inside and b_inside: cls='mutual_alternate_entry_or_alias'
 elif a_inside: cls='A_entry_reachable_inside_B_CFG'
 elif b_inside: cls='B_entry_reachable_inside_A_CFG'
 elif common and (max(common)>=min(a,b)): cls='shared_tail_or_non_nested_CFG'
 elif common: cls='shared_internal_CFG_blocks'
 else: cls='no_reproduced_instruction_overlap'
 pairs.append({'a':old['a'],'a_map':old['a_map'],'b':old['b'],'b_map':old['b_map'],'shared_instruction_count':len(common),'a_start_is_instruction_in_b_cfg':a_inside,'b_start_is_instruction_in_a_cfg':b_inside,'classification':cls,'confidence':'medium CFG ownership evidence; MAP confirms entry only','shared_instruction_sample':[{'address':f'0x{x:08X}','mnemonic':fa[x].mnemonic,'op_str':fa[x].op_str} for x in common[:8]]})
# Every non-MAP candidate entry found inside one or more MAP-seed CFGs.
for cand in funcs:
 if cand in seedset: continue
 for owner,ins in by_addr.items():
  if cand in ins: candidate_owner.setdefault(cand,set()).add(owner)
nonseed=[{'address':f'0x{cand:08X}','map_name':rows.get(cand),'owner_seeds':[{'address':f'0x{o:08X}','name':rows.get(o)} for o in sorted(owners)],'classification':'instruction entry reachable inside MAP-seed CFG; not an independent confirmed function'} for cand,owners in sorted(candidate_owner.items())]
class_counts={}
for p in pairs: class_counts[p['classification']]=class_counts.get(p['classification'],0)+1
out={'target_sha256':h,'map_sha256':hashlib.sha256((ROOT/'evidence'/'genewars-1_1.map').read_bytes()).hexdigest(),'seed_count':len(seeds),'recovered_cfg_count':len(funcs),'expected_seed_pairs':len(prior_pairs),'reproduced_seed_pairs':len(pairs),'seed_pair_classes':class_counts,'seed_pairs':pairs,'nonmap_candidate_count':len(nonseed),'nonmap_candidates_inside_seed_cfgs':nonseed,'independent_function_count_adjustment':0,'policy':'A MAP start is evidence for entry VA, not ownership of its full decoded body. Overlap candidates remain unconfirmed as independent extents until byte/flow review; candidates reached as instruction entries remain CFG labels, not added functions.'}
(ROOT/'evidence'/'map_overlap_ownership_work1.json').write_text(json.dumps(out,indent=2)+'\n',encoding='utf-8')
print(json.dumps({k:v for k,v in out.items() if k not in ('seed_pairs','nonmap_candidates_inside_seed_cfgs')},indent=2))
