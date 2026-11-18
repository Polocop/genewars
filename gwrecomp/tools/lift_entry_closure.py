"""Recursively add exact-boundary direct callees of the entry-rooted lift unit."""
import hashlib,json,re,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'src')); sys.path.insert(0,str(ROOT/'third_party'/'pcrecomp'))
from le_loader import load_le
from extract_symbol_corpus import le_fixup_header,parse_fixups
from tools.disasm.disasm32 import Disassembler
from tools.pe.pe_analyze import Section
from tools.lift.lift32 import Lifter
src=(ROOT/'build'/'entry_path_combined.c').read_text(encoding='utf-8')
imgpath=ROOT/'evidence'/'genewars-1_1.exe'; img=load_le(imgpath); obj=img.objects[0]; lo=obj.base; hi=lo+obj.virtual_size; code=bytes(img.mem[lo-img.mem_base:hi-img.mem_base])
mapnames={}
for line in (ROOT/'evidence'/'genewars-1_1.map').read_text(errors='replace').splitlines():
 p=line.split()
 if len(p)>=2 and p[0].startswith('0001:'):
  try: mapnames[int(p[0].split(':')[1],16)]=p[1]
  except ValueError: pass
# Recover the CRT callback table from the code that consumes it, then read the
# loaded LE image so each target reflects the loader's applied fixups.
asm=(ROOT/'evidence'/'genewars-1_1-le_disasm.s').read_text(encoding='utf-8',errors='replace')
init_body=re.search(r'(?ms)^__InitRtns:.*?(?=^__FiniRtns:)',asm)
if not init_body: raise SystemExit('cannot find __InitRtns disassembly')
table_refs=re.findall(r'ds mov \$data_([0-9A-Fa-f]+),%(esi|edi)',init_body.group(0))
if len(table_refs)!=2 or table_refs[0][1]!='esi' or table_refs[1][1]!='edi':
 raise SystemExit(f'unexpected __InitRtns table bounds: {table_refs}')
table_start,table_end=(int(x[0],16) for x in table_refs)
stride_match=re.search(r'add\s+\$0x([0-9A-Fa-f]+),%esi',init_body.group(0))
if not stride_match: raise SystemExit('__InitRtns record stride is not statically recoverable')
record_size=int(stride_match.group(1),16)
if record_size<6 or (table_end-table_start)%record_size:
 raise SystemExit(f'invalid initializer table extent/stride: {table_start:#x}..{table_end:#x}/{record_size}')
if not all(x in init_body.group(0) for x in ('cmpb   $0x2,(%esi)','mov    0x2(%ebx),%eax','movb   $0x2,(%ebx)')):
 raise SystemExit('__InitRtns status or callback fields do not match the supported table layout')
start_body=re.search(r'(?ms)^start:\s*/\*.*?(?=^__InitRtns:)',asm)
if not start_body: raise SystemExit('cannot find startup caller of __InitRtns')
threshold_match=re.search(r'mov\s+\$0x([0-9A-Fa-f]+),%eax\s*\n\s*call\s+__InitRtns',start_body.group(0))
if not threshold_match: raise SystemExit('cannot recover the __InitRtns priority threshold from start_')
init_threshold=int(threshold_match.group(1),16)&0xFF
image_bytes=imgpath.read_bytes(); fix_header=le_fixup_header(image_bytes)
all_fixups=parse_fixups(image_bytes,img.objects,fix_header['page_size'],fix_header['num_pages'],fix_header['obj_tab'],fix_header['obj_cnt'],fix_header['fixup_page_tab'],fix_header['fixup_rec_tab'])
fixups_by_source={}
for source,target,stype in all_fixups: fixups_by_source.setdefault(source,[]).append((target,stype))
table_object=img.object_containing(table_start)
if not table_object or not table_object.writable or table_object.executable or not img.object_containing(table_end-1):
 raise SystemExit('initializer table is not fully contained in a writable LE data object')
crt_records=[]
for index in range((table_end-table_start)//record_size):
 address=table_start+index*record_size; offset=address-img.mem_base
 state=img.mem[offset]; priority=img.mem[offset+1]
 target=int.from_bytes(img.mem[offset+2:offset+6],'little')
 if state not in (0,2): raise SystemExit(f'initializer record {index} has unknown state {state:#x}')
 field_fixups=fixups_by_source.get(address+2,[])
 verified=next(((t,s) for t,s in field_fixups if t==target and s==7),None)
 if not verified: raise SystemExit(f'initializer pointer {index} at {address+2:#x} lacks matching OFFSET32 fixup')
 target_object=img.object_containing(target)
 if not target_object or not target_object.executable:
  raise SystemExit(f'initializer pointer {index} targets non-code address {target:#x}')
 crt_records.append({'index':index,'record_va':f'0x{address:08X}','state':state,'priority':priority,'target':target,'target_va':f'0x{target:08X}','map_name':mapnames.get(target),'fixup_source':f'0x{address+2:08X}','fixup_type':verified[1],'target_object':target_object.index})
# Assembly selection keeps replacing EBX for priorities <= the current AL.
# Therefore the lowest eligible priority runs first; ties select the last
# matching table entry because the scan is forward and later matches replace it.
eligible=[r for r in crt_records if r['state']==0 and r['priority']<=init_threshold]
crt_dispatch_order=sorted(eligible,key=lambda r:(r['priority'],-r['index']))
crt_targets=[r['target'] for r in crt_dispatch_order]
def definitions(text):
 out={}
 for m in re.finditer(r'\bvoid\s+([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{',text):
  nm=m.group(1); tail=text[m.start():]; e=tail.find('{'); depth=0; stop=None
  for i,ch in enumerate(tail[e:],e):
   if ch=='{':depth+=1
   elif ch=='}':
    depth-=1
    if depth==0:stop=m.start()+i+1;break
  if stop:
   body=text[m.start():stop]; va=re.search(r'RECOMP_ENTER\(0x([0-9A-Fa-f]+)u\)',body)
   if va:out[int(va.group(1),16)]=(nm,body)
 return out
def direct_calls(text):
 out=[]; caller=None
 for line in text.splitlines():
  m=re.search(r'RECOMP_ENTER\(0x([0-9A-Fa-f]+)u\)',line)
  if m:caller=int(m.group(1),16)
  m=re.search(r'RECOMP_CALL\(([A-Za-z_]\w*)\).*?0x([0-9A-Fa-f]+):\s*call\s+0x([0-9A-Fa-f]+)',line)
  if m:out.append({'symbol':m.group(1),'site':int(m.group(2),16),'target':int(m.group(3),16),'caller':caller})
 return out
by_va=definitions(src); by_name={v[0]:a for a,v in by_va.items()}; macros=dict(re.findall(r'^#define\s+(\w+)\s+(\w+)\s*$',src,re.M))
existing_names=set(by_name)|set(macros)|set(macros.values())
map_by_name={name:va for va,name in mapnames.items()}
thunk_targets={int(address,16):map_by_name[target] for _,address,target in re.findall(r'(?m)^([A-Za-z_]\w*):\s*/\*\s*0x([0-9A-Fa-f]+)\s*\*/\s*\r?\n\s*jmp\s+([A-Za-z_]\w*)',asm) if target in map_by_name}
initial=direct_calls(src); targets=sorted({x['target'] for x in initial})
rows=[(a,n) for a,n in mapnames.items() if lo<=a<hi]
seeds=sorted({a for a,n in rows if n.startswith(('W?','Lb')) or n.endswith('_') and not n.startswith(('jpt_','def_'))}|set(targets)|set(crt_targets))
sec=Section('.text',obj.base,obj.virtual_size,0,obj.virtual_size,0x20000020)
t0=time.time(); funcs=Disassembler(code,0,[sec]).find_functions(lo,hi,seeds=seeds)
lift=Lifter()
# This extender helper RETs into the executable's INT 31h vector table. Its
# existing closure body must be regenerated with current dynamic-RET semantics,
# even when it already exists in entry_path_combined.c.
ret_thunk=funcs.get(0x000D226E)
if ret_thunk is None: raise SystemExit('cannot recover exact FUN_000D226E body for dynamic RET refresh')
ret_thunk.name='sub_000D226E'
fresh_ret_body=lift.lift_function(ret_thunk)
src,ret_refreshes=re.subn(r'(?ms)^void sub_000D226E\(void\) \{.*?^\}',fresh_ret_body,src,count=1)
if ret_refreshes!=1: raise SystemExit('expected exactly one existing sub_000D226E body in entry_path_combined.c')
pending=sorted({x['target'] for x in initial if x['symbol'] not in existing_names})
queue=sorted(set(pending)|set(crt_targets)); queued=set(queue); recovered=[]; aliases={}; missing=[]; external=[]; synthetic_thunks=[]; max_count=5000
while queue and len(by_va)+len(recovered)<max_count:
 a=queue.pop(0)
 if a in by_va:
  aliases[f'sub_{a:08X}']=by_va[a][0]; continue
 if a<lo or a>=hi:
  external.append({'address':f'0x{a:08X}','map_name':mapnames.get(a),'class':'outside_LE_code_object'}); continue
 f=funcs.get(a)
 if f is None:
  tail_target=thunk_targets.get(a)
  if tail_target is not None:
   target_object=img.object_containing(tail_target)
   if not target_object or not target_object.executable:
    missing.append({'address':f'0x{a:08X}','map_name':mapnames.get(a),'class':'thunk_target_not_executable','tail_target':f'0x{tail_target:08X}'}); continue
   body=(f'void sub_{a:08X}(void) {{\n'
         f'    int _fpu_cmp = 0; uint32_t _cf = 0; int _df = 1;\n'
         f'    uint32_t _flag_a = 0, _flag_b = 0; uint32_t _flag_k = FK_NONE;\n'
         f'    RECOMP_ENTER(0x{a:08X}u);\n'
         f'    RECOMP_ITAIL(0x{tail_target:08X}u);\n'
         f'}}\n')
   recovered.append({'address':a,'map_name':mapnames.get(a),'end':a+5,'instructions':1,'synthetic_direct_jump_thunk':True,'tail_target':f'0x{tail_target:08X}','code':body})
   by_va[a]=(f'sub_{a:08X}',body); synthetic_thunks.append({'source':f'0x{a:08X}','target':f'0x{tail_target:08X}'})
   if tail_target not in queued: queue.append(tail_target); queued.add(tail_target)
   continue
  owners=[hex(o) for o,ob in funcs.items() if any(i.address==a for b in ob.blocks.values() for i in b.instructions)]
  missing.append({'address':f'0x{a:08X}','map_name':mapnames.get(a),'class':'no_exact_recovered_boundary','containing_cfgs':owners[:10]}); continue
 f.name=f'sub_{a:08X}'
 try: body=lift.lift_function(f)
 except Exception as ex:
  missing.append({'address':f'0x{a:08X}','map_name':mapnames.get(a),'class':'lifter_unsupported','detail':f'{type(ex).__name__}: {ex}'});continue
 recovered.append({'address':a,'map_name':mapnames.get(a),'end':f.end,'instructions':sum(len(b.instructions) for b in f.blocks.values()),'code':body})
 by_va[a]=(f.name,body)
 for call in direct_calls(body):
  t=call['target']; sym=call['symbol']
  if t in by_va and sym not in existing_names: aliases[sym]=by_va[t][0]
  elif sym not in existing_names and t not in queued: queue.append(t);queued.add(t)
if queue: missing.extend({'address':f'0x{x:08X}','class':'closure_limit_reached'} for x in queue)
# Resolve verified callback arguments passed in registers to direct callees
# that invoke a saved argument through RECOMP_ICALL. This remains narrow:
# the callee must save the register into the exact stack slot later used by
# its indirect call, and the caller value must be an exact executable CFG
# entry in the LE image. This covers CRT/library callback idioms such as the
# formatter's output function without treating arbitrary code-looking data as
# function pointers.
callback_edges=[]; callback_unresolved=[]; callback_done=set()
def callback_registers(body):
 regs=set()
 for operand in re.findall(r'RECOMP_ICALL\(MEM32\(([^)]+)\)\)',body):
  pat=r'MEM32\('+re.escape(operand)+r'\)\s*=\s*(eax|ebx|ecx|edx|esi|edi|ebp);'
  saved=re.search(pat,body)
  if saved: regs.add(saved.group(1))
 return regs
while True:
 found=[]
 for caller_va,(caller_name,body) in list(by_va.items()):
  constants={}; indirect_regs=callback_registers(body)
  for line in body.splitlines():
   if re.match(r'\s*L_[0-9A-Fa-f]{8}:',line): constants.clear()
   call=re.search(r'RECOMP_CALL\((\w+)\).*?0x[0-9A-Fa-f]+:\s*call\s+0x([0-9A-Fa-f]+)',line)
   if call:
    callee_va=int(call.group(2),16)
    callee=by_va.get(callee_va)
    if callee:
     for reg in callback_registers(callee[1]):
      target=constants.get(reg)
      if target is None or target in callback_done: continue
      target_object=img.object_containing(target)
      if not target_object or not target_object.executable: continue
      if target not in funcs:
       callback_unresolved.append({'caller':f'0x{caller_va:08X}','callee':f'0x{callee_va:08X}','register':reg,'target':f'0x{target:08X}','class':'not_an_exact_cfg_entry'}); callback_done.add(target); continue
      found.append({'caller':f'0x{caller_va:08X}','caller_name':caller_name,'callsite':line.split('/*')[-1].split(':')[0].strip() if '/*' in line else None,'callee':f'0x{callee_va:08X}','register':reg,'target':target})
    constants.clear()
    continue
   if 'RECOMP_ICALL(' in line: constants.clear(); continue
   assign=re.search(r'\b(eax|ebx|ecx|edx|esi|edi|ebp)\s*=\s*(0x[0-9A-Fa-f]+)u\s*;',line)
   clobber=re.search(r'\b(eax|ebx|ecx|edx|esi|edi|ebp)\s*=',line)
   if assign: constants[assign.group(1)]=int(assign.group(2),16)
   elif clobber: constants.pop(clobber.group(1),None)
 if not found: break
 new_targets=[]
 for edge in found:
  target=edge['target']; callback_done.add(target)
  if target in by_va:
   callback_edges.append({**edge,'target_va':f'0x{target:08X}','already_in_closure':True}); continue
  f=funcs.get(target)
  if f is None:
   callback_unresolved.append({**edge,'target':f'0x{target:08X}','class':'no_exact_recovered_boundary'}); continue
  f.name=f'sub_{target:08X}'
  try: body=lift.lift_function(f)
  except Exception as ex:
   callback_unresolved.append({**edge,'target':f'0x{target:08X}','class':'lifter_unsupported','detail':f'{type(ex).__name__}: {ex}'}); continue
  recovered.append({'address':target,'map_name':mapnames.get(target),'end':f.end,'instructions':sum(len(b.instructions) for b in f.blocks.values()),'indirect_callback_target':True,'code':body})
  by_va[target]=(f.name,body); callback_edges.append({**edge,'target_va':f'0x{target:08X}','already_in_closure':False})
  new_targets.append(target)
 if not new_targets: break
# Newly lifted callback bodies can expose ordinary direct dependencies.
callback_direct_queue=[]
for target in new_targets:
 for call in direct_calls(by_va[target][1]):
  if call['symbol'] not in existing_names and call['target'] not in by_va:
   callback_direct_queue.append(call['target'])
for target in sorted(set(callback_direct_queue)):
 if target not in funcs or target in by_va: continue
 f=funcs[target]; f.name=f'sub_{target:08X}'
 try: body=lift.lift_function(f)
 except Exception as ex:
  missing.append({'address':f'0x{target:08X}','class':'lifter_unsupported','detail':f'{type(ex).__name__}: {ex}'}); continue
 recovered.append({'address':target,'map_name':mapnames.get(target),'end':f.end,'instructions':sum(len(b.instructions) for b in f.blocks.values()),'code':body})
 by_va[target]=(f.name,body)
# Alias exact previously selected lift entries only; generated new bodies retain their sub_VA names.
alias_lines='\n'.join(f'#define {k} {v}' for k,v in sorted(aliases.items()) if k!=v)
base='\n'.join(x for x in src.splitlines() if x.strip() not in ('#define RECOMP_GENERATED_CODE','#include "recomp_types.h"'))
header='#define RECOMP_GENERATED_CODE\n#include "recomp_types.h"\n#include "gw_recomp_stop.h"\n'+alias_lines+'\n'
bodies='\n'.join(x['code'] for x in recovered)+'\n'
preliminary=header+base+'\n'+bodies
call_names=set(re.findall(r'RECOMP_CALL\((\w+)\)',preliminary))
alias_names={k for k,v in re.findall(r'^#define\s+(\w+)\s+(\w+)\s*$',preliminary,re.M)}
protos='\n'.join(f'extern void {n}(void);' for n in sorted(call_names-alias_names))+'\n'
alltext=header+protos+base+'\n'+bodies
# Optional no-state-change basic-block probe for native startup diagnostics.
# The weak stub keeps the generated object independently linkable; a bounded
# test harness can override it with an observer.
probe='''#include <stdint.h>
#ifdef GW_NATIVE_CAPTURE_CRT_STARTUP
__attribute__((weak)) void gw_native_capture_block(uint32_t va) { (void)va; }
#define GW_NATIVE_CAPTURE_BLOCK(va) gw_native_capture_block(va)
__attribute__((weak)) void gw_native_capture_callsite(uint32_t caller, uint32_t target, uint32_t site) { (void)caller; (void)target; (void)site; }
#define GW_NATIVE_CAPTURE_CALLSITE(caller, target, site) gw_native_capture_callsite((caller), (target), (site))
#ifdef GW_NATIVE_CAPTURE_ALLOC_CHAIN
__attribute__((weak)) void gw_native_capture_alloc_callsite(uint32_t caller, uint32_t target, uint32_t site) { (void)caller; (void)target; (void)site; }
#define GW_NATIVE_CAPTURE_ALLOC_CALLSITE(caller, target, site) do { RECOMP_FLAGS_OUT(); RECOMP_REGS_OUT(); gw_native_capture_alloc_callsite((caller), (target), (site)); } while (0)
__attribute__((weak)) void gw_native_capture_alloc_block(uint32_t site) { (void)site; }
#define GW_NATIVE_CAPTURE_ALLOC_BLOCK(site) do { RECOMP_FLAGS_OUT(); RECOMP_REGS_OUT(); gw_native_capture_alloc_block((site)); } while (0)
__attribute__((weak)) void gw_native_capture_alloc_return(uint32_t site) { (void)site; }
#define GW_NATIVE_CAPTURE_ALLOC_RETURN(site) do { RECOMP_FLAGS_OUT(); RECOMP_REGS_OUT(); gw_native_capture_alloc_return((site)); } while (0)
#else
#define GW_NATIVE_CAPTURE_ALLOC_CALLSITE(caller, target, site) ((void)0)
#define GW_NATIVE_CAPTURE_ALLOC_BLOCK(site) ((void)0)
#define GW_NATIVE_CAPTURE_ALLOC_RETURN(site) ((void)0)
#endif
#else
#define GW_NATIVE_CAPTURE_BLOCK(va) ((void)0)
#define GW_NATIVE_CAPTURE_CALLSITE(caller, target, site) ((void)0)
#define GW_NATIVE_CAPTURE_ALLOC_CALLSITE(caller, target, site) ((void)0)
#define GW_NATIVE_CAPTURE_ALLOC_BLOCK(site) ((void)0)
#define GW_NATIVE_CAPTURE_ALLOC_RETURN(site) ((void)0)
#endif
'''
alltext=alltext.replace('#define RECOMP_GENERATED_CODE\n', '#define RECOMP_GENERATED_CODE\n'+probe, 1)
alltext=re.sub(r'(?m)^(L_([0-9A-Fa-f]{8}):\s*)$',
               lambda m:m.group(1)+'\n    GW_NATIVE_CAPTURE_BLOCK(0x'+m.group(2)+'u);', alltext)
# Targeted dynamic provenance hook for isatty_. Emit from the generator so
# capture code remains reproducible and normal execution compiles to a no-op.
alltext=re.sub(
    r'RECOMP_CALL\(sub_000C896A\); /\* 0x([0-9A-Fa-f]{8}): call [^*]+\*/',
    lambda m:'GW_NATIVE_CAPTURE_CALLSITE(g_cur_func, 0x000C896Au, 0x'+m.group(1)+'u); '
             'RECOMP_CALL(sub_000C896A); /* 0x'+m.group(1)+': call 0xc896a */',
    alltext)
# Targeted, opt-in dynamic callsite probes for the initial heap allocation
# chain. The callback is injected only at the two hash-bound guest CALL sites;
# it receives synchronized guest state before RECOMP_CALL pushes its dummy RA.
alloc_call_sites={
 0x000AE038:0x000C3E2A, 0x000AE287:0x000C3E2A,
 0x000C3E54:0x000C3D7A, 0x000C3D98:0x000C3F76,
 0x000C3DB0:0x000C3CA9, 0x000DFE0D:0x000ADF95,
}
def instrument_alloc_call(m):
 site=int(m.group(2),16); target=alloc_call_sites.get(site)
 if target is None: return m.group(0)
 return (f'GW_NATIVE_CAPTURE_ALLOC_CALLSITE(g_cur_func, 0x{target:08X}u, 0x{site:08X}u); '
         +m.group(0))
alltext=re.sub(r'RECOMP_CALL\((sub_000ADF95|sub_000C3E2A|sub_000C3D7A|sub_000C3F76|sub_000C3CA9)\); /\* 0x([0-9A-Fa-f]{8}): call [^*]+\*/',
               instrument_alloc_call,alltext)
alltext=re.sub(r'(RECOMP_CALL\(sub_000C3F76\); /\* 0x000C3D98: call [^*]+\*/)',
               r'\1 GW_NATIVE_CAPTURE_ALLOC_RETURN(0x000C3D98u);',alltext)
# Synchronize register locals at the two instructions that decide whether the
# first __setenvp_ call passes the computed difference or the literal 1.
for va in (0x000DFE04,0x000DFE08):
 alltext=alltext.replace(f'GW_NATIVE_CAPTURE_BLOCK(0x{va:08X}u);',
                         f'GW_NATIVE_CAPTURE_ALLOC_BLOCK(0x{va:08X}u);')
out=ROOT/'build'/'entry_path_closure.c';out.write_text(alltext,encoding='utf-8')
defs=definitions(alltext); calls=direct_calls(alltext)
macro_names={k for k,v in re.findall(r'^#define\s+(\w+)\s+(\w+)\s*$',alltext,re.M)}
defined_symbols=set(n for n,b in defs.values())|macro_names
left={}
for x in calls:
 if x['symbol'] in defined_symbols:continue
 a=x['target']; rec={'address':f'0x{a:08X}','symbol':x['symbol'],'map_name':mapnames.get(a),'call_site':f'0x{x["site"]:08X}','caller':f'0x{x["caller"]:08X}' if x['caller'] is not None else None,'class':'outside_LE_code_object' if not lo<=a<hi else 'missing_in_image_closure'}
 left.setdefault((a,x['symbol']),rec)
report={'target_sha256':hashlib.sha256(imgpath.read_bytes()).hexdigest(),'code_range':[f'0x{lo:08X}',f'0x{hi:08X}'],'initial_unresolved_direct_targets':len(pending),'newly_lifted_functions':len(recovered),'combined_function_bodies':len(defs),'direct_call_sites':len(calls),'unresolved_unique_direct_targets':len(left),'unresolved_direct_targets':list(left.values()),'ambiguous_or_unsupported':missing,'out_of_code_targets':external,'exact_selected_aliases':aliases,'closure_limit':max_count,'elapsed_seconds':round(time.time()-t0,1),'guest_entry_executed':False,'crt_init_table':{'start':f'0x{table_start:08X}','end_exclusive':f'0x{table_end:08X}','record_size':record_size,'threshold_from_start':init_threshold,'records':crt_records,'dispatch_order':[f'0x{x["target"]:08X}' for x in crt_dispatch_order],'synthetic_direct_jump_thunks':synthetic_thunks,'unresolved_table_targets':[x for x in missing if x.get('address') in {r['target_va'] for r in crt_records}]}}
report['indirect_callback_edges']=callback_edges
report['unresolved_indirect_callback_targets']=callback_unresolved
(ROOT/'evidence'/'entry_path_closure.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print(json.dumps({k:v for k,v in report.items() if k not in ('unresolved_direct_targets','ambiguous_or_unsupported','out_of_code_targets','exact_selected_aliases')},indent=2))
