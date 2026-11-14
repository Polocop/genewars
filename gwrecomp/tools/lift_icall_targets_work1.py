import hashlib, json, re, sys, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src')); sys.path.insert(0,str(ROOT/'third_party'/'pcrecomp'))
from le_loader import load_le
from tools.disasm.disasm32 import Disassembler
from tools.pe.pe_analyze import Section
from tools.lift.lift32 import Lifter
icall=json.loads((ROOT/'evidence'/'icall_dispatch_table.json').read_text(encoding='utf-8'))
missing=[r for r in icall['records'] if r.get('resolved_class')=='not_lifted_in_range']
targets=sorted({int(r['slot_static_ptr'],16) for r in missing})
imgpath=ROOT/'evidence'/'genewars-1_1.exe'; img=load_le(imgpath); obj=img.objects[0]; lo=obj.base; hi=lo+obj.virtual_size
code=bytes(img.mem[lo-img.mem_base:hi-img.mem_base]); sec=Section('.text',obj.base,obj.virtual_size,0,obj.virtual_size,0x20000020)
t0=time.time(); funcs=Disassembler(code,0,[sec]).find_functions(lo,hi,seeds=targets)
source=(ROOT/'build'/'recomp_282.c').read_text(encoding='utf-8'); compiled={int(x,16) for x in re.findall(r'RECOMP_ENTER\(0x([0-9A-Fa-f]{8})u\)',source)}
lift=Lifter(); bodies=[]; records=[]
for va in targets:
 f=funcs.get(va)
 if f is None: raise RuntimeError(f'no exact function boundary: {va:#x}')
 f.name=f'sub_{va:08X}'; body=lift.lift_function(f)
 if f'RECOMP_ENTER(0x{va:08X}u)' not in body: raise RuntimeError(f'lift entry mismatch {va:#x}')
 bodies.append(f'/* ICALL resolved target 0x{va:08X} */\n'+body)
 records.append({'va':f'0x{va:08X}','end':f'0x{f.end:08X}','instructions':sum(len(b.instructions) for b in f.blocks.values()),'map_name':None})
header='\n/* Incremental ICALL targets: L-ICALL-LIFT7 */\n'
append=header+'\n'.join(bodies)+'\n'
candidate=ROOT/'build'/'recomp_282_icall.c'; candidate.write_text(source+append,encoding='utf-8')
report={'task':'L-ICALL-LIFT7','target_sha256':hashlib.sha256(imgpath.read_bytes()).hexdigest(),'source_before_sha256':hashlib.sha256(source.encode()).hexdigest(),'targets':records,'previous_functions':len(compiled),'new_functions':len(records),'candidate':str(candidate.relative_to(ROOT)),'candidate_sha256':hashlib.sha256(candidate.read_bytes()).hexdigest(),'elapsed_seconds':round(time.time()-t0,2)}
(ROOT/'evidence'/'icall_lift_work1.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print(json.dumps(report,indent=2))
