"""Validate a LOCAL ICALL target against LE/MAP and refresh it with the current Lifter."""
import hashlib, json, re, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'third_party'/'pcrecomp')]
from le_loader import load_le
from tools.disasm.disasm32 import Disassembler
from tools.pe.pe_analyze import Section
from tools.lift.lift32 import Lifter
VA=0x00096B10; EXPECTED_END=0x00096B23
TARGET=ROOT/'evidence'/'genewars-1_1.exe'; MAP=ROOT/'evidence'/'genewars-1_1.map'
def function_span(text, name=None, va=None):
    for m in re.finditer(r'\bvoid\s+([A-Za-z_]\w*)\s*\(\s*void\s*\)\s*\{', text):
        brace=text.index('{',m.start()); depth=0
        for i in range(brace,len(text)):
            if text[i]=='{': depth+=1
            elif text[i]=='}':
                depth-=1
                if depth==0:
                    body=text[m.start():i+1]
                    ent=re.search(r'RECOMP_ENTER\(0x([0-9A-Fa-f]+)u\)',body)
                    found=int(ent.group(1),16) if ent else None
                    if (name is None or name==m.group(1)) and (va is None or va==found): return m.start(),i+1,m.group(1),body
                    break
    return None

def instruction_addresses(body):
    return [int(x,16) for x in re.findall(r'/\*\s*0x([0-9A-Fa-f]{8}):',body)]

sha=hashlib.sha256(TARGET.read_bytes()).hexdigest()
if sha!='2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f': raise SystemExit('target SHA mismatch')
map_name=None
for line in MAP.read_text(errors='replace').splitlines():
    cols=line.split()
    if cols and cols[0]=='0001:00096B10': map_name=cols[1]; break
if map_name!='mem_putc_': raise SystemExit(f'MAP mismatch at target: {map_name}')
img=load_le(TARGET); obj=img.objects[0]
if obj.base!=0x10000: raise SystemExit(f'LE base mismatch: {obj.base:#x}')
code=bytes(img.mem[obj.base-img.mem_base:obj.base+obj.virtual_size-img.mem_base])
sec=Section('.text',obj.base,obj.virtual_size,0,obj.virtual_size,0x20000020)
f=Disassembler(code,0,[sec]).disassemble_function(VA)
if f is None or f.address!=VA or f.end!=EXPECTED_END: raise SystemExit('MAIN.EXE boundary mismatch')
source_path=ROOT/'build'/'recomp_282.c'; batch_src=source_path.read_text(encoding='utf-8')
batch=function_span(batch_src,va=VA)
if batch is None: raise SystemExit('LOCAL batch body for VA missing')
name,batch_body=batch[2],batch[3]
f.name='sub_00096B10'; fresh=Lifter().lift_function(f)
if instruction_addresses(batch_body)!=instruction_addresses(fresh): raise SystemExit('batch and current lift instruction addresses differ')
if 'DS_BASE +' not in fresh or 'recomp_begin_memory_access' not in fresh: raise SystemExit('fresh lift lacks segment/range guards')
combined=ROOT/'build'/'entry_path_combined.c'; text=combined.read_text(encoding='utf-8')
existing=[]
for m in list(re.finditer(r'\bvoid\s+[A-Za-z_]\w*\s*\(\s*void\s*\)\s*\{',text)):
    # use the shared parser from this same source to find VA entry
    span=function_span(text,va=VA)
    if span: existing=[span]; break
if len(existing)>1: raise SystemExit('duplicate canonical target VA')
if existing:
    start,end,_,_=existing[0]; text=text[:start]+fresh+text[end:]
else:
    text+='\n/* Re-lifted verified LOCAL ICALL target mem_putc_ with current segment checks. */\n'+fresh+'\n'
combined.write_text(text,encoding='utf-8')
body=function_span(text,va=VA)
if body is None or body[3]!=fresh: raise SystemExit('combined source does not contain canonical fresh lift')
closure=ROOT/'build'/'entry_path_closure.c'; closure_text=closure.read_text(encoding='utf-8')
if len(re.findall(r'RECOMP_ENTER\(0x00096B10u\)',closure_text))!=1: raise SystemExit('entry closure must contain target exactly once')
report={'task':'W1-027','target_sha256':sha,'map_sha256':hashlib.sha256(MAP.read_bytes()).hexdigest(),'le_base':'0x00010000','va':'0x00096B10','map_symbol':map_name,'boundary_end':f'0x{f.end:08X}','raw_bytes_sha256':hashlib.sha256(bytes(img.mem[VA-img.mem_base:f.end-img.mem_base])).hexdigest(),'batch_source':'build/recomp_282.c','batch_function':name,'batch_body_sha256':hashlib.sha256(batch_body.encode()).hexdigest(),'batch_instruction_addresses_match':True,'batch_body_used_verbatim':False,'batch_delta':'The LOCAL body omits the current lifter DS_BASE and guarded access instrumentation; refreshed body uses both.','fresh_lift_sha256':hashlib.sha256(fresh.encode()).hexdigest(),'combined_body_matches_fresh_lift':True,'closure_contains_target_once':True,'closure_function_count':len(re.findall(r'RECOMP_ENTER\(0x[0-9A-Fa-f]+u\)',closure_text)),'compilation_evidence':'evidence/entry_path_closure_routed_compile.json','native_frontier_evidence':'evidence/native_entry_after_mem_putc_work1.json','passed':True}
(ROOT/'evidence'/'entry_mem_putc_integration_work1.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print(json.dumps(report,indent=2))
