"""Seed pcrecomp's x86-32 CFG recovery with symbols from GeneWars 1.1's LE map."""
import json, sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'third_party'/'pcrecomp'))
from le_loader import load_le
from tools.disasm.disasm32 import Disassembler
from tools.pe.pe_analyze import Section
root=Path(__file__).resolve().parents[1]; image=load_le(root/'evidence'/'genewars-1_1.exe')
code_obj=image.objects[0]; code_start=code_obj.base; code_end=code_obj.base+code_obj.virtual_size
code=bytes(image.mem[code_start-image.mem_base:code_end-image.mem_base])
section=Section('.text',code_obj.base,code_obj.virtual_size,0,code_obj.virtual_size,0x20000020)
rows=[]
for line in (root/'evidence'/'genewars-1_1.map').read_text(errors='replace').splitlines():
 p=line.split()
 if len(p)<2 or not p[0].startswith('0001:'):continue
 try:addr=int(p[0].split(':')[1],16)
 except ValueError:continue
 rows.append((addr,p[1]))
map_symbols={a:n for a,n in rows}
seeds=sorted({a for a,n in rows if code_start<=a<code_end and (n.startswith(('W?','Lb')) or n.endswith('_') and not n.startswith(('jpt_','def_')))})
d=Disassembler(code,0,[section]); funcs=d.find_functions(code_start,code_end,seeds=seeds)
matched=sum(1 for a in funcs if a in map_symbols)
report={'binary_sha256':'2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f','code_range':[hex(code_start),hex(code_end)],'map_public_symbols_seg1':len(rows),'map_seed_count':len(seeds),'functions_discovered':len(funcs),'function_starts_matching_map':matched,'function_samples':[{'address':f'0x{a:08X}','name':map_symbols.get(a,''),'end':f'0x{funcs[a].end:08X}','blocks':len(funcs[a].blocks),'instructions':sum(len(b.instructions) for b in funcs[a].blocks.values())} for a in sorted(funcs)[:100]]}
(root/'evidence'/'function_catalog.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items() if k!='function_samples'},indent=2))
