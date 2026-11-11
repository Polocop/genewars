"""Lift and compare simple functions from the 1.1 DOS/4GW LE executable."""
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'third_party' / 'pcrecomp'))
from le_loader import load_le
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, x86_const
from tools.lift.lift32 import Lifter
from tools.disasm.disasm32 import Instruction, BasicBlock, Function

ROOT=Path(__file__).resolve().parents[1]; EXE=ROOT/'evidence'/'genewars-1_1.exe'; MAP=ROOT/'evidence'/'genewars-1_1.map'
N=int(sys.argv[1]) if len(sys.argv)>1 else 10; im=load_le(EXE)
rows=[]
for line in MAP.read_text(errors='replace').splitlines():
 s=line.split()
 if len(s)>=2 and s[0].startswith('0001:'):
  try: rows.append((int(s[0].split(':')[1],16),s[1]))
  except ValueError: pass
md=Cs(CS_ARCH_X86,CS_MODE_32); md.detail=True; candidates=[]; seen=set()
for idx,(addr,name) in enumerate(rows):
 if not name.startswith(('W?','Lb')) or addr in seen or addr<im.mem_base or addr>=0xef930: continue
 next_method=min((a for a,n in rows[idx+1:] if n.startswith('W?')),default=addr+0x80)
 if next_method<=addr:continue
 lim=min(next_method,addr+0x80); off=addr-im.mem_base; decoded=list(md.disasm(im.mem[off:off+lim-addr],addr)); selected=[]; valid=True; ended=False
 for x in decoded:
  if x.mnemonic=='ret': selected.append(x); ended=True; break
  if x.mnemonic=='xor' and len(x.operands)==2 and x.operands[0].type==x86_const.X86_OP_REG and x.operands[0].reg==x.operands[1].reg:
   selected.append(x); continue
  if x.mnemonic!='mov' or len(x.operands)!=2: valid=False; break
  dst,src=x.operands
  if dst.type==x86_const.X86_OP_MEM and src.type in (x86_const.X86_OP_IMM,x86_const.X86_OP_REG):
   if dst.size not in (1,2,4) or dst.mem.index!=0 or dst.mem.base not in (0,x86_const.X86_REG_EAX): valid=False; break
   if dst.mem.base==x86_const.X86_REG_EAX and not (0<=dst.mem.disp<512): valid=False; break
   if dst.mem.base==0 and not (0x10000<=dst.mem.disp<0x1b1000): valid=False; break
  elif dst.type==x86_const.X86_OP_REG and src.type==x86_const.X86_OP_MEM and src.mem.base==0 and src.mem.index==0 and src.size in (1,2,4) and 0x10000<=src.mem.disp<0x1b1000:
   pass
  else: valid=False; break
  selected.append(x)
 if not valid or not ended or not selected[:-1]:continue
 code=im.mem[off:off+sum(x.size for x in selected)]
 if b''.join(bytes(x.bytes) for x in selected)!=code:continue
 candidates.append((addr,name,code,selected));seen.add(addr)
 if len(candidates)>=N:break
if len(candidates)<N:raise SystemExit(f'only {len(candidates)} candidates satisfy this liftable straight-line contract; found {len(candidates)}')

prelude='#define RECOMP_GENERATED_CODE\n#include "recomp_types.h"\n'
generated=[prelude]; tests=[]; lifter=Lifter()
for i,(addr,name,code,ins) in enumerate(candidates):
 fn=f'lifted_{i:03d}'; wrapped=[Instruction(x.address,x.size,x.mnemonic,x.op_str,bytes(x.bytes),list(x.operands)) for x in ins]
 bb=BasicBlock(addr,addr+len(code),wrapped,[],True); func=Function(addr,addr+len(code),fn,{addr:bb},size=len(code))
 generated.append(lifter.lift_function(func)); generated.append('')
 abs_offsets=sorted({x.address-addr+x.disp_offset for x in ins if x.disp_size==4 and any(op.type==x86_const.X86_OP_MEM and op.mem.base==0 and op.mem.index==0 for op in x.operands)})
 tests.append((i,addr,name,code,fn,f'raw_{i:03d}',abs_offsets))
(ROOT/'build'/'recomp_batch.c').write_text('\n'.join(generated))
lines=['#include <stdint.h>','#include <stdio.h>','#include <string.h>','#include <windows.h>','#include "recomp_batch.c"','uint32_t g_eax,g_ecx,g_edx,g_ebx,g_esp,g_ebp,g_esi,g_edi; double g_st[8]; int g_fp_top; uint16_t g_fpu_cw; ptrdiff_t g_mem_base; uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_fs,g_seg_gs,g_seg_ss; uint32_t g_fs_base,g_gs_base,g_cur_func; static uint8_t guest_mem[0x1B1000];']
for i,addr,name,code,fn,rn,_ in tests:lines.append(f'static const uint8_t {rn}[] = {{{",".join(f"0x{b:02x}" for b in code)}}};')
for i,addr,name,code,fn,rn,offsets in tests:
 if offsets: lines.append(f'static const unsigned abs_off_{i}[] = {{{",".join(str(x) for x in offsets)}}};')
lines += ['typedef void (__attribute__((cdecl)) * raw_fn)(void);','static void shift_abs(uint8_t *p,unsigned off,uint32_t delta){uint32_t v;memcpy(&v,p+off,4);v+=delta;memcpy(p+off,&v,4);}','int main(void) {','  const uint32_t guest_base_old=0x10000u,mem_size=0x1B1000u; uint8_t *original=(uint8_t*)VirtualAlloc(NULL,mem_size,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE); if(!original){puts("cannot allocate relocated guest image");return 20;} uint32_t guest_base=(uint32_t)(uintptr_t)original,delta=guest_base-guest_base_old;','  uint8_t *execmem=(uint8_t*)VirtualAlloc(NULL,0x10000,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE); if(!execmem)return 21;','  void (*lifts[])(void) = {'+','.join(x[4] for x in tests)+'};','  const uint8_t *raws[] = {'+','.join(x[5] for x in tests)+'};','  const unsigned sizes[] = {'+','.join(str(len(x[3])) for x in tests)+'};','  const unsigned *offsets[] = {'+','.join(('abs_off_'+str(x[0]) if x[6] else 'NULL') for x in tests)+'};','  const unsigned offset_counts[] = {'+','.join(str(len(x[6])) for x in tests)+'};',f'  for(unsigned i=0;i<{N};++i){{','    for(uint32_t j=0;j<mem_size;++j) original[j]=(uint8_t)((j*17u+i*29u)&255);','    memcpy(guest_mem,original,mem_size); g_mem_base=(ptrdiff_t)(uintptr_t)guest_mem-(ptrdiff_t)guest_base_old; uint8_t *fncode=execmem; memcpy(fncode,raws[i],sizes[i]); for(unsigned k=0;k<offset_counts[i];++k)shift_abs(fncode,offsets[i][k],delta); uint32_t raw_eax;','    __asm__ volatile ("mov %1, %%eax\\n\\tcall *%2\\n\\tmov %%eax, %0" : "=a"(raw_eax) : "S"(original), "D"(fncode) : "ecx","edx","memory","cc");','    g_eax=guest_base_old; g_esp=0x1B0000u; lifts[i]();','    uint32_t raw_guest_eax=raw_eax; if(raw_eax>=guest_base && raw_eax<guest_base+mem_size)raw_guest_eax-=delta;','    if(g_eax!=raw_guest_eax){printf("EAX FAIL %u %08X %08X\\n",i,g_eax,raw_guest_eax);return 2;}','    if(memcmp(original,guest_mem,mem_size)!=0){printf("MEM FAIL %u\\n",i);return 1;}','  }',f'  printf("PASS {N} original-vs-current-pcrecomp lifts\\n"); return 0;','}']
(ROOT/'tests'/'test_recomp_batch.c').write_text('\n'.join(lines)+'\n')
(ROOT/'evidence'/f'batch_{N}.json').write_text(json.dumps({'target_sha256':'2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f','count':N,'functions':[{'index':i,'address':f'0x{a:08X}','name':n,'end':f'0x{a+len(c):08X}','bytes':c.hex(),'lifted_name':f} for i,a,n,c,f,_,_ in tests]},indent=2)+'\n')
print(f'generated {N} functions with standalone pcrecomp; first={tests[0][1]:08X} {tests[0][2]}')

