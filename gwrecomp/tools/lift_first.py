import sys
from pathlib import Path
sys.path.insert(0, r'E:\GWRecomp\third_party\recoil-recomp\tools\pcrecomp')
sys.path.insert(0, r'E:\GWRecomp\src')
from le_loader import load_le
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
from tools.lift.lift32 import Lifter

root=Path(r'E:\GWRecomp')
exe=root/'evidence'/'genewars-1_1.exe'; mp=root/'evidence'/'genewars-1_1.map'
addr=0x248F0; end=0x248FE; name='W?$ct:InfoRequester$n()_'
im=load_le(exe)
code=im.mem[addr-im.mem_base:end-im.mem_base]
md=Cs(CS_ARCH_X86,CS_MODE_32); md.detail=True
ins=list(md.disasm(code,addr))
assert b''.join(bytes(x.bytes) for x in ins)==code and ins[-1].mnemonic=='ret'
lifter=Lifter()
lines=['#include <stdint.h>','uint32_t eax,ecx,edx,ebx,esp,ebp,esi,edi;','double _st[8]; int _fp_top,_fpu_cmp; uint32_t _cf; int _df; uint16_t _fpu_cw;','static uint8_t guest_mem[256];','#define MEM8(a) (*(uint8_t*)(guest_mem + ((a)-0x1000)))','#define MEM16(a) (*(uint16_t*)(guest_mem + ((a)-0x1000)))','#define MEM32(a) (*(uint32_t*)(guest_mem + ((a)-0x1000)))','void lifted_info_requester_ctor(void) {']
for x in ins:
 for line in lifter.lift_instruction(x): lines.append('  '+line)
lines += ['}']
out='\n'.join(lines)+'\n'
(root/'build'/'lifted_info_requester.c').write_text(out)
(root/'evidence'/'info_requester_ctor.bin').write_bytes(code)
print('address',hex(addr),'end',hex(end),'name',name,'bytes',code.hex(),'instructions',len(ins))
print(out)
