"""Lift the actual __save_8087_ bytes and compare saved x87 state against x86."""
import hashlib,json,os,pathlib,subprocess,sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'third_party'/'pcrecomp'))
sys.path.insert(0,str(ROOT/'src'))
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
from tools.disasm.disasm32 import Instruction,BasicBlock,Function
from tools.lift.lift32 import Lifter
raw=bytes.fromhex('9b dd 30 9b c3'); address=0xBC09F
md=Cs(CS_ARCH_X86,CS_MODE_32);md.detail=True
ins=[Instruction(x.address,x.size,x.mnemonic,x.op_str,bytes(x.bytes),x.operands) for x in md.disasm(raw,address)]
assert len(ins)==4 and [x.mnemonic for x in ins]==['wait','fnsave','wait','ret']
block=BasicBlock(address,address+len(raw),ins,is_exit=True)
f=Function(address,end=address+len(raw),name='__save_8087_',blocks={address:block},size=len(raw))
body=Lifter().lift_function(f)
assert 'recomp_fnsave_image' in body and 'recomp_fwait' in body and 'UNIMPLEMENTED: fnsave' not in body
src='#define RECOMP_GENERATED_CODE\n#include "recomp_types.h"\n#include "recomp_x87.h"\n'+body+'\n'
(ROOT/'build'/'fnsave_lift.c').write_text(src,encoding='utf-8')
cache=ROOT/'cache';cache.mkdir(exist_ok=True)
env={**os.environ,'TEMP':str(cache),'TMP':str(cache),'TMPDIR':str(cache),'PATH':r'E:\\msys64\\mingw32\\bin;E:\\msys64\\usr\\bin;'+os.environ.get('PATH','')}
cmd=[r'E:\\msys64\\mingw32\\bin\\gcc.exe','-std=gnu11','-m32','-O0','-I',str(ROOT/'runtime'),'-I',str(ROOT/'third_party'/'pcrecomp'/'runtime'/'recomp32'),'-o',str(ROOT/'build'/'test_fnsave.exe'),str(ROOT/'tests'/'test_fnsave.c'),str(ROOT/'runtime'/'recomp_x87.c'),str(ROOT/'build'/'fnsave_lift.c')]
p=subprocess.run(cmd,cwd=ROOT,env=env,text=True,capture_output=True)
if p.returncode: print(p.stdout,p.stderr); raise SystemExit(p.returncode)
r=subprocess.run([str(ROOT/'build'/'test_fnsave.exe')],cwd=ROOT,env=env,text=True,capture_output=True)
if r.returncode: print(r.stdout,r.stderr); raise SystemExit(r.returncode)
report={'target_sha256':'2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f','map_symbol':'__save_8087_','address':f'0x{address:08X}','bytes':raw.hex(),'patterns':4,'oracle':'native x86-32 FNSAVE image with unmodeled IP/selector/opcode fields normalized','checks':['CW','SW TOP','tag word','logical ST0..ST7 80-bit image','virtual TOP reset','FPU control reset','post-save FWAIT'],'passed':True,'compile_exit':0,'execution_exit':0,'stdout':r.stdout.strip()}
(ROOT/'evidence'/'fnsave_semantics.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print(r.stdout.strip())
