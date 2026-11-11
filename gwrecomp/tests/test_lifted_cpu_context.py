"""Extract and compare a real lifted function under direct and explicit-context calls."""
import os,pathlib,subprocess,json,hashlib
ROOT=pathlib.Path(__file__).resolve().parents[1]
cache=ROOT/'cache'; cache.mkdir(exist_ok=True)
env={**os.environ,'TEMP':str(cache),'TMP':str(cache),'TMPDIR':str(cache),'PATH':r'E:\\msys64\\mingw32\\bin;E:\\msys64\\usr\\bin;'+os.environ.get('PATH','')}
src=(ROOT/'build'/'recomp_catalog_100.c').read_text(encoding='utf-8')
name='gw_lift_0000'; start=src.index('void '+name+'('); brace=src.index('{',start); depth=0; end=None
for i in range(brace,len(src)):
    if src[i]=='{': depth+=1
    elif src[i]=='}':
        depth-=1
        if depth==0: end=i+1; break
assert end is not None
(ROOT/'build'/'lift_cpu_context_fixture.c').write_text('#define RECOMP_GENERATED_CODE\n#include "recomp_types.h"\n'+src[start:end]+'\n',encoding='utf-8')
cmd=['E:/msys64/mingw32/bin/gcc.exe','-std=gnu11','-m32','-O0','-I',str(ROOT/'runtime'),'-I',str(ROOT/'third_party'/'pcrecomp'/'runtime'/'recomp32'),'-o',str(ROOT/'build'/'test_lifted_cpu_context.exe'),str(ROOT/'tests'/'test_lifted_cpu_context.c'),str(ROOT/'runtime'/'recomp_context.c'),str(ROOT/'runtime'/'gw_interrupts.c'),str(ROOT/'runtime'/'gw_segments.c'),str(ROOT/'runtime'/'recomp_bridge.c'),str(ROOT/'build'/'lift_cpu_context_fixture.c')]
p=subprocess.run(cmd,cwd=ROOT,text=True,capture_output=True,env=env)
if p.returncode:
    print(p.stdout); print(p.stderr); raise SystemExit(p.returncode)
p=subprocess.run([str(ROOT/'build'/'test_lifted_cpu_context.exe')],cwd=ROOT,text=True,capture_output=True,env=env)
print('run rc',p.returncode,'stdout=',p.stdout,'stderr=',p.stderr)
if p.returncode: raise SystemExit(p.returncode)
report={'test':'real generated gw_lift_0000 direct/global vs explicit CPU context','source_sha256':hashlib.sha256((ROOT/'build'/'recomp_catalog_100.c').read_bytes()).hexdigest(),'compile_exit':0,'run_exit':0,'checks':['all GPRs','lazy flag state','segments','x87 state','guest stack','guest memory effects','null rejection','nested BUSY rejection'],'passed':True}
(ROOT/'evidence'/'lifted_cpu_context.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print('lifted CPU context PASS: direct/global and explicit-context state/memory match')

