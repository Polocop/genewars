"""Boundary-gated, rebase-aware differential test for new call-free MAIN.MAP CFGs."""
import json, pathlib, re, subprocess, sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src")); sys.path.insert(0, str(ROOT / "third_party" / "pcrecomp"))
from le_loader import load_le
from tools.disasm.disasm32 import Disassembler
from tools.pe.pe_analyze import Section
from tools.lift.lift32 import Lifter
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, x86_const
N = 32
IMAGE = ROOT / "evidence" / "genewars-1_1.exe"
image = load_le(IMAGE); obj=image.objects[0]; start=obj.base; end=start+obj.virtual_size
code = bytes(image.mem[start-image.mem_base:end-image.mem_base])
map_path=ROOT/"evidence"/"genewars-1_1.map"; rows=[]
for line in map_path.read_text(errors="replace").splitlines():
    p=line.split()
    if len(p)>=2 and p[0].startswith("0001:"):
        try: rows.append((int(p[0].split(":")[1],16),p[1]))
        except ValueError: pass
function_like=lambda n: n.startswith(("W?","Lb")) or (n.endswith("_") and not n.startswith(("jpt_","def_")))
map_names={a:n for a,n in rows}
seeds=sorted({a for a,n in rows if start<=a<end and function_like(n)})
prior=json.loads((ROOT/"evidence"/"batch_10.json").read_text(encoding="utf-8")); prior_addrs={int(x["address"],16) for x in prior["functions"]}
boundary=json.loads((ROOT/"evidence"/"boundary_revalidation_work3.json").read_text(encoding="utf-8")); overlaps={int(a,16) for a in boundary["overlap"]["per_seed_profiles"]}
section=Section(".text",obj.base,obj.virtual_size,0,obj.virtual_size,0x20000020)
md=Cs(CS_ARCH_X86,CS_MODE_32); md.detail=True
funcs=Disassembler(code,0,[section]).find_functions(start,end,seeds=seeds)

# Keep routines whose full body is a contiguous, loop-free instruction span. Their
# only explicit register is EAX; all memory is absolute guest data or [EAX+small].
def qualifies(f):
    ins=sorted((i for b in f.blocks.values() for i in b.instructions),key=lambda i:i.address)
    if not ins or f.entry_kind!="start" or any(i.is_call for i in ins): return None
    if not any(i.is_ret for i in ins) or any(i.mnemonic in {"retf","iret","int","int1","int3","hlt","push","pop","pushf","popf","pusha","popa","call"} for i in ins): return None
    cursor=f.address
    addresses={i.address for i in ins}
    for i in ins:
        if i.address!=cursor: return None
        cursor+=i.size
    if cursor!=f.end: return None
    branches=0; eax_pointer=True; eax_guest=start
    for i in ins:
        if i.is_jump:
            branches+=1; t=i.get_branch_target()
            if t is None or t not in addresses or t<i.address: return None
        if i.mnemonic in ("loop","loope","loopne","loopz","loopnz","jecxz","jcxz"): return None
        for op in (i.operands or []):
            if op.type==x86_const.X86_OP_REG and op.reg!=x86_const.X86_REG_EAX: return None
            if op.type==x86_const.X86_OP_MEM:
                if op.mem.index!=0 or op.mem.base not in (0,x86_const.X86_REG_EAX): return None
                if op.mem.base==x86_const.X86_REG_EAX:
                    if not eax_pointer or not (start<=eax_guest+op.mem.disp<0x1B1000): return None
                elif not (start<=op.mem.disp<0x1B1000): return None
        # Any destination register other than EAX would need a matched raw CPU seed.
        if i.operands and i.operands[0].type==x86_const.X86_OP_REG and i.operands[0].reg!=x86_const.X86_REG_EAX:
            if i.mnemonic not in ("cmp","test","bt"): return None
        # Memory-to-EAX loads make EAX data-dependent; do not permit later [EAX] accesses.
        if i.mnemonic=="mov" and len(i.operands)==2 and i.operands[0].type==x86_const.X86_OP_REG and i.operands[0].reg==x86_const.X86_REG_EAX:
            src=i.operands[1]
            if src.type==x86_const.X86_OP_IMM:
                eax_guest=src.imm & 0xffffffff; eax_pointer=start<=eax_guest<0x1B1000
            elif src.type==x86_const.X86_OP_REG and src.reg==x86_const.X86_REG_EAX:
                pass
            else: eax_pointer=False
        elif i.operands and i.operands[0].type==x86_const.X86_OP_REG and i.operands[0].reg==x86_const.X86_REG_EAX:
            if i.mnemonic in ("add","sub") and len(i.operands)==2 and i.operands[1].type==x86_const.X86_OP_IMM and eax_pointer:
                delta=i.operands[1].imm if i.mnemonic=="add" else -i.operands[1].imm
                eax_guest=(eax_guest+delta)&0xffffffff; eax_pointer=start<=eax_guest<0x1B1000
            elif i.mnemonic not in ("cmp","test","bt"):
                eax_pointer=False
    try:
        f.name="w3_probe"; Lifter().lift_function(f)
    except Exception: return None
    raw=bytes(image.mem[f.address-image.mem_base:f.end-image.mem_base])
    decoded=b"".join(i.bytes for i in ins)
    if raw!=decoded: return None
    # Rebase only absolute memory operands that address the emulated LE/DOS image.
    native=list(md.disasm(raw,f.address))
    offsets=sorted({i.address-f.address+i.disp_offset for i in native if i.disp_size==4 and any(op.type==x86_const.X86_OP_MEM and op.mem.base==0 and op.mem.index==0 for op in i.operands)})
    return ins,raw,offsets,branches

candidates=[]
for a in seeds:
    if a in prior_addrs or a in overlaps: continue
    f=funcs.get(a)
    if f is None: continue
    q=qualifies(f)
    if q is None: continue
    ins,raw,offsets,branches=q
    candidates.append((f,map_names.get(a,""),ins,raw,offsets,branches))
    if len(candidates)>=N: break
if len(candidates)<N:
    raise SystemExit(f"only {len(candidates)} clean non-overlapping function-like MAP entries satisfy this CFG/ISA contract; need {N}")

# Emit independently lifted leaf bodies and a C oracle that runs original x86 bytes
# at a rebased executable address against the generated C under the same state.
code_lines=["#define RECOMP_GENERATED_CODE","#include \"recomp_types.h\"",""]
records=[]; lifter=Lifter()
for i,(f,name,ins,raw,offsets,branches) in enumerate(candidates):
    f.name=f"w3_lift_{i:03d}"; code_lines.extend([lifter.lift_function(f),""])
    records.append({"index":i,"address":f"0x{f.address:08X}","name":name,"end":f"0x{f.end:08X}","size":len(raw),"bytes":raw.hex(),"instructions":len(ins),"conditional_or_direct_branches":branches,"direct_calls":0,"entry_kind":f.entry_kind,"relocated_absolute_displacements":offsets,"overlap_excluded":False})
(ROOT/"build"/"recomp_cfg_leaf_work3.c").write_text("\n".join(code_lines),encoding="utf-8")
N=len(records)
lines=["#include <stdint.h>","#include <stdio.h>","#include <string.h>","#include <windows.h>","#include \"recomp_cfg_leaf_work3.c\"",
"uint32_t g_eax,g_ecx,g_edx,g_ebx,g_esp,g_ebp,g_esi,g_edi; double g_st[8]; int g_fp_top; uint16_t g_fpu_cw; ptrdiff_t g_mem_base; uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_fs,g_seg_gs,g_seg_ss; uint32_t g_cs_base,g_ds_base,g_es_base,g_fs_base,g_gs_base,g_ss_base,g_cur_func;",
"static uint8_t guest_mem[0x1B1000]; static uint32_t host_saved_esp, raw_saved_esp;",
"static void shift_abs(uint8_t *p,unsigned off,uint32_t delta){uint32_t v;memcpy(&v,p+off,4);v+=delta;memcpy(p+off,&v,4);}"]
for i,r in enumerate(records):
    raw=bytes.fromhex(r["bytes"]); lines.append(f"static const uint8_t raw_{i:03d}[]={{"+",".join(f"0x{x:02x}" for x in raw)+"};")
    if r["relocated_absolute_displacements"]: lines.append(f"static const unsigned abs_{i:03d}[]={{"+",".join(map(str,r["relocated_absolute_displacements"]))+"};")
lines += ["int main(void){",f"  void(*lifts[{N}])(void)={{"+",".join(f"w3_lift_{i:03d}" for i in range(N))+"};",
"  uint8_t *original=(uint8_t*)VirtualAlloc(NULL,0x1B1000,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE); if(!original)return 20; uint32_t guest_base=(uint32_t)(uintptr_t)original, delta=guest_base-0x10000u;",
"  uint8_t *execmem=(uint8_t*)VirtualAlloc(NULL,0x10000,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE); if(!execmem)return 21;",
"  for(unsigned i=0;i<"+str(N)+";++i) for(unsigned pattern=0;pattern<4;++pattern){",
"    for(uint32_t j=0;j<0x1B1000;++j) original[j]=(uint8_t)(pattern==0?0:pattern==1?0xff:pattern==2?(j*17u+i*29u):(j*73u+pattern*31u+i*11u));",
"    memcpy(guest_mem,original,0x1B1000); g_mem_base=(ptrdiff_t)(uintptr_t)guest_mem-(ptrdiff_t)0x10000u;",
"    uint8_t *fncode=execmem; uint32_t raw_eax=0,raw_flags=0;",
"    switch(i){"]
for i,r in enumerate(records):
    size=r["size"]; offsets=r["relocated_absolute_displacements"]
    lines.append(f"      case {i}: memcpy(fncode,raw_{i:03d},{size});")
    if offsets: lines.append(f"        for(unsigned k=0;k<{len(offsets)};++k)shift_abs(fncode,abs_{i:03d}[k],delta);")
    lines.append("        break;")
lines += ["      default:return 22; }",
"    __asm__ volatile (\"pushl $0x202\\n\\tpopfl\\n\\tmov %2, %%eax\\n\\tcall *%3\\n\\tpushfl\\n\\tpopl %%ecx\\n\\tmov %%ecx, %1\\n\\tmov %%eax, %0\" : \"=m\"(raw_eax),\"=m\"(raw_flags) : \"S\"(original),\"D\"(fncode) : \"eax\",\"ecx\",\"edx\",\"memory\",\"cc\");",
"    uint32_t raw_guest_eax=raw_eax; if(raw_eax>=guest_base && raw_eax<guest_base+0x1B1000u)raw_guest_eax-=delta;",
"    g_eax=0x10000u; g_ecx=g_edx=g_ebx=g_ebp=g_esi=g_edi=0; g_esp=0x001A0000u; g_flag_k=FK_NONE;g_flag_a=g_flag_b=g_flag_cf=0; lifts[i]();",
"    uint32_t lifted_flags=recomp_eflags(g_flag_k,g_flag_a,g_flag_b,g_flag_cf,1);",
"    if(g_eax!=raw_guest_eax){printf(\"EAX FAIL fn=%u pattern=%u lifted=%08X raw=%08X\\n\",i,pattern,g_eax,raw_guest_eax);return 2;}",
"    if(((lifted_flags^raw_flags)&0x8D5u)!=0){printf(\"EFLAGS FAIL fn=%u pattern=%u lifted=%08X raw=%08X\\n\",i,pattern,lifted_flags,raw_flags);return 3;}",
"    if(memcmp(original,guest_mem,0x1B1000)!=0){printf(\"MEM FAIL fn=%u pattern=%u\\n\",i,pattern);return 4;}",
"  }",f"  printf(\"PASS {N} new non-overlapping MAP functions x 4 memory patterns; EAX/EFLAGS/memory match\\n\"); return 0;", "}"]
test_path=ROOT/"tests"/"test_recomp_cfg_leaf_work3.c"; test_path.write_text("\n".join(lines)+"\n",encoding="utf-8")
if "--generate-only" in sys.argv:
    import hashlib
    print(json.dumps({"generated_test":str(test_path.relative_to(ROOT)),"lift_source_sha256":hashlib.sha256((ROOT/"build"/"recomp_cfg_leaf_work3.c").read_bytes()).hexdigest(),"functions":N}))
    raise SystemExit(0)
compiler=pathlib.Path(r"E:\msys64\mingw32\bin\gcc.exe"); exe=ROOT/"build"/"test_recomp_cfg_leaf_work3.exe"; hdr=ROOT/"third_party"/"pcrecomp"/"runtime"/"recomp32"
cmd=[str(compiler),"-std=gnu11","-m32","-O0","-w","-I",str(hdr),"-I",str(ROOT/"build"),"-o",str(exe),str(test_path),str(ROOT/"runtime"/"recomp_x87.c")]
cp=subprocess.run(cmd,capture_output=True,text=True,cwd=ROOT)
if cp.returncode: raise SystemExit("compile failed:\n"+cp.stderr[-6000:])
run=subprocess.run([str(exe)],capture_output=True,text=True,cwd=ROOT)
report={"task":"W3-007","target_sha256":__import__("hashlib").sha256(IMAGE.read_bytes()).hexdigest(),"code_range":[f"0x{start:08X}",f"0x{end:08X}"],"selected_new_functions":records,"new_function_count":N,"functions_overlap_excluded":True,"oracle_model":"rebase original instruction bytes into a private executable buffer; run against independent generated C lifts using matched randomized memory; compare returned EAX, defined EFLAGS mask CF/PF/ZF/SF/OF/DF, and full memory after four deterministic patterns per function","direct_call_coverage":"0 direct calls by selection; no CALL instruction accepted", "instruction_branches":sum(x["conditional_or_direct_branches"] for x in records),"patterns_per_function":4,"semantic_cases":N*4,"compile_returncode":cp.returncode,"execution_returncode":run.returncode,"execution_stdout":run.stdout.strip(),"execution_stderr":run.stderr[-2000:],"limitations":["Only call-free, forward-branch, contiguous CFGs with EAX and guest-memory operands are selected; this does not cover indirect calls, stack arguments, x87, or DOS services.","Boundary confidence uses corrected VA CFG, exact MAIN.MAP starts, non-overlap exclusion, byte identity, and RET; the 10 stored oracle fixtures remain the only target-authored exact size oracle."]}
(ROOT/"evidence"/"differential_cfg_leaf_work3.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
print(json.dumps({k:report[k] for k in ("new_function_count","instruction_branches","semantic_cases","compile_returncode","execution_returncode","execution_stdout","execution_stderr")},indent=2))
if run.returncode: raise SystemExit(run.returncode)


