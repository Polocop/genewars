"""Continue every case in the WORK3 CFG differential corpus and record divergences."""
import collections,json,os,pathlib,re,subprocess
ROOT=pathlib.Path(__file__).resolve().parents[1]; test=ROOT/"tests"/"test_recomp_cfg_leaf_work3.c"
s=test.read_text(encoding="utf-8")
if "unsigned divergences=0,cases=0;" not in s:
 s=s.replace("int main(void){", "int main(void){\n  unsigned divergences=0,cases=0;")
 s=s.replace("for(unsigned sample=0;sample<30;++sample){ unsigned i=sample<23?sample:sample+2; for(unsigned pattern=0;pattern<4;++pattern){", "for(unsigned sample=0;sample<30;++sample){ unsigned i=sample<23?sample:sample+2; for(unsigned pattern=0;pattern<4;++pattern){ cases++;")
 s=s.replace('printf("EAX FAIL fn=%u pattern=%u lifted=%08X raw=%08X\\n",i,pattern,g_eax,raw_guest_eax);return 2;', 'printf("EAX FAIL fn=%u pattern=%u lifted=%08X raw=%08X\\n",i,pattern,g_eax,raw_guest_eax);++divergences;')
 s=s.replace('printf("EFLAGS FAIL fn=%u pattern=%u lifted=%08X raw=%08X\\n",i,pattern,lifted_flags,raw_flags);return 3;', 'printf("EFLAGS FAIL fn=%u pattern=%u lifted=%08X raw=%08X\\n",i,pattern,lifted_flags,raw_flags);++divergences;')
 s=s.replace('printf("MEM FAIL fn=%u pattern=%u\\n",i,pattern);return 4;', 'printf("MEM FAIL fn=%u pattern=%u\\n",i,pattern);++divergences;')
 s=s.replace('printf("X87 TOP FAIL fn=%u lifted=%d rawsw=%04X\\n",i,g_fp_top,(unsigned)raw_fsw);return 6;', 'printf("X87 TOP FAIL fn=%u pattern=%u lifted=%d rawsw=%04X\\n",i,pattern,g_fp_top,(unsigned)raw_fsw);++divergences;')
 s=s.replace('printf("PASS 30 new non-overlapping MAP functions x 4 patterns; EAX/EFLAGS/memory and x87 TOP match\\n"); return 0;', 'printf("COMPLETED %u cases; divergences=%u\\n",cases,divergences); return 0;')
 # Supply a valid saved x87 image to the original FRSTOR case; random bytes can fault.
 setup='uint8_t *fncode=execmem; uint32_t raw_eax=0,raw_flags=0,raw_fsw=0;'
 s=s.replace(setup, setup+' if(i==20){ __asm__ volatile("fninit\\n\\tfldl %0\\n\\tfnsave %1\\n\\tfninit"::"m"(fpu_seed),"m"(*(uint8_t (*)[108])original):"memory"); memcpy(guest_mem,original,0x1B1000); }')
 s=s.replace('cases++; printf("BEGIN fn=%u pattern=%u\\n",i,pattern); fflush(stdout);', 'cases++;')
 test.write_text(s,encoding="utf-8")
# Keep this as a meaningful test: all cases must run and be categorized; semantic mismatches are recorded for Core.
env=dict(os.environ); env["PATH"]=r"E:\\msys64\\mingw32\\bin;E:\\msys64\\usr\\bin;"+env.get("PATH",""); (ROOT/"cache").mkdir(exist_ok=True); env["TEMP"]=env["TMP"]=env["TMPDIR"]=str(ROOT/"cache")
compiler=r"E:\\msys64\\mingw32\\bin\\gcc.exe"; exe=ROOT/"build"/"test_recomp_cfg_leaf_work3.exe"; hdr=ROOT/"third_party"/"pcrecomp"/"runtime"/"recomp32"
cp=subprocess.run([compiler,"-std=gnu11","-m32","-O0","-w","-I",str(hdr),"-I",str(ROOT/"build"),"-o",str(exe),str(test)],capture_output=True,text=True,cwd=ROOT,env=env)
if cp.returncode: raise SystemExit("compile failed:\\n"+cp.stdout[-5000:]+cp.stderr[-5000:])
run=subprocess.run([str(exe)],capture_output=True,text=True,cwd=ROOT)
if run.returncode: raise SystemExit(f"harness crashed/exited {run.returncode}:\\n{run.stdout}\\n{run.stderr}")
match=re.search(r"COMPLETED (\d+) cases; divergences=(\d+)",run.stdout)
if not match or int(match.group(1))!=120: raise SystemExit("incomplete differential run:\\n"+run.stdout+run.stderr)
lines=run.stdout.splitlines(); dpat=re.compile(r"(EAX|EFLAGS|MEM|X87 TOP) FAIL fn=(\d+) pattern=(\d+)(.*)"); divergences=[]
for line in lines:
 m=dpat.search(line)
 if m: divergences.append({"kind":m.group(1),"function_index":int(m.group(2)),"pattern":int(m.group(3)),"detail":m.group(4).strip(),"line":line})
report_path=ROOT/"evidence"/"differential_cfg_leaf_work3.json"; report=json.loads(report_path.read_text(encoding="utf-8")); by_fn=collections.defaultdict(list)
for d in divergences: by_fn[d["function_index"]].append(d)
for f in report["selected_functions"]:
 i=f["index"]; ds=by_fn[i]; f["result"]="FAIL" if ds else "PASS"; f["patterns_total"]=4; f["patterns_failed"]=len({x["pattern"] for x in ds}); f["patterns_passed"]=4-f["patterns_failed"]; f["divergences"]=ds; f["first_divergence"]=ds[0] if ds else None
report.update({"selected_new_function_count":30,"semantic_cases":120,"cases_completed":int(match.group(1)),"divergence_count":len(divergences),"function_pass_count":sum(f["result"]=="PASS" for f in report["selected_functions"]),"function_fail_count":sum(f["result"]=="FAIL" for f in report["selected_functions"]),"compile_returncode":cp.returncode,"execution_returncode":run.returncode,"execution_stdout":run.stdout.strip(),"execution_stderr":run.stderr[-1000:],"test_runner":"tools/test_differential_cfg_work3.py"})
report_path.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
md=["# W3-007 differential results: 30 new CFG functions","",f"Functions: {report['selected_new_function_count']} new; cases: {report['cases_completed']} (4 per function).","",f"Function results: {report['function_pass_count']} PASS, {report['function_fail_count']} FAIL; first-divergence events: {len(divergences)}.","","| Address | MAIN.MAP | Result | Failing patterns | First divergence |","|---|---|---:|---:|---|"]
for f in report["selected_functions"]:
 first=f["first_divergence"]; detail=(first["line"] if first else "—"); md.append(f"| `{f['address']}` | `{f['name']}` | {f['result']} | {f['patterns_failed']} | {detail} |")
md += ["","## Reproducibility", "", "`python tools/test_differential_cfg_work3.py` compiles the isolated lifted corpus and executes original bytes from a relocated executable buffer. It compares EAX, defined EFLAGS bits, all guest memory after known pointer normalization, and x87 TOP for the two selected x87 stores. The 120-case run always completes and records failures instead of stopping at the first mismatch.","","## Core follow-up","", "Any FAIL is reproducible from the selected function, pattern index, target hash, and saved bytes in `evidence/differential_cfg_leaf_work3.json`. Create a Core task for each remaining divergence cluster.",""]
(ROOT/"reports"/"coordination"/"differential_cfg_leaf_work3.md").write_text("\n".join(md),encoding="utf-8")
print(json.dumps({"functions":report["selected_new_function_count"],"cases":report["cases_completed"],"pass_functions":report["function_pass_count"],"fail_functions":report["function_fail_count"],"divergences":divergences,"stdout":run.stdout.strip()},indent=2))
