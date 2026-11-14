"""Non-mutating original-byte call-chain capture for setup_game."""
import os as _gw_os
from pathlib import Path as _GwPath
_GW_ROOT=str(_GwPath(__file__).resolve().parents[2])
_GW_FX=_gw_os.environ.get("GENEWARSFX_ROOT",_gw_os.path.join(_GW_ROOT,"third_party","GeneWarsFX"))
import hashlib,importlib.util,json,pathlib,sys
ROOT=pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'.venv'/'Lib'/'site-packages'))
spec=importlib.util.spec_from_file_location('probe_callchain',ROOT/'tools'/'probes'/'unicorn_int21.py');probe=importlib.util.module_from_spec(spec);spec.loader.exec_module(probe)
sys.path.insert(0,str(ROOT/'runtime'))
from dos_filesystem import DosFileSystem
from dos_cdrom import CueImage
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_CS,UC_X86_REG_DS,UC_X86_REG_ES,UC_X86_REG_SS,UC_X86_REG_FS,UC_X86_REG_GS,UC_X86_REG_GDTR,UC_X86_REG_LDTR
TARGET=ROOT/'evidence/genewars-1_1.exe'; CUE=pathlib.Path((_GW_FX + '\\evidence\\original_disc\\Genewars (Europe) (En,Fr,De,Es,It,Sv).cue'))
STAGE=ROOT/'build/dos_c_reference_20261006'; PROFILE=ROOT/'build/dos_user_profile_w2_036'; CONFIG=PROFILE/'GENEWARS/config.ini'
if not CONFIG.exists() or CONFIG.stat().st_size!=0:raise SystemExit('Expected existing empty config; refusing to mutate it')
sha=hashlib.sha256(TARGET.read_bytes()).hexdigest()
if sha!='2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f':raise SystemExit('target hash mismatch')
cue_before=hashlib.sha256(CUE.read_bytes()).hexdigest(); original_prepare=probe.prepare_guest
probe.prepare_guest=lambda image:original_prepare(image,command_tail=b'-k')
BASE_FS=probe.DosFileSystem; BASE_HOST=probe.DosHost
class ProfileHost(BASE_HOST):
 def __init__(self,boot,**kwargs):kwargs['dos_memory_profile']='post_dos4gw_le_entry';super().__init__(boot,**kwargs)
class ProfileFs(BASE_FS):
 def __init__(self,root,**kwargs):super().__init__(root,overlay_root=PROFILE,**kwargs);self.seed_empty_file('config.ini')
probe.DosHost=ProfileHost;probe.DosFileSystem=ProfileFs
base_install=probe.install_trace_hooks; watch_points={0x19433D:'main_to_setup_game_callsite',0x194AC0:'setup_game_entry',0x194B51:'this_global_read'}; seen=[]
def snap(uc,addr,size,label):
 regs={k:f'0x{v:08x}' for k,v in probe.regs_snapshot(uc).items()}; esp=int(regs['esp'],16);ebp=int(regs['ebp'],16)
 segregs=[('cs',UC_X86_REG_CS),('ds',UC_X86_REG_DS),('es',UC_X86_REG_ES),('ss',UC_X86_REG_SS),('fs',UC_X86_REG_FS),('gs',UC_X86_REG_GS)]
 segs={n:f'0x{uc.reg_read(r):04x}' for n,r in segregs}
 try: stack=bytes(uc.mem_read(esp,0x80)).hex()
 except Exception as e:stack='ERROR:'+str(e)
 try: words=[f'0x{int.from_bytes(uc.mem_read(esp+i*4,4),"little"):08x}' for i in range(12)]
 except Exception as e:words=['ERROR:'+str(e)]
 try: prev=int.from_bytes(uc.mem_read(ebp,4),'little');ret=int.from_bytes(uc.mem_read(ebp+4,4),'little');chain={'ebp_prev':f'0x{prev:08x}','ebp_return':f'0x{ret:08x}'}
 except Exception as e:chain={'error':str(e)}
 try: ins=bytes(uc.mem_read(addr,15)).hex()
 except Exception as e:ins='ERROR:'+str(e)
 descriptors={}
 for n in ('cs','ds','es','ss'):
  sel=int(segs[n],16); off=0x8000+(sel&0xfff8)
  try:descriptors[n]=bytes(uc.mem_read(off,8)).hex()
  except Exception as e:descriptors[n]='ERROR:'+str(e)
 return {'label':label,'runtime_eip':f'0x{addr:08x}','instruction_bytes':ins,'instruction_size':size,'registers':regs,'segments':segs,'eflags':regs.get('eflags'),'gdtr':str(uc.reg_read(UC_X86_REG_GDTR)),'ldtr':str(uc.reg_read(UC_X86_REG_LDTR)),'segment_descriptors':descriptors,'stack_linear':f'0x{esp:08x}','stack_bytes_0x80':stack,'stack_dwords':words,'ebp_chain':chain}
def install(uc,trace,limit,host=None):
 global seen
 this_addr=0x214CA8
 trace['this_global_initial_bytes']=bytes(uc.mem_read(this_addr,4)).hex()
 count=base_install(uc,trace,limit,host)
 def hook(uc,address,size,user):
  if address in watch_points and not any(x['runtime_eip']==f'0x{address:08x}' for x in seen):seen.append(snap(uc,address,size,watch_points[address]))
 uc.hook_add(UC_HOOK_CODE,hook)
 trace['callchain_hook_points']=[f'0x{x:08X}' for x in watch_points]
 return count
probe.install_trace_hooks=install
track=[(1,5,60,38,59,0),(2,0,2,0,0,64),(3,26,38,22,0,0),(4,3,45,31,0,0),(5,2,38,41,0,0)]
image=CueImage.from_cue(CUE)
trace=probe.target_probe(10_000_000,True,dos_root=STAGE,timeout_us=0,cdrom_drives=('D',),cdrom_images=(image,))
cue_after=hashlib.sha256(CUE.read_bytes()).hexdigest()
result={'task':'W3-054','target_sha256':sha,'cue_path':str(CUE),'cue_sha256_before':cue_before,'cue_sha256_after':cue_after,'cue_unchanged':cue_before==cue_after,'config_sha256':hashlib.sha256(CONFIG.read_bytes()).hexdigest(),'command':'original-byte CD-present -k; target_probe instruction_limit=10000000; no guest-state mutation','runtime_fingerprint':trace.get('runtime_fingerprint'),'runtime_files':[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in ['runtime/dos_services.py','runtime/dos_filesystem.py','runtime/dos_cdrom.py','tools/probes/unicorn_int21.py','tools/probes/trace_setup_game_callchain_work3.py']],'captures':seen,'events_total':len(seen),'stop_reason':trace.get('stop_reason'),'last_guest_eip':trace.get('last_guest_eip'),'executed_instruction_count':trace.get('executed_instruction_count'),'first_unsupported':trace.get('first_unsupported'),'menu_reached':False}
(ROOT/'evidence/dynamic_setup_game_callchain_work3.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'captures':seen,'stop_reason':result['stop_reason'],'last_guest_eip':result['last_guest_eip'],'instructions':result['executed_instruction_count']},indent=2))
