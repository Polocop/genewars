import hashlib, importlib.util, json, pathlib, sys

ROOT=pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'.venv'/'Lib'/'site-packages'))
spec=importlib.util.spec_from_file_location('probe_rm2f',ROOT/'tools'/'probes'/'unicorn_int21.py')
probe=importlib.util.module_from_spec(spec); spec.loader.exec_module(probe)
sys.path.insert(0,str(ROOT/'runtime'))
from dos_filesystem import DosFileSystem
from dos_cdrom import CueImage
from unicorn import UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.x86_const import (UC_X86_REG_CS,UC_X86_REG_DS,UC_X86_REG_ES,UC_X86_REG_SS,
    UC_X86_REG_FS,UC_X86_REG_GS,UC_X86_REG_GDTR,UC_X86_REG_LDTR)

TARGET=ROOT/'evidence'/'genewars-1_1.exe'
CUE=pathlib.Path(r'E:\GeneWarsFX\evidence\original_disc\Genewars (Europe) (En,Fr,De,Es,It,Sv).cue')
STAGE=ROOT/'build'/'dos_c_reference_20261006'
PROFILE=ROOT/'build'/'dos_user_profile_w2_036'
CONFIG=PROFILE/'GENEWARS'/'config.ini'
if not CONFIG.exists() or CONFIG.stat().st_size!=0: raise SystemExit('Expected existing empty config fixture; refusing to mutate it')
if hashlib.sha256(TARGET.read_bytes()).hexdigest()!='2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f': raise SystemExit('target hash mismatch')
cue_before=hashlib.sha256(CUE.read_bytes()).hexdigest()
original_prepare=probe.prepare_guest
probe.prepare_guest=lambda image: original_prepare(image,command_tail=b'-k')
BASE_FS=probe.DosFileSystem; BASE_HOST=probe.DosHost
class ProfileHost(BASE_HOST):
    def __init__(self,boot,**kwargs):
        kwargs['dos_memory_profile']='post_dos4gw_le_entry'; super().__init__(boot,**kwargs)
class ProfileFs(BASE_FS):
    def __init__(self,root,**kwargs):
        super().__init__(root,overlay_root=PROFILE,**kwargs); self.seed_empty_file('config.ini')
probe.DosHost=ProfileHost; probe.DosFileSystem=ProfileFs
TARGET_LINK=0x114CA8
trace_events=[]
base_install=probe.install_trace_hooks

def context(uc,address,size,value,access):
    regs={k:f'0x{v:08x}' for k,v in probe.regs_snapshot(uc).items()}
    segs={name:f'0x{uc.reg_read(reg):04x}' for name,reg in [('cs',UC_X86_REG_CS),('ds',UC_X86_REG_DS),('es',UC_X86_REG_ES),('ss',UC_X86_REG_SS),('fs',UC_X86_REG_FS),('gs',UC_X86_REG_GS)]}
    esp=int(regs['esp'],16)
    try: stack=bytes(uc.mem_read(esp,0x80)).hex()
    except Exception as e: stack=f'ERROR:{e}'
    try: old=bytes(uc.mem_read(address,max(size,4))).hex()
    except Exception as e: old=f'ERROR:{e}'
    try: insn=bytes(uc.mem_read(int(regs['eip'],16),15)).hex()
    except Exception as e: insn=f'ERROR:{e}'
    return {'kind':'write' if access==UC_HOOK_MEM_WRITE else 'read','linear':f'0x{address:08x}','size':size,
        'value':f'0x{value & ((1 << min(size*8,64))-1):x}' if access==UC_HOOK_MEM_WRITE else None,
        'old_bytes':old,'eip':regs['eip'],'instruction_bytes':insn,'registers':regs,'segments':segs,
        'eflags':regs['eflags'],'stack_linear':f'0x{esp:08x}','stack_0x80':stack,
        'gdtr':str(uc.reg_read(UC_X86_REG_GDTR)),'ldtr':str(uc.reg_read(UC_X86_REG_LDTR))}

def install(uc,trace,limit,host=None):
    loaded=TARGET_LINK+0x100000
    initial=bytes(uc.mem_read(loaded,4)).hex()
    trace['this_global']={'map_link_va':'0x00114ca8','rebase':'0x00100000',
        'image_mem_base':f'0x{host.boot.image.mem_base:08x}','runtime_address':f'0x{loaded:08x}','object':host.boot.image.object_containing(loaded).__dict__ if host.boot.image.object_containing(loaded) else None,'initial_bytes_before_guest':initial}
    def watch(uc,access,address,size,value,user):
        if address <= loaded+3 and loaded <= address+size-1:
            item=context(uc,address,size,value,access)
            item['slot_bytes_at_event']=bytes(uc.mem_read(loaded,4)).hex()
            trace_events.append(item)
            if len(trace_events)<=256: trace.setdefault('this_global_events',[]).append(item)
    uc.hook_add(UC_HOOK_MEM_READ,watch)
    uc.hook_add(UC_HOOK_MEM_WRITE,watch)
    count=base_install(uc,trace,limit,host)
    trace['segment_descriptors']={
        'cs':bytes(uc.mem_read(0x8000+((uc.reg_read(UC_X86_REG_CS)&0xfff8)),8)).hex(),
        'ds':bytes(uc.mem_read(0x8000+((uc.reg_read(UC_X86_REG_DS)&0xfff8)),8)).hex(),
        'es':bytes(uc.mem_read(0x8000+((uc.reg_read(UC_X86_REG_ES)&0xfff8)),8)).hex(),
        'ss':bytes(uc.mem_read(0x8000+((uc.reg_read(UC_X86_REG_SS)&0xfff8)),8)).hex()}
    return count
probe.install_trace_hooks=install
original_track_info=[(1,5,60,38,59,0),(2,0,2,0,0,64),(3,26,38,22,0,0),(4,3,45,31,0,0),(5,2,38,41,0,0)]
image=CueImage.from_cue(CUE)
trace=probe.target_probe(10_000_000,True,dos_root=STAGE,timeout_us=0,cdrom_drives=('D',),
    cdrom_images=(image,))
cue_after=hashlib.sha256(CUE.read_bytes()).hexdigest()
result={'task':'W3-048','target_sha256':trace.get('target_sha256'),'cue_path_read_only':str(CUE),
    'cue_sha256_before':cue_before,'cue_sha256_after':cue_after,'cue_unchanged':cue_before==cue_after,
    'fixture':{'path':str(CONFIG),'size':CONFIG.stat().st_size,'sha256':hashlib.sha256(CONFIG.read_bytes()).hexdigest()},
    'runtime_fingerprint':trace.get('runtime_fingerprint'),'command':'original-byte CD-present -k; target_probe instruction_limit=10000000; empty config fixture; CUE mounted read-only','target_probe_runtime_files':[
        {'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()} for p in [
        'runtime/dos_services.py','runtime/dos_filesystem.py','runtime/dos_cdrom.py','tools/probes/unicorn_int21.py']],
    'this_global':trace.get('this_global'),'events_total':len(trace_events),
    'first_events':trace.get('this_global_events',[]),'segment_descriptors':trace.get('segment_descriptors'),'stop_reason':trace.get('stop_reason'),
    'executed_instruction_count':trace.get('executed_instruction_count'),'last_guest_eip':trace.get('last_guest_eip'),
    'first_unsupported':trace.get('first_unsupported'),'process_exit':trace.get('process_exit'),
    'root_hits':trace.get('root_hits'),'original_trace_summary':probe.boot_summary(probe.prepare_guest(TARGET))}
out=ROOT/'evidence'/'setup_game_this_provenance_work3.json'
out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
print(json.dumps({k:result.get(k) for k in ['target_sha256','this_global','events_total','first_events','stop_reason','executed_instruction_count','last_guest_eip','process_exit']},indent=2))











