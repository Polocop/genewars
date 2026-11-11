import hashlib, importlib.util, json, pathlib, sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'.venv'/'Lib'/'site-packages'))
spec=importlib.util.spec_from_file_location('unicorn_profile_probe',ROOT/'tools'/'probes'/'unicorn_int21.py')
probe=importlib.util.module_from_spec(spec); spec.loader.exec_module(probe)
sys.path.insert(0,str(ROOT/'runtime'))
from dos_filesystem import DosFileSystem
BASE_FS=probe.DosFileSystem
stage=ROOT/'build'/'dos_c_reference_20261006'
manifest=json.loads((ROOT/'evidence'/'dos_game_install_manifest.json').read_text(encoding='utf-8'))
expected_gwerr=next(x['sha256'] for x in manifest['file_manifest'] if x['relative_path'].casefold()=='gw.err')
original_prepare=probe.prepare_guest
probe.prepare_guest=lambda image: original_prepare(image,command_tail=b'-k')
label_hits=[]
config_returns=[]
active_config_call=[]
original_install=probe.install_trace_hooks
def install(uc,trace,limit,host=None):
    counter=original_install(uc,trace,limit,host)
    def on_code(uc,address,size,user):
        if address in (0x00114bf0,0x00114e6c,0x00114f38):
            label_hits.append({'guest_eip':f'0x{address:08x}','eax':f'0x{uc.reg_read(probe.UC_X86_REG_EAX):08x}',
                'ecx':f'0x{uc.reg_read(probe.UC_X86_REG_ECX):08x}','edx':f'0x{uc.reg_read(probe.UC_X86_REG_EDX):08x}'})
        if address == 0x00114bf0:
            esp=uc.reg_read(probe.UC_X86_REG_ESP)
            ret=int.from_bytes(bytes(uc.mem_read(esp,4)),'little')
            active_config_call.append({'ret':ret,'esp':esp})
        elif active_config_call and address==active_config_call[-1]['ret'] and uc.reg_read(probe.UC_X86_REG_ESP)==active_config_call[-1]['esp']+4:
            config_returns.append({'guest_eip':f'0x{address:08x}','eax':f'0x{uc.reg_read(probe.UC_X86_REG_EAX):08x}',
                'esp':f'0x{uc.reg_read(probe.UC_X86_REG_ESP):08x}'})
            active_config_call.pop()
    uc.hook_add(probe.UC_HOOK_CODE,on_code)
    return counter
probe.install_trace_hooks=install

def run(profile,seed):
    returns_before=len(config_returns)
    class ProfileFileSystem(BASE_FS):
        def __init__(self,root,**kwargs):
            super().__init__(root,overlay_root=profile,**kwargs)
            if seed: self.seed_empty_file('config.ini')
    probe.DosFileSystem=ProfileFileSystem
    before=len(label_hits)
    trace=probe.target_probe(200000,True,dos_root=stage)
    hits=label_hits[before:]
    returns=config_returns[returns_before:]
    return trace,hits,returns

profile=ROOT/'build'/'dos_user_profile_w2_036'
profile_config=profile/'GENEWARS'/'config.ini'
if profile_config.exists() and profile_config.stat().st_size:
    raise AssertionError('refusing to replace a nonempty per-user config')
seeded,hits,success_returns=run(profile,True)
if not profile_config.exists() or profile_config.read_bytes()!=b'': raise AssertionError('empty config was not seeded in user overlay')
if (stage/'GENEWARS'/'config.ini').exists(): raise AssertionError('config was written into staged reference GAME tree')
config_open=next((i for i in seeded.get('interrupts',[]) if i.get('dos_filename',{}).get('path','').casefold()=='config.ini' and i.get('service')=='dos21.open_file'),None)
read=next((i for i in seeded.get('interrupts',[]) if i.get('service')=='dos21.read_file'),None)
if not config_open or not read or (int(read['registers_after']['eax'],16)&0xffff)!=0 or (int(read['registers_after']['eflags'],16)&1):
    raise AssertionError('original-byte startup did not open config and observe EOF')
if not success_returns or (int(success_returns[0]['eax'],16)&0xff)!=1:
    raise AssertionError(f'GetConfigs did not return AL=1: {success_returns!r}')
no_cfg_profile=ROOT/'build'/'dos_user_profile_w2_036_no_config'
no_config,miss_hits,missing_returns=run(no_cfg_profile,False)
config_attempts=[i for i in no_config.get('interrupts',[]) if i.get('dos_filename',{}).get('path','').casefold()=='config.ini']
if not config_attempts or config_attempts[-1].get('service')!='dos21.open_file.error' or not no_config.get('process_exit') or not missing_returns or (int(missing_returns[0]['eax'],16)&0xff)!=0:
    raise AssertionError('no-config behavior changed')
gwerr_hash=hashlib.sha256((stage/'GENEWARS'/'GW.ERR').read_bytes()).hexdigest()
source_root=pathlib.Path(r'E:\\GeneWarsFX\\work\\disc_extracted\\GAME')
source_gwerr=hashlib.sha256((source_root/'GW.ERR').read_bytes()).hexdigest()
if gwerr_hash!=expected_gwerr or source_gwerr!=expected_gwerr: raise AssertionError('staged reference GW.ERR changed')
summary={
 'target_sha256':seeded.get('target_sha256'),'command_tail':'-k','staged_reference_root':str(stage),
 'user_overlay_root':str(profile),'empty_config_path':str(profile_config),'empty_config_sha256':hashlib.sha256(profile_config.read_bytes()).hexdigest(),
 'reference_config_absent':not (stage/'GENEWARS'/'config.ini').exists(),'config_open':config_open,'eof_read':read,
 'getconfigs_label_hits':hits,'getconfigs_returns':success_returns,'no_config_getconfigs_returns':missing_returns,'empty_profile_stop':{'first_unsupported':seeded.get('first_unsupported'),'process_exit':seeded.get('process_exit'),'instructions':seeded.get('executed_instruction_count'),'dos_memory_state':seeded.get('dos_memory_state')},
 'port_io':seeded.get('port_io',[]),'last_guest_eip':seeded.get('last_guest_eip'),
 'interrupts_tail':seeded.get('interrupts',[])[-8:],
 'no_config_profile_root':str(no_cfg_profile),'no_config_open_attempts':config_attempts,'no_config_exit':no_config.get('process_exit'),
 'gw_err_sha256':{'manifest':expected_gwerr,'staged_after':gwerr_hash,'read_only_source':source_gwerr,'matches':True},'passed':True}
(ROOT/'evidence'/'empty_config_overlay_work2.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
print(json.dumps({k:summary[k] for k in ('config_open','eof_read','getconfigs_label_hits','getconfigs_returns','no_config_getconfigs_returns','empty_profile_stop','no_config_open_attempts','no_config_exit','passed')},indent=2))

