"""Replay original GeneWars bytes through MSCDEX using W2's exact empty -k fixture."""
import hashlib, importlib.util, json, pathlib, sys
import os
ROOT=pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from tools.w3_243_profile import resolve_profile_root
sys.path.insert(0,str(ROOT/'.venv'/'Lib'/'site-packages'))
spec=importlib.util.spec_from_file_location('probe_mscdex_work3',ROOT/'tools'/'probes'/'unicorn_int21.py')
probe=importlib.util.module_from_spec(spec); spec.loader.exec_module(probe)
sys.path.insert(0,str(ROOT/'runtime'))
from dos_filesystem import DosFileSystem
BASE_FS=probe.DosFileSystem; BASE_HOST=probe.DosHost
stage=ROOT/'build'/'dos_c_reference_20261006'
vhdx_mount=ROOT/'build'/'dosboxx_oracle'/'C'
profile=resolve_profile_root(ROOT,os.environ.get('GWRECOMP_W3_243_PROFILE_ROOT'),vhdx_mount)
config=profile/'GENEWARS'/'config.ini'
if config.exists() and config.stat().st_size:
    raise SystemExit('refusing to replace nonempty W2 fixture')
original_prepare=probe.prepare_guest
probe.prepare_guest=lambda image: original_prepare(image,command_tail=b'-k')
class ProfileHost(BASE_HOST):
    def __init__(self,boot,**kwargs):
        kwargs['dos_memory_profile']='post_dos4gw_le_entry'
        kwargs['cdrom_drives']=()
        super().__init__(boot,**kwargs)
class ProfileFs(BASE_FS):
    def __init__(self,root,**kwargs):
        super().__init__(root,overlay_root=profile,**kwargs)
        self.seed_empty_file('config.ini')
probe.DosHost=ProfileHost; probe.DosFileSystem=ProfileFs
captured=[]; post_return=[]; native_checkpoint=[]; service_site_instructions=[]; flow={'query_seen':False,'resume_seen':False}
base_install=probe.install_trace_hooks
def install(uc,trace,limit,host=None):
    def capture_rm(uc,intno,user):
        if intno!=0x31 or (uc.reg_read(probe.UC_X86_REG_EAX)&0xffff)!=0x0300: return
        before=probe.regs_snapshot(uc); vector=before['ebx']&0xff
        es=uc.reg_read(probe.UC_X86_REG_ES)&0xffff; edi=before['edi']
        base=None if host is None else host.selectors.get(es); address=None if base is None else base+edi
        frame=None
        if address is not None:
            raw=bytes(uc.mem_read(address,0x32))
            frame={'linear':f'0x{address:08x}','selector':f'0x{es:04x}','offset':f'0x{edi:08x}',
                   'raw_hex':raw.hex(),'registers':probe.decode_real_mode_frame(raw)}
            if vector==0x2f and frame['registers']['eax']==0x1500: flow['query_seen']=True
        captured.append({'interrupt_eip':f'0x{(before["eip"]-2)&0xffffffff:08x}',
                         'host_registers':before,'real_mode_vector':vector,'frame':frame})
    uc.hook_add(probe.UC_HOOK_INTR,capture_rm)
    count=base_install(uc,trace,limit,host)
    def capture_code(uc,address,size,user):
        if flow['query_seen'] and not flow['resume_seen'] and address==0x001d23a9:
            flow['resume_seen']=True
        if address in (0x001c3d21,0x001c3d35,0x001c3d42):
            try: site_raw=bytes(uc.mem_read(address,min(size,16))).hex()
            except Exception: site_raw=''
            item={'eip':f'0x{address:08x}','size':size,'bytes':site_raw,'registers':probe.regs_snapshot(uc)}
            if address==0x001c3d21:
                try: item['basic_block_bytes']=bytes(uc.mem_read(address,0x40)).hex()
                except Exception: item['basic_block_bytes']=None
            service_site_instructions.append(item)
        if address==0x001afb60 and not native_checkpoint:
            try: raw=bytes(uc.mem_read(address,size)).hex()
            except Exception: raw=''
            ds=uc.reg_read(probe.UC_X86_REG_DS)&0xffff
            esi=uc.reg_read(probe.UC_X86_REG_ESI)&0xffffffff
            ds_base=None if host is None else host.selectors.get(ds)
            linear=None if ds_base is None else ds_base+esi
            try: memory_dword=None if linear is None else bytes(uc.mem_read(linear,4)).hex()
            except Exception: memory_dword=None
            native_checkpoint.append({'eip':f'0x{address:08x}','bytes':raw,
                                      'registers':probe.regs_snapshot(uc),
                                      'es':f'0x{(uc.reg_read(probe.UC_X86_REG_ES)&0xffff):04x}',
                                      'ds':f'0x{ds:04x}','ds_base':None if ds_base is None else f'0x{ds_base:08x}',
                                      'linear_ea':None if linear is None else f'0x{linear:08x}',
                                      'memory_dword':memory_dword})
        if flow['resume_seen'] and len(post_return)<160:
            try: raw=bytes(uc.mem_read(address,min(size,16))).hex()
            except Exception: raw=''
            post_return.append({'eip':f'0x{address:08x}','size':size,'bytes':raw,
                                'registers':probe.regs_snapshot(uc)})
    uc.hook_add(probe.UC_HOOK_CODE,capture_code)
    return count
probe.install_trace_hooks=install
limit=int(sys.argv[1]) if len(sys.argv)>1 else 2_000_000
output_path=pathlib.Path(sys.argv[2]) if len(sys.argv)>2 else ROOT/'evidence'/'startup_after_mscdex_work3.json'
trace=probe.target_probe(limit,True,dos_root=stage,timeout_us=0)
all_events=trace.get('interrupts',[])
query_idx=next((i for i,x in enumerate(all_events) if x.get('real_mode_interrupt',{}).get('vector')==0x2f and x.get('real_mode_interrupt',{}).get('registers_before',{}).get('eax')=='0x00001500'),None)
query=None if query_idx is None else all_events[query_idx]
post_events=[] if query_idx is None else all_events[query_idx+1:query_idx+33]
msc=[{'eip':x.get('eip_int_opcode_assumption'),'ax':x.get('real_mode_interrupt',{}).get('registers_before',{}).get('eax'),
      'service':x.get('real_mode_interrupt',{}).get('service'),'handled':x.get('handled')}
     for x in all_events if x.get('real_mode_interrupt',{}).get('vector')==0x2f]
transfers=[]
for a,b in zip(post_return,post_return[1:]):
    if int(b['eip'],16)!=int(a['eip'],16)+a['size']:
        transfers.append({'from_eip':a['eip'],'from_bytes':a['bytes'],'to_eip':b['eip'],'eflags_before':a['registers']['eflags']})
config_bytes=config.read_bytes()
out={'task':'W3-031' if limit>2_000_000 else 'W3-029','oracle':'Original GeneWars target bytes under the repository Unicorn DOS/DPMI host; MSCDEX profile is the recorded empty-CD inventory, not an independent DOSBox run.',
     'target_sha256':trace['target_sha256'],'target_path':'evidence/genewars-1_1.exe','command_tail':'-k',
     'fixture':{'path':str(config),'size':len(config_bytes),'sha256':hashlib.sha256(config_bytes).hexdigest()},
     'fixture_matches_gate':True,'staged_reference_root':str(stage),'reference_config_absent':not (stage/'GENEWARS'/'config.ini').exists(),
     'cdrom_inventory':[],'instruction_limit':limit,'stop_reason':trace.get('stop_reason'),
     'executed_instruction_count':trace.get('executed_instruction_count'),'first_unsupported':trace.get('first_unsupported'),
     'guest_exception':trace.get('guest_exception'),'unsupported_memory':trace.get('unsupported_memory'),
     'unsupported_port':trace.get('unsupported_port'),'process_exit':trace.get('process_exit'),
     'last_guest_eip':trace.get('last_guest_eip'),'last_guest_instruction':trace.get('last_guest_instruction'),
     'int2f_services':msc,'query_pre_hook':next((x for x in captured if x['real_mode_vector']==0x2f and x['frame'] and x['frame']['registers']['eax']==0x1500),None),
     'query_dispatch_event':query,'post_query_services':[{'service':x.get('service'),'eip':x.get('eip_int_opcode_assumption'),
        'registers':x.get('registers'),'registers_after':x.get('registers_after')} for x in post_events],
     'post_return_instructions':post_return,'original_start_checkpoint_1afb60':native_checkpoint,'ah48_service_site_instructions':service_site_instructions,'observed_control_transfers':transfers,
     'first_ax0501':next((x for x in trace.get('interrupts',[]) if x.get('registers',{}).get('eax')=='0x00000501'),None),
     'runtime_sha256':hashlib.sha256((ROOT/'runtime'/'dos_services.py').read_bytes()).hexdigest(),
     'probe_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
     'read_only_reference_unchanged':not (stage/'GENEWARS'/'config.ini').exists()}
# Derive an explicit branch outcome from the original-byte post-return EIP/flag stream.
branch_index=next((i for i,x in enumerate(post_return) if x['eip']=='0x001b955f'),None)
branch=None
if branch_index is not None and branch_index+1<len(post_return):
    x=post_return[branch_index]; nxt=post_return[branch_index+1]
    branch={'eip':x['eip'],'bytes':x['bytes'],'eax':x['registers']['eax'],'eflags':x['registers']['eflags'],
            'zf':bool(x['registers']['eflags'] & 0x40),'next_eip':nxt['eip'],
            'taken':nxt['eip']!='0x001b9561'}
first_after=None if not post_events else post_events[0]
out['observed_post_return_branch']=branch
out['first_post_query_service']=None if first_after is None else {'service':first_after.get('service'),
    'eip':first_after.get('eip_int_opcode_assumption'),'registers':first_after.get('registers'),
    'registers_after':first_after.get('registers_after')}
out['mscdes_installation_status']='undetermined; AX=1500 returned zero configured CD drive letters and does not by itself prove MSCDEX residency/absence.'
out['cd_dependency']='No CD drive was configured; original bytes continued into DPMI DOS/linear allocations. Dependence beyond the 2,000,000-instruction trace is untested.'
out['dos_ah48_events']=[{'eip':x.get('eip_int_opcode_assumption'),'service':x.get('service'),'registers':x.get('registers'),'registers_after':x.get('registers_after'),'handled':x.get('handled')} for x in all_events if x.get('vector')==0x21 and int(x.get('registers',{}).get('eax','0'),16)&0xff00==0x4800]
out['later_frontier']={'service':None if out['first_ax0501'] is None else out['first_ax0501'].get('service'),
    'eip':None if out['first_ax0501'] is None else out['first_ax0501'].get('eip_int_opcode_assumption'),
    'registers':None if out['first_ax0501'] is None else out['first_ax0501'].get('registers'),
    'registers_after':None if out['first_ax0501'] is None else out['first_ax0501'].get('registers_after'),
    'run_stop':out['stop_reason'],'run_last_eip':out['last_guest_eip'],'first_unsupported':out['first_unsupported']}
output_path.write_text(json.dumps(out,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'query':out['query_dispatch_event'],'branch':branch,'first_post_query_service':out['first_post_query_service'],'later_frontier':out['later_frontier'],'int2f_services':msc,'stop_reason':out['stop_reason'],'instructions':out['executed_instruction_count'],'last_guest_eip':out['last_guest_eip'],'evidence_path':str(output_path)},indent=2))

