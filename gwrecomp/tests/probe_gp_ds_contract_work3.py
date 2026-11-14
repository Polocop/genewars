"""Replay original GeneWars bytes through MSCDEX using W2's exact empty -k fixture."""
import hashlib, importlib.util, json, pathlib, sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'.venv'/'Lib'/'site-packages'))
spec=importlib.util.spec_from_file_location('probe_mscdex_work3',ROOT/'tools'/'probes'/'unicorn_int21.py')
probe=importlib.util.module_from_spec(spec); spec.loader.exec_module(probe)
sys.path.insert(0,str(ROOT/'runtime'))
from dos_filesystem import DosFileSystem
BASE_FS=probe.DosFileSystem; BASE_HOST=probe.DosHost
stage=ROOT/'build'/'dos_c_reference_20261006'
profile=ROOT/'build'/'dos_user_profile_w2_036'
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
    if len(sys.argv)>3 and sys.argv[3]=='--replay-measured-pre-fix-ah48':
        forced={'used':False}
        def replay_measured_ah48(uc,intno,user):
            if intno==0x21 and not forced['used'] and uc.reg_read(probe.UC_X86_REG_EIP)==0x001c3d23:
                eax=uc.reg_read(probe.UC_X86_REG_EAX); flags=uc.reg_read(probe.UC_X86_REG_EFLAGS)
                if (eax&0xffff)==0x004c and not (flags&1):
                    forced['used']=True; uc.reg_write(probe.UC_X86_REG_EAX,(eax&0xffff0000)|0x9fca)
                    trace.setdefault('measured_harness_overrides',[]).append({'service':'DOS AH=48h','input_eax':f'0x{eax:08x}','measured_return_ax':'0x9fca','measured_from':'evidence/startup_ah48_sites_work3.json','carry_preserved':False,'purpose':'replay historical pre-W2-053 return to capture actual MOV ES selector fault; not current oracle behavior'})
        uc.hook_add(probe.UC_HOOK_INTR,replay_measured_ah48)
    def capture_code(uc,address,size,user):
        if flow['query_seen'] and not flow['resume_seen'] and address==0x001d23a9:
            flow['resume_seen']=True
        if address in (0x001c3d21,0x001c3d35,0x001c3d42):
            try: site_raw=bytes(uc.mem_read(address,min(size,16))).hex()
            except Exception: site_raw=''
            item={'eip':f'0x{address:08x}','size':size,'bytes':site_raw,'registers':probe.regs_snapshot(uc),'segments':{n:f'0x{uc.reg_read(r)&0xffff:04x}' for n,r in [('cs',probe.UC_X86_REG_CS),('ds',probe.UC_X86_REG_DS),('es',probe.UC_X86_REG_ES),('ss',probe.UC_X86_REG_SS),('fs',probe.UC_X86_REG_FS),('gs',probe.UC_X86_REG_GS)]}}
            if address==0x001c3d42:
                gdtr=uc.reg_read(probe.UC_X86_REG_GDTR); ldtr=uc.reg_read(probe.UC_X86_REG_LDTR)
                sel=uc.reg_read(probe.UC_X86_REG_EAX)&0xffff; ti=bool(sel&4); base=ldtr[1] if ti else gdtr[1]; limit=ldtr[2] if ti else gdtr[2]; off=sel&0xfff8; desc=None
                if off+7<=limit:
                    rawd=bytes(uc.mem_read(base+off,8)); q=int.from_bytes(rawd,"little"); lim=(q&0xffff)|(((q>>48)&0xf)<<16); db=((q>>16)&0xffff)|(((q>>32)&0xff)<<16)|(((q>>56)&0xff)<<24)
                    if (q>>55)&1: lim=(lim<<12)|0xfff
                    desc={"linear":f"0x{base+off:08x}","raw_hex":rawd.hex(),"base":f"0x{db:08x}","limit":f"0x{lim:08x}","present":bool((q>>47)&1),"type":(q>>40)&15,"dpl":(q>>45)&3}
                item["descriptor_fault_analysis"]={"gdtr":{"base":f"0x{gdtr[1]:08x}","limit":gdtr[2]},"ldtr":{"selector":ldtr[0],"base":f"0x{ldtr[1]:08x}","limit":ldtr[2]},"attempted_selector":f"0x{sel:04x}","table":"LDT" if ti else "GDT","descriptor_offset":f"0x{off:08x}","descriptor_within_limit":off+7<=limit,"descriptor":desc,"host_selector_base":None if host is None else host.selectors.get(sel),"host_selector_limit":None if host is None else host.selector_limits.get(sel)}
                segment_descriptors={}
                for sn,sr in [("cs",probe.UC_X86_REG_CS),("ds",probe.UC_X86_REG_DS),("es",probe.UC_X86_REG_ES),("ss",probe.UC_X86_REG_SS),("fs",probe.UC_X86_REG_FS),("gs",probe.UC_X86_REG_GS)]:
                    sv=uc.reg_read(sr)&0xffff; st=ldtr if sv&4 else gdtr; sb=st[1]; sl=st[2]; so=sv&0xfff8
                    if (sv&0xfff8)==0: segment_descriptors[sn]={"selector":f"0x{sv:04x}","null":True}; continue
                    if so+7>sl: segment_descriptors[sn]={"selector":f"0x{sv:04x}","table_limit":sl,"descriptor_offset":so,"valid_index":False}; continue
                    rd=bytes(uc.mem_read(sb+so,8)); dq=int.from_bytes(rd,"little"); dlm=(dq&0xffff)|(((dq>>48)&15)<<16); dbs=((dq>>16)&0xffff)|(((dq>>32)&255)<<16)|(((dq>>56)&255)<<24)
                    if (dq>>55)&1: dlm=(dlm<<12)|0xfff
                    segment_descriptors[sn]={"selector":f"0x{sv:04x}","table":"LDT" if sv&4 else "GDT","raw_hex":rd.hex(),"base":f"0x{dbs:08x}","limit":f"0x{dlm:08x}","present":bool((dq>>47)&1),"type":(dq>>40)&15,"dpl":(dq>>45)&3,"valid_index":True}
                item["segment_descriptors"]=segment_descriptors
                sp=uc.reg_read(probe.UC_X86_REG_ESP)&0xffffffff; item["stack_context"]={"linear":f"0x{sp:08x}","bytes_hex":bytes(uc.mem_read(sp,64)).hex()}
            if address==0x001afb60:
                ds=uc.reg_read(probe.UC_X86_REG_DS)&0xffff; esi=uc.reg_read(probe.UC_X86_REG_ESI)&0xffffffff; db=None if host is None else host.selectors.get(ds); dl=None if host is None else host.selector_limits.get(ds); ea=None if db is None else db+esi; val=None if ea is None else bytes(uc.mem_read(ea,4)).hex()
                item["ds_access"]={"selector":f"0x{ds:04x}","base":None if db is None else f"0x{db:08x}","limit":None if dl is None else f"0x{dl:08x}","esi":f"0x{esi:08x}","linear_ea":None if ea is None else f"0x{ea:08x}","dword":val}
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
            gdtr_ds=uc.reg_read(probe.UC_X86_REG_GDTR); ldtr_ds=uc.reg_read(probe.UC_X86_REG_LDTR); ti_ds=bool(ds&4); tb_ds=ldtr_ds[1] if ti_ds else gdtr_ds[1]; tl_ds=ldtr_ds[2] if ti_ds else gdtr_ds[2]; off_ds=ds&0xfff8; ds_descriptor=None
            if off_ds+7<=tl_ds:
                rds=bytes(uc.mem_read(tb_ds+off_ds,8)); qds=int.from_bytes(rds,"little"); limds=(qds&0xffff)|(((qds>>48)&15)<<16); baseds=((qds>>16)&0xffff)|(((qds>>32)&255)<<16)|(((qds>>56)&255)<<24)
                if (qds>>55)&1: limds=(limds<<12)|0xfff
                ds_descriptor={"table":"LDT" if ti_ds else "GDT","linear":f"0x{tb_ds+off_ds:08x}","raw_hex":rds.hex(),"base":f"0x{baseds:08x}","limit":f"0x{limds:08x}","present":bool((qds>>47)&1),"type":(qds>>40)&15,"dpl":(qds>>45)&3}
            native_checkpoint.append({'eip':f'0x{address:08x}','bytes':raw,
                                      'registers':probe.regs_snapshot(uc),
                                      'es':f'0x{(uc.reg_read(probe.UC_X86_REG_ES)&0xffff):04x}',
                                      'ds':f'0x{ds:04x}','ds_base':None if ds_base is None else f'0x{ds_base:08x}',
                                      'ds_limit':None if ds_descriptor is None else ds_descriptor['limit'],'ds_descriptor':ds_descriptor,
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
output_path=pathlib.Path(sys.argv[2]) if len(sys.argv)>2 else ROOT/'evidence'/'gp_ds_contract_work3.json'
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
out={'task':'W3-045','replay_mode':'current_runtime_original_bytes','oracle':'Original GeneWars target bytes under the repository Unicorn DOS/DPMI host; empty-CD -k fixture; not an independent DOSBox run.',
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
     'runtime_sha256':hashlib.sha256((ROOT/'runtime'/'dos_services.py').read_bytes()).hexdigest(),'measured_harness_overrides':trace.get('measured_harness_overrides',[]),
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







