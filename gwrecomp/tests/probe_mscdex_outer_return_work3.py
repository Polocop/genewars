import hashlib, importlib.util, json, pathlib, struct, sys

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'.venv'/'Lib'/'site-packages'))
spec=importlib.util.spec_from_file_location('probe_rm2f',ROOT/'tools'/'probes'/'unicorn_int21.py')
probe=importlib.util.module_from_spec(spec); spec.loader.exec_module(probe)
sys.path.insert(0,str(ROOT/'runtime'))
from dos_filesystem import DosFileSystem

def decode_request_header(data: bytes) -> dict:
    if len(data) < 13:
        return {"error": "DOS request header shorter than 13 bytes", "captured_bytes": len(data)}
    return {"length": data[0], "unit": data[1], "command": data[2],
            "status": int.from_bytes(data[3:5], "little"),
            "reserved_hex": data[5:13].hex(), "command_data_hex": data[13:].hex()}

BASE_FS=probe.DosFileSystem
BASE_HOST=probe.DosHost
instruction_limit=int(sys.argv[1]) if len(sys.argv)>1 else 1000000
evidence_path=pathlib.Path(sys.argv[2]) if len(sys.argv)>2 else ROOT/'evidence'/'dpmi_0300_frame_work2.json'
if not evidence_path.is_absolute(): evidence_path=ROOT/evidence_path
stage=ROOT/'build'/'dos_c_reference_20261006'
profile=ROOT/'build'/'dos_user_profile_w2_036'
config=profile/'GENEWARS'/'config.ini'
if config.exists() and config.stat().st_size:
    raise SystemExit('refusing to replace a nonempty user config fixture')

original_prepare=probe.prepare_guest
probe.prepare_guest=lambda image: original_prepare(image,command_tail=b'-k')
class ProfileHost(BASE_HOST):
    def __init__(self,boot,**kwargs):
        kwargs['dos_memory_profile']='post_dos4gw_le_entry'
        super().__init__(boot,**kwargs)
class ProfileFs(BASE_FS):
    def __init__(self,root,**kwargs):
        super().__init__(root,overlay_root=profile,**kwargs)
        self.seed_empty_file('config.ini')
probe.DosHost=ProfileHost
probe.DosFileSystem=ProfileFs
captured=[]
base_install=probe.install_trace_hooks
def install(uc,trace,limit,host=None):
    def capture_rm(uc,intno,user):
        if intno!=0x31 or (uc.reg_read(probe.UC_X86_REG_EAX)&0xffff)!=0x0300:
            return
        before=probe.regs_snapshot(uc)
        vector=before['ebx']&0xff
        es=uc.reg_read(probe.UC_X86_REG_ES)&0xffff
        edi=before['edi']
        base=None if host is None else host.selectors.get(es)
        address=None if base is None else base+edi
        frame=None
        if address is not None:
            raw=bytes(uc.mem_read(address,0x32))
            frame={'linear':f'0x{address:08x}','selector':f'0x{es:04x}',
                   'offset':f'0x{edi:08x}','raw_hex':raw.hex(),
                   'registers':probe.decode_real_mode_frame(raw)}
        request_header=None
        if vector==0x2f and frame is not None and (frame['registers'].get('eax',0)&0xffff)==0x1510:
            packet_segment=frame['registers'].get('es',0)&0xffff
            packet_offset=frame['registers'].get('ebx',0)&0xffff
            packet_base=host.selectors.get(packet_segment)
            packet_address=(packet_base+packet_offset) if packet_base is not None else ((packet_segment<<4)+packet_offset)
            try:
                packet_bytes=bytes(uc.mem_read(packet_address,32))
                request_header={'segment':f'0x{packet_segment:04x}','offset':f'0x{packet_offset:04x}',
                                'linear':f'0x{packet_address:08x}','selector_base':None if packet_base is None else f'0x{packet_base:08x}','bytes_hex':packet_bytes.hex()}
                request_header['decoded']=decode_request_header(bytes.fromhex(request_header['bytes_hex']))
                transfer_offset=int.from_bytes(packet_bytes[14:16],'little')
                transfer_segment=int.from_bytes(packet_bytes[16:18],'little')
                transfer_count=int.from_bytes(packet_bytes[18:20],'little')
                transfer_linear=(transfer_segment<<4)+transfer_offset
                try:
                    transfer_bytes=bytes(uc.mem_read(transfer_linear,32))
                    request_header['transfer_buffer']={'offset':f'0x{transfer_offset:04x}',
                        'segment':f'0x{transfer_segment:04x}','linear':f'0x{transfer_linear:08x}',
                        'declared_length':transfer_count,'captured_length':len(transfer_bytes),
                        'bytes_hex':transfer_bytes.hex(),
                        'subfunction':transfer_bytes[0] if transfer_bytes else None}
                except Exception as exc:
                    request_header['transfer_buffer']={'error':str(exc),'offset':f'0x{transfer_offset:04x}',
                        'segment':f'0x{transfer_segment:04x}','linear':f'0x{transfer_linear:08x}',
                        'declared_length':transfer_count}
            except Exception as exc: request_header={'error':str(exc)}
        captured.append({'interrupt_eip':f'0x{(before["eip"]-2)&0xffffffff:08x}',
                         'host_registers':before,'real_mode_vector':vector,
                         'frame':frame,'request_header':request_header})
    uc.hook_add(probe.UC_HOOK_INTR,capture_rm)
    count=base_install(uc,trace,limit,host)
    def capture_last(uc,address,size,user):
        try: raw=bytes(uc.mem_read(address,min(size,16))).hex()
        except Exception: raw=''
        trace['last_guest_instruction']={'eip':f'0x{address:08x}','size':size,'bytes':raw}
        if address == 0x001d23a7 and (uc.reg_read(probe.UC_X86_REG_EAX)&0xffff)==0x0300:
            regs=probe.regs_snapshot(uc)
            esp=regs['esp']
            try:
                stack=bytes(uc.mem_read(esp,64))
                ret=int.from_bytes(stack[:4],'little')
                outer=int.from_bytes(stack[24:28],'little')
                ret_code=bytes(uc.mem_read(ret,12)).hex()
                outer_code=bytes(uc.mem_read(outer,24)).hex()
            except Exception as exc:
                stack=b''; ret=None; outer=None; ret_code=''; outer_code=''; trace['return_context_error']=str(exc)
            trace['dpmi_stub_call_context']={'eip':f'0x{address:08x}','instruction_bytes':raw,
                'registers':regs,'esp':f'0x{esp:08x}','stack_bytes_hex':stack.hex(),
                'ret_target':None if ret is None else f'0x{ret:08x}','ret_target_bytes_hex':ret_code,
                'outer_ret_slot_offset':24,'outer_ret_target':None if outer is None else f'0x{outer:08x}',
                'outer_ret_target_bytes_hex':outer_code}
    uc.hook_add(probe.UC_HOOK_CODE,capture_last)
    return count
probe.install_trace_hooks=install
cdrom_drives=tuple(sys.argv[3].split(",")) if len(sys.argv)>3 and sys.argv[3] else ()
cdrom_audio_disc_info=tuple(map(int,sys.argv[4].split(","))) if len(sys.argv)>4 and sys.argv[4] else None
cdrom_audio_track_info=(tuple(tuple(map(int,item.split(","))) for item in sys.argv[5].split(";"))
                        if len(sys.argv)>5 and sys.argv[5] else ())
trace=probe.target_probe(instruction_limit,True,dos_root=stage,timeout_us=0,cdrom_drives=cdrom_drives,
                         cdrom_audio_disc_info=cdrom_audio_disc_info,
                         cdrom_audio_track_info=cdrom_audio_track_info)
runtime_paths=[ROOT/'runtime'/'dos_services.py',ROOT/'runtime'/'dos_filesystem.py',
               ROOT/'tools'/'probes'/'unicorn_int21.py',pathlib.Path(__file__).resolve()]
runtime_files=[{'path':str(path.relative_to(ROOT)).replace('\\','/'),
                'sha256':hashlib.sha256(path.read_bytes()).hexdigest()} for path in runtime_paths]
runtime_sha256=hashlib.sha256(''.join(x['path']+':'+x['sha256']+'\n' for x in runtime_files).encode()).hexdigest()
result={'target_sha256':trace['target_sha256'],'runtime_sha256':runtime_sha256,
        'runtime_files':runtime_files,'stop_reason':trace.get('stop_reason'),
        'executed_instruction_count':trace.get('executed_instruction_count'),
        'first_unsupported':trace.get('first_unsupported'),'real_mode_0300':captured,
        'cdrom_request_events':[i for i in trace.get('interrupts',[])
            if i.get('real_mode_interrupt',{}).get('vector')==0x2f
            and i.get('real_mode_interrupt',{}).get('registers_before',{}).get('eax')=='0x00001510'],
        'interrupts':[i for i in trace.get('interrupts',[]) if i.get('service') == 'dpmi31.simulate_real_mode_interrupt' or not i.get('handled')],
        'interrupt_tail':trace.get('interrupts',[])[-12:],
        'runtime_service_tail':[{'vector':i.get('vector'),'service':i.get('service'),'handled':i.get('handled'),
            'eip':i.get('eip_int_opcode_assumption'),'registers':i.get('registers'),
            'registers_after':i.get('registers_after'),'dos_filename':i.get('dos_filename'),
            'real_mode_interrupt':i.get('real_mode_interrupt'),'guest_writes':i.get('guest_writes')}
            for i in trace.get('interrupts',[])[-100:]],
        'post_query_services':[],
        'linear_allocation_calls':[], 'instruction_limit':instruction_limit,
        'process_exit':trace.get('process_exit'),'guest_exception':trace.get('guest_exception'),
        'unsupported_port':trace.get('unsupported_port'),'unsupported_memory':trace.get('unsupported_memory'),
        'last_fault':trace.get('last_fault'),
        'last_guest_instruction':trace.get('last_guest_instruction'),
        'dpmi_stub_call_context':trace.get('dpmi_stub_call_context'),
        'guest_allocations':trace.get('guest_allocations',[]),
        'guest_allocation_page_count':trace.get('guest_allocation_page_count',0),
        'allocation_backing_checks':trace.get('allocation_backing_checks',[]),
        'dos_memory_state':trace.get('dos_memory_state'),'dos4gw_segment_aliases':trace.get('dos4gw_segment_aliases',[]),
        'last_guest_eip':trace.get('last_guest_eip'),'fixture':{
            'path':str(config),'size':config.stat().st_size,
            'sha256':hashlib.sha256(config.read_bytes()).hexdigest()},
        'read_only_reference_unchanged':not (stage/'GENEWARS'/'config.ini').exists()}
all_interrupts=trace.get('interrupts',[])
query_index=next((i for i,item in enumerate(all_interrupts)
                 if item.get('real_mode_interrupt',{}).get('service')=='int2f.mscdex_install_check'),None)
if query_index is not None:
    result['post_query_services']=[{'service':item.get('service'),'handled':item.get('handled'),
        'eax':item.get('registers',{}).get('eax'),'ebx':item.get('registers',{}).get('ebx'),
        'registers_after':item.get('registers_after'),'eip':item.get('eip_int_opcode_assumption')}
        for item in all_interrupts[query_index+1:query_index+13]]
result['linear_allocation_calls']=[{'service':item.get('service'),'handled':item.get('handled'),
    'registers':item.get('registers'),'registers_after':item.get('registers_after'),
    'eip':item.get('eip_int_opcode_assumption')}
    for item in all_interrupts if item.get('registers',{}).get('eax')=='0x00000501'][:16]
result['first_linear_allocation_failures']=[{'service':item.get('service'),'handled':item.get('handled'),
    'registers':item.get('registers'),'registers_after':item.get('registers_after'),
    'eip':item.get('eip_int_opcode_assumption')}
    for item in all_interrupts if item.get('registers',{}).get('eax')=='0x00000501'
    and item.get('service','').endswith('.unavailable')][:4]
evidence_path.parent.mkdir(parents=True,exist_ok=True)
evidence_path.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'target_sha256':result['target_sha256'],'stop_reason':result['stop_reason'],
    'executed_instruction_count':result['executed_instruction_count'],'instruction_limit':instruction_limit,
    'first_unsupported':result['first_unsupported'],
    'int2f_service':next((i.get('real_mode_interrupt',{}).get('service') for i in result['interrupts']
                          if i.get('real_mode_interrupt',{}).get('vector')==0x2f),None),
    'ax0501_success_count':len(result['guest_allocations']),
    'materialized_allocation_pages':result['guest_allocation_page_count'],
    'first_ax0501_failure':(result['first_linear_allocation_failures'] or [None])[0],
    'last_guest_instruction':result['last_guest_instruction']},indent=2))
