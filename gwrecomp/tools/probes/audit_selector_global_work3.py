import importlib.util,json,pathlib,sys
root=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('uw',root/'tools/probes/unicorn_int21.py')
uw=importlib.util.module_from_spec(spec); spec.loader.exec_module(uw)
original=uw.install_trace_hooks
watch=0x20b795
def traced(uc,trace,limit,host=None):
    count=original(uc,trace,limit,host)
    def write(uc,access,address,size,value,user):
        if address <= watch+1 and address+size > watch:
            trace.setdefault('selector_global_writes',[]).append({'eip':f"0x{uc.reg_read(uw.UC_X86_REG_EIP):08x}",'address':f'0x{address:08x}','size':size,'value':f'0x{value:0{size*2}x}','ds':f"0x{uc.reg_read(uw.UC_X86_REG_DS):04x}",'es':f"0x{uc.reg_read(uw.UC_X86_REG_ES):04x}"})
    uc.hook_add(uw.UC_HOOK_MEM_WRITE,write)
    return count
uw.install_trace_hooks=traced
out={'baseline':uw.target_probe(10000,False),'environment_alias_experiment':uw.target_probe(10000,True)}
p=root/'evidence'/'selector_global_write_audit_work3.json'; p.write_text(json.dumps(out,indent=2)+'\n',encoding='utf-8')
print(json.dumps({k:{'stop':v.get('stop_reason'),'fault':v.get('guest_exception'),'first_unsupported':v.get('first_unsupported'),'writes':v.get('selector_global_writes',[]),'instructions':v.get('executed_instruction_count')} for k,v in out.items()},indent=2))
