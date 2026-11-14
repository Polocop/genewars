"""Capture a bounded ring of original instructions before the current startup stop."""
import importlib.util,json,pathlib
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('probe',ROOT/'tools/probes/unicorn_int21.py')
probe=importlib.util.module_from_spec(spec);spec.loader.exec_module(probe)
original_prepare=probe.prepare_guest
original_fs_init=probe.DosFileSystem.__init__
fs_holder={}
def traced_fs_init(self,*args,**kwargs):
 original_fs_init(self,*args,**kwargs)
 fs_holder['fs']=self
probe.DosFileSystem.__init__=traced_fs_init
probe.prepare_guest=lambda image: original_prepare(image,command_tail=b'-k')
original=probe.install_trace_hooks
ring_holder={}
exit_holder={}
root_hits={}
main_path=[]
gate_holder={}
def install(uc,trace,limit,host=None):
 count=original(uc,trace,limit,host); ring=[]; ring_holder['ring']=ring
 def on_code(uc,address,size,user):
  if 0x00193f30<=address<0x00194420:
   try: mp=bytes(uc.mem_read(address,size)).hex()
   except Exception: mp=''
   main_path.append({'eip':f'0x{address:08x}','bytes':mp,'registers':{k:f'0x{v:08x}' for k,v in probe.regs_snapshot(uc).items()}})
  if address==0x0019432f:
   esp=uc.reg_read(probe.UC_X86_REG_ESP)
   raw_gate=bytes(uc.mem_read(address,0x20))
   raw_locals=bytes(uc.mem_read(esp+0x50,0x20))
   gate_holder['gate']={'guest_eip':f'0x{address:08x}','bytes':raw_gate.hex(),'esp':f'0x{esp:08x}','locals_esp_50_hex':raw_locals.hex(),'local_60':uc.mem_read(esp+0x60,1).hex(),'local_64':uc.mem_read(esp+0x64,1).hex(),'local_68':uc.mem_read(esp+0x68,1).hex(),'registers':{k:f'0x{v:08x}' for k,v in probe.regs_snapshot(uc).items()}}
  for root,name in ((0x00193f30,'main_'),(0x00194ac0,'setup_game'),(0x00192930,'PlayIntro'),(0x00192710,'game')):
   if address==root and name not in root_hits: root_hits[name]={'guest_eip':f'0x{address:08x}','bytes':bytes(uc.mem_read(address,size)).hex(),'registers':{k:f'0x{v:08x}' for k,v in probe.regs_snapshot(uc).items()}}
  try: raw=bytes(uc.mem_read(address,size)).hex()
  except Exception: raw=''
  try: regs=probe.regs_snapshot(uc)
  except Exception: regs={}
  if address in (0x001afbfd,0x001c8a26,0x001c8a3b,0x001afc33):
   esp0=uc.reg_read(probe.UC_X86_REG_ESP)
   try: stk0=bytes(uc.mem_read(esp0,0x40))
   except Exception: stk0=b''
   exit_holder.setdefault('path_events',[]).append({'eip':f'0x{address:08x}','registers':{k:f'0x{v:08x}' for k,v in probe.regs_snapshot(uc).items()},'stack_esp':f'0x{esp0:08x}','stack_dwords':[f'0x{int.from_bytes(stk0[i:i+4],"little"):08x}' for i in range(0,len(stk0)-3,4)]})
  if address==0x001afc33:
   esp=uc.reg_read(probe.UC_X86_REG_ESP)
   try: stack=bytes(uc.mem_read(esp,0x80))
   except Exception: stack=b''
   exit_holder['stack']={'esp':f'0x{esp:08x}','bytes':stack.hex(),'dwords':[f'0x{int.from_bytes(stack[i:i+4],"little"):08x}' for i in range(0,len(stack)-3,4)]}
  rec={'eip':f'0x{address:08x}','bytes':raw,'size':size,'registers':{k:f'0x{v:08x}' for k,v in regs.items()},'ds':f"0x{uc.reg_read(probe.UC_X86_REG_DS):04x}",'es':f"0x{uc.reg_read(probe.UC_X86_REG_ES):04x}"}
  ring.append(rec)
  if len(ring)>512: del ring[0]
 uc.hook_add(probe.UC_HOOK_CODE,on_code)
 return count
probe.install_trace_hooks=install
BaseUc=probe.Uc
class LongTimeoutUc:
 def __init__(self,*args,**kwargs): self._uc=BaseUc(*args,**kwargs)
 def emu_start(self,begin,until,timeout=0,count=0): return self._uc.emu_start(begin,until,timeout=max(timeout,30000000),count=count)
 def __getattr__(self,name): return getattr(self._uc,name)
probe.Uc=LongTimeoutUc
trace=probe.target_probe(200000,True)
summary={k:trace.get(k) for k in ('target_sha256','environment_alias_experiment','stop_reason','executed_instruction_count','guest_exception','unsupported_memory','unsupported_port','unsupported_service','first_unsupported','process_exit')}
summary['exit_stack']=exit_holder.get('stack')
summary['exit_path_events']=exit_holder.get('path_events',[])
summary['root_hits']=root_hits
summary['main_path_instructions']=main_path
summary['game_gate_snapshot']=gate_holder.get('gate')
summary['filesystem_attempts']=list(getattr(fs_holder.get('fs'),'attempts',[]))
summary['command_tail']='-k'
summary['game_gate_snapshot']=gate_holder.get('gate')
summary['filesystem_attempts']=list(getattr(fs_holder.get('fs'),'attempts',[]))
summary['last_interrupts']=trace.get('interrupts',[])[-8:]
summary['last_instructions']=ring_holder.get('ring',[])
out=ROOT/'evidence'/'getconfigs_files_oracle_work3.json';out.write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
print(json.dumps({k:v for k,v in summary.items() if k not in ('last_instructions','last_interrupts')},indent=2));print('last interrupts',summary['last_interrupts']);print('ring records',len(summary['last_instructions']))

