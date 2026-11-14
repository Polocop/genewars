import hashlib, importlib.util, io, json, pathlib, sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'.venv'/'Lib'/'site-packages'))
spec=importlib.util.spec_from_file_location('unicorn_read_probe',ROOT/'tools'/'probes'/'unicorn_int21.py')
probe=importlib.util.module_from_spec(spec); spec.loader.exec_module(probe)
sys.path.insert(0,str(ROOT/'runtime'))
from dos_filesystem import DosFileSystem, DosFsError, Handle
original_open=DosFileSystem.open
original_prepare=probe.prepare_guest
probe.prepare_guest=lambda image: original_prepare(image,command_tail=b'-k')

def isolated_open(self,path,*,access='r',create=False,truncate=False):
    if access=='r' and not create: return original_open(self,path,access=access,create=create,truncate=truncate)
    host=self.resolve(path); exists=host.exists()
    if not exists and not create: raise DosFsError(self.ERR_FILE_NOT_FOUND,'file not found',path)
    if exists and host.is_dir(): raise DosFsError(self.ERR_ACCESS_DENIED,'cannot open directory as file',path)
    initial=host.read_bytes() if exists and not truncate and access in ('w','rw') else b''
    stream=io.BytesIO(initial)
    if access=='w' and not truncate and not create: stream.seek(0)
    elif access=='w' and not truncate: stream.seek(0,io.SEEK_END)
    handle=next(h for h in range(5,0x10000) if h not in self.handles)
    self.handles[handle]=Handle(stream,True,path); self._record('open',path,handle=handle,result=True); return handle
DosFileSystem.open=isolated_open

def run(root):
    holder={}; original_init=DosFileSystem.__init__
    def capture_init(self,*args,**kwargs): original_init(self,*args,**kwargs); holder['fs']=self
    DosFileSystem.__init__=capture_init
    try: trace=probe.target_probe(200000,True,dos_root=root)
    finally: DosFileSystem.__init__=original_init
    return trace,holder['fs'].attempts
fixture=ROOT/'build'/'work3_empty_config_fixture'
config=(fixture/'GENEWARS'/'config.ini')
if not config.exists() or config.stat().st_size!=0: raise AssertionError('expected WORK3 isolated empty config fixture')
empty,empty_attempts=run(fixture)
reads=[i for i in empty.get('interrupts',[]) if i.get('registers',{}).get('eax','').endswith('3f06')]
if not reads or not reads[0].get('handled') or reads[0].get('service')!='dos21.read_file':
    raise AssertionError(f'original-byte probe did not handle AH=3F: {reads!r}')
read=reads[0]
if int(read['registers_after']['eax'],16)&0xffff != 0 or int(read['registers_after']['eflags'],16)&1:
    raise AssertionError('empty config read should return AX=0, CF clear')
if read.get('dos_read_buffer',{}).get('linear')!='0x003c403c': raise AssertionError(f'unexpected read buffer: {read.get("dos_read_buffer")}')
no_config_root=ROOT/'build'/'dos_c_reference_20261006'
missing,missing_attempts=run(no_config_root)
missing_configs=[a for a in missing_attempts if a['operation']=='open' and a['path'].casefold()=='config.ini']
if not missing_configs or missing_configs[-1]['result'] is not False or missing.get('process_exit',{}).get('code')!=0:
    raise AssertionError('no-config branch no longer follows original exit path')
next_int=next((i for i in empty.get('interrupts',[]) if empty.get('first_unsupported',{}).get('eip')==i.get('eip_int_opcode_assumption')),None)
summary={
  'target_sha256':empty.get('target_sha256'),'command_tail':'-k','empty_fixture':str(config),
  'config_sha256':hashlib.sha256(config.read_bytes()).hexdigest(),
  'read_interrupt':read,'empty_fixture_stop':{'next_unsupported_interrupt':next_int,'reason':empty.get('stop_reason'),'process_exit':empty.get('process_exit'),'first_unsupported':empty.get('first_unsupported'),'executed_instruction_count':empty.get('executed_instruction_count')},
  'no_config_root':str(no_config_root),'no_config_attempts':missing_configs,
  'no_config_exit':missing.get('process_exit'),'no_config_stop_reason':missing.get('stop_reason'),
  'no_config_attempt_log':missing_attempts,
  'writes_policy':'guest writes routed to in-memory streams; config fixture and staged GAME files are unchanged',
  'passed':True}
out=ROOT/'evidence'/'dos_read_file_probe_work2.json'; out.write_text(json.dumps(summary,indent=2),encoding='utf-8')
print(json.dumps({k:summary[k] for k in ('read_interrupt','empty_fixture_stop','no_config_attempts','no_config_exit','passed')},indent=2))
