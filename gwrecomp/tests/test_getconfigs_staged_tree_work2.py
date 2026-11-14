import hashlib, importlib.util, io, json, pathlib, sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'.venv'/'Lib'/'site-packages'))
spec=importlib.util.spec_from_file_location('unicorn_probe',ROOT/'tools'/'probes'/'unicorn_int21.py')
probe=importlib.util.module_from_spec(spec); spec.loader.exec_module(probe)
sys.path.insert(0,str(ROOT/'runtime'))
from dos_filesystem import DosFileSystem, DosFsError, Handle
original_open=DosFileSystem.open
original_init=DosFileSystem.__init__
original_prepare=probe.prepare_guest
fs_holder={}
probe.prepare_guest=lambda image: original_prepare(image,command_tail=b'-k')
def capture_init(self,*args,**kwargs):
    original_init(self,*args,**kwargs); fs_holder['fs']=self
DosFileSystem.__init__=capture_init

def isolated_open(self,path,*,access='r',create=False,truncate=False):
    if access=='r' and not create:
        return original_open(self,path,access=access,create=create,truncate=truncate)
    host=self.resolve(path)
    exists=host.exists()
    if not exists and not create: raise DosFsError(self.ERR_FILE_NOT_FOUND,'file not found',path)
    if exists and host.is_dir(): raise DosFsError(self.ERR_ACCESS_DENIED,'cannot open directory as file',path)
    initial=b''
    if exists and not truncate and access in ('w','rw'): initial=host.read_bytes()
    stream=io.BytesIO(initial)
    if access=='w' and not truncate and not create: stream.seek(0,io.SEEK_SET)
    elif access=='w' and not truncate: stream.seek(0,io.SEEK_END)
    handle=next(h for h in range(5,0x10000) if h not in self.handles)
    self.handles[handle]=Handle(stream,True,path)
    self._record('open',path,handle=handle,result=True)
    return handle
DosFileSystem.open=isolated_open
root=ROOT/'build'/'dos_c_reference_20261006'
trace=probe.target_probe(200000,True,dos_root=root)
fs=fs_holder['fs']
attempts=fs.attempts
config=[a for a in attempts if a['operation']=='open' and a['path'].casefold()=='config.ini']
gwerr=[a for a in attempts if a['operation']=='open' and a['path'].casefold()=='gw.err']
if not config or config[-1]['result'] is not False or config[-1]['error']!=DosFileSystem.ERR_FILE_NOT_FOUND:
    raise AssertionError(f'expected config.ini not found in staged GAME mount, got {config!r}')
if len(gwerr)<1 or not gwerr[-1]['result']:
    raise AssertionError(f'expected staged GW.ERR lookup then isolated write, got {gwerr!r}')
manifest=json.loads((ROOT/'evidence'/'dos_game_install_manifest.json').read_text(encoding='utf-8'))
expected=next(x['sha256'] for x in manifest['file_manifest'] if x['relative_path'].casefold()=='gw.err')
staged_hash=hashlib.sha256((root/'GENEWARS'/'GW.ERR').read_bytes()).hexdigest()
source_file=pathlib.Path(manifest['source_root'])/'GW.ERR'
source_hash=hashlib.sha256(source_file.read_bytes()).hexdigest()
if staged_hash != expected or source_hash != expected:
    raise AssertionError('GW.ERR source or staged copy changed during read-only-mount probe')
if not trace.get('process_exit') or trace['process_exit'].get('code')!=0:
    raise AssertionError(f'original-byte -k probe did not reach normal process exit: {trace.get("stop_reason")}')
summary={
    'target_sha256':trace['target_sha256'],
    'dos_root':str(root),
    'mount':'C:\\GENEWARS -> build/dos_c_reference_20261006/GENEWARS',
    'command_tail':'-k',
    'instruction_count':trace.get('executed_instruction_count'),
    'process_exit':trace['process_exit'],
    'config_ini_attempts':config,
    'gw_err_attempts':gwerr,
    'all_filesystem_attempts':attempts,
    'write_policy':'all guest writes routed to in-memory BytesIO handles; staged reference tree unchanged',
    'gw_err_sha256':{'expected_manifest':expected,'staged_after':staged_hash,'read_only_source':source_hash,'all_match':True},
    'next_target_stop_link_va':'0x00094AE9',
    'next_target_stop_source':'evidence/startup_option_gate_work3.json original-byte oracle return address after GetConfigs failure branch',
    'unsupported':trace.get('first_unsupported'),
    'passed':True,
}
out=ROOT/'evidence'/'getconfigs_staged_tree_work2.json'
out.write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
print(json.dumps({k:summary[k] for k in ('command_tail','instruction_count','process_exit','config_ini_attempts','gw_err_attempts','next_target_stop_link_va','passed')},indent=2))
