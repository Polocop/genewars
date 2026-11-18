import json, pathlib, subprocess, sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
runner=ROOT/'tests'/'test_native_guest_image.py'
def run(tail,evidence):
    cmd=[sys.executable,str(runner),'--evidence-name',evidence]
    if tail: cmd += ['--command-tail='+tail]
    p=subprocess.run(cmd,cwd=ROOT,text=True,capture_output=True)
    print(p.stdout,end=''); print(p.stderr,end='')
    if p.returncode: raise SystemExit(p.returncode)
    return json.loads((ROOT/'evidence'/evidence).read_text(encoding='utf-8'))
def main():
    default=run('', 'native_lift_boot_tail_default.json')
    option=run('-k','native_lift_boot_tail_k.json')
    assert default['command_tail']=={'text':'','length':0,'hex':''}
    assert option['command_tail']=={'text':'-k','length':2,'hex':'2d6b'}
    assert default['entry']==option['entry'] and default['target_sha256']==option['target_sha256']
    oracle=json.loads((ROOT/'evidence'/'startup_option_gate_work3.json').read_text(encoding='utf-8'))
    assert oracle['command_tail']=='-k' and oracle['gate']['local_64']=='01' and oracle['gate']['local_68']=='01'
    assert 'setup_game' in oracle['result']
    print('PASS default and -k tails reach native PSP seed; original-byte -k oracle takes measured option branch')
if __name__=='__main__': main()
