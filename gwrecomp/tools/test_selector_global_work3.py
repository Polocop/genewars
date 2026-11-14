import hashlib,json,pathlib,sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from src.le_loader import load_le
image_path=ROOT/'evidence/genewars-1_1.exe'
image=load_le(image_path)
trace=json.loads((ROOT/'evidence/runtime_backend_execution.json').read_text(encoding='utf-8'))['target']
alias=json.loads((ROOT/'evidence/runtime_environment_alias_experiment.json').read_text(encoding='utf-8'))['target']
audit=json.loads((ROOT/'evidence/selector_global_write_audit_work3.json').read_text(encoding='utf-8'))
rebase=0x100000; guest_va=0x20b795; link_va=guest_va-rebase; owner=image.object_containing(link_va)
assert owner is not None and owner.index==3
raw=lambda va,n:bytes(image.mem[va-image.mem_base:va-image.mem_base+n])
checks={
 'target_sha256':hashlib.sha256(image_path.read_bytes()).hexdigest(),
 'object3_range':[hex(owner.base),hex(owner.end)],
 'global_guest_va':hex(guest_va),'global_link_va':hex(link_va),'object':owner.index,'object_offset':hex(link_va-owner.base),
 'map_public_name':None,
 'code_evidence':{
  'psp_env_read':{'va':'0x000afad8','bytes':raw(0xafad8,8).hex()},
  'selector_slot_store_va':'0x000afb14','bytes_store':raw(0xafb14,7).hex(),
  'selector_slot_load_ds_va':'0x000afb56','bytes_load':raw(0xafb56,8).hex()},
 'runtime_write':audit['baseline']['selector_global_writes'],
 'baseline_fault':trace.get('guest_exception'),
 'alias_experiment':{'selector_alias_enabled':alias.get('environment_alias_experiment'),'first_unsupported':alias.get('first_unsupported'),'guest_exception':alias.get('guest_exception'),'executed_instruction_count':alias.get('executed_instruction_count')},
 'interpretation':'unnamed selector slot in LE object 3 stack/data; startup copies the PSP environment segment selector there, then loads DS from it. The bounded synthetic GDT alias at selector 0x1100 resolves this #GP and advances to the next unsupported DOS INT 21h AH=3Dh.',
 'limitations':['Object 3 is flagged STACK in MAIN.MAP; this slot has no public symbol name.','The alias descriptor experiment is synthetic and proves the immediate selector contract, not the canonical DOS/4GW descriptor base/limit/access policy.','Initial GPRs, PSP, environment, and descriptor tables remain synthetic; the trace does not establish the real extender launch state.']}
assert checks['code_evidence']['psp_env_read']['bytes']=='66268b0d2c000000'
assert checks['code_evidence']['bytes_store']=='66890d95b71000'
assert checks['code_evidence']['bytes_load']=='26668e1d95b71000'
assert checks['runtime_write'][0]['value']=='0x1100' and checks['runtime_write'][0]['eip']=='0x001afb14'
assert checks['baseline_fault']['vector']==13 and checks['baseline_fault']['selector_value']==0x1100
assert checks['alias_experiment']['first_unsupported']['vector']==33 and checks['alias_experiment']['first_unsupported']['function']==61
assert checks['alias_experiment']['guest_exception'] is None
out=ROOT/'evidence/selector_contract_work3.json'; out.write_text(json.dumps(checks,indent=2)+'\n',encoding='utf-8')
lines=['# W3-008 — startup environment selector slot','',f"Target SHA-256: `{checks['target_sha256']}`.",'',f"Guest VA `0x20B795` minus runtime rebase `0x100000` maps to link VA `0x{link_va:08X}`. It lies in LE object {owner.index}, range `0x{owner.base:08X}–0x{owner.end:08X}`, at object offset `0x{link_va-owner.base:X}`. MAIN.MAP classifies object 3 as `STACK`; there is no public symbol at this address. Classify it as an unnamed startup selector slot in the stack/data object, not a named executable global.",'','## Provenance','',f"At `0x000AFAD8`, bytes `{raw(0xafad8,8).hex()}` read the PSP environment segment from `ES:[0x2C]`. At `0x000AFB14`, bytes `{raw(0xafb14,7).hex()}` store CX to link address `0x0010B795`; the runtime write hook independently records value `0x1100` at guest address `0x0020B795`. At `0x000AFB56`, bytes `{raw(0xafb56,8).hex()}` load DS from `ES:[0x20B795]`. The synthetic baseline lacks that selector descriptor and raises #GP vector 13.",'','## Selector/runtime contract','',"The startup path expects selector `0x1100` to be loadable into DS after it copies the PSP environment selector. In the isolated GDT alias experiment, a data descriptor at selector `0x1100` based at the seeded environment block resolves the #GP; execution continues to the next unsupported DOS INT 21h call, AH=`0x3D` at EIP `0x001AFCC4`. This is direct evidence for the immediate contract, not proof of the canonical DOS/4GW descriptor policy.",'','WORK2 task W2-013 is READY with dependency W3-008 and can now implement the required selector state after this evidence is recorded. Do not treat vector 13 as a DOS interrupt.','', '## Limits','',*['- '+x for x in checks['limitations']],'','Reproduction: `py -3 tools/test_selector_global_work3.py`. Evidence: `evidence/selector_contract_work3.json`.','']
(ROOT/'reports/runtime_selector_fault.md').write_text('\n'.join(lines),encoding='utf-8')
print(json.dumps({'object':owner.index,'offset':hex(link_va-owner.base),'runtime_write':checks['runtime_write'],'baseline_vector':checks['baseline_fault']['vector'],'alias_next':checks['alias_experiment']['first_unsupported']},indent=2))
