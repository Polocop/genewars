import hashlib,json,re
from pathlib import Path
R=Path(__file__).resolve().parents[1]
report=json.loads((R/'evidence/entry_mem_putc_integration_work1.json').read_text())
compiled=json.loads((R/'evidence/entry_path_closure_routed_compile.json').read_text())
native=json.loads((R/'evidence/native_entry_after_mem_putc_work1.json').read_text())
closure=(R/'build/entry_path_closure.c').read_text()
lookup=(R/'build/entry_path_native_lookup.c').read_text()
assert report['passed'] and report['target_sha256']=='2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f'
assert report['map_symbol']=='mem_putc_' and report['le_base']=='0x00010000'
assert report['batch_instruction_addresses_match'] and not report['batch_body_used_verbatim']
assert report['closure_contains_target_once'] and len(re.findall(r'RECOMP_ENTER\(0x00096B10u\)',closure))==1
assert compiled['passed'] and compiled['compile_exit']==0 and compiled['function_definitions']==1112
assert hashlib.sha256((R/'build/entry_path_closure_routed.o').read_bytes()).hexdigest()==compiled['object_sha256']
assert native['passed'] and native['native_indirect_dispatch']['mapped_function_count']==1112
assert '{ 0x00096B10u, sub_00096B10 }' in lookup or '0x00096B10u, sub_00096B10' in lookup
fault=native['fault_stderr']
assert 'icall_last=00096b10' in fault.lower() and 'ICALL: unresolved VA 0x00096B10' not in fault
assert native['link_va_layout']['mem_base']=='0x10000' and native['link_va_layout']['rebase']=='0x0'
print('PASS current LE/MAP boundary, guarded lift, x86-32 compile, native ICALL lookup and fixed base')
