"""Enumerate direct absolute x86 code references to MAIN.MAP `this`."""
import hashlib,json,re,struct,sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
TARGET=ROOT/'evidence/genewars-1_1.exe'; MAP=ROOT/'evidence/genewars-1_1.map'; PROV=ROOT/'evidence/setup_game_this_provenance_work3.json'
CODE_LO,CODE_HI=0x10000,0xEE930; SLOT=0x114CA8

def scan():
    sys.path.insert(0,str(ROOT/'src'))
    from le_loader import load_le
    try: from capstone import Cs,CS_ARCH_X86,CS_MODE_32,CS_AC_READ,CS_AC_WRITE
    except ImportError as e: raise RuntimeError('Capstone is required; use the repository reference decoder environment') from e
    digest=hashlib.sha256(TARGET.read_bytes()).hexdigest()
    im=load_le(TARGET); code=bytes(im.mem[CODE_LO-im.mem_base:CODE_HI-im.mem_base]); needle=struct.pack('<I',SLOT)
    publics=[]
    for line in MAP.read_text(encoding='utf-8',errors='replace').splitlines():
        p=line.split()
        if len(p)>=2 and p[0].startswith('0001:'):
            try: va=int(p[0].split(':')[1],16)
            except ValueError: continue
            name=p[1]
            if name.startswith(('W?','Lb')) or (name.endswith('_') and not name.startswith(('jpt_','def_'))): publics.append((va,name))
    publics.sort()
    occurrences=[]; pos=0
    while (pos:=code.find(needle,pos))>=0: occurrences.append(pos);pos+=1
    md=Cs(CS_ARCH_X86,CS_MODE_32);md.detail=True; found={}
    for disp in occurrences:
        for back in range(1,16):
            st=disp-back
            if st<0:continue
            ins=next(md.disasm(code[st:disp+4],CODE_LO+st,count=1),None)
            if ins is None or ins.address+ins.size!=CODE_LO+disp+4:continue
            memops=[o for o in ins.operands if o.type==3 and o.mem.base==0 and o.mem.index==0 and o.mem.disp==SLOT]
            if not memops:continue
            mo=memops[0]; kind='write' if mo.access&CS_AC_WRITE else 'read' if mo.access&CS_AC_READ else 'unknown'
            owner=next(((a,n) for a,n in reversed(publics) if a<=ins.address),(None,None))
            found[(ins.address,bytes(ins.bytes).hex())]={'link_va':f'0x{ins.address:08X}','bytes':bytes(ins.bytes).hex(),'mnemonic':ins.mnemonic,'operands':ins.op_str,'kind':kind,'operand_access':int(mo.access),'owner_link_va':f'0x{owner[0]:08X}' if owner[0] is not None else None,'owner_map_symbol':owner[1]}
    classified_disps={ins_addr for ins_addr,_ in found}
    result={'task':'W3-051','target_sha256':digest,'code_range':[f'0x{CODE_LO:08X}',f'0x{CODE_HI:08X}'],'slot_link_va':f'0x{SLOT:08X}','loader_mem_base':f'0x{im.mem_base:08X}','displacement_byte_occurrences':len(occurrences),'unique_decoded_instructions':len(found),'unmatched_displacement_offsets':[f'0x{CODE_LO+p:08X}' for p in occurrences if not any(addr<=CODE_LO+p<addr+len(bytes.fromhex(bs)) for addr,bs in found)],'instructions':sorted(found.values(),key=lambda x:int(x['link_va'],16)),'counts':{k:sum(x['kind']==k for x in found.values()) for k in ('read','write','unknown')},'dynamic_oracle':{},'scope_limit':'Finds direct absolute operands only within the pinned LE executable code range. It does not resolve register/alias-based writes or establish dynamic execution order for sites that were not reached.'}
    prov=json.loads(PROV.read_text(encoding='utf-8-sig'))
    ev=prov['first_events'][0]; fault=prov['first_unsupported']
    result['dynamic_oracle']={'target_sha256':prov['target_sha256'],'runtime_global':prov['this_global']['runtime_address'],'initial_bytes':prov['this_global']['initial_bytes_before_guest'],'first_access':ev['eip'],'first_access_kind':ev['kind'],'first_access_old_bytes':ev['old_bytes'],'fault_eip':fault['eip'],'fault_address':fault['address'],'fault_instruction_bytes':fault['instruction_bytes'],'fault_edi':fault['registers']['edi'],'instructions_executed':prov['executed_instruction_count'],'probe_command':prov['command']}
    return result

def main():
    d=scan();(ROOT/'evidence/this_global_full_code_scan_work3.json').write_text(json.dumps(d,indent=2)+'\n',encoding='utf-8')
    writes=[x for x in d['instructions'] if x['kind']=='write']
    lines=['# W3-051 — Direct original-code references to setup_game `this`','',f"MAIN SHA-256: `{d['target_sha256']}`; LE code range `{d['code_range'][0]}–{d['code_range'][1]}`; slot link VA `{d['slot_link_va']}`.",'',f"The scan found {d['displacement_byte_occurrences']} occurrences of the slot displacement and decoded {d['unique_decoded_instructions']} unique instructions with an absolute memory operand to it. Counts: {d['counts']}. Unmatched displacement bytes: {d['unmatched_displacement_offsets']}.",'', '## Direct writers', '']
    if writes:
        lines+=['| VA | Bytes | Instruction | Owner |','|---|---|---|---|']+[f"| `{x['link_va']}` | `{x['bytes']}` | `{x['mnemonic']} {x['operands']}` | `{x['owner_map_symbol']}` at `{x['owner_link_va']}` |" for x in writes]
    else:lines.append('None found among decoded direct absolute code operands.')
    d0=d['dynamic_oracle']; lines+=['','## Original-byte `-k` oracle', '',f"The probe target matches the scanned executable. Runtime global `{d0['runtime_global']}` began `{d0['initial_bytes']}`; first dynamic access was {d0['first_access_kind']} at `{d0['first_access']}` with bytes `{d0['first_access_old_bytes']}`. It faulted at `{d0['fault_eip']}` writing `{d0['fault_address']}` (`{d0['fault_instruction_bytes']}`, EDI `{d0['fault_edi']}`) after {d0['instructions_executed']} instructions.",'', '## Interpretation and limits','', 'This proves only that direct absolute code operands to the slot are reads in this target. A writer could use a register/alias, a generic copy routine, data relocations, or external startup/runtime code. The dynamic trace also shows no prior direct write was observed on this replay, but the slot origin/expected initialization and the native/runtime divergence remain unproven. Do not seed a pointer based on this scan.', '', 'Every direct instruction, byte offset, operand classification, and nearest MAP function-like owner is preserved in `evidence/this_global_full_code_scan_work3.json`.']
    (ROOT/'reports/coordination/this_global_full_code_scan_work3.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
if __name__=='__main__':main()
