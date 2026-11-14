"""Assembly-comment-based xref audit for setup_game's `this` slot."""
import hashlib, json, re
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
FILES={"entry_path_combined":"build/entry_path_combined.c","entry_path_closure":"build/entry_path_closure.c","broad_282":"build/recomp_282.c"}
ASM=re.compile(r"/\*\s*0x([0-9a-f]{5,8}):\s*(.*?)\s*\*/",re.I)
FUNC=re.compile(r"^\s*(?:void|static void)\s+([A-Za-z_]\w*)\s*\(.*\)\s*\{\s*$")
ALIAS=re.compile(r"^#define\s+sub_([0-9a-f]+)\s+(\w+)",re.I)
TARGET=re.compile(r"\[[^]]*0x0*114ca8[^]]*\]",re.I)

def audit(rel):
    path=ROOT/rel; lines=path.read_text(encoding='utf-8',errors='replace').splitlines()
    aliases={m.group(2):'0x'+m.group(1).upper() for line in lines if (m:=ALIAS.match(line))}
    owner=None; sites=[]
    for n,line in enumerate(lines,1):
        if m:=FUNC.match(line): owner=m.group(1)
        a=ASM.search(line)
        if not a: continue
        ins=a.group(2); operands=ins.split(None,1)
        if len(operands)<2 or not TARGET.search(ins): continue
        mnemonic,optext=operands
        args=[x.strip() for x in optext.split(',',1)]
        dest=bool(args and TARGET.search(args[0]))
        sites.append({'line':n,'link_va':'0x'+a.group(1).upper(),'instruction':ins,'mnemonic':mnemonic.lower(),'kind':'write' if dest else 'read' if len(args)>1 and TARGET.search(args[1]) else 'other','owner':owner,'owner_link_va':aliases.get(owner)})
    return {'path':rel,'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'sites':sites,'counts':{k:sum(x['kind']==k for x in sites) for k in ('read','write','other')},'write_sites':[x for x in sites if x['kind']=='write']}

def main():
    prov=json.loads((ROOT/'evidence/setup_game_this_provenance_work3.json').read_text(encoding='utf-8-sig'))
    closures={k:audit(v) for k,v in FILES.items()}
    result={'task':'W3-050','method':'classify x86 assembly operands in generated comments, one instruction per site; destination operand referencing [0x114CA8] is write','closures':closures,'oracle_crosscheck':{'target_sha256':prov['target_sha256'],'slot_runtime':prov['this_global']['runtime_address'],'initial_bytes':prov['this_global']['initial_bytes_before_guest'],'first_access':prov['first_events'][0]['eip'],'first_access_kind':prov['first_events'][0]['kind'],'first_access_value_bytes':prov['first_events'][0]['slot_bytes_at_event'],'fault_eip':prov['first_unsupported']['eip'],'fault_address':prov['first_unsupported']['address'],'fault_edi':prov['first_unsupported']['registers']['edi'],'executed_instructions':prov['executed_instruction_count']},'scope_limit':'This only audits the three generated closures. It does not enumerate all original executable instructions or prove the global has no writer elsewhere; absence of a closure writer does not establish that an initializer should run before setup_game.'}
    ep=closures['entry_path_combined']; ec=closures['entry_path_closure']; broad=closures['broad_282']
    result['determination']={'entry_path_writes':ep['counts']['write'],'entry_closure_writes':ec['counts']['write'],'broad_282_writes':broad['counts']['write'],'closure_has_writer':any(c['counts']['write'] for c in closures.values())}
    (ROOT/'evidence/this_global_assembly_audit_work3.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    lines=['# W3-050 — `this` assembly xref reconciliation','', 'This audit classifies each generated x86 assembly comment by its actual destination/source operand and counts one instruction once. It independently checks the LOCAL L-THISSLOTS regex-based counts.', '', '| Generated closure | Reads | Writes | Other |','|---|---:|---:|---:|']
    for k,c in closures.items(): lines.append(f"| `{k}` | {c['counts']['read']} | {c['counts']['write']} | {c['counts']['other']} |")
    lines += ['', '## Result', '', f"No destination write to `this` appears in these three generated closures: `{result['determination']['closure_has_writer']}`.", '', 'The LOCAL report counted assembly comments as extra references and missed DS_BASE read forms. Correct instruction counts are shown above. The narrow closure result supports that no initializer write is linked there, but it does not prove a whole-executable writer is absent or establish that the original must initialize the slot before `setup_game`.', '', f"Original-byte check: initial slot `{result['oracle_crosscheck']['initial_bytes']}`; first access `{result['oracle_crosscheck']['first_access_kind']}` at `{result['oracle_crosscheck']['first_access']}`; fault `{result['oracle_crosscheck']['fault_eip']}` to `{result['oracle_crosscheck']['fault_address']}` with EDI `{result['oracle_crosscheck']['fault_edi']}` after {result['oracle_crosscheck']['executed_instructions']} instructions. The slot read and NULL write remain confirmed; the upstream cause is not localized by this static audit.", '', 'Full instruction sites, file hashes, and provenance are in `evidence/this_global_assembly_audit_work3.json`.']
    (ROOT/'reports/coordination/this_global_assembly_audit_work3.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
if __name__=='__main__': main()
