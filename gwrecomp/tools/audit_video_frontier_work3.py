"""Validate unique BIOS-video sites and the static VESA/framebuffer frontier."""
import hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
FILES={'entry_path_combined':'build/entry_path_combined.c','entry_path_closure':'build/entry_path_closure.c','broad_282':'build/recomp_282.c'}
ASM=re.compile(r'/\*\s*0x([0-9a-f]{5,8}):\s*int\s+0x([0-9a-f]{1,2})\b',re.I)

def main():
    closures={}
    for name,rel in FILES.items():
        p=ROOT/rel; data=p.read_bytes(); text=data.decode('utf-8','replace')
        ints={}
        for m in ASM.finditer(text):
            vector=int(m.group(2),16); va=int(m.group(1),16)
            ints.setdefault(vector,set()).add(va)
        closures[name]={'path':rel,'sha256':hashlib.sha256(data).hexdigest(),'unique_int10_sites':[f'0x{x:08X}' for x in sorted(ints.get(0x10,set()))],'unique_int21_sites':[f'0x{x:08X}' for x in sorted(ints.get(0x21,set()))],'unique_int31_sites':[f'0x{x:08X}' for x in sorted(ints.get(0x31,set()))]}
    mt=(ROOT/'evidence/genewars-1_1.map').read_text(encoding='utf-8',errors='replace')
    needed={'0x0009FD40':'LbScreenSetupAnyMode_','0x000A3A00':'LbVesaSetMode_','0x000A3A5C':'LbVesaSetPage_'}
    owners={}
    for va,name in needed.items():owners[va]={'symbol':name,'map_present':f'{int(va,16):08X}'[-8:] in mt and name in mt}
    sites=[]
    for va in (0xA3A91,0xA3AB7):
        nearest=max((x for x in (0xA3A5C,0xA3A00,0x9FD40) if x<=va),default=None)
        sites.append({'link_va':f'0x{va:08X}','map_owner':'LbVesaSetPage_' if nearest==0xA3A5C else None})
    source=(ROOT/'build/entry_path_closure.c').read_text(encoding='utf-8',errors='replace')
    call='RECOMP_CALL(sub_000A3A00); /* 0x0009FDCC: call 0xa3a00 */'
    fb='MEM32(DS_BASE + (0x19CA58)) = 0x000A0000u; /* 0x0009FDEF: mov dword ptr [0x19ca58], 0xa0000 */'
    call_sites=re.findall(r'RECOMP_CALL\(sub_000A3A00\); /\* 0x([0-9a-f]+): call 0xa3a00 \*/',source,re.I)
    callback={'slot_map':'0x001A029C','symbol':'_smack_draw_callback','prior_task':'W3-030','prior_status':'BLOCKED','dynamic_callback_reached':False,'source':'PROJECT_STATE.md blocker list: current oracle has not reached _smack_draw_callback'}
    out={'task':'W3-053','closures':closures,'map_owners':owners,'vesa_page_int10_sites':sites,'screen_setup_to_mode_call_sites':[f'0x{x.upper()}' for x in call_sites],'framebuffer_base_store':{'link_va':'0x0009FDEF','global_link_va':'0x0019CA58','assigned_value':'0x000A0000','meaning':'static framebuffer base candidate; no dynamic write observed'},'callback':callback,'dynamic_gate':{'original_byte_oracle_fault_eip':'0x00194B5A','setup_game_fault_precedes_this_video_frontier':True,'first_visible_menu_observed':False},'post_W1_033_capture_points':['0x0009FD40 LbScreenSetupAnyMode_ entry','0x0009FDCC call LbVesaSetMode_','0x000A3A00 LbVesaSetMode_ entry','0x000A3A5C LbVesaSetPage_ entry','0x000A3A91 INT 10h','0x000A3AB7 INT 10h','0x0009FDEF framebuffer-base assignment','first guest memory write within the measured A0000 framebuffer mapping','first read/write/registration of callback slot 0x001A029C'],'capture_fields':['EAX EBX ECX EDX ESI EDI EBP ESP EIP EFLAGS','CS DS ES SS FS GS and selector descriptors/GDTR/LDTR','stack and caller return chain','INT 10/INT 31 vector and request registers before/after','guest writes to the measured framebuffer range','callback slot old/new bytes and writer EIP'],'interpretation':'The entry_path_combined source contains no INT 10 site. The larger entry_path_closure contains two unique INT 10 instructions in LbVesaSetPage_; recomp_282 repeats those same two. LbScreenSetupAnyMode_ calls LbVesaSetMode_ and assigns 0xA0000 to 0x19CA58 statically. INT 21 alone does not prove BIOS video without AH/AL, and closure reachability does not prove dynamic execution or MENU.'}
    (ROOT/'evidence/video_frontier_work3.json').write_text(json.dumps(out,indent=2)+'\n',encoding='utf-8')
    lines=['# W3-053 — VESA and framebuffer candidate frontier','', '| Source | Unique INT 10 sites | Unique INT 21 sites | Unique INT 31 sites |','|---|---:|---:|---:|']
    for n,c in closures.items():lines.append(f"| `{n}` | {len(c['unique_int10_sites'])} | {len(c['unique_int21_sites'])} | {len(c['unique_int31_sites'])} |")
    lines+=['','The `entry_path_combined` slice contains no INT 10 instruction. The larger `entry_path_closure` contains two unique sites, `0xA3A91` and `0xA3AB7`, both owned by MAP symbol `LbVesaSetPage_` at `0xA3A5C`; `recomp_282` repeats the same sites. The former local report counted four occurrences by summing duplicate closure copies, and its vector-only INT 21 classification does not establish video use.', '', '`LbScreenSetupAnyMode_` at `0x9FD40` has a direct call to `LbVesaSetMode_` at `0x9FDCC`. It later assigns `0xA0000` to global `0x19CA58` at `0x9FDEF`; this is a static framebuffer-base candidate, not a dynamically observed pixel/framebuffer write. The call may be outside the executed `-k` branch.', '', f"`_smack_draw_callback` remains blocked at slot `0x001A029C` (W3-030); this oracle has not reached it. The original-byte replay currently faults earlier at `0x00194B5A`. No VESA call, framebuffer write, callback dispatch, or visible MENU has been captured dynamically.", '', 'After W1-033 establishes a native/original differential, instrument the listed static frontiers and capture registers, flags, selectors/descriptors, stack/caller chain, INT 10/31 request state, first guest write to the mapped framebuffer, and callback slot old/new values with writer EIP. Full hashes and points are in `evidence/video_frontier_work3.json`.']
    (ROOT/'reports/coordination/video_frontier_work3.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
if __name__=='__main__':main()
