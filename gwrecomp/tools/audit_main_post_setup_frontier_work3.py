"""Extract and validate the static main_ transition after setup_game."""
import hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def run():
 closure=ROOT/'build/entry_path_closure.c'; text=closure.read_text(encoding='utf-8',errors='replace')
 body=text.split('void gw_entry_main(void) {',1)[1].split('void ',1)[0]
 call_re=re.compile(r'RECOMP_CALL\(sub_([0-9A-Fa-f]+)\); /\* 0x([0-9A-Fa-f]+): call 0x([0-9A-Fa-f]+) \*/')
 calls=[{'callee_link_va':'0x'+m.group(1).upper(),'callsite_link_va':'0x'+m.group(2).upper(),'encoded_target':'0x'+m.group(3).upper()} for m in call_re.finditer(body) if int(m.group(2),16)>=0x9433D and int(m.group(2),16)<=0x94360]
 expected=[('0x00094AC0','0x0009433D'),('0x00092930','0x00094342'),('0x00092710','0x00094347'),('0x0009FC90','0x0009434C'),('0x000954A0','0x00094351'),('0x00092170','0x00094356')]
 maptext=(ROOT/'evidence/genewars-1_1.map').read_text(encoding='utf-8',errors='replace')
 symbols={'0x00093F30':'main_','0x00094AC0':'setup_game','0x00092930':'W?PlayIntro$n()v','0x00092710':'W?game$n()v','0x0009FC90':'StopMusic_'}
 mapcheck={a:{'symbol':n,'present':n in maptext and a[2:] in maptext} for a,n in symbols.items()}
 dynamic=json.loads((ROOT/'evidence/dynamic_setup_game_callchain_work3.json').read_text(encoding='utf-8'))
 original=json.loads((ROOT/'evidence/startup_option_gate_work3.json').read_text(encoding='utf-8-sig'))
 return {'task':'W3-055','target_sha256':dynamic['target_sha256'],'closure_sha256':hashlib.sha256(closure.read_bytes()).hexdigest(),'main_map_symbols':mapcheck,'branch':{'link_range':['0x0009432F','0x0009433B'],'condition':'[ESP+0x64] != 0 and [ESP+0x68] != 0','oracle_option_gate_locals':{'local_64':original['gate']['local_64'],'local_68':original['gate']['local_68']},'source_evidence':'evidence/startup_option_gate_work3.json'},'calls':calls,'expected_calls':[{'callee_link_va':a,'callsite_link_va':b} for a,b in expected],'dynamic_return_crosscheck':{'callee_entry':'0x00194ac0','stack_return':dynamic['captures'][1]['stack_dwords'][0],'expected_runtime_return':'0x00194342','link_return':'0x00094342','matches':dynamic['captures'][1]['stack_dwords'][0]=='0x00194342'},'post_gate_probe_points':['0x00194342 / link 0x94342: PlayIntro entry callsite','0x00192930 / link 0x92930: first PlayIntro entry','0x00194347 / link 0x94347: game callsite after PlayIntro returns','0x00192710 / link 0x92710: game entry'],'menu_reached':False,'interpretation':'If setup_game returns through the measured 0x94342 return, main_ calls PlayIntro, game, StopMusic, then two additional functions before continuing at 0x943F8. This is a static next-state sequence; neither PlayIntro entry nor a visible MENU has been dynamically observed on the CD-present route.'}

def main():
 d=run();(ROOT/'evidence/main_post_setup_frontier_work3.json').write_text(json.dumps(d,indent=2)+'\n',encoding='utf-8')
 lines=['# W3-055 — `main_` transition after `setup_game`','', 'The original-byte dynamic callchain confirms `setup_game` is entered at runtime `0x194AC0` with return address `0x194342` (link `0x94342`). That address is the next direct call in lifted `main_`.', '', 'Before the call, `main_` checks locals `[ESP+0x64]` and `[ESP+0x68]`; the recorded `-k` option gate has both equal to 1. The branch sequence then calls `setup_game` (`0x9433D`), `PlayIntro` (`0x94342`), `game` (`0x94347`), `StopMusic_` (`0x9434C`), and two additional callees (`0x94351`, `0x94356`) before jumping to `0x943F8`.', '', 'Post-gate dynamic breakpoints: `0x194342` before `PlayIntro`, `0x192930` at `PlayIntro`, `0x194347` before `game`, and `0x192710` at `game`. Capture the CPU/segment/stack state and callback/video writes at these boundaries. This static sequence does not prove that `PlayIntro` or `game` is reached, and does not identify a visible MENU. The original-byte CD-present run still faults earlier at `0x194B5A`.', '', 'MAP and generated closure hashes, exact call records, and return-address cross-check are in `evidence/main_post_setup_frontier_work3.json`.']
 (ROOT/'reports/coordination/main_post_setup_frontier_work3.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
if __name__=='__main__':main()
