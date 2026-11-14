from pathlib import Path
import json,re,sys
ROOT=Path(__file__).resolve().parents[1]
E=ROOT/'evidence'
report_path=E/'single_0x10_order_ralph_walk_to_turn750.json'
report=json.loads(report_path.read_text(encoding='utf-8'))
control_path=E/'building11_placement_grid_probe_v2.stderr.log'
control=control_path.read_text(encoding='utf-8',errors='replace')
checks=[]
def check(name,ok,detail=None):
    checks.append({'name':name,'passed':bool(ok),'detail':detail})
packet=report['packet']; replay=report['replay']; move=report['movement']; ab=report['ab_comparison']
check('single action packet is PA_IFC_MOVE_GO at the original emitter',packet['action']=='PA_IFC_MOVE_GO (0x10)' and packet['emitter_eip']=='0x0006D567' and packet['turn']==443,packet)
check('original handler dispatched exactly once',packet['handler_eip']=='0x00076750' and 'count=1 Action=10' in packet['dispatch_trace'])
check('single-order replay completed all 750 turns with integrity',replay['final_turn']==750 and replay['frontier'] is None and replay['unexpected_writes']==0 and replay['MCB_chain_valid'] is True,replay)
check('Ralph reached the packet destination and remained there',move['first_turn_at_exact_destination']==552 and move['end_xy']==[19839,13439])
check('no second order or mouse input replaced the 0x10 order',ab['B_single_order']['later_Action_0x03_count']==0 and ab['B_single_order']['post_order_mouse_input_count']==0)
control_10=next((x for x in control.splitlines() if x.startswith('TRACE activation_packet_action_write ') and 'after=10' in x),None)
control_03=next((x for x in control.splitlines() if x.startswith('TRACE activation_packet_action_write ') and 'after=03' in x and 'Turn=446' in x),None)
check('A/B control shows later click replaced the earlier 0x10 with 0x03',control_10 is not None and control_03 is not None,{'control_order_10':control_10,'control_later_03':control_03})
check('payload bytes match original runtime capture',packet['bytes_hex']=='00000a00000b7f4d7f3410')
failed=[x for x in checks if not x['passed']]
out={'schema':'gw-pa-ifc-move-go-single-order-ab-test/v1','evidence':str(report_path.relative_to(ROOT)),'checks':checks,'passed':not failed}
out_path=E/'single_0x10_order_ab_test.json'; out_path.write_text(json.dumps(out,indent=2)+'\n',encoding='utf-8')
print(f"{'PASS' if not failed else 'FAIL'} single PA_IFC_MOVE_GO A/B verifier: {len(checks)-len(failed)}/{len(checks)} checks; {out_path}")
if failed:
    for item in failed: print('FAIL',item['name'],item.get('detail'))
    raise SystemExit(1)
