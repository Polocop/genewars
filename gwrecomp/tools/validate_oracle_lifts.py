"""Compare pcrecomp catalog boundaries with stored, target-verified byte fixtures."""
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
oracle=json.loads((ROOT/'evidence'/'batch_10.json').read_text(encoding='utf-8'))
catalog=json.loads((ROOT/'evidence'/'catalog_lift_100.json').read_text(encoding='utf-8'))
records={int(x['address'],16):x for x in catalog['functions']}
fail=[]; checks=[]
for ref in oracle['functions']:
    addr=int(ref['address'],16); expected=bytes.fromhex(ref['bytes']); rec=records.get(addr)
    result={'address':ref['address'],'map_name':ref['name'],'expected_size':len(expected),'catalog_present':rec is not None}
    if rec is None:
        result['pass']=False; result['reason']='oracle function not included in 100-function lift'; fail.append(result)
    else:
        actual=bytes.fromhex(rec.get('bytes',''))
        result.update({'lift_name':rec['lift_name'],'catalog_end':rec['end'],'catalog_size':rec['size'],'catalog_bytes_match':actual==expected})
        result['pass']=rec['size']==len(expected) and actual==expected
        if not result['pass']:
            result['reason']='boundary size or raw bytes differ from oracle'
            fail.append(result)
    checks.append(result)
out={'target_sha256':oracle['target_sha256'],'count':len(checks),'pass':len(checks)-len(fail),'fail':len(fail),'checks':checks}
(ROOT/'evidence'/'oracle_boundary_validation.json').write_text(json.dumps(out,indent=2)+'\n',encoding='utf-8')
print(json.dumps({k:v for k,v in out.items() if k!='checks'},indent=2))
if fail: raise SystemExit(1)
