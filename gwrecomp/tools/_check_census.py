import os as _gw_os
from pathlib import Path as _GwPath
_GW_ROOT=str(_GwPath(__file__).resolve().parents[1])

import json
d = json.load(open((_GW_ROOT + '\\evidence\\lifter_hazard_census.json')))
print("pattern_counts:", d.get("pattern_counts"))
print("findings_total:", d.get("findings_total"))
note = d.get("note","")
print("note:", note[:400] if note else "(none)")
# find P05/P06/P08 keys anywhere
pc = d.get("pattern_counts", {})
for k in pc:
    if any(t in k for t in ("P05","P06","P08","repne","repe","neg","scasb","cmpsb")):
        print("  KEY:", k, "=>", pc[k])
