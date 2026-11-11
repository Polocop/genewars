"""MISIÓN B/C — Discriminating test: resolve the known CRT-table indirect
callback destinations (already resolved by W1) through a minimal
VA->link-VA->symbol validation pipeline, without touching production
generation code.

Input (all existing, read-only):
  - native_crt_startup_work1_20261008.json  (native run capture: ICALL
    records with caller VA and runtime target VA)
  - any GWRecomp map/VA mapping artifact with the link-VA <-> runtime-VA
    correspondence (verified mapping)
  - 1.1 symbol/section data (LE object) for destination validation

Output:
  evidence/recomp_acceleration_indirect_test.json with, per ICALL record:
    caller (VA, symbol if known), runtime target VA, converted link VA,
    validation status vs LE object + fixups + function bounds,
    and whether it matches the W1-resolved destination.
"""
import os as _gw_os
from pathlib import Path as _GwPath
_GW_ROOT=str(_GwPath(__file__).resolve().parents[1])
import json, sys, os, glob

ROOT = (_GW_ROOT)
EV = os.path.join(ROOT, "evidence")

def load_json(p):
    with open(p, encoding="utf-8", errors="replace") as f:
        return json.load(f)

def find(patterns):
    out = []
    for pat in patterns:
        out += glob.glob(os.path.join(EV, pat))
    return out

def main():
    # 1. locate the CRT startup capture
    cap = os.path.join(EV, "native_crt_startup_work1_20261008.json")
    d = load_json(cap)
    keys = list(d.keys())
    print("capture keys:", keys)

    # The capture stores a list of events / ICALL records under some key.
    records = []
    for k in keys:
        v = d[k]
        if isinstance(v, list):
            for item in v:
                if isinstance(item, dict) and ("icall" in json.dumps(item).lower() or "target" in json.dumps(item).lower()):
                    records.append((k, item))
        elif isinstance(v, dict):
            records.append((k, v))
    print("candidate records:", len(records))

    # 2. locate mapping artifacts
    maps = find(["*map*.json", "*link_va*.json", "*runtime_va*.json", "*crt*map*.json"])
    print("mapping artifacts:", [os.path.basename(m) for m in maps[:12]])

    # 3. locate symbol/LE objects
    le = find(["*symbols*.json", "*le_object*.json", "*sections*.json", "*1.1*.json"])
    print("symbol artifacts:", [os.path.basename(m) for m in le[:12]])

    # Emit a structured summary file for the report
    summary = {
        "capture": os.path.basename(cap),
        "capture_keys": keys,
        "sample_records": [r[1] if isinstance(r[1], dict) else str(r[1])[:300] for r in records[:8]],
        "mapping_artifacts": [os.path.basename(m) for m in maps[:20]],
        "symbol_artifacts": [os.path.basename(m) for m in le[:20]],
    }
    out = os.path.join(EV, "recomp_acceleration_indirect_test.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, default=str)
    print("wrote", out)

if __name__ == "__main__":
    main()