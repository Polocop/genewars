"""Compare two lifter outputs that differ only in how functions are named.

usage: python compare_lift_outputs.py --legacy-c ref.c --legacy-report ref_report.json --address-c new.c
  ref.c / ref_report.json : produced with GWRECOMP_SYMBOL_STEMS=map and the reference map (historical identifiers)
  new.c                   : produced with the default address-based identifiers (with or without the map)
The legacy identifiers are rewritten to their address form using the legacy report, then the two files are compared:
same multiset of lines, same function definitions in the same order, and a classification of any differing lines.
Prints aggregate results only (no symbol names).
"""
import argparse, collections, json, pathlib, re

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--legacy-c", required=True); ap.add_argument("--legacy-report", required=True); ap.add_argument("--address-c", required=True)
    a = ap.parse_args()
    rep = json.load(open(a.legacy_report, encoding="utf-8"))
    m = {}
    for r in rep["lifted"]:
        old = r["lift_name"]; addr = int(r["address"], 16)
        if old.startswith("gw_partial_") and not old.startswith("gw_partial_0x"): m[old[len("gw_partial_"):]] = "0x%08X" % addr
    pat = re.compile(r"gw_partial_([A-Za-z0-9_]+)")
    legacy = pathlib.Path(a.legacy_c).read_text(encoding="utf-8", errors="replace")
    norm = pat.sub(lambda mo: "gw_partial_" + m.get(mo.group(1), mo.group(1)), legacy)
    new = pathlib.Path(a.address_c).read_text(encoding="utf-8", errors="replace")
    la, lb = norm.split("\n"), new.split("\n")
    print("functions renamed from map-derived to address form:", len(m))
    print("identical after normalisation:", norm == new)
    print("same number of lines:", len(la) == len(lb), "| same multiset of lines:", collections.Counter(la) == collections.Counter(lb))
    diff = [i for i, (x, y) in enumerate(zip(la, lb)) if x != y]
    kinds = collections.Counter("forward declaration order" if la[i].startswith("extern void recomp_gw_partial_") else "other" for i in diff)
    print("differing line positions:", len(diff), dict(kinds))
    fa = re.findall(r"^void (gw_partial_[A-Za-z0-9_]+)\(void\) \{", norm, re.M); fb = re.findall(r"^void (gw_partial_[A-Za-z0-9_]+)\(void\) \{", new, re.M)
    print("function definitions:", len(fa), len(fb), "same set:", set(fa) == set(fb), "same order:", fa == fb)
if __name__ == "__main__":
    main()
