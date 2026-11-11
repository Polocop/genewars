"""Report which user-supplied inputs are present and correct (names and SHA-256 only; nothing is copied).

usage: python check_inputs.py [--install DIR] [--cue FILE] [--map FILE]
Defaults come from GENEWARS_INSTALL_DIR, GENEWARS_CUE and GENEWARS_MAP. Exit code 0 only if every input is present and matches;
1 otherwise. Each line says PASS, MISSING or MISMATCH so you can see exactly what is blocking the build (see inputs.json).
"""
import argparse, hashlib, json, os, re, sys
from pathlib import Path

def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""): h.update(chunk)
    return h.hexdigest()

def cue_report(cue, want):
    nonlocal_bad = 0
    label = "CD image cue (GENEWARS_CUE)"
    if not cue or not Path(cue).is_file():
        print(f"MISSING  {label}"); return 1
    if sha(cue) == want:
        print(f"PASS     {label}"); return 0
    # same disc content under a differently spelled cue sheet?
    prof = json.loads((Path(__file__).with_name("profiles") / "gw11-europe.json").read_text(encoding="utf-8"))["disc"]["tracks"]
    names = re.findall(r'FILE\s+"([^"]+)"', Path(cue).read_text(encoding="utf-8", errors="replace"))
    files = [Path(cue).parent / n for n in names]
    if len(files) == len(prof) and all(f.is_file() and f.stat().st_size == p["size"] and sha(f) == p["sha256"] for f, p in zip(files, prof)):
        print(f"PASS     {label}: different cue text, but all {len(prof)} track images match the version profile"); return 0
    print(f"MISMATCH {label}: neither the verified cue text nor track images matching the version profile ({len(files)} FILE entries)"); return 1

def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--install", default=os.environ.get("GENEWARS_INSTALL_DIR"))
    ap.add_argument("--cue", default=os.environ.get("GENEWARS_CUE"))
    ap.add_argument("--map", default=os.environ.get("GENEWARS_MAP"))
    a = ap.parse_args(argv)
    spec = json.loads((Path(__file__).with_name("inputs.json")).read_text(encoding="utf-8"))
    bad = 0
    def report(label, path, want):
        nonlocal bad
        if not path or not Path(path).is_file():
            print(f"MISSING  {label}"); bad += 1; return
        got = sha(path)
        if got == want: print(f"PASS     {label}")
        else: print(f"MISMATCH {label}\n         have {got}\n         want {want}"); bad += 1
    if not a.install: print("MISSING  GENEWARS_INSTALL_DIR is not set"); bad += 1
    else:
        roles = {f["path"]: f["role"] for f in json.loads((Path(__file__).with_name("profiles") / "gw11-europe.json").read_text(encoding="utf-8"))["install_files"]}
        for f in spec["install_files"]: report(f"{f['path']} [{roles.get(f['path'], '?')}]", Path(a.install) / f["path"], f["sha256"])
    bad += cue_report(a.cue, spec["cue"]["sha256"])
    if a.map:
        report("symbol map (GENEWARS_MAP, optional reference)", a.map, spec["map"]["sha256"])
    else:
        print("SKIPPED  symbol map (optional reference; the build does not need it)")
    print("ALL INPUTS PRESENT" if not bad else f"{bad} input(s) missing or different: Level B cannot run")
    print("roles: retail-disc = byte-identical to the file on the retail Europe disc; patch-1.1 = shipped by the 1.1 patch; local-config = written by the game installer; local-fixture = a file the maintainers created (cannot be reproduced; see docs/INPUTS.md)")
    return 1 if bad else 0

if __name__ == "__main__":
    sys.exit(main())
