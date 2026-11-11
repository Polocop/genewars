"""Report which user-supplied inputs are present and correct (names and SHA-256 only; nothing is copied).

usage: python check_inputs.py [--install DIR] [--cue FILE] [--map FILE]
Defaults come from GENEWARS_INSTALL_DIR, GENEWARS_CUE and GENEWARS_MAP. Exit code 0 only if every input is present and matches;
1 otherwise. Each line says PASS, MISSING or MISMATCH so you can see exactly what is blocking the build (see inputs.json).
"""
import argparse, hashlib, json, os, sys
from pathlib import Path

def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""): h.update(chunk)
    return h.hexdigest()

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
        for f in spec["install_files"]: report(f["path"], Path(a.install) / f["path"], f["sha256"])
    report("CD image cue (GENEWARS_CUE)", a.cue, spec["cue"]["sha256"])
    report("symbol map (GENEWARS_MAP)", a.map, spec["map"]["sha256"])
    print("ALL INPUTS PRESENT" if not bad else f"{bad} input(s) missing or different: Level B cannot run")
    return 1 if bad else 0

if __name__ == "__main__":
    sys.exit(main())
