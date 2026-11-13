#!/usr/bin/env python3
"""Report long hex byte literals in tests/, tools/, runtime/ (Issue #4 provenance check).

Looks for C-style arrays (0xNN, 0xNN, ...) and Python/other hex strings / bytes.fromhex literals.
Usage: python tools/scan_hex_literals.py [--min-c 8] [--min-hex 16]   exit 1 when something at/above the threshold is found.
"""
import argparse, os, re, sys

ap = argparse.ArgumentParser()
ap.add_argument("--min-c", type=int, default=8, help="shortest C array (bytes) to report")
ap.add_argument("--keep-digests", action="store_true", help="also report 20-byte (SHA-1) and 32-byte (SHA-256) strings, normally digests")
ap.add_argument("--min-hex", type=int, default=16, help="shortest hex string (bytes) to report")
a = ap.parse_args()
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
c_re = re.compile(r"(?:0x[0-9a-fA-F]{2}\s*,\s*){%d,}0x[0-9a-fA-F]{2}" % (a.min_c - 1))
h_re = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}[ _]?){%d,}(?![0-9a-fA-F])" % a.min_hex)
found = 0
for top in ("tests", "tools", "runtime"):
    for dp, dn, fn in os.walk(os.path.join(root, top)):
        dn[:] = [d for d in dn if d not in (".venv", "__pycache__", "fixtures")]
        for f in fn:
            if not f.endswith((".c", ".h", ".py", ".ps1", ".json")) or f == os.path.basename(__file__):
                continue
            p = os.path.join(dp, f)
            try:
                t = open(p, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            for m in c_re.finditer(t):
                n = m.group(0).count("0x")
                print(f"C-array {n:4d} bytes  {os.path.relpath(p, root)}:{t.count(chr(10), 0, m.start()) + 1}"); found += 1
            if f.endswith(".py"):
                for m in re.finditer(r"""(?:bytes\.fromhex\(|b?["'])([0-9a-fA-F ]{%d,})["']""" % (a.min_hex * 2), t):
                    n = len(re.sub(r"\s", "", m.group(1))) // 2
                    if n in (20, 32) and not a.keep_digests:
                        continue
                    print(f"hex-str {n:4d} bytes  {os.path.relpath(p, root)}:{t.count(chr(10), 0, m.start()) + 1}"); found += 1
print(f"{found} literal(s) at or above the threshold (C >= {a.min_c} bytes, hex string >= {a.min_hex} bytes)")
sys.exit(1 if found else 0)
