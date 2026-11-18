"""Measure what an (optional, private) reference symbol map contains and how much of it can be checked against GW.EXE.

usage: python measure_reference_map.py --map genewars-1_1.map --exe GW.EXE [--disc-map MAIN.MAP]
Prints AGGREGATE COUNTS ONLY (no symbol names, no addresses), so the output is safe to paste into an issue.

Entry classes (by the shape of the name):
  ida-switch   jpt_XXXX / def_XXXX  disassembler switch-table analysis (jump table / default case label)
  ida-string   aCamelCase           disassembler label for a C string
  ida-other    nullsub_N, unknown_libname_N, loc_/sub_...
  watcom-c     names with the Watcom C convention (trailing underscore) and C-library names
  cpp-mangled  W?name$...           Watcom-mangled C++ names
Checks that need only GW.EXE:
  jpt  : the address starts a run of >= 2 consecutive 4-byte slots that carry LE fixups
  def  : the address lies inside executable code
  string: the address holds a printable NUL-terminated string
With --disc-map (the Watcom linker map shipped on the retail disc, a different build) it also counts how many plain names
appear verbatim in it.
"""
import argparse, collections, pathlib, re, sys
HERE = pathlib.Path(__file__).resolve()
sys.path.insert(0, str(HERE.parents[3] / "src"))
from le_loader import load_le  # noqa: E402

def parse_map(path):
    ent = []
    for l in pathlib.Path(path).read_text(errors="replace").splitlines():
        m = re.match(r"^ ([0-9A-Fa-f]{4}):([0-9A-Fa-f]{8})\s+(\S+)\s*$", l)
        if m: ent.append((int(m.group(1), 16), int(m.group(2), 16), m.group(3)))
    return ent

def kind(n):
    if re.match(r"^(jpt|def)_[0-9A-Fa-f]+$", n): return "ida-switch"
    if re.match(r"^a[A-Z]\w*$", n): return "ida-string"
    if re.match(r"^(nullsub|loc|sub)_\w+$", n) or n.startswith("unknown_libname"): return "ida-other"
    if n.startswith("W?"): return "cpp-mangled"
    return "watcom-c"

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--map", required=True); ap.add_argument("--exe", required=True); ap.add_argument("--disc-map")
    a = ap.parse_args()
    ent = [e for e in parse_map(a.map) if not re.fullmatch(r"0000\w+H", e[2])]
    img = load_le(pathlib.Path(a.exe)); fix = {f.source_link for f in img.fixups}
    tot = collections.Counter(kind(n) for _, _, n in ent)
    print("entries:", len(ent), dict(tot))
    ok = collections.Counter(); bad = collections.Counter()
    for seg, off, n in ent:
        k = kind(n)
        if n.startswith("jpt_"):
            run = 0
            while (off + 4 * run) in fix and run < 4096: run += 1
            (ok if run >= 2 else bad)["jpt"] += 1
        elif n.startswith("def_"):
            o = img.object_containing(off); (ok if o is not None and o.executable else bad)["def"] += 1
        elif k == "ida-string":
            o = img.object_containing(off); good = False
            if o is not None:
                data = bytes(img.object_data(o.index)); rel = off - o.base
                if 0 <= rel < len(data):
                    end = data.find(b"\0", rel); s = data[rel:end] if end >= 0 else b""
                    good = len(s) >= 1 and all(32 <= c < 127 or c in (9, 10, 13) for c in s)
            (ok if good else bad)["string"] += 1
    print("verifiable from GW.EXE alone (ok / not ok):", {k: (ok[k], bad[k]) for k in ("jpt", "def", "string")})
    mech = sum(ok.values()); print("entries whose address is mechanically confirmed: %d of %d (%.1f%%)" % (mech, len(ent), 100 * mech / len(ent)))
    if a.disc_map:
        dm = set()
        for l in pathlib.Path(a.disc_map).read_text(errors="replace").splitlines():
            m = re.match(r"^[0-9a-f]{4}:[0-9a-f]{8}[+*]?\s+(.*\S)\s*$", l)
            if m: dm.add(m.group(1))
        plain = [n for _, _, n in ent if kind(n) == "watcom-c"]
        print("watcom-c names appearing verbatim in the disc map: %d of %d" % (sum(1 for n in plain if n in dm), len(plain)))
        print("(cpp-mangled names are the mangled form of the disc map's demangled C++ signatures; they are not compared here)")
if __name__ == "__main__":
    main()
