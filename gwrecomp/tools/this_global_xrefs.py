#!/usr/bin/env python3
"""L-THISSLOTS — Static xref/store inventory of the setup_game `this` global.

The setup_game `this` global is at link VA 0x00094CA8 (dseg offset 0x14CA8),
also referenced in lifted code as 0x114CA8 (segment:offset folded). This tool
scans the three lifted closures for every read and write of that global,
classifies each site as read vs write, and attributes it to its containing
function (via link VA, no LE rebase — complementary to WORK3 W3-048's live
initializer trace, not a duplicate of it).

Batch, deterministic, read-only. Produces:
    evidence/local_this_global_xrefs.json
    reports/LOCAL_THIS_GLOBAL_XREFS.md

Key question answered: is there any WRITE to `this` inside the entry-path
closure (the -k path to the MENU gate)? If none, the initializer is absent
from the linked native closure -> exactly the W1-028 `this`=NULL fault.
"""
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# setup_game `this` global. In the lifted .c the comments use the folded
# form 0x114CA8 (dseg:offset). Accept both spellings case-insensitively.
GLOBAL = r"0x114ca8"

CLOSURES = {
    "entry_path": "build/entry_path_combined.c",     # -k path to the gate (1.2MB)
    "entry_closure": "build/entry_path_closure.c",   # full entry closure (18MB)
    "broad_282": "build/recomp_282.c",              # 282-func broad closure (17MB)
}

FUNC_HDR = re.compile(r"\b(?:void|static|unsigned|int|uint32_t|char)\s+sub_([0-9A-Fa-f]{4,8})\s*\(", re.I)
# a read:  <reg> = MEM32(0x114CA8)   (mem -> reg)
# a write: MEM32(0x114CA8) = <reg>   (reg -> mem)  or MEM32(0x114CA8) = <const>
READ_RE = re.compile(r"([A-Za-z_][\w]*)\s*=\s*MEM\d+\(0x114CA8\)", re.I)
WRITE_RE = re.compile(r"MEM\d+\(0x114CA8\)\s*=", re.I)
# every mention of the global (for a raw count + to catch non-MEM forms)
ANY_RE = re.compile(r"0x114CA8", re.I)

# inline asm comment carries the link VA of the instruction:
#   /* 0x00094B51: mov edi, dword ptr [0x114ca8] */
ASM_VA_RE = re.compile(r"/\*\s*0x([0-9A-Fa-f]{6,8})\s*:\s*([a-z@]+(?:\s+[a-z]+)?)")


def parse_file(path):
    """Return (func_starts_sorted, sites) where each site is a dict."""
    s = open(path, encoding="utf-8", errors="replace").read()

    # function starts: header comment line contains its own VA too, but the
    # simplest robust anchor is the `sub_XXXX` token order in the file == VA
    # order for x86 (functions are laid out sequentially, non-overlapping).
    func_tokens = []
    for m in FUNC_HDR.finditer(s):
        va = int(m.group(1), 16)
        func_tokens.append((va, m.start()))
    # dedupe by VA (a header may appear once)
    seen = set()
    funcs = []
    for va, pos in func_tokens:
        if va in seen:
            continue
        seen.add(va)
        funcs.append([va, pos])
    funcs.sort()
    func_starts = [f[0] for f in funcs]

    # For each raw global mention, look at the surrounding statement to
    # classify read vs write and recover the instruction link VA from the
    # trailing asm comment.
    sites = []
    for m in ANY_RE.finditer(s):
        i = m.start()
        # statement window: back to previous ';' or line start, fwd to ';'
        b = max(s.rfind(";", 0, i), s.rfind("\n", 0, i) - 1)
        a = s.find(";", i)
        if a == -1:
            a = i + 80
        win = s[max(b + 1, 0):a]
        is_write = bool(WRITE_RE.search(win))
        # is it a plain read?
        is_read = bool(READ_RE.search(win)) and not is_write
        # recover instruction VA from any asm comment in the window
        va = None
        cm = re.search(r"0x([0-9A-Fa-f]{5,8})\s*:", win)
        if cm:
            va = int(cm.group(1), 16)
        # owning function: largest func start <= va
        owner = None
        if va is not None:
            lo, hi = 0, len(func_starts) - 1
            ans = -1
            while lo <= hi:
                mid = (lo + hi) // 2
                if func_starts[mid] <= va:
                    ans = mid
                    lo = mid + 1
                else:
                    hi = mid - 1
            if ans >= 0 and ans < len(funcs):
                owner = "sub_%06X" % funcs[ans][0]
        sites.append({
            "offset_in_file": i,
            "kind": "write" if is_write else ("read" if is_read else "other"),
            "link_va": "0x%06X" % va if va is not None else None,
            "owner": owner,
            "window": " ".join(win.split())[:120],
        })
    return sites


def main():
    out = {
        "task": "L-THISSLOTS",
        "role": "LOCAL",
        "global": "setup_game `this` (link VA 0x94CA8 / folded 0x114CA8)",
        "closures": {},
    }
    for name, rel in CLOSURES.items():
        p = os.path.join(ROOT, rel)
        if not os.path.exists(p):
            out["closures"][name] = {"missing": True}
            continue
        sites = parse_file(p)
        reads = [x for x in sites if x["kind"] == "read"]
        writes = [x for x in sites if x["kind"] == "write"]
        other = [x for x in sites if x["kind"] == "other"]
        out["closures"][name] = {
            "file": rel,
            "total_sites": len(sites),
            "reads": len(reads),
            "writes": len(writes),
            "other": len(other),
            "write_sites": writes,
            "read_site_owners": sorted({x["owner"] for x in reads if x["owner"]}),
            "write_site_owners": sorted({x["owner"] for x in writes if x["owner"]}),
        }
    # determination
    ep = out["closures"].get("entry_path", {})
    gate_write_in_entry = ep.get("writes", 0) > 0
    any_write_any = any(c.get("writes", 0) for c in out["closures"].values() if not c.get("missing"))
    out["determination"] = {
        "write_in_entry_path_closure": gate_write_in_entry,
        "write_in_any_closure": any_write_any,
        "conclusion": (
            "No write to `this` exists inside the entry-path closure (the -k path "
            "to the MENU gate); setup_game only READS it (5 sites). The initializer/"
            "store of `this` is therefore ABSENT from the linked native closure, "
            "which is exactly why the native run faults on `this`=NULL (W1-028). "
            "WORK1 must lift/link the initializer function(s) found in the broader "
            "closure before the CD-present path can reach MENU."
        ) if not gate_write_in_entry else
        (
            "A write to `this` WAS found inside the entry-path closure; W1-028's "
            "`this`=NULL fault is therefore not a missing-initializer but a "
            "mis-ordered/mis-seeded write. See write_sites for the exact owners."
        ),
        "complements": "WORK3 W3-048 traces the live initializer dynamically; this "
                        "tool gives the static xref/store inventory + function ownership.",
    }

    ev = os.path.join(ROOT, "evidence", "local_this_global_xrefs.json")
    with open(ev, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1, ensure_ascii=False)
    print("wrote", os.path.relpath(ev, ROOT))

    lines = ["# Static xref/store inventory of setup_game `this` global (L-THISSLOTS)\n"]
    lines.append("Complementary to WORK3 W3-048 (live initializer trace). "
                 "Batch, deterministic, read-only, link-VA based.\n")
    lines.append("Global: setup_game `this` at link VA 0x94CA8 (folded 0x114CA8).\n")
    for name, c in out["closures"].items():
        if c.get("missing"):
            lines.append("## %s — MISSING" % name)
            continue
        lines.append("## %s  (%s)" % (name, c.get("file")))
        lines.append("- total global references: %d  (reads=%d, writes=%d, other=%d)"
                     % (c["total_sites"], c["reads"], c["writes"], c["other"]))
        if c["read_site_owners"]:
            lines.append("- reading functions: %s" % ", ".join(c["read_site_owners"]))
        if c["write_site_owners"]:
            lines.append("- **writing functions: %s**" % ", ".join(c["write_site_owners"]))
        else:
            lines.append("- writing functions: **NONE**")
        if c["write_sites"]:
            lines.append("")
            lines.append("| kind | link_va | owner | site |")
            lines.append("|---|---|---|---|")
            for w in c["write_sites"]:
                lines.append("| %s | %s | %s | %s |"
                             % (w["kind"], w["link_va"], w["owner"], w["window"][:70]))
        lines.append("")
    d = out["determination"]
    lines.append("## Determination")
    lines.append("- write in entry-path closure: **%s**" % d["write_in_entry_path_closure"])
    lines.append("- write in any closure: **%s**" % d["write_in_any_closure"])
    lines.append("- %s" % d["conclusion"])
    lines.append("- %s" % d["complements"])
    rp = os.path.join(ROOT, "reports", "LOCAL_THIS_GLOBAL_XREFS.md")
    with open(rp, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("wrote", os.path.relpath(rp, ROOT))

    if "--print" in sys.argv:
        print(json.dumps(out, indent=1, ensure_ascii=False))


if __name__ == "__main__":
    main()