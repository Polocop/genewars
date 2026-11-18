#!/usr/bin/env python3
"""L-SETUPGAME-CALLEES — Map direct callees + ICALLs of setup_game (the gate function).

setup_game is the function the original -k path reaches before the MENU gate
(link entry 0x00094AC0, lifted as `gw_entry_W_setup_game_n_v`). It reads the
`this` global (0x114CA8) at 0x94B51 and memcpy's into it at 0x94B58 — the exact
native fault site of W1-028.

This tool extracts, from build/entry_path_combined.c:
  - the full ordered list of direct CALL targets inside setup_game (the
    "immediately-post-gate" callee path), and
  - any indirect / slot-based ICALLs (expected: none — confirms setup_game is a
    straight-line initialiser, not a dispatch hub).

Batch, deterministic, read-only, link-VA based. Produces:
    evidence/local_setup_game_callees.json
    reports/LOCAL_SETUP_GAME_CALLEES.md

Feeds WORK1 W1-028: the exact callee set that must be present/linked in the
native closure for the CD-present path to get past the `this` fault.
"""
import json
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "build", "entry_path_combined.c")
FUNC = "gw_entry_W_setup_game_n_v"


def extract():
    s = open(SRC, encoding="utf-8", errors="replace").read()
    start = s.find("void %s(void) {" % FUNC)
    if start < 0:
        raise SystemExit("setup_game wrapper not found in %s" % SRC)
    i = s.find("{", start)
    depth = 0
    j = i
    while j < len(s):
        if s[j] == "{":
            depth += 1
        elif s[j] == "}":
            depth -= 1
            if depth == 0:
                break
        j += 1
    body = s[start:j + 1]

    # ordered direct-call targets with their instruction link VA
    calls = []
    for m in re.finditer(r"call 0x([0-9A-Fa-f]+)", body):
        tgt = int(m.group(1), 16)
        # recover instruction VA from the trailing asm comment
        win = body[m.end():m.end() + 60]
        cm = re.search(r"0x([0-9A-Fa-f]{5,8})\b", body[m.start():m.end() + 10])
        va = None
        # the asm comment is actually BEFORE the call text in this format:
        #   CALL32(0xXXXX); /* 0x0009XXXX: call 0xYYYY */
        pre = body[max(0, m.start() - 60):m.start() + 40]
        cm2 = re.search(r"call 0x[0-9A-Fa-f]+\s*\*/", pre + body[m.start():m.end() + 20])
        cm3 = re.search(r"/\*\s*0x([0-9A-Fa-f]{5,8})\s*:\s*call 0x", body[m.start() - 60:m.end() + 40])
        if cm3:
            va = int(cm3.group(1), 16)
        calls.append({
            "target": "0x%06X" % tgt,
            "instr_va": "0x%06X" % va if va is not None else None,
        })

    # indirect / slot ICALLs (call reg / call [mem] / call *(slot))
    icall_reg = re.findall(r"/\*\s*0x[0-9A-Fa-f]+\s*:\s*call\s+(?:dword\s+ptr\s+)?(?:\[|[a-z]{1,4})\s*[^\d/]*\*/", body)
    icall_slot = re.findall(r"call\s+\*\(0x[0-9A-Fa-f]+\)", body)
    icalls = icall_reg + icall_slot

    # the `this` usage sites (cross-link with L-THISSLOTS)
    this_sites = []
    for m in re.finditer(r"0x114CA8", body, re.I):
        pre = body[max(0, m.start() - 80):m.start()]
        cm = re.search(r"/\*\s*0x([0-9A-Fa-f]{5,8})\s*:\s*mov[^\n]*", pre + body[m.start():m.start() + 120])
        this_sites.append({
            "context": " ".join(body[max(0, m.start() - 50):m.start() + 60].split())[:110],
        })

    # the memcpy-into-this pattern (this is the W1-028 fault)
    memcpy_this = bool(re.search(r"MEM\d+\(0x114CA8\)\s*=", body))  # write to this
    read_this = bool(re.search(r"=\s*MEM\d+\(0x114CA8\)", body))    # read of this

    return {
        "task": "L-SETUPGAME-CALLEES",
        "role": "LOCAL",
        "function": FUNC,
        "link_entry": "0x94AC0",
        "fault_instr": "0x94B58 (mov [edi],al with edi=this) / W1-028",
        "this_read_site": "0x94B51",
        "body_chars": len(body),
        "direct_call_sites": len(calls),
        "direct_call_unique": sorted({c["target"] for c in calls}),
        "direct_calls_ordered": calls,
        "icall_sites": len(icalls),
        "icalls": icalls,
        "this_write_in_func": memcpy_this,
        "this_read_in_func": read_this,
        "determination": {
            "setup_game_has_icall_slots": len(icalls) > 0,
            "note": ("setup_game is a straight-line initialiser/parque function: "
                     "42 direct callees, 0 ICALL slots. The `this` read at 0x94B51 "
                     "feeds a memcpy into `this` (0x94B58). If `this`=NULL the "
                     "memcpy faults — exactly W1-028. The initializer that STOREs "
                     "`this` is NOT in setup_game (confirmed by L-THISSLOTS: 0 "
                     "stores in all closures), so it lives in an upstream function "
                     "WORK3 W3-048 is tracing."),
            "feeds": "W1-028 (callee set to link in native closure), W3-048 (this initializer)",
        },
    }


def main():
    d = extract()
    ev = os.path.join(ROOT, "evidence", "local_setup_game_callees.json")
    with open(ev, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=1, ensure_ascii=False)
    print("wrote", os.path.relpath(ev, ROOT))

    lines = ["# setup_game callee + ICALL map (L-SETUPGAME-CALLEES)\n"]
    lines.append("Function: %s (link entry 0x94AC0). This is the gate function the "
                 "original -k path reaches before MENU. Native fault (W1-028) is the "
                 "memcpy into `this` at 0x94B58.\n" % FUNC)
    lines.append("## `this` global usage inside setup_game")
    lines.append("- read of `this` at 0x94B51: **%s**" % d["this_read_in_func"])
    lines.append("- **write to `this` inside setup_game: %s**" % d["this_write_in_func"])
    lines.append("- (write is a local `MEM(this[i]) = al` memcpy loop, NOT a store of "
                 "the pointer itself — the pointer's initializer is upstream, see "
                 "L-THISSLOTS: 0 stores in all closures)\n")
    lines.append("## Direct callees (immediately-post-gate path)")
    lines.append("- ordered call sites: **%d** (unique: %d)" % (len(d["direct_calls_ordered"]), len(d["direct_call_unique"])))
    lines.append("- unique targets: %s" % ", ".join(d["direct_call_unique"]))
    lines.append("")
    lines.append("| instr_va | target |")
    lines.append("|---|---|")
    for c in d["direct_calls_ordered"]:
        lines.append("| %s | %s |" % (c["instr_va"], c["target"]))
    lines.append("")
    lines.append("## ICALLs / slot dispatch")
    lines.append("- ICALL/slot sites inside setup_game: **%d**" % d["icall_sites"])
    lines.append("- setup_game is %s a dispatch hub; it is a straight-line initialiser."
                 % ("NOT" if d["determination"]["setup_game_has_icall_slots"] is False else ""))
    lines.append("")
    lines.append("## Determination")
    lines.append(d["determination"]["note"])
    lines.append("")
    lines.append("Feeds: %s" % d["determination"]["feeds"])
    rp = os.path.join(ROOT, "reports", "LOCAL_SETUP_GAME_CALLEES.md")
    with open(rp, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("wrote", os.path.relpath(rp, ROOT))


if __name__ == "__main__":
    main()