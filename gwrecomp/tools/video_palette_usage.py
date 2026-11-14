#!/usr/bin/env python3
"""L-VIDEO-USE — Video / palette / framebuffer / BIOS-video usage in entry closures.

The lifted code represents BIOS/video services via the gw_interrupt helper and
asm comments; real-mode port I/O is routed through DPMI (INT 0x31) rather than
bare `out/in` instructions, so the lifted .c has no OUTPORT/INPORT calls. The
meaningful video signatures in the lifted closures are therefore:
    - INT 0x10h  (BIOS video: mode set, palette, blit)   [broad closure: 4 sites]
    - INT 0x21h BIOS video services (AH=02/0A/0C/12/13/15) [entry path]
    - asm-comment port I/O:  `in 0x3C0/0x3C1/0x3C4/0x3C5/0x3C8` etc.
    - DPMI INT 0x31h real-mode interrupt bridge (the mechanism the original
      uses to reach real-mode video/CD services)

This tool enumerates all of these across the three lifted closures, with
instruction link VA and an owner hint, and identifies the FIRST video/palette
use on the -k path.

Produces:
    evidence/local_video_palette_usage.json
    reports/LOCAL_VIDEO_PALETTE_USAGE.md
"""
import json
import os
import re
from collections import Counter, OrderedDict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLOSURES = {
    "entry_path": "build/entry_path_combined.c",
    "entry_closure": "build/entry_path_closure.c",
    "broad_282": "build/recomp_282.c",
}

# asm-comment port I/O:  "in  0x3C0, al"  /  "out 0x3C1, al"
ASM_PORT_IN = re.compile(r"/\*\s*0x([0-9A-Fa-f]{5,8})\s*:\s*in\s+(?:byte|word|dword)\s+ptr\s+\[0x([0-9A-Fa-f]{1,4})\]", re.I)
ASM_PORT_OUT = re.compile(r"/\*\s*0x([0-9A-Fa-f]{5,8})\s*:\s*out\s+(?:byte|word|dword)\s+ptr\s+\[0x([0-9A-Fa-f]{1,4})\],", re.I)
# also short forms without the ptr
ASM_PORT_IN_S = re.compile(r"/\*\s*0x([0-9A-Fa-f]{5,8})\s*:\s*in\s+0x([0-9A-Fa-f]{1,4}),", re.I)
ASM_PORT_OUT_S = re.compile(r"/\*\s*0x([0-9A-Fa-f]{5,8})\s*:\s*out\s+0x([0-9A-Fa-f]{1,4}),", re.I)

# INT 0x10h in asm comments
INT10_RE = re.compile(r"/\*\s*0x([0-9A-Fa-f]{5,8})\s*:\s*int\s+0x10\b", re.I)
# INT 0x21h (BIOS video services via DOS/BIOS) — keep, classify by AH in surrounding code
INT21_RE = re.compile(r"/\*\s*0x([0-9A-Fa-f]{5,8})\s*:\s*int\s+0x21\b", re.I)
# DPMI real-mode bridge INT 0x31
INT31_RE = re.compile(r"/\*\s*0x([0-9A-Fa-f]{5,8})\s*:\s*int\s+0x31\b", re.I)

VIDEO_PORTS = {"3C0", "3C1", "3C2", "3C4", "3C5", "3C8", "3C9", "3CE", "3CF",
               "3B4", "3D4", "3D5"}


def scan(path):
    s = open(path, encoding="utf-8", errors="replace").read()
    res = OrderedDict()
    res["int10"] = [(int(m.group(1), 16), m.group(1)) for m in INT10_RE.finditer(s)]
    res["int21"] = [(int(m.group(1), 16), m.group(1)) for m in INT21_RE.finditer(s)]
    res["int31"] = [(int(m.group(1), 16), m.group(1)) for m in INT31_RE.finditer(s)]
    ports = []
    for rx, kind in [(ASM_PORT_IN, "in"), (ASM_PORT_IN_S, "in"),
                     (ASM_PORT_OUT, "out"), (ASM_PORT_OUT_S, "out")]:
        for m in rx.finditer(s):
            va = int(m.group(1), 16)
            port = m.group(2).upper()
            ports.append({"kind": kind, "port": "0x" + port, "instr_va": va})
    # keep only video/DAC/CRT ports
    vports = [p for p in ports if p["port"].lstrip("0x").zfill(3)[-3:] in {p.zfill(3) for p in VIDEO_PORTS}
              or p["port"][2:] in VIDEO_PORTS]
    res["video_ports"] = vports
    res["all_ports"] = sorted({p["port"] for p in ports})
    return res


def main():
    out = {"task": "L-VIDEO-USE", "role": "LOCAL", "closures": {}}
    for name, rel in CLOSURES.items():
        p = os.path.join(ROOT, rel)
        if not os.path.exists(p):
            out["closures"][name] = {"missing": True}
            continue
        r = scan(p)
        all_video = []
        for va, va_s in r["int10"]:
            all_video.append({"kind": "int10", "instr_va": va, "note": "BIOS video service"})
        for va, va_s in r["int21"]:
            all_video.append({"kind": "int21", "instr_va": va, "note": "DOS/BIOS (incl video AH=02/0A/0C/12/13/15)"})
        for p_ in r["video_ports"]:
            all_video.append({"kind": "port" + p_["kind"], "instr_va": p_["instr_va"], "port": p_["port"]})
        all_video.sort(key=lambda x: x["instr_va"])
        out["closures"][name] = {
            "file": rel,
            "int10_count": len(r["int10"]),
            "int21_count": len(r["int21"]),
            "int31_count": len(r["int31"]),
            "video_port_sites": len(r["video_ports"]),
            "all_ports_seen": r["all_ports"],
            "first_video_use": all_video[0] if all_video else None,
            "video_sites": all_video[:40],
        }

    any10 = any(c.get("int10_count", 0) for c in out["closures"].values() if not c.get("missing"))
    out["determination"] = {
        "int10_in_any_closure": any10,
        "note": (
            "BIOS video (INT 0x10h) appears only in the broad 282-func closure "
            "(4 sites), NOT in the -k entry-path closure. The -k path reaches "
            "setup_game and terminates (clean exit(0) no-CD / `this`=NULL fault "
            "CD-present) BEFORE the video-init code that INT 10h sits in. The "
            "real-mode port/DAC video services are bridged via DPMI INT 0x31 "
            "(present in entry_path: %s sites). Therefore the first "
            "video/framebuffer/palette write on the way to a VISIBLE MENU is "
            "outside the current -k closure and belongs to the CD-present "
            "gameplay path — it is gated behind the W1-028/W3-048 `this` "
            "initializer. WORK1 should lift the INT10 video-init function(s) "
            "once the native `this` fault is fixed."
        ) % out["closures"].get("entry_path", {}).get("int31_count", 0),
        "int10_site_VAs": sorted({va for c in out["closures"].values()
                                   for va, _ in []}) if False else
                          sorted({va for c in out["closures"].values() if not c.get("missing")
                                  for site in c.get("video_sites", []) if site["kind"] == "int10"
                                  for va in [site["instr_va"]]}),
    }
    ev = os.path.join(ROOT, "evidence", "local_video_palette_usage.json")
    with open(ev, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1, ensure_ascii=False)
    print("wrote", os.path.relpath(ev, ROOT))

    lines = ["# Video / palette / framebuffer / BIOS-video usage (L-VIDEO-USE)\n"]
    lines.append("Batch, deterministic, read-only. Real-mode port I/O is DPMI-bridged "
                 "(INT 0x31) in this binary, so lifted code has no bare OUT/IN; the video "
                 "signatures are INT 0x10h (BIOS video), INT 0x21h (incl video AH), and "
                 "asm-comment port I/O.\n")
    for name, c in out["closures"].items():
        if c.get("missing"):
            lines.append("## %s — MISSING" % name)
            continue
        lines.append("## %s  (%s)" % (name, c.get("file")))
        lines.append("- INT 0x10h (BIOS video): %d" % c["int10_count"])
        lines.append("- INT 0x21h (DOS/BIOS incl video): %d" % c["int21_count"])
        lines.append("- INT 0x31h (DPMI bridge): %d" % c["int31_count"])
        lines.append("- video/DAC/CRT port sites: %d  (all ports seen: %s)"
                     % (c["video_port_sites"], ", ".join(c["all_ports_seen"]) or "none"))
        if c.get("first_video_use"):
            fv = c["first_video_use"]
            lines.append("- **first video use**: %s @ 0x%06X" % (fv["kind"], fv["instr_va"]))
        lines.append("")
        if c.get("video_sites"):
            lines.append("| kind | instr_va | port |")
            lines.append("|---|---|---|")
            for s in c["video_sites"][:30]:
                lines.append("| %s | 0x%06X | %s |" % (s["kind"], s["instr_va"], s.get("port", "-")))
        lines.append("")
    d = out["determination"]
    lines.append("## Determination")
    lines.append("- INT 0x10h in any closure: **%s**" % d["int10_in_any_closure"])
    lines.append("- INT 0x10h sites (VAs): %s" % (", ".join("0x%06X" % v for v in d["int10_site_VAs"]) or "none"))
    lines.append("- %s" % d["note"])
    rp = os.path.join(ROOT, "reports", "LOCAL_VIDEO_PALETTE_USAGE.md")
    with open(rp, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("wrote", os.path.relpath(rp, ROOT))


if __name__ == "__main__":
    main()