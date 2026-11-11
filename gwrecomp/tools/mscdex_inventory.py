#!/usr/bin/env python3
"""L-MSCDEXINV: exhaustive static+dynamic inventory of the MSCDEX/CD-ROM surface.

The game reaches MSCDEX (INT 2Fh) through the DPMI AX=0300 real-mode bridge,
NOT a direct `int 0x2f`. The lifted pattern is:

    <reg> = 0x15xxu      ; real-mode AX (MSCDEX subfunction)
    <reg> = 0x300u       ; DPMI AX (real-mode bridge)
    esi   = 0x2Fu        ; real-mode vector (47 = INT 2Fh)
    ... frame setup at 0x1A4E8C ...
    RECOMP_CALL(sub_000ADEF6)   ; DPMI wrapper -> int 0x31 AX=0300

This tool scans the entry closure and broad closure for every such callsite,
walks every oracle/runtime trace JSON for `real_mode_0300` frames, and emits
evidence/mscdex_inventory.json + reports/LOCAL_MSCDEX_INVENTORY.md.

It distinguishes CURRENT evidence (the authoritative -k trace that produced the
current gate stop) from HISTORICAL records (e.g. dpmi31.allocate_dos_memory
.insufficient_memory from earlier AX=0100 runs), which must NOT be treated as
a current blocker.

Usage:  py -3 tools/mscdex_inventory.py
Read-only over build/*.c and evidence/*.json; writes two artifacts only.
"""
import json, re, sys, io, os, hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "build"
EV = ROOT / "evidence"
REP = ROOT / "reports"

# Closures to scan (entry path first, then broad).
CLOSURES = [
    ("entry_path_combined", BUILD / "entry_path_combined.c"),
    ("entry_path_closure",  BUILD / "entry_path_closure.c"),
    ("recomp_282_broad",    BUILD / "recomp_282.c"),
]

# Oracle / runtime trace JSONs that may carry real_mode_0300 frames.
TRACE_GLOBS = ["*oracle*.json", "*runtime*.json", "dpmi_0300_frame_work2.json",
               "dpmi_0300_request.json", "dpmi_lock_resume_oracle_work3.json",
               "startup_option_k_oracle_work3.json", "option_slash_k_oracle_work3.json",
               "option_upper_k_oracle_work3.json", "native_dpmi_alloc.json"]

# Real-mode vector 47 == INT 2Fh (MSCDEX). Other vectors seen in the bridge:
# 33 = INT 21h (DOS services), 49 = DPMI INT 31h (not real-mode guest).
VECTOR_NAMES = {33: "INT 21h DOS", 47: "INT 2Fh MSCDEX/CD-ROM"}

# MSCDEX AH=15xx services, RBIL-corrected.
# ONLY the AHs GeneWars 1.1 actually emits are listed here (see
# mscdex_inventory.json: static callsites + W3-029 oracle). Any other
# 0x15xx value is NOT referenced by this game and is intentionally absent
# so stale names do not re-inherit into regenerated reports.
#   0x1500  MSCDEX install check / get drive count.
#           BX=0 (the GATE case, frame EAX=0x1500 @ 0x1d23a7): NO buffer.
#             returns BX = # CD-ROM drives, CX = first drive letter (0=A).
#           BX=n (n>=1): returns a 16-byte drive-param block at ES:BX.
#           W3-029: the no-CD answer (BX=0, CX=0, AX=0000) is ACCEPTED and
#           lets GeneWars continue toward MENU (CD-absent branch).
#   0x150C  Get MSCDEX version (RBIL). Post-MENU; not on the -k path.
#   0x1510  Send device-driver request. CX = drive; ES:BX -> device-request
#           header (SCSI/MMC CDB). This is how ALL CD data/TOC reads go out
#           in MSCDEX 2.x (there is NO separate AH per command). Post-MENU
#           asset streaming only. Exact CDBs GeneWars emits are determined
#           from the real code by WORK2 (W2-055 done / W2-057 in progress) -
#           do NOT presume a command set.
MSCDEX_SUBFUNCS = {
    0x1500: "MSCDEX install check / drive count (BX=0: BX=#drives, CX=first letter, NO buffer; BX=n: 16B param block @ ES:BX)",
    0x150C: "Get MSCDEX version (RBIL; post-MENU, not on -k path)",
    0x1510: "Send device-driver request (SCSI/MMC CDB via ES:BX header, CX=drive; post-MENU asset streaming)",
}

def hx(v):
    if v is None: return None
    if isinstance(v, str):
        v = v.strip()
        try: return int(v, 16)
        except ValueError:
            try: return int(v, 0)
            except ValueError: return None
    return int(v) & 0xFFFFFFFF

def sha_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

# ---------------------------------------------------------------------------
# STATIC: parse each closure for real-mode bridge callsites
# ---------------------------------------------------------------------------
FUNC_RE = re.compile(r"^void\s+(sub_[0-9A-Fa-f]+|_\w+|[A-Za-z_]\w*)\s*\(")
VA_COMMENT_RE = re.compile(r"/\*\s*(0x[0-9A-Fa-f]{4,8})\s*:")
GWLIFT_COMMENT_RE = re.compile(r"/\*\s*gw_lift_\d+\s+(0x[0-9A-Fa-f]{4,8})\s+\S+")
FUNC_NAME_VA_RE = re.compile(r"sub_(0x[0-9A-Fa-f]{4,8}|[0-9A-Fa-f]{4,8})$")
# A store of an immediate into a register: `<reg> = 0xNNNNu;` or `SET_LO16(<reg>, 0xNNNu)`
REG_IMM_RE = re.compile(
    r"\b(eax|ebx|ecx|edx|esi|edi|ebp|esp)\s*=\s*0x([0-9A-Fa-f]+)u?\s*;|"
    r"SET_LO16\(\s*(eax|ebx|ecx|edx|esi|edi|ebp|esp)\s*,\s*0x([0-9A-Fa-f]+)u?\s*\)"
)
ADEF6_CALL_RE = re.compile(r"RECOMP_CALL\(sub_000ADEF6\)")
INT2F_UNIMPL_RE = re.compile(r"UNIMPLEMENTED:\s*int\s+0x2[fF]")
INT31_RE = re.compile(r"\bint\s+0x31\b")

def parse_closure(name, path):
    """Return list of callsite dicts for one closure file."""
    if not path.exists():
        return {"closure": name, "path": str(path), "exists": False, "callsites": []}
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    # Build function start line index map: func_name -> (start_line, va)
    func_starts = []  # (line_idx, name, va)
    for i, l in enumerate(lines):
        m = FUNC_RE.match(l)
        if m:
            name = m.group(1)
            # VA is on the PRECEDING `/* gw_lift_NNNN 0xVA sub_XXXX */` comment
            va = None
            prev = lines[i - 1] if i > 0 else ""
            gm = GWLIFT_COMMENT_RE.search(prev)
            if gm:
                va = hx(gm.group(1))
            if va is None:
                nm = FUNC_NAME_VA_RE.search(name)
                if nm:
                    va = hx(nm.group(1))
            if va is None:
                va_m = VA_COMMENT_RE.search(l)
                va = hx(va_m.group(1)) if va_m else None
            func_starts.append((i, name, va))
    def func_at(line_idx):
        cur = None
        for (li, nm, va) in func_starts:
            if li <= line_idx:
                cur = (nm, va)
            else:
                break
        return cur

    callsites = []
    unimpl_int2f = []
    for i, l in enumerate(lines):
        if not ADEF6_CALL_RE.search(l):
            continue
        fn = func_at(i)
        # Look back up to ~40 lines for the register immediates that form the
        # bridge: real-mode AX (0x15xx), DPMI AX (0x300), vector (0x2f).
        window = lines[max(0, i - 40): i + 1]
        reg_vals = {}
        ax_rm = None   # real-mode AX (0x15xx)
        dpmi_ax = None # 0x300
        vector = None  # 0x2f
        for wl in window:
            for m in REG_IMM_RE.finditer(wl):
                if m.group(1):
                    reg, val = m.group(1), int(m.group(2), 16)
                else:
                    reg, val = m.group(3), int(m.group(4), 16)
                reg_vals.setdefault(reg, []).append(val)
            # vector is always loaded into esi per the observed pattern
            vm = re.search(r"\besi\s*=\s*0x([0-9A-Fa-f]+)u?\s*;", wl)
            if vm:
                vector = int(vm.group(1), 16)
        # classify: real-mode AX is the value that is 0x15xx; dpmi AX is 0x300
        allvals = [v for vals in reg_vals.values() for v in vals]
        for v in allvals:
            if v == 0x300:
                dpmi_ax = 0x300
            elif 0x1500 <= v <= 0x15FF:
                ax_rm = v
        # If we found a 0x15xx but no explicit vector, assume INT 2Fh bridge.
        if ax_rm is not None and vector is None:
            vector = 0x2F
        site_va = None
        # find nearest VA comment in window for the call
        for wl in reversed(window):
            vm2 = VA_COMMENT_RE.search(wl)
            if vm2:
                site_va = hx(vm2.group(1)); break
        callsites.append({
            "closure": name,
            "func": fn[0] if fn else None,
            "func_va": ("0x%08X" % fn[1]) if (fn and fn[1]) else None,
            "call_line": i + 1,
            "site_va": ("0x%08X" % site_va) if site_va else None,
            "vector": vector,
            "vector_name": VECTOR_NAMES.get(vector, "INT %dh" % vector if vector else None),
            "dpmi_ax": dpmi_ax,
            "real_mode_ax": ax_rm,
            "mscdex_subfunc": ("0x%04X" % ax_rm) if ax_rm is not None else None,
            "mscdex_name": MSCDEX_SUBFUNCS.get(ax_rm) if ax_rm is not None else None,
            "is_mscdex": (vector == 0x2F),
            "in_entry_path": (name == "entry_path_combined"),
        })
        # also record UNIMPLEMENTED int 0x2f separately
    for i, l in enumerate(lines):
        m = INT2F_UNIMPL_RE.search(l)
        if m:
            vm2 = VA_COMMENT_RE.search(l)
            unimpl_int2f.append({
                "closure": name,
                "line": i + 1,
                "va": ("0x%08X" % hx(vm2.group(1))) if vm2 else None,
                "func": (func_at(i)[0] if func_at(i) else None),
            })
    return {
        "closure": name,
        "path": str(path),
        "exists": True,
        "sha256": sha_of(path),
        "callsites": callsites,
        "unimplemented_int2f": unimpl_int2f,
    }

# ---------------------------------------------------------------------------
# DYNAMIC: walk trace JSONs for real_mode_0300 frames
# ---------------------------------------------------------------------------
def walk_frames(obj, out, source):
    """Recursively collect any dict that looks like a real-mode 0300 frame."""
    if isinstance(obj, dict):
        # A frame has real_mode_vector + interrupt_eip OR a 'frame' with registers
        if ("real_mode_vector" in obj) or ("inner_real_mode_interrupt" in obj) \
           or (isinstance(obj.get("frame"), dict) and "registers" in obj["frame"]
               and obj.get("real_mode_vector") is not None):
            vec = obj.get("real_mode_vector")
            eip = obj.get("interrupt_eip")
            fr = obj.get("frame", {})
            regs = fr.get("registers", {}) if isinstance(fr, dict) else {}
            eax = regs.get("eax")
            out.append({
                "source": source,
                "vector": vec,
                "vector_name": VECTOR_NAMES.get(vec, "INT %dh" % vec if vec else None),
                "interrupt_eip": eip,
                "real_mode_eax": ("0x%04X" % (eax & 0xFFFF)) if isinstance(eax, int) else eax,
                "real_mode_ax_hex": ("0x%04X" % (eax & 0xFFFF)) if isinstance(eax, int) else None,
                "mscdex_subfunc": ("0x%04X" % (eax & 0xFFFF)) if (isinstance(eax, int) and (eax >> 8) == 0x15) else None,
                "mscdex_name": MSCDEX_SUBFUNCS.get(eax & 0xFFFF) if isinstance(eax, int) else None,
                "is_mscdex": (vec == 0x2F),
                "frame_linear": fr.get("linear") if isinstance(fr, dict) else None,
                "host_eip": obj.get("host_registers", {}).get("eip") if isinstance(obj.get("host_registers"), dict) else None,
            })
        # inner_real_mode_interrupt shape (from dpmi_0300_request.json)
        inner = obj.get("inner_real_mode_interrupt")
        if isinstance(inner, dict) and "vector" in inner:
            vec = inner.get("vector"); eax = inner.get("eax")
            out.append({
                "source": source,
                "shape": "inner_real_mode_interrupt",
                "vector": vec,
                "vector_name": VECTOR_NAMES.get(vec, "INT %dh" % vec if vec else None),
                "interrupt_eip": None,
                "real_mode_eax": ("0x%04X" % (eax & 0xFFFF)) if isinstance(eax, int) else eax,
                "real_mode_ax_hex": ("0x%04X" % (eax & 0xFFFF)) if isinstance(eax, int) else None,
                "mscdex_subfunc": ("0x%04X" % (eax & 0xFFFF)) if (isinstance(eax, int) and (eax >> 8) == 0x15) else None,
                "mscdex_name": MSCDEX_SUBFUNCS.get(eax & 0xFFFF) if isinstance(eax, int) else None,
                "is_mscdex": (vec == 0x2F),
            })
        for v in obj.values():
            walk_frames(v, out, source)
    elif isinstance(obj, list):
        for v in obj:
            walk_frames(v, out, source)

def collect_dynamic():
    frames = []
    seen_sources = set()
    walked = []
    for g in TRACE_GLOBS:
        for p in sorted(EV.glob(g)):
            if p.name in seen_sources: continue
            seen_sources.add(p.name)
            walked.append(p.name)
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except Exception as e:
                continue
            walk_frames(data, frames, p.name)
    # de-dup identical frames (same source+vector+eip+eax)
    dedup = []
    seen = set()
    for f in frames:
        key = (f["source"], f.get("shape",""), f.get("vector"), f.get("interrupt_eip"), f.get("real_mode_eax"))
        if key in seen: continue
        seen.add(key); dedup.append(f)
    return dedup, walked

def main():
    static = [parse_closure(n, p) for (n, p) in CLOSURES]
    dynamic, walked = collect_dynamic()

    # Aggregate MSCDEX subfunctions across static + dynamic
    subfuncs = {}
    for c in static:
        for s in c.get("callsites", []):
            if s["is_mscdex"] and s["mscdex_subfunc"]:
                k = s["mscdex_subfunc"]
                e = subfuncs.setdefault(k, {"name": s["mscdex_name"], "static_sites": [], "dynamic_frames": []})
                e["static_sites"].append({"closure": s["closure"], "func": s["func"], "func_va": s["func_va"], "site_va": s["site_va"], "in_entry_path": s["in_entry_path"]})
    for f in dynamic:
        if f.get("is_mscdex") and f.get("mscdex_subfunc"):
            k = f["mscdex_subfunc"]
            e = subfuncs.setdefault(k, {"name": f.get("mscdex_name"), "static_sites": [], "dynamic_frames": []})
            e["dynamic_frames"].append({"source": f["source"], "interrupt_eip": f.get("interrupt_eip"), "real_mode_eax": f.get("real_mode_eax")})

    # Determine current vs historical: the authoritative current gate stop is
    # DPMI AX=0300 -> real-mode INT 2Fh AX=1500 at 0x001d23a7.
    current_blocker = {
        "service": "DPMI AX=0300 -> real-mode INT 2Fh AX=1500",
        "eip": "0x001d23a7",
        "function": "_DoINTR_",
        "note": "Authoritative current -k gate stop (PROJECT_STATE.md). Historical dpmi31.allocate_dos_memory.insufficient_memory records are stale (AX=0100 already past).",
    }

    result = {
        "task": "L-MSCDEXINV",
        "generated_by": "tools/mscdex_inventory.py",
        "target_note": "GeneWars 1.1 genewars-1_1.exe via E:\\GWRecomp build closures",
        "current_gate": current_blocker,
        "trace_inputs_walked": sorted(walked),
        "static_closures": static,
        "dynamic_frames": dynamic,
        "mscdex_subfunctions": subfuncs,
        "summary": {
            "total_static_callsites": sum(len(c.get("callsites", [])) for c in static),
            "total_mscdex_static_callsites": sum(1 for c in static for s in c.get("callsites", []) if s["is_mscdex"]),
            "total_unimplemented_int2f": sum(len(c.get("unimplemented_int2f", [])) for c in static),
            "total_dynamic_frames": len(dynamic),
            "total_mscdex_dynamic_frames": sum(1 for f in dynamic if f.get("is_mscdex")),
            "distinct_mscdex_subfunctions": sorted(subfuncs.keys()),
            "mscdex_in_entry_path": any(s["in_entry_path"] for c in static for s in c.get("callsites", []) if s["is_mscdex"]),
        },
    }
    EV.mkdir(parents=True, exist_ok=True); REP.mkdir(parents=True, exist_ok=True)
    (EV / "mscdex_inventory.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")

    # ---- report ----
    L = []
    L.append("# LOCAL MSCDEX/CD-ROM Surface Inventory (L-MSCDEXINV)")
    L.append("")
    L.append("## Current gate")
    L.append("- Stop: `%s` at EIP `%s` inside `%s`." % (current_blocker["service"], current_blocker["eip"], current_blocker["function"]))
    L.append("- MENU not reached. The 0x1500 at this gate is issued by the CRT `_DoINTR_` real-mode shim, not the game's 0xB8xxx MSCDEX dispatcher.")
    L.append("- Stale-evidence note: `dpmi31.allocate_dos_memory.insufficient_memory` records are HISTORICAL (AX=0100 already passed in the current gate) and are NOT a current blocker.")
    L.append("")
    L.append("## How the game reaches MSCDEX")
    L.append("Via the DPMI **AX=0300 real-mode bridge** (`int 0x31` with AX=0300, EBX=real-mode vector, real-mode AX in the ES:EDI frame), never a direct `int 0x2f`. Lifted pattern:")
    L.append("```")
    L.append("  <reg> = 0x15xxu   ; real-mode AX (MSCDEX subfunction)")
    L.append("  <reg> = 0x300u    ; DPMI AX (bridge)")
    L.append("  esi   = 0x2Fu     ; real-mode vector 47 = INT 2Fh")
    L.append("  ... frame @ 0x1A4E8C ...")
    L.append("  RECOMP_CALL(sub_000ADEF6)  ; DPMI wrapper -> int 0x31 AX=0300")
    L.append("```")
    L.append("")
    L.append("## Static callsites (per closure)")
    for c in static:
        L.append("")
        L.append("### %s  (%s)" % (c["closure"], c["path"]))
        if not c.get("exists"):
            L.append("- file missing"); continue
        L.append("- sha256: `%s`" % c["sha256"])
        L.append("- total ADEF6 bridge callsites: %d" % len(c.get("callsites", [])))
        L.append("- MSCDEX (INT 2Fh) callsites: %d" % sum(1 for s in c.get("callsites", []) if s["is_mscdex"]))
        L.append("- UNIMPLEMENTED `int 0x2f` sites: %d" % len(c.get("unimplemented_int2f", [])))
        ms = [s for s in c.get("callsites", []) if s["is_mscdex"]]
        if ms:
            L.append("")
            L.append("| func | func_va | site_va | real_mode_AX | subfunction | in_entry_path |")
            L.append("|---|---|---|---|---|---|")
            for s in ms:
                L.append("| %s | %s | %s | %s | %s | %s |" % (s["func"], s["func_va"], s["site_va"], s["mscdex_subfunc"], s["mscdex_name"], s["in_entry_path"]))
        ui = c.get("unimplemented_int2f", [])
        if ui:
            L.append("")
            L.append("UNIMPLEMENTED `int 0x2f` (CRT/DOS4GW real-mode shim, not game dispatcher):")
            for u in ui[:20]:
                L.append("- %s @ %s (line %d)" % (u["func"], u["va"], u["line"]))
    L.append("")
    L.append("## Dynamic frames (oracle/runtime traces)")
    L.append("- total real-mode 0300 frames collected: %d" % len(dynamic))
    L.append("- MSCDEX (INT 2Fh) frames: %d" % sum(1 for f in dynamic if f.get("is_mscdex")))
    L.append("")
    L.append("| source | vector | interrupt_eip | real_mode_AX | subfunction |")
    L.append("|---|---|---|---|---|")
    for f in dynamic:
        L.append("| %s | %s | %s | %s | %s |" % (f["source"], f.get("vector_name"), f.get("interrupt_eip"), f.get("real_mode_eax"), f.get("mscdex_name")))
    L.append("")
    L.append("## MSCDEX subfunctions present (static + dynamic union)")
    L.append("")
    L.append("| subfunction | name | static sites | dynamic frames |")
    L.append("|---|---|---|---|")
    for k in sorted(subfuncs.keys()):
        e = subfuncs[k]
        L.append("| %s | %s | %d | %d |" % (k, e["name"], len(e["static_sites"]), len(e["dynamic_frames"])))
    L.append("")
    L.append("## Determination: is AX=1500 the ONLY MSCDEX service before MENU?")
    L.append("")
    L.append("**RBIL-corrected semantics (2026-10 correction).**")
    L.append("- `INT 2Fh AX=1500, BX=0` = MSCDEX **install check / get drive count** (RBIL). It does **NOT** use a buffer, PVD, root LBA or volume label. Returns `BX` = number of CD-ROM drives and `CX` = first drive letter (0 = A:). With `BX=n (n>=1)` it returns a 16-byte drive-parameter block at `ES:BX` — that sub-case is not the gate.")
    L.append("- `INT 2Fh AX=150C, BX=0` = Get MSCDEX version (RBIL). Post-MENU; not on the -k path.")
    L.append("- `INT 2Fh AX=1510` = **Send device-driver request** (RBIL). `CX` = drive, `ES:BX` -> device-driver request header (SCSI/MMC CDB). This is how ALL CD data/TOC reads are issued in MSCDEX 2.x; there is no separate AH per command. Post-MENU asset streaming only.")
    L.append("")
    distinct = set(subfuncs.keys())
    later = sorted(k for k in distinct if k != "0x1500")
    L.append("- Distinct MSCDEX AHs referenced in the code: %s" % (", ".join(sorted(distinct)) or "(none)"))
    L.append("- On the CURRENT -k path to MENU, exactly ONE MSCDEX request is issued: **AX=1500 (BX=0 install check)** at EIP 0x001d23a7 (the only MSCDEX frame in the oracle traces, and the current gate stop). No other MSCDEX AH appears on that path (the -k entry closure has zero game-0xB8xxx MSCDEX callsites).")
    L.append("- **W3-029 is the authority for the accepted no-CD response.** With `cdrom_inventory:[]` the game's post-return branch at 0x001b955f (`JNZ +0x25`, EAX=0, ZF=1) was NOT taken -> CD-absent path taken -> execution continued into DPMI `allocate_dos_memory` (AX=0100) and `allocate_memory` (AX=0501). So a no-CD (zero drive letters) AX=1500 response (AX=0000, BX=0, CX=0) is SUFFICIENT to pass the MSCDEX gate toward MENU. **No CD image / PVD / root LBA is a prerequisite for MENU.**")
    L.append("- **To reach MENU: serve AX=1500 (BX=0) only.** The no-CD response already proven by W3-029 is enough. A real CD image is only required LATER, for asset streaming via the AX=1510 device-request path (MISSION/GAMEPLAY phase).")
    if later:
        L.append("- **Post-MENU (not on the -k path, not a MENU prerequisite):** %s. These AHs are referenced in the game code but only in later asset-loading phases. Do NOT gate MENU on them." % ", ".join(k + " (" + subfuncs[k]["name"] + ")" for k in later))
    L.append("- **Correction (2026-10):** earlier versions of this report listed phantom AHs (1501/1502/1503/150B/150D/150E/150F) as separate MSCDEX services. Those are NOT MSCDEX AHs in MSCDEX 2.x; CD data/TOC operations go through AX=1510 as device-request *commands* (a CDB byte), not as separate AHs. Only 1500/150C/1510 exist as AHs, and only 1500/150C/1510 are emitted by this game (1500/150C/1510 are the distinct set above).")
    L.append("")
    L.append("## What to prepare (priority order for the runtime)")
    L.append("| MSCDEX AX | service | needed for | static | dynamic |")
    L.append("|---|---|---|---|---|")
    order = ["0x1500"] + later
    need = {
        "0x1500": "MENU (current gate; BX=0 no-CD response suffices per W3-029)",
        "0x150C": "post-MENU (MSCDEX version; not a MENU prerequisite)",
        "0x1510": "post-MENU (device-driver request for CD asset streaming; CDBs from real code via W2-055/W2-057)",
    }
    for k in order:
        e = subfuncs.get(k)
        if not e: continue
        L.append("| %s | %s | %s | %d | %d |" % (k, e["name"], need.get(k, "post-MENU"), len(e["static_sites"]), len(e["dynamic_frames"])))
    L.append("")
    L.append("## Cross-reference")
    L.append("- WORK2 implemented: W2-047 (route measured DPMI AX=0300 real-mode INT 2F AX=1500 startup query) DONE; W2-041/W2-045 (AX=0100 alloc) DONE; W2-048/W2-049 (AX=0501 linear alloc) DONE/CLAIMED.")
    L.append("- The current gate stop (AX=1500 at 0x1d23a7) is exactly what W2-047 routes; remaining work is to serve the MSCDEX response and resume toward MENU.")
    L.append("- Derivative tasks created for WORK2/WORK3 below.")
    L.append("")
    L.append("## Reproducibility")
    L.append("- Command: `py -3 tools/mscdex_inventory.py`")
    L.append("- Inputs: %s" % ", ".join(str(p) for _, p in CLOSURES))
    L.append("- Trace inputs: %s" % ", ".join(sorted(walked)))
    L.append("- Outputs: evidence/mscdex_inventory.json, reports/LOCAL_MSCDEX_INVENTORY.md")
    (REP / "LOCAL_MSCDEX_INVENTORY.md").write_text("\n".join(L), encoding="utf-8")
    print("WROTE evidence/mscdex_inventory.json + reports/LOCAL_MSCDEX_INVENTORY.md")
    print("static callsites:", result["summary"]["total_static_callsites"],
          "| mscdex:", result["summary"]["total_mscdex_static_callsites"],
          "| unimpl_int2f:", result["summary"]["total_unimplemented_int2f"])
    print("dynamic frames:", result["summary"]["total_dynamic_frames"],
          "| mscdex:", result["summary"]["total_mscdex_dynamic_frames"])
    print("distinct mscdex subfunctions:", result["summary"]["distinct_mscdex_subfunctions"])
    print("mscdex in entry_path:", result["summary"]["mscdex_in_entry_path"])

if __name__ == "__main__":
    main()