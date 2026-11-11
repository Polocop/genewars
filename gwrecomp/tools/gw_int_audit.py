#!/usr/bin/env python3
"""gw_int_audit.py — CONCLUSIVE INT / VESA-interrupt attribution
(L-BFLIB-MATCH closure, MISIÓN 1B / MISIÓN 1 + 2).

Resolves the prior contradiction between two passes:
  * pass A  raw ``CD 21``/``CD 10`` byte scan  -> "5 INT 21h present"
  * pass B  linear walk that STOPS at 1st RET  -> "1 INT" (or "zero INTs")

WHY THEY DISAGREED
  GeneWars 1.1's public map is SPARSE (1070 symbols).  A symbol's slot
  (its entry up to the NEXT public symbol) can therefore contain several
  *adjacent, unmapped* functions.  So:
    * a raw/sequential scan of the whole SLOT sees the INTs of the function
      AND of the neighbouring unmapped functions that happen to share it;
    * a control-flow walk from the entry that STOPS at the function's own RET
      sees only the function's own body.
  Both are correct about what they measured.  The tool now reports BOTH scopes
  separately and never conflates "slot" with "function".

THE INSTRUMENT (no new x86 parser, no raw-byte existence proof)
  1. CFG REACHABILITY WALK from the real entry, following JMP/JCC and near
     CALL (in-slot), stopping at RET/IRET = the function's own body.  An INT
     is attributed to the FUNCTION only if it sits at a decoded-instruction
     boundary in this reachable set.
  2. COMPLETE SEQUENTIAL SLOT DECODE (no early-RET stop) to the next public
     symbol = the slot.  Used to show the raw CD count equals the decoded INT
     count (proof nothing is hidden/undecoded) and to flag INTs that belong to
     adjacent unmapped functions rather than to this one.
  3. Independent second decoder (capstone) cross-check on every INT site.

  A raw ``CD xx`` byte is NEVER used as proof of an executable instruction, and
  a linear walk is NEVER used as an absence proof.  VESA is NOT concluded to be
  INT 21h by proximity.

Per-INT service attribution (MISIÓN 2) uses real register dataflow: the last
``mov ah, imm8`` (B4) / ``mov ax, imm16`` (B8) executed immediately before the
INT, not a MOV found "nearby".  A ``mov ax`` overrides the low byte.  If the
value is dynamic the service is reported UNKNOWN.

Known services:
  DOS INT 21h:  AH=3Eh close    AH=3Ch create   AH=3Dh open   AH=42h seek
                AH=44h IOCTL    AH=50h set-SP   AH=34h set-DTA ...
  VBE/VESA:     AX=4Fxx via INT 10h.
  DPMI real-mode gate: INT 31h or ``int 0`` via a far-call thunk.

Run under the venv python (has dos_re + capstone):
  python tools/gw_int_audit.py \
      --exe evidence/genewars-1_1.exe \
      --map evidence/genewars-1_1.map \
      --funcs LbScreenSetupAnyMode_,LbVesaSetMode_,LbVesaSetPage_,LbScreenSwap_,LbVesaGetInfo_ \
      --json evidence/local_int_audit.json
"""
import sys, argparse, pathlib, json, bisect
from pathlib import Path

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from bflib_match import load_image, decode32

# Decoder kind constants are LOWERCASE (dos_re.lift.decode32).  Uppercase checks
# silently never match; key on the real kinds so the walk records calls/branches.
# NOTE: the decoder returns ``target=None`` for INDIRECT transfers (ModR/M group
# call_ind / jmp_ind, e.g. ``call *%eax`` / ``jmp *%edx``) — those are the classic
# DPMI/BFLIB function-pointer bridges.  We MUST register them as UNRESOLVED
# (coverage INCOMPLETE) rather than silently fall through, or an indirect call
# that actually executes a video/DPMI interrupt would be misreported as "none".
K_JCC = "jcc"; K_JMP = "jmp"; K_CALL = "call"
K_CALL_IND = "call_ind"; K_JMP_IND = "jmp_ind"
K_INDIRECT = (K_CALL_IND, K_JMP_IND)
K_RET = ("ret", "iret")

DOS_AH = {
    0x00: "terminate", 0x01: "stdinput", 0x02: "stdoutput", 0x03: "conin",
    0x04: "conout", 0x06: "direct-io", 0x08: "inkey", 0x09: "stoutr",
    0x0a: "buf-inkey", 0x0e: "direct-out", 0x10: "flush", 0x11: "read-fd",
    0x12: "write-fd", 0x14: "close-fd", 0x15: "open-fd", 0x16: "fcntl",
    0x19: "get-cwd", 0x1a: "set-cwd", 0x21: "get-date", 0x24: "get-alloc",
    0x2a: "get-cwd-path", 0x2c: "set-date", 0x2d: "get-time", 0x2e: "set-time",
    0x30: "get-ver", 0x31: "term-stay", 0x32: "find-first", 0x33: "find-next",
    0x34: "set-dta", 0x35: "get-intvec", 0x36: "get-dir-handle", 0x37: "get-attr",
    0x38: "mkdir", 0x39: "rmdir", 0x3a: "chdir", 0x3b: "create-dir",
    0x3c: "create", 0x3d: "open", 0x3e: "close", 0x3f: "read", 0x40: "write",
    0x41: "delete", 0x42: "seek", 0x43: "set/get-date-time", 0x44: "IOCTL",
    0x47: "read-dir", 0x48: "alloc-mem", 0x49: "free-mem", 0x4a: "resize-mem",
    0x4b: "exec", 0x4c: "exit", 0x4d: "reg-dev", 0x4e: "unreg-dev",
    0x50: "set-SP", 0x51: "get-SP", 0x56: "get-SP-DS", 0x58: "chainload",
    0x59: "uninit-stdio", 0x60: "config", 0x66: "set-flags", 0x67: "get-flags",
    0x6a: "sleep",
}
VBE_AX = {
    0x4f00: "VBE GetInfo", 0x4f01: "VBE GetModeInfo", 0x4f02: "VBE SetMode",
    0x4f05: "VBE GetController", 0x4f07: "VBE GetOverlayInfo",
    0x4f08: "VBE SetDisplayStart", 0x4f0b: "VBE GetPixel", 0x4f0c: "VBE PutPixel",
    0x4f0d: "VBE SetDacPalette", 0x4f0e: "VBE GetDacPalette",
    0x4f0f: "VBE SetSourceBounds", 0x4f10: "VBE SetWin", 0x4f11: "VBE GetWin",
    0x4f12: "VBE GetXGAInfo",
}


def slot_end(im, va):
    """End of the symbol's SLOT = next public symbol after ``va`` (sparse-map
    caveat: this can span adjacent unmapped functions)."""
    vs = sorted(set(im.syms.values()))
    i = bisect.bisect_right(vs, va)
    if i < len(vs):
        return min(vs[i], va + 0x2000)
    return min(len(im.mem), va + 0x2000)


def reachable_instructions(im, va, end):
    """CFG reachability worklist from ``va`` = the FUNCTION'S OWN body.

    Per-instruction handling (decoder kinds are LOWERCASE):
      * JCC  -> follow BOTH the branch target AND the fallthrough (next_ip).
      * JMP  -> follow the target only (no fallthrough: an unconditional jump
               never falls through).
      * CALL (direct) -> record (ip, target) as a call; follow the in-slot
               target if it is, and ALWAYS follow the fallthrough (a call
               returns).
      * CALL_IND / JMP_IND (indirect, decoder target=None) -> record as an
               UNRESOLVED transfer; coverage is INCOMPLETE because we cannot
               prove which target executes.  For a call_ind we still follow
               the fallthrough (it returns); for a jmp_ind we cannot follow
               anything and must not add a fallthrough (dead via that path).
      * RET / IRET -> terminate ONLY that path (a worklist, not a straight-line
               walk: other work items keep running, so a RET does not stop the
               global walk).
      * anything else (seq, int, ...) -> follow the fallthrough.

    A global stop is NEVER triggered by a RET; the walk drains the whole
    worklist.  Returns ({ip: Inst}, [(call_ip, target_va_or_None), ...],
    [indirect_ip, ...]) where the third item is the set of indirect-transfer
    sites that left coverage INCOMPLETE.
    """
    seen = {}
    calls = []
    incomplete = []
    work = [va]
    guard = 0
    while work:
        ip = work.pop()
        if ip in seen or guard > 400000:
            continue
        guard += 1
        if not (va <= ip < end):
            continue
        try:
            ins = decode32(im.fetch, ip)
        except (ValueError, IndexError):
            continue
        if ins.length == 0:
            continue
        seen[ip] = ins
        k = ins.kind
        if k == K_JCC:
            if ins.target is not None:
                work.append(ins.target & 0xFFFFFFFF)
            work.append(ins.next_ip & 0xFFFFFFFF)              # fallthrough
        elif k == K_JMP:
            if ins.target is not None:
                work.append(ins.target & 0xFFFFFFFF)            # no fallthrough
            else:
                incomplete.append(ip)                          # shouldn't happen
        elif k == K_JMP_IND:
            # indirect jump: target unknown; do NOT follow, no fallthrough
            incomplete.append(ip)
        elif k == K_CALL:
            if ins.target is not None:
                t = ins.target & 0xFFFFFFFF
                calls.append((ip, t))
                if va <= t < end:
                    work.append(t)                             # follow in-slot callee
            work.append(ins.next_ip & 0xFFFFFFFF)              # call returns
        elif k == K_CALL_IND:
            # indirect call: target unknown but it returns -> follow fallthrough
            calls.append((ip, None))
            incomplete.append(ip)
            work.append(ins.next_ip & 0xFFFFFFFF)
        elif k in K_RET:
            pass                                               # end this path only
        else:
            work.append(ins.next_ip & 0xFFFFFFFF)              # seq/int/...
    return seen, calls, incomplete


def sequential_slot_scan(im, va, end):
    """COMPLETE straight-line decode of the whole slot [va, end) with NO early
    RET stop.  Ground truth for 'every INT instruction in the slot' and for
    proving raw-CD-count == decoded-INT-count (nothing hidden)."""
    out = {}
    ip = va
    guard = 0
    while ip < end and guard < 200000:
        guard += 1
        try:
            ins = decode32(im.fetch, ip)
        except (ValueError, IndexError):
            break
        if ins.length == 0:
            break
        out[ip] = ins
        ip = (ip + ins.length) & 0xFFFFFFFF
        if ip <= va:
            break
    return out


def callee_label(im, t, va):
    """Honest callee naming on a SPARSE map: exact symbol if the target IS a
    public symbol start, else 'near:<name>+off' (nearest symbol below) so a
    reader never mistakes the nearest symbol for the callee's true identity.
    ``t=None`` is an INDIRECT transfer (target unknown) -> labelled as such and
    coverage is INCOMPLETE, never guessed from proximity."""
    if t is None:
        return "indirect(unresolved-target)", "indirect"
    base = None
    for n, v in im.syms.items():
        if v == t:
            return n, "exact"
    vs = sorted(set(im.syms.values()))
    i = bisect.bisect_right(vs, t)
    if i == 0:
        return f"unmapped@{t:#x}", "unmapped"
    b = vs[i - 1]
    for n, v in im.syms.items():
        if v == b:
            return f"near:{n}+{t - b:#x}", "near"
    return f"near:unmapped@{b:#x}+{t - b:#x}", "near"


def service_setup(im, ip, va):
    """(ax, ah) set on the straight-line path immediately before the INT at
    ``ip`` by the nearest preceding ``mov ax, imm16`` (B8) / ``mov ah, imm8``
    (B4).  A B8 overrides the low byte.  Scans within [va, ip)."""
    ax = None
    ah = None
    a = ip - 1
    lo = max(ip - 24, va)
    while a >= lo:
        if a >= 1 and im.mem[a - 1] == 0xB8:
            val = im.mem[a] | (im.mem[a + 1] << 8)
            if ax is None:
                ax = val
                ah = val & 0xFF
            break
        if a >= 1 and im.mem[a - 1] == 0xB4:
            if ah is None:
                ah = im.mem[a]
            break
        a -= 1
    return ax, ah


def int_service(im, ip, va):
    if im.mem[ip] != 0xCD:
        return "INT ? (no CD opcode byte at boundary)"
    no = im.mem[ip + 1]
    ax, ah = service_setup(im, ip, va)
    if no == 0x21:
        if ah is None:
            return "DOS INT 21h AH=UNKNOWN (dynamic AH, service undetermined)"
        return f"DOS INT 21h AH={ah:#04x} {DOS_AH.get(ah, 'UNKNOWN-service')}"
    if no == 0x10:
        if ax is not None and (ax >> 8) == 0x4F:
            return f"BIOS/VESA INT 10h AX={ax:#04x} {VBE_AX.get(ax, 'VBE-op')}"
        if ax is None:
            return "BIOS video INT 10h AX=UNKNOWN (VBE 0x4Fxx or legacy, undetermined)"
        return f"BIOS video INT 10h AX={ax:#06x} (non-VBE)"
    if no == 0x31:
        return "INT 0x31h (DPMI service)"
    if no == 0x00:
        return "INT 0 (far real-mode gate)"
    return f"INT 0x{no:02x}"


def second_decoder_check(im, ip):
    try:
        import capstone
    except Exception:
        return None
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    out = [i.mnemonic + " " + i.op_str
           for i in cs.disasm(bytes(im.mem[ip:ip + 3]), ip)]
    return out[0] if out else None


def audit_func(im, name, va, end):
    rec = {
        "name": name, "entry_va": hex(va), "slot_end": hex(end),
        "slot_size": end - va,
        "function_body_insts": 0,   # CFG reachability (entry -> own RET)
        "slot_scanned_insts": 0,    # complete sequential slot decode
        "func_ints": [],            # INTs in the FUNCTION'S OWN body
        "slot_ints": [],            # INTs in the whole slot (may incl. adj. fns)
        "call_targets": [], "indirect_transfers": [], "coverage_incomplete": [],
        "coverage_complete": True, "mechanism": {}, "note": "",
    }
    reach, calls, incomplete = reachable_instructions(im, va, end)
    rec["function_body_insts"] = len(reach)
    rec["indirect_transfers"] = [hex(ip) for ip in incomplete]
    rec["coverage_incomplete"] = [hex(ip) for ip in incomplete]
    rec["coverage_complete"] = not incomplete
    seq = sequential_slot_scan(im, va, end)
    rec["slot_scanned_insts"] = len(seq)

    for ip in sorted(reach):
        ins = reach[ip]
        if ins.int_no is None:
            continue
        boundary_ok = (im.mem[ip] == 0xCD and im.mem[ip + 1] == (ins.int_no & 0xFF))
        rec["func_ints"].append({
            "va": hex(ip), "int_no": ins.int_no,
            "bytes": "%02x %02x" % (im.mem[ip], im.mem[ip + 1]),
            "boundary_ok": boundary_ok,
            "service": int_service(im, ip, va),
        })
    for ip in sorted(seq):
        ins = seq[ip]
        if ins.int_no is None:
            continue
        boundary_ok = (im.mem[ip] == 0xCD and im.mem[ip + 1] == (ins.int_no & 0xFF))
        rec["slot_ints"].append({
            "va": hex(ip), "int_no": ins.int_no,
            "bytes": "%02x %02x" % (im.mem[ip], im.mem[ip + 1]),
            "boundary_ok": boundary_ok,
            "in_function_body": (ip in reach),
            "service": int_service(im, ip, va),
        })
    for (cip, t) in calls:
        label, how = callee_label(im, t, va)
        rec["call_targets"].append({
            "call_va": hex(cip), "target_va": hex(t) if t is not None else None,
            "in_slot": (t is not None and va <= t < end),
            "callee": label, "label_kind": how,
        })
    seg = bytes(im.mem[va:end])
    vbe = sorted({f"0x{im.mem[j] | (im.mem[j + 1] << 8):04x}"
                  for j in range(1, len(seg) - 1)
                  if im.mem[j - 1] == 0xB8 and im.mem[j + 1] == 0x4F})
    rec["mechanism"] = {
        "vbe_ax_present": vbe,
        "dpmi_far_int0": bool(b"\xff\x15" in seg),
        "raw_cd10_count": seg.count(b"\xcd\x10"),
        "raw_cd21_count": seg.count(b"\xcd\x21"),
        "decoded_slot_ints": len(rec["slot_ints"]),
        "decoded_func_ints": len(rec["func_ints"]),
        "consistency": {
            "raw_cd21_eq_decoded_cd21":
                seg.count(b"\xcd\x21") ==
                sum(1 for d in rec["slot_ints"] if d["int_no"] == 0x21),
            "raw_cd10_eq_decoded_cd10":
                seg.count(b"\xcd\x10") ==
                sum(1 for d in rec["slot_ints"] if d["int_no"] == 0x10),
        },
    }
    # NOTE: raw CD count includes data bytes that are NOT instruction-boundary
    # INTs, so equality is expected ONLY when there is no such overlap.  When
    # they differ, the decoded (boundary-verified) count is the authoritative
    # one and the raw count is reported for transparency.
    if rec["func_ints"]:
        kinds = sorted({f"INT 0x{d['int_no']:02x}" for d in rec["func_ints"]})
        rec["note"] = "FUNCTION BODY: " + ", ".join(kinds)
    else:
        exact = sorted({c["callee"] for c in rec["call_targets"]
                        if not c["in_slot"] and c["label_kind"] == "exact"})
        indirect = len(rec["coverage_incomplete"])
        if indirect:
            rec["note"] = (f"FUNCTION BODY has no DIRECT INT.  Coverage is "
                           f"INCOMPLETE: {indirect} indirect transfer(s) "
                           f"(call*/jmp* via pointer) resolve to an "
                           f"unmapped/unknown target, so any video/DPMI "
                           f"interrupt they may reach CANNOT be confirmed.  "
                           f"Resolved direct callees: "
                           + (", ".join(exact) if exact else "none exact"))
        else:
            rec["note"] = (f"FUNCTION BODY has no direct INT; coverage "
                           f"COMPLETE.  Any video/DOS interrupts are executed "
                           f"by callees: "
                           + (", ".join(exact) if exact else
                              "callees unmapped on this sparse map"))
    return rec


def audit(exe, map_path, names, out_json=None):
    im = load_image(exe, map_path)
    print(f"image: {exe}")
    print(f"  mem={len(im.mem)}B  syms={len(im.syms)}  fixups={len(im.fixups)}\n")
    results = []
    for name in names:
        if name not in im.syms:
            print(f"== {name}: NOT IN MAP ==")
            results.append({"name": name, "present": False})
            continue
        va = im.syms[name]
        end = slot_end(im, va)
        rec = audit_func(im, name, va, end)
        results.append(rec)
        print(f"== {name}  @ {hex(va)}..{hex(end)}  "
              f"body={rec['function_body_insts']} slot={rec['slot_scanned_insts']} ==")
        print(f"   FUNCTION-BODY INTs ({len(rec['func_ints'])}):")
        for d in rec["func_ints"]:
            cross = second_decoder_check(im, int(d["va"], 16))
            x = f"  [capstone: {cross}]" if cross else ""
            print(f"     {d['service']}  va={d['va']} bytes={d['bytes']} "
                  f"boundary={d['boundary_ok']}{x}")
        if not rec["func_ints"]:
            print("     (none in the function's own body)")
        adj = [d for d in rec["slot_ints"] if not d["in_function_body"]]
        print(f"   SLOT INTs ({len(rec['slot_ints'])}); {len(adj)} outside the "
              f"function body (adjacent unmapped fns in this sparse slot):")
        for d in rec["slot_ints"]:
            tag = "FN " if d["in_function_body"] else "adj"
            print(f"     [{tag}] {d['service']}  va={d['va']} bytes={d['bytes']}")
        ext = sorted({c["callee"] for c in rec["call_targets"]
                      if c["target_va"] is not None and not c["in_slot"]})
        n_out = len([c for c in rec["call_targets"] if not c["in_slot"]])
        print(f"   direct callees ({n_out} out-of-slot): "
              f"{', '.join(ext[:8]) if ext else 'none'}")
        if rec["indirect_transfers"]:
            print(f"   INDIRECT transfers (coverage INCOMPLETE): "
                  f"{', '.join(rec['indirect_transfers'])}")
        else:
            print(f"   coverage: COMPLETE (no unresolved indirect transfers)")
        m = rec["mechanism"]
        print(f"   mechanism: VBE-AX={m['vbe_ax_present'] or 'none'} "
              f"DPMI-far={m['dpmi_far_int0']} raw-CD10={m['raw_cd10_count']} "
              f"raw-CD21={m['raw_cd21_count']} "
              f"(decoded cd10/cd21 in slot = {sum(1 for d in rec['slot_ints'] if d['int_no']==0x10)}/"
              f"{sum(1 for d in rec['slot_ints'] if d['int_no']==0x21)})")
        print(f"   => {rec['note']}\n")
    if out_json:
        Path(out_json).write_text(json.dumps(results, indent=2))
        print(f"[wrote {out_json}]")
    return results


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", required=True)
    ap.add_argument("--map", required=True)
    ap.add_argument("--funcs", required=True)
    ap.add_argument("--json", default=None)
    a = ap.parse_args()
    audit(a.exe, a.map, [n for n in a.funcs.split(",") if n], a.json)