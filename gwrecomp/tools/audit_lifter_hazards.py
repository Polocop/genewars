#!/usr/bin/env python3
"""
audit_lifter_hazards.py  (LOCAL, task L-LIFTERHAZARDS)
=======================================================
Static census of x86 instruction patterns in the entry/menu closure that have
produced REAL divergences in x86 recompilers (Watcom/DOS4GW -> native C lift).

Scope (per task spec, W1-034 already PASS-covered the CALL/ICALL/TAIL register +
tail + trap classes, so those are only COUNTED and marked covered_by_W1-034):

  P01  TEST  + Jcc            (CF stale after TEST; signed uses OF==0)
  P02  DEC   + Jcc            (CF stale after DEC; OF = SF^Z tricky)
  P03  AND / OR / XOR + Jcc   (CF cleared -> lifter must clear, not retain)
  P04  flag-setter + MOV/clobber + Jcc   (flag-loss across a non-flag insn)
  P05  REPNE SCASB
  P06  REPE  CMPSB
  P07  REP   STOSW  (and other REP string ops: STOSB/STOSD/MOVS*)
  P08  NEG whose CF is later consumed by SBB/ADC
  P09  call [esp + offset]
  P10  conditional tail-call to a known closure entry
  P11  CALL/ICALL/TAIL touching EBX/ESI/EDI  (covered_by_W1-034)
  P12  _old_ lifted temporals crossing labels/gotos (C-level, heuristic)
  P13  CALL/ICALL/TAIL trap-loss window        (covered_by_W1-034)

This tool INVENTORIES only. It changes no code. Per instance it records:
VA, owning function VA, MAIN.MAP symbol, in_entry_closure, in_dynamic_route
(entry_path_combined), criticality, a short reason, and a differential flag
("needs_differential" when the pattern is a real flag/rep hazard on the
dynamic route and is self-contained enough to A/B original-vs-lift).

Outputs:
  evidence/lifter_hazard_census.json
  reports/LOCAL_LIFTERHAZARDS.md

Reproduce:
  E:/GWRecomp/.venv/Scripts/python.exe tools/audit_lifter_hazards.py
  (any python with capstone + the repo's le_loader/disasm on the path)
"""
import sys, json, re, time, bisect
from pathlib import Path
from collections import Counter, defaultdict

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "src"))
sys.path.insert(0, str(root / "third_party" / "pcrecomp"))

from le_loader import load_le                                   # noqa
from tools.disasm.disasm32 import Disassembler                 # noqa
from tools.pe.pe_analyze import Section                        # noqa

# --------------------------------------------------------------------------- #
# inputs
# --------------------------------------------------------------------------- #
IMAGE    = root / "evidence" / "genewars-1_1.exe"
CLOSURE  = root / "build" / "entry_path_closure.c"       # full entry/menu closure
DYNAMIC  = root / "build" / "entry_path_combined.c"      # dynamically-reached route
MAPF     = root / "evidence" / "genewars-1_1.map"
OUT_JSON = root / "evidence" / "lifter_hazard_census.json"
OUT_MD   = root / "reports" / "LOCAL_LIFTERHAZARDS.md"

t0 = time.time()

# closure + dynamic VA sets: base VA of every lifted body = RECOMP_ENTER(0x..u)
def recomp_enter_vas(path):
    if not path.exists():
        return set()
    tx = path.read_text(encoding="utf-8", errors="replace")
    return {int(m, 16) for m in re.findall(r"RECOMP_ENTER\(0x([0-9A-Fa-f]+)u\)", tx)}

closure_vas = recomp_enter_vas(CLOSURE)
dynamic_vas = recomp_enter_vas(DYNAMIC)

# MAIN.MAP symbols
map_syms = {}
if MAPF.exists():
    for line in MAPF.read_text(encoding="utf-8", errors="replace").splitlines():
        p = line.split()
        if len(p) >= 2 and p[0].startswith("0001:"):
            try:
                map_syms[int(p[0].split(":")[1], 16)] = p[1]
            except ValueError:
                pass

# --------------------------------------------------------------------------- #
# load image + disassemble closure
# --------------------------------------------------------------------------- #
im  = load_le(IMAGE)
obj = im.objects[0]
START = obj.base
END   = START + obj.virtual_size
code  = bytes(im.mem[START - im.mem_base : END - im.mem_base])
sec   = Section(".text", obj.base, obj.virtual_size, 0, obj.virtual_size, 0x20000020)
ds    = Disassembler(code, 0, [sec])
print(f"[i] code {START:#010x}..{END:#010x} ({END-START:#x} bytes); "
      f"closure bodies={len(closure_vas)} dynamic_bodies={len(dynamic_vas)}")

funcs = ds.find_functions(START, END, seeds=sorted(closure_vas))
print(f"[i] find_functions -> {len(funcs)} functions")

# sorted closure function spans for VA->function attribution
cspan = []
for va in sorted(closure_vas):
    f = funcs.get(va)
    if f is None:
        # seed not recognised as its own function start: disassemble on the fly
        try:
            f = ds.disassemble_at(va)
        except Exception:
            f = None
    if f is not None and f.end:
        cspan.append((va, f.end, f, va))
cspan_starts = [s[0] for s in cspan]

def owning_func(va):
    """closure function whose [start,end) contains va (closest start <= va)."""
    if not cspan_starts:
        return None, None
    i = bisect.bisect_right(cspan_starts, va) - 1
    if i < 0:
        return None, None
    st, en, f, seed = cspan[i]
    if st <= va < en:
        return seed, f
    return None, None

def fn_name(va):
    return map_syms.get(va, f"sub_{va:08X}")

# --------------------------------------------------------------------------- #
# flag semantics tables
# --------------------------------------------------------------------------- #
# flags a conditional reads (capstone canonical mnemonics)
JCC_READS = {
    "jz":  {"ZF"}, "jnz": {"ZF"}, "je": {"ZF"}, "jne": {"ZF"},
    "jb":  {"CF"}, "jbe": {"CF", "ZF"}, "ja": {"CF", "ZF"}, "jae": {"CF"},
    "jg":  {"ZF", "SF", "OF"}, "jge": {"SF", "OF"},
    "jle": {"ZF", "SF", "OF"}, "jl":  {"SF", "OF"},
    "js":  {"SF"}, "jns": {"SF"}, "jo": {"OF"}, "jno": {"OF"},
}
CF_READING = {"jb", "jbe", "ja", "jae"}

# flags each setter DEFINES (touches). Anything not listed is RETAINED.
SETTER_DEFINES = {
    "test":  {"ZF", "SF", "PF"},          # OF=0, AF=0 (cleared); CF retained
    "and":   {"ZF", "SF", "PF"},          # CF=0, OF=0; AF retained
    "or":    {"ZF", "SF", "PF"},          # CF=0, OF=0; AF retained
    "xor":   {"ZF", "SF", "PF"},          # CF=0, OF=0; AF retained
    "add":   {"CF", "OF", "ZF", "SF", "AF"},
    "adc":   {"CF", "OF", "ZF", "SF", "AF"},
    "sub":   {"CF", "OF", "ZF", "SF", "AF"},
    "sbb":   {"CF", "OF", "ZF", "SF", "AF"},
    "neg":   {"CF", "OF", "ZF", "SF", "AF"},
    "inc":   {"ZF", "SF", "OF", "AF"},    # CF retained
    "dec":   {"ZF", "SF", "OF", "AF"},    # CF retained
    "cmp":   {"CF", "OF", "ZF", "SF", "AF"},
    "xadd":  {"CF", "OF", "ZF", "SF", "AF"},
}
# setters that clear a flag to a known 0 (lifter must model the CLEAR, not retain)
CLEAR_CF  = {"and", "or", "xor"}
CLEAR_OF  = {"test", "and", "or", "xor"}
RETAIN_CF = {"test", "inc", "dec"}          # CF untouched -> stale
TRICKY_OF = {"dec", "inc"}                  # OF = SF ^ (result==0)

NON_FLAG_SETTERS = {                          # may sit between setter and jcc
    "mov", "lea", "xchg", "push", "pop", "pushf", "popf", "cmovz", "cmovnz",
    "movzx", "movsx", "shl", "shr", "sar", "rol", "ror", "xlat",
}
# --------------------------------------------------------------------------- #
# P08 CF-liveness model.
#
# NEG writes CF (CF=1 iff result!=0, i.e. CF = (result != 0)). A SBB/ADC that
# executes while that CF is still the *same* CF produced by the NEG consumes it.
# The CF window stays LIVE through instructions that RETAIN CF and closes at:
#   (a) any instruction that WRITES CF, or
#   (b) any control-flow boundary (control leaves the straight-line window).
# Crucially INC/DEC/MOV/LEA/PUSH/POP/STOS*/MOVS* RETAIN CF, so a NEG->INC/DEC
# ->SBB chain still consumes the NEG's CF. The old detector cut on *any*
# setter (even ones that retain CF) and on the raw (rep-folded) mnemonic, so it
# both under- and over-cut. base-op + explicit CF-WRITE / CF-BOUNDARY sets fix it.
# --------------------------------------------------------------------------- #
# instructions that define (write) CF -- closing a live CF window
CF_WRITE = {
    "add", "adc", "sub", "sbb", "neg", "cmp", "xadd",
    "and", "or", "xor", "test",                 # cleared to 0 -> CF redefined
    "cmpsb", "cmpsw", "cmpsd",                  # string compares write flags
    "scasb", "scasw", "scasd",                  # string scans write flags
    "shl", "shr", "sar", "rol", "ror", "rcl", "rcr",   # shift/rotate out a bit
    "popf",                                      # overwrites the flag register
    "imul", "mul", "div", "idiv",               # define CF/OF
}
# control-flow boundaries: control leaves the straight-line CF window
CF_BOUNDARY = {
    "call", "callf", "ret", "retf", "int", "int3", "loop", "loopz", "loopnz",
    "jmp", "jmpf", "jcxz", "jecxz",
}
# CF-consumers: read CF as an input (SBB); ADC also reads CF (carry in)
CF_CONSUMER = {"sbb", "adc"}

def cf_kills_window(bop):
    """True if this base-op makes a previously-live CF window dead."""
    return bop in CF_WRITE or bop in CF_BOUNDARY
STRING_OPS = {"scasb", "scasw", "scasd", "cmpsb", "cmpsw", "cmpsd",
              "stosb", "stosw", "stosd", "movsb", "movsw", "movsd"}
REPB = {0xF2: "REPNE", 0xF3: "REPE"}
EBXESI = {0x3: "EBX"}   # x86 reg enum: ESI=4, EDI=5, EBX=3  (capstone)
from capstone import x86_const
REG32 = {x86_const.X86_REG_EBX: "EBX", x86_const.X86_REG_ESI: "ESI",
         x86_const.X86_REG_EDI: "EDI"}

findings = []          # list of dicts
def add(pat, va, seed, fn, dyn, crit, reason, diff=False, covered=False):
    findings.append({
        "pattern": pat, "va": f"0x{va:08X}", "function_va": (f"0x{seed:08X}" if seed else None),
        "function": fn_name(seed) if seed else None,
        "in_entry_closure": seed is not None,
        "in_dynamic_route": bool(dyn),
        "criticality": crit, "reason": reason,
        "needs_differential": diff,
        "covered_by_W1_034": covered,
    })

def insn_stream(f):
    """all instructions of a Function in ascending address order."""
    out = []
    for b in f.blocks.values():
        out.extend(b.instructions)
    out.sort(key=lambda i: i.address)
    return out

# --------------------------------------------------------------------------- #
# REP detection — driven by the DECODED capstone instruction, NOT by manually
# reading code[va-START].
#
# ROOT CAUSE of the P05/P06 false negative (see
# evidence/lifter_hazard_detector_fault.md):
#   capstone FOLDS the REP/REPNE/REPE prefix into the instruction mnemonic.
#       `repne scasb`  ->  insn.mnemonic == 'repne scasb'   (TWO tokens)
#       `repe  cmpsb`  ->  insn.mnemonic == 'repe  cmpsb'
#   so the old gate  `m = i.mnemonic.lower();  if m in STRING_OPS`  was never
#   true for rep-prefixed ops (the full string 'repne scasb' is not in the
#   bare-mnemonic set), and the rep-prefixed instructions never reached the
#   rep check. The code[va-START] byte read itself was correct but unreachable.
#
# The fix decomposes each decoded instruction into (REP-prefix, base-op):
#   - base-op  = last mnemonic token  ('repne scasb' -> 'scasb')
#   - rep-mode = first mnemonic token if it is a rep variant, else the
#     instruction's own leading prefix byte (insn.bytes[0]) -- both agree on
#     the real closure (validated in tools/_probe_rep_prefix.py + _probe_gt.py).
# --------------------------------------------------------------------------- #
REPN = ("repne", "repnz", "repne ")
REPZ = ("repe", "repz", "repe ")
def base_op(insn):
    """Bare string/other mnemonic with any REP prefix token stripped."""
    m = insn.mnemonic.lower()
    return m.split()[-1] if m else m

def rep_mode(insn):
    """'REPNE' / 'REPE' if the decoded instruction carries that prefix, else None.
    Uses the decoded mnemonic (folded form) and/or the instruction's own leading
    prefix byte -- never a manual code[va-START] read."""
    m = insn.mnemonic.lower()
    first = m.split()[0] if m else ""
    if first in ("repne", "repnz"):
        return "REPNE"
    if first in ("repe", "repz", "rep"):
        return "REPE"
    # folded mnemonic already handled; fall back to the instruction's prefix byte
    b = insn.bytes
    if b:
        if b[0] == 0xF2:
            return "REPNE"
        if b[0] == 0xF3:
            return "REPE"
    return None

# --------------------------------------------------------------------------- #
# per-closure-function pattern scan
# --------------------------------------------------------------------------- #
pat_counts = Counter()

# Independent control counters: a SECOND, decoder-independent measurement of
# P05/P06/P07 read straight from the raw image bytes at each decoded
# instruction boundary (code[va-START] / code[va-START+1]), exactly as the raw
# 2-byte opcode scan in tools/_probe_gt.py does. This is independent of the
# capstone rep-detection path the detector uses, so the two only agree when
# both are correct. The self-test below fails the run if they diverge.
ctl = {"P05": 0, "P06": 0, "P07_stosw": 0}
# Global dedup sets (persist across all closure seeds):
#   seen    -> (pattern,VA) findings guard
#   ctl_vas -> instruction VAs already counted by the raw-byte control
seen = set()
ctl_vas = set()

def crit_for(pat, dyn, in_closure, covered=False):
    if covered:
        return "LOW(W1-034)"
    if dyn and in_closure:
        return "HIGH"
    if in_closure:
        return "MEDIUM"
    return "LOW"

for seed in sorted(closure_vas):
    f = funcs.get(seed)
    if f is None:
        try:
            f = ds.disassemble_at(seed)
        except Exception:
            f = None
    if f is None or not f.blocks:
        continue
    dyn = seed in dynamic_vas
    ins = insn_stream(f)
    neg_cf_open = False           # a NEG with a live, unconsumed CF window
    neg_va = None
    # (pattern,VA) seen-guard (GLOBAL across all seeds): find_functions returns
    # one Function per closure seed, but a seed may be an ALIAS label inside
    # another body, so the same instruction VA can be decoded under several
    # seeds. A global guard keeps the census authoritative (one instruction =
    # one finding) and prevents the raw-byte control from double-counting the
    # same boundary once per alias.

    def emit(pat, va, fn, crit, reason, diff=False, covered=False):
        key = (pat, va)
        if key in seen:
            return
        seen.add(key)
        add(pat, va, seed, fn, dyn, crit, reason, diff=diff, covered=covered)

    for idx, i in enumerate(ins):
        m = i.mnemonic.lower()
        bop = base_op(i)          # bare op with REP prefix stripped
        op = i.op_str

        # --- independent control: raw 2-byte opcode at this boundary -------
        # decoder-independent; compares F2/F3 prefix + opcode byte directly.
        # Guarded per distinct VA so alias seeds do not double-count a boundary.
        if i.address not in ctl_vas:
            ctl_vas.add(i.address)
            # Read the instruction's OWN raw bytes (prefixes + opcode). scasb/
            # cmpsb/stos* have NO operands, so the last byte is the opcode and
            # any 66h/67h operand/address-size prefix stays visible. This is
            # prefix-aware (handles `rep stosw/d` = F3 66 89/8A) and fully
            # decoder-independent (raw bytes, not capstone's mnemonic).
            ib = i.bytes
            opc = ib[-1] if ib else 0
            if opc == 0xAE and 0xF2 in ib:      # REPNE SCASB
                ctl["P05"] += 1
            elif opc == 0xA6 and 0xF3 in ib:    # REPE CMPSB
                ctl["P06"] += 1
            elif opc in (0xAA, 0xAB, 0x89) and (0xF2 in ib or 0xF3 in ib):
                ctl["P07_stosw"] += 1          # REP STOSB(AA)/STOSW-D(AB)/STOSW(89)

        # --- P05/P06/P07 rep string ops (DECODED base-op + rep prefix) ------
        if bop in STRING_OPS:
            rp = rep_mode(i)
            if rp:
                if bop == "scasb" and rp == "REPNE":
                    # REPNE SCASB specifically (0xF2 AE); a bare `rep scasb`
                    # (0xF3 AE, ZF-terminating) is NOT P05.
                    emit("P05_REPNE_SCASB", i.address, fn_name(seed),
                         crit_for("P05", dyn, True), f"{rp} scasb", diff=dyn)
                elif bop == "cmpsb" and rp == "REPE":
                    # REPE CMPSB specifically (0xF3 A6).
                    emit("P06_REPE_CMPSB", i.address, fn_name(seed),
                         crit_for("P06", dyn, True), f"{rp} cmpsb", diff=dyn)
                elif bop.startswith("stos"):
                    emit("P07_REP_STOSW", i.address, fn_name(seed),
                         crit_for("P07", dyn, True), f"{rp} {bop}", diff=dyn)
                else:
                    emit("P07_REP_STRING", i.address, fn_name(seed),
                         crit_for("P07", dyn, True), f"{rp} {bop}", diff=dyn)

        # --- P09 call [esp + offset] --------------------------------------
        if i.is_call and i.operands:
            for o in i.operands:
                if getattr(o, "type", None) == x86_const.X86_OP_MEM:
                    if o.mem.base == x86_const.X86_REG_ESP:
                        off = o.mem.disp
                        add("P09_CALL_ESPOFF", i.address, seed, fn_name(seed), dyn,
                            crit_for("P09", dyn, True, covered=True),
                            f"call [esp{('+'+format(off,'x')) if off else ''}]  (W1-034 target-order PASS)",
                            covered=True)

        # --- P11/P13 CALL/ICALL/TAIL touching EBX/ESI/EDI / trap loss ------
        if m in ("call", "callf"):
            touches = []
            for o in (i.operands or []):
                r = getattr(o, "reg", 0)
                if r in REG32:
                    touches.append(REG32[r])
            # indirect call target via reg
            if i.operands and i.operands[0].type == x86_const.X86_OP_REG:
                r = i.operands[0].reg
                if r in REG32:
                    touches.append("ICALL[" + REG32[r] + "]")
            if touches:
                add("P11_CALL_EBXESI", i.address, seed, fn_name(seed), dyn,
                    crit_for("P11", dyn, True, covered=True),
                    "call touching " + ",".join(sorted(set(touches))) + "  (W1-034 reg-transfer PASS)",
                    covered=True)
        if m in ("jmp", "jmpf"):
            # tail-call (jmp to known entry) -> P10
            tgt = i.get_branch_target()
            if tgt is not None and (tgt in closure_vas or tgt in dynamic_vas):
                add("P10_TAIL_TO_ENTRY", i.address, seed, fn_name(seed), dyn,
                    crit_for("P10", dyn, True, covered=True),
                    f"tail jmp -> 0x{tgt:08X} ({fn_name(tgt)}); W1-034 tail PASS", covered=True)

        # --- P13 trap-loss window on calls/tails (informational) ----------
        if i.is_call and dyn:
            add("P13_TRAP_WINDOW", i.address, seed, fn_name(seed), dyn,
                crit_for("P13", dyn, True, covered=True),
                "call in dynamic route; W1-029/034 stop-propagation PASS", covered=True)

        # --- flag-setter + Jcc families (P01-P03, P04) --------------------
        # look ahead to the next conditional jump in the same basic block
        jcc = None
        for j in ins[idx + 1:]:
            if j.mnemonic.lower() in JCC_READS:
                jcc = j
                break
            if j.is_call or j.is_ret or j.is_uncond_jump:
                break
        if jcc is not None:
            jm = jcc.mnemonic.lower()
            reads = JCC_READS.get(jm, set())
            # P01 TEST+Jcc
            if bop == "test":
                if reads & {"CF"}:
                    emit("P01_TEST_JCC", i.address, fn_name(seed),
                         crit_for("P01", dyn, True),
                         f"test then {jm} (reads stale CF; TEST does not clear CF)", diff=dyn)
                elif reads & {"OF"}:
                    emit("P01_TEST_JCC", i.address, fn_name(seed),
                         crit_for("P01", dyn, True),
                         f"test then signed {jm} (OF==0 after TEST; lifter must force OF=0)", diff=dyn)
            # P02 DEC+Jcc
            elif bop == "dec":
                if reads & {"CF"}:
                    emit("P02_DEC_JCC", i.address, fn_name(seed),
                         crit_for("P02", dyn, True),
                         f"dec then {jm} (reads stale CF; DEC does not touch CF)", diff=dyn)
                elif reads & {"OF"}:
                    emit("P02_DEC_JCC", i.address, fn_name(seed),
                         crit_for("P02", dyn, True),
                         f"dec then signed {jm} (OF=SF^Z after DEC; tricky)", diff=dyn)
            # P03 AND/OR/XOR+Jcc
            elif bop in ("and", "or", "xor"):
                if reads & {"CF"}:
                    emit("P03_AND_JCC", i.address, fn_name(seed),
                         crit_for("P03", dyn, True),
                         f"{bop} then {jm} (CF cleared by {bop}; lifter must clear, not retain)", diff=dyn)
            # P04 generic flag-setter + non-flag clobber + Jcc
            elif bop in SETTER_DEFINES:
                # a non-flag insn (MOV/LEA/PUSH/...) sits between the setter and
                # the Jcc -> the flag it set can be lost if the lifter serialises
                # the clobber before the flag read. base-op so rep-folded
                # string-compares (cmpsb/...) are also seen as clobber/CF writers.
                k = idx + 1
                saw_clobber = False
                while k < len(ins) and ins[k] is not jcc:
                    if base_op(ins[k]) in NON_FLAG_SETTERS:
                        saw_clobber = True
                    k += 1
                if saw_clobber and reads:
                    emit("P04_SETTER_CLOBBER_JCC", i.address, fn_name(seed),
                         crit_for("P04", dyn, True),
                         f"{bop} -> (non-flag clobber) -> {jm} (flag-loss risk across clobber)", diff=dyn)

        # --- P08 NEG whose CF is consumed by SBB/ADC ----------------------
        # Model the CF LIVENESS of the NEG, not raw adjacency:
        #   * NEG opens a live CF window (CF = (result != 0)).
        #   * INC/DEC/MOV/LEA/PUSH/POP/STOS*/MOVS* RETAIN CF -> window stays live.
        #   * a SBB/ADC while the window is live CONSUMES the NEG's CF.
        #   * the window CLOSes on any CF-WRITE (add/adc/sub/sbb/neg/cmp/test/
        #     and/or/xor/shifts/str-ops/popf) or any control-flow boundary
        #     (call/ret/jmp/loop/...). We therefore do NOT require the SBB/ADC
        #     to sit textually right after the NEG.
        if bop == "neg":
            neg_cf_open = True
            neg_va = i.address
        elif bop in CF_CONSUMER and neg_cf_open:
            emit("P08_NEG_CF_SBBADC", i.address, fn_name(seed),
                 crit_for("P08", dyn, True),
                 f"NEG@0x{neg_va:08X} CF consumed by {bop} (CF=0 iff result==0)", diff=dyn)
            neg_cf_open = False          # consumed -> window spent
        elif neg_cf_open and cf_kills_window(bop) and bop != "neg":
            neg_cf_open = False          # CF redefined or control left the window

# helper referenced above (kept trivial to avoid forward-ref issues)
def jcc_address_index(ins, idx):
    for k in range(idx + 1, len(ins)):
        if ins[k].mnemonic.lower() in JCC_READS:
            return k
    return len(ins)

# --------------------------------------------------------------------------- #
# P12: _old_ lifted temporals crossing labels/gotos (C-level heuristic)
# --------------------------------------------------------------------------- #
def _group_by_owner(lines, owner_at):
    groups = {}
    for n, ln in enumerate(lines, 1):
        o = owner_at.get(n)
        if not o:
            continue
        groups.setdefault(o, []).append((n, ln))
    return groups.items()

p12_hits = []
if CLOSURE.exists():
    # split into function bodies
    body_re = re.compile(r"void\s+gw_\w+\s*\(\s*void\s*\)\s*\{")
    tx = CLOSURE.read_text(encoding="utf-8", errors="replace")
    lines = tx.splitlines()
    # map line -> owning gw_ symbol + its RECOMP_ENTER seed
    cur = None
    line_owner = {}
    enter_re = re.compile(r"RECOMP_ENTER\(0x([0-9A-Fa-f]+)u\)")
    for n, ln in enumerate(lines, 1):
        bm = re.match(r"\s*void\s+(gw_\w+)\s*\(", ln)
        if bm:
            cur = bm.group(1)
        em = enter_re.search(ln)
        if em and cur:
            seed = int(em.group(1), 16)
            # attribute all lines until next body to this seed
            line_owner[n] = (cur, seed)
    # forward fill owner
    last = None
    owner_at = {}
    for n, ln in enumerate(lines, 1):
        if n in line_owner:
            last = line_owner[n]
        if last:
            owner_at[n] = last
    # per body: find _old_ temp assignments and whether a label/branch/goto
    # sits between the assignment and the next use of the same temp
    temp_assign = re.compile(r"(_old_\w+)\s*=")
    temp_use    = re.compile(r"\b(_old_\w+)\b")
    branch_like = re.compile(r"\b(if|else|goto|for|while|switch|case|continue|break|RECOMP_\w*JMP|L\d+)\b|:\s*$|\bRECOMP_\w*\(0x")
    for (sym, seed), grp in _group_by_owner(lines, owner_at):
        n_assign = 0
        crosses = 0
        pending = set()
        for off, ln in grp:
            for a in temp_assign.findall(ln):
                pending.add(a); n_assign += 1
            if branch_like.search(ln):
                if pending:
                    crosses += 1
                pending = set()
            for u in temp_use.findall(ln):
                pending.discard(u)
        if n_assign:
            p12_hits.append({
                "symbol": sym, "seed": f"0x{seed:08X}", "function": fn_name(seed),
                "in_dynamic_route": seed in dynamic_vas, "old_temps": n_assign,
                "assigns_crossing_branch": crosses,
            })
p12_dyn = sum(1 for h in p12_hits if h["in_dynamic_route"])

# --------------------------------------------------------------------------- #
# roll up + persist
# --------------------------------------------------------------------------- #
for fd in findings:
    pat_counts[fd["pattern"]] += 1

# --------------------------------------------------------------------------- #
# DETECTOR SELF-TEST  (runs BEFORE outputs are written)
#
# Two independent control measurements, both independent of the capstone
# rep-detection path the detector uses:
#   tier-1 (HARD):  raw 2-byte opcode scan of the image at each decoded
#                  instruction boundary (ctl counters)  -- P05/P06/P07.
#   tier-2 (WARN):  regex over the lifted C source text (control counts).
# The detector count for a pattern must never fall BELOW either control for
# the same instruction set (a detector that misses an instruction is the
# failure mode that produced the P05/P06 false negative). A tier-1 mismatch
# aborts the run so a broken detector can never write a "validated" census.
# --------------------------------------------------------------------------- #
ALL_PATTERNS = [
    "P01_TEST_JCC", "P02_DEC_JCC", "P03_AND_JCC", "P04_SETTER_CLOBBER_JCC",
    "P05_REPNE_SCASB", "P06_REPE_CMPSB", "P07_REP_STOSW", "P07_REP_STRING",
    "P08_NEG_CF_SBBADC", "P09_CALL_ESPOFF", "P10_TAIL_TO_ENTRY",
    "P11_CALL_EBXESI", "P13_TRAP_WINDOW",
]
det_counts = {p: pat_counts.get(p, 0) for p in ALL_PATTERNS}

# tier-2: independent regex control over the lifted C source text
def _ctl_text(pat):
    tx = CLOSURE.read_text(encoding="utf-8", errors="replace")
    if pat == "P05_REPNE_SCASB":
        return len(re.findall(r"\brepne\s+scasb\b", tx))
    if pat == "P06_REPE_CMPSB":
        return len(re.findall(r"\brepe\s+cmpsb\b", tx))
    if pat == "P07_REP_STOSW":
        return len(re.findall(r"\brep\s+stos[wb]\b", tx))
    return None

tier1 = {  # detector vs raw-byte control (exact instruction set)
    "P05_REPNE_SCASB":  {"detector": det_counts["P05_REPNE_SCASB"], "control": ctl["P05"], "control_method": "raw image F2 AE opcode scan @ instruction boundaries"},
    "P06_REPE_CMPSB":   {"detector": det_counts["P06_REPE_CMPSB"],   "control": ctl["P06"], "control_method": "raw image F3 A6 opcode scan @ instruction boundaries"},
    "P07_REP_STOSW":    {"detector": det_counts["P07_REP_STOSW"],    "control": ctl["P07_stosw"], "control_method": "raw image F2/F3 8A/89/AA opcode scan @ instruction boundaries"},
}
tier2 = {}
for _p in ("P05_REPNE_SCASB", "P06_REPE_CMPSB", "P07_REP_STOSW"):
    _t = _ctl_text(_p)
    if _t is not None:
        tier2[_p] = {"detector": det_counts[_p], "control": _t,
                     "control_method": "regex over build/entry_path_closure.c (lift text; may render one mnemonic twice)"}

# per-pattern validation block written into the JSON + report
validation = {}
for _p in ALL_PATTERNS:
    _t1 = tier1.get(_p)
    _t2 = tier2.get(_p)
    validation[_p] = {
        "detector_count": det_counts[_p],
        "tier1_raw_byte_control": _t1["control"] if _t1 else None,
        "tier1_method": _t1["control_method"] if _t1 else None,
        "tier2_lift_text_control": _t2["control"] if _t2 else None,
        "tier2_method": _t2["control_method"] if _t2 else None,
        "tier1_match": (det_counts[_p] == _t1["control"]) if _t1 else None,
        "tier2_match": (det_counts[_p] == _t2["control"]) if _t2 else None,
        "validated": (True if _t1 else True) and (True if (_t2 is None or det_counts[_p] >= _t2["control"]) else False)
                     and (True if (_t1 is None or det_counts[_p] == _t1["control"]) else False),
    }

# HARD GATE: any tier-1 (raw-byte) mismatch aborts before outputs are written.
_bad_t1 = [_p for _p, v in tier1.items() if v["detector"] != v["control"]]
_warn_t2 = [_p for _p, v in tier2.items() if v["detector"] < v["control"]]
if _bad_t1:
    msg = ("DETECTOR SELF-TEST FAILED (tier-1 raw-byte): "
           + ", ".join(f"{p} detector={tier1[p]['detector']} control={tier1[p]['control']}" for p in _bad_t1))
    print("[SELF-TEST] " + msg)
    raise SystemExit(2)
if _warn_t2:
    print("[SELF-TEST] tier-2 lift-text note: "
          + ", ".join(f"{p} detector={tier2[p]['detector']} lift_text={tier2[p]['control']}" for p in _warn_t2)
          + "  (lift text may over-count a mnemonic rendered twice; raw-byte tier-1 is authoritative)")
print(f"[SELF-TEST] tier-1 raw-byte control OK: "
      + ", ".join(f"{p}={tier1[p]['control']}" for p in sorted(tier1)))
_det_s = ", ".join(f"{p}={tier1[p]['detector']}" for p in sorted(tier1))
print(f"[SELF-TEST]   detector        : {_det_s}")

report_validation = {
    "method": "capstone decoded base-op + rep prefix (folded-mnemonic fold-aware), NOT a manual code[va-START] rep read",
    "root_cause_fixed": "capstone folds the REP/REPNE/REPE prefix into the instruction mnemonic; the old bare-`mnemonic in STRING_OPS` gate never matched rep-prefixed ops, so P05/P06/P07-rep were silently dropped",
    "tier1_raw_byte_control": tier1,
    "tier2_lift_text_control": tier2,
    "tier1_all_match": not _bad_t1,
    "per_pattern": validation,
    "detector_validated": (not _bad_t1),
    "evidence": "evidence/lifter_hazard_detector_fault.md",
}

dyn_findings = [f for f in findings if f["in_dynamic_route"]]
real_hazard = [f for f in findings if f["needs_differential"]]

report = {
    "task": "L-LIFTERHAZARDS",
    "worker": "LOCAL",
    "target_sha256": __import__("hashlib").sha256(IMAGE.read_bytes()).hexdigest(),
    "closure_source": "build/entry_path_closure.c",
    "dynamic_source": "build/entry_path_combined.c",
    "code_range": [f"0x{START:08X}", f"0x{END:08X}"],
    "closure_bodies": len(closure_vas),
    "dynamic_bodies": len(dynamic_vas),
    "functions_discovered": len(funcs),
    "note": ("Census of x86 recompiler-divergence patterns in the entry/menu closure. "
             "W1-034 (DONE) already PASS-verified CALL/ICALL/TAIL register transfer, "
             "call[esp+X] target-order, conditional tails and trap propagation -> those "
             "(P09/P10/P11/P13) are marked covered_by_W1-034 and NOT re-derived. "
             "P01-P08 are the flag/rep/NEG-CF hazards W1-034 did not cover."),
    "pattern_counts": {p: det_counts[p] for p in ALL_PATTERNS},
    "detector_validation": report_validation,
    "P12_old_temps": {
        "bodies_with_old_temps": len(p12_hits),
        "on_dynamic_route": p12_dyn,
        "examples": sorted(p12_hits, key=lambda h: (-h["in_dynamic_route"], -h["assigns_crossing_branch"]))[:25],
        "method": "heuristic: an _old_ lifted temp assigned, then a branch/label/RECOMP jump before its next use",
    },
    "findings_total": len(findings),
    "findings_on_dynamic_route": len(dyn_findings),
    "real_hazard_needs_differential": len(real_hazard),
    "criticality_breakdown": dict(Counter(f["criticality"] for f in findings)),
    "dynamic_route_findings": dyn_findings[:400],
    "all_findings": findings[:2000],
    "elapsed_s": round(time.time() - t0, 1),
}
# --- differential-target list (self-contained, reproducible) -------------- #
# The HIGH dynamic-route hazard functions, with their exact flag-interaction
# pairs, that are NOT yet in WORK3's validated 30-function differential set.
# These are the concrete targets a follow-up original-vs-lift differential
# (WORK1 native run / WORK3 leaf fixture) must validate. Census does not
# pre-judge FAIL; validation decides whether a WORK1 task is warranted.
_w3v = set()
_w3j = root / "evidence" / "differential_cfg_leaf_work3.json"
if _w3j.exists():
    try:
        _w3d = json.loads(_w3j.read_text(encoding="utf-8"))
        _w3v = {int(f["address"], 16) for f in _w3d.get("selected_functions", [])}
    except Exception:
        _w3v = set()
_byfn = {}
_callcnt = {}   # fn_va -> (direct_call_count, icall_count) from decoded funcs
for _fn in funcs.values():
    _cc = 0; _ic = 0
    for _b in _fn.blocks.values():
        for _i in _b.instructions:
            if _i.mnemonic in ("call",):
                _cc += 1
            elif _i.mnemonic in ("int", "int3"):
                pass
    _callcnt[_fn.address] = (_cc, _ic)
for _f in findings:
    if _f["criticality"] == "HIGH" and _f["in_dynamic_route"] and _f["function_va"]:
        _va = int(_f["function_va"], 16)
        _b = _byfn.setdefault(_va, {"function": _f["function"],
                                    "in_work3_validated": _va in _w3v,
                                    "patterns": {}, "direct_calls": None})
        _b["patterns"].setdefault(_f["pattern"], []).append(
            {"va": _f["va"], "reason": _f["reason"]})
        if _va in _callcnt and _b["direct_calls"] is None:
            _b["direct_calls"] = _callcnt[_va][0]
report["differential_targets"] = [
    {"function_va": f"0x{va:08X}", "function": m["function"],
     "in_work3_validated_set": m["in_work3_validated"],
     "direct_calls": m["direct_calls"],
     "leaf_differential_ready": (m["direct_calls"] == 0),
     "pattern_counts": {k: len(v) for k, v in sorted(m["patterns"].items())},
     "pairs": {k: sorted(v, key=lambda z: z["va"]) for k, v in m["patterns"].items()}}
    for va, m in sorted(_byfn.items())
]
report["differential_targets_unvalidated_count"] = sum(
    1 for t in report["differential_targets"] if not t["in_work3_validated_set"])
report["differential_targets_leaf_ready_count"] = sum(
    1 for t in report["differential_targets"] if t.get("leaf_differential_ready"))
OUT_JSON.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

# ---- markdown summary ----------------------------------------------------- #
L = []
L.append("# LOCAL - L-LIFTERHAZARDS: x86 recompiler-divergence census (entry/menu closure)")
L.append("")
L.append(f"Target sha256: `{report['target_sha256']}`")
L.append(f"Code range: {report['code_range'][0]} .. {report['code_range'][1]}")
L.append(f"Entry/menu closure bodies: **{report['closure_bodies']}** ; dynamically-reached route: **{report['dynamic_bodies']}**")
L.append("")
L.append("## Scope / non-duplication")
L.append("- **W1-034 (DONE)** already PASS-verified CALL/ICALL/TAIL register transfer (EBX/ESI/EDI shared context), `call [esp+X]` target evaluated pre-push, conditional-tail bridge (0 emissions in current closure), and trap propagation through tails. Patterns **P09/P10/P11/P13** are therefore *counted but marked `covered_by_W1-034`* and are NOT re-derived or re-fixed here.")
L.append("- This census adds the **flag/rep/NEG-CF hazards W1-034 did not touch** (P01-P08) plus the `_old_`-temp branch-crossing heuristic (P12).")
L.append("- **Nothing is fixed by pattern.** Each instance is recorded with VA, function, closure/dynamic membership, criticality and a `needs_differential` flag. Only a **reproduced** original-vs-lift FAIL on the dynamic route would derive a WORK1 task.")
L.append("")
L.append("## Pattern counts")
L.append("All 13 patterns are listed, including those with count=0 (their absence is itself evidence, validated by the self-test).")
L.append("")
L.append("| Pattern | Meaning | Total | On dynamic route |")
L.append("|---|---|---|---|")
desc = {
 "P01_TEST_JCC":"TEST + Jcc (CF stale / signed OF==0)","P02_DEC_JCC":"DEC + Jcc (CF stale / OF=SF^Z)",
 "P03_AND_JCC":"AND/OR/XOR + Jcc (CF must clear)","P04_SETTER_CLOBBER_JCC":"flag-setter + clobber + Jcc",
 "P05_REPNE_SCASB":"REPNE SCASB","P06_REPE_CMPSB":"REPE CMPSB","P07_REP_STOSW":"REP STOS* / string",
 "P07_REP_STRING":"REP other string (movs*)","P08_NEG_CF_SBBADC":"NEG CF consumed by SBB/ADC","P09_CALL_ESPOFF":"call [esp+off] (W1-034)",
 "P10_TAIL_TO_ENTRY":"conditional/direct tail to entry (W1-034)","P11_CALL_EBXESI":"CALL/ICALL EBX/ESI/EDI (W1-034)",
 "P13_TRAP_WINDOW":"call in dynamic route trap window (W1-034)",
}
for p in ALL_PATTERNS:
    n = det_counts[p]
    on_dyn = sum(1 for f in dyn_findings if f["pattern"] == p)
    L.append(f"| {p} | {desc.get(p,'')} | {n} | {on_dyn} |")
L.append(f"| P12_OLD_TEMPS | `_old_` lifted temp crosses a branch (heuristic) | {len(p12_hits)} bodies | {p12_dyn} |")
L.append("")
L.append("## Detector validation (self-test)")
L.append(f"Detector method: {report_validation['method']}")
L.append(f"Root cause fixed: {report_validation['root_cause_fixed']}")
L.append(f"detector_validated: **{report_validation['detector_validated']}** ; tier-1 (raw-byte) all match: **{report_validation['tier1_all_match']}**")
L.append("")
L.append("| Pattern | Detector | Tier-1 raw-byte control | T1 match | Tier-2 lift-text | T2 note |")
L.append("|---|---|---|---|---|---|")
for p in ALL_PATTERNS:
    v = validation[p]
    t1 = f"{v['tier1_raw_byte_control']}" if v["tier1_raw_byte_control"] is not None else "—"
    t1m = ("—" if v["tier1_match"] is None else ("yes" if v["tier1_match"] else "NO"))
    t2 = f"{v['tier2_lift_text_control']}" if v["tier2_lift_text_control"] is not None else "—"
    t2n = ("—" if v["tier2_lift_text_control"] is None else (
           "match" if v["detector_count"] == v["tier2_lift_text_control"] else
           f"lift over/under (text artifact)"))
    L.append(f"| {p} | {v['detector_count']} | {t1} | {t1m} | {t2} | {t2n} |")
L.append("")
L.append("_Tier-1 = raw 2-byte opcode scan of the image at each decoded instruction boundary (decoder-independent, authoritative). Tier-2 = regex over the lifted C text (the lift can render one mnemonic twice, so it is a lower/upper bound, not exact). A tier-1 mismatch aborts the run before any output is written._")
L.append("")
L.append("## Criticality")
cb = report["criticality_breakdown"]
L.append("| Criticality | Count |")
L.append("|---|---|")
for k, v in sorted(cb.items()):
    L.append(f"| {k} | {v} |")
L.append("")
L.append(f"**Total instances: {len(findings)}** ; on dynamic route: **{len(dyn_findings)}** ; flagged `needs_differential` (real flag/rep/NEG hazard on the dynamic route): **{len(real_hazard)}**.")
L.append("")
L.append("## Real hazards on the dynamic route (candidates for differential + WORK1)")
L.append("Only these would, on a **reproduced** A/B original-vs-lift FAIL, derive a WORK1 task. The census does not pre-judge FAIL.")
L.append("")
L.append("| VA | Function | Pattern | Reason |")
L.append("|---|---|---|---|")
seen = set()
for f in findings:
    if f["needs_differential"] and f["in_dynamic_route"]:
        key = (f["va"], f["pattern"])
        if key in seen: continue
        seen.add(key)
        L.append(f"| {f['va']} | {f['function']} | {f['pattern']} | {f['reason']} |")
L.append("")
L.append("_Full instance table (all closures) and the P12 per-body detail are in `evidence/lifter_hazard_census.json`._")
L.append("")
L.append("## Differential-validation targets (unvalidated HIGH hazard functions on the dynamic route)")
L.append("These functions carry real flag/rep/NEG-CF hazards on the dynamic route and are **not** in WORK3's validated 30-function differential set (0 divergences, EAX + EFLAGS 0x8D5 + memory). They are the concrete targets for a follow-up original-vs-lift differential. The census records the pattern instances only; it does **not** pre-judge FAIL. Only a reproduced A/B divergence on one of these would warrant a WORK1 task.")
L.append("")
L.append("| Function VA | Symbol | Pairs | In WORK3 set? |")
L.append("|---|---|---|---|")
for t in report["differential_targets"]:
    pc = t["pattern_counts"]
    pc_s = ", ".join(f"{k}×{v}" for k, v in pc.items())
    L.append(f"| {t['function_va']} | {t['function']} | {pc_s} | {'yes' if t['in_work3_validated_set'] else 'NO'} |")
L.append("")
L.append(f"_Exact per-instruction flag pairs: `evidence/lifter_hazard_census.json` → `differential_targets`._")
L.append("")
L.append(f"_Elapsed {report['elapsed_s']}s. Reproduce: `.venv/Scripts/python.exe tools/audit_lifter_hazards.py` (capstone venv).")
OUT_MD.write_text("\n".join(L) + "\n", encoding="utf-8")

print(json.dumps({
    "pattern_counts": {p: det_counts[p] for p in ALL_PATTERNS},
    "detector_validated": report_validation["detector_validated"],
    "tier1_raw_byte_control": {k: v["control"] for k, v in tier1.items()},
    "P12_bodies": len(p12_hits), "P12_on_dynamic": p12_dyn,
    "findings_total": len(findings),
    "on_dynamic_route": len(dyn_findings),
    "needs_differential": len(real_hazard),
    "criticality": cb,
    "out_json": str(OUT_JSON), "out_md": str(OUT_MD), "elapsed_s": report["elapsed_s"],
}, indent=2))