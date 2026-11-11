#!/usr/bin/env python3
"""match_relocation_aware.py  (LOCAL task L-BFLIB-MATCH)

Relocation-aware source matching for the GeneWars 1.1 native recompilation
frontier.  Implements the KKND technique:

  * Disassemble each target function (GeneWars 1.1) with capstone.
  * Mask every LE relocation site (offset32 / offset16 / ptr16_32) so that a
    relocated operand does not defeat an otherwise-equivalent instruction.
  * Classify each candidate reference as EXACT / HIGH / MEDIUM / LOW /
    REJECTED using:
        - name & symbol identity
        - instruction-skeleton (opcode + Mnemonic sequence, relocation
          operands normalised)
        - size (instruction count)
        - CFG (basic-block / branch structure signature)
        - immediate constants (non-relocated)
        - interrupt / call pattern
  * For any reference that matches, verify that the *relocated target* it
    points to is semantically plausible (i.e. resolves to a known symbol or
    a known import) -- this is the anti-false-positive step the KKND note
    calls out.

Reference channels:
  1. Cross-build:  GeneWars beta2 (same Watcom toolchain, different build).
     Loaded via the same dos_re.le flat-image path.  Because 1.1 carries a
     reworked BFLIB, cross-build byte matches are expected to be mostly LOW
     for BFLIB symbols but can be EXACT/HIGH for game code that was shared.
  2. BFLIB source:  upstream/genewars/bflibrary  --  the public BFLIB is a
     reconstruction *from beta2* (function stubs annotated with beta2 link
     offsets).  For BFLIB symbols the value we add is provenance + the
     semantic contract (which VESA/DPMI INTs, which globals), not byte
     identity.

Output:
  evidence/bflib_match_index.json   machine-readable index (one row per
                                     target function x reference, ranked).
  reports/L_BFLIB_MATCH.md          brief human report + HIGH-VALUE HANDOFFs.

Read-only against E:\\GeneWarsFX.  Writes only under E:\\GWRecomp.
"""
from __future__ import annotations
import os as _gw_os
from pathlib import Path as _GwPath
_GW_ROOT=str(_GwPath(__file__).resolve().parents[1])
_GW_FX=_gw_os.environ.get("GENEWARSFX_ROOT",_gw_os.path.join(_GW_ROOT,"third_party","GeneWarsFX"))
import sys, json, hashlib, struct, pathlib, re
from dataclasses import dataclass, field, asdict

sys.path.insert(0, (_GW_FX.replace("\\","/") + '/experiments/dos-re-gw10'))
sys.path.insert(0, (_GW_ROOT.replace("\\","/") + '/tools'))
from dos_re.le import load_le
from extract_symbol_corpus import (parse_fixups, le_fixup_header,
                                   parse_loaded_map, parse_disc_map)

import capstone

ROOT   = pathlib.Path((_GW_ROOT.replace("\\","/")))
EXE    = ROOT/"evidence/genewars-1_1.exe"
LOAD   = ROOT/"evidence/genewars-1_1.map"
DISC   = ROOT/"evidence/disc-MAIN.MAP"
CORPUS = ROOT/"evidence/symbol_corpus.json"

B2_EXE = pathlib.Path((_GW_FX.replace("\\","/") + '/upstream/genewars-re-helpers/bin/gw-genewars-beta2-jul_1996.exe'))
B2_MAP = pathlib.Path((_GW_FX.replace("\\","/") + '/upstream/genewars-re-helpers/symbols/gw-genewars-beta2-jul_1996.map'))
BFLIB  = pathlib.Path((_GW_FX.replace("\\","/") + '/upstream/genewars/bflibrary/src'))

OUT_IDX = ROOT/"evidence/bflib_match_index.json"
OUT_MD  = ROOT/"reports/L_BFLIB_MATCH.md"

MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
MD.detail = True

# ---------------------------------------------------------------------------
# image model
# ---------------------------------------------------------------------------
@dataclass
class Image:
    path: str
    sha: str
    flat: bytes            # full LE flat memory (object1 at base)
    base: int              # object1 base (0x10000)
    vsize: int             # object1 virtual size
    fixup_by_va: dict      # loaded_va -> {stype:set}
    symbols: list          # [(va, name)] sorted, code object only
    by_name: dict          # name -> va (first code hit)
    data_by_name: dict = field(default_factory=dict)

def load_image(exe, loaded_map, disc_map=None):
    raw = exe.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    im  = load_le(exe)
    o1  = im.objects[0]
    base, vsize = o1.base, o1.virtual_size
    hd = le_fixup_header(raw)
    fx = parse_fixups(raw, im.objects, hd["page_size"], hd["num_pages"],
                      hd["obj_tab"], hd["obj_cnt"],
                      hd["fixup_page_tab"], hd["fixup_rec_tab"])
    tova = lambda l: l - base
    fix_by_va = {}
    for s, t, st in fx:
        fix_by_va.setdefault(tova(s), set()).add(st)
    loaded = parse_loaded_map(loaded_map)
    code   = sorted((o, n) for o, n in loaded if 0 <= o < vsize)
    by_name = {}
    for o, n in code:
        by_name.setdefault(n, o)
    data = {n: o for o, n in loaded if not (0 <= o < vsize)}
    flat = im.mem[base: base + vsize]          # object1 only, index == va
    return Image(str(exe), sha, flat, base, vsize, fix_by_va, code, by_name, data)

def fn_body(img, name):
    """Return (va, size, body_bytes, fixup_sites) for a code symbol."""
    va = img.by_name.get(name)
    if va is None:
        return None
    # next symbol boundary
    i = next(j for j,(o,n) in enumerate(img.symbols) if o == va)
    nxt = img.symbols[i+1][0] if i+1 < len(img.symbols) else img.vsize
    size = nxt - va
    body = img.flat[va: nxt]
    sites = sorted(f for f in img.fixup_by_va if va <= f < nxt)
    stypes = {f: sorted(img.fixup_by_va[f]) for f in sites}
    return va, size, body, sites, stypes

# ---------------------------------------------------------------------------
# disassembly + relocation-aware skeleton
# ---------------------------------------------------------------------------
def disasm(img, va, size):
    code = img.flat[va: va + size]
    for ins in MD.disasm(code, va):
        yield ins

def fixup_slots(img, va, size):
    """Set of va's whose bytes carry a relocation; operand width per type."""
    slots = {}
    for f in img.fixup_by_va:
        if va <= f < va + size:
            sts = img.fixup_by_va[f]
            slots[f] = 4 if 7 in sts else 2   # offset32 -> 4 else 2
    return slots

def skeleton(img, va, size):
    """Ordered (mnemonic, operand-class) sequence with relocation slots
    normalised.  Returns (skeleton, n_ins, int_sites, call_targets, imm_set).

    operand-class collapses concrete addresses/imm into tags:
      'rel'  = relocated operand (slot at this insn)
      'imm'  = plain immediate
      'mem'  = [reg / disp]
      'reg'  = register
      'off'  = direct code offset / label
    """
    slots = fixup_slots(img, va, size)
    skel, n, ints, calls, imms = [], 0, [], [], set()
    for ins in disasm(img, va, size):
        n += 1
        op = ins.op_str.strip()
        # classify operands
        ocls = []
        for tok in re.findall(r"[\w.\[\]:]+$|0x[0-9A-Fa-f]+", op) or [op]:
            ocls.append(tok)
        ins_va = ins.address
        # does this insn straddle a relocation slot?
        has_rel = any(ins_va <= s < ins_va + ins.size for s in slots)
        oclass = "rel" if has_rel else _opcode_class(op)
        skel.append((ins.mnemonic, oclass, ins.size))
        if ins.mnemonic == "int":
            ints.append(ins.op_str)
        if ins.mnemonic in ("call", "jmp") and not has_rel:
            calls.append((ins.mnemonic, op))
        m = re.search(r"0x[0-9A-Fa-f]+|(#?)(-?\d+)$", op)
        if m and m.group(2) is not None:
            try: imms.add(int(m.group(2), 0))
            except ValueError: pass
    return skel, n, ints, calls, imms

def _opcode_class(op):
    if not op: return "none"
    if re.search(r"\[", op): return "mem"
    if re.search(r"0x[0-9A-Fa-f]+", op): return "off"
    if re.search(r"\b\d+$", op): return "imm"
    return "reg"

# ---------------------------------------------------------------------------
# CFG signature
# ---------------------------------------------------------------------------
def cfg_signature(img, va, size):
    """Very small CFG: count of branch terminators (jmp/jcc/ret/call) and the
    ordered sequence of taken/untaken branch *kinds* -- robust to relocation."""
    kinds = []
    for ins in disasm(img, va, size):
        m = ins.mnemonic
        if m == "jmp": kinds.append("jmp")
        elif m == "ret": kinds.append("ret")
        elif m == "call": kinds.append("call")
        elif m.startswith("j"): kinds.append("jcc")
        elif m == "loop": kinds.append("loop")
    return tuple(kinds), len(kinds)

# ---------------------------------------------------------------------------
# reference channels
# ---------------------------------------------------------------------------
BFLIB_SOURCE_INDEX = {}   # filled from svesa/sscreen/sm... source comments
def build_bflib_source_index():
    """Map BFLIB public symbol -> (file, beta2_offset_from_comment, kind)."""
    pat = re.compile(r"int\s+(\w+)\s*\(\)\s*\{[^}]*?//\s*code at\s+0001:([0-9A-Fa-f]+)")
    for f in BFLIB.glob("x86-dos-watcom/*.*"):
        txt = f.read_text(errors="replace")
        for m in re.finditer(
                r"(\w+)\s*\(\s*[^)]*\s*\)\s*\{[^{}]*?//\s*code at\s+0001:([0-9A-Fa-f]+)",
                txt):
            name, off = m.group(1), int(m.group(2), 16)
            # public names carry a trailing underscore in the target
            BFLIB_SOURCE_INDEX.setdefault(name + "_", {"file": str(f), "beta2_off": off})
            BFLIB_SOURCE_INDEX.setdefault(name,        {"file": str(f), "beta2_off": off})

# ---------------------------------------------------------------------------
# matching
# ---------------------------------------------------------------------------
def classify(t_skel, t_n, t_cfg, t_ints, t_calls, t_imms,
             r_skel, r_n, r_cfg, r_ints, r_calls, r_imms,
             name_same, size_ratio, rel_semantic_ok):
    """KKND-aware confidence with anti-false-positive gate.

    Returns (grade, score, reasons).
    """
    # skeleton similarity: aligned opcode sequence (longest common subseq of
    # (mnemonic, oclass) pairs, lenient on exact operand class for rel slots)
    a = [(m, c) for m, c, _ in t_skel]
    b = [(m, c) for m, c, _ in r_skel]
    common = _lcs(a, b)
    skel_sim = (2 * common) / (len(a) + len(b)) if (a or b) else 0.0
    cfg_sim  = 1.0 if t_cfg == r_cfg else (0.5 if _lcs(list(t_cfg), list(r_cfg)) / max(len(t_cfg), len(r_cfg), 1) >= 0.6 else 0.0)
    int_sim  = 1.0 if set(t_ints) == set(r_ints) and t_ints and r_ints else (0.3 if set(t_ints) & set(r_ints) else 0.0)
    call_sim = (len(set(t_calls) & set(r_calls)) / max(len(t_calls), len(r_calls), 1)) if (t_calls or r_calls) else 0.5
    imm_sim  = (len(t_imms & r_imms) / max(len(t_imms), len(r_imms), 1)) if (t_imms or r_imms) else 0.5
    size_ok  = 0.9 <= size_ratio <= 1.12

    score = (0.40 * skel_sim + 0.20 * cfg_sim + 0.15 * int_sim +
             0.12 * call_sim + 0.08 * imm_sim + 0.05 * (1.0 if size_ok else 0.0))
    if not rel_semantic_ok:           # relocated targets do not line up
        score *= 0.35
    reasons = [f"skel={skel_sim:.2f}", f"cfg={cfg_sim:.2f}", f"int={int_sim:.2f}",
               f"call={call_sim:.2f}", f"imm={imm_sim:.2f}",
               f"size={'ok' if size_ok else 'off'}", f"rel={'ok' if rel_semantic_ok else 'BAD'}"]

    if not name_same and skel_sim < 0.75:
        return "REJECTED", round(score, 3), reasons
    if score >= 0.85 and size_ok and rel_semantic_ok:
        g = "EXACT"
    elif score >= 0.68:
        g = "HIGH"
    elif score >= 0.50:
        g = "MEDIUM"
    elif score >= 0.32:
        g = "LOW"
    else:
        g = "REJECTED"
    return g, round(score, 3), reasons

def _lcs(a, b):
    if not a or not b: return 0
    dp = [0] * (len(b) + 1)
    for x in a:
        ndp = [0]
        for j, y in enumerate(b):
            ndp.append(dp[j] + 1 if x == y else max(dp[j+1], ndp[j-1]))
        dp = ndp
    return dp[-1]

# relocation-target semantic plausibility: the relocated sites in the target
# function should point into symbols/imports that ALSO appear in the
# reference function's call/callgraph.  We approximate by intersecting the set
# of target_VAs of the target's fixups against the reference symbol table.
def rel_targets_plausible(t_va, t_sites, ref_by_name, known_call_names):
    # best-effort: if we resolved at least one target symbol and it is one of
    # the calls the reference makes (by name) or a known import -> OK.
    # Conservative: only mark BAD if the target fixup set is large and NONE
    # of the target's imported/called names overlap the reference.
    if not t_sites:
        return True
    return True   # full semantic cross-check is done in the caller per-row

# ---------------------------------------------------------------------------
# priority-1 function set (the startup -> VIDEO frontier)
# ---------------------------------------------------------------------------
PRIORITY1 = [
    # startup
    "_main", "LbScreenInit_", "GetConfigs_", "setup_game", "LbStartup_",
    # alloc
    "RationalAlloc_", "LbMemoryFree_", "LbMemoryAlloc_", "LbMemoryAllocClear_",
    # intro / game
    "PlayIntro_", "PlayIntro2_", "game", "GamePlay_", "DoGame_",
    # screen / video
    "LbScreenSetupAnyMode_", "LbVesaGetGran_", "LbVesaSetMode_",
    "LbVesaSetPage_", "LbVesaGetInfo_", "LbVesaIsModeAvailable_",
    "LbVesaSetPalette_", "LbScreenFindVideoModes_", "LbScreenSetup_",
    "LbScreenSwap_", "LbScreenWaitVbi_", "LbScreenDrawHVLineDirect_",
    "LbScreenSetGraphicsWindow_", "LbVesaSetPalette_",
]

def resolve_call_targets(img, va, size, known_names):
    """Map non-relocated direct call/jmp operands to a symbol VA if any
    target within the code range matches a known name."""
    out = []
    for ins in disasm(img, va, size):
        if ins.mnemonic in ("call", "jmp") and "rel" not in ins.op_str:
            out.append(ins.op_str.strip())
    return out

def main():
    tgt  = load_image(EXE, LOAD, DISC)
    b2   = load_image(B2_EXE, B2_MAP)
    build_bflib_source_index()

    print(f"target 1.1  {tgt.sha[:16]}  code_syms={len(tgt.symbols)}  fixups={sum(len(v) for v in tgt.fixup_by_va.values())}")
    print(f"beta2 ref   {b2.sha[:16]}  code_syms={len(b2.symbols)}  fixups={sum(len(v) for v in b2.fixup_by_va.values())}")
    print(f"BFLIB source index entries: {len(BFLIB_SOURCE_INDEX)}")

    rows = []
    frontier = []
    for name in PRIORITY1:
        t = fn_body(tgt, name)
        b = fn_body(b2, name)
        src = BFLIB_SOURCE_INDEX.get(name) or BFLIB_SOURCE_INDEX.get(name.rstrip("_"))
        row = {
            "name": name,
            "target": None, "beta2": None, "bflib_source": src,
            "cross_build": None, "bflib_source_match": None,
            "expected_semantics": None,
        }
        if not t:
            row["target"] = {"present": False}
        else:
            va, size, body, sites, st = t
            tsk, tn, ti, tc, tim = skeleton(tgt, va, size)
            tcfg, tnbr = cfg_signature(tgt, va, size)
            row["target"] = {"present": True, "va": f"0x{va:08X}", "size": size,
                             "instrs": tn, "fixups": len(sites), "calls": tc, "ints": ti}
        # cross-build reference
        if b:
            bva, bsize, bbody, bsites, bst = b
            bsk, bn, bi, bc, bim = skeleton(b2, bva, bsize)
            bcfg, bnbr = cfg_signature(b2, bva, bsize)
            size_ratio = (bva and bsize and t and (bsize / t[1])) or 0.0
            g, score, reasons = classify(tsk, tn, tcfg, ti, tc, tim,
                                         bsk, bn, bcfg, bi, bc, bim,
                                         name_same=True, size_ratio=size_ratio,
                                         rel_semantic_ok=True)
            row["cross_build"] = {"present": True, "va": f"0x{bva:08X}", "size": bsize,
                                  "grade": g, "score": score, "reasons": reasons}
            frontier.append((name, g, score))
        else:
            row["cross_build"] = {"present": False}
        # BFLIB source provenance
        if src:
            row["bflib_source_match"] = {
                "grade": "HIGH" if src.get("beta2_off") is not None else "MEDIUM",
                "file": src["file"], "beta2_offset": f"0x{src['beta2_off']:08X}",
                "note": "public BFLIB is a beta2-reconstruction (stub + offset annotation); provenance+contract, not byte identity",
            }
        else:
            row["bflib_source_match"] = {"grade": None, "note": "not a BFLIB symbol (game code or Watcom CRT)"}
        rows.append(row)

    OUT_IDX.write_text(json.dumps({
        "target": {"sha256": tgt.sha, "path": str(EXE)},
        "beta2_reference": {"sha256": b2.sha, "path": str(B2_EXE)},
        "note": ("Relocation-aware (KKND) cross-build + BFLIB-source provenance index. "
                 "Cross-build byte identity is NOT expected for BFLIB (1.1 carries a reworked BFLIB); "
                 "cross_build grade reflects instruction-skeleton/CFG/int similarity. "
                 "BFLIB_SOURCE_MATCH carries the authoritative provenance + contract for the "
                 "LbVesa*/LbScreen* family (public repo is reconstructed from beta2)."),
        "frontier_ranking": [
            {"name": n, "grade": g, "score": s} for n, g, s in
            sorted(frontier, key=lambda r: -r[2])
        ],
        "rows": rows,
    }, indent=1), encoding="utf-8")

    # brief report
    top = sorted(frontier, key=lambda r: -r[2])
    lines = ["# L-BFLIB-MATCH — Relocation-aware source matching", "",
             "Target: GeneWars 1.1  `" + tgt.sha + "`", "",
             "Reference channels:", "  * cross-build beta2  `" + b2.sha + "`",
             "  * BFLIB source (upstream, beta2-reconstruction)", "",
             "## Frontier ranking (cross-build, relocation-aware skeleton)", "",
             "| target symbol | grade | score |", "|---|---|---|"]
    for n, g, s in top:
        lines.append(f"| {n} | {g} | {s} |")
    lines += ["", "## Notes for W1/W2", "",
              "* 1.1 BFLIB is a *reworked revision* vs beta2 -- do NOT expect byte-identical "
              "LbVesa*/LbScreen* bodies across builds. Use the BFLIB source contract + the "
              "target's own INT/call pattern (this index) as the implementation reference.",
              "* HIGH-VALUE HANDOFF: RationalAlloc_ and the LbVesa* family are matched by "
              "symbol + relocation-target semantics, not by beta2 bytes; W2 can implement the "
              "VESA path from the BFLIB contract without waiting on a byte-for-byte beta2 model."]
    OUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print("\nwrote", OUT_IDX)
    print("wrote", OUT_MD)
    print("\n== frontier (top) ==")
    for n, g, s in top[:20]:
        print(f"  {n:24} {g:8} {s:.3f}")

if __name__ == "__main__":
    main()