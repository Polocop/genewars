#!/usr/bin/env python3
"""
bflib_match.py — relocation-aware function matcher between two GeneWars LE images.

Compares a source function (e.g. GeneWars 1.1) against a destination function
(e.g. Beta2) across four independent channels and classifies the pair:

  A. EXACT bytes      : identical encoded bytes over the confirmed body.
  B. RELATION-AWARE   : identical after masking ONLY the fields that carry a
                        fixup (relocation).  Relocated targets are reported
                        separately and checked for semantic plausibility.
  C. INSTRUCTION      : opcode family / operand size / reg / mod-rm / sib /
                        branch-class / call sites (operand *values* ignored).
  D. CFG              : block leaders, edges, exits, back-edges (loops), int
                        set — all normalized to entry-relative offsets.

Classification
--------------
  EXACT    full body byte-identical (equal length)
  HIGH     relocation-aware identical AND instruction skeletons equal AND CFG
           isomorphic  ->  only relocations differ (the KKND case)
  MEDIUM   >= 0.85 instruction-token match AND same block count, operand/const
           differences present
  LOW      coarse structure only (same mnemonic family), notable divergence
  REJECTED structurally different (size, int usage, branch/loop structure)
  UNKNOWN  insufficient evidence (symbol missing, decode refusal, bad bounds)

A name match NEVER proves equivalence; a similar opcode run NEVER does either.
Every result carries matched evidence, unmatched evidence, semantic differences
and relocation-target checks.

The comparison engine is a set of pure functions over (bytes, fixups, insts)
so it is unit-testable without a real LE image.  The LE loader is thin and
reuses dos_re (load_le / scan_function32) plus the shared map/fixup parsers in
extract_symbol_corpus.py.

Usage
-----
  python bflib_match.py --src A.exe --srcmap A.map --dst B.exe --dstmap B.map \
      --symbols LbVesaSetMode_ LbVesaSetPage_ LbVesaGetInfo_ [--json out.json]
  python bflib_match.py --selftest
"""

from __future__ import annotations
import os as _gw_os
from pathlib import Path as _GwPath
_GW_ROOT=str(_GwPath(__file__).resolve().parents[1])
_GW_FX=_gw_os.environ.get("GENEWARSFX_ROOT",_gw_os.path.join(_GW_ROOT,"third_party","GeneWarsFX"))
import argparse
import dataclasses
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

# --- reuse existing, tested infrastructure (no new x86 parser) ---------------
sys.path.insert(0, (_GW_FX.replace("\\","/") + '/experiments/dos-re-gw10'))
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

from dos_re.le import load_le                       # flat LE image + objects
from dos_re.lift.cfg32 import EXIT_KINDS            # (RET, IRET, JMP_IND)
from dos_re.lift.decode32 import decode32           # existing 32-bit decoder
from extract_symbol_corpus import (                   # shared, already fixed
    parse_loaded_map, le_fixup_header, parse_fixups,
)


# =============================================================================
# 1. LE LOADER (thin; the only image-specific code)
# =============================================================================
@dataclass
class ImageRef:
    path: str
    map_path: str
    data: bytes
    mem: bytearray              # flat image; index == object-1 VA (rebase=0)
    img: object                 # dos_re LEImage
    syms: dict                  # name -> va (object-1 offset)
    fixups: list                # (addr, tgt_linear, stype)

    def read(self, addr: int, size: int) -> bytes:
        a = addr & 0xFFFFFFFF
        if a < 0:
            return b"\x00" * size
        return bytes(self.mem[a:a + size]) if a < len(self.mem) else b"\x00" * size

    def fetch(self, ip: int):
        ip &= 0xFFFFFFFF
        if ip < len(self.mem):
            return self.mem[ip]
        return 0

    def body_window(self, va: int, bound_va: int | None, cap: int = 0x2000) -> int:
        """Upper offset (exclusive) for the function body at ``va``."""
        end = len(self.mem)
        if bound_va is not None and bound_va > va:
            end = min(end, bound_va)
        return min(end, va + cap)


def load_image(exe: str, map_path: str) -> ImageRef:
    data = Path(exe).read_bytes()
    img = load_le(exe)                     # rebase=0 -> disasm addr == link VA
    syms = {}
    for va, name in parse_loaded_map(Path(map_path)):
        # object-1 code symbols only; first occurrence wins for dedup
        if name not in syms:
            syms[name] = va
    hd = le_fixup_header(data)
    fixups = parse_fixups(data, img.objects, hd["page_size"], hd["num_pages"],
                          hd["obj_tab"], hd["obj_cnt"], hd["fixup_page_tab"],
                          hd["fixup_rec_tab"])
    return ImageRef(path=exe, map_path=map_path, data=data, mem=img.mem,
                    img=img, syms=syms, fixups=fixups)


# =============================================================================
# 2. PURE COMPARISON ENGINE (unit-testable, image-agnostic)
# =============================================================================
# Relocated-field byte width per fixup src-type (matches extract_symbol_corpus).
_SRC_BYTE = 0x00; _SRC_SELECTOR16 = 0x02; _SRC_PTR16_16 = 0x03
_SRC_OFFSET16 = 0x05; _SRC_PTR16_32 = 0x06; _SRC_OFFSET32 = 0x07
_SRC_SELF_REL32 = 0x08


def _fixup_fieldsize(stype: int) -> int:
    return {
        _SRC_BYTE: 1, _SRC_SELECTOR16: 2, _SRC_PTR16_16: 4,
        _SRC_OFFSET16: 2, _SRC_PTR16_32: 4, _SRC_OFFSET32: 4,
        _SRC_SELF_REL32: 4,
    }.get(stype, 2)


def mask_relocations(body: bytes, base_va: int, fixups: list):
    """Return (masked, fixup_sites).  masked[i] is None where byte i falls in a
    fixup field belonging to an instruction inside [base_va, base_va+len(body)).
    fixup_sites = [(rel_off, tgt_linear, stype, fieldsize), ...] in body order."""
    n = len(body)
    masked = list(body)
    sites = []
    for addr, tgt, stype in fixups:
        rel = (addr - base_va) & 0xFFFFFFFF
        fs = _fixup_fieldsize(stype)
        if 0 <= rel < n:
            hi = min(n, rel + fs)
            for i in range(rel, hi):
                masked[i] = None
            sites.append((rel, tgt, stype, fs))
    sites.sort(key=lambda s: s[0])
    return masked, sites


def masked_equal(a: list, b: list) -> bool:
    if len(a) != len(b):
        return False
    for x, y in zip(a, b):
        if x is None or y is None:
            continue
        if x != y:
            return False
    return True


def byte_diff_count(a: list, b: list, ignore_none: bool = True) -> int:
    n = min(len(a), len(b))
    d = 0
    for i in range(n):
        if a[i] is None or b[i] is None:
            if ignore_none and a[i] is None and b[i] is None:
                continue
        elif a[i] != b[i]:
            d += 1
    if len(a) != len(b):
        d += abs(len(a) - len(b))
    return d


def _branch_class(kind: str) -> str:
    return kind  # caller passes normalized kind (JCC/JMP/CALL/CALL_IND/EXIT_KIND)


@dataclass
class InstTok:
    """Relocation-aware instruction token: structure only, no operand values.

    Branch/call targets are NOT part of the token: their *placement* differs
    between builds (the linker lays the same code at different VAs), so an
    absolute entry-relative target offset would make the instruction channel
    collapse to 0.00 on every cross-build pair — exactly the false signal that
    made token_sim contradict cfg_sim.  Instead we record the *branch shape*:
    the branch class plus whether it is backward (a loop / fall-back) or
    forward, which is placement-independent.  Absolute target offsets are still
    compared structurally by the CFG channel (cfg_isomorphic / cfg_similarity),
    which already normalizes targets to entry-relative offsets.
    """
    kind: str
    mnem: str
    opsize: int
    adsize: int
    op: int
    reg: int | None
    mod: int | None
    rm: int | None
    sib: int | None
    disp_present: bool
    imm_present: bool
    int_no: int | None
    branch_dir: str      # "" , "fwd", "back" — placement-independent


# Decoder kind constants are LOWERCASE (see dos_re.lift.decode32): seq, jcc,
# jmp, jmp_ind, call, call_ind, int, ret, iret.  EXIT_KINDS from cfg32 is also
# lowercase.  The earlier "JCC"/"JMP"/"CALL" (uppercase) tests silently matched
# nothing, dropping every edge/call -> cfg_sim degenerated to 1.0 (comparing
# two empty edge sets).  Use the real constants so CFG edges are recorded.
_KIND_JCC = "jcc"; _KIND_JMP = "jmp"; _KIND_CALL = "call"
_KIND_BRANCH = (_KIND_JCC, _KIND_JMP)


def inst_token(inst, entry_va: int) -> InstTok:
    bdir = ""
    if inst.kind in (_KIND_BRANCH + (_KIND_CALL,)) and inst.target is not None:
        rel = (inst.ip - entry_va) & 0xFFFFFFFF
        trel = (inst.target - entry_va) & 0xFFFFFFFF
        bdir = "back" if (trel - rel) & 0x80000000 else "fwd"
    return InstTok(
        kind=inst.kind, mnem=inst.mnemonic, opsize=inst.opsize,
        adsize=inst.adsize, op=inst.op,
        reg=getattr(inst, "reg", None), mod=getattr(inst, "mod", None),
        rm=getattr(inst, "rm", None), sib=getattr(inst, "sib", None),
        disp_present=inst.disp is not None, imm_present=inst.imm is not None,
        int_no=inst.int_no, branch_dir=bdir,
    )


def skeleton_signature(toks: list[InstTok]) -> list[str]:
    out = []
    for t in toks:
        out.append("|".join([
            t.kind, t.mnem, str(t.opsize), str(t.adsize),
            f"r{t.reg}" if t.reg is not None else "-",
            f"m{t.mod}" if t.mod is not None else "-",
            f"x{t.rm}" if t.rm is not None else "-",
            f"s{t.sib}" if t.sib is not None else "-",
            "d" if t.disp_present else "-",
            "i" if t.imm_present else "-",
            t.branch_dir or "-",
            f"I{t.int_no}" if t.int_no is not None else "-",
        ]))
    return out


def token_similarity(a: list[str], b: list[str]) -> float:
    if not a and not b:
        return 1.0
    n = min(len(a), len(b))
    if n == 0:
        return 0.0
    same = sum(1 for i in range(n) if a[i] == b[i])
    base = max(len(a), len(b))
    return same / base


# --- CFG ---------------------------------------------------------------------
@dataclass
class CfgView:
    leaders_rel: set = field(default_factory=set)
    edges: set = field(default_factory=set)     # (from_rel, target_rel)
    exits_rel: list = field(default_factory=list)
    backedges: set = field(default_factory=set)
    ints: set = field(default_factory=set)
    n_insts: int = 0
    size: int = 0
    exits: bool = True                          # at least one in-slot exit seen

    def to_dict(self):
        return {
            "leaders_rel": sorted(hex(x) for x in self.leaders_rel),
            "edges": [ [hex(f), hex(t)] for f, t in sorted(self.edges) ],
            "exits_rel": sorted(hex(x) for x in self.exits_rel),
            "backedges": sorted(hex(x) for x in self.backedges),
            "ints": sorted(self.ints),
            "n_insts": self.n_insts, "size": self.size, "exits": self.exits,
        }


def build_cfg_view(insts: list, entry_va: int, bound: int, exit_kinds=frozenset()) -> CfgView:
    """CFG over a *sequential* in-slot instruction list (no out-of-slot walk,
    so no region-budget / no-exit artifacts).  Edges whose target leaves the
    slot are recorded as out-of-slot transfers (calls / branches), not chased."""
    v = CfgView()
    v.n_insts = len(insts)
    v.size = (bound - entry_va) if insts else 0
    exits_seen = False
    for inst in insts:
        rel = (inst.ip - entry_va) & 0xFFFFFFFF
        if inst.int_no is not None:
            v.ints.add(inst.int_no)
        if inst.kind in exit_kinds:
            v.exits_rel.append(rel)
            exits_seen = True
        if inst.kind in _KIND_BRANCH and inst.target is not None:
            t = (inst.target - entry_va) & 0xFFFFFFFF
            v.edges.add((rel, t))
            v.leaders_rel.add(t)
            if inst.kind == _KIND_JCC:
                v.leaders_rel.add((rel + inst.length) & 0xFFFFFFFF)
            if t < rel:                      # back-edge => loop
                v.backedges.add(rel)
        elif inst.kind == _KIND_CALL and inst.target is not None:
            v.edges.add((rel, (inst.target - entry_va) & 0xFFFFFFFF))
    v.leaders_rel.add(0)
    v.exits = exits_seen
    return v


def cfg_isomorphic(a: CfgView, b: CfgView) -> bool:
    if a.size != b.size or a.n_insts != b.n_insts:
        return False
    if a.leaders_rel != b.leaders_rel:
        return False
    if a.edges != b.edges:
        return False
    if set(a.ints) != set(b.ints):
        return False
    if sorted(a.exits_rel) != sorted(b.exits_rel):
        return False
    return True


def cfg_similarity(a: CfgView, b: CfgView) -> float:
    """Fraction of structure shared (leader/edge/int sets)."""
    parts = [
        _set_sim(a.leaders_rel, b.leaders_rel),
        _set_sim(a.edges, b.edges),
        _set_sim(a.ints, b.ints),
        _set_sim(a.backedges, b.backedges),
    ]
    parts.append(1.0 if a.size == b.size else 0.0)
    return sum(parts) / len(parts)


def _set_sim(a, b) -> float:
    if not a and not b:
        return 1.0
    u = len(a | b)
    return len(a & b) / u if u else 1.0


# --- fixup-target semantic check --------------------------------------------
def relocation_target_check(im: ImageRef, sites, entry_va, name_by_va=None):
    """For each relocated field in the body, report the relocated target and,
    where resolvable via the image's own symbol map, the semantic symbol name.
    A target that is NOT a known code/data symbol is flagged (potential false
    positive source)."""
    if name_by_va is None:
        name_by_va = {va: n for n, va in im.syms.items()}
    out = []
    for rel, tgt, stype, fs in sites:
        resolved = name_by_va.get(tgt)
        out.append({
            "field_off": hex(rel), "target_va": hex(tgt & 0xFFFFFFFF),
            "fieldsize": fs, "src_type": hex(stype),
            "resolved_symbol": resolved,
            "plausible": (resolved is not None) or tgt < 0x400000,
        })
    return out


# Cross-build relocation-target COMPATIBILITY (MISIÓN 1A guard).
#
# A masked-equal (HIGH) or exact match is only semantically valid if, for every
# relocated field, the two builds relocate to targets that mean the same thing.
# Fixup *address* values legitimately differ between builds (they are the
# linker-assigned absolute addresses of otherwise-equivalent symbols), so we
# compare by the RESOLVED SYMBOL NAME, not the raw address:
#
#   same_symbol            target address differs but both resolve to the same
#                          symbol name  -> benign, the normal relocation case
#   diff_symbol            targets resolve to DIFFERENT symbols -> the two
#                          functions touch semantically different objects ->
#                          a structural match is a FALSE POSITIVE, cap at MEDIUM
#   fixup_type_diff        same slot, different fixup src-type -> codegen
#                          genuinely changed -> cap at MEDIUM
#   unknown_target         one/both targets not in the symbol map -> data gap;
#                          warn (cannot confirm nor deny equivalence)
#   missing_fixup          one side has a fixup field the other lacks ->
#                          structural difference; warn
def relocation_target_compatibility(src_im, dst_im, s, d):
    def _side(im, view):
        nbv = {va: n for n, va in im.syms.items()}
        m = {}
        for rel, tgt, st, fs in view.fixup_sites:
            m.setdefault(rel, []).append((tgt, st, nbv.get(tgt)))
        return m
    a = _side(src_im, s)
    b = _side(dst_im, d)
    rows = []
    issues = {"same_symbol": 0, "diff_symbol": 0, "fixup_type_diff": 0,
              "unknown_target": 0, "missing_fixup": 0}
    for rel in sorted(set(a) | set(b)):
        la = a.get(rel, []); lb = b.get(rel, [])
        if not la or not lb:
            issues["missing_fixup"] += 1
            rows.append({"field_off": hex(rel), "case": "missing_fixup",
                         "src": [r for r in la], "dst": [r for r in lb]})
            continue
        for i in range(max(len(la), len(lb))):
            if i >= len(la) or i >= len(lb):
                issues["missing_fixup"] += 1
                rows.append({"field_off": hex(rel), "case": "missing_fixup",
                             "src": [la[i]] if i < len(la) else None,
                             "dst": [lb[i]] if i < len(lb) else None})
                continue
            ta, sta, ra = la[i]
            tb, stb, rb = lb[i]
            if sta != stb:
                case = "fixup_type_diff"; issues["fixup_type_diff"] += 1
            elif ra and rb and ra != rb:
                case = "diff_symbol"; issues["diff_symbol"] += 1
            elif ra is None or rb is None:
                case = "unknown_target"; issues["unknown_target"] += 1
            else:
                case = "same_symbol"
                issues["same_symbol"] += 1
            rows.append({"field_off": hex(rel), "case": case,
                         "src_symbol": ra, "dst_symbol": rb,
                         "src_target": hex(ta & 0xFFFFFFFF),
                         "dst_target": hex(tb & 0xFFFFFFFF),
                         "src_type": hex(sta), "dst_type": hex(stb)})
    return rows, issues


# =============================================================================
# 3. FUNCTION EXTRACTION + CLASSIFICATION
# =============================================================================
@dataclass
class FuncView:
    name: str
    va: int
    size: int
    body: bytes
    masked: list
    fixup_sites: list
    toks: list
    sig: list
    cfg: object
    scan_ok: bool
    refusal: str = ""
    missing: bool = False


def extract_function(im: ImageRef, name: str, bound_va: int | None = None) -> FuncView:
    va = im.syms.get(name)
    if va is None:
        return FuncView(name=name, va=-1, size=0, body=b"", masked=[],
                        fixup_sites=[], toks=[], sig=[], cfg=CfgView(),
                        scan_ok=False, missing=True)
    end = im.body_window(va, bound_va)
    body = im.read(va, end - va)
    # --- sequential in-slot decode (reuses the existing 32-bit decoder) -------
    # Walk straight-line instructions from va, stopping at end (next symbol).
    # We do NOT follow branches out of the slot: that is what tripped
    # region-budget/no-exit in scan_function32, a coverage artifact, not a
    # decode failure.  Edges to out-of-slot targets are recorded, not chased.
    insts = []
    refusals = []
    ip = va
    while ip < end:
        try:
            inst = decode32(im.fetch, ip)
        except (ValueError, IndexError) as exc:
            refusals.append(f"{hex(ip)}:undecodable:{exc}")
            break
        if inst.length == 0:
            refusals.append(f"{hex(ip)}:zero-length")
            break
        insts.append(inst)
        ip = (ip + inst.length) & 0xFFFFFFFF
        if ip <= va:                     # safety: no forward progress
            refusals.append(f"{hex(va)}:no-progress")
            break
    scan_ok = bool(insts) and not refusals
    refusal = "; ".join(refusals[:5])
    toks = [inst_token(i, va) for i in insts]
    masked, sites = mask_relocations(body, va, im.fixups)
    cfg = build_cfg_view(insts, va, end, exit_kinds=EXIT_KINDS)
    return FuncView(name=name, va=va, size=cfg.size, body=body, masked=masked,
                    fixup_sites=sites, toks=toks, sig=skeleton_signature(toks),
                    cfg=cfg, scan_ok=scan_ok, refusal=refusal)


@dataclass
class MatchResult:
    name: str
    src_va: str; dst_va: str
    src_size: int; dst_size: int
    classification: str
    byte_exact: bool
    masked_equal: bool
    byte_diff: int
    token_sim: float
    cfg_iso: bool
    cfg_sim: float
    src_fixups: int; dst_fixups: int
    relocation_checks_src: list
    relocation_checks_dst: list
    matched_evidence: list
    unmatched_evidence: list
    semantic_diffs: list
    unknown_reason: str = ""
    cfg_src: dict = field(default_factory=dict)
    cfg_dst: dict = field(default_factory=dict)
    reloc_compat: list = field(default_factory=list)
    reloc_compat_issues: dict = field(default_factory=dict)


def _next_symbol_va(im: ImageRef, va: int):
    cands = [v for v in im.syms.values() if v > va]
    return min(cands) if cands else None


def classify(name: str, s: FuncView, d: FuncView,
             src_im: ImageRef, dst_im: ImageRef) -> MatchResult:
    r = MatchResult(
        name=name, src_va=hex(s.va) if s.va >= 0 else "MISSING",
        dst_va=hex(d.va) if d.va >= 0 else "MISSING",
        src_size=s.size, dst_size=d.size,
        classification="UNKNOWN", byte_exact=False, masked_equal=False,
        byte_diff=0, token_sim=0.0, cfg_iso=False, cfg_sim=0.0,
        src_fixups=len(s.fixup_sites), dst_fixups=len(d.fixup_sites),
        relocation_checks_src=relocation_target_check(src_im, s.fixup_sites, s.va),
        relocation_checks_dst=relocation_target_check(dst_im, d.fixup_sites, d.va),
        matched_evidence=[], unmatched_evidence=[], semantic_diffs=[],
        cfg_src=s.cfg.to_dict(), cfg_dst=d.cfg.to_dict(),
    )
    # --- hard gates -> UNKNOWN ------------------------------------------------
    if s.missing or d.missing:
        r.unknown_reason = ("missing in " + ("src" if s.missing else "dst") + " map")
        return r
    if not s.scan_ok or not d.scan_ok:
        r.unknown_reason = (f"decode: src[{s.refusal or 'ok'}] dst[{d.refusal or 'ok'}]")
        return r
    if s.size <= 0 or d.size <= 0:
        r.unknown_reason = "empty/bad function bounds"
        return r

    # --- relocation-target compatibility, computed for ALL paths (incl. EXACT) --
    # MISIÓN 1A: a byte-identical (or structurally identical) body is only a
    # *demonstrated* equivalence if the relocated fields on both sides resolve
    # to the SAME symbols.  This must run before the EXACT early-return, or a
    # coincidental byte match whose fixups touch different objects escapes as
    # EXACT.  Categories:
    #   diff_symbol / fixup_type_diff / missing_fixup -> PROVEN difference ->
    #       cap at MEDIUM (a structural match is a false positive)
    #   unknown_target -> a data gap: cannot confirm nor deny -> on the EXACT
    #       path this downgrades to HIGH (not a *demonstrated* equivalence), on
    #       the HIGH path it warns without capping
    bad_t = [c for c in r.relocation_checks_src + r.relocation_checks_dst
             if not c["plausible"]]
    if bad_t:
        r.semantic_diffs.append(f"{len(bad_t)} relocation target(s) unresolved")
    r.reloc_compat, r.reloc_compat_issues = relocation_target_compatibility(
        src_im, dst_im, s, d)
    if r.reloc_compat_issues["diff_symbol"]:
        r.semantic_diffs.append(
            f"{r.reloc_compat_issues['diff_symbol']} relocation target(s) resolve "
            f"to DIFFERENT symbols (semantic false-positive risk)")
    if r.reloc_compat_issues["fixup_type_diff"]:
        r.semantic_diffs.append(
            f"{r.reloc_compat_issues['fixup_type_diff']} fixup field type(s) differ")

    def _cap():
        return (r.reloc_compat_issues["diff_symbol"]
                or r.reloc_compat_issues["fixup_type_diff"]
                or r.reloc_compat_issues["missing_fixup"])

    n = min(len(s.body), len(d.body))
    # A. EXACT — byte-identical body, but only *demonstrated* when the fixups
    #    also line up semantically.  Incompatible fixups cap to MEDIUM; an
    #    unmapped (unknown) fixup target caps to HIGH (not fully demonstrated).
    if s.size == d.size and s.body == d.body:
        r.byte_exact = True
        if _cap():
            r.classification = "MEDIUM"
            r.matched_evidence.append(
                f"byte-identical body ({s.size} bytes) but relocation targets "
                "resolve to different symbols / differ in fixup type / a fixup "
                "is missing on one side -> NOT demonstrated equivalent, capped at MEDIUM")
        elif r.reloc_compat_issues["unknown_target"]:
            r.classification = "HIGH"
            r.matched_evidence.append(
                f"byte-identical body ({s.size} bytes) but "
                f"{r.reloc_compat_issues['unknown_target']} relocation target(s) "
                "unmapped -> equivalence not fully demonstrated, capped at HIGH")
        else:
            r.classification = "EXACT"
            r.matched_evidence.append(f"byte-identical body ({s.size} bytes)")
        return r

    # B. relocation-aware (masked) over the min length
    sm = s.masked[:n]; dm = d.masked[:n]
    r.masked_equal = masked_equal(sm, dm) and (s.size == d.size)
    r.byte_diff = byte_diff_count(sm, dm)
    # C. instruction skeleton
    r.token_sim = token_similarity(s.sig, d.sig)
    # D. CFG
    r.cfg_iso = cfg_isomorphic(s.cfg, d.cfg)
    r.cfg_sim = cfg_similarity(s.cfg, d.cfg)

    # (relocation-target compatibility already computed for all paths above;
    #  the diff_symbol / fixup_type_diff / missing_fixup / unknown_target caps
    #  below use r.reloc_compat_issues, which is populated on both the EXACT and
    #  non-EXACT paths before classification.)

    # --- classification -------------------------------------------------------
    if r.masked_equal and r.cfg_iso and r.token_sim >= 0.99:
        r.classification = "HIGH"
        r.matched_evidence.append("relocation-aware byte-identical (only fixups differ)")
        r.matched_evidence.append(f"CFG isomorphic (size {s.size}, {s.cfg.n_insts} insts)")
    elif r.token_sim >= 0.85 and s.cfg.n_insts == d.cfg.n_insts and r.cfg_sim >= 0.7:
        r.classification = "MEDIUM"
        r.matched_evidence.append(f"instruction token match {r.token_sim:.2f}")
        r.semantic_diffs.append("operand/constant or minor CFG differences")
    elif r.token_sim >= 0.55 and s.cfg.n_insts == d.cfg.n_insts:
        r.classification = "LOW"
        r.matched_evidence.append(f"coarse instruction similarity {r.token_sim:.2f}")
        r.semantic_diffs.append("notable structural divergence")
    else:
        r.classification = "REJECTED"
        r.semantic_diffs.append(
            f"size {s.size}!={d.size}; token {r.token_sim:.2f}; "
            f"insts {s.cfg.n_insts}!={d.cfg.n_insts}; cfg_sim {r.cfg_sim:.2f}")

    # --- MISIÓN 1A: relocation-target compatibility cap ----------------------
    # A structural HIGH/EXACT is only valid if the two sides relocate to the
    # SAME symbols.  diff_symbol / fixup_type_diff means the function touches
    # semantically different objects (a false positive) -> cap at MEDIUM, never
    # HIGH/EXACT.  A lone unknown_target is a data gap, not proof of difference.
    if r.classification in ("HIGH", "EXACT"):
        if (r.reloc_compat_issues["diff_symbol"]
                or r.reloc_compat_issues["fixup_type_diff"]
                or r.reloc_compat_issues["missing_fixup"]):
            r.classification = "MEDIUM"
            r.matched_evidence.append(
                "structural match downgraded: relocation targets not semantically "
                "confirmed identical (diff_symbol/fixup_type/missing_fixup)")

    # --- evidence (matched vs unmatched) -------------------------------------
    if s.size != d.size:
        r.unmatched_evidence.append(f"body size {s.size} vs {d.size}")
    if r.byte_diff:
        r.unmatched_evidence.append(f"{r.byte_diff} non-matching byte(s) after masking")
    if not r.cfg_iso:
        r.unmatched_evidence.append("CFG not isomorphic")
    if r.relocation_checks_src or r.relocation_checks_dst:
        r.matched_evidence.append(
            f"relocations: src {len(r.relocation_checks_src)}, dst {len(r.relocation_checks_dst)}")
    if s.cfg.ints:
        r.matched_evidence.append(f"int set {sorted(s.cfg.ints)}")
    if s.cfg.backedges:
        r.matched_evidence.append(f"loops (back-edges) {len(s.cfg.backedges)}")
    return r


def compare_symbol(name: str, src_im: ImageRef, dst_im: ImageRef) -> MatchResult:
    sv = extract_function(src_im, name, _next_symbol_va(src_im, src_im.syms.get(name, 0)))
    dv = extract_function(dst_im, name, _next_symbol_va(dst_im, dst_im.syms.get(name, 0)))
    return classify(name, sv, dv, src_im, dst_im)


# =============================================================================
# 4. CLI
# =============================================================================
def _result_json(r: MatchResult) -> dict:
    d = dataclasses.asdict(r)
    d["cfg_src"] = r.cfg_src
    d["cfg_dst"] = r.cfg_dst
    return d


def run(src_exe, src_map, dst_exe, dst_map, symbols):
    src_im = load_image(src_exe, src_map)
    dst_im = load_image(dst_exe, dst_map)
    print(f"[load] src {src_im.path}  {len(src_im.syms)} syms, {len(src_im.fixups)} fixups",
          file=sys.stderr)
    print(f"[load] dst {dst_im.path}  {len(dst_im.syms)} syms, {len(dst_im.fixups)} fixups",
          file=sys.stderr)
    results = [compare_symbol(s, src_im, dst_im) for s in symbols]
    for r in results:
        print(
            f"\n=== {r.name} ===\n"
            f"  src va {r.src_va} size {r.src_size}   dst va {r.dst_va} size {r.dst_size}\n"
            f"  classification: {r.classification}   "
            f"exact={r.byte_exact} masked_eq={r.masked_equal} diff={r.byte_diff}\n"
            f"  token_sim={r.token_sim:.3f}  cfg_iso={r.cfg_iso} cfg_sim={r.cfg_sim:.3f}\n"
            f"  fixups src={r.src_fixups} dst={r.dst_fixups}\n"
        )
        for e in r.matched_evidence:
            print(f"    MATCH  {e}")
        for e in r.unmatched_evidence:
            print(f"    UNM    {e}")
        for e in r.semantic_diffs:
            print(f"    SEM    {e}")
        if r.unknown_reason:
            print(f"    UNKNOWN {r.unknown_reason}")
    return [(_result_json(r)) for r in results]


def main(argv=None):
    ap = argparse.ArgumentParser(description="relocation-aware LE function matcher")
    ap.add_argument("--src"); ap.add_argument("--srcmap")
    ap.add_argument("--dst"); ap.add_argument("--dstmap")
    ap.add_argument("--symbols", nargs="*", default=[])
    ap.add_argument("--json", help="write machine-readable results here")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args(argv)
    if a.selftest:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "selftest_bflib_match", Path(__file__).with_name("selftest_bflib_match.py"))
        mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
        raise SystemExit(mod.run())
    if not (a.src and a.srcmap and a.dst and a.dstmap and a.symbols):
        ap.error("need --src --srcmap --dst --dstmap --symbols (or --selftest)")
    results = run(a.src, a.srcmap, a.dst, a.dstmap, a.symbols)
    if a.json:
        Path(a.json).write_text(json.dumps(results, indent=2))
        print(f"\n[json] wrote {a.json} ({len(results)} results)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())