"""selftest for bflib_match.py — synthetic + real-image cases.

Run:  python bflib_match.py --selftest
All assertions must pass.  Synthetic cases exercise the pure comparison engine
without any real executable; real cases run only when the two pinned LE images
are present (they are, in evidence/), and exercise the full load->decode->CFG
pipeline on the actual GeneWars 1.1 vs Beta2 VESA functions.
"""
from __future__ import annotations
import os as _gw_os
from pathlib import Path as _GwPath
_GW_ROOT=str(_GwPath(__file__).resolve().parents[1])
_GW_FX=_gw_os.environ.get("GENEWARSFX_ROOT",_gw_os.path.join(_GW_ROOT,"third_party","GeneWarsFX"))
import os, sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bflib_match as M
from bflib_match import FuncView, CfgView, classify, inst_token
import gw_int_audit as A   # reachability walk (OBJ 2) — shares decode32/ImageRef

ROOT = Path(__file__).resolve().parent.parent
EV = ROOT / "evidence"
B2 = Path((_GW_FX.replace("\\","/") + '/upstream/genewars-re-helpers'))

# ---------------------------------------------------------------- helpers ----
class FakeIm:
    """Minimal stand-in carrying only what classify()/relocation_target_check
    touch: .syms and (optionally) .mem/.fixups."""
    def __init__(self, syms=None):
        self.syms = syms or {}
        self.mem = bytearray(0)
        self.fixups = []


def fv(name, va, body, masked=None, sig=None, size=None, scan_ok=True,
       missing=False, fixup_sites=None, cfg=None, refusal=""):
    masked = masked if masked is not None else list(body)
    sig = sig if sig is not None else ["x"] * len(body)
    size = size if size is not None else len(body)
    cfg = cfg if cfg is not None else CfgView()
    cfg.size = size
    cfg.n_insts = len(sig)
    return FuncView(name=name, va=va, size=size, body=bytes(body), masked=masked,
                    fixup_sites=fixup_sites or [], toks=[], sig=sig, cfg=cfg,
                    scan_ok=scan_ok, missing=missing, refusal=refusal)


def cfg_view(leaders, edges, size, n_insts, exits=(), backedges=(), ints=()):
    c = CfgView()
    c.leaders_rel = set(leaders); c.edges = set(edges)
    c.size = size; c.n_insts = n_insts
    c.exits_rel = list(exits); c.backedges = set(backedges); c.ints = set(ints)
    return c


# ---------------------------------------------------------------- cases -----
def t_identical():
    body = bytes(range(1, 33))
    sig = [f"i{k}" for k in range(32)]
    s = fv("f", 0x100, body, sig=sig, cfg=cfg_view([0, 8], [(0, 8), (8, 24)], 32, 32, exits=[31]))
    d = fv("f", 0x200, body, sig=sig, cfg=cfg_view([0, 8], [(0, 8), (8, 24)], 32, 32, exits=[31]))
    r = classify("f", s, d, FakeIm(), FakeIm())
    assert r.classification == "EXACT" and r.byte_exact, r
    return r


def t_equiv_relocs():
    # identical structure; two reloc fields (bytes 4..7 and 20..21) differ in
    # value but are masked None on both sides -> only relocations differ.
    body_s = bytearray(32); body_d = bytearray(32)
    for i in range(32):
        body_s[i] = i
        body_d[i] = i
    body_s[4:8] = b"\x11\x22\x33\x44"      # src reloc value
    body_d[4:8] = b"\xAA\xBB\xCC\xDD"      # dst reloc value (different target)
    body_s[20:22] = b"\x01\x02"; body_d[20:22] = b"\x99\x88"
    sig = [f"i{k}" for k in range(32)]
    sites_s = [(4, 0x900, 0x07, 4), (20, 0x500, 0x05, 2)]
    sites_d = [(4, 0xF000, 0x07, 4), (20, 0x1234, 0x05, 2)]
    def mk(body, sites):
        masked = list(bytes(body))
        for rel, tgt, st, fs in sites:
            for i in range(rel, rel + fs):
                masked[i] = None
        cfg = cfg_view([0, 8], [(0, 8), (8, 24)], 32, 32, exits=[31])
        return fv("f", 0x100, bytes(body), masked=masked, sig=sig,
                  fixup_sites=sites, cfg=cfg)
    r = classify("f", mk(body_s, sites_s), mk(body_d, sites_d),
                 FakeIm(), FakeIm())
    assert r.classification == "HIGH", (r.classification, r.semantic_diffs)
    # false-positive guard: the differing reloc targets MUST be surfaced
    ts = {c["target_va"] for c in r.relocation_checks_src}
    td = {c["target_va"] for c in r.relocation_checks_dst}
    assert ts != td, "relocation target difference not reported"
    return r


def t_name_only_rejected():
    # same size, totally different instruction skeleton + cfg -> REJECTED.
    body_s = bytes([1] * 40); body_d = bytes([9] * 40)
    s = fv("f", 0x100, body_s, sig=[f"a{k}" for k in range(40)],
           cfg=cfg_view([0, 4], [(0, 4)], 40, 40, exits=[39]))
    d = fv("f", 0x200, body_d, sig=[f"z{k}" for k in range(40)],
           cfg=cfg_view([0, 20, 30], [(0, 20), (20, 30)], 40, 40, exits=[39],
                        backedges=[30], ints=[0x21]))
    r = classify("f", s, d, FakeIm(), FakeIm())
    assert r.classification == "REJECTED", r
    return r


def t_similar_instr_diff_cfg():
    # same size, same inst count, ~75% token overlap but different CFG -> LOW
    # (must NOT be promoted to MEDIUM/HIGH by instruction similarity alone).
    sig = [f"i{k}" for k in range(30)]
    sig_d = list(sig)
    for k in range(0, 30, 4):      # mutate 25% of tokens
        sig_d[k] = f"X{k}"
    body_s = bytes(range(30))
    body_d = bytes(range(30, 60))   # DIFFERENT body so EXACT cannot short-circuit
    s = fv("f", 0x100, body_s, sig=sig,
           cfg=cfg_view([0, 8, 16], [(0, 8), (8, 16), (16, 29)], 30, 30, exits=[29]))
    d = fv("f", 0x200, body_d, sig=sig_d,
           cfg=cfg_view([0, 10, 20], [(0, 10), (10, 20)], 30, 30, exits=[29]))
    r = classify("f", s, d, FakeIm(), FakeIm())
    assert r.classification in ("LOW", "REJECTED"), r
    assert r.classification != "HIGH" and r.classification != "MEDIUM"
    return r


def t_missing_dst():
    s = fv("f", 0x100, bytes(20), scan_ok=True, cfg=cfg_view([0], set(), 20, 20))
    d = fv("f", -1, b"", missing=True, scan_ok=False)
    r = classify("f", s, d, FakeIm(), FakeIm())
    assert r.classification == "UNKNOWN" and "missing" in r.unknown_reason, r
    return r


def t_bad_bounds():
    s = fv("f", 0x100, bytes(0), size=0, cfg=cfg_view([], set(), 0, 0), scan_ok=True)
    d = fv("f", 0x200, bytes(5), cfg=cfg_view([0], set(), 5, 5), scan_ok=True)
    r = classify("f", s, d, FakeIm(), FakeIm())
    assert r.classification == "UNKNOWN" and "bounds" in r.unknown_reason, r
    return r


def t_decode_refusal():
    s = fv("f", 0x100, bytes(20), scan_ok=False, refusal="undecodable@0x104",
           cfg=cfg_view([0], set(), 20, 20))
    d = fv("f", 0x200, bytes(20), scan_ok=True, cfg=cfg_view([0], set(), 20, 20))
    r = classify("f", s, d, FakeIm(), FakeIm())
    assert r.classification == "UNKNOWN" and "decode" in r.unknown_reason, r
    return r


def t_nonhex_map_headers():
    """parse_loaded_map / parse_disc_map must survive non-hex header lines."""
    from bflib_match import parse_loaded_map
    from extract_symbol_corpus import parse_disc_map
    tmp = Path(os.environ.get("TMPDIR", "/tmp"))
    lm = tmp / "t_loaded.map"
    lm.write_text(
        "Start   Length  Name  Class\n"
        " 0001:00000000 0000EBC30H cseg01    CODE\n"
        "Created on: 96/08/09 16:20:45\n"   # non-hex header
        " 0001:000C2838       LbVesaSetMode_\n"
        " 0001:000C2894       LbVesaSetPage_\n"
        "Address Publics by Value\n"
    )
    syms = parse_loaded_map(lm)
    got = {n: v for v, n in syms}
    assert got.get("LbVesaSetMode_") == 0xC2838, got
    assert got.get("LbVesaSetPage_") == 0xC2894, got
    dm = parse_disc_map(Path(EV / "disc-MAIN.MAP"))   # real file, header junk present
    assert any(v.get("class") == "code" for v in dm.values()), "no code syms parsed"
    return {"loaded": sorted(got), "disc_code_syms":
            sum(1 for v in dm.values() if v.get("class") == "code")}


def t_reloc_diff_symbol_caps_high():
    """MISIÓN 1A: identical structure + masked-equal bytes + isomorphic CFG, but
    the relocated fields point at DIFFERENT symbols on each side.  This is the
    classic false-HIGH: a coincidental structural match whose semantics differ.
    The target-compatibility guard MUST cap it at MEDIUM (never HIGH/EXACT)."""
    sig = [f"i{k}" for k in range(32)]
    cfg = lambda: cfg_view([0, 8], [(0, 8), (8, 24)], 32, 32, exits=[31])
    body_s = bytearray(32); body_d = bytearray(32)
    for i in range(32):
        body_s[i] = i; body_d[i] = i
    # linear-space targets (offset+0x4000).  src -> 0x5000 = mode_state_a,
    # dst -> 0x6000 = unrelated_b: DIFFERENT symbols.
    body_s[4:8] = b"\x11\x22\x33\x44"
    body_d[4:8] = b"\xaa\xbb\xcc\xdd"
    sites_s = [(4, 0x5000, 0x07, 4)]   # -> mode_state_a
    sites_d = [(4, 0x6000, 0x07, 4)]   # -> unrelated_b
    def mk(body, sites, syms):
        masked = list(bytes(body))
        for rel, tgt, st, fs in sites:
            for i in range(rel, rel + fs):
                masked[i] = None
        return fv("f", 0x100, bytes(body), masked=masked, sig=sig,
                  fixup_sites=sites, cfg=cfg())
    src = FakeIm(syms={"mode_state_a": 0x5000, "unrelated_b": 0x6000})
    dst = FakeIm(syms={"mode_state_a": 0x5000, "unrelated_b": 0x6000})
    s = mk(body_s, sites_s, src.syms)
    d = mk(body_d, sites_d, dst.syms)
    r = classify("f", s, d, src, dst)
    assert r.reloc_compat_issues["diff_symbol"] >= 1, r.reloc_compat_issues
    assert r.classification in ("MEDIUM", "LOW", "REJECTED"), \
        f"false HIGH escaped: {r.classification}"
    assert r.classification not in ("HIGH", "EXACT")
    return r


def t_reloc_same_symbol_stays_high():
    """MISIÓN 1A positive: identical structure, relocated fields differ in
    ADDRESS but both resolve to the SAME symbol -> benign, must stay HIGH
    (this is the normal cross-build relocation case)."""
    sig = [f"i{k}" for k in range(32)]
    body_s = bytearray(32); body_d = bytearray(32)
    for i in range(32):
        body_s[i] = i; body_d[i] = i
    # linear-space: both builds relocate to the same symbol 'mode_state'
    # (src -> 0x5000, dst -> 0x6000, same name, different address)
    body_s[4:8] = b"\x11\x22\x33\x44"; body_d[4:8] = b"\xaa\xbb\xcc\xdd"
    def mk(body, tgt):
        masked = list(bytes(body))
        for i in range(4, 8):
            masked[i] = None
        return fv("f", 0x100, bytes(body), masked=masked, sig=sig,
                  fixup_sites=[(4, tgt, 0x07, 4)],
                  cfg=cfg_view([0, 8], [(0, 8), (8, 24)], 32, 32, exits=[31]))
    s = mk(body_s, 0x5000); d = mk(body_d, 0x6000)
    src = FakeIm(syms={"mode_state": 0x5000})
    dst = FakeIm(syms={"mode_state": 0x6000})
    r = classify("f", s, d, src, dst)
    assert r.reloc_compat_issues["diff_symbol"] == 0, r.reloc_compat_issues
    assert r.reloc_compat_issues["same_symbol"] >= 1, r.reloc_compat_issues
    assert r.classification == "HIGH", (r.classification, r.semantic_diffs)
    return r


def t_fixup_type_diff_caps_high():
    """MISIÓN 1A: same reloc slot + same target symbol, but different fixup
    src-type (codegen changed the field width) -> must not be HIGH/EXACT."""
    sig = [f"i{k}" for k in range(32)]
    body_s = bytes(range(32)); body_d = bytearray(32)
    for i in range(32):
        body_d[i] = i
    # distinct raw reloc value on each side (masked on both) so EXACT suppressed
    body_s = bytearray(body_s); 
    for i in range(4, 8): body_s[i] = 0x11
    for i in range(4, 8): body_d[i] = 0xAA
    def mk(body, st):
        masked = list(bytes(body))
        for i in range(4, 8):
            masked[i] = None
        return fv("f", 0x100, bytes(body), masked=masked, sig=sig,
                  fixup_sites=[(4, 0x5000, st, 4)],
                  cfg=cfg_view([0, 8], [(0, 8), (8, 24)], 32, 32, exits=[31]))
    src = FakeIm(syms={"g": 0x5000}); dst = FakeIm(syms={"g": 0x5000})
    r = classify("f", mk(body_s, 0x07), mk(body_d, 0x05), src, dst)
    assert r.reloc_compat_issues["fixup_type_diff"] >= 1, r.reloc_compat_issues
    assert r.classification not in ("HIGH", "EXACT"), r.classification
    return r


def t_unknown_target_warns_not_rejects():
    """MISIÓN 1A: a relocated target absent from the symbol map (data gap) is
    NOT proof of difference -> the grade must NOT be capped, only warned."""
    sig = [f"i{k}" for k in range(32)]
    body = bytearray(32)
    for i in range(32):
        body[i] = i
    # src target resolves, dst target is unmapped (unknown) -> warn, stay HIGH
    src = FakeIm(syms={"g": 0x1000})
    dst = FakeIm(syms={})            # 0x2000 unmapped
    # distinct raw reloc value on each side so bodies differ (EXACT suppressed)
    body_src = bytearray(body)
    for i in range(4, 8): body_src[i] = 0x11
    body_dst = bytearray(body)
    for i in range(4, 8): body_dst[i] = 0xAA
    def mk2(bd, tgt):
        masked = list(bytes(bd))
        for i in range(4, 8):
            masked[i] = None
        return fv("f", 0x100, bytes(bd), masked=masked, sig=sig,
                  fixup_sites=[(4, tgt, 0x07, 4)],
                  cfg=cfg_view([0, 8], [(0, 8), (8, 24)], 32, 32, exits=[31]))
    r = classify("f", mk2(body_src, 0x1000), mk2(body_dst, 0x2000), src, dst)
    assert r.reloc_compat_issues["unknown_target"] >= 1, r.reloc_compat_issues
    # unknown alone does not cap: still HIGH (structural match valid)
    assert r.classification == "HIGH", (r.classification, r.semantic_diffs)
    return r


def t_prologue_displacement_no_false_high():
    """MISIÓN 2: same instruction multiset but one side has an extra prologue
    instruction (e.g. an extra `push`/frame setup) so the token *positions*
    shift.  Positional token alignment must drop, and the CFG (extra block)
    differs -> must NOT be HIGH/EXACT.  Guards against matching on the
    *presence* of opcodes rather than their structure."""
    # src: 30 tokens. dst: same 30 tokens but one inserted at the front,
    # so every position is misaligned and there is an extra instruction.
    sig = [f"i{k}" for k in range(30)]
    sig_d = ["PUSH"] + sig            # prologue displacement + extra inst
    body_s = bytes(range(30)); body_d = bytes(range(30, 61))
    s = fv("f", 0x100, body_s, sig=sig,
           cfg=cfg_view([0, 8, 16], [(0, 8), (8, 16), (16, 29)], 30, 30, exits=[29]))
    d = fv("f", 0x200, body_d, sig=sig_d,
           cfg=cfg_view([0, 9, 17, 26], [(0, 9), (9, 17), (17, 30)], 31, 31, exits=[30]))
    r = classify("f", s, d, FakeIm(), FakeIm())
    assert r.classification not in ("HIGH", "EXACT"), r.classification
    # different inst count + shifted positions -> not a clean structural match
    assert r.cfg_iso is False
    return r


def t_size_shift_not_high():
    """MISIÓN 2: bodies differ in size (one build added an instruction) even
    though a large shared prefix is byte-identical.  A size change alone must
    preclude HIGH/EXACT (which require equal length)."""
    sig_s = [f"i{k}" for k in range(20)]
    sig_d = [f"i{k}" for k in range(22)]        # 2 extra tail instrs
    body_s = bytes(range(20)); body_d = bytes(range(20)) + bytes([0x90, 0x90])
    s = fv("f", 0x100, body_s, sig=sig_s,
           cfg=cfg_view([0], [(0, 19)], 20, 20, exits=[19]))
    d = fv("f", 0x200, body_d, sig=sig_d,
           cfg=cfg_view([0], [(0, 21)], 22, 22, exits=[21]))
    r = classify("f", s, d, FakeIm(), FakeIm())
    # sizes differ -> masked_equal requires s.size==d.size -> False; not HIGH
    assert r.classification not in ("HIGH", "EXACT"), r.classification
    assert r.src_size != r.dst_size
    return r


def t_absolute_address_never_compared():
    """MISIÓN 2: the two builds place the same function at different VAs.  The
    engine must normalize to entry-relative offsets (never compare absolute
    addresses), so a pure relocation/constant change at a different base still
    matches.  Feeds two views that are structurally identical but at far
    apart VAs -> must be HIGH (or EXACT), proving no absolute-address leak."""
    sig = [f"i{k}" for k in range(16)]
    body = bytes(range(16))
    s = fv("f", 0x1000, body, sig=sig,
           cfg=cfg_view([0, 4], [(0, 4), (4, 15)], 16, 16, exits=[15]))
    d = fv("f", 0xB00000, body, sig=sig,      # wildly different base VA
           cfg=cfg_view([0, 4], [(0, 4), (4, 15)], 16, 16, exits=[15]))
    r = classify("f", s, d, FakeIm(), FakeIm())
    assert r.classification in ("HIGH", "EXACT"), r.classification
    return r


def t_exact_path_reloc_guard():
    """MISIÓN 1A/2 (EXACT path): two byte-identical bodies must NOT be a
    *demonstrated* EXACT if their fixups resolve to different symbols.
    This is the exact regression for the bug where the EXACT early-return
    bypassed the relocation-target compatibility check."""
    body = bytes(range(32))
    def fv(body, sites):
        masked = list(bytes(body))
        for rel, tgt, st, fs in sites:
            for i in range(rel, rel + fs):
                masked[i] = None
        cfg = cfg_view([], set(), len(body), len(body))
        return FuncView(name="f", va=0x100, size=len(body), body=bytes(body),
                        masked=masked, fixup_sites=sites, toks=[],
                        sig=["x"] * len(body), cfg=cfg, scan_ok=True)
    class FI:
        def __init__(self, syms): self.syms = syms; self.mem = bytearray(0); self.fixups = []
    # A: diff symbol -> must cap to MEDIUM (never EXACT)
    rA = classify("f", fv(body, [(4, 0x5000, 0x07, 4)]), fv(body, [(4, 0x6000, 0x07, 4)]),
                  FI({"symA": 0x5000, "symB": 0x6000}), FI({"symA": 0x5000, "symB": 0x6000}))
    assert rA.classification == "MEDIUM" and rA.reloc_compat_issues["diff_symbol"] == 1, rA
    # B: same symbol (different address) -> benign, stays EXACT
    rB = classify("f", fv(body, [(4, 0x5000, 0x07, 4)]), fv(body, [(4, 0x6000, 0x07, 4)]),
                  FI({"symC": 0x5000}), FI({"symC": 0x6000}))
    assert rB.classification == "EXACT" and rB.reloc_compat_issues["same_symbol"] == 1, rB
    # C: unmapped target -> data gap, cap to HIGH (not a demonstrated equivalence)
    rC = classify("f", fv(body, [(4, 0x5000, 0x07, 4)]), fv(body, [(4, 0x9999, 0x07, 4)]),
                  FI({"g": 0x5000}), FI({}))
    assert rC.classification == "HIGH" and rC.reloc_compat_issues["unknown_target"] == 1, rC
    return {"diff_symbol": "MEDIUM", "same_symbol": "EXACT", "unknown_target": "HIGH"}


def _real_paths():
    s = (EV / "genewars-1_1.exe", EV / "genewars-1_1.map")
    d = (B2 / "bin" / "gw-genewars-beta2-jul_1996.exe",
         B2 / "symbols" / "gw-genewars-beta2-jul_1996.map")
    if all(Path(p).exists() for p in s + d):
        return s + d
    return None


def t_real_vesa():
    p = _real_paths()
    if p is None:
        return None
    src = M.load_image(p[0], p[1])
    dst = M.load_image(p[2], p[3])
    out = {}
    for name in ("LbVesaSetMode_", "LbVesaSetPage_", "LbVesaGetInfo_"):
        r = M.compare_symbol(name, src, dst)
        out[name] = {
            "src_va": r.src_va, "dst_va": r.dst_va,
            "src_size": r.src_size, "dst_size": r.dst_size,
            "classification": r.classification, "token_sim": round(r.token_sim, 3),
            "cfg_iso": r.cfg_iso, "cfg_sim": round(r.cfg_sim, 3),
            "byte_diff": r.byte_diff, "masked_equal": r.masked_equal,
            "src_fixups": r.src_fixups, "dst_fixups": r.dst_fixups,
            "match": r.matched_evidence, "unmatch": r.unmatched_evidence,
            "sem": r.semantic_diffs, "unknown": r.unknown_reason,
            "rel_src": r.relocation_checks_src[:6], "rel_dst": r.relocation_checks_dst[:6],
        }
        # invariant: a real comparison must never be UNKNOWN unless a symbol is
        # genuinely absent from a map
        if r.classification == "UNKNOWN" and not r.unknown_reason.startswith("missing"):
            raise AssertionError(f"{name}: unexpected UNKNOWN {r.unknown_reason}")
    return out


# =============================================================================
# CFG regression tests (OBJ 1): lock the decoder-kind casing fix.  The decoder
# emits LOWERCASE kinds (seq/jcc/jmp/call/...); if build_cfg_view were ever
# reverted to testing uppercase, every edge/leader/exit would silently vanish
# and cfg_similarity would degenerate to 1.0 (two empty sets).  These tests
# assert that the expected edges/leaders/exits ARE recorded, so a regression to
# the wrong casing fails hard instead of producing false-high similarities.
# =============================================================================
class FInst:
    """Minimal stand-in carrying only what build_cfg_view reads: ip, kind,
    target, length, int_no."""
    __slots__ = ("ip", "kind", "target", "length", "int_no")
    def __init__(self, ip, kind, target=None, length=1, int_no=None):
        self.ip = ip; self.kind = kind; self.target = target
        self.length = length; self.int_no = int_no


def _cfg(insts, bound):
    from bflib_match import build_cfg_view, EXIT_KINDS
    return build_cfg_view(insts, entry_va=0, bound=bound, exit_kinds=EXIT_KINDS)


def t_cfg_jcc_two_destinations():
    """JCC records BOTH successors: the branch TARGET as an edge, and the
    FALLTHROUGH as a leader (rel+length).  If the JCC kind test were ever
    reverted to the wrong casing, neither would be recorded and cfg_sim would
    degenerate to 1.0 on empty structure — this test fails hard instead."""
    # jcc @0 -> target 10, fallthrough (0+length=4); then filler seqs.
    insts = [FInst(0, "jcc", target=10, length=4),
             FInst(4, "seq"), FInst(8, "seq"), FInst(10, "seq")]
    v = _cfg(insts, bound=12)
    assert (0, 10) in v.edges, "target edge missing: %r" % v.edges
    assert 10 in v.leaders_rel, "target leader missing: %r" % v.leaders_rel
    assert 4 in v.leaders_rel, "fallthrough leader missing: %r" % v.leaders_rel
    assert 0 in v.leaders_rel
    return {"edges": sorted(v.edges), "leaders": sorted(v.leaders_rel)}


def t_cfg_jmp_unconditional():
    """JMP records only the target edge — an unconditional jump has NO
    fallthrough edge (code immediately after a jmp is NOT a successor)."""
    insts = [FInst(0, "jmp", target=8, length=5),
             FInst(5, "seq"), FInst(8, "seq")]
    v = _cfg(insts, bound=10)
    assert (0, 8) in v.edges, v.edges
    assert (0, 5) not in v.edges, "jmp must not record a fallthrough edge"
    assert 5 not in v.leaders_rel, "5 is not a branch target of the jmp"
    assert 8 in v.leaders_rel
    return {"edges": sorted(v.edges)}


def t_cfg_call_and_return():
    """A near CALL records an edge to its target (even out-of-slot, recorded not
    chased) and a RET records an exit."""
    insts = [FInst(0, "call", target=12, length=5),
             FInst(5, "seq"), FInst(7, "ret", length=1)]
    v = _cfg(insts, bound=11)
    assert (0, 12) in v.edges, v.edges
    assert 7 in v.exits_rel and v.exits is True, (v.exits_rel, v.exits)
    return {"edges": sorted(v.edges), "exits": v.exits_rel}


def t_cfg_multiple_rets_reachable():
    """Multiple RETs on different paths are all recorded as exits — a RET must
    not truncate the CFG view (each is just another exit block)."""
    insts = [FInst(0, "seq"), FInst(4, "ret", length=1),
             FInst(6, "seq"), FInst(8, "ret", length=1)]
    v = _cfg(insts, bound=10)
    assert 4 in v.exits_rel and 8 in v.exits_rel, v.exits_rel
    assert len(v.exits_rel) == 2
    return {"exits": v.exits_rel}


def t_cfg_code_after_ret_present_in_sequential_view():
    """The matcher's structural view decodes the WHOLE slot sequentially (it
    does not stop at a RET), so an edge defined by an instruction that sits
    AFTER an earlier RET is still recorded.  This is the documented matcher
    semantics: a symmetric slot-level view across builds.  (The audit's
    reachability walk — see t_audit_adjacent_function_excluded — is the
    instrument that correctly excludes such code from a single function's body.)
    """
    # ret @4, then a jcc @8 -> target 16, fallthrough 8+4=12
    insts = [FInst(0, "seq"), FInst(4, "ret", length=1),
             FInst(6, "seq"), FInst(8, "jcc", target=16, length=4),
             FInst(12, "seq"), FInst(14, "seq")]
    v = _cfg(insts, bound=17)
    # the jcc after the RET must still contribute its target edge and
    # fallthrough leader (proving the sequential view does not stop at a RET)
    assert (8, 16) in v.edges, "post-RET jcc target edge missing: %r" % v.edges
    assert 12 in v.leaders_rel, "post-RET jcc fallthrough leader missing: %r" % v.leaders_rel
    # and the earlier RET is recorded as an exit, not a truncation point
    assert 4 in v.exits_rel
    return {"edges": sorted(v.edges), "leaders": sorted(v.leaders_rel)}


def t_audit_adjacent_function_excluded():
    """Reachability walk (the audit's instrument) must attribute ONLY code
    reachable from the entry to the function.  A jmp that skips over a region
    excludes that region; code after a RET (an adjacent unmapped function) is
    NOT reachable and is never attributed to this function.

    Layout (entry=0):
      0:  jmp rel32 -> 9        (E9 04 00 00 00)  [skips 5..8]
      5:  int 21h               (CD 21)  -> UNREACHABLE (skipped by jmp)
      7:  nop                   (90)     -> UNREACHABLE
      8:  nop                   (90)     -> UNREACHABLE
      9:  int 21h               (CD 21)  -> REACHABLE (jmp target)
      11: ret                  (C3)
      12: int 21h               (CD 21)  -> UNREACHABLE (adjacent fn, after RET)
      14..: nop
    """
    code = bytearray(16)
    code[0:5] = bytes([0xE9, 0x04, 0x00, 0x00, 0x00])   # jmp -> 9
    code[5:7] = b"\xcd\x21"                              # int21 (skipped)
    code[7] = 0x90
    code[8] = 0x90
    code[9:11] = b"\xcd\x21"                             # int21 (reachable)
    code[11] = 0xC3                                      # ret
    code[12:14] = b"\xcd\x21"                            # int21 (adjacent fn)
    code[14] = 0x90; code[15] = 0x90
    img = M.ImageRef(path="", map_path="", data=bytes(code), mem=code,
                     img=None, syms={}, fixups=[])
    reach, calls, incomplete = A.reachable_instructions(img, 0, 16)
    reach_ips = set(reach)
    assert 9 in reach_ips, "jmp target must be reachable"
    assert 5 not in reach_ips, "code skipped over by the jmp must be excluded"
    assert 12 not in reach_ips, "adjacent function after RET must be excluded"
    # the only reachable INT is the one at the jmp target (9)
    ints_seen = sorted(ip for ip in reach_ips if reach[ip].int_no is not None)
    assert ints_seen == [9], ints_seen
    return {"reachable_ints": ints_seen, "n_reachable": len(reach_ips)}


# ---------------------------------------------------------------- runner ----
CASES = [
    ("identical -> EXACT", t_identical),
    ("equivalent relocations -> HIGH", t_equiv_relocs),
    ("name-only / different body -> REJECTED", t_name_only_rejected),
    ("similar instr, different CFG -> not promoted", t_similar_instr_diff_cfg),
    ("missing symbol -> UNKNOWN", t_missing_dst),
    ("bad bounds -> UNKNOWN", t_bad_bounds),
    ("decode refusal -> UNKNOWN", t_decode_refusal),
    ("non-hex map headers parse OK", t_nonhex_map_headers),
    ("reloc diff-symbol -> cap at MEDIUM (no false HIGH)", t_reloc_diff_symbol_caps_high),
    ("reloc same-symbol (diff addr) -> stays HIGH", t_reloc_same_symbol_stays_high),
    ("fixup type diff -> cap at MEDIUM", t_fixup_type_diff_caps_high),
    ("unknown reloc target -> warns, not capped", t_unknown_target_warns_not_rejects),
    ("EXACT path: byte-identical + incompatible fixups -> not EXACT", t_exact_path_reloc_guard),
    ("prologue displacement -> not HIGH", t_prologue_displacement_no_false_high),
    ("size shift -> not HIGH/EXACT", t_size_shift_not_high),
    ("absolute address never compared", t_absolute_address_never_compared),
    ("CFG: JCC two destinations (target + fallthrough)", t_cfg_jcc_two_destinations),
    ("CFG: JMP records no fallthrough", t_cfg_jmp_unconditional),
    ("CFG: CALL edge + RET exit", t_cfg_call_and_return),
    ("CFG: multiple RETs all recorded as exits", t_cfg_multiple_rets_reachable),
    ("CFG: code after RET present in sequential view", t_cfg_code_after_ret_present_in_sequential_view),
    ("audit: adjacent fn / skipped code excluded by reachability", t_audit_adjacent_function_excluded),
    ("real VESA 1.1 vs beta2", t_real_vesa),
]


def run():
    failed = 0
    for label, fn in CASES:
        try:
            res = fn()
            tag = "PASS"
            detail = "" if res is None else f"  {res if not isinstance(res, dict) else {k: res[k] for k in list(res)[:6]}}"
        except AssertionError as e:
            failed += 1; tag = "FAIL"; detail = f"  assertion: {e}"
        except Exception as e:
            failed += 1; tag = "ERROR"; detail = f"  {type(e).__name__}: {e}"
        print(f"[{tag}] {label}{detail}")
    if failed:
        print(f"\nSELFTEST FAILED: {failed}/{len(CASES)} cases", file=sys.stderr)
        return 1
    print(f"\nSELFTEST OK: {len(CASES)}/{len(CASES)} cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())