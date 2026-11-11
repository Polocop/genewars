#!/usr/bin/env python3
"""gw_match_lookup.py — reference-lookup index for the L-BFLIB-MATCH deliverable
(MISIÓN 3).  Given a GeneWars symbol or VA, return the known cross-build
matches, the reference source, confidence, semantic differences and W1/W2
relevance.

Design (per MISIÓN 3): REUSE the existing artifacts, do NOT rebuild a catalog.
  * match results  : evidence/local_bflib_match_results.json   (bflib_match.py)
  * INT/VESA audit : evidence/local_bflib_int_audit.json       (gw_int_audit.py)
This tool only adds the human-facing layer: confidence, source-reference and
W1/W2 relevance annotations, keyed by symbol or VA.

Usage:
  python gw_match_lookup.py --symbol LbVesaSetMode_
  python gw_match_lookup.py --va 0xa3a00
  python gw_match_lookup.py --list            # show every indexed function
  python gw_match_lookup.py --symbol X --json # machine-readable single row
"""
import sys, json, argparse, pathlib, bisect

HERE = pathlib.Path(__file__).resolve().parent.parent
MATCH_JSON = HERE / "evidence" / "local_bflib_match_results.json"
AUDIT_JSON = HERE / "evidence" / "local_bflib_int_audit.json"

# Reference source for each BFLIB function (public reconstructed source in
# E:/GeneWarsFX, read-only) + a one-line role.  This is the "reference file /
# reference project" the deliverable asks for.
REFERENCE = {
    "LbScreenSetupAnyMode_":   ("bflibrary/src/x86-dos-watcom/sscreen.cpp (stub, beta2-derived)",
                                 "top-level screen-mode entry; picks VESA/VGA mode for the game"),
    "LbVesaSetMode_":          ("bflibrary/src/x86-dos-watcom/svesa.cpp (stub, beta2-derived)",
                                 "set VESA text/graphics mode (mode 0x1x via the VBE layer)"),
    "LbVesaSetPage_":          ("bflibrary/src/x86-dos-watcom/svesa.cpp (stub, beta2-derived)",
                                 "swap the double-buffer page (framebuffer front/back)"),
    "LbVesaGetInfo_":          ("bflibrary/src/x86-dos-watcom/svesa.cpp (stub, beta2-derived)",
                                 "fill the VBE mode info block (bytes-per-pixel, granularity, xres)"),
    "LbVesaGetGran_":          ("bflibrary/src/x86-dos-watcom/svesa.cpp (stub, beta2-derived)",
                                 "return the VESA granularity (rows per page)"),
    "LbVesaIsModeAvailable_":  ("bflibrary/src/x86-dos-watcom/svesa.cpp (stub, beta2-derived)",
                                 "probe whether a VESA mode is offered by the VBE"),
    "LbScreenSwap_":           ("bflibrary/src/x86-dos-watcom/sscreen.cpp (stub, beta2-derived)",
                                 "Bullfrog screen-blit/swap primitive (flip front buffer)"),
}

# W1/W2 relevance: which work-stream the match accelerates and why.
RELEVANCE = {
    "LbScreenSetupAnyMode_":  "W2: entry point for VIDEO setup — its own body has 1 direct INT 21h "
                              "(AH=3E lseek, a DOS file op, NOT a VESA int); 4 additional INTs in its "
                              "slot belong to adjacent unmapped functions. VESA path is fanned out to "
                              "the LbVesa* set. W1: none directly.",
    "LbVesaSetMode_":         "W2 HIGH-VALUE: CFG is NOT isomorphic (cfg_sim 0.61) — the 1.1 revision "
                              "rewrote instruction selection; encode 1.1 semantics, not beta2 bytes. "
                              "No direct INT in the function body. W1: the mode-state the framebuffer "
                              "depends on.",
    "LbVesaSetPage_":         "W2: page-granularity + double-buffer swap; 4 OFFSET32 fixups each "
                              "(identical shape in both builds, different targets). No direct INT in "
                              "the function body.",
    "LbVesaGetInfo_":         "W2: source of the VBE info block W2 must populate before first image. "
                              "No direct INT in the function body; delegates to 5 unmapped callees.",
    "LbVesaGetGran_":         "W2: rows-per-page for page math; needs W3 to confirm decode (UNKNOWN).",
    "LbVesaIsModeAvailable_": "W2: mode probe used by the setup fallback ladder.",
    "LbScreenSwap_":          "W2: the actual front-buffer flip before the first frame is shown. No "
                              "direct INT in the function body.",
}


def confidence_of(cls):
    return {"EXACT": 1.0, "HIGH": 0.9, "MEDIUM": 0.6, "LOW": 0.35,
            "REJECTED": 0.1, "UNKNOWN": 0.0}.get(cls, 0.0)


def load():
    m = {}
    if MATCH_JSON.exists():
        for r in json.loads(MATCH_JSON.read_text()):
            m[r["name"]] = r
    a = {}
    if AUDIT_JSON.exists():
        for r in json.loads(AUDIT_JSON.read_text()):
            a[r["name"]] = r
    return m, a


def _fmt_hex(v):
    try:
        return hex(int(v, 16) if isinstance(v, str) and v.startswith("0x") else v)
    except Exception:
        return str(v)


def build_row(name, m, a):
    mr = m.get(name)
    ar = a.get(name)
    row = {
        "symbol": name,
        "reference_file": REFERENCE.get(name, ("(no public BFLIB stub)", ""))[0],
        "reference_project": "Open Watcom BFLIB (x86-dos-watcom) via E:/GeneWarsFX/upstream/genewars",
        "role": REFERENCE.get(name, ("", ""))[1],
        "relevance": RELEVANCE.get(name, "(no W1/W2 annotation yet)"),
        "match": None, "audit": None, "confidence": None,
    }
    if mr is None:
        row["note"] = "no match result on disk — run bflib_match.py --symbols ..."
    else:
        row["match"] = mr
        row["confidence"] = confidence_of(mr.get("classification", "UNKNOWN"))
    if ar is not None:
        row["audit"] = ar
    return row


def row_text(row):
    L = []
    L.append(f"== {row['symbol']} ==")
    L.append(f"   reference : {row['reference_file']}")
    L.append(f"   project   : {row['reference_project']}")
    L.append(f"   role      : {row['role']}")
    if row.get("match"):
        mr = row["match"]
        L.append(f"   1.1 VA    : {mr.get('src_va')}  size {mr.get('src_size')}")
        L.append(f"   beta2 VA  : {mr.get('dst_va')}  size {mr.get('dst_size')}")
        L.append(f"   class     : {mr.get('classification')}   (confidence {row['confidence']:.2f})")
        L.append(f"   byte      : {mr.get('byte_diff')}/{mr.get('src_size')} diff   "
                 f"masked_equal={mr.get('masked_equal')}   token={mr.get('token_sim', 0):.2f} "
                 f"cfg={mr.get('cfg_sim', 0):.2f} iso={mr.get('cfg_iso')}")
        L.append(f"   fixups    : src {mr.get('src_fixups')} / dst {mr.get('dst_fixups')}")
        if mr.get("matched_evidence"):
            L.append(f"   MATCH     : " + "; ".join(mr["matched_evidence"]))
        if mr.get("unmatched_evidence"):
            L.append(f"   UNMATCH   : " + "; ".join(mr["unmatched_evidence"]))
        if mr.get("semantic_diffs"):
            L.append(f"   SEMDIFF   : " + "; ".join(mr["semantic_diffs"]))
        # reloc compat issues
        ci = mr.get("reloc_compat_issues") or {}
        ci = {k: v for k, v in ci.items() if v}
        if ci:
            L.append(f"   RELOC-CMP : {ci}")
        for side, key in (("src", "relocation_checks_src"), ("dst", "relocation_checks_dst")):
            for rc in (mr.get(key) or [])[:6]:
                L.append(f"   reloc-{side} {rc.get('field_off')} -> {rc.get('target_va')} "
                         f"({rc.get('src_type')}) {rc.get('resolved_symbol') or '(unmapped)'}")
    if row.get("audit"):
        ar = row["audit"]
        n_fn = len(ar.get("func_ints", []))
        n_slot = len(ar.get("slot_ints", []))
        cov = "COMPLETE" if ar.get("coverage_complete") else f"INCOMPLETE ({len(ar.get('coverage_incomplete', []))} unresolved)"
        L.append(f"   INT audit : 1.1@{ar.get('entry_va')}..{ar.get('slot_end')} "
                 f"body {ar.get('function_body_insts')} insts / slot {ar.get('slot_scanned_insts')} insts")
        if n_fn:
            fnk = ", ".join(sorted({d['service'] for d in ar['func_ints']}))
            L.append(f"   FUNC-BODY : {n_fn} direct INT  ->  {fnk}")
        else:
            L.append("   FUNC-BODY : no direct INT in the function's reachable body")
        if n_slot > n_fn:
            adj = [d['service'] for d in ar.get('slot_ints', []) if not d.get('in_function_body')]
            L.append(f"   SLOT-ONLY : {n_slot - n_fn} INT in the slot but outside the body (adjacent fns)  ->  {', '.join(adj)}")
        L.append(f"   coverage  : {cov}")
        callees = ar.get("call_targets", [])
        if callees:
            cc = ", ".join(f"{c.get('callee')}@{c.get('target_va')}" for c in callees[:6])
            L.append(f"   callees   : {cc}" + (f" (+{len(callees)-6} more)" if len(callees) > 6 else ""))
        else:
            L.append("   callees   : none (or all in-slot)")
    L.append(f"   relevance : {row['relevance']}")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--symbol", action="append")
    g.add_argument("--va")
    g.add_argument("--list", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    m, au = load()
    if a.list:
        rows = [build_row(n, m, au) for n in sorted(set(m) | set(REFERENCE))]
        if a.json:
            print(json.dumps(rows, indent=2))
        else:
            for r in rows:
                print(f"  {r['symbol']:26s} conf={r['confidence'] if r['confidence'] is not None else float('nan'):.2f}  "
                      f"{(r['match'] or {}).get('classification', '—')}")
        return
    names = list(a.symbol or [])
    if a.va:
        va = int(a.va, 16) if a.va.lower().startswith("0x") else int(a.va)
        hit = [n for n, r in m.items() if r.get("src_va") and
               (int(r["src_va"], 16) if isinstance(r["src_va"], str) and r["src_va"].startswith("0x") else r["src_va"]) == va]
        names += hit or [f"<VA {a.va} not in match index>"]
    out = []
    for n in names:
        row = build_row(n, m, au)
        if a.json:
            out.append(row)
        else:
            print(row_text(row) + "\n")
    if a.json:
        print(json.dumps(out if len(out) > 1 else out[0], indent=2))


if __name__ == "__main__":
    main()