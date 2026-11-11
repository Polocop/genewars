from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

ROOT = Path(r"E:\GWRecomp")
EVIDENCE = ROOT / "evidence/w3_224_ah4400_ordinal6_caller.json"
TRACE = ROOT / "build/dosboxx_oracle/C/W3_224_AH4400_ORDINAL6_20261009_01.jsonl"
SOURCE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
MAP = ROOT / "evidence/genewars-1_1.map"
OUT = ROOT / "evidence/w3_225_ah4400_static_audit.json"
REPORT = ROOT / "reports/coordination/w3_225_ah4400_static_audit.md"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def audit() -> dict:
    capture = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    rows = [json.loads(line) for line in TRACE.read_text(encoding="utf-8-sig").splitlines()
            if line.strip()]
    callback = next(x for x in rows if x.get("event") == "original_int21_ah44"
                    and x.get("ordinal") == 6)
    cps = [x for x in rows if x.get("event") == "target_runtime_checkpoint"
           and x.get("process_psp") == callback.get("process_psp")]
    callsite = next(x for x in cps if x.get("sequence") == callback["sequence"] - 1
                    and x.get("link_va") == 0xC8973)
    paired_registers = all((callsite.get(reg, -1) & 0xffff) == callback.get(field)
                           for reg, field in (("eax", "in_ax"), ("ebx", "in_bx"),
                                              ("ecx", "in_cx"), ("edx", "in_dx")))
    preceding = [x for x in cps if x.get("sequence", 0) < callsite["sequence"]]
    prior_isatty = [x for x in preceding if x.get("checkpoint") == "AH44_ISATTY_ENTRY"]
    prior_chktty_call = [x for x in preceding
                         if x.get("checkpoint") == "AH44_CHKTTY_ISATTY_CALL"]
    words = callsite.get("stack_words_u32", [])
    raw_return = words[0] if words else None
    rebase = callback.get("main_code_rebase")
    candidate_link = raw_return - rebase if raw_return is not None and rebase else None

    symbol_rows = []
    for line in MAP.read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.match(r"\s*0001:([0-9A-Fa-f]{6,8})\s+(\S+)", line)
        if m:
            symbol_rows.append((int(m.group(1), 16), m.group(2)))
    before = max((s for s in symbol_rows if candidate_link is not None and s[0] <= candidate_link),
                 default=None)
    after = min((s for s in symbol_rows if candidate_link is not None and s[0] > candidate_link),
                default=None)

    source = SOURCE.read_text(encoding="utf-8", errors="replace")
    measured_pos = source.index("const bool measured_address_matches = target_main_rebase")
    append_pos = source.index("if (exec_trace::append_event(record))", measured_pos)
    assign_pos = source.index("target_main_rebase = ip_point - link_va", append_pos)
    anchor = capture["main_mapping_anchors"][0]
    candidate_rebase = anchor["candidate_rebase"]
    # An unset prior rebase makes the field false; the accepted byte-signature
    # anchor then seeds target_main_rebase after the event is serialized.
    false_semantics_confirmed = (not anchor["measured_address_matches"]
                                 and anchor["byte_signature_matches"]
                                 and measured_pos < append_pos < assign_pos
                                 and candidate_rebase == callback["main_code_rebase"])

    result = {
        "schema": "gwrecomp.w3-225-ah4400-static-audit/v1",
        "task": "W3-225",
        "evidence_level": "ORIGINAL_OBSERVED_WITH_STATIC_RECONCILIATION",
        "inputs": {
            "capture": {"path": str(EVIDENCE), "sha256": sha256(EVIDENCE)},
            "trace": {"path": str(TRACE), "sha256": sha256(TRACE), "rows": len(rows)},
            "instrumentation_source": {"path": str(SOURCE), "sha256": sha256(SOURCE)},
            "exact_target_map": {"path": str(MAP), "sha256": sha256(MAP)},
        },
        "ordinal6": {
            "sequence": callback["sequence"], "psp": callback["process_psp"],
            "request": {"AX": callback["in_ax"], "BX": callback["in_bx"],
                        "CX": callback["in_cx"], "DX": callback["in_dx"]},
            "return": {"AX": callback["out_ax"], "DX": callback["out_dx"],
                       "CF": callback["cf"]},
            "cwd": callback.get("cwd"), "same_process_callsite_sequence": callsite["sequence"],
            "callsite_link_va": callsite["link_va"],
            "callsite_registers_match_callback": paired_registers,
            "mapping_rebase_from_capture": rebase,
            "stack_return_raw": raw_return,
            "stack_return_candidate_link_va": candidate_link,
            "map_nearest_symbol_before": ({"va": before[0], "name": before[1]} if before else None),
            "map_nearest_symbol_after": ({"va": after[0], "name": after[1]} if after else None),
            "direct_caller": "UNKNOWN",
            "direct_caller_reason": "The captured stack word resolves to a candidate VA beyond the exact-target MAP's highest code-section symbol; no instruction bytes or runtime checkpoint at that candidate were recorded. The return word therefore cannot be safely attributed as a caller address.",
            "prior_isatty_checkpoint_count": len(prior_isatty),
            "prior_chktty_isatty_call_checkpoint_count": len(prior_chktty_call),
            "latest_prior_target_checkpoint": ({"sequence": preceding[-1]["sequence"],
                                                "checkpoint": preceding[-1].get("checkpoint"),
                                                "link_va": preceding[-1].get("link_va")}
                                               if preceding else None),
        },
        "mapping_marker_audit": {
            "anchor_link_va": anchor["link_va"],
            "anchor_candidate_rebase": candidate_rebase,
            "byte_signature_matches": anchor["byte_signature_matches"],
            "serialized_measured_address_matches": anchor["measured_address_matches"],
            "instrumentation_order_confirms_false_is_preseed": false_semantics_confirmed,
            "interpretation": "The marker was evaluated while the prior target_main_rebase was still zero. After the anchor record was appended, matching MAIN_ENTRY seeded target_main_rebase from ip_point minus link_va. Thus false is expected for this first self-seeding anchor; it does not establish a mapping mismatch. The candidate rebase equals the callback's 0x1EB000, but this run has no independent code anchor, so classify as signature-seeded/corroborated by callback metadata, not independently anchored.",
        },
        "conclusion": "ORIGINAL ordinal 6 is observed as INT 21 AX=4400/BX=2 at link 0xC8973; the immediately preceding same-process checkpoint has matching request registers and the DOS return is AX=DX=2, CF=0. The call is inside isatty_ by its static site. This bounded trace does not show the __chktty_ -> isatty_ chain for ordinal 6 and the captured stack return cannot establish another direct caller.",
        "next_action": "If caller attribution remains required, add a narrow capture at the exact call/return boundary that validates the stack return as an executable code address under the measured CS descriptor and target image bounds; do not repeat the prior capture unchanged or infer caller from the ordinal alone.",
    }
    OUT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(
        "# W3-225 — ordinal-6 AX=4400 static audit\n\n"
        f"Evidence: [{OUT.name}](../../{OUT.as_posix()})\n\n"
        "W3-224 captured original ordinal 6 at sequence 43: AX=4400, BX=2, "
        "CX=0x483C, DX=0x2B61; DOS returned AX=DX=2 with CF clear. Sequence 42 "
        "is a same-process 0xC8973 checkpoint with the same low-word request registers.\n\n"
        "The available trace does not include an immediately preceding isatty entry or "
        "__chktty_ callsite for this ordinal. The top stack word is 0x382B61; subtracting "
        "the candidate 0x1EB000 rebase gives 0x197B61, beyond the exact-target MAP's "
        "highest code-section symbol (0x0EE860). With no code bytes/checkpoint there, "
        "the direct caller remains UNKNOWN.\n\n"
        "The anchor's `measured_address_matches=false` is not by itself a mapping failure: "
        "the instrumentation computes it before accepting/appending the first anchor, then "
        "sets `target_main_rebase` from that anchor. The byte signature matched; the candidate "
        "rebase is 0x1EB000, matching the callback metadata, but an independent code anchor "
        "was absent.\n\n"
        "No new Oracle run was made. Next: if caller attribution is still needed, capture the "
        "call boundary and validate the return target against executable image bounds.\n",
        encoding="utf-8")
    return result


if __name__ == "__main__":
    print(json.dumps(audit(), indent=2, ensure_ascii=False))
