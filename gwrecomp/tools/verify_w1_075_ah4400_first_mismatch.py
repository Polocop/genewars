"""Validate the bounded, cross-run AX=4400 request-sequence reconciliation."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def validate(path: Path) -> list[str]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    errors: list[str] = []
    if doc.get("schema") != "gwrecomp.w1-075-ah4400-first-mismatch/v1":
        errors.append("unexpected evidence schema")
    if doc.get("task") != "W1-075" or doc.get("evidence_level") != "INCONCLUSIVE":
        errors.append("task/evidence classification must preserve unresolved causality")
    for item in doc.get("source_artifacts", []):
        source = ROOT / item["path"]
        if not source.is_file():
            errors.append(f"missing source evidence: {item['path']}")
        elif hashlib.sha256(source.read_bytes()).hexdigest() != item["sha256"]:
            errors.append(f"source fingerprint changed: {item['path']}")

    seq = doc.get("sequence_alignment", {})
    if seq.get("original_bx_sequence") != [5, 5, 5, 5, 5, 2, 2, 2]:
        errors.append("original one-based request sequence changed")
    if seq.get("native_bx_sequence") != [5] * 8:
        errors.append("W1-074 native zero-based request sequence changed")
    mismatch = seq.get("first_request_sequence_mismatch", {})
    if mismatch.get("ordinal_one_based") != 6 or mismatch.get("original_bx") != "0x00000002" or mismatch.get("native_bx") != "0x00000005":
        errors.append("first observed request mismatch must remain ordinal 6: BX=2 versus BX=5")

    launch = doc.get("launch", {})
    if launch.get("normalized_argument_tokens_match") is not True or launch.get("raw_psp_tail_byte_parity") is not False:
        errors.append("launch evidence must distinguish normalized arguments from raw tail bytes")
    if doc.get("conclusion", {}).get("same_dynamic_invocation") is not False:
        errors.append("must not claim same dynamic invocation")
    if doc.get("conclusion", {}).get("first_causal_divergence") != "UNKNOWN; not established by these separate checkpoints":
        errors.append("causal first divergence must remain unknown")
    if doc.get("conclusion", {}).get("core_fix_required") is not False:
        errors.append("no Core fix may be claimed without causal evidence")
    gates = doc.get("queue_gates", {})
    if gates.get("W1-043", {}).get("status") != "BLOCKED" or gates.get("W3-060", {}).get("status") != "BLOCKED":
        errors.append("W1-043 and W3-060 must remain BLOCKED")
    w2 = gates.get("W2-086", {})
    if (w2.get("status") != "READY" or w2.get("claimable") is not False or
            w2.get("dependencies") != ["W3-060", "W1-043"]):
        errors.append("W2-086 must be labeled READY but unclaimable on its incomplete dependencies")
    queue_capture = ROOT / "evidence/w1_076_w2_086_queue_state.json"
    if not queue_capture.is_file():
        errors.append("missing authoritative W2-086 queue-state capture")
    else:
        queue_doc = json.loads(queue_capture.read_text(encoding="utf-8"))
        if queue_doc.get("rows", {}).get("W2-086", {}).get("status") != "READY":
            errors.append("queue-state capture does not record W2-086 as READY")
        preview = json.loads(queue_doc.get("preview", {}).get("stdout", "{}") or "{}")
        if preview.get("claimable") is not False:
            errors.append("queue-state capture must record W2-086 as not claimable")
    return errors


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "evidence/w1_075_ah4400_first_mismatch.json"
    if not path.is_absolute():
        path = ROOT / path
    errors = validate(path)
    if errors:
        for error in errors:
            print(f"FAIL W1-075: {error}")
        return 1
    print("PASS W1-075 bounded AX=4400 mismatch evidence; causal divergence remains unknown")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
