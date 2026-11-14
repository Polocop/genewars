"""Read-only audit of bounded original AH=4400 events in the W3-214 trace."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
W3_214 = ROOT / "evidence/w3_214_ax6300_pointer_capture.json"
W3_186 = ROOT / "evidence/w3_186_ah4400_bx1_provenance.json"
OUT = ROOT / "evidence/w3_218_ah4400_tail_audit.json"
REPORT = ROOT / "reports/coordination/w3_218_ah4400_tail_audit.md"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def audit() -> dict:
    evidence = json.loads(W3_214.read_text(encoding="utf-8"))
    prior = json.loads(W3_186.read_text(encoding="utf-8"))
    trace = Path(evidence["source"]["trace_path"])
    raw = trace.read_bytes()
    if len(raw) != evidence["trace"]["bytes"] or digest(trace) != evidence["trace"]["sha256"]:
        raise ValueError("W3-214 trace provenance mismatch")
    rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    callbacks = [r for r in rows if r.get("event") == "original_int21_ah44"]
    if len(callbacks) != 8 or [r.get("ordinal") for r in callbacks] != list(range(1, 9)):
        raise ValueError("expected exactly eight chronologically ordered AH=4400 callbacks")
    normalized = []
    for row in callbacks:
        if row.get("in_ax") != 0x4400:
            raise ValueError("unexpected AX in the AH=4400 callback set")
        normalized.append({
            "sequence": row["sequence"],
            "ordinal": row["ordinal"],
            "input": {k: row[f"in_{k}"] for k in ("ax", "bx", "cx", "dx")},
            "output": {"ax": row["out_ax"], "dx": row["out_dx"], "cf": row["cf"]},
            "psp": row["process_psp"],
            "default_drive": row["default_drive"],
            "cwd": row["cwd"],
            "caller_link_va": row["caller_link_va"],
            "caller_context": row["caller_context"],
        })
    handles = [e["input"]["bx"] for e in normalized]
    if handles != [5, 5, 5, 5, 5, 2, 2, 2]:
        raise ValueError("unexpected AX=4400 handle sequence")
    if any(e["output"] != {"ax": 2, "dx": 2, "cf": False} for e in normalized):
        raise ValueError("unexpected DOS response in the captured callbacks")
    if any(e["default_drive"] != "C" or e["cwd"] != "GENEWARS" or e["caller_link_va"] is not None for e in normalized):
        raise ValueError("unexpected context or caller-attribution status")
    if any(e["input"]["bx"] == 1 for e in normalized):
        raise ValueError("BX=1 must remain absent from this trace")
    if evidence["source"]["psp_tail"] != " -k 38928":
        raise ValueError("W3-214 recorded launch tail differs from the matched-tail premise")

    original_bx1 = prior["original_observed"]
    if original_bx1["request"]["bx"] != "0x1" or original_bx1["response"]["ax"] != "0x80d3":
        raise ValueError("W3-091 BX=1 source record changed")
    return {
        "schema": "w3-218-ah4400-tail-audit/v1",
        "task": "W3-218",
        "classification": "MATCHED_TAIL_EARLY_CALLBACKS_NO_BX1_OBSERVED",
        "source_evidence": {
            "w3_214": {"path": "evidence/w3_214_ax6300_pointer_capture.json", "sha256": digest(W3_214)},
            "w3_214_trace": {"path": evidence["source"]["trace_path"], "sha256": evidence["trace"]["sha256"], "bytes": len(raw), "event_count": len(rows)},
            "w3_186": {"path": "evidence/w3_186_ah4400_bx1_provenance.json", "sha256": digest(W3_186)},
        },
        "w3_214_run": {
            "run_id": evidence["run_id"],
            "target_sha256": evidence["source"]["target_sha256"],
            "staging_revision": evidence["source"]["source_revision"],
            "runtime_sha256": evidence["source"]["runtime_sha256"],
            "config_sha256": evidence["source"]["config_sha256"],
            "cue_sha256": evidence["source"]["cue_sha256"],
            "recorded_dos_launch_tail": evidence["source"]["psp_tail"],
            "main_code_rebase": f"0x{evidence['capture']['main_code_rebase']:08X}",
            "psp": 7811,
            "cwd": "GENEWARS",
            "guard_cause": evidence["guard"]["cause"],
            "guard_timeout_s": evidence["guard"]["limits"]["timeout_s"],
        },
        "ax4400_callbacks": normalized,
        "observed_bx_sequence": handles,
        "bx1_observed_in_w3_214_trace": False,
        "distinct_w3_091_bx1_contract": {
            "request": original_bx1["request"],
            "response": original_bx1["response"],
            "configured_launch_has_no_launcher_tail": original_bx1["configured_launch_has_no_launcher_tail"],
            "same_run_as_w3_214": False,
        },
        "limits": [
            "All eight callbacks have caller_link_va=null; none is attributed to MAIN link 0xC8973.",
            "The W3-214 trace ended at its 10-second oracle_guard timeout. No BX=1 in this bounded trace does not prove BX=1 never occurs later in that run.",
            "The recorded -k 38928 DOS EXEC tail does not establish full original/native seed equivalence or the initial provenance of ADDRESS.TXT.",
            "AX=2/DX=2/CF clear responses for BX=5 and BX=2 cannot be reused for handle 1/BX=1."
        ],
        "next_action": "Use this as a bounded same-tail early callback sequence. To unblock W1-043/W2-086, obtain an authenticated matched original/native pre-call seed or first-divergence capture at the specific C8973/BX=1 frontier; do not replay unchanged or synthesize a response."
    }


def write_outputs(data: dict) -> None:
    OUT.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    counts = {str(n): data["observed_bx_sequence"].count(n) for n in (1, 2, 5)}
    REPORT.write_text(
        "# W3-218 — AX=4400 callbacks in the matched-tail original trace\n\n"
        "## Result\n\n"
        "Read-only audit of the existing W3-214 trace (no new DOSBox run). The recorded DOS launch tail is ` -k 38928`, the same tail string used by W1-053. Before the 10-second guard timeout, the original produced eight AX=4400 callbacks: five with BX=5, then three with BX=2. Each returned AX=2, DX=2, CF clear, in `C:\\GENEWARS` on drive C. No BX=1 callback appears in this bounded interval.\n\n"
        "The trace records `caller_link_va=null` for all eight callbacks. It therefore does not attribute them to MAIN `0xC8973`. W3-091 remains the separate original BX=1 observation (`AX=DX=0x80D3`, CF clear, handle 1/CON) under a configured launch without launcher tail; the BX=5/BX=2 responses here do not define BX=1 behavior.\n\n"
        "## Limitations and next step\n\n"
        "Absence in a 10-second bounded trace is not proof that the run never reaches BX=1 later. The matched tail alone does not establish full seed equivalence or initial `ADDRESS.TXT` provenance. Continue only with an authenticated matched pre-call seed or first-divergence capture at `0xC8973`/BX=1; do not reuse responses or repeat the unchanged replay.\n\n"
        "Machine-readable events and source hashes: `evidence/w3_218_ah4400_tail_audit.json`.\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    result = audit()
    write_outputs(result)
    print(json.dumps({"task": "W3-218", "classification": result["classification"], "bx_counts": {str(n): result["observed_bx_sequence"].count(n) for n in (1, 2, 5)}}, indent=2))
