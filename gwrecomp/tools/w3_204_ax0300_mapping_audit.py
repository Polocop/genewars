"""Read-only reconciliation of W3-184's original AX=0300 capture."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
W3_184 = ROOT / "evidence/w3_184_original_ax0300_window.json"
W1_070 = ROOT / "evidence/native_original_ax0300_frame_compare_w1_070.json"


def audit() -> dict:
    source = json.loads(W3_184.read_text(encoding="utf-8"))
    compare = json.loads(W1_070.read_text(encoding="utf-8"))
    trace_path = ROOT / source["trace"]["path"]
    raw = trace_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != source["trace"]["sha256"]:
        raise ValueError("W3-184 trace hash does not match its evidence manifest")
    rows = [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]
    entry = next((r for r in rows if r.get("checkpoint") == "W3_182_DPMI0300_ENTRY"), None)
    ret = next((r for r in rows if r.get("checkpoint") == "W3_182_DPMI0300_RETURN"), None)
    if entry is None or ret is None:
        raise ValueError("W3-184 trace lacks its recorded AX=0300 entry/return pair")
    code_rebase = int(entry["eip"]) - int(entry["link_va"])
    frame_ptr_mapping = bool(
        entry.get("w3_182_frame_descriptor_valid") is True
        and entry.get("w3_182_frame_valid") is True
        and ret.get("w3_182_frame_descriptor_valid") is True
        and ret.get("w3_182_frame_valid") is True
        and entry.get("w3_182_frame_descriptor_base") == ret.get("w3_182_frame_descriptor_base")
        and entry.get("w3_182_frame_linear") == ret.get("w3_182_frame_linear")
    )
    environment_map = bool(
        ret.get("w3_140_env_descriptor_valid") is True
        and ret.get("w3_140_env_descriptor_valid") is True
        and ret.get("w3_140_env_sample_bytes", 0) > 0
        and ret.get("w3_140_env_double_nul_found") is True
    )
    return {
        "schema": "w3-204-ax0300-mapping-audit/v1",
        "task": "W3-204",
        "classification": "PARTIAL_ORIGINAL_OBSERVED",
        "source_evidence": {
            "w3_184": "evidence/w3_184_original_ax0300_window.json",
            "w3_184_sha256": hashlib.sha256(W3_184.read_bytes()).hexdigest(),
            "trace": str(trace_path.relative_to(ROOT)),
            "trace_bytes": len(raw),
            "trace_sha256": hashlib.sha256(raw).hexdigest(),
            "trace_events": len(rows),
            "w1_070": "evidence/native_original_ax0300_frame_compare_w1_070.json",
            "w1_070_sha256": hashlib.sha256(W1_070.read_bytes()).hexdigest(),
        },
        "original_capture": {
            "entry_sequence": entry["sequence"],
            "return_sequence": ret["sequence"],
            "entry_link_va": hex(entry["link_va"]),
            "return_link_va": hex(ret["link_va"]),
            "code_rebase": hex(code_rebase),
            "process_psp": entry["process_psp"],
            "entry_es": hex(entry["es"]),
            "entry_edi": hex(entry["edi"]),
            "frame_pointer_descriptor_valid": frame_ptr_mapping,
            "frame_pointer_descriptor_base": hex(entry["w3_182_frame_descriptor_base"]),
            "frame_pointer_descriptor_limit": hex(entry["w3_182_frame_descriptor_limit"]),
            "frame_pointer_linear": hex(entry["w3_182_frame_linear"]),
            "frame_entry_hex": entry["w3_182_frame_hex"],
            "frame_return_hex": ret["w3_182_frame_hex"],
            "returned_inner_ds_si_descriptor_mapping": "NOT_CAPTURED",
            "environment_identity": source.get("environment_identity_status", "UNKNOWN"),
            "environment_descriptor_valid": ret.get("w3_140_env_descriptor_valid"),
            "environment_sample_bytes": ret.get("w3_140_env_sample_bytes"),
        },
        "w1_070_comparison": {
            "original_vs_native_same_run": compare["limitations"]["same_run_equivalence"],
            "original_entry_return_diff_offsets": compare["comparison"]["original_entry_return_diff_offsets"],
            "service_semantics_inferred": compare["limitations"]["service_semantics_inferred"],
        },
        "audit_conclusion": {
            "frame_storage_pointer_mapping_proven": frame_ptr_mapping,
            "returned_inner_ds_si_mapping_proven": False,
            "environment_identity_proven": environment_map,
            "missing_evidence": [
                "Decode the returned real-mode register frame using the exact pinned DPMI structure layout, then capture its returned DS and SI fields.",
                "Resolve the returned DS according to the observed execution mode and sample a bounded range at the resulting DS:SI only after descriptor/physical bounds are validated in the same run.",
            ],
            "next_action": "Prepare a single narrowly gated capture of the returned AX=0300 frame fields and same-run DS:SI mapping; no global trace, no injected response, and no environment identity inference from raw PSP:2C.",
        },
    }


if __name__ == "__main__":
    print(json.dumps(audit(), indent=2))
