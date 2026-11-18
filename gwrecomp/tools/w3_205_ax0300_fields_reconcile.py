"""Read-only correction of W3-204: decode measured inner AX=0300 fields."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
W3_184 = ROOT / "evidence/w3_184_original_ax0300_window.json"
W2_115 = ROOT / "evidence/w2_115_dpmi0300_bridge.json"
W2_HEADER = ROOT / "runtime/gw_dos_services.h"


def audit() -> dict:
    ev = json.loads(W3_184.read_text(encoding="utf-8"))
    w2 = json.loads(W2_115.read_text(encoding="utf-8"))
    header = W2_HEADER.read_text(encoding="utf-8")
    ret = ev["return"]
    raw = bytes.fromhex(ret["w3_182_frame_hex"])
    # The locally implemented packed AX=0300 structure is eight dwords,
    # FLAGS, then ES, DS, FS, GS, IP, CS, SP, SS (50 bytes total).
    if "uint32_t edi, esi, ebp, reserved, ebx, edx, ecx, eax;" not in header:
        raise ValueError("packed DPMI frame GPR layout is absent from W2 header")
    if "uint16_t flags, es, ds, fs, gs, ip, cs, sp, ss;" not in header:
        raise ValueError("packed DPMI frame segment layout is absent from W2 header")
    if len(raw) != 48:
        raise ValueError(f"expected the original bounded 48-byte sample, got {len(raw)}")
    si = int.from_bytes(raw[4:6], "little")
    ds = int.from_bytes(raw[36:38], "little")
    if ds != 0xC808 or si != 0:
        raise ValueError(f"original returned DS:SI bytes no longer match reported pair: {ds:04x}:{si:04x}")
    trace = ROOT / ev["trace"]["path"]
    trace_bytes = trace.read_bytes()
    trace_sha = hashlib.sha256(trace_bytes).hexdigest()
    if trace_sha != ev["trace"]["sha256"]:
        raise ValueError("W3-184 trace hash does not match evidence")
    return {
        "schema": "w3-205-ax0300-field-reconciliation/v1",
        "task": "W3-205",
        "classification": "ORIGINAL_FIELDS_DECODED_MEMORY_CONTENTS_UNOBSERVED",
        "evidence_hashes": {
            "w3_184": hashlib.sha256(W3_184.read_bytes()).hexdigest(),
            "w2_115": hashlib.sha256(W2_115.read_bytes()).hexdigest(),
            "w2_115_header": hashlib.sha256(W2_HEADER.read_bytes()).hexdigest(),
            "w3_184_trace": trace_sha,
        },
        "frame_layout_source": "runtime/gw_dos_services.h gw_dos_real_mode_registers; packed structure is 50 bytes, with ESI at offset 4 and DS word at offset 36.",
        "original_return": {
            "sequence": ret["sequence"],
            "checkpoint": ret["checkpoint"],
            "inner_eax": "0x6300",
            "inner_si": hex(si),
            "inner_ds": hex(ds),
            "inner_ds_si": f"{ds:04X}:{si:04X}",
            "sampled_frame_bytes": len(raw),
            "full_frame_bytes": 50,
            "outer_frame_storage": {
                "selector_es": hex(ret["es"]),
                "edi": hex(ret["edi"]),
                "descriptor_base": hex(ret["w3_182_frame_descriptor_base"]),
                "linear": hex(ret["w3_182_frame_linear"]),
            },
        },
        "mapping_and_payload": {
            "inner_ds_is_outer_protected_selector": False,
            "inner_ds_descriptor_lookup_performed": False,
            "segment_linear_candidate_if_real_mode_segmentation_applies": hex((ds << 4) + si),
            "candidate_is_inference_not_observed_mapping": True,
            "bytes_at_inner_ds_si_sampled_in_w3_184": False,
            "environment_identity": "UNKNOWN",
        },
        "correction_to_w3_204": {
            "already_measured": "The numeric inner DS:SI fields decode from the recorded return frame as C808:0000; they do not need to be recaptured.",
            "still_missing": "A same-run mapping of that inner returned address under its real-mode semantics and any bounded bytes read from it. Do not treat inner DS=C808 as the outer protected-mode DS selector.",
        },
        "source_report_note": w2.get("evidence", {}).get("original_capture", "W2-115 report cross-references the W3-184 original frame; see reports/coordination/w2_115_dpmi0300_bridge.md"),
        "next_action": "Use the existing W3-184 AX=0300 return event; if table bytes are necessary, add one bounded sample at the verified real-mode DS:SI address (candidate linear C8080) only after confirming the DPMI segment-address rule and guest-memory bounds. No unchanged replay is needed just to decode DS:SI.",
    }


if __name__ == "__main__":
    print(json.dumps(audit(), indent=2))
