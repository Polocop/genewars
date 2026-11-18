"""Offline, hash-bound audit of the bounded LbScreenSwap sample in W3-231."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "evidence/w3_231_gwerr_dispatch_capture.json"
TRACE = ROOT / "build/dosboxx_oracle/C/W3_231_GWERR_DISPATCH_20261009_01.jsonl"
PRIOR = ROOT / "evidence/w3_151_screen_write_capture.json"
OUTPUT = ROOT / "evidence/w3_234_screen_copy_audit.json"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def extract_copy(rows: Iterable[dict[str, Any]]) -> dict[str, Any]:
    selected = {
        row.get("checkpoint"): row
        for row in rows
        if row.get("checkpoint") in {
            "W3_151_VESA_BRANCH",
            "W3_151_COPY_NONVESA_PRE",
            "W3_151_COPY_NONVESA_POST",
        }
    }
    branch = selected.get("W3_151_VESA_BRANCH")
    pre = selected.get("W3_151_COPY_NONVESA_PRE")
    post = selected.get("W3_151_COPY_NONVESA_POST")
    if not (branch and pre and post):
        return {"classification": "INCONCLUSIVE", "reason": "missing required checkpoint"}
    if not (branch["sequence"] < pre["sequence"] < post["sequence"]):
        return {"classification": "INCONCLUSIVE", "reason": "checkpoint order invalid"}

    count = int(pre.get("w3_151_copy_dword_count", 0))
    source = int(pre.get("w3_151_copy_source_start", 0))
    destination = int(pre.get("w3_151_copy_destination_start", 0))
    copied_bytes = count * 4
    valid_descriptors = bool(
        pre.get("ds_descriptor_valid") and post.get("w3_151_copy_ds_valid")
        and post.get("w3_151_copy_es_valid")
    )
    valid_bounds = bool(
        post.get("w3_151_copy_source_bounds_valid")
        and post.get("w3_151_copy_destination_bounds_valid")
    )
    sample_hex = str(post.get("w3_151_copy_sample_hex", ""))
    sample_bytes = int(post.get("w3_151_copy_sample_bytes", 0))
    register_progress = (
        int(post.get("esi", 0)) - int(pre.get("esi", 0)) == copied_bytes
        and int(post.get("edi", 0)) - int(pre.get("edi", 0)) == copied_bytes
        and int(post.get("ecx", -1)) == 0
    )
    sample_valid = (
        post.get("w3_151_copy_sample_valid") is True
        and sample_bytes == len(sample_hex) // 2
        and sample_bytes <= 16
        and len(sample_hex) % 2 == 0
    )
    complete = bool(
        branch.get("branch_taken") is False
        and branch.get("w3_151_vesa_global_valid") is True
        and branch.get("w3_151_vesa_global_u8") == 0
        and pre.get("w3_151_copy_inputs_valid") is True
        and count > 0 and valid_descriptors and valid_bounds
        and register_progress and sample_valid
    )
    return {
        "classification": "ORIGINAL_OBSERVED_COPY_COMPLETED" if complete else "INCONCLUSIVE",
        "branch": {
            "sequence": branch["sequence"],
            "link_va": f"0x{branch['link_va']:05X}",
            "taken": branch.get("branch_taken"),
            "vesa_state": branch.get("w3_151_vesa_global_u8"),
        },
        "pre": {
            "sequence": pre["sequence"],
            "link_va": f"0x{pre['link_va']:05X}",
            "esi_source": f"0x{source:08X}",
            "edi_destination": f"0x{destination:08X}",
            "ecx_dwords": count,
            "copy_bytes_from_count": copied_bytes,
            "data_rebase": f"0x{pre.get('data_rebase', 0):X}",
            "source_sample_windows": pre.get("w3_171_sample_windows", []),
        },
        "post": {
            "sequence": post["sequence"],
            "link_va": f"0x{post['link_va']:05X}",
            "esi_after": f"0x{int(post.get('esi', 0)):08X}",
            "edi_after": f"0x{int(post.get('edi', 0)):08X}",
            "ecx_after": post.get("ecx"),
            "ds_descriptor_valid": post.get("w3_151_copy_ds_valid"),
            "es_descriptor_valid": post.get("w3_151_copy_es_valid"),
            "ds_base": f"0x{int(post.get('w3_151_copy_ds_base', 0)):08X}",
            "es_base": f"0x{int(post.get('w3_151_copy_es_base', 0)):08X}",
            "ds_limit": f"0x{int(post.get('w3_151_copy_ds_limit', 0)):08X}",
            "es_limit": f"0x{int(post.get('w3_151_copy_es_limit', 0)):08X}",
            "source_bounds_valid": post.get("w3_151_copy_source_bounds_valid"),
            "destination_bounds_valid": post.get("w3_151_copy_destination_bounds_valid"),
            "sample_bytes": sample_bytes,
            "sample_hex": sample_hex,
            "sample_all_zero": bool(sample_hex) and set(sample_hex) <= {"0"},
        },
        "checks": {
            "valid_descriptors": valid_descriptors,
            "valid_bounds": valid_bounds,
            "register_progress_matches_count": register_progress,
            "sample_within_16_byte_cap": sample_valid,
        },
        "limits": [
            "The sample proves only the 16 destination bytes read at the post-copy checkpoint; all were zero.",
            "The trace does not establish VRAM/page mapping, visible pixels, first framebuffer, menu, or gameplay.",
            "Flat descriptor base/limit and bounds are emulator memory validation, not display-device mapping evidence.",
        ],
    }


def run_audit() -> dict[str, Any]:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    trace_meta = manifest["trace"]
    actual_bytes = TRACE.stat().st_size
    actual_hash = sha256(TRACE)
    if actual_bytes != trace_meta["bytes"] or actual_hash != trace_meta["sha256"]:
        raise ValueError("W3-231 trace does not match its stored manifest hash/size")
    rows = [json.loads(line) for line in TRACE.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(rows) != trace_meta["event_count"]:
        raise ValueError("W3-231 trace event count mismatch")
    prior = json.loads(PRIOR.read_text(encoding="utf-8"))
    copy = extract_copy(rows)
    return {
        "schema": "gwrecomp-w3-231-screen-copy-audit/v1",
        "task": "W3-234",
        "evidence_level": "ORIGINAL_OBSERVED",
        "classification": copy["classification"],
        "run": {
            "run_id": manifest["run_id"],
            "trace": str(TRACE.relative_to(ROOT)),
            "trace_bytes": actual_bytes,
            "trace_sha256": actual_hash,
            "trace_event_count": len(rows),
            "guest_executable_sha256": manifest["provenance"]["fixture_sha256"],
            "config_sha256": manifest["provenance"]["config_sha256"],
            "staging_revision": manifest["provenance"]["staging_revision"],
            "guard_used": manifest["scope"]["oracle_guard_used"],
            "guard_sandbox_verified": manifest["scope"]["sandbox_verified"],
        },
        "copy": copy,
        "prior_w3_151": {
            "classification": prior.get("classification"),
            "report": "reports/coordination/w3_151_screen_write_capture.md",
            "difference": "W3-151 ended before the post-copy checkpoint; the W3-231 trace has ordered pre and post checkpoints and a bounded destination sample.",
        },
        "first_framebuffer_verified": False,
        "menu_verified": False,
        "gameplay_verified": False,
    }


def main() -> int:
    result = run_audit()
    OUTPUT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"classification": result["classification"], "output": str(OUTPUT), "trace_sha256": result["run"]["trace_sha256"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
