from __future__ import annotations
import os as _gw_os
from pathlib import Path as _GwPath
_GW_ROOT=str(_GwPath(__file__).resolve().parents[1])

import hashlib
import json
from pathlib import Path

ROOT = Path((_GW_ROOT))
CAPTURE = ROOT / "evidence/w3_224_ah4400_ordinal6_caller.json"
TRACE = ROOT / "build/dosboxx_oracle/C/W3_224_AH4400_ORDINAL6_20261009_01.jsonl"
OUT = ROOT / "evidence/original_ah44_handle2_frontier_work3.json"
REPORT = ROOT / "reports/coordination/original_ah44_handle2_frontier_work3.md"


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def build_contract() -> dict:
    capture = json.loads(CAPTURE.read_text(encoding="utf-8"))
    ctx = capture["ordinal6_context"]
    service = ctx["service"]
    site = ctx["same_register_callsite"]
    callbacks = capture["ax4400_callbacks"]
    following = next((r for r in callbacks if r["sequence"] > service["sequence"]), None)
    snapshot = next((r for r in capture["handle_table_snapshots"]
                    if r["sequence"] < service["sequence"]), None)
    jft = next((r for r in (snapshot or {}).get("entries", [])
                if r.get("entry") == service["in_bx"]), None)
    matches = all((site.get(reg, -1) & 0xffff) == service.get(field)
                  for reg, field in (("eax", "in_ax"), ("ebx", "in_bx"),
                                     ("ecx", "in_cx"), ("edx", "in_dx")))
    result = {
        "schema": "gwrecomp.original-ah44-bx2-contract-w3-060/v1",
        "task": "W3-060",
        "evidence_level": "ORIGINAL_OBSERVED",
        "provenance": {
            "run_id": capture["run_id"],
            "captured_utc": capture["captured_utc"],
            "target_sha256": capture["preflight"]["fixture"]["GW.EXE"]["sha256"],
            "staging_revision": capture["preflight"]["runtime"]["staging_revision"],
            "staging_binary_sha256": capture["preflight"]["runtime"]["sha256"],
            "config_sha256": capture["preflight"]["config"]["sha256"],
            "cue_sha256": capture["preflight"]["cue"]["sha256"],
            "cue_read_only": capture["preflight"]["cue"]["read_only_mount"],
            "launch": capture["preflight"]["launch"]["autoexec"],
            "dos_exec_tail_observed": capture["tail_minus_k_38928_observed"],
            "fixture_target_sha256": capture["preflight"]["fixture"]["GW.EXE"]["sha256"],
            "capture_sha256": sha(CAPTURE), "trace_sha256": sha(TRACE),
        },
        "request": {
            "ordinal": service["ordinal"], "sequence": service["sequence"],
            "process_psp": service["process_psp"], "AX": service["in_ax"],
            "AL": service["in_al"], "BX": service["in_bx"],
            "CX": service["in_cx"], "DX": service["in_dx"],
            "ESI": service["in_esi"], "EDI": service["in_edi"],
            "EBP": service["in_ebp"], "EFLAGS": service["in_eflags"],
            "DOS_callback_CS": service["callback_cs"],
            "DOS_callback_EIP": service["callback_eip"],
            "main_code_rebase": service["main_code_rebase"],
            "main_callsite": {
                "sequence": site["sequence"], "link_va": site["link_va"],
                "runtime_eip": site["eip"], "CS": site["cs"], "DS": site["ds"],
                "ES": site["es"], "SS": site["ss"], "ESP": site["esp"],
                "EFLAGS": site["eflags"],
                "all_request_registers_match": matches,
            },
            "drive": service["default_drive"], "cwd": service["cwd"],
            "cwd_valid": service["cwd_valid"],
            "JFT_entry": jft,
        },
        "response": {
            "AX": service["out_ax"], "BX": service["out_bx"],
            "CX": service["out_cx"], "DX": service["out_dx"],
            "ESI": service["out_esi"], "EDI": service["out_edi"],
            "EBP": service["out_ebp"],
            "EFLAGS_register": service["out_register_eflags"],
            "iret_flags": service["iret_flags"], "CF": service["cf"],
            "ioctl_ok": service["ioctl_ok"], "dos_error": service["dos_error"],
        },
        "continuation": {
            "next_recorded_ah44": ({"sequence": following["sequence"],
                                     "ordinal": following["ordinal"],
                                     "BX": following["in_bx"], "AX": following["in_ax"],
                                     "CX": following["in_cx"], "DX": following["in_dx"]}
                                    if following else None),
            "immediate_return_checkpoint": False,
            "explanation": "The bounded trace records the next guest DOS_AH44 callsite and subsequent callback, but no dedicated checkpoint at the instruction immediately after this BX=2 INT."
        },
        "limits": [
            "This is an original GeneWars 1.1 execution under pinned DOSBox Staging, not the separate original-byte Unicorn replay.",
            "It measures BX=2 only. It must not be used as the response for BX=1 or any other handle/subfunction.",
            "The exact same-register callsite is verified, but the dynamic direct caller chain for ordinal 6 remains UNKNOWN.",
            "Separate native and original runs are not claimed equivalent; W1-043 remains unresolved.",
        ],
        "acceptance_checks": {
            "original_ax4400_bx2_observed": service["in_ax"] == 0x4400 and service["in_bx"] == 2,
            "site_mapping_verified_for_capture": site["link_va"] == 0xC8973 and
                site["eip"] == site["link_va"] + service["main_code_rebase"],
            "same_process_and_registers": site["process_psp"] == service["process_psp"] and matches,
            "dos_return_observed": service["out_ax"] == 2 and service["out_dx"] == 2 and
                service["cf"] is False,
            "next_runtime_dos_event_observed": following is not None,
        },
    }
    OUT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(
        "# W3-060 — original DOS AH=44 / BX=2 contract\n\n"
        f"Evidence: [{OUT.name}](../../{OUT.as_posix()})\n\n"
        f"W3-224's guarded original Staging run observed the sixth AH=4400 callback in "
        f"the same process as a same-register MAIN checkpoint at link VA 0xC8973 / "
        f"runtime EIP 0x{site['eip']:08X}, with code rebase 0x{service['main_code_rebase']:X}. "
        f"The request was BX=2, CX=0x{service['in_cx']:X}, DX=0x{service['in_dx']:X}; "
        f"DOS returned AX=2, DX=2, CF=clear.\n\n"
        f"The prior handle-table snapshot maps PSP JFT entry 2 to internal handle "
        f"{(jft or {}).get('internal_handle')} ({(jft or {}).get('name')}). The following "
        f"record is another AH=4400 callsite/callback (ordinal {following['ordinal'] if following else 'unknown'}); "
        "the trace lacks a dedicated instruction-after-INT checkpoint.\n\n"
        "This closes only the original BX=2 service observation. The dynamic caller for "
        "this ordinal is UNKNOWN; it does not establish BX=1 semantics or native/original "
        "seed parity. No replay was run for W3-060.\n",
        encoding="utf-8")
    return result


if __name__ == "__main__":
    print(json.dumps(build_contract(), indent=2, ensure_ascii=False))
