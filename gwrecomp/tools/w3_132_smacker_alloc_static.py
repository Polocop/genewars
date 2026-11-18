"""Hash-bound static analysis for W3-131's 0x4AC allocator restart."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
TARGET_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def analyze_text(disassembly: str, map_text: str, target_sha256: str,
                 trace_rows: list[dict[str, Any]]) -> dict[str, Any]:
    if target_sha256 != TARGET_SHA256:
        raise ValueError("unexpected GeneWars target hash")
    wrapper_start = disassembly.find("play_smk_:")
    direct_start = disassembly.find("play_smk_direct:")
    via_start = disassembly.find("play_smk_via_buffer:")
    rad_start = disassembly.find("RADMALLOC:", via_start)
    radfree_start = disassembly.find("RADFREE:", rad_start)
    smack_start = disassembly.find("SMACKOPEN:")
    next_smack = disassembly.find("unknown_libname_11:", smack_start)
    if min(wrapper_start, direct_start, via_start, rad_start, radfree_start, smack_start, next_smack) < 0:
        raise ValueError("required exact-target function boundary missing")
    wrapper = disassembly[wrapper_start:direct_start]
    direct = disassembly[direct_start:via_start]
    via = disassembly[via_start:rad_start]
    rad = disassembly[rad_start:radfree_start]
    smack = disassembly[smack_start:next_smack]
    alloc_events = [row for row in trace_rows
                    if row.get("event") == "w3_127_target_instruction_restart"
                    and row.get("link_va") == 0x91E00 and row.get("eax") == 0x4AC]
    add_calls = [row for row in trace_rows if row.get("event") == "target_runtime_checkpoint"
                 and row.get("link_va") == 0x92ADD]
    data_start = disassembly.find("_smack_malloc:")
    data_end = disassembly.find("_smack_free:", data_start)
    if data_start < 0 or data_end < 0:
        raise ValueError("_smack_malloc data initializer missing")
    data_init = disassembly[data_start:data_end]
    static = {
        "map_play_smk_via_buffer": "0001:000AE4D8" in map_text,
        "map_play_smk_direct": "0001:000AE308" in map_text,
        "map_radm_malloc": "0001:000AE63C" in map_text,
        "map_smackopen": "0001:000C62F0" in map_text,
        "wrapper_selects_direct_or_buffer": "call   play_smk_via_buffer" in wrapper and "call   play_smk_direct" in wrapper,
        "direct_path_calls_smackopen": "call   SMACKOPEN" in direct,
        "via_buffer_calls_smackopen": "call   SMACKOPEN" in via,
        "via_buffer_direct_allocator_call": "call   LbMemoryAlloc_" in via,
        "smackopen_passes_0x4ac": "push   $0x4ac" in smack,
        "smackopen_calls_radm_malloc": "call   RADMALLOC" in smack,
        "radm_malloc_indirect_call": "call   *_smack_malloc" in rad,
        "smack_malloc_initialized_to_lbmemoryalloc": ".long   LbMemoryAlloc_" in data_init,
    }
    if not all(static.values()):
        raise ValueError(f"static chain did not validate: {static}")
    return {
        "classification": "STATIC_PATH_MATCH_DYNAMIC_CALLER_UNPROVEN" if alloc_events and add_calls
                         else "STATIC_PATH_ONLY",
        "dynamic": {
            "play_smk_callsite_92add_seen_before_alloc": bool(add_calls and alloc_events and
                min(row.get("sequence", 0) for row in add_calls) <
                min(row.get("sequence", 0) for row in alloc_events)),
            "lbmemoryalloc_91e00_eax_4ac_events": alloc_events,
            "caller_link_va": None,
            "return_link_va": None,
            "runtime_smack_malloc_pointer_value": None,
            "caller_identity_proven": False,
        },
        "static": static,
        "static_chain": [
            {"function": "play_smk_", "link_entry": "0x000AE2D0",
             "observation": "selects direct or via-buffer playback using _smack_draw_callback and BL flags; those runtime branch inputs were not captured for this allocator event"},
            {"functions": ["play_smk_direct", "play_smk_via_buffer"],
             "link_entries": ["0x000AE308", "0x000AE4D8"],
             "observation": "both static paths call SMACKOPEN; via-buffer also has a later separate LbMemoryAlloc_ request computed from returned structure fields"},
            {"function": "SMACKOPEN", "link_entry": "0x000C62F0",
             "observation": "pushes constant 0x4AC and calls RADMALLOC"},
            {"function": "RADMALLOC", "link_entry": "0x000AE63C",
             "observation": "calls through _smack_malloc when request is neither zero nor 0xFFFFFFFF"},
            {"data": "_smack_malloc", "link_data_va": "0x0010B4DC",
             "observation": "static initializer is .long LbMemoryAlloc_"},
            {"function": "LbMemoryAlloc_", "link_entry": "0x00091E00",
             "observation": "the W3-131 trace separately observed EAX=0x4AC at this entry; dynamic call chain is not captured"},
        ],
        "next_capture": {
            "targets": ["SMACKOPEN 0xC62F0", "RADMALLOC 0xAE63C", "LbMemoryAlloc_ 0x91E00"],
            "purpose": "measure the same-invocation call/return stack and runtime _smack_malloc pointer value",
            "do_not_infer": "static initializer alone does not prove the callback was unchanged or invoked on the observed event",
        },
    }


def build_evidence() -> dict[str, Any]:
    disasm_path = ROOT / "evidence/genewars-1_1-le_disasm.s"
    map_path = ROOT / "evidence/genewars-1_1.map"
    prior_path = ROOT / "evidence/w3_131_game_entry_capture.json"
    prior = json.loads(prior_path.read_text(encoding="utf-8"))
    trace_path = ROOT / prior["trace"]["path"]
    trace_bytes = trace_path.read_bytes()
    trace_hash = hashlib.sha256(trace_bytes).hexdigest()
    if trace_hash != prior["trace"]["sha256"]:
        raise ValueError("W3-131 raw trace hash mismatch")
    rows = [json.loads(line) for line in trace_bytes.splitlines() if line.strip()]
    result = analyze_text(disasm_path.read_text(encoding="utf-8", errors="replace"),
                          map_path.read_text(encoding="utf-8", errors="replace"),
                          prior["target_sha256"], rows)
    return {
        "schema": "w3-132-smacker-allocation-static/v1",
        "task": "W3-132",
        "target_sha256": prior["target_sha256"],
        "inputs": {
            "w3_131_evidence_sha256": sha256(prior_path),
            "w3_131_trace_path": str(trace_path.relative_to(ROOT)),
            "w3_131_trace_sha256": trace_hash,
            "disassembly_sha256": sha256(disasm_path),
            "map_sha256": sha256(map_path),
        },
        **result,
        "limitations": [
            "The W3-131 0x91E00 event is a restart record without stack or return address.",
            "Temporal adjacency to the 0x92ADD callsite does not prove the same dynamic call chain.",
            "The static data initializer does not prove _smack_malloc retained that value at runtime.",
            "No framebuffer, page mapping, visible frame, or menu is established by this analysis.",
        ],
    }


if __name__ == "__main__":
    output = ROOT / "evidence/w3_132_smacker_alloc_static.json"
    if output.exists():
        raise SystemExit(f"refusing to overwrite {output}")
    result = build_evidence()
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output), "classification": result["classification"],
                      "static_chain_valid": all(result["static"].values())}, indent=2))
