"""Hash-bound static and trace audit of GeneWars' direct Smacker screen path."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "evidence/genewars-1_1.exe"
DISASM = ROOT / "evidence/genewars-1_1-le_disasm.s"
TRACE = ROOT / "build/dosboxx_oracle/C/W3_168_WSCREEN_GATE_CAPTURE_20261009_01.jsonl"
CAPTURE = ROOT / "evidence/w3_168_wscreen_gate_capture.json"
SAMPLES = ROOT / "evidence/w3_154_source_destination_samples.json"
TARGET_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _rows(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _section(text: str, start: str, end: str) -> str:
    a = text.index(start)
    b = text.index(end, a + len(start))
    return text[a:b]


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text)


def audit() -> dict[str, Any]:
    target_sha = _sha(TARGET)
    if target_sha != TARGET_SHA256:
        raise ValueError("exact target hash mismatch")
    capture = json.loads(CAPTURE.read_text(encoding="utf-8"))
    if capture["source"]["target_sha256"] != target_sha:
        raise ValueError("W3-168 capture target provenance mismatch")
    disasm_raw = DISASM.read_bytes()
    disasm = disasm_raw.decode("utf-8")
    direct = _normalize(_section(disasm, "play_smk_direct:\t/* 0xae308 */", "RADMALLOC:\t/* 0xae63c */"))
    loader = _normalize(_section(disasm, "SMACKTOBUFFER:\t/* 0xc5140 */", "SMACKDOFRAME:\t/* 0xc5bd0 */"))
    doframe = _normalize(_section(disasm, "SMACKDOFRAME:\t/* 0xc5bd0 */", "func_c5cb0:"))
    swap = _normalize(_section(disasm, "LbScreenSwap_:\t/* 0x9ffe0 */", "LbScreenSwapBoxClear_:\t/* 0xa0090 */"))

    direct_facts = {
        "passes_wscreen_global_to_smacktobuffer": "mov lbDisplay__WScreen,%eax push %eax" in direct and "call SMACKTOBUFFER" in direct,
        "calls_smackdoframe": "call SMACKDOFRAME" in direct,
        "calls_screen_swap": "call LbScreenSwap_" in direct,
        "screen_swap_reads_wscreen": "mov lbDisplay__WScreen,%esi" in swap,
        "screen_swap_rep_movs": "rep movsl %ds:(%esi),%es:(%edi)" in swap,
        "smacktobuffer_allocates_internal_buffer": "call RADMALLOC" in loader and "mov %eax,0x3a0(%esi)" in loader,
        "smacktobuffer_zeroes_internal_buffer": "rep stos %eax,%es:(%edi)" in loader,
        "doframe_uses_internal_buffer_and_unsmack": "mov 0x3a0(%esi),%ebp" in doframe and "call _Unsmack" in doframe,
    }
    if not all(direct_facts.values()):
        raise ValueError("one or more exact-target dataflow anchors were not found")

    trace_raw = TRACE.read_bytes()
    trace_sha = hashlib.sha256(trace_raw).hexdigest()
    if len(trace_raw) != capture["trace"]["bytes"] or trace_sha != capture["trace"]["sha256"]:
        raise ValueError("W3-168 raw trace does not match capture manifest")
    trace_rows = [json.loads(line) for line in trace_raw.decode("utf-8").splitlines() if line.strip()]
    names = ["W3_133_PLAY_SMK_DIRECT_ENTRY", "W3_142_SMACKTOBUFFER_ENTRY",
             "W3_142_SMACKDOFRAME_ENTRY", "W3_148_SMACKDOFRAME_RETURN",
             "W3_142_LBSCREENSWAP_ENTRY", "W3_151_COPY_NONVESA_PRE",
             "W3_151_COPY_NONVESA_POST"]
    events = {name: next((r for r in trace_rows if r.get("checkpoint") == name), None) for name in names}
    if any(value is None for value in events.values()):
        raise ValueError("missing dynamic direct-Smacker event in W3-168 trace")
    seqs = [int(events[name]["sequence"]) for name in names]
    if seqs != sorted(seqs) or len(set(seqs)) != len(seqs):
        raise ValueError("direct-Smacker events are not uniquely ordered in one trace")
    psps = {int(events[name]["process_psp"]) for name in names}
    if psps != {int(capture["main_checkpoint"]["process_psp"])}:
        raise ValueError("direct-Smacker events do not share MAIN PSP")
    code_rebase = int(capture["mapping"]["code_rebase"])
    for row in events.values():
        if int(row["eip"]) - code_rebase != int(row["link_va"]):
            raise ValueError("direct-Smacker link/runtime mapping mismatch")
    if int(events["W3_142_SMACKTOBUFFER_ENTRY"]["eax"]) != int(events["W3_151_COPY_NONVESA_PRE"]["esi"]):
        raise ValueError("SMACKTOBUFFER argument does not match observed screen-copy source")
    copy = events["W3_151_COPY_NONVESA_PRE"]
    copy_post = events["W3_151_COPY_NONVESA_POST"]
    completed = (int(copy_post["ecx"]) == 0
                 and int(copy_post["esi"]) - int(copy["esi"]) == int(copy["ecx"]) * 4
                 and int(copy_post["edi"]) - int(copy["edi"]) == int(copy["ecx"]) * 4)
    if not completed:
        raise ValueError("same-run REP completion arithmetic failed")

    sample_evidence = json.loads(SAMPLES.read_text(encoding="utf-8"))
    observed = sample_evidence["observed_copy"]
    if (sample_evidence["source"]["target_sha256"] != target_sha
            or observed["source_start"] != int(copy["esi"])
            or observed["destination_start"] != int(copy["edi"])
            or observed["dword_count"] != int(copy["ecx"])):
        raise ValueError("separate W3-154 copy evidence does not align on target/copy addresses")
    windows = sample_evidence["source_destination_samples"]["windows"]

    return {
        "schema": "w3-170-screen-buffer-producer-audit/v1",
        "task": "W3-170",
        "classification": "ORIGINAL_OBSERVED_WITH_STATIC_DATAFLOW",
        "replay_performed": False,
        "target": {"path": "evidence/genewars-1_1.exe", "sha256": target_sha, "bytes": TARGET.stat().st_size},
        "static_reference": {"path": "evidence/genewars-1_1-le_disasm.s",
                             "sha256": hashlib.sha256(disasm_raw).hexdigest(),
                             "anchors": direct_facts,
                             "interpretation": "Direct route passes the WScreen global to SMACKTOBUFFER, calls SMACKDOFRAME, then LbScreenSwap_. SMACKTOBUFFER contains a code path that allocates/zeroes an internal Smacker buffer; SMACKDOFRAME references that object buffer and calls _Unsmack. These static excerpts do not prove which sampled WScreen bytes those functions write at runtime."},
        "w3_168_same_run": {"run_id": capture["run_id"], "trace_sha256": trace_sha,
                            "code_rebase": hex(code_rebase), "psp": next(iter(psps)),
                            "events": [{"sequence": int(events[name]["sequence"]), "checkpoint": name,
                                        "link_va": hex(int(events[name]["link_va"])),
                                        "eax": hex(int(events[name]["eax"])),
                                        "esi": hex(int(events[name]["esi"])),
                                        "edi": hex(int(events[name]["edi"])),
                                        "ecx": hex(int(events[name]["ecx"]))} for name in names],
                            "screen_buffer_pointer": hex(int(events["W3_142_SMACKTOBUFFER_ENTRY"]["eax"])),
                            "copy_completed_bytes": int(copy["ecx"]) * 4,
                            "copy_destination": hex(int(copy["edi"]))},
        "w3_154_separate_run": {"run_id": sample_evidence["run_id"],
                                "trace_sha256": sample_evidence["trace"]["sha256"],
                                "same_target_config_cue_revision": all([
                                    sample_evidence["source"]["target_sha256"] == target_sha,
                                    sample_evidence["source"]["config_sha256"] == capture["source"]["config_sha256"],
                                    sample_evidence["source"]["cue_sha256"] == capture["source"]["cue_sha256"],
                                    sample_evidence["source"]["staging_revision"] == capture["source"]["staging_revision"]]),
                                "sample_windows": windows,
                                "all_sampled_source_and_destination_bytes_zero": all(
                                    bytes.fromhex(w["source_hex"]) == bytes.fromhex(w["destination_hex"]) == bytes(len(bytes.fromhex(w["source_hex"])))
                                    for w in windows),
                                "all_pairs_equal": sample_evidence["source_destination_samples"]["all_pairs_equal"]},
        "conclusion": {"first_copy_source_is_wscreen": True,
                       "first_copy_source_dynamic_address": hex(int(copy["esi"])),
                       "same_run_smacktobuffer_wscreen_argument_and_copy_source_match": True,
                       "smackdoframe_written_sampled_wscreen_bytes": "NOT MEASURED",
                       "exact_writer_for_nonzero_wscreen_bytes": "UNKNOWN",
                       "minimal_next_observation": "In one bounded original replay, sample only the verified WScreen pointer's offsets 0, 32000, and 63984 immediately at the natural SMACKDOFRAME return 0xAE466 and at first-copy pre 0xA0013; preserve the same run/rebase/PSP and cap samples at 96 bytes. This distinguishes whether those samples change across the frame routine, but does not claim full-buffer contents.",
                       "do_not_repeat_copy_capture": True},
        "limits": ["W3-168 and W3-154 are different original runs; only their matching fixture identity and compatible copy contract are correlated.",
                  "SMACKTOBUFFER receives the WScreen address dynamically; this alone does not prove the exact writer to WScreen.",
                  "W3-154 sampled only three 16-byte offsets and found zeros; it did not prove the entire source buffer was zero.",
                  "No host VGA aperture mapping, visible presentation, menu, or gameplay is established by this static/evidence audit."],
    }


def write_result(output: Path) -> dict[str, Any]:
    result = audit()
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    out = ROOT / "evidence/w3_170_screen_buffer_producer_audit.json"
    result = write_result(out)
    print(json.dumps({"output": str(out), "copy_source_is_wscreen": result["conclusion"]["first_copy_source_is_wscreen"],
                      "next_observation": result["conclusion"]["minimal_next_observation"]}, indent=2))
