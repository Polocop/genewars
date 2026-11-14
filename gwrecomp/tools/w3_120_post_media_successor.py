"""Hash-bound static decode of the first instruction after PlaySmacker return."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.w3_117_play_smacker_call_boundary import relative_call_target
RESULT = ROOT / "evidence/w3_118_play_smacker_call_boundary.json"
TRACE = ROOT / "build/dosboxx_oracle/C/W3_118_PLAYSMACKER_CALL_20261009_01.jsonl"
MAP = ROOT / "evidence/genewars-1_1.map"
OUT = ROOT / "evidence/w3_120_post_media_successor.json"
CONTINUATION = 0x92AE2
TARGET = 0x5B880
FALLTHROUGH = 0x92AE7
TARGET_SYMBOL = "W?ResetAllInputs$n()v"


def derive() -> dict:
    result = json.loads(RESULT.read_text(encoding="utf-8"))
    raw = TRACE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != result["trace"]["sha256"]:
        raise ValueError("raw trace hash does not match W3-118 evidence")
    rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    observed = next((r for r in rows if r.get("link_va") == CONTINUATION and
                     r.get("checkpoint") == "W3_117_PLAYSMACKER_CALL_RETURN"), None)
    if observed is None:
        raise ValueError("original continuation 0x92AE2 is not in the raw trace")
    encoded = bytes.fromhex(observed["bytes"][:10])
    target, fallthrough = relative_call_target(CONTINUATION, encoded)
    map_text = MAP.read_text(encoding="utf-8")
    if (target, fallthrough) != (TARGET, FALLTHROUGH):
        raise ValueError("post-return CALL does not resolve to the expected target")
    map_line = next((line.strip() for line in map_text.splitlines()
                     if "0001:0005B880" in line and "ResetAllInputs" in line), None)
    if map_line is None or TARGET_SYMBOL not in map_line:
        raise ValueError("map symbol does not match decoded successor")
    return {
        "schema": "w3-120-post-media-successor/v1",
        "task": "W3-120",
        "target_sha256": result["target_sha256"],
        "source_revision": result["source"]["revision"],
        "raw_trace": {"path": str(TRACE.relative_to(ROOT)),
                      "sha256": hashlib.sha256(raw).hexdigest(),
                      "bytes": len(raw)},
        "dynamic_observation": {
            "link_va": observed["link_va"], "runtime_eip": observed["eip"],
            "cs": observed["cs"], "elapsed_ms": observed["elapsed_ms"],
            "instruction_bytes": observed["bytes"][:10],
            "statement": "original execution reached the caller continuation after play_smk_"
        },
        "static_decode": {
            "opcode": "CALL rel32", "fallthrough_link_va": fallthrough,
            "relative_target_link_va": target, "map_line": map_line,
            "statement": "the instruction at the observed continuation encodes a call to ResetAllInputs"
        },
        "limitations": [
            "ResetAllInputs entry was not dynamically observed in W3-118.",
            "The continuation's following CALL execution and return are static decoding only.",
            "No framebuffer, menu, or whole-run parity is claimed."
        ]
    }


def main() -> int:
    data = derive()
    OUT.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(OUT), "static_target": hex(TARGET),
                      "fallthrough": hex(FALLTHROUGH)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
