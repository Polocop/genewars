#!/usr/bin/env python3
"""Validate the W1-088 rebuilt native entry replay without executing it."""
from __future__ import annotations

import hashlib
import json
import pathlib
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGET_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"


def fail(message: str) -> None:
    raise SystemExit(f"FAIL W1-088 native evidence: {message}")


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    if len(sys.argv) != 2:
        fail("usage: verify_w1_088_native_replay.py EVIDENCE.json")
    evidence_path = (ROOT / sys.argv[1]).resolve()
    try:
        evidence_path.relative_to(ROOT)
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read evidence: {exc}")

    if evidence.get("target_sha256") != TARGET_SHA256:
        fail("target hash is not the canonical 1.1 executable")
    if evidence.get("native_returncode") != 0 or evidence.get("fresh_replay") is not True:
        fail("native harness did not complete a fresh replay")
    if evidence.get("original_equivalence_claimed") is not False:
        fail("evidence must keep original equivalence unclaimed")

    frontier = evidence.get("frontier", {})
    request = frontier.get("request_registers", {})
    if (frontier.get("newly_observed") is not True
            or int(request.get("vector", "-1"), 16) != 0x31
            or request.get("eax", "").lower() != "00000200"
            or request.get("eip", "").lower() != "000c8cd2"):
        fail("fresh frontier is not the observed INT 31h AX=0200 at 0xC8CD2")

    fingerprints = evidence.get("build_fingerprints", {})
    compile_path = pathlib.Path(fingerprints.get("closure_compile_evidence", ""))
    if not compile_path.is_absolute():
        compile_path = ROOT / compile_path
    try:
        compile_path.resolve().relative_to(ROOT)
        compile_evidence = json.loads(compile_path.read_text(encoding="utf-8"))
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read task-scoped compile evidence: {exc}")

    closure_path = ROOT / "build" / "entry_path_closure.c"
    if (compile_evidence.get("passed") is not True
            or compile_evidence.get("compile_exit") != 0
            or compile_evidence.get("target_sha256") != TARGET_SHA256
            or compile_evidence.get("source_sha256") != fingerprints.get("closure_source_sha256")
            or compile_evidence.get("object_sha256") != fingerprints.get("routed_closure_object_sha256")
            or sha256(closure_path) != fingerprints.get("closure_source_sha256")):
        fail("compile receipt, closure, and replay fingerprints do not agree")
    if compile_evidence.get("runtime_header_added_for_port_io") is not True:
        fail("generated port I/O Runtime declarations were not linked into the build")
    if closure_path.read_text(encoding="utf-8", errors="replace").count("gw_recomp_port_io(") < 1:
        fail("rebuilt closure does not dispatch generated port I/O callbacks")
    pit_path = ROOT / "runtime" / "gw_pit8254.c"
    if sha256(pit_path) != fingerprints.get("pit_runtime_source_sha256"):
        fail("PIT Runtime source fingerprint differs from the replay")

    print("PASS W1-088 native evidence: rebuilt callbacks compile; fresh replay reaches INT 31h AX=0200 at 0xC8CD2")
    print("No native PIT reach, original-run equivalence, or framebuffer is claimed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
