"""Validate the structured W2-123 callback-to-PIT evidence."""
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_w2_123_port_io_runtime.py EVIDENCE.json")
    evidence_path = (ROOT / sys.argv[1]).resolve()
    evidence_path.relative_to(ROOT.resolve())
    data = json.loads(evidence_path.read_text(encoding="utf-8"))
    assert data["task"] == "W2-123"
    assert data["execution_kind"] == "SYNTHETIC_PASS"
    assert data["compile_exit"] == 0 and data["run_exit"] == 0
    assert data["callback_abi"]["source_contract_match"] is True
    assert data["recovery"]["verified_isolated_restore"] is True
    assert data["original_evidence"]["original_port_values_measured"] is False
    assert data["original_evidence"]["native_frontier_reached"] is False
    assert all(data["synthetic_checks"].values())
    assert data["claims"]["synthetic_callback_contract_pass"] is True
    assert data["claims"]["original_pit_values_match"] is False
    assert data["claims"]["native_replay_run"] is False
    for key, rel in {
        "runtime_c_sha256": "runtime/recomp_context.c",
        "runtime_h_sha256": "runtime/recomp_context.h",
        "pit_c_sha256": "runtime/gw_pit8254.c",
        "pit_h_sha256": "runtime/gw_pit8254.h",
        "test_c_sha256": "tests/test_w2_123_port_io_runtime.c",
        "test_py_sha256": "tests/test_w2_123_port_io_runtime.py",
    }.items():
        assert data["fingerprints"][key] == sha(ROOT / rel), key
    print("PASS W2-123 evidence validator; synthetic-only claims and source hashes verified")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
