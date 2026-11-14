"""Validate W1-087's focused generated port-I/O contract evidence."""
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(path):
    evidence_path = Path(path)
    if not evidence_path.is_absolute():
        evidence_path = ROOT / evidence_path
    data = json.loads(evidence_path.read_text(encoding="utf-8"))
    assert data["task"] == "W1-087"
    assert data["result"] == "PASS"
    assert data["regression"]["passed"] == data["regression"]["total"] == 6
    assert set(data["regression"]["cases"]) == {
        "in_al_immediate", "in_eax_dx", "out_immediate_al", "out_dx_eax",
        "outsb_fail_closed", "instruction_tick",
    }
    assert data["runtime_contract"]["guest_instruction_tick"] == "gw_recomp_guest_instruction(guest_va)"
    assert data["runtime_contract"]["port_dispatch"] == "gw_recomp_port_io(operation, port, width, value, guest_va, value_out)"
    assert data["runtime_contract"]["unsupported_returns_false_after_latching_guest_trap"] is True
    assert data["original_claims"]["pit_values_measured"] is False
    assert data["original_claims"]["native_c427e_reached"] is False
    generator = ROOT / "third_party/pcrecomp/tools/lift/lift32.py"
    test_file = ROOT / "tests/test_w1_087_port_io_lift.py"
    assert sha256(generator) == data["fingerprints"]["lift32.py"]
    assert sha256(test_file) == data["fingerprints"]["test_w1_087_port_io_lift.py"]
    manifest = json.loads((ROOT / "work/recovery/W1-087/recovery_manifest.json").read_text(encoding="utf-8"))
    assert manifest["restore_verified"] is True
    assert manifest["sha256"] == manifest["backup_sha256"] == manifest["isolated_restore_sha256"]
    print("W1-087 port-I/O codegen evidence: PASS")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_w1_087_port_io_codegen.py evidence.json")
    main(sys.argv[1])
