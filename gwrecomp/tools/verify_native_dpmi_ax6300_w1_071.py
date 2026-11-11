"""Validate the fresh provider-backed native AX=6300 checkpoint."""
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(path):
    evidence_path = (ROOT / path).resolve()
    if not evidence_path.is_relative_to(ROOT.resolve()):
        raise SystemExit("evidence path escapes project")
    capture = json.loads(evidence_path.read_text(encoding="utf-8"))
    event = capture["ax6300"]["event"]
    fields = dict(token.split("=", 1) for token in event.split()[1:] if "=" in token)
    env = json.loads((ROOT / "evidence/w3_140_original_setenvp_environment.json").read_text(encoding="utf-8"))
    sample = bytes.fromhex(env["capture"]["environment"]["sample_hex"])
    runtime = capture["runtime_fingerprint"]
    recovery = json.loads((ROOT / "evidence/w1_071_recovery_manifest.json").read_text(encoding="utf-8"))
    sys.path.insert(0, str(ROOT / "tools"))
    import frontier_snapshot
    expected_runtime = {
        "c_h_sha256": frontier_snapshot.runtime_hash(ROOT),
        "python_sha256": frontier_snapshot.manifest_hash(list((ROOT / "runtime").glob("*.py")), ROOT),
    }
    checks = {
        "task_and_schema": capture.get("task") == "W1-071" and capture.get("schema") == "gwrecomp.native-dpmi-ax6300-provider/v1",
        "fresh_capture": bool(capture.get("capture_id")) and bool(capture.get("captured_at")),
        "source_recovery_verified": capture["recovery"]["all_source_backup_and_isolated_restore_hashes_verified"] is True and
            capture["recovery"]["manifest_sha256"] == sha256(ROOT / "evidence/w1_071_recovery_manifest.json") and
            all(item.get("verified") is True and item.get("sha256") == item.get("backup_sha256") ==
                item.get("isolated_restore_sha256") for item in recovery.get("files", [])) and len(recovery.get("files", [])) == 2,
        "authentic_environment": capture["authenticated_environment"]["exact_bytes_loaded"] is True and
            capture["authenticated_environment"]["sha256"] == hashlib.sha256(sample).hexdigest() and len(sample) == 86,
        "native_execution": capture.get("execution_mode") == "native_recompiled_guest" and capture.get("evidence_level") == "NATIVE_REACHED",
        "crt_state": capture["crt"]["callback_count"] == 19 and capture["crt"]["argc"] == 3,
        "bridge_request": fields.get("eip") == "000bc765" and fields.get("vector") == "31" and
            fields.get("inner_eax") == "00006300" and fields.get("ordinal") == "1",
        "measured_return": fields.get("result") == "1" and fields.get("inner_cf") == "0" and
            fields.get("inner_si") == "0000" and fields.get("table_size") == "12" and fields.get("table_zero") == "1",
        "dynamic_guest_pointer": int(fields.get("alloc_segment", "0"), 16) > 0 and
            int(fields.get("alloc_selector", "0"), 16) > 0 and
            int(fields.get("table_linear", "0"), 16) == int(fields.get("inner_ds", "0"), 16) * 16 + int(fields.get("inner_si", "0"), 16),
        "single_dynamic_allocation": fields.get("alloc_calls") == "1",
        "unsupported_request_regression": all(token in capture["ax6300"]["unsupported_input_regression"]
            for token in ("unsupported_vector=trapped", "unsupported_ax=trapped", "no_allocation=1")),
        "fresh_frontier": capture["next_frontier"]["newly_observed_in_this_replay"] is True and
            bool(capture["next_frontier"]["trap"].get("eip")) and
            capture["next_frontier"]["trap"].get("eip", "").lower() not in ("000bc765", "0x000bc765"),
        "runtime_fingerprint_current": runtime == expected_runtime,
        "build_fingerprint_current": capture["build_id"] == capture["build_fingerprints"]["native_executable_sha256"] and
            capture["build_fingerprints"]["harness_c_sha256"] == sha256(ROOT / "tests/test_native_guest_image.c") and
            capture["build_fingerprints"]["driver_sha256"] == sha256(ROOT / "tests/test_native_guest_image.py"),
        "no_original_equivalence_claim": capture.get("original_equivalence_claimed") is False and
            capture["ax6300"]["original_equivalence_claimed"] is False,
    }
    failed = [name for name, passed in checks.items() if not passed]
    print(json.dumps({"validator": "W1-071", "checks": checks, "event_fields": fields,
                      "next_frontier": capture.get("next_frontier")}, indent=2))
    if failed:
        raise SystemExit("FAIL W1-071: " + ", ".join(failed))
    print("PASS W1-071 native DPMI AX=0300 / INT 21h AX=6300 provider replay")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_native_dpmi_ax6300_w1_071.py EVIDENCE.json")
    main(sys.argv[1])
