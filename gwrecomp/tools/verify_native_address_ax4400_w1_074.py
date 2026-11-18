"""Read-only integrity and contract checks for W1-074 native evidence."""
import hashlib
import json
import pathlib
import sys
import uuid
from datetime import datetime

ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGET_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
ADDRESS_SHA256 = "7b1c5391160e1d95393d3abe980dde978b8a79ecb2814e144ee032d9710ba6ee"


def require(condition, message):
    if not condition:
        raise SystemExit("FAIL W1-074: " + message)


def fields(line):
    return dict(token.split("=", 1) for token in line.split()[1:] if "=" in token) if line else {}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(path):
    evidence_path = pathlib.Path(path)
    if not evidence_path.is_absolute():
        evidence_path = ROOT / evidence_path
    capture = json.loads(evidence_path.read_text(encoding="utf-8"))
    require(capture.get("task") == "W1-074" and
            capture.get("schema") == "gwrecomp.native-address-ax4400-w1-074/v1", "task/schema mismatch")
    require(capture.get("fresh_replay") is True and capture.get("passed") is True and
            not capture.get("acceptance_errors"), "capture is not a fresh passing replay")
    require(capture.get("original_equivalence_claimed") is False, "capture overclaims original/native equivalence")
    try:
        uuid.UUID(capture["capture_id"])
        datetime.fromisoformat(capture["captured_at"])
    except (KeyError, ValueError, TypeError):
        require(False, "capture id/timestamp invalid")
    require(capture.get("target_sha256", "").lower() == TARGET_SHA256, "target executable fingerprint mismatch")
    require(capture.get("command_tail") == "-k 38928", "diagnostic tail differs from the recorded fixture")
    crt = capture.get("crt", {})
    require(crt.get("callback_count") == 19 and crt.get("argc") == 3, "CRT callback/argc contract mismatch")
    require(crt.get("argv", [None, None, None])[1:] == ["-k", "38928"], "argv did not reflect the diagnostic PSP tail")
    env = capture.get("authenticated_environment", {})
    require(env.get("exact_bytes_loaded") is True and env.get("size_bytes") == 86 and
            env.get("sha256") == "65c4d22c258efbf93a93cfcaa8d9d8c489e510cb2be76530646c36e0250ee895",
            "authenticated W3-140 environment mismatch")

    address = capture.get("address_txt", {})
    fixture = ROOT / address.get("fixture", "")
    require(fixture.is_file() and fixture.stat().st_size == 24 and sha(fixture) == ADDRESS_SHA256 and
            address.get("size") == 24 and address.get("sha256", "").lower() == ADDRESS_SHA256,
            "ADDRESS.TXT fixture is not the authenticated 24-byte W3-067 seed")
    require(address.get("authentic_evidence") == "evidence/w3_067_staging_functional_validation_20261008.json",
            "W3-067 fixture provenance missing")
    auth = json.loads((ROOT / address["authentic_evidence"]).read_text(encoding="utf-8"))
    require(address.get("authentic_evidence_sha256") == sha(ROOT / address["authentic_evidence"]) and
            auth["runtime"]["guest_errors"]["ADDRESS_TXT_sha256"].lower() == ADDRESS_SHA256,
            "W3-067 provenance hash does not authenticate this seed")
    provider = fields(address.get("virtual_seed_event"))
    opened = fields(address.get("open_event"))
    open_request = fields(address.get("open_request_response"))
    handle = int(open_request.get("response_eax", "-1"), 16)
    require(provider.get("provider") == "virtual-memory" and provider.get("bytes") == "24" and
            provider.get("sha256", "").lower() == ADDRESS_SHA256, "guest virtual provider was not seeded with authenticated bytes")
    require(opened.get("bytes") == "24" and opened.get("cf") == "0" and
            open_request.get("request_eax", "").lower() == "00003d01" and
            open_request.get("resolved_path", "").replace("/", "\\").casefold() == r"c:\address.txt" and
            open_request.get("handled") == "1" and int(opened.get("handle", "-2")) == handle,
            "natural AH=3D01 open does not resolve to the dynamic virtual ADDRESS.TXT handle")
    require(address.get("host_filesystem_used") is False and
            address.get("physical_host_path_observation", {}).get("guest_provider_source") is False,
            "physical host path is confused with the virtual guest provider")

    ax = capture.get("ax4400", {})
    events = [fields(line) for line in ax.get("requests", [])]
    correlated = ax.get("correlated_address_event", {})
    address_events = [event for event in events if event.get("path", "").casefold() == r"c:\address.txt" and
                      int(event.get("ebx_in", "-1"), 16) == handle]
    require(ax.get("dynamic_handle_from_ah3d_return") == handle and len(address_events) >= 1 and
            len(address_events) == len(ax.get("correlated_address_events", [])),
            "AX=4400 requests were not correlated to the active address handle")
    require(correlated in address_events, "selected correlated AX=4400 event is not in the raw request log")
    for event in address_events:
        require(event.get("eax_in", "").lower() == "00004400" and
                (int(event.get("eax_out", "-1"), 16) & 0xffff) == 2 and
                (int(event.get("edx_out", "-1"), 16) & 0xffff) == 2 and
                event.get("carry") == "0" and event.get("handled") == "1",
                f"W2-106 AX=DX=2/CF=0 contract failed at ordinal {event.get('ordinal')}")
        for register in ("ebx", "ecx", "esi", "edi", "ebp", "esp"):
            require(event.get(register + "_in") == event.get(register + "_out"),
                    f"AX=4400 changed {register.upper()} at ordinal {event.get('ordinal')}")
    require(ax.get("register_preservation") == {name: True for name in ("ebx", "ecx", "esi", "edi", "ebp", "esp")},
            "captured register-preservation summary is incomplete")
    contract_evidence = ROOT / "evidence/native_dos_ax4400_runtime_work2.json"
    require(ax.get("contract", {}).get("basis", "").startswith("W2-106") and contract_evidence.is_file(),
            "W2-106 contract reference is missing")

    frontier = capture.get("next_frontier", {})
    require(frontier.get("newly_observed_in_this_replay") is True and
            frontier.get("event") and frontier.get("cpu"), "new frontier was not captured")
    frontier_event = fields(frontier["event"])
    if frontier_event.get("eax", "").lower() == "00004400":
        require(int(frontier_event.get("ebx", "-1"), 16) != handle,
                "frontier repeats the serviced AX=4400 file-handle context")
    require(capture.get("runtime_ax4400_contract", {}).get("used_by_replay") is True,
            "capture does not prove the existing Runtime callback handled the request")
    build = capture.get("build_fingerprints", {})
    exe = ROOT / "build/entry_path_native_boot.exe"
    require(exe.is_file() and sha(exe) == capture.get("build_id") == build.get("native_executable_sha256"),
            "native executable fingerprint mismatch")
    require(build.get("harness_c_sha256") == sha(ROOT / "tests/test_native_guest_image.c") and
            build.get("driver_sha256") == sha(ROOT / "tests/test_native_guest_image.py"),
            "current harness/driver do not match the fresh replay fingerprints")
    recovery = capture.get("recovery", {})
    manifest = ROOT / recovery.get("manifest", "")
    verification = ROOT / recovery.get("verification", "")
    require(manifest.is_file() and sha(manifest) == recovery.get("manifest_sha256") and
            verification.is_file() and sha(verification) == recovery.get("verification_sha256"),
            "recovery artifact fingerprint mismatch")
    restore_doc = json.loads(verification.read_text(encoding="utf-8"))
    require(restore_doc.get("task") == "W1-074" and restore_doc.get("all_verified") is True and
            all(item.get("backup_matches") and item.get("isolated_restore_matches")
                for item in restore_doc.get("files", [])), "pre-edit backup/isolated restore verification missing")
    require(capture.get("runtime_fingerprint", {}).get("c_h_sha256"), "Runtime fingerprint is missing")
    print("PASS W1-074 fresh native ADDRESS.TXT AX=4400 metadata replay")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_native_address_ax4400_w1_074.py EVIDENCE.json")
    main(sys.argv[1])
