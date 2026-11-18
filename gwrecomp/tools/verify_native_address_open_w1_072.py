"""Read-only validation for a fresh W1-072 native ADDRESS.TXT replay."""
import hashlib
import json
import pathlib
import sys
from datetime import datetime
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
EXPECTED_TARGET = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
EXPECTED_ADDRESS = "7b1c5391160e1d95393d3abe980dde978b8a79ecb2814e144ee032d9710ba6ee"


def require(condition, message):
    if not condition:
        raise SystemExit("FAIL W1-072: " + message)


def fields(line):
    if not line:
        return {}
    return dict(token.split("=", 1) for token in line.split()[1:] if "=" in token)


def main(path):
    evidence_path = pathlib.Path(path)
    if not evidence_path.is_absolute():
        evidence_path = ROOT / evidence_path
    capture = json.loads(evidence_path.read_text(encoding="utf-8"))
    require(capture.get("task") == "W1-072" and
            capture.get("schema") == "gwrecomp.native-address-open-w1-072/v1", "task/schema mismatch")
    require(capture.get("fresh_replay") is True and capture.get("passed") is True,
            "capture is not a passing fresh native replay")
    try:
        uuid.UUID(capture["capture_id"])
        datetime.fromisoformat(capture["captured_at"])
    except (KeyError, ValueError, TypeError):
        require(False, "capture identifier or timestamp is invalid")
    require(capture.get("original_equivalence_claimed") is False, "capture overclaims original/native equivalence")
    require(capture.get("target_sha256", "").lower() == EXPECTED_TARGET, "native target fingerprint mismatch")
    require(capture.get("crt", {}).get("callback_count") == 19 and capture["crt"].get("argc") == 3,
            "CRT callback/argc contract mismatch")
    gate = capture.get("game_gate", {})
    require(isinstance(gate.get("main_gate_observed"), bool) and
            isinstance(gate.get("setup_game_entry_observed"), bool) and
            isinstance(gate.get("observed_setup_events"), list),
            "setup/gate observations are not recorded explicitly")
    if gate.get("setup_game_entry_observed"):
        require(gate.get("setup_callsite", {}).get("eip", "").lower() == "0009433d" and
                gate.get("callee_14bf0", {}).get("eip", "").lower() == "00014bf0",
                "observed setup_game entry lacks the measured callsite/callee")
    api = capture.get("runtime_api", {})
    require(api.get("configure") == "gw_dos_dbcs_table_configure" and
            api.get("callback") == "gw_dos_services_real_mode_interrupt" and
            api.get("used_by_replay") is True, "W2-116 Runtime provider API was not used")
    ax = capture.get("ax6300", {})
    ax_event = fields(ax.get("event"))
    require(ax_event.get("result") == "1" and ax_event.get("ordinal") == "1" and
            ax_event.get("inner_eax") == "00006300" and ax_event.get("inner_cf") == "0" and
            ax_event.get("table_size") == "12" and ax_event.get("table_zero") == "1",
            "natural AX=6300 guest-table result mismatch")
    returned_linear = int(ax_event.get("inner_ds", "0"), 16) * 16 + int(ax_event.get("inner_si", "0"), 16)
    require(returned_linear != 0 and returned_linear == int(ax_event.get("table_linear", "0"), 16),
            "AX=6300 DS:SI does not resolve to the allocated dynamic table")
    address = capture.get("address_txt", {})
    fixture = ROOT / address.get("fixture", "")
    require(fixture.is_file() and fixture.stat().st_size == 24 and
            hashlib.sha256(fixture.read_bytes()).hexdigest() == EXPECTED_ADDRESS and
            address.get("size") == 24 and address.get("sha256", "").lower() == EXPECTED_ADDRESS,
            "native ADDRESS.TXT seed does not match the authenticated 24-byte fixture")
    require(address.get("authentic_evidence") == "evidence/w3_067_staging_functional_validation_20261008.json",
            "W3-067 seed provenance missing")
    provider = fields(address.get("virtual_seed_event"))
    opened = fields(address.get("open_event"))
    request = fields(address.get("request_response"))
    require(provider.get("provider") == "virtual-memory" and provider.get("bytes") == "24" and
            provider.get("sha256", "").lower() == EXPECTED_ADDRESS,
            "virtual provider was not seeded with authenticated bytes")
    require(opened.get("eip", "").lower() == "000afcc4" and opened.get("bytes") == "24" and
            opened.get("sha256", "").lower() == EXPECTED_ADDRESS and opened.get("cf") == "0",
            "natural virtual ADDRESS.TXT open marker mismatch")
    require(request.get("eip", "").lower() == "000afcc4" and
            request.get("request_eax", "").lower() == "00003d01" and
            request.get("resolved_path", "").replace("/", "\\").casefold() == r"c:\address.txt" and
            request.get("cf_out") == "0" and request.get("handled") == "1" and
            int(request.get("response_eax", "0"), 16) == int(opened.get("handle", "-1")),
            "AH=3D01 request and provider response do not match")
    physical = address.get("physical_host_path_observation", {})
    require(address.get("host_filesystem_used") is False and physical.get("guest_provider_source") is False,
            "guest provider source is confused with the physical host fixture")
    frontier = capture.get("next_frontier", {})
    trap = fields(frontier.get("event"))
    require(frontier.get("newly_observed_in_this_replay") is True and trap and
            trap.get("eip", "").lower() != "000afcc4" and frontier.get("cpu"),
            "post-open native frontier missing or stale")
    build = capture.get("build_fingerprints", {})
    exe = ROOT / "build" / "entry_path_native_boot.exe"
    require(exe.is_file() and hashlib.sha256(exe.read_bytes()).hexdigest() == capture.get("build_id") ==
            build.get("native_executable_sha256"), "native executable fingerprint mismatch")
    require(build.get("harness_c_sha256") == hashlib.sha256((ROOT / "tests/test_native_guest_image.c").read_bytes()).hexdigest() and
            build.get("driver_sha256") == hashlib.sha256((ROOT / "tests/test_native_guest_image.py").read_bytes()).hexdigest(),
            "harness/driver fingerprints do not match the captured build")
    recovery = capture.get("recovery", {})
    manifest = ROOT / recovery.get("manifest", "")
    require(manifest.is_file() and hashlib.sha256(manifest.read_bytes()).hexdigest() == recovery.get("manifest_sha256"),
            "recovery manifest fingerprint mismatch")
    recovery_doc = json.loads(manifest.read_text(encoding="utf-8"))
    require(recovery_doc.get("task") == "W1-072" and all(item.get("backup_matches") and
            item.get("isolated_restore_matches") for item in recovery_doc.get("files", [])),
            "isolated recovery verification missing")
    require(capture.get("runtime_fingerprint", {}).get("c_h_sha256"), "Runtime fingerprint is absent")
    require(not capture.get("acceptance_errors"), "capture lists acceptance errors")
    print("PASS W1-072 fresh Runtime-backed AX=6300 and authenticated ADDRESS.TXT open")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_native_address_open_w1_072.py EVIDENCE.json")
    main(sys.argv[1])
