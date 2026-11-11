"""Validate the fresh native SOUND.INI continuation without running the guest."""
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
EXPECTED_TARGET = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
EXPECTED_SOUND = "339a99f3fac46182dc52bec753c7122a7fcb1e3cf762e79d6693a9461c8cb9c3"


def verify(path):
    evidence_path = pathlib.Path(path)
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    replay = evidence["sound_ini_continuation"]
    assert evidence["native_returncode"] == 0
    assert evidence["target_sha256"] == EXPECTED_TARGET
    assert replay["size"] == 11 and replay["sha256"] == EXPECTED_SOUND
    fixture = ROOT / replay["fixture"]
    assert len(fixture.read_bytes()) == 11
    assert hashlib.sha256(fixture.read_bytes()).hexdigest() == EXPECTED_SOUND
    assert replay["guest_path_allowlist"].casefold() == r"c:\genewars\sound.ini"
    assert replay["provider"] == "bounded in-memory only" and replay["access"] == "read-only"
    request = replay["fresh_native_request"]
    assert request["vector"] == "21" and request["eip"].lower() == "000af93a"
    assert int(request["request_eax"], 16) & 0xffff == 0x4300
    assert request["ds"] and request["request_edx"]
    assert request["path"].replace("/", "\\").casefold() == r"c:\genewars\sound.ini"
    assert int(request["response_eax"], 16) & 0xffff == 0x20
    assert int(request["response_ecx"], 16) & 0xffff == 0x20
    assert request["cf_out"] == "0" and request["handled"] == "1"
    assert replay["response_cx16"] == "0x0020" and replay["response_contract_passed"]
    assert replay["provider_open_count"] > 0 and replay["provider_close_count"] > 0
    assert all("access=read-only" in line and EXPECTED_SOUND in line for line in replay["provider_open"])
    assert replay["crt_callbacks"] == 19 and replay["argc"] == "3" and replay["gate"] == "1/1"
    assert replay["setup_game_entered"] and replay["callee_14bf0_entered"]
    runtime = replay["runtime_fingerprint"]
    assert runtime["matches_w2_107"]
    assert runtime["gw_dos_services_c_sha256"] == runtime["w2_107_expected_c_sha256"]
    assert not replay["original_equivalence_claimed"]
    assert replay["original_caller_link_va"] == "UNKNOWN"
    caller_evidence = ROOT / replay["w3_077_caller_evidence"]
    assert hashlib.sha256(caller_evidence.read_bytes()).hexdigest() == replay["w3_077_caller_evidence_sha256"]
    caller_json = json.loads(caller_evidence.read_text(encoding="utf-8"))
    assert any(x.get("int_instruction_link_va_candidate", "").lower()=="0xaf93a" and x.get("matches_w1_frontier")
               for x in caller_json["sound_ini_callers"])
    assert replay["original_callsite_match"] and replay["dynamic_invocation_equivalence"] is False
    recovery = evidence["recovery"]
    recovery_file = ROOT / recovery["verification"]
    assert hashlib.sha256(recovery_file.read_bytes()).hexdigest() == recovery["verification_sha256"]
    recovery_json = json.loads(recovery_file.read_text(encoding="utf-8"))
    assert recovery_json["all_copy_hashes_match"] and recovery_json["all_isolated_restores_match"]
    assert recovery_json["live_sources_unchanged"] is True
    frontier = replay["next_frontier"]
    assert frontier["trap_vector"] and frontier["trap_va"] and frontier["eax"]
    frontier_cpu = replay["next_frontier_cpu"]
    assert frontier_cpu["eip"].lower() == frontier["trap_va"].lower()
    assert frontier_cpu["eax"].lower() == frontier["eax"].lower()
    assert all(key in frontier_cpu for key in ("ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "flag_cf", "cs", "ds", "ss"))
    assert evidence["prior_ax4300_checkpoint_reused"] is False
    return {"passed": True, "evidence": evidence_path.as_posix(),
            "sound_ini_calls": replay["ah43_event_count_at_site"],
            "frontier": frontier}


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_native_sound_ini_w1_051.py EVIDENCE.json")
    result = verify(sys.argv[1])
    print(json.dumps(result, indent=2))
