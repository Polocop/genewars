"""Validate fresh native dynamic caller provenance for AX=4400 BX=1."""
import hashlib
import json
import pathlib
import sys


def validate(path: pathlib.Path) -> dict:
    root = path.resolve().parents[1]
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != "gwrecomp.native-setup-replay/v1" or data.get("native_returncode") != 0:
        raise ValueError("native replay evidence schema/status mismatch")
    if data.get("command_tail") != " -k 38928" or not data.get("frontier", {}).get("fresh_replay"):
        raise ValueError("expected a fresh W1 fixture replay with the measured diagnostic tail")
    rec = data.get("recovery", {})
    if rec.get("verification") != "work/recovery/W1-053-20261008-211015/verification.json":
        raise ValueError("current W1-053 recovery proof is not attached")
    verify = json.loads((root / rec["verification"]).read_text(encoding="utf-8"))
    if not all(verify.get(k) is True for k in ("all_copy_hashes_match", "all_isolated_restores_match", "live_sources_unchanged")):
        raise ValueError("W1-053 source recovery proof failed")
    path_data = data["sound_ini_continuation"]
    if path_data.get("crt_callbacks") != 19 or str(path_data.get("argc")) != "3" or path_data.get("gate") != "1/1":
        raise ValueError("CRT/main argument gate regressed")
    if not path_data.get("setup_game_entered") or not path_data.get("callee_14bf0_entered"):
        raise ValueError("the established setup/callee path was not reached")
    origin = path_data.get("ax4400_origin", {})
    callsites = origin.get("callsites", [])
    entries = origin.get("helper_entries", [])
    requests = origin.get("requests", [])
    bx1 = origin.get("requests_bx1", [])
    if len(callsites) != 12 or len(entries) != 12 or len(requests) != 12 or len(bx1) != 1:
        raise ValueError("expected the fresh 12-call isatty sequence and one BX=1 request")
    if not origin.get("callsite_to_entry_correlated_by_ordinal") or not origin.get("request_to_helper_entry_correlated_by_ordinal"):
        raise ValueError("callsite/helper/request ordinals do not correlate")
    req = bx1[0]
    ordinal = int(req["ordinal"])
    call, entry = callsites[ordinal], entries[ordinal]
    expected = {"ordinal": str(ordinal), "caller": "000ba4d6", "target": "000c896a", "site": "000ba4e4", "eax": "00000001"}
    if any(call.get(key) != value for key, value in expected.items()):
        raise ValueError(f"BX=1 caller/callsite/EAX mismatch: {call}")
    if int(entry["eax"], 16) != 1 or int(req["ebx"], 16) != 1 or req.get("eip") != "000c8973":
        raise ValueError("dynamic callsite, helper entry, and DOS request disagree")
    closure = root / "build" / "entry_path_closure.c"
    if hashlib.sha256(closure.read_bytes()).hexdigest() != data["build_fingerprints"]["closure_source_sha256"]:
        raise ValueError("capture closure source changed after this replay")
    text = closure.read_text(encoding="utf-8")
    if "eax = MEM32(edx + 0x10); /* 0x000BA4E1" not in text or "MEM8(eax + 0xD)" not in text:
        raise ValueError("generated caller dataflow lacks expected field load/flag test")
    if not path_data["runtime_fingerprint"].get("matches_w2_107"):
        raise ValueError("W2-107 Runtime fingerprint changed")
    if path_data.get("original_equivalence_claimed") is not False:
        raise ValueError("native/original dynamic equivalence must remain unclaimed")
    return {"passed": True, "dynamic_caller": "0x000BA4D6 (__chktty_)",
            "callsite": "0x000BA4E4", "isatty_entry_eax": "0x00000001",
            "request_bx": "0x00000001", "original_equivalence": False}


if __name__ == "__main__":
    target = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path("evidence/native_ah44_bx1_callsite_work1.json")
    print(json.dumps(validate(target), indent=2))
