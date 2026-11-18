"""Validate a fresh native AX=4400/BX=1 producer capture without running it."""
import json
import pathlib
import sys


def validate(path: pathlib.Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != "gwrecomp.native-setup-replay/v1":
        raise ValueError("unexpected native replay evidence schema")
    if data.get("native_returncode") != 0:
        raise ValueError("native guest capture did not exit cleanly")
    if data.get("command_tail") != " -k 38928":
        raise ValueError("capture does not use the recorded W1-051 diagnostic tail")
    if data.get("recovery", {}).get("verification") != "work/recovery/W1-052-20261008-210405/verification.json":
        raise ValueError("current W1-052 recovery proof is not attached")
    recovery = json.loads((path.parents[1] / data["recovery"]["verification"]).read_text(encoding="utf-8"))
    if not all(recovery.get(k) is True for k in ("all_copy_hashes_match", "all_isolated_restores_match", "live_sources_unchanged")):
        raise ValueError("recovery copy/isolated restoration verification failed")
    capture = data.get("sound_ini_continuation", {})
    origin = capture.get("ax4400_origin", {})
    entries = origin.get("helper_entries", [])
    requests = origin.get("requests", [])
    bx1 = origin.get("requests_bx1", [])
    if not capture.get("setup_game_entered") or not capture.get("callee_14bf0_entered"):
        raise ValueError("fresh execution did not reach the established setup path")
    if capture.get("crt_callbacks") != 19 or str(capture.get("argc")) != "3" or capture.get("gate") != "1/1":
        raise ValueError("CRT/argument/game gate regressed")
    if len(entries) != 12 or len(requests) != 12 or len(bx1) != 1:
        raise ValueError(f"expected 12 helper/request pairs and one BX=1 frontier: {len(entries)}/{len(requests)}/{len(bx1)}")
    if origin.get("helper_entry_va") != "0x000C896A" or origin.get("interrupt_va") != "0x000C8973":
        raise ValueError("captured instruction boundary differs")
    if not origin.get("request_to_helper_entry_correlated_by_ordinal"):
        raise ValueError("request/helper ordinals do not align")
    req = bx1[0]
    entry = entries[int(req["helper_ordinal"])]
    if int(entry["eax"], 16) != 1 or int(req["ebx"], 16) != 1:
        raise ValueError("BX=1 is not backed by the captured guest EAX input")
    if entry.get("return_address") != "dead0000" or entry.get("callsite") != "00000000":
        raise ValueError("expected the known dummy guest return marker; caller must remain unresolved")
    if not origin.get("file_handle_events_in_execution_order"):
        raise ValueError("no preceding DOS file/handle event history was retained")
    if origin.get("callsites"):
        raise ValueError("this evidence version must not claim generated callsite instrumentation")
    return {"passed": True, "entries": len(entries), "requests": len(requests), "bx1": req,
            "dynamic_caller": "unresolved: dummy RECOMP_RETADDR is not a caller address"}


if __name__ == "__main__":
    target = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path("evidence/native_ah44_bx1_origin_work1.json")
    print(json.dumps(validate(target), indent=2))
