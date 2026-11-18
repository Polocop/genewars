"""Permanent evidence-backed A/B regression for the original PA_IFC_MOVE_GO build order.

The native treatment/control runs are produced by the deterministic SDL replay
profile. This test checks their persisted original-code packet, handler,
movement, integrity, and replacement-order evidence without launching another
long replay.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence"
LE = EVIDENCE / "genewars-1_1.exe"
LE_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
ORDER = EVIDENCE / "single_0x10_order_ralph_walk_to_turn750.json"
AB = EVIDENCE / "single_0x10_order_ab_test.json"
CONTROL_LOG = EVIDENCE / "building11_placement_grid_probe_v2.stderr.log"
COMPLETION = EVIDENCE / "building11_turn1234_to_2000_full_byte_diff.json"
SCHEMA = "gw-native-building-order-ab-regression/v2"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    if not LE.is_file() or sha256(LE) != LE_SHA256:
        raise SystemExit("canonical GeneWars 1.1 LE hash mismatch or file missing")
    if not ORDER.is_file() or not AB.is_file() or not CONTROL_LOG.is_file() or not COMPLETION.is_file():
        raise SystemExit("native build-order A/B source evidence is missing")
    order = json.loads(ORDER.read_text(encoding="utf-8"))
    ab = json.loads(AB.read_text(encoding="utf-8"))
    control = CONTROL_LOG.read_text(encoding="utf-8", errors="replace")
    completion = json.loads(COMPLETION.read_text(encoding="utf-8"))
    completion_snapshots = {int(row["turn"]): row for row in completion.get("snapshots", [])}
    turn_1235 = completion_snapshots.get(1235, {}).get("building", {}).get("fields", {})
    turn_1500 = completion_snapshots.get(1500, {}).get("building", {}).get("fields", {})
    packet = order["packet"]
    replay = order["replay"]
    movement = order["movement"]
    comparison = order["ab_comparison"]
    checks = [
        ("canonical LE unchanged", sha256(LE) == LE_SHA256, sha256(LE)),
        ("A/B evidence passed", ab.get("passed") is True and all(x.get("passed") for x in ab.get("checks", [])), ab.get("checks", [])),
        ("one original PA_IFC_MOVE_GO emitted at 0x6D567 on Turn 443",
         packet.get("action") == "PA_IFC_MOVE_GO (0x10)" and packet.get("emitter_eip") == "0x0006D567" and packet.get("turn") == 443,
         {k: packet.get(k) for k in ("action", "emitter_eip", "turn", "bytes_hex")}),
        ("original handler 0x76750 dispatched once",
         packet.get("handler_eip") == "0x00076750" and "count=1 Action=10" in packet.get("dispatch_trace", ""), packet.get("dispatch_trace")),
        ("single-order native replay reached 750 with intact memory",
         replay.get("final_turn") == 750 and replay.get("frontier") is None and replay.get("unexpected_writes") == 0 and replay.get("MCB_chain_valid") is True,
         {k: replay.get(k) for k in ("final_turn", "frontier", "unexpected_writes", "MCB_chain_valid")}),
        ("Ralph reached the original 0x10 destination",
         movement.get("first_turn_at_exact_destination") == 552 and movement.get("end_xy") == [19839, 13439], movement),
        ("completed building 11 has Building+0x31 bit 0 set from turn 1235 onward",
         completion.get("target_sha256", "").lower() == LE_SHA256 and
         turn_1235.get("progress_2b_u16") == 280 and (turn_1235.get("flags_31_u16", 0) & 1) == 1 and
         turn_1500.get("progress_2b_u16") == 280 and (turn_1500.get("flags_31_u16", 0) & 1) == 1,
         {"turn_1235": turn_1235, "turn_1500": turn_1500}),
        ("control replay replaced the 0x10 order with a later 0x03",
         comparison.get("B_single_order", {}).get("later_Action_0x03_count") == 0 and
         comparison.get("B_single_order", {}).get("post_order_mouse_input_count") == 0 and
         "after=10" in control and "after=03" in control, comparison),
    ]
    report = {
        "schema": SCHEMA,
        "canonical_le_sha256": LE_SHA256,
        "sources": [str(p.relative_to(ROOT)) for p in (ORDER, AB, CONTROL_LOG, COMPLETION)],
        "checks": [{"name": name, "passed": bool(ok), "detail": detail} for name, ok, detail in checks],
        "passed": all(ok for _, ok, _ in checks),
    }
    out = EVIDENCE / "native_build_order_ab_regression.json"
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if not report["passed"]:
        raise SystemExit(f"native PA_IFC_MOVE_GO build-order A/B failed: {out}")
    print(f"PASS native PA_IFC_MOVE_GO build-order A/B: {out}")


if __name__ == "__main__":
    main()
