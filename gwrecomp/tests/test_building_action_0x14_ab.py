"""A/B regression for the original EXTRACTOR gadget's PA action 0x14."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence"
LE = EVIDENCE / "genewars-1_1.exe"
EXPECTED_SHA = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def main() -> None:
    if not LE.is_file() or hashlib.sha256(LE.read_bytes()).hexdigest() != EXPECTED_SHA:
        raise SystemExit("canonical GeneWars 1.1 LE hash mismatch or file missing")
    # Use the latest retained run: unlike the earlier selection-only profile,
    # this one emits Action=0x14 and completes the original bounded game loop.
    active_path = EVIDENCE / "action14_final_sequence.json"
    active_log_path = EVIDENCE / "action14_final_sequence.stderr.log"
    baseline_path = EVIDENCE / "building_selection_6b0de_panel_probe_contract2.json"
    baseline_log_path = EVIDENCE / "building_selection_6b0de_panel_probe_contract2.stderr.log"
    static_path = EVIDENCE / "action_0x14_from_6e18c_live_dispatch.json"
    old_frontier_path = EVIDENCE / "action_0x14_from_6e18c_live_dispatch.json"
    lifter_source = ROOT / "tools" / "lift_entry_path.py"
    generated_source = ROOT / "work" / "ifctitle_plugin_load_at_closure.c"
    for path in (active_path, active_log_path, baseline_path, baseline_log_path,
                 static_path, old_frontier_path, lifter_source, generated_source):
        if not path.is_file():
            raise SystemExit(f"Action 0x14 A/B source evidence missing: {path}")

    active = read_json(active_path)
    baseline = read_json(baseline_path)
    static = read_json(static_path)
    active_log = active_log_path.read_text(encoding="utf-8", errors="replace")
    baseline_log = baseline_log_path.read_text(encoding="utf-8", errors="replace")
    old_frontier = read_json(old_frontier_path)
    lifter_text = lifter_source.read_text(encoding="utf-8", errors="replace")
    generated_text = generated_source.read_text(encoding="utf-8", errors="replace")
    checks = []

    def check(name: str, passed: bool, detail):
        checks.append({"name": name, "passed": bool(passed), "detail": detail})

    run = active.get("run", {})
    integrity = (active.get("passed") is True and active.get("frontier") is None and
                 active.get("unexpected_writes") == 0 and active.get("MCB_chain_valid") is True and
                 active.get("guest_turn_final") == 1350)
    action_store = next((line for line in active_log.splitlines()
                         if "writer_eip=000215af" in line and "after=14" in line), "")
    packet_dispatch = next((line for line in active_log.splitlines()
                            if "eip=00093010" in line and "Action=14" in line and "turn=1294" in line), "")
    check("IFCPlanetside original update wrote Action 0x14 at 0x215AF", bool(action_store), action_store)
    check("process_packets received Action 0x14 at Turn 1294", bool(packet_dispatch), packet_dispatch)
    static_emitter = static.get("static", {}).get("guards_and_emitter", {}).get("6DFE0_to_6E18C", {})
    check("canonical building-controller method contains the Action 0x14 emitter",
          any("0x6E18C" in item and "0x14" in item for item in static_emitter.get("emitter", [])),
          static_emitter)
    check("0x39BEF has a canonical fail-closed LE slot contract",
          "0x39BEF=0x111DFC:40" in lifter_text and
          "gw_recomp_icall_allow_00039BEF[] = { 0x00254E20u }" in generated_text and
          "GW_RECOMP_ICALL_ALLOWED_AT(0x00039BEFu, MEM32(DS_BASE + (edi + 0x44))" in generated_text,
          {"lifter_rule": "0x39BEF=0x111DFC:40",
           "slot": "[EDI+0x44]", "allowed_le_rebased_target": "0x00254E20"})
    # A prior run recorded the exact failure at this site (target was data).
    # The latest successful replay has no frontier; it did not include a
    # dedicated 0x39BEF operand snapshot, so do not invent one here.
    old_frontier_line = next((line for line in old_frontier.get("live", {}).get("trace_lines", [])
                              if "RUNTIME_FRONTIER eip=00039BEF" in line), "")
    check("prior frontier diagnosis is retained and latest rerun is clean",
          "target EAX=0033D276" in old_frontier_line and active.get("frontier") is None,
          {"prior_observation": old_frontier_line,
           "latest_frontier": active.get("frontier"),
           "latest_direct_operand_snapshot": "not captured"})
    check("latest Action 0x14 replay reached Turn 1350 with clean integrity", integrity,
          {k: active.get(k) for k in ("frontier", "unexpected_writes", "MCB_chain_valid", "guest_turn_final")})

    baseline_clean = baseline.get("passed") is True and baseline.get("frontier") is None and \
        baseline.get("unexpected_writes") == 0 and baseline.get("MCB_chain_valid") is True
    baseline_actions = sorted(set(re.findall(r"Action=([0-9a-fA-F]{2})", baseline_log)))
    active_actions = sorted(set(re.findall(r"Action=([0-9a-fA-F]{2})", active_log)))
    check("A/B control panel replay stayed at PA_NULL", baseline_clean and baseline_actions == ["00"],
          {"control_integrity": baseline_clean, "control_actions": baseline_actions})
    check("A/B activated replay changed from PA_NULL to PA action 0x14", "14" in active_actions,
          {"active_actions": active_actions})

    report = {
        "schema": "gw-native-building-action-0x14-ab-regression/v1",
        "canonical_le_sha256": EXPECTED_SHA,
        "source_evidence": [str(p.relative_to(ROOT)) for p in
                            (active_path, active_log_path, baseline_path, baseline_log_path,
                             static_path, old_frontier_path)],
        "checks": checks,
        "passed": all(item["passed"] for item in checks),
    }
    out = EVIDENCE / "native_building_action_0x14_ab_regression.json"
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if not report["passed"]:
        raise SystemExit(f"Action 0x14 A/B regression failed: {out}")
    print(f"PASS Action 0x14 A/B dispatch regression: {out}")


if __name__ == "__main__":
    main()
