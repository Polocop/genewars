"""Evidence-backed regression for finished-building selection and its EXTRACTOR panel.

The native replay is retained as evidence; this fast test revalidates the canonical
LE vtable/switch contracts, live 0x6B0DE selection, integrity, and the captured HUD.
It reports panel Action 0x13/0x14 as unobserved when the input probe left the
original packet action at zero.
"""
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


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def main() -> None:
    if not LE.is_file() or sha(LE) != EXPECTED_SHA:
        raise SystemExit("canonical GeneWars 1.1 LE hash mismatch or file missing")
    sys.path.insert(0, str(ROOT / "src"))
    from le_loader import load_le

    selection_path = EVIDENCE / "building_selection_6b0de_opened.json"
    selection_log_path = EVIDENCE / "building_selection_6b0de_opened.stderr.log"
    panel_path = EVIDENCE / "building_selection_6b0de_panel_probe_contract2.json"
    panel_log_path = EVIDENCE / "building_selection_6b0de_panel_probe_contract2.stderr.log"
    screenshot = EVIDENCE / "frontier_6b0de_building_selected_hud.bmp"
    analysis_path = EVIDENCE / "vtable_111b8c_and_switch_2473d_extractor_panel.json"
    required = (selection_path, selection_log_path, panel_path, panel_log_path, screenshot, analysis_path)
    missing = [str(p) for p in required if not p.is_file()]
    if missing:
        raise SystemExit(f"building selection/panel evidence missing: {missing}")

    selection = load_json(selection_path)
    panel = load_json(panel_path)
    analysis = load_json(analysis_path)
    selection_log = selection_log_path.read_text(encoding="utf-8", errors="replace")
    panel_log = panel_log_path.read_text(encoding="utf-8", errors="replace")
    image = load_le(LE)
    fixups = {f.source_link: f for f in image.fixups}
    object1 = image.objects[0]

    vtable_targets = []
    for slot in range(8):
        src = 0x111B8C + slot * 4
        f = fixups.get(src)
        if f is None or f.source_type != 0x07 or f.target_object != 1:
            raise SystemExit(f"vtable slot lacks an Object-1 LE offset fixup: 0x{src:08X}")
        vtable_targets.append(object1.base + f.target_offset)
    expected_vtable = [0x13840, 0x13830, 0x13820, 0x6B490, 0x13810, 0x6B1B0, 0x6B9F0, 0x6DDD0]

    table_targets = []
    for slot in range(12):
        src = 0x24514 + slot * 4
        f = fixups.get(src)
        if f is None or f.source_type != 0x07 or f.target_object != 1:
            raise SystemExit(f"building panel jump-table slot lacks an Object-1 LE fixup: 0x{src:08X}")
        table_targets.append(object1.base + f.target_offset)
    expected_table = [0x24723, 0x2472B, 0x246F7, 0x2472B, 0x2472B, 0x2472B,
                      0x2472B, 0x2472B, 0x2472B, 0x246F7, 0x2472B, 0x246F7]

    checks = []

    def check(name: str, ok: bool, detail):
        checks.append({"name": name, "passed": bool(ok), "detail": detail})

    check("canonical LE unchanged", sha(LE) == EXPECTED_SHA, EXPECTED_SHA)
    clean = (selection.get("passed") is True and selection.get("frontier") is None and
             selection.get("unexpected_writes") == 0 and selection.get("MCB_chain_valid") is True and
             selection.get("guest_turn_final") == 1350)
    check("native replay integrity through Turn 1350", clean,
          {k: selection.get(k) for k in ("frontier", "unexpected_writes", "MCB_chain_valid", "guest_turn_final")})
    site = "TRACE building_selection_6b0de turn=1292 eip=0006b0de"
    check("original 0x6B0DE call reached LE vtable slot +0x0C target 0x6B490",
          site in selection_log and "slot0c=00256490" in selection_log and
          "virtual_ebx=002ebbe8" in selection_log,
          {"site": site, "vtable_guest": "0x002EBB8C", "target_guest": "0x00256490"})
    selected_line = next((line for line in selection_log.splitlines()
                          if "eip=0006b490" in line and "selected=0033d276" in line and
                          "c8=0035fa7d" in line), "")
    check("selectedBuilding becomes 0x0033D276 and EXTRACTOR controller is active",
          bool(selected_line) and "building31=0001" in selected_line,
          selected_line or "matching live 0x6B490 state line missing")
    check("all 8 slots of vtable 0x111B8C are fixup-backed and match decoded targets",
          vtable_targets == expected_vtable, [hex(x) for x in vtable_targets])
    check("all 12 building-type switch entries at 0x24514 are fixup-backed",
          table_targets == expected_table, [hex(x) for x in table_targets])

    code = bytes(image.object_data(1))
    code_offset = image.link_to_linear(0x2473D) - image.mem_base
    building_type_11_target = table_targets[9]
    check("building type 11 selects case/index 9 of the 0x2473D switch",
          building_type_11_target == 0x246F7 and code[code_offset:code_offset + 8] == bytes.fromhex("2eff248514450200"),
          {"index": 9, "target": hex(building_type_11_target), "meaning": "building detail render path"})
    check("selected EXTRACTOR HUD BMP exists and matches captured evidence",
          screenshot.stat().st_size == 1228922 and
          sha(screenshot) == "1068207af6c3f8cf2517eb0832e7a45040c968c890fcba9af9b087abdc5a45cf",
          {"path": str(screenshot.relative_to(ROOT)), "bytes": screenshot.stat().st_size, "sha256": sha(screenshot)})
    panel_integrity = (panel.get("passed") is True and panel.get("frontier") is None and
                       panel.get("unexpected_writes") == 0 and panel.get("MCB_chain_valid") is True)
    click_rows = all(f"kind=building_panel_row{i}_left_{edge}_selected_building" in panel_log
                     for i in (1, 2, 3) for edge in ("down", "up"))
    check("panel control probe completed with integrity clean and exercised rows 1-3",
          panel_integrity and click_rows,
          {"frontier": panel.get("frontier"), "unexpected_writes": panel.get("unexpected_writes"),
           "MCB_chain_valid": panel.get("MCB_chain_valid"), "row_clicks_present": click_rows})
    actions = sorted(set(re.findall(r"Action=([0-9a-fA-F]{2})", panel_log)))
    check("panel interaction did not fabricate an action packet",
          actions == ["00"], {"observed_action_values": actions, "PA_0x13_or_0x14_emitted": False})
    check("static report is hash-bound and records the panel-action limitation",
          analysis.get("target_sha256") == EXPECTED_SHA and
          analysis.get("live_panel_probe", {}).get("action13_or14_emitted") is False,
          analysis.get("live_panel_probe"))

    report = {"schema": "gw-native-building-selection-and-panel-regression/v1",
              "canonical_le_sha256": EXPECTED_SHA,
              "source_evidence": [str(p.relative_to(ROOT)) for p in required],
              "vtable_targets_link": [f"0x{x:08X}" for x in vtable_targets],
              "switch_targets_link": [f"0x{x:08X}" for x in table_targets],
              "checks": checks, "selection_and_panel_open_verified": all(c["passed"] for c in checks),
              "panel_action_result": "No Action 0x13/0x14 observed; successful selection/HUD opening is verified, panel-button action trigger remains unidentified."}
    out = EVIDENCE / "native_building_selection_and_panel_regression.json"
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if not report["selection_and_panel_open_verified"]:
        raise SystemExit(f"building selection/panel regression failed: {out}")
    print(f"PASS building selection and EXTRACTOR panel regression: {out}")


if __name__ == "__main__":
    main()
