from __future__ import annotations

import hashlib
import json
import re
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence"
SNAPSHOTS = ROOT / "snapshots"
EXPECTED_LE = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
ARRAYS = [
    {"name": "BioGame::__creatures", "base": 0x32CF86, "slots": 300, "stride": 0x7C, "expected_ttype": 1},
    {"name": "BioGame::__plants", "base": 0x3360D6, "slots": 512, "stride": 0x31, "expected_ttype": 2},
    {"name": "BioGame::__team/PlSpec", "base": 0x33C2D6, "slots": 16, "stride": 0xC8, "expected_ttype": 3},
    {"name": "BioGame::__buildings", "base": 0x33D276, "slots": 4, "stride": 0x10C0, "expected_ttype": 4},
    {"name": "BioGame::__effects", "base": 0x341576, "slots": 200, "stride": 0x51, "expected_ttype": 5},
]


def u8(b: bytes, off: int) -> int:
    return b[off]


def s16(b: bytes, off: int) -> int:
    return struct.unpack_from("<h", b, off)[0]


def snapshot_mem(path: Path) -> tuple[bytes, int]:
    mem_path = path.with_suffix(path.suffix + ".mem")
    raw = path.read_bytes()
    # GWSNAP2 footer tables follow the fixed guest memory. These two certified
    # snapshots have a 0x03002000-byte memory image and are 16-byte aligned.
    mem_size = 0x03002000
    if len(raw) < mem_size:
        raise ValueError(f"snapshot too short: {path}")
    offset = len(raw) - mem_size
    payload = raw[offset:]
    if len(payload) != mem_size:
        raise ValueError(f"snapshot payload length mismatch: {path}")
    if mem_path.exists():
        sidecar = mem_path.read_bytes()
        if sidecar != payload:
            raise ValueError(f"snapshot .mem sidecar differs from source snapshot: {path}")
        return sidecar, offset
    return payload, offset


def entity_census(memory: bytes) -> dict:
    grouped: dict[str, dict] = {}
    for arr in ARRAYS:
        items = []
        for idx in range(arr["slots"]):
            addr = arr["base"] + idx * arr["stride"]
            if addr + 0x2E >= len(memory):
                break
            thing_type = u8(memory, addr + 0x06)
            if thing_type != arr["expected_ttype"]:
                continue
            item = {
                "index": idx,
                "guest_address": f"0x{addr:08X}",
                "ttype_plus_0x06": f"0x{thing_type:02X}",
                "subtype_plus_0x07": f"0x{u8(memory, addr + 0x07):02X}",
                "world_xy_signed16_at_plus_07_plus_09": [s16(memory, addr + 0x07), s16(memory, addr + 0x09)],
                "owner_plus_0x18": f"0x{u8(memory, addr + 0x18):02X}",
                "byte_plus_0x16": f"0x{u8(memory, addr + 0x16):02X}",
                "byte_plus_0x17": f"0x{u8(memory, addr + 0x17):02X}",
                "flags_plus_0x1c": f"0x{u8(memory, addr + 0x1C):02X}",
                "byte_plus_0x2d": f"0x{u8(memory, addr + 0x2D):02X}",
            }
            if thing_type == 3:
                item["PlSpec_class_plus_0x16"] = f"0x{u8(memory, addr + 0x16):02X}"
                item["PlSpec_profession_plus_0x2d"] = f"0x{u8(memory, addr + 0x2D):02X}"
            items.append(item)
        grouped[arr["name"]] = {
            "base": f"0x{arr['base']:08X}", "slots": arr["slots"], "stride": arr["stride"],
            "expected_ttype": arr["expected_ttype"], "live_count": len(items), "entities": items,
        }
    counts = {}
    for group in grouped.values():
        t = group["expected_ttype"]
        counts[f"ttype_{t}"] = counts.get(f"ttype_{t}", 0) + group["live_count"]
    return {"group_counts_by_actual_Thing_ttype": counts, "arrays": grouped,
            "taxonomy_note": "Canonical LE evidence identifies ttype 1=Creature, 2=Plant, 3=PlSpec, 4=Building, 5=Effect. The attachment's proposed 1=Specialist / 3=Creature mapping is reversed for 1 and 3."}


def function_membership(addresses: set[int]) -> dict[int, dict]:
    found: dict[int, dict] = {}
    for path in (ROOT / "build").glob("*.c"):
        current = None
        for line in path.read_text(errors="ignore").splitlines():
            marker = re.search(r"gw_lift_\d+\s+(0x[0-9A-Fa-f]+)\s+(\w+)", line)
            if marker:
                current = {"entry": int(marker.group(1), 16), "name": marker.group(2), "source": path.name}
            ins_comment = re.search(r"0x([0-9a-fA-F]{8}):", line)
            if ins_comment:
                addr = int(ins_comment.group(1), 16)
                if addr in addresses and current:
                    found.setdefault(addr, current.copy())
    return found


def mapfilter_writer_table() -> list[dict]:
    prior = json.loads((EVIDENCE / "second_specialist_panel_and_mapdisplay_1f_writers.json").read_text())
    rows = prior["mapdisplay_filter"]["direct_word_writers"]
    site_addrs = {int(x["link_eip"], 16) for x in rows}
    owners = function_membership(site_addrs)
    verified_context = {
        0x21B09: {"entry_link": "0x00021380", "name": "IFCPlanetside::Update", "source": "existing LE/live analyses"},
        0x21C49: {"entry_link": "0x00021380", "name": "IFCPlanetside::Update", "source": "existing LE/live analyses"},
        0x21C74: {"entry_link": "0x00021380", "name": "IFCPlanetside::Update", "source": "existing LE/live analyses"},
        0x66EAD: {"entry_link": "0x00066DD0", "name": "FUN_00066DD0", "source": "existing LE disassembly context"},
    }
    answer = []
    for row in rows:
        addr = int(row["link_eip"], 16)
        inst = row["instruction"]
        imm = re.search(r",\s*(0x[0-9a-f]+)$", inst)
        value = int(imm.group(1), 16) if imm else None
        answer.append({
            "eip_link": row["link_eip"], "bytes": row["bytes"], "instruction": inst,
            "containing_lifted_function": ({"entry_link": f"0x{owners[addr]['entry']:08X}", "name": owners[addr]["name"], "source": owners[addr]["source"]} if addr in owners else verified_context.get(addr)),
            "written_value": (f"0x{value:04X}" if value is not None else f"runtime {row.get('value_semantics', 'register value')}"),
            "written_value_hex_static": (f"0x{value:04X}" if value is not None else None),
            "value_kind": "immediate" if value is not None else "dynamic register; runtime value needed",
            "plant_bit_0x0004": (bool(value & 4) if value is not None else "unknown without the live source register"),
            "prior_classification": row.get("location_group"), "note": row.get("note"),
        })
    return answer


def plus16_store_inventory() -> list[dict]:
    # Read lifted instruction annotations for stores to [base + 0x16]. This is
    # only an instruction inventory: a register base cannot be typed as PlSpec
    # without a caller/def-use proof.
    rows: dict[int, dict] = {}
    for path in (ROOT / "build").glob("*.c"):
        current = None
        for line in path.read_text(errors="ignore").splitlines():
            marker = re.search(r"gw_lift_\d+\s+(0x[0-9A-Fa-f]+)\s+(\w+)", line)
            if marker:
                current = {"entry": int(marker.group(1), 16), "name": marker.group(2), "source": path.name}
            ins = re.search(r"/\*\s+0x([0-9a-fA-F]{8}):\s*(.*?)\s*\*/", line)
            if not ins or not re.search(r"(?:byte|word|dword) ptr \[[^\]]+\+ 0x16\]", ins.group(2)):
                continue
            addr = int(ins.group(1), 16)
            mnem = ins.group(2).split()[0].lower()
            if mnem in {"mov", "or", "and", "add", "sub", "xor", "inc", "dec", "xchg", "not", "neg"}:
                rows.setdefault(addr, {"eip_link": f"0x{addr:08X}", "instruction": ins.group(2),
                    "lifted_function": (None if not current else {"entry_link": f"0x{current['entry']:08X}", "name": current["name"], "source": current["source"]}),
                    "PlSpec_attribution": "unproven from this generic register-relative instruction alone"})
    return [rows[k] for k in sorted(rows)]


def main() -> None:
    le_path = EVIDENCE / "genewars-1_1.exe"
    le_hash = hashlib.sha256(le_path.read_bytes()).hexdigest()
    if le_hash != EXPECTED_LE:
        raise SystemExit(f"canonical LE hash mismatch: {le_hash}")
    census = {}
    offsets = {}
    for turn in (435, 1292):
        snap = SNAPSHOTS / ("turn_435_post_landing.snap" if turn == 435 else "turn_1292_extractor_selected.snap")
        memory, offset = snapshot_mem(snap)
        offsets[str(turn)] = {"snapshot": str(snap.relative_to(ROOT)), "memory_image_size": len(memory), "memory_offset_in_container": offset}
        census[str(turn)] = entity_census(memory)
    prior = json.loads((EVIDENCE / "second_specialist_panel_and_mapdisplay_1f_writers.json").read_text())
    action_report = json.loads((EVIDENCE / "new_packet_actions_from_35_table_live_dispatch.json").read_text())
    action_table = json.loads((EVIDENCE / "process_packets_full_table_and_snapshot_probes.json").read_text())["static_dispatch"]["actions"]
    table = mapfilter_writer_table()
    out1 = {
        "schema": "gw-full-entity-census-and-mapdisplay-1f-writers/v1",
        "target_sha256": le_hash,
        "snapshot_memory_method": "Read guest RAM images from existing certified GWSNAP2 snapshots; no guest memory modified. Snapshot memory extraction used existing .mem sidecar when present, otherwise isolated the 0x03002000 guest-memory payload.",
        "snapshot_image_metadata": offsets,
        "entity_census": census,
        "mapdisplay_filter": {"guest_address": "0x00346D8F", "link_address": "0x0016CD8F", "writer_count": len(table), "writers": table,
            "containing_function_resolved_count": sum(x["containing_lifted_function"] is not None for x in table),
            "all_30_function_attributions_resolved": all(x["containing_lifted_function"] is not None for x in table),
            "bit_0x0004_meaning": "With the LE's picker ttype mask, set permits ttype=2 plants; clear excludes them.",
            "only_static_constants": [{"eip": x["eip_link"], "value": x["written_value"], "bit_0x0004": x["plant_bit_0x0004"]} for x in table if x["value_kind"] == "immediate"]},
        "plus_0x16_writer_audit": {
            "snapshot_specialist_values": {str(t): [{"address": e["guest_address"], "ttype": e["ttype_plus_0x06"], "class_plus_0x16": e.get("PlSpec_class_plus_0x16"), "profession_plus_0x2d": e.get("PlSpec_profession_plus_0x2d")} for e in census[str(t)]["arrays"]["BioGame::__team/PlSpec"]["entities"]] for t in (435, 1292)},
            "instruction_inventory": plus16_store_inventory(),
            "conclusion": "The snapshots contain two live PlSpec slots and both class bytes are 0x02. Generic [reg+0x16] writes exist in lifted code, but the available disassembly does not prove a store to these two PlSpec slots; the observed value comes from level/record initialization. Do not relabel unrelated register-relative +0x16 writes as profession updates.",
            "selector_branch": "sub_0001F4D0 reads byte [object/mode + 0x16], compares it to 1, writes 0xFF5F on equality and 0xFF5B otherwise (LE 0x1F565..0x1F574). This proves the branch behavior, not that a live class-1 PlSpec exists."},
        "prior_live_plant_attempt": {
            "evidence": "evidence/frontier_fix_plant_pick_and_new_action_report.json",
            "snapshot": "snapshots/turn_435_post_landing.snap",
            "result": "After natural portrait selection of 0x0033C2D6, class +0x16=0x02 and filter=0xFF5B. The plant click left MapDisplay+0x18=0; no accepted candidate call to FUN_0003D470 and Action remained 0.",
            "status": "not selected; no plant order or packet may be claimed"},
        "taxonomy_correction": "Actual LE Thing::ttype mapping is 1 Creature, 2 Plant, 3 PlSpec, 4 Building, 5 Effect. The prompt's parenthetical list incorrectly calls 1 Specialist and 3 Creature.",
        "analysis_artifacts_written": True,
    }
    (EVIDENCE / "full_entity_census_and_30_mapdisplay_1f_writers.json").write_text(json.dumps(out1, indent=2) + "\n", encoding="utf-8")

    # Reconcile this older table artifact with the live-action codes certified
    # in the current project history.
    live_codes = {0x03, 0x04, 0x10, 0x12, 0x14, 0x15, 0x1F}
    action_audit = []
    for a in action_table:
        code = int(a["action"], 16)
        if code in live_codes or code == 0:
            continue
        action_audit.append({"action": a["action"], "enum": a["enum_name"], "handler_link": a["handler_link"], "emitters": a["emitters"], "dynamic_emitter_anchors": a["dynamic_emitter_anchors"],
            "snapshot_reachability": "not demonstrated by the two snapshots; see emitter guard assessment"})
    out2 = {
        "schema": "gw-eighth-packet-action-and-plant-filter-live-report/v1",
        "target_sha256": le_hash,
        "static_table_source": "evidence/process_packets_full_table_and_snapshot_probes.json",
        "plant_pick": {
            "snapshots": ["snapshots/turn_435_post_landing.snap", "snapshots/turn_1292_extractor_selected.snap"],
            "eligible_live_plant_count_turn435": census["435"]["arrays"]["BioGame::__plants"]["live_count"],
            "live_class1_specialists": 0,
            "live_class2_specialists": 2,
            "filter_writer": "0x1F569 writes 0xFF5F only when the selected mode object's +0x16 equals 1; else 0x1F574 writes 0xFF5B.",
            "attempt_evidence": "evidence/ralph_plant_snapshot_probe_v3.stderr.log and evidence/frontier_fix_plant_pick_and_new_action_report.json",
            "observed_filter_after_Ralph_selection": "0xFF5B",
            "MapDisplay_plus_0x18": "0x00000000",
            "FUN_0003D470": "not called on an accepted plant candidate",
            "Action": "0x00",
            "result": "Plant pick cannot be certified from these snapshots through the natural class-1 filter path; no guest state was forced."},
        "remaining_action_audit": action_audit,
        "best_snapshot_candidates": [
            {"action": "0x18 PA_SET_SHIELD_MODE", "emitter": "0x6E114", "guard": "FUN_0006DFE0 input gadget index BX=0x0E and selected entity owner matches local player", "observed": "previous snapshot sweep registered gadget IDs did not include 14; no packet"},
            {"action": "0x17 PA_SET_SHEPHERD_THING / 0x19 PA_CREATURE_ACTION", "emitters": ["0x6E67F", "0x6E851"], "guard": "eligible in-viewport creature target and owner/state guard", "observed": "the only live creature is owner=4 and its projected coordinate in snapshot435 is outside the viewport; map18 remained null"},
            {"action": "0x16 PA_MESSAGE", "emitter": "0x1DBB3", "guard": "Thing+0x45 signed > -1 and global byte 0x184806 == 2", "observed": "snapshot435 and snapshot1292 byte at 0x184806 is 0; no action"},
            {"action": "0x01 PA_QUIT", "emitters": ["0x5B0F8", "0x71468", "0x724B6"], "observed": "prior Escape probe changed current IFC and emitted no packet"},
        ],
        "new_action_dispatch": {"new_action_code": None, "emitted": False, "dispatched": False, "frontier": None, "unexpected_writes": None, "MCB_chain_valid": None,
            "reason": "No snapshot-backed emitter guard among the candidates above is naturally satisfiable with the entities and live gadgets present; existing evidence shows rejected attempts, not a new action dispatch. No guest packet byte or structure was forced."},
        "previously_certified_regression_results": action_report.get("regressions", []),
        "current_regression_results": (json.loads((EVIDENCE / "eighth_packet_action_regressions_current.json").read_text()) if (EVIDENCE / "eighth_packet_action_regressions_current.json").exists() else None),
        "analysis_complete": True,
        "requested_new_action_goal_met": False,
        "passed": False,
        "limitations": ["This report does not claim a new 8th Action dispatch. The requested 8th live code remains blocked by the absent eligible entity, gadget, or runtime state described above.", "The branch at 0x1F569/0x1F574 is directly supported by LE bytes; the live snapshots have no class-1 specialist.", "No tests were run by this report-generation script."],
    }
    (EVIDENCE / "eighth_packet_action_and_plant_filter_live_report.json").write_text(json.dumps(out2, indent=2) + "\n", encoding="utf-8")

    print(json.dumps({"entity_census": "evidence/full_entity_census_and_30_mapdisplay_1f_writers.json", "packet_audit": "evidence/eighth_packet_action_and_plant_filter_live_report.json", "sha256": le_hash, "counts": {t: census[t]["group_counts_by_actual_Thing_ttype"] for t in census}, "writer_count": len(table), "plus16_store_rows": len(out1["plus_0x16_writer_audit"]["instruction_inventory"])}, indent=2))


if __name__ == "__main__":
    main()
