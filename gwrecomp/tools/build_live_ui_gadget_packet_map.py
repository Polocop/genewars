from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence"
SNAPSHOTS = ROOT / "snapshots"
EXPECTED_LE = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
MEMORY_SIZE = 0x03002000


def load_snapshot(turn: int) -> tuple[bytes, dict]:
    filename = "turn_435_post_landing.snap" if turn == 435 else "turn_1292_extractor_selected.snap"
    path = SNAPSHOTS / filename
    raw = path.read_bytes()
    offset = len(raw) - MEMORY_SIZE
    if offset < 0:
        raise ValueError(f"bad snapshot length: {path}")
    memory = raw[offset:]
    sidecar = path.with_suffix(path.suffix + ".mem")
    sidecar_matches = None
    if sidecar.exists():
        side = sidecar.read_bytes()
        sidecar_matches = side == memory
        if not sidecar_matches:
            raise ValueError(f"snapshot sidecar differs from embedded payload: {path}")
    return memory, {"path": str(path.relative_to(ROOT)), "file_bytes": len(raw),
                    "memory_bytes": len(memory), "memory_payload_offset": offset,
                    "sidecar_present_and_matches": sidecar_matches}


def u16(m: bytes, a: int) -> int:
    return struct.unpack_from("<H", m, a)[0]


def s16(m: bytes, a: int) -> int:
    return struct.unpack_from("<h", m, a)[0]


def u32(m: bytes, a: int) -> int:
    return struct.unpack_from("<I", m, a)[0]


def live_gadgets(m: bytes) -> list[dict]:
    head = u32(m, 0x00379490)
    node = head
    seen: set[int] = set()
    out = []
    for ordinal in range(128):
        if not node or node in seen or node + 0x28 > len(m):
            break
        seen.add(node)
        flags = u32(m, node)
        gid = s16(m, node + 0x0C)
        action_cb = u32(m, node + 0x0E)
        help_cb = u32(m, node + 0x22)
        x, y, w, h = struct.unpack_from("<hhhh", m, node + 4)
        next_link = u32(m, node + 0x1E)
        # +0x08 is the list sentinel and +0x01 is the disabled/removed marker
        # used by the original traversal. Preserve the raw bits as primary evidence.
        is_sentinel = bool(flags & 0x02 and w == 0 and h == 0)
        out.append({
            "ordinal": ordinal,
            "guest_address": f"0x{node:08X}",
            "gadget_id": gid,
            "rect_logical_640x480": {"x": x, "y": y, "w": w, "h": h},
            "rect_host_2x": {"x": 2*x, "y": 2*y, "w": 2*w, "h": 2*h},
            "flags_raw": f"0x{flags:08X}",
            "flags_bit_0x08": bool(flags & 0x08),
            "flags_bit_0x01": bool(flags & 0x01),
            "registered_in_live_chain": True,
            "hit_test_enablement": "raw flags recorded; availability also depends on original hit-test state and input routing",
            "click_callback_slot_plus_0x0E": f"0x{action_cb:08X}",
            "help_callback_slot_plus_0x22": f"0x{help_cb:08X}",
            "handler_route": ("central IFCPlanetside::Update input_index dispatch; +0x0E is null"
                              if action_cb == 0 else "per-record callback plus original interface dispatch"),
            "next_guest": f"0x{next_link:08X}",
            "sentinel_record": is_sentinel,
            "raw_40_bytes": m[node:node+0x28].hex(),
        })
        if (flags & 0x02) and not (flags & 0x01):
            node = next_link
        else:
            node += 0x28
    return out


def main() -> None:
    le_path = EVIDENCE / "genewars-1_1.exe"
    le_hash = hashlib.sha256(le_path.read_bytes()).hexdigest()
    if le_hash != EXPECTED_LE:
        raise SystemExit(f"canonical LE hash mismatch: {le_hash}")

    old_census = json.loads((EVIDENCE / "full_entity_census_and_30_mapdisplay_1f_writers.json").read_text())
    packet_table_report = json.loads((EVIDENCE / "process_packets_full_table_and_snapshot_probes.json").read_text())
    prior_packet_probe = json.loads((EVIDENCE / "new_packet_actions_from_35_table_live_dispatch.json").read_text())
    action_audit = json.loads((EVIDENCE / "eighth_packet_action_and_plant_filter_live_report.json").read_text())
    panel_probe = json.loads((EVIDENCE / "packet18_snapshot_probe.json").read_text())

    snapshots = {}
    gadget_records = {}
    for turn in (435, 1292):
        memory, meta = load_snapshot(turn)
        gadgets = live_gadgets(memory)
        c8 = u32(memory, 0x0035F9BC)
        c8_vtable = u32(memory, c8) if c8 and c8 + 4 <= len(memory) else 0
        specs = old_census["entity_census"][str(turn)]["arrays"]["BioGame::__team/PlSpec"]["entities"]
        creatures = old_census["entity_census"][str(turn)]["arrays"]["BioGame::__creatures"]["entities"]
        snapshots[str(turn)] = {
            **meta,
            "game_turn": turn,
            "guest_my_gadget_head": f"0x{u32(memory, 0x00379490):08X}",
            "selected_plspec": f"0x{u32(memory, 0x002F1434):08X}",
            "selected_building_pointer": f"0x{u32(memory, 0x0035FA81):08X}",
            "ifcplanetside_this_plus_0xC8": f"0x{c8:08X}",
            "mode_object_vtable": f"0x{c8_vtable:08X}",
            "mapdisplay_filter_0x1F": f"0x{u16(memory, 0x00346D8F):04X}",
            "specialists": specs,
            "creatures": creatures,
            "gadget_count_in_chain": len(gadgets),
        }
        gadget_records[str(turn)] = gadgets

    action_rows = packet_table_report["static_dispatch"]["actions"]
    previously_live = {"0x03", "0x04", "0x10", "0x12", "0x14", "0x15", "0x1F"}
    live_ids = {str(turn): sorted({g["gadget_id"] for g in gadget_records[str(turn)]
                                   if g["gadget_id"] > 0 and not g["sentinel_record"]})
                for turn in (435, 1292)}
    known_guards = {
        "0x01": "Escape can transition the active IFC; prior snapshot probe changed interface without an Action dispatch.",
        "0x05": "Mode-specific IFC action path; requires accepted target/action return from FUN_0003D470 or a valid selected-mode command.",
        "0x07": "Team/capsule workflow; prior evidence locates the packet writer in FUN_00067030, not a live surface HUD control in these snapshots.",
        "0x09": "Drop-zone order requires the original selected effect/monolith path; not exposed by a live gadget in these lists.",
        "0x11": "Sentinel-zone input is restricted to creature/tamed-creature context; no eligible creature target is available in view.",
        "0x16": "PA_MESSAGE requires Thing+0x45 signed > -1 and global byte 0x184806 == 2; snapshot byte is 0.",
        "0x17": "Requires a valid in-viewport creature and original selected-mode target context; creature is outside view and has Thing+0x17 == 0.",
        "0x18": "FUN_0006DFE0 requires gadget input index 0x0E (ID 14) and owner guard; ID 14 is absent in both live chains.",
        "0x19": "Requires a valid in-viewport creature/action target and the original owner/state predicates.",
        "0x14": "Previously verified on the extractor panel through gadget ID 7; not a new Action code.",
    }
    pending = []
    for row in action_rows:
        code = row["action"]
        if code == "0x00" or code in previously_live:
            continue
        emitters = row.get("emitters", [])
        guard = known_guards.get(code, "Static emitter exists; exact user-input guard is not established by current snapshot evidence.")
        candidate_ids = []
        if code == "0x18":
            candidate_ids = [14]
        pending.append({
            "action": code,
            "enum": row.get("enum_name"),
            "handler_link": row.get("handler_link"),
            "handler_fixup_verified": row.get("fixup_verified"),
            "emitters": [{"store_link": e.get("store_link"), "anchor_link": e.get("anchor"),
                          "value": e.get("value"), "classification": e.get("classification")}
                         for e in emitters],
            "candidate_gadget_ids_or_keys": candidate_ids,
            "candidate_present_turn435": [x for x in candidate_ids if x in live_ids["435"]],
            "candidate_present_turn1292": [x for x in candidate_ids if x in live_ids["1292"]],
            "guard_assessment": guard,
            "live_dispatch_observed_in_this_task": False,
        })

    writers = old_census["mapdisplay_filter"]["writers"]
    writer_rows = []
    for row in writers:
        fn = row.get("containing_lifted_function")
        eip = row["eip_link"]
        # The two immediate stores have complete predicate evidence from the prior LE analysis.
        predicate = None
        if eip.lower() == "0x0001f569":
            predicate = "[selected_mode_object+0x16] == 1 writes 0xFF5F; this enables mask bit 0x0004 (TT_PLANT)."
        elif eip.lower() == "0x0001f574":
            predicate = "fallback when [selected_mode_object+0x16] != 1 writes 0xFF5B; mask bit 0x0004 (TT_PLANT) is clear."
        writer_rows.append({
            "eip_link": eip,
            "instruction": row.get("instruction"),
            "static_source_register_or_value": row.get("written_value"),
            "mapdisplay_filter_plant_bit_0x0004": row.get("plant_bit_0x0004"),
            "lifted_function_attribution": fn,
            "exact_condition_if_proven": predicate,
            "function_resolution": "resolved from existing lifted source/context" if fn else "not resolved by current lifted-function mapping; address and instruction are exact from canonical LE analysis",
        })

    c435 = snapshots["435"]["creatures"]
    c1292 = snapshots["1292"]["creatures"]
    creature_picker = {
        "snapshot435_entity": c435[0] if c435 else None,
        "snapshot1292_entity": c1292[0] if c1292 else None,
        "taxonomy": "Canonical LE: ttype 1=Creature; ttype 3=PlSpec. The request's ttype=3 creature premise reverses these types.",
        "filter_mask_fact": "0xFF5B has bit 0x0002 set (1 << ttype 1), so the creature passes the type-mask test; bit 0x0008 also permits ttype 3 PlSpecs.",
        "actual_picker_gate": "The original picker also requires signed Thing+0x17 > 0 before its sprite hit-test (0x78D8A path).",
        "observed_thing_plus_0x17": "0x00 in both snapshots for creature 0x0032CF86.",
        "projected_screen_xy_turn435": [-712, 93],
        "scroll_assessment": "Camera scroll alone cannot make this creature selectable in these snapshots because the earlier +0x17 predicate fails independently of viewport coordinates. No camera mutation or manual guest-state edit was made.",
        "live_action17_or19": "Prior snapshot attempt remained Action=0 and MapDisplay+0x18=0 with frontier=0; no new packet is claimed.",
    }

    out1 = {
        "schema": "gw-live-ui-gadgets-to-packet-emitters-map/v1",
        "target_sha256": le_hash,
        "snapshot_sources": snapshots,
        "gadget_records_by_snapshot": gadget_records,
        "gadget_record_layout": {"stride": "0x28", "id_offset": "0x0C", "rect_offsets": ["0x04", "0x06", "0x08", "0x0A"],
                                  "flags_offset": "0x00", "click_callback_offset": "0x0E", "help_callback_offset": "0x22"},
        "dispatch_model": "Most live records have a null +0x0E action callback; the original IFCPlanetside::Update central input_index switch handles IDs, and per-record +0x22 is a help callback. Record membership/flags are preserved; no inferred enabled state is substituted for hit-test evidence.",
        "pending_action_crosswalk": pending,
        "mapdisplay_1f_writers": {
            "global_guest": "0x00346D8F", "writer_count": len(writer_rows), "writers": writer_rows,
            "fully_attributed_count": sum(bool(x["lifted_function_attribution"]) for x in writer_rows),
            "unresolved_function_eips": [x["eip_link"] for x in writer_rows if not x["lifted_function_attribution"]],
            "plant_bit_writer_proven": "Only 0x1F569 is an immediate 0xFF5F store with a decoded class==1 predicate. Other dynamic-register writers need live register/call-context evidence to claim bit 0x0004 set.",
        },
        "runtime_panel_sweep": {"evidence": "evidence/new_packet_actions_from_35_table_live_dispatch.json",
                                "panel_probe": "evidence/packet18_snapshot_probe.json",
                                "sweep_actions_emitted": sorted({x.get("action") for x in prior_packet_probe.get("new_live_action_dispatches", []) if x.get("action")}),
                                "interpretation": "The recorded 54 SDL stages exercised registered panel IDs in the Turn-1292 snapshot; they did not produce a new Action dispatch."},
        "new_packet_goal_met": False,
        "limitations": ["Eleven MapDisplay+0x1F store instructions still lack a resolved containing-function attribution in the current source map.",
                        "No new Action code was emitted or dispatched; current snapshot evidence rules out the most direct candidates by missing gadget/guard state."]
    }
    (EVIDENCE / "live_ui_gadgets_to_packet_emitters_map.json").write_text(json.dumps(out1, indent=2) + "\n", encoding="utf-8")

    regressions_path = EVIDENCE / "eighth_packet_action_regressions_current.json"
    regressions = json.loads(regressions_path.read_text()) if regressions_path.exists() else None
    out2 = {
        "schema": "gw-eighth-action-and-creature-viewport-report/v1",
        "target_sha256": le_hash,
        "canonical_le_sha256_verified": le_hash == EXPECTED_LE,
        "task1_report": "evidence/live_ui_gadgets_to_packet_emitters_map.json",
        "new_action": {"required": True, "emitted": False, "dispatched": False, "code": None,
                       "frontier": None, "unexpected_writes": None, "MCB_chain_valid": None,
                       "reason": "No eighth Action was observed. The available 1292 panel sweep was clean but only existing paths were reached; the 0x18 emitter requires absent gadget ID 14, while the creature emitters require a valid target that fails Thing+0x17 in the snapshot."},
        "creature_viewport": creature_picker,
        "existing_live_evidence": {
            "turn1292_panel_sweep": {"artifact": "evidence/new_packet_actions_from_35_table_live_dispatch.json",
                                     "snapshot_probe": "evidence/packet18_snapshot_probe.json",
                                     "SDL_stages": 54, "new_packet_dispatches": 0},
            "turn435_creature_probe": {"artifact": "evidence/new_packet_actions_from_35_table_live_dispatch.json",
                                       "result": "MapDisplay+0x18 null; Action 0; frontier 0; MCB valid"},
        },
        "regressions": regressions,
        "regressions_all_exit_0": bool(regressions and regressions.get("all_exit_0")),
        "passed": False,
        "limitations": ["The requested new eighth packet was not obtained; the report records the causal guard blockers rather than treating a negative attempt as success.",
                        "No scroll replay was launched because the snapshot's signed +0x17 picker predicate fails before cursor-box comparison, so a camera-only experiment cannot satisfy the original selection path.",
                        "No guest globals, packet bytes, specialist flags, or entity fields were forced."]
    }
    (EVIDENCE / "eighth_action_verified_and_creature_viewport_report.json").write_text(json.dumps(out2, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"reports": ["evidence/live_ui_gadgets_to_packet_emitters_map.json", "evidence/eighth_action_verified_and_creature_viewport_report.json"],
                      "canonical_le_sha256": le_hash, "gadgets": {k: v["gadget_count_in_chain"] for k,v in snapshots.items()},
                      "filter_writers": len(writer_rows), "unresolved_filter_writer_functions": len(out1["mapdisplay_1f_writers"]["unresolved_function_eips"]),
                      "new_action_dispatched": False}, indent=2))


if __name__ == "__main__":
    main()
