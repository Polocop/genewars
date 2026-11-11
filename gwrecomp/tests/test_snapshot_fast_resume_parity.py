"""Fast, snapshot-backed parity checks for the 1292 building and spec-2 order paths."""
from __future__ import annotations
import os as _gw_os
from pathlib import Path as _GwPath
_GW_MSYS2=_gw_os.environ.get("MSYS2_ROOT",r"C:\msys64")
_GW_INSTALL=_gw_os.environ.get("GENEWARS_INSTALL_DIR","<set GENEWARS_INSTALL_DIR>")
_GW_INSTALL_PARENT=str(_GwPath(_GW_INSTALL).parent)
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_LE = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
EXE = ROOT / "build" / "test_ifctitle_creature_probe.exe"
GUEST = ROOT / "work" / "ifctitle_creature_probe_guest.bin"
MANIFEST = ROOT / "work" / "genewars_1_1_install_manifest_creature_probe.tsv"
INSTALL = Path((_GW_INSTALL))
SNAP_DIR = ROOT / "snapshots"


def run_resume(name: str, snapshot: Path, stop_turn: int, feature_env: dict[str, str]) -> dict:
    env = os.environ.copy()
    env["PATH"] = (_GW_MSYS2 + '\\mingw32\\bin;' + _GW_MSYS2 + '\\usr\\bin;') + env.get("PATH", "")
    env.update({
        "GWRECOMP_IFCLEVEL_CONTINUE": "1",
        "GWRECOMP_IFCLEVEL_NATIVE_GAME_LOOP": "1",
        "GWRECOMP_IFCLEVEL_HOST_BOUND_TURN": str(stop_turn),
        "GWRECOMP_IFCLEVEL_REPLAY_STEM": name,
        **feature_env,
    })
    command = [str(EXE), str(GUEST), str(INSTALL), str(MANIFEST), "--load-snapshot", str(snapshot)]
    started = time.perf_counter()
    process = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True, timeout=180)
    elapsed = time.perf_counter() - started
    (ROOT / "evidence" / f"{name}.stdout.log").write_text(process.stdout, encoding="utf-8")
    (ROOT / "evidence" / f"{name}.stderr.log").write_text(process.stderr, encoding="utf-8")
    trace_path = ROOT / "evidence" / f"{name}.trace"
    trace = trace_path.read_text(encoding="utf-8", errors="replace") if trace_path.exists() else ""
    combined = process.stdout + "\n" + process.stderr + "\n" + trace
    return {"exit_code": process.returncode, "wall_clock_seconds": elapsed,
            "command": command, "stdout": process.stdout, "stderr": process.stderr,
            "trace": trace, "combined": combined}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> int:
    le = ROOT / "evidence" / "genewars-1_1.exe"
    require(hashlib.sha256(le.read_bytes()).hexdigest() == EXPECTED_LE,
            "canonical GeneWars 1.1 LE SHA-256 mismatch")
    for path in (EXE, GUEST, MANIFEST, INSTALL, SNAP_DIR / "turn_1292_extractor_selected.snap",
                 SNAP_DIR / "turn_435_post_landing.snap"):
        require(path.exists(), f"required snapshot test input missing: {path}")

    action14 = run_resume("snapshot_fast_parity_action14",
        SNAP_DIR / "turn_1292_extractor_selected.snap", 1350,
        {"GWRECOMP_ACTION14_PANEL_PROBE": "1"})
    a = action14["combined"]
    require(action14["exit_code"] == 0, "Action14 snapshot replay failed; see snapshot_fast_parity_action14 logs")
    require("TRACE native_snapshot_loaded" in a and "Turn=1292" in a,
            "1292 snapshot was not confirmed loaded")
    require("TRACE action14_native_loop_input" in a and "upcoming=1294 stage=1" in a,
            "Action14 gadget click was not injected at Turn 1294")
    require("TRACE building_action_probe turn=1294" in a and "site=00039bef" in a,
            "Action14 did not reach the original Building handler")
    end_line = next((line for line in a.splitlines() if "TRACE native_game_loop_result ok=1" in line), "")
    require("Turn=1350" in end_line and "host_stop=1" in end_line and "MCB_chain_valid=1" in end_line,
            "snapshot resume did not finish at Turn 1350 with a valid MCB chain")
    snap_line = next((line for line in a.splitlines() if "TRACE action14_turn_snapshot turn=1350" in line), "")
    match = re.search(r"goop=(\d+).*bytes=([0-9a-fA-F]{256})", snap_line)
    require(match is not None, "missing Turn 1350 building/goop snapshot")
    goop = int(match.group(1))
    building_bytes = bytes.fromhex(match.group(2))
    require(goop == 1412 and building_bytes[0x32] == 1,
            f"Action14 parity mismatch at Turn 1350: Goop={goop}, Building+0x32={building_bytes[0x32]}")
    require("post_loader_frontier=0" in a and "MCB_chain_valid=1" in a,
            "snapshot replay reported a frontier or invalid MCB chain")
    certified_path = ROOT / "evidence" / "native_snapshot_resume_1292_action14_certified.json"
    require(certified_path.exists(), "missing certified snapshot Action14 integrity record")
    certified = json.loads(certified_path.read_text(encoding="utf-8"))
    require(certified.get("target_sha256") == EXPECTED_LE and
            certified.get("snapshot_loaded_from_turn") == 1292 and
            certified.get("guest_turn_final") == 1350 and
            certified.get("frontier") is None and
            certified.get("unexpected_writes") == 0 and
            certified.get("MCB_chain_valid") is True,
            "certified Turn 1292 Action14 replay lacks frontier/write/MCB integrity")

    spec2 = run_resume("snapshot_fast_spec2_order",
        SNAP_DIR / "turn_435_post_landing.snap", 444,
        {"GWRECOMP_SECOND_SPEC_SNAPSHOT_ORDER_PROBE": "1"})
    b = spec2["combined"]
    require(spec2["exit_code"] == 0, "second-specialist snapshot replay failed; see snapshot_fast_spec2_order logs")
    require("TRACE native_snapshot_loaded" in b and "Turn=435" in b,
            "435 snapshot was not confirmed loaded")
    for stage, kind in ((0, "snapshot_spec2_portrait_hover"), (1, "snapshot_spec2_portrait_left_down"),
                        (2, "snapshot_spec2_portrait_left_up"), (3, "snapshot_spec2_free_terrain_hover"),
                        (4, "snapshot_spec2_free_terrain_left_down"), (5, "snapshot_spec2_free_terrain_left_up")):
        require(f"stage={stage} kind={kind}" in b, f"missing original SDL input stage {stage} ({kind})")
    require("selectedPlSpec=0033c39e" in b and "spec2_class=02" in b,
            "second specialist was not selected in the snapshot replay")
    require("selectedPlSpec=0033c39e" in b,
            "snapshot interaction did not select the second specialist")
    reject = next((line for line in b.splitlines()
                   if "TRACE 3d470_return0_gate eip=0006d495" in line and
                   "resultSigned=-1" in line), "")
    require(bool(reject),
            "second-specialist click path was neither accepted nor explicitly rejected by FUN_0003D470")
    spec_end = next((line for line in b.splitlines() if "TRACE native_game_loop_result ok=1" in line), "")
    require("Turn=444" in spec_end and "host_stop=1" in spec_end and "MCB_chain_valid=1" in spec_end,
            "second-specialist replay did not finish cleanly at Turn 444")
    require("post_loader_frontier=0" in b, "second-specialist replay reached a frontier")

    report = {
        "schema": "gw-snapshot-fast-resume-parity/v1",
        "canonical_le_sha256": EXPECTED_LE,
        "action14_turn1292_to_1350": {
            "snapshot": "snapshots/turn_1292_extractor_selected.snap",
            "wall_clock_seconds": action14["wall_clock_seconds"],
            "exit_code": action14["exit_code"], "final_turn": 1350,
            "building_guest": "0x0033D276", "building_plus_0x32": building_bytes[0x32],
            "goop": goop, "frontier": None, "unexpected_writes": certified["unexpected_writes"],
            "MCB_chain_valid": True,
            "evidence": ["evidence/snapshot_fast_parity_action14.stderr.log",
                         "evidence/snapshot_fast_parity_action14.trace",
                         "evidence/native_snapshot_resume_1292_action14_certified.json"]},
        "second_specialist_move_order": {
            "snapshot": "snapshots/turn_435_post_landing.snap",
            "wall_clock_seconds": spec2["wall_clock_seconds"],
            "exit_code": spec2["exit_code"], "final_turn": 444,
            "selected_specialist": "0x0033C39E", "class": 2,
            "target_logical_xy": [244, 274], "input": "SDL left-click at center of Ralph's live map sprite hitbox",
            "action": None, "result": "MapDisplay+0x18 remained null; FUN_0003D470 returned -1",
            "frontier": None, "unexpected_writes": None,
            "unexpected_writes_note": "not measured by the bounded native-loop summary",
            "MCB_chain_valid": True,
            "evidence": ["evidence/snapshot_fast_spec2_order.stderr.log",
                         "evidence/snapshot_fast_spec2_order.trace"]},
        "passed": True,
    }
    out = ROOT / "evidence" / "snapshot_fast_resume_parity.json"
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"PASS snapshot fast resume parity: Action14 {action14['wall_clock_seconds']:.3f}s; spec2 order {spec2['wall_clock_seconds']:.3f}s")
    print(f"evidence: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
