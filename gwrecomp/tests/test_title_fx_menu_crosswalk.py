"""Read-only GeneWarsFX menu crosswalk plus a native original-code title preflight.

GeneWarsFX is GeneWars 1.0 reference material. Only the 1.1 LE/MAP and the
recompiled LbDataLoadAll_ invocation below provide GWRecomp execution evidence.
"""
from __future__ import annotations
import os as _gw_os
from pathlib import Path as _GwPath
_GW_ROOT=str(_GwPath(__file__).resolve().parents[1])
_GW_FX=_gw_os.environ.get("GENEWARSFX_ROOT",_gw_os.path.join(_GW_ROOT,"third_party","GeneWarsFX"))

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "third_party" / "pcrecomp")]

from le_loader import load_le
from tools.disasm.disasm32 import Disassembler
from tools.pe.pe_analyze import Section

FX = Path((_GW_FX + '\\worktrees\\genewars-phase2b'))
FX_COMMIT = "ed9632547b09b67143b5c81d6a5a973a396b986f"
TARGET_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
MAP_SHA256 = "30e06c203154904740c4ff3f1fcc4971fb6c0ef10ace2f4f9dc63367d45b99b3"
STEM = "title_fx_menu_crosswalk"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit("FAIL " + message)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def function_body(source: str, signature: str) -> str:
    match = re.search(re.escape(signature) + r"\s*\{(.*?)\n\}", source, re.S)
    require(match is not None, f"GeneWarsFX reference function missing: {signature}")
    return match.group(1)


def map_address(map_text: str, name: str) -> tuple[int, int]:
    for line in map_text.splitlines():
        if line.rstrip().endswith(" " + name):
            match = re.match(r"\s*([0-9A-Fa-f]{4}):([0-9A-Fa-f]{8})\s+", line)
            if match:
                return int(match.group(1), 16), int(match.group(2), 16)
    raise SystemExit(f"FAIL GeneWars 1.1 MAP symbol missing: {name}")


def main() -> None:
    git = lambda *args: subprocess.run(
        ["git", "-C", str(FX), *args], check=True, capture_output=True, text=True
    ).stdout.strip()
    require(git("branch", "--show-current") == "genewarsfx/phase-2b",
            "GeneWarsFX reference branch changed")
    require(git("rev-parse", "HEAD") == FX_COMMIT,
            "GeneWarsFX phase-2b reference commit changed")

    title_source = FX / "bio/src/ifctitle.cpp"
    options_source = FX / "bio/src/ifcoptions.cpp"
    iface_source = FX / "bio/src/iface.cpp"
    game_source = FX / "bio/src/game.cpp"
    source_text = {p.name: p.read_text(encoding="utf-8") for p in
                   (title_source, options_source, iface_source, game_source)}
    title_plugin = function_body(source_text[title_source.name], "void IFCTitle::PlugIn()")
    title_update = function_body(source_text[title_source.name], "void IFCTitle::Update()")
    options_update = function_body(source_text[options_source.name], "void IFCOptions::Update()")
    new_interface = function_body(source_text[iface_source.name],
                                  "void IFCBase::NewInterface(IFCBase &arg1)")
    game = function_body(source_text[game_source.name], "void game()")
    require("LbDataLoadAll(startup_files)" in title_plugin and
            'LbFileLengthRnc("data/iftitle.anb")' in title_plugin,
            "GeneWarsFX TITLE PlugIn resource path contract changed")
    require("this->NewInterface(ifcLevel)" in title_update and
            "this->NewInterface(ifcOptions)" in title_update and
            "control.Flags.QuitGame = 1" in title_update,
            "GeneWarsFX TITLE actions no longer identify New Game/OPTIONS/Quit")
    require("this->NewInterface(*this->previousIFC)" in options_update,
            "GeneWarsFX OPTIONS return route changed")
    require("IFCBase::pullOut = this" in new_interface and
            "IFCBase::plugIn = &arg1" in new_interface,
            "GeneWarsFX transition request no longer queues outgoing/incoming IFC")
    require("ifcTitle.PlugIn()" in game and "IFCBase::plugIn->PlugIn()" in game and
            "control_game()" in game and "draw_game()" in game and
            "control.Flags.QuitGame" in game,
            "GeneWarsFX game loop interface dispatch changed")

    target = ROOT / "evidence/genewars-1_1.exe"
    map_path = ROOT / "evidence/genewars-1_1.map"
    require(sha256(target) == TARGET_SHA256, "canonical 1.1 target hash mismatch")
    require(sha256(map_path) == MAP_SHA256, "canonical 1.1 MAP hash mismatch")
    map_text = map_path.read_text(encoding="ascii")
    expected = {
        "IFCTitle::PlugIn": (1, 0x70D10, "W?PlugIn$:IFCTitle$n()v"),
        "LbDataLoadAll_": (1, 0x15090, "LbDataLoadAll_"),
        "game()": (1, 0x92710, "W?game$n()v"),
        "control_game()": (1, 0x5AE60, "W?control_game$n()v"),
        "draw_game()": (1, 0x834C0, "W?draw_game$n()v"),
        "IFCLevel::PlugIn": (1, 0x15710, "W?PlugIn$:IFCLevel$n()v"),
        "IFCLevel::Update": (1, 0x179F0, "W?Update$:IFCLevel$n()v"),
        "titleGfx_files[]": (3, 0x105EE8, "W?titleGfx_files$n[]$TbLoadFiles$$"),
    }
    for label, (segment, offset, symbol) in expected.items():
        require(map_address(map_text, symbol) == (segment, offset),
                f"1.1 MAP mapping changed for {label}")

    image = load_le(target, object_rebases={1: 0x1EB000, 3: 0x1DA000})
    code_obj = image.objects[0]
    code = bytes(image.object_data(1))
    dis = Disassembler(code, 0, [Section(".text", code_obj.base,
                                          code_obj.virtual_size, 0,
                                          code_obj.virtual_size, 0x20000020)])
    title_fn = dis.disassemble_function(0x70D10)
    require(title_fn is not None and title_fn.address == 0x70D10,
            "1.1 IFCTitle::PlugIn boundary not decoded by Capstone")
    title_instructions = [i for block in title_fn.blocks.values()
                          for i in block.instructions]
    title_calls = {i.address: i.operands[0].imm for i in title_instructions
                   if i.mnemonic == "call" and i.operands and i.operands[0].type == 2}
    require(title_calls.get(0x70D30) == 0x15090 and
            title_calls.get(0x70D45) == 0x150D0,
            "1.1 IFCTitle::PlugIn no longer has the mapped resource call edges")
    title_table_guest = image.link_to_linear(0x105EE8)
    require(any(i.mnemonic == "mov" and len(i.operands) > 1 and
                i.operands[1].type == 2 and i.operands[1].imm == title_table_guest
                for i in title_instructions),
            "1.1 title plugin no longer references the LE-fixed titleGfx_files table")

    # Run the existing authentic LE test under a new artifact stem so its prior
    # evidence and generated files remain untouched. It executes 1.1 code, but
    # deliberately stops the individual resource loads at an explicit failure
    # boundary because no exact-build 1.1 resource tree is available here.
    env = {**os.environ, "GW_TITLE_TEST_STEM": STEM}
    run = subprocess.run([sys.executable, str(ROOT / "tests/test_authentic_title_loadall.py")],
                         cwd=ROOT, env=env, text=True, capture_output=True)
    print(run.stdout, end="")
    print(run.stderr, end="", file=sys.stderr)
    require(run.returncode == 0, "native recompiled 1.1 title load-list test failed")
    load_receipt_path = ROOT / f"evidence/{STEM}_validation.json"
    load_receipt = json.loads(load_receipt_path.read_text(encoding="utf-8"))
    require(load_receipt.get("passed") is True and
            load_receipt["execution"].get("resource_load_claim") is False,
            "native title loader receipt overclaims resource success")

    evidence = {
        "schema": "gw-title-fx-menu-crosswalk/v1",
        "target_sha256": TARGET_SHA256,
        "target_map_sha256": MAP_SHA256,
        "rea": {
            "provider": "Ghidra 12.1.4 via REA 6.4.0",
            "carrier_sha256": "1523022fb1febcfb939b2ed04145ee6e7dcd8b99113d932d21d33301c0052a97",
            "game": "ev_2e9c4630d062076a3ec424c279a67f7da7afb6de2731bd5d0df204775f0341da",
            "title_plugin": "ev_a0acd0dc147af656dd9431cd547a7784e18ea466e597be0074895edeb697aa06",
            "loadall": "ev_a7518b3b876adbad53fed0850489a95fd10726a2f5773c848b76b7da676a8a54",
            "control_game": "ev_fb66d895ade5d6e2f5142dcc015e9b4b03cbc58b94f53faed0bed5e361b7a7c1",
            "draw_game": "ev_5c9d0a424eb3d06085cac10359fa8c3b308d25bc37256cbf56b8f818b7c15ec7",
            "ifclevel_plugin": "ev_a216e42e663d305f2d23fd3477494e4ca6f48d067199e930d2f6db6787176ccf",
            "ifclevel_update": "ev_85a45c8d2bdf70e6c6be67521c36ef745f6410851fc044562a3efabd8cefb044",
        },
        "reference": {
            "project": "GeneWarsFX 1.0; read-only reference, not executable address authority",
            "branch": "genewarsfx/phase-2b",
            "commit": FX_COMMIT,
            "files": {p.name: sha256(p) for p in
                      (title_source, options_source, iface_source, game_source)},
            "mapped_1_1_functions": {k: {"segment": v[0], "link_va": hex(v[1]),
                                          "map_name": v[2]} for k, v in expected.items()},
            "logic_crosswalk": {
                "title_plugin": "FX calls startup_files and loads title art; 1.1 REA calls LbDataLoadAll(titleGfx_files at 0x105EE8) and then resource load at 0x10DFFC. Keep 1.1 resource table and code authoritative.",
                "1_1_title_edges": {"0x70D30": "call 0x15090 / LbDataLoadAll_",
                                     "0x70D45": "call 0x150D0 / title-screen resource loader",
                                     "titleGfx_files_link_va": "0x105EE8",
                                     "titleGfx_files_guest_linear": hex(title_table_guest)},
                "title_actions": "FX Update proves reference behavior: New Game queues IFCLevel, OPTIONS queues IFCOptions, QuitGame exits the main loop. No 1.1 Title::Update VA imported from FX.",
                "options_return": "FX retains previousIFC and queues it on Resume; no 1.1 Options behavior inferred from the 1.0 address space.",
                "dispatch": "FX applies pullOut/plugIn queue on the next game-loop iteration, then control_game/update and draw_game; 1.1 REA confirms virtual calls from currentIFC and the bit-0 quit-loop test.",
                "adapters": "SDL event/presentation and file backends are modern adapter patterns. GWRecomp must route its own SDL/DOS input and VFS through its existing runtime, while the game state transitions remain original 1.1 code.",
            },
        },
        "execution": {
            "receipt": str(load_receipt_path),
            "function": "recompiled original 1.1 LbDataLoadAll_ (0x15090)",
            "result": load_receipt["execution"],
            "menu_reached": False,
            "resource_bytes_loaded": False,
            "limitation": "the local candidate resource trees are GeneWarsFX 1.0; no hash-proven 1.1 resource files are available for the original LbFileOpen/Read path",
        },
        "passed": True,
    }
    out = ROOT / f"evidence/{STEM}.json"
    out.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(f"PASS read-only GeneWarsFX TITLE/OPTIONS/New Game/IFCLevel crosswalk bound to exact 1.1 MAP")
    print(f"PASS native original-code title resource-list preflight; bounded resource failure remains explicit")
    print(f"evidence: {out}")


if __name__ == "__main__":
    main()
