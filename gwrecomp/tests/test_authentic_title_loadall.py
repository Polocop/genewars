"""Validate external GeneWars symbols/layout and execute original title list walker."""
from __future__ import annotations
import os as _gw_os
from pathlib import Path as _GwPath
_GW_MSYS2=_gw_os.environ.get("MSYS2_ROOT",r"C:\msys64")

import hashlib
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
from tools.lift.lift32 import Lifter

TARGET = ROOT / "evidence" / "genewars-1_1.exe"
MAP = ROOT / "evidence" / "genewars-1_1.map"
EXPECTED_TARGET_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
EXPECTED_MAP_SHA256 = "30e06c203154904740c4ff3f1fcc4971fb6c0ef10ace2f4f9dc63367d45b99b3"
REBASES = {1: 0x1EB000, 3: 0x1DA000}

SYMBOLS = {
    "LbDataLoad_": (1, 0x14FF0, "LbDataLoad_"),
    "LbDataLoadAll_": (1, 0x15090, "LbDataLoadAll_"),
    "IFCTitle::PlugIn": (1, 0x70D10, "W?PlugIn$:IFCTitle$n()v"),
    "LbMemorySetup_": (1, 0x921F0, "LbMemorySetup_"),
    "game()": (1, 0x92710, "W?game$n()v"),
    "setup_game()": (1, 0x94AC0, "W?setup_game$n()v"),
    "reset_game()": (1, 0x954A0, "W?reset_game$n()v"),
    "LbFileOpen": (1, 0x98C70, "LbFileOpen"),
    "LbFileRead_": (1, 0x98D70, "LbFileRead_"),
    "StopMusic_": (1, 0x9FC90, "StopMusic_"),
    "titleGfx_files[]": (3, 0x105EE8, "W?titleGfx_files$n[]$TbLoadFiles$$"),
    "currentIFC": (3, 0x1157E8, "W?currentIFC$npn$IFCBase$$"),
    "GameControl::__Flags": (3, 0x117464, "W?control$n$GameControl$$__Flags___bf0"),
}


def fail(message: str) -> None:
    raise SystemExit(message)


def map_offset(map_text: str, name: str) -> tuple[int, int]:
    for line in map_text.splitlines():
        if line.rstrip().endswith(" " + name):
            match = re.match(r"\s*([0-9A-Fa-f]{4}):([0-9A-Fa-f]{8})\s+", line)
            if match:
                return int(match.group(1), 16), int(match.group(2), 16)
    fail(f"external symbol missing from imported 1.1 map: {name}")


def main() -> None:
    artifact_stem = os.environ.get("GW_TITLE_TEST_STEM", "authentic_title_loadall")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", artifact_stem):
        fail(f"invalid GW_TITLE_TEST_STEM: {artifact_stem!r}")
    target_hash = hashlib.sha256(TARGET.read_bytes()).hexdigest()
    if target_hash != EXPECTED_TARGET_SHA256:
        fail(f"protected GeneWars 1.1 target hash mismatch: {target_hash}")
    map_bytes = MAP.read_bytes()
    map_hash = hashlib.sha256(map_bytes).hexdigest()
    if map_hash != EXPECTED_MAP_SHA256:
        fail(f"imported external 1.1 MAP digest changed: {map_hash}")
    map_text = map_bytes.decode("ascii")
    for name, (segment, offset, map_name) in SYMBOLS.items():
        if map_offset(map_text, map_name) != (segment, offset):
            fail(f"MAP address mismatch for {name}: {map_offset(map_text, map_name)} != {(segment, offset)}")

    image = load_le(TARGET, object_rebases=REBASES)
    code_obj = image.objects[0]
    if image.link_to_linear(0x14FF0) != 0x1FFFF0 or image.link_to_linear(0x70D10) != 0x25BD10:
        fail("verified object-1 rebase no longer maps symbol entries as expected")
    code = bytes(image.object_data(1))
    dis = Disassembler(code, 0, [Section(".text", code_obj.base, code_obj.virtual_size,
                                         0, code_obj.virtual_size, 0x20000020)])
    for name, (_, va, _) in list(SYMBOLS.items())[:10]:
        fn = dis.disassemble_function(va)
        if fn is None or fn.address != va or not fn.blocks:
            fail(f"Capstone no longer decodes MAP entry {name} at {va:#x}")

    # The table really is four 44-byte LE records plus an empty terminator.
    # Pointer fields are interpreted only after the independently checked LE fixups.
    table_va = image.link_to_linear(0x105EE8)
    table_off = table_va - image.mem_base
    records = []
    for index in range(16):
        off = table_off + index * 44
        raw = bytes(image.mem[off:off + 44])
        if len(raw) != 44:
            fail("truncated titleGfx_files record")
        name = raw[:28].split(b"\0", 1)[0].decode("ascii")
        if not name:
            if index != 4:
                fail(f"expected title list terminator at entry 4, got {index}")
            break
        start = int.from_bytes(raw[28:32], "little")
        send = int.from_bytes(raw[32:36], "little")
        slength = int.from_bytes(raw[36:40], "little")
        flags = int.from_bytes(raw[40:42], "little")
        spare = int.from_bytes(raw[42:44], "little")
        if not start or image.object_containing_linear(start) is None:
            fail(f"{name}: LE-fixed Start pointer is not in a demonstrated object")
        records.append({"name": name, "guest_start_cell": start, "send": send,
                        "slength": slength, "flags": flags, "spare": spare})
    expected_names = ["data/iftitle.anb", "data/titlescr.pal", "data/font2.dat", "data/font2.tab"]
    if [x["name"] for x in records] != expected_names:
        fail(f"unexpected original title resource list: {[x['name'] for x in records]}")

    # game() really enters IFCTitle::PlugIn, whose direct call reaches the
    # list walker; QuitGame is the bit tested to leave the loop, not a menu event.
    game_fn = dis.disassemble_function(0x92710)
    ins = [i for block in game_fn.blocks.values() for i in block.instructions]
    call_targets = {i.operands[0].imm for i in ins
                    if i.mnemonic == "call" and i.operands and i.operands[0].type == 2}
    if 0x70D10 not in call_targets:
        fail("original game() no longer calls IFCTitle::PlugIn at the mapped entry")
    title_object_link = 0x184AB8
    title_object_guest = image.link_to_linear(title_object_link)
    title_object_raw = bytes(image.mem[title_object_guest-image.mem_base:
                                       title_object_guest-image.mem_base+32])
    if not any(i.address == 0x92756 and i.mnemonic == "mov" and i.operands and
               i.op_str.lower().startswith("eax, ") and i.operands[1].type == 2 and
               i.operands[1].imm == title_object_guest for i in ins) or \
            not any(i.address == 0x9275B and i.mnemonic == "call" and
                    i.operands and i.operands[0].type == 2 and i.operands[0].imm == 0x70D10
                    for i in ins):
        fail("game() no longer passes the mapped static title object to the original PlugIn")
    quit_flag_guest = image.link_to_linear(0x117464)
    if not any(i.mnemonic == "test" and f"{quit_flag_guest:#x}" in i.op_str and
               i.op_str.endswith(", 1") for i in ins):
        fail("original game() no longer tests GameControl::__Flags bit zero")

    load_all = dis.disassemble_function(0x15090)
    if load_all is None or load_all.end - load_all.address != 0x34:
        fail("LbDataLoadAll_ instruction boundary changed")
    lifted = Lifter().lift_function(load_all).replace(
        "void sub_00015090(void) {", "void gw_original_title_loadall(void) {", 1)
    lifted = lifted.replace("{\n", "{\n    RECOMP_REGS_LOCALS\n", 1)
    generated = ROOT / "build" / f"{artifact_stem}_lift.c"
    generated.write_text(
        '#define RECOMP_GENERATED_CODE\n#include "recomp_types.h"\n'
        '#include "recomp_context.h"\n#include "gw_recomp_stop.h"\n'
        '#include "gw_segments.h"\nvoid sub_00014FF0(void);\n' + lifted,
        encoding="utf-8")
    guest = ROOT / "build" / f"{artifact_stem}_guest.bin"
    guest.write_bytes(image.mem)

    exe = ROOT / "build" / f"test_{artifact_stem}.exe"
    env = {**os.environ,
           "GW_TITLE_LOADALL_GUEST": str(guest),
           "PATH": (_GW_MSYS2 + '\\mingw32\\bin;' + _GW_MSYS2 + '\\usr\\bin;') + os.environ.get("PATH", "")}
    command = [(_GW_MSYS2 + '\\mingw32\\bin\\gcc.exe'), "-std=gnu11", "-m32", "-O0",
               "-I", str(ROOT / "runtime"),
               "-I", str(ROOT / "third_party" / "pcrecomp" / "runtime" / "recomp32"),
               "-o", str(exe), str(ROOT / "tests" / "test_authentic_title_loadall.c"),
               str(generated), str(ROOT / "runtime" / "recomp_context.c"),
               str(ROOT / "runtime" / "gw_interrupts.c"), str(ROOT / "runtime" / "gw_segments.c"),
               str(ROOT / "runtime" / "gw_pit8254.c"), str(ROOT / "runtime" / "recomp_bridge.c")]
    built = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True)
    print(built.stdout, end="")
    print(built.stderr, end="")
    if built.returncode:
        raise SystemExit(built.returncode)
    ran = subprocess.run([str(exe)], cwd=ROOT, env=env, text=True, capture_output=True)
    print(ran.stdout, end="")
    print(ran.stderr, end="")
    if ran.returncode:
        raise SystemExit(ran.returncode)

    evidence = {
        "schema": "gw-authentic-title-loadall-validation/v1",
        "target_sha256": target_hash,
        "source_map_sha256": map_hash,
        "authority": "exact 1.1 LE and byte-identical imported symbol MAP; no 1.0 addresses transferred",
        "rea": {
            "provider": "Ghidra 12.1.4 via REA 6.4.0",
            "game_evidence": "ev_2e9c4630d062076a3ec424c279a67f7da7afb6de2731bd5d0df204775f0341da",
            "title_plugin_evidence": "ev_a0acd0dc147af656dd9431cd547a7784e18ea466e597be0074895edeb697aa06",
            "loadall_evidence": "ev_a7518b3b876adbad53fed0850489a95fd10726a2f5773c848b76b7da676a8a54",
            "current_ifc_xrefs": "ev_1d622f1d6823fae17a585f30841d157b87ff59e87e54be1309de28749fea4b69",
            "game_flags_xrefs": "ev_6386eec9f66d59cd3f9ce99414a04f105f85d2599bd64cd8a28aed090a9dfdd6"
        },
        "validated_symbol_entries": {name: {"segment": seg, "link_va": hex(va),
                                               "guest_linear": hex(image.link_to_linear(va)),
                                               "map_label": label}
                                     for name, (seg, va, label) in SYMBOLS.items()},
        "tbloadfiles": {"size": 44, "fields": {"FName": 0, "Start": 28, "SEnd": 32,
                                                    "SLength": 36, "Flags": 40, "Spare": 42},
                        "titleGfx_files_guest_linear": hex(table_va), "records": records,
                        "terminator_index": 4},
        "game_loop": {"entry": "0x92710", "title_plugin_call": "0x70D10",
                      "title_object_link_va": hex(title_object_link),
                      "title_object_guest_linear": hex(title_object_guest),
                      "title_object_first_32_bytes_before_runtime_initializers": title_object_raw.hex(),
                      "title_object_pre_runtime_bytes_all_zero": not any(title_object_raw),
                      "note": "game() passes this object to PlugIn; the raw LE is pre-runtime state, so an isolated call must execute the authentic initializer first",
                      "quit_flag_byte_link_va": "0x117464",
                      "quit_flag_byte_guest_linear": hex(quit_flag_guest),
                      "exit_test": f"TEST byte ptr [{quit_flag_guest:#x}], 1 after the object-3 rebase",
                      "meaning": "bit 0 gates loop termination; it is not a title-to-menu transition"},
        "execution": {"function": "LbDataLoadAll_", "link_va": "0x15090",
                      "execution_mode": "original_recompiled_instructions",
                      "native_load_function": "bounded call boundary returning DOS/resource failure 0",
                      "resource_load_claim": False,
                      "purpose": "execute authentic table walk and error-count logic over the original titleGfx_files[]"},
        "build": {"compile_exit": built.returncode, "run_exit": ran.returncode,
                  "stdout": ran.stdout.strip(),
                  "generated_sha256": hashlib.sha256(generated.read_bytes()).hexdigest(),
                  "executable_sha256": hashlib.sha256(exe.read_bytes()).hexdigest()},
        "passed": True
    }
    path = ROOT / "evidence" / f"{artifact_stem}_validation.json"
    path.write_text(__import__("json").dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(f"evidence: {path}")


if __name__ == "__main__":
    main()
