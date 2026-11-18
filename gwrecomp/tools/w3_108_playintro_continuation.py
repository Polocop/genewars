from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TARGET_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"

INPUTS = {
    "disassembly": "evidence/genewars-1_1-le_disasm.s",
    "map": "evidence/genewars-1_1.map",
    "closure": "build/entry_path_closure.c",
    "video_preflight": "evidence/video_closure_preflight_work1.json",
    "prior_callers": "evidence/w3_104_vesa_page_callers.json",
    "dynamic_capture": "evidence/w3_107_main_transition.json",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require(text: str, needles: tuple[str, ...], label: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise ValueError(f"{label}: required exact evidence missing: {missing}")


def extract_closure_instructions(source: str) -> dict[int, str]:
    """Extract address/opcode comments from corrected-VA lifted closure C."""
    return {
        int(address, 16): instruction.strip()
        for address, instruction in re.findall(r"/\*\s*(0x[0-9A-Fa-f]+):\s*(.*?)\s*\*/", source)
    }


def derive_screen_setup_return_chain(instructions: dict[int, str]) -> list[dict[str, str]]:
    expected = {
        0x9FEAF: "ret",
        0x962F7: "call 0x9fd40",
        0x962FC: "add esp, 0x10",
        0x962FF: "ret",
        0x92A11: "call 0x962f0",
        0x92A16: "mov ebx, 1",
    }
    for address, opcode in expected.items():
        actual = instructions.get(address, "").lower()
        if actual != opcode:
            raise ValueError(f"return-chain mismatch at 0x{address:08X}: expected {opcode!r}, got {actual!r}")
    return [
        {"link_va": f"0x{address:08X}", "instruction": expected[address]}
        for address in (0x9FEAF, 0x962F7, 0x962FC, 0x962FF, 0x92A11, 0x92A16)
    ]


def build_evidence() -> dict:
    paths = {name: ROOT / relative for name, relative in INPUTS.items()}
    blobs = {name: path.read_text(encoding="utf-8") for name, path in paths.items()}
    parsed = json.loads(blobs["dynamic_capture"])
    fixture_hash = parsed["preflight"]["fixture_sha256"]
    if fixture_hash != TARGET_SHA256:
        raise ValueError("W3-107 capture target hash does not match the pinned 1.1 target")

    asm = blobs["disassembly"]
    closure = blobs["closure"]
    closure_instructions = extract_closure_instructions(closure)
    return_chain = derive_screen_setup_return_chain(closure_instructions)
    map_text = blobs["map"]
    require(map_text, (
        "0001:00092930       W?PlayIntro$n()v",
        "0001:000929D0       W?PlaySmacker$n(pnaucuc)v",
        "0001:000962F0       LbScreenSetup_",
        "0001:0009FD40       LbScreenSetupAnyMode_",
    ), "MAP")
    require(asm, (
        "PlayIntro:\t/* 0x92930 */",
        "PlaySmacker:\t/* 0x929d0 */",
        "LbScreenSetup_:\t/* 0x962f0 */",
        "LbScreenSetupAnyMode_:\t/* 0x9fd40 */",
        "call   LbVesaSetMode_",
        "movl   $0xa0000,_lbDisplay",
    ), "disassembly")
    require(closure, (
        "/* 0x00092A11: call 0x962f0 */",
        "/* 0x00092A16: mov ebx, 1 */",
        "/* 0x00092ADD: call 0xae2d0 */",
        "/* 0x0009FEAF: ret  */",
        "/* 0x000962FF: ret  */",
        "/* 0x00092983: call 0x929d0 */",
        "/* 0x00092996: call 0x929d0 */",
        "/* 0x000929A9: call 0x929d0 */",
    ), "corrected-VA closure")

    target_events = parsed["trace"]["target_events"]
    observed_names = [event.get("checkpoint") for event in target_events]
    observed_links = [event.get("link_va") for event in target_events]
    # W3-107 directly observed the mode callsite/entry and assignment checkpoint;
    # it did not instrument the wrapper return at 0x92A16.
    if 0x9FDF9 not in observed_links:
        # The capture stores some video sub-events as named events rather than
        # target_runtime_checkpoint; validate the documented ordered frontier.
        if "VIDEO_FRAMEBUFFER_ASSIGN_AFTER" not in observed_names:
            raise ValueError("W3-107 has no measured post-mode assignment checkpoint")

    records = [
        {"link_va": "0x0009FDCC", "owner": "LbScreenSetupAnyMode_", "instruction": "call LbVesaSetMode_", "relation": "W3-107 dynamically observed mode callsite"},
        {"link_va": "0x0009FDF9", "owner": "LbScreenSetupAnyMode_", "instruction": "movsx esi, cl", "relation": "W3-107 dynamically observed post-assignment checkpoint; static continuation"},
        {"link_va": "0x0009FEAF", "owner": "LbScreenSetupAnyMode_", "instruction": "ret", "relation": "static function return to LbScreenSetup_"},
        {"link_va": "0x000962F7", "owner": "LbScreenSetup_", "instruction": "call LbScreenSetupAnyMode_", "relation": "static wrapper call"},
        {"link_va": "0x000962FC", "owner": "LbScreenSetup_", "instruction": "add esp, 0x10", "relation": "static stack cleanup after mode setup"},
        {"link_va": "0x000962FF", "owner": "LbScreenSetup_", "instruction": "ret", "relation": "static return to PlaySmacker"},
        {"link_va": "0x00092A11", "owner": "PlaySmacker", "instruction": "call LbScreenSetup_", "relation": "static caller of screen setup"},
        {"link_va": "0x00092A16", "owner": "PlaySmacker", "instruction": "mov ebx, 1", "relation": "earliest exact natural checkpoint after wrapper return"},
        {"link_va": "0x00092A24", "owner": "PlaySmacker", "instruction": "call LbMouseSetup_", "relation": "later setup progress checkpoint"},
        {"link_va": "0x00092A39", "owner": "PlaySmacker", "instruction": "call LbScreenClear_", "relation": "later setup progress checkpoint"},
        {"link_va": "0x00092ADD", "owner": "PlaySmacker", "instruction": "call play_smk_", "relation": "first intro media playback call after screen setup path"},
        {"link_va": "0x00092983", "owner": "PlayIntro", "instruction": "call PlaySmacker", "relation": "first of three static PlayIntro calls"},
        {"link_va": "0x00092996", "owner": "PlayIntro", "instruction": "call PlaySmacker", "relation": "second static PlayIntro call"},
        {"link_va": "0x000929A9", "owner": "PlayIntro", "instruction": "call PlaySmacker", "relation": "third static PlayIntro call"},
        {"link_va": "0x000929C0", "owner": "PlayIntro", "instruction": "call sub_000756C0", "relation": "static post-intro continuation"},
        {"link_va": "0x000929C8", "owner": "PlayIntro", "instruction": "ret", "relation": "static return to main_ after three PlaySmacker calls"},
        {"link_va": "0x00094347", "owner": "main_", "instruction": "call game", "relation": "W3-107 nominated dynamic next-main checkpoint; not observed"},
    ]
    return {
        "schema": "w3-108-playintro-continuation/v1",
        "task": "W3-108",
        "target_sha256": TARGET_SHA256,
        "inputs": {name: {"path": INPUTS[name], "sha256": sha256(path)} for name, path in paths.items()},
        "dynamic_evidence": {
            "source": "W3-107 original Staging capture",
            "source_sha256": sha256(paths["dynamic_capture"]),
            "observed_checkpoints": observed_names,
            "observed_link_vas": [f"0x{value:08X}" for value in observed_links],
            "code_rebase": "0x001EB000",
            "scope_limit": "The 30-second guarded run did not observe PlaySmacker return 0x92A16, PlayIntro return 0x929C4, or main_ game call 0x94347. It does not establish the last guest EIP at timeout.",
        },
        "static_chain": records,
        "first_exact_capture_frontier": {
            "link_va": "0x00092A16",
            "owner": "PlaySmacker",
            "why": "The nested return chain is LbScreenSetupAnyMode_ RET 0x9FEAF -> LbScreenSetup_ continuation 0x962FC and RET 0x962FF -> PlaySmacker instruction 0x92A16. This is the earliest exact instruction after the screen-setup wrapper returns.",
            "status": "STATIC_ONLY_NOT_DYNAMICALLY_OBSERVED",
        },
        "screen_setup_return_chain": return_chain,
        "next_distinguishing_frontiers": [
            {"link_va": "0x00092A24", "purpose": "confirm PlaySmacker proceeds into mouse setup"},
            {"link_va": "0x00092ADD", "purpose": "confirm PlaySmacker reaches the first intro media call"},
            {"link_va": "0x00092996", "purpose": "confirm first PlaySmacker returned to PlayIntro and second intro call begins"},
            {"link_va": "0x000929A9", "purpose": "confirm second PlaySmacker returned and third intro call begins"},
            {"link_va": "0x000929C8", "purpose": "confirm PlayIntro returns to main_"},
            {"link_va": "0x00094347", "purpose": "confirm main_ reaches game call"},
        ],
        "interpretation": "These links describe static reachability only. W3-107 dynamically observed main_, setup_game return, PlayIntro entry, and the VESA mode path; it did not observe these later return/caller checkpoints. The W3-107 timeout is not proof that PlayIntro remained active.",
        "handoff_recommendation": "A future narrow capture should add 0x92A16, 0x92A24, 0x92ADD, 0x92996, 0x929A9, 0x929C4, and 0x94347 with per-target caps; no replay is part of this task.",
    }


def main() -> None:
    evidence = build_evidence()
    output = ROOT / "evidence/w3_108_playintro_continuation.json"
    output.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(output)


if __name__ == "__main__":
    main()
