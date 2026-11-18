#!/usr/bin/env python3
"""Build a bounded exact-target CFG from setup_game continuation to W_SCREEN call."""
from __future__ import annotations

import hashlib
import json
import re
from collections import deque
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "evidence/genewars-1_1.exe"
CODE = ROOT / "evidence/genewars-1_1.bytes"
DISASM = ROOT / "evidence/genewars-1_1-le_disasm.s"
W3156 = ROOT / "evidence/w3_156_wscreen_loader_callsite.json"
W3158 = ROOT / "evidence/w3_158_loader_call_discriminator.json"
RESULT = ROOT / "evidence/w3_159_wscreen_call_cfg.json"
TARGET_SHA = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
CODE_SHA = "899a99dad400558ca64ecae803ce7e6d1f6e631e64bb3f45300a1a779f0c6004"
DISASM_SHA = "dcad6dc4e0f836dba0fa0a63664b1e350c05592dc02b2ceeaa4c6788f68d5271"
CODE_BASE = 0x10000
START = 0x94AE9
END = 0x94DC1
CALL = 0x94DBC
LOADER = 0x15090


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_target(op_str: str) -> int | None:
    m = re.fullmatch(r"\s*(?:0x)?([0-9a-fA-F]+)\s*", op_str)
    if not m:
        return None
    return int(m.group(1), 16)


def build_cfg(data: bytes, start: int = START, end: int = END, call_va: int = CALL) -> dict:
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    instructions = list(md.disasm(data[start - CODE_BASE:end - CODE_BASE], start))
    ins_by_addr = {ins.address: ins for ins in instructions}
    leaders = {start}
    for ins in instructions:
        next_ip = ins.address + ins.size
        if ins.group(CS_GRP_JUMP):
            target = parse_target(ins.op_str)
            if target is not None and start <= target < end:
                leaders.add(target)
            if ins.mnemonic not in ("jmp", "ljmp") and start <= next_ip < end:
                leaders.add(next_ip)
        elif ins.group(CS_GRP_RET) or ins.mnemonic.startswith("ret"):
            if start <= next_ip < end:
                leaders.add(next_ip)
    blocks: dict[int, dict] = {}
    ordered_leaders = sorted(x for x in leaders if x in ins_by_addr)
    for leader_index, leader in enumerate(ordered_leaders):
        next_leader = ordered_leaders[leader_index + 1] if leader_index + 1 < len(ordered_leaders) else end
        current = leader
        block_instructions = []
        while current in ins_by_addr and current < next_leader:
            ins = ins_by_addr[current]
            block_instructions.append({"address": ins.address, "bytes": ins.bytes.hex(),
                                       "mnemonic": ins.mnemonic, "operands": ins.op_str})
            next_ip = ins.address + ins.size
            is_jump = ins.group(CS_GRP_JUMP)
            is_ret = ins.group(CS_GRP_RET) or ins.mnemonic.startswith("ret")
            if is_jump or is_ret:
                break
            current = next_ip
        if not block_instructions:
            continue
        last = ins_by_addr[block_instructions[-1]["address"]]
        next_ip = last.address + last.size
        edges = []
        if last.group(CS_GRP_JUMP):
            target = parse_target(last.op_str)
            conditional = last.mnemonic not in ("jmp", "ljmp")
            edges.append({"kind": "conditional_taken" if conditional else
                                  ("indirect_jump" if target is None else "jump"),
                          "from": last.address, "to": target,
                          "in_range": target is not None and start <= target < end,
                          "condition": last.mnemonic if conditional else None})
            if conditional:
                edges.append({"kind": "fallthrough", "from": last.address, "to": next_ip,
                              "in_range": next_ip < end})
        elif last.group(CS_GRP_RET) or last.mnemonic.startswith("ret"):
            edges.append({"kind": "return", "from": last.address, "to": None, "in_range": False})
        else:
            edges.append({"kind": "fallthrough", "from": last.address, "to": next_ip,
                          "in_range": next_ip < end})
        for ins in (ins_by_addr[row["address"]] for row in block_instructions):
            if ins.group(CS_GRP_CALL):
                target = parse_target(ins.op_str)
                edges.append({"kind": "call", "from": ins.address, "to": target,
                              "in_range": target is not None and start <= target < end})
                edges.append({"kind": "call_return", "from": ins.address,
                              "to": ins.address + ins.size, "in_range": ins.address + ins.size < end})
        blocks[leader] = {"start": leader, "end_exclusive": next_ip,
                          "instructions": block_instructions, "edges": edges}
    reachable = set()
    q = deque([start])
    while q:
        node = q.popleft()
        if node in reachable:
            continue
        reachable.add(node)
        block = blocks.get(node)
        if not block:
            continue
        for edge in block["edges"]:
            if edge.get("kind") != "call" and edge.get("in_range") and edge.get("to") in blocks:
                q.append(edge["to"])
    reachable_instruction_addresses = {ins["address"] for k in reachable
                                       for ins in blocks[k]["instructions"]}
    all_ins = {ins.address: {"address": ins.address, "bytes": ins.bytes.hex(),
                             "mnemonic": ins.mnemonic, "operands": ins.op_str}
               for ins in instructions}
    call_instruction = all_ins.get(call_va)
    call_block = next((b for b in blocks.values()
                       if any(ins["address"] == call_va for ins in b["instructions"])), None)
    previous = max((a for a in all_ins if a < call_va), default=None)
    conditional_edges = []
    for block in blocks.values():
        for ins in block["instructions"]:
            if ins["mnemonic"].startswith("j") and ins["mnemonic"] not in ("jmp", "ljmp"):
                conditional_edges.append({"address": ins["address"], "bytes": ins["bytes"],
                                          "mnemonic": ins["mnemonic"], "operands": ins["operands"]})
    route_parent: dict[int, tuple[int, dict]] = {}
    route_queue = deque([start])
    route_seen = {start}
    while route_queue and call_block and call_block["start"] not in route_seen:
        node = route_queue.popleft()
        for edge in blocks.get(node, {}).get("edges", []):
            target = edge.get("to")
            if edge.get("kind") != "call" and edge.get("in_range") and target in blocks and target not in route_seen:
                route_seen.add(target)
                route_parent[target] = (node, edge)
                route_queue.append(target)
    route = []
    if call_block and call_block["start"] in route_seen:
        node = call_block["start"]
        while node != start:
            prior, edge = route_parent[node]
            route.append({"from_block": prior, "edge": edge, "to_block": node})
            node = prior
        route.reverse()
    return {"start": start, "end_exclusive": end,
            "reached_callsite_static": call_va in reachable_instruction_addresses,
            "call_instruction": call_instruction,
            "callsite_block_start": call_block["start"] if call_block else None,
            "route_to_callsite": route,
            "callsite_previous_instruction": all_ins.get(previous),
            "conditional_instructions": sorted(conditional_edges, key=lambda x: x["address"]),
            "blocks": [blocks[k] for k in sorted(blocks)],
            "reachable_block_starts": sorted(reachable)}


def main() -> int:
    for path in (TARGET, CODE, DISASM, W3156, W3158):
        if not path.is_file():
            raise FileNotFoundError(path)
    target_sha, code_sha, disasm_sha = sha(TARGET), sha(CODE), sha(DISASM)
    if (target_sha, code_sha, disasm_sha) != (TARGET_SHA, CODE_SHA, DISASM_SHA):
        raise RuntimeError("exact-target or extracted-code provenance mismatch")
    prior = json.loads(W3156.read_text(encoding="utf-8"))
    dynamic = json.loads(W3158.read_text(encoding="utf-8"))
    if prior["provenance"]["target_sha256"] != TARGET_SHA:
        raise RuntimeError("W3-156 static callsite evidence targets another binary")
    cfg = build_cfg(CODE.read_bytes())
    if cfg["call_instruction"] is None or cfg["call_instruction"]["bytes"] != "e8cf02f8ff":
        raise RuntimeError("exact 0x94DBC instruction bytes do not match W3-156")
    result = {
        "schema": "w3-159-exact-target-wscreen-call-cfg/v1", "task": "W3-159",
        "provenance": {"target_sha256": target_sha, "code_object_bytes_sha256": code_sha,
                       "disassembly_sha256": disasm_sha, "code_object_link_base": hex(CODE_BASE),
                       "static_call_evidence": "evidence/w3_156_wscreen_loader_callsite.json",
                       "dynamic_run_evidence": "evidence/w3_158_loader_call_discriminator.json"},
        "range": {"start": hex(START), "end_exclusive": hex(END), "loader_callsite": hex(CALL),
                  "loader_entry": hex(LOADER)},
        "cfg": cfg,
        "call_target_verified": cfg["call_instruction"]["bytes"] == prior["w_screen_loader"]["call_bytes"] and
                                prior["w_screen_loader"]["target_link_va"] == hex(LOADER),
        "call_gate": [
            {"link_va": "0x94ce1", "bytes": "0f85b8000000", "condition": "JNE",
             "tested_value": "byte [0x117662] bit 0 != 0", "taken_target": "0x94d9f",
             "effect": "bypasses the second test and enters the W_SCREEN loader block"},
            {"link_va": "0x94cee", "bytes": "0f85ab000000", "condition": "JNE",
             "tested_value": "byte [0x1174a4] != 0", "taken_target": "0x94d9f",
             "effect": "enters the W_SCREEN loader block when the first gate fell through"},
            {"link_va": "0x94cf4", "bytes": "f6c301", "condition": "TEST BL,1; JE",
             "tested_value": "BL bit 0", "taken_target": "0x94d03",
             "effect": "when both W_SCREEN gates fall through, execution proceeds to startup-file/resource cleanup and mode dispatch, not 0x94d9f"}
        ],
        "gate_global_references_in_range": {
            "0x117662": [
                {"link_va": "0x94c85", "instruction": "or byte ptr [0x117662], 1",
                 "effect": "sets bit 0 only after the prior file-length comparison equals 0x17be71c"},
                {"link_va": "0x94cda", "instruction": "test byte ptr [0x117662], 1",
                 "effect": "tests bit 0 and branches to 0x94d9f when set"}],
            "0x1174a4": [
                {"link_va": "0x94b2a", "instruction": "cmp byte ptr [0x1174a4], 0",
                 "effect": "read; used to derive an earlier local value"},
                {"link_va": "0x94ce7", "instruction": "cmp byte ptr [0x1174a4], 0",
                 "effect": "read; branches to 0x94d9f if nonzero"}],
            "scope_limit": "These are references in the analyzed range only; the origin of 0x1174a4 is not established here."},
        "dynamic_reconciliation": {
            "w3_158_setup_entry": dynamic["checkpoints"].get("callsite"),
            "w3_158_loader_entry": dynamic["checkpoints"].get("loader_entry"),
            "w3_158_call_return": dynamic["checkpoints"].get("call_return"),
            "w3_158_later_copy_pre": dynamic["checkpoints"].get("first_copy_pre"),
            "runtime_branch_values_for_this_cfg": "not captured; static branches do not establish the executed path"},
        "interpretation": {"callsite_statically_reachable_from_continuation": cfg["reached_callsite_static"],
                           "dynamic_call_observed_in_w3_158": bool(dynamic["checkpoints"].get("callsite")),
                           "why_dynamic_callsite_absent": "unknown from current evidence; the static gate supplies concrete candidate conditions, but neither was measured in W3-158"}}
    RESULT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(RESULT), "blocks": len(cfg["blocks"]),
                      "conditional_instructions": len(cfg["conditional_instructions"]),
                      "static_callsite_reachable": cfg["reached_callsite_static"],
                      "callsite_block": cfg["callsite_block_start"],
                      "route_blocks": len(cfg["route_to_callsite"])}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
