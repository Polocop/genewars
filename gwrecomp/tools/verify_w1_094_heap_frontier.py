#!/usr/bin/env python3
"""Validate the bounded native W1-094 heap-frontier receipt."""
from __future__ import annotations

import json
import pathlib
import sys

EXPECTED_TARGET = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"


def validate(path: pathlib.Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != "gwrecomp.native-heap-frontier-w1-094/v1":
        raise ValueError("unexpected W1-094 evidence schema")
    if data.get("task") != "W1-094" or data.get("fresh_replay") is not True:
        raise ValueError("fresh W1-094 native replay identity is missing")
    if data.get("target_sha256") != EXPECTED_TARGET:
        raise ValueError("evidence is not bound to canonical GeneWars 1.1")
    if data.get("guest_state_injected") is not False or data.get("original_equivalence_claimed") is not False:
        raise ValueError("evidence misstates guest injection or original equivalence")
    if not isinstance(data.get("stdout_sha256"), str) or len(data["stdout_sha256"]) != 64:
        raise ValueError("bounded native stdout digest is missing")
    lines = data.get("selected_lines")
    if not isinstance(lines, list):
        raise ValueError("selected native marker lines are missing")
    required = ("NATIVE_DPMI_GUEST_MEMORY_MAP ", "NATIVE_W1_093_HEAP_WINDOW_ARM ")
    if any(not any(line.startswith(prefix) for line in lines) for prefix in required):
        raise ValueError("native memory map or heap-window arm marker is missing")
    guard = next((line for line in lines if line.startswith("NATIVE_W1_093_REPEAT_GUARD ")), None)
    trap = next((line for line in lines if line.startswith("NATIVE_NEXT_TRAP ")), None)
    cpu = next((line for line in lines if line.startswith("NATIVE_FRONTIER_CPU ")), None)
    exception = next((line for line in lines if line.startswith("NATIVE_EXCEPTION ")), None)
    if data.get("native_replay_timed_out") is not False:
        raise ValueError("bounded replay did not terminate within its time budget")
    if guard is None and not ((trap is not None and cpu is not None) or exception is not None):
        raise ValueError("neither bounded repeat guard, complete natural CPU trap frontier, nor native exception frontier was captured")
    if guard is not None and "stop=identical_state_repeated" not in guard and "stop=state_budget" not in guard:
        raise ValueError("unexpected repeat-guard stop reason")
    return {"task": "W1-094", "frontier": "repeat_guard" if guard else "native_exception" if exception else "natural_trap",
            "repeat_guard": guard.split(" stop=", 1)[1].split()[0] if guard else None,
            "trap": trap.split()[1] if trap else None,
            "exception": exception.split()[1] if exception else None,
            "selected_line_count": len(lines), "target_sha256": data["target_sha256"]}


if __name__ == "__main__":
    try:
        print("PASS W1-094 heap frontier: " + json.dumps(validate(pathlib.Path(sys.argv[1])), sort_keys=True))
    except Exception as exc:
        print(f"FAIL W1-094 heap frontier: {exc}", file=sys.stderr)
        raise SystemExit(1)
