#!/usr/bin/env python3
"""Compare the opt-in function-entry counter (runtime/gw_func_coverage.c) with trace-based coverage.

Inputs are produced by a bounded native replay (see run-evidence/replay_recipe_turn725_730.md):
  --coverage  JSON written by the counter (GWRECOMP_FUNC_COVERAGE=1, schema gw-function-coverage/v1)
  --on-stderr stderr of the counter-enabled run
  --off-stderr stderr of the same exe with the counter unset (optional, neutrality check)
  --out       comparison JSON to write (schema gw-function-coverage-compare/v1)

Trace-based coverage is the set of func=XXXXXXXX values seen in TRACE lines of --on-stderr. That is
the limitation the counter replaces: it only sees functions that happen to print a trace line.
Behaviour lines are the input_index_source and global_180c44 TRACE lines, which the earlier replays
used as the observable check. Equal lines between the on and off runs show the counter did not
change the observed behaviour. This is a check of the observed lines only, not of playability.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

FUNC_RE = re.compile(r"func=([0-9A-Fa-f]{8})")
BEHAVIOUR_RE = re.compile(r"TRACE (input_index_source|global_180c44_)")
SUMMARY_RE = re.compile(r"TRACE func_coverage_summary .*")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def behaviour_lines(path: Path) -> list[str]:
    return [line.rstrip("\r\n") for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
            if BEHAVIOUR_RE.search(line)]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--coverage", required=True, type=Path)
    parser.add_argument("--on-stderr", required=True, type=Path)
    parser.add_argument("--off-stderr", type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    coverage = json.loads(args.coverage.read_text(encoding="utf-8"))
    schema_ok = coverage.get("schema") == "gw-function-coverage/v1"
    entered = coverage.get("entered", [])
    counter_vas = {int(item["va"], 16) for item in entered}
    integrity = coverage.get("integrity", {})

    on_text = args.on_stderr.read_text(encoding="utf-8", errors="replace")
    trace_vas = {int(m, 16) for m in FUNC_RE.findall(on_text)}
    summary_lines = SUMMARY_RE.findall(on_text)

    on_behaviour = behaviour_lines(args.on_stderr)
    report = {
        "schema": "gw-function-coverage-compare/v1",
        "inputs": {
            "coverage_json": str(args.coverage),
            "coverage_json_sha256": sha256(args.coverage),
            "on_stderr": str(args.on_stderr),
            "on_stderr_sha256": sha256(args.on_stderr),
        },
        "counter": {
            "schema_ok": schema_ok,
            "total_entries": coverage.get("total_entries"),
            "distinct_functions": coverage.get("distinct_functions"),
            "overflow_entries": coverage.get("overflow_entries"),
            "entered_len": len(entered),
            "integrity": integrity,
        },
        "trace_func_limited": {
            "distinct_func_in_trace": len(trace_vas),
            "func_in_trace_not_in_counter": sorted(f"0x{v:08X}" for v in trace_vas - counter_vas),
            "counter_not_in_trace": len(counter_vas - trace_vas),
        },
        "summary_line": summary_lines[-1] if summary_lines else None,
        "behaviour": {
            "on_lines": len(on_behaviour),
        },
    }

    if args.off_stderr:
        off_behaviour = behaviour_lines(args.off_stderr)
        report["inputs"]["off_stderr"] = str(args.off_stderr)
        report["inputs"]["off_stderr_sha256"] = sha256(args.off_stderr)
        report["behaviour"]["off_lines"] = len(off_behaviour)
        report["behaviour"]["identical_on_vs_off"] = on_behaviour == off_behaviour
        report["behaviour"]["first_difference"] = next(
            ({"index": i, "on": a, "off": b} for i, (a, b) in enumerate(zip(on_behaviour, off_behaviour)) if a != b),
            None if len(on_behaviour) == len(off_behaviour) else {"index": min(len(on_behaviour), len(off_behaviour)),
                                                                   "on": None, "off": None},
        )

    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"WROTE {args.out} entered={len(entered)} trace_func={len(trace_vas)} schema_ok={schema_ok}")
    return 0 if schema_ok else 1


if __name__ == "__main__":
    sys.exit(main())
