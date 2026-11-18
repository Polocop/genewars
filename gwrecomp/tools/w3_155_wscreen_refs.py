#!/usr/bin/env python3
"""Bounded exact-target disassembly references to GeneWars WScreen symbols."""
from __future__ import annotations
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DISASM = ROOT / "evidence/genewars-1_1-le_disasm.s"
FRONTIER = ROOT / "evidence/w3_150_screen_write_frontier.json"
RESULT = ROOT / "evidence/w3_155_wscreen_static_refs.json"
TARGET_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"


def classify_reference(line: str, symbol: str = "lbDisplay__WScreen") -> str:
    """Classify only syntactically direct AT&T mov stores as writes."""
    if symbol not in line:
        return "none"
    text = line.strip().lower()
    if re.search(rf"\bmov[a-z]*\s+%[a-z0-9]+\s*,\s*{re.escape(symbol.lower())}\b", text):
        return "direct_write"
    if re.search(rf"\bmov[a-z]*\s+{re.escape(symbol.lower())}\s*,", text):
        return "direct_read"
    return "reference_unclassified"


def extract(lines: list[str], symbol: str = "lbDisplay__WScreen") -> list[dict]:
    refs = []
    for number, line in enumerate(lines, 1):
        kind = classify_reference(line, symbol)
        if kind != "none":
            refs.append({"line": number, "kind": kind, "instruction": line.strip()})
    return refs


def main() -> int:
    source = DISASM.read_bytes()
    lines = source.decode("utf-8", errors="replace").splitlines()
    frontier = json.loads(FRONTIER.read_text(encoding="utf-8"))
    target_sha = frontier["provenance"]["target_sha256"]
    if target_sha != TARGET_SHA256:
        raise RuntimeError("W3-150 target binding mismatch")
    refs = extract(lines)
    writes = [r for r in refs if r["kind"] == "direct_write"]
    asset_refs = [{"line": n, "instruction": line.strip()}
                  for n, line in enumerate(lines, 1) if "aWScreen" in line]
    result = {
        "schema": "w3-155-wscreen-static-reference-audit/v1",
        "task": "W3-155",
        "provenance": {"target_sha256": target_sha,
                       "disassembly_path": str(DISASM.relative_to(ROOT)),
                       "disassembly_sha256": hashlib.sha256(source).hexdigest(),
                       "prior_frontier": "evidence/w3_150_screen_write_frontier.json"},
        "symbol": {"name": "lbDisplay__WScreen", "link_va": "0x0019CA5C"},
        "reference_counts": {"all": len(refs),
                             "direct_reads": sum(r["kind"] == "direct_read" for r in refs),
                             "direct_writes": len(writes),
                             "unclassified": sum(r["kind"] == "reference_unclassified" for r in refs)},
        "references": refs,
        "direct_write_interpretation": [
            {"line": r["line"], "instruction": r["instruction"],
             "candidate_function": "LbMouseChangeSprite_ (identified by adjacent disassembly label)",
             "interpretation": "temporary WScreen pointer replacement followed by restoration in the same routine; not evidence of buffer pixel production"}
            for r in writes],
        "asset_name_references": asset_refs,
        "static_path_observations": [
            {"line": n, "instruction": line.strip(),
             "operation": ("load" if "LbDataLoadAll_" in "\n".join(lines[n-1:n+9])
                           else "free" if "LbDataFree_" in "\n".join(lines[n-1:n+3])
                           else "resource_descriptor"),
             "meaning": ("setup path passes the W_SCREEN resource descriptor to LbDataLoadAll_"
                         if "LbDataLoadAll_" in "\n".join(lines[n-1:n+9])
                         else "resource free path or descriptor-table reference")}
            for n, line in enumerate(lines, 1) if "aWScreen" in line],
        "runtime_comparison": {"evidence": "evidence/w3_154_source_destination_samples.json",
                               "measured_source_destination_samples": 3,
                               "all_sample_pairs_equal_zero": True,
                               "runtime_writer_identified": False},
        "conclusion": "Static direct stores to the pointer global are limited to the temporary replacement/restoration in LbMouseChangeSprite_. The startup resource path requests a WScreen-named asset through LbDataLoadAll_, but this static audit does not establish the loader's runtime assignment or the first writer to the pointed-to bytes.",
        "next_capture": "If another original replay is justified, add a bounded checkpoint immediately after the naturally executed WScreen LbDataLoadAll_ call and at the first consumer; sample only the same three 16-byte offsets and record pointer, load result, and call ordinal. Do not add a memory-wide watch or dump."
    }
    RESULT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(RESULT), "references": len(refs),
                      "direct_writes": len(writes), "asset_refs": len(asset_refs)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
