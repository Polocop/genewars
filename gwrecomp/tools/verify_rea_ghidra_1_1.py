#!/usr/bin/env python3
"""Validate persisted controlled-PE and GeneWars 1.1 REA/Ghidra Evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

EXPECTED_SOURCE_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"


def check(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["schema"] == "rea-ghidra-genewars-1.1-analysis-v1"
    assert data["target"]["sha256"] == EXPECTED_SOURCE_SHA256
    assert data["rea"]["provider"]["id"] == "ghidra"
    assert data["rea"]["provider"]["version"] == "12.1.4"
    assert data["rea"]["package_version"] == "6.4.0"
    assert data["rea"]["exit_code"] == 0
    assert data["rea"]["analysis_seeds"]["entries"]["function"] == 6
    assert data["rea"]["analysis_seeds"]["path"].endswith("\\seeds.tsv")
    fn = data["function"]
    assert fn["verified_map_seed"]["name"] == "LbScreenSetup_"
    assert fn["verified_map_seed"]["link_va"] == 0x962F0
    assert fn["procedure"]["address"] == "0x962f0"
    assert fn["procedure"]["body"]["ranges"] == [{"start": "0x962f0", "end": "0x962ff"}]
    assert fn["boundaries_match_capstone"] is True
    assert fn["bytes_identical_after_loader_mapping"] is True
    assert fn["pe_va_start"] == fn["link_va_start"] == 0x962F0
    assert fn["pe_rva_start"] == 0x952F0
    assert len(fn["original_le_file_offsets_per_byte"]) == 16
    assert len(fn["capstone_instructions"]) == 8
    assert "LbScreenSetupAnyMode_" in fn["pseudocode"]
    assert fn["rea_call_reference_count"] > 0
    assert any(x["target_address"] == "0x962f0" for x in fn["rea_incoming_references"])

    manifest_path = Path(data["target"]["manifest_path"])
    manifest_bytes = manifest_path.read_bytes()
    assert hashlib.sha256(manifest_bytes).hexdigest() == data["target"]["manifest_sha256"]
    manifest = json.loads(manifest_bytes)
    assert manifest["le"]["fixup_count"] == 25204
    assert manifest["carrier"]["additional_carrier_relocation_count"] == 0
    assert manifest["carrier"]["image_base"] == 0x1000
    assert manifest["carrier"]["sha256"] == data["target"]["carrier_sha256"]

    lx = json.loads((path.parent / "lx_loader_build.json").read_text(encoding="utf-8"))
    assert lx["status"] == "BUILD_SUCCESSFUL" and lx["exit_code"] == 0
    assert lx["ghidra_version"] == "12.1.4" and lx["gradle_version"] == "9.7.1"
    extension_zip = Path(lx["extension_zip"])
    assert hashlib.sha256(extension_zip.read_bytes()).hexdigest() == lx["extension_zip_sha256"]
    assert lx["modified_ghidra_installation"] is False
    assert lx["protected_gene_wars_fx_modified"] is False

    fixture = data["controlled_pe32_validation"]
    assert fixture["fixture_sha256"] == "2161d1cbd7b79160c5a5a85fe55adde6275d1a397d8a0bc4d7fd2cdf1741a58c"
    commands = fixture["commands"]
    by_name = {record["command"][0]: record for record in commands}
    assert {"inspect", "function", "decompile"}.issubset(by_name)
    for record in commands:
        assert record["exit_code"] == 0
    pe_function = json.loads(by_name["function"]["stdout"])
    assert pe_function["provider"]["id"] == "ghidra"
    assert pe_function["provider"]["version"] == "12.1.4"
    assert "return 0x2c" in pe_function["raw_result"]["value"]["pseudocode"]
    assert pe_function["raw_result"]["value"]["assembly"][0].startswith("0x401000:")
    return {"status": "PASS", "provider": "REA 6.4.0 / Ghidra 12.1.4",
            "carrier_sha256": manifest["carrier"]["sha256"],
            "fixup_sites": manifest["le"]["fixup_count"],
            "function": "LbScreenSetup_ at LE/PE VA 0x962f0",
            "capstone_instruction_count": len(fn["capstone_instructions"]),
            "incoming_call_references": fn["rea_call_reference_count"],
            "controlled_fixture_decompilation": "return 0x2c"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("analysis", type=Path)
    args = parser.parse_args()
    print(json.dumps(check(args.analysis), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
