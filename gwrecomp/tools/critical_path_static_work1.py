"""Build bounded offline caller/path evidence for W1-047; never launches a guest."""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

TARGET = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"


def _json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def _sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _symbol_va(path, symbol):
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[-1] == symbol and ":" in fields[0]:
            return int(fields[0].rsplit(":", 1)[1], 16)
    return None


def build_evidence(root):
    root = Path(root)
    ev = root / "evidence"
    orig_div = _json(ev / "native_ah44_register_divergence_work1.json")
    w3_061 = _json(ev / "ah44_call_entry_alignment_work3.json")
    seed = _json(ev / "native_startup_seed_parity_work3.json")
    post = _json(ev / "main_post_setup_frontier_work3.json")
    video = _json(ev / "video_closure_preflight_work1.json")
    if any(x.get("target_sha256") != TARGET for x in (orig_div, w3_061, seed, post)):
        raise ValueError("critical evidence does not match the pinned target")

    exact_map = Path(r"E:\GeneWarsFX\upstream\genewars-re-helpers\symbols\gw-genewars-1_1-nov_1996.map")
    beta_map = Path(r"E:\GeneWarsFX\upstream\genewars-re-helpers\symbols\gw-genewars-beta2-jul_1996-original_bld.map")
    source_root = Path(r"E:\GeneWarsFX\upstream\genewars")
    source_files = {
        "main": source_root / "bio/src/pcmain.cpp",
        "game": source_root / "bio/src/game.cpp",
        "screen": source_root / "bflibrary/src/x86-dos-watcom/sscreen.cpp",
        "vesa": source_root / "bflibrary/src/x86-dos-watcom/svesa.cpp",
    }
    source_repo = subprocess.run(["git", "-C", str(source_root), "rev-parse", "HEAD"],
                                 check=True, capture_output=True, text=True).stdout.strip()

    callsite_notes = {
        "0x000AFCEF": {
            "caller": "sopen_",
            "entry_eax": "DOS handle carried in EDI; preceding DOS AH=3Dh result is rotated and saved at [ESP], then low word is loaded into DI on success",
            "guard": "open flags at [ESP+0x28] select the path; EDI must not be 0xFFFFFFFF",
            "memory_inputs": ["open result [ESP]", "open flags [ESP+0x28]", "option byte [ESP+0x29]"],
            "confidence": "high static local dataflow; dynamic callsite unconfirmed",
        },
        "0x000AFE09": {
            "caller": "sopen_",
            "entry_eax": "EDI file descriptor after __IOMode_ returns and EAX is restored from EDI",
            "guard": "follows the secondary sopen_ mode path; no proof this is the runtime occurrence",
            "memory_inputs": ["EDI descriptor", "data_10BA14 mode table via __IOMode_"],
            "confidence": "high static local dataflow; dynamic callsite unconfirmed",
        },
        "0x000C89C7": {
            "caller": "__IOMode_",
            "entry_eax": "EDX, copied from __IOMode_ input EAX; descriptor/index argument remains in EDX",
            "guard": "index below data_10B9C0 and <= 5; mode-table byte at data_10BA14 + 4*index must lack bit 0x40",
            "memory_inputs": ["data_10B9C0", "data_10BA14 indexed table", "table flag byte +1"],
            "confidence": "high static local dataflow; dynamic caller unconfirmed",
        },
        "0x000BA4E4": {
            "caller": "__chktty_",
            "entry_eax": "FILE-like object field [entry EAX + 0x10], after preserving object pointer in EDX",
            "guard": "skip if byte [object + 0x0D] already has bit 0x20",
            "memory_inputs": ["stream flag byte +0x0D", "stream handle field +0x10"],
            "confidence": "high static local dataflow; dynamic caller unconfirmed",
        },
        "0x000B0181": {
            "caller": "_AIL_startup",
            "entry_eax": "FILE-like object field [EAX + 0x10] from fopen_ result stored in _file",
            "guard": "only if fopen_ succeeded and returned non-null _file",
            "memory_inputs": ["_file", "FILE-like handle field +0x10", "getenv_ result"],
            "confidence": "high static local dataflow; dynamic caller unconfirmed",
        },
    }
    callers = []
    for row in orig_div["candidate_callers_from_canonical_closure"]:
        m = re.fullmatch(r"(0x[0-9A-Fa-f]+) in (.+)", row)
        if not m:
            raise ValueError(f"unrecognized caller entry: {row}")
        site, caller = m.groups()
        site = f"0x{int(site, 16):08X}"
        note = callsite_notes.get(site)
        if note is None:
            raise ValueError(f"missing local dataflow note for {site}")
        callers.append({"callsite": site, **note})

    funcs = video["functions"]
    video_path = []
    for va in ("0x0009FD40", "0x000A3A00", "0x000A3A5C"):
        f = funcs.get(va)
        if f is None:
            raise ValueError(f"missing Core preflight for {va}")
        video_path.append({"va": va, "name": f["name"], "direct_callees": f["direct_calls"],
                           "indirect_calls": f["indirect_calls"], "tail_calls": f["tail_calls"],
                           "int10_sites": f["int10_sites"], "unsupported_markers": f["unsupported_markers"],
                           "segment_memory_bridge_sites": f["segment_memory_bridge_sites"],
                           "body_present": f["body_present"]})

    symbols = {
        "main_": (0x00093F30, "main_"),
        "setup_game": (0x00094AC0, "W?setup_game$n()v"),
        "PlayIntro": (0x00092930, "W?PlayIntro$n()v"),
        "game": (0x00092710, "W?game$n()v"),
        "LbScreenSetupAnyMode_": (0x0009FD40, "LbScreenSetupAnyMode_"),
        "LbVesaSetMode_": (0x000A3A00, "LbVesaSetMode_"),
        "LbVesaSetPage_": (0x000A3A5C, "LbVesaSetPage_"),
        "isatty_": (0x000C896A, "isatty_"),
    }
    source_matches = []
    source_candidates = {
        "main_": {"path": str(source_files["main"]), "candidate_va_comment": None,
                  "similarity": "static call order: setup_game -> optional PlayIntro -> game -> StopMusic -> reset_game -> LbMemoryReset",
                  "confidence": "medium for source-level call order; not proven exact machine-source build"},
        "PlayIntro": {"path": str(source_files["game"]), "candidate_va_comment": "0x0005F640",
                      "similarity": "symbol/function name matches; source has a shorter one-intro path than exact 1.1 assembly's three PlaySmacker calls",
                      "confidence": "low behavioral candidate; address/body mismatch"},
        "LbScreenSetupAnyMode_": {"path": str(source_files["screen"]), "candidate_va_comment": "0x000954E0",
                                  "similarity": "name matches; source body is a placeholder and its address matches Beta2 original_bld, not exact 1.1",
                                  "confidence": "low; nomenclature only, no body match"},
        "LbVesaSetMode_": {"path": str(source_files["vesa"]), "candidate_va_comment": "0x000B2838",
                           "similarity": "name matches; source body is a placeholder and its address matches Beta2 original_bld, not exact 1.1",
                           "confidence": "low; nomenclature only, no body match"},
        "LbVesaSetPage_": {"path": str(source_files["vesa"]), "candidate_va_comment": "0x000B2894",
                           "similarity": "name matches; source body is a placeholder and its address matches Beta2 original_bld, not exact 1.1",
                           "confidence": "low; nomenclature only, no body match"},
        "isatty_": {"path": None, "candidate_va_comment": None,
                    "similarity": "no Open Watcom CRT source or matching C implementation found in the bounded local candidate trees",
                    "confidence": "unresolved; exact pinned target disassembly and 1.1 map remain authority"},
    }
    for name, (address, map_symbol) in symbols.items():
        found = _symbol_va(exact_map, map_symbol)
        if found != address:
            raise ValueError(f"exact 1.1 map mismatch for {name}: {found!r}")
        source_matches.append({"gene_wars_va": f"0x{address:08X}", "symbol": name,
                               "exact_1_1_map_symbol": map_symbol,
                               **source_candidates.get(name, {"path": None, "candidate_va_comment": None,
                                  "similarity": "no independent source candidate checked", "confidence": "unresolved"})})

    main_calls = [{"callsite": x["callsite_link_va"], "target": x["callee_link_va"]}
                  for x in post["calls"]]
    return {
        "task": "W1-047",
        "target_sha256": TARGET,
        "source_evidence": ["native_ah44_register_divergence_work1.json", "ah44_call_entry_alignment_work3.json",
                            "native_startup_seed_parity_work3.json", "main_post_setup_frontier_work3.json",
                            "video_closure_preflight_work1.json", "rationalalloc_core_validation_work1.json"],
        "static_ah44_provenance": {
            "function": "sub_000C896A / exact 1.1 symbol isatty_",
            "instruction_chain": orig_div["byte_authoritative_instruction_chain"],
            "measured_request_delta": orig_div["measured_comparison"],
            "static_callers": callers,
            "dynamic_callsite_pairing": w3_061["site"]["dynamically_reached_callsite_identified"],
            "fixture_seed_parity": w3_061["fixture_comparison"]["complete_original_native_runtime_seed_parity"],
            "classification": "unresolved; EAX-to-EBX copy proves only that request-state difference predates INT 21h AH=44 semantics",
            "first_causal_divergence_known": False,
            "next_required_capture": "Capture original and native at each dynamically identified call to 0xC896A and before the caller's EAX writer under one complete measured seed/fixture."
        },
        "static_critical_path": {
            "rationalalloc_native_backtrace": [
                "RationalAlloc_ 0x000C3CA9",
                "__CreateNewNHeap_ 0x000C3D7A",
                "__ExpandDGROUP_ 0x000C3E2A",
                "upstream startup call chain in native AX=0501 evidence; this is not a matched original caller trace"
            ],
            "main_gate": {"function": "main_", "va": "0x00093F30", "calls": main_calls,
                          "branch": post["branch"], "dynamic_setup_game_return_crosscheck": post["dynamic_return_crosscheck"]},
            "screen_route": {
                "wrapper": {"va": "0x000962F0", "symbol": "LbScreenSetup_",
                            "operation": "sign-extend AL, push mode argument, direct call LbScreenSetupAnyMode_"},
                "known_static_edges": [
                    {"from": "PlayIntro -> PlaySmacker", "basis": "exact MAIN disassembly at PlayIntro 0x00092930"},
                    {"from": "PlaySmacker -> LbScreenSetup_", "basis": "exact MAIN disassembly; guarded by Smacker mode/flags"},
                    {"from": "LbScreenSetup_ 0x000962F0 -> LbScreenSetupAnyMode_ 0x0009FD40", "basis": "exact MAIN disassembly"},
                    {"from": "LbScreenSetupAnyMode_ -> LbVesaSetMode_ 0x000A3A00", "basis": "W1-044 exact-target closure preflight"},
                    {"from": "LbVesaSetPage_ 0x000A3A5C -> INT 10h", "basis": "W1-044 exact-target closure preflight"}
                ],
                "core_preflight": video_path,
                "int10_sites": video["int10_closure_sites"],
                "dynamic_reachability": False,
                "first_visible_image_observed": False
            },
            "dynamic_limits": {"playintro_reached": False, "game_reached": False,
                               "setup_game_target_return_not_proven": True,
                               "oracle_vhdx": str(root / "build/dosboxx_oracle/oracle_c.vhdx"),
                               "oracle_vhdx_present": (root / "build/dosboxx_oracle/oracle_c.vhdx").is_file(),
                               "oracle_sandbox_verified": False}
        },
        "source_guided_matches": {
            "gene_wars_source_repo_commit": source_repo,
            "candidate_tree_is_read_only_reference": True,
            "exact_1_1_map_path": str(exact_map),
            "exact_1_1_map_sha256": _sha(exact_map),
            "beta2_comparison_map_path": str(beta_map),
            "beta2_comparison_map_sha256": _sha(beta_map),
            "matches": source_matches,
            "files_sha256": {str(p): _sha(p) for p in source_files.values()},
            "version_rule": "Exact 1.1 MAP names are supported by the 1.1 helper map. Beta2 addresses/source comments are version-mismatched; no Beta2 offset is used for target disassembly."
        },
        "safety": {"oracle_launched": False, "runtime_semantics_modified": False,
                   "gene_wars_fx_written": False, "target_sha256": TARGET},
        "confidence": "static-path/caller dataflow only; no dynamic caller alignment, full seed parity, post-gate execution, or first-image proof"
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    p.add_argument("--out", default="evidence/critical_path_static_work1.json")
    args = p.parse_args()
    root = Path(args.root)
    out = build_evidence(root)
    target = Path(args.out)
    if not target.is_absolute():
        target = root / target
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"out": str(target), "target_sha256": out["target_sha256"],
                      "static_callers": len(out["static_ah44_provenance"]["static_callers"]),
                      "video_functions": len(out["static_critical_path"]["screen_route"]["core_preflight"]),
                      "oracle_launched": False}, indent=2))


if __name__ == "__main__":
    main()
