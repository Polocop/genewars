"""Independent audit of L-282's unresolved call counts and seed scope."""
import collections, hashlib, json, re
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
metrics = json.loads((ROOT / "evidence" / "scale_282_metrics.json").read_text(encoding="utf-8"))
closure = json.loads((ROOT / "evidence" / "dependency_closure_va_corrected.json").read_text(encoding="utf-8"))
boundaries = json.loads((ROOT / "evidence" / "boundary_revalidation_work3.json").read_text(encoding="utf-8"))
source_path = ROOT / "build" / "recomp_282.c"
source = source_path.read_text(encoding="utf-8", errors="replace")
# Function definitions only: require an opening brace so extern prototypes do not count.
definitions = {int(x, 16) for x in re.findall(r"^void sub_([0-9A-Fa-f]{8})\(void\)\s*\{", source, re.M)}
calls = []
for m in re.finditer(r"RECOMP_CALL\((\w+)\)\s*;\s*/\*\s*0x([0-9A-Fa-f]+): call 0x([0-9A-Fa-f]+)", source):
    calls.append({"symbol": m.group(1), "site": int(m.group(2), 16), "target": int(m.group(3), 16)})
targets = {x["target"] for x in calls}
missing = sorted(targets - definitions)
resolved = targets & definitions
map_rows = []
for line in (ROOT / "evidence" / "genewars-1_1.map").read_text(errors="replace").splitlines():
    parts = line.split()
    if len(parts) >= 2 and parts[0].startswith("0001:"):
        try:
            map_rows.append((int(parts[0].split(":")[1], 16), parts[1]))
        except ValueError:
            pass
map_names = collections.defaultdict(list)
for address, name in map_rows:
    map_names[address].append(name)
# Calculate LE object ranges from the loader, not from the section-zero assumption.
import sys
sys.path.insert(0, str(ROOT / "src"))
from le_loader import load_le
image = load_le(ROOT / "evidence" / "genewars-1_1.exe")
objects = [{"index": i, "base": f"0x{o.base:08X}", "end": f"0x{o.base + o.virtual_size:08X}", "virtual_size": f"0x{o.virtual_size:08X}"} for i, o in enumerate(image.objects)]
missing_details = []
for address in missing:
    refs = [x for x in calls if x["target"] == address]
    containing = [o for o in objects if int(o["base"], 16) <= address < int(o["end"], 16)]
    raw = bytes(image.mem[refs[0]["site"] - image.mem_base:refs[0]["site"] - image.mem_base + 5]) if refs else b""
    displacement = int.from_bytes(raw[1:5], "little", signed=True) if len(raw) == 5 and raw[0] == 0xE8 else None
    computed = refs[0]["site"] + 5 + displacement if displacement is not None else None
    missing_details.append({"target": f"0x{address:08X}", "map_names": map_names.get(address, []), "containing_le_objects": containing, "call_sites": [f"0x{x['site']:08X}" for x in refs], "callers": len(refs), "raw_call_bytes": raw.hex(), "rel32_target_recomputed": f"0x{computed:08X}" if computed is not None else None})
# Reproduce the bug from source: target strings are compared directly to integer lift addresses.
string_targets = {f"0x{x:08X}" for x in targets}
naive_unresolved = sum(t not in definitions for t in string_targets)  # always true for str-vs-int
scale_source = (ROOT / "tools" / "scale_282.py").read_text(encoding="utf-8")
source_has_type_mismatch = 'all_targets = {e["target"] for e in edges}' in scale_source and 'lifted_set = set(lifted.keys())' in scale_source and 't not in lifted_set' in scale_source
report = {
  "task": "W3-006", "target_sha256": metrics["target_sha256"], "code_object_range": metrics["code_object"],
  "scale_artifact": {k: metrics[k] for k in ("map_symbols", "map_matched_seeds", "lifts_attempted", "lifts_succeeded", "recursive_lifts_added", "total_functions_in_object", "direct_call_edges", "unique_direct_targets", "unresolved_targets", "unresolved_by_category", "indirect_calls_in_lifts", "compile_ok", "compiled_object_bytes")},
  "generated_c_audit": {"definitions": len(definitions), "direct_call_sites_parsed": len(calls), "unique_direct_targets": len(targets), "targets_matching_a_defined_function": len(resolved), "actual_missing_direct_targets": len(missing), "type_mismatch_reproduced": source_has_type_mismatch, "naive_unresolved_when_comparing_string_targets_to_integer_definitions": naive_unresolved, "missing_target_details": missing_details},
  "map_scope": {"exact_map_start_candidates": boundaries["map_exact_start_count"], "function_like_map_seeds": boundaries["map_function_like_seeds"], "extra_exact_map_entries_not_function_like": boundaries["map_exact_start_count"] - boundaries["map_function_like_seeds"], "scale_seed_selection_includes_all_exact_map_starts": 'matched_addrs |= {a for a, n in map_syms.items()' in scale_source, "note": "scale_282.py first filters seeds_all, then unions every MAP address in funcs; this includes non-function-like labels (including def_/jpt_ candidates)."},
  "corrected_selected_closure": {"functions": closure["total_lifted_functions"], "selected_seed_lifts": closure["selected_seed_lifts"], "recursive_lifts": closure["recursive_lifts"], "unique_direct_targets": closure["unique_direct_targets"], "unresolved_direct_targets": closure["unique_targets_unresolved"], "compiled_object_bytes": closure["compiled_object_bytes"], "oracle_fixture_pass": boundaries["oracle"]["pass"], "oracle_fixture_fail": boundaries["oracle"]["fail"]},
  "le_objects": objects,
  "conclusion": "L-282 compile succeeded, but its reported 1300 unresolved targets are inflated by a str/int set-membership bug. The generated C independently shows 1299 of 1300 unique direct target addresses have function definitions; one direct call to 0x00F65590 from 0x000E0D15 has no definition and lies outside every LE object. L-282 also treats 194 additional exact MAP candidate addresses beyond the 651 function-like seeds as seeds. The 250-function closure covers only its selected 100 seeds and 150 recursive functions, so its zero-unresolved metric does not establish the 1561-function/full-MAP gate. 553 indirect calls remain unmodeled by direct closure."
}
if not source_has_type_mismatch or len(missing) != 1 or missing[0] != 0x00F65590 or len(targets) != 1300 or len(resolved) != 1299 or missing_details[0]["rel32_target_recomputed"] != "0x00F65590":
    raise SystemExit("L-282 audit expectation changed; inspect artifact before accepting")
(ROOT / "evidence" / "closure_282_reconciliation_work3.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
lines = ["# W3-006: reconcile L-282 with the VA-corrected selected closure", "", f"Target SHA-256: `{metrics['target_sha256']}`", "", "## Same image, different scope", "", f"Both artifacts target the same image hash and code range `{metrics['code_object']}`. L-282 generated {metrics['total_functions_in_object']} functions from {metrics['map_matched_seeds']} selected MAP addresses plus {metrics['recursive_lifts_added']} recursive functions. The corrected dependency artifact covers {closure['selected_seed_lifts']} selected seeds plus {closure['recursive_lifts']} callees ({closure['total_lifted_functions']} total). It is a smaller gate, not a replacement validation for L-282's full MAP scope.", "", f"The VA-corrected audit found {boundaries['map_function_like_seeds']} function-like seeds and {boundaries['map_exact_start_count']} exact MAP starts. `scale_282.py` unions every recovered MAP address back into its seed set, so {boundaries['map_exact_start_count']-boundaries['map_function_like_seeds']} additional non-function-like MAP entries enter the batch. The current gate count also includes CFG ambiguity tracked by W1-007.", "", "## False unresolved-target metric", "", f"L-282 reports {metrics['unique_direct_targets']}/{metrics['unique_direct_targets']} direct targets unresolved. Source inspection confirms `all_targets` contains formatted strings (`0x...`) while `lifted_set` contains integer VAs; membership is always false. Independent parsing of the generated C finds {len(resolved)}/{len(targets)} unique target addresses have actual function definitions and only {len(missing)} does not. The object compile did not validate unresolved externals.", "", "| Target | Call site | In any LE object | MAP name | Finding |", "|---|---|---:|---|---|"]
for x in missing_details:
    lines.append(f"| `{x['target']}` | {', '.join(f'`{s}`' for s in x['call_sites'])} | {bool(x['containing_le_objects'])} | {', '.join(x['map_names']) or 'none'} | outside all four LE objects; investigate fixup/runtime/bad boundary |")
lines += ["", f"There are {metrics['indirect_calls_in_lifts']} indirect calls outside the direct-call graph. The corrected 250-function unit reports zero unresolved direct calls for its own selected subset and its stored oracle checks pass {boundaries['oracle']['pass']}/{boundaries['oracle']['count']}; it does not cover all L-282 entries.", "", "## Follow-up", "", "- W1-008: fix string/integer accounting, stop promoting all `def_`/`jpt_` entries into function seeds, verify a real link, then refresh full-scope gate metrics.", "- W2-009: trace the only remaining direct target `0x00F65590` at `0x000E0D15` against LE fixups/imports and runtime contracts before deciding whether a host service exists.", "- Existing W1-007 owns the ambiguous shared-CFG entry clusters. Existing W2-008 tests an original-byte execution backend.", "", "The WORK3 validation script asserts 1300 unique targets, 1299 defined targets, and recomputes the residual CALL target from the original five bytes. `gw test W3-006` also runs the script and infrastructure gate.", ""]
(ROOT / "reports" / "coordination" / "closure_282_reconciliation_work3.md").write_text("\n".join(lines), encoding="utf-8")
print(json.dumps({"scale_unresolved": metrics["unresolved_targets"], "unique_targets": len(targets), "defined_targets": len(resolved), "actual_missing": missing_details, "non_function_map_extra_seeds": report["map_scope"]["extra_exact_map_entries_not_function_like"], "indirect_calls": metrics["indirect_calls_in_lifts"]}, indent=2))


