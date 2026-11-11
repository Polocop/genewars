"""Read-only static preflight of six lifted video/VESA entry-closure functions."""
import hashlib, json, re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {
    "0x000A38F0": "LbVesaGetGran_",
    "0x000A3A00": "LbVesaSetMode_",
    "0x000A3A5C": "LbVesaSetPage_",
    "0x000A3AD0": "LbVesaGetInfo_",
    "0x000A3BA4": "LbVesaIsModeAvailable_",
    "0x0009FD40": "LbScreenSetupAnyMode_",
}

def body_for(source, va):
    m = re.search(rf"void sub_{va[2:]}\(void\) \{{", source)
    if not m:
        return None
    end = re.search(r"\nvoid [A-Za-z_]\w*\(void\) \{", source[m.end():])
    return source[m.start():m.end() + end.start()] if end else source[m.start():]

def build_report(root=ROOT):
    root = Path(root)
    source_path = root / "build/entry_path_closure.c"
    source_bytes = source_path.read_bytes()
    source = source_bytes.decode("utf-8", errors="replace")
    closure = json.loads((root / "evidence/entry_path_closure.json").read_text(encoding="utf-8"))
    compile_ev = json.loads((root / "evidence/entry_path_closure_routed_compile.json").read_text(encoding="utf-8"))
    link_ev = json.loads((root / "evidence/entry_path_native_full_link.json").read_text(encoding="utf-8"))
    definitions = set(re.findall(r"\bvoid\s+([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{", source))
    aliases = dict(re.findall(r"^\s*#define\s+(sub_[0-9A-Fa-f]+)\s+(\w+)\s*$", source, re.M))
    functions = {}
    for va, name in TARGETS.items():
        body = body_for(source, va)
        if body is None:
            functions[va] = {"name": name, "body_present": False}
            continue
        calls = [{"kind": kind, "target": target.strip()} for kind, target in re.findall(
            r"RECOMP_(CALL|ICALL|TAIL(?:_IF|_COND)?|TAILCALL)\(([^)]*)\)", body)]
        direct = [c["target"] for c in calls if c["kind"] == "CALL"]
        indirect = [c["target"] for c in calls if c["kind"] == "ICALL"]
        tails = [c for c in calls if c["kind"].startswith("TAIL") or c["kind"] == "TAILCALL"]
        resolved = [{"guest_target": t, "canonical_symbol": aliases.get(t, t),
                     "resolution": "selected_alias" if t in aliases else "function_body"}
                    for t in direct if aliases.get(t, t) in definitions]
        unresolved = [t for t in direct if aliases.get(t, t) not in definitions]
        seg_insns = []
        for line in body.splitlines():
            m = re.search(r"/\*\s*(0x[0-9a-fA-F]+):\s*(mov|pop|lds|les|lfs|lgs|lss)\s+(cs|ds|es|ss|fs|gs)\b([^*]*)\*/", line, re.I)
            if m:
                seg_insns.append({"va": m.group(1), "instruction": (m.group(2) + " " + m.group(3) + m.group(4)).strip(),
                                  "bridge": "recomp_write_segment" in body or "recomp_load_segment" in body})
        int10 = []
        for m in re.finditer(r"/\*\s*(0x[0-9a-fA-F]+):\s*int\s+0x10\s*\*/", body, re.I):
            va10 = m.group(1)
            window = body[m.start():m.start()+700]
            dispatch = bool(re.search(r"gw_interrupt_dispatch\(0x10u,\s*" + re.escape(va10) + r"u\)", window, re.I))
            trap_guard = bool(re.search(r"if\s*\(_gw_int_result\s*!=\s*GW_INTERRUPT_HANDLED\)\s*return", window))
            int10.append({"va": va10, "dispatch_bridge": dispatch, "unhandled_trap_returns": trap_guard})
        unsupported_markers = [line.strip() for line in body.splitlines()
                               if re.search(r"UNIMPLEMENTED|UNSUPPORTED|unsupported instruction|unknown instruction", line, re.I)]
        raw_segment_assignments = [line.strip() for line in body.splitlines()
                                   if re.search(r"(?:ctx->)?(?:cs|ds|es|ss|fs|gs)\s*=", line, re.I)]
        functions[va] = {
            "name": name, "body_present": True, "body_bytes": len(body.encode()),
            "direct_calls": direct, "resolved_direct_targets": resolved, "unresolved_direct_targets": unresolved,
            "indirect_calls": indirect, "tail_calls": tails,
            "segment_register_loads": seg_insns, "segment_memory_bridge_sites": len(re.findall(r"recomp_begin_memory_access\(RECOMP_SEG_", body)),
            "raw_segment_assignments": raw_segment_assignments,
            "int10_sites": int10, "unsupported_markers": unsupported_markers,
        }
    all_int10 = []
    for m in re.finditer(r"/\*\s*(0x[0-9a-fA-F]+):\s*int\s+0x10\s*\*/", source, re.I):
        all_int10.append(m.group(1))
    src_hash = hashlib.sha256(source_bytes).hexdigest()
    current_compile = compile_ev.get("passed") is True and compile_ev.get("source_sha256") == src_hash
    current_link = (link_ev.get("passed") is True and link_ev.get("object_sha256") == compile_ev.get("object_sha256")
                    and current_compile)
    return {
        "task": "W1-044", "target_sha256": closure.get("target_sha256"),
        "canonical_source": "build/entry_path_closure.c", "source_sha256": src_hash,
        "closure_metrics": {"function_bodies": closure.get("combined_function_bodies"),
                             "unresolved_direct_targets": closure.get("unresolved_unique_direct_targets"),
                             "ambiguous_or_unsupported_manifest": closure.get("ambiguous_or_unsupported")},
        "functions": functions,
        "int10_closure_sites": all_int10,
        "compile": {"evidence": "evidence/entry_path_closure_routed_compile.json", "passed": current_compile,
                    "source_sha256_matches": compile_ev.get("source_sha256") == src_hash,
                    "object_sha256": compile_ev.get("object_sha256"), "function_definitions": compile_ev.get("function_definitions")},
        "link": {"evidence": "evidence/entry_path_native_full_link.json", "passed": current_link,
                 "object_sha256_matches_compile": link_ev.get("object_sha256") == compile_ev.get("object_sha256"),
                 "executable_sha256": link_ev.get("executable_sha256"), "entry_smoke_passed": link_ev.get("passed")},
        "interpretation": "Static Core preflight only; INT10 dispatch/trap plumbing is checked, BIOS/VESA service behavior remains Runtime-owned. Dynamic reachability of these six functions is not established by this audit."
    }

def main():
    out = build_report()
    path = ROOT / "evidence/video_closure_preflight_work1.json"
    path.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"evidence": str(path), "source_sha256": out["source_sha256"],
                      "functions_present": sum(x.get("body_present", False) for x in out["functions"].values()),
                      "compile_current": out["compile"]["passed"], "link_current": out["link"]["passed"],
                      "int10_sites": out["int10_closure_sites"]}, indent=2))

if __name__ == "__main__":
    main()
