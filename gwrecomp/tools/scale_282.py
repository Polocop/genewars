#!/usr/bin/env python3
"""
scale_282.py — Batch lift + dependency closure + classification for all
MAP-matched functions in the GeneWars 1.1 LE image.

Usage:
    py -3 tools/scale_282.py            # full pipeline
    py -3 tools/scale_282.py --no-compile   # skip compile step
    py -3 tools/scale_282.py --limit N     # cap seeds at N (for testing)

Produces:
    build/recomp_282.c                 combined lift source (all seeds + recursive)
    build/recomp_282.o                 compiled x86-32 object (if --compile)
    evidence/scale_282_metrics.json    metrics + target classification
    reports/LOCAL_SCALE_282.md         human-readable summary
"""
import os as _gw_os
from pathlib import Path as _GwPath
_GW_MSYS2=_gw_os.environ.get("MSYS2_ROOT",r"C:\msys64")
import json, os, re, subprocess, sys, time
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "third_party" / "pcrecomp"))

from le_loader import load_le
from tools.disasm.disasm32 import Disassembler
from tools.pe.pe_analyze import Section
from tools.lift.lift32 import Lifter

# ── arguments ──────────────────────────────────────────────────────────────
args = [a for a in sys.argv[1:]]
NO_COMPILE = "--no-compile" in args
LIMIT = None
if "--limit" in args:
    LIMIT = int(args[args.index("--limit") + 1])
    args.remove("--limit")
    args.remove(str(LIMIT))

# ── load image + map ───────────────────────────────────────────────────────
t0 = time.time()
image = load_le(ROOT / "evidence" / "genewars-1_1.exe")
obj = image.objects[0]
START = obj.base                # 0x10000
END = START + obj.virtual_size  # 0xE8930
code = bytes(image.mem[START - image.mem_base : END - image.mem_base])
print(f"[1/7] LE loaded: obj0 base=0x{START:08X} end=0x{END:08X} size=0x{END-START:06X}", flush=True)

map_syms = {}
map_rows = []
for line in (ROOT / "evidence" / "genewars-1_1.map").read_text(errors="replace").splitlines():
    p = line.split()
    if len(p) >= 2 and p[0].startswith("0001:"):
        try:
            a = int(p[0].split(":")[1], 16)
            map_syms[a] = p[1]
            map_rows.append((a, p[1]))
        except ValueError:
            pass
print(f"[1/7] MAP: {len(map_syms)} symbols in genewars-1_1.map", flush=True)

# ── disassemble + find functions ───────────────────────────────────────────
seeds_all = sorted({
    a for a, n in map_syms.items()
    if START <= a < END
    and (n.startswith(("W?", "Lb")) or (n.endswith("_") and not n.startswith(("jpt_", "def_"))))
})
# VA->byte translation: the `code` buffer is sliced from obj.base (0x10000),
# so the section's virtual_address base MUST be obj.base, not 0. Passing 0
# (the pre-W1-004 bug) shifts every disassembled byte by 0x10000.
sec = Section(".text", obj.base, obj.virtual_size, 0, obj.virtual_size, 0x20000020)
dis = Disassembler(code, 0, [sec])
funcs = dis.find_functions(START, END, seeds=seeds_all)
print(f"[2/7] Disassembler: {len(funcs)} functions found; {len(seeds_all)} seed symbols", flush=True)

# MAP-matched: function start address is in map_syms (excl. jpt_/def_)
matched_addrs = {a for a in funcs if a in map_syms and not map_syms[a].startswith(("jpt_", "def_"))}
matched_addrs |= {a for a, n in map_syms.items() if START <= a < END and a in funcs}
if LIMIT:
    # cap by size ascending (same ordering as lift_catalog.py)
    matched_sorted = sorted(matched_addrs, key=lambda a: (
        sum(len(b.instructions) for b in funcs[a].blocks.values()), a
    ))
    matched_addrs = set(matched_sorted[:LIMIT])
    print(f"      --limit={LIMIT}: capped to {len(matched_addrs)} seeds", flush=True)
print(f"[2/7] MAP-matched function seeds: {len(matched_addrs)}", flush=True)

# ── lift all matched + recursive closure ──────────────────────────────────
lift = Lifter()
lifted = {}       # addr -> lifted source text
edges = []        # (caller, call_site, target)
unlifted_calls = []  # call targets outside code object / missing boundary

lift_queue = list(matched_addrs)
lift_seen = set()
lift_errors = []
unsupported = Counter()
x87_hits = Counter()

def try_lift(addr):
    """Lift one function; return source text or None."""
    f = funcs.get(addr)
    if f is None:
        return None
    f.name = f"sub_{addr:08X}"
    try:
        text = lift.lift_function(f)
        return text
    except Exception as e:
        err_msg = str(e)
        lift_errors.append({"addr": f"0x{addr:08X}", "symbol": map_syms.get(addr), "error": err_msg})
        # classify
        if "x87" in err_msg.lower() or "st(" in err_msg.lower():
            x87_hits[addr] += 1
        elif "unsupported" in err_msg.lower() or "opcode" in err_msg.lower():
            unsupported[addr] += 1
        return None

while lift_queue:
    addr = lift_queue.pop(0)
    if addr in lift_seen:
        continue
    lift_seen.add(addr)

    text = try_lift(addr)
    if text is None:
        if not (START <= addr < END):
            # out of range — record as external
            unlifted_calls.append({"addr": f"0x{addr:08X}", "reason": "out_of_code_object",
                                    "symbol": map_syms.get(addr)})
        else:
            # in range but failed to lift
            unlifted_calls.append({"addr": f"0x{addr:08X}", "reason": "lift_failed",
                                    "symbol": map_syms.get(addr),
                                    "in_range": True})
        continue

    lifted[addr] = text

    # extract direct call targets from this function's source
    for m in re.finditer(r"RECOMP_CALL\(([A-Za-z0-9_]+)\)\s*;\s*/\*\s*0x([0-9A-Fa-f]+): call 0x([0-9A-Fa-f]+)", text):
        sym, site_s, tgt_s = m.group(1), int(m.group(2), 16), int(m.group(3), 16)
        edges.append({"caller": f"0x{addr:08X}", "call_site": f"0x{site_s:08X}",
                      "target": f"0x{tgt_s:08X}", "symbol": sym,
                      "target_symbol": map_syms.get(tgt_s),
                      "target_in_code": START <= tgt_s < END,
                      "target_lifted": tgt_s in lifted})
        if START <= tgt_s < END and tgt_s not in lift_seen:
            lift_queue.append(tgt_s)

    # also catch indirect calls (RECOMP_CALL via register / icall)
    for m in re.finditer(r"RECOMP_ICALL|RECOMP_CALL_REG|RECOMP_JMP_REG", text):
        pass  # count them but don't expand (can't resolve statically)

# re-scan lifted functions for indirect calls to count them
icall_count = 0
for addr, text in lifted.items():
    icall_count += len(re.findall(r"RECOMP_ICALL|call\s+\[|call\s+e?[a-d][a-z]\]", text))

print(f"[3/7] Lifted {len(lifted)} functions from {len(lift_seen)} attempted; "
      f"{len(lift_errors)} lift errors; {icall_count} indirect calls", flush=True)

# ── classify unresolved targets ────────────────────────────────────────────
all_targets = {e["target"] for e in edges}
lifted_set = set(lifted.keys())
unresolved_targets = sorted(t for t in all_targets if t not in lifted_set)

import bisect
_func_starts_sorted = sorted(funcs.keys())
_func_start_of = {a: a for a in _func_starts_sorted}

# classify each unresolved target
def classify_target(addr_hex):
    a = int(addr_hex, 16)
    sym = map_syms.get(a)
    if not (START <= a < END):
        if a < START:
            return "below_code_object", f"addr 0x{a:08X} < code base 0x{START:08X} (DOS4GW stub / DPMI / low-runtime)"
        else:
            return "above_code_object", f"addr 0x{a:08X} >= code end 0x{END:08X} (data or CRT)"
    # in code-object range but not lifted
    # 1) does the disassembler have a function boundary here?
    if a in funcs:
        # boundary exists; not lifted means it was not reached in the closure
        # path (no caller in the lifted set invokes it) — or it was an alias
        # subsumed into a larger function. This is a real gap for coverage.
        return "in_range_not_reached", f"addr 0x{a:08X} has a boundary ({map_syms.get(a)}) but is not in the lifted closure"
    # 2) no boundary at `a` — find the owning function span (bisect)
    i = bisect.bisect_right(_func_starts_sorted, a) - 1
    owner = _func_starts_sorted[i] if (i >= 0 and _func_starts_sorted[i] <= a < funcs[_func_starts_sorted[i]].end) else None
    if owner is not None and owner in lifted:
        oname = map_syms.get(owner, f"sub_{owner:08X}")
        return "inside_lifted_function", (f"addr 0x{a:08X} is mid-body of {oname} "
                f"(0x{funcs[owner].address:08X}-0x{funcs[owner].end:08X}); benign call target, no separate lift needed")
    if owner is not None:
        oname = map_syms.get(owner, f"sub_{owner:08X}")
        return "inside_unlifted_function", f"addr 0x{a:08X} is mid-body of {oname} (not lifted)"
    # 3) in code object but no boundary at a and not inside any function
    return "no_boundary_in_code", f"addr 0x{a:08X} in code object but disassembler found no function boundary ({map_syms.get(a) or 'unsym'})"

classified = []
for t in unresolved_targets:
    cat, note = classify_target(t)
    classified.append({"target": t, "category": cat, "note": note,
                       "symbol": map_syms.get(int(t, 16))})

cat_counts = Counter(c["category"] for c in classified)
print(f"[4/7] Unresolved targets: {len(unresolved_targets)} "
      f"(categories: {dict(cat_counts)})", flush=True)

# ── generate combined .c source ────────────────────────────────────────────
# Order: seeds first (by size ascending), then recursive additions
seed_list = sorted(matched_addrs, key=lambda a: (
    sum(len(b.instructions) for b in funcs[a].blocks.values()), a
))
recursive_list = sorted(set(lifted.keys()) - set(matched_addrs))
all_ordered = seed_list + recursive_list

# collect all extern symbols needed
all_lifted_names = {f"sub_{a:08X}" for a in all_ordered if a in lifted}
all_call_syms = set()
for e in edges:
    all_call_syms.add(e["symbol"])
extern_needed = sorted(all_call_syms - all_lifted_names)

lines = ['#define RECOMP_GENERATED_CODE', '#include "recomp_types.h"', ""]
for sym in extern_needed:
    lines.append(f"extern void {sym}(void);")
lines.append("")

for i, addr in enumerate(all_ordered):
    if addr not in lifted:
        continue
    sym = map_syms.get(addr, f"sub_{addr:08X}")
    lines.append(f"/* gw_lift_{i:04d} 0x{addr:08X} {sym} */")
    lines.append(lifted[addr])
    lines.append("")

src_text = "\n".join(lines)
out_c = ROOT / "build" / "recomp_282.c"
out_c.parent.mkdir(parents=True, exist_ok=True)
out_c.write_text(src_text, encoding="utf-8")
print(f"[5/7] Wrote {out_c} ({out_c.stat().st_size} bytes, {len([a for a in all_ordered if a in lifted])} functions)", flush=True)

# ── compile ─────────────────────────────────────────────────────────────────
compile_ok = False
compile_err = ""
compile_out = ""
if not NO_COMPILE:
    gcc = (_GW_MSYS2.replace("\\","/") + '/mingw32/bin/gcc.exe')
    hdr = str(ROOT / "third_party" / "pcrecomp" / "runtime" / "recomp32")
    env = dict(os.environ)
    _m = os.environ.get("MSYS2_ROOT", r"C:\msys64").replace("\\", "/")
    env["PATH"] = f"{_m}/mingw32/bin;{_m}/usr/bin;" + env.get("PATH", "")
    cmd = [gcc, "-m32", "-std=gnu99", "-Wno-implicit-function-declaration",
           f"-I{hdr}", f"-I{ROOT}/build",
           "-c", str(out_c), "-o", str(ROOT / "build" / "recomp_282.o")]
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT), env=env)
    compile_ok = (r.returncode == 0)
    compile_err = r.stderr
    compile_out = r.stdout
    if compile_ok:
        osize = (ROOT / "build" / "recomp_282.o").stat().st_size
        print(f"[6/7] Compiled OK: recomp_282.o ({osize} bytes)", flush=True)
    else:
        err_lines = [l for l in compile_err.splitlines() if "error:" in l]
        print(f"[6/7] Compile FAILED: {len(err_lines)} errors", flush=True)
        for l in err_lines[:20]:
            print(f"    {l}", flush=True)
else:
    print("[6/7] Compile skipped (--no-compile)", flush=True)

# ── metrics ────────────────────────────────────────────────────────────────
lift_errors_by_cat = Counter()
for e in lift_errors:
    msg = e["error"].lower()
    if "x87" in msg or "st(" in msg:
        lift_errors_by_cat["x87"] += 1
    elif "unsupported" in msg or "opcode" in msg:
        lift_errors_by_cat["unsupported_opcode"] += 1
    elif "register" in msg or "segment" in msg:
        lift_errors_by_cat["segment_or_register"] += 1
    else:
        lift_errors_by_cat["other"] += 1

metrics = {
    "target_sha256": "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f",
    "code_object": f"0x{START:08X}-0x{END:08X}",
    "discovered_functions": len(funcs),
    "map_symbols": len(map_syms),
    "map_matched_seeds": len(matched_addrs),
    "lifts_attempted": len(lift_seen),
    "lifts_succeeded": len(lifted),
    "lift_errors": len(lift_errors),
    "lift_error_categories": dict(lift_errors_by_cat),
    "x87_pending": len(x87_hits),
    "unsupported_opcode_hits": len(unsupported),
    "recursive_lifts_added": len(recursive_list),
    "total_functions_in_object": len(all_ordered),
    "direct_call_edges": len(edges),
    "unique_direct_targets": len(all_targets),
    "unresolved_targets": len(unresolved_targets),
    "unresolved_by_category": dict(cat_counts),
    "indirect_calls_in_lifts": icall_count,
    "compile_ok": compile_ok,
    "compile_error_count": len([l for l in compile_err.splitlines() if "error:" in l]) if not compile_ok else 0,
    "compiled_object_bytes": (ROOT / "build" / "recomp_282.o").stat().st_size if compile_ok else 0,
    "elapsed_seconds": round(time.time() - t0, 2),
    # top unresolved targets for quick inspection
    "unresolved_sample": classified[:30],
    # detailed lift errors (first 30)
    "lift_error_sample": lift_errors[:30],
}

out_json = ROOT / "evidence" / "scale_282_metrics.json"
out_json.parent.mkdir(parents=True, exist_ok=True)
out_json.write_text(json.dumps(metrics, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(f"[7/7] Metrics → {out_json}", flush=True)

# ── report ─────────────────────────────────────────────────────────────────
rep = ROOT / "reports" / "LOCAL_SCALE_282.md"
rep.parent.mkdir(parents=True, exist_ok=True)
lines = [
    "# LOCAL Batch: Scale to 282 MAP-matched functions",
    "",
    f"Generated: {time.strftime('%Y-%m-%dT%H:%M:%S+00:00')}",
    f"Elapsed: {metrics['elapsed_seconds']}s",
    "",
    "## Metrics",
    "",
    f"| Metric | Value |",
    f"|---|---|",
    f"| Code object | `{metrics['code_object']}` |",
    f"| Functions discovered | {metrics['discovered_functions']} |",
    f"| MAP symbols in genewars-1_1.map | {metrics['map_symbols']} |",
    f"| MAP-matched seeds | {metrics['map_matched_seeds']} |",
    f"| Lifts attempted | {metrics['lifts_attempted']} |",
    f"| Lifts succeeded | {metrics['lifts_succeeded']} |",
    f"| Lift errors | {metrics['lift_errors']} |",
    f"| Recursive lifts added | {metrics['recursive_lifts_added']} |",
    f"| Total functions in object | {metrics['total_functions_in_object']} |",
    f"| Direct call edges | {metrics['direct_call_edges']} |",
    f"| Unique direct targets | {metrics['unique_direct_targets']} |",
    f"| Unresolved targets | {metrics['unresolved_targets']} |",
    f"| Indirect calls in lifts | {metrics['indirect_calls_in_lifts']} |",
    f"| x87 pending | {metrics['x87_pending']} |",
    f"| Unsupported opcode hits | {metrics['unsupported_opcode_hits']} |",
    f"| Compile OK | {metrics['compile_ok']} |",
    f"| Compiled object bytes | {metrics['compiled_object_bytes']} |",
    "",
    "## Unresolved target categories",
    "",
    "| Category | Count |",
    "|---|---|",
]
for cat, n in sorted(cat_counts.items(), key=lambda x: -x[1]):
    lines.append(f"| `{cat}` | {n} |")
lines += ["", "## Lift error categories", "", "| Category | Count |", "|---|---|"]
for cat, n in sorted(lift_errors_by_cat.items(), key=lambda x: -x[1]):
    lines.append(f"| `{cat}` | {n} |")

if classified:
    lines += ["", "## Unresolved targets (sample)", "",
              "| Target | Category | Symbol | Note |",
              "|---|---|---|---|"]
    for c in classified[:30]:
        lines.append(f"| `{c['target']}` | {c['category']} | {c['symbol'] or ''} | {c['note'][:80]} |")

if not compile_ok and compile_err:
    err_lines = [l for l in compile_err.splitlines() if "error:" in l][:20]
    if err_lines:
        lines += ["", "## Compile errors (first 20)", "", "```"]
        lines += err_lines
        lines.append("```")

rep.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"      Report → {rep}", flush=True)
print("DONE", flush=True)