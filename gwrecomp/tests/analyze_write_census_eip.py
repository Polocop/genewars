"""G-GP-002: attribute the opt-in write census to instructions and store direction.

Input: the stderr of a native 725->730 replay run with GWRECOMP_WRITE_CENSUS=1
(lines "TRACE write_census_eip ..." written by runtime/gw_segments.c at exit).
Join: each EIP is looked up in the lifted closure comment
    /* 0xVA: <instruction text> */
and the instruction text is classified as store / rmw / load / other. The
classification reads the Intel-style operand text; it is a text inference,
recorded as such in the output, not an execution fact.

Output: a compact JSON summary (no raw trace copy). Labels: counts are observed
(same-run census); direction and "blind store" are inferred from the closure text.
"""
import argparse
import collections
import datetime
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
CLOSURE = ROOT / "work" / "ifctitle_creature_probe_closure.c"

EIP_RE = re.compile(r"^TRACE write_census_eip eip=([0-9a-f]{8}) entry=(\w+) scope=(\w+) kind=(\w+) "
                    r"outcome=(\w+) count=(\d+) mnemonic=(\S+)$")
BUCKET_RE = re.compile(r"^TRACE write_census entry=(\w+) scope=(\w+) active=([01]) kind=(\w+) outcome=(\w+) count=(\d+)$")
TEXT_RE = re.compile(r"/\* 0x([0-9A-Fa-f]{8}): (.*?) \*/")

RMW = {"add", "or", "adc", "sbb", "and", "sub", "xor", "inc", "dec", "neg", "not",
       "rol", "ror", "rcl", "rcr", "shl", "shr", "sar", "xchg"}
STORE = {"mov", "set", "fistp", "fist", "fstp", "fst", "fnstcw", "fnstsw", "stos", "movs",
         "push", "call", "pusha", "pushf", "fstsw", "stosb", "stosw", "stosd", "movsb", "movsw", "movsd"}
NOSTORE = {"cmp", "test", "bt", "lods", "scas", "cmps", "jmp", "idiv", "div", "mul", "imul"}
MEM_RE = re.compile(r"\b(byte|word|dword|qword|tbyte|fword)\s+ptr\s*\[|\bes:\[|^\[")


def closure_text(path):
    """First instruction text per EIP from the closure comments."""
    text = {}
    if not path.exists():
        return text
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if "/* 0x" not in line:
                continue
            for m in TEXT_RE.finditer(line):
                eip = int(m.group(1), 16)
                text.setdefault(eip, m.group(2).strip())
    return text


def classify(instr):
    """Return (direction, reason) from an Intel-style instruction text."""
    if not instr:
        return "unknown", "no closure comment"
    body = re.sub(r"^rep[a-z]*\s+", "", instr.strip())
    parts = body.split(None, 1)
    mnem = parts[0].lower() if parts else ""
    ops = parts[1] if len(parts) > 1 else ""
    if mnem in ("stos", "stosb", "stosw", "stosd"):
        return "store", "string store to es:[edi]"
    if mnem in ("movs", "movsb", "movsw", "movsd"):
        return "store", "string move: destination es:[edi]"
    if mnem in ("lods", "scas", "cmps"):
        return "load", "string load/compare"
    if mnem in ("push", "pusha", "pushf", "call"):
        # The announced access of a push/call with a memory operand is the operand read;
        # the stack write is a separate access that the census counts on its own.
        if "[" in instr:
            return "load", "memory operand is read; stack write is a separate access"
        return "stack_write", "register push/call: the stack write is a separate access"
    if mnem in ("pop", "popa", "popf", "ret", "leave"):
        return "load", "pop or return reads the stack"
    dest = ops.split(",", 1)[0].strip() if "," in ops else ops.strip()
    dest_is_mem = bool(MEM_RE.search(dest)) and "ptr" in dest or dest.startswith("[")
    if mnem in NOSTORE:
        return "load", "compare or test: memory operand is read"
    if dest_is_mem:
        if mnem in RMW:
            return "rmw", "memory destination of a read-modify-write op"
        if mnem in STORE or mnem.startswith("set") or mnem.startswith("fst") or mnem.startswith("fist"):
            return "store", "memory destination"
        return "store?", "memory destination, mnemonic not in table"
    return "load", "no memory destination"


def parse_log(path):
    eips, buckets = [], []
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            m = EIP_RE.match(line)
            if m:
                eips.append({"eip": int(m.group(1), 16), "entry": m.group(2), "scope": m.group(3),
                             "kind": m.group(4), "outcome": m.group(5), "count": int(m.group(6)),
                             "mnemonic": "" if m.group(7) == "-" else m.group(7)})
                continue
            b = BUCKET_RE.match(line)
            if b:
                buckets.append({"entry": b.group(1), "scope": b.group(2), "active": int(b.group(3)),
                                "kind": b.group(4), "outcome": b.group(5), "count": int(b.group(6))})
    return eips, buckets


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("stderr_log")
    ap.add_argument("out_json")
    ap.add_argument("--closure", default=str(CLOSURE))
    ap.add_argument("--watch", default="0006F78F,00019717,000374CA,000A38C0,000DD8B7,00019755,0003776D",
                    help="comma-separated EIPs to report explicitly")
    args = ap.parse_args()

    eips, buckets = parse_log(pathlib.Path(args.stderr_log))
    if not eips:
        sys.exit("no TRACE write_census_eip lines in " + args.stderr_log)
    text = closure_text(pathlib.Path(args.closure))

    rows = []
    for e in eips:
        direction, reason = classify(text.get(e["eip"], ""))
        rows.append({**e, "instruction": text.get(e["eip"], ""), "direction": direction, "direction_reason": reason})

    # Totals per (direction, kind, outcome) over checked addresses (counts are per address resolution).
    totals = collections.Counter()
    for r in rows:
        totals[(r["entry"], r["scope"], r["direction"], r["kind"], r["outcome"])] += r["count"]
    total_rows = [{"entry": k[0], "scope": k[1], "direction": k[2], "kind": k[3], "outcome": k[4], "count": v}
                  for k, v in sorted(totals.items(), key=lambda kv: -kv[1])]

    # Completeness check: the silent EIP rows must sum exactly to the silent bucket totals
    # (per entry, scope and announced kind). A mismatch means the per-instruction table is incomplete.
    silent_rows = collections.Counter()
    for r in rows:
        if r["outcome"] == "checked_no_observer":
            silent_rows[(r["entry"], r["scope"], r["kind"])] += r["count"]
    silent_buckets = collections.Counter()
    for b in buckets:
        if b["outcome"] == "checked_no_observer" and b["active"] == 1:
            silent_buckets[(b["entry"], b["scope"], b["kind"])] += b["count"]
    completeness = {"/".join(k): {"rows_sum": silent_rows.get(k, 0), "bucket_sum": silent_buckets.get(k, 0),
                                  "match": silent_rows.get(k, 0) == silent_buckets.get(k, 0)}
                    for k in set(silent_rows) | set(silent_buckets)}
    complete = all(v["match"] for v in completeness.values())

    # Silent store-capable accesses: a store or rmw whose outcome never reached the observer.
    silent_store = [r for r in rows if r["outcome"] == "checked_no_observer" and r["direction"] in ("store", "rmw", "store?")]
    silent_store_total = sum(r["count"] for r in silent_store)
    silent_read_kind_store = [r for r in silent_store if r["kind"] in ("READ", "UNKNOWN")]
    observed_bucket_total = {f'{b["entry"]}/{b["scope"]}/{b["kind"]}': b["count"]
                             for b in buckets if b["outcome"] == "observed"}

    watch = {}
    for w in args.watch.split(","):
        w = w.strip().lower()
        if not w:
            continue
        va = int(w, 16)
        hit = [r for r in rows if r["eip"] == va]
        watch[f"0x{va:08X}"] = [{k: r[k] for k in ("entry", "scope", "kind", "outcome", "count", "direction", "instruction")}
                                for r in hit] or "not_in_table"

    top_silent = sorted(silent_store, key=lambda r: -r["count"])[:40]
    report = {
        "schema": "gwrecomp.write-census-eip/v1",
        "goal": "G-GP-002",
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "input": str(pathlib.Path(args.stderr_log).as_posix()),
        "closure_for_direction": str(pathlib.Path(args.closure).as_posix()),
        "label": "counts observed (same-run census); direction inferred from closure text; blind-store attribution inferred",
        "distinct_instructions": len(rows),
        "bucket_totals_from_run": buckets,
        "totals_by_direction": total_rows,
        "silent_store_capable_total": silent_store_total,
        "silent_store_capable_announced_read_or_unknown": sum(r["count"] for r in silent_read_kind_store),
        "silent_rows_complete_vs_buckets": complete,
        "silent_rows_vs_buckets": completeness,
        "observed_bucket_totals": observed_bucket_total,
        "watch_eips": watch,
        "top_silent_store_capable": [{k: r[k] for k in ("eip", "entry", "scope", "kind", "count", "mnemonic", "direction", "instruction")} for r in top_silent],
        "limits": [
            "Counts are per checked address resolution: one block-form rep movsd is one call with width n*4, not one per element.",
            "READWRITE resolves twice per RMW instruction (as in the earlier census).",
            "Direction comes from closure text; a store announced with READ is a store by text, not by the announced kind.",
            "Counts cover the 725->730 window only and are not per-turn.",
        ],
    }
    out = pathlib.Path(args.out_json)
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"WROTE {out}")
    print(f"silent_rows={len(rows)} silent_store_capable={silent_store_total} "
          f"silent_announced_read_or_unknown={report['silent_store_capable_announced_read_or_unknown']} "
          f"complete_vs_buckets={complete}")


if __name__ == "__main__":
    main()
