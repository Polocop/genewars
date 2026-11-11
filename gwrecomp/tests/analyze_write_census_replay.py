"""G-GP-002: summarize the opt-in write census from a native replay (GWRECOMP_WRITE_CENSUS=1).

Reads the replay stderr, keeps the exit-time "TRACE write_census" buckets (totals for the whole
run), and checks that the census build did not change behaviour: the input_index_source and
global_180c44 lines must match a reference replay that ran without the census.

Usage: python tests/analyze_write_census_replay.py <census_stderr.log> <reference_stderr.log> <out.json>
Labels: census counts are "observed" for this run; the mapping of buckets to writer kinds is a
reading of runtime/gw_segments.c, recorded per bucket below.
"""
import json
import pathlib
import re
import sys

CENSUS_RE = re.compile(r"^TRACE write_census entry=(\w+) scope=(\w+) active=([01]) kind=(\w+) outcome=(\w+) count=(\d+)$")
BEHAVIOUR_RE = re.compile(r"^TRACE (input_index_source|global_180c44_value_change|global_180c44_write)\b")

WRITER_MEANING = {
    ("mem", "guest", "1", "WRITE", "observed"): "generated store announced WRITE, observer ran",
    ("mem", "guest", "1", "READWRITE", "observed"): "generated RMW announced READWRITE, observer ran (counted per address resolution)",
    ("mem", "guest", "1", "READ", "checked_no_observer"): "generated access announced READ (loads, and stores announced as READ)",
    ("mem", "guest", "1", "WRITE", "invalid"): "announced WRITE rejected by range/backing check",
    ("mem", "guest", "1", "UNKNOWN", "checked_no_observer"): "window announced UNKNOWN via recomp_begin_memory_access_ex; all 14 static sites in the closure are mnemonic test (read-only), so inferred reads",
    ("mem", "guest", "0", "UNKNOWN", "early"): "address request with no announced access (unannounced loads and stores, probe reads)",
    ("seg", "guest", "1", "UNKNOWN", "checked_no_observer"): "generic segmented address (string ops, MEMSEG loads and stores): observer never runs",
    ("seg", "guest", "1", "UNKNOWN", "seg_reject"): "generic segmented address rejected before the check",
    ("seg", "host", "1", "UNKNOWN", "checked_no_observer"): "host DOS buffer access (scope set by gw_dos_services.c): observer never runs",
    ("seg", "host", "1", "UNKNOWN", "invalid"): "host DOS buffer access rejected",
}


def read_census(path):
    buckets = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = CENSUS_RE.match(line.strip())
        if m:
            key = "/".join(m.group(i) for i in range(1, 6))
            buckets[key] = buckets.get(key, 0) + int(m.group(6))
    return buckets


def behaviour_lines(path):
    lines = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if BEHAVIOUR_RE.match(line):
            lines.append(line)
    return lines


def main():
    census_log, reference_log, out_path = (pathlib.Path(p) for p in sys.argv[1:4])
    buckets = read_census(census_log)
    census_lines = behaviour_lines(census_log)
    reference_lines = behaviour_lines(reference_log)
    report = {
        "schema": "gwrecomp.write-census-replay/v1",
        "goal": "G-GP-002",
        "census_log": str(census_log),
        "reference_log": str(reference_log),
        "behaviour_identical_to_reference": census_lines == reference_lines,
        "behaviour_lines": {"census_run": len(census_lines), "reference_run": len(reference_lines)},
        "global_180c44_write_lines": sum(1 for l in census_lines if l.startswith("TRACE global_180c44_write")),
        "buckets": [
            {"bucket": k, "count": v, "meaning": WRITER_MEANING.get(tuple(k.split("/")), "unclassified"),
             "label": "observed"}
            for k, v in sorted(buckets.items(), key=lambda kv: -kv[1])
        ],
        "limitations": [
            "Totals for the whole 725->730 replay, not per turn; the census is dumped at exit.",
            "seg/guest UNKNOWN counts mix string-op and MEMSEG loads with stores; they are an upper bound on blind writes.",
            "Host memcpy writes (DBCS table, DOS MCB, real-mode register block, VBE OEM string, snapshot fread) do not call the segment API and are not counted.",
            "READWRITE counts two address resolutions per RMW instruction.",
        ],
    }
    out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"WROTE {out_path}")
    print(f"behaviour_identical_to_reference={report['behaviour_identical_to_reference']} "
          f"global_180c44_write_lines={report['global_180c44_write_lines']}")
    for b in report["buckets"]:
        print(f"{b['count']:>10}  {b['bucket']}")


if __name__ == "__main__":
    main()
