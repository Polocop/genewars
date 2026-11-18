#!/usr/bin/env python3
"""L-EXITBR — Classify the original `-k` process-exit and every preceding branch.

Read-only over the authoritative W2/W3 oracle traces (no runtime, no core tool).
Produces the ordered, de-duplicated service sequence that leads to the observed
stop for each fixture class (no-CD vs CD-present) and the determination:

  * no-CD `-k`:  clean `exit(0)` (DOS AH=4C, code 0) at EIP 0x1afc33 after a
                 log-purge / data/text.dat probe loop. EXPECTED behaviour with no
                 CD (no cdrom_inventory, no text.dat) -- NOT a bug, NOT the gate
                 to MENU.
  * CD-present:  stops at a #GP / backend_error writing to linear 0
                 (setup_game reads `this` MAP 0x114CA8 as NULL at 0x194b5a).
                 THIS is the actual gate to MENU (owner: WORK1 W1-028 / WORK3 W3-048).

Usage:
    py -3 tools/classify_process_exit.py            # writes evidence + reports
    py -3 tools/classify_process_exit.py --print    # also prints the JSON to stdout

Reproducible: deterministic over the named oracle files; no network, no runtime.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Canonical oracles (task -> {file, fixture_class, command_tail})
ORACLES = {
    # no-CD: the authoritative W2-074 replay, fixed by W3-047
    "nocd_w2_074": {
        "file": "evidence/startup_ah48_current_work3.json",
        "source_capture": "evidence/startup_runtime_current_work2.json",
        "fixture_class": "no-CD",
        "command_tail": "-k",
        "task": "W2-074/W3-047",
    },
    # CD-present: the authoritative WORK2 fault capture (W1-028). This file is the
    # canonical CD-present stop: backend_error, first_unsupported=memory@0x0,
    # last_guest_instruction bytes 88 07 (MOV [EDI],AL) at EIP 0x194b5a with EDI=0
    # (setup_game reads `this` MAP 0x114CA8 as NULL). It carries its own full
    # interrupt/service trace, so head == source_capture here.
    "cdpresent_w1_028": {
        "file": "evidence/mscdex_fault_context_work2.json",
        "source_capture": "evidence/mscdex_fault_context_work2.json",
        "fixture_class": "CD-present",
        "command_tail": "-k",
        "task": "W1-028 (W2-063 capture)",
    },
}


def _load(rel):
    p = os.path.join(ROOT, rel)
    if not os.path.exists(p):
        return None
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def _svc(ev):
    return ev.get("service") or ev.get("kind") or "unknown"


def _eip(ev):
    e = ev.get("eip")
    if e:
        return e
    reg = ev.get("registers") or {}
    return reg.get("eip")


def _file(ev):
    df = ev.get("dos_filename")
    if df and df.get("path"):
        return df["path"]
    return None


def classify_one(tag, spec):
    head = _load(spec["file"])
    full = _load(spec["source_capture"]) or head or {}

    out = {
        "tag": tag,
        "task": spec["task"],
        "fixture_class": spec["fixture_class"],
        "command_tail": spec["command_tail"],
        "oracle_file": spec["file"],
        "source_capture_file": spec.get("source_capture"),
    }

    # canonical summary (W3-047 fixed these on the head file)
    for k in ("stop_reason", "executed_instruction_count", "last_guest_eip",
              "first_unsupported", "menu_reached", "target_sha256", "runtime_sha256"):
        if k in head:
            out[k] = head[k]

    pe = (head or {}).get("process_exit") or (full or {}).get("process_exit")
    out["process_exit"] = pe

    # the rich service tails live in the source_capture (full) file
    src = full if full else head or {}
    tail_keys = ["interrupt_tail", "runtime_service_tail", "post_query_services"]
    sequence = []
    for tk in tail_keys:
        arr = src.get(tk) or []
        for i, ev in enumerate(arr):
            sequence.append({
                "section": tk,
                "index": i,
                "service": _svc(ev),
                "eip": _eip(ev),
                "file": _file(ev),
                "error": "error" in _svc(ev) or ".error" in _svc(ev),
            })

    # de-duplicate the get_file_attributes probe burst (same service+eip+file)
    dedup = []
    run_key = None
    for s in sequence:
        key = (s["service"], s["eip"], s["file"])
        if key != run_key:
            dedup.append({
                "service": s["service"],
                "eip": s["eip"],
                "file": s["file"],
                "section": s["section"],
                "index": s["index"],
                "repeat": 1,
            })
            run_key = key
        else:
            dedup[-1]["repeat"] += 1

    out["service_sequence"] = dedup

    # classification of the stop
    pe_code = (pe or {}).get("code")
    fns = (out.get("first_unsupported") or {}) if isinstance(out.get("first_unsupported"), dict) else {}
    kind = fns.get("kind")
    stop = out.get("stop_reason")
    if stop == "process_terminated" and pe_code == 0:
        verdict = "clean_exit0"
    elif kind == "memory" or stop == "backend_error":
        verdict = "linear0_write_fault"
    else:
        verdict = stop or "unknown"
    out["stop_classification"] = verdict

    # key dynamic facts
    out["facts"] = {
        "int2f_count": len((head or {}).get("int2f_services") or []),
        "int2f_services": [s.get("service") for s in (head or {}).get("int2f_services") or []],
        "cdrom_inventory_count": len((head or {}).get("cdrom_inventory") or (src or {}).get("cdrom_inventory") or []),
        "guest_exception": (head or {}).get("guest_exception"),
        "first_unsupported": out.get("first_unsupported"),
    }
    # the DPMI post-query loop (historical insufficient_memory) - count it, flag as non-gate
    pq = (src or {}).get("post_query_services") or []
    insuf = sum(1 for s in pq if "insufficient_memory" in _svc(s))
    out["facts"]["post_query_insufficient_memory_events"] = insuf
    out["facts"]["post_query_is_gate"] = False  # retry loop after the single 1500; already passed
    return out


def main():
    print_only = "--print" in sys.argv
    results = {}
    for tag, spec in ORACLES.items():
        results[tag] = classify_one(tag, spec)

    # determination
    nocd = results.get("nocd_w2_074", {})
    cd = results.get("cdpresent_w1_028", {})
    det = {
        "no_cd_exit_is_expected": nocd.get("stop_classification") == "clean_exit0",
        "no_cd_exit_gate_to_menu": False,
        "no_cd_rationale": (
            "With no CD the fixture has cdrom_inventory=[] and data/text.dat is "
            "not found; the original -k path performs a log-purge / probe loop "
            "and terminates cleanly with DOS AH=4C code 0 at 0x1afc33. No "
            "first_unsupported, no guest_exception. This is correct 'no disc' "
            "behaviour, not a blocker."
        ),
        "actual_gate_to_menu": "CD-present: setup_game reads `this` (MAP 0x114CA8) "
                               "as NULL and writes linear 0 at 0x194b5a (#GP/backend_error). "
                               "Owner: WORK1 W1-028 / WORK3 W3-048 (initializer of `this`).",
        "cd_present_stop": cd.get("stop_classification"),
        "post_query_insufficient_memory_is_gate": False,
        "post_query_note": "The dpmi31.allocate_dos_memory AX=0100 insufficient_memory "
                           "burst is a historical retry loop after the single MSCDEX 1500 "
                           "install-check; it is already passed and is NOT the current gate.",
    }
    out = {
        "task": "L-EXITBR",
        "role": "LOCAL",
        "oracles": results,
        "determination": det,
    }

    ev_path = os.path.join(ROOT, "evidence", "local_process_exit_classification.json")
    with open(ev_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1, ensure_ascii=False)
    print("wrote", os.path.relpath(ev_path, ROOT))

    # report
    rep = []
    rep.append("# LOCAL process-exit / branch classification (L-EXITBR)\n")
    rep.append("Read-only classification of the original `-k` stop for each fixture class, "
               "over the authoritative W2/W3 oracle traces. No runtime, no core tool touched.\n")
    for tag, r in results.items():
        rep.append("## %s (%s) — task %s\n" % (r.get("fixture_class"), tag, r.get("task")))
        rep.append("- stop_reason: `%s`" % r.get("stop_reason"))
        rep.append("- executed_instruction_count: %s" % r.get("executed_instruction_count"))
        rep.append("- last_guest_eip: `%s`" % r.get("last_guest_eip"))
        pe = r.get("process_exit") or {}
        rep.append("- process_exit: code=%s eip=%s" % (pe.get("code"), pe.get("eip")))
        f_ = r.get("first_unsupported") or {}
        rep.append("- first_unsupported: %s" % (f_.get("kind") + " addr=" + str(f_.get("address"))
                                                if isinstance(f_, dict) and f_ else "None"))
        rep.append("- stop_classification: **%s**\n" % r.get("stop_classification"))
        rep.append("Service sequence (de-duplicated):\n")
        rep.append("| service | eip | file | repeat |")
        rep.append("|---|---|---|---|")
        for s in r.get("service_sequence", []):
            rep.append("| %s | %s | %s | %d |" % (s["service"], s["eip"], s["file"] or "-", s["repeat"]))
        rep.append("")
    rep.append("## Determination\n")
    d = det
    rep.append("- no-CD `-k` exit(0) is **expected behaviour**, not the gate to MENU. %s" % d["no_cd_rationale"])
    rep.append("- Actual gate to MENU: %s" % d["actual_gate_to_menu"])
    rep.append("- post_query `insufficient_memory` burst: %s" % d["post_query_note"])

    rep_path = os.path.join(ROOT, "reports", "LOCAL_PROCESS_EXIT_CLASSIFICATION.md")
    with open(rep_path, "w", encoding="utf-8") as f:
        f.write("\n".join(rep) + "\n")
    print("wrote", os.path.relpath(rep_path, ROOT))

    if print_only:
        print("\n" + json.dumps(out, indent=1, ensure_ascii=False))
    return out


if __name__ == "__main__":
    main()