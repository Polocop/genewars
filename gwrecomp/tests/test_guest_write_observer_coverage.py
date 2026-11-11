"""G-GP-002: measure which guest-write paths reach the write observer.

Two measurements, both bounded and both independent of game state:

1. Synthetic self-test: tests/test_guest_write_observer_coverage.c is compiled
   with the same mingw gcc -m32 flow as test_memory_access_diagnostic.py and
   drives the real access macros and runtime/gw_segments.c. Each path reports
   whether its store happened and how many observer calls it produced.

2. Static census of the lifted closure (work/ifctitle_creature_probe_closure.c):
   each store site is classified by the mechanism that reaches (or bypasses)
   the observer. This is a line-level count, not an execution count.

The report is written to run-evidence/observer_coverage_selftest_report.json.
Labels: "observed" = measured here; "inferred" = read from code, not executed.
"""
import datetime
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
GCC = r"E:\msys64\mingw32\bin\gcc.exe"
CLOSURE = ROOT / "work" / "ifctitle_creature_probe_closure.c"
REPLAY_LOG = (ROOT / "run-evidence" / "mission" / "20261028-005647-G-GP-002-93ed"
              / "replay_725_730.stderr.log")
REPORT = ROOT / "run-evidence" / "observer_coverage_selftest_report.json"

# id -> (path, mechanism, source, expected verdict)
# Expected verdicts record the behaviour predicted from code reading before the
# measurement; the run asserts they hold, so a silent change in gw_segments.c fails.
ROWS = {
    "G1_store_mov_byte_write": ("generated plain store (mov byte ptr [m], imm)",
        "begin(WRITE) + MEM8 store", "tests/test_guest_write_observer_coverage.c:g1; closure:2392-2393", "COVERED"),
    "G2_store_mov_dword_write": ("generated plain store, computed address (mov [ebx+off], eax)",
        "begin(WRITE) + MEM32 store", "closure:2398-2399", "COVERED"),
    "G3_push_ss_write": ("generated push (SS:esp write)",
        "begin(WRITE,'push') + MEM32 store", "closure: first 'push' WRITE site (see census.first_lines)", "COVERED"),
    "G4_rmw_or_byte_readwrite": ("generated read-modify-write (or byte ptr [m], imm)",
        "begin(READWRITE) + MEM8 read and store", "closure:3944-3946", "COVERED_TWICE"),
    "G5_fstp_dword_write": ("generated x87 store (fstp dword ptr [m])",
        "begin(WRITE,'fstp') + MEMF store", "closure: first 'fstp' WRITE site (see census.first_lines)", "COVERED"),
    "G6_read_mov_dword_read": ("generated read (mov eax, [m]) - control, no write intent",
        "begin(READ) + MEM32 load", "closure:2400-2401 pattern", "NO_WRITE_INTENT"),
    "G7_store_mov_byte_write_diag_on": ("generated plain store with opt-in diagnostics enabled",
        "begin(WRITE) + MEM8 store, diag=1", "runtime/gw_segments.c:256-285", "COVERED"),
    "G8_store_without_begin": ("store with no announced access (access_active=0)",
        "bare MEM8 store", "census.unannounced_mem_store (static count)", "NOT_COVERED"),
    "S1a_rep_movsd_es_write_diag_off": ("generated rep movsd, ES:EDI destination, diag off",
        "recomp_checked_segment_addr(ES) -> UNKNOWN kind, then host memcpy", "closure:4972 (rep movsd 0x0001061A); emitted block form at closure:2719", "NOT_COVERED"),
    "S1b_rep_movsd_es_write_diag_on": ("generated rep movsd, ES:EDI destination, diag on",
        "begin(ES,WRITE) overwritten by recomp_checked_segment_addr(UNKNOWN)", "closure:2719 (diag-guarded begin)", "NOT_COVERED"),
    "S2_rep_stosd_es_write": ("generated rep stosd, ES:EDI destination",
        "recomp_checked_segment_addr(ES) -> UNKNOWN, then host memcpy/memset", "closure:923656", "NOT_COVERED"),
    "S3_movsd_nonrep_memseg32_es": ("generated non-rep movsd es:[edi], [esi]",
        "MEMSEG32(ES) store -> recomp_checked_segment_addr -> UNKNOWN", "closure:5973 (0x0001090E)", "NOT_COVERED"),
    "S4_memseg32_es_store_after_begin_write": ("MEMSEG32(ES) store after explicit begin(WRITE)",
        "announced WRITE is overwritten by UNKNOWN in recomp_checked_segment_addr", "runtime/gw_segments.c:418-445", "NOT_COVERED"),
    "H1_host_dos_read_checked_segment_addr": ("host DOS read service fills guest buffer",
        "recomp_checked_segment_addr(DS) -> UNKNOWN, then host file read", "runtime/gw_dos_services.c:564-600 (dos_read_open_file, buffer at :582)", "NOT_COVERED"),
    "H2_host_addr_translated_pointer": ("host helper writes through ADDR() translated pointer, no window",
        "recomp_checked_mem_addr(width 0) with access_active=0", "runtime/gw_segments.c:330-338; recomp_types.h:235", "NOT_COVERED"),
    "H3_host_bulk_copy_into_guest_image": ("bulk host copy into mapped guest image (snapshot-style)",
        "no runtime call on the path", "tests/test_ifctitle_creature_probe.c:6925 (fread into memory)", "NOT_COVERED"),
    "M1_store_announced_as_read_setcc": ("real store announced with READ intent (setle/setg/fistp/fnstcw destinations)",
        "begin(READ) + MEM8 store: observer only checks WRITE/READWRITE", "census.read_announced_store_samples (closure:70875, 183400)", "NOT_COVERED"),
    "M2_store_announced_read_fistp_ds": ("real x87 integer store (fistp dword [esi+0x97d]) announced READ",
        "begin(READ,'fistp') + MEM32 store", "closure:70874 (0x00019717)", "NOT_COVERED"),
    "M3_store_announced_read_setb_ss": ("real setcc store to stack temp (setb byte [ebp-8]) announced READ",
        "begin(READ,'setb') + MEM8 store", "closure:254849 (0x000374CA)", "NOT_COVERED"),
    "M4_store_announced_read_fnstcw_ss": ("real control-word store (fnstcw word [esp]) announced READ",
        "begin(READ,'fnstcw') + MEM16 store", "closure:849029 (0x000A38C0)", "NOT_COVERED"),
    "M5_store_announced_read_rol_mem_ds": ("real rotate of memory (rol dword [m], 4) announced READ",
        "begin(READ,'rol') + MEM32 store (write-back)", "closure:1114092 (0x000DD8B7)", "NOT_COVERED"),
    "C1_control_fistp_ds_announced_write": ("control: the M2 store announced WRITE instead of READ",
        "begin(WRITE,'fistp') + MEM32 store", "closure:70874 (same store as M2)", "COVERED"),
    "E1_store_rejected_by_range_validator": ("store rejected by segment range validator",
        "validator returns 0 -> fault pending, no observer (fail-closed by design)", "runtime/gw_segments.c:358", "NOT_EXERCISED_REJECTED"),
    "E2_store_after_first_fault_diag_on": ("store after first memory fault, diagnostics on",
        "fault_sink suppression returns before observer", "runtime/gw_segments.c:324-327", "NOT_EXERCISED_REJECTED"),
    "E3_translated_pointer_inside_write_window": ("translated pointer (width 0) taken inside begin(WRITE)",
        "width adopted from access_width; observer fires at address resolution", "runtime/gw_segments.c:339, 399-403", "COVERED"),
}

ROW_RE = re.compile(r"^ROW (\S+) hits=(\d+) stored=(\d) fault=(\d) linear=([0-9a-f]+) eip=([0-9a-f]+)$")
# One line per nonzero census bucket, printed per row on stderr (GWRECOMP_WRITE_CENSUS=1).
CENSUS_RE = re.compile(r"^TRACE write_census tag=(\S+) entry=(\w+) scope=(\w+) active=([01]) kind=(\w+) outcome=(\w+) count=(\d+)$")
# Minimum census buckets per row. They tie the census to the matrix: an empty
# bucket means the census disagrees with the observer result for that row.
CENSUS_EXPECT = [
    ("G1_store_mov_byte_write", "mem/guest/1/WRITE/observed", 1),
    ("G4_rmw_or_byte_readwrite", "mem/guest/1/READWRITE/observed", 2),
    ("G6_read_mov_dword_read", "mem/guest/1/READ/checked_no_observer", 1),
    ("G8_store_without_begin", "mem/guest/0/UNKNOWN/early", 1),
    ("S1a_rep_movsd_es_write_diag_off", "seg/guest/1/UNKNOWN/checked_no_observer", 1),
    ("S1b_rep_movsd_es_write_diag_on", "seg/guest/1/UNKNOWN/checked_no_observer", 1),
    ("S2_rep_stosd_es_write", "seg/guest/1/UNKNOWN/checked_no_observer", 1),
    ("S3_movsd_nonrep_memseg32_es", "seg/guest/1/UNKNOWN/checked_no_observer", 1),
    ("S4_memseg32_es_store_after_begin_write", "seg/guest/1/UNKNOWN/checked_no_observer", 1),
    ("H1_host_dos_read_checked_segment_addr", "seg/host/1/UNKNOWN/checked_no_observer", 1),
    ("H2_host_addr_translated_pointer", "mem/guest/0/UNKNOWN/early", 1),
    ("E1_store_rejected_by_range_validator", "mem/guest/1/WRITE/invalid", 1),
    ("E3_translated_pointer_inside_write_window", "mem/guest/1/WRITE/observed", 1),
    ("M2_store_announced_read_fistp_ds", "mem/guest/1/READ/checked_no_observer", 1),
    ("M3_store_announced_read_setb_ss", "mem/guest/1/READ/checked_no_observer", 1),
    ("M4_store_announced_read_fnstcw_ss", "mem/guest/1/READ/checked_no_observer", 1),
    ("M5_store_announced_read_rol_mem_ds", "mem/guest/1/READ/checked_no_observer", 1),
    ("C1_control_fistp_ds_announced_write", "mem/guest/1/WRITE/observed", 1),
]


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_selftest(env):
    exe = ROOT / "build" / "test_guest_write_observer_coverage.exe"
    command = [GCC, "-std=gnu11", "-m32", "-O0", "-Wall", "-Wno-unused-function",
               "-I", str(ROOT / "third_party/pcrecomp/runtime/recomp32"),
               "-o", str(exe), str(ROOT / "tests/test_guest_write_observer_coverage.c"),
               str(ROOT / "runtime/gw_segments.c")]
    built = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True, timeout=300)
    if built.returncode:
        raise SystemExit("observer self-test compile failed:\n" + built.stdout + built.stderr)
    return exe


def run_selftest(exe, env):
    ran = subprocess.run([str(exe)], cwd=ROOT, env=env, text=True, capture_output=True, timeout=60)
    if ran.returncode:
        raise SystemExit(f"observer self-test failed ({ran.returncode}):\n{ran.stdout}{ran.stderr}")
    census_buckets = {}
    for line in ran.stderr.splitlines():
        m = CENSUS_RE.match(line.strip())
        if m:
            key = f"{m.group(2)}/{m.group(3)}/{m.group(4)}/{m.group(5)}/{m.group(6)}"
            census_buckets.setdefault(m.group(1), {})[key] = int(m.group(7))
    rows = {}
    for line in ran.stdout.splitlines():
        m = ROW_RE.match(line.strip())
        if m:
            rows[m.group(1)] = {"observer_calls": int(m.group(2)), "store_happened": m.group(3) == "1",
                                "fault_pending": m.group(4) == "1",
                                "last_linear": "0x" + m.group(5), "last_eip": "0x" + m.group(6)}
    if "DONE observer coverage self-test rows" not in ran.stdout:
        raise SystemExit("self-test did not complete:\n" + ran.stdout)
    return rows, census_buckets


def verdict_for(measured, row_id):
    if row_id.startswith("G6"):
        return "NO_WRITE_INTENT"
    if not measured["store_happened"]:
        return "NOT_EXERCISED_REJECTED" if measured["fault_pending"] else "NOT_EXERCISED"
    if measured["observer_calls"] == 0:
        return "NOT_COVERED"
    if measured["observer_calls"] >= 2:
        return "COVERED_TWICE"
    return "COVERED"


# ---------------------------------------------------------------- static census
BEGIN_RE = re.compile(r"recomp_begin_memory_access_ex\((RECOMP_SEG_\w+),[^,]+,[^,]+,\s*RECOMP_MEM_ACCESS_(\w+),\s*[^,]+,\s*\"([^\"]*)\"\)")
MACRO_RE = re.compile(r"\b(MEM8|MEM16|MEM32|MEM64|MEMF|MEMD|MEMSEG8|MEMSEG16|MEMSEG32)\(")
ASSIGN_RE = re.compile(r"^\s*(?:[-+*/%&|^]|<<|>>)?=(?!=)")
COMMENT_RE = re.compile(r"/\*\s*0x([0-9A-Fa-f]{8}):\s*([a-z0-9]+)\s*(.*?)\s*\*/")


def matching_paren_end(text, open_index):
    depth = 0
    for i in range(open_index, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


def census(path):
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    counts = {"announced_write_mem": 0, "announced_readwrite_mem": 0,
              "announced_read_but_store": 0, "guarded_announce_mem": 0,
              "unannounced_mem_store": 0, "memseg_store_blind": 0}
    first_lines = {}
    blind_mnemonics = {}
    announced_mnemonics = {}
    read_announced_mnemonics = {}
    read_announced_samples = []
    addr_write_begin_kinds = {}
    unannounced_samples = []
    string_dst_lines = 0
    string_dst_mnemonics = {}
    addr_write_candidates = 0
    total_begin = {}
    active = None  # (line_index, kind, guarded)
    for idx, line in enumerate(lines):
        if "recomp_end_memory_access()" in line:
            active = None
        bm = BEGIN_RE.search(line)
        if bm:
            guarded = "recomp_memory_diag_enabled()) recomp_begin" in line
            active = (idx, bm.group(2), guarded, bm.group(3))
            total_begin[bm.group(2)] = total_begin.get(bm.group(2), 0) + 1
            if bm.group(2) in ("WRITE", "READWRITE") and bm.group(3) not in first_lines:
                first_lines[bm.group(3)] = idx + 1
        cm = COMMENT_RE.search(line)
        mnem = cm.group(2) if cm else ""
        if "recomp_checked_segment_addr(RECOMP_SEG_ES" in line:
            string_dst_lines += 1
            string_dst_mnemonics[mnem] = string_dst_mnemonics.get(mnem, 0) + 1
        if "ADDR(" in line and mnem in ("fstp", "fist", "fistp", "stos", "movs") and cm:
            addr_write_candidates += 1
            live_kind = active[1] if (active and idx - active[0] <= 3) else "NONE"
            addr_write_begin_kinds[live_kind] = addr_write_begin_kinds.get(live_kind, 0) + 1
        for mm in MACRO_RE.finditer(line):
            open_i = mm.end() - 1
            close_i = matching_paren_end(line, open_i)
            if close_i < 0:
                continue
            if not ASSIGN_RE.match(line[close_i + 1:]):
                continue
            family = mm.group(1)
            if family.startswith("MEMSEG"):
                counts["memseg_store_blind"] += 1
                blind_mnemonics[mnem] = blind_mnemonics.get(mnem, 0) + 1
                continue
            live = active if (active and idx - active[0] <= 3) else None
            if live is None:
                counts["unannounced_mem_store"] += 1
                if len(unannounced_samples) < 5:
                    unannounced_samples.append({"line": idx + 1, "mnemonic": mnem})
            elif live[2]:
                counts["guarded_announce_mem"] += 1
            elif live[1] == "READWRITE":
                counts["announced_readwrite_mem"] += 1
                announced_mnemonics[mnem] = announced_mnemonics.get(mnem, 0) + 1
            elif live[1] == "WRITE":
                counts["announced_write_mem"] += 1
                announced_mnemonics[mnem] = announced_mnemonics.get(mnem, 0) + 1
            else:
                counts["announced_read_but_store"] += 1
                read_announced_mnemonics[mnem] = read_announced_mnemonics.get(mnem, 0) + 1
                if len(read_announced_samples) < 6:
                    read_announced_samples.append({"line": idx + 1, "mnemonic": mnem})
    return {
        "source": "work/ifctitle_creature_probe_closure.c (lifted, line-level static count)",
        "total_lines": len(lines),
        "begin_calls_by_kind": total_begin,
        "store_sites": counts,
        "memseg_blind_by_mnemonic": dict(sorted(blind_mnemonics.items(), key=lambda kv: -kv[1])[:12]),
        "announced_store_mnemonics_top": dict(sorted(announced_mnemonics.items(), key=lambda kv: -kv[1])[:12]),
        "string_dst_checked_segment_lines": string_dst_lines,
        "string_dst_mnemonics": string_dst_mnemonics,
        "addr_write_candidates_x87_string": addr_write_candidates,
        "unannounced_mem_store_samples": unannounced_samples,
        "read_announced_store_mnemonics": read_announced_mnemonics,
        "read_announced_store_samples": read_announced_samples,
        "addr_write_candidates_begin_kind": addr_write_begin_kinds,
        "first_lines": first_lines,
        "method_notes": [
            "A store site is a MEM8/16/32/64/F/D or MEMSEG8/16/32 macro whose matching close parenthesis is followed by an assignment operator.",
            "A MEM store is announced when a recomp_begin_memory_access_ex call precedes it within 3 lines and before recomp_end_memory_access.",
            "MEMSEG stores are blind by construction: recomp_checked_segment_addr resets access kind to UNKNOWN.",
            "Counts are static: a site inside a function that never runs is still counted.",
        ],
    }


def replay_crosscheck():
    if not REPLAY_LOG.exists():
        return {"status": "replay log not present"}
    text = REPLAY_LOG.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    wr = [l for l in lines if "TRACE global_180c44_write" in l]
    chg = [l for l in lines if "TRACE global_180c44_value_change" in l]
    byte_728 = {}
    byte_729 = {}
    for l in lines:
        m = re.search(r"TRACE input_index_source turn=(72[89]) eip=(\w+) .*byte35ac44=([0-9a-f]{2})", l)
        if m:
            target = byte_728 if m.group(1) == "728" else byte_729
            target.setdefault(m.group(3), 0)
            target[m.group(3)] += 1
    return {
        "status": "measured",
        "log": str(REPLAY_LOG.relative_to(ROOT)).replace("\\", "/"),
        "global_180c44_write_lines": len(wr),
        "global_180c44_value_change_lines": chg,
        "input_index_byte35ac44_values_turn728": byte_728,
        "input_index_byte35ac44_values_turn729": byte_729,
    }


def main():
    env = {**os.environ,
           "TEMP": str(ROOT / "cache"), "TMP": str(ROOT / "cache"), "TMPDIR": str(ROOT / "cache"),
           "PATH": r"E:\msys64\mingw32\bin;E:\msys64\usr\bin;" + os.environ.get("PATH", ""),
           "GWRECOMP_WRITE_CENSUS": "1"}
    exe = build_selftest(env)
    measured, census_rows = run_selftest(exe, env)
    matrix = []
    failures = []
    census_checks = []
    for row_id, key, minimum in CENSUS_EXPECT:
        got = census_rows.get(row_id, {}).get(key, 0)
        ok = got >= minimum
        census_checks.append({"row": row_id, "bucket": key, "minimum": minimum, "measured": got, "ok": ok})
        if not ok:
            failures.append(f"census {row_id}: {key}={got}, expected >= {minimum}")
    for row_id, (path_desc, mechanism, source, expected) in ROWS.items():
        if row_id not in measured:
            failures.append(f"missing row {row_id}")
            continue
        m = measured[row_id]
        v = verdict_for(m, row_id)
        if v != expected:
            failures.append(f"{row_id}: measured {v}, predicted {expected}")
        matrix.append({"id": row_id, "path": path_desc, "mechanism": mechanism, "source": source,
                       "store_happened": m["store_happened"], "observer_calls": m["observer_calls"],
                       "fault_pending": m["fault_pending"], "last_observer_eip": m["last_eip"],
                       "verdict": v, "predicted_verdict": expected, "label": "observed"})
    covered = [r["id"] for r in matrix if r["verdict"].startswith("COVERED")]
    not_covered = [r["id"] for r in matrix if r["verdict"] == "NOT_COVERED"]
    census_result = census(CLOSURE)
    report = {
        "schema": "gwrecomp.observer-coverage-selftest/v1",
        "goal": "G-GP-002",
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "target": {"name": "GeneWars 1.1 canonical", "sha256": "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"},
        "inputs": {
            "runtime/gw_segments.c": sha256(ROOT / "runtime/gw_segments.c"),
            "tests/test_guest_write_observer_coverage.c": sha256(ROOT / "tests/test_guest_write_observer_coverage.c"),
            "work/ifctitle_creature_probe_closure.c": sha256(CLOSURE) if CLOSURE.exists() else None,
        },
        "method": ("Synthetic self-test drives the real MEM*/MEMSEG* macros, recomp_begin/end_memory_access, "
                   "recomp_checked_segment_addr and runtime/gw_segments.c. Guest memory is a private buffer; "
                   "no game state, snapshot, binary or oracle is used. Each row reports whether the store "
                   "happened and how many times the observer fired."),
        "matrix": matrix,
        "census_selftest": {"env": "GWRECOMP_WRITE_CENSUS=1", "buckets_per_row": census_rows,
                            "checks": census_checks,
                            "label": "observed (synthetic; each checked address is classified by entry, scope, announced kind and outcome)"},
        "paths_covered": covered,
        "paths_not_covered_measured": not_covered,
        "paths_not_covered": [
            {"id": "S1a/S1b/S2/S3/S4", "what": "every generated string-op store and MEMSEG store (rep/non-rep movs, stos)",
             "why": "recomp_checked_segment_addr resets access_kind to UNKNOWN; observer only checks WRITE/READWRITE",
             "static_sites_memseg_blind": census_result["store_sites"]["memseg_store_blind"],
             "static_string_dst_lines": census_result["string_dst_checked_segment_lines"],
             "label": "observed (synthetic) + inferred (static count)"},
            {"id": "H1/H2/H3", "what": "host services and loaders: DOS read buffer, ADDR() translated writes, snapshot/bulk copies into the guest image",
             "why": "no recomp_begin_memory_access_ex with WRITE on these paths; H1 uses UNKNOWN kind; H3 has no hook",
             "label": "observed (synthetic) + observed (code: tests/test_ifctitle_creature_probe.c:6925)"},
            {"id": "G8", "what": "stores with no announced access window",
             "why": "observer requires access_active==1",
             "static_sites_unannounced": census_result["store_sites"]["unannounced_mem_store"],
             "label": "observed (synthetic) + inferred (static count)"},
            {"id": "test-filter", "what": "probe callback records only 11 watched cells and the 0x35AC44 range under MAP1C_RELEASE_PROBE",
             "why": "tests/test_ifctitle_creature_probe.c:1280-1282 and watched_cell_guest[11] at :1144",
             "label": "observed (code)"},
            {"id": "test-suppression", "what": "probe disables the observer entirely under g_fast_interactive_profile unless a probe flag is set",
             "why": "tests/test_ifctitle_creature_probe.c:1459-1465 (recomp_set_guest_write_observer(NULL,NULL))",
             "label": "observed (code)"},
            {"id": "M1", "what": "real stores announced with READ intent (setcc, fistp, fnstcw, ror/rol destinations)",
             "why": "access kind is READ, so the WRITE/READWRITE check in recomp_checked_mem_addr is false",
             "static_sites": census_result["store_sites"]["announced_read_but_store"],
             "static_mnemonics": census_result["read_announced_store_mnemonics"],
             "label": "observed (synthetic M1) + observed (static count; classification is a lifter decision)"},
            {"id": "E1/E2", "what": "rejected or post-fault writes (fail-closed, intentional)",
             "why": "validator / fault_sink return before the observer", "label": "observed (synthetic)"},
        ],
        "host_direct_guest_write_sites_label": "inferred from code reading (grep of runtime/ and tests/); not executed",
        "host_direct_guest_write_sites": [
            {"site": "runtime/gw_dos_services.c:76", "function": "gw_dos_dbcs_table_configure", "op": "memcpy into guest DBCS table via g_mem_base", "observer_call": False},
            {"site": "runtime/gw_dos_services.c:134", "function": "dos_dpmi_simulate_real_mode_interrupt", "op": "memcpy of real-mode register block back into guest", "observer_call": False},
            {"site": "runtime/gw_dos_services.c:770", "function": "dos_mcb_write", "op": "memcpy into guest DOS MCB via g_mem_base", "observer_call": False},
            {"site": "runtime/gw_vbe_provider.c:85", "function": "controller_info", "op": "memcpy of VBE OEM string into d->guest_memory", "observer_call": False},
            {"site": "runtime/gw_dos_services.c:582,1203", "function": "dos_read_open_file / stream read", "op": "file read into buffer from recomp_checked_segment_addr (UNKNOWN kind)", "observer_call": False},
            {"site": "tests/test_ifctitle_creature_probe.c:6925", "function": "native_snapshot_load", "op": "fread into guest memory image", "observer_call": False},
        ],
        "static_census": census_result,
        "native_replay_crosscheck": replay_crosscheck(),
        "hypotheses": {
            "H1": {"statement": "translated code writes that never reach the observer (access_active=0 or misclassified kind)",
                   "result": "SUPPORTED",
                   "evidence": ["S1a,S1b,S2,S3,S4 store_happened=1 observer_calls=0", "G8 unannounced store silent",
                                "M2-M5 real READ-announced stores (fistp, setb, fnstcw, rol) store_happened=1 observer_calls=0",
                                "C1 control: same fistp store announced WRITE fires (attribution to the announced kind)"],
                   "falsifier_status": "not met: generated plain WRITE/READWRITE stores (G1-G5,G7,C1) do fire"},
            "H2": {"statement": "host-side writes never reach the observer",
                   "result": "SUPPORTED_FOR_TESTED_HOST_PATHS",
                   "evidence": ["H1 (DOS read service pattern) observer_calls=0", "H2 (ADDR translated pointer) observer_calls=0",
                                "H3 (bulk copy) no hook; tests/test_ifctitle_creature_probe.c:6925"],
                   "falsifier_status": "no host service found that announces WRITE; grep of runtime/ shows recomp_begin_memory_access_ex only in gw_segments.c"},
        },
        "limitations": [
            "The self-test is synthetic: it proves the mechanism in gw_segments.c, not the executed frequency of each path in the 725-730 replay.",
            "Static census counts sites in the lifted closure, not executed stores.",
            "The observer fires at address resolution, before the host store; a fired hit does not prove the byte changed.",
            "READWRITE fires twice per RMW instruction (read address and write address resolve through the same checked path).",
        ],
    }
    if failures:
        report["unexpected_verdicts"] = failures
    REPORT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"WROTE {REPORT.relative_to(ROOT)}")
    print(f"covered={len(covered)} not_covered={len(not_covered)} rows={len(matrix)}")
    if failures:
        print("UNEXPECTED: " + "; ".join(failures))
        return 1
    print("PASS observer coverage matrix matches code-predicted behaviour")
    return 0


if __name__ == "__main__":
    sys.exit(main())
