#!/usr/bin/env python3
"""L-DISK-GUARD acceptance tests (synthetic, safe -- never fills E:).

Each test spawns a controlled child under oracle_guard.run_oracle (in-process,
so the free-space override hook is reachable) against an isolated scratch
staging dir on the scratch volume, and asserts the guard's behaviour:

  A  single-file runaway (writes a .TXT past the 512 MiB file cap)
     -> ABORTED_BY_DISK_GUARD, child tree killed, staging bounded, small evidence
  B  multi-file staging runaway (several files -> total past run cap)
     -> RUN_STAGING_LIMIT, bounded, killed
  C  timeout (child lives past --timeout-s)
     -> TIMEOUT, killed
  D  host free-space floor (injected via _FREE_OVERRIDE; never fills E:)
     -> preflight refuses AND watchdog aborts with HOST_FREE_SPACE_FLOOR
  E  parent + child kill-tree (child spawns a grandchild writer)
     -> whole tree killed, no grandchild left writing
  F  normal run (small write, quick exit)
     -> PASS, not aborted
  G  VHDX physical cap (gated): only runs when the 16 GiB VHDX is mounted;
     proves staging cannot exceed the physical volume capacity.

Artifacts: evidence/disk_guard_test_<name>.json (one per test) + a summary.
Run:  E:\\GWRecomp\\.venv\\Scripts\\python.exe E:\\GWRecomp\\tests\\test_oracle_guard.py
"""
from __future__ import annotations
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import oracle_guard as og  # noqa: E402
# A-F use isolated synthetic scratch directories. The production CLI retains
# hard-sandbox enforcement; H exercises its fail-closed branch explicitly.
og.SANDBOX_REQUIRED = False

PY = sys.executable
SCRATCH = Path(os.environ.get("LDG_SCRATCH",
          r"E:\AI\hermes\profiles\ninfer\cache\scratch\ldg_tests"))
EV = ROOT / "evidence" / "oracle_runs"
GENEWARSFX = r"E:\GeneWarsFX"
os.environ.setdefault("GWRECOMP_GENEWARSFX", GENEWARSFX)

RESULTS = []


def _child(path: Path, code: str):
    path.write_text(code, encoding="utf-8")


def _spawn_child(code: str, staging: Path) -> list[str]:
    """Write a child script into staging and return the argv for oracle_guard."""
    _child(staging / "_child.py", code)
    return [PY, str(staging / "_child.py")]


def _mk_limits(**kw) -> og.Limits:
    L = og.Limits()
    for k, v in kw.items():
        setattr(L, k, v)
    L.clamp()
    return L


def _run_case(name: str, staging: Path, argv: list[str], limits: og.Limits,
              free_override: int | None = None,
              prov: dict | None = None) -> dict:
    if free_override is not None:
        og._FREE_OVERRIDE["E"] = free_override
    else:
        og._FREE_OVERRIDE.pop("E", None)
    res = og.run_oracle(
        exe=argv[0], config=None, extra=argv[1:],
        limits=limits, staging=staging, host_drive="E:",
        run_id=name, operation=name, prov=prov or {},
        evidence_dir=EV, create_flags=og.CREATE_NEW_PROCESS_GROUP,
    )
    # record a per-test artifact copy
    ev = EV / f"oracle_runs_{name}.json"
    out = EV / f"disk_guard_test_{name}.json"
    if ev.exists():
        data = json.loads(ev.read_text(encoding="utf-8"))
        data["_test"] = name
        out.write_text(json.dumps(data, indent=2, ensure_ascii=False),
                       encoding="utf-8")
        res = data
    # sample payload byte-size (how much runaway evidence was kept)
    sample_bytes = 0
    for s in res.get("samples_preserved", []):
        for k in ("head", "tail", "middle"):
            if s.get(k):
                sample_bytes += len(base64.b64decode(s[k]))
    res["sample_bytes_preserved"] = sample_bytes
    res["test_artifact"] = str(out)
    return res


def _staging(name: str) -> Path:
    d = SCRATCH / name
    d.mkdir(parents=True, exist_ok=True)
    return d


def _alive(pid: int) -> bool:
    try:
        out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/FO",
                             "CSV", "/NH"], capture_output=True, text=True,
                             timeout=10).stdout
        return pid in out
    except Exception:
        return False


# ---------------------------------------------------------------------------
# the tests
# ---------------------------------------------------------------------------

def test_A_single_file() -> bool:
    """Child writes one .TXT far past the 512 MiB cap -> FILE_SIZE/GROWTH trip."""
    name = "A_single_file"
    st = _staging(name)
    code = (
        "import os,time\n"
        "p=os.path.join(os.environ['LDG_STAGE'],'RUNAWAY.TXT')\n"
        "with open(p,'wb') as f:\n"
        "    while True:\n"
        "        f.write(b'0'* (256*1024)); f.flush()\n"
        "        time.sleep(0.05)\n"
    )
    os.environ["LDG_STAGE"] = str(st)
    # tight file cap so the runaway is caught quickly (still a real .TXT limit)
    lim = _mk_limits(max_file_text=4 * 1024 * 1024,
                     max_file_bin=4 * 1024 * 1024,
                     max_run=2 * 1024 ** 3, growth_text_mibs=16.0,
                     timeout=60)
    argv = _spawn_child(code, st)
    t0 = time.time()
    res = _run_case(name, st, argv, lim)
    dt = time.time() - t0
    killed = res.get("killed_processes", [])
    # the runaway .TXT must not have reached the (much larger) run cap; it is
    # bounded by the file cap (128 MiB) plus a little slack from the final tick.
    txt = st / "RUNAWAY.TXT"
    txt_size = txt.stat().st_size if txt.exists() else 0
    checks = {
        "aborted": res.get("exit_reason") == "ABORTED_BY_DISK_GUARD",
        "cause_is_file_or_growth": res.get("cause") in
            ("FILE_SIZE_LIMIT", "FILE_GROWTH_RATE"),
        "bounded_below_run_cap": txt_size <= int(1.25 * 1024 * 1024 * 1024),
        "killed_recorded": bool(killed),
        "small_evidence": res.get("sample_bytes_preserved", 0) <= 3 * 1024 * 1024,
        "no_giant_file": txt_size < (1024 ** 3),
    }
    res.update({"duration_s": round(dt, 2), "runaway_txt_bytes": int(txt_size),
                "killed": killed[:20], "checks": checks})
    (EV / f"disk_guard_test_{name}.json").write_text(
        json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8")
    return all(checks.values())


def test_B_multi_file() -> bool:
    """Several child writers push total staging past the run cap."""
    name = "B_multi_file"
    st = _staging(name)
    code = (
        "import os,time,threading\n"
        "base=os.environ['LDG_STAGE']\n"
        "def w(n):\n"
        "    p=os.path.join(base,f'STAGE_{n}.LOG')\n"
        "    with open(p,'wb') as f:\n"
        "        while True:\n"
        "            for _ in range(20): f.write(b'x'*(64*1024)); f.flush()\n"
        "            time.sleep(0.02)\n"
        "ts=[threading.Thread(target=w,args=(i,),daemon=True) for i in range(4)]\n"
        "[t.start() for t in ts]; [t.join() for t in ts]\n"
    )
    os.environ["LDG_STAGE"] = str(st)
    lim = _mk_limits(max_file_text=2 * 1024 ** 3, max_file_bin=2 * 1024 ** 3,
                     max_run=1 * 1024 ** 3, growth_text_mibs=200.0,
                     growth_bin_mibs=200.0, timeout=90)
    argv = _spawn_child(code, st)
    t0 = time.time()
    res = _run_case(name, st, argv, lim)
    dt = time.time() - t0
    total = og.staging_total_bytes(st)
    checks = {
        "aborted": res.get("exit_reason") == "ABORTED_BY_DISK_GUARD",
        "cause_is_staging": res.get("cause") == "RUN_STAGING_LIMIT",
        "bounded": total <= int(1.25 * 1024 ** 3),
        "killed": bool(res.get("killed_processes")),
    }
    res.update({"duration_s": round(dt, 2), "staging_total_bytes": int(total),
                "checks": checks})
    (EV / f"disk_guard_test_{name}.json").write_text(
        json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8")
    return all(checks.values())


def test_C_timeout() -> bool:
    """Child lives past --timeout-s (writes a tiny amount so size limits don't
    trip first) -> TIMEOUT."""
    name = "C_timeout"
    st = _staging(name)
    code = (
        "import os,time\n"
        "p=os.path.join(os.environ['LDG_STAGE'],'tick.LOG')\n"
        "with open(p,'wb') as f:\n"
        "    for _ in range(4000):\n"
        "        f.write(b'tick\\n'); f.flush(); time.sleep(0.05)\n"
    )
    os.environ["LDG_STAGE"] = str(st)
    lim = _mk_limits(max_file_text=2 * 1024 ** 3, max_file_bin=2 * 1024 ** 3,
                     max_run=8 * 1024 ** 3, growth_text_mibs=9999.0,
                     growth_bin_mibs=9999.0, timeout=12)
    argv = _spawn_child(code, st)
    t0 = time.time()
    res = _run_case(name, st, argv, lim)
    dt = time.time() - t0
    checks = {
        "aborted": res.get("exit_reason") == "ABORTED_BY_DISK_GUARD",
        "cause_is_timeout": res.get("cause") == "TIMEOUT",
        "near_timeout": 12 <= dt <= 30,
        "killed": bool(res.get("killed_processes")),
    }
    res.update({"duration_s": round(dt, 2), "checks": checks})
    (EV / f"disk_guard_test_{name}.json").write_text(
        json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8")
    return all(checks.values())


def test_D_free_floor() -> bool:
    """Inject E: free = 1 GiB (below 100 GiB floor) via the test hook -- no
    disk actually filled. (a) preflight must refuse; (b) the watchdog must
    abort an in-flight run with HOST_FREE_SPACE_FLOOR."""
    name = "D_free_floor"
    st = _staging(name)
    ok_a = False
    ok_b = False
    det_a = det_b = None
    # (a) preflight refusal
    ok_a, det_a = og.preflight(st, "E:", _mk_limits(host_floor=100 * 1024 ** 3), None) if False else (None, None)
    og._FREE_OVERRIDE["E"] = 1 * 1024 ** 3  # 1 GiB free
    ok_a, det_a = og.preflight(st, "E:", og.Limits(), None)
    # (b) watchdog abort during a run
    code = (
        "import os,time\n"
        "p=os.path.join(os.environ['LDG_STAGE'],'t.LOG')\n"
        "with open(p,'wb') as f:\n"
        "    for _ in range(1000): f.write(b'z\\n'); f.flush(); time.sleep(0.05)\n"
    )
    os.environ["LDG_STAGE"] = str(st)
    lim = og.Limits()  # real floor 100 GiB; override forces 1 GiB
    argv = _spawn_child(code, st)
    og._FREE_OVERRIDE["E"] = 1 * 1024 ** 3
    res = _run_case(name, st, argv, lim, free_override=1 * 1024 ** 3)
    og._FREE_OVERRIDE.pop("E", None)
    ok_b = (res.get("exit_reason") == "ABORTED_BY_DISK_GUARD"
            and res.get("cause") == "HOST_FREE_SPACE_FLOOR")
    det_b = f"cause={res.get('cause')} reason={res.get('exit_reason')}"
    checks = {
        "preflight_refused": (not ok_a),
        "watchdog_aborted_floor": ok_b,
    }
    res.update({"preflight": det_a, "watchdog": det_b, "checks": checks})
    (EV / f"disk_guard_test_{name}.json").write_text(
        json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8")
    return checks["preflight_refused"] and ok_b


def test_E_kill_tree() -> bool:
    """Child spawns a grandchild writer; guard must kill the whole tree and no
    grandchild may keep writing after the abort."""
    name = "E_kill_tree"
    st = _staging(name)
    code = (
        "import os,time,subprocess,sys\n"
        "base=os.environ['LDG_STAGE']\n"
        "child=[sys.executable, os.path.join(base,'_grand.py')]\n"
        "p=subprocess.Popen(child, env=dict(os.environ))\n"
        "with open(os.path.join(base,'PARENT.ERR'),'wb') as f:\n"
        "    while True:\n"
        "        f.write(b'p'* (128*1024)); f.flush(); time.sleep(0.05)\n"
    )
    grand = (
        "import os,time\n"
        "p=os.path.join(os.environ['LDG_STAGE'],'GRANDCH.TXT')\n"
        "with open(p,'wb') as f:\n"
        "    while True:\n"
        "        f.write(b'g'* (128*1024)); f.flush(); time.sleep(0.05)\n"
    )
    os.environ["LDG_STAGE"] = str(st)
    _child(st / "_grand.py", grand)
    lim = _mk_limits(max_file_text=128 * 1024 * 1024,
                     max_file_bin=128 * 1024 * 1024,
                     max_run=1 * 1024 ** 3, growth_text_mibs=16.0, timeout=60)
    argv = _spawn_child(code, st)
    t0 = time.time()
    res = _run_case(name, st, argv, lim)
    dt = time.time() - t0
    time.sleep(1.5)  # let any stray writer reveal itself
    total_after = og.staging_total_bytes(st)
    time.sleep(1.5)
    total_later = og.staging_total_bytes(st)
    still_writing = (total_later - total_after) > (100 * 1024)
    checks = {
        "aborted": res.get("exit_reason") == "ABORTED_BY_DISK_GUARD",
        "killed": bool(res.get("killed_processes")),
        "no_writer_after": not still_writing,
        "bounded": total_later <= int(1.25 * 1024 ** 3),
    }
    res.update({"duration_s": round(dt, 2),
                "staging_after_kill": int(total_after),
                "growth_after_3s": int(total_later - total_after),
                "killed": res.get("killed_processes", [])[:20],
                "checks": checks})
    (EV / f"disk_guard_test_{name}.json").write_text(
        json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8")
    return all(checks.values())


def test_F_normal() -> bool:
    """A normal, small, fast run must PASS and NOT be aborted."""
    name = "F_normal"
    st = _staging(name)
    code = (
        "import os,time,sys\n"
        "base=os.environ['LDG_STAGE']\n"
        "open(os.path.join(base,'out.txt'),'w').write('done\\n')\n"
        "time.sleep(0.3)\n"
        "sys.exit(0)\n"
    )
    os.environ["LDG_STAGE"] = str(st)
    lim = og.Limits()  # production defaults
    argv = _spawn_child(code, st)
    t0 = time.time()
    res = _run_case(name, st, argv, lim)
    dt = time.time() - t0
    checks = {
        "passed": res.get("exit_reason") == "PASS",
        "not_aborted": res.get("exit_reason") != "ABORTED_BY_DISK_GUARD",
        "exit_code_0": res.get("exit_code") == 0,
        "no_samples": not res.get("samples_preserved"),
        "fast": dt < 30,
    }
    res.update({"duration_s": round(dt, 2), "checks": checks})
    (EV / f"disk_guard_test_{name}.json").write_text(
        json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8")
    return all(checks.values())


def test_G_vhdx_physical() -> bool | None:
    """Gated: only meaningful once the 16 GiB VHDX is mounted as the guest C:
    volume. If no VHDX is mounted we report SKIPPED (None) -- the physical cap
    is a one-time user-admin setup, not part of the software-guard acceptance.
    When mounted: a child that writes unboundedly must be stopped by the
    physical volume ceiling (DISK_FULL), proving staging cannot exceed the
    VHDX capacity regardless of the watchdog."""
    name = "G_vhdx_physical"
    vhdx = ROOT / "build" / "dosboxx_oracle" / "oracle_c.vhdx"
    mounted = False
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command",
                              "Get-Volume | Where-Object {$_.FileSystemLabel -like '*ORACLE*' -or $_.DriveLetter -eq 'F'} | Select-Object DriveLetter,FileSystemLabel,SizeRemaining,Size | ConvertTo-Json"],
                              capture_output=True, text=True, timeout=30).stdout
        mounted = ("ORACLE" in out.upper())
    except Exception:
        mounted = False
    if not mounted:
        res = {"_test": name, "status": "SKIPPED",
               "reason": "VHDX not mounted (one-time user-admin setup pending). "
                         "Physical cap inactive; software guard is the active layer.",
               "vhdx_path": str(vhdx), "checks": {}}
        (EV / f"disk_guard_test_{name}.json").write_text(
            json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8")
        return None
    # mounted -> run an unbounded writer; the VHDX ceiling must stop it.
    st = _staging(name)
    code = (
        "import os,time\n"
        "p=os.path.join(os.environ['LDG_STAGE'],'FILL.BIN')\n"
        "with open(p,'wb') as f:\n"
        "    while True:\n"
        "        try: f.write(b'\\0'*(4*1024*1024)); f.flush()\n"
        "        except OSError: break\n"
        "        time.sleep(0.01)\n"
    )
    os.environ["LDG_STAGE"] = str(st)
    lim = _mk_limits(timeout=240)
    argv = _spawn_child(code, st)
    res = _run_case(name, st, argv, lim)
    size = (st / "FILL.BIN").stat().st_size if (st / "FILL.BIN").exists() else 0
    cap = 16 * 1024 ** 3
    checks = {"stopped": size <= int(1.05 * cap), "bounded_by_volume": size < cap}
    res.update({"fill_bytes": int(size), "checks": checks})
    (EV / f"disk_guard_test_{name}.json").write_text(
        json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8")
    return all(checks.values())


def test_H_fail_closed_without_sandbox() -> bool:
    old = og.SANDBOX_REQUIRED
    og.SANDBOX_REQUIRED = True
    try:
        stage = ROOT / "build" / "dosboxx_oracle" / "C"
        ok, reason = og.preflight(stage, "E:", og.Limits(), str(stage))
        passed = (not ok) and "HARD_SANDBOX_REQUIRED" in reason
    finally:
        og.SANDBOX_REQUIRED = old
    (EV / "disk_guard_test_H_fail_closed.json").write_text(
        json.dumps({"_test": "H fail closed without sandbox", "passed": passed,
                    "detail": reason}, indent=2), encoding="utf-8")
    return passed


CASES = [
    ("A single-file runaway", test_A_single_file),
    ("B multi-file staging runaway", test_B_multi_file),
    ("C timeout", test_C_timeout),
    ("D free-space floor (injected)", test_D_free_floor),
    ("E parent+child kill-tree", test_E_kill_tree),
    ("F normal run PASS", test_F_normal),
    ("G VHDX physical cap (gated)", test_G_vhdx_physical),
    ("H fail closed without VHDX", test_H_fail_closed_without_sandbox),
]


def main() -> int:
    SCRATCH.mkdir(parents=True, exist_ok=True)
    EV.mkdir(parents=True, exist_ok=True)
    print("L-DISK-GUARD acceptance tests")
    print(f"  python={PY}\n  scratch={SCRATCH}\n  evidence={EV}\n")
    passed = failed = skipped = 0
    for label, fn in CASES:
        print(f"== {label} ", end="", flush=True)
        try:
            r = fn()
        except Exception as e:  # noqa: BLE001
            import traceback
            traceback.print_exc()
            r = False
        if r is None:
            print("SKIPPED (gated)")
            skipped += 1
        elif r:
            print("PASS")
            passed += 1
        else:
            print("FAIL")
            failed += 1
    total = passed + failed
    summary = {
        "suite": "L-DISK-GUARD oracle_guard",
        "python": PY,
        "passed": passed, "failed": failed, "skipped": skipped,
        "software_guard": "PASS" if (failed == 0 and passed >= 7) else "FAIL",
        "vhdx_physical": "PENDING" if skipped else ("PASS" if failed == 0 else "FAIL"),
    }
    (EV / "disk_guard_summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8")
    print("\nSUMMARY:", json.dumps(summary))
    return 0 if (failed == 0 and passed >= 7) else 1


if __name__ == "__main__":
    raise SystemExit(main())
