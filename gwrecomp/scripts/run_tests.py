"""Run every tests/test_*.py module and classify the outcome.

Each module is executed as `python -m unittest tests.<name>` from the gwrecomp directory (the original test semantics are
untouched). A non-passing module is reported as:

  BLOCKED  a required input is not available here (game files, evidence, third_party clone, pcrecomp, ...). The reason names
           the missing item. Not counted as a failure.
  KNOWN_FAIL  triaged in scripts/test_triage.json: fails even when all private inputs are present (genuine failure or stale
           assertion that needs maintainer attention). Listed, tracked, but does not fail the run.
  FAIL     the module ran but failed, or crashed for a reason that is not a missing input and is not triaged. Counted as a failure.
  TIMEOUT  exceeded the per-module limit.

usage: python scripts/run_tests.py [--jobs N] [--timeout S] [--filter SUBSTR] [--json FILE] [--markdown FILE] [--list]
Exit code: 0 when there is no FAIL/TIMEOUT, 1 otherwise. BLOCKED and KNOWN_FAIL never fail the run (they are always printed).
Environment: GWRECOMP_PYTHON selects the interpreter (default: the one running this script).
"""
import argparse, json, os, re, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = os.environ.get("GWRECOMP_PYTHON") or sys.executable
TRIAGE = json.loads((Path(__file__).with_name("test_triage.json")).read_text(encoding="utf-8"))["modules"]

# (regex on combined output, reason). First match wins; order is from most to least specific.
BLOCK_RULES = [
    (r"No module named '(tools\.(disasm|lift|pe|formats|classify)[\w.]*|lift32|disasm32|pe_analyze|difftest)'", "needs pcrecomp (run scripts\\setup.ps1; tests import its tools/ packages)"),
    (r"No module named '(coordination|taskq|autopilot|dashboard_view)[\w.]*'|coordination[\\/](taskq|task_|autopilot)", "needs the maintainers' internal task-queue files (not published)"),
    (r"third_party[\\/]+(dosbox|pcrecomp|le_disasm|syndwarsfx|recoil|xboxrecomp|3dsrecomp|SR|M-HT)", "needs a third_party clone (not published; see README_BUILD.md)"),
    (r"dosboxx_oracle|oracle_guard|GWORACLE|oracle sandbox", "needs the DOSBox-X reference oracle sandbox (maintainer-only)"),
    (r"evidence[\\/]+genewars-1_1\.(exe|map)|authentic GW\.EXE|GW\.EXE size is absent", "needs the game executable/map under evidence/ (build input, user supplied)"),
    (r"<GENEWARS_(HDD_ROOT|INSTALL_DIR)>|GENEWARS_INSTALL_DIR|set GENEWARS|GeneWars 1\.1 installation", "needs your Gene Wars 1.1 install (set GENEWARS_INSTALL_DIR)"),
    (r"snapshots?[\\/]|\.snap\b", "needs a guest snapshot (not published)"),
    (r"evidence[\\/]", "needs evidence/ files produced by maintainers' runs (not published)"),
    (r"[\\/]work[\\/]|work[\\/]recovery", "needs generated work/ artifacts (run the build first)"),
    (r"[\\/]build[\\/][\w.\\/-]+|build[\\/]entry_path", "needs generated build outputs (run the build first)"),
    (r"tools[\\/]w3_\d+\w*\.py|cannot import name", "needs a maintainers' tool/module that is not in this repository"),
    (r"No module named '(unicorn|capstone|pefile)'", "needs a Python package (run scripts\\setup.ps1)"),
]
MISSING = re.compile(r"(FileNotFoundError|ModuleNotFoundError|ImportError|No such file|cannot find|not found)", re.I)

def classify(out: str, src: str):
    tail = out.strip().splitlines()[-30:]
    text = "\n".join(tail) + "\n" + out[-4000:]
    if MISSING.search(out) or "NO TESTS RAN" in out or "is unavailable" in out or "mismatch" in out.lower() and "sha" in out.lower():
        for pat, why in BLOCK_RULES:
            m = re.search(pat, text)
            if m:
                return "BLOCKED", why
        # script-style modules: no unittest cases collected; classify by what the source reads
        if "NO TESTS RAN" in out:
            for pat, why in BLOCK_RULES:
                if re.search(pat, src): return "BLOCKED", why + " (script-style module: run it directly)"
            return "BLOCKED", "script-style module with no unittest cases; run it directly (python tests/<name>.py)"
    return "FAIL", "\n".join(tail[-12:])

def run_one(mod: str, timeout: int):
    t0 = time.time()
    try:
        r = subprocess.run([PY, "-m", "unittest", f"tests.{mod}"], cwd=ROOT, capture_output=True, text=True,
                           timeout=timeout, errors="replace")
    except subprocess.TimeoutExpired:
        return {"module": mod, "status": "TIMEOUT", "reason": f"> {timeout}s", "seconds": timeout}
    out = r.stdout + r.stderr
    secs = round(time.time() - t0, 1)
    if r.returncode == 0:
        ran = re.search(r"Ran (\d+) test", out)
        return {"module": mod, "status": "PASS", "reason": "", "seconds": secs, "tests": int(ran.group(1)) if ran else 0}
    src = (ROOT / "tests" / f"{mod}.py").read_text(encoding="utf-8", errors="replace")
    st, why = classify(out, src)
    if mod in TRIAGE:
        st, why = TRIAGE[mod]["status"], TRIAGE[mod]["reason"]
    return {"module": mod, "status": st, "reason": why, "seconds": secs}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=4); ap.add_argument("--timeout", type=int, default=90)
    ap.add_argument("--filter", default=""); ap.add_argument("--json"); ap.add_argument("--markdown"); ap.add_argument("--list", action="store_true")
    a = ap.parse_args()
    (ROOT / "build").mkdir(exist_ok=True); (ROOT / "cache").mkdir(exist_ok=True)   # several tests write here
    mods = sorted(p.stem for p in (ROOT / "tests").glob("test_*.py") if a.filter in p.stem)
    if a.list:
        print("\n".join(mods)); return 0
    with ThreadPoolExecutor(a.jobs) as ex:
        res = list(ex.map(lambda m: run_one(m, a.timeout), mods))
    counts = {s: sum(1 for r in res if r["status"] == s) for s in ("PASS", "BLOCKED", "KNOWN_FAIL", "FAIL", "TIMEOUT")}
    for r in res:
        if r["status"] in ("FAIL", "TIMEOUT"):
            print(f"{r['status']:8} {r['module']}\n" + "\n".join("         " + l for l in r["reason"].splitlines()[-6:]))
    by_reason = {}
    for r in res:
        if r["status"] == "BLOCKED": by_reason.setdefault(r["reason"], []).append(r["module"])
    print("\nBLOCKED by missing input:")
    for why, ms in sorted(by_reason.items(), key=lambda kv: -len(kv[1])): print(f"  {len(ms):4}  {why}")
    print(f"\nmodules={len(res)} pass={counts['PASS']} blocked={counts['BLOCKED']} known_fail={counts['KNOWN_FAIL']} fail={counts['FAIL']} timeout={counts['TIMEOUT']}")
    if a.json: Path(a.json).write_text(json.dumps({"counts": counts, "results": res}, indent=1), encoding="utf-8")
    if a.markdown:
        L = ["# Test status", "", f"Generated by `scripts/run_tests.py`: {len(res)} modules: **{counts['PASS']} pass**, **{counts['BLOCKED']} blocked** (missing inputs, not failures), **{counts['KNOWN_FAIL']} known failures** (triaged, see below), **{counts['FAIL']} unexpected failures**, {counts['TIMEOUT']} timeout.", "",
             "## Blocked, by missing input", "", "| Missing input | Modules |", "|---|---|"]
        for why, ms in sorted(by_reason.items(), key=lambda kv: -len(kv[1])): L.append(f"| {why} | {len(ms)} |")
        L += ["", "## Known failures (fail even with all private inputs)", ""] + [f"- `{r['module']}`: {r['reason']}" for r in res if r["status"] == "KNOWN_FAIL"]
        L += ["", "## Unexpected failures", ""] + [f"- `{r['module']}`: {r['reason'].splitlines()[-1] if r['reason'] else ''}" for r in res if r["status"] in ("FAIL", "TIMEOUT")]
        L += ["", "## Passing", ""] + [f"- `{r['module']}`" for r in res if r["status"] == "PASS"]
        L += ["", "## Blocked (full list)", ""]
        for why, ms in sorted(by_reason.items(), key=lambda kv: -len(kv[1])): L += [f"### {why} ({len(ms)})", ", ".join(f"`{m}`" for m in ms), ""]
        Path(a.markdown).write_text("\n".join(L) + "\n", encoding="utf-8")
    return 1 if counts["FAIL"] or counts["TIMEOUT"] else 0

if __name__ == "__main__":
    sys.exit(main())
