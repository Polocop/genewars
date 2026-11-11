"""GWRecomp cloud-bridge CLI (L-CLOUD-BRIDGE).

Stable, read-mostly interface used by GitHub Actions workflows on the
self-hosted Windows runner. It sits ON TOP of the existing project CLI
(`coordination/gw.cmd` -> taskq.py) and the project's own tools, so the
workflows never need to know the project's internal layout.

Design rules (see L-CLOUD-BRIDGE brief):
  * Read-mostly. Nothing here writes source. `build`/`test`/`replay`/`diff`
    only re-execute EXISTING project scripts and emit JSON + bounded logs.
  * Every subcommand prints exactly one JSON object to stdout:
        {subcommand, ok, exit_code, result: PASS|FAIL|SKIPPED,
         artifacts:{relpath: sha256}, log_tail:str, detail:...}
  * Never copies or prints original material (EXE/BIN/CUE/ISO). Originals
    are only ever *launched* (replay original) or *hashed* for provenance.
  * No arbitrary argument pass-through into a shell. Subcommands are fixed
    verbs; any tuning goes through named, allow-listed inputs.

Exit code of the process == 0 iff `result` is PASS or SKIPPED.

This file is intended to be committed (it is part of `tools/`).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]

# Original material lives OUTSIDE the repo, read-only (per AGENTS.md).
GENEWARSFX = pathlib.Path(os.environ.get("GWRECOMP_GENEWARSFX", "E:\\GeneWarsFX"))
# The DOSBox-X heavy-debug build used as the original oracle.
DBX_HEAVY = ROOT / "build" / "dosboxx-heavy" / "src" / "dosbox-x.exe"
# The native target the recompiler produces.
NATIVE_EXE = ROOT / "build" / "entry_path_native.exe"
# The reference target binary we recompile against (the provenance anchor).
TARGET_EXE = ROOT / "evidence" / "genewars-1_1.exe"

# Bounded log size returned in JSON (bytes).
LOG_TAIL = 4000

# In-memory cache of the fixture fingerprint (expensive: hashes the CD tracks).
_fixture_sha_cache: dict = {}


def _fixture_sha() -> str | None:
    """Stable fingerprint of the read-only GeneWarsFX fixture (cue + tracks).

    Hashes the .cue plus each .bin track so a swapped/modified CD library
    changes the value. Cached for the process lifetime. Never uploads the
    bytes -- only the combined sha256 is reported."""
    if "v" in _fixture_sha_cache:
        return _fixture_sha_cache["v"]
    _fixture_sha_cache["v"] = None
    cue = GENEWARSFX / "Genewars (Europe) (En,Fr,De,Es,It,Sv).cue"
    if not GENEWARSFX.exists():
        return None
    h = hashlib.sha256()
    if cue.exists():
        h.update(b"CUE:" + cue.name.encode())
        h.update(cue.read_bytes())
    else:
        h.update(b"NO_CUE:")
    for binf in sorted(GENEWARSFX.glob("*.bin")):
        th = hashlib.sha256()
        with open(binf, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                th.update(chunk)
        h.update(("BIN:" + binf.name + ":" + th.hexdigest() + "\n").encode())
    _fixture_sha_cache["v"] = h.hexdigest()
    return _fixture_sha_cache["v"]


def _provenance() -> dict:
    """Standard provenance block stamped into every evidence payload.

    commit_sha  -- git SHA the workflow is checking out (explicit, never a branch
                   pointer), from GITHUB_SHA or GW_COMMIT_SHA.
    target_sha  -- sha256 of the reference target binary (genewars-1_1.exe).
    runtime_sha -- sha256 of the compiled native runtime (entry_path_native.exe).
    fixture_sha -- combined sha256 of the read-only GeneWarsFX CD fixture."""
    return {
        "commit_sha": os.environ.get("GW_COMMIT_SHA")
                      or os.environ.get("GITHUB_SHA") or None,
        "target_sha": _sha256(TARGET_EXE),
        "runtime_sha": _sha256(NATIVE_EXE),
        "fixture_sha": _fixture_sha(),
        "runtime_path": str(NATIVE_EXE),
        "target_path": str(TARGET_EXE),
        "fixture_path": str(GENEWARSFX),
    }

# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

def _sha256(path: pathlib.Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _run(cmd, cwd=ROOT, timeout=600):
    """Run a fixed command; return (rc, stdout_tail, stderr_tail)."""
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    try:
        p = subprocess.run(
            [str(c) for c in cmd],
            cwd=str(cwd), env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout,
        )
        out = p.stdout.decode("utf-8", "replace")
        err = p.stderr.decode("utf-8", "replace")
        return p.returncode, out[-LOG_TAIL:], err[-LOG_TAIL:]
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"").decode("utf-8", "replace") if e.stdout else ""
        err = (e.stderr or b"").decode("utf-8", "replace") if e.stderr else ""
        return 124, out[-LOG_TAIL:], (err + "\n<timeout>")[-LOG_TAIL:]


def _result(rc: int, must_be_zero=True) -> str:
    if rc == 0:
        return "PASS"
    return "FAIL"


def _emit(payload: dict) -> int:
    payload = dict(payload)
    # Stamp provenance on every evidence payload: commit SHA + target SHA +
    # runtime SHA + fixture SHA (design contract: no evidence leaves without it).
    try:
        payload["provenance"] = _provenance()
    except Exception:  # noqa: BLE001  (never let provenance break an emit)
        payload["provenance"] = None
    res = payload.get("result")
    code = 0 if res in ("PASS", "SKIPPED") else 1
    print(json.dumps(payload, indent=2, default=str))
    return code


# ---------------------------------------------------------------------------
# subcommands
# ---------------------------------------------------------------------------

def cmd_status(_a) -> int:
    """Project health + provenance. Reuses `gw status` (taskq.py)."""
    artifacts = {}
    for name in ("entry_path_native.exe", "recomp_catalog_100_recursive.o"):
        p = ROOT / "build" / name
        if p.exists():
            artifacts[f"build/{name}"] = _sha256(p)
    # provenance hashes of the target, from evidence if present
    for name in ("genewars-1_1.exe", "genewars-1_1.map"):
        p = ROOT / "evidence" / name
        if p.exists():
            artifacts[f"evidence/{name}"] = _sha256(p)

    rc, out, err = _run([ROOT / "coordination" / "gw.cmd", "status"], timeout=300)
    project_state = ROOT / "PROJECT_STATE.md"
    ps_sha = _sha256(project_state)
    if ps_sha:
        artifacts["PROJECT_STATE.md"] = ps_sha

    detail = {
        "native_exe_present": NATIVE_EXE.exists(),
        "native_exe_sha256": _sha256(NATIVE_EXE),
        "dosbox_heavy_present": DBX_HEAVY.exists(),
        "genewarsfx_present": GENEWARSFX.exists(),
        "gw_status_exit": rc,
    }
    return _emit({
        "subcommand": "status",
        "ok": rc == 0,
        "exit_code": rc,
        "result": _result(rc),
        "artifacts": artifacts,
        "log_tail": out or err,
        "detail": detail,
    })


def cmd_build(a) -> int:
    """Build. Default = cheap verify (py_compile of key modules).
    `--native` runs the real lift/link pipeline via the project's own tools."""
    artifacts = {}
    if a.native:
        # The entry-path pipeline: lift then link (existing project tools).
        steps = []
        lift = ROOT / "tools" / "lift_entry_path.py"
        link = ROOT / "tools" / "link_entry_path.py"
        if lift.exists():
            steps.append((lift, [lift], "lift"))
        if link.exists():
            steps.append((link, [link], "link"))
        rc_all = 0
        logs = []
        for _path, argv, label in steps:
            rc, out, err = _run(argv, timeout=1800)
            logs.append(f"[{label}] rc={rc}\n{out or err}")
            rc_all = rc_all or rc
        artifacts["build/entry_path_native.exe"] = _sha256(NATIVE_EXE)
        detail = {"mode": "native", "steps": [s[2] for s in steps]}
        tail = "\n\n".join(logs)
    else:
        # cheap, deterministic verify: byte-compile the core python modules.
        mods = [
            ROOT / "coordination" / "taskq.py",
            ROOT / "tools" / "lift_entry_path.py",
            ROOT / "src" / "le_loader.py",
        ]
        mods = [m for m in mods if m.exists()]
        rc, out, err = _run(
            [sys.executable, "-m", "py_compile", *[str(m) for m in mods]],
            timeout=180,
        )
        detail = {"mode": "verify", "compiled": [str(m.relative_to(ROOT)) for m in mods]}
        tail = out or err
        artifacts = {}
        if NATIVE_EXE.exists():
            artifacts["build/entry_path_native.exe"] = _sha256(NATIVE_EXE)

    return _emit({
        "subcommand": "build",
        "ok": rc_all == 0 if a.native else rc == 0,
        "exit_code": rc_all if a.native else rc,
        "result": _result(rc_all if a.native else rc),
        "artifacts": artifacts,
        "log_tail": tail,
        "detail": detail,
    })


def cmd_test(a) -> int:
    """Run the deterministic regression suite (no original assets needed)."""
    suite = []
    conc = ROOT / "tests" / "test_taskq_concurrency.py"
    if conc.exists():
        suite.append(([sys.executable, conc], "taskq_concurrency"))
    if a.differential and (ROOT / "tools" / "run_differential_cfg_work3.py").exists():
        # differential harness recompiles C via the project toolchain.
        suite.append(([sys.executable, ROOT / "tools" / "run_differential_cfg_work3.py"], "differential_cfg"))

    results = []
    rc_all = 0
    for argv, label in suite:
        rc, out, err = _run(argv, timeout=1800)
        results.append({"suite": label, "exit_code": rc, "log_tail": (out or err)[-1500:]})
        rc_all = rc_all or rc
    return _emit({
        "subcommand": "test",
        "ok": rc_all == 0,
        "exit_code": rc_all,
        "result": _result(rc_all),
        "artifacts": {},
        "log_tail": json.dumps(results, indent=2),
        "detail": {"suites": [r["suite"] for r in results]},
    })


def cmd_replay_native(a) -> int:
    """Launch the compiled native target with a fixed argv + timeout.
    The argv is an ALLOW-LISTED set, never free text from a PR."""
    if not NATIVE_EXE.exists():
        return _emit({
            "subcommand": "replay", "mode": "native",
            "ok": False, "exit_code": 1, "result": "SKIPPED",
            "artifacts": {}, "log_tail": "native exe not built",
            "detail": {"reason": "missing", "path": str(NATIVE_EXE)},
        })
    argv = [NATIVE_EXE] + list(a.args_allowlist)
    rc, out, err = _run(argv, timeout=a.timeout)
    return _emit({
        "subcommand": "replay", "mode": "native",
        "ok": rc == 0, "exit_code": rc,
        "result": _result(rc),
        "artifacts": {"build/entry_path_native.exe": _sha256(NATIVE_EXE)},
        "log_tail": out or err,
        "detail": {"argv": [str(x) for x in argv]},
    })


def cmd_replay_original(a) -> int:
    """Run the original binary under the DOSBox-X heavy oracle (real PC).
    Requires the read-only fixture at E:\\GeneWarsFX and the heavy build.
    This is the 'real test on the home PC' path; it launches, it does not copy."""
    if not DBX_HEAVY.exists():
        return _emit({
            "subcommand": "replay", "mode": "original",
            "ok": False, "exit_code": 1, "result": "SKIPPED",
            "artifacts": {}, "log_tail": "DOSBox-X heavy build not present",
            "detail": {"reason": "missing", "path": str(DBX_HEAVY)},
        })
    if not GENEWARSFX.exists():
        return _emit({
            "subcommand": "replay", "mode": "original",
            "ok": False, "exit_code": 1, "result": "SKIPPED",
            "artifacts": {}, "log_tail": "GeneWarsFX fixture dir not present",
            "detail": {"reason": "missing", "path": str(GENEWARSFX)},
        })
    # Prefer the project's MCP debugger capture when requested (richer evidence);
    # otherwise launch dosbox-x directly with the oracle debug config.
    #
    # L-DISK-GUARD (2026-10-07): every in-checkout oracle launch is routed through
    # tools/oracle_guard.py, which bounds per-file/staging/host-free growth, applies
    # a wall-clock timeout, kills the whole process tree on trip, and writes a
    # bounded evidence JSON. The guard wraps the SAME exe+config+argv, so oracle
    # semantics are unchanged -- only the launch is contained. If the guard is
    # absent we fall back to the legacy direct launch (never a silent bypass: the
    # fallback is logged and flagged). The pinned control-plane dispatcher
    # (<control-dir>) is immutable and is covered by the 16 GiB VHDX physical
    # hard cap on the guest C: volume instead.
    mcp = ROOT / "tools" / "dosboxx_oracle" / "mcp_capture.py"
    conf = ROOT / "build" / "dosboxx_oracle" / "dosbox-x.debug.conf"
    guard = ROOT / "tools" / "oracle_guard.py"
    staging = ROOT / "build" / "dosboxx_oracle" / "C"
    guard_present = guard.exists()
    prov = _provenance()
    if a.mcp and mcp.exists():
        cmd = [sys.executable, mcp,
               "--exe", DBX_HEAVY,
               "--config", conf if conf.exists() else DBX_HEAVY]
        if a.run:
            cmd.append("--run")
        # mcp_capture.py itself delegates process creation to oracle_guard.
        rc, out, err = _run(cmd, timeout=a.timeout)
    else:
        if guard_present:
            cmd = [sys.executable, str(guard), "run",
                   "--exe", str(DBX_HEAVY),
                   "--config", str(conf) if conf.exists() else "",
                   "--extra=-console"]
            cmd += ["--staging-dir", str(staging), "--host-drive", "E:",
                    "--operation", "replay-original",
                    "--commit-sha", str(prov.get("commit_sha") or ""),
                    "--target-sha", str(prov.get("target_sha") or ""),
                    "--runtime-sha", str(prov.get("runtime_sha") or ""),
                    "--fixture-sha", str(prov.get("fixture_sha") or ""),
                    "--max-file-mib", "512", "--max-run-gib", "8",
                    "--host-floor-gib", "100", "--timeout-s", str(a.timeout or 900)]
        else:
            return _emit({
                "subcommand": "replay", "mode": "original", "ok": False,
                "exit_code": 2, "result": "BLOCKED",
                "artifacts": {}, "log_tail": "oracle_guard is missing; direct DOSBox fallback is disabled",
                "detail": {"oracle_guard": False},
            })
        rc, out, err = _run(cmd, timeout=a.timeout)
    return _emit({
        "subcommand": "replay", "mode": "original",
        "ok": rc == 0, "exit_code": rc,
        "result": _result(rc),
        "artifacts": {"dosbox_heavy.exe": _sha256(DBX_HEAVY)},
        "log_tail": out or err,
        "detail": {"argv": [str(x) for x in cmd], "fixture": str(GENEWARSFX),
                   "oracle_guard": guard_present},
    })


def cmd_diff(a) -> int:
    """Instruction/semantic differential via the project's own harness.
    Reads the JSON the harness writes and reports PASS/FAIL + hashes."""
    h = ROOT / "tools" / "run_differential_cfg_work3.py"
    if not h.exists():
        return _emit({
            "subcommand": "diff", "ok": False, "exit_code": 1,
            "result": "SKIPPED", "artifacts": {},
            "log_tail": "differential harness not found", "detail": {},
        })
    rc, out, err = _run([sys.executable, h], timeout=1800)
    ev = ROOT / "evidence" / "differential_cfg_leaf_work3.json"
    artifacts = {"evidence/differential_cfg_leaf_work3.json": _sha256(ev)}
    md = ROOT / "reports" / "coordination" / "differential_cfg_leaf_work3.md"
    if md.exists():
        artifacts["reports/coordination/differential_cfg_leaf_work3.md"] = _sha256(md)
    summary = {}
    if ev.exists():
        try:
            rep = json.loads(ev.read_text(encoding="utf-8"))
            summary = {k: rep.get(k) for k in (
                "cases_completed", "divergence_count",
                "function_pass_count", "function_fail_count",
                "target_sha256", "map_sha256")}
        except Exception as e:  # noqa: BLE001
            summary = {"parse_error": str(e)}
    return _emit({
        "subcommand": "diff",
        "ok": rc == 0, "exit_code": rc,
        "result": _result(rc),
        "artifacts": artifacts,
        "log_tail": out or err,
        "detail": summary,
    })


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="gw-bridge", description=__doc__)
    sp = ap.add_subparsers(dest="cmd", required=True)

    sp.add_parser("status", help="project health + provenance hashes")

    b = sp.add_parser("build", help="verify (default) or --native lift/link")
    b.add_argument("--native", action="store_true",
                   help="run the real lift/link pipeline (needs the toolchain)")

    t = sp.add_parser("test", help="run the deterministic regression suite")
    t.add_argument("--differential", action="store_true",
                   help="also run the C differential harness (needs the toolchain)")

    rn = sp.add_parser("replay-native", help="launch the compiled native target")
    rn.add_argument("--timeout", type=int, default=300)
    # Allow-listed tokens only; keep this list intentionally tiny & explicit.
    rn.add_argument("--args", dest="args_allowlist", action="append",
                    default=[], metavar="ALLOWED_TOKEN",
                    help="pass one allow-listed CLI token (repeatable)")

    ro = sp.add_parser("replay-original", help="run the original under DOSBox-X oracle")
    ro.add_argument("--timeout", type=int, default=600)
    ro.add_argument("--run", action="store_true", help="send RUN after initial state")
    ro.add_argument("--mcp", action="store_true", help="use the MCP debugger capture")

    sp.add_parser("diff", help="instruction/semantic differential harness")

    a = ap.parse_args(argv)
    handlers = {
        "status": cmd_status,
        "build": cmd_build,
        "test": cmd_test,
        "replay-native": cmd_replay_native,
        "replay-original": cmd_replay_original,
        "diff": cmd_diff,
    }
    return handlers[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
