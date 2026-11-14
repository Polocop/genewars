#!/usr/bin/env python3
"""oracle_guard -- hard disk-safety containment for every DOSBox/DOSBox-X oracle launch.

L-DISK-GUARD (2026-10-07). After a GeneWars-guest runaway (c:\\ADDRESS.TXT ~145.9 GiB
+ c:\\GENEWARS\\GW.ERR ~41.0 GiB, ~186.9 GiB of E:) left the host with ~4.6 MiB free,
this guard is the single supported, mandatory wrapper for launching any oracle
(DOSBox-X normal, DOSBox-X heavy-debug, DEBUGBOX, the original oracle, any replay).

Two independent containment layers (see reports/DISK_GUARD_DESIGN.md):

  * PHYSICAL hard cap (pending one-time user admin setup): a 16 GiB VHDX mounted as
    the guest's C: volume. This bounds EVERY launch path -- in-checkout bridge, the
    pinned control-plane dispatcher, and manual runs -- even if the watchdog below
    fails completely. See tools/setup_oracle_vhdx.ps1 (run as admin, once).

  * SOFTWARE watchdog (this module): pre-flight checks, a per-tick monitor of
    individual file size, staging total, host free-space floor, wall-clock timeout,
    and sustained-growth runaway detection; a safe abort (clean break, grace, then
    kill the whole process tree); small evidence (bounded samples, never full copies);
    and a bounded JSON evidence file per run.

Why stdlib-only: the project venv has no psutil. Windows API calls go through ctypes
and the documented `taskkill /T` tree-kill. `taskkill /T` kills the entire tree of the
root PID, which is exactly the containment we need for a DOSBox/X + DEBUGBOX child.

Usage (CLI, what the bridge / workflows / control-plane should call):

  python tools/oracle_guard.py run --exe <dosbox-x.exe> --config <conf>
        [--operation NAME] [--commit-sha S] [--target-sha S] [--runtime-sha S]
        [--fixture-sha S] [--staging-dir PATH] [--host-drive E:]
        [--max-file-mib N] [--max-run-gib N] [--host-floor-gib N] [--timeout-s N]
        [--run-id ID] [--extra ARG ...]

  python tools/oracle_guard.py monitor --pid <root-pid> --staging-dir PATH
        [--host-drive E:] [same limit flags] [--run-id ID] [--operation NAME]

Exit code: the child's exit code when it finishes normally; 0 when the guard itself
trips a limit (the abort is *expected* behaviour, not a crash) but the run is marked
ABORTED_BY_DISK_GUARD in the evidence; non-zero on guard-side error.

This module NEVER reads or writes <GENEWARSFX_ROOT> (read-only reference library) and
never launches an oracle directly -- callers pass the already-decided argv.
"""
from __future__ import annotations
import os as _gw_os
from pathlib import Path as _GwPath
_GW_ROOT=str(_GwPath(__file__).resolve().parents[1])
_GW_FX=_gw_os.environ.get("GENEWARSFX_ROOT",_gw_os.path.join(_GW_ROOT,"third_party","GeneWarsFX"))

import argparse
import base64
import ctypes
import ctypes.wintypes as wt
import dataclasses
import hashlib
import json
import math
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parents[1]
GENEWARSFX = Path(os.environ.get("GWRECOMP_GENEWARSFX", (_GW_FX)))
SANDBOX_VERIFY = ROOT / "tools" / "verify_oracle_sandbox.ps1"
SANDBOX_REQUIRED = True  # production policy; no CLI/environment opt-out

# --- Windows process-creation flags -------------------------------------------
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_NO_WINDOW = 0x08000000
DETACHED_PROCESS = 0x00000008
INFINITE = 0xFFFFFFFF

# TEST-only injection point (Test D): maps drive letter -> forced free bytes.
# Production code never sets this; the real value is read.
_FREE_OVERRIDE: dict[str, int] = {}

# ctypes: GetDiskFreeSpaceExW
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_GetDiskFreeSpaceExW = _kernel32.GetDiskFreeSpaceExW
_pui64 = ctypes.POINTER(ctypes.c_ulonglong)
_GetDiskFreeSpaceExW.argtypes = [wt.LPWSTR, _pui64, _pui64, _pui64]
_GetDiskFreeSpaceExW.restype = wt.BOOL


# ---------------------------------------------------------------------------
# limits
# ---------------------------------------------------------------------------

@dataclass
class Limits:
    """Soft defaults + hard maxima. The guard refuses to run with values above
    the hard maxima, so a bad override can never re-open the runaway path.

    Defaults (conservative, per the brief):
      max_file_text  = 512 MiB   (per individual .txt/.err/.log/.trace/.dmp/.dump)
      max_file_bin   = 1024 MiB  (per individual binary -- generous for legit .iso/dumps)
      max_run        = 8 GiB     (total staging for the run)
      host_floor     = 100 GiB   (free space that must remain on the host drive)
      timeout        = 900 s     (15 min)
      growth_text    = 8 MiB/s sustained   (early runaway detect, text/log family)
      growth_bin     = 24 MiB/s sustained (early runaway detect, binary family)
      growth_window  = 5 samples at 1 Hz (~5 s) before a rate is trusted

    Hard maxima (never exceed, even if a caller asks):
      max_file_text <= 2 GiB
      max_file_bin  <= 4 GiB
      max_run       <= 16 GiB
      host_floor    <= 512 GiB
      timeout       <= 3600 s (60 min)
    """
    max_file_text: int = 512 * 1024 * 1024
    max_file_bin: int = 1024 * 1024 * 1024
    max_run: int = 8 * 1024 * 1024 * 1024
    host_floor: int = 100 * 1024 * 1024 * 1024
    timeout: int = 900
    growth_text_mibs: float = 8.0
    growth_bin_mibs: float = 24.0
    growth_window: int = 5
    poll_hz: float = 1.0

    # hard maxima -- the guard will refuse to start if an override exceeds these
    HARD = {
        "max_file_text": 2 * 1024 * 1024 * 1024,
        "max_file_bin": 2 * 1024 * 1024 * 1024,
        "max_run": 16 * 1024 * 1024 * 1024,
        "host_floor": 512 * 1024 * 1024 * 1024,
        "timeout": 3600,
    }

    @classmethod
    def from_args(cls, a: argparse.Namespace) -> "Limits":
        def g(name: str, default):
            v = getattr(a, name, None)
            return default if v is None else v
        L = cls()
        # file-size limits (bytes)
        if a.max_file_mib is not None:
            L.max_file_text = int(a.max_file_mib * 1024 * 1024)
            L.max_file_bin = L.max_file_text
        if a.max_file_text_mib is not None:
            L.max_file_text = int(a.max_file_text_mib * 1024 * 1024)
        if a.max_file_bin_mib is not None:
            L.max_file_bin = int(a.max_file_bin_mib * 1024 * 1024)
        if a.max_run_gib is not None:
            L.max_run = int(a.max_run_gib * 1024 * 1024 * 1024)
        if a.host_floor_gib is not None:
            L.host_floor = int(a.host_floor_gib * 1024 * 1024 * 1024)
        if a.timeout_s is not None:
            L.timeout = int(a.timeout_s)
        if a.growth_text_mibs is not None:
            L.growth_text_mibs = float(a.growth_text_mibs)
        if a.growth_bin_mibs is not None:
            L.growth_bin_mibs = float(a.growth_bin_mibs)
        if a.poll_hz is not None:
            L.poll_hz = float(a.poll_hz)
        L.clamp()
        return L

    def clamp(self) -> "Limits":
        """Refuse to run if any override exceeds a hard maximum."""
        for k, cap in self.HARD.items():
            v = getattr(self, k)
            if v > cap:
                raise ValueError(
                    f"oracle_guard: limit {k}={v} exceeds hard maximum {cap}; "
                    f"refusing to run. Lower the override."
                )
        if self.max_file_text <= 0 or self.max_file_bin <= 0 or self.max_run <= 0:
            raise ValueError("oracle_guard: non-positive size limit; refusing to run")
        if self.timeout <= 0:
            raise ValueError("oracle_guard: non-positive timeout; refusing to run")
        return self

    def as_dict(self) -> dict:
        return {
            "max_file_text": self.max_file_text,
            "max_file_bin": self.max_file_bin,
            "max_run": self.max_run,
            "host_floor": self.host_floor,
            "timeout_s": self.timeout,
            "growth_text_mibs": self.growth_text_mibs,
            "growth_bin_mibs": self.growth_bin_mibs,
            "growth_window": self.growth_window,
            "poll_hz": self.poll_hz,
            "hard_max": dict(self.HARD),
        }


# which extensions are "text/log" family for the stricter per-file limit + growth
TEXT_EXT = {".txt", ".err", ".log", ".trace", ".trc"}
# anything not in TEXT_EXT is treated as binary (looser)
def _is_text(path: Path) -> bool:
    return path.suffix.lower() in TEXT_EXT


# ---------------------------------------------------------------------------
# low-level probes (stdlib / ctypes only)
# ---------------------------------------------------------------------------

def drive_free_bytes(drive: str, override: Optional[int] = None) -> Optional[int]:
    """Free space in bytes on a drive ('E:'). Returns None on error.

    `override` is a TEST-only injection (Test D: free-space floor without filling
    E:). In production it is always None and the real value is read.
    """
    if override is not None:
        return int(override)
    ov = _FREE_OVERRIDE.get(drive.upper().rstrip("\\:"))
    if ov is not None:
        return int(ov)
    drive = drive.upper().strip()
    if not re.fullmatch(r"[A-Z]:\\?", drive):
        return None
    if not drive.endswith(":"):
        drive = drive.rstrip("\\") + ":"
    free = ctypes.c_ulonglong(0)
    total = ctypes.c_ulonglong(0)
    avail = ctypes.c_ulonglong(0)
    ok = _GetDiskFreeSpaceExW(drive, ctypes.byref(total),
                              ctypes.byref(avail), ctypes.byref(free))
    if not ok:
        return None
    return int(free.value)


def file_scan(staging: Path) -> list[dict]:
    """Recursively list files under staging with size/mtime/extension class."""
    out = []
    if not staging.exists():
        return out
    try:
        for p in staging.rglob("*"):
            try:
                if not p.is_file():
                    continue
                st = p.stat()
                out.append({
                    "path": str(p),
                    "rel": str(p.relative_to(staging)),
                    "size": st.st_size,
                    "mtime": st.st_mtime,
                    "text": _is_text(p),
                })
            except OSError:
                continue
    except OSError:
        pass
    return out


def lexical_path(path: os.PathLike | str) -> Path:
    """Absolute normalized path without resolving Windows volume mountpoints.

    Path.resolve() follows a mountpoint to its drive letter (for example the
    intended E:\\...\\C staging path becomes R:\\), losing the policy path.
    Keep the configured path lexical; the PowerShell verifier independently
    proves which VHDX volume owns it.
    """
    return Path(os.path.abspath(os.path.normpath(os.fspath(path))))


def staging_total_bytes(staging: Path) -> int:
    return sum(f["size"] for f in file_scan(staging))


# ---------------------------------------------------------------------------
# runaway / evidence
# ---------------------------------------------------------------------------

def _sample_file(path: Path, head: int = 64 * 1024,
                 tail: int = 64 * 1024) -> dict:
    """Bounded evidence sample: first `head` bytes, last `tail` bytes, and a
    small middle slice. Never reads a huge file more than O(head+tail)."""
    sz = path.stat().st_size
    res = {
        "path": str(path),
        "size": sz,
        "head": b"", "tail": b"", "middle": b"",
        "head_sha256": None, "tail_sha256": None,
    }
    try:
        with open(path, "rb") as f:
            hb = f.read(head)
            f.seek(0, os.SEEK_END)
            f.seek(-min(tail, sz), os.SEEK_END) if sz > tail else f.seek(0)
            tb = f.read(tail)
            midoff = max(0, (sz // 2) - 8192)
            if sz > (head + tail + 16384):
                f.seek(midoff)
                mb = f.read(16384)
            else:
                mb = b""
        res["head"] = hb
        res["tail"] = tb
        res["middle"] = mb
        res["head_sha256"] = hashlib.sha256(hb).hexdigest()
        res["tail_sha256"] = hashlib.sha256(tb).hexdigest()
    except OSError:
        pass
    return res


def preserve_samples(files: list[dict], staging: Path, max_samples: int = 3,
                     max_bytes_each: int = 64 * 1024) -> list[dict]:
    """Pick the largest files (the runaway candidates) and sample them."""
    cand = sorted(files, key=lambda f: f["size"], reverse=True)[:max_samples]
    out = []
    for f in cand:
        p = Path(f["path"])
        if not p.exists():
            continue
        if f["size"] < (1024 * 1024):  # skip <1 MiB -- not a runaway
            continue
        s = _sample_file(p)
        # bound base64 payloads so the evidence JSON stays small
        for key in ("head", "tail", "middle"):
            b = s.get(key, b"")
            if len(b) > max_bytes_each:
                b = b[:max_bytes_each]
            s[key] = base64.b64encode(b).decode("ascii")
        out.append(s)
    return out


def kill_tree(pid: int, root: Optional[subprocess.Popen] = None) -> list[int]:
    """Kill the entire process tree rooted at `pid`.

    Uses `taskkill /T /F /PID` which kills the process and all its descendants
    (DOSBox/X + any DEBUGBOX child + any coprocess). Records which PIDs we saw.
    Falls back to a best-effort SIGKILL on the Popen handle if taskkill fails.
    """
    killed = []
    # try to enumerate the tree first (best-effort, for the evidence log).
    # Use bytes + errors="replace" (not text=True) so a non-ASCII / garbled
    # reader thread can never raise and take the evidence capture down with it.
    try:
        out = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
            capture_output=True, timeout=10,
        ).stdout.decode("utf-8", "replace")
        for line in out.splitlines():
            m = re.search(r'"(\d+)"', line)
            if m:
                killed.append(int(m.group(1)))
    except Exception:
        pass
    # kill the tree
    try:
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(pid)],
                       capture_output=True, timeout=30)
        killed.append(pid)
    except Exception as e:
        # fall back: if we own the Popen handle, kill it directly
        if root is not None:
            try:
                root.kill()
            except Exception:
                pass
        print(f"oracle_guard: taskkill failed ({e}); attempted root.kill()",
              file=sys.stderr)
    return killed


def _wait_gone(root: Optional[subprocess.Popen], grace_s: float = 5.0) -> bool:
    """Wait up to grace_s for the process to actually exit; True if it did."""
    if root is None:
        return True
    try:
        root.wait(timeout=grace_s)
        return True
    except subprocess.TimeoutExpired:
        return False


# ---------------------------------------------------------------------------
# the watchdog
# ---------------------------------------------------------------------------

@dataclass
class WatchResult:
    exit_reason: str = "PASS"          # PASS | ABORTED_BY_DISK_GUARD
    cause: Optional[str] = None         # FILE_SIZE_LIMIT | RUN_STAGING_LIMIT |
    #                                     HOST_FREE_SPACE_FLOOR | SANDBOX_FULL |
    #                                     FILE_GROWTH_RATE | SANDBOX_FULL | TIMEOUT
    exit_code: int = 0
    killed: list[int] = field(default_factory=list)
    samples: list[dict] = field(default_factory=list)
    max_file_seen: dict = field(default_factory=dict)
    max_staging_seen: int = 0
    ticks: int = 0
    started: float = 0.0
    ended: float = 0.0

    @property
    def duration(self) -> float:
        return self.ended - self.started if self.started else 0.0


def _trip(res: WatchResult, cause: str, detail: str, files: list[dict],
          staging: Path, host_free: Optional[int], limit: int) -> dict:
    res.exit_reason = "ABORTED_BY_DISK_GUARD"
    res.cause = cause
    res.detail = detail
    # preserve small samples of the largest offenders (never full copies)
    res.samples = preserve_samples(files, staging)
    res.max_staging_seen = max(res.max_staging_seen, staging_total_bytes_safe(staging))
    return {
        "cause": cause, "detail": detail,
        "host_free": host_free, "limit": limit,
    }


def staging_total_bytes_safe(staging: Path) -> int:
    try:
        return staging_total_bytes(staging)
    except Exception:
        return 0


def watchdog(root_pid: int, staging: Path, limits: Limits,
             host_drive: str, root: Optional[subprocess.Popen] = None,
             extra_watch: Optional[Path] = None,
             res: Optional[WatchResult] = None) -> WatchResult:
    """Poll until the child exits or a limit trips. Returns the result.

    `root` is the Popen handle (run mode) so we can wait on it / kill it. In
    monitor mode root is None and we rely on taskkill + the host floor / timeout
    to bound an externally-launched tree.

    `res` lets a caller (run_oracle's watchdog thread, monitor_pid) pass in the
    SAME WatchResult it will read after the call, so the thread's mutations
    (exit_reason / cause / killed / samples / max_*_seen) are visible to the
    caller. When omitted, a fresh WatchResult is created here.
    """
    if res is None:
        res = WatchResult(started=time.time())
    limit = limits
    poll = max(0.2, 1.0 / max(0.2, limit.poll_hz))
    window = max(3, int(limit.growth_window))
    # per-file recent samples for growth detection: path -> deque[(t,size)]
    hist: "dict[str, list[tuple[float, int]]]" = {}
    start_free = drive_free_bytes(host_drive)
    deadline = res.started + limit.timeout

    while True:
        now = time.time()
        res.ticks += 1
        host_free = drive_free_bytes(host_drive)
        files = file_scan(staging)
        total = sum(f["size"] for f in files)
        res.max_staging_seen = max(res.max_staging_seen, total)
        big = max(files, key=lambda f: f["size"], default=None)
        if big:
            res.max_file_seen = {"path": big["path"], "size": big["size"]}
        try:
            sandbox_free = shutil.disk_usage(staging).free
        except OSError:
            sandbox_free = None

        def alive() -> bool:
            if root is not None:
                return root.poll() is None
            # monitor mode: assume alive until taskkill reports / pid reaps
            try:
                import ctypes as _c
                kernel = _c.WinDLL("kernel32", use_last_error=True)
                SYNCHRONIZE = 0x00100000
                h = kernel.OpenProcess(SYNCHRONIZE, False, root_pid)
                if not h:
                    return False
                r = kernel.WaitForSingleObject(h, 0)
                kernel.CloseHandle(h)
                return r != 0x00000000  # WAIT_OBJECT_0 == exited
            except Exception:
                return True

        if sandbox_free == 0:
            _trip(res, "SANDBOX_FULL", "sandbox volume has no free bytes",
                  files, staging, host_free, 0)
            _do_abort(res, root, root_pid, staging, files)
            return res

        if not alive():
            # child exited on its own -> normal completion
            res.exit_reason = "PASS"
            res.cause = None
            res.ended = now
            return res

        # --- limit checks (priority order) --------------------------------
        # 1) per-file size
        for f in files:
            cap = limit.max_file_text if f["text"] else limit.max_file_bin
            if f["size"] > cap:
                _trip(res, "FILE_SIZE_LIMIT",
                      f"{f['rel']} reached {f['size']} bytes (> {cap})",
                      files, staging, host_free, cap)
                _do_abort(res, root, root_pid, staging, files)
                return res
        # 2) staging total for the run
        if total > limit.max_run:
            _trip(res, "RUN_STAGING_LIMIT",
                  f"staging total {total} bytes (> {limit.max_run})",
                  files, staging, host_free, limit.max_run)
            _do_abort(res, root, root_pid, staging, files)
            return res
        # 3) host free-space floor
        if host_free is not None and host_free < limit.host_floor:
            _trip(res, "HOST_FREE_SPACE_FLOOR",
                  f"{host_drive} free {host_free} bytes (< floor {limit.host_floor})",
                  files, staging, host_free, limit.host_floor)
            _do_abort(res, root, root_pid, staging, files)
            return res
        # 4) sustained growth runaway (early detect, before absolute caps)
        growth = _detect_growth(files, hist, limit, now, window)
        if growth is not None:
            cause, detail = growth
            _trip(res, cause, detail, files, staging, host_free,
                  int(limit.growth_text_mibs * 1024 * 1024))
            _do_abort(res, root, root_pid, staging, files)
            return res
        # 5) timeout
        if now > deadline:
            _trip(res, "TIMEOUT",
                  f"run exceeded {limit.timeout}s wall-clock",
                  files, staging, host_free, limit.timeout)
            _do_abort(res, root, root_pid, staging, files)
            return res
        time.sleep(poll)


def _detect_growth(files, hist, limit, now, window):
    """Return (cause, detail) if any file shows sustained runaway growth."""
    mib = 1024 * 1024
    for f in files:
        rel = f["rel"]
        h = hist.setdefault(rel, [])
        h.append((now, f["size"]))
        # trim to window worth of samples
        while len(h) > window + 2 and (now - h[0][0]) > window:
            h.pop(0)
        if len(h) < window:
            continue
        oldest_t, oldest_s = h[0]
        newest_t, newest_s = h[-1]
        span = newest_t - oldest_t
        if span < 1.0:
            continue
        growth = (newest_s - oldest_s) / span  # bytes/s
        if growth <= 0:
            continue
        thr = (limit.growth_text_mibs if f["text"] else limit.growth_bin_mibs) * mib
        if growth > thr:
            if f["text"]:
                return ("FILE_GROWTH_RATE",
                        f"{rel} growing {growth/mib:.1f} MiB/s sustained "
                        f"> {limit.growth_text_mibs} MiB/s")
            else:
                return ("FILE_GROWTH_RATE",
                        f"{rel} growing {growth/mib:.1f} MiB/s sustained "
                        f"> {limit.growth_bin_mibs} MiB/s (binary)")
    return None


def _do_abort(res, root, root_pid, staging, files):
    res.ended = time.time()
    if root is not None:
        # Clean break first (Windows: send CTRL_BREAK to the child's own new
        # process group; DOSBox/X and most emulators honour it for a graceful
        # exit). Best-effort -- if it's ignored we escalate to a hard kill.
        for sig in (getattr(signal, "CTRL_BREAK_EVENT", None),
                    getattr(signal, "CTRL_C_EVENT", None)):
            if sig is None:
                continue
            try:
                os.kill(root_pid, sig)
                break
            except Exception:
                continue
        if not _wait_gone(root, grace_s=3.0):
            res.killed = kill_tree(root_pid, root)
        else:
            res.killed = [root_pid]
            res.exit_code = root.returncode if root.returncode is not None else 0
    else:
        res.killed = kill_tree(root_pid, root)
    # verify no writer is still growing the staging dir
    time.sleep(1.0)
    post = file_scan(staging)
    if post:
        post_max = max(f["size"] for f in post)
        pre_max = res.max_file_seen.get("size", 0)
        if post_max > pre_max + (1024 * 1024):
            # still growing -> escalate to a second hard kill
            res.killed = list(dict.fromkeys(res.killed + kill_tree(root_pid, root)))


# ---------------------------------------------------------------------------
# run mode (in-checkout launchers pass exe+config; the guard owns the child)
# ---------------------------------------------------------------------------

def run_oracle(exe: str, config: Optional[str], extra: list[str],
               limits: Limits, staging: Path, host_drive: str,
               run_id: str, operation: str, prov: dict,
               evidence_dir: Path, create_flags: int) -> dict:
    argv = [exe]
    if config:
        argv += ["-conf", config]
    argv += extra
    argv = [str(a) for a in argv]
    staging.mkdir(parents=True, exist_ok=True)
    host_free_before = drive_free_bytes(host_drive)
    try:
        sandbox = sandbox_info(staging)
    except Exception as e:
        sandbox = {"verified": False, "capacity_bytes": None,
                   "reason": str(e), "mount_path": str(staging)}
    res = WatchResult(started=time.time())
    ev = {
        "run_id": run_id,
        "start_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(res.started)),
        "operation": operation,
        "command_kind": operation,
        "argv": argv,
        "staging": str(staging),
        "staging_path": str(staging),
        "host_drive": host_drive,
        "host_free_before": host_free_before,
        "sandbox": sandbox,
        "sandbox_verified": sandbox.get("verified", False),
        "sandbox_capacity": sandbox.get("capacity_bytes"),
        "provenance": prov,
        "limits": limits.as_dict(),
        # filled below
    }
    proc = None
    aborted = False
    try:
        proc = subprocess.Popen(
            argv, cwd=str(staging),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=create_flags,
        )
        res.ticks = 0
        # capture bounded stdout/stderr so a runaway can't fill our pipes
        outbuf = _bounded_pipe_reader(proc.stdout)
        errbuf = _bounded_pipe_reader(proc.stderr)
        # run the watchdog in a thread so we can drain pipes concurrently.
        # It mutates the SAME `res` object we read below (via res=), so the
        # thread's exit_reason/cause/killed/samples are visible to us after join.
        wt_ = threading.Thread(target=watchdog,
                               args=(proc.pid, staging, limits, host_drive, proc),
                               kwargs={"res": res}, daemon=True)
        wt_.start()
        wt_.join()
        res.ended = time.time()
        # drain any remaining pipe data (bounded)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            kill_tree(proc.pid, proc)
        out_data = outbuf.getvalue()
        err_data = errbuf.getvalue()
        ev["stdout_tail"] = out_data[-4000:].decode("utf-8", "replace")
        ev["stderr_tail"] = err_data[-4000:].decode("utf-8", "replace")
        ev["exit_reason"] = res.exit_reason
        ev["cause"] = res.cause
        ev["detail"] = getattr(res, "detail", None)
        ev["exit_code"] = (res.exit_code if res.cause else
                           (proc.returncode if proc.returncode is not None else 0))
        ev["killed_processes"] = res.killed[:200]
        ev["samples_preserved"] = res.samples
        ev["max_file_seen"] = res.max_file_seen
        ev["max_staging_seen"] = res.max_staging_seen
        aborted = (res.exit_reason == "ABORTED_BY_DISK_GUARD")
    except Exception as e:  # guard-side failure, not a limit trip
        ev["guard_error"] = repr(e)
        ev["exit_reason"] = "GUARD_ERROR"
        ev["exit_code"] = 1
        if proc is not None and proc.poll() is None:
            try:
                kill_tree(proc.pid, proc)
            except Exception:
                pass
    finally:
        host_free_after = drive_free_bytes(host_drive)
        ev["host_free_after"] = host_free_after
        ev["end_time"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(res.ended))
        ev["duration_s"] = round(res.duration, 3)
        ev["ticks"] = res.ticks
        evidence_dir.mkdir(parents=True, exist_ok=True)
        evpath = evidence_dir / f"oracle_runs_{run_id}.json"
        evpath.write_text(json.dumps(ev, indent=2, ensure_ascii=False),
                          encoding="utf-8")
        ev["evidence_path"] = str(evpath)
    # exit code contract: 0 if the run PASSED or was expectedly aborted by the guard
    if ev["exit_reason"] in ("PASS", "ABORTED_BY_DISK_GUARD"):
        return {**ev, "ok": True}
    return {**ev, "ok": False}


def _bounded_pipe_reader(stream):
    """Drain a pipe on a background thread, keeping only the last N bytes."""
    import collections
    buf = collections.deque(maxlen=64)
    cap = 4 * 1024 * 1024  # 4 MiB retained
    stop = threading.Event()

    class _R:
        def __init__(self, s):
            self.s = s
            self.data = b""
            self._thread = threading.Thread(target=self._drain, daemon=True)
            self._thread.start()
        def _drain(self):
            while True:
                try:
                    b = self.s.read(65536)
                except Exception:
                    break
                if not b:
                    break
                self.data = (self.data + b)[-cap:]
        def getvalue(self):
            self._thread.join(timeout=2)
            return self.data
    return _R(stream)


# ---------------------------------------------------------------------------
# monitor mode (wrap an already-running external PID -- e.g. the pinned
# control-plane dispatcher or a manual DOSBox-X)
# ---------------------------------------------------------------------------

def monitor_pid(root_pid: int, staging: Path, limits: Limits, host_drive: str,
                run_id: str, operation: str, prov: dict, evidence_dir: Path) -> dict:
    host_free_before = drive_free_bytes(host_drive)
    res = WatchResult(started=time.time())
    ev = {
        "run_id": run_id,
        "start_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(res.started)),
        "operation": operation,
        "monitored_pid": root_pid,
        "staging": str(staging),
        "host_drive": host_drive,
        "host_free_before": host_free_before,
        "sandbox": None,
        "provenance": prov,
        "limits": limits.as_dict(),
    }
    try:
        watchdog(root_pid, staging, limits, host_drive, root=None, res=res)
        res.ended = time.time()
        ev["exit_reason"] = res.exit_reason
        ev["cause"] = res.cause
        ev["detail"] = getattr(res, "detail", None)
        ev["exit_code"] = res.exit_code
        ev["killed_processes"] = res.killed[:200]
        ev["samples_preserved"] = res.samples
        ev["max_file_seen"] = res.max_file_seen
        ev["max_staging_seen"] = res.max_staging_seen
        ev["exit_reason"] = res.exit_reason
    except Exception as e:
        ev["guard_error"] = repr(e)
        ev["exit_reason"] = "GUARD_ERROR"
        ev["exit_code"] = 1
    finally:
        ev["host_free_after"] = drive_free_bytes(host_drive)
        ev["end_time"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(res.ended))
        ev["duration_s"] = round(res.duration, 3)
        ev["ticks"] = res.ticks
        evidence_dir.mkdir(parents=True, exist_ok=True)
        evpath = evidence_dir / f"oracle_runs_{run_id}.json"
        evpath.write_text(json.dumps(ev, indent=2, ensure_ascii=False), encoding="utf-8")
        ev["evidence_path"] = str(evpath)
    ev["ok"] = ev["exit_reason"] in ("PASS", "ABORTED_BY_DISK_GUARD")
    return ev


# ---------------------------------------------------------------------------
# pre-flight (shared by run + monitor)
# ---------------------------------------------------------------------------

def preflight(staging: Path, host_drive: str, limits: Limits,
              staging_arg: Optional[str]) -> tuple[bool, str]:
    """Return (ok, message). Fails closed on any safety violation."""
    # 1) staging must exist / be creatable and must NOT be GeneWarsFX or inside it
    try:
        s = lexical_path(staging)
    except Exception as e:
        return False, f"staging path does not resolve: {e}"
    g = GENEWARSFX.resolve()
    if s == g or g in s.parents or s in g.parents:
        return False, f"REFUSED: staging {s} is inside/identical to read-only {g}"
    # 2) host drive present + floor sanity
    hf = drive_free_bytes(host_drive)
    if hf is None:
        return False, f"host drive {host_drive} not found"
    if hf < limits.host_floor:
        return False, (f"host floor already breached before start: {host_drive} "
                       f"free {hf} < floor {limits.host_floor}; abort heavy tasks")
    # 3) refuse to point staging at a read-only source / the fixture
    for banned in (GENEWARSFX,):
        try:
            if s == banned or banned in s.parents:
                return False, f"REFUSED: staging points at read-only {banned}"
        except Exception:
            pass
    staging.mkdir(parents=True, exist_ok=True)
    if SANDBOX_REQUIRED:
        # The PowerShell verifier asks Windows for the mounted volume identity,
        # partition capacity and access path. A normal E: directory is a hard
        # failure; never silently fall back to it.
        try:
            check = subprocess.run(
                ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                 "-File", str(SANDBOX_VERIFY), "-Path", str(s), "-Json"],
                capture_output=True, text=True, timeout=30,
            )
            payload = json.loads(check.stdout.strip().splitlines()[-1]) if check.stdout.strip() else {}
            if check.returncode != 0 or not payload.get("verified"):
                return False, "HARD_SANDBOX_REQUIRED: " + str(payload.get("reason", check.stderr[-1000:] or "verification failed"))
            if lexical_path(payload.get("mount_path", "")) != s:
                return False, "HARD_SANDBOX_REQUIRED: staging is not the verified VHDX mountpoint"
        except Exception as e:
            return False, f"HARD_SANDBOX_REQUIRED: VHDX verification unavailable: {e}"
    return True, "ok"


def sandbox_info(staging: Path) -> dict:
    """Return bounded mount metadata for run evidence."""
    if not SANDBOX_REQUIRED:
        return {"verified": False, "capacity_bytes": None, "mount_path": str(staging)}
    check = subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
         "-File", str(SANDBOX_VERIFY), "-Path", str(staging), "-Json"],
        capture_output=True, text=True, timeout=30,
    )
    payload = json.loads(check.stdout.strip().splitlines()[-1]) if check.stdout.strip() else {}
    payload["verified"] = bool(check.returncode == 0 and payload.get("verified"))
    return payload


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _add_limit_args(p: argparse.ArgumentParser):
    p.add_argument("--max-file-mib", type=int, default=None,
                   help="per-file cap (MiB) for both text+binary; overrides text/bin")
    p.add_argument("--max-file-text-mib", type=int, default=None)
    p.add_argument("--max-file-bin-mib", type=int, default=None)
    p.add_argument("--max-run-gib", type=float, default=None,
                   help="total staging cap (GiB) for the run")
    p.add_argument("--host-floor-gib", type=float, default=None,
                   help="host free-space floor (GiB)")
    p.add_argument("--timeout-s", type=int, default=None)
    p.add_argument("--growth-text-mibs", type=float, default=None)
    p.add_argument("--growth-bin-mibs", type=float, default=None)
    p.add_argument("--poll-hz", type=float, default=None)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="oracle_guard", description=__doc__)
    sp = ap.add_subparsers(dest="cmd", required=True)

    r = sp.add_parser("run", help="launch the oracle child and guard it")
    r.add_argument("--exe", required=True)
    r.add_argument("--config", default=None)
    r.add_argument("--extra", nargs="*", default=[])
    r.add_argument("--staging-dir", required=True)
    r.add_argument("--host-drive", default="E:")
    r.add_argument("--run-id", default=None)
    r.add_argument("--operation", default="replay-original")
    r.add_argument("--commit-sha", default=None)
    r.add_argument("--target-sha", default=None)
    r.add_argument("--runtime-sha", default=None)
    r.add_argument("--fixture-sha", default=None)
    r.add_argument("--evidence-dir", default=None)
    r.add_argument("--no-new-group", action="store_true",
                   help="do not create a new process group (not recommended)")
    _add_limit_args(r)

    m = sp.add_parser("monitor", help="guard an already-running root PID")
    m.add_argument("--pid", type=int, required=True)
    m.add_argument("--staging-dir", required=True)
    m.add_argument("--host-drive", default="E:")
    m.add_argument("--run-id", default=None)
    m.add_argument("--operation", default="replay-external")
    m.add_argument("--commit-sha", default=None)
    m.add_argument("--target-sha", default=None)
    m.add_argument("--runtime-sha", default=None)
    m.add_argument("--fixture-sha", default=None)
    m.add_argument("--evidence-dir", default=None)
    _add_limit_args(m)
    return ap


def _default_run_id(operation: str) -> str:
    return f"ldg_{operation}_{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}"


def main(argv: Optional[list[str]] = None) -> int:
    ap = build_parser()
    a = ap.parse_args(argv)
    limits = Limits.from_args(a)
    host_drive = a.host_drive
    staging = Path(a.staging_dir)
    run_id = a.run_id or _default_run_id(a.operation)
    evdir = Path(a.evidence_dir) if a.evidence_dir else (ROOT / "evidence" / "oracle_runs")
    prov = {
        "commit_sha": a.commit_sha,
        "target_sha": a.target_sha,
        "runtime_sha": a.runtime_sha,
        "fixture_sha": a.fixture_sha,
    }

    ok, msg = preflight(staging, host_drive, limits, a.staging_dir)
    if not ok:
        cause = ("HOST_FREE_SPACE_FLOOR" if "host floor already breached" in msg
                 else "OTHER_GUARD_FAILURE")
        payload = {
            "run_id": run_id, "operation": a.operation, "ok": False,
            "start_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "end_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "command_kind": a.operation, "staging_path": str(staging),
            "host_free_before": drive_free_bytes(host_drive),
            "sandbox_verified": False, "sandbox_capacity": None,
            "exit_reason": "PREFLIGHT_FAILED", "cause": cause, "detail": msg,
            "exit_code": 2, "provenance": prov, "limits": limits.as_dict(),
        }
        evdir.mkdir(parents=True, exist_ok=True)
        (evdir / f"oracle_runs_{run_id}.json").write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        print(json.dumps(payload))
        return 2

    if a.cmd == "run":
        create_flags = 0 if a.no_new_group else CREATE_NEW_PROCESS_GROUP
        res = run_oracle(a.exe, a.config, a.extra, limits, staging, host_drive,
                         run_id, a.operation, prov, evdir, create_flags)
        print(json.dumps(res))
        return 0 if res["ok"] else 1
    elif a.cmd == "monitor":
        res = monitor_pid(a.pid, staging, limits, host_drive, run_id,
                          a.operation, prov, evdir)
        print(json.dumps(res))
        return 0 if res["ok"] else 1
    else:  # pragma: no cover
        ap.print_help()
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
