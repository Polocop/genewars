"""Artifact gate for the GWRecomp cloud bridge (L-CLOUD-BRIDGE, Fase 4).

GitHub Actions workflows call this BEFORE uploading any artifact so that
only an allow-list of safe output types ever leaves the machine:

    ALLOWED  : *.json  *.md  *.markdown  *.log  *.txt (bounded)  *.sha256  *.jsonl
               plus the explicit evidence paths a workflow names.
    BLOCKED  : *.exe  *.dll  *.bin  *.cue  *.iso  *.nrg  *.img  *.sub
               *.idb  *.id0  *.id1  *.bytes  *.map  *.s  *.o  *.obj  *.a
               *.lib  *.so  *.pyc  *.dmp  *.stack  and anything under
               E:\\GeneWarsFX (original read-only library) or under build/
               or cache/ or .venv/ or third_party/.

Usage:
    python tools/artifact_gate.py --paths "evidence/x.json" "reports/y.md"
    python tools/artifact_gate.py --paths @filelist.txt
    # exit 0 => all safe; exit 1 => something is blocked (printed, not uploaded)

The gate is intentionally fail-closed: an unknown extension is BLOCKED unless
the workflow explicitly lists it in --allow-extensions.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
GENEWARSFX = pathlib.Path(os.environ.get("GWRECOMP_GENEWARSFX", "E:\\GeneWarsFX"))

# Only these extensions may ever become a GitHub artifact.
ALLOWED_EXT = {
    ".json", ".md", ".markdown", ".log", ".txt", ".sha256", ".jsonl", ".sum",
}

# Anything matching these is hard-blocked no matter what.
BLOCKED_EXT = {
    ".exe", ".dll", ".bin", ".cue", ".iso", ".nrg", ".img", ".sub",
    ".md5", ".mdf", ".idb", ".id0", ".id1", ".bytes", ".map", ".s",
    ".o", ".obj", ".a", ".lib", ".so", ".pyc", ".dmp", ".stack", ".pyd",
    ".pak", ".zip", ".7z", ".rar",
}

# Directory prefixes (relative to repo root) that must never be uploaded.
BLOCKED_DIRS = {
    "build", "cache", ".venv", "venv", "third_party", "Include", "Lib",
    "Scripts", "runner", ".runner", "secrets", "evidence/genewars-1_1.exe",
}


def _resolve(p: str) -> pathlib.Path:
    q = pathlib.Path(p)
    if not q.is_absolute():
        q = ROOT / q
    try:
        q = q.resolve()
    except OSError:
        return pathlib.Path(p)
    return q


def _in_blocked_dir(q: pathlib.Path) -> bool:
    try:
        rel = q.relative_to(ROOT)
        for part in rel.parts[:-1]:
            if part in BLOCKED_DIRS:
                return True
    except ValueError:
        pass
    # outside the repo entirely (e.g. under E:\GeneWarsFX) => block
    if GENEWARSFX.exists():
        try:
            q.relative_to(GENEWARSFX.resolve())
            return True
        except ValueError:
            pass
    return False


def check(path: str, allow_ext: set[str] | None) -> tuple[bool, str]:
    """Return (safe, reason). Fail-closed: a blocked extension or a blocked
    directory is rejected even if the file does not exist on disk, so a
    name-based upload list can never smuggle a .exe/.bin/.cue through."""
    q = _resolve(path)
    ext = q.suffix.lower()
    if ext in BLOCKED_EXT:
        return False, f"blocked-extension ({ext})"
    if _in_blocked_dir(q):
        return False, f"blocked-dir ({q})"
    if not q.exists():
        return True, "missing (skipped)"
    if ext in ALLOWED_EXT:
        return True, f"allowed ({ext})"
    if allow_ext and ext in allow_ext:
        return True, f"allowed-by-flag ({ext})"
    return False, f"unknown-extension ({ext})"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--paths", nargs="+", required=True,
                    help="file paths, or @file that lists one path per line")
    ap.add_argument("--allow-extensions", default="",
                    help="comma list of extra extensions to permit")
    a = ap.parse_args(argv)

    paths = []
    for tok in a.paths:
        if tok.startswith("@"):
            p = _resolve(tok[1:])
            if p.exists():
                paths.extend(ln.strip() for ln in p.read_text().splitlines() if ln.strip())
        else:
            paths.append(tok)

    allow_ext = {e for e in a.allow_extensions.split(",") if e}
    if allow_ext:
        allow_ext = {e if e.startswith(".") else "." + e for e in allow_ext}

    blocked = []
    for p in paths:
        safe, reason = check(p, allow_ext)
        tag = "OK   " if safe else "BLOCK"
        if not safe:
            blocked.append((p, reason))
        print(f"{tag}  {p}  ({reason})")

    if blocked:
        print("\nARTIFACT GATE: BLOCKED (nothing from the list above may be uploaded):")
        for p, r in blocked:
            print(f"  - {p}: {r}")
        return 1
    print("\nARTIFACT GATE: all clear.")
    return 0


if __name__ == "__main__":
    sys.exit(main())