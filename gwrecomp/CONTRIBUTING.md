# Contributing to GWRecomp

Thanks for helping. Please read this first.

## Ground rules

- **Never submit game material**: no executables, data files, Smacker videos, audio, disc images, memory snapshots/dumps, disassembly listings, or generated lifted C of the original binary. PRs containing them will be closed. Hashes and addresses are fine.
- Short test vectors are welcome only when needed; prefer describing behaviour by address and observed values.
- Be honest about verification: say what you ran, on what, and what you could not run.
- No license has been assigned yet; by contributing you agree your contribution may be licensed under whatever license the maintainers later choose after discussion. Open an issue if that is a concern.

## Building and running

See [README.md](README.md) and [`tools/rebuild/README_BUILD.md`](tools/rebuild/README_BUILD.md). In short, from the `gwrecomp` directory:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\setup.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\build.ps1 -Level A
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\test.ps1
```

Levels B and C need your own game files (see the README). Do not hard-code machine paths: use the variables documented in `scripts/gwconfig.ps1` / `README_BUILD.md`.

## Tests

`scripts\test.ps1` (or `python scripts/run_tests.py`) runs every `tests/test_*.py` module and classifies it as PASS, BLOCKED (a named input is missing), KNOWN_FAIL (triaged in `scripts/test_triage.json`) or FAIL (unexpected). A PR must not add unexpected FAILs. If you fix a KNOWN_FAIL, remove its entry; if you add a test that needs private inputs, make it fail with a message naming the missing file so the runner can classify it. Do not delete or weaken tests to get a green result. Current numbers: [docs/TEST_STATUS.md](docs/TEST_STATUS.md).

## Reporting bugs

Use the issue templates. Include Windows version, toolchain versions, exact commands, bounded logs (not full traces), and the game version/hash you used. Do not attach game files.

## Pull requests

- Branch from `gwrecomp-native-port`; keep PRs focused.
- Describe what changed and how you verified it.
- Do not commit build outputs, logs, or caches.
- Do not force-push shared branches.
