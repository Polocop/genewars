# Contributing to GWRecomp

Thanks for helping. Please read this first.

## Ground rules

- **Never submit game material**: no executables, data files, Smacker videos, audio, disc images, memory snapshots/dumps, disassembly listings, or generated lifted C of the original binary. PRs containing them will be closed. Hashes and addresses are fine.
- Short test vectors are welcome only when needed; prefer describing behaviour by address and observed values.
- Be honest about verification: say what you ran, on what, and what you could not run.
- No license has been assigned yet; by contributing you agree your contribution may be licensed under whatever license the maintainers later choose after discussion. Open an issue if that is a concern.

## Building and running

See [README.md](README.md) and [`tools/rebuild/README_BUILD.md`](tools/rebuild/README_BUILD.md). You need your own copy of the game. The build currently assumes the author's Windows layout; making it portable is a welcome contribution.

## Tests

Tests are `unittest` modules under `tests/`, run from this directory:

```
python -m unittest tests.test_<name>
```

Create `build/` and `cache/` directories first. Many tests need local inputs that are deliberately not published. [docs/TEST_STATUS.md](docs/TEST_STATUS.md) separates, for all 466 modules, those that pass on a clean checkout (92), those blocked by missing external inputs (364, not counted as failures) and those needing triage (10).

## Reporting bugs

Use the issue templates. Include Windows version, toolchain versions, exact commands, bounded logs (not full traces), and the game version/hash you used. Do not attach game files.

## Pull requests

- Branch from `gwrecomp-native-port`; keep PRs focused.
- Describe what changed and how you verified it.
- Do not commit build outputs, logs, or caches.
- Do not force-push shared branches.
