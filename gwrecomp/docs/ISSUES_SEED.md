# Issue seeds and labels

Suggested labels: `good first issue`, `help wanted`, `audio`, `video`, `rendering`, `reverse-engineering`, `gameplay`, `testing`, `documentation`, `build`.

Each item lists labels and a definition of done.

1. **Parameterise hard-coded build paths** — `build`, `help wanted`. Largely done (see `scripts/gwconfig.ps1`); remaining: maintainers-only oracle tools and residual literals. *Done when* a second machine reproduces Levels A and B.
2. **Document each test's prerequisites** — `testing`, `documentation`, `good first issue`. Produce a table of tests vs. required external inputs. *Done when* every module under `tests/` is classified (self-contained / needs evidence / needs third_party) and self-contained ones pass on a clean checkout.
3. **Fix tests that fail on a clean checkout due to missing directories** — `testing`, `good first issue`. Create `build/`/`cache/` on demand. *Done when* no test fails with `FileNotFoundError` for these.
4. **Replace pcrecomp patch with a fork/pin** — `build`, `help wanted`. Follow "Migrating to an own fork" in `tools/rebuild/README_BUILD.md`.
5. **Smacker audio and AIL timer/IRQ0 path** — `audio`, `video`, `reverse-engineering`. *Done when* an intro plays with audio and a bounded run records no mixer/DMA errors.
6. **Miles background hiss** — `audio`, `help wanted`. A/B capture with `GW_VSB16_CAPTURE` and attribute the cause.
7. **First-click-lost after screen change** (`title_unjugador_after_biolose`) — `gameplay`, `reverse-engineering`. *Done when* the first click after a transition is delivered in a reproducible test.
8. **Creature order acceptance (picker gate)** — `gameplay`, `reverse-engineering`. *Done when* a selected creature accepts a move/research order with same-run guest evidence.
9. **Original-byte boot path to menu** — `reverse-engineering`. *Done when* startup passes `setup_game` through intros to the menu without snapshots.
10. **Save/load state restoration check** — `gameplay`, `testing`. *Done when* guest state after Load is compared to expectations by an automated check.
11. **Rendering bit-exactness of terrain** — `rendering`, `help wanted`.
12. **Portable CI smoke test (docs-only lint, scripts parse)** — `testing`, `good first issue`.
13. **`SAVE0.SAV` dependency** - `build`, `testing`, `reverse-engineering`, `help wanted`. The driver pins the digest of a save file the maintainers created. *Done when* the replays have a validated profile that does not need it (or another reproducible solution is documented), and Level B runs on an install without it.
14. **Readable name overlay from the user's own disc** - `reverse-engineering`, `help wanted`. Rebuild names for the 1.1 binary from the retail disc's `MAIN.MAP` with the existing matchers, as a local optional tool (nothing derived is published). *Done when* precision against the private reference map is measured and reported as counts.
