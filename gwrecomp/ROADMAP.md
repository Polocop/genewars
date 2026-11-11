# Roadmap

Priorities derived from the audit; ordered roughly by blocking impact.

1. **Portable, reproducible build.** Done so far: paths are configurable, `scripts\setup.ps1`/`build.ps1`/`test.ps1` exist, Level A is reproducible from a clean clone. Open: obtain or regenerate the symbol map so outsiders can run Levels B and C; decide which binary `expected_v07.json` should validate; replace the pinned `pcrecomp` patch with a fork.
2. **Boot and state transitions.** Make the original-byte path reach intros → menu → game without a snapshot; investigate state differences across those transitions; fix first-click-lost after a screen change.
3. **Smacker intros.** Full integration including audio, IRQ0 and the AIL timer path (currently gated off).
4. **Miles audio and music.** Resolve the background hiss, validate the virtual SB16 against more scenarios, harden CD-DA.
5. **Interface and menus.** ESC menu, menu navigation, input mapping, resolution/scaling.
6. **Save and load.** Verify exact guest-state restoration after Load; save compatibility with the original format.
7. **Creature and specialist AI/commands.** Finish the picker-gate investigation so orders are accepted (`MapDisplay+0x18` commit path).
8. **Fidelity vs. original.** Differential testing against the original executable (instruction/semantic oracles), terrain renderer bit-exactness.
9. **Performance and stability.** Memory/heap contracts, long-run stability, timing.
10. **Campaign testing.** Play-through of all missions with logged regressions.

Suggested first issues are in [docs/ISSUES_SEED.md](docs/ISSUES_SEED.md).
