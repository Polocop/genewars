# DOSBox-X heavy-debug oracle probe

The DOSBox-X clone/build is isolated under `third_party/dosbox-x` and `build/dosboxx-heavy`; do not copy or modify game files under `<GENEWARSFX_ROOT>`.

The source debugger supports `CPU`, `GDT`, `LDT`, protected-mode `BPM`, selector-relative memory-change `BPPM`, linear `BPLM`, `BPINT`, `BPLIST`, `MEMDUMP`, and the optional MCP TCP control channel (`mcp_server=58991`). The confirmed debugger command forms come from upstream `README.debugger` and the checked out source.

## Address resolution before breakpoints

1. Start with the exact staged 1.1 MAIN, `-k`, empty `config.ini`, and original CUE/BIN set. Preserve the reference hashes.
2. At DOSBox-X debugger stop, capture `CPU`, `GDT`, `LDT`, and `HELP`. Record CS/DS/SS/ES selectors and descriptor bases, limits, access/present state. Determine the loaded LE object bases from live descriptors and observed code mapping; derive the relocation delta from the code selector/EIP at a verified MAIN instruction.
3. MAP `this` link VA `0x114CA8` belongs to LE data object 3 at object-relative offset `0x14CA8` (per W3-048 evidence). Identify the live selector whose base and limit map that object. Then arm `BPPM <selector>:<0x14CA8>` and record resolved linear `base+offset`. This deliberately does not assume Unicorn's `0x214CA8`.
4. Arm code breakpoints at link VAs `0x194AC0`, `0x194B51`, and `0x194B5A` only after deriving DOSBox's live relocation/selector mapping. At every stop capture CPU, GDT/LDT, breakpoint list, stack, nearby MAP bytes, and caller returns.
5. The first BPPM hit is the writer evidence: stop before resuming, save old/new value and instruction bytes/EIP, caller chain, all registers/flags/segments and descriptor state. Compare against `evidence/setup_game_this_provenance_work3.json` and the W3-054 caller trace. Align the full event streams and name the first divergence.

## Downstream video breakpoints

Prepare breakpoints using the same measured load mapping for `setup_game` return, PlayIntro `0x94342`, game `0x94347`, `LbScreenSetupAnyMode_` `0x9FD40`, its `LbVesaSetMode_` call `0x9FDCC`, and `LbVesaSetPage_` `0xA3A5C`. Track unique INT10 sites `0xA3A91`/`0xA3AB7`; capture AX/BX/CX/DX/ES:DI and outputs. Watch the live resolved mapping for global `0x19CA58` at assignment site `0x9FDEF` and set a write watch over the actual mapped A0000 VGA region after mode set. Record first palette IO/BIOS write, first blit/callback, and slot `0x1A029C` old/new value with writer EIP. `0xA0000`/`0x19CA58` are candidates, not observed framebuffer facts.

## Known process exit control

No-CD `-k` ends at `0x1AFC33` with DOS INT 21h AH=4Ch, AL=0 after the required-CD message. This is expected for that fixture and is not MENU. Compare equivalent branch and exit service in DOSBox; do not conflate it with the CD-present `setup_game` route.

## First palette I/O probe

The DOSBox-X debug build has a local one-shot, logging-only hook in `src/hardware/iohandler.cpp` for the first guest write to VGA DAC index/data ports `0x3C8/0x3C9`. It records guest CS:EIP, port, width, value, GPRs, EFLAGS, and segment selectors under the marker `W3_FIRST_VGA_PALETTE_WRITE`; the regular I/O handler receives the same port/value. The exact patch is saved at `tools/dosboxx_oracle/patches/first_vga_palette_event.patch`. This event is classified by its caller/EIP before calling it game palette work because DOS/BIOS may write a palette earlier.
