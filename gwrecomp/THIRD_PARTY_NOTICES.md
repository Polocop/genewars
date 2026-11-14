# Third-party notices

This file is informational and is not legal advice. Nothing here has been reviewed by counsel.

## pcrecomp (MIT)

`tools/rebuild/patches/P01_pcrecomp_local_mods.patch` is a patch against <https://github.com/sp00nznet/pcrecomp> commit `35548b8d0fd8aa853da67edcf7cd6134f6b9cdc7` (five files, ~660 changed lines, with surrounding context lines from the upstream). pcrecomp itself is **not** vendored. Its license notice is reproduced here because the patch contains upstream text:

```
MIT License

Copyright (c) 2026 sp00nz

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## DOSBox-X (GPL-2.0)

`tools/dosboxx_oracle/patches/first_vga_palette_event.patch` (48 lines) patches `src/hardware/iohandler.cpp` of DOSBox-X, licensed under the GNU GPL version 2 (see <https://github.com/joncampbell123/dosbox-x/blob/master/COPYING>). Only the patch is included. We treat the patch as covered by GPL-2.0. It is used for a local reference-run oracle and is not part of any distributed GWRecomp binary. Whether other files in this repository that interoperate with that oracle are affected is **not** established.

## Others

`tools/`, `runtime/` and `tests/` reference but do not include: Unicorn, Capstone, SDL2, Open Watcom runtime behaviour, Miles Sound System (AIL3DIG) driver behaviour, Smacker. Their licenses are those of their owners.


The license texts for the two patches are also stored next to them: `tools/rebuild/patches/LICENSE-pcrecomp-MIT.txt` and `tools/dosboxx_oracle/patches/LICENSE-DOSBox-X-GPL-2.0.txt`.
