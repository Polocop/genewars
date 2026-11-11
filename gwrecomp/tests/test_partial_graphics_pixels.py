"""Run the original 1.1 graphics-window clear over a guarded guest surface."""
import os as _gw_os
from pathlib import Path as _GwPath
_GW_ROOT=str(_GwPath(__file__).resolve().parents[1])
_GW_MSYS2=_gw_os.environ.get("MSYS2_ROOT",r"C:\msys64")
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PYTHON = ROOT / ".venv" / "Scripts" / "python.exe"
GCC = Path((_GW_MSYS2 + '\\mingw32\\bin\\gcc.exe'))
TARGET = ROOT / "evidence" / "genewars-1_1.exe"
REA = ROOT / "evidence" / "rea_partial_graphics_pixel_analysis.json"
ENV = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "TEMP": str(ROOT / "cache"),
       "TMP": str(ROOT / "cache"), "TMPDIR": str(ROOT / "cache"),
       "PATH": (_GW_ROOT + '\\build\\staging-w3-253-exec\\Debug;' + _GW_MSYS2 + '\\mingw32\\bin;' + _GW_MSYS2 + '\\usr\\bin;') + os.environ.get("PATH", "")}
EXPECTED_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
FB = 0x390000
VIDEO_FB = 0x000A0000
# Experimental presentation surface; no authentic mode dimensions are claimed.
SCREEN_W, SCREEN_H = 320, 200
DRAW_X, DRAW_Y, DRAW_W, DRAW_H = 10, 20, 64, 32
COLOR, INITIAL = 0x5A, 0x11


def run(cmd, *, echo=True):
    result = subprocess.run([str(x) for x in cmd], cwd=ROOT, env=ENV,
                            text=True, capture_output=True)
    if echo and result.stdout:
        print(result.stdout, end="")
    if echo and result.stderr:
        print(result.stderr, end="")
    if result.returncode:
        raise SystemExit(f"command exit {result.returncode}: {cmd}")
    return result


def bmp24(path, pixels):
    """Diagnostic grayscale view of the captured byte indices (not game palette)."""
    width, height = SCREEN_W, SCREEN_H
    row_bytes = (width * 3 + 3) & ~3
    rows = bytearray()
    for y in range(height - 1, -1, -1):
        row = bytearray()
        for x in range(width):
            shade = pixels[y * width + x]
            row.extend((shade, shade, shade))
        row.extend(b"\0" * (row_bytes - width * 3))
        rows.extend(row)
    file_size = 14 + 40 + len(rows)
    header = struct.pack("<2sIHHI", b"BM", file_size, 0, 0, 54)
    dib = struct.pack("<IiiHHIIiiII", 40, width, height, 1, 24, 0,
                      len(rows), 2835, 2835, 0, 0)
    path.write_bytes(header + dib + rows)


def read_bmp_rgb(path, x, y):
    """Read one BMP sample so SDL presentation is checked against guest bytes."""
    data = path.read_bytes()
    pixel_offset = struct.unpack_from("<I", data, 10)[0]
    width, height = struct.unpack_from("<ii", data, 18)
    bpp = struct.unpack_from("<H", data, 28)[0]
    if data[:2] != b"BM" or bpp not in (24, 32) or not (0 <= x < width and 0 <= y < abs(height)):
        raise SystemExit(f"unsupported SDL BMP layout: {path}, {width}x{height}x{bpp}")
    row_bytes = ((width * bpp + 31) // 32) * 4
    source_y = y if height < 0 else abs(height) - 1 - y
    offset = pixel_offset + source_y * row_bytes + x * (bpp // 8)
    blue, green, red = data[offset:offset+3]
    return red, green, blue


def verify_sdl_capture_matches_guest(path, pixels):
    data = path.read_bytes()
    if data[:2] != b"BM":
        raise SystemExit("SDL presentation capture is not a BMP")
    pixel_offset = struct.unpack_from("<I", data, 10)[0]
    width, height = struct.unpack_from("<ii", data, 18)
    bpp = struct.unpack_from("<H", data, 28)[0]
    if (width, abs(height)) != (SCREEN_W*3, SCREEN_H*3) or bpp not in (24, 32):
        raise SystemExit(f"unexpected SDL capture geometry/format: {width}x{height}x{bpp}")
    row_bytes = ((width * bpp + 31) // 32) * 4
    expanded = bytearray()
    for y in range(SCREEN_H):
        for x in range(SCREEN_W):
            sample = y*SCREEN_W+x
            expected = pixels[sample]
            for dy in range(3):
                source_y = y*3+dy if height < 0 else abs(height)-1-(y*3+dy)
                for dx in range(3):
                    offset = pixel_offset+source_y*row_bytes+(x*3+dx)*(bpp//8)
                    blue, green, red = data[offset:offset+3]
                    if (red, green, blue) != (expected,)*3:
                        raise SystemExit(f"SDL capture mismatch at guest video pixel ({x},{y}) replica ({dx},{dy})")
            expanded.append(expected)
    if hashlib.sha256(expanded).digest() != hashlib.sha256(pixels).digest():
        raise SystemExit("SDL capture sample hash differs from post-swap video bytes")


def main():
    raw_target = TARGET.read_bytes()
    digest = hashlib.sha256(raw_target).hexdigest()
    if digest != EXPECTED_SHA256:
        raise SystemExit(f"GeneWars 1.1 target hash changed: {digest}")
    rea = json.loads(REA.read_text())
    if rea["target"]["sha256"] != digest or rea["provider"] != {
            "id": "ghidra", "name": "Ghidra", "version": "12.1.4", "rea": "6.4.0"}:
        raise SystemExit("REA evidence identity does not match the canonical 1.1 target")

    # Verify REA's link-coordinate carrier bytes against the original LE with
    # Capstone's parser. The lifted code below separately uses measured 1/3 deltas.
    sys.path[:0] = [str(ROOT / "src"), str(ROOT / "third_party" / "pcrecomp")]
    from le_loader import load_le
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    image = load_le(TARGET)
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for record in rea["bytes"]:
        address = int(record["address"], 16)
        owner = image.object_containing(address)
        if owner is None:
            raise SystemExit(f"REA byte range outside LE objects at {record['address']}")
        source = bytes(image.object_data(owner.index)[address-owner.base:
                       address-owner.base+record["requested_bytes"]])
        if source.hex() != record["bytes_hex"]:
            raise SystemExit(f"REA/LE byte mismatch at {record['address']}")
        decoded = list(md.disasm(source, address))
        if not decoded or decoded[0].address != address:
            raise SystemExit(f"Capstone could not decode REA bytes at {record['address']}")
    swap_owner = image.object_containing(0x9FFE0)
    swap_code = bytes(image.object_data(swap_owner.index))
    swap_function_insns = [
        {"address": f"0x{i.address:08X}", "bytes": i.bytes.hex(),
         "mnemonic": i.mnemonic, "operands": i.op_str}
        for i in md.disasm(swap_code[0x9FFE0-swap_owner.base:0xA008F-swap_owner.base], 0x9FFE0)
    ]
    if not any(i["address"] == "0x000A0013" and i["mnemonic"] == "rep movsd"
               for i in swap_function_insns):
        raise SystemExit("Capstone did not confirm the original VGA REP MOVSD site")

    run([PYTHON, "tools/lift_entry_path.py", "--object-map", "measured-1-3",
         "--partial-root", "0x96338", "--partial-root", "0x9FEB0", "--partial-root", "0x9FFE0",
         "--stack-range", "0x3FE000:0x2000", "--dynamic-range", "0x390000:0x10000",
         "--rep-movsd-source-range", "0x390000:0x10000",
         "--rep-movsd-destination-range", "0x000A0000:0x10000"], echo=False)
    report_path = ROOT / "evidence" / "partial_entry_path_lifts.json"
    report = json.loads(report_path.read_text())
    lifted = {int(row["address"], 16): row for row in report["lifted"]}
    required = {0x96338, 0x9FEB0, 0x9FFE0, 0xA16F0, 0xA1824, 0xBBB10, 0xB7050, 0xB7087}
    if not required.issubset(lifted):
        raise SystemExit(f"partial closure misses original functions: {sorted(required-set(lifted))}")
    if report["missing_or_unsupported"] or report["partial_rejections"]:
        raise SystemExit("partial closure contains unsupported code or rejected dependencies")
    if report["object_map"][1]["linear_base_verified"] or report["object_map"][3]["linear_base_verified"]:
        raise SystemExit("test must leave unknown LE objects 2 and 4 unresolved")
    if report["dynamic_guest_ranges"] != [["0x00390000", "0x003A0000"]]:
        raise SystemExit("dynamic surface contract changed")
    if report["rep_movsd_guest_ranges"] != {
            "source": ["0x00390000", "0x003A0000"],
            "destination": ["0x000A0000", "0x000B0000"]}:
        raise SystemExit("REP MOVSD source/destination contracts changed")
    rep_movsd_sites = {row["instruction"] for row in report["dynamic_accesses"]
                       if row["instruction"] in {"0x000A0013", "0x000A005D"}}
    if rep_movsd_sites != {"0x000A0013", "0x000A005D"}:
        raise SystemExit("partial closure misses a verified REP MOVSD operand contract")
    generated = (ROOT / report["output"]).read_text()
    if ("L_00096C10:" not in generated or "goto L_00096C10" not in generated or
            "RECOMP_CALL(recomp_gw_partial_STOSD)" not in generated):
        raise SystemExit("the generated closure lost the original memset/STOSD path")

    exe = ROOT / "build" / "test_partial_graphics_pixels.exe"
    run([GCC, "-std=gnu11", "-m32", "-O0", "-DRECOMP_TRACE", "-I", ROOT / "runtime",
         "-I", (_GW_MSYS2 + '\\mingw32\\include\\SDL2'),
         "-I", ROOT / "third_party/pcrecomp/runtime/recomp32", "-o", exe,
         ROOT / "tests/test_partial_graphics_pixels.c", ROOT / "build/partial_entry_path.c",
         ROOT / "runtime/recomp_context.c", ROOT / "runtime/gw_interrupts.c",
         ROOT / "runtime/gw_segments.c", ROOT / "runtime/gw_pit8254.c",
         "-L", (_GW_MSYS2 + '\\mingw32\\lib'), "-lSDL2"])
    process = run([exe])
    swap_access_line = next((line for line in process.stdout.splitlines()
                             if line.startswith("SWAP_ACCESS ")), None)
    if swap_access_line is None:
        raise SystemExit("native harness did not preserve REP MOVSD memory access provenance")

    surface_path = ROOT / "evidence" / "partial_graphics_pixel_surface.raw"
    pixels = surface_path.read_bytes()
    if len(pixels) != SCREEN_W * SCREEN_H:
        raise SystemExit(f"surface has {len(pixels)} bytes, expected {SCREEN_W*SCREEN_H}")
    for y in range(SCREEN_H):
        for x in range(SCREEN_W):
            expected = COLOR if DRAW_X <= x < DRAW_X+DRAW_W and DRAW_Y <= y < DRAW_Y+DRAW_H else INITIAL
            if pixels[y*SCREEN_W+x] != expected:
                raise SystemExit(f"buffer mismatch at ({x},{y}): {pixels[y*SCREEN_W+x]:02X} != {expected:02X}")

    video_path = ROOT / "evidence" / "partial_graphics_pixel_video.raw"
    video = video_path.read_bytes()
    if len(video) != SCREEN_W * SCREEN_H or video != pixels:
        raise SystemExit("LbScreenSwap destination does not exactly match the guest WScreen source")

    bmp = ROOT / "evidence" / "partial_graphics_pixel_surface.bmp"
    bmp24(bmp, pixels)
    presented = ROOT / "evidence" / "partial_graphics_pixel_sdl_present.bmp"
    if read_bmp_rgb(presented, 5*3, 5*3) != (INITIAL,)*3:
        raise SystemExit("SDL presentation background does not match original guest buffer bytes")
    if read_bmp_rgb(presented, (DRAW_X+5)*3+1, (DRAW_Y+5)*3+1) != (COLOR,)*3:
        raise SystemExit("SDL presentation rectangle does not match GeneWars guest writes")
    verify_sdl_capture_matches_guest(presented, video)
    evidence = {
        "execution_mode": "bounded_partial_authentic_lift",
        "natural_boot_framebuffer": False,
        "target_sha256": digest,
        "rea_provider": {"name": "Ghidra", "version": "12.1.4", "rea": "6.4.0",
                         "carrier_sha256": rea["carrier"]["sha256"]},
        "rea_evidence": rea["function_evidence"],
        "swap_analysis": {
            "rea_evidence_ids": {
                "function": "ev_97b8d064185efe5eb8e9bad4a5eb94c423e66314f1e103a4685353c294098751",
                "assembly": "ev_f6b12e6ef701706573c763fdbce217d9d15759f77f5b83c1a9c46981fefb1699",
                "callers": "ev_b68dd9f44a17564cd854b8a08b36867d8bba147950d061dfa777291d38bf8ac8",
                "mouse_place": "ev_635fc134cedee7ba75cd2ab55bac2ef8a1b19283a3908e2fad85a868a320f470",
                "mouse_remove": "ev_32639fd015e06956af985fd76782f6894fae5fe868c81477702b49b81a2ca384",
                "vesa_page": "ev_3fb439de01c5371b601280c9c72bd1e019abc875ddbf2ec0d7628470fe38659a"},
            "capstone_original_instructions": swap_function_insns,
            "interpretation": "REA/Ghidra decompilation is corroborated against Capstone decoding of bytes in canonical LE; the controlled fixture only executes the non-VESA branch."},
        "original_functions_executed": [
            {"name": "LbScreenSetGraphicsWindow_", "link_va": "0x96338"},
            {"name": "LbScreenClearGraphicsWindow_", "link_va": "0x9FEB0"},
            {"name": "LbScreenSwap_", "link_va": "0x9FFE0"},
            {"name": "FUN_000A16F0", "link_va": "0xA16F0"},
            {"name": "FUN_000A1824", "link_va": "0xA1824"},
            {"name": "LbMemorySet_", "link_va": "0xBBB10"},
            {"name": "memset_", "link_va": "0x96C10"},
            {"name": "__STOSB", "link_va": "0xB7050"},
            {"name": "__STOSD", "link_va": "0xB7087"}],
        "closure": {"lifted_link_addresses": [f"0x{x:08X}" for x in sorted(lifted)],
                    "inline_tail_body_addresses": ["0x00096C10"],
                    "executed_original_path": ["0x0009FEB0", "0x000BBB10", "0x00096C10",
                                               "0x000B7050", "0x000B7087"],
                    "known_guest_objects": [1, 3], "objects_2_and_4": "unresolved; not referenced by this closure",
                    "dynamic_guest_range": report["dynamic_guest_ranges"][0],
                    "rep_movsd_ranges": report["rep_movsd_guest_ranges"]},
        "screen_swap": {"link_va": "0x0009FFE0", "source_global_link_va": "0x0019CA5C",
                        "destination_global_link_va": "0x0019CA58",
                        "size_expression": "4*floor((width*height)/4) bytes via dword REP MOVSD",
                        "copy_instruction": "REP MOVSD at 0x000A0013 in conventional VGA branch",
                        "fixture_source_guest": f"0x{FB:08X}",
                        "fixture_destination_guest": f"0x{VIDEO_FB:08X}",
                        "fixture_copy_bytes": SCREEN_W*SCREEN_H,
                        "vesa_branch_executed": False,
                        "mode_pitch_palette": "experimental contiguous 320-byte pitch; no authentic mode, VBE response, or palette asserted"},
        "swap_access_diagnostics": swap_access_line,
        "experimental_surface": {"guest_base": f"0x{FB:08X}", "width_bytes": SCREEN_W,
                                  "height_rows": SCREEN_H, "pitch_bytes": SCREEN_W,
                                  "dimensions_verified_for_original_mode": False,
                                  "pitch_verified_for_original_mode": False,
                                  "pixel_interpretation": "byte-indexed window path: x advances by one byte and color is an 8-bit value; no VESA mode selection or game palette is claimed",
                                  "fill_rect": {"x": DRAW_X, "y": DRAW_Y, "width": DRAW_W, "height": DRAW_H},
                                  "initial_byte": f"0x{INITIAL:02X}", "fill_byte": f"0x{COLOR:02X}"},
        "checks": ["REA byte ranges match canonical LE bytes", "Capstone decodes the same link-coordinate bytes",
                   "generated original-code closure compiled and ran in gw_recomp_invoke",
                   "function-entry trace includes setter, clear-window, LbScreenSwap_, mouse helpers, LbMemorySet, __STOSB and __STOSD",
                   "backed guest memory and before/after guard canaries checked",
                   f"{DRAW_W*DRAW_H} writes hit exactly the requested rectangle; all other non-stack guest bytes unchanged",
                   "original x86 fill stores and guest access context checked",
                   "LbScreenSwap_ original REP MOVSD copied WScreen into a separate bounded guest video destination",
                   "video destination byte-for-byte equals WScreen after swap; destination canaries unchanged",
                   "all SDL capture pixels are checked against the expanded grayscale post-swap video bytes"],
        "surface_raw_sha256": hashlib.sha256(pixels).hexdigest(),
        "surface_raw": "evidence/partial_graphics_pixel_surface.raw",
        "video_raw_sha256": hashlib.sha256(video).hexdigest(),
        "video_raw": "evidence/partial_graphics_pixel_video.raw",
        "surface_bmp_sha256": hashlib.sha256(bmp.read_bytes()).hexdigest(),
        "surface_bmp": "evidence/partial_graphics_pixel_surface.bmp",
        "surface_bmp_palette": "grayscale visualization of byte values; not GeneWars palette data",
        "sdl_present": {"window_title": "GeneWars 1.1 recomp — experimental authentic swapped video buffer",
                        "window_size": [SCREEN_W*3, SCREEN_H*3],
                        "source": "post-LbScreenSwap_ guest video destination at 0x000A0000; SDL conversion/presentation does not generate or modify guest pixels",
                        "presented_surface": "evidence/partial_graphics_pixel_sdl_present.bmp",
                        "presented_surface_sha256": hashlib.sha256((ROOT/"evidence/partial_graphics_pixel_sdl_present.bmp").read_bytes()).hexdigest(),
                        "palette": "diagnostic identity grayscale; not original game palette"},
        "process_output": process.stdout.splitlines(),
        "passed": True}
    out = ROOT / "evidence" / "partial_graphics_pixel_write.json"
    out.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(f"PASS authentic pixel buffer: {surface_path.relative_to(ROOT)}")
    print(f"PASS authentic LbScreenSwap_ destination: {video_path.relative_to(ROOT)}")
    print(f"PASS SDL capture matches every post-swap byte sample: {presented.relative_to(ROOT)}")
    print(f"PASS diagnostic BMP (grayscale byte visualization): {bmp.relative_to(ROOT)}")
    print(f"PASS evidence: {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
