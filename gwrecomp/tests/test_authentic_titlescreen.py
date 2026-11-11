"""Run the original 1.1 title RNC decoder and VESA LbScreenSwap closure."""
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

ROOT = Path(__file__).resolve().parents[1]
PYTHON = ROOT / ".venv" / "Scripts" / "python.exe"
GCC = Path(r"E:\msys64\mingw32\bin\gcc.exe")
TARGET = ROOT / "evidence" / "genewars-1_1.exe"
REA = ROOT / "evidence" / "rea_graphics_setup_20261011.json"
ASSET_DIR = (ROOT / "build" / "dosboxx_oracle" /
             "C.seed.20261007_185846" / "GENEWARS" / "DATA")
PAL = ASSET_DIR / "TITLESCR.PAL"
DAT = ASSET_DIR / "TITLESCR.DAT"
SETUP_SEED = ROOT / "evidence" / "genewars_11_object3_setup_seed.raw"
EXPECTED = {
    TARGET: "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f",
    PAL: "d5ec91e731c2ff7e8d74dbbde6a3fe0410ec602ff0da52eb1e6f6bb1a44307c7",
    DAT: "2548b024fede333b49fc4011541939fc8ce294cb95b48cdb41ed7d0cec54a0b9",
}
ENV = {
    **os.environ,
    "PYTHONDONTWRITEBYTECODE": "1",
    "TEMP": str(ROOT / "cache"), "TMP": str(ROOT / "cache"),
    "TMPDIR": str(ROOT / "cache"),
    "PATH": (r"E:\GWRecomp\build\staging-w3-253-exec\Debug;"
             r"E:\msys64\mingw32\bin;E:\msys64\usr\bin;" + os.environ.get("PATH", "")),
}
WIDTH, HEIGHT = 640, 480
VIDEO_BYTES = WIDTH * HEIGHT
REA_DIRECT = {
    "provider": {"name": "Ghidra", "version": "12.1.4", "rea": "6.4.0"},
    "carrier_sha256": "1523022fb1febcfb939b2ed04145ee6e7dcd8b99113d932d21d33301c0052a97",
    "evidence_ids": {
        "LbScreenSetup": "ev_d8e61f108ebc8f61bde521437e082519ec35acd3bd9b5a2159578dbe886a6f48",
        "LbScreenSetupAnyMode": "ev_de57b19facb5c731bf7006fca4af8354f0a820dcf27f363dc690b4873cecd52c",
        "LbVesaSetMode": "ev_414263d86fcf88e9b2823a8701248ec6c6caea116d2f224a1b4d775e70338b1f",
        "LbVesaSetPage": "ev_c2aae81806242277500da8d7d255c9148a15b33f5d16c9c604c6b5f98d970b5d",
        "palette_writer": "ev_62c154a0c5ba45a7b30da73ca65b203dd4232fa9501682f340c5a83c665b1688",
        "mode_info": "ev_dcd9f1479825383230048667fd91c57ebd916842db9396652229656ed45e9078",
        "title_rnc1_decoder": "ev_eeb9b24c320823735680f88dd09b125979e1728086fd2e7d42b4ea9e91778838",
        "mode_available": "ev_c13ec35867860e67eb3d7fc7a37b21b7987ae413d2b6750048d1779590e3fe61",
        "mode_state_setup": "ev_826933ea70988992b9fd8a58443727856cefa8318e23b05497a225eac7003c7f",
        "real_mode_call_wrapper": "ev_f1ddfb554783b7d4ff21b40cc92cf291560b7976f02c437f52a2697f91350e6f",
        "real_mode_trampoline": "ev_fb4296687592b1932b0bc3bcd09a37374315214e98c41d8664f231a33fb3cba0",
        "real_mode_trampoline_callee": "ev_ea5d3e9a85b6d4a82f03e8e8714caac0978b977a871a8e7e3958526bda6eb3b9",
        "mode_interrupt_thunks": ["ev_24c3013156c96c2aed9f129008b88b8d1d13cb63c1c37a4b3976b144d4bdcf72",
                                  "ev_713446f97a0e885740f7671b92771547cbfe35bb2b31dbffe8908380c7126a6b"],
        "title_loader_FUN_00070D10": "ev_ce4736d9b2f8823f2d89111defe89bdb89c3f6489d5d568d8696e8e1fab46d28",
        "title_presenter_FUN_00092710": "ev_2e9c4630d062076a3ec424c279a67f7da7afb6de2731bd5d0df204775f0341da",
        "startup_sequence_FUN_00093F30": "ev_6867fbbf7cf9af8eea8a4c8b99d4a740b7590f43bd3d93330d1fb58d92239c94",
        "post_title_cleanup_FUN_0009FC90": "ev_f5fc0b7fd41b12f600e19cf390981f659771b20af9ceedfe6d488bc58ab0c291",
        "next_assets_FUN_000954A0": "ev_f40dd669cb4305d308ef65b6d523bf6021c43a35bf73588e0b0890c8c0fc3660",
    },
}


def run(command, *, echo=True):
    result = subprocess.run([str(part) for part in command], cwd=ROOT, env=ENV,
                            text=True, capture_output=True)
    if echo and result.stdout:
        print(result.stdout, end="")
    if echo and result.stderr:
        print(result.stderr, end="")
    if result.returncode:
        raise SystemExit(f"exit {result.returncode}: {command}\n{result.stderr}")
    return result


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_capture(path, pixels, palette):
    data = path.read_bytes()
    if data[:2] != b"BM":
        raise SystemExit("SDL capture is not a BMP")
    offset = struct.unpack_from("<I", data, 10)[0]
    w, h = struct.unpack_from("<ii", data, 18)
    bpp = struct.unpack_from("<H", data, 28)[0]
    if (w, abs(h), bpp) != (WIDTH * 2, HEIGHT * 2, 32):
        raise SystemExit(f"unexpected SDL BMP format: {w}x{h}x{bpp}")
    pitch = ((w * bpp + 31) // 32) * 4
    for y in range(HEIGHT):
        for x in range(WIDTH):
            index = pixels[y * WIDTH + x]
            expected = tuple((palette[index * 3 + i] * 255 // 63) for i in range(3))
            for dy in range(2):
                file_y = y * 2 + dy if h < 0 else abs(h) - 1 - (y * 2 + dy)
                for dx in range(2):
                    p = offset + file_y * pitch + (x * 2 + dx) * 4
                    blue, green, red = data[p:p + 3]
                    if (red, green, blue) != expected:
                        raise SystemExit(f"SDL BMP differs from indexed palette at ({x},{y})")


def main():
    before = {p: digest(p) for p in EXPECTED}
    for path, expected in EXPECTED.items():
        if before[path] != expected:
            raise SystemExit(f"protected input hash mismatch: {path}: {before[path]}")
    rea = json.loads(REA.read_text(encoding="utf-8"))
    if rea["target"]["sha256"] != EXPECTED[TARGET] or rea["target"]["provider"] != "REA 6.4.0 / Ghidra 12.1.4":
        raise SystemExit("REA static-analysis record is not bound to the canonical GeneWars 1.1 target")
    native_vesa = json.loads((ROOT / "evidence/w3_100_targeted_vesa_capture.json").read_text())
    natural_mode_event = next((row for row in native_vesa["trace"]["target_events"]
                               if row["checkpoint"] == "VIDEO_VESA_SET_MODE_ENTRY"), None)
    if not natural_mode_event or (natural_mode_event["eax"], natural_mode_event["ebx"],
                                  natural_mode_event["ecx"]) != (0x101, 0x101, 13):
        raise SystemExit("original W3-100 mode 0x101 evidence changed or is incomplete")

    # Cross-check the REA link-address interpretation against original LE bytes
    # and independently decode the actual entry instructions with Capstone.
    sys.path.insert(0, str(ROOT / "src"))
    from le_loader import load_le
    le = load_le(TARGET)
    capstone = Cs(CS_ARCH_X86, CS_MODE_32)
    original_code = []
    for va, expected_mnemonic in ((0xB9CFC, "push"), (0xADEAC, "push"),
                                  (0x9FFE0, "push"), (0xA3A5C, "push"),
                                  (0x962F0, "push"), (0x9FD40, "push"),
                                  (0xD2344, "int"), (0xD23A7, "int")):
        obj = le.object_containing(va)
        if obj is None:
            raise SystemExit(f"original LE has no object at 0x{va:08X}")
        data = bytes(le.object_data(obj.index)[va - obj.base:va - obj.base + 16])
        insns = list(capstone.disasm(data, va))
        if not insns or insns[0].mnemonic != expected_mnemonic:
            raise SystemExit(f"Capstone/LE entry mismatch at 0x{va:08X}")
        original_code.append({"link_va": f"0x{va:08X}", "bytes": insns[0].bytes.hex(),
                              "mnemonic": insns[0].mnemonic, "operands": insns[0].op_str})
    le = load_le(TARGET, object_rebases={1: 0x1EB000, 3: 0x1DA000})
    setup_object = le.objects[2]
    if (setup_object.linear_base != 0x2DA000 or not setup_object.linear_base_verified or
            setup_object.virtual_size != 0xA8C50):
        raise SystemExit("the verified LE object 3 setup-data mapping changed")
    setup_seed = bytes(le.object_data(3))
    if len(setup_seed) != setup_object.virtual_size:
        raise SystemExit("rebiased LE object 3 data has an unexpected extent")
    SETUP_SEED.write_bytes(setup_seed)
    setup_seed_sha256 = digest(SETUP_SEED)

    # Validate the exact compressed resource extents before running game code.
    pal_header, dat_header = PAL.read_bytes()[:18], DAT.read_bytes()[:18]
    if pal_header[:8] != b"RNC\x01\x00\x00\x03\x00" or dat_header[:8] != b"RNC\x01\x00\x04\xB0\x00":
        raise SystemExit("TITLESCR resource method or decompressed-size header changed")

    # Reuse the existing partial lifter and constrain it to known code/data and
    # the explicitly backed title surface, stack, and VBE aperture.
    run([PYTHON, "tools/lift_entry_path.py", "--object-map", "measured-1-3",
         "--partial-root", "0x96338", "--partial-root", "0x9FFE0",
         "--partial-root", "0xB9CFC", "--partial-root", "0xADEAC",
         "--partial-root", "0x962F0", "--partial-root", "0xD2344",
         "--partial-root", "0xD23A7",
         "--stack-range", "0x3FE000:0x2000",
         "--dynamic-range", "0x390000:0x6E000",
         "--rep-movsd-source-range", "0x3B3000:0x4B000",
         "--rep-movsd-destination-range", "0x000A0000:0x10000"], echo=False)
    report = json.loads((ROOT / "evidence" / "partial_entry_path_lifts.json").read_text())
    lifted = {int(row["address"], 16) for row in report["lifted"]}
    needed = {0x962F0, 0x9FD40, 0x96338, 0x9FFE0, 0xA3A00, 0xA3A5C,
              0xBBB43, 0xD2236, 0xD226E, 0xD2344, 0xD23A7, 0xADEAC,
              0xB9CFC, 0xB9E99, 0xB9EA2, 0xB9EE5, 0xB9F68}
    if not needed.issubset(lifted) or report["missing_or_unsupported"] or report["partial_rejections"]:
        raise SystemExit(f"partial original-code closure incomplete: missing={sorted(needed-lifted)}")
    if report["object_map"][1]["linear_base_verified"] or report["object_map"][3]["linear_base_verified"]:
        raise SystemExit("this resource closure unexpectedly asserts unresolved LE objects 2/4")

    exe = ROOT / "build" / "test_authentic_titlescreen.exe"
    run([GCC, "-std=gnu11", "-m32", "-O0", "-DRECOMP_TRACE",
         "-I", ROOT / "runtime", "-I", r"E:\msys64\mingw32\include\SDL2",
         "-I", ROOT / "third_party/pcrecomp/runtime/recomp32", "-o", exe,
         ROOT / "tests/test_authentic_titlescreen.c", ROOT / report["output"],
         ROOT / "runtime/recomp_context.c", ROOT / "runtime/gw_interrupts.c",
         ROOT / "runtime/gw_segments.c", ROOT / "runtime/gw_pit8254.c",
         ROOT / "runtime/gw_dos_services.c", ROOT / "runtime/gw_vbe_provider.c",
         "-L", r"E:\msys64\mingw32\lib", "-lSDL2"])
    process = run([exe, PAL, DAT, SETUP_SEED])
    count_line = next((line for line in process.stdout.splitlines()
                       if line.startswith("VBECOUNTS ")), None)
    if not count_line:
        raise SystemExit("setup replay did not report the VBE service calls")
    vbe_counts = {name.lower(): int(value) for name, value in
                  re.findall(r"(4F00|4F01|4F02|4F05|0F)=(\d+)", count_line)}

    palette = (ROOT / "evidence/genewars_11_titlescreen_palette.raw").read_bytes()
    dac6 = (ROOT / "evidence/genewars_11_titlescreen_dac6.raw").read_bytes()
    pixels = (ROOT / "evidence/genewars_11_titlescreen_surface.raw").read_bytes()
    video = (ROOT / "evidence/genewars_11_titlescreen_video.raw").read_bytes()
    if len(palette) != 768 or len(dac6) != 768 or any(component > 63 for component in dac6):
        raise SystemExit("source/effective palette extents or six-bit DAC fixture are inconsistent")
    if dac6 != bytes(component & 0x3F for component in palette):
        raise SystemExit("original palette writer/DAC device output does not match raw source bytes")
    if len(pixels) != VIDEO_BYTES or len(set(pixels)) < 2:
        raise SystemExit("original title decoder did not produce a non-uniform 640x480 indexed image")
    if video != pixels:
        raise SystemExit("original LbScreenSwap destination differs from its decoded title source")
    bmp = ROOT / "evidence/genewars_11_titlescreen_sdl.bmp"
    verify_capture(bmp, video, dac6)
    if {p: digest(p) for p in EXPECTED} != before:
        raise SystemExit("a protected target/resource file changed during the isolated test")

    summary = {
        "execution_scope": "isolated original GeneWars 1.1 title resource path; not natural boot",
        "natural_boot_framebuffer": False,
        "original_screen_setup_executed": True,
        "loaded_original_le_object3": {"linear_base": "0x002DA000",
                                        "size": len(setup_seed),
                                        "rebased_sha256": setup_seed_sha256,
                                        "source": "load_le object 3, verified per-object delta +0x1DA000"},
        "setup_execution_scope": "original lifted LbScreenSetup_ -> LbScreenSetupAnyMode_ with host-emulated VBE; isolated, not natural DOS/4GW boot",
        "target_sha256": before[TARGET],
        "input_hashes": {str(p.relative_to(ROOT)): before[p] for p in (PAL, DAT)},
        "rea": REA_DIRECT,
        "natural_mode_observation": {
            "evidence": "evidence/w3_100_targeted_vesa_capture.json",
            "observed_request": "VESA mode 0x101 at mode-set entry; mode-catalog slot 13",
            "limitation": "mode 0x101 request was naturally observed; this replay supplies an explicit host-emulated VBE 2.0 response, not a DOSBox response",
        },
        "capstone_original_entries": original_code,
        "controlled_state": {
            "dimensions": [WIDTH, HEIGHT], "format": "8-bit palette indices",
            "pitch_bytes": WIDTH, "palette_source": "original compressed TITLESCR.PAL",
            "palette_entries": 256,
            "raw_component_range": [min(palette), max(palette)],
            "dac_component_range": [0, 63],
            "dac_model": "experimental VGA-compatible 6-bit DAC; original routine writes source bytes unchanged; fixture masks values to low 6 bits",
            "bank_granularity_kb": 64,
            "initial_window_state": "mode and windows initialized by original setup code; bank 0 selected by emulated VBE 4F02",
            "bank_profile": "host-emulated VBE 2.0 profile: 640x480x8, 640-byte pitch, 64KiB windows/granularity, 320KiB VRAM; not a captured DOSBox response",
            "mode_request": "W3-100 original observation: mode-table slot 13 requested VBE 0x101; isolated test feeds slot 13 to the original setup, provider advertises only VBE standard mode 0x101",
            "vbe_services": {"controller_info_4f00": vbe_counts["4f00"], "mode_info_4f01": vbe_counts["4f01"], "set_mode_4f02": vbe_counts["4f02"], "set_window_4f05": vbe_counts["4f05"], "legacy_get_mode_0f": vbe_counts["0f"]},
        },
        "original_functions_executed": [
            {"name": "FUN_000B9CFC (RNC1 title resource decoder)", "link_va": "0xB9CFC"},
            {"name": "LbScreenSetup_", "link_va": "0x962F0"},
            {"name": "LbScreenSetupAnyMode_", "link_va": "0x9FD40"},
            {"name": "LbVesaSetMode_", "link_va": "0xA3A00"},
            {"name": "FUN_000A38F0 (VBE mode-info request and global field init)", "link_va": "0xA38F0"},
            {"name": "LbScreenSetGraphicsWindow_", "link_va": "0x96338"},
            {"name": "FUN_000ADEAC (original palette port writer)", "link_va": "0xADEAC"},
            {"name": "LbScreenSwap_", "link_va": "0x9FFE0"},
            {"name": "LbVesaSetPage_", "link_va": "0xA3A5C"},
        ],
        "next_natural_title_to_game_state_dependency": {
            "startup_sequence_link_va": "0x93F30",
            "sequence_after_title_presenter": ["0x9FC90", "0x954A0", "0x92170"],
            "first_next_function": "FUN_000954A0",
            "first_next_function_evidence": "ev_f40dd669cb4305d308ef65b6d523bf6021c43a35bf73588e0b0890c8c0fc3660",
            "observed_assets_loaded": ["*B_SCREEN", "*W_SCREEN", "data/text.dat", "data/spec/harch.anb"],
            "status": "static REA call-sequence/decompile evidence only; not executed by the isolated title closure",
            "following_function": {"name": "FUN_00092170", "link_va": "0x92170", "status": "not yet executed or analyzed in this task"},
        },
        "vbe_response_structures_verified_by_setup": {
            "controller_mode_list": ["0x0101", "0xFFFF"],
            "mode_info": {"attributes": "0x001B", "window_a_attributes": "0x07", "granularity_kb": 64,
                           "window_size_kb": 64, "window_a_segment": "0xA000", "pitch_bytes": 640,
                           "width": 640, "height": 480, "planes": 1, "bits_per_pixel": 8,
                           "number_of_banks": 5, "memory_model": 4, "linear_framebuffer": False},
            "profile": "explicit host-emulated VBE fixture; not an observed DOSBox BIOS response",
        },
        "remaining_graphics_setup_dependency": {
            "function": "FUN_000D226E relocated INT-vector thunk dispatch",
            "link_va": "0xD226E",
            "direct_backend": ["FUN_000BBB43", "FUN_000D2236", "FUN_000D226E"],
            "status": "resolved for the tested vectors: original LEA+RET dispatches through relocated INT 10h/31h thunks at host linear 0x2BD344/0x2BD3A7; existing partial dispatcher resolves only those verified thunk addresses",
        },
        "dimensions_and_transfer": {
            "source": "decoded original TITLESCR.DAT resource",
            "output_size_bytes": VIDEO_BYTES,
            "banks": [0, 1, 2, 3, 4],
            "bytes_per_bank": [65536, 65536, 65536, 65536, 45056],
            "vbe_calls": "BH=0 set window A and B to each required bank; success AX=004Fh",
            "video_equal_to_source": True,
        },
        "artifact_hashes": {
            "palette_raw": digest(ROOT / "evidence/genewars_11_titlescreen_palette.raw"),
            "dac6_effective": digest(ROOT / "evidence/genewars_11_titlescreen_dac6.raw"),
            "surface_raw": digest(ROOT / "evidence/genewars_11_titlescreen_surface.raw"),
            "video_raw": digest(ROOT / "evidence/genewars_11_titlescreen_video.raw"),
            "sdl_bmp": digest(bmp),
        },
        "checks": [
            "source EXE and both original compressed title assets remained hash-identical",
            "original lifted RNC1 decoder emitted 768-byte palette and 307200-byte indexed title buffer",
            "original palette writer emitted exactly 256 index selections and 768 RGB bytes; DAC6 conversion is explicitly experimental",
            "original lifted setup issued VBE 4F00/4F02/4F01; original lifted VESA LbScreenSwap_ called original LbVesaSetPage_ for banks 0..4 via 4F05",
            "every destination byte equals the original-decoder output; transfer and source guards intact",
            "every scaled SDL BMP pixel matches post-swap video index expanded with the decoded original palette",
        ],
        "process_output": process.stdout.splitlines(),
        "passed": True,
    }
    evidence_path = ROOT / "evidence/genewars_11_titlescreen_functional.json"
    evidence_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print("PASS authentic title resource decoded and transferred by original lifted GeneWars 1.1 functions")
    print(f"PASS SDL capture verified pixel-for-pixel: {bmp}")
    print(f"PASS functional evidence: {evidence_path}")


if __name__ == "__main__":
    main()
