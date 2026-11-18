#!/usr/bin/env python3
"""Build an analysis-only PE32 carrier from the authenticated GeneWars 1.1 LE.

The carrier preserves LE link VAs: ImageBase is 0x1000 and every section RVA is
the LE object base minus 0x1000.  le_loader.py's already-applied internal
fixups therefore remain valid PE virtual addresses; this tool performs no
second relocation pass and does not claim that the carrier is executable.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import le_loader  # noqa: E402

CANONICAL_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
PE_IMAGE_BASE = 0x1000
SECTION_ALIGNMENT = 0x1000
FILE_ALIGNMENT = 0x200
FIXUP_NAMES = {le_loader.SRC_OFFSET32: "SRC_OFFSET32"}
SEED_NAMES = (
    "PlaySmacker",
    "setup_game",
    "LbScreenSetup_",
    "LbScreenSetupAnyMode_",
    "LbVesaSetMode_",
    "LbVesaSetPage_",
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def align(value: int, boundary: int) -> int:
    return (value + boundary - 1) & ~(boundary - 1)


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def parse_map_seeds(map_path: Path) -> list[dict]:
    found: dict[str, dict] = {}
    pattern = re.compile(r"^\s*(\d{4}):([0-9A-Fa-f]{8})\s+(.+?)\s*$")
    for line in map_path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = pattern.match(line)
        if not match:
            continue
        address = int(match.group(2), 16)
        decorated = match.group(3)
        for wanted in SEED_NAMES:
            if decorated == wanted or wanted in decorated:
                found.setdefault(wanted, {"name": wanted, "map_symbol": decorated,
                                          "link_va": address, "map_segment": int(match.group(1))})
    missing = [name for name in SEED_NAMES if name not in found]
    if missing:
        raise ValueError(f"1.1 MAP lacks expected exact seed symbols: {missing}")
    return [found[name] for name in SEED_NAMES]


def parse_fixups(source: bytes, image: le_loader.LEImage) -> tuple[list[dict], list[dict]]:
    """Decode the same LE fixup stream shape as le_loader and cross-check it.

    1.1 currently uses only internal OFFSET32 fixups. Fail closed if that
    evidence changes; do not silently extend the parser to new record kinds.
    """
    h = _u32(source, 0x3C)
    page_size = _u32(source, h + 0x28)
    num_pages = _u32(source, h + 0x14)
    obj_tab = h + _u32(source, h + 0x40)
    obj_count = _u32(source, h + 0x44)
    page_map_off = h + _u32(source, h + 0x48)
    fixup_page_tab = h + _u32(source, h + 0x68)
    fixup_rec_tab = h + _u32(source, h + 0x6C)
    data_pages = _u32(source, h + 0x80)
    last_page_bytes = _u32(source, h + 0x2C)
    if obj_count != len(image.objects) or page_size != image.page_size:
        raise ValueError("LE loader metadata disagrees with object/page tables")

    page_map: list[dict] = []
    linear_page = 1
    for obj in image.objects:
        for local_page in range(obj.page_count):
            entry = page_map_off + (obj.first_page - 1 + local_page) * 4
            physical_page = int.from_bytes(source[entry:entry + 3], "big")
            flags = source[entry + 3]
            if flags:
                raise ValueError(f"unsupported LE page flags 0x{flags:x}")
            page_bytes = last_page_bytes if physical_page == num_pages else page_size
            page_map.append({
                "linear_page": linear_page,
                "object": obj.index,
                "local_page": local_page,
                "link_va": obj.base + local_page * page_size,
                "physical_page": physical_page,
                "source_file_offset": data_pages + (physical_page - 1) * page_size,
                "available_bytes": page_bytes,
            })
            linear_page += 1
    if len(page_map) != num_pages:
        raise ValueError(f"page map count {len(page_map)} != LE num_pages {num_pages}")

    by_va = sorted(page_map, key=lambda p: p["link_va"])

    def source_offsets_for_va(va: int, size: int) -> list[int]:
        offsets = []
        for byte_index in range(size):
            current = va + byte_index
            page = next((p for p in by_va if p["link_va"] <= current < p["link_va"] + page_size), None)
            if page is None:
                raise ValueError(f"fixup byte at link VA 0x{current:x} falls in unmapped page gap")
            within = current - page["link_va"]
            if within >= page["available_bytes"]:
                raise ValueError(f"fixup byte at link VA 0x{current:x} is zero-fill, not file-backed")
            offsets.append(page["source_file_offset"] + within)
        return offsets

    fixes: list[dict] = []
    census: dict[str, int] = {}
    for page_num in range(1, num_pages + 1):
        start = fixup_rec_tab + _u32(source, fixup_page_tab + (page_num - 1) * 4)
        end = fixup_rec_tab + _u32(source, fixup_page_tab + page_num * 4)
        cursor = start
        page_linear_va = next(p["link_va"] for p in page_map if p["linear_page"] == page_num)
        while cursor < end:
            record_start = cursor
            source_type = source[cursor]
            target_flags = source[cursor + 1]
            cursor += 2
            base_type = source_type & le_loader.SRC_TYPE_MASK
            if base_type != le_loader.SRC_OFFSET32:
                raise ValueError(f"unexpected LE fixup source type 0x{base_type:x} on page {page_num}")
            if target_flags & le_loader.TGT_TYPE_MASK != le_loader.TGT_INTERNAL:
                raise ValueError(f"non-internal LE fixup on page {page_num}")
            if target_flags & le_loader.TGT_ADDITIVE:
                raise ValueError(f"additive LE fixup not represented by current loader contract on page {page_num}")
            if source_type & le_loader.SRC_FLAG_LIST:
                count = source[cursor]
                cursor += 1
                source_offsets = [struct.unpack_from("<h", source, cursor + 2 * n)[0] for n in range(count)]
                cursor += count * 2
            else:
                source_offsets = [struct.unpack_from("<h", source, cursor)[0]]
                cursor += 2
            if target_flags & le_loader.TGT_16BIT_OBJNUM:
                obj_num = _u16(source, cursor)
                cursor += 2
            else:
                obj_num = source[cursor]
                cursor += 1
            if target_flags & le_loader.TGT_32BIT_OFFSET:
                target_offset = _u32(source, cursor)
                cursor += 4
            else:
                target_offset = _u16(source, cursor)
                cursor += 2
            if not 1 <= obj_num <= len(image.objects):
                raise ValueError(f"LE fixup target object {obj_num} is out of range")
            target = image.objects[obj_num - 1]
            target_va = target.base + target_offset
            for source_offset in source_offsets:
                source_va = page_linear_va + source_offset
                mem_index = source_va - image.mem_base
                if mem_index < 0 or mem_index + 4 > len(image.mem):
                    raise ValueError(f"LE fixup source VA 0x{source_va:x} outside loaded image")
                loaded = bytes(image.mem[mem_index:mem_index + 4])
                if struct.unpack("<I", loaded)[0] != target_va:
                    raise ValueError(f"loader/fixup mismatch at 0x{source_va:x}: {loaded.hex()} != {target_va:#x}")
                raw_offsets = source_offsets_for_va(source_va, 4)
                original = bytes(source[offset] for offset in raw_offsets)
                fixes.append({
                    "record_file_offset": record_start,
                    "source_type": FIXUP_NAMES[base_type],
                    "source_page": page_num,
                    "source_link_va": source_va,
                    "source_original_file_offsets": raw_offsets,
                    "source_original_bytes": original.hex(),
                    "loader_applied_bytes": loaded.hex(),
                    "target_object": obj_num,
                    "target_offset": target_offset,
                    "target_link_va": target_va,
                    "pe_va": target_va,
                    "pe_rva": target_va - PE_IMAGE_BASE,
                    "additional_carrier_relocation_delta": 0,
                })
                census[FIXUP_NAMES[base_type]] = census.get(FIXUP_NAMES[base_type], 0) + 1
    if len(fixes) != image.fixup_count:
        raise ValueError(f"parsed {len(fixes)} fixup sites, loader applied {image.fixup_count}")
    expected = {FIXUP_NAMES[k]: v for k, v in image.fixup_census.items()}
    if census != expected:
        raise ValueError(f"fixup census disagrees with loader: parsed={census}, loader={expected}")
    return fixes, page_map


def build_pe(image: le_loader.LEImage) -> tuple[bytes, list[dict]]:
    objects = image.objects
    number_of_sections = len(objects)
    pe_offset = 0x80
    optional_size = 224
    section_table = pe_offset + 4 + 20 + optional_size
    size_headers = align(section_table + number_of_sections * 40, FILE_ALIGNMENT)
    raw_cursor = size_headers
    sections: list[dict] = []
    for obj in objects:
        if obj.base < PE_IMAGE_BASE or obj.base % SECTION_ALIGNMENT:
            raise ValueError(f"object {obj.index} base cannot be represented at PE section alignment")
        raw_size = align(obj.virtual_size, FILE_ALIGNMENT)
        sections.append({
            "object": obj,
            "name": f".o{obj.index}",
            "rva": obj.base - PE_IMAGE_BASE,
            "virtual_size": obj.virtual_size,
            "raw_size": raw_size,
            "raw_offset": raw_cursor,
            "characteristics": 0x60000020 if obj.executable else (0xC0000040 if obj.writable else 0x40000040),
        })
        raw_cursor += raw_size
    image_end = max(obj.end for obj in objects)
    size_image = align(image_end - PE_IMAGE_BASE, SECTION_ALIGNMENT)
    code_objs = [s for s in sections if s["object"].executable]
    data_objs = [s for s in sections if not s["object"].executable]
    entry_rva = image.entry_linear - PE_IMAGE_BASE
    image_base = PE_IMAGE_BASE
    buf = bytearray(raw_cursor)
    buf[:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, pe_offset)
    buf[pe_offset:pe_offset + 4] = b"PE\0\0"
    coff = pe_offset + 4
    struct.pack_into("<HHIIIHH", buf, coff, 0x14C, number_of_sections, 0, 0, 0, optional_size, 0x0102)
    opt = coff + 20
    struct.pack_into("<HBBIIIIII", buf, opt, 0x10B, 1, 0,
                     sum(s["raw_size"] for s in code_objs),
                     sum(s["raw_size"] for s in data_objs), 0,
                     entry_rva, code_objs[0]["rva"], data_objs[0]["rva"] if data_objs else 0)
    struct.pack_into("<I", buf, opt + 28, image_base)
    struct.pack_into("<II", buf, opt + 32, SECTION_ALIGNMENT, FILE_ALIGNMENT)
    struct.pack_into("<HHHHHH", buf, opt + 40, 4, 0, 0, 0, 4, 0)
    struct.pack_into("<I", buf, opt + 52, 0)
    struct.pack_into("<II", buf, opt + 56, size_image, size_headers)
    struct.pack_into("<I", buf, opt + 64, 0)
    struct.pack_into("<HH", buf, opt + 68, 3, 0)
    struct.pack_into("<IIIIII", buf, opt + 72, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    for index, section in enumerate(sections):
        obj = section["object"]
        sh = section_table + index * 40
        name = section["name"].encode("ascii")[:8].ljust(8, b"\0")
        buf[sh:sh + 8] = name
        struct.pack_into("<IIIIIIHHI", buf, sh + 8,
                         section["virtual_size"], section["rva"], section["raw_size"],
                         section["raw_offset"], 0, 0, 0, 0, section["characteristics"])
        start = obj.base - image.mem_base
        payload = bytes(image.mem[start:start + obj.virtual_size])
        if len(payload) != obj.virtual_size:
            raise ValueError(f"loaded LE bytes for object {obj.index} are incomplete")
        buf[section["raw_offset"]:section["raw_offset"] + len(payload)] = payload
        section["object_bytes_sha256"] = sha256(payload)
        section["object_link_start"] = obj.base
        section["object_link_end"] = obj.end
        section["pe_va_start"] = image_base + section["rva"]
        section["pe_va_end"] = image_base + section["rva"] + obj.virtual_size
        section["pe_raw_payload_sha256"] = sha256(bytes(buf[section["raw_offset"]:section["raw_offset"] + obj.virtual_size]))
        section["file_offset"] = section["raw_offset"]
        section["object_flags"] = obj.flags
        section["executable"] = obj.executable
        section["writable"] = obj.writable
        del section["object"]
    return bytes(buf), sections


def generate(source_path: Path, map_path: Path, output_dir: Path) -> dict:
    source = source_path.read_bytes()
    actual_hash = sha256(source)
    if actual_hash != CANONICAL_SHA256:
        raise ValueError(f"canonical GeneWars 1.1 SHA-256 mismatch: {actual_hash}")
    image = le_loader.load_le(source_path, rebase=0)
    fixups, pages = parse_fixups(source, image)
    carrier, sections = build_pe(image)
    seeds = parse_map_seeds(map_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    carrier_path = output_dir / "carrier.exe"
    seed_path = output_dir / "seeds.tsv"
    manifest_path = output_dir / "manifest.json"
    carrier_path.write_bytes(carrier)
    seed_lines = [f"0x{s['link_va']:08X}\tfunction\t{s['name']}" for s in seeds]
    seed_path.write_text("\n".join(seed_lines) + "\n", encoding="utf-8")
    manifest = {
        "schema": "genewars-1.1-le-pe-carrier-v1",
        "purpose": "analysis-only PE32 carrier; not executable GeneWars and not a playable port",
        "source": {"path": str(source_path.resolve()), "sha256": actual_hash, "bytes": len(source)},
        "map": {"path": str(map_path.resolve()), "sha256": sha256(map_path.read_bytes())},
        "loader": {"path": str((ROOT / "src" / "le_loader.py").resolve()), "sha256": sha256((ROOT / "src" / "le_loader.py").read_bytes()), "entry_link_va": image.entry_linear, "stack_link_va": image.stack_linear, "mem_base": image.mem_base, "mem_size": len(image.mem), "loaded_memory_sha256": sha256(bytes(image.mem))},
        "le": {"page_size": image.page_size, "objects": [{"index": o.index, "link_va_start": o.base, "link_va_end": o.end, "virtual_size": o.virtual_size, "flags": o.flags, "executable": o.executable, "writable": o.writable, "page_count": o.page_count} for o in image.objects], "fixup_count": image.fixup_count, "fixup_census": {FIXUP_NAMES[k]: v for k, v in image.fixup_census.items()}, "fixup_sites": fixups, "file_page_map": pages},
        "carrier": {"path": str(carrier_path.resolve()), "sha256": sha256(carrier), "bytes": len(carrier), "machine": "IMAGE_FILE_MACHINE_I386", "optional_magic": "PE32", "image_base": PE_IMAGE_BASE, "section_alignment": SECTION_ALIGNMENT, "file_alignment": FILE_ALIGNMENT, "entry_rva": image.entry_linear - PE_IMAGE_BASE, "entry_pe_va": PE_IMAGE_BASE + image.entry_linear - PE_IMAGE_BASE, "mapping_formula": "PE_VA = ImageBase + section_RVA + object_offset = LE_link_VA; PE_RVA = LE_link_VA - 0x1000", "sections": sections, "additional_carrier_relocation_count": 0},
        "byte_transformations": ["LE file pages are mapped and internal LE fixups are applied by src/le_loader.py exactly once.", "Each PE section stores the resulting bytes for one LE object; no code/data byte is otherwise rewritten.", "ImageBase=0x1000 and section RVA=LE object base-0x1000 preserve every object link VA and the loader-applied internal offset fixup target value.", "PE headers and section padding are analysis-container bytes; zero-fill gaps between LE objects are not materialized as sections."],
        "seeds": {"path": str(seed_path.resolve()), "format": "address<TAB>function<TAB>name", "symbols": seeds},
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def verify_carrier(path: Path, manifest_path: Path) -> dict:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    data = path.read_bytes()
    if sha256(data) != manifest["carrier"]["sha256"]:
        raise ValueError("carrier SHA-256 differs from manifest")
    if data[:2] != b"MZ" or data[_u32(data, 0x3C):_u32(data, 0x3C) + 4] != b"PE\0\0":
        raise ValueError("carrier is not a valid MZ/PE image")
    pe = _u32(data, 0x3C)
    coff = pe + 4
    machine, nsects = struct.unpack_from("<HH", data, coff)
    opt = coff + 20
    magic = _u16(data, opt)
    imagebase = _u32(data, opt + 28)
    if machine != 0x14C or magic != 0x10B or imagebase != PE_IMAGE_BASE:
        raise ValueError("carrier PE32 architecture or mapping base is unexpected")
    section_table = opt + _u16(data, coff + 16)
    if nsects != len(manifest["carrier"]["sections"]):
        raise ValueError("carrier section count differs from manifest")
    for i, item in enumerate(manifest["carrier"]["sections"]):
        sh = section_table + i * 40
        virtual_size, rva, raw_size, raw_off = struct.unpack_from("<IIII", data, sh + 8)
        if (rva, virtual_size, raw_size, raw_off) != (item["rva"], item["virtual_size"], item["raw_size"], item["raw_offset"]):
            raise ValueError(f"carrier section {i} does not match manifest")
        payload = data[raw_off:raw_off + virtual_size]
        if sha256(payload) != item["object_bytes_sha256"]:
            raise ValueError(f"carrier section {i} payload hash differs")
        if imagebase + rva != item["object_link_start"]:
            raise ValueError(f"carrier section {i} does not preserve link VA")
    for fixup in manifest["le"]["fixup_sites"]:
        if fixup["pe_va"] != fixup["target_link_va"] or fixup["additional_carrier_relocation_delta"] != 0:
            raise ValueError(f"fixup does not preserve target VA at {fixup['source_link_va']:#x}")
    return {"carrier_sha256": sha256(data), "machine": f"0x{machine:04x}", "pe32": magic == 0x10B,
            "image_base": imagebase, "sections": nsects, "fixup_sites_verified": len(manifest["le"]["fixup_sites"]),
            "mapping_preserves_link_addresses": True}


def write_controlled_pe32_fixture(path: Path) -> dict:
    """Write a tiny, deterministic PE32 x86 function used only as a provider check."""
    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    coff = 0x84
    struct.pack_into("<HHIIIHH", data, coff, 0x14C, 1, 0, 0, 0, 224, 0x0102)
    opt = coff + 20
    struct.pack_into("<HBBIIIIII", data, opt, 0x10B, 1, 0, 0x200, 0, 0,
                     0x1000, 0x1000, 0)
    struct.pack_into("<I", data, opt + 28, 0x400000)
    struct.pack_into("<II", data, opt + 32, 0x1000, 0x200)
    struct.pack_into("<HHHHHH", data, opt + 40, 4, 0, 0, 0, 4, 0)
    struct.pack_into("<I", data, opt + 52, 0)
    struct.pack_into("<II", data, opt + 56, 0x2000, 0x200)
    struct.pack_into("<I", data, opt + 64, 0)
    struct.pack_into("<HH", data, opt + 68, 3, 0)
    struct.pack_into("<IIIIII", data, opt + 72, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    section_table = opt + 224
    data[section_table:section_table + 8] = b".text\0\0\0"
    struct.pack_into("<IIIIIIHHI", data, section_table + 8,
                     0x10, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    code = bytes.fromhex("55 89 e5 b8 2a 00 00 00 83 c0 02 5d c3")
    data[0x200:0x200 + len(code)] = code
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return {"path": str(path.resolve()), "sha256": sha256(bytes(data)),
            "entry_va": "0x401000", "function_bytes": code.hex()}


def run_controlled_pe32_fixture(output_dir: Path, node: Path, rea_script: Path) -> dict:
    fixture_path = output_dir / "pe32_fixture.exe"
    fixture = write_controlled_pe32_fixture(fixture_path)
    env = os.environ.copy()
    env["REA_ANALYSIS_PROVIDER"] = "ghidra"
    env.pop("REA_GHIDRA_SEED_FILE", None)
    commands = []
    for operation, args in (("inspect", []), ("function", ["0x401000"]), ("decompile", ["0x401000"])):
        command = [str(node), str(rea_script), operation, str(fixture_path), *args,
                   "--provider", "ghidra", "--format", "json"]
        proc = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=600)
        commands.append({"command": command[2:], "exit_code": proc.returncode,
                         "stdout": proc.stdout, "stderr": proc.stderr})
        if proc.returncode:
            raise RuntimeError(f"controlled REA PE32 {operation} failed: {proc.stderr[-2000:]}")
    function = json.loads(commands[1]["stdout"])
    pseudo = function.get("raw_result", {}).get("value", {}).get("pseudocode", "")
    if function.get("provider", {}).get("id") != "ghidra" or "return 0x2c" not in pseudo:
        raise ValueError("controlled PE32 fixture did not produce the expected Ghidra decompilation")
    result = {"phase": "controlled_pe32_fixture", "fixture": fixture["path"],
              "fixture_sha256": fixture["sha256"], "entry_va": fixture["entry_va"],
              "function_bytes": fixture["function_bytes"], "commands": commands}
    (output_dir / "analysis.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def _source_file_offsets(manifest: dict, va: int, length: int) -> list[int]:
    page_size = manifest["le"]["page_size"]
    pages = manifest["le"]["file_page_map"]
    result = []
    for current in range(va, va + length):
        page = next((p for p in pages if p["link_va"] <= current < p["link_va"] + page_size), None)
        if page is None:
            raise ValueError(f"link VA 0x{current:x} has no original LE page mapping")
        within = current - page["link_va"]
        if within >= page["available_bytes"]:
            raise ValueError(f"link VA 0x{current:x} is zero-fill, not backed by original LE bytes")
        result.append(page["source_file_offset"] + within)
    return result


def analyze_with_rea(source_path: Path, output_dir: Path, node: Path, rea_script: Path,
                     function_va: int = 0x962F0) -> dict:
    """Query one known 1.1 function through REA/Ghidra and save raw Evidence."""
    carrier_path = output_dir / "carrier.exe"
    manifest_path = output_dir / "manifest.json"
    analysis_path = output_dir / "analysis.json"
    if not os.environ.get("GHIDRA_INSTALL_DIR") or not os.environ.get("JAVA_HOME"):
        raise ValueError("set GHIDRA_INSTALL_DIR and JAVA_HOME before REA analysis")
    previous_analysis = json.loads(analysis_path.read_text(encoding="utf-8")) if analysis_path.is_file() else {}
    controlled = previous_analysis.get("controlled_pe32_validation")
    if not controlled and previous_analysis.get("phase") == "controlled_pe32_fixture":
        controlled = previous_analysis
    if not controlled:
        controlled = run_controlled_pe32_fixture(output_dir, node, rea_script)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    verify_carrier(carrier_path, manifest_path)
    env = os.environ.copy()
    env["REA_ANALYSIS_PROVIDER"] = "ghidra"
    env["REA_GHIDRA_SEED_FILE"] = str((output_dir / "seeds.tsv").resolve())
    env["REA_GHIDRA_LANGUAGE_ID"] = "x86:LE:32:default"
    env.pop("REA_GHIDRA_COMPILER_SPEC_ID", None)  # no Ghidra Watcom spec is shipped
    command = [str(node), str(rea_script), "function", str(carrier_path), hex(function_va),
               "--provider", "ghidra", "--format", "json"]
    proc = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=1200)
    if proc.returncode:
        raise RuntimeError(f"REA function query failed ({proc.returncode}): {proc.stderr[-4000:]}\n{proc.stdout[-2000:]}")
    query = json.loads(proc.stdout)
    raw_value = query.get("raw_result", {}).get("value", {})
    procedure = raw_value.get("procedure", {})
    if query.get("provider", {}).get("id") != "ghidra" or query.get("provider", {}).get("version") != "12.1.4":
        raise ValueError("REA query did not use the expected Ghidra 12.1.4 provider")
    if int(procedure.get("address", "0"), 16) != function_va:
        raise ValueError(f"REA resolved a different function entry: {procedure.get('address')}")
    ranges = procedure.get("body", {}).get("ranges", [])
    if len(ranges) != 1 or not ranges[0].get("start") or not ranges[0].get("end"):
        raise ValueError("REA did not return one complete contiguous function range")
    start = int(ranges[0]["start"], 16)
    end_inclusive = int(ranges[0]["end"], 16)
    function_size = end_inclusive - start + 1
    if start != function_va or function_size != procedure.get("body", {}).get("total_bytes"):
        raise ValueError("REA function boundary/byte count is inconsistent")

    import capstone
    image = le_loader.load_le(source_path, rebase=0)
    mem_off = start - image.mem_base
    original_loaded = bytes(image.mem[mem_off:mem_off + function_size])
    if len(original_loaded) != function_size:
        raise ValueError("function bytes fall outside mapped LE image")
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoded = list(cs.disasm(original_loaded, start))
    capstone_rows = [{"address": f"0x{i.address:x}", "size": i.size, "bytes": bytes(i.bytes).hex(),
                      "mnemonic": i.mnemonic, "operands": i.op_str} for i in decoded]
    rea_assembly = raw_value.get("assembly", [])
    rea_addresses = [int(line.split(":", 1)[0], 16) for line in rea_assembly if ":" in line]
    capstone_addresses = [i.address for i in decoded]
    if rea_addresses != capstone_addresses:
        raise ValueError(f"REA and Capstone instruction boundaries differ: {rea_addresses} != {capstone_addresses}")
    carrier = carrier_path.read_bytes()
    section = next(s for s in manifest["carrier"]["sections"]
                   if s["object_link_start"] <= start and end_inclusive < s["object_link_end"])
    carrier_off = section["raw_offset"] + start - section["object_link_start"]
    carrier_bytes = carrier[carrier_off:carrier_off + function_size]
    if carrier_bytes != original_loaded:
        raise ValueError("carrier code bytes differ from le_loader mapped bytes")
    source_offsets = _source_file_offsets(manifest, start, function_size)
    seed = next((s for s in manifest["seeds"]["symbols"] if s["name"] == "LbScreenSetup_"), None)
    if not seed or seed["link_va"] != start:
        raise ValueError("selected function entry is not the verified exact 1.1 MAP seed")
    incoming = raw_value.get("incoming_references", [])
    call_refs = [r for r in incoming if r.get("kind", {}).get("call")]
    result = {
        "schema": "rea-ghidra-genewars-1.1-analysis-v1",
        "evidence_level": "static-authenticated-bytes-and-provider-observed-analysis",
        "controlled_pe32_validation": controlled,
        "target": {"path": str(source_path.resolve()), "sha256": sha256(source_path.read_bytes()),
                   "carrier_path": str(carrier_path.resolve()), "carrier_sha256": manifest["carrier"]["sha256"],
                   "manifest_path": str(manifest_path.resolve()), "manifest_sha256": sha256(manifest_path.read_bytes())},
        "rea": {"cli_node": str(node.resolve()), "cli_script": str(rea_script.resolve()),
                "package_version": "6.4.0", "provider": query.get("provider"),
                "analysis_profile": query.get("analysis_profile"), "evidence_id": query.get("evidence_id"),
                "command": command, "exit_code": proc.returncode, "analysis_seeds": query.get("analysis_profile", {}).get("parameters", {}).get("analysis_seeds")},
        "function": {"verified_map_seed": seed, "procedure": procedure,
                     "pseudocode": raw_value.get("pseudocode"), "rea_assembly": rea_assembly,
                     "rea_incoming_references": incoming, "rea_call_reference_count": len(call_refs),
                     "rea_callers": raw_value.get("callers", []), "rea_callees": raw_value.get("callees", []),
                     "capstone_instructions": capstone_rows,
                     "boundaries_match_capstone": True,
                     "link_va_start": start, "link_va_end_inclusive": end_inclusive,
                     "pe_va_start": manifest["carrier"]["image_base"] + section["rva"] + start - section["object_link_start"],
                     "pe_rva_start": start - manifest["carrier"]["image_base"],
                     "original_le_file_offsets_per_byte": source_offsets,
                     "le_loaded_bytes_sha256": sha256(original_loaded),
                     "carrier_bytes_sha256": sha256(carrier_bytes),
                     "bytes_identical_after_loader_mapping": original_loaded == carrier_bytes},
        "full_rea_function_evidence": query,
        "limitations": ["PE carrier is for static Ghidra/REA analysis only and is not a runnable GeneWars build.",
                        "Ghidra's recovered signature/calling convention is a decompiler observation, not a Watcom ABI declaration.",
                        "No Watcom compiler specification exists in the installed x86 language definition; the compiler spec remains the Ghidra loader default.",
                        "This analysis does not establish runtime behavior or a framebuffer."],
    }
    analysis_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build")
    build.add_argument("--source", type=Path, default=ROOT / "evidence" / "genewars-1_1.exe")
    build.add_argument("--map", type=Path, default=ROOT / "evidence" / "genewars-1_1.map")
    build.add_argument("--output-dir", type=Path, default=ROOT / "evidence" / "rea_ghidra_1_1")
    verify = sub.add_parser("verify")
    verify.add_argument("--carrier", type=Path, default=ROOT / "evidence" / "rea_ghidra_1_1" / "carrier.exe")
    verify.add_argument("--manifest", type=Path, default=ROOT / "evidence" / "rea_ghidra_1_1" / "manifest.json")
    analyze = sub.add_parser("analyze")
    analyze.add_argument("--source", type=Path, default=ROOT / "evidence" / "genewars-1_1.exe")
    analyze.add_argument("--output-dir", type=Path, default=ROOT / "evidence" / "rea_ghidra_1_1")
    analyze.add_argument("--rea-node", type=Path, default=Path(os.environ.get("REA_NODE", sys.executable)))
    analyze.add_argument("--rea-script", type=Path, required=True)
    analyze.add_argument("--function-va", type=lambda x: int(x, 0), default=0x962F0)
    fixture = sub.add_parser("fixture-test")
    fixture.add_argument("--output-dir", type=Path, default=ROOT / "evidence" / "rea_ghidra_1_1")
    fixture.add_argument("--rea-node", type=Path, default=Path(os.environ.get("REA_NODE", sys.executable)))
    fixture.add_argument("--rea-script", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "build":
        result = generate(args.source, args.map, args.output_dir)
        print(json.dumps({"carrier": result["carrier"], "fixup_count": result["le"]["fixup_count"], "seed_count": len(result["seeds"]["symbols"])}, indent=2))
    elif args.command == "verify":
        print(json.dumps(verify_carrier(args.carrier, args.manifest), indent=2))
    elif args.command == "fixture-test":
        print(json.dumps(run_controlled_pe32_fixture(args.output_dir, args.rea_node, args.rea_script), indent=2))
    else:
        result = analyze_with_rea(args.source, args.output_dir, args.rea_node, args.rea_script, args.function_va)
        print(json.dumps({"analysis_path": str((args.output_dir / "analysis.json").resolve()),
                          "evidence_id": result["rea"]["evidence_id"],
                          "provider": result["rea"]["provider"],
                          "function": result["function"]["procedure"],
                          "instructions_match_capstone": result["function"]["boundaries_match_capstone"],
                          "call_references": result["function"]["rea_call_reference_count"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
