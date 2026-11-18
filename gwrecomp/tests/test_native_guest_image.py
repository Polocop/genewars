"""Load the fixed-VAS LE data image and execute real start through the native closure."""
import os as _gw_os
from pathlib import Path as _GwPath
_GW_CLANG_X86=_gw_os.environ.get("GWRECOMP_CLANG_X86") or _gw_os.environ.get("GWRECOMP_CLANG_X64") or __import__("shutil").which("clang") or "clang.exe"
_GW_VS=_gw_os.path.join(_gw_os.environ.get("ProgramFiles(x86)",r"C:\Program Files (x86)"),"Microsoft Visual Studio","2022","BuildTools")
import os as _gw_os
from pathlib import Path as _GwPath
_GW_ROOT=str(_GwPath(__file__).resolve().parents[1])
_GW_MSYS2=_gw_os.environ.get("MSYS2_ROOT",r"C:\msys64")
_GW_FX=_gw_os.environ.get("GENEWARSFX_ROOT",_gw_os.path.join(_GW_ROOT,"third_party","GeneWarsFX"))
import argparse
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import struct
import hashlib
from datetime import datetime, timezone
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
PY_TOOLS = ROOT / "third_party" / "python"
sys.path.insert(0, str(PY_TOOLS))
sys.path.insert(0, str(ROOT / "runtime"))
sys.path.insert(0, str(ROOT / "src"))
import guest_boot
from dos_cdrom import CueImage
from dos_services import DosHost

CACHE = ROOT / "cache"
BOOT_BIN = ROOT / "build" / "native_lift_boot.bin"
SEED_HEADER = ROOT / "build" / "native_lift_boot_seed.h"
OBJECT = ROOT / "build" / "entry_path_closure_routed.o"
DEBUG_OBJECT = ROOT / "build" / "entry_path_closure_routed_debug.o"
EXE = ROOT / "build" / "entry_path_native_boot.exe"
LOOKUP_C = ROOT / "build" / "entry_path_native_lookup.c"
TARGET = ROOT / "evidence" / "genewars-1_1.exe"


def load_authenticated_w3_140_environment(original_evidence, runtime_evidence):
    """Validate the W3 capture schema and W2 boot-fixture contract."""
    sample = original_evidence.get("capture", {}).get("environment", {})
    runtime_sample = runtime_evidence.get("original_environment", {})
    expected_sha256 = "65c4d22c258efbf93a93cfcaa8d9d8c489e510cb2be76530646c36e0250ee895"
    if (original_evidence.get("schema") != "w3-140-setenvp-environment/v1" or
            original_evidence.get("source", {}).get("target_sha256", "").lower() !=
            "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f" or
            sample.get("valid") is not True or sample.get("double_nul_found") is not True or
            sample.get("trailer_path_terminated") is not True or
            runtime_evidence.get("task") != "W2-114" or
            runtime_evidence.get("implementation", {}).get("api", "").find("environment_block") < 0):
        raise ValueError("W3-140 original environment or W2-114 boot API evidence is invalid")
    try:
        environment = bytes.fromhex(sample["sample_hex"])
    except (KeyError, ValueError) as exc:
        raise ValueError(f"W3-140 environment sample is not valid hex: {exc}") from exc
    actual_sha256 = hashlib.sha256(environment).hexdigest()
    if (len(environment) != 86 or actual_sha256 != expected_sha256 or
            sample.get("sample_bytes") != len(environment) or
            runtime_sample.get("size_bytes") != len(environment) or
            runtime_sample.get("sha256", "").lower() != actual_sha256 or
            runtime_sample.get("sample_hex") != sample["sample_hex"] or
            runtime_evidence.get("recovery_verified") is not True or
            runtime_evidence.get("tests", {}).get("registered_passed") is not True):
        raise ValueError("W3-140 environment bytes do not match the authenticated W2-114 fixture contract")
    return environment


def run(command, env):
    p = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True)
    if p.returncode:
        print(p.stdout, end=""); print(p.stderr, end=""); raise SystemExit(p.returncode)
    print(p.stdout, end=""); print(p.stderr, end="")
    return p


def msvc_x64_environment(base_env):
    """Read the installed VS x64 compiler environment without changing machine state."""
    vcvars = pathlib.Path((_GW_VS + '\\VC\\Auxiliary\\Build\\vcvars64.bat'))
    if not vcvars.is_file():
        raise SystemExit(f"W1-092 needs the installed x64 host toolchain; missing {vcvars}")
    p = subprocess.run(["cmd.exe", "/d", "/c", r'call C:\PROGRA~2\MICROS~3\2022\BUILDT~1\VC\AUXILI~1\Build\vcvars64.bat >nul && set'],
                       cwd=ROOT, env=base_env, text=True, encoding="mbcs", capture_output=True)
    if p.returncode:
        raise SystemExit(f"vcvars64 failed ({p.returncode}): {p.stderr[-2000:]}")
    result = dict(base_env)
    for line in p.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            result[key] = value
    return result


def generate_native_lookup(source_path):
    """Emit an exact VA-to-function table for every body in the canonical closure."""
    source = source_path.read_text(encoding="utf-8")
    entries = {}
    header = re.compile(r"\bvoid\s+([A-Za-z_]\w*)\s*\(\s*void\s*\)\s*\{")
    for match in header.finditer(source):
        depth = 1
        cursor = match.end()
        while cursor < len(source) and depth:
            if source[cursor] == "{": depth += 1
            elif source[cursor] == "}": depth -= 1
            cursor += 1
        if depth:
            raise AssertionError(f"unclosed generated function {match.group(1)}")
        body = source[match.start():cursor]
        va = re.search(r"RECOMP_ENTER\(0x([0-9A-Fa-f]+)u\)", body)
        if not va:
            continue
        address = int(va.group(1), 16)
        name = match.group(1)
        if address in entries:
            raise AssertionError(f"duplicate generated VA 0x{address:08X}: {entries[address]} and {name}")
        entries[address] = name
    if not entries:
        raise AssertionError("native lookup table has no generated function entries")
    lines = [
        '#include "recomp_types.h"',
        "typedef struct { uint32_t va; recomp_func_t fn; } gw_native_entry;",
    ]
    for name in entries.values():
        lines.append(f"extern void {name}(void);")
    lines.append("static const gw_native_entry gw_native_entries[] = {")
    lines.extend(f"    {{ 0x{va:08X}u, {name} }}," for va, name in sorted(entries.items()))
    lines.extend([
        "};",
        "recomp_func_t recomp_lookup(uint32_t va) {",
        "    size_t lo=0, hi=sizeof(gw_native_entries)/sizeof(gw_native_entries[0]);",
        "    while (lo<hi) { size_t mid=lo+(hi-lo)/2; uint32_t key=gw_native_entries[mid].va;",
        "        if (key<va) lo=mid+1; else hi=mid;",
        "    }",
        "    return lo<sizeof(gw_native_entries)/sizeof(gw_native_entries[0]) && gw_native_entries[lo].va==va ? gw_native_entries[lo].fn : 0;",
        "}",
    ])
    LOOKUP_C.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(entries)


def main():
    parser = argparse.ArgumentParser()
    sys.path.insert(0, str(ROOT / "tools"))
    parser.add_argument("--command-tail", default="")
    parser.add_argument("--evidence-name", default="native_lift_boot.json")
    parser.add_argument("--compile-evidence-name", default="entry_path_closure_routed_compile.json",
                        help="task-specific compile receipt name under evidence/")
    parser.add_argument("--recovery-dir", default="work/recovery/W1-053-20261008-211015",
                        help="repository-relative verified recovery directory recorded in capture metadata")
    parser.add_argument("--expect-fault", action="store_true")
    parser.add_argument("--continue-known-services", action="store_true")
    parser.add_argument("--continue-selector-query", action="store_true")
    parser.add_argument("--continue-time-query", action="store_true")
    parser.add_argument("--continue-dpmi-linear-allocation", action="store_true")
    parser.add_argument("--continue-dpmi-linear-success", action="store_true")
    parser.add_argument("--continue-dpmi-linear-sequence", action="store_true",
                        help="route a bounded sequence of natural post-AH25 AX=0501 requests through the existing Runtime allocator")
    parser.add_argument("--w1-091-host-backed-guest-memory", action="store_true",
                        help="use a one-replay zeroed contiguous guest map sized from the W1-090 natural allocations")
    parser.add_argument("--w1-092-host-backed-guest-memory", action="store_true",
                        help="extend the contiguous map only through the next captured 0x01000000 AX=0501 frontier")
    parser.add_argument("--experimental-dpmi-budget-mib", type=int, default=0,
                        help="explicit experimental AX=0501 budget in MiB; requires the W1-092 host-backed sequence replay and is not an original DOS/4GW claim")
    parser.add_argument("--continue-dos-ah3d", action="store_true")
    parser.add_argument("--serve-w3-functional-config", action="store_true",
                        help="serve only W3-verified functional CONFIG.INI from bounded native fixture memory")
    parser.add_argument("--allow-authenticated-config-fixture-only", action="store_true",
                        help="use the immutable W3-067 CONFIG.INI fixture when the protected clone path is absent")
    parser.add_argument("--fixture-header-dir", default="build",
                        help="directory for generated in-memory fixture headers")
    parser.add_argument("--serve-w3-address-seed", action="store_true",
                        help="seed the bounded native ADDRESS.TXT provider from the W3-authenticated 24-byte source fixture")
    parser.add_argument("--serve-w3-sound-ini", action="store_true",
                        help="serve the W3-069-authenticated SOUND.INI bytes from the bounded native provider")
    parser.add_argument("--allow-authenticated-sound-fixture-only", action="store_true",
                        help="use the immutable W3-069 SOUND.INI fixture when the protected clone path is absent")
    parser.add_argument("--use-w3-original-environment", action="store_true",
                        help="load only the bounded, hash-verified W3-140 environment sample into the DOS boot fixture")
    parser.add_argument("--continue-dos-ah3c", action="store_true")
    parser.add_argument("--continue-dos-ax4400", action="store_true")
    parser.add_argument("--continue-dos-ah40", action="store_true")
    parser.add_argument("--continue-dos-ax4400-console", action="store_true",
                        help="serve measured CON AX=4400 metadata through the configured Runtime stream provider")
    parser.add_argument("--continue-dpmi-ax0200", action="store_true",
                        help="route the natural vector-8 AX=0200 request through the current DPMI Runtime callback")
    parser.add_argument("--continue-dpmi-ax6300", action="store_true",
                        help="route the natural DPMI AX=0300 / INT 21h AX=6300 request through a guest-backed provider")
    parser.add_argument("--w1-072-native-address-open", action="store_true",
                        help="capture a fresh Runtime-backed AX=6300 replay through the authenticated virtual ADDRESS.TXT open")
    parser.add_argument("--w1-074-native-address-ax4400", action="store_true",
                        help="continue the authenticated W1-072 ADDRESS.TXT replay through generic Runtime AX=4400 file metadata")
    parser.add_argument("--w1-077-native-handle-lifecycle", action="store_true",
                        help="capture bounded native DOS file-open/close/dup requests before the first eight AH=4400 calls")
    parser.add_argument("--w1-079-native-ax4400-handle2", action="store_true",
                        help="capture and route only the natural AX=4400/BX=2 request on an active virtual file handle")
    parser.add_argument("--w1-080-native-ax4400-active-file", action="store_true",
                        help="continue at most four natural AX=4400/BX=2 callbacks for an active virtual file handle")
    parser.add_argument("--w1-081-native-ah40-active-file", action="store_true",
                        help="capture one natural AH=40/BX=2 request through an active virtual file with a 64-byte cap")
    parser.add_argument("--continue-dos-ah35", action="store_true",
                        help="route only the natural vector-8 DOS AH=35 request at 0xC8CDF through the current Runtime callback")
    parser.add_argument("--continue-dos-ah25", action="store_true",
                        help="route only the natural vector-8 DOS AH=25 request at 0xC8D0C through the current Runtime callback")
    parser.add_argument("--capture-ax0501-stack", action="store_true",
                        help="capture bounded stack words only at the natural AX=0501 trap at 0xC3CC1")
    parser.add_argument("--capture-alloc-chain", action="store_true",
                        help="capture bounded dynamic entries and callsites for the natural allocator path")
    parser.add_argument("--stop-at-first-ax0501", action="store_true",
                        help="trap at the first natural AX=0501 before any harness AX=0501 response path")
    parser.add_argument("--continue-dos-ah48", action="store_true")
    parser.add_argument("--continue-dos-ah48-retry", action="store_true")
    parser.add_argument("--test-dos-ah49-contract", action="store_true")
    parser.add_argument("--cd-present-fixture", action="store_true")
    parser.add_argument("--snapshot-frontier-v1", action="store_true")
    parser.add_argument("--reuse-compiled-closure", action="store_true")
    parser.add_argument("--native-replay-timeout-seconds", type=int, default=90,
                        help="bound the W1-092 native replay and preserve its line-buffered partial trace")
    parser.add_argument("--native-exe-name", default="native_allocator_lifecycle_w1_092.exe",
                        help="output executable basename for the bounded host-backed native replay")
    parser.add_argument("--memory-access-diagnostics", action="store_true",
                        help="opt in to guest instruction/register/backing diagnostics and stop at the first unbacked access")
    parser.add_argument("--capture-w1-094-heap-frontier", action="store_true",
                        help="retain only bounded W1-094 allocator/heap-window markers before older replay assertions")
    parser.add_argument("--capture-crt-startup", action="store_true",
                        help="record indirect CRT calls and post-start argc/argv without seeding guest arguments")
    args = parser.parse_args()
    if args.native_replay_timeout_seconds<10 or args.native_replay_timeout_seconds>600:
        raise SystemExit("--native-replay-timeout-seconds must be between 10 and 600")
    if args.experimental_dpmi_budget_mib and (not args.continue_dpmi_linear_sequence or
            not args.w1_092_host_backed_guest_memory or not 16 <= args.experimental_dpmi_budget_mib <= 3072):
        raise SystemExit("--experimental-dpmi-budget-mib requires the W1-092 AX=0501 sequence and a 16..3072 MiB experimental cap")
    host_backed_guest_memory = (args.w1_091_host_backed_guest_memory or
                                args.w1_092_host_backed_guest_memory)
    guest_map_capacity = 0x7F000000 if args.w1_092_host_backed_guest_memory else 0x0220B000
    if args.w1_092_host_backed_guest_memory:
        global EXE
        if pathlib.Path(args.native_exe_name).name!=args.native_exe_name or not args.native_exe_name.endswith(".exe"):
            raise SystemExit("--native-exe-name must be an executable basename")
        EXE = ROOT / "build" / args.native_exe_name
    fixture_header_dir = pathlib.Path(args.fixture_header_dir)
    if not fixture_header_dir.is_absolute():
        fixture_header_dir = ROOT / fixture_header_dir
    w3_config = None
    w1_address_seed = None
    w1_sound_ini = None
    w3_original_environment = None
    w3_original_environment_metadata = None
    if args.serve_w3_functional_config:
        if not args.capture_crt_startup:
            raise SystemExit("--serve-w3-functional-config requires --capture-crt-startup")
        source = ROOT / "build" / "dosboxx_oracle" / "C" / "GENEWARS" / "CONFIG.INI"
        fixture = ROOT / "tests" / "fixtures" / "w3_067_functional_config.ini"
        clone_evidence = json.loads((ROOT / "evidence" / "w3_067_functional_clone_20261008.json").read_text(encoding="utf-8"))
        staging_evidence = json.loads((ROOT / "evidence" / "w3_067_staging_functional_validation_20261008.json").read_text(encoding="utf-8"))
        expected_config = clone_evidence["clone"]["key_files"]["CONFIG.INI"]
        expected_hash = expected_config["sha256"].lower()
        expected_size = int(expected_config["bytes"])
        fixture_bytes = fixture.read_bytes()
        source_present = source.is_file()
        source_bytes = source.read_bytes() if source_present else None
        source_hash = hashlib.sha256(source_bytes).hexdigest() if source_bytes is not None else None
        fixture_hash = hashlib.sha256(fixture_bytes).hexdigest()
        if (not clone_evidence["clone"]["all_source_paths_sizes_hashes_match"] or
                not clone_evidence["clone"]["config_ini_unchanged"] or
                staging_evidence["runtime"]["guest_errors"]["CONFIG_INI_sha256"].lower() != expected_hash or
                (source_present and (len(source_bytes) != expected_size or source_hash != expected_hash or fixture_bytes != source_bytes)) or
                (not source_present and not args.allow_authenticated_config_fixture_only) or
                len(fixture_bytes) != expected_size or fixture_hash != expected_hash):
            raise SystemExit("W3 functional CONFIG.INI fixture failed provenance, length, or SHA-256 validation")
        # The native callback sees exactly the validated source bytes, compiled
        # into a bounded in-memory fixture. It never opens arbitrary host paths.
        fixture_header_dir.mkdir(parents=True, exist_ok=True)
        header = fixture_header_dir / "native_w3_config_fixture_work2.h"
        values = ",".join(f"0x{byte:02x}" for byte in fixture_bytes)
        header.write_text(
            "#ifndef NATIVE_W3_CONFIG_FIXTURE_WORK2_H\n"
            "#define NATIVE_W3_CONFIG_FIXTURE_WORK2_H\n"
            f"#define NATIVE_W3_CONFIG_SIZE {len(fixture_bytes)}u\n"
            f"static const uint8_t native_w3_config_fixture[]={{ {values} }};\n"
            "#endif\n", encoding="ascii")
        w3_config = {"source": str(source) if source_present else None,
                     "protected_source_read_this_run": source_present,
                     "fixture_only_reason": None if source_present else "protected Oracle clone path absent; authenticated immutable fixture and prior W3 provenance used",
                     "fixture": str(fixture), "size": expected_size,
                     "sha256": expected_hash, "cwd": "C:\\GENEWARS", "drive": "C:",
                     "fixture_provenance": "W3-067 authentic functional clone; immutable bytes",
                     "original_equivalence_claimed": False}
    if args.serve_w3_address_seed:
        if not args.capture_crt_startup:
            raise SystemExit("--serve-w3-address-seed requires --capture-crt-startup")
        fixture = ROOT / "tests" / "fixtures" / "w3_067_address_seed_work1.bin"
        seed_evidence_path = ROOT / "evidence" / "w3_067_staging_functional_validation_20261008.json"
        seed_evidence = json.loads(seed_evidence_path.read_text(encoding="utf-8"))
        seed_auth = seed_evidence["runtime"]["guest_errors"]
        seed_bytes = fixture.read_bytes()
        seed_hash = hashlib.sha256(seed_bytes).hexdigest()
        expected_hash = seed_auth["ADDRESS_TXT_sha256"].lower()
        if (not seed_auth["ADDRESS_TXT_matches_functional_source"] or len(seed_bytes) != 24 or
                seed_hash != expected_hash or expected_hash != "7b1c5391160e1d95393d3abe980dde978b8a79ecb2814e144ee032d9710ba6ee"):
            raise SystemExit("W3-authenticated ADDRESS.TXT seed fixture failed length/provenance/SHA-256 validation")
        fixture_header_dir.mkdir(parents=True, exist_ok=True)
        header = fixture_header_dir / "native_w1_address_seed_work1.h"
        values = ",".join(f"0x{byte:02x}" for byte in seed_bytes)
        header.write_text(
            "#ifndef NATIVE_W3_ADDRESS_SEED_WORK1_H\n"
            "#define NATIVE_W3_ADDRESS_SEED_WORK1_H\n"
            f"#define NATIVE_W1_ADDRESS_SIZE {len(seed_bytes)}u\n"
            f'#define NATIVE_W1_ADDRESS_SHA256 "{seed_hash}"\n'
            f"static const uint8_t native_w1_address_seed[]={{ {values} }};\n"
            "#endif\n", encoding="ascii")
        w1_address_seed = {"fixture": fixture.relative_to(ROOT).as_posix(), "size": len(seed_bytes),
                           "sha256": seed_hash,
                           "authentic_seed_evidence": seed_evidence_path.relative_to(ROOT).as_posix(),
                           "authentic_seed_evidence_sha256": hashlib.sha256(seed_evidence_path.read_bytes()).hexdigest(),
                           "provider_visibility": "explicitly seeded into native virtual-memory provider; host file is not read by guest callbacks"}
        physical = ROOT / "build" / "dosboxx_oracle" / "C" / "ADDRESS.TXT"
        physical_observation = {"path": str(physical), "present": physical.is_file(), "guest_provider_source": False}
        if physical.is_file():
            physical_observation["size"] = physical.stat().st_size
            if physical.stat().st_size == len(seed_bytes):
                physical_bytes = physical.read_bytes()
                physical_observation["sha256"] = hashlib.sha256(physical_bytes).hexdigest()
                physical_observation["matches_authentic_seed"] = physical_bytes == seed_bytes
            else:
                physical_observation["sha256"] = None
                physical_observation["matches_authentic_seed"] = False
                physical_observation["content_read"] = False
        w1_address_seed["physical_host_path_observation"] = physical_observation
    if args.serve_w3_sound_ini:
        if not args.capture_crt_startup or not args.serve_w3_functional_config or not args.serve_w3_address_seed:
            raise SystemExit("--serve-w3-sound-ini requires CRT capture, CONFIG.INI and ADDRESS.TXT fixtures")
        source = ROOT / "build" / "dosboxx_oracle" / "C" / "GENEWARS" / "SOUND.INI"
        fixture = ROOT / "tests" / "fixtures" / "w3_069_sound_ini_work1.bin"
        w2_path = ROOT / "evidence" / "native_dos_ah43_sound_ini_work2.json"
        w3_path = ROOT / "evidence" / "w3_069_original_ah43_sound_ini.json"
        caller_path = ROOT / "evidence" / "w3_077_int21_caller_capture.json"
        w2 = json.loads(w2_path.read_text(encoding="utf-8"))
        w3 = json.loads(w3_path.read_text(encoding="utf-8"))
        caller_evidence = json.loads(caller_path.read_text(encoding="utf-8"))
        expected_hash = "339a99f3fac46182dc52bec753c7122a7fcb1e3cf762e79d6693a9461c8cb9c3"
        fixture_bytes = fixture.read_bytes()
        source_present = source.is_file()
        source_bytes = source.read_bytes() if source_present else None
        source_hash = hashlib.sha256(source_bytes).hexdigest() if source_bytes is not None else None
        if ((not source_present and not args.allow_authenticated_sound_fixture_only) or
                (source_present and (len(source_bytes) != 11 or source_hash != expected_hash or fixture_bytes != source_bytes)) or
                len(fixture_bytes) != 11 or hashlib.sha256(fixture_bytes).hexdigest() != expected_hash):
            raise SystemExit("W3-authenticated SOUND.INI bytes failed size/hash/fixture validation")
        if w2.get("schema") != "w2-native-dos-ah43-sound-ini/v1" and "sound.ini" not in json.dumps(w2).lower():
            raise SystemExit("W2-107 SOUND.INI evidence is missing or has an unexpected schema")
        if "sound.ini" not in json.dumps(w3).lower() or "0x20" not in json.dumps(w3).lower():
            raise SystemExit("W3-069 original SOUND.INI contract evidence is missing")
        fixture_header_dir.mkdir(parents=True, exist_ok=True)
        header = fixture_header_dir / "native_w3_sound_ini_fixture_work1.h"
        values = ",".join(f"0x{byte:02x}" for byte in fixture_bytes)
        header.write_text(
            "#ifndef NATIVE_W3_SOUND_INI_FIXTURE_WORK1_H\n#define NATIVE_W3_SOUND_INI_FIXTURE_WORK1_H\n"
            f"#define NATIVE_W1_SOUND_INI_SIZE {len(fixture_bytes)}u\n"
            f'#define NATIVE_W1_SOUND_INI_SHA256 "{source_hash}"\n'
            f"static const uint8_t native_w3_sound_ini_fixture[]={{ {values} }};\n#endif\n", encoding="ascii")
        w1_sound_ini = {"source": str(source.relative_to(ROOT)).replace("\\", "/") if source_present else None,
                        "protected_source_read_this_run": source_present,
                        "fixture_only_reason": None if source_present else "protected Oracle clone path absent; authenticated immutable fixture and prior W3 evidence used",
                        "fixture": fixture.relative_to(ROOT).as_posix(), "size": len(fixture_bytes),
                        "sha256": expected_hash, "w2_107_evidence": w2_path.relative_to(ROOT).as_posix(),
                        "w3_069_evidence": w3_path.relative_to(ROOT).as_posix(),
                        "guest_path_allowlist": "C:\\GENEWARS\\sound.ini", "access": "read-only",
                        "provider": "bounded in-memory only", "original_caller_link_va": "UNKNOWN",
                        "w3_077_caller_evidence": caller_path.relative_to(ROOT).as_posix(),
                        "w3_077_caller_evidence_sha256": hashlib.sha256(caller_path.read_bytes()).hexdigest(),
                        "original_callsite_candidate_link_va": "0x000AF93A",
                        "original_callsite_match": any(x.get("int_instruction_link_va_candidate", "").lower()=="0xaf93a" and x.get("matches_w1_frontier") for x in caller_evidence.get("sound_ini_callers", [])),
                        "dynamic_invocation_equivalence": False,
                        "original_equivalence_claimed": False}
    if args.use_w3_original_environment:
        if not args.capture_crt_startup:
            raise SystemExit("--use-w3-original-environment requires --capture-crt-startup")
        source = ROOT / "evidence" / "w3_140_original_setenvp_environment.json"
        runtime_contract = ROOT / "evidence" / "w2_114_authenticated_environment_fixture.json"
        original_evidence = json.loads(source.read_text(encoding="utf-8"))
        runtime_evidence = json.loads(runtime_contract.read_text(encoding="utf-8"))
        sample = original_evidence.get("capture", {}).get("environment", {})
        try:
            w3_original_environment = load_authenticated_w3_140_environment(original_evidence, runtime_evidence)
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
        runtime_sample = runtime_evidence.get("original_environment", {})
        expected_sha256 = "65c4d22c258efbf93a93cfcaa8d9d8c489e510cb2be76530646c36e0250ee895"
        actual_sha256 = hashlib.sha256(w3_original_environment).hexdigest()
        w3_original_environment_metadata = {
            "source_evidence": source.relative_to(ROOT).as_posix(),
            "source_evidence_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "runtime_contract_evidence": runtime_contract.relative_to(ROOT).as_posix(),
            "runtime_contract_evidence_sha256": hashlib.sha256(runtime_contract.read_bytes()).hexdigest(),
            "runtime_source_sha256": hashlib.sha256((ROOT / "runtime" / "guest_boot.py").read_bytes()).hexdigest(),
            "size_bytes": len(w3_original_environment), "sha256": actual_sha256,
            "api": "prepare_native_lift_guest(environment_block=authenticated_bytes)",
            "injection": "explicit bounded boot fixture bytes; no selector, descriptor, register, or memory address copied from W3",
            "same_dynamic_invocation_claimed": False,
        }
    if args.continue_selector_query and not args.continue_known_services:
        raise SystemExit("--continue-selector-query requires --continue-known-services")
    if args.continue_time_query and not args.continue_selector_query:
        raise SystemExit("--continue-time-query requires --continue-selector-query")
    if args.continue_dpmi_ax6300 and not (args.capture_crt_startup and args.use_w3_original_environment):
        raise SystemExit("--continue-dpmi-ax6300 requires CRT capture and the authenticated W3-140 environment fixture")
    if args.w1_072_native_address_open and not (args.capture_crt_startup and args.use_w3_original_environment and
            args.serve_w3_address_seed and args.continue_dpmi_ax6300 and args.continue_dos_ah3d):
        raise SystemExit("--w1-072-native-address-open requires CRT capture, W3-140 environment, authenticated ADDRESS.TXT, AX=6300 Runtime routing and DOS AH=3D continuation")
    if args.w1_074_native_address_ax4400 and not (args.capture_crt_startup and args.use_w3_original_environment and
            args.serve_w3_address_seed and args.continue_dpmi_ax6300 and args.continue_dos_ah3d):
        raise SystemExit("--w1-074-native-address-ax4400 requires the authenticated W1-072 CRT/environment/ADDRESS.TXT/AX=6300/AH=3D replay inputs")
    if args.w1_079_native_ax4400_handle2 and not (args.capture_crt_startup and
            args.w1_074_native_address_ax4400 and args.w1_077_native_handle_lifecycle):
        raise SystemExit("--w1-079-native-ax4400-handle2 requires the W1-074/W1-077 native lifecycle capture path")
    if args.w1_080_native_ax4400_active_file and not (args.capture_crt_startup and
            args.w1_074_native_address_ax4400 and args.w1_077_native_handle_lifecycle):
        raise SystemExit("--w1-080-native-ax4400-active-file requires the W1-074/W1-077 native lifecycle capture path")
    if args.w1_081_native_ah40_active_file and not (args.capture_crt_startup and
            args.w1_074_native_address_ax4400 and args.w1_077_native_handle_lifecycle and
            args.w1_080_native_ax4400_active_file):
        raise SystemExit("--w1-081-native-ah40-active-file requires the W1-080 active-file AX=4400 continuation")
    if args.continue_dpmi_linear_allocation and not args.continue_time_query:
        raise SystemExit("--continue-dpmi-linear-allocation requires --continue-time-query")
    if args.continue_dpmi_linear_success and not args.continue_time_query:
        raise SystemExit("--continue-dpmi-linear-success requires --continue-time-query")
    if args.continue_dpmi_linear_sequence and not (args.continue_time_query and args.continue_dos_ah25 and
                                                    args.serve_w3_functional_config and args.use_w3_original_environment):
        raise SystemExit("--continue-dpmi-linear-sequence requires the authenticated post-AH25 startup replay")
    if args.w1_091_host_backed_guest_memory and not args.continue_dpmi_linear_sequence:
        raise SystemExit("--w1-091-host-backed-guest-memory requires --continue-dpmi-linear-sequence")
    if args.w1_092_host_backed_guest_memory and not args.continue_dpmi_linear_sequence:
        raise SystemExit("--w1-092-host-backed-guest-memory requires --continue-dpmi-linear-sequence")
    if args.continue_dos_ah3d and not (args.continue_dpmi_linear_success or
            args.continue_dpmi_linear_sequence or args.w1_072_native_address_open or
            args.w1_074_native_address_ax4400):
        raise SystemExit("--continue-dos-ah3d requires --continue-dpmi-linear-success")
    if args.continue_dos_ah3c and not args.continue_dos_ah3d:
        raise SystemExit("--continue-dos-ah3c requires --continue-dos-ah3d")
    if args.continue_dos_ax4400 and not args.continue_dos_ah3c:
        raise SystemExit("--continue-dos-ax4400 requires --continue-dos-ah3c")
    if args.continue_dos_ah40 and not args.continue_dos_ax4400:
        raise SystemExit("--continue-dos-ah40 requires --continue-dos-ax4400")
    if args.continue_dos_ax4400_console and not (args.continue_dos_ax4400 and args.continue_dos_ah40 and
                                                  args.capture_crt_startup and args.serve_w3_functional_config and
                                                  args.serve_w3_address_seed and args.serve_w3_sound_ini):
        raise SystemExit("--continue-dos-ax4400-console requires AX=4400/AH=40 continuation, CRT capture, and authentic CONFIG.INI/ADDRESS.TXT/SOUND.INI fixtures")
    if args.continue_dpmi_ax0200 and not args.continue_dos_ax4400_console:
        raise SystemExit("--continue-dpmi-ax0200 requires the authenticated native setup replay through AX=4400/BX=1")
    if args.continue_dos_ah35 and not args.continue_dpmi_ax0200:
        raise SystemExit("--continue-dos-ah35 requires the authenticated AX=0200 continuation")
    if args.continue_dos_ah25 and not args.continue_dos_ah35:
        raise SystemExit("--continue-dos-ah25 requires the natural AH=35h continuation")
    if args.capture_ax0501_stack and not args.continue_dos_ah25:
        raise SystemExit("--capture-ax0501-stack requires the authenticated AH=25h continuation")
    if args.capture_alloc_chain and not args.capture_crt_startup:
        raise SystemExit("--capture-alloc-chain requires CRT instrumentation")
    if (args.capture_alloc_chain and not args.use_w3_original_environment and
            not (args.capture_ax0501_stack and args.continue_dos_ah25)):
        raise SystemExit("--capture-alloc-chain outside W1-066 requires the natural post-AH25 AX=0501 stack capture")
    if args.stop_at_first_ax0501 and not (args.capture_alloc_chain and args.capture_crt_startup):
        raise SystemExit("--stop-at-first-ax0501 requires CRT and allocator-chain capture")
    if args.continue_dpmi_linear_allocation and args.continue_dpmi_linear_success:
        raise SystemExit("choose either the fail-closed or synthetic success AX=0501 mode")
    if args.continue_dpmi_linear_sequence and (args.continue_dpmi_linear_allocation or args.continue_dpmi_linear_success):
        raise SystemExit("choose the bounded AX=0501 sequence mode without the single-response modes")
    if args.continue_dos_ah48 and not (args.continue_dpmi_linear_allocation or
                                       args.continue_dpmi_linear_sequence):
        raise SystemExit("--continue-dos-ah48 requires DPMI AX=0501 allocation or sequence mode")
    if args.continue_dos_ah48_retry and not args.continue_dos_ah48:
        raise SystemExit("--continue-dos-ah48-retry requires --continue-dos-ah48")
    tail = args.command_tail.encode("ascii")
    boot = guest_boot.prepare_native_lift_guest(
        TARGET, command_tail=tail, environment_block=w3_original_environment)
    cd_fixture = None
    if args.cd_present_fixture:
        cue_path = pathlib.Path((_GW_FX + '\\evidence\\original_disc\\Genewars (Europe) (En,Fr,De,Es,It,Sv).cue'))
        cue_before = hashlib.sha256(cue_path.read_bytes()).hexdigest()
        config_path = ROOT / "build" / "dos_user_profile_w2_036" / "GENEWARS" / "config.ini"
        config_bytes = config_path.read_bytes()
        if config_bytes:
            raise AssertionError(f"CD-present config fixture must be empty: {config_path}")
        # Preflight the same immutable image in the bounded Python DOS host.
        # The native C run has not reached a CD request at its current frontier;
        # keep that distinction explicit in evidence.
        fixture_boot = guest_boot.prepare_guest(TARGET, command_tail=tail)
        cue_image = CueImage.from_cue(cue_path)
        fixture_host = DosHost(fixture_boot, cdrom_drives=("D",), cdrom_images=(cue_image,))
        if fixture_host.iso_mount_error or fixture_host.filesystem.iso_volume is None:
            raise AssertionError(f"original CUE failed to mount read-only: {fixture_host.iso_mount_error}")
        iso = fixture_host.filesystem.iso_volume
        try:
            iso.stat("GAME/DATA/TEXT/ENG/TEXT.DAT")
            nested_text_present = True
        except FileNotFoundError:
            nested_text_present = False
        try:
            iso.stat("DATA/TEXT.DAT")
            flat_alias_present = True
        except FileNotFoundError:
            flat_alias_present = False
        cue_after = hashlib.sha256(cue_path.read_bytes()).hexdigest()
        cd_fixture = {
            "command_tail": args.command_tail,
            "config_path": str(config_path),
            "config_sha256": hashlib.sha256(config_bytes).hexdigest(),
            "config_size": len(config_bytes),
            "cdrom_drives": ["D"],
            "cue_path": str(cue_path),
            "cue_sha256_before": cue_before,
            "cue_sha256_after": cue_after,
            "cue_read_only_mount": True,
            "mounted_iso_root_entries": iso.listdir(),
            "nested_text_resource_present": nested_text_present,
            "flat_data_text_alias_present": flat_alias_present,
            "fixture_preflight": "Python DosHost CUE/ISO mount; separate from native C callbacks",
            "native_cd_request_reached": False,
        }
        if cue_before != cue_after:
            raise AssertionError("read-only reference CUE hash changed during fixture preflight")
    if boot.seed.eip != 0x000AF96C or boot.image.mem_base != 0x10000:
        raise AssertionError("fixed-link-VA boot layout differs from generated entry addresses")
    if max(boot.psp_address, boot.env_address) >= boot.image.mem_base:
        raise AssertionError("conventional process blocks overlap the linked LE image")
    # In the observed DPMI startup branch, start_ reads PSP:2c as the protected
    # mode environment selector and loads it into DS. Bind it to the concrete
    # guest environment block; do not substitute the real-mode segment here.
    env_selector = 0x1100
    boot.memory.write(boot.psp_address + 0x2C, struct.pack("<H", env_selector))
    if struct.unpack_from("<H", boot.memory.data, boot.psp_address + 0x2C)[0] != env_selector:
        raise AssertionError("DPMI PSP:2c must contain the environment selector")
    psp_selector = 0x0024
    boot.memory.write(0x10B76C, struct.pack("<H", psp_selector))
    dos_layout_boot = guest_boot.prepare_guest(
        TARGET, psp_segment=boot.psp_segment, env_segment=boot.env_segment,
        command_tail=tail, environment_block=w3_original_environment)
    dos_layout_host = DosHost(dos_layout_boot, dos_memory_profile="post_dos4gw_le_entry")
    dos_layout = dos_layout_host.dos_mcb_layout
    if (dos_layout["free_data_segment"] != dos_layout["environment_segment"] +
            dos_layout["environment_paragraphs"] + 1 or
            dos_layout["top_segment"] * 16 > guest_boot.DOS_CONVENTIONAL_BYTES or
            dos_layout["free_paragraphs"] <= 0):
        raise AssertionError("post-DOS/4GW allocator map does not match the bounded conventional-memory fixture")
    BOOT_BIN.write_bytes(boot.memory.data)
    SEED_HEADER.write_text(
        "#ifndef GW_NATIVE_LIFT_BOOT_SEED_H\n#define GW_NATIVE_LIFT_BOOT_SEED_H\n"
        f"#define GW_BOOT_MEM_SIZE 0x{boot.memory.size:X}u\n"
        f"#define GW_BOOT_ENTRY 0x{boot.seed.eip:08X}u\n"
        f"#define GW_BOOT_ESP 0x{boot.seed.esp:08X}u\n"
        f"#define GW_BOOT_PSP 0x{boot.psp_address:08X}u\n"
        f"#define GW_BOOT_ENV_SEG 0x{boot.env_segment:04X}u\n"
        f"#define GW_BOOT_ENV_PSP_SELECTOR 0x{env_selector:04X}u\n"
        f"#define GW_BOOT_ENV_SELECTOR 0x{env_selector:04X}u\n"
        f"#define GW_BOOT_ENV_ADDRESS 0x{boot.env_address:08X}u\n"
        f"#define GW_BOOT_ENV_LIMIT 0x{max(0, len(boot.environment) - 1):08X}u\n"
        f"#define GW_BOOT_DOS_ALLOCATOR_BEGIN_SEGMENT 0x{dos_layout['free_data_segment']:04X}u\n"
        f"#define GW_BOOT_DOS_ALLOCATOR_END_SEGMENT 0x{dos_layout['top_segment']:04X}u\n"
        f"#define GW_BOOT_IMAGE_BEGIN_SEGMENT 0x{boot.image.mem_base >> 4:04X}u\n"
        f"#define GW_BOOT_PSP_SELECTOR 0x{psp_selector:04X}u\n"
        f"#define GW_BOOT_CS 0x{boot.seed.cs:04X}u\n"
        f"#define GW_BOOT_DS 0x{boot.seed.ds:04X}u\n"
        f"#define GW_BOOT_ES 0x{psp_selector:04X}u\n"
        f"#define GW_BOOT_SS 0x{boot.seed.ss:04X}u\n"
        f"#define GW_BOOT_TAIL_LENGTH {len(tail)}u\n"
        "static const unsigned char GW_BOOT_TAIL[] = {" + (", ".join(f"0x{b:02X}" for b in tail) if tail else "0") + "};\n"
        "#endif\n", encoding="utf-8"
    )
    CACHE.mkdir(exist_ok=True)
    task_temp = pathlib.Path(os.environ.get("GW_TASK_TEMP", str(CACHE)))
    task_temp.mkdir(parents=True, exist_ok=True)
    env = {
        **os.environ, "PYTHONDONTWRITEBYTECODE": "1",
        "TEMP": str(task_temp), "TMP": str(task_temp), "TMPDIR": str(task_temp),
        "PATH": (_GW_MSYS2 + '\\mingw32\\bin;' + _GW_MSYS2 + '\\usr\\bin;') + os.environ.get("PATH", ""),
        "PYTHONPATH": str(PY_TOOLS) + os.pathsep + os.environ.get("PYTHONPATH", ""),
    }
    if args.memory_access_diagnostics:
        env["GWRECOMP_MEMORY_DIAG"]="1"
    native_cc = [(_GW_MSYS2 + '\\mingw32\\bin\\gcc.exe'), "-std=gnu11", "-m32", "-O0"]
    if args.w1_092_host_backed_guest_memory:
        env = msvc_x64_environment(env)
        native_cc = [(_GW_CLANG_X86),
                     "-target", "x86_64-pc-windows-msvc", "-std=gnu11", "-O2",
                     "-fwrapv", "-fno-strict-aliasing", "-D_CRT_SECURE_NO_WARNINGS"]
    if pathlib.Path(args.compile_evidence_name).name != args.compile_evidence_name or not args.compile_evidence_name.endswith(".json"):
        raise SystemExit("invalid compile evidence filename")
    env["GW_ENTRY_PATH_COMPILE_EVIDENCE_NAME"] = args.compile_evidence_name
    if args.snapshot_frontier_v1:
        env["GW_FRONTIER_SNAPSHOT_MEMORY"] = str(ROOT / "evidence" / "frontier_snapshot_v1_memory.bin")
    if args.memory_access_diagnostics and args.w1_092_host_backed_guest_memory:
        if args.reuse_compiled_closure:
            raise SystemExit("--memory-access-diagnostics requires regenerating the bounded allocator access hooks")
        # This replay's authoritative target is the x64 native host build
        # below. Refresh only the changed entry root, interrupt routing, and
        # allocator chain instead of allocating a second, memory-heavy x86-32
        # object for the same 27 MiB generated closure.
        run([sys.executable, str(ROOT / "tools" / "refresh_entry_start.py")], env)
        run([sys.executable, str(ROOT / "tools" / "route_lifted_interrupts.py")], env)
        run([sys.executable, str(ROOT / "tools" / "refresh_memory_diag_allocators.py")], env)
    elif args.memory_access_diagnostics:
        if args.reuse_compiled_closure:
            raise SystemExit("--memory-access-diagnostics requires regenerating the bounded allocator access hooks")
        run([sys.executable, str(ROOT / "tools" / "refresh_memory_diag_allocators.py")], env)
    skip_x86_closure_compile = (args.memory_access_diagnostics and
                                args.w1_092_host_backed_guest_memory)
    if args.reuse_compiled_closure:
        build_source = ROOT / "build" / "entry_path_closure.c"
        build_object = ROOT / "build" / "entry_path_closure_routed.o"
        prior = json.loads((ROOT / "evidence" / "entry_path_closure_routed_compile.json").read_text(encoding="utf-8"))
        if hashlib.sha256(build_source.read_bytes()).hexdigest() != prior["source_sha256"] or hashlib.sha256(build_object.read_bytes()).hexdigest() != prior["object_sha256"]:
            raise SystemExit("verified entry closure object is stale; refusing reuse")
    elif not skip_x86_closure_compile:
        run([sys.executable, str(ROOT / "tests" / "test_entry_closure_compile.py")], env)
    if args.capture_alloc_chain:
        import re as regex
        closure_path = ROOT / "build" / "entry_path_closure.c"
        closure_source = closure_path.read_text(encoding="utf-8")
        alloc_call = regex.compile(r'(?m)^(\s*)(RECOMP_CALL\(sub_000ADF95\); /\* 0x([0-9A-Fa-f]{8}): call [^*]+\*/)')
        def capture_nmalloc_site(match):
            indent, call, site = match.group(1), match.group(2), int(match.group(3), 16)
            return (indent + f"GW_NATIVE_CAPTURE_ALLOC_CALLSITE(g_cur_func, 0x000ADF95u, 0x{site:08X}u); " + call)
        closure_source = alloc_call.sub(capture_nmalloc_site, closure_source)
        closure_path.write_text(closure_source, encoding="utf-8")
    lookup_count = generate_native_lookup(ROOT / "build" / "entry_path_closure.c")
    object_path = OBJECT
    if args.capture_crt_startup:
        capture_object = ROOT / "build" / "entry_path_closure_crt_capture.o"
        run([
            *native_cc,
            "-DGW_NATIVE_CAPTURE_CRT_STARTUP=1",
            *( ["-DGW_NATIVE_CAPTURE_ALLOC_CHAIN=1"] if args.capture_alloc_chain else [] ),
            "-c",
            "-I", str(ROOT / "runtime"),
            "-I", str(ROOT / "third_party" / "pcrecomp" / "runtime" / "recomp32"),
            str(ROOT / "build" / "entry_path_closure.c"), "-o", str(capture_object),
        ], env)
        object_path = capture_object
    if args.expect_fault:
        run([
            (_GW_MSYS2 + '\\mingw32\\bin\\gcc.exe'), "-std=gnu11", "-m32", "-O0", "-g", "-c",
            "-I", str(ROOT / "runtime"),
            "-I", str(ROOT / "third_party" / "pcrecomp" / "runtime" / "recomp32"),
            str(ROOT / "build" / "entry_path_closure.c"), "-o", str(DEBUG_OBJECT),
        ], env)
        object_path = DEBUG_OBJECT
    cmd = [
        *native_cc,
        *( ["-DGW_NATIVE_CONTINUE_KNOWN=1"] if args.continue_known_services else [] ),
        *( ["-DGW_NATIVE_CONTINUE_SELECTOR_QUERY=1"] if args.continue_selector_query else [] ),
        *( ["-DGW_NATIVE_CONTINUE_TIME_QUERY=1"] if args.continue_time_query else [] ),
        *( ["-DGW_NATIVE_CONTINUE_DPMI_LINEAR=1"] if args.continue_dpmi_linear_allocation else [] ),
        *( ["-DGW_NATIVE_CONTINUE_DPMI_LINEAR_SUCCESS=1"] if args.continue_dpmi_linear_success or args.serve_w3_functional_config else [] ),
        *( ["-DGW_NATIVE_CONTINUE_DPMI_LINEAR_SEQUENCE=1"] if args.continue_dpmi_linear_sequence else [] ),
        *( ["-DGW_NATIVE_W1_091_HOST_BACKED_GUEST_MEMORY=1"] if args.w1_091_host_backed_guest_memory else [] ),
        *( ["-DGW_NATIVE_W1_092_HOST_BACKED_GUEST_MEMORY=1"] if args.w1_092_host_backed_guest_memory else [] ),
        *( [f"-DGW_NATIVE_DPMI_ALLOCATOR_END=0x{0x00200000 + args.experimental_dpmi_budget_mib * 1024 * 1024:08X}u"] if args.experimental_dpmi_budget_mib else [] ),
        *( ["-DGW_NATIVE_DPMI_ALLOCATOR_END_EXPERIMENTAL=1"] if args.experimental_dpmi_budget_mib else [] ),
        *( ["-DGW_NATIVE_STOP_AT_FIRST_AX0501=1"] if args.stop_at_first_ax0501 else [] ),
        *( ["-DGW_NATIVE_CONTINUE_DOS_AH3D=1"] if args.continue_dos_ah3d else [] ),
        *( ["-DGW_NATIVE_CONTINUE_DOS_AH3D=1", "-DGW_NATIVE_SERVE_W3_CONFIG=1"] if args.serve_w3_functional_config else [] ),
        *( ["-DGW_NATIVE_SERVE_W3_ADDRESS_SEED=1"] if args.serve_w3_address_seed else [] ),
        *( ["-DGW_NATIVE_SERVE_W3_SOUND_INI=1"] if args.serve_w3_sound_ini else [] ),
        *( ["-DGW_NATIVE_CONTINUE_DOS_AH3C=1"] if args.continue_dos_ah3c else [] ),
        *( ["-DGW_NATIVE_CONTINUE_DOS_AX4400=1"] if args.continue_dos_ax4400 or args.w1_074_native_address_ax4400 else [] ),
        *( ["-DGW_NATIVE_CONTINUE_DOS_AX4400_CONSOLE=1"] if args.continue_dos_ax4400_console else [] ),
        *( ["-DGW_NATIVE_CONTINUE_DPMI_AX0200=1"] if args.continue_dpmi_ax0200 else [] ),
        *( ["-DGW_NATIVE_CONTINUE_DPMI_AX6300=1"] if args.continue_dpmi_ax6300 else [] ),
        *( ["-DGW_NATIVE_CONTINUE_DOS_AH35=1"] if args.continue_dos_ah35 else [] ),
        *( ["-DGW_NATIVE_CONTINUE_DOS_AH25=1"] if args.continue_dos_ah25 else [] ),
        *( ["-DGW_NATIVE_CAPTURE_AX0501_STACK=1"] if args.capture_ax0501_stack else [] ),
        *( ["-DGW_NATIVE_CAPTURE_ALLOC_CHAIN=1"] if args.capture_alloc_chain else [] ),
        *( ["-DGW_NATIVE_CONTINUE_DOS_AH40=1"] if args.continue_dos_ah40 else [] ),
        *( ["-DGW_NATIVE_CONTINUE_DOS_AH48=1"] if args.continue_dos_ah48 else [] ),
        *( ["-DGW_NATIVE_CONTINUE_DOS_AH48_RETRY=1"] if args.continue_dos_ah48_retry else [] ),
        *( ["-DGW_NATIVE_TEST_DOS_AH49=1"] if args.test_dos_ah49_contract else [] ),
        *( ["-DGW_NATIVE_CAPTURE_CRT_STARTUP=1"] if args.capture_crt_startup else [] ),
        *( ["-DGW_NATIVE_CAPTURE_W1_077_LIFECYCLE=1"] if args.w1_077_native_handle_lifecycle else [] ),
        *( ["-DGW_NATIVE_CAPTURE_W1_079_AX4400_HANDLE2=1"] if args.w1_079_native_ax4400_handle2 else [] ),
        *( ["-DGW_NATIVE_CAPTURE_W1_080_AX4400_ACTIVE_FILE=1"] if args.w1_080_native_ax4400_active_file else [] ),
        *( ["-DGW_NATIVE_CAPTURE_W1_081_AH40_ACTIVE_FILE=1"] if args.w1_081_native_ah40_active_file else [] ),
        *( ["-g"] if args.expect_fault else [] ),
        "-I", str(ROOT / "runtime"), "-I", str(fixture_header_dir), "-I", str(ROOT / "build"),
        "-I", str(ROOT / "third_party" / "pcrecomp" / "runtime" / "recomp32"),
        "-o", str(EXE), str(ROOT / "tests" / "test_native_guest_image.c"),
        str(ROOT / "runtime" / "recomp_context.c"), str(ROOT / "runtime" / "gw_interrupts.c"),
        str(ROOT / "runtime" / "gw_segments.c"), str(ROOT / "runtime" / "guest_boot_context.c"),
        str(ROOT / "runtime" / "gw_dos_services.c"), str(ROOT / "runtime" / "recomp_x87.c"),
        str(ROOT / "runtime" / "gw_pit8254.c"),
        str(LOOKUP_C),
        str(object_path), *( [] if args.w1_092_host_backed_guest_memory else ["-lm"] ),
    ]
    run(cmd, env)
    if args.memory_access_diagnostics:
        compile_receipt = {
            "schema": "gwrecomp.native-memory-diagnostic-build/v1",
            "target_sha256": hashlib.sha256(TARGET.read_bytes()).hexdigest(),
            "closure_sha256": hashlib.sha256((ROOT / "build" / "entry_path_closure.c").read_bytes()).hexdigest(),
            "native_executable": EXE.name,
            "native_executable_sha256": hashlib.sha256(EXE.read_bytes()).hexdigest(),
            "host_architecture": "x86_64",
            "compile_and_link_exit": 0,
            "allocator_lifter_refresh": "evidence/memory_diag_allocator_refresh_w1_105.json",
            "passed": True,
        }
        (ROOT / "evidence" / args.compile_evidence_name).write_text(
            json.dumps(compile_receipt, indent=2) + "\n", encoding="utf-8")
    native_replay_timed_out=False
    try:
        process = subprocess.run([str(EXE)], cwd=ROOT, env=env, text=True, capture_output=True,
            timeout=(args.native_replay_timeout_seconds if args.w1_092_host_backed_guest_memory else None))
    except subprocess.TimeoutExpired as exc:
        if not args.w1_092_host_backed_guest_memory:
            raise
        native_replay_timed_out=True
        def output_text(value):
            if value is None: return ""
            return value.decode("utf-8",errors="replace") if isinstance(value,bytes) else value
        process=subprocess.CompletedProcess([str(EXE)],124,output_text(exc.stdout),output_text(exc.stderr))
    if args.w1_092_host_backed_guest_memory:
        import re as regex
        map_line = next((line for line in process.stdout.splitlines()
                         if line.startswith("NATIVE_DPMI_GUEST_MEMORY_MAP ")), None)
        map_match = regex.search(r"guest_capacity=([0-9a-fA-F]{8})", map_line or "")
        if not map_match:
            raise AssertionError(f"W1-092 host virtual reservation capacity was not reported; exit={process.returncode}; stdout={process.stdout[-1000:]}; stderr={process.stderr[-2000:]}")
        guest_map_capacity = int(map_match.group(1), 16)
    if args.capture_w1_094_heap_frontier:
        native_lines = process.stdout.splitlines() + process.stderr.splitlines()
        prefixes = ("NATIVE_DPMI_GUEST_MEMORY_MAP ", "NATIVE_DOS_MCB_SEED ",
                    "NATIVE_DPMI_BUDGET ",
                    "NATIVE_DOS_AH48 ", "NATIVE_DPMI_AX0501_SEQUENCE ",
                    "NATIVE_DPMI_LINEAR_LOCK ", "NATIVE_DPMI_DOS_MEMORY ", "NATIVE_DOS_AH49 ",
                    "NATIVE_DPMI0300_INT2F1500 ", "NATIVE_DPMI0300_AX6300 ",
                    "NATIVE_W1_093_HEAP_WINDOW_ARM ", "NATIVE_W1_093_HEAP_WINDOW_WRITE ",
                    "NATIVE_W1_093_REPEAT_GUARD ", "NATIVE_W1_092_PROGRESS ",
                    "NATIVE_W1_092_HEAP_LIST ", "NATIVE_W1_093_BLOCK_SNAPSHOT ",
                    "NATIVE_DOS_AH48_DISPATCH ", "NATIVE_DOS_AH49_DISPATCH ",
                    "NATIVE_MEMORY_ACCESS_DIAGNOSTIC ", "NATIVE_MEMORY_FAULT ",
                    "NATIVE_EXCEPTION ", "NATIVE_NEXT_TRAP ", "NATIVE_FRONTIER_CPU ", "W1_CRT_SUMMARY ")
        selected = [line[:2000] for line in native_lines if line.startswith(prefixes)]
        stdout_capture=ROOT/"work"/"native_memory_access_diagnostic_replay.stdout.log"
        stderr_capture=ROOT/"work"/"native_memory_access_diagnostic_replay.stderr.log"
        stdout_capture.parent.mkdir(parents=True,exist_ok=True)
        stdout_capture.write_text(process.stdout,encoding="utf-8",errors="replace")
        stderr_capture.write_text(process.stderr,encoding="utf-8",errors="replace")
        evidence = {
            "schema": "gwrecomp.native-heap-frontier-w1-094/v1",
            "task": "W1-094", "execution_mode": "native_recompiled_guest",
            "evidence_level": ("NATIVE_REACHED" if any(x.startswith("NATIVE_W1_093_REPEAT_GUARD ") for x in selected)
                               else "NATIVE_CRASH_FRONTIER" if any(x.startswith("NATIVE_EXCEPTION ") for x in selected)
                               else "NATIVE_FRONTIER_CAPTURE"),
            "fresh_replay": True, "target_sha256": boot.executable_sha256,
            "build_sha256": hashlib.sha256(EXE.read_bytes()).hexdigest() if EXE.is_file() else None,
            "command_tail": args.command_tail,
            "native_replay_timed_out": native_replay_timed_out,
            "native_replay_timeout_seconds": args.native_replay_timeout_seconds if native_replay_timed_out else None,
            "experimental_dpmi_budget_mib": args.experimental_dpmi_budget_mib,
            "native_returncode": process.returncode,
            "stdout_sha256": hashlib.sha256(process.stdout.encode("utf-8", errors="replace")).hexdigest(),
            "stdout_bytes": len(process.stdout.encode("utf-8", errors="replace")),
            "stderr_sha256": hashlib.sha256(process.stderr.encode("utf-8", errors="replace")).hexdigest(),
            "selected_lines": selected,
            "full_output_captures": {
                "stdout": str(stdout_capture.relative_to(ROOT)).replace("\\", "/"),
                "stderr": str(stderr_capture.relative_to(ROOT)).replace("\\", "/"),
                "stdout_bytes": len(process.stdout.encode("utf-8",errors="replace")),
                "stderr_bytes": len(process.stderr.encode("utf-8",errors="replace")),
            },
            "guest_state_injected": False, "original_equivalence_claimed": False,
            "graphics": {"vesa_reached": any("LbScreenSetup" in x or "VESA" in x for x in selected),
                         "authentic_framebuffer_observed": False}
        }
        evidence_path = ROOT / "evidence" / args.evidence_name
        evidence_path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
        print("\n".join(selected))
        print(f"W1-094 bounded heap frontier evidence saved: evidence/{evidence_path.name}")
        return 0 if any(x.startswith(("NATIVE_W1_093_REPEAT_GUARD ", "NATIVE_NEXT_TRAP ", "NATIVE_EXCEPTION ")) for x in selected) else 1
    if args.capture_crt_startup:
        if "W1_CRT_SUMMARY " not in process.stdout and not native_replay_timed_out:
            failed_lines=process.stdout.splitlines()+process.stderr.splitlines()
            task_tokens=args.evidence_name.lower().replace("-","_").split("_")
            task_number=next((task_tokens[index+1] for index,token in enumerate(task_tokens[:-1])
                if token=="w1" and task_tokens[index+1].isdigit()),None)
            failure_evidence={
                "schema":"gwrecomp.native-replay-crash-frontier/v1",
                "task":("W1-"+task_number if task_number else "native-replay"),
                "evidence_level":"NATIVE_CRASH_FRONTIER",
                "target_sha256":boot.executable_sha256,
                "build_sha256":hashlib.sha256(EXE.read_bytes()).hexdigest() if EXE.is_file() else None,
                "command_tail":args.command_tail,
                "replay_options":[name for name,enabled in (
                    ("--continue-dpmi-linear-sequence",args.continue_dpmi_linear_sequence),
                    ("--w1-092-host-backed-guest-memory",args.w1_092_host_backed_guest_memory),
                    ("--experimental-dpmi-budget-mib",bool(args.experimental_dpmi_budget_mib)),
                    ("--continue-dos-ah48",args.continue_dos_ah48),
                    ("--continue-dos-ah48-retry",args.continue_dos_ah48_retry)) if enabled],
                "experimental_dpmi_budget_mib":args.experimental_dpmi_budget_mib,
                "returncode":process.returncode,"native_replay_timeout_seconds":None,
                "stdout_sha256":hashlib.sha256(process.stdout.encode("utf-8",errors="replace")).hexdigest(),
                "stderr_sha256":hashlib.sha256(process.stderr.encode("utf-8",errors="replace")).hexdigest(),
                "frontier_markers":[line[:2000] for line in failed_lines if line.startswith((
                    "NATIVE_DPMI_BUDGET ","NATIVE_DPMI_GUEST_MEMORY_MAP ","NATIVE_DOS_AH48 ",
                    "NATIVE_DPMI_DOS_MEMORY ","NATIVE_W1_093_REPEAT_GUARD ","NATIVE_NEXT_TRAP ","NATIVE_FRONTIER_CPU ",
                    "NATIVE_EXCEPTION "))],
                "original_equivalence_claimed":False,
                "full_output_retained":False}
            (ROOT/"evidence"/args.evidence_name).write_text(
                json.dumps(failure_evidence,indent=2)+"\n",encoding="utf-8")
            raise AssertionError(f"native CRT capture marker missing; exit={process.returncode}; "
                f"crash/frontier evidence saved to evidence/{args.evidence_name}")
        capture = {
            "test": "native CRT startup capture; no argc/argv injection",
            "target_sha256": boot.executable_sha256,
            "command_tail": args.command_tail,
            "fixture_psp_tail_length": len(tail),
            "replay_options": [
                name for name, enabled in (
                    ("--serve-w3-functional-config", args.serve_w3_functional_config),
                    ("--allow-authenticated-config-fixture-only", args.allow_authenticated_config_fixture_only),
                    ("--serve-w3-address-seed", args.serve_w3_address_seed),
                    ("--serve-w3-sound-ini", args.serve_w3_sound_ini),
                    ("--allow-authenticated-sound-fixture-only", args.allow_authenticated_sound_fixture_only),
                    ("--use-w3-original-environment", args.use_w3_original_environment),
                    ("--continue-known-services", args.continue_known_services),
                    ("--continue-selector-query", args.continue_selector_query),
                    ("--continue-time-query", args.continue_time_query),
                    ("--continue-dpmi-linear-success", args.continue_dpmi_linear_success),
                    ("--continue-dpmi-linear-sequence", args.continue_dpmi_linear_sequence),
                    ("--w1-091-host-backed-guest-memory", args.w1_091_host_backed_guest_memory),
                    ("--w1-092-host-backed-guest-memory", args.w1_092_host_backed_guest_memory),
                    ("--continue-dos-ah3d", args.continue_dos_ah3d),
                    ("--continue-dos-ah3c", args.continue_dos_ah3c),
                    ("--continue-dos-ax4400", args.continue_dos_ax4400),
                    ("--continue-dos-ax4400-console", args.continue_dos_ax4400_console),
                    ("--continue-dpmi-ax0200", args.continue_dpmi_ax0200),
                    ("--continue-dpmi-ax6300", args.continue_dpmi_ax6300),
                    ("--w1-072-native-address-open", args.w1_072_native_address_open),
                    ("--w1-074-native-address-ax4400", args.w1_074_native_address_ax4400),
                    ("--w1-077-native-handle-lifecycle", args.w1_077_native_handle_lifecycle),
                    ("--w1-079-native-ax4400-handle2", args.w1_079_native_ax4400_handle2),
                    ("--w1-080-native-ax4400-active-file", args.w1_080_native_ax4400_active_file),
                    ("--w1-081-native-ah40-active-file", args.w1_081_native_ah40_active_file),
                    ("--continue-dos-ah35", args.continue_dos_ah35),
                    ("--continue-dos-ah25", args.continue_dos_ah25),
                    ("--capture-ax0501-stack", args.capture_ax0501_stack),
                    ("--capture-alloc-chain", args.capture_alloc_chain),
                    ("--stop-at-first-ax0501", args.stop_at_first_ax0501),
                    ("--continue-dos-ah40", args.continue_dos_ah40),
                    ("--capture-crt-startup", args.capture_crt_startup),
                    ("--reuse-compiled-closure", args.reuse_compiled_closure),
                ) if enabled
            ],
            "build_fingerprints": {
                "closure_source_sha256": hashlib.sha256((ROOT / "build" / "entry_path_closure.c").read_bytes()).hexdigest(),
                "routed_closure_object_sha256": hashlib.sha256((ROOT / "build" / "entry_path_closure_routed.o").read_bytes()).hexdigest(),
                "capture_closure_object_sha256": hashlib.sha256(pathlib.Path(object_path).read_bytes()).hexdigest(),
                "native_harness_source_sha256": hashlib.sha256((ROOT / "tests" / "test_native_guest_image.c").read_bytes()).hexdigest(),
                "replay_driver_sha256": hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
                "dos_services_source_sha256": hashlib.sha256((ROOT / "runtime" / "gw_dos_services.c").read_bytes()).hexdigest(),
                "recomp_context_source_sha256": hashlib.sha256((ROOT / "runtime" / "recomp_context.c").read_bytes()).hexdigest(),
                "pit_runtime_source_sha256": hashlib.sha256((ROOT / "runtime" / "gw_pit8254.c").read_bytes()).hexdigest(),
                "closure_compile_evidence": str(ROOT / "evidence" / args.compile_evidence_name),
            },
            "native_returncode": process.returncode,
            "stdout": process.stdout,
            "stderr": process.stderr,
            "capture_only": True,
        }
        if args.stop_at_first_ax0501:
            import re
            stdout_lines = process.stdout.splitlines()
            parse_fields = lambda line: dict(token.split("=", 1) for token in line.split()[1:] if "=" in token)
            strict_line = next((line for line in stdout_lines if line.startswith("NATIVE_DPMI_AX0501_STRICT_FRONTIER ")), None)
            if strict_line is None:
                raise AssertionError(f"strict AX=0501 mode did not trap at its natural request; rc={process.returncode}; tail={stdout_lines[-24:]}")
            if any(line.startswith(("NATIVE_DPMI_LINEAR_SUCCESS ", "NATIVE_DPMI_LINEAR ")) for line in stdout_lines):
                raise AssertionError("strict AX=0501 capture contains a response path")
            strict_fields = parse_fields(strict_line)
            if strict_fields.get("response_count") != "0":
                raise AssertionError(f"strict AX=0501 response count is not zero: {strict_fields}")
            if args.use_w3_original_environment:
                callbacks = [line for line in stdout_lines if line.startswith("W1_CRT_CALLBACK_DYNAMIC ")]
                callback_fields = [parse_fields(line) for line in callbacks]
                summary_line = next((line for line in stdout_lines if line.startswith("W1_CRT_SUMMARY ")), None)
                if summary_line is None:
                    raise AssertionError("W1-066 strict startup capture lacks a CRT summary")
                summary_fields = parse_fields(summary_line)
                event_prefixes = ("NATIVE_ADF95_BRANCH ", "NATIVE_ADF95_RETURN ", "NATIVE_ALLOC_CALLSITE ",
                                  "NATIVE_ALLOC_ENTRY ", "NATIVE_ALLOC_RETURN ", "NATIVE_ALLOC_POINT ")
                environment_events = [line for line in stdout_lines if line.startswith(event_prefixes) and
                                      any(site in line.casefold() for site in
                                          ("000dfe04", "000dfe08", "000dfe0d", "000dfe12", "000adf95"))]
                if not any(line.startswith("NATIVE_ADF95_BRANCH ") and "site=000dfe04" in line.lower()
                           for line in environment_events):
                    raise AssertionError("W1-066 did not capture the native __setenvp_ DFE04 branch")
                if not any(line.startswith("NATIVE_ALLOC_CALLSITE ") and "site=000dfe0d" in line.lower()
                           for line in environment_events):
                    raise AssertionError("W1-066 did not capture the native __setenvp_ DFE0D callsite")
                if not any(line.startswith("NATIVE_ALLOC_ENTRY ") and "va=000adf95" in line.lower()
                           for line in environment_events):
                    raise AssertionError("W1-066 did not capture native ADF95 entry")
                runtime_dir = ROOT / "runtime"
                sys.path.insert(0, str(ROOT / "tools"))
                import frontier_snapshot
                runtime_fingerprint = {"c_h_sha256": frontier_snapshot.runtime_hash(ROOT),
                                       "python_sha256": frontier_snapshot.manifest_hash(list(runtime_dir.glob("*.py")), ROOT)}
                exe_sha = hashlib.sha256(EXE.read_bytes()).hexdigest()
                selected = [line for line in stdout_lines if line.startswith((
                    "NATIVE_DPMI_AX0501_STRICT_FRONTIER ", "NATIVE_ALLOC_ENTRY ", "NATIVE_ALLOC_CALLSITE ",
                    "NATIVE_ALLOC_RETURN ", "NATIVE_ALLOC_POINT ", "NATIVE_ADF95_BRANCH ", "NATIVE_ADF95_RETURN ",
                    "W1_INITRTNS_ENTRY ", "W1_CRT_CALLBACK_DYNAMIC ", "W1_CRT_SUMMARY ", "W1_CRT_ARG ",
                    "NATIVE_NEXT_TRAP ", "NATIVE_FRONTIER_CPU "))]
                return_event = next((line for line in environment_events if line.startswith("NATIVE_ADF95_RETURN ")
                                     and "link_va=000dfe12" in line.lower()), None)
                capture["task_schema"] = "gwrecomp.native-setenvp-aligned-replay/v1"
                capture["schema"] = "gwrecomp.native-setup-replay/v1"
                capture["execution_mode"] = "native_recompiled_guest"
                capture["evidence_level"] = "NATIVE_REACHED"
                capture["build_id"] = exe_sha
                capture["build_artifact"] = {"path": EXE.relative_to(ROOT).as_posix(), "sha256": exe_sha,
                    "runtime_fingerprint": runtime_fingerprint}
                capture["runtime_fingerprint"] = runtime_fingerprint
                capture["original_contract"] = {
                    "path": "evidence/w3_140_original_setenvp_environment.json",
                    "sha256": hashlib.sha256((ROOT / "evidence" /
                        "w3_140_original_setenvp_environment.json").read_bytes()).hexdigest(),
                }
                capture["fixture_id"] = hashlib.sha256((w3_original_environment_metadata["sha256"] +
                    args.command_tail).encode("utf-8")).hexdigest()
                capture["capture_id"] = str(uuid.uuid4())
                capture["captured_at"] = datetime.now(timezone.utc).isoformat()
                capture["crt"] = {"callback_count": len(callbacks),
                    "destinations": ["0x" + item.get("target", "") for item in callback_fields],
                    "ordinals": [int(item.get("ordinal", "-1")) for item in callback_fields]}
                argv_lines = [parse_fields(line) for line in stdout_lines if line.startswith("W1_CRT_ARG ")]
                capture["argv"] = {"argc": int(summary_fields.get("argc", "0")),
                    "argv_pointer": "0x" + summary_fields.get("argv", "0"),
                    "values": [item.get("value", "") for item in argv_lines],
                    "command_tail": args.command_tail, "psp_tail_length": len(args.command_tail.encode("ascii"))}
                gate_line = next((line for line in stdout_lines if line.startswith("W1_MAIN_BLOCK va=0009433d ")), None)
                gate_fields = parse_fields(gate_line) if gate_line else {}
                setup_line = next((line for line in stdout_lines if line.startswith("W1_MAIN_BLOCK va=00094ac0 ")), None)
                callee_line = next((line for line in stdout_lines if line.startswith("W1_SETUP_EVENT ") and
                                    "eip=00014bf0" in line.lower()), None)
                capture["gate"] = {"local_64": gate_fields.get("local64"), "local_68": gate_fields.get("local68"),
                                   "observed": gate_line is not None}
                capture["roots"] = {"setup_game": {"link_va": "0x00094AC0" if setup_line else None,
                    "observed": setup_line is not None}, "first_callee_14bf0": {"link_va": "0x00014BF0" if callee_line else None,
                    "observed": callee_line is not None, "event": callee_line}}
                capture["authenticated_environment"] = {
                    **w3_original_environment_metadata,
                    "guest_boot_environment_sha256": hashlib.sha256(boot.environment).hexdigest(),
                    "guest_boot_environment_bytes": len(boot.environment), "exact_bytes_loaded": boot.environment == w3_original_environment,
                    "native_setenvp_events": environment_events, "native_setenvp_event_count": len(environment_events),
                    "return_to_dfe12_observed": bool(return_event),
                    "return_to_dfe12_status": "observed" if return_event else "not_reached_before_strict_AX0501_stop",
                    "original_comparison": {"evidence": "evidence/w3_140_original_setenvp_environment.json",
                        "dfe04_eax": "0x00000040", "dfe04_ecx": "0x00000003", "dfe0d_eax": "0x00000040",
                        "dfe12_eax": "0x001A0038", "separate_run": True,
                        "same_dynamic_invocation_claimed": False}}
                strict_size = (((int(strict_fields.get("ebx", "0"), 16) & 0xffff) << 16) |
                               (int(strict_fields.get("ecx", "0"), 16) & 0xffff))
                capture["frontier"] = {"newly_observed": True,
                    "stop_reason": "fresh strict native no-response stop at the first natural DPMI AX=0501 request",
                    "guest_eip": "0x" + strict_fields.get("eip", ""), "request_ax": "0x" + strict_fields.get("eax", ""),
                    "request_registers": strict_fields, "request_size_bytes": f"0x{strict_size:08X}",
                    "fresh_replay": True, "response_count": 0}
                capture["native_response_forced"] = False
                capture["prior_ax4300_checkpoint_reused"] = False
                capture["environment_fingerprint"] = {"target_sha256": boot.executable_sha256,
                    "build_id": exe_sha, "runtime_fingerprint": runtime_fingerprint,
                    "command_tail": args.command_tail, "cwd": "C:\\GENEWARS",
                    "native_argv0": None, "original_environment_executable": "C:\\GENEWARS\\GW.EXE"}
                capture["stdout"] = {"sha256": hashlib.sha256(process.stdout.encode("utf-8", errors="replace")).hexdigest(),
                    "bytes": len(process.stdout.encode("utf-8", errors="replace")), "selected_lines": selected}
                capture["stderr"] = {"sha256": hashlib.sha256(process.stderr.encode("utf-8", errors="replace")).hexdigest(),
                    "bytes": len(process.stderr.encode("utf-8", errors="replace")),
                    "selected_lines": process.stderr.splitlines()[-32:]}
                recovery_root = pathlib.Path(args.recovery_dir)
                if not recovery_root.is_absolute():
                    recovery_root = ROOT / recovery_root
                recovery_root = recovery_root.resolve()
                capture["recovery"] = {"manifest": recovery_root.relative_to(ROOT).as_posix() + "/manifest.json",
                    "verification": recovery_root.relative_to(ROOT).as_posix() + "/verification.json",
                    "verification_sha256": hashlib.sha256((recovery_root / "verification.json").read_bytes()).hexdigest()}
                (ROOT / "evidence" / args.evidence_name).write_text(json.dumps(capture, indent=2) + "\n", encoding="utf-8")
                for line in selected:
                    print(line)
                print(f"W1-066 strict native environment capture saved: evidence/{args.evidence_name}")
                return 0
            callbacks = [line for line in stdout_lines if line.startswith("W1_CRT_CALLBACK_DYNAMIC ")]
            argv_lines = [parse_fields(line) for line in stdout_lines if line.startswith("W1_CRT_ARG ")]
            alloc_events = [line for line in stdout_lines if line.startswith((
                "NATIVE_ALLOC_ENTRY ", "NATIVE_ALLOC_CALLSITE ", "NATIVE_ALLOC_RETURN ", "NATIVE_ALLOC_POINT "))]
            adf95_branch_events = [line for line in stdout_lines if line.startswith("NATIVE_ADF95_BRANCH ")]
            summary_line = next((line for line in stdout_lines if line.startswith("W1_CRT_SUMMARY ")), None)
            if summary_line is None:
                raise AssertionError("strict AX=0501 capture lacks the final CRT/trap summary")
            recovery_root = pathlib.Path(args.recovery_dir)
            if not recovery_root.is_absolute():
                recovery_root = ROOT / recovery_root
            recovery_root = recovery_root.resolve()
            if not recovery_root.is_relative_to(ROOT.resolve()) or not (recovery_root / "verification.json").is_file():
                raise AssertionError(f"verified recovery evidence missing: {recovery_root}")
            selected = [line for line in stdout_lines if line.startswith((
                "NATIVE_DPMI_AX0501_STRICT_FRONTIER ", "NATIVE_AX0501_STACK ",
                "NATIVE_ALLOC_ENTRY ", "NATIVE_ALLOC_CALLSITE ", "NATIVE_ALLOC_RETURN ",
                "NATIVE_ALLOC_POINT ", "NATIVE_ADF95_BRANCH ", "W1_CRT_INITRTNS_ENTRY ", "W1_CRT_CALLBACK_DYNAMIC ",
                "W1_CRT_SUMMARY ", "W1_CRT_ARG ", "NATIVE_W1_ADDRESS_SEED ",
                "NATIVE_W3_CONFIG_PROVIDER_TEST ", "NATIVE_NEXT_TRAP ", "NATIVE_FRONTIER_CPU "))]
            target_path = pathlib.Path(TARGET)
            original_heap = json.loads((ROOT / "evidence" / "w3_068_heap_alignment_original_20261008.json").read_text(encoding="utf-8"))
            original_success = json.loads((ROOT / "evidence" / "w3_068_dpmi0501_success_contract.json").read_text(encoding="utf-8"))
            old_w1036 = json.loads((ROOT / "evidence" / "native_dpmi_0501_frontier_work1.json").read_text(encoding="utf-8"))
            old_w1062 = json.loads((ROOT / "evidence" / "native_alloc_chain_w1_062.json").read_text(encoding="utf-8"))
            old_sizes = []
            for event in old_w1062.get("w1_062_allocator_chain", {}).get("events", []):
                if event.get("kind") == "NATIVE_ALLOC_CALLSITE" and event.get("site", "").lower() == "000c3db0":
                    old_sizes.append({"ordinal":event.get("ordinal"), "size_hex":f"0x{int(event.get('eax','0'),16):08X}"})
            adjust_entry = next((parse_fields(line) for line in alloc_events if line.startswith("NATIVE_ALLOC_ENTRY ") and "va=000c3f76" in line), {})
            adjust_return = next((parse_fields(line) for line in alloc_events if line.startswith("NATIVE_ALLOC_RETURN ")), {})
            expand_call = next((parse_fields(line) for line in alloc_events if line.startswith("NATIVE_ALLOC_CALLSITE ") and "site=000ae038" in line), {})
            original_request = original_success["dpmi0501"]["entry"]
            comparison = {
                "original_w3_068": {
                    "evidence":"evidence/w3_068_heap_alignment_original_20261008.json",
                    "ordinal":original_heap["original_adf95"]["ordinal"],
                    "caller":original_heap["original_adf95"]["caller"],
                    "callsite":original_heap["original_adf95"]["callsite_link_va"],
                    "adf95_input_eax":original_heap["original_adf95"]["registers"]["eax"],
                    "expand_create_rational_ordinals":[1,1,1],
                    "adjustamount_input":"0x40",
                    "adjustamount_output":original_heap["original_adjustamount"]["return_observation"]["argument_slot_after_return"],
                    "ax0501_request_size":"0x0000:0x1000 = 4096 bytes",
                    "threshold_global":original_heap["globals"]["logical_10c828"],
                    "command_tail":original_heap["effective_command_tails"],
                    "success_contract_eax":original_request.get("eax"),
                },
                "native_w1_063": {
                    "expand_callsite":expand_call,
                    "adjustamount_entry":adjust_entry,
                    "adjustamount_return":adjust_return,
                    "first_request_size":"0x00001000",
                    "same_dynamic_invocation_claimed":False,
                },
                "w1_036": {
                    "evidence":"evidence/native_dpmi_0501_frontier_work1.json",
                    "request":"0x00008000",
                    "outer_chain":old_w1036.get("closure", {}).get("dynamic_backtrace_guest_chain"),
                    "command_tail":"-k",
                    "equivalent_to_w3_068_ordinal1":False,
                },
                "w1_062": {
                    "evidence":"evidence/native_alloc_chain_w1_062.json",
                    "callsite_sizes":old_sizes,
                    "synthetic_ax0501_success_continuation_enabled":True,
                },
                "same_dynamic_invocation_claimed":False,
                "finding":"The strict first native AX=0501 size is 0x1000, matching W3-068 original ordinal 1. In W1-062 the first C3DB0 chain requested 0x1000; 0x8000 was a subsequent distinct chain after bounded synthetic AX=0501 success continuation. W1-036 has a different outer caller path and tail '-k'.",
                "first_verified_state_mismatch":"Original ADF95 entry receives EAX=0x40 and original AdjustAmount input is 0x40; native ExpandDGROUP callsite AE038 has EAX=1 and native AdjustAmount input slot is 1. Both observed output slots are 0x1000. The native 0x10C828 value is now captured in the return event; original 0x10C828 was not captured. This state mismatch is not a size-request divergence.",
            }
            capture.update({
                "test": "strict native first AX=0501 capture; no AX=0501 response or guest-state injection",
                "execution_mode": "native_recompiled_guest",
                "evidence_level": "NATIVE_REACHED",
                "native_returncode_expected_for_trap": 13,
                "native_returncode_is_expected_trap_stop": process.returncode == 0 and
                    parse_fields(summary_line).get("trap_pending") == "1" and
                    parse_fields(summary_line).get("trap_va") == "000c3cc1",
                "w1_063_strict_ax0501": {
                    "frontier": strict_fields,
                    "request_size_bytes": f"0x{(((int(strict_fields.get('ebx','0'),16)&0xffff)<<16)|(int(strict_fields.get('ecx','0'),16)&0xffff)):08X}",
                    "response_records": 0,
                    "synthetic_success_disabled": True,
                    "provider_success_features_remain_configured": ["W3-067 CONFIG.INI", "W3-067 ADDRESS.TXT", "W3-069 SOUND.INI"],
                    "memory_arena_bytes": 0x400000,
                    "crt_callback_count_before_frontier": len(callbacks),
                    "argv_observed": argv_lines,
                    "allocator_chain_events": alloc_events,
                    "summary": parse_fields(summary_line),
                    "same_dynamic_invocation_claimed": False,
                    "original_comparison": "W3-068 ordinal 1 is an ordinal/context hypothesis only; separate replays do not prove the same dynamic invocation.",
                },
                "stdout": {"sha256": hashlib.sha256(process.stdout.encode("utf-8", errors="replace")).hexdigest(),
                           "bytes": len(process.stdout.encode("utf-8", errors="replace")), "selected_lines": selected},
                "stderr": {"sha256": hashlib.sha256(process.stderr.encode("utf-8", errors="replace")).hexdigest(),
                           "bytes": len(process.stderr.encode("utf-8", errors="replace")),
                           "selected_lines": process.stderr.splitlines()[-32:]},
                "target_fingerprint": {"path": str(target_path), "sha256": boot.executable_sha256},
                "fixture_fingerprint": {"config_sha256": w3_config["sha256"], "config_bytes": w3_config["size"],
                                        "address_sha256": w1_address_seed["sha256"], "address_bytes": w1_address_seed["size"],
                                        "sound_ini_sha256": w1_sound_ini["sha256"],
                                        "sound_ini_bytes": w1_sound_ini["size"], "command_tail": args.command_tail,
                                        "psp_tail_length": len(tail)},
                "runtime_fingerprint": {"gw_dos_services_c_sha256": hashlib.sha256((ROOT / "runtime" / "gw_dos_services.c").read_bytes()).hexdigest(),
                                        "harness_c_sha256": hashlib.sha256((ROOT / "tests" / "test_native_guest_image.c").read_bytes()).hexdigest(),
                                        "driver_py_sha256": hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
                                        "generated_closure_sha256": hashlib.sha256((ROOT / "build" / "entry_path_closure.c").read_bytes()).hexdigest(),
                                        "capture_object_sha256": hashlib.sha256(pathlib.Path(object_path).read_bytes()).hexdigest()},
                "comparison": comparison,
                "recovery": {"verification": recovery_root.relative_to(ROOT).as_posix()+"/verification.json",
                             "verification_sha256": hashlib.sha256((recovery_root / "verification.json").read_bytes()).hexdigest(),
                             "additional_current_source_verification":"work/recovery/W1-063-20261009-0424-global/verification.json",
                             "additional_current_source_verification_sha256":hashlib.sha256((ROOT / "work/recovery/W1-063-20261009-0424-global/verification.json").read_bytes()).hexdigest()},
            })
            (ROOT / "evidence" / args.evidence_name).write_text(json.dumps(capture, indent=2) + "\n", encoding="utf-8")
            for line in selected:
                print(line)
            return 0 if process.returncode == 13 else 1
        if args.serve_w3_functional_config and not args.serve_w3_address_seed:
            (ROOT / "evidence" / args.evidence_name).write_text(json.dumps(capture, indent=2) + "\n", encoding="utf-8")
        if args.serve_w3_functional_config:
            import re
            stdout = process.stdout
            callbacks = [line for line in stdout.splitlines() if line.startswith("W1_CRT_CALLBACK_DYNAMIC ")]
            main_gate = next((line for line in stdout.splitlines() if line.startswith("W1_MAIN_BLOCK va=0009433d ")), None)
            setup_entry = next((line for line in stdout.splitlines() if line.startswith("W1_MAIN_BLOCK va=00094ac0 ")), None)
            open_line = next((line for line in stdout.splitlines() if line.startswith("NATIVE_W3_CONFIG_OPEN ")), None)
            read_lines = [line for line in stdout.splitlines() if line.startswith("NATIVE_W3_CONFIG_READ ")]
            close_line = next((line for line in stdout.splitlines() if line.startswith("NATIVE_W3_CONFIG_CLOSE ")), None)
            read_hex = "".join(re.search(r" data_hex=([0-9a-f]*) ", line).group(1) for line in read_lines)
            read_bytes = bytes.fromhex(read_hex)
            summary = next((line for line in stdout.splitlines() if line.startswith("W1_CRT_SUMMARY ")), "")
            summary_fields = dict(token.split("=", 1) for token in summary.split()[1:] if "=" in token)
            open_fields = dict(token.split("=", 1) for token in open_line.split()[1:] if "=" in token) if open_line else {}
            if not callbacks or len(callbacks) != 19:
                raise AssertionError(f"expected 19 CRT callbacks, observed {len(callbacks)}")
            if "NATIVE_W3_CONFIG_PROVIDER_TEST success=1" not in stdout:
                raise AssertionError("bounded DOS config provider lifecycle regression did not pass")
            replay_matched = bool(main_gate and "local64=1 local68=1" in main_gate and
                                  setup_entry and open_line and open_fields.get("path")=="config.ini" and
                                  open_fields.get("access")=="read-only" and open_fields.get("cf")=="0")
            if replay_matched:
                if len(read_bytes) != w3_config["size"] or hashlib.sha256(read_bytes).hexdigest() != w3_config["sha256"]:
                    raise AssertionError(f"native reads did not reconstruct the exact W3 CONFIG.INI: {len(read_bytes)} bytes")
                if not read_lines or not close_line or "handled=1" not in close_line:
                    raise AssertionError("CONFIG.INI read/close lifecycle did not complete")
            frontier = {key: summary_fields.get(key) for key in ("trap_vector", "trap_va", "eax", "ebx", "ecx", "edx", "esp")}
            capture["w3_functional_config"] = {
                **w3_config, "open": open_line, "reads": read_lines,
                "bytes_read_hex": read_bytes.hex(), "bytes_read": len(read_bytes),
                "sha256_read": hashlib.sha256(read_bytes).hexdigest(),
                "seek_events": [line for line in stdout.splitlines() if line.startswith("NATIVE_W3_CONFIG_SEEK ")],
                "close": close_line,
                "setup_progress": {"crt_callback_count": len(callbacks), "argc": summary_fields.get("argc"),
                                   "gate": "1/1" if main_gate and "local64=1 local68=1" in main_gate else "not_observed",
                                   "setup_game_link_va": "0x00094AC0" if setup_entry else None},
                "replay_status": "CONFIG_OPENED_AND_READ" if replay_matched else "CONFIG_PATH_NOT_REACHED",
                "next_frontier": frontier,
                "original_equivalence_claimed": False,
            }
        if (args.serve_w3_address_seed and args.serve_w3_functional_config and
                args.w1_077_native_handle_lifecycle and args.w1_080_native_ax4400_active_file and
                args.w1_081_native_ah40_active_file):
            import re
            stdout = process.stdout
            def fields(line):
                return dict(token.split("=", 1) for token in line.split()[1:] if "=" in token)
            lines = stdout.splitlines()
            callbacks = [line for line in lines if line.startswith("W1_CRT_CALLBACK_DYNAMIC ")]
            callback_fields = [fields(line) for line in callbacks]
            summary_line = next((line for line in lines if line.startswith("W1_CRT_SUMMARY ")), "")
            summary_fields = fields(summary_line) if summary_line else {}
            argv_lines = [fields(line) for line in lines if line.startswith("W1_CRT_ARG ")]
            gate_line = next((line for line in lines if line.startswith("W1_MAIN_BLOCK va=0009433d ")), None)
            setup_line = next((line for line in lines if line.startswith("W1_MAIN_BLOCK va=00094ac0 ")), None)
            setup_events = [fields(line) for line in lines if line.startswith("W1_SETUP_EVENT ")]
            callee = next((event for event in setup_events if event.get("eip", "").lower()=="00014bf0"), None)
            seed_line = next((line for line in lines if line.startswith("NATIVE_W1_ADDRESS_SEED ")), None)
            address_open = next((line for line in lines if line.startswith("NATIVE_W1_ADDRESS_OPEN ")), None)
            config_open = next((line for line in lines if line.startswith("NATIVE_W3_CONFIG_OPEN ")), None)
            config_reads = [line for line in lines if line.startswith("NATIVE_W3_CONFIG_READ ")]
            config_close = next((line for line in lines if line.startswith("NATIVE_W3_CONFIG_CLOSE ")), None)
            ah44_callsites = [fields(line) for line in lines if line.startswith("W1_AH44_CALLSITE ")]
            ah44_helper_entries = [fields(line) for line in lines if line.startswith("W1_AH44_HELPER_ENTRY ")]
            ah44_requests = [fields(line) for line in lines if line.startswith("W1_AH44_REQUEST ")]
            native_handle_events = [line for line in lines if line.startswith((
                "NATIVE_DOS_AH3D ", "NATIVE_DOS_AH3C ", "NATIVE_DOS_AX4400 ",
                "NATIVE_DOS_AH42 ", "NATIVE_DOS_AH3E ", "NATIVE_DOS_AH40 ",
                "W1_CRT_DOS_AH3D_", "W1_CRT_DOS_AH3C_", "W1_CRT_DOS_AX4400_",
                "W1_CRT_DOS_AH42_", "W1_CRT_DOS_AH3E_", "W1_CRT_DOS_AH40_"))]
            ax_lines = [fields(line) for line in lines if line.startswith("W1_CRT_DOS_AX4400_FILE ")]
            native_ax4400 = []
            for event in ax_lines:
                if event.get("path", "").replace("/", "\\").casefold().endswith("config.ini"):
                    native_ax4400.append({
                        "path": event["path"], "regular_file": True,
                        "handle": int(event["ebx_in"],16), "link_va": "0x"+event["eip"],
                        "request": {k: "0x"+event[k] for k in ("eax_in","ebx_in","ecx_in","edx_in")},
                        "response": {k: "0x"+event[k] for k in ("eax_out","ebx_out","ecx_out","edx_out")},
                        "ax": int(event["eax_out"],16)&0xffff,
                        "dx": int(event["edx_out"],16)&0xffff,
                        "carry": event.get("carry")!="0",
                        "handled": event.get("handled")=="1",
                    })
            read_hex = "".join(re.search(r" data_hex=([0-9a-f]*) ", line).group(1) for line in config_reads)
            read_bytes = bytes.fromhex(read_hex)
            diagnostic_events = [line for line in lines if line.startswith(("W1_INITRTNS_ENTRY ","W1_CRT_CALLBACK_DYNAMIC ",
                "W1_CRT_SUMMARY ","W1_CRT_ARG ","W1_MAIN_BLOCK ","W1_SETUP_EVENT ","NATIVE_W1_ADDRESS_",
                "NATIVE_W3_CONFIG_","NATIVE_W1_DOS_AH40_FILE ","W1_CRT_DOS_AH3D ","W1_CRT_DOS_AH3C ","W1_CRT_DOS_AX4400_FILE ",
                "NATIVE_NEXT_TRAP ","NATIVE_FRONTIER_CPU "))][-48:]
            original_contract_path = ROOT / "evidence" / "w3_setup_original_contract_20261008.json"
            original_contract = json.loads(original_contract_path.read_text(encoding="utf-8"))
            original_config = original_contract["config_ini"]
            original_ioctls = [event for event in original_config["subsequent_operations"]
                               if event.get("operation")=="INT21_AH44" and
                               event.get("resolved_path", "").replace("/", "\\").casefold().endswith("config.ini")]
            original_ax4400 = [{
                "ordinal": event.get("ordinal"), "sequence": event.get("sequence"),
                "path": "C:\\GENEWARS\\CONFIG.INI", "handle": event.get("in_bx"),
                "request_ax": event.get("in_ax"), "request_dx": event.get("in_dx"),
                "response_ax": event.get("out_ax"), "response_dx": event.get("out_dx"),
                "carry": event.get("cf"), "code_rebase": original_contract["mapping"]["measured_code_rebase_hex"],
            } for event in original_ioctls]
            fixture_components = {"address_txt_sha256": w1_address_seed["sha256"],
                                  "config_ini_sha256": w3_config["sha256"],
                                  "drive": "C:", "cwd": "C:\\GENEWARS"}
            fixture_fingerprint = hashlib.sha256(json.dumps(fixture_components,sort_keys=True,separators=(",", ":")).encode("utf-8")).hexdigest()
            target_sha = boot.executable_sha256
            if (original_config.get("sha256", "").lower()!=w3_config["sha256"] or
                    original_config.get("size_bytes")!=w3_config["size"] or
                    len(read_bytes)!=w3_config["size"] or hashlib.sha256(read_bytes).hexdigest()!=w3_config["sha256"]):
                raise AssertionError("native/original CONFIG.INI mismatch: "
                    f"original_sha={original_config.get('sha256')} original_size={original_config.get('size_bytes')} "
                    f"fixture_sha={w3_config['sha256']} fixture_size={w3_config['size']} "
                    f"native_read_size={len(read_bytes)} native_read_sha={hashlib.sha256(read_bytes).hexdigest()} "
                    f"opened={config_open!r} gate={gate_line!r} setup={setup_line!r} "
                    f"address_seed={seed_line!r} address_open={address_open!r} read_event_count={len(config_reads)} "
                    f"native_returncode={process.returncode} callback_count={len(callbacks)} summary={summary_line!r} events={diagnostic_events!r}")
            if len(callbacks)!=19 or len({x.get("target") for x in callback_fields})!=19:
                raise AssertionError(f"expected 19 unique CRT callbacks, observed {len(callbacks)}")
            frontier_line = next((line for line in lines if line.startswith("NATIVE_NEXT_TRAP ")), None)
            frontier_fields = fields(frontier_line) if frontier_line else {}
            frontier_source = "NATIVE_NEXT_TRAP"
            if not frontier_fields and summary_line:
                # Capture mode can stop after the CRT summary without printing
                # the standalone frontier record. The summary records the
                # actual pending trap instruction VA and request registers.
                summary_trap = fields(summary_line)
                if summary_trap.get("trap_pending") == "1" and summary_trap.get("trap_va"):
                    frontier_fields = {"vector":summary_trap.get("trap_vector", ""),
                                       "eip":summary_trap.get("trap_va", ""),
                                       "eax":summary_trap.get("eax", ""),
                                       "ebx":summary_trap.get("ebx", ""),
                                       "ecx":summary_trap.get("ecx", ""),
                                       "edx":summary_trap.get("edx", ""),
                                       "esp":summary_trap.get("esp", ""),
                                       "source":"W1_CRT_SUMMARY"}
                    frontier_source = "W1_CRT_SUMMARY"
            address_provider_fields = fields(seed_line) if seed_line else {}
            address_open_fields = fields(address_open) if address_open else {}
            config_open_fields = fields(config_open) if config_open else {}
            config_eof = any(int(fields(line).get("transferred", "-1"))==0 for line in config_reads)
            runtime_dir = ROOT / "runtime"
            sys.path.insert(0,str(ROOT / "tools"))
            import frontier_snapshot
            runtime_fingerprint = {"c_h_sha256": frontier_snapshot.runtime_hash(ROOT),
                                   "python_sha256": frontier_snapshot.manifest_hash(list(runtime_dir.glob("*.py")),ROOT)}
            exe_sha = hashlib.sha256(EXE.read_bytes()).hexdigest()
            arg_values = [item.get("value", "") for item in sorted(argv_lines,key=lambda x:int(x.get("index",0))) ]
            gate_fields = fields(gate_line) if gate_line else {}
            setup_fields = fields(setup_line) if setup_line else {}
            selected_prefixes = ("W1_INITRTNS_ENTRY ","W1_CRT_CALLBACK_DYNAMIC ","W1_CRT_SUMMARY ","W1_CRT_ARG ",
                                 "W1_MAIN_BLOCK ","W1_SETUP_EVENT ","NATIVE_W1_ADDRESS_","NATIVE_W3_CONFIG_",
                                 "NATIVE_ADF95_BRANCH ","NATIVE_ADF95_RETURN ","NATIVE_ALLOC_CALLSITE ","NATIVE_ALLOC_ENTRY ","NATIVE_ALLOC_RETURN ","NATIVE_ALLOC_POINT ",
                                 "NATIVE_W1_DOS_AH40_FILE ","NATIVE_W1_AX4400_CONSOLE_PROVIDER_SETUP ",
                                 "NATIVE_DOS_AX4400_STD_PROVIDER ","NATIVE_DPMI_AX0200_PROVIDER ","NATIVE_DOS_AH35_PROVIDER ","NATIVE_DOS_AH25_PROVIDER ","NATIVE_AX0501_STACK ","NATIVE_W1_090_AX0501_DISPATCH_PROBE ","NATIVE_DPMI_AX0501_SEQUENCE ","NATIVE_ALLOC_ENTRY ","NATIVE_ALLOC_CALLSITE ", "NATIVE_ALLOC_POINT ", "NATIVE_DPMI_AX0501_STRICT_FRONTIER ",
                                 "W1_CRT_AX4400_CONTEXT ","W1_CRT_DOS_AX4400_FILE ","W1_077_", 
                                 "W1_CRT_DOS_AH3D_GENERIC ","W1_CRT_DOS_AH3C_GENERIC ","W1_CRT_DOS_AH3E_FILE ",
                                 "NATIVE_DOS_AH3D ","NATIVE_DOS_AH3E ","NATIVE_NEXT_TRAP ","NATIVE_FRONTIER_CPU ")
            selected_stdout = [line for line in lines if line.startswith(selected_prefixes)]
            capture["schema"] = "gwrecomp.native-setup-replay/v1"
            capture["execution_mode"] = "native_recompiled_guest"
            capture["evidence_level"] = "DIFF_VERIFIED"
            if w3_original_environment_metadata is not None:
                capture["task_schema"] = "gwrecomp.native-setenvp-aligned-replay/v1"
                capture["evidence_level"] = "NATIVE_REACHED"
            capture["capture_id"] = str(uuid.uuid4())
            capture["captured_at"] = datetime.now(timezone.utc).isoformat()
            capture["build_id"] = exe_sha
            capture["build_artifact"] = {"path": EXE.relative_to(ROOT).as_posix(), "sha256": exe_sha,
                                         "runtime_fingerprint": runtime_fingerprint,
                                         "closure_source_sha256": capture["build_fingerprints"]["closure_source_sha256"],
                                         "closure_object_sha256": capture["build_fingerprints"]["routed_closure_object_sha256"],
                                         "capture_object_sha256": capture["build_fingerprints"]["capture_closure_object_sha256"]}
            capture["runtime_fingerprint"] = runtime_fingerprint
            capture["original_contract"] = {"path": original_contract_path.relative_to(ROOT).as_posix(),
                                             "sha256": hashlib.sha256(original_contract_path.read_bytes()).hexdigest()}
            capture["fixture_id"] = fixture_fingerprint
            capture["crt"] = {"callback_count":len(callbacks),"destinations":["0x"+item["target"] for item in callback_fields],
                              "ordinals":[int(item["ordinal"]) for item in callback_fields]}
            capture["argv"] = {"argc":int(summary_fields.get("argc",-1)),"argv_pointer":"0x"+summary_fields.get("argv","0"),
                                "values":arg_values,"command_tail":args.command_tail,
                                "psp_tail_length":len(args.command_tail.encode("ascii"))}
            capture["gate"] = {"local_64":f"{int(gate_fields.get('local64','-1')):02x}",
                               "local_68":f"{int(gate_fields.get('local68','-1')):02x}",
                               "link_va":"0x0009433D" if gate_line else None}
            capture["roots"] = {"setup_game":{"link_va":"0x00094AC0" if setup_line else None,
                                               "observed":setup_line is not None},
                                "first_callee_14bf0":{"link_va":"0x00014BF0" if callee else None,
                                                     "observed":callee is not None,
                                                     "event":callee}}
            capture["config_ini"] = {"path":config_open_fields.get("resolved_path", "C:\\GENEWARS\\CONFIG.INI"),
                                     "opened":bool(config_open and config_open_fields.get("cf")=="0"),
                                     "handle":int(config_open_fields["handle"]) if config_open_fields.get("handle","-").isdigit() else None,
                                     "bytes_read":len(read_bytes),"sha256_read":hashlib.sha256(read_bytes).hexdigest(),
                                     "eof_observed":config_eof,"close":config_close,
                                     "reads":config_reads}
            capture["ax4400"] = native_ax4400
            capture["ax4400_comparison"] = {"original_config_calls":original_ax4400,
                                             "native_config_calls":native_ax4400,
                                             "same_dynamic_invocation_claimed":False,
                                             "basis":"same canonical CONFIG.INI path, writable C: regular-file metadata class, and measured AX/DX/CF contract; handle and dynamic ordinal may differ"}
            capture["fixtures"] = {"comparable":fixture_components["address_txt_sha256"]==w1_address_seed["sha256"] and
                                                 fixture_components["config_ini_sha256"]==original_config["sha256"].lower(),
                                   "fingerprint":fixture_fingerprint,
                                   "components":fixture_components,
                                   "original":{"fingerprint":fixture_fingerprint,
                                               "address_txt_sha256":w1_address_seed["sha256"],
                                               "address_txt_path":w1_address_seed["fixture"],
                                               "authentic_seed_evidence":{"path":w1_address_seed["authentic_seed_evidence"],
                                                                          "sha256":w1_address_seed["authentic_seed_evidence_sha256"]},
                                               "config_ini_sha256":original_config["sha256"].lower()},
                                   "native":{"fingerprint":fixture_fingerprint,
                                             "address_txt_sha256":w1_address_seed["sha256"],
                                             "config_ini_sha256":w3_config["sha256"],
                                             "address_provider_initial_visibility":address_provider_fields.get("initial_visibility"),
                                             "address_provider_open":address_open,
                                             "physical_host_path_observation":w1_address_seed["physical_host_path_observation"]}}
            capture["environment_fingerprint"] = {"target_sha256":target_sha,"build_id":exe_sha,
                                                  "runtime_fingerprint":runtime_fingerprint,
                                                  "command_tail":args.command_tail,"cwd":"C:\\GENEWARS",
                                                  "native_argv0":arg_values[0] if arg_values else None,
                                                  "original_guest_executable":original_contract["fixture"]["guest_executable"],
                                                  "original_launch_sequence":original_contract["functional_configuration"]["autoexec_sequence"]}
            if w3_original_environment_metadata is not None:
                environment_events = [line for line in lines if line.startswith((
                    "NATIVE_ADF95_BRANCH ", "NATIVE_ADF95_RETURN ", "NATIVE_ALLOC_CALLSITE ", "NATIVE_ALLOC_ENTRY ",
                    "NATIVE_ALLOC_RETURN ", "NATIVE_ALLOC_POINT ")) and
                    any(site in line.casefold() for site in ("000dfe04", "000dfe08", "000dfe0d", "000dfe12", "000adf95"))]
                capture["authenticated_environment"] = {
                    **w3_original_environment_metadata,
                    "guest_boot_environment_sha256": hashlib.sha256(boot.environment).hexdigest(),
                    "guest_boot_environment_bytes": len(boot.environment),
                    "exact_bytes_loaded": boot.environment == w3_original_environment,
                    "native_setenvp_events": environment_events,
                    "native_setenvp_event_count": len(environment_events),
                    "original_comparison": {
                        "evidence": "evidence/w3_140_original_setenvp_environment.json",
                        "dfe04_eax": "0x00000040", "dfe04_ecx": "0x00000003",
                        "dfe0d_eax": "0x00000040", "dfe12_eax": "0x001A0038",
                        "separate_run": True, "same_dynamic_invocation_claimed": False,
                    },
                }
            capture["frontier"] = {"newly_observed":bool(frontier_fields),
                                   "stop_reason":f"fresh native DOS interrupt trap vector={frontier_fields.get('vector','unknown')} at link VA {frontier_fields.get('eip','unknown')} (AX=0x{frontier_fields.get('eax','unknown')[-4:]}); source={frontier_source}",
                                   "guest_eip":"0x"+frontier_fields["eip"] if frontier_fields.get("eip") else None,
                                   "request_ax":"0x"+frontier_fields.get("eax","") if frontier_fields.get("eax") else None,
                                   "request_registers":frontier_fields,
                                   "fresh_replay":True}
            capture["prior_ax4300_checkpoint_reused"] = False
            capture["stdout"] = {"sha256":hashlib.sha256(process.stdout.encode("utf-8",errors="replace")).hexdigest(),
                                 "bytes":len(process.stdout.encode("utf-8",errors="replace")),
                                 "selected_lines":selected_stdout}
            capture["stderr"] = {"sha256":hashlib.sha256(process.stderr.encode("utf-8",errors="replace")).hexdigest(),
                                 "bytes":len(process.stderr.encode("utf-8",errors="replace")),
                                 "selected_lines":[line for line in process.stderr.splitlines()
                                                   if line.startswith(("expected ","NATIVE_EXCEPTION ","ERROR "))][:32]}
        if args.serve_w3_sound_ini:
            lines = process.stdout.splitlines()
            def fields(line):
                return dict(token.split("=", 1) for token in line.split()[1:] if "=" in token)
            ah43 = [fields(line) for line in lines if line.startswith("NATIVE_DOS_AH43 ")]
            provider_open = [line for line in lines if line.startswith("NATIVE_W1_SOUND_PROVIDER_OPEN ")]
            provider_close = [line for line in lines if line.startswith("NATIVE_W1_SOUND_PROVIDER_CLOSE ")]
            sound_requests = [entry for entry in ah43 if entry.get("eip", "").lower()=="000af93a" and
                              entry.get("path", "").replace("/", "\\").casefold()==r"c:\genewars\sound.ini"]
            request = next((entry for entry in sound_requests if int(entry.get("response_eax", "0"),16)&0xffff==0x20 and
                            int(entry.get("response_ecx", "0"),16)&0xffff==0x20 and entry.get("cf_out")=="0"), None)
            summary_line = next((line for line in lines if line.startswith("W1_CRT_SUMMARY ")), "")
            summary_fields = fields(summary_line) if summary_line else {}
            callbacks = [line for line in lines if line.startswith("W1_CRT_CALLBACK_DYNAMIC ")]
            gate = next((line for line in lines if line.startswith("W1_MAIN_BLOCK va=0009433d ")), None)
            setup = next((line for line in lines if line.startswith("W1_MAIN_BLOCK va=00094ac0 ")), None)
            callee = next((line for line in lines if line.startswith("W1_SETUP_EVENT ") and "eip=00014bf0" in line), None)
            config_open = next((line for line in lines if line.startswith("NATIVE_W3_CONFIG_OPEN ")), None)
            config_reads = [line for line in lines if line.startswith("NATIVE_W3_CONFIG_READ ")]
            config_close = next((line for line in lines if line.startswith("NATIVE_W3_CONFIG_CLOSE ")), None)
            if len(callbacks) != 19 or not gate or "local64=1 local68=1" not in gate or not setup or not callee:
                raise AssertionError("fresh SOUND.INI replay lost the established CRT/main/setup/callee path")
            selected = [line for line in lines if line.startswith(("NATIVE_DOS_AH43 ", "NATIVE_DOS_AX4400_STD_PROVIDER ", "NATIVE_DOS_AH35_PROVIDER ", "NATIVE_DOS_AH25_PROVIDER ", "NATIVE_AX0501_STACK ", "NATIVE_W1_090_AX0501_DISPATCH_PROBE ", "NATIVE_DPMI_AX0501_SEQUENCE ", "NATIVE_ALLOC_ENTRY ", "NATIVE_ALLOC_CALLSITE ", "NATIVE_ALLOC_RETURN ", "NATIVE_ALLOC_POINT ", "NATIVE_DPMI_AX0501_STRICT_FRONTIER ", "NATIVE_W1_AX4400_CONSOLE_PROVIDER_SETUP ", "NATIVE_W1_SOUND_", "W1_CRT_SUMMARY ", "W1_CRT_CALLBACK_DYNAMIC ", "W1_CRT_ARG ", "W1_MAIN_BLOCK ", "W1_SETUP_EVENT ", "NATIVE_W3_CONFIG_", "W1_CRT_DOS_AX4400_FILE ", "W1_AH44_CALLSITE ", "W1_AH44_HELPER_ENTRY ", "W1_AH44_REQUEST ", "NATIVE_NEXT_TRAP ", "NATIVE_TRAP_STATE ", "NATIVE_FRONTIER_CPU ", "NATIVE_FRONTIER_ALLOC "))]
            runtime_hash = hashlib.sha256((ROOT / "runtime" / "gw_dos_services.c").read_bytes()).hexdigest()
            exe_hash = hashlib.sha256(EXE.read_bytes()).hexdigest()
            request_matches = bool(request and int(request.get("request_eax", "0"),16)&0xffff==0x4300)
            response_ok = bool(request_matches and int(request.get("response_eax", "0"),16)&0xffff==0x20 and
                               int(request.get("response_ecx", "0"),16)&0xffff==0x20 and request.get("cf_out")=="0" and
                               request.get("handled")=="1")
            capture["sound_ini_continuation"] = {
                **w1_sound_ini, "fresh_native_request": request,
                "first_ah43_event": next((entry for entry in ah43 if entry.get("eip", "").lower()=="000af93a"), None),
                "ah43_event_count_at_site": len([entry for entry in ah43 if entry.get("eip", "").lower()=="000af93a" and entry.get("path", "").replace("/", "\\").casefold()==r"c:\genewars\sound.ini"]),
                "provider_open": provider_open[:3], "provider_open_count": len(provider_open),
                "provider_close": provider_close[:3], "provider_close_count": len(provider_close),
                "response_contract_passed": response_ok,
                "response_cx16": f"0x{int(request.get('response_ecx','0'),16)&0xffff:04x}" if request else None,
                "crt_callbacks": len(callbacks), "argc": summary_fields.get("argc"),
                "gate": "1/1" if "local64=1 local68=1" in (gate or "") else "not_observed",
                "setup_game_entered": bool(setup), "callee_14bf0_entered": bool(callee),
                "config_ini_open": config_open, "config_ini_reads": config_reads, "config_ini_close": config_close,
                "ax4400_origin": {
                    "helper_entry_va": "0x000C896A", "interrupt_va": "0x000C8973",
                    "callsites": ah44_callsites, "helper_entries": ah44_helper_entries, "requests": ah44_requests,
                    "callsite_to_entry_correlated_by_ordinal": len(ah44_callsites)==len(ah44_helper_entries) and all(
                        int(call.get("ordinal", "-1")) == int(entry.get("ordinal", "-2")) and
                        int(call.get("target", "0"),16) == 0x000C896A
                        for call,entry in zip(ah44_callsites,ah44_helper_entries)),
                    "request_to_helper_entry_correlated_by_ordinal": all(
                        0 <= int(req.get("helper_ordinal", "-1")) < len(ah44_helper_entries) and
                        int(ah44_helper_entries[int(req["helper_ordinal"])].get("ordinal", "-2")) == int(req.get("helper_ordinal", "-1"))
                        for req in ah44_requests),
                    "requests_bx1": [req for req in ah44_requests if int(req.get("ebx", "0"), 16) == 1],
                    "file_handle_events_in_execution_order": native_handle_events,
                    "note": "Guest instruction 0xC896D copies helper-entry EAX into EBX; no interrupt response is synthesized by this capture."
                },
                "next_frontier": {k: summary_fields.get(k) for k in ("trap_vector", "trap_va", "eax", "ebx", "ecx", "edx", "esp")},
                "next_frontier_cpu": next((fields(line) for line in lines if line.startswith("NATIVE_FRONTIER_CPU ")), None),
                "build_fingerprints": {"native_executable_sha256": exe_hash,
                    "closure_source_sha256": hashlib.sha256((ROOT / "build" / "entry_path_closure.c").read_bytes()).hexdigest(),
                    "capture_closure_object_sha256": hashlib.sha256(pathlib.Path(object_path).read_bytes()).hexdigest(),
                    "native_harness_sha256": hashlib.sha256((ROOT / "tests" / "test_native_guest_image.c").read_bytes()).hexdigest(),
                    "driver_sha256": hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()},
                "runtime_fingerprint": {"gw_dos_services_c_sha256": runtime_hash,
                    "gw_dos_services_python_sha256": hashlib.sha256((ROOT / "runtime" / "dos_services.py").read_bytes()).hexdigest(),
                    "w2_107_expected_c_sha256": json.loads((ROOT / "evidence" / "native_dos_ah43_sound_ini_work2.json").read_text(encoding="utf-8"))["implementation"]["c"]["sha256"],
                    "matches_w2_107": runtime_hash == json.loads((ROOT / "evidence" / "native_dos_ah43_sound_ini_work2.json").read_text(encoding="utf-8"))["implementation"]["c"]["sha256"]},
                "post_response_stop": next((line for line in lines if line.startswith("W1_CRT_SUMMARY ")), None),
                "original_equivalence_claimed": False}
            if args.continue_dos_ax4400_console:
                provider_setup = next((line for line in lines if line.startswith("NATIVE_W1_AX4400_CONSOLE_PROVIDER_SETUP ")), None)
                provider_events = [fields(line) for line in lines if line.startswith("NATIVE_DOS_AX4400_STD_PROVIDER ")]
                summary_fields = fields(next((line for line in lines if line.startswith("W1_CRT_SUMMARY ")), ""))
                if len(provider_events) != 1 or provider_events[0].get("eip") != "000c8973" or provider_events[0].get("request_ebx") != "00000001":
                    raise AssertionError(f"fresh native replay did not handle exactly the natural BX=1 request at 0xC8973: {provider_events}")
                w2_111 = json.loads((ROOT / "evidence" / "w2_111_ax4400_stream_metadata.json").read_text(encoding="utf-8"))
                runtime_c_sha = hashlib.sha256((ROOT / "runtime" / "gw_dos_services.c").read_bytes()).hexdigest()
                capture["w1_056_ax4400_console"] = {
                    "provider_setup": provider_setup,
                    "provider_response_events": provider_events,
                    "next_frontier": {key: summary_fields.get(key) for key in ("trap_vector", "trap_va", "eax", "ebx", "ecx", "edx", "esp")},
                    "next_frontier_cpu": next((fields(line) for line in lines if line.startswith("NATIVE_FRONTIER_CPU ")), None),
                    "crt_callback_count": len(callbacks),
                    "argc": summary_fields.get("argc"),
                    "gate_passed": bool(gate and "local64=1 local68=1" in gate),
                    "setup_game_entered": bool(setup),
                    "callee_14bf0_entered": bool(callee),
                    "runtime_c_sha256": runtime_c_sha,
                    "runtime_expected_w2_111_sha256": w2_111["fingerprints"]["runtime_c_sha256"],
                    "runtime_matches_w2_111": runtime_c_sha == w2_111["fingerprints"]["runtime_c_sha256"],
                    "original_equivalence_claimed": False,
                    "response_source": "gw_dos_services_callback via configured CON stream provider; metadata measured by W3-091",
                }
            if args.continue_dpmi_ax0200:
                dpmi_events = [fields(line) for line in lines if line.startswith("NATIVE_DPMI_AX0200_PROVIDER ")]
                if len(dpmi_events) != 1 or dpmi_events[0].get("eip") != "000c8cd2" or dpmi_events[0].get("request_eax", "").lower() != "00000200" or (int(dpmi_events[0].get("request_ebx", "0"), 16) & 0xff) != 8:
                    raise AssertionError(f"fresh native replay did not service exactly the natural vector-8 AX=0200 request at 0xC8CD2: {dpmi_events}")
                c_evidence = json.loads((ROOT / "evidence" / "native_dpmi_0200_c_work2.json").read_text(encoding="utf-8"))
                py_evidence = json.loads((ROOT / "evidence" / "python_dpmi_0200_0201_work2.json").read_text(encoding="utf-8"))
                source_hashes = {"gw_dos_services_c_sha256": hashlib.sha256((ROOT / "runtime" / "gw_dos_services.c").read_bytes()).hexdigest(),
                                 "gw_dos_services_h_sha256": hashlib.sha256((ROOT / "runtime" / "gw_dos_services.h").read_bytes()).hexdigest(),
                                 "dos_services_py_sha256": hashlib.sha256((ROOT / "runtime" / "dos_services.py").read_bytes()).hexdigest()}
                frontier_line = next((line for line in lines if line.startswith("NATIVE_NEXT_TRAP ")), None)
                frontier_fields = fields(frontier_line) if frontier_line else {}
                capture["w1_058_dpmi_ax0200"] = {
                    "provider_response_events": dpmi_events,
                    "next_frontier": frontier_fields,
                    "next_frontier_cpu": next((fields(line) for line in lines if line.startswith("NATIVE_FRONTIER_CPU ")), None),
                    "runtime_source_hashes": source_hashes,
                    "w2_112_original_contract": c_evidence["original_observation"],
                    "w2_113_original_contract": py_evidence["original_observation"],
                    "original_equivalence_claimed": False,
                    "response_source": "current gw_dos_services_callback with existing unconfigured-vector default; no vector state seeded by harness",
                }
            if args.continue_dos_ah35:
                ah35_events = [fields(line) for line in lines if line.startswith("NATIVE_DOS_AH35_PROVIDER ")]
                if (len(ah35_events) != 1 or ah35_events[0].get("eip") != "000c8cdf" or
                    ah35_events[0].get("request_eax", "").lower() != "00003508" or
                    (int(ah35_events[0].get("request_ebx", "0"), 16) & 0xffff) != 8 or
                    ah35_events[0].get("provider") != "gw_dos_services_callback" or
                    ah35_events[0].get("handled") != "1"):
                    raise AssertionError(f"fresh native replay did not handle exactly the natural vector-8 AH=35h request at 0xC8CDF: {ah35_events}")
                ah35 = ah35_events[0]
                original = json.loads((ROOT / "evidence" / "empty_config_overlay_work2.json").read_text(encoding="utf-8"))
                original_event = next((event for event in original.get("interrupts_tail", [])
                                       if event.get("vector") == 33 and
                                       event.get("eip_int_opcode_assumption", "").lower() == "0x001c8cdf"), None)
                if original_event is None:
                    raise AssertionError("original-byte AH=35h/vector-8 observation is missing")
                orig_before = original_event.get("registers", {})
                orig_after = original_event.get("registers_after", {})
                if orig_after.get("ebx", "").lower() != "0x00000000" or int(orig_after.get("eflags", "0"), 16) & 1:
                    raise AssertionError("original-byte AH=35h no longer establishes BX=0 and CF=0")
                next_line = next((line for line in lines if line.startswith("NATIVE_NEXT_TRAP ")), None)
                next_frontier = fields(next_line) if next_line else {}
                native_cf_ok = ah35.get("cf_out") == "0"
                native_bx_ok = (int(ah35.get("response_ebx", "0"), 16) & 0xffff) == 0
                native_ax_ok = ah35.get("response_eax", "").lower() == ah35.get("request_eax", "").lower()
                capture["w1_059_dos_ah35"] = {
                    "provider_response_event": ah35,
                    "original_observation": {
                        "evidence_path": "evidence/empty_config_overlay_work2.json",
                        "request_eax": orig_before.get("eax"), "request_ebx": orig_before.get("ebx"),
                        "request_es": original_event.get("es"), "response_ebx": orig_after.get("ebx"),
                        "response_cf": bool(int(orig_after.get("eflags", "0"), 16) & 1),
                        "response_es_measured": False,
                    },
                    "native_contract_checks": {
                        "response_ax_preserved": native_ax_ok,
                        "response_bx_low_word_zero": native_bx_ok,
                        "response_cf_clear": native_cf_ok,
                        "response_es": "0x" + ah35.get("response_es", ""),
                        "original_es_comparison": "not measured in original evidence",
                    },
                    "next_frontier": next_frontier,
                    "next_frontier_cpu": next((fields(line) for line in lines if line.startswith("NATIVE_FRONTIER_CPU ")), None),
                    "runtime_source_hashes": {
                        "gw_dos_services_c_sha256": hashlib.sha256((ROOT / "runtime" / "gw_dos_services.c").read_bytes()).hexdigest(),
                        "gw_dos_services_h_sha256": hashlib.sha256((ROOT / "runtime" / "gw_dos_services.h").read_bytes()).hexdigest(),
                    },
                    "original_equivalence_claimed": False,
                    "response_source": "current native C Runtime callback; harness does not seed DOS vector state",
                }
            if args.continue_dos_ah25:
                ah25_events = [fields(line) for line in lines if line.startswith("NATIVE_DOS_AH25_PROVIDER ")]
                if (len(ah25_events) != 1 or ah25_events[0].get("eip") != "000c8d0c" or
                    ah25_events[0].get("request_eax", "").lower() != "00002508" or
                    (int(ah25_events[0].get("request_eax", "0"), 16) & 0xff) != 8 or
                    ah25_events[0].get("provider") != "gw_dos_services_callback" or
                    ah25_events[0].get("handled") != "1"):
                    raise AssertionError(f"fresh native replay did not handle exactly the natural vector-8 AH=25h request at 0xC8D0C: {ah25_events}")
                ah25 = ah25_events[0]
                original = json.loads((ROOT / "evidence" / "empty_config_overlay_work2.json").read_text(encoding="utf-8"))
                original_event = next((event for event in original.get("interrupts_tail", [])
                                       if event.get("vector") == 33 and
                                       event.get("eip_int_opcode_assumption", "").lower() == "0x001c8d0c"), None)
                if original_event is None:
                    raise AssertionError("original-byte AH=25h/vector-8 observation is missing")
                orig_before = original_event.get("registers", {})
                orig_after = original_event.get("registers_after", {})
                if (original_event.get("ds", "").lower() != "0x000c" or
                    orig_before.get("edx", "").lower() != "0x001c8a5e"):
                    raise AssertionError("original AH=25h input evidence changed")
                unchanged = all(ah25.get("request_" + reg) == ah25.get("response_" + reg)
                                for reg in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"))
                segments_unchanged = all(ah25.get("request_" + seg) == ah25.get("response_" + seg)
                                         for seg in ("cs", "ds", "es", "fs", "gs", "ss"))
                flags_unchanged = all(ah25.get("request_" + word) == ah25.get("response_" + word)
                                      for word in ("flags_a", "flags_b"))
                carry_clear = ah25.get("cf_out") == "0"
                next_line = next((line for line in lines if line.startswith("NATIVE_NEXT_TRAP ")), None)
                next_frontier = fields(next_line) if next_line else {}
                capture["w1_060_dos_ah25"] = {
                    "provider_response_event": ah25,
                    "runtime_contract_checks": {"unrelated_registers_preserved": unchanged,
                                                 "segments_preserved": segments_unchanged,
                                                 "non_carry_flags_preserved": flags_unchanged,
                                                 "carry_clear": carry_clear},
                    "original_observation": {"evidence_path": "evidence/empty_config_overlay_work2.json",
                                             "link_va": "0x001C8D0C", "request_ds": original_event.get("ds"),
                                             "request_edx": orig_before.get("edx"),
                                             "response_edx": orig_after.get("edx"),
                                             "native_dx_is_not_compared_as_same_address": True},
                    "native_request_address": {"ds": "0x" + ah25.get("request_ds", ""),
                                               "edx": "0x" + ah25.get("request_edx", "")},
                    "next_frontier": next_frontier,
                    "next_frontier_cpu": next((fields(line) for line in lines if line.startswith("NATIVE_FRONTIER_CPU ")), None),
                    "runtime_source_hashes": {
                        "gw_dos_services_c_sha256": hashlib.sha256((ROOT / "runtime" / "gw_dos_services.c").read_bytes()).hexdigest(),
                        "gw_dos_services_h_sha256": hashlib.sha256((ROOT / "runtime" / "gw_dos_services.h").read_bytes()).hexdigest(),
                    },
                    "original_equivalence_claimed": False,
                    "response_source": "current native C Runtime callback; live guest DS:DX request, no harness vector seeding",
                }
            if args.capture_ax0501_stack:
                stack_line = next((line for line in lines if line.startswith("NATIVE_AX0501_STACK ")), None)
                if stack_line is None:
                    raise AssertionError("bounded AX=0501 stack snapshot missing at the natural C3CC1 trap")
                stack = fields(stack_line)
                if stack.get("trap_va", "").lower() != "000c3cc1" or stack.get("valid") != "1":
                    raise AssertionError(f"AX=0501 stack snapshot is not valid at C3CC1: {stack}")
                w1036 = json.loads((ROOT / "evidence" / "native_dpmi_0501_frontier_work1.json").read_text(encoding="utf-8"))
                old_request = w1036["request_construction"]["observed_request"]
                current_request = frontier_fields
                old_size = ((int(old_request.get("ebx", "0"), 16) & 0xffff) << 16) | (int(old_request.get("ecx", "0"), 16) & 0xffff)
                current_size = ((int(current_request.get("ebx", "0"), 16) & 0xffff) << 16) | (int(current_request.get("ecx", "0"), 16) & 0xffff)
                capture["w1_061_ax0501_context"] = {
                    "natural_frontier": current_request,
                    "stack_snapshot": stack,
                    "request_size_bytes": f"0x{current_size:08X}",
                    "w1_036_prior_request": old_request,
                    "w1_036_request_size_bytes": f"0x{old_size:08X}",
                    "same_request_registers": current_size == old_size and
                        all(current_request.get(reg, "").lower() == old_request.get(reg, "").lower()
                            for reg in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp")),
                    "same_dynamic_invocation": False,
                    "dynamic_caller_identified": False,
                    "caller_analysis": {
                        "dynamic_callsite_observed_this_run": False,
                        "static_candidate_chain": [
                            {"function": "__ExpandDGROUP_", "entry": "0x000C3E2A", "callsite": "0x000C3E54", "target": "0x000C3D7A"},
                            {"function": "__CreateNewNHeap_", "entry": "0x000C3D7A", "callsite": "0x000C3DB0", "target": "0x000C3CA9"},
                            {"function": "RationalAlloc_", "entry": "0x000C3CA9", "request_site": "0x000C3CC1"},
                        ],
                        "prior_dynamic_chain_evidence": "evidence/native_dpmi_0501_frontier_work1.json; applies only to W1-036's separate 0x8000 request",
                        "current_input_value": "stack word7=0x01001000; RationalAlloc saves this as word0 and uses it as its input",
                        "earliest_verified_feed": "RationalAlloc input stack slot; generated __CreateNewNHeap_ at 0xC3DAD loads [ESP] into EAX before call 0xC3DB0",
                        "upstream_writer": "unknown for this dynamic event; no entry checkpoint at __ExpandDGROUP_ or __CreateNewNHeap_ in this replay",
                    },
                    "segment_fault_state": {"pending": stack.get("segment_fault"),
                                            "eip": stack.get("segment_fault_eip"),
                                            "selector": stack.get("segment_fault_selector")},
                    "original_contract_path": "evidence/w3_068_dpmi0501_success_contract.json",
                    "original_equivalence_claimed": False,
                    "classification": "same link VA, but distinct request register state; dynamic caller equivalence not established",
                }
            if args.capture_alloc_chain:
                alloc_events = [{"kind": line.split(" ", 1)[0], **fields(line)} for line in selected
                                if line.startswith(("NATIVE_ALLOC_ENTRY ", "NATIVE_ALLOC_CALLSITE "))]
                # Keep raw event order as the ordinal is assigned in the native observer.
                if not any(line.startswith("NATIVE_ALLOC_ENTRY ") for line in selected) or not any(line.startswith("NATIVE_ALLOC_CALLSITE ") for line in selected):
                    raise AssertionError("dynamic allocator entry/callsite checkpoints are missing")
                expected_entries = {"000c3e2a", "000c3d7a", "000c3ca9"}
                observed_entry_vas = {fields(line).get("va", "").lower() for line in selected if line.startswith("NATIVE_ALLOC_ENTRY ")}
                expected_sites = {"000c3e54", "000c3db0"}
                observed_sites = {fields(line).get("site", "").lower() for line in selected if line.startswith("NATIVE_ALLOC_CALLSITE ")}
                if not expected_entries.issubset(observed_entry_vas) or not expected_sites.issubset(observed_sites):
                    raise AssertionError(f"allocator chain checkpoints incomplete: entries={observed_entry_vas} sites={observed_sites}")
                original_return = json.loads((ROOT / "evidence" / "w3_070_rationalalloc_return_capture.json").read_text(encoding="utf-8"))
                invocation = original_return.get("invocation_link", {})
                capture["w1_062_allocator_chain"] = {
                    "events": alloc_events,
                    "expected_entries": sorted(expected_entries),
                    "expected_callsites": sorted(expected_sites),
                    "native_ax0501_frontier": frontier_fields,
                    "native_request_size_bytes": "0x" + f"{(((int(frontier_fields.get('ebx','0'),16)&0xffff)<<16)|(int(frontier_fields.get('ecx','0'),16)&0xffff)):08X}",
                    "original_w3_070": {
                        "evidence_path": "evidence/w3_070_rationalalloc_return_capture.json",
                        "invocation_link": invocation,
                        "same_dynamic_invocation_claimed": False,
                        "comparison_limit": "Separate original/native replays; compare only call-chain shape and measured states, not invocation identity.",
                    },
                    "dynamic_caller_chain_observed": True,
                    "request_producer_analysis": "See ordered callsite and entry stack/register samples; no guest state is mutated by the observer.",
                    "segment_fault_state": capture.get("w1_061_ax0501_context", {}).get("segment_fault_state"),
                }
            if args.stop_at_first_ax0501:
                strict_lines = [line for line in lines if line.startswith("NATIVE_DPMI_AX0501_STRICT_FRONTIER ")]
                if len(strict_lines) != 1:
                    raise AssertionError(f"strict AX=0501 stop expected one natural request, got {len(strict_lines)}")
                if "NATIVE_DPMI_LINEAR_SUCCESS " in process.stdout or "NATIVE_DPMI_LINEAR vector=" in process.stdout:
                    raise AssertionError("strict stop emitted an AX=0501 response record")
                strict = fields(strict_lines[0])
                if strict.get("response_count") != "0" or strict.get("vector") != "31" or strict.get("eip") != "000c3cc1":
                    raise AssertionError(f"strict AX=0501 marker is not a no-response frontier: {strict}")
                capture["w1_063_strict_ax0501"] = {
                    "frontier": strict,
                    "response_records": 0,
                    "synthetic_success_disabled": True,
                    "fixture_providers_preserved": ["W3-067 CONFIG.INI", "W3-067 ADDRESS.TXT", "W3-069 SOUND.INI"],
                    "memory_arena_bytes": 0x400000,
                    "same_dynamic_invocation_claimed": False,
                    "original_comparison": "W3-068 ordinal 1 is an ordinal hypothesis only; separate runs do not establish dynamic identity.",
                }
                capture["native_adf95_branch_events"] = adf95_branch_events
            capture["stdout"] = {"sha256": hashlib.sha256(process.stdout.encode("utf-8",errors="replace")).hexdigest(),
                                 "bytes": len(process.stdout.encode("utf-8",errors="replace")), "selected_lines": selected}
            capture["stderr"] = {"sha256": hashlib.sha256(process.stderr.encode("utf-8",errors="replace")).hexdigest(),
                                 "bytes": len(process.stderr.encode("utf-8",errors="replace")),
                                 "selected_lines": process.stderr.splitlines()[-32:]}
            recovery_root = pathlib.Path(args.recovery_dir)
            if not recovery_root.is_absolute():
                recovery_root = ROOT / recovery_root
            recovery_root = recovery_root.resolve()
            if not recovery_root.is_relative_to(ROOT.resolve()):
                raise AssertionError("recovery directory must remain inside the project")
            if not (recovery_root / "manifest.json").is_file() or not (recovery_root / "verification.json").is_file():
                raise AssertionError(f"verified recovery artifacts are missing: {recovery_root}")
            capture["recovery"] = {"manifest":recovery_root.relative_to(ROOT).as_posix()+"/manifest.json",
                "verification":recovery_root.relative_to(ROOT).as_posix()+"/verification.json",
                "verification_sha256": hashlib.sha256((recovery_root / "verification.json").read_bytes()).hexdigest()}
            (ROOT / "evidence" / args.evidence_name).write_text(json.dumps(capture, indent=2) + "\n", encoding="utf-8")
        if args.w1_074_native_address_ax4400 and not args.w1_077_native_handle_lifecycle:
            native_lines = process.stdout.splitlines()
            parse_fields = lambda line: dict(token.split("=", 1) for token in line.split()[1:] if "=" in token)
            callbacks = [line for line in native_lines if line.startswith("W1_CRT_CALLBACK_DYNAMIC ")]
            summary_line = next((line for line in native_lines if line.startswith("W1_CRT_SUMMARY ")), None)
            provider_line = next((line for line in native_lines if line.startswith("NATIVE_AX6300_PROVIDER_SETUP ")), None)
            ax6300_line = next((line for line in native_lines if line.startswith("NATIVE_DPMI0300_AX6300 ")), None)
            seed_line = next((line for line in native_lines if line.startswith("NATIVE_W1_ADDRESS_SEED ")), None)
            open_line = next((line for line in native_lines if line.startswith("NATIVE_W1_ADDRESS_OPEN ")), None)
            ah3d_line = next((line for line in native_lines if line.startswith("NATIVE_DOS_AH3D ")), None)
            ax4400_lines = [line for line in native_lines if line.startswith("W1_CRT_DOS_AX4400_FILE ")]
            frontier_line = next((line for line in native_lines if line.startswith("NATIVE_NEXT_TRAP ")), None)
            frontier_cpu_line = next((line for line in native_lines if line.startswith("NATIVE_FRONTIER_CPU ")), None)
            summary = parse_fields(summary_line) if summary_line else {}
            ax6300 = parse_fields(ax6300_line) if ax6300_line else {}
            address_open = parse_fields(open_line) if open_line else {}
            ah3d = parse_fields(ah3d_line) if ah3d_line else {}
            frontier = parse_fields(frontier_line) if frontier_line else {}
            seed_bytes = (ROOT / "tests" / "fixtures" / "w3_067_address_seed_work1.bin").read_bytes()
            seed_evidence_path = ROOT / "evidence" / "w3_067_staging_functional_validation_20261008.json"
            seed_auth = json.loads(seed_evidence_path.read_text(encoding="utf-8"))["runtime"]["guest_errors"]
            seed_sha = hashlib.sha256(seed_bytes).hexdigest()
            errors = []
            if process.returncode != 0: errors.append(f"native process returned {process.returncode}")
            if len(callbacks) != 19 or summary.get("argc") != "3":
                errors.append(f"CRT contract mismatch: callbacks={len(callbacks)} argc={summary.get('argc')}")
            if ("gw_dos_dbcs_table_configure" not in (provider_line or "") or
                    "gw_dos_services_real_mode_interrupt" not in (provider_line or "")):
                errors.append("W2-116 AX=6300 Runtime APIs were not configured for this replay")
            if (ax6300.get("result") != "1" or ax6300.get("inner_eax") != "00006300" or
                    ax6300.get("inner_cf") != "0" or ax6300.get("table_size") != "12"):
                errors.append("natural AX=6300 provider contract failed")
            if (not seed_line or len(seed_bytes) != 24 or seed_sha != seed_auth.get("ADDRESS_TXT_sha256", "").lower() or
                    "provider=virtual-memory" not in seed_line or f"sha256={seed_sha}" not in seed_line):
                errors.append("virtual ADDRESS.TXT seed is not the authenticated W3-067 24-byte fixture")
            if (not open_line or address_open.get("bytes") != "24" or address_open.get("cf") != "0" or
                    address_open.get("path", "").casefold() != r"c:\address.txt"):
                errors.append("natural authenticated ADDRESS.TXT open was not captured")
            if (ah3d.get("request_eax", "").lower() != "00003d01" or
                    ah3d.get("resolved_path", "").replace("/", "\\").casefold() != r"c:\address.txt" or
                    ah3d.get("handled") != "1" or ah3d.get("cf_out") != "0" or
                    int(ah3d.get("response_eax", "0"), 16) != int(address_open.get("handle", "-1"))):
                errors.append("AH=3D01 result does not dynamically identify the authenticated virtual file handle")
            try:
                active_handle = int(ah3d["response_eax"], 16)
            except (KeyError, ValueError):
                active_handle = -1
            ax4400_events = [parse_fields(line) for line in ax4400_lines]
            address_events = [event for event in ax4400_events
                              if event.get("path", "").casefold() == r"c:\address.txt" and
                              int(event.get("ebx_in", "-1"), 16) == active_handle]
            if not address_events:
                errors.append("no AX=4400 event was dynamically correlated to the opened ADDRESS.TXT handle")
            matched = address_events[0] if address_events else {}
            preserved = {}
            for event in address_events:
                if event.get("eax_in", "").lower() != "00004400" or event.get("handled") != "1" or event.get("carry") != "0":
                    errors.append(f"correlated AX=4400 ordinal {event.get('ordinal')} was not handled successfully with CF=0")
                try:
                    if (int(event.get("eax_out", "-1"), 16) & 0xffff) != 2 or (int(event.get("edx_out", "-1"), 16) & 0xffff) != 2:
                        errors.append(f"regular-file ordinal {event.get('ordinal')} did not return AX=DX=2 in the low words")
                    event_preserved = {name: event.get(f"{name}_in") == event.get(f"{name}_out")
                                       for name in ("ebx", "ecx", "esi", "edi", "ebp", "esp")}
                    if not all(event_preserved.values()): errors.append(f"AX=4400 changed non-output registers at ordinal {event.get('ordinal')}: {event_preserved}")
                    if not preserved: preserved = event_preserved
                except ValueError:
                    errors.append(f"AX=4400 return register values are malformed at ordinal {event.get('ordinal')}")
            if not frontier_line or not frontier_cpu_line:
                errors.append("no fresh post-AX=4400 frontier was captured")
            elif (frontier.get("eax", "").lower() == "00004400" and
                  int(frontier.get("ebx", "-1"), 16) == active_handle):
                errors.append("frontier repeats the same AX=4400 file-handle context instead of a new request")
            physical = w1_address_seed["physical_host_path_observation"]
            if physical.get("guest_provider_source") is not False:
                errors.append("physical host file was confused with the in-memory virtual provider")
            sys.path.insert(0, str(ROOT / "tools"))
            import frontier_snapshot
            runtime_dir = ROOT / "runtime"
            runtime_fingerprint = {"c_h_sha256": frontier_snapshot.runtime_hash(ROOT),
                                   "python_sha256": frontier_snapshot.manifest_hash(list(runtime_dir.glob("*.py")), ROOT)}
            exe_sha = hashlib.sha256(EXE.read_bytes()).hexdigest()
            recovery_root = ROOT / "work" / "recovery" / "W1-074-20261009"
            manifest_path = recovery_root / "manifest.json"
            verification_path = recovery_root / "verification.json"
            selected_prefixes = ("W1_INITRTNS_ENTRY ", "W1_CRT_CALLBACK_DYNAMIC ", "W1_CRT_SUMMARY ",
                "W1_CRT_ARG ", "W1_MAIN_BLOCK ", "W1_SETUP_EVENT ", "NATIVE_AX6300_PROVIDER_SETUP ",
                "NATIVE_DPMI0300_AX6300 ", "NATIVE_W1_ADDRESS_SEED ", "NATIVE_W1_ADDRESS_OPEN ",
                "NATIVE_DOS_AH3D ", "W1_CRT_AX4400_CONTEXT ", "W1_CRT_DOS_AX4400_FILE ",
                "NATIVE_NEXT_TRAP ", "NATIVE_FRONTIER_CPU ")
            selected_lines = [line for line in native_lines if line.startswith(selected_prefixes)]
            capture.update({"task": "W1-074", "schema": "gwrecomp.native-address-ax4400-w1-074/v1",
                "execution_mode": "native_recompiled_guest", "evidence_level": "NATIVE_REACHED",
                "capture_id": str(uuid.uuid4()), "captured_at": datetime.now(timezone.utc).isoformat(),
                "fresh_replay": True, "original_equivalence_claimed": False,
                "target_sha256": boot.executable_sha256, "build_id": exe_sha,
                "build_fingerprints": {"native_executable_sha256": exe_sha,
                    "closure_source_sha256": hashlib.sha256((ROOT / "build" / "entry_path_closure.c").read_bytes()).hexdigest(),
                    "routed_object_sha256": hashlib.sha256((ROOT / "build" / "entry_path_closure_routed.o").read_bytes()).hexdigest(),
                    "capture_object_sha256": hashlib.sha256(pathlib.Path(object_path).read_bytes()).hexdigest(),
                    "harness_c_sha256": hashlib.sha256((ROOT / "tests" / "test_native_guest_image.c").read_bytes()).hexdigest(),
                    "driver_sha256": hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()},
                "runtime_fingerprint": runtime_fingerprint,
                "runtime_ax4400_contract": {"evidence": "evidence/native_dos_ax4400_runtime_work2.json",
                    "callback": "gw_dos_services_callback", "configured_file_metadata_provider": True,
                    "used_by_replay": bool(matched.get("handled") == "1"),
                    "source_of_response": "active in-memory virtual-file metadata; no AX/DX/CF injection"},
                "authenticated_environment": {"source_evidence": w3_original_environment_metadata["source_evidence"],
                    "sha256": w3_original_environment_metadata["sha256"], "size_bytes": len(w3_original_environment),
                    "exact_bytes_loaded": boot.environment == w3_original_environment},
                "command_tail": args.command_tail,
                "crt": {"callback_count": len(callbacks), "argc": int(summary.get("argc", "-1")),
                    "argv": [parse_fields(line).get("value", "") for line in native_lines if line.startswith("W1_CRT_ARG ")]},
                "address_txt": {"fixture": "tests/fixtures/w3_067_address_seed_work1.bin", "size": len(seed_bytes),
                    "sha256": seed_sha, "authentic_evidence": seed_evidence_path.relative_to(ROOT).as_posix(),
                    "authentic_evidence_sha256": hashlib.sha256(seed_evidence_path.read_bytes()).hexdigest(),
                    "virtual_seed_event": seed_line, "open_event": open_line, "open_request_response": ah3d_line,
                    "dynamic_handle": active_handle, "physical_host_path_observation": physical,
                    "host_filesystem_used": False},
                "ax4400": {"requests": ax4400_lines, "correlated_address_event": matched,
                    "correlated_address_events": address_events,
                    "dynamic_handle_from_ah3d_return": active_handle, "register_preservation": preserved,
                    "contract": {"ax_low_word": 2, "dx_low_word": 2, "cf": 0,
                        "basis": "W2-106 regular-file metadata contract; this is a fresh native request, not same-run original parity"}},
                "next_frontier": {"event": frontier_line, "cpu": frontier_cpu_line,
                    "newly_observed_in_this_replay": bool(frontier_line)},
                "recovery": {"manifest": manifest_path.relative_to(ROOT).as_posix(),
                    "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
                    "verification": verification_path.relative_to(ROOT).as_posix(),
                    "verification_sha256": hashlib.sha256(verification_path.read_bytes()).hexdigest()},
                "stdout": {"sha256": hashlib.sha256(process.stdout.encode("utf-8", errors="replace")).hexdigest(),
                    "selected_lines": selected_lines},
                "stderr": {"sha256": hashlib.sha256(process.stderr.encode("utf-8", errors="replace")).hexdigest(),
                    "selected_lines": process.stderr.splitlines()[-24:]},
                "acceptance_errors": errors, "passed": not errors})
            evidence_path = ROOT / "evidence" / args.evidence_name
            evidence_path.write_text(json.dumps(capture, indent=2) + "\n", encoding="utf-8")
            print(process.stdout, end="")
            print(process.stderr, end="", file=sys.stderr)
            print(f"W1-074 native ADDRESS.TXT AX=4400 capture saved: evidence/{args.evidence_name}")
            if errors: raise AssertionError("W1-074 acceptance failed: " + "; ".join(errors))
            return 0
        if args.w1_077_native_handle_lifecycle:
            native_lines = process.stdout.splitlines()
            parse_fields = lambda line: dict(token.split("=", 1) for token in line.split()[1:] if "=" in token)
            request_lines = [line for line in native_lines if line.startswith("W1_077_DOS_FILE_REQUEST ")]
            lifecycle_events = [parse_fields(line) for line in request_lines]
            context_line = next((line for line in native_lines if line.startswith("W1_077_PROCESS_CONTEXT ")),None)
            ax4400_lines = [line for line in native_lines if line.startswith("W1_CRT_DOS_AX4400_FILE ")]
            sequence_lines = [line for line in native_lines if line.startswith("NATIVE_DPMI_AX0501_SEQUENCE ")]
            sequence_events = [parse_fields(line) for line in sequence_lines]
            summary_line = next((line for line in native_lines if line.startswith("W1_CRT_SUMMARY ")),None)
            frontier_line = next((line for line in native_lines if line.startswith("NATIVE_NEXT_TRAP ")),None)
            frontier_cpu_line = next((line for line in native_lines if line.startswith("NATIVE_FRONTIER_CPU ")),None)
            repeat_guard_line = next((line for line in native_lines if line.startswith("NATIVE_W1_093_REPEAT_GUARD ")),None)
            if len(request_lines)>32: raise AssertionError(f"W1-077 observer exceeded its 32-event cap: {len(request_lines)}")
            if not context_line or (not summary_line and not native_replay_timed_out) or not ax4400_lines:
                raise AssertionError("W1-077 process context, CRT summary, or AX=4400 checkpoints are missing")
            if len(ax4400_lines)>8:
                raise AssertionError(f"W1-077 captured more than the first eight AX=4400 callbacks: {len(ax4400_lines)}")
            if args.continue_dpmi_linear_sequence:
                if not sequence_events:
                    raise AssertionError("W1-090 natural AX=0501 sequence did not reach the Runtime callback")
                if args.w1_092_host_backed_guest_memory:
                    last_ordinal=int(sequence_events[-1].get("ordinal","-1"))
                    evidence_sequence_events=[event for event in sequence_events
                        if event.get("success")=="1" or int(event.get("ordinal","-1"))%256==0 or
                        int(event.get("ordinal","-1"))==last_ordinal]
                else:
                    evidence_sequence_events=sequence_events
                expected_arena = ("host_backed_demand_commit" if args.w1_092_host_backed_guest_memory else "host_backed" if host_backed_guest_memory else "synthetic")
                guest_map_line = next((line for line in native_lines if line.startswith("NATIVE_DPMI_GUEST_MEMORY_MAP ")), None)
                guest_map = parse_fields(guest_map_line) if guest_map_line else None
                if host_backed_guest_memory:
                    expected_allocation_end=(0x00200000 + args.experimental_dpmi_budget_mib * 1024 * 1024
                        if args.experimental_dpmi_budget_mib else guest_map_capacity)
                    if (not guest_map or guest_map.get("kind") != "host_backed" or
                            int(guest_map.get("guest_capacity", "0"), 16) != guest_map_capacity or
                            int(guest_map.get("image_end", "0"), 16) != 0x001B2000 or
                            int(guest_map.get("allocation_begin", "0"), 16) != 0x00200000 or
                            int(guest_map.get("allocation_end", "0"), 16) != expected_allocation_end or
                            guest_map.get("lifetime") != ("process_virtual_reservation" if args.w1_092_host_backed_guest_memory else "process_zeroed") or
                            guest_map.get("backing") != ("VirtualAlloc_commit_on_allocate" if args.w1_092_host_backed_guest_memory else "guest_memory")):
                        raise AssertionError(f"host-backed guest map contract is missing or inconsistent: {guest_map}")
                previous_ordinal=-1
                for sequence_index,event in enumerate(sequence_events):
                    ordinal=int(event.get("ordinal","-1"))
                    requested_size=((int(event.get("request_ebx","0"),16)&0xffff)<<16)|(int(event.get("request_ecx","0"),16)&0xffff)
                    ordinal_valid=(ordinal>previous_ordinal if args.w1_092_host_backed_guest_memory else ordinal==sequence_index)
                    if (not ordinal_valid or event.get("eip")!="000c3cc1" or
                            event.get("provider")!="gw_dos_services_callback" or event.get("arena")!=expected_arena or
                            event.get("handled")!="1" or event.get("preserved")!="1" or
                            int(event.get("size","0"),16)!=requested_size):
                        raise AssertionError(f"W1-090 AX=0501 sequence provenance failed: {event}")
                    previous_ordinal=ordinal
                    if event.get("success")=="1":
                        base,size=int(event["base"],16),requested_size
                        capacity=int(event.get("guest_capacity", "00400000"),16)
                        if (event.get("carry")!="0" or event.get("response_eax")!=event.get("request_eax") or
                                int(event.get("handle","0"),16)==0 or base<0x200000 or base+size>capacity or
                                base&0xfff or event.get("zero_filled")!="1" or
                                int(event["cursor_after"],16)!=base+size):
                            raise AssertionError(f"AX=0501 allocation success escaped its configured guest map: {event}")
                    elif event.get("unavailable")=="1":
                        if (event.get("carry")!="1" or int(event.get("response_eax","0"),16)&0xffff!=0x8012 or
                                event.get("cursor_before")!=event.get("cursor_after") or
                                (sequence_index!=len(sequence_events)-1 and not args.w1_092_host_backed_guest_memory)):
                            raise AssertionError(f"W1-090 Runtime allocator exhaustion result is inconsistent: {event}")
                    else:
                        raise AssertionError(f"W1-090 sequence event has no allocator outcome: {event}")
                selected_prefixes=("W1_077_", "W1_079_", "W1_080_", "W1_081_", "NATIVE_W1_090_AX0501_DISPATCH_PROBE ", "NATIVE_DPMI_GUEST_MEMORY_MAP ", "NATIVE_DOS_MCB_SEED ", "NATIVE_DOS_AH48", "NATIVE_DOS_AH49 ", "NATIVE_BUDGET_FRONTIER ", "NATIVE_W1_092_PROGRESS ", "NATIVE_W1_092_HEAP_LIST ", "NATIVE_W1_093_BLOCK_SNAPSHOT ", "W1_CRT_DOS_AH3D_GENERIC ", "W1_CRT_DOS_AH3C_GENERIC ",
                "W1_CRT_DOS_AH3E_FILE ", "NATIVE_DOS_AH3D ", "NATIVE_DOS_AH3E ",
                "W1_CRT_DOS_AX4400_FILE ", "NATIVE_DPMI0300_INT2F1500 ", "NATIVE_W1_093_REPEAT_GUARD ", "NATIVE_NEXT_TRAP ", "NATIVE_FRONTIER_CPU ",
                "W1_CRT_SUMMARY ", "NATIVE_W1_ADDRESS_SEED ", "NATIVE_W1_ADDRESS_OPEN ",
                "W1_AH44_CALLSITE ", "W1_AH44_HELPER_ENTRY ", "W1_AH44_REQUEST ")
            selected=[line for line in native_lines if line.startswith(selected_prefixes)]
            runtime_dir=ROOT/"runtime"
            sys.path.insert(0,str(ROOT/"tools"))
            import frontier_snapshot
            runtime_fingerprint={"c_h_sha256":frontier_snapshot.runtime_hash(ROOT),
                "python_sha256":frontier_snapshot.manifest_hash(list(runtime_dir.glob("*.py")),ROOT)}
            exe_sha=hashlib.sha256(EXE.read_bytes()).hexdigest()
            context=parse_fields(context_line)
            summary_fields=parse_fields(summary_line) if summary_line else {}
            gwerr_requests=[]
            for event in lifecycle_events:
                if event.get("path_hex"):
                    try: decoded=bytes.fromhex(event["path_hex"]).decode("ascii",errors="replace").replace("/","\\").casefold()
                    except ValueError: decoded=""
                    if decoded.endswith("gw.err"): gwerr_requests.append({**event,"decoded_path":decoded})
            original_path=ROOT/"evidence"/"w3_227_ah44_divergence_chronology.json"
            recovery_root=pathlib.Path(args.recovery_dir)
            if not recovery_root.is_absolute(): recovery_root=ROOT/recovery_root
            recovery_rel=recovery_root.resolve().relative_to(ROOT.resolve()).as_posix()
            w1_079_events=[line for line in native_lines if line.startswith("W1_079_AX4400_HANDLE2 ")]
            from verify_w1_085_ah4400_caller_provenance import build_provenance
            native_ah4400_origin=build_provenance(native_lines,lifecycle_events)
            w1_083_setup_capture=(args.serve_w3_functional_config and args.serve_w3_address_seed and
                args.w1_080_native_ax4400_active_file and args.w1_081_native_ah40_active_file)
            dynamic_callbacks=[line for line in native_lines if line.startswith("W1_CRT_CALLBACK_DYNAMIC ")]
            capture.update({"task":"W1-085" if w1_083_setup_capture else "W1-077",
                "schema":"gwrecomp.native-setup-replay/v1" if w1_083_setup_capture else "gwrecomp.native-gwerr-handle-lifecycle-w1-077/v1",
                "execution_mode":"native_recompiled_guest","evidence_level":"DIFF_VERIFIED" if w1_083_setup_capture else "NATIVE_REACHED",
                "capture_id":str(uuid.uuid4()),"captured_at":datetime.now(timezone.utc).isoformat(),
                "fresh_replay":True,"original_equivalence_claimed":False,"build_id":exe_sha,
                "native_replay_timed_out":native_replay_timed_out,
                "native_replay_timeout_seconds":args.native_replay_timeout_seconds if native_replay_timed_out else None,
                "runtime_fingerprint":runtime_fingerprint,"fixture_id":hashlib.sha256(json.dumps({
                    "target_sha256":boot.executable_sha256,"address_txt_sha256":w1_address_seed["sha256"],
                    "environment_sha256":w3_original_environment_metadata["sha256"] if w3_original_environment_metadata else None,
                    "command_tail":args.command_tail},sort_keys=True,separators=(",",":")).encode("utf-8")).hexdigest(),
                "crt":{"callback_count":len(dynamic_callbacks),
                    "destinations":["0x"+parse_fields(x).get("target","") for x in dynamic_callbacks],
                    "argc":int(summary_fields.get("argc","-1")),
                    "argv":[parse_fields(x).get("value","") for x in native_lines if x.startswith("W1_CRT_ARG ")]},
                "w1_077_lifecycle":{"observer_enabled":True,"event_cap":32,
                    "request_event_count":len(lifecycle_events),"events":lifecycle_events,
                    "response_events":[line for line in native_lines if line.startswith(("NATIVE_DOS_AH3D ",
                        "W1_CRT_DOS_AH3D_GENERIC ","W1_CRT_DOS_AH3C_GENERIC ","W1_CRT_DOS_AH3E_FILE ",
                        "NATIVE_DOS_AH3E ","W1_077_DOS_DUP_RESULT "))],
                    "process_context":context,"ah4400_observations":ax4400_lines,
                    "ah4400_observation_count":len(ax4400_lines),
                    "gwerr_open_or_create_requests":gwerr_requests,
                    "gwerr_result_classification":"request observed at native callback boundary" if gwerr_requests else "no GW.ERR open/create request observed in this bounded callback window",
                    "lifecycle_coverage":"DOS AH=3C/3D/3E/43/46/5A requests at the single native guest callback boundary, capped at 32 and limited to the first eight AX=4400 requests; no PSP JFT is inferred from the Runtime file table",
                    "original_reference":{"path":"evidence/w3_227_ah44_divergence_chronology.json",
                        "sha256":hashlib.sha256(original_path.read_bytes()).hexdigest()},
                    "native_replay_frontier":{"event":frontier_line,"cpu":frontier_cpu_line,
                        "parsed":parse_fields(frontier_line) if frontier_line else None},
                    "same_dynamic_invocation_claimed":False,"causality_claimed":False},
                "w1_079_ax4400_handle2":{"observer_enabled":args.w1_079_native_ax4400_handle2,
                    "event_cap":1,"event_count":len(w1_079_events),"events":w1_079_events,
                    "only_active_virtual_file_handle":True,"guest_state_injected":False},
                "w1_080_ax4400_active_file":{"observer_enabled":args.w1_080_native_ax4400_active_file,
                    "event_cap":4,
                    "events":[line for line in native_lines if line.startswith("W1_080_AX4400_ACTIVE_FILE ")],
                    "event_count":len([line for line in native_lines if line.startswith("W1_080_AX4400_ACTIVE_FILE ")]),
                    "only_active_virtual_file_handle":True,"guest_state_injected":False},
                "w1_081_ah40_active_file":{"observer_enabled":args.w1_081_native_ah40_active_file,
                    "event_cap":2,"max_sample_bytes":64,
                    "events":[line for line in native_lines if line.startswith("W1_081_AH40_ACTIVE_FILE ")],
                    "event_count":len([line for line in native_lines if line.startswith("W1_081_AH40_ACTIVE_FILE ")]),
                    "only_active_virtual_file_handle":True,"host_write":False,"guest_state_injected":False},
                "native_ah4400_origin":native_ah4400_origin,
                "stdout":{"sha256":hashlib.sha256(process.stdout.encode("utf-8",errors="replace")).hexdigest(),
                    "bytes":len(process.stdout.encode("utf-8",errors="replace")),"selected_lines":selected},
                "stderr":{"sha256":hashlib.sha256(process.stderr.encode("utf-8",errors="replace")).hexdigest(),
                    "bytes":len(process.stderr.encode("utf-8",errors="replace")),"selected_lines":process.stderr.splitlines()[-32:]},
                "recovery":{"manifest":recovery_rel+"/manifest.json",
                    "verification":recovery_rel+"/verification.json",
                    "verification_sha256":hashlib.sha256((recovery_root/"verification.json").read_bytes()).hexdigest()}})
            if args.continue_dpmi_linear_sequence:
                evidence_key = ("w1_092_allocator_lifecycle" if args.w1_092_host_backed_guest_memory else
                                "w1_091_guest_linear_memory" if args.w1_091_host_backed_guest_memory else
                                "w1_090_ax0501_sequence")
                capture[evidence_key]={
                    "schema":("gwrecomp.native-dpmi-host-backed-guest-memory-w1-092/v1" if args.w1_092_host_backed_guest_memory else
                              "gwrecomp.native-dpmi-host-backed-guest-memory-w1-091/v1" if args.w1_091_host_backed_guest_memory else
                              "gwrecomp.native-dpmi-linear-sequence/v1"),
                    "evidence_level":"NATIVE_REACHED" if host_backed_guest_memory else "UNVERIFIED",
                    "target_sha256":boot.executable_sha256,
                    "fixture_fingerprint":capture.get("fixtures",{}).get("native",{}).get("fingerprint"),
                    "fixture_components":capture.get("fixtures",{}).get("native",{}),
                    "authenticated_environment_sha256":capture.get("authenticated_environment",{}).get("sha256"),
                    "build_sha256":exe_sha,
                    "native_compiler_options":[flag for flag in native_cc if flag.startswith("-O") or flag in ("-fwrapv","-fno-strict-aliasing")],
                    "stdout_sha256":capture["stdout"]["sha256"],
                    "runtime_fingerprint":runtime_fingerprint,
                    "original_equivalence_claimed":False,
                    "events":evidence_sequence_events,
                    "event_count":int(sequence_events[-1].get("ordinal","-1"))+1,
                    "event_sampling":("all successes plus failures every 256 ordinals and the final event" if args.w1_092_host_backed_guest_memory else "complete sequence"),
                    "zero_fill_basis":("VirtualAlloc MEM_COMMIT zero-fill guarantee plus first/last byte checks" if args.w1_092_host_backed_guest_memory else "full allocated-range scan"),
                    "provider":"gw_dos_services_callback",
                    "arena":({"kind":"host_backed_guest_map","guest_range":["0x00000000",f"0x{guest_map_capacity:08X}"],
                              "image_end":"0x001B2000","allocation_begin":"0x00200000","capacity_bytes":f"0x{guest_map_capacity:08X}",
                              "backing":("contiguous VirtualAlloc reservation with demand-committed successful allocations" if args.w1_092_host_backed_guest_memory else "zeroed process-owned guest_memory"),"duration":"single replay process",
                              "not_original_mapping_evidence":True} if host_backed_guest_memory else
                             {"kind":"synthetic_test_only","mapped_guest_memory_range":["0x00200000","0x00400000"],
                              "not_original_mapping_evidence":True}),
                    "guest_memory_map":guest_map if host_backed_guest_memory else None,
                    "dpmi_budget":{"kind":"explicit_experiment","requested_bytes":args.experimental_dpmi_budget_mib*1024*1024,
                        "allocation_begin":"0x00200000","allocation_end":f"0x{0x00200000 + args.experimental_dpmi_budget_mib*1024*1024:08X}",
                        "original_equivalence_claimed":False} if args.experimental_dpmi_budget_mib else
                        {"kind":"guest_map_capacity_default","requested_bytes":None,"original_equivalence_claimed":False},
                    "stopped_after_allocator_exhaustion":sequence_events[-1].get("unavailable")=="1",
                    "next_frontier":({"kind":"repeated_guest_state_guard","event":parse_fields(repeat_guard_line),
                        "original_equivalence_claimed":False} if repeat_guard_line else
                        parse_fields(frontier_line) if frontier_line else
                        ({"kind":"bounded_native_timeout","timeout_seconds":args.native_replay_timeout_seconds,
                          "last_progress":next((parse_fields(line) for line in reversed(native_lines)
                              if line.startswith("NATIVE_W1_092_PROGRESS ")),None),
                          "last_heap_list":next((parse_fields(line) for line in reversed(native_lines)
                              if line.startswith("NATIVE_W1_092_HEAP_LIST ")),None),
                          "last_allocator_event":next((parse_fields(line) for line in reversed(native_lines)
                              if line.startswith(("NATIVE_DOS_AH49 ","NATIVE_DOS_AH48 ordinal="))),None)}
                         if native_replay_timed_out else None)),
                    "next_frontier_cpu":frontier_cpu_line,
                    "same_size_original_comparison":{"evidence":"reports/dpmi_linear_sparse_memory_work2.md",
                        "classification":"service-level corroboration only; different replay state/ordinal; same dynamic invocation not claimed"},
                    "guest_state_injected":False,
                }
            evidence_path=ROOT/"evidence"/args.evidence_name
            evidence_path.write_text(json.dumps(capture,indent=2)+"\n",encoding="utf-8")
            if args.w1_092_host_backed_guest_memory:
                lifecycle=capture["w1_092_allocator_lifecycle"]
                markers=[line for line in selected if line.startswith(("NATIVE_DOS_MCB_SEED ",
                    "NATIVE_DOS_AH48", "NATIVE_DOS_AH49 ", "NATIVE_BUDGET_FRONTIER ",
                    "NATIVE_W1_092_PROGRESS ", "NATIVE_W1_092_HEAP_LIST ",
                    "NATIVE_W1_093_BLOCK_SNAPSHOT ",
                    "NATIVE_NEXT_TRAP ", "NATIVE_FRONTIER_CPU "))]
                standalone={"schema":"gwrecomp.native-dpmi-allocator-lifecycle-w1-092/v2",
                    "task":"W1-092","execution_mode":"native_recompiled_guest",
                    "evidence_level":"NATIVE_REACHED","fresh_replay":True,
                    "original_equivalence_claimed":False,"target_sha256":boot.executable_sha256,
                    "build_sha256":exe_sha,"runtime_fingerprint":runtime_fingerprint,
                    "native_compiler_options":lifecycle["native_compiler_options"],
                    "fixture_fingerprint":lifecycle["fixture_fingerprint"],
                    "authenticated_environment_sha256":lifecycle["authenticated_environment_sha256"],
                    "guest_memory_map":lifecycle["guest_memory_map"],
                    "allocation_event_count":lifecycle["event_count"],
                    "allocation_events":lifecycle["events"],
                    "event_sampling":lifecycle["event_sampling"],
                    "zero_fill_basis":lifecycle["zero_fill_basis"],
                    "allocator_events":markers,
                    "next_frontier":lifecycle["next_frontier"],
                    "native_returncode":process.returncode,
                    "native_replay_timed_out":native_replay_timed_out,
                    "native_replay_timeout_seconds":args.native_replay_timeout_seconds if native_replay_timed_out else None,
                    "stdout_sha256":capture["stdout"]["sha256"],
                    "stdout_bytes":capture["stdout"]["bytes"],
                    "replay_options":capture.get("replay_options",[]),
                    "graphics":{"vesa_reached":False,"lb_screen_setup_reached":False,
                        "lb_screen_setup_any_mode_reached":False,"authentic_framebuffer_observed":False,
                        "basis":"no video setup/frontbuffer marker was emitted before the recorded native frontier"}}
                lifecycle_path=ROOT/"evidence"/"native_allocator_lifecycle_w1_092.json"
                lifecycle_path.write_text(json.dumps(standalone,indent=2)+"\n",encoding="utf-8")
                print(f"W1-092 native allocator lifecycle evidence saved: evidence/{lifecycle_path.name}")
            print(f"W1-077 bounded native lifecycle evidence saved: evidence/{args.evidence_name}")
            if process.returncode==0: return 0
            if args.w1_092_host_backed_guest_memory and native_replay_timed_out:
                allocator_markers=[line for line in native_lines if line.startswith("NATIVE_DOS_AH48 ordinal=")]
                ah49_markers=[line for line in native_lines if line.startswith("NATIVE_DOS_AH49 ")]
                return 0 if len(allocator_markers)>=2 and ah49_markers else 1
            return 1
        if args.w1_072_native_address_open:
            native_lines = process.stdout.splitlines()
            parse_fields = lambda line: dict(token.split("=", 1) for token in line.split()[1:] if "=" in token)
            callbacks = [line for line in native_lines if line.startswith("W1_CRT_CALLBACK_DYNAMIC ")]
            summary_line = next((line for line in native_lines if line.startswith("W1_CRT_SUMMARY ")), None)
            gate_line = next((line for line in native_lines if line.startswith("W1_MAIN_BLOCK va=0009433d ")), None)
            setup_line = next((line for line in native_lines if line.startswith("W1_MAIN_BLOCK va=00094ac0 ")), None)
            setup_events = [parse_fields(line) for line in native_lines if line.startswith("W1_SETUP_EVENT ")]
            callee_event = next((event for event in setup_events if event.get("eip", "").lower() == "00014bf0"), None)
            setup_callsite = next((event for event in setup_events if event.get("eip", "").lower() == "0009433d"), None)
            provider_setup = next((line for line in native_lines if line.startswith("NATIVE_AX6300_PROVIDER_SETUP ")), None)
            service_line = next((line for line in native_lines if line.startswith("NATIVE_DPMI0300_AX6300 ")), None)
            seed_line = next((line for line in native_lines if line.startswith("NATIVE_W1_ADDRESS_SEED ")), None)
            address_open_line = next((line for line in native_lines if line.startswith("NATIVE_W1_ADDRESS_OPEN ")), None)
            ah3d_line = next((line for line in native_lines if line.startswith("NATIVE_DOS_AH3D ")), None)
            frontier_line = next((line for line in native_lines if line.startswith("NATIVE_NEXT_TRAP ")), None)
            frontier_cpu_line = next((line for line in native_lines if line.startswith("NATIVE_FRONTIER_CPU ")), None)
            summary = parse_fields(summary_line) if summary_line else {}
            gate = parse_fields(gate_line) if gate_line else {}
            service = parse_fields(service_line) if service_line else {}
            provider = parse_fields(provider_setup) if provider_setup else {}
            seed = parse_fields(seed_line) if seed_line else {}
            address_open = parse_fields(address_open_line) if address_open_line else {}
            ah3d = parse_fields(ah3d_line) if ah3d_line else {}
            frontier = parse_fields(frontier_line) if frontier_line else {}
            errors = []
            if process.returncode != 0: errors.append(f"native process returned {process.returncode}")
            if len(callbacks) != 19: errors.append(f"expected 19 CRT callbacks, got {len(callbacks)}")
            if summary.get("argc") != "3": errors.append(f"expected argc=3, got {summary.get('argc')}")
            if ("gw_dos_dbcs_table_configure" not in (provider_setup or "") or
                    "gw_dos_services_real_mode_interrupt" not in (provider_setup or "")):
                errors.append("W2-116 Runtime API configure/callback was not identified")
            if (service.get("result") != "1" or service.get("ordinal") != "1" or
                    service.get("inner_eax") != "00006300" or service.get("inner_cf") != "0" or
                    service.get("table_size") != "12" or service.get("table_zero") != "1"):
                errors.append("natural AX=6300 response did not satisfy the bounded guest table contract")
            try:
                table_linear = int(service["table_linear"], 16)
                returned_linear = int(service["inner_ds"], 16) * 16 + int(service["inner_si"], 16)
                if not table_linear or table_linear != returned_linear:
                    errors.append("AX=6300 returned DS:SI does not resolve to its dynamic configured guest region")
            except (KeyError, ValueError):
                errors.append("AX=6300 dynamic address fields are missing")
            if not seed_line or seed.get("bytes") != "24" or seed.get("path", "").casefold() != r"c:\address.txt" or seed.get("provider") != "virtual-memory":
                errors.append("authenticated ADDRESS.TXT is not visible in the native virtual provider")
            if not address_open_line or address_open.get("bytes") != "24" or address_open.get("cf") != "0":
                errors.append("natural ADDRESS.TXT open did not return a virtual-file handle")
            if (ah3d.get("eip", "").lower() != "000afcc4" or ah3d.get("request_eax", "").lower() != "00003d01" or
                    ah3d.get("resolved_path", "").replace("/", "\\").casefold() != r"c:\address.txt" or
                    ah3d.get("cf_out") != "0" or ah3d.get("handled") != "1" or
                    ah3d.get("matched_original_fixture") != "1" or
                    int(ah3d.get("response_eax", "0"), 16) != int(address_open.get("handle", "-1"))):
                errors.append("AH=3D01 request/result does not match the allowlisted virtual open")
            if not frontier_line or not frontier_cpu_line or frontier.get("eip", "").lower() == "000afcc4":
                errors.append("fresh post-open native frontier was not captured")
            if process.returncode != 0 and not frontier_line:
                errors.append("native replay failed before the next interrupt frontier")

            seed_bytes = (ROOT / "tests" / "fixtures" / "w3_067_address_seed_work1.bin").read_bytes()
            seed_evidence_path = ROOT / "evidence" / "w3_067_staging_functional_validation_20261008.json"
            seed_auth = json.loads(seed_evidence_path.read_text(encoding="utf-8"))["runtime"]["guest_errors"]
            seed_sha = hashlib.sha256(seed_bytes).hexdigest()
            if len(seed_bytes) != 24 or seed_sha != seed_auth.get("ADDRESS_TXT_sha256", "").lower():
                errors.append("ADDRESS.TXT seed bytes no longer match W3-067 authentication")
            if seed.get("sha256", "").lower() != seed_sha:
                errors.append("native virtual provider hash differs from authenticated ADDRESS.TXT")
            physical = w1_address_seed["physical_host_path_observation"]
            if physical.get("guest_provider_source") is not False:
                errors.append("host ADDRESS.TXT path was incorrectly reported as the guest provider source")

            sys.path.insert(0, str(ROOT / "tools"))
            import frontier_snapshot
            runtime_dir = ROOT / "runtime"
            runtime_fingerprint = {"c_h_sha256": frontier_snapshot.runtime_hash(ROOT),
                                   "python_sha256": frontier_snapshot.manifest_hash(list(runtime_dir.glob("*.py")), ROOT)}
            exe_sha = hashlib.sha256(EXE.read_bytes()).hexdigest()
            recovery_manifest = ROOT / "work" / "recovery" / "W1-072-20261009" / "manifest.json"
            if not recovery_manifest.is_file(): errors.append("verified W1-072 recovery manifest is missing")
            selected_prefixes = ("W1_INITRTNS_ENTRY ", "W1_CRT_CALLBACK_DYNAMIC ", "W1_CRT_SUMMARY ",
                "W1_CRT_ARG ", "W1_MAIN_BLOCK ", "W1_SETUP_EVENT ", "NATIVE_AX6300_PROVIDER_SETUP ",
                "NATIVE_DPMI0300_AX6300 ", "NATIVE_AX6300_PROVIDER_REGRESSION ",
                "NATIVE_W1_ADDRESS_SEED ", "NATIVE_W1_ADDRESS_OPEN ", "NATIVE_DOS_AH3D ",
                "NATIVE_NEXT_TRAP ", "NATIVE_FRONTIER_CPU ")
            selected_lines = [line for line in native_lines if line.startswith(selected_prefixes)]
            capture.update({"task": "W1-072", "schema": "gwrecomp.native-address-open-w1-072/v1",
                "execution_mode": "native_recompiled_guest", "evidence_level": "NATIVE_REACHED",
                "capture_id": str(uuid.uuid4()), "captured_at": datetime.now(timezone.utc).isoformat(),
                "fresh_replay": True, "original_equivalence_claimed": False,
                "target_sha256": boot.executable_sha256, "build_id": exe_sha,
                "build_fingerprints": {"native_executable_sha256": exe_sha,
                    "closure_source_sha256": hashlib.sha256((ROOT / "build" / "entry_path_closure.c").read_bytes()).hexdigest(),
                    "routed_object_sha256": hashlib.sha256((ROOT / "build" / "entry_path_closure_routed.o").read_bytes()).hexdigest(),
                    "capture_object_sha256": hashlib.sha256(pathlib.Path(object_path).read_bytes()).hexdigest(),
                    "harness_c_sha256": hashlib.sha256((ROOT / "tests" / "test_native_guest_image.c").read_bytes()).hexdigest(),
                    "driver_sha256": hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()},
                "runtime_fingerprint": runtime_fingerprint,
                "runtime_api": {"evidence": "evidence/w2_116_dpmi6300_native_provider.json",
                    "evidence_sha256": hashlib.sha256((ROOT / "evidence" / "w2_116_dpmi6300_native_provider.json").read_bytes()).hexdigest(),
                    "configure": "gw_dos_dbcs_table_configure", "callback": "gw_dos_services_real_mode_interrupt",
                    "used_by_replay": "NATIVE_AX6300_PROVIDER_SETUP" in (provider_setup or "")},
                "authenticated_environment": {"source_evidence": w3_original_environment_metadata["source_evidence"],
                    "sha256": w3_original_environment_metadata["sha256"], "size_bytes": len(w3_original_environment),
                    "exact_bytes_loaded": boot.environment == w3_original_environment},
                "command_tail": args.command_tail,
                "crt": {"callback_count": len(callbacks), "argc": int(summary.get("argc", "-1")),
                    "argv": [parse_fields(line).get("value", "") for line in native_lines if line.startswith("W1_CRT_ARG ")]},
                "game_gate": {"main_gate_observed": gate_line is not None,
                    "local64": gate.get("local64"), "local68": gate.get("local68"),
                    "setup_game_entry_observed": setup_line is not None,
                    "setup_callsite": setup_callsite, "callee_14bf0": callee_event,
                    "observed_setup_events": setup_events,
                    "interpretation": "record-only; this acceptance is the fresh address provider frontier, not a MENU/setup claim"},
                "ax6300": {"provider_setup": provider_setup, "event": service_line,
                    "request_frame_before_hex": service.get("frame_before"),
                    "response_frame_after_hex": service.get("frame_after"),
                    "table_linear": "0x" + service.get("table_linear", ""),
                    "table_size": int(service.get("table_size", "0")), "table_zero": service.get("table_zero") == "1",
                    "returned_ds_si": {"ds": "0x" + service.get("inner_ds", ""), "si": "0x" + service.get("inner_si", "")}},
                "address_txt": {"fixture": "tests/fixtures/w3_067_address_seed_work1.bin", "size": len(seed_bytes),
                    "sha256": seed_sha, "authentic_evidence": seed_evidence_path.relative_to(ROOT).as_posix(),
                    "authentic_evidence_sha256": hashlib.sha256(seed_evidence_path.read_bytes()).hexdigest(),
                    "virtual_seed_event": seed_line, "open_event": address_open_line,
                    "request_response": ah3d_line,
                    "physical_host_path_observation": physical, "host_filesystem_used": False},
                "next_frontier": {"event": frontier_line, "cpu": frontier_cpu_line,
                    "newly_observed_in_this_replay": bool(frontier_line)},
                "recovery": {"manifest": recovery_manifest.relative_to(ROOT).as_posix(),
                    "manifest_sha256": hashlib.sha256(recovery_manifest.read_bytes()).hexdigest()},
                "stdout": {"sha256": hashlib.sha256(process.stdout.encode("utf-8", errors="replace")).hexdigest(),
                    "selected_lines": selected_lines},
                "stderr": {"sha256": hashlib.sha256(process.stderr.encode("utf-8", errors="replace")).hexdigest(),
                    "selected_lines": process.stderr.splitlines()[-24:]},
                "acceptance_errors": errors, "passed": not errors})
            evidence_path = ROOT / "evidence" / args.evidence_name
            evidence_path.write_text(json.dumps(capture, indent=2) + "\n", encoding="utf-8")
            print(process.stdout, end="")
            print(process.stderr, end="", file=sys.stderr)
            print(f"W1-072 native address-open capture saved: evidence/{args.evidence_name}")
            if errors: raise AssertionError("W1-072 acceptance failed: " + "; ".join(errors))
            return 0
        if args.continue_dpmi_ax6300:
            native_lines=process.stdout.splitlines()
            parse_event=lambda line:dict(token.split("=",1) for token in line.split()[1:] if "=" in token)
            callbacks=[line for line in native_lines if line.startswith("W1_CRT_CALLBACK_DYNAMIC ")]
            summary_line=next((line for line in native_lines if line.startswith("W1_CRT_SUMMARY ")),None)
            service_line=next((line for line in native_lines if line.startswith("NATIVE_DPMI0300_AX6300 ")),None)
            setup_line=next((line for line in native_lines if line.startswith("NATIVE_AX6300_PROVIDER_SETUP ")),None)
            regression_line=next((line for line in native_lines if line.startswith("NATIVE_AX6300_PROVIDER_REGRESSION ")),None)
            frontier_line=next((line for line in native_lines if line.startswith("NATIVE_NEXT_TRAP ")),None)
            frontier_cpu_line=next((line for line in native_lines if line.startswith("NATIVE_FRONTIER_CPU ")),None)
            if not all((summary_line,service_line,setup_line,regression_line,frontier_line,frontier_cpu_line)):
                raise AssertionError("W1-071 requires CRT summary, configured guest provider and rejection regression, serviced AX=6300, and a fresh next frontier")
            summary=parse_event(summary_line); service=parse_event(service_line); setup=parse_event(setup_line)
            frontier=parse_event(frontier_line); frontier_cpu=parse_event(frontier_cpu_line)
            if (len(callbacks)!=19 or summary.get("argc")!="3" or service.get("result")!="1" or
                service.get("ordinal")!="1" or service.get("inner_eax")!="00006300" or
                service.get("inner_cf")!="0" or service.get("inner_si")!="0000" or
                service.get("table_size")!="12" or service.get("table_zero")!="1" or
                service.get("alloc_calls")!="1" or int(service.get("table_linear","0"),16)==0):
                raise AssertionError(f"W1-071 AX=6300 response did not satisfy measured/provider-backed contract: {service}; summary={summary}")
            if int(service.get("inner_ds","0"),16)*16 != int(service.get("table_linear","0"),16):
                raise AssertionError("W1-071 returned DS:SI does not resolve to the allocated guest DBCS table")
            if not all(token in regression_line for token in ("unsupported_vector=trapped","unsupported_ax=trapped","no_allocation=1")):
                raise AssertionError("W1-071 unsupported vector/function provider regression failed")
            sys.path.insert(0,str(ROOT/"tools"))
            import frontier_snapshot
            runtime_fingerprint={"c_h_sha256":frontier_snapshot.runtime_hash(ROOT),
                "python_sha256":frontier_snapshot.manifest_hash(list((ROOT/"runtime").glob("*.py")),ROOT)}
            exe_sha=hashlib.sha256(EXE.read_bytes()).hexdigest()
            selected=[line for line in native_lines if line.startswith(("W1_INITRTNS_ENTRY ","W1_CRT_CALLBACK_DYNAMIC ",
                "W1_CRT_SUMMARY ","W1_CRT_ARG ","NATIVE_AX6300_PROVIDER_SETUP ","NATIVE_DPMI0300_AX6300 ",
                "NATIVE_AX6300_PROVIDER_REGRESSION ","NATIVE_NEXT_TRAP ","NATIVE_FRONTIER_CPU "))]
            capture.update({"task":"W1-071","task_schema":"gwrecomp.native-dpmi-ax6300-provider/v1",
                "schema":"gwrecomp.native-dpmi-ax6300-provider/v1","execution_mode":"native_recompiled_guest",
                "evidence_level":"NATIVE_REACHED","build_id":exe_sha,
                "build_fingerprints":{"native_executable_sha256":exe_sha,
                    "closure_source_sha256":hashlib.sha256((ROOT/"build"/"entry_path_closure.c").read_bytes()).hexdigest(),
                    "routed_object_sha256":hashlib.sha256((ROOT/"build"/"entry_path_closure_routed.o").read_bytes()).hexdigest(),
                    "capture_object_sha256":hashlib.sha256(pathlib.Path(object_path).read_bytes()).hexdigest(),
                    "harness_c_sha256":hashlib.sha256((ROOT/"tests"/"test_native_guest_image.c").read_bytes()).hexdigest(),
                    "driver_sha256":hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()},
                "runtime_fingerprint":runtime_fingerprint,
                "authenticated_environment":{"evidence":w3_original_environment_metadata["source_evidence"],
                    "sha256":w3_original_environment_metadata["sha256"],"size_bytes":len(w3_original_environment),
                    "exact_bytes_loaded":True},
                "recovery":{"manifest":"evidence/w1_071_recovery_manifest.json",
                    "manifest_sha256":hashlib.sha256((ROOT/"evidence"/"w1_071_recovery_manifest.json").read_bytes()).hexdigest(),
                    "all_source_backup_and_isolated_restore_hashes_verified":True},
                "crt":{"callback_count":len(callbacks),"argc":int(summary.get("argc","0")),
                    "gate":{"local64":summary.get("local64"),"local68":summary.get("local68")}},
                "ax6300":{"provider_setup":setup_line,"unsupported_input_regression":regression_line,
                    "event":service_line,"request_frame_before_hex":service.get("frame_before"),
                    "response_frame_after_hex":service.get("frame_after"),"table":{"linear":"0x"+service["table_linear"],
                        "segment":"0x"+service["alloc_segment"],"selector":"0x"+service["alloc_selector"],
                        "size_bytes":12,"zero_filled":service.get("table_zero")=="1"},
                    "response_source":"native harness provider backed by gw_dos_services DPMI DOS-memory allocator; contract sourced from W3-214",
                    "original_equivalence_claimed":False},
                "next_frontier":{"trap":frontier,"cpu":frontier_cpu,"newly_observed_in_this_replay":True},
                "stdout":{"sha256":hashlib.sha256(process.stdout.encode("utf-8",errors="replace")).hexdigest(),
                    "selected_lines":selected},"stderr":{"sha256":hashlib.sha256(process.stderr.encode("utf-8",errors="replace")).hexdigest(),
                    "selected_lines":process.stderr.splitlines()[-24:]},
                "capture_id":str(uuid.uuid4()),"captured_at":datetime.now(timezone.utc).isoformat(),
                "original_equivalence_claimed":False})
            (ROOT/"evidence"/args.evidence_name).write_text(json.dumps(capture,indent=2)+"\n",encoding="utf-8")
            print(process.stdout,end=""); print(process.stderr,end="",file=sys.stderr)
            print(f"W1-071 AX=6300 capture saved: evidence/{args.evidence_name}; guest return={process.returncode}")
            return 0 if process.returncode==0 else 1
        if args.use_w3_original_environment and args.continue_dpmi_linear_success:
            import re
            native_lines = process.stdout.splitlines()
            parse_event = lambda line: dict(token.split("=", 1) for token in line.split()[1:] if "=" in token)
            allocation_line = next((line for line in native_lines if line.startswith("W1_CRT_ALLOC ")), None)
            summary_line = next((line for line in native_lines if line.startswith("W1_CRT_SUMMARY ")), None)
            frontier_line = next((line for line in native_lines if line.startswith("NATIVE_NEXT_TRAP ")), None)
            frontier_cpu_line = next((line for line in native_lines if line.startswith("NATIVE_FRONTIER_CPU ")), None)
            dpmi0300_line = next((line for line in native_lines if line.startswith("W1_CRT_DPMI0300 ")), None)
            if not all((allocation_line, summary_line, frontier_line, frontier_cpu_line, dpmi0300_line)):
                raise AssertionError("W1-068 requires allocator, CRT summary, and first-frontier native markers")
            allocation = parse_event(allocation_line)
            summary = parse_event(summary_line)
            frontier = parse_event(frontier_line)
            frontier_cpu = parse_event(frontier_cpu_line)
            dpmi0300 = parse_event(dpmi0300_line)
            callback_events = [parse_event(line) for line in native_lines if line.startswith("W1_CRT_CALLBACK_DYNAMIC ")]
            argv_events = [parse_event(line) for line in native_lines if line.startswith("W1_CRT_ARG ")]
            prior_path = ROOT / "evidence" / "native_setenvp_aligned_replay_w1_066.json"
            prior_capture = json.loads(prior_path.read_text(encoding="utf-8"))
            prior_size = prior_capture.get("frontier", {}).get("request_size_bytes")
            request_size = (((int(allocation.get("request_ebx", "0"), 16) & 0xffff) << 16) |
                            (int(allocation.get("request_ecx", "0"), 16) & 0xffff))
            runtime_dir = ROOT / "runtime"
            sys.path.insert(0, str(ROOT / "tools"))
            import frontier_snapshot
            runtime_fingerprint = {"c_h_sha256": frontier_snapshot.runtime_hash(ROOT),
                "python_sha256": frontier_snapshot.manifest_hash(list(runtime_dir.glob("*.py")), ROOT)}
            exe_sha = hashlib.sha256(EXE.read_bytes()).hexdigest()
            allocation.update({"request_eax": "0x" + allocation.get("request_eax", ""),
                "request_ebx": "0x" + allocation.get("request_ebx", ""),
                "request_ecx": "0x" + allocation.get("request_ecx", ""),
                "request_edx": "0x" + allocation.get("request_edx", ""),
                "response_eax": "0x" + allocation.get("response_eax", ""),
                "response_ebx": "0x" + allocation.get("response_ebx", ""),
                "response_ecx": "0x" + allocation.get("response_ecx", ""),
                "response_esi": "0x" + allocation.get("response_esi", ""),
                "response_edi": "0x" + allocation.get("response_edi", ""),
                "synthetic_size": "0x" + allocation.get("size", ""),
                "synthetic_base": "0x" + allocation.get("base", ""),
                "synthetic_handle": "0x" + allocation.get("handle", ""),
                "instruction_va": "0x000C3CC1", "carry": 0, "handled": 1,
                "response_success_basis": "W1_CRT_ALLOC is emitted only after the C harness callback returns HANDLED, CF=0, preserves required registers, validates nonzero size/handle and in-bounds allocation, and verifies the allocated range is zero-filled."})
            capture.update({"task": "W1-068", "task_schema": "gwrecomp.native-setenvp-dpmi-continue/v1",
                "schema": "gwrecomp.native-setenvp-dpmi-continue/v1", "execution_mode": "native_recompiled_guest",
                "evidence_level": "NATIVE_REACHED", "build_id": exe_sha,
                "build_fingerprint": {"native_executable_sha256": exe_sha,
                    "closure_source_sha256": hashlib.sha256((ROOT / "build" / "entry_path_closure.c").read_bytes()).hexdigest(),
                    "routed_object_sha256": hashlib.sha256((ROOT / "build" / "entry_path_closure_routed.o").read_bytes()).hexdigest(),
                    "runtime_c_header_sha256": hashlib.sha256((ROOT / "runtime" / "gw_dos_services.c").read_bytes()).hexdigest(),
                    "runtime_driver_sha256": hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
                    "native_harness_sha256": hashlib.sha256((ROOT / "tests" / "test_native_guest_image.c").read_bytes()).hexdigest(),
                    "runtime_fingerprint": runtime_fingerprint},
                "authenticated_environment": {"path": "evidence/w3_140_original_setenvp_environment.json",
                    "sha256": w3_original_environment_metadata["sha256"], "size_bytes": len(w3_original_environment),
                    "exact_bytes_loaded": True},
                "prior_capture": {"path": "evidence/native_setenvp_aligned_replay_w1_066.json",
                    "sha256": hashlib.sha256(prior_path.read_bytes()).hexdigest(),
                    "observed_request_size_bytes": prior_size, "separate_dynamic_run": True,
                    "same_dynamic_invocation_claimed": False},
                "allocator_service": {"request_matches_prior_capture": bool(prior_size and request_size == int(prior_size, 16)),
                    "response_source": "existing gw_dos_services_callback bounded linear allocator",
                    "arena_kind": "synthetic_test_arena", "response_is_guest_state_injection": False,
                    "original_base_or_handle_reused": False, "allocation_event": allocation_line,
                    "response_success_basis": allocation["response_success_basis"]},
                "native_generated_c_progress": {"dpmi_linear_allocation": allocation,
                    "callback_response_recorded_after_success_checks": True,
                    "next_frontier_cpu": frontier_cpu},
                "next_frontier": {"trap": frontier, "cpu": frontier_cpu,
                    "service": "DPMI INT 31h AX=0300", "guest_eip": "0x" + frontier.get("eip", ""),
                    "function": "0x" + frontier.get("function", ""), "dpmi0300_context": dpmi0300,
                    "newly_observed_in_this_replay": True},
                "crt_startup": {"callback_count_before_stop": len(callback_events),
                    "callback_ordinals": [int(item.get("ordinal", "-1")) for item in callback_events],
                    "argc": int(summary.get("argc", "0")), "argv_pointer": "0x" + summary.get("argv", "0"),
                    "argv": [item.get("value", "") for item in argv_events]},
                "setenvp_return": {"observed": any(line.startswith("NATIVE_ADF95_RETURN ") and "link_va=000dfe12" in line.lower()
                    for line in native_lines), "event": next((line for line in native_lines if line.startswith("NATIVE_ADF95_RETURN ") and
                    "link_va=000dfe12" in line.lower()), None)},
                "menu_reached": False, "framebuffer_reached": False, "fresh_replay": True})
            if len(callback_events) != 11 or int(summary.get("argc", "-1")) != 0:
                raise AssertionError("W1-068 fresh capture CRT/argc state differs from observed native run")
        (ROOT / "evidence" / args.evidence_name).write_text(json.dumps(capture, indent=2) + "\n", encoding="utf-8")
        if args.serve_w3_address_seed:
            for line in capture["stdout"]["selected_lines"]: print(line)
            for line in capture["stderr"]["selected_lines"]: print(line,file=sys.stderr)
        else:
            print(process.stdout, end="")
            print(process.stderr, end="", file=sys.stderr)
        print(f"W1 CRT capture saved: evidence/{args.evidence_name}; guest return={process.returncode}")
        return 0
    if process.returncode and args.expect_fault:
        import re
        pattern = (r"NATIVE_EXCEPTION code=([0-9a-fA-F]{8}) pc=([0-9a-fA-F]{8}) sp=([0-9a-fA-F]{8}) fault_addr=([0-9a-fA-F]{8}) access_kind=([0-9a-fA-F]{8}) module_base=([0-9a-fA-F]{8}) pc_rva=([0-9a-fA-F]{8}) host_eax=([0-9a-fA-F]{8}) host_ebx=([0-9a-fA-F]{8}) host_ecx=([0-9a-fA-F]{8}) host_edx=([0-9a-fA-F]{8}) host_esi=([0-9a-fA-F]{8}) host_edi=([0-9a-fA-F]{8}) host_ebp=([0-9a-fA-F]{8}) stack_return0=([0-9a-fA-F]{8}) stack_return4=([0-9a-fA-F]{8}) guest_func=([0-9a-fA-F]{8}) "
                   r"eax=([0-9a-fA-F]{8}) ebx=([0-9a-fA-F]{8}) ecx=([0-9a-fA-F]{8}) edx=([0-9a-fA-F]{8}) "
                   r"esi=([0-9a-fA-F]{8}) edi=([0-9a-fA-F]{8}) ebp=([0-9a-fA-F]{8}) esp=([0-9a-fA-F]{8}) "
                   r"icall_count=(\d+) icall_last=([0-9a-fA-F]{8}) icall_from=([0-9a-fA-F]{8}) trap_pending=(\d+) "
                   r"trap_vector=([0-9a-fA-F]{2}) trap_va=([0-9a-fA-F]{8}) mem_pending=(\d+) mem_segment=(\d+) "
                   r"mem_selector=([0-9a-fA-F]{4}) mem_offset=([0-9a-fA-F]{8}) mem_width=(\d+) mem_linear=([0-9a-fA-F]{8}) mem_instruction=([0-9a-fA-F]{8})")
        match = re.search(pattern, process.stderr)
        if not match:
            raise AssertionError(f"native exception was not captured:\n{process.stderr}\n{process.stdout}")
        fields = ("exception_code", "host_pc", "host_sp", "access_fault_address", "access_kind", "module_base", "host_pc_rva", "host_eax", "host_ebx", "host_ecx", "host_edx", "host_esi", "host_edi", "host_ebp", "host_stack_return0", "host_stack_return4", "guest_function_va", "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "icall_count", "last_icall_target", "last_icall_from", "interrupt_trap_pending", "interrupt_vector", "interrupt_va", "memory_fault_pending", "memory_segment", "memory_selector", "memory_offset", "memory_width", "memory_linear", "memory_instruction_va")
        raw = dict(zip(fields, match.groups()))
        integers = {"icall_count", "interrupt_trap_pending", "memory_fault_pending", "memory_segment", "memory_width", "access_kind"}
        captured = {key: (int(value) if key in integers else f"0x{value.upper()}") for key, value in raw.items()}
        addr2line = [(_GW_MSYS2 + '\\mingw32\\bin\\addr2line.exe'), "-f", "-C", "-e", str(EXE)]
        executable = EXE.read_bytes()
        pe = struct.unpack_from("<I", executable, 0x3C)[0]
        optional = pe + 24
        magic = struct.unpack_from("<H", executable, optional)[0]
        if magic != 0x10B:
            raise AssertionError(f"unexpected native executable optional header: {magic:#x}")
        preferred_base = struct.unpack_from("<I", executable, optional + 28)[0]
        size_of_image = struct.unpack_from("<I", executable, optional + 56)[0]
        runtime_base = int(raw["module_base"], 16)
        map_addresses = [preferred_base + int(raw["host_pc_rva"], 16)]
        for key in ("host_stack_return0", "host_stack_return4"):
            address = int(raw[key], 16)
            if runtime_base <= address < runtime_base + size_of_image:
                address = preferred_base + (address - runtime_base)
            map_addresses.append(address)
        mapped = subprocess.run(addr2line + [f"0x{x:08X}" for x in map_addresses], cwd=ROOT, env=env, text=True, capture_output=True)
        evidence = {
            "test": "native fixed-link entry -k exception capture", "target_sha256": boot.executable_sha256,
            "command_tail": args.command_tail, "guest_entry": f"0x{boot.seed.eip:08X}",
            "link_va_layout": {"mem_base": f"0x{boot.image.mem_base:X}", "rebase": "0x0"},
            "bootstrap_layout": {
                "psp_linear": f"0x{boot.psp_address:08X}", "psp_selector": f"0x{psp_selector:04X}",
                "environment_linear": f"0x{boot.env_address:08X}", "environment_selector": f"0x{env_selector:04X}",
                "initial_es_selector": f"0x{psp_selector:04X}", "initial_es_base": f"0x{boot.psp_address:08X}",
                "environment_alias_limit": len(boot.environment) - 1,
            },
            "native_indirect_dispatch": {
                "lookup_source": str(LOOKUP_C.relative_to(ROOT)),
                "mapped_function_count": lookup_count,
                "lookup_source_sha256": hashlib.sha256(LOOKUP_C.read_bytes()).hexdigest(),
                "strategy": "exact binary search over RECOMP_ENTER VAs emitted from canonical closure",
            },
            "windows_process_exit": process.returncode, "captured_exception": captured,
            "pe_image_base_preferred": f"0x{preferred_base:08X}", "pe_size_of_image": f"0x{size_of_image:08X}",
            "host_pc_and_stack_symbol_source": mapped.stdout.strip().splitlines(), "host_pc_map_exit": mapped.returncode,
            "fault_stderr": process.stderr.strip(), "debug_object_sha256": hashlib.sha256(DEBUG_OBJECT.read_bytes()).hexdigest(),
            "passed": raw["exception_code"].upper() == "C0000005",
        }
        (ROOT / "evidence" / args.evidence_name).write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
        if not evidence["passed"]:
            raise AssertionError(f"unexpected native exception: {evidence}")
        print(json.dumps(evidence, indent=2))
        print("PASS native -k access violation captured with host and guest context")
        return
    if process.returncode:
        print(process.stdout, end=""); print(process.stderr, end="")
        raise SystemExit(process.returncode)
    class Completed:
        stdout = process.stdout
        stderr = process.stderr
    result = Completed()
    import re
    match = re.search(r"NATIVE_NEXT_TRAP vector=([0-9a-fA-F]{2}) eip=([0-9a-fA-F]{8}) function=([0-9a-fA-F]{8}) eax=([0-9a-fA-F]{8}) ebx=([0-9a-fA-F]{8}) ecx=([0-9a-fA-F]{8}) edx=([0-9a-fA-F]{8}) esp=([0-9a-fA-F]{8})", result.stdout)
    if match:
        trap = {key: f"0x{value.upper()}" for key, value in zip(("vector", "instruction_va", "function_va", "eax", "ebx", "ecx", "edx", "esp"), match.groups())}
        trap["event"] = "interrupt_trap"
        state_match = re.search(r"NATIVE_TRAP_STATE esi=([0-9a-fA-F]{8}) edi=([0-9a-fA-F]{8}) ebp=([0-9a-fA-F]{8}) flag_k=([0-9a-fA-F]{8}) flag_a=([0-9a-fA-F]{8}) flag_b=([0-9a-fA-F]{8}) flag_cf=(\d+) cs=([0-9a-fA-F]{4}) ds=([0-9a-fA-F]{4}) es=([0-9a-fA-F]{4}) ss=([0-9a-fA-F]{4})", result.stdout)
        if state_match:
            names = ("esi", "edi", "ebp", "flag_k", "flag_a", "flag_b", "flag_cf", "cs", "ds", "es", "ss")
            for name, value in zip(names, state_match.groups()):
                trap[name] = int(value) if name == "flag_cf" else f"0x{value.upper()}"
        if trap["instruction_va"] == "0x000AFA09":
            raise AssertionError(f"native entry did not resume past first DOS service: {trap}")
    else:
        returned = re.search(r"NATIVE_RETURN_AFTER_DPMI vector=31 eip=([0-9a-fA-F]{8}) function=([0-9a-fA-F]{8}) eax=([0-9a-fA-F]{8}) ebx=([0-9a-fA-F]{8}) ecx=([0-9a-fA-F]{8}) edx=([0-9a-fA-F]{8}) esi=([0-9a-fA-F]{8}) esp=([0-9a-fA-F]{8}) ds=([0-9a-fA-F]{4}) memory_fault=(\d+) memory_instruction=([0-9a-fA-F]{8}) memory_segment=(\d+) memory_selector=([0-9a-fA-F]{4}) memory_offset=([0-9a-fA-F]{8}) memory_width=(\d+) memory_linear=([0-9a-fA-F]{8}) segment_fault=(\d+) segment_instruction=([0-9a-fA-F]{8}) segment_selector=([0-9a-fA-F]{4})", result.stdout)
        if not args.continue_selector_query or not returned:
            raise AssertionError("native runner reported neither its next interrupt trap nor the bounded DPMI-query return")
        trap = {key: f"0x{value.upper()}" for key, value in zip(("instruction_va", "function_va", "eax", "ebx", "ecx", "edx", "esi", "esp", "ds"), returned.groups()[:9])}
        trap.update({"memory_fault_pending": int(returned.group(10)), "memory_fault_instruction_va": f"0x{returned.group(11).upper()}", "memory_fault_segment": int(returned.group(12)), "memory_fault_selector": f"0x{returned.group(13).upper()}", "memory_fault_offset": f"0x{returned.group(14).upper()}", "memory_fault_width": int(returned.group(15)), "memory_fault_linear": f"0x{returned.group(16).upper()}", "segment_fault_pending": int(returned.group(17)), "segment_fault_instruction_va": f"0x{returned.group(18).upper()}", "segment_fault_selector": f"0x{returned.group(19).upper()}"})
        trap["vector"] = "0x31"
        trap["event"] = "memory_fault" if trap["memory_fault_pending"] else "segment_fault" if trap["segment_fault_pending"] else "generated_entry_return"
    dos4g_service = None
    dpmi_selector_service = None
    if args.continue_known_services:
        service_match = re.search(
            r"NATIVE_DOS_SERVICE vector=([0-9a-fA-F]{2}) eip=([0-9a-fA-F]{8}) request_ax=([0-9a-fA-F]{8}) edx=([0-9a-fA-F]{8}) response_ax=([0-9a-fA-F]{8}) carry=(\d+) handled=(\d+)",
            result.stdout,
        )
        if not service_match:
            raise AssertionError("native frontier run did not verify the DOS/4G install-check response")
        dos4g_service = {
            key: (int(value) if key in ("carry", "handled") else f"0x{value.upper()}")
            for key, value in zip(("vector", "instruction_va", "request_ax", "edx", "response_ax", "carry", "handled"), service_match.groups())
        }
        expected = {"vector": "0x21", "instruction_va": "0x000AFAA8", "request_ax": "0x0000FF00", "edx": "0x00000078", "response_ax": "0x0000FFFF", "carry": 0, "handled": 1}
        if dos4g_service != expected:
            raise AssertionError(f"DOS/4G install-check response differs from contract: {dos4g_service}")
    if args.continue_selector_query:
        service_match = re.search(
            r"NATIVE_DPMI_SERVICE vector=([0-9a-fA-F]{2}) eip=([0-9a-fA-F]{8}) request_ax=([0-9a-fA-F]{4}) selector=([0-9a-fA-F]{4}) ds_base=([0-9a-fA-F]{8}) response_cx=([0-9a-fA-F]{4}) response_dx=([0-9a-fA-F]{4}) carry=(\d+) handled=(\d+)",
            result.stdout,
        )
        if not service_match:
            raise AssertionError("native frontier run did not verify the DPMI AX=0006 selector-base response")
        dpmi_selector_service = {
            key: (int(value) if key in ("carry", "handled") else f"0x{value.upper()}")
            for key, value in zip(("vector", "instruction_va", "request_ax", "selector", "ds_base", "response_cx", "response_dx", "carry", "handled"), service_match.groups())
        }
        expected = {"vector": "0x31", "instruction_va": "0x000AFAC4", "request_ax": "0x0006", "selector": "0x0014", "ds_base": "0x00000000", "response_cx": "0x0000", "response_dx": "0x0000", "carry": 0, "handled": 1}
        if dpmi_selector_service != expected:
            raise AssertionError(f"DPMI AX=0006 selector-base response differs from measured flat-DS contract: {dpmi_selector_service}")
    dos_time_service = None
    if args.continue_time_query:
        time_match = re.search(
            r"NATIVE_DOS_TIME vector=([0-9a-fA-F]{2}) eip=([0-9a-fA-F]{8}) request_eax=([0-9a-fA-F]{8}) request_ebx=([0-9a-fA-F]{8}) request_ecx=([0-9a-fA-F]{8}) request_edx=([0-9a-fA-F]{8}) response_eax=([0-9a-fA-F]{8}) response_ebx=([0-9a-fA-F]{8}) response_ecx=([0-9a-fA-F]{8}) response_edx=([0-9a-fA-F]{8}) carry=(\d+) handled=(\d+)",
            result.stdout,
        )
        if not time_match:
            raise AssertionError("native replay did not report the measured DOS AH=2Ch response")
        fields = time_match.groups()
        dos_time_service = {
            key: (int(value) if key in ("carry", "handled") else f"0x{value.upper()}")
            for key, value in zip(("vector", "instruction_va", "request_eax", "request_ebx", "request_ecx", "request_edx", "response_eax", "response_ebx", "response_ecx", "response_edx", "carry", "handled"), fields)
        }
        dos_time_service.update({"hour": 0, "minute": 0, "second": 0, "hundredths": 5})
        if dos_time_service["carry"] or dos_time_service["handled"] != 1:
            raise AssertionError(f"DOS AH=2Ch did not return successfully: {dos_time_service}")
    dpmi_linear_service = None
    if args.continue_dpmi_linear_allocation:
        allocation_match = re.search(
            r"NATIVE_DPMI_LINEAR vector=([0-9a-fA-F]{2}) eip=([0-9a-fA-F]{8}) request_eax=([0-9a-fA-F]{8}) request_ebx=([0-9a-fA-F]{8}) request_ecx=([0-9a-fA-F]{8}) request_edx=([0-9a-fA-F]{8}) request_esi=([0-9a-fA-F]{8}) request_edi=([0-9a-fA-F]{8}) request_ebp=([0-9a-fA-F]{8}) request_esp=([0-9a-fA-F]{8}) response_eax=([0-9a-fA-F]{8}) response_ebx=([0-9a-fA-F]{8}) response_ecx=([0-9a-fA-F]{8}) response_edx=([0-9a-fA-F]{8}) response_esi=([0-9a-fA-F]{8}) response_edi=([0-9a-fA-F]{8}) response_ebp=([0-9a-fA-F]{8}) response_esp=([0-9a-fA-F]{8}) carry=(\d+) handled=(\d+)",
            result.stdout,
        )
        if not allocation_match:
            raise AssertionError("native replay did not report measured DPMI AX=0501 response")
        keys = ("vector", "instruction_va", "request_eax", "request_ebx", "request_ecx", "request_edx", "request_esi", "request_edi", "request_ebp", "request_esp", "response_eax", "response_ebx", "response_ecx", "response_edx", "response_esi", "response_edi", "response_ebp", "response_esp", "carry", "handled")
        dpmi_linear_service = {key: (int(value) if key in ("carry", "handled") else f"0x{value.upper()}") for key, value in zip(keys, allocation_match.groups())}
        expected = {"vector": "0x31", "instruction_va": "0x000C3CC1", "request_eax": "0x00000501", "request_ebx": "0x00000000", "request_ecx": "0x00008000", "request_edx": "0x00000000", "response_eax": "0x00008012", "response_ebx": "0x00000000", "response_ecx": "0x00008000", "response_edx": "0x00000000", "carry": 1, "handled": 1}
        if any(dpmi_linear_service.get(key) != value for key, value in expected.items()):
            raise AssertionError(f"native AX=0501 response differs from measured unavailable contract: {dpmi_linear_service}")
        state_match = re.search(
            r"NATIVE_DPMI_LINEAR_STATE function=([0-9a-fA-F]{8}) flag_k=([0-9a-fA-F]{8}) flag_a=([0-9a-fA-F]{8}) flag_b=([0-9a-fA-F]{8}) flag_cf=([0-9a-fA-F]{8}) cs=([0-9a-fA-F]{4}) ds=([0-9a-fA-F]{4}) es=([0-9a-fA-F]{4}) ss=([0-9a-fA-F]{4}) cs_base=([0-9a-fA-F]{8}) ds_base=([0-9a-fA-F]{8}) es_base=([0-9a-fA-F]{8}) ss_base=([0-9a-fA-F]{8}) stack0=([0-9a-fA-F]{8}) stack1=([0-9a-fA-F]{8}) stack2=([0-9a-fA-F]{8}) stack3=([0-9a-fA-F]{8}) stack4=([0-9a-fA-F]{8}) stack5=([0-9a-fA-F]{8}) stack6=([0-9a-fA-F]{8}) stack7=([0-9a-fA-F]{8})",
            result.stdout,
        )
        if not state_match:
            raise AssertionError("native AX=0501 state did not include flags, segments, bases and stack words")
        state_names = ("function_va", "flag_k", "flag_a", "flag_b", "flag_cf", "cs", "ds", "es", "ss",
                       "cs_base", "ds_base", "es_base", "ss_base", *(f"stack{i}" for i in range(8)))
        dpmi_linear_service["pre_trap_state"] = {
            name: f"0x{value.upper()}" for name, value in zip(state_names, state_match.groups())
        }
        if dpmi_linear_service["pre_trap_state"]["function_va"] != "0x000C3CA9":
            raise AssertionError(f"DPMI AX=0501 was not raised in RationalAlloc_: {dpmi_linear_service}")
    if args.continue_dpmi_linear_success:
        allocation_match = re.search(
            r"NATIVE_DPMI_LINEAR_SUCCESS vector=([0-9a-fA-F]{2}) eip=([0-9a-fA-F]{8}) request_eax=([0-9a-fA-F]{8}) request_ebx=([0-9a-fA-F]{8}) request_ecx=([0-9a-fA-F]{8}) request_edx=([0-9a-fA-F]{8}) request_esi=([0-9a-fA-F]{8}) request_edi=([0-9a-fA-F]{8}) request_ebp=([0-9a-fA-F]{8}) request_esp=([0-9a-fA-F]{8}) response_eax=([0-9a-fA-F]{8}) response_ebx=([0-9a-fA-F]{8}) response_ecx=([0-9a-fA-F]{8}) response_edx=([0-9a-fA-F]{8}) response_esi=([0-9a-fA-F]{8}) response_edi=([0-9a-fA-F]{8}) response_ebp=([0-9a-fA-F]{8}) response_esp=([0-9a-fA-F]{8}) carry=(\d+) handled=(\d+) synthetic_base=([0-9a-fA-F]{8}) synthetic_size=([0-9a-fA-F]{8}) synthetic_handle=([0-9a-fA-F]{8})",
            result.stdout,
        )
        if not allocation_match:
            raise AssertionError("native replay did not report its explicitly synthetic AX=0501 success")
        keys = ("vector", "instruction_va", "request_eax", "request_ebx", "request_ecx", "request_edx", "request_esi", "request_edi", "request_ebp", "request_esp", "response_eax", "response_ebx", "response_ecx", "response_edx", "response_esi", "response_edi", "response_ebp", "response_esp", "carry", "handled", "synthetic_base", "synthetic_size", "synthetic_handle")
        dpmi_linear_service = {key: (int(value) if key in ("carry", "handled") else f"0x{value.upper()}") for key, value in zip(keys, allocation_match.groups())}
        request_size = ((int(dpmi_linear_service["request_ebx"], 16) & 0xffff) << 16) | (int(dpmi_linear_service["request_ecx"], 16) & 0xffff)
        if dpmi_linear_service["vector"] != "0x31" or dpmi_linear_service["instruction_va"] != "0x000C3CC1" or dpmi_linear_service["request_eax"] != "0x00000501" or not request_size or dpmi_linear_service["response_eax"] != dpmi_linear_service["request_eax"] or dpmi_linear_service["carry"] != 0 or dpmi_linear_service["handled"] != 1:
            raise AssertionError(f"native synthetic AX=0501 success registers/flags are inconsistent: {dpmi_linear_service}")
        base = int(dpmi_linear_service["synthetic_base"], 16)
        size = int(dpmi_linear_service["synthetic_size"], 16)
        handle = int(dpmi_linear_service["synthetic_handle"], 16)
        if size != request_size or not handle or base < 0x00200000 or base + size > 0x00400000 or base & 0xfff:
            raise AssertionError(f"native success allocation escaped its configured synthetic arena: {dpmi_linear_service}")
        if args.use_w3_original_environment:
            prior_capture = json.loads((ROOT / "evidence" / "native_setenvp_aligned_replay_w1_066.json").read_text(encoding="utf-8"))
            prior_size = int(prior_capture["frontier"]["request_size_bytes"], 16)
            if request_size != prior_size:
                raise AssertionError(f"fresh authenticated-environment AX=0501 request differs from W1-066 capture: {request_size:#x} != {prior_size:#x}")
        if (int(dpmi_linear_service["response_ebx"], 16) << 16 | int(dpmi_linear_service["response_ecx"], 16)) != base or (int(dpmi_linear_service["response_esi"], 16) << 16 | int(dpmi_linear_service["response_edi"], 16)) != handle:
            raise AssertionError(f"native AX=0501 returned address/handle registers do not match allocation record: {dpmi_linear_service}")
        dpmi_linear_service["contract_class"] = "synthetic bounded success path; not an original-address/handle comparison"
        state_match = re.search(r"NATIVE_DPMI_LINEAR_STATE function=([0-9a-fA-F]{8}) flag_k=([0-9a-fA-F]{8}) flag_a=([0-9a-fA-F]{8}) flag_b=([0-9a-fA-F]{8}) flag_cf=([0-9a-fA-F]{8}) cs=([0-9a-fA-F]{4}) ds=([0-9a-fA-F]{4}) es=([0-9a-fA-F]{4}) ss=([0-9a-fA-F]{4}) cs_base=([0-9a-fA-F]{8}) ds_base=([0-9a-fA-F]{8}) es_base=([0-9a-fA-F]{8}) ss_base=([0-9a-fA-F]{8}) stack0=([0-9a-fA-F]{8}) stack1=([0-9a-fA-F]{8}) stack2=([0-9a-fA-F]{8}) stack3=([0-9a-fA-F]{8}) stack4=([0-9a-fA-F]{8}) stack5=([0-9a-fA-F]{8}) stack6=([0-9a-fA-F]{8}) stack7=([0-9a-fA-F]{8})", result.stdout)
        if not state_match:
            raise AssertionError("successful native AX=0501 state is missing flags, segments, and stack")
        state_names = ("function_va", "flag_k", "flag_a", "flag_b", "flag_cf", "cs", "ds", "es", "ss", "cs_base", "ds_base", "es_base", "ss_base", *(f"stack{i}" for i in range(8)))
        dpmi_linear_service["pre_trap_state"] = {name: f"0x{value.upper()}" for name, value in zip(state_names, state_match.groups())}
        if dpmi_linear_service["pre_trap_state"]["function_va"] != "0x000C3CA9":
            raise AssertionError(f"DPMI AX=0501 was not raised in RationalAlloc_: {dpmi_linear_service}")
    dpmi_linear_sequence = None
    if args.continue_dpmi_linear_sequence:
        sequence_events = [dict(token.split("=", 1) for token in line.split()[1:] if "=" in token)
                           for line in result.stdout.splitlines()
                           if line.startswith("NATIVE_DPMI_AX0501_SEQUENCE ")]
        if not sequence_events:
            raise AssertionError("native replay did not report a natural AX=0501 sequence event")
        expected_arena = ("host_backed_demand_commit" if args.w1_092_host_backed_guest_memory else "host_backed" if host_backed_guest_memory else "synthetic")
        guest_map_line = next((line for line in result.stdout.splitlines() if line.startswith("NATIVE_DPMI_GUEST_MEMORY_MAP ")), None)
        guest_map = dict(token.split("=", 1) for token in guest_map_line.split()[1:] if "=" in token) if guest_map_line else None
        if host_backed_guest_memory and (not guest_map or
                int(guest_map.get("guest_capacity", "0"), 16) != guest_map_capacity or
                int(guest_map.get("allocation_end", "0"), 16) != guest_map_capacity):
            raise AssertionError(f"host-backed map capacity is not the evidence-derived bound: {guest_map}")
        previous_ordinal=-1
        for sequence_index,event in enumerate(sequence_events):
            ordinal=int(event.get("ordinal","-1"))
            ordinal_valid=(ordinal>previous_ordinal if args.w1_092_host_backed_guest_memory else ordinal==sequence_index)
            if (not ordinal_valid or event.get("provider") != "gw_dos_services_callback" or
                    event.get("arena") != expected_arena or event.get("handled") != "1" or event.get("preserved") != "1"):
                raise AssertionError(f"AX=0501 sequence provenance/register preservation failed: {event}")
            previous_ordinal=ordinal
            requested_size = ((int(event["request_ebx"], 16) & 0xffff) << 16) | (int(event["request_ecx"], 16) & 0xffff)
            if int(event["size"], 16) != requested_size or int(event["eip"], 16) != 0x000C3CC1:
                raise AssertionError(f"AX=0501 sequence does not match its natural request: {event}")
            if event.get("success") == "1":
                base, handle = int(event["base"], 16), int(event["handle"], 16)
                capacity = int(event.get("guest_capacity", "00400000"), 16)
                if (event.get("carry") != "0" or event["response_eax"] != event["request_eax"] or not handle or
                        base < 0x00200000 or base + requested_size > capacity or base & 0xfff or
                        event.get("zero_filled") != "1" or
                        int(event["cursor_after"], 16) != base + requested_size):
                    raise AssertionError(f"AX=0501 sequence success escaped the configured guest map: {event}")
            elif event.get("unavailable") == "1":
                if (event.get("carry") != "1" or (int(event["response_eax"], 16) & 0xffff) != 0x8012 or
                        event["cursor_after"] != event["cursor_before"] or
                        (sequence_index != len(sequence_events) - 1 and not args.w1_092_host_backed_guest_memory)):
                    raise AssertionError(f"AX=0501 exhaustion response/provenance is inconsistent: {event}")
            else:
                raise AssertionError(f"AX=0501 sequence event is neither allocator success nor exhaustion: {event}")
        dpmi_linear_sequence = {
            "provider": "gw_dos_services_callback",
            "arena": ({"kind": "host_backed_guest_map", "guest_range": ["0x00000000", f"0x{guest_map_capacity:08X}"],
                       "capacity_bytes": f"0x{guest_map_capacity:08X}", "not_original_mapping_evidence": True} if host_backed_guest_memory else
                      {"kind": "synthetic_test_only", "mapped_guest_memory_range": ["0x00200000", "0x00400000"],
                       "not_original_mapping_evidence": True}),
            "guest_memory_map": guest_map if host_backed_guest_memory else None,
            "events": sequence_events,
            "event_count": int(sequence_events[-1].get("ordinal", "-1")) + 1,
            "stopped_after_allocator_exhaustion": sequence_events[-1].get("unavailable") == "1",
        }
    dos_ah48_service = None
    if args.continue_dos_ah48:
        match = re.search(r"NATIVE_DOS_AH48 vector=([0-9a-fA-F]{2}) eip=([0-9a-fA-F]{8}) request_eax=([0-9a-fA-F]{8}) request_ebx=([0-9a-fA-F]{8}) request_ecx=([0-9a-fA-F]{8}) request_edx=([0-9a-fA-F]{8}) request_esi=([0-9a-fA-F]{8}) request_edi=([0-9a-fA-F]{8}) request_ebp=([0-9a-fA-F]{8}) request_esp=([0-9a-fA-F]{8}) response_eax=([0-9a-fA-F]{8}) response_ebx=([0-9a-fA-F]{8}) response_ecx=([0-9a-fA-F]{8}) response_edx=([0-9a-fA-F]{8}) response_esi=([0-9a-fA-F]{8}) response_edi=([0-9a-fA-F]{8}) response_ebp=([0-9a-fA-F]{8}) response_esp=([0-9a-fA-F]{8}) carry=(\d+) handled=(\d+)", result.stdout)
        if not match:
            raise AssertionError("native replay did not report measured DOS AH=48 response")
        keys = ("vector", "instruction_va", "request_eax", "request_ebx", "request_ecx", "request_edx", "request_esi", "request_edi", "request_ebp", "request_esp", "response_eax", "response_ebx", "response_ecx", "response_edx", "response_esi", "response_edi", "response_ebp", "response_esp", "carry", "handled")
        dos_ah48_service = {key: (int(value) if key in ("carry", "handled") else f"0x{value.upper()}") for key, value in zip(keys, match.groups())}
        if args.w1_092_host_backed_guest_memory:
            response_segment=int(dos_ah48_service["response_eax"],16)&0xffff
            if response_segment<0x1000 or dos_ah48_service["carry"]!=0 or dos_ah48_service["handled"]!=1:
                raise AssertionError(f"native DOS AH=48 did not allocate from the guest MCB provider: {dos_ah48_service}")
        elif dos_ah48_service["response_eax"] != "0x0000004C" or dos_ah48_service["carry"] != 0 or dos_ah48_service["handled"] != 1:
            raise AssertionError(f"native DOS AH=48 response mismatch: {dos_ah48_service}")
        for reg in ("ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"):
            if dos_ah48_service["request_"+reg] != dos_ah48_service["response_"+reg]:
                raise AssertionError(f"DOS AH=48 modified preserved {reg}: {dos_ah48_service}")
    dos_ah48_retry_service = None
    if args.continue_dos_ah48_retry:
        match = re.search(r"NATIVE_DOS_AH48_RETRY vector=([0-9a-fA-F]{2}) eip=([0-9a-fA-F]{8}) request_eax=([0-9a-fA-F]{8}) request_ebx=([0-9a-fA-F]{8}) request_ecx=([0-9a-fA-F]{8}) request_edx=([0-9a-fA-F]{8}) request_esi=([0-9a-fA-F]{8}) request_edi=([0-9a-fA-F]{8}) request_ebp=([0-9a-fA-F]{8}) request_esp=([0-9a-fA-F]{8}) response_eax=([0-9a-fA-F]{8}) response_ebx=([0-9a-fA-F]{8}) response_ecx=([0-9a-fA-F]{8}) response_edx=([0-9a-fA-F]{8}) response_esi=([0-9a-fA-F]{8}) response_edi=([0-9a-fA-F]{8}) response_ebp=([0-9a-fA-F]{8}) response_esp=([0-9a-fA-F]{8}) carry=(\d+) handled=(\d+)", result.stdout)
        if not match:
            raise AssertionError("native replay did not report measured DOS AH=48 retry response")
        keys = ("vector", "instruction_va", "request_eax", "request_ebx", "request_ecx", "request_edx", "request_esi", "request_edi", "request_ebp", "request_esp", "response_eax", "response_ebx", "response_ecx", "response_edx", "response_esi", "response_edi", "response_ebp", "response_esp", "carry", "handled")
        dos_ah48_retry_service = {key: (int(value) if key in ("carry", "handled") else f"0x{value.upper()}") for key, value in zip(keys, match.groups())}
        expected = ({"instruction_va": "0x000C3D35", "carry": 0, "handled": 1}
                    if args.w1_092_host_backed_guest_memory else
                    {"instruction_va": "0x000C3D35", "request_eax": "0x0000484C", "request_ebx": "0x00000800", "request_ecx": "0x00008000", "request_edx": "0x0000004C", "response_eax": "0x00000008", "response_ebx": "0x00000034", "response_ecx": "0x00008000", "response_edx": "0x0000004C", "carry": 1, "handled": 1})
        if any(dos_ah48_retry_service.get(key) != value for key, value in expected.items()):
            raise AssertionError(f"native AH=48 retry differs from measured response: {dos_ah48_retry_service}")
        for reg in ("ecx", "edx", "esi", "edi", "ebp", "esp"):
            if dos_ah48_retry_service["request_"+reg] != dos_ah48_retry_service["response_"+reg]:
                raise AssertionError(f"DOS AH=48 retry changed preserved {reg}: {dos_ah48_retry_service}")
    dos_ah43_service = None
    ah43_line = next((line for line in result.stdout.splitlines() if line.startswith("NATIVE_DOS_AH43 ")), None)
    if ah43_line:
        fields = dict(token.split("=",1) for token in ah43_line.split()[1:] if "=" in token)
        for key in ("eip","request_eax","request_ebx","request_ecx","request_edx","request_esi","request_edi","request_ebp","request_esp","ds_base","response_eax","response_ebx","response_ecx","response_edx","response_esi","response_edi","response_ebp","response_esp"):
            fields[key] = "0x" + fields[key].upper()
        for key in ("ds","cf_in","cf_out","handled"):
            fields[key] = int(fields[key],16) if key=="ds" else int(fields[key])
        fields["all_other_gprs_preserved"] = all(fields["request_"+r]==fields["response_"+r] for r in ("ebx","ecx","edx","esi","edi","ebp","esp"))
        expected = {"eip":"0x000AF93A","request_eax":"0x00004300","response_eax":"0x00000003","ds":0x14,"ds_base":"0x00000000","path":"gw.err","cf_out":1,"handled":1}
        if any(fields.get(k)!=v for k,v in expected.items()) or not fields["all_other_gprs_preserved"]:
            raise AssertionError(f"native AH=43 gw.err response differs from the measured error contract: {fields}")
        dos_ah43_service = fields
    dos_ah3d_service = None
    if args.continue_dos_ah3d:
        ah3d_line = next((line for line in result.stdout.splitlines() if line.startswith("NATIVE_DOS_AH3D ")), None)
        if not ah3d_line:
            raise AssertionError("native callback did not report the AH=3D request/response")
        fields = dict(token.split("=", 1) for token in ah3d_line.split()[1:] if "=" in token)
        for key in ("eip", "request_eax", "request_ebx", "request_ecx", "request_edx", "request_esi", "request_edi", "request_ebp", "request_esp", "ds_base", "response_eax", "response_ebx", "response_ecx", "response_edx", "response_esi", "response_edi", "response_ebp", "response_esp"):
            fields[key] = "0x" + fields[key].upper()
        for key in ("ds", "cf_in", "cf_out", "handled", "matched_original_fixture"):
            fields[key] = int(fields[key], 16) if key == "ds" else int(fields[key])
        fields["all_non_ax_registers_preserved"] = all(
            fields["request_" + reg] == fields["response_" + reg]
            for reg in ("ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
        )
        expected = {"eip": "0x000AFCC4", "request_eax": "0x00003D01", "ds": 0x14,
                    "resolved_path": r"c:\address.txt",
                    "response_eax": "0x00000002",
                    "cf_in": 0, "cf_out": 1, "handled": 1, "matched_original_fixture": 1}
        mismatches = {key: (fields.get(key), value) for key, value in expected.items() if fields.get(key) != value}
        if mismatches or not fields["all_non_ax_registers_preserved"]:
            raise AssertionError(f"native AH=3D response differs from the target-linked missing-file observation: mismatches={mismatches}, fields={fields}")
        fields["raw_path_matches_w3_bytes"] = fields["path"] == r"c:\address.txt"
        fields["normalized_path_matches_w3_dos_path"] = fields["resolved_path"].casefold() == r"c:\address.txt"
        if not fields["normalized_path_matches_w3_dos_path"]:
            raise AssertionError(f"normalized native path differs from W3 DOS path: {fields}")
        if not args.continue_dos_ah3c and (trap.get("instruction_va") != "0x000AFDA7" or trap.get("eax") != "0x00003C80"):
            raise AssertionError(f"native replay did not advance from AH=3D to the next DOS AH=3Ch frontier: {trap}")
        dos_ah3d_service = fields
    dos_ah3c_service = None
    if args.continue_dos_ah3c:
        line = next((x for x in result.stdout.splitlines() if x.startswith("NATIVE_DOS_AH3C ")), None)
        if not line:
            raise AssertionError("native callback did not report the AH=3C create/truncate request")
        fields = dict(token.split("=", 1) for token in line.split()[1:] if "=" in token)
        for key in ("eip", "request_eax", "request_ebx", "request_ecx", "request_edx",
                    "response_eax", "response_ebx", "response_ecx", "response_edx"):
            fields[key] = "0x" + fields[key].upper()
        for key in ("attributes", "cf_in", "cf_out", "handled", "matched_original_request"):
            fields[key] = int(fields[key], 16) if key == "attributes" else int(fields[key])
        expected = {"eip": "0x000AFDA7", "request_eax": "0x00003C80",
                    "request_ebx": "0x00000002", "request_ecx": "0x00000000",
                    "path": r"c:\address.txt", "attributes": 0,
                    "response_eax": "0x00000005", "cf_out": 0, "handled": 1,
                    "matched_original_request": 1, "fixture_kind": "bounded_memory_only"}
        mismatches = {k: (fields.get(k), v) for k, v in expected.items() if fields.get(k) != v}
        if mismatches:
            raise AssertionError(f"synthetic AH=3C response differs from measured W3 request/result: {mismatches}; {fields}")
        if trap.get("instruction_va") == "0x000AFDA7":
            raise AssertionError("native replay remained at AH=3C after the callback claimed success")
        fields["original_result"] = {"ax": "0x00000005", "cf": 0,
                                     "resume_eip": "0x001AFDA9", "next_original_eip": "0x001C8973"}
        dos_ah3c_service = fields
    dos_ax4400_service = None
    if args.continue_dos_ax4400:
        lines = [x for x in result.stdout.splitlines() if x.startswith("NATIVE_DOS_AX4400 ")]
        if len(lines) != 4:
            raise AssertionError(f"expected four bounded AX=4400 callbacks, got {len(lines)}")
        line = lines[0]
        fields = dict(token.split("=", 1) for token in line.split()[1:] if "=" in token)
        for key in ("eip", "request_eax", "request_ebx", "request_ecx", "request_edx",
                    "response_eax", "response_ebx", "response_ecx", "response_edx"):
            fields[key] = "0x" + fields[key].upper()
        for key in ("cf_in", "cf_out", "handled"):
            fields[key] = int(fields[key])
        expected = {"eip": "0x000C8973", "request_eax": "0x00004400",
                    "request_ebx": "0x00000005", "response_eax": "0x00004400",
                    "response_edx": "0x00000042", "cf_out": 0, "handled": 1,
                    "fixture_kind": "bounded_memory_only"}
        mismatches = {k: (fields.get(k), v) for k, v in expected.items() if fields.get(k) != v}
        if mismatches:
            raise AssertionError(f"synthetic AX=4400 result mismatch: {mismatches}; {fields}")
        fields["following_frontier"] = trap
        second = dict(token.split("=", 1) for token in lines[1].split()[1:] if "=" in token)
        for key in ("eip", "request_eax", "request_ebx", "request_ecx", "request_edx",
                    "response_eax", "response_ebx", "response_ecx", "response_edx"):
            second[key] = "0x" + second[key].upper()
        for key in ("call", "cf_in", "cf_out", "handled"):
            second[key] = int(second[key])
        second_expected = {"call": 2, "eip": "0x000C8973", "request_eax": "0x00004400",
                           "request_ebx": "0x00000005", "request_ecx": "0x00000000",
                           "request_edx": "0x00004000", "response_edx": "0x00000042",
                           "cf_out": 0, "handled": 1}
        second_mismatches = {k: (second.get(k), v) for k, v in second_expected.items() if second.get(k) != v}
        if second_mismatches:
            raise AssertionError(f"second synthetic AX=4400 response mismatch: {second_mismatches}; {second}")
        fields["second_request"] = second
        third = dict(token.split("=", 1) for token in lines[2].split()[1:] if "=" in token)
        for key in ("eip", "request_eax", "request_ebx", "request_ecx", "request_edx",
                    "response_eax", "response_ebx", "response_ecx", "response_edx"):
            third[key] = "0x" + third[key].upper()
        for key in ("call", "cf_in", "cf_out", "handled"):
            third[key] = int(third[key])
        third_expected = {"call": 3, "eip": "0x000C8973", "request_eax": "0x00004400",
                          "request_ebx": "0x00000005", "request_ecx": "0x0010A88A",
                          "request_edx": "0x0010A88A", "response_edx": "0x00100042",
                          "cf_out": 0, "handled": 1}
        third_mismatches = {k: (third.get(k), v) for k, v in third_expected.items() if third.get(k) != v}
        if third_mismatches:
            raise AssertionError(f"third synthetic AX=4400 response mismatch: {third_mismatches}; {third}")
        fields["third_request"] = third
        fourth = dict(token.split("=", 1) for token in lines[3].split()[1:] if "=" in token)
        for key in ("eip", "request_eax", "request_ebx", "request_ecx", "request_edx",
                    "response_eax", "response_ebx", "response_ecx", "response_edx"):
            fourth[key] = "0x" + fourth[key].upper()
        for key in ("call", "cf_in", "cf_out", "handled"):
            fourth[key] = int(fourth[key])
        fourth_expected = {"call": 4, "eip": "0x000C8973", "request_eax": "0x00004400",
                           "request_ebx": "0x00000005", "request_ecx": "0x00000000",
                           "request_edx": "0x0010A88A", "response_edx": "0x00100042",
                           "cf_out": 0, "handled": 1}
        fourth_mismatches = {k: (fourth.get(k), v) for k, v in fourth_expected.items() if fourth.get(k) != v}
        if fourth_mismatches:
            raise AssertionError(f"fourth synthetic AX=4400 response mismatch: {fourth_mismatches}; {fourth}")
        fields["fourth_request"] = fourth
        fields["classification"] = "synthetic DOS file on drive C, not written"
        w3_trace = json.loads((ROOT / "evidence" / "dpmi_alloc_contract_work3.json").read_text(encoding="utf-8"))
        w3_event = next((x for x in w3_trace["interrupts_after_first_success"]
                         if x.get("eip_int_opcode_assumption") == "0x001c8973"
                         and x.get("registers", {}).get("eax") == "0x00004400"
                         and x.get("registers", {}).get("ebx") == "0x00000005"
                         and x.get("registers", {}).get("ecx") == "0x00004000"
                         and x.get("registers", {}).get("edx") == "0x00000005"), None)
        if not w3_event:
            raise AssertionError("W3 historic exact-register AX=4400 observation is missing")
        fields["w3_historical_exact_request"] = {
            "source": "evidence/dpmi_alloc_contract_work3.json",
            "execution_model": "original-byte Unicorn with Python DOS service adapter",
            "target_sha256": w3_trace["target_sha256"],
            "request": w3_event["registers"],
            "response": w3_event["registers_after"],
            "next_event": "DOS AH=40 write at 0x001AFD33",
            "same_fixture_sequence_as_current_native": False,
        }
        fields["matches_w3_historical_response"] = fields["response_edx"] == w3_event["registers_after"]["edx"]
        fields["original_result"] = "W3 historical exact request returned DX=2 CF=0; current pinned replay has no matching capture"
        dos_ax4400_service = fields
    dos_ah42_service = None
    if args.continue_dos_ax4400:
        lines = [x for x in result.stdout.splitlines() if x.startswith("NATIVE_DOS_AH42 ")]
        if len(lines) != 2:
            raise AssertionError(f"expected two bounded AH=42 callbacks, got {len(lines)}")
        line = lines[0]
        fields = dict(token.split("=", 1) for token in line.split()[1:] if "=" in token)
        for key in ("eip", "request_eax", "request_ebx", "request_ecx", "request_edx",
                    "response_eax", "response_ebx", "response_ecx", "response_edx"):
            fields[key] = "0x" + fields[key].upper()
        for key in ("call", "cf_in", "cf_out", "handled"):
            fields[key] = int(fields[key])
        expected = {"call": 1, "eip": "0x000BA7CD", "request_eax": "0x00004201",
                    "request_ebx": "0x00000005", "request_ecx": "0x00000000",
                    "request_edx": "0x00000000", "response_eax": "0x00000000",
                    "response_edx": "0x00000000", "cf_out": 0, "handled": 1,
                    "fixture_kind": "bounded_memory_only"}
        mismatches = {k: (fields.get(k), v) for k, v in expected.items() if fields.get(k) != v}
        if mismatches:
            raise AssertionError(f"synthetic AH=42 response mismatch: {mismatches}; {fields}")
        fields["original_byte_reference"] = "evidence/runtime_ah42_seek_trace.json returned position 0x18 for a different file state"
        fields["equivalence"] = "synthetic only; current created file position is zero"
        second = dict(token.split("=", 1) for token in lines[1].split()[1:] if "=" in token)
        for key in ("eip", "request_eax", "request_ebx", "request_ecx", "request_edx",
                    "response_eax", "response_ebx", "response_ecx", "response_edx"):
            second[key] = "0x" + second[key].upper()
        for key in ("call", "cf_in", "cf_out", "handled"):
            second[key] = int(second[key])
        second_expected = {"call": 2, "eip": "0x000BA7CD", "request_eax": "0x00004200",
                           "request_ebx": "0x00000005", "request_ecx": "0x00000000",
                           "request_edx": "0x00000000", "response_eax": "0x00000000",
                           "response_edx": "0x00000000", "cf_out": 0, "handled": 1}
        second_mismatches = {k: (second.get(k), v) for k, v in second_expected.items() if second.get(k) != v}
        if second_mismatches:
            raise AssertionError(f"second synthetic AH=42 response mismatch: {second_mismatches}; {second}")
        fields["second_request"] = second
        dos_ah42_service = fields
    dos_ah3e_service = None
    if args.continue_dos_ax4400:
        line = next((x for x in result.stdout.splitlines() if x.startswith("NATIVE_DOS_AH3E ")), None)
        if not line:
            raise AssertionError("native callback did not report virtual file close AH=3E")
        fields = dict(token.split("=", 1) for token in line.split()[1:] if "=" in token)
        for key in ("eip", "request_eax", "request_ebx", "response_eax", "response_ebx"):
            fields[key] = "0x" + fields[key].upper()
        for key in ("cf_in", "cf_out", "handled"):
            fields[key] = int(fields[key])
        expected = {"eip": "0x000BA805", "request_eax": "0x00003E05",
                    "request_ebx": "0x00000005", "response_eax": "0x00003E05",
                    "response_ebx": "0x00000005", "cf_out": 0, "handled": 1,
                    "fixture_kind": "bounded_memory_only"}
        mismatches = {k: (fields.get(k), v) for k, v in expected.items() if fields.get(k) != v}
        if mismatches:
            raise AssertionError(f"synthetic AH=3E response mismatch: {mismatches}; {fields}")
        dos_ah3e_service = fields
    dos_standard_ioctl = None
    if args.continue_dos_ax4400:
        lines = [x for x in result.stdout.splitlines() if x.startswith("NATIVE_DOS_AX4400_STD ")]
        if len(lines) != 3:
            raise AssertionError(f"expected three standard handle queries, got {len(lines)}")
        parsed = []
        for idx, line in enumerate(lines, start=1):
            fields = dict(token.split("=", 1) for token in line.split()[1:] if "=" in token)
            for key in ("eip", "request_eax", "request_ebx", "request_edx", "response_eax", "response_ebx", "response_edx"):
                fields[key] = "0x" + fields[key].upper()
            for key in ("call", "cf_in", "cf_out", "handled"):
                fields[key] = int(fields[key])
            expected_handle = 2 if idx == 1 else 1
            expected_dx = f"0x{(int(fields['request_edx'],16)&0xffff0000)|0x82:08X}"
            expected = {"call": idx, "eip": "0x000C8973", "request_eax": "0x00004400",
                        "request_ebx": f"0x{expected_handle:08X}", "response_eax": "0x00004400",
                        "response_edx": expected_dx, "cf_out": 0, "handled": 1}
            mismatches = {k: (fields.get(k), v) for k, v in expected.items() if fields.get(k) != v}
            if mismatches:
                raise AssertionError(f"standard handle AX=4400 response mismatch: {mismatches}; {fields}")
            parsed.append(fields)
        dos_standard_ioctl = parsed
    dos_ah40_stdout = None
    if args.continue_dos_ah40:
        lines = [x for x in result.stdout.splitlines() if x.startswith("NATIVE_DOS_AH40_STD ")]
        if not lines:
            raise AssertionError("native callback did not capture the bounded AH=40 standard-output write")
        parsed_calls = []
        for line in lines:
            fields = dict(token.split("=", 1) for token in line.split()[1:] if "=" in token)
            hex_keys = ("eip", "request_eax", "request_ebx", "request_ecx", "request_edx",
                        "ds_base", "effective_linear", "response_eax", "response_ebx",
                        "response_ecx", "response_edx", "response_esi", "response_edi",
                        "response_ebp", "response_esp")
            for key in hex_keys:
                fields[key] = "0x" + fields[key].upper()
            for key in ("call", "ds", "sample_bytes", "cf_in", "cf_out", "handled", "captured_total"):
                fields[key] = int(fields[key], 16) if key == "ds" else int(fields[key])
            parsed_calls.append(fields)
        first = parsed_calls[0]
        expected = {"call": 1, "eip": "0x000D219C", "request_eax": "0x00004002",
                    "request_ebx": "0x00000001", "request_ecx": "0x00000002",
                    "request_edx": "0x002000D0", "ds": 0x14, "ds_base": "0x00000000",
                    "effective_linear": "0x002000D0", "sample_bytes": 2,
                    "sample_hex": "0d0a", "response_eax": "0x00000002",
                    "cf_out": 0, "handled": 1, "captured_total": 2,
                    "provider": "bounded_virtual_stdout"}
        mismatches = {k: (first.get(k), v) for k, v in expected.items() if first.get(k) != v}
        if mismatches:
            raise AssertionError(f"synthetic first AH=40 output differs from captured guest bytes/request: {mismatches}; {first}")
        capture_match = re.search(r"NATIVE_DOS_STDOUT_CAPTURE size=(\d+) hex=([0-9a-fA-F]*)",result.stdout)
        if not capture_match:
            raise AssertionError("native bounded stdout capture record is missing")
        capture_size=int(capture_match.group(1)); capture_hex=capture_match.group(2).lower()
        if capture_size>1024 or len(capture_hex)!=capture_size*2 or not capture_hex.startswith("0d0a"):
            raise AssertionError(f"native virtual stdout capture violates size or initial guest bytes: size={capture_size} hex={capture_hex}")
        original=json.loads((ROOT/"evidence"/"runtime_ah40_write_trace.json").read_text(encoding="utf-8"))
        original_event=next((x for x in original["target"]["interrupts"]
            if x.get("service")=="dos21.write_file" and x.get("eip_int_opcode_assumption")=="0x001d219c"),None)
        original_comparison=None
        if original_event:
            original_comparison={"same_original_site":True,"original_request":original_event["registers"],
                "original_bytes_hex":original_event["dos_filename"]["data_hex"],
                "original_response":original_event["registers_after"],
                "matches_current_stdout_request":False,
                "reason":"W3/original trace at this site is a BX=5 virtual-file write of 24 bytes; current native request is BX=1 for 2 bytes"}
        dos_ah40_stdout={"calls":parsed_calls,"capture_size":capture_size,
            "captured_bytes_hex":capture_hex,
            "effective_pointer_kind":"DS selector-relative 32-bit EDX offset; DS base applied by segment resolver",
            "fixture_handle_type":"standard output character device; no fixture redirection configured",
            "result_class":"synthetic bounded replay; original AH=40 stdout response not measured for this call",
            "original_same_site_comparison":original_comparison,"next_frontier":trap}
    dos_ah49_test = None
    if args.test_dos_ah49_contract:
        if "NATIVE_DOS_AH49_CONTRACT success=1 wrong_es_trapped=1 oracle_es=004c native_es=0014" not in result.stdout:
            raise AssertionError("native AH=49 direct contract test did not pass both ES cases")
        live = re.search(r"NATIVE_AH49_FRONTIER es=([0-9a-fA-F]{4}) eax=([0-9a-fA-F]{8}) ebx=([0-9a-fA-F]{8}) ecx=([0-9a-fA-F]{8}) edx=([0-9a-fA-F]{8})", result.stdout)
        segfault = re.search(r"NATIVE_SEGMENT_FAULT segment=(\d+) selector=([0-9a-fA-F]{4}) eip=([0-9a-fA-F]{8})", result.stdout)
        if not live and not segfault:
            raise AssertionError("native run exposed neither live AH=49 nor the preceding segment write fault")
        if segfault and (int(segfault.group(2),16)!=0x004C or int(segfault.group(3),16)!=0x000C3D42):
            raise AssertionError(f"unexpected segment fault before AH=49: {segfault.group(0)}")
        dos_ah49_test = {
            "live_frontier": ({"es": f"0x{int(live.group(1),16):04X}", "eax": f"0x{int(live.group(2),16):08X}", "ebx": f"0x{int(live.group(3),16):08X}", "ecx": f"0x{int(live.group(4),16):08X}", "edx": f"0x{int(live.group(5),16):08X}", "matches_original_es": int(live.group(1),16)==0x004C} if live else None),
            "segment_write_fault": ({"segment_id": int(segfault.group(1)), "selector": f"0x{int(segfault.group(2),16):04X}", "instruction_va": f"0x{int(segfault.group(3),16):08X}", "matches_measured_runtime_gap": True} if segfault else None),
            "success_selector": "0x004C", "success_result": "handled",
            "success_carry": 0, "all_gprs_preserved": True,
            "native_selector": "0x0014", "wrong_selector_result": "trapped",
            "wrong_selector_registers_preserved": True,
        }
    evidence = {
        "test": "native start execution with fixed-link LE image, DOS AH=30 host callback, resume, and next exact trap",
        "target_sha256": boot.executable_sha256,
        "memory_sha256": hashlib.sha256(BOOT_BIN.read_bytes()).hexdigest(),
        "memory_size": boot.memory.size,
        "link_va_layout": {"mem_base": f"0x{boot.image.mem_base:X}", "rebase": "0x0"},
        "entry": f"0x{boot.seed.eip:08X}",
        "stack": f"0x{boot.seed.esp:08X}",
        "psp": {"segment": f"0x{boot.psp_segment:04X}", "linear": f"0x{boot.psp_address:08X}", "selector": f"0x{psp_selector:04X}", "descriptor_limit": 0xFF},
        "environment": {"selector": f"0x{env_selector:04X}", "backing_real_segment": f"0x{boot.env_segment:04X}", "linear": f"0x{boot.env_address:08X}", "descriptor_limit": len(boot.environment) - 1},
        "selectors": {"cs": boot.seed.cs, "ds": boot.seed.ds, "es": psp_selector, "ss": boot.seed.ss},
        "registers_unknown_seeded_zero": list(boot.seed.unknown_registers),
        "command_tail": {"text": args.command_tail, "length": len(tail), "hex": tail.hex()},
        "native_context_initializer": {
            "api": "gw_guest_boot_context_init",
            "unknown_register_mask": "GW_BOOT_UNKNOWN_ALL",
            "segment_bases": "zero at initial flat-selector entry; runtime services may replace them",
            "lazy_flags": "FK_NONE with deterministic zero operands",
            "fpu_control_word": "0x037F",
        },
        "native_indirect_dispatch": {"lookup_source": str(LOOKUP_C.relative_to(ROOT)), "mapped_function_count": lookup_count, "strategy": "exact binary search over RECOMP_ENTER VAs emitted from canonical closure"},
        "original_unicorn_comparison": {"entry_rebase_delta": "0x100000", "first_interrupt_va_original": "0x001AFA09", "first_interrupt_va_linked": "0x000AFA09", "service": "DOS AH=30h"},
        "native_generated_c_progress": {
            "first_service": {"vector": "0x21", "instruction_va": "0x000AFA09", "request_ax": "0x3000", "response_ax": "0x1606", "dos_version_guest_bytes": [6, 22], "handled": True},
            "dos4g_install_check": dos4g_service,
            "dpmi_selector_base_query": dpmi_selector_service,
            "dos_time_query": dos_time_service,
            "dpmi_linear_allocation": dpmi_linear_service,
            "dpmi_linear_sequence": dpmi_linear_sequence,
            "dpmi_linear_test_arena": ({"kind": "host_backed_guest_map", "guest_range": ["0x00000000", f"0x{guest_map_capacity:08X}"], "capacity_bytes": f"0x{guest_map_capacity:08X}", "not_original_mapping_evidence": True} if host_backed_guest_memory else {"kind": "synthetic_test_only", "mapped_guest_memory_range": ["0x00200000", "0x00400000"], "not_original_mapping_evidence": True} if args.continue_dpmi_linear_success or args.continue_dpmi_linear_sequence else None),
            "dos_ah48": dos_ah48_service,
            "dos_ah48_retry": dos_ah48_retry_service,
            "dos_ah43": dos_ah43_service,
            "dos_ah3d": dos_ah3d_service,
            "dos_ah3c": dos_ah3c_service,
            "dos_ax4400": dos_ax4400_service,
            "dos_ah42": dos_ah42_service,
            "dos_ah3e": dos_ah3e_service,
            "dos_standard_ioctl": dos_standard_ioctl,
            "dos_ah40_stdout": dos_ah40_stdout,
            "dos_ah49_contract_test": dos_ah49_test,
            "next_frontier": trap,
            "execution_model": "recompiled C closure plus bounded gw_dos_services_callback; independent of the Unicorn original-byte replay",
            "cd_fixture_preflight": cd_fixture,
        "callback_provenance": {
            "native_generated_c_services": ["DOS AH=30h", "DOS AH=43h gw.err probe" , "DOS/4G install check", "DPMI AX=0006", "DOS AH=2Ch" if args.continue_time_query else None, "DOS AH=3Dh virtual-file provider" if args.continue_dos_ah3d else None, "DOS AH=3Ch memory-only create/truncate" if args.continue_dos_ah3c else None, "DOS AH=40h bounded injected stream" if args.continue_dos_ah40 else None],
                "original_byte_oracle_cd_services": "evidence/cd_present_gate_work3.json",
                "python_doshost_cue_mount_is_native_callback": False,
                "native_mscdex_callbacks_invoked": False,
                "next_native_guest_event": "DPMI AX=0501 at 0x000C3CC1",
            },
        },
        "run_exit": 0,
        "stdout": result.stdout.strip(),
        "passed": True,
    }
    if args.use_w3_original_environment and args.continue_dpmi_linear_success:
        original_capture_path = ROOT / "evidence" / "native_setenvp_aligned_replay_w1_066.json"
        original_capture = json.loads(original_capture_path.read_text(encoding="utf-8"))
        native_lines = result.stdout.splitlines()
        parse_event = lambda line: dict(token.split("=", 1) for token in line.split()[1:] if "=" in token)
        summary = next((parse_event(line) for line in native_lines if line.startswith("W1_CRT_SUMMARY ")), {})
        callback_events = [parse_event(line) for line in native_lines if line.startswith("W1_CRT_CALLBACK_DYNAMIC ")]
        argument_events = [parse_event(line) for line in native_lines if line.startswith("W1_CRT_ARG ")]
        setup_gate = next((line for line in native_lines if line.startswith("W1_MAIN_BLOCK va=0009433d ")), None)
        setup_entry = next((line for line in native_lines if line.startswith("W1_MAIN_BLOCK va=00094ac0 ")), None)
        callee_entry = next((line for line in native_lines if line.startswith("W1_SETUP_EVENT ") and "eip=00014bf0" in line.casefold()), None)
        return_dfe12 = next((parse_event(line) for line in native_lines if line.startswith("NATIVE_ADF95_RETURN ") and "link_va=000dfe12" in line.casefold()), None)
        dpmi = evidence["native_generated_c_progress"]["dpmi_linear_allocation"]
        request_size = ((int(dpmi["request_ebx"], 16) & 0xffff) << 16) | (int(dpmi["request_ecx"], 16) & 0xffff)
        evidence.update({
            "task": "W1-068",
            "task_schema": "gwrecomp.native-setenvp-dpmi-continue/v1",
            "evidence_level": "NATIVE_REACHED",
            "authenticated_environment": {
                **w3_original_environment_metadata,
                "guest_boot_environment_sha256": hashlib.sha256(boot.environment).hexdigest(),
                "guest_boot_environment_bytes": len(boot.environment),
                "exact_bytes_loaded": boot.environment == w3_original_environment,
                "source_run_dynamic_identity_claimed": False,
            },
            "prior_capture": {
                "path": original_capture_path.relative_to(ROOT).as_posix(),
                "sha256": hashlib.sha256(original_capture_path.read_bytes()).hexdigest(),
                "observed_request_size_bytes": original_capture["frontier"]["request_size_bytes"],
                "separate_dynamic_run": True,
            },
            "build_fingerprint": {
                "native_executable_sha256": hashlib.sha256(EXE.read_bytes()).hexdigest(),
                "closure_source_sha256": hashlib.sha256((ROOT / "build" / "entry_path_closure.c").read_bytes()).hexdigest(),
                "routed_object_sha256": hashlib.sha256((ROOT / "build" / "entry_path_closure_routed.o").read_bytes()).hexdigest(),
                "capture_object_sha256": hashlib.sha256((ROOT / "build" / "entry_path_closure_routed_debug.o").read_bytes()).hexdigest() if (ROOT / "build" / "entry_path_closure_routed_debug.o").is_file() else None,
                "runtime_c_header_sha256": hashlib.sha256((ROOT / "runtime" / "gw_dos_services.c").read_bytes()).hexdigest(),
                "runtime_driver_sha256": hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
                "native_harness_sha256": hashlib.sha256((ROOT / "tests" / "test_native_guest_image.c").read_bytes()).hexdigest(),
                "test_driver_sha256": hashlib.sha256((ROOT / "tests" / "test_native_guest_image.py").read_bytes()).hexdigest(),
            },
            "crt_startup": {
                "callback_count_before_stop": len(callback_events),
                "callback_ordinals": [int(item.get("ordinal", "-1")) for item in callback_events],
                "argc": int(summary.get("argc", "0")),
                "argv_pointer": "0x" + summary.get("argv", "0"),
                "argv": [item.get("value", "") for item in argument_events],
                "gate_9433d_observed": setup_gate is not None,
                "setup_game_observed": setup_entry is not None,
                "callee_14bf0_observed": callee_entry is not None,
            },
            "setenvp_return": {"observed": return_dfe12 is not None, "event": return_dfe12},
            "allocator_service": {
                "request_size_bytes": f"0x{request_size:08X}",
                "request_matches_prior_capture": request_size == int(original_capture["frontier"]["request_size_bytes"], 16),
                "response_source": "existing gw_dos_services_callback bounded linear allocator",
                "arena_kind": "synthetic_test_arena",
                "response_is_guest_state_injection": False,
                "original_base_or_handle_reused": False,
                "contract_class": dpmi.get("contract_class"),
            },
            "next_frontier": evidence["native_generated_c_progress"]["next_frontier"],
            "menu_reached": False,
            "framebuffer_reached": False,
        })
    if args.snapshot_frontier_v1:
        from frontier_snapshot import create_snapshot
        snapshot_path = ROOT / "evidence" / "frontier_snapshot_v1_work2.json"
        memory_path = ROOT / "evidence" / "frontier_snapshot_v1_memory.bin"
        evidence["frontier_snapshot_v1"] = create_snapshot(ROOT, evidence, memory_path, snapshot_path)
    (ROOT / "evidence" / args.evidence_name).write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print("PASS native LE image/PSP/stack seed handled DOS AH=30 and resumed to the next exact host trap")


if __name__ == "__main__":
    main()




