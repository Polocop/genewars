"""Lift full entry roots or a fail-closed verified GeneWars 1.1 subgraph."""
import argparse
import hashlib
import json
import os
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "runtime"), str(ROOT / "third_party" / "pcrecomp")]
from capstone.x86 import (X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_AX, X86_REG_BL, X86_REG_CS, X86_REG_DS, X86_REG_EAX,
                          X86_REG_EBP, X86_REG_EBX, X86_REG_ECX, X86_REG_EDI, X86_REG_EDX, X86_REG_ES,
                          X86_REG_ESI, X86_REG_ESP, X86_REG_SS)
from capstone.x86 import X86_REG_GS
from le_loader import load_le
from guest_boot import GENEWARS_11_MEASURED_OBJECT_DELTAS
from tools.disasm.disasm32 import Disassembler
from tools.pe.pe_analyze import Section
from tools.lift.lift32 import Lifter

TARGET = ROOT / "evidence" / "genewars-1_1.exe"
EXPECTED = {"start": 0xAF96C, "main_": 0x93F30, "W?setup_game$n()v": 0x94AC0,
            "W?PlayIntro$n()v": 0x92930, "W?game$n()v": 0x92710}
parser = argparse.ArgumentParser(description=__doc__, fromfile_prefix_chars="@")
parser.add_argument("--object-map", choices=("link-analysis", "measured-1-3"), default="link-analysis",
                    help="apply only hash-bound object 1/3 guest deltas")
parser.add_argument("--partial-root", action="append", default=[],
                    help="verified LE link VA to lift; repeatable; requires --object-map measured-1-3")
parser.add_argument("--stack-range", help="bounded guest stack BASE:SIZE required for partial lifts that touch the stack")
parser.add_argument("--dynamic-range", action="append", default=[],
                    help="explicit guest region allowed for register-based memory operands in a partial closure; the fixture must validate every write")
parser.add_argument("--segment-relative-access", action="append", default=[],
                    metavar="SITE=ES:OFFSET:WIDTH",
                    help="admit one exact absolute segment-relative operand; decoded site/segment/offset/width must match and the runtime range validator must bound it")
parser.add_argument("--stop-after-call", action="append", default=[],
                    metavar="SITE=TARGET",
                    help="for one bounded partial entry, retain original instructions through the instruction after an exact direct call, then return; the call target is still lifted normally")
parser.add_argument("--verified-indirect-target", action="append", default=[],
                    metavar="CALLSITE=TARGET",
                    help="add a hash-bound original-code callback target for one indirect callsite; runtime must verify the actual guest pointer before invocation")
parser.add_argument("--verified-le-vtable-call", action="append", default=[],
                    metavar="CALLSITE=VTABLE_LINK:COUNT",
                    help="admit one exact CALL [vtable+disp] only after verifying the complete contiguous LE SRC_OFFSET32 vtable and guarding its live base and selected target")
parser.add_argument("--verified-le-vtable-function", action="append", default=[],
                    metavar="ENTRY=VTABLE_LINK:COUNT[,VTABLE_LINK:COUNT...]",
                    help="batch exact virtual-call sites in one decoded LE function against finite fixup-backed vtables; each live call still has per-site/base/target guards")
parser.add_argument("--deferred-indirect-call", action="append", default=[],
                    metavar="CALLSITE",
                    help="retain one exact original indirect call as a fail-closed runtime dispatch; the test must prove it is not reached")
parser.add_argument("--runtime-fail-closed", action="store_true",
                    help="emit exact-EIP traps for unresolved indirect control flow and dynamic memory instead of rejecting the whole partial lift")
parser.add_argument("--batch-le-fixup-vtables", action="store_true",
                    help="for reachable CALL [GPR+disp] sites, admit every matching contiguous Object-3 SRC_OFFSET32 code-pointer table slot; retain live table-base and target guards")
parser.add_argument("--indexed-cs-table", action="append", default=[],
                    metavar="SITE=TABLE_LINK:COUNT:BASE_REG:INDEX_REG",
                    help="admit one original CS indexed table read with a runtime guard; COUNT excludes the NUL terminator")
parser.add_argument("--indexed-code-jump-table", action="append", default=[],
                    metavar="SITE=TABLE_LINK:COUNT:INDEX_REG",
                    help="admit a byte-verified CS dword switch table with a bounded original index and executable destinations")
parser.add_argument("--runtime-indexed-code-jump-table", action="append", default=[],
                    metavar="SITE=TABLE_LINK:COUNT:INDEX_REG",
                    help="admit one exact runtime-populated code table whose LE writer instructions and runtime destinations have a finite, verified contract")
parser.add_argument("--rep-movsd-source-range",
                    help="explicit guest backing BASE:SIZE for the source of the two verified LbScreenSwap REP MOVSD sites")
parser.add_argument("--rep-movsd-destination-range",
                    help="explicit guest backing BASE:SIZE for the destination of the two verified LbScreenSwap REP MOVSD sites")
parser.add_argument("--output-c", help="write generated C to this path instead of the shared default")
parser.add_argument("--report", help="write the JSON lift report to this path instead of the shared default")
args = parser.parse_args()
# Large test closures can approach Windows' CreateProcess command-line limit.
# Preserve the same exact, fail-closed validation while allowing tests to pass
# a small supplemental batch through the environment instead of another long
# repeated CLI list.
args.verified_le_vtable_call.extend(
    row for row in os.environ.get("GWRECOMP_LIFT_VTABLE_CALLS", "").split(";") if row)
args.partial_root.extend(
    row for row in os.environ.get("GWRECOMP_LIFT_PARTIAL_ROOTS", "").split(";") if row)
args.indexed_code_jump_table.extend(
    row for row in os.environ.get("GWRECOMP_LIFT_INDEXED_CODE_JUMP_TABLES", "").split(";") if row)
sha = hashlib.sha256(TARGET.read_bytes()).hexdigest()
# This draw callback was reached during the bounded IFCLevel continuation:
# the live receiver is the 0x111B2C LE address point and the observed slot
# (+0x10) is fixed by the canonical Object-3 -> Object-1 LE fixup to thunk
# 0x13810. Keep this narrow contract implicit in the CLI to avoid exceeding
# Windows' command line limit for the already-large creature probe closure.
# It is enabled only for this exact canonical executable and only when the
# caller requested the corresponding DrawMapDisplay entry.
canonical_drawmap_vtable = (
    sha == "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
    and args.object_map == "measured-1-3"
    and any((int(root, 0) if root.lower().startswith("0x") else int(root, 16)) == 0x22F40
            for root in args.partial_root)
)
if canonical_drawmap_vtable:
    if "0x13810" not in args.partial_root:
        args.partial_root.append("0x13810")
    # The same live Building draw path then calls the inherited slot +0x0C
    # through the IFCPlanetside address point 0x111BE8. Its slot at 0x111BF4
    # is an LE SRC_OFFSET32 fixup to the adjustor thunk 0x6B490; validate the
    # contiguous 18-slot address-point table and keep the callsite guarded.
    if "0x6B490" not in args.partial_root:
        args.partial_root.append("0x6B490")
    if "0x6B9F0" not in args.partial_root:
        args.partial_root.append("0x6B9F0")
    if "0x6EE40" not in args.partial_root:
        args.partial_root.append("0x6EE40")
    if "0x13830" not in args.partial_root:
        args.partial_root.append("0x13830")
    if "0x6B1B0" not in args.partial_root:
        args.partial_root.append("0x6B1B0")
    indexed_switch = "0x6B94A=0x6B584:12:eax"
    if indexed_switch not in args.indexed_code_jump_table:
        args.indexed_code_jump_table.append(indexed_switch)
    for draw_callback_call in ("0x22F87=0x111B8C:18",
                               "0x22FEA=0x111B8C:18",
                               "0x22FEA=0x111BE8:18",
                               "0x22FEA=0x111BB8:30",
                               "0x22FFE=0x111B8C:41",
                               "0x223D1=0x111B8C:41",
                               "0x215AC=0x111B8C:41",
                               "0x6BAB7=0x111B8C:41",
                               "0x6BA1F=0x111DFC:40"):
        if draw_callback_call not in args.verified_le_vtable_call:
            args.verified_le_vtable_call.append(draw_callback_call)
    vtable_function_row = "0x22F40=0x111B2C:65"
else:
    vtable_function_row = None
rebases = GENEWARS_11_MEASURED_OBJECT_DELTAS if args.object_map == "measured-1-3" else None
image = load_le(TARGET, object_rebases=rebases)
unknown = [o.index for o in image.objects if not o.linear_base_verified]
if args.partial_root:
    if args.object_map != "measured-1-3" or not unknown:
        raise SystemExit("partial closure requires the incomplete, hash-bound measured-1-3 map")
elif rebases is not None and unknown:
    raise SystemExit(f"refusing full entry-path lift with incomplete runtime map; unknown LE objects: {unknown}")

map_rows = {}
for line in (ROOT / "evidence" / "genewars-1_1.map").read_text(errors="replace").splitlines():
    fields = line.split()
    if len(fields) >= 2 and fields[0].startswith("0001:"):
        try:
            map_rows[int(fields[0].split(":")[1], 16)] = fields[1]
        except ValueError:
            pass

code_obj = image.objects[0]
code = bytes(image.object_data(1))
section = Section(".text", code_obj.base, code_obj.virtual_size, 0, code_obj.virtual_size, 0x20000020)
dis = Disassembler(code, 0, [section])
link_dis = None
link_code = b""
link_obj = None
if args.indexed_code_jump_table or args.partial_root:
    link_image = load_le(TARGET)
    link_obj = link_image.objects[0]
    link_code = bytes(link_image.object_data(1))
    link_dis = Disassembler(link_code, 0,
        [Section(".text", link_obj.base, link_obj.virtual_size, 0, link_obj.virtual_size, 0x20000020)])
if args.partial_root:
    roots = []
    for text in args.partial_root:
        try:
            address = int(text, 0) if text.lower().startswith("0x") else int(text, 16)
        except ValueError:
            raise SystemExit(f"invalid --partial-root address: {text}")
        obj = image.object_containing(address)
        if obj is None or not obj.executable or not obj.linear_base_verified:
            raise SystemExit(f"partial root 0x{address:08X} is outside verified executable LE code")
        roots.append(address)
    if not args.stack_range or ":" not in args.stack_range:
        raise SystemExit("partial closure requires an explicit --stack-range BASE:SIZE contract")
    if len(args.stop_after_call) > 1:
        raise SystemExit("only one --stop-after-call boundary is supported per bounded closure")
    stop_after_call = None
    if args.stop_after_call:
        if "=" not in args.stop_after_call[0]:
            raise SystemExit("invalid --stop-after-call; use SITE=TARGET")
        site_text, target_text = args.stop_after_call[0].split("=", 1)
        try:
            stop_after_call = (int(site_text, 0), int(target_text, 0))
        except ValueError:
            raise SystemExit("invalid --stop-after-call numeric field")
        if any(value < 0 or value > 0xFFFFFFFF for value in stop_after_call):
            raise SystemExit("invalid --stop-after-call address")
    matched_stop_after_call = False
    try:
        stack_base_text, stack_size_text = args.stack_range.split(":", 1)
        stack_base = int(stack_base_text, 0); stack_size = int(stack_size_text, 0)
    except ValueError:
        raise SystemExit("invalid --stack-range; use hexadecimal BASE:SIZE")
    if stack_base < 0 or stack_size <= 0 or stack_base + stack_size > 0x100000000:
        raise SystemExit("invalid bounded guest stack range")
    dynamic_ranges = []
    for text in args.dynamic_range:
        if ":" not in text:
            raise SystemExit("invalid --dynamic-range; use hexadecimal BASE:SIZE")
        try:
            base_text, size_text = text.split(":", 1)
            base = int(base_text, 0); size = int(size_text, 0)
        except ValueError:
            raise SystemExit("invalid --dynamic-range; use hexadecimal BASE:SIZE")
        if base < 0 or size <= 0 or base + size > 0x100000000:
            raise SystemExit("invalid bounded dynamic guest range")
        if base < stack_base + stack_size and stack_base < base + size:
            raise SystemExit("dynamic guest range overlaps the declared stack")
        dynamic_ranges.append((base, base + size))
    segment_relative_contracts = {}
    for text in args.segment_relative_access:
        if "=" not in text:
            raise SystemExit("invalid --segment-relative-access; use SITE=ES:OFFSET:WIDTH")
        site_text, contract_text = text.split("=", 1)
        parts = contract_text.split(":")
        if len(parts) != 3 or parts[0].upper() != "ES":
            raise SystemExit("invalid --segment-relative-access; only an explicit ES:OFFSET:WIDTH contract is supported")
        try:
            site = int(site_text, 0)
            offset = int(parts[1], 0)
            width = int(parts[2], 0)
        except ValueError:
            raise SystemExit("invalid --segment-relative-access numeric field")
        if site < 0 or site > 0xFFFFFFFF or offset < 0 or offset > 0xFFFFFFFF or width not in (1, 2, 4, 8):
            raise SystemExit("invalid --segment-relative-access bounds/width")
        if site in segment_relative_contracts:
            raise SystemExit(f"duplicate --segment-relative-access site 0x{site:08X}")
        segment_relative_contracts[site] = (offset, width)
    matched_segment_relative_contracts = set()
    def parse_rep_range(text, label):
        if not text or ":" not in text:
            raise SystemExit(f"{label} requires an explicit hexadecimal BASE:SIZE")
        try:
            base_text, size_text = text.split(":", 1)
            base = int(base_text, 0); size = int(size_text, 0)
        except ValueError:
            raise SystemExit(f"invalid {label}; use hexadecimal BASE:SIZE")
        if base < 0 or size <= 0 or base + size > 0x100000000:
            raise SystemExit(f"invalid {label} bounds")
        if base < stack_base + stack_size and stack_base < base + size:
            raise SystemExit(f"{label} overlaps the declared stack")
        return (base, base + size)
    rep_movsd_source = (parse_rep_range(args.rep_movsd_source_range, "REP MOVSD source range")
                        if args.rep_movsd_source_range else None)
    rep_movsd_destination = (parse_rep_range(args.rep_movsd_destination_range, "REP MOVSD destination range")
                             if args.rep_movsd_destination_range else None)
    if bool(rep_movsd_source) != bool(rep_movsd_destination):
        raise SystemExit("REP MOVSD requires both explicit source and destination ranges")
else:
    roots = list(EXPECTED.values())
    dynamic_ranges = []
    segment_relative_contracts = {}
    matched_segment_relative_contracts = set()
    stop_after_call = None
    matched_stop_after_call = False
    for name, address in EXPECTED.items():
        if map_rows.get(address) != name:
            raise SystemExit(f"MAP root mismatch {name} {address:#x}: {map_rows.get(address)}")

# Optional callback edges are intentionally scoped to exact indirect
# callsites. A callsite may have multiple hash-bound targets when the original
# code reaches it through distinct verified tables. The generated dispatch
# checks the live guest pointer against that finite set; no pointer is written
# into guest memory by this option.
verified_indirect_by_site = {}
verified_le_vtable_calls = {}
batch_vtable_contract_pairs = set()
# Build candidate address-point tables from the canonical LE relocation map.
# A candidate is accepted only when it is an aligned contiguous run of unique
# Object-3 SRC_OFFSET32 fixups to decoded executable Object-1 instructions.
# Callsite-specific use is still required below, and the emitted runtime guard
# pairs the live base register with the exact target fixed at that slot.
le_vtable_candidates_by_slot = {}
if args.batch_le_fixup_vtables:
    data_fixups = {}
    for fix in image.fixups:
        source_owner = image.object_containing(fix.source_link)
        target = image.objects[0].base + fix.target_offset if fix.target_object == 1 else None
        target_owner = image.object_containing(target) if target is not None else None
        if (source_owner is not None and source_owner.index == 3 and
                fix.source_type == 0x07 and fix.target_object == 1 and
                (fix.target_flags & 0x03) == 0 and target_owner is not None and
                target_owner.index == 1 and target_owner.executable):
            data_fixups[fix.source_link] = fix
    candidate_runs = []
    for source in sorted(data_fixups):
        if candidate_runs and source == candidate_runs[-1][-1] + 4:
            candidate_runs[-1].append(source)
        else:
            candidate_runs.append([source])
    for sources in candidate_runs:
        if len(sources) < 2 or sources[0] & 3:
            continue
        entries = []
        valid = True
        for index, source in enumerate(sources):
            fix = data_fixups[source]
            target = image.objects[0].base + fix.target_offset
            first = next(link_dis.disassemble_at(target, max_bytes=16), None) if link_dis else None
            if first is None or first.address != target or first.mnemonic.lower() in ("int3", "ud2"):
                valid = False
                break
            entries.append({"index": index, "source_link": source,
                            "target_link": target, "target_offset": fix.target_offset,
                            "target_flags": fix.target_flags})
        if valid:
            table_link = sources[0]
            for index, entry in enumerate(entries):
                le_vtable_candidates_by_slot.setdefault(index, []).append(
                    (table_link, len(entries), entry, entries))
vtable_call_rows=list(args.verified_le_vtable_call)
# These three exact UI callbacks are rewritten and verified by the harness
# after lift generation. Preserve that contract ownership; the batch resolver
# must not pre-consume their fail-closed marker.
batch_vtable_postlift_contract_sites = {0x20C0B, 0x219A6, 0x2293D,
    0x7720F, 0x772DE, 0x766EE}
# FUN_00078B30 shares its [EDX+4] query with the fixed BioGame effect vtable.
# Keep that third base/target pair exact to this one callsite; do not admit
# the whole table throughout the picker function.
if "0x78BA1=0x1121E4:64" not in vtable_call_rows:
    vtable_call_rows.append("0x78BA1=0x1121E4:64")
# The original plant-state accessor at 0x6EDF3 is shared by the plant
# address point and the sibling entity address point. The latter's +0x1C
# slot is independently fixed by the LE to the same 0x69E50 method.
if "0x6EDF3=0x111DFC:40" not in vtable_call_rows:
    vtable_call_rows.append("0x6EDF3=0x111DFC:40")
# FUN_00079100's hover/action query also receives the address point at
# 0x111DFC; its +0x6C slot is fixed to the same LE predicate as the plant
# table's corresponding slot. Bind that receiver only at this callsite.
if "0x79155=0x111DFC:40" not in vtable_call_rows:
    vtable_call_rows.append("0x79155=0x111DFC:40")
# The subsequent entity-selection predicate in FUN_00079100 is another
# distinct fixed slot on that same entity address point: +0x24 -> 0x6ED40.
if "0x79178=0x111DFC:40" not in vtable_call_rows:
    vtable_call_rows.append("0x79178=0x111DFC:40")
# DrawMapSprites can revisit a selected Thing through its base entity vtable
# at [EDX+0x6C]. The 0x111E68 LE fixup is independently verified to 0x6ED30;
# keep this base admitted only at the selectedThing callsite.
if "0x7949D=0x111DFC:40" not in vtable_call_rows:
    vtable_call_rows.append("0x7949D=0x111DFC:40")
# The entity-list renderer reaches the same selected-object vtable through
# ECX at 0x80A3A. Slot 0x111E0C is fixed by the LE to 0x6EE10; constrain the
# complete vtable contract to this one dispatch site.
if "0x80A3A=0x111DFC:40" not in vtable_call_rows:
    vtable_call_rows.append("0x80A3A=0x111DFC:40")
# The 0x6ED7D helper is shared by the plant address point and its sibling
# entity address point; both slots are independently fixed by the LE.
if "0x6ED7D=0x111DFC:40" not in vtable_call_rows:
    vtable_call_rows.append("0x6ED7D=0x111DFC:40")
# Building completion dispatch at 0x392B6 reads the [Building+0x23]
# callback object and invokes slot +0x44. The live receiver is 0x111DFC;
# its exact LE slot 0x111E40 is an object-1 SRC_OFFSET32 fixup to 0x69E20.
if "0x392B6=0x111DFC:40" not in vtable_call_rows:
    vtable_call_rows.append("0x392B6=0x111DFC:40")
# Action 0x14's building-state handler reaches the same exact address point
# and slot. Admit the call only when the runtime receiver is 0x111DFC and its
# live [EDI+0x44] value equals the canonical LE fixup target 0x69E20.
if "0x39BEF=0x111DFC:40" not in vtable_call_rows:
    vtable_call_rows.append("0x39BEF=0x111DFC:40")
# At 0x6ED7D the live receiver is the plant/MapDisplay address point
# 0x111EA4; its +0x18 slot is independently fixed to 0x568E0. Do not attach
# the separate 0x111DFC/0x389E0 alternative here without a matching receiver
# observation for this callsite.
if "0x6ED7D=0x111EA4:29" not in vtable_call_rows:
    vtable_call_rows.append("0x6ED7D=0x111EA4:29")
# These two PlSpec lifecycle helpers are reached by the single-order
# continuation after bounded state dispatch. Their callbacks are admitted only
# through the complete, fixup-validated PlSpec vtable, and only at callsites
# in these exact functions. Keeping the contracts here avoids expanding the
# already long Windows command line used by the focused harness.
verified_le_vtable_function_rows = list(args.verified_le_vtable_function)
if vtable_function_row and vtable_function_row not in verified_le_vtable_function_rows:
    verified_le_vtable_function_rows.append(vtable_function_row)
for default_row in ("0x403B0=0x112060:52", "0x81020=0x112060:52",
                    "0x38DD0=0x111DFC:40", "0x3C820=0x111DFC:40",
                    "0x39F20=0x111DFC:40",
                    # The picker shares calls across three independently
                    # fixup-backed receiver tables. Keep the sibling entity
                    # address point 0x111DFC as well as plant/MapDisplay and
                    # PlSpec: 0x111DFC+0x70 -> 0x6EC70, while PlSpec
                    # 0x112060+0x70 -> 0x6A2A0.
                    "0x78B30=0x111DFC:40,0x111EA4:29,0x112060:52",
                    "0x83BF0=0x1121E4:45"):
    if default_row not in verified_le_vtable_function_rows:
        verified_le_vtable_function_rows.append(default_row)
for row in verified_le_vtable_function_rows:
    if "=" not in row:
        raise SystemExit(f"invalid --verified-le-vtable-function {row!r}; expected ENTRY=VTABLE_LINK:COUNT[,..]")
    entry_text, table_text = row.split("=",1)
    try: entry=int(entry_text,0)
    except ValueError: raise SystemExit(f"invalid LE vtable function entry {entry_text!r}")
    entry_obj=image.object_containing(entry)
    if entry_obj is None or entry_obj.index!=1 or not entry_obj.executable or not entry_obj.linear_base_verified:
        raise SystemExit(f"LE vtable batch entry 0x{entry:08X} is outside verified object-1 code")
    candidates=[]
    for spec in table_text.split(","):
        parts=spec.split(":")
        if len(parts)!=2: raise SystemExit(f"invalid LE vtable batch table {spec!r}; expected TABLE_LINK:COUNT")
        try: table,count=int(parts[0],0),int(parts[1],0)
        except ValueError: raise SystemExit(f"invalid LE vtable batch numeric table {spec!r}")
        owner=image.object_containing(table)
        if (count<=0 or count>256 or owner is None or owner.index!=3 or
                not owner.linear_base_verified or table+count*4>owner.end):
            raise SystemExit(f"LE vtable batch table 0x{table:08X} is outside verified object-3 data")
        # Prove the declared table once before considering callsites.
        for index in range(count):
            fix=next((f for f in image.fixups if f.source_link==table+index*4),None)
            if (fix is None or fix.source_type!=0x07 or fix.target_object!=1 or fix.target_flags&0x03):
                raise SystemExit(f"LE vtable batch slot 0x{table+index*4:08X} lacks its object-1 SRC_OFFSET32 fixup")
        candidates.append((table,count))
    fn=link_dis.disassemble_function(entry) if link_dis else None
    if fn is None: raise SystemExit("LE vtable batch requires decoded link-coordinate instructions")
    for block in fn.blocks.values():
        for insn in block.instructions:
            if (insn.mnemonic.lower()!="call" or not insn.operands or
                    insn.operands[0].type!=X86_OP_MEM or insn.operands[0].mem.index or
                    insn.operands[0].mem.disp<0 or insn.operands[0].mem.disp%4):
                continue
            slot=insn.operands[0].mem.disp//4
            for table,count in candidates:
                if slot<count and next((f for f in image.fixups if f.source_link==table+slot*4),None):
                    candidate=f"0x{insn.address:X}=0x{table:X}:{count}"
                    if candidate not in vtable_call_rows: vtable_call_rows.append(candidate)
if args.verified_indirect_target and not args.partial_root:
    raise SystemExit("--verified-indirect-target is valid only for a bounded partial closure")
for row in args.verified_indirect_target:
    if "=" not in row:
        raise SystemExit(f"invalid --verified-indirect-target {row!r}; expected CALLSITE=TARGET")
    left, right = row.split("=", 1)
    try:
        callsite, target = int(left, 0), int(right, 0)
    except ValueError:
        raise SystemExit(f"invalid --verified-indirect-target {row!r}; addresses must be hexadecimal")
    target_obj = image.object_containing(target)
    if target_obj is None or not target_obj.executable or not target_obj.linear_base_verified:
        raise SystemExit(f"verified indirect target 0x{target:08X} is not in a verified executable object")
    targets = verified_indirect_by_site.setdefault(callsite, set())
    if target in targets:
        raise SystemExit(f"duplicate verified target 0x{target:08X} for callsite 0x{callsite:08X}")
    targets.add(target)

if args.verified_le_vtable_call and not args.partial_root:
    raise SystemExit("--verified-le-vtable-call is valid only for a bounded partial closure")
for row in vtable_call_rows:
    if "=" not in row:
        raise SystemExit(f"invalid --verified-le-vtable-call {row!r}; expected CALLSITE=VTABLE_LINK:COUNT")
    site_text, detail = row.split("=", 1)
    parts = detail.split(":")
    if len(parts) != 2:
        raise SystemExit(f"invalid --verified-le-vtable-call {row!r}; expected CALLSITE=VTABLE_LINK:COUNT")
    try:
        site, vtable_link, count = int(site_text, 0), int(parts[0], 0), int(parts[1], 0)
    except ValueError:
        raise SystemExit(f"invalid --verified-le-vtable-call {row!r}; numeric fields must be hexadecimal/integer")
    if count <= 0 or count > 256:
        raise SystemExit(f"invalid LE vtable contract at 0x{site:08X}")
    owner = image.object_containing(vtable_link)
    if owner is None or owner.index != 3 or not owner.linear_base_verified or \
            vtable_link + count * 4 > owner.end:
        raise SystemExit(f"LE vtable 0x{vtable_link:08X} is outside verified object 3")
    decoded_call = next(link_dis.disassemble_at(site, max_bytes=8), None) if link_dis else None
    if (decoded_call is None or decoded_call.address != site or
            decoded_call.mnemonic.lower() != "call" or len(decoded_call.operands) != 1 or
            decoded_call.operands[0].type != X86_OP_MEM or
            decoded_call.operands[0].mem.index or
            decoded_call.operands[0].mem.base not in (X86_REG_EAX,X86_REG_EBX,X86_REG_ECX,
                                                       X86_REG_EDX,X86_REG_EBP,X86_REG_ESI,X86_REG_EDI) or
            decoded_call.operands[0].mem.disp < 0):
        raise SystemExit(f"LE vtable callsite 0x{site:08X} is not CALL [GPR+disp]")
    displacement = decoded_call.operands[0].mem.disp
    base_codes={X86_REG_EAX:0,X86_REG_ECX:1,X86_REG_EDX:2,X86_REG_EBX:3,
                X86_REG_EBP:5,X86_REG_ESI:6,X86_REG_EDI:7}
    base_code=base_codes[decoded_call.operands[0].mem.base]
    # ModRM encodes zero displacement in the compact mode-00 form except
    # EBP (whose mode-00/rm-101 means disp32). Preserve the exact original
    # x86 encoding while still validating the decoded base and displacement.
    if displacement == 0 and base_code != 5:
        expected_call = bytes((0xFF,0x10+base_code))
    elif displacement <= 0x7F:
        expected_call = bytes((0xFF,0x50+base_code,displacement))
    else:
        expected_call = bytes((0xFF,0x90+base_code))+struct.pack("<I",displacement)
    if decoded_call.bytes != expected_call:
        raise SystemExit(f"LE vtable callsite 0x{site:08X} encoding no longer matches its decoded displacement")
    slot_index = displacement // 4
    if displacement % 4 or slot_index >= count:
        raise SystemExit(f"LE vtable callsite 0x{site:08X} selects a slot outside the declared table")
    entries = []
    for index in range(count):
        source = vtable_link + index * 4
        fixup = next((f for f in image.fixups if f.source_link == source), None)
        if (fixup is None or fixup.source_type != 0x07 or fixup.target_object != 1 or
                fixup.target_flags & 0x03):
            raise SystemExit(f"LE vtable slot 0x{source:08X} lacks an internal object-1 SRC_OFFSET32 fixup")
        target = image.objects[0].base + fixup.target_offset
        target_obj = image.object_containing(target)
        first = next(link_dis.disassemble_at(target, max_bytes=16), None) if link_dis else None
        if (target_obj is None or target_obj.index != 1 or not target_obj.executable or
                not target_obj.linear_base_verified or first is None or first.address != target or
                first.mnemonic.lower() in ("int3", "ud2")):
            raise SystemExit(f"LE vtable slot 0x{source:08X} does not resolve to decoded object-1 code")
        entries.append({"index":index,"source_link":source,"target_link":target,
                        "target_offset":fixup.target_offset,"target_flags":fixup.target_flags})
    selected = entries[slot_index]
    selected_target = selected["target_link"]
    verified_indirect_by_site.setdefault(site, set()).add(selected_target)
    base_register={X86_REG_EAX:"eax",X86_REG_EBX:"ebx",X86_REG_ECX:"ecx",
                   X86_REG_EDX:"edx",X86_REG_EBP:"ebp",X86_REG_ESI:"esi",
                   X86_REG_EDI:"edi"}[decoded_call.operands[0].mem.base]
    verified_le_vtable_calls.setdefault(site, []).append({"vtable_link":vtable_link,"vtable_guest":image.link_to_linear(vtable_link),
        "base_register":base_register,
        "count":count,"slot_index":slot_index,"slot_link":selected["source_link"],
        "target_link":selected_target,"entries":entries})

# The original MAP identifies vsscanf_ at 0xC8392. It builds its stack
# callback pair from the two adjacent MAP functions, each address supplied by
# an LE SRC_OFFSET32 fixup. Admit only the corresponding parser callsites and
# targets; the generated ICALL path still checks the live pointer.
for callsite, (store_site, link_target, expected_reg) in {
        0xD73FD:(0xC8397,0xC8365,"ecx"),
        0xD7404:(0xC839C,0xC838E,"esi")}.items():
    store = next(link_dis.disassemble_at(store_site), None) if link_dis else None
    fixup = next((f for f in image.fixups if f.source_link == store_site + 1), None)
    if (store is None or store.mnemonic.lower() != "mov" or len(store.operands) != 2 or
            store.operands[0].type != X86_OP_REG or store.operands[0].reg != {
                "ecx":X86_REG_ECX,"esi":X86_REG_ESI}[expected_reg] or
            store.operands[1].type != X86_OP_IMM or
            (store.operands[1].imm & 0xFFFFFFFF) != link_target or
            fixup is None or fixup.source_type != 0x07 or fixup.target_object != 1 or
            image.objects[0].base + fixup.target_offset != link_target):
        raise SystemExit(f"vsscanf callback LE-fixup contract changed for callsite 0x{callsite:08X}")
    # The target is activated only if this callsite is actually present in the
    # requested closure, avoiding unused allowlists in unrelated partial lifts.
static_vsscanf_callback_targets = {0xD73FD:{0xC8365}, 0xD7404:{0xC838E}}

deferred_indirect_sites = set()
for text in args.deferred_indirect_call:
    try:
        site = int(text, 0)
    except ValueError:
        raise SystemExit(f"invalid --deferred-indirect-call address: {text}")
    if site in deferred_indirect_sites:
        raise SystemExit(f"duplicate deferred indirect callsite 0x{site:08X}")
    deferred_indirect_sites.add(site)

indexed_cs_tables = {}
for row in args.indexed_cs_table:
    if "=" not in row:
        raise SystemExit(f"invalid --indexed-cs-table {row!r}; expected SITE=TABLE_LINK:COUNT:BASE_REG:INDEX_REG")
    site_text, detail = row.split("=", 1)
    parts = detail.split(":")
    if len(parts) != 4:
        raise SystemExit(f"invalid --indexed-cs-table {row!r}; expected SITE=TABLE_LINK:COUNT:BASE_REG:INDEX_REG")
    try:
        site = int(site_text, 0)
        table_link = int(parts[0], 0)
        count = int(parts[1], 0)
    except ValueError:
        raise SystemExit(f"invalid --indexed-cs-table {row!r}; numeric fields must be hexadecimal/integer")
    regs = {"eax": "eax", "ebx": "ebx", "ecx": "ecx", "edx": "edx",
            "esi": "esi", "edi": "edi", "ebp": "ebp"}
    base_reg, index_reg = parts[2].lower(), parts[3].lower()
    if base_reg not in regs or index_reg not in regs or count <= 0 or count > 256:
        raise SystemExit(f"invalid --indexed-cs-table {row!r}; unsupported registers or count")
    if site in indexed_cs_tables:
        raise SystemExit(f"duplicate indexed CS table site 0x{site:08X}")
    table_guest = image.link_to_linear(table_link)
    owner = image.object_containing_linear(table_guest)
    if owner is None or not owner.linear_base_verified or table_guest + count + 1 > owner.linear_end:
        raise SystemExit(f"indexed CS table at 0x{table_link:08X} is outside verified loaded object")
    raw = bytes(image.mem[table_guest-image.mem_base:table_guest-image.mem_base+count+1])
    if len(raw) != count + 1 or raw[-1] != 0:
        raise SystemExit(f"indexed CS table at 0x{table_link:08X} lacks the declared NUL terminator")
    indexed_cs_tables[site] = {"table_link": table_link, "table_guest": table_guest,
                               "count": count, "base_reg": regs[base_reg],
                               "index_reg": regs[index_reg], "raw": raw}

# Deliberately narrow, per-site switch-table contracts. Each exact original
# guard is byte checked, the LE dword table is checked against its loaded
# fixups, and every destination must be an instruction block in the function.
indexed_code_jump_tables = {}
runtime_indexed_code_jump_tables = {}
code_table_contracts = {
    # Additional finite Object-1 tail-dispatch tables found while closing the
    # residual indirect sites. Each contract binds the exact original JMP,
    # its index-producing/bounds bytes and every target to canonical LE
    # fixups. These tables transfer to separate routines, so the destination
    # entries are decoded independently and still pass the runtime exact-table
    # guard; they are not treated as blocks of the dispatching function.
    0x2D696: {"table_link":0x2CF40,"count":7,"index_reg":"eax",
        "function_entry":0x2CF60,"addressing":"scaled-index",
        "dispatch_bytes":"2eff248540cf0200",
        "guard":[(0x2D688,"8a432d"),(0x2D68B,"2c03"),
                 (0x2D68D,"3c06"),(0x2D68F,"77ad"),
                 (0x2D691,"25ff000000")],"segment":"cs"},
    0x2F1BF: {"table_link":0x2E0F0,"count":4,"index_reg":"eax",
        "function_entry":0x2E100,"addressing":"scaled-index",
        "dispatch_bytes":"2eff2485f0e00200",
        "guard":[(0x2F1AB,"8aac2430010000"),(0x2F1B2,"80fd03"),
                 (0x2F1B5,"0f87d6fcffff"),(0x2F1BB,"31c0"),
                 (0x2F1BD,"88e8")],"segment":"cs"},
    0x2F48F: {"table_link":0x2F1D4,"count":14,"index_reg":"eax",
        "function_entry":0x2F210,"addressing":"scaled-index",
        "dispatch_bytes":"2eff2485d4f10200",
        "guard":[(0x2F46B,"8a842430040000"),(0x2F472,"2c02"),
                 (0x2F474,"88842478040000"),(0x2F47B,"8ab42478040000"),
                 (0x2F482,"80fe0d"),(0x2F485,"0f8770180000"),
                 (0x2F48B,"31c0"),(0x2F48D,"88f0")],"segment":"cs"},
    0x32DCA: {"table_link":0x32CC4,"count":7,"index_reg":"ebx",
        "function_entry":0x32D00,"addressing":"scaled-index",
        "dispatch_bytes":"2eff249dc42c0300",
        "guard":[(0x32D8E,"0fbe4b0c"),(0x32D92,"85c9"),
                 (0x32D94,"7c1d"),(0x32DB5,"8a5b04"),
                 (0x32DB8,"80eb07"),(0x32DBB,"80fb06"),
                 (0x32DBE,"0f8784fdffff"),(0x32DC4,"81e3ff000000")],
        "segment":"cs"},
    0xAC965: {"table_link":0xAC942,"count":4,"index_reg":"eax",
        "function_entry":0xAC8CB,"addressing":"prescaled-base",
        "dispatch_bytes":"2effa042c90a00",
        "guard":[(0xAC958,"807de403"),(0xAC95C,"77e2"),
                 (0xAC95E,"0fb645e4"),(0xAC962,"c1e002")],
        "segment":"cs","default_target":0xAC940,"index_max":3},
    0xD6868: {"table_link":0xD6818,"count":10,"index_reg":"esi",
        "function_entry":0xD6844,"addressing":"scaled-index",
        "dispatch_bytes":"2eff24b518680d00",
        "guard":[(0xD685F,"83f809"),(0xD6862,"0f87da020000")],
        "segment":"cs"},
    # IFCPlanetside's building-row renderer dispatches the live building type
    # through the canonical 12-entry CS table jpt_2473D. The original
    # SUB AL,2 / CMP AL,0Bh / JA sequence bounds the table index to 0..11;
    # every slot is an Object-1 LE fixup to a decoded block in this routine.
    0x2473D: {"table_link":0x24514,"count":12,"index_reg":"eax",
        "function_entry":0x24550,"addressing":"scaled-index",
        "dispatch_bytes":"2eff248514450200",
        "guard":[(0x24732,"2c02"),(0x24734,"3c0b"),
                 (0x24736,"77f3"),(0x24738,"25ff000000")],"segment":"cs"},
    # V29: Gene Pod panel gadget-event handler (Building secondary vtable slot 1,
    # 0x69D00 -> 0x68380). SUB EDI,7 / CMP DI,3 / JA bound the gadget id to 7..10;
    # the 4-slot CS table 0x68370 is LE-fixup-backed (0x68C45/0x6893D/0x6873E/0x68846,
    # all blocks of 0x68380).
    0x68736: {"table_link":0x68370,"count":4,"index_reg":"eax",
        "function_entry":0x68380,"addressing":"scaled-index",
        "dispatch_bytes":"2eff248570830600",
        "guard":[(0x68724,"83ef07"),(0x68727,"6683ff03"),
                 (0x6872B,"0f8756050000"),(0x68731,"31c0"),
                 (0x68733,"6689f8")],"segment":"cs"},
    # Four bounded state dispatches in the native entity-update method at
    # 0x118E0. The LE stores one contiguous 16-slot run, viewed through four
    # overlapping slices; each JMP has its own preceding unsigned bound and
    # the exact slice length below. Every admitted entry must remain an
    # object-1 SRC_OFFSET32 fixup to a decoded block of this method.
    0x1201A: {"table_link":0x11890,"count":4,"index_reg":"eax",
        "function_entry":0x118E0,"addressing":"scaled-index",
        "dispatch_bytes":"2eff248590180100",
        "guard":[(0x1200D,"3c03"),(0x1200F,"0f8725faffff"),
                 (0x12015,"25ff000000")],"segment":"cs"},
    0x1239A: {"table_link":0x118A0,"count":5,"index_reg":"eax",
        "function_entry":0x118E0,"addressing":"scaled-index",
        "dispatch_bytes":"2eff2485a0180100",
        "guard":[(0x1238D,"3c04"),(0x1238F,"0f87a5f6ffff"),
                 (0x12395,"25ff000000")],"segment":"cs"},
    0x12A57: {"table_link":0x118B4,"count":6,"index_reg":"eax",
        "function_entry":0x118E0,"addressing":"scaled-index",
        "dispatch_bytes":"2eff2485b4180100",
        "guard":[(0x12A4A,"3c05"),(0x12A4C,"0f87e8efffff"),
                 (0x12A52,"25ff000000")],"segment":"cs"},
    0x131BA: {"table_link":0x118CC,"count":5,"index_reg":"eax",
        "function_entry":0x118E0,"addressing":"scaled-index",
        "dispatch_bytes":"2eff2485cc180100",
        "guard":[(0x131AD,"3c04"),(0x131AF,"0f878cfeffff"),
                 (0x131B5,"25ff000000")],"segment":"cs"},
    # The PlSpec/Thing state switch in FUN_00047EE0 indexes MAP's jpt_47F63
    # at 0x47ECC. The original SUB AL,1 / CMP AL,3 / JA bounds types 1..4;
    # each of the four slots has an object-1 SRC_OFFSET32 LE fixup to a
    # decoded block in this function. Keep the byte-exact guard and runtime
    # target validation for this complete switch.
    0x47F63: {"table_link":0x47ECC,"count":4,"index_reg":"eax",
        "function_entry":0x47EE0,"addressing":"scaled-index",
        "dispatch_bytes":"2eff2485cc7e0400",
        "guard":[(0x47F56,"3c03"),(0x47F58,"0f873d010000"),
                 (0x47F5E,"25ff000000")],"segment":"cs"},
    # Entity-kind dispatch in the PlSpec/map interaction routine. The LE
    # subtracts one from Thing::ttype, rejects values above 3, masks EAX to
    # one byte, then uses this four-entry CS table. All entries are original
    # object-1 SRC_OFFSET32 fixups and decode as blocks in the same routine.
    0x55E20: {"table_link":0x562C0,"count":4,"index_reg":"eax",
        "function_entry":0x55CF0,"addressing":"scaled-index",
        "dispatch_bytes":"2eff2485c0620500",
        "guard":[(0x55E0E,"8a4606"),(0x55E11,"fec8"),
                 (0x55E13,"3c03"),(0x55E15,"0f870d010000"),
                 (0x55E1B,"25ff000000")],"segment":"cs"},
    # FUN_0004B1F0's secondary entity-type switch at 0x50B18 indexes four
    # adjacent object-1 fixups at 0x4B1D4 after the original byte bound.
    0x50B18: {"table_link":0x4B1D4,"count":4,"index_reg":"eax",
        "function_entry":0x4B1F0,"addressing":"scaled-index",
        "dispatch_bytes":"2eff2485d4b10400",
        "guard":[(0x50B0B,"3c03"),(0x50B0D,"0f8733010000"),
                 (0x50B13,"25ff000000")],"segment":"cs"},
    # Original game() cadence's Watcom code/state switch. The LE map names
    # jpt_492AA at 0x49140; CMP AL,0x0A / JA selects the default block for
    # out-of-range states, and AND EAX,0xFF normalizes the bounded index.
    # All eleven dwords have exact object-1 SRC_OFFSET32 fixups and resolve
    # to decoded blocks in FUN_00049170. Keep the original CS indexed JMP and
    # runtime bounds/backing checks; this is not a guessed dispatcher target.
    0x492AA: {"table_link":0x49140,"count":11,"index_reg":"eax",
        "function_entry":0x49170,"addressing":"scaled-index",
        "dispatch_bytes":"2eff248540910400",
        "guard":[(0x4929D,"3c0a"),(0x4929F,"0f870bffffff"),
                 (0x492A5,"25ff000000")],"segment":"cs"},
    # FUN_0003D470's four-way mode/state dispatch. The live object state is
    # loaded from [thing+0xC0]+0x16, checked against 0..3, zero-extended, and
    # used by the original CS table jpt_3DB3D at 0x3D460. All four entries
    # carry object-1 SRC_OFFSET32 fixups into this same function body.
    0x3DB3D: {"table_link":0x3D460,"count":4,"index_reg":"esi",
        "function_entry":0x3D470,"addressing":"scaled-index",
        "dispatch_bytes":"2eff24b560d40300",
        "guard":[(0x3DB35,"80f903"),(0x3DB38,"770b")]},
    # MapDisplay edge-scroll direction switch. The original CMP DL,7 / JA
    # bounds the direction index to 0..7; the canonical MAP names the CS
    # table jpt_7A0C4 at 0x79DA4. Its eight contiguous LE SRC_OFFSET32
    # fixups target decoded basic blocks in FUN_00079DD0 itself.
    0x7A0C4: {"table_link":0x79DA4,"count":8,"index_reg":"eax","function_entry":0x79DD0,
        "addressing":"scaled-index","dispatch_bytes":"2eff2485a49d0700",
        "guard":[(0x7A0B7,"80fa07"),(0x7A0BA,"0f8724000000")]},
    # FUN_00075750's four-way gadget-kind dispatcher. The original CMP DL,3 /
    # JA guard bounds EDX to 0..3, and the canonical LE MAP names the CS table
    # jpt_7583A at 0x75734. All four dwords have SRC_OFFSET32 fixups to local
    # blocks in this same function; this is a static, bounded code table.
    0x7583A: {"table_link":0x75734,"count":4,"index_reg":"edx","function_entry":0x75750,
        "addressing":"scaled-index","dispatch_bytes":"2eff249534570700",
        "guard":[(0x7582F,"80fa03"),(0x75832,"77ea")]},
    # IFCLevel::PlugIn's nine-case initialization switch. The original
    # CMP/JGE and CMP/JA constrain the zero-extended AL index to 0..8; the
    # contiguous LE table at 0x156E0 has nine SRC_OFFSET32 fixups into this
    # same function body.
    0x159CF: {"table_link":0x156E0,"count":9,"index_reg":"edx","function_entry":0x15710,
        "addressing":"scaled-index","dispatch_bytes":"2eff2495e0560100",
        "guard":[(0x159C2,"83fa09"),(0x159C5,"7d10"),
                 (0x159C7,"3c08"),(0x159C9,"77f1")]},
    # Four-way game/level generator switch reached after Smacker's original
    # cleanup returns into the IFCLevel setup path. MAP identifies the LE
    # table at 0x751DC; all four dwords carry SRC_OFFSET32 fixups to blocks in
    # FUN_000751F0, and CMP BL,3 / JA bounds the index before JMP [CS:EAX*4+].
    0x7520F: {"table_link":0x751DC,"count":4,"index_reg":"eax","function_entry":0x751F0,
        "addressing":"scaled-index","dispatch_bytes":"2eff2485dc510700",
        "guard":[(0x75202,"80fb03"),(0x75205,"0f87b7010000")]},
    # FUN_00083BF0's glyph/render-code switch. The LE MAP names jpt_83F60 at
    # 0x83AD4; CMP CH,0x45 / JA 0x84EEE bounds the original byte index to 70
    # slots, each with an exact object-1 SRC_OFFSET32 fixup to a local block.
    0x83F60: {"table_link":0x83AD4,"count":0x46,"index_reg":"eax","function_entry":0x83BF0,
        "addressing":"scaled-index","dispatch_bytes":"2eff2485d43a0800",
        "guard":[(0x83F53,"80fd45"),(0x83F56,"0f87920f0000")]},
    # setup_game's mode/error text switch: MAP names the table jpt_94D56 and
    # default block def_94D56. Original CMP/JA bounds EAX to five entries.
    0x94D56: {"table_link":0x94AA4,"count":5,"index_reg":"eax","function_entry":0x94AC0,
        "addressing":"scaled-index","dispatch_bytes":"2eff2485a44a0900",
        "guard":[(0x94D4D,"3c04"),(0x94D4F,"7747"),(0x94D51,"25ff000000")]},
    # InitAudio_ (MAP symbol at 0xAF200) reaches this resource-format helper.
    # Ghidra function boundaries split its computed switch arms, but the LE
    # contains an explicit CMP/JA guard and two map-named CS tables.  Their
    # entries are relocation-checked below against the complete CFG.
    0xCA80E: {"table_link": 0xCA758, "count": 4, "index_reg": "eax", "function_entry": 0xCA780,
        "addressing": "scaled-index", "dispatch_bytes":"2eff248558a70c00",
        "guard": [(0xCA805,"83f803"),(0xCA808,"0f878e000000")]},
    0xCA9E0: {"table_link": 0xCA768, "count": 4, "index_reg": "eax", "function_entry": 0xCA780,
        "addressing": "scaled-index", "dispatch_bytes":"2eff248568a70c00",
        "guard": [(0xCA9DB,"83f803"),(0xCA9DE,"773f")]},
    # process_packets' end-of-handler dispatch at 0x9358B uses MAP's
    # jpt_9358B at 0x92F7C. All 35 contiguous entries have exact object-1
    # SRC_OFFSET32 LE fixups and target blocks inside process_packets' CFG.
    # There is no verified original upper-bound branch at the dispatch, so
    # the emitted guest read is explicitly range-checked to indices 0..34.
    0x9358B: {"table_link":0x92F7C,"count":35,"index_reg":"edx",
        "function_entry":0x93010,"addressing":"scaled-index",
        "dispatch_bytes":"2eff24957c2f0900","guard":[]},
    # FUN_0004B1F0's packet-kind dispatch is MAP's jpt_505B7 at 0x4B170.
    # The original CMP AL,0x18 / JA bounds the byte selector to 0..24;
    # AND EAX,0xff preserves that selector before the CS-indexed JMP.
    # All 25 entries are contiguous SRC_OFFSET32 fixups to blocks in this
    # same decoded function. Admit the complete table, not a live index, and
    # retain the emitted runtime bounds/backing check.
    0x505B7: {"table_link":0x4B170,"count":25,"index_reg":"eax",
        "function_entry":0x4B1F0,"addressing":"scaled-index",
        "dispatch_bytes":"2eff248570b10400",
        "guard":[(0x505AA,"3c18"),(0x505AC,"0f875faeffff"),
                 (0x505B2,"25ff000000")]},
    0x70ED1: {"table_link": 0x70E9C, "count": 4, "index_reg": "eax", "function_entry": 0x70EB0,
        "addressing": "scaled-index",
        "dispatch_bytes":"2eff24859c0e0700",
        "guard": [(0x70EC2,"663d0300"),(0x70EC6,"0f87a4010000"),(0x70ECC,"25ffff0000")]},
    0x6F854: {"table_link": 0x6F7C0, "count": 31, "index_reg": "ebx", "function_entry": 0x6F840,
        "addressing": "scaled-index",
        "dispatch_bytes":"2eff249dc0f70600",
        "guard": [(0x6F841,"8a1a"),(0x6F843,"fecb"),(0x6F845,"80fb1e"),
                  (0x6F848,"0f87aa000000"),(0x6F84E,"81e3ff000000")]},
    0x6B064: {"table_link": 0x6AB08, "count": 10, "index_reg": "eax", "function_entry": 0x13600,
        "addressing": "scaled-index", "dispatch_bytes":"2eff248508ab0600",
        "guard": [(0x6B055,"663d0900"),(0x6B059,"0f87c8fbffff"),(0x6B05F,"25ffff0000")]},
    0x57A0C: {"table_link": 0x57900, "count": 8, "index_reg": "edx", "function_entry": 0x57900,
        "addressing": "scaled-index", "dispatch_bytes":"2eff249500790500",
        "guard": [(0x579F8,"8a5202"),(0x579FB,"feca"),(0x579FD,"80fa07"),
                  (0x57A00,"0f8729ffffff"),(0x57A06,"81e2ff000000")]},
    0xA1611: {"table_link": 0xA1524, "count": 5, "index_reg": "eax", "function_entry": 0xA1540,
        "addressing": "scaled-index", "dispatch_bytes":"2eff248524150a00",
        "guard": [(0xA1608,"3c04"),(0xA160A,"7719"),(0xA160C,"25ff000000")]},
    # Sound-manager frame work's ten-way format/device switch. The original
    # CMP AL,9 / JA bounds the zero-extended EAX index; every dword in the
    # CS table at CBC48 has an object-1 LE SRC_OFFSET32 fixup to a decoded
    # block in this exact function body.
    0xCBC93: {"table_link":0xCBC48,"count":10,"index_reg":"eax",
        "function_entry":0xCBC70,"addressing":"scaled-index",
        "dispatch_bytes":"2eff248548bc0c00",
        "guard":[(0xCBC86,"3c09"),(0xCBC88,"0f8733020000"),
                 (0xCBC8E,"25ff000000")]},
    # These Watcom switches scale EAX explicitly before indexing a CS dword
    # table. The exact compare/branch/zero-extend/shift chain is part of each
    # per-site contract, so this does not admit an unbounded computed jump.
    0xC22B5: {"table_link": 0xC2283, "count": 5, "index_reg": "eax", "function_entry": 0xC208E,
        "addressing": "prescaled-base", "dispatch_bytes":"2effa083220c00",
        "guard": [(0xC22A2,"80bd50ffffff04"),(0xC22A9,"77c1"),
                  (0xC22AB,"0fb68550ffffff"),(0xC22B2,"c1e002")],
        "default_target": 0xC226C, "index_max": 4},
    0xC2500: {"table_link": 0xC24DB, "count": 4, "index_reg": "eax", "function_entry": 0xC23EA,
        "addressing": "prescaled-base", "dispatch_bytes":"2effa0db240c00",
        "guard": [(0xC24F3,"807dd403"),(0xC24F7,"77d2"),
                  (0xC24F9,"0fb645d4"),(0xC24FD,"c1e002")],
        "default_target": 0xC24CB, "index_max": 3},
    0xC2D7B: {"table_link": 0xC2D54, "count": 5, "index_reg": "eax", "function_entry": 0xC2C43,
        "addressing": "prescaled-base", "dispatch_bytes":"2effa0542d0c00",
        "guard": [(0xC2D6E,"807dd804"),(0xC2D72,"77de"),
                  (0xC2D74,"0fb645d8"),(0xC2D78,"c1e002")],
        "default_target": 0xC2D52, "index_max": 4},
    0xC28EC: {"table_link": 0xC28B9, "count": 5, "index_reg": "eax", "function_entry": 0xC25EA,
        "addressing": "prescaled-base", "dispatch_bytes":"2effa0b9280c00",
        "guard": [(0xC28D9,"80bd3cffffff04"),(0xC28E0,"77d5"),
                  (0xC28E2,"0fb6853cffffff"),(0xC28E9,"c1e002")],
        "default_target": 0xC28B7, "index_max": 4},
    # FUN_000E19C0's state switch. MAP names the inline table jpt_E1B20 at
    # E1B27; exactly 27 consecutive SRC_OFFSET32 fixups end at E1B90, with
    # code resuming at E1B93. The live decoder-state index has no immediate
    # bounds branch at this dispatch, so the generated path bounds the table
    # read and traps if the state is outside 0..26. No segment override means
    # the original effective segment is DS.
    0xE1B20: {"table_link":0xE1B27,"count":27,"index_reg":"eax","function_entry":0xE19C0,
        "addressing":"scaled-index","dispatch_bytes":"ff2485271b0e00","guard":[],"segment":"ds"},
    # Smacker's active decode-state machine has parallel, LE-fixed 27-way
    # tables. Their entries are all contiguous object-1 SRC_OFFSET32 fixups;
    # emitted dispatches retain a runtime EAX bounds/backing check.
    0xE242D: {"table_link":0xE2434,"count":27,"index_reg":"eax","function_entry":0xE19C0,
        "addressing":"scaled-index","dispatch_bytes":"ff248534240e00","guard":[],"segment":"ds"},
    0xE2D5B: {"table_link":0xE2D62,"count":27,"index_reg":"eax","function_entry":0xE19C0,
        "addressing":"scaled-index","dispatch_bytes":"ff2485622d0e00","guard":[],"segment":"ds"},
    0xE31DA: {"table_link":0xE31E1,"count":27,"index_reg":"eax","function_entry":0xE19C0,
        "addressing":"scaled-index","dispatch_bytes":"ff2485e1310e00","guard":[],"segment":"ds"},
    # MAP's jpt_E4148 is a 16-entry jump table in the authentic frame decoder.
    # Every slot is a contiguous LE SRC_OFFSET32 fixup into FUN_000E19C0;
    # the runtime still bounds EAX and verifies the selected relocated target.
    0xE4148: {"table_link":0xE4150,"count":16,"index_reg":"eax","function_entry":0xE19C0,
        "addressing":"scaled-index","dispatch_bytes":"ff248550410e00","guard":[],"segment":"ds"},
    # Parallel 16-state dispatches in the same original frame decoder. Both
    # have 16 contiguous object-1 fixups and the preceding AND masks their
    # indexes to 0..15; the generated access remains bounded and fail-closed.
    0xE4453: {"table_link":0xE445A,"count":16,"index_reg":"esi","function_entry":0xE19C0,
        "addressing":"scaled-index","dispatch_bytes":"ff24b55a440e00","guard":[],"segment":"ds"},
    0xE83CF: {"table_link":0xE83E0,"count":16,"index_reg":"eax","function_entry":0xE19C0,
        "addressing":"scaled-index","dispatch_bytes":"ff2485e0830e00","guard":[],"segment":"ds"},
    # FUN_0004AB10 state dispatch. MAP names jpt_4AB28 at 0x4AAA0; all 28
    # entries are contiguous object-1 SRC_OFFSET32 fixups. CMP AL,0x1B / JA
    # bounds the natural state, then AND EAX,0xFF zero-extends the index.
    # Two terminal entries target the decoded shared block 0x490FB in the
    # separate FUN_00048E30 body; all other entries target FUN_0004AB10.
    0x4AB28: {"table_link":0x4AAA0,"count":28,"index_reg":"eax","function_entry":0x4AB10,
        "addressing":"scaled-index","dispatch_bytes":"2eff2485a0aa0400",
        "guard":[(0x4AB1B,"3c1b"),(0x4AB1D,"0f8740040000"),(0x4AB23,"25ff000000")],
        "segment":"cs","external_cfg_targets":{0x490FB:0x48E30}},
    # FUN_00078B30 dispatches the entity-type cases through MAP table
    # jpt_790AA. The CMP AL,6 / JA path bounds types to seven entries before
    # the byte mask and CS indexed JMP; every entry has an object-1 fixup.
    0x790AA: {"table_link":0x78B10,"count":7,"index_reg":"eax","function_entry":0x78B30,
        "addressing":"scaled-index","dispatch_bytes":"2eff2485108b0700",
        "guard":[(0x7909D,"3c06"),(0x7909F,"0f87e2fdffff"),(0x790A5,"25ff000000")],
        "segment":"cs"},
    # IFCPlanetside::Update dispatches packet/UI actions through MAP
    # jpt_21AEB. The original DEC DL / CMP DL,7 / JA bounds the 8 slots,
    # followed by AND EDX,0xff. Admit the complete table only with all eight
    # contiguous Object 1 LE fixups and preserve runtime index/target checks.
    0x21AEB: {"table_link":0x21354,"count":8,"index_reg":"edx",
        "function_entry":0x21380,"addressing":"scaled-index",
        "dispatch_bytes":"2eff249554130200",
        "guard":[(0x21ADC,"80fa07"),(0x21ADF,"0f8726020000"),
                 (0x21AE5,"81e2ff000000")],"segment":"cs"},
    # BioGame effect initialization's 65-way type dispatch. The live type at
    # 0x8936F is normalized by SUB AL,6, bounded by CMP AL,0x40 / JA, then
    # zero-extended before indexing MAP's jpt_8936F. All 65 entries are
    # contiguous object-1 SRC_OFFSET32 fixups. Keep the index and relocated
    # target checks active at runtime; the live EAX=0x2B selects slot 43.
    0x8936F: {"table_link":0x86704,"count":65,"index_reg":"eax","function_entry":0x86810,
        "addressing":"scaled-index","dispatch_bytes":"2eff248504670800",
        "guard":[(0x89362,"3c40"),(0x89364,"0f874bd6ffff"),(0x8936A,"25ff000000")],
        "segment":"cs"},
    # PlSpec/entity lifecycle switch reached after landing. The LE embeds a
    # seven-entry CS table immediately before FUN_0003F680; CMP AL,6 / JA
    # bounds the state and AND EAX,0xFF zero-extends the index. Every slot is
    # an original object-1 SRC_OFFSET32 fixup to a block in this routine.
    0x3F69A: {"table_link":0x3F664,"count":7,"index_reg":"eax","function_entry":0x3F680,
        "addressing":"scaled-index","dispatch_bytes":"2eff248564f60300",
        "guard":[(0x3F68D,"3c06"),(0x3F68F,"0f87a7020000"),(0x3F695,"25ff000000")],
        "segment":"cs"},
    # PlSpec interaction/state helper reached after an IFC_MOVE_GO order.
    # Its mode-class dispatch at 0x3DBDD is bounded by CMP AL,3 / JA to the
    # shared epilogue and zero-extends EAX before indexing four contiguous
    # object-1 LE SRC_OFFSET32 fixups at 0x3DB60.
    0x3DBDD: {"table_link":0x3DB60,"count":4,"index_reg":"eax",
        "function_entry":0x3DB70,"addressing":"scaled-index",
        "dispatch_bytes":"2eff248560db0300",
        "guard":[(0x3DBD0,"3c03"),(0x3DBD2,"0f878a100000"),
                 (0x3DBD8,"25ff000000")],"segment":"cs"},
    # The PlSpec lifecycle continuation reached after 0x3DBDD performs a
    # six-way state dispatch at 0x4103A. CMP AX,5 / JA bounds the index;
    # AND EAX,0xFFFF clears the upper half before the CS lookup. All six
    # adjacent table entries are LE object-1 fixups to original code blocks.
    0x4103A: {"table_link":0x40390,"count":6,"index_reg":"eax",
        "function_entry":0x403B0,"addressing":"scaled-index",
        "dispatch_bytes":"2eff248590030400",
        "guard":[(0x4102B,"663d0500"),(0x4102F,"0f878e070000"),
                 (0x41035,"25ffff0000")],"segment":"cs"},
    # Building/entity-type update path inside the 0x39F20 lifecycle routine.
    # The type-1..12 index is bounded by CMP AL,11 / JA, then zero-extended;
    # all twelve entries at the CS table are LE object-1 fixups.
    0x3C6A8: {"table_link":0x39EE4,"count":12,"index_reg":"eax",
        "function_entry":0x39F20,"addressing":"scaled-index",
        "dispatch_bytes":"2eff2485e49e0300",
        "guard":[(0x3C69F,"3c0b"),(0x3C6A1,"775a"),
                 (0x3C6A3,"25ff000000")],"segment":"cs"},
    # FUN_00044570's 12-way PlSpec update/action dispatch. The state is
    # decremented, bounded by CMP AL,0x0B / JA, and zero-extended before the
    # CS table; the 12 LE fixups all target blocks in this same function.
    0x44A31: {"table_link":0x4450C,"count":12,"index_reg":"eax","function_entry":0x44570,
        "addressing":"scaled-index","dispatch_bytes":"2eff24850c450400",
        "guard":[(0x44A22,"28d8"),(0x44A24,"3c0b"),(0x44A26,"0f8732030000"),
                  (0x44A2C,"25ff000000")],"segment":"cs"},
    # Secondary PlSpec state/action switch in the same FUN_00044570. The
    # decremented state is bounded to 0..11 before this CS-relative table;
    # all twelve destinations are LE SRC_OFFSET32 fixups into this routine.
    0x44EA3: {"table_link":0x4453C,"count":12,"index_reg":"eax","function_entry":0x44570,
        "addressing":"scaled-index","dispatch_bytes":"2eff24853c450400",
        "guard":[(0x44E94,"fec8"),(0x44E96,"3c0b"),(0x44E98,"0f8792010000"),
                  (0x44E9E,"25ff000000")],"segment":"cs"},
    # IFCPlanetside's specialist-mode dispatcher at 0x6DB38 uses a bounded
    # four-entry CS table. CMP CL,3 / JA / AND ECX,0xff guards the index, and
    # every dword has an object-1 LE fixup into the decoded CFG rooted at 6D230.
    0x6DB38: {"table_link":0x6D21C,"count":4,"index_reg":"ecx","function_entry":0x6D230,
        "addressing":"scaled-index","dispatch_bytes":"2eff248d1cd20600",
        "guard":[(0x6DB29,"80f903"),(0x6DB2C,"0f871efaffff"),
                 (0x6DB32,"81e1ff000000")],"segment":"cs"},
    # The PA_ABORT_MOVE handler at 0x76C00 contains an eleven-way action
    # subdispatch. CMP AX,10 / JA and AND EAX,0xffff bound it; all slots are
    # object-1 SRC_OFFSET32 fixups to decoded blocks of that handler.
    0x76C21: {"table_link":0x76BCC,"count":11,"index_reg":"eax","function_entry":0x76C00,
        "addressing":"scaled-index","dispatch_bytes":"2eff2485cc6b0700",
        "guard":[(0x76C12,"663d0a00"),(0x76C16,"0f879ef3ffff"),
                 (0x76C1C,"25ffff0000")],"segment":"cs"},
    # PlSpec class-state switch in func_3ECA0. The original byte guard
    # bounds the class to 0..3, and the four contiguous dwords at 0x3EC88
    # are object-1 LE SRC_OFFSET32 fixups to decoded blocks in this routine.
    0x3F024: {"table_link":0x3EC88,"count":4,"index_reg":"ebx",
        "function_entry":0x3ECA0,"addressing":"scaled-index",
        "dispatch_bytes":"2eff249d88ec0300",
        "guard":[(0x3F015,"80fb03"),(0x3F018,"0f87b3fcffff"),
                 (0x3F01E,"81e3ff000000")],"segment":"cs"},
    # Building update's type/state dispatch. The original byte state is
    # bounded by CMP AL,0x0B / JA and zero-extended before indexing the
    # twelve LE-fixed Object-1 case blocks in jpt_39083.
    0x39083: {"table_link":0x38EC4,"count":12,"index_reg":"eax",
        "function_entry":0x38F00,"addressing":"scaled-index",
        "dispatch_bytes":"2eff2485c48e0300",
        "guard":[(0x3907A,"3c0b"),(0x3907C,"7762"),
                 (0x3907E,"25ff000000")],"segment":"cs"},
    # Building::Update has a second type dispatch after the initial state
    # switch. CMP AL,0x0D / JA bounds the type to 0..13; all 14 entries in
    # the LE table at 0x39EAC are contiguous Object-1 SRC_OFFSET32 fixups.
    # The exact CS indexed JMP remains guarded and target-checked at runtime.
    0x3A18E: {"table_link":0x39EAC,"count":14,"index_reg":"eax",
        "function_entry":0x38F00,"addressing":"scaled-index",
        "dispatch_bytes":"2eff2485ac9e0300",
        "guard":[(0x3A181,"3c0d"),(0x3A183,"0f8777240000"),
                 (0x3A189,"25ff000000")],"segment":"cs",
        # The type-specific Building handlers are separate CFG roots. These
        # LE-fixed targets are decoded at their own entry points below.
        "external_cfg_targets":{
            0x3A196:0x3A196,0x3BB81:0x3BB81,0x3B212:0x3B212,
            0x3A853:0x3A853,0x3AED1:0x3AED1,0x3BA28:0x3BA28,
            0x3AB93:0x3AB93,0x3C3AA:0x3C3AA,0x3C600:0x3C600,
            0x3BB01:0x3BB01,0x3B57A:0x3B57A,0x3C140:0x3C140,
            0x3BFE9:0x3BFE9}},
    # PlSpec mode-state dispatch at 0x3F5AC. The original byte guard bounds
    # [mode+0x16] to 0..3 before indexing the four contiguous SRC_OFFSET32
    # Object-1 entries in jpt_3F5AC at 0x3F1A4. Class 0 (Ralph) is entry 0;
    # do not treat the live zero index as a null function pointer.
    0x3F5AC: {"table_link":0x3F1A4,"count":4,"index_reg":"eax",
        "function_entry":0x3F1C0,"addressing":"scaled-index",
        "dispatch_bytes":"2eff2485a4f10300",
        "guard":[(0x3F59F,"3c03"),(0x3F5A1,"0f8716fdffff"),
                 (0x3F5A7,"25ff000000")],"segment":"cs",
        "external_cfg_targets":{
            0x3F3F1:0x3F3F1,0x3F528:0x3F528,
            0x3F577:0x3F577,0x3F558:0x3F558}},
    # Thing/building type switch in FUN_000114B0. The original CMP/JA at
    # 0x11602..0x11605 bounds DL to 0..11; the LE table contains 12 contiguous
    # Object-1 fixups, all resolving to the two original in-function arms.
    0x1160D: {"table_link":0x11478,"count":12,"index_reg":"edx",
        "function_entry":0x114B0,"addressing":"scaled-index",
        "dispatch_bytes":"2eff249578140100",
        "guard":[(0x11602,"80fa0b"),(0x11605,"77f4"),
                 (0x11607,"81e2ff000000")],"segment":"cs",
        "external_cfg_targets":{0x115F7:0x115F7,0x115FB:0x115FB}},
    # FUN_0006B5C0 dispatches by the original Thing::ttype after subtracting
    # 2 and bounding AL to 0..11. The complete CS table at 0x6B584 contains
    # 12 Object-1 SRC_OFFSET32 fixups (three distinct in-function blocks);
    # retain the exact CMP/JA/AND and indirect-JMP bytes as runtime bounds.
    0x6B94A: {"table_link":0x6B584,"count":12,"index_reg":"eax",
        "function_entry":0x6B5C0,"addressing":"scaled-index",
        "dispatch_bytes":"2eff248584b50600",
        "guard":[(0x6B93C,"8a462d"),(0x6B93F,"2c02"),
                 (0x6B941,"3c0b"),(0x6B943,"77ed"),
                 (0x6B945,"25ff000000")],"segment":"cs"},
}
# Remaining fixup-backed switch tails from the batch audit. Each entry is
# byte-checked at the dispatch instruction, bounds the indexed read to the
# exact selector range, and verifies the loaded target against the complete
# contiguous Object-1 SRC_OFFSET32 fixup run. The original LE guard executes
# unchanged before the host-side bounds check.
_remaining_switch_contracts = (
    (0x1086F,0x104B0,6,"eax",0x104D0,"2eff2485b0040100","scaled-index"),
    (0x266C0,0x26628,4,"eax",0x26650,"2eff248528660200","scaled-index"),
    (0x267F1,0x26638,4,"eax",0x26650,"2eff248538660200","scaled-index"),
    (0x298CA,0x28FFC,4,"eax",0x29010,"2eff2485fc8f0200","scaled-index"),
    (0x2B1F7,0x2B100,5,"ebx",0x2B120,"2eff249d00b10200","scaled-index"),
    (0x3248D,0x31680,7,"edx",0x316A0,"2eff249580160300","scaled-index"),
    (0x32D18,0x32CE0,7,"ecx",0x32D00,"2eff248de02c0300","scaled-index"),
    (0x33AE8,0x33AA4,4,"eax",0x33AC0,"2eff2485a43a0300","scaled-index"),
    (0x37873,0x37454,8,"eax",0x37480,"2eff248554740300","scaled-index"),
    (0x39390,0x392E8,12,"eax",0x39320,"2eff2485e8920300","scaled-index"),
    (0x39705,0x39614,11,"edx",0x39670,"2eff249514960300","scaled-index"),
    (0x3972F,0x39640,10,"eax",0x39670,"2eff248540960300","scaled-index"),
    (0x3A077,0x39E80,11,"edx",0x39F20,"2eff2495809e0300","scaled-index"),
    (0x3DE6D,0x3DB50,4,"eax",0x3DB70,"2eff248550db0300","scaled-index"),
    (0x64BCB,0x64990,7,"eax",0x649B0,"2eff248590490600","scaled-index"),
    (0x71424,0x713EC,6,"ecx",0x69E10,"2eff248dec130700","scaled-index"),
    (0x72EEA,0x72D40,27,"eax",0x69E10,"2eff2485402d0700","scaled-index"),
    (0x84674,0x83AA0,6,"eax",0x83BF0,"2eff2485a03a0800","scaled-index"),
    (0x84B26,0x83AB8,7,"eax",0x83BF0,"2eff2485b83a0800","scaled-index"),
    (0x85BEC,0x85230,4,"eax",0x85240,"2effa030520800","precomputed-scaled-base"),
    (0x85CEB,0x85230,4,"eax",0x85240,"2effa030520800","precomputed-scaled-base"),
    (0x873A0,0x866C0,7,"eax",0x86810,"2eff2485c0660800","scaled-index"),
    (0x87F30,0x866DC,10,"eax",0x86810,"2eff2485dc660800","scaled-index"),
    (0xD5B90,0xD5B58,9,"ebx",0xD5B7C,"2eff249d585b0d00","scaled-index"),
    # V35_C: plant slot-25 method FUN_000899D0; six-entry object-1 fixup table 0x899B0, original guard
    # SUB AL,2 / CMP AL,5 / JA at 0x899E5-0x899E9.
    (0x899F4,0x899B0,6,"eax",0x899D0,"2eff2485b0990800","scaled-index"),
)
for _site,_table,_count,_index,_entry,_bytes,_addressing in _remaining_switch_contracts:
    code_table_contracts[_site]={"table_link":_table,"count":_count,
        # Use the dispatch instruction as the local CFG anchor for the new
        # switches. Several contain anonymous Watcom subfunctions with no
        # MAP entry at the top of their enclosing routine; the original
        # table targets must nevertheless decode as blocks reachable from
        # this exact jump. The two precomputed-offset jumps need the earlier
        # function anchor because their targets precede the second site.
        "index_reg":_index,"function_entry":(_entry if _addressing=="precomputed-scaled-base" else _site),
        "addressing":_addressing,
        "dispatch_bytes":_bytes,"guard":[],"segment":"cs"}
code_table_contracts[0x85BEC]["guard"]=[(0x85BDF,"837d4203"),(0x85BE3,"0f8753000000"),(0x85BE9,"8b453e")]
code_table_contracts[0x85BEC].update(default_target=0x85C3C,index_max=3)
code_table_contracts[0x85CEB]["guard"]=[(0x85CDE,"837d4203"),(0x85CE2,"0f8754ffffff"),(0x85CE8,"8b453e")]
code_table_contracts[0x85CEB].update(default_target=0x85C3C,index_max=3)
# IFCLevel::Draw's shared 27-way state machine has a second, LE-fixed table
# named jpt_E1DE1 at 0xE35D3. Ghidra reports 24 references to this same table;
# Capstone confirms every one is the identical `jmp [eax*4+0xE35D3]`. The LE
# carries a contiguous SRC_OFFSET32 fixup for every slot, all to object 1 and
# to a block in FUN_000E19C0. The live state is checked against 0..26 before
# each table read; no computed target is admitted without that runtime guard.
draw_state_dispatch_sites = (
    0xE1DE1, 0xE1E1A, 0xE2016, 0xE2048, 0xE21EF, 0xE221A,
    0xE2342, 0xE2366, 0xE271B, 0xE2754, 0xE296E, 0xE29A0,
    0xE2B56, 0xE2B81, 0xE2CA9, 0xE2CCD, 0xE2EF0, 0xE2FF3,
    0xE30BA, 0xE314C, 0xE3372, 0xE346D, 0xE3537, 0xE35CC,
)
for site in draw_state_dispatch_sites:
    code_table_contracts[site] = {
        "table_link": 0xE35D3, "count": 27, "index_reg": "eax",
        "function_entry": 0xE19C0, "addressing": "scaled-index",
        "dispatch_bytes": "ff2485d3350e00", "guard": [], "segment": "ds"}
function_cfg_cache = {}
for row in args.indexed_code_jump_table:
    if "=" not in row:
        raise SystemExit(f"invalid --indexed-code-jump-table {row!r}; expected SITE=TABLE_LINK:COUNT:INDEX_REG")
    site_text, detail = row.split("=", 1)
    parts = detail.split(":")
    if len(parts) != 3:
        raise SystemExit(f"invalid --indexed-code-jump-table {row!r}; expected SITE=TABLE_LINK:COUNT:INDEX_REG")
    try:
        site, table_link, count = (int(site_text, 0), int(parts[0], 0), int(parts[1], 0))
    except ValueError:
        raise SystemExit(f"invalid --indexed-code-jump-table {row!r}; numeric fields must be hexadecimal/integer")
    index_reg = parts[2].lower()
    contract = code_table_contracts.get(site)
    if (contract is None or table_link != contract["table_link"] or
            count != contract["count"] or index_reg != contract["index_reg"] or
            site in indexed_code_jump_tables):
        raise SystemExit(f"unverified indexed code jump table contract at 0x{site:08X}")
    table_guest = image.link_to_linear(table_link)
    table_owner = image.object_containing_linear(table_guest)
    if (table_owner is None or table_owner.index != 1 or not table_owner.linear_base_verified or
            table_guest + count * 4 > table_owner.linear_end):
        raise SystemExit(f"code jump table at 0x{table_link:08X} is outside verified executable object 1")
    dispatch = next(dis.disassemble_at(site), None)
    raw_dispatch = next(link_dis.disassemble_at(site), None) if link_dis else None
    addressing = contract["addressing"]
    expected_reg = {"eax":X86_REG_EAX,"ebx":X86_REG_EBX,"ecx":X86_REG_ECX,
                    "edx":X86_REG_EDX,"esi":X86_REG_ESI}[index_reg]
    if addressing == "scaled-index":
        addressing_matches = (dispatch is not None and dispatch.operands and
            dispatch.operands[0].type == X86_OP_MEM and dispatch.operands[0].mem.base == 0 and
            dispatch.operands[0].mem.index == expected_reg and dispatch.operands[0].mem.scale == 4)
    elif addressing in ("prescaled-base","precomputed-scaled-base"):
        addressing_matches = (dispatch is not None and dispatch.operands and
            dispatch.operands[0].type == X86_OP_MEM and dispatch.operands[0].mem.base == expected_reg and
            dispatch.operands[0].mem.index == 0 and dispatch.operands[0].mem.scale == 1)
    else:
        addressing_matches = False
    table_segment = contract.get("segment", "cs").lower()
    expected_mem_segment = X86_REG_CS if table_segment == "cs" else 0 if table_segment == "ds" else -1
    if (dispatch is None or dispatch.mnemonic.lower() != "jmp" or not dispatch.operands or
            raw_dispatch is None or bytes(raw_dispatch.bytes).hex() != contract["dispatch_bytes"] or
            dispatch.operands[0].type != X86_OP_MEM or
            dispatch.operands[0].mem.segment != expected_mem_segment or not addressing_matches or
            (dispatch.operands[0].mem.disp & 0xFFFFFFFF) != table_guest):
        raise SystemExit(f"original {table_segment.upper()} code table instruction changed at 0x{site:08X}")
    for va, encoded in contract["guard"]:
        insn=next(link_dis.disassemble_at(va),None) if link_dis else None
        if insn is None or bytes(insn.bytes).hex()!=encoded:
            raise SystemExit(f"original code-table index guard changed at 0x{va:08X}")
    if addressing == "prescaled-base":
        guard_insns = [next(link_dis.disassemble_at(va), None) for va, _ in contract["guard"]]
        if (not contract.get("default_target") or contract.get("index_max") != count - 1 or
                any(insn is None for insn in guard_insns) or
                guard_insns[0].mnemonic.lower() != "cmp" or
                guard_insns[1].mnemonic.lower() != "ja" or
                (guard_insns[1].operands[0].imm & 0xFFFFFFFF) != contract["default_target"] or
                guard_insns[2].mnemonic.lower() != "movzx" or
                guard_insns[3].mnemonic.lower() != "shl" or
                guard_insns[3].operands[-1].imm != 2):
            raise SystemExit(f"pre-scaled code-table index guard is not a bounded 0..{count-1} dispatch at 0x{site:08X}")
    if addressing == "precomputed-scaled-base":
        gi=[next(link_dis.disassemble_at(va),None) for va,_ in contract["guard"]]
        cmp_ok=(len(gi)==3 and gi[0] is not None and gi[0].mnemonic.lower()=="cmp" and
            gi[0].operands[-1].type==X86_OP_IMM and (gi[0].operands[-1].imm&0xFFFFFFFF)==count-1)
        ja_ok=(len(gi)==3 and gi[1] is not None and gi[1].mnemonic.lower()=="ja" and
            (gi[1].operands[0].imm&0xFFFFFFFF)==contract.get("default_target",-1))
        load_ok=(len(gi)==3 and gi[2] is not None and gi[2].mnemonic.lower()=="mov" and
            gi[2].operands[0].type==X86_OP_REG and gi[2].operands[0].reg==X86_REG_EAX and
            gi[2].operands[1].type==X86_OP_MEM and gi[2].operands[1].mem.base==X86_REG_EBP and
            (gi[2].operands[1].mem.disp&0xFFFFFFFF)==0x3E)
        if (not cmp_ok or not ja_ok or not load_ok or contract.get("index_max")!=count-1 or
            not contract.get("default_target")):
            raise SystemExit(f"precomputed code-table offset lacks its exact bounded LE guard at 0x{site:08X}")
    raw = bytes(image.mem[table_guest-image.mem_base:table_guest-image.mem_base+count*4])
    if len(raw) != count * 4:
        raise SystemExit(f"short relocated code jump table at 0x{table_link:08X}")
    raw_link=(link_code[table_link-link_obj.base:table_link-link_obj.base+count*4]
              if link_dis and link_obj and link_obj.base <= table_link and
                 table_link + count*4 <= link_obj.end else b"")
    link_targets=list(struct.unpack("<"+"I"*count,raw_link)) if len(raw_link)==count*4 else []
    targets = list(struct.unpack("<"+"I"*count,raw))
    expected_targets=[image.link_to_linear(target) for target in link_targets]
    if (len(link_targets)!=count or targets!=expected_targets or
            any(image.object_containing(target) is not table_owner for target in link_targets)):
        raise SystemExit(f"code jump table values/fixups disagree at 0x{table_link:08X}")
    fixup_slots=[]
    for index,target_link in enumerate(link_targets):
        source_link=table_link+index*4
        fixup=next((item for item in image.fixups if item.source_link==source_link),None)
        target_obj=image.object_containing(target_link)
        if (fixup is None or target_obj is None or fixup.target_object!=target_obj.index or
                target_obj.base+fixup.target_offset!=target_link):
            raise SystemExit(f"code jump table slot 0x{source_link:08X} lacks its exact LE object fixup")
        fixup_slots.append({"index":index,"source_link":source_link,
            "target_object":fixup.target_object,"target_offset":fixup.target_offset,
            "target_link":target_link})
    fn = function_cfg_cache.get(contract["function_entry"]) if link_dis else None
    if link_dis and fn is None:
        fn = link_dis.disassemble_function(contract["function_entry"])
        function_cfg_cache[contract["function_entry"]] = fn
    target_set = set(fn.jump_targets) if fn else set()
    target_links = [image.linear_to_link(target) for target in targets]
    block_starts={insn.address for block in fn.blocks.values() for insn in block.instructions} if fn else set()
    external_target_starts=set()
    external_cfg_targets=contract.get("external_cfg_targets",{})
    for external_target, external_entry in external_cfg_targets.items():
        external_fn=link_dis.disassemble_function(external_entry) if link_dis else None
        external_blocks={insn.address for block in external_fn.blocks.values()
                         for insn in block.instructions} if external_fn else set()
        if external_target not in external_blocks:
            raise SystemExit(f"external code-table target 0x{external_target:08X} is not a decoded block in 0x{external_entry:08X}")
        external_target_starts.add(external_target)
    if (addressing == "scaled-index" and
            (not set(target_links).issubset(target_set | set(external_cfg_targets) | external_target_starts) or
             not set(target_links).issubset(block_starts | external_target_starts)) or
            addressing in ("prescaled-base","precomputed-scaled-base") and
            (len(target_links) != count or any(not fn.address <= target < fn.end for target in target_links) or
             not fn.address <= contract["default_target"] < fn.end) or
            any(image.object_containing(target_link) is not table_owner for target_link in target_links)):
        raise SystemExit(f"code switch targets disagree with original LE CFG at 0x{site:08X}: {target_links!r}")
    indexed_code_jump_tables[site] = {"table_link": table_link, "table_guest": table_guest,
                                     "count": count, "index_reg": index_reg,
                                     "addressing": addressing,
                                     "segment": table_segment.upper(),
                                     "function_entry": contract["function_entry"],
                                     "default_target": contract.get("default_target"),
                                     "targets": target_links, "targets_guest": targets, "raw": raw,
                                     "fixup_slots":fixup_slots}

# This Smacker decoder table is zero-filled in the LE image and populated by
# original MOV instructions in _Unsmack. Admit only the observed variant's
# exact four targets; the emitted Runtime guard compares the live indexed
# entry against that per-index target and fails closed on any other state.
runtime_code_table_contracts = {
    0xEDEAD: {
        "table_link":0x10C950,"count":4,"index_reg":"ecx",
        "dispatch_bytes":"ff248d50c91000",
        "index_copy_site":0xEDE96,"index_copy_bytes":"8bc8",
        "index_mask_site":0xEDE9E,"index_mask_bytes":"83e103",
        "writers":[
            (0xEDBE9,0x10C950,0xECCF0,"c70550c91000f0cc0e00"),
            (0xEDBF3,0x10C954,0xED030,"c70554c9100030d00e00"),
            (0xEDBFD,0x10C958,0xED840,"c70558c9100040d80e00"),
            (0xEDC07,0x10C95C,0xED990,"c7055cc9100090d90e00"),
        ],
        "symbols":["_SmackInternal010","_SmackInternal011",
                    "_SmackInternal012","_SmackInternal013"],
    }
}
for row in args.runtime_indexed_code_jump_table:
    if "=" not in row:
        raise SystemExit(f"invalid --runtime-indexed-code-jump-table {row!r}; expected SITE=TABLE_LINK:COUNT:INDEX_REG")
    site_text, detail = row.split("=",1)
    parts = detail.split(":")
    if len(parts) != 3:
        raise SystemExit(f"invalid --runtime-indexed-code-jump-table {row!r}; expected SITE=TABLE_LINK:COUNT:INDEX_REG")
    try:
        site,table_link,count = int(site_text,0),int(parts[0],0),int(parts[1],0)
    except ValueError:
        raise SystemExit(f"invalid --runtime-indexed-code-jump-table {row!r}; numeric fields must be hexadecimal/integer")
    index_reg=parts[2].lower()
    contract=runtime_code_table_contracts.get(site)
    if (contract is None or site in runtime_indexed_code_jump_tables or
            table_link!=contract["table_link"] or count!=contract["count"] or
            index_reg!=contract["index_reg"]):
        raise SystemExit(f"unverified runtime-indexed code table at 0x{site:08X}")
    table_guest=image.link_to_linear(table_link)
    owner=image.object_containing_linear(table_guest)
    if owner is None or owner.index!=3 or not owner.linear_base_verified or table_guest+count*4>owner.linear_end:
        raise SystemExit(f"runtime code table 0x{table_link:08X} is outside verified object 3 backing")
    dispatch=next(dis.disassemble_at(site),None)
    raw_dispatch=next(link_dis.disassemble_at(site),None) if link_dis else None
    if (dispatch is None or raw_dispatch is None or dispatch.mnemonic.lower()!="jmp" or
            bytes(raw_dispatch.bytes).hex()!=contract["dispatch_bytes"] or
            not dispatch.operands or dispatch.operands[0].type!=X86_OP_MEM or
            dispatch.operands[0].mem.base or dispatch.operands[0].mem.index!=X86_REG_ECX or
            dispatch.operands[0].mem.scale!=4 or
            (dispatch.operands[0].mem.disp&0xFFFFFFFF)!=table_guest or
            dispatch.operands[0].size!=4):
        raise SystemExit(f"original runtime-indexed code-jump instruction changed at 0x{site:08X}")
    for guard_site,expected in ((contract["index_copy_site"],contract["index_copy_bytes"]),
                                (contract["index_mask_site"],contract["index_mask_bytes"])):
        guard=next(link_dis.disassemble_at(guard_site),None)
        if guard is None or bytes(guard.bytes).hex()!=expected:
            raise SystemExit(f"original Smacker table index guard changed at 0x{guard_site:08X}")
    targets=[]
    for writer_site,slot,target,expected in contract["writers"]:
        writer=next(link_dis.disassemble_at(writer_site),None) if link_dis else None
        if (writer is None or bytes(writer.bytes).hex()!=expected or
                writer.mnemonic.lower()!="mov" or len(writer.operands)!=2 or
                writer.operands[0].type!=X86_OP_MEM or
                (writer.operands[0].mem.disp&0xFFFFFFFF)!=slot or
                writer.operands[1].type!=X86_OP_IMM or
                (writer.operands[1].imm&0xFFFFFFFF)!=target):
            raise SystemExit(f"original Smacker jump-table writer changed at 0x{writer_site:08X}")
        target_obj=image.object_containing(target)
        if target_obj is None or target_obj.index!=1 or not target_obj.executable or not target_obj.linear_base_verified:
            raise SystemExit(f"Smacker jump-table target 0x{target:08X} is outside verified object-1 code")
        targets.append(target)
    if [map_rows.get(target) for target in targets]!=contract["symbols"]:
        raise SystemExit(f"Smacker table target MAP symbols changed: {[map_rows.get(x) for x in targets]!r}")
    runtime_indexed_code_jump_tables[site]={
        "table_link":table_link,"table_guest":table_guest,"count":count,
        "index_reg":index_reg,"targets":targets,
        "targets_guest":[image.link_to_linear(x) for x in targets],
        "expected_symbols":contract["symbols"]}

# Miles' original service switch is a CS indexed CALL rather than a JMP. Its
# Exact LE-backed indexed code-call contracts. The Switch1 decoder table is
# validated in one contiguous 256-slot pass; the independent Miles service
# table retains its existing 128-slot contract.
indexed_code_call_tables = {}
indexed_code_call_contracts = {
    # Smacker's Switch1 decode dispatch. Four original CALLs share the same
    # immutable 256-entry object-3 table. Each path masks EAX to one byte
    # before the scaled lookup; the mask and the absence of later EAX writes
    # are verified below from the canonical LE bytes.
    0xEB445: (0x10CB00, 256, "eax", "ff148500cb1000", 0xEB440, "25ff000000", 0),
    0xEB473: (0x10CB00, 256, "eax", "ff148500cb1000", 0xEB460, "25ff000000", 0),
    0xECEF5: (0x10CB00, 256, "eax", "ff148500cb1000", 0xECEF0, "25ff000000", 0),
    0xECF13: (0x10CB00, 256, "eax", "ff148500cb1000", 0xECF08, "25ff000000", 0),
    # Miles' original service switch is a 128-entry CS indexed CALL.
    0xDBEF3: (0xD8C0C, 128, "eax", "2eff14850c8c0d00", None, None, X86_REG_CS),
    # V20: the same library's software mixer dispatches each sample through a 256-slot CS table indexed by EBP (= flags word
    # [0x10CFE8], built by 0xDBC46 from bits 0x01/0x02/0x04/0x08/0x10/0x40/0x80, so always < 0x100).
    0xDBDA9: (0xD8E0C, 256, "ebp", "2eff14ad0c8e0d00", None, None, X86_REG_CS),
}
for site, (table_link, count, index_name, expected_bytes, mask_site, expected_mask_bytes, expected_segment) in indexed_code_call_contracts.items():
    table_guest = image.link_to_linear(table_link)
    owner = image.object_containing_linear(table_guest)
    table_link_owner = link_image.object_containing(table_link) if link_image else None
    link_table_data = bytes(link_image.object_data(table_link_owner.index)) if table_link_owner else b""
    dispatch = next(dis.disassemble_at(site), None)
    raw_dispatch = next(link_dis.disassemble_at(site), None) if link_dis else None
    index_register = {"eax": X86_REG_EAX, "ebp": X86_REG_EBP}[index_name]
    if (owner is None or table_link_owner is None or owner.index != table_link_owner.index or
            not owner.linear_base_verified or
            table_guest + count * 4 > owner.linear_end or dispatch is None or
            raw_dispatch is None or dispatch.mnemonic.lower() != "call" or
            not dispatch.operands or dispatch.operands[0].type != X86_OP_MEM or
            dispatch.operands[0].mem.segment != expected_segment or
            dispatch.operands[0].mem.base or dispatch.operands[0].mem.index != index_register or
            dispatch.operands[0].mem.scale != 4 or
            (dispatch.operands[0].mem.disp & 0xFFFFFFFF) != table_guest or
            dispatch.operands[0].size != 4 or
            (expected_bytes and bytes(raw_dispatch.bytes).hex() != expected_bytes)):
        raise SystemExit(f"original indexed code-call table instruction changed at 0x{site:08X}")
    if mask_site is not None:
        mask = next(link_dis.disassemble_at(mask_site), None) if link_dis else None
        if (mask is None or bytes(mask.bytes).hex() != expected_mask_bytes or
                mask.mnemonic.lower() != "and" or len(mask.operands) != 2 or
                mask.operands[0].type != X86_OP_REG or mask.operands[0].reg != X86_REG_EAX or
                mask.operands[1].type != X86_OP_IMM or mask.operands[1].imm != 0xFF or
                mask_site + mask.size > site):
            raise SystemExit(f"indexed Smacker callsite lacks its original 8-bit index mask at 0x{site:08X}")
        pc = mask_site + mask.size
        while pc < site:
            between = next(link_dis.disassemble_at(pc), None)
            if between is None or pc + between.size > site:
                raise SystemExit(f"cannot prove bounded Smacker index from 0x{mask_site:08X} to 0x{site:08X}")
            writes_eax = (between.operands and between.operands[0].type == X86_OP_REG and
                          between.operands[0].reg in (X86_REG_EAX, X86_REG_AX))
            if writes_eax or between.mnemonic.lower() in ("call", "ret", "jmp", "pushad", "popad"):
                raise SystemExit(f"Smacker index register may change after its mask before 0x{site:08X}")
            pc += between.size
        if pc != site:
            raise SystemExit(f"Smacker index-mask sequence does not end at the expected callsite 0x{site:08X}")
    table_obj = table_link_owner
    if (table_obj is None or table_obj.index != owner.index or
            table_link < table_obj.base or
            table_link + count*4 > table_obj.end):
        raise SystemExit(f"indexed call table 0x{table_link:08X} is outside canonical LE object 3")
    raw_link = link_table_data[table_link-table_obj.base:table_link-table_obj.base+count*4]
    raw_loaded = bytes(image.mem[table_guest-image.mem_base:table_guest-image.mem_base+count*4])
    if len(raw_link) != count*4 or len(raw_loaded) != count*4:
        raise SystemExit(f"short LE indexed call table at 0x{table_link:08X}")
    link_targets = list(struct.unpack("<" + "I"*count, raw_link))
    guest_targets = list(struct.unpack("<" + "I"*count, raw_loaded))
    target_set = set()
    fixups_by_source = {f.source_link: f for f in image.fixups}
    table_fixup_rows = []
    for index, target_link in enumerate(link_targets):
        source_link = table_link + index*4
        fixup = fixups_by_source.get(source_link)
        if target_link == 0:
            if fixup is not None:
                raise SystemExit(f"zero entry in original call table has unexpected fixup at 0x{source_link:08X}")
            continue
        target_obj = image.object_containing(target_link)
        if (fixup is None or fixup.source_type != 0x07 or fixup.target_object != 1 or
                target_obj is None or not target_obj.executable or not target_obj.linear_base_verified or
                target_link != target_obj.base + fixup.target_offset or
                guest_targets[index] != image.link_to_linear(target_link)):
            raise SystemExit(f"LE call-table entry 0x{source_link:08X} is not a verified object-1 code fixup")
        target_set.add(target_link)
        table_fixup_rows.append({"index":index,"slot_link":source_link,"target_link":target_link,
                                 "target_guest":guest_targets[index]})
    if not target_set:
        raise SystemExit("original indexed call table has no fixup-backed code entries")
    indexed_code_call_tables[site] = {"table_link":table_link,"table_guest":table_guest,
        "count":count,"index_reg":index_name,"index_x86":index_register,"targets":sorted(target_set),
        "targets_guest":sorted(image.link_to_linear(x) for x in target_set),
        "raw":raw_loaded,"slots":table_fixup_rows,"mask_site":mask_site,
        "segment":"CS" if expected_segment == X86_REG_CS else "DS",
        "index_guard":"EAX AND 0xFF immediately bounds index to 0..255" if mask_site is not None else
                      "call-site contract bounds EAX to table count"}
    # The finite target set is attached only when the closure reaches this
    # exact indirect callsite (see call-edge resolution below).

# These exact GS operands are accesses through DOS paragraphs obtained by the
# original INT 31h/0100 allocator. D01D0 rounds requested bytes up to paragraph
# units; callers request 4 bytes (one 16-byte paragraph) or 0x200 bytes. The
# runtime descriptor/DOS-block range validator remains authoritative on every
# access. This contract only admits operands whose byte range fits a paragraph.
selector_guard_contracts = {
    0xD037B:("eax",0,2,16,"DPMI 0100 one-paragraph scratch at globals 1A4CD4/1A4CD8"),
    0xD0398:("eax",2,2,16,"DPMI 0100 one-paragraph scratch at globals 1A4CD4/1A4CD8"),
    0xD0428:("eax",0,2,16,"DPMI 0100 one-paragraph scratch at globals 1A4CD4/1A4CD8"),
    0xD0445:("eax",2,2,16,"DPMI 0100 one-paragraph scratch at globals 1A4CD4/1A4CD8"),
    0xD04FB:("eax",0,2,16,"DPMI 0100 one-paragraph scratch at globals 1A4CD4/1A4CD8"),
    0xD0518:("eax",2,2,16,"DPMI 0100 one-paragraph scratch at globals 1A4CD4/1A4CD8"),
    0xD05AB:("eax",0,2,16,"DPMI 0100 one-paragraph scratch at globals 1A4CD4/1A4CD8"),
    0xD05C8:("eax",2,2,16,"DPMI 0100 one-paragraph scratch at globals 1A4CD4/1A4CD8"),
    0xD078D:("ebx",0,4,0x200,"DPMI 0100 0x200-byte read buffer at globals 1A4CC4/1A4CC8"),
    0xD0796:("ebx",4,4,0x200,"DPMI 0100 0x200-byte read buffer at globals 1A4CC4/1A4CC8"),
    0xD0803:("eax",2,4,16,"DPMI 0100 one-paragraph response record"),
    0xD081A:("edi",0,2,16,"DPMI 0100 one-paragraph response record"),
    0xD0874:("edi",0xA,4,16,"DPMI 0100 one-paragraph response record"),
    0xD089D:("edi",6,4,16,"DPMI 0100 one-paragraph response record"),
    0xD08BC:("edi",0xA,4,16,"DPMI 0100 one-paragraph response record"),
}
matched_selector_guard_sites = set()

funcs = {}
rejections = []
runtime_frontiers = {}
runtime_le_backed_dispatch_sites = set()
runtime_le_backed_verified_dispatch_sites = set()
runtime_le_backed_tail_sites = set()
# These callsites are replaced later by the harness with stronger contracts
# that bind the exact live receiver, vptr and slot. Keep them on that narrow
# path instead of wrapping them in the general fixup-backed dispatcher.
harness_exact_indirect_sites = {
    0x00039BEF, 0x00020C0B, 0x000219A6, 0x0002293D,
    0x0007720F, 0x000772DE, 0x000766EE, 0x00080921,
    # The startup regression verifies the original Watcom __InitRtns table
    # contract independently; keep its 19-entry allowlist exact.
    0x000C8759, 0x000A9F3B, 0x00092821, 0x0009282C, 0x000A8D95,
}
tail_transfers = []
dynamic_accesses = []
indirect_targets = []
ENTITY_UPDATE_VTABLE_SLOTS = {
    0x59D9F: (0x4, 0x111D08, 0x5A2E0,
              "52 89 C2 8B 40 27 2B 42"),
    0x59DAB: (0x74, 0x111D78, 0x36B90,
              "0F BE 40 7A 01 C0 05 2C"),
    0x59E30: (0x10, 0x111D14, 0x5A240,
              "66 8B 40 49 30 C0 80 E4"),
}

def verified_heap_qsort_target(callsite, insn):
    """Resolve only the callback threaded through LbMemorySetup_'s qsort.

    FUN_000921F0 passes the original comparator in ECX to FUN_000A33C0.
    That implementation saves the comparator in its frame and forwards it to
    FUN_000A3368; these exact callsites invoke the saved argument.  This is a
    bounded, byte-checked exception, not a general indirect-call heuristic.
    """
    if 0x921F0 not in roots or not insn.operands or insn.operands[0].type != X86_OP_MEM:
        return None
    callback_sites = {0xA337A, 0xA3385, 0xA3390, 0xA33A3, 0xA33AE,
                      0xA3483, 0xA35F8, 0xA3643}
    if callsite not in callback_sites:
        return None
    mem = insn.operands[0].mem
    if mem.base != X86_REG_EBP or mem.index or mem.disp not in (-4, -0x10):
        return None

    # Verify the original setup call's comparator argument and target.  Any
    # changed encoding or call path keeps the closure fail-closed.
    expected = {
        0x92413: ("mov", 2),  # mov ecx, 0x92670
        0x92418: ("mov", 2),  # mov ebx, 12
        0x9241D: ("mov", 2),  # mov eax, 0x186c40
        0x92422: ("mov", 2),  # mov edx, ebp
        0x92424: ("call", 1), # call FUN_000A33C0
    }
    rows = [next(dis.disassemble_at(va), None) for va in expected]
    if any(row is None or row.mnemonic.lower() != expected[va][0]
           for va, row in zip(expected, rows)):
        return None
    if (rows[0].operands[0].reg != X86_REG_ECX or rows[0].operands[1].type != X86_OP_IMM or
            (rows[0].operands[1].imm & 0xFFFFFFFF) != image.link_to_linear(0x92670) or
            rows[1].operands[1].type != X86_OP_IMM or rows[1].operands[1].imm != 0xC or
            rows[2].operands[1].type != X86_OP_IMM or
            (rows[2].operands[1].imm & 0xFFFFFFFF) != image.link_to_linear(0x186C40) or
            rows[3].operands[0].reg != X86_REG_EDX or
            (rows[4].operands[0].imm & 0xFFFFFFFF) != 0xA33C0):
        return None
    target = image.link_to_linear(0x92670)
    target_obj = image.object_containing_linear(target)
    if target_obj is None or not target_obj.executable or not target_obj.linear_base_verified:
        return None
    return target, "verified_heap_qsort_argument", 0x92424

if args.partial_root:
    # Recursively include direct calls and direct tail jumps into verified code.
    # Indirect calls and dynamic memory without an explicit guest range remain unsupported.
    queue = list(roots)
    while queue:
        address = queue.pop(0)
        if address in funcs:
            continue
        owner = image.object_containing(address)
        if owner is None or not owner.executable or not owner.linear_base_verified:
            rejections.append(f"code target 0x{address:08X} has no verified executable object")
            continue
        function = dis.disassemble_function(address)
        if function is None:
            rejections.append(f"no function body recovered at 0x{address:08X}")
            continue
        if stop_after_call is not None:
            stop_site, stop_target = stop_after_call
            containing = [(block, index, insn)
                          for block in function.blocks.values()
                          for index, insn in enumerate(block.instructions)
                          if insn.address == stop_site]
            if containing:
                block, index, call_insn = containing[0]
                target = call_insn.get_branch_target()
                if (call_insn.mnemonic.lower() != "call" or target != stop_target or
                        len(containing) != 1 or index + 1 >= len(block.instructions) or
                        block.instructions[index + 1].address != call_insn.address + call_insn.size):
                    rejections.append(f"stop-after-call contract does not match a direct call with a sequential continuation at 0x{stop_site:08X}")
                else:
                    # Preserve the post-call instruction boundary as evidence,
                    # then terminate the synthetic bounded prefix. Calls,
                    # branches and data accesses after that boundary are not
                    # part of this execution and are deliberately not pulled
                    # into the closure.
                    marker = block.instructions[index + 1]
                    block.instructions = block.instructions[:index + 2]
                    block.end = marker.address + marker.size
                    block.successors = []
                    block.is_exit = True
                    reachable = set()
                    pending = [function.address]
                    while pending:
                        current = pending.pop()
                        if current in reachable or current not in function.blocks:
                            continue
                        reachable.add(current)
                        pending.extend(function.blocks[current].successors)
                    function.blocks = {start: row for start, row in function.blocks.items()
                                       if start in reachable}
                    function.end = max((row.end for row in function.blocks.values()),
                                       default=function.address)
                    function.size = sum(row.end-row.start for row in function.blocks.values())
                    # Keep the runtime-generated procedure's public extent
                    # bounded to the retained prefix, rather than its old CFG
                    # size (which included code beyond the explicit stop).
                    matched_stop_after_call = True
        function_starts = {insn.address for block in function.blocks.values()
                           for insn in block.instructions}
        tables_in_function = {site: table for site, table in indexed_code_jump_tables.items()
                              if site in function_starts}
        if tables_in_function:
            # The loaded LE table contains guest-linear code pointers, while
            # the control-flow graph needs link-VAs for its local labels.
            # Reuse the raw exact-target CFG and substitute every instruction
            # from the rebased bytes so relocated data operands stay correct.
            original_function = link_dis.disassemble_function(address) if link_dis else None
            if original_function is None:
                rejections.append(f"could not recover raw switch CFG for 0x{address:08X}")
                continue
            for block in original_function.blocks.values():
                loaded_instructions = []
                for original_insn in block.instructions:
                    loaded_insn = next(dis.disassemble_at(original_insn.address,
                                                          max_bytes=original_insn.size), None)
                    if (loaded_insn is None or loaded_insn.address != original_insn.address or
                            loaded_insn.size != original_insn.size):
                        rejections.append(f"rebased switch instruction boundary mismatch at 0x{original_insn.address:08X}")
                        loaded_instructions = []
                        break
                    loaded_instructions.append(loaded_insn)
                if not loaded_instructions:
                    break
                block.instructions = loaded_instructions
            # Capstone's generic CFG walker recognizes `[index*4 + table]`
            # switches, but not Watcom's equivalent `shl eax,2; jmp [eax+table]`
            # form. For those three byte/guard-verified sites only, recover each
            # table arm and merge its blocks when it stays inside the already
            # recovered function extent. Calls and memory operands in the arms
            # still pass through the usual closure and backing validators.
            for table_site, table in tables_in_function.items():
                if (table["addressing"] not in ("prescaled-base","precomputed-scaled-base") or table_site not in {
                        insn.address for block in original_function.blocks.values()
                        for insn in block.instructions}):
                    if table["addressing"] == "scaled-index":
                        continue
                    rejections.append(f"pre-scaled switch 0x{table_site or 0:08X} is not in its declared original function")
                    continue
                merged = dict(original_function.blocks)
                for target_link in table["targets"]:
                    arm_function = link_dis.disassemble_function(target_link)
                    if arm_function is None:
                        rejections.append(f"could not recover pre-scaled switch arm 0x{target_link:08X}")
                        continue
                    for start, arm_block in arm_function.blocks.items():
                        if (start < original_function.address or arm_block.end > original_function.end or
                                start in merged):
                            continue
                        merged[start] = arm_block
                original_function.blocks = merged
                original_function.jump_targets.update(table["targets"])
                original_function.size = sum(block.end-block.start
                                             for block in original_function.blocks.values())
            function = original_function
        lift_stem = "gw_partial_" + re.sub(r"\W+", "_", map_rows.get(address, f"0x{address:08X}")).strip("_")
        # Watcom MAP aliases are not guaranteed unique (for example the
        # int386x public name labels both its wrapper and the internal thunk).
        # Keep dispatcher identity address-based when the MAP stem collides.
        if any(existing.name == lift_stem for existing in funcs.values()):
            lift_stem += f"_0x{address:08X}"
        function.name = lift_stem
        funcs[address] = function
        starts = {i.address for b in function.blocks.values() for i in b.instructions}
        for block in function.blocks.values():
            for insn in block.instructions:
                if not (owner.base <= insn.address and insn.address + insn.size <= owner.end):
                    rejections.append(f"instruction 0x{insn.address:08X} escapes verified object {owner.index}")
                if insn.mnemonic.startswith("call"):
                    if not insn.operands or insn.operands[0].type != X86_OP_IMM:
                        resolved = []
                        operand = insn.operands[0] if insn.operands else None
                        if operand is not None and operand.type == X86_OP_MEM:
                            mem = operand.mem
                            qsort_target = verified_heap_qsort_target(insn.address, insn)
                            if qsort_target is not None:
                                resolved.append(qsort_target)
                            slot = mem.disp & 0xFFFFFFFF
                            # A statically addressed callback slot is accepted only when its
                            # loaded bytes live in a measured object and the LE loader's
                            # actual fixup resolves the value to verified executable code.
                            if not mem.base and not mem.index:
                                slot_obj = image.object_containing_linear(slot)
                                if (slot_obj is not None and slot_obj.linear_base_verified and
                                        slot + 4 <= slot_obj.linear_end):
                                    raw_slot = image.mem[slot-image.mem_base:slot-image.mem_base+4]
                                    if len(raw_slot) == 4:
                                        target_linear = int.from_bytes(raw_slot, "little")
                                        target_obj = image.object_containing_linear(target_linear)
                                        if (target_obj is not None and target_obj.executable and
                                                target_obj.linear_base_verified):
                                            resolved.append((target_linear, "loaded-le-fixup", slot))
                            # FUN_000989EC stores one of two callback addresses in its
                            # private [ESP] slot along both paths. Verify those exact
                            # original instructions and their loaded LE fixups; don't
                            # infer the call from a possible static xref.
                            elif (mem.base == X86_REG_ESP and not mem.index and
                                  address == 0x989EC and insn.address in (0x98A2C, 0x98A5E)):
                                callback_sites = ((0x98A01, 0x91E90), (0x98A0A, 0x91E00))
                                valid_sites = True
                                for store_va, link_target in callback_sites:
                                    store = next(dis.disassemble_at(store_va), None)
                                    if (store is None or store.mnemonic.lower() != "mov" or
                                            len(store.operands) != 2 or
                                            store.operands[0].type != X86_OP_MEM or
                                            store.operands[0].mem.base != X86_REG_ESP or
                                            store.operands[0].mem.disp != 0 or
                                            store.operands[1].type != X86_OP_IMM or
                                            (store.operands[1].imm & 0xFFFFFFFF) != image.link_to_linear(link_target)):
                                        valid_sites = False
                                        break
                                    callback_linear = store.operands[1].imm & 0xFFFFFFFF
                                    callback_obj = image.object_containing_linear(callback_linear)
                                    if callback_obj is None or not callback_obj.executable or not callback_obj.linear_base_verified:
                                        valid_sites = False
                                        break
                                if valid_sites:
                                    resolved.extend((image.link_to_linear(link_target),
                                                     "verified-stack-store", store_va)
                                                    for store_va, link_target in callback_sites)
                        if insn.address in static_vsscanf_callback_targets:
                            verified_indirect_by_site.setdefault(insn.address, set()).update(
                                static_vsscanf_callback_targets[insn.address])
                        if insn.address in indexed_code_call_tables:
                            verified_indirect_by_site.setdefault(insn.address, set()).update(
                                indexed_code_call_tables[insn.address]["targets"])
                        # The bounded native replay captured this exact runtime
                        # callback through the original object field EDX+0x68:
                        # EDX=0x002EBD04, [EDX+0x68]=0x00255070, which maps
                        # through object 1's verified +0x1EB000 placement to
                        # link VA 0x0006A070. This is a live-initialized field,
                        # not an LE fixup. Admit only that one target, and only
                        # while the callsite encoding and target body bytes in
                        # the canonical LE still match the observed contract.
                        if insn.address == 0x23633:
                            callback_ok = bool(
                                insn.mnemonic.lower() == "call" and insn.operands and
                                insn.operands[0].type == X86_OP_MEM and
                                insn.operands[0].mem.base == X86_REG_EDX and
                                not insn.operands[0].mem.index and
                                insn.operands[0].mem.disp == 0x68)
                            callback_obj = image.object_containing(0x6A070)
                            if callback_obj is None or callback_obj.index != 1 or not callback_obj.executable:
                                callback_ok = False
                            else:
                                callback_data = image.object_data(1)
                                callback_off = 0x6A070 - callback_obj.base
                                callback_ok = callback_ok and callback_data[callback_off:callback_off+8] == bytes.fromhex(
                                    "80 78 5E 18 0F 93 C0 C3")
                            if callback_ok:
                                verified_indirect_by_site.setdefault(insn.address, set()).add(0x6A070)
                        # A second Draw frontier is CALL [EBX+0x1c] at 0x1F478.
                        # The live vptr is 0x002EC060 (LE object-3 link 0x112060),
                        # so the call reads slot 0x11207C. Admit its destination
                        # only from that exact SRC_OFFSET32 fixup to executable
                        # object 1; the live dispatcher still compares the actual
                        # pointer against the single resolved target.
                        if insn.address == 0x1F478:
                            call_ok = bool(
                                insn.mnemonic.lower() == "call" and insn.operands and
                                insn.operands[0].type == X86_OP_MEM and
                                insn.operands[0].mem.base == X86_REG_EBX and
                                not insn.operands[0].mem.index and
                                insn.operands[0].mem.disp == 0x1C)
                            vtable_link, slot_link = 0x112060, 0x11207C
                            vtable_obj = image.object_containing(vtable_link)
                            slot_fixup = next((f for f in image.fixups
                                               if f.source_link == slot_link), None)
                            if (not call_ok or vtable_obj is None or vtable_obj.index != 3 or
                                    image.link_to_linear(vtable_link) != 0x2EC060 or
                                    slot_fixup is None or slot_fixup.source_type != 0x07 or
                                    slot_fixup.target_object != 1):
                                call_ok = False
                            if call_ok:
                                target_link = image.objects[0].base + slot_fixup.target_offset
                                target_obj = image.object_containing(target_link)
                                if target_link != 0x69E50 or target_obj is None or not target_obj.executable:
                                    call_ok = False
                            if call_ok:
                                verified_indirect_by_site.setdefault(insn.address, set()).add(target_link)
                        # process_packets walks BioGame::__team (MAP link 0x1622D6),
                        # loads a live team object's method slot at +0x64, and calls
                        # it at 0x45228. The exact original object field at link
                        # 0x1120C4 is backed by an LE SRC_OFFSET32 fixup to object 1
                        # offset 0x34570 (link VA 0x44570). Admit only that target;
                        # the emitted dispatcher still checks the live guest pointer.
                        if insn.address == 0x45228:
                            call_ok = bool(
                                insn.mnemonic.lower() == "call" and insn.operands and
                                insn.operands[0].type == X86_OP_MEM and
                                insn.operands[0].mem.base == X86_REG_EBX and
                                not insn.operands[0].mem.index and
                                insn.operands[0].mem.disp == 0x64)
                            callback_owner = image.object_containing(0x112060)
                            slot_fixup = next((f for f in image.fixups
                                               if f.source_link == 0x1120C4), None)
                            if (not call_ok or callback_owner is None or callback_owner.index != 3 or
                                    image.link_to_linear(0x112060) != 0x2EC060 or
                                    slot_fixup is None or slot_fixup.source_type != 0x07 or
                                    slot_fixup.target_object != 1 or
                                    slot_fixup.target_offset != 0x34570):
                                call_ok = False
                            if call_ok:
                                target_link = image.objects[0].base + slot_fixup.target_offset
                                target_obj = image.object_containing(target_link)
                                target_bytes = image.object_data(1)[target_link-image.objects[0].base:][:8]
                                if (target_link != 0x44570 or target_obj is None or
                                        not target_obj.executable or
                                        target_bytes != bytes.fromhex("53 51 52 56 57 55 89 E5")):
                                    call_ok = False
                            if call_ok:
                                verified_indirect_by_site.setdefault(insn.address, set()).add(target_link)
                        # FUN_00054BB0 walks the MAP-identified BioGame creature
                        # array. At its two virtual calls, ESI resolves to the
                        # original object at link 0x111D04 and both method slots
                        # are explicit SRC_OFFSET32 LE fixups. Keep each callsite
                        # to its one fixup-backed object-1 destination.
                        creature_method_slots = {
                            0x54C19:(0x68,0x111D6C,0x6A070,0x5A070,
                                     "80 78 5E 18 0F 93 C0 C3"),
                            0x54C50:(0x64,0x111D68,0x4B1F0,0x3B1F0,
                                     "53 51 52 56 57 55 89 E5"),
                        }
                        if insn.address in creature_method_slots:
                            disp,slot_link,expected_link,expected_offset,prologue = \
                                creature_method_slots[insn.address]
                            call_ok = bool(
                                insn.mnemonic.lower() == "call" and insn.operands and
                                insn.operands[0].type == X86_OP_MEM and
                                insn.operands[0].mem.base == X86_REG_ESI and
                                not insn.operands[0].mem.index and
                                insn.operands[0].mem.disp == disp)
                            callback_object_owner = image.object_containing(0x111D04)
                            slot_fixup = next((f for f in image.fixups
                                               if f.source_link == slot_link), None)
                            if (not call_ok or callback_object_owner is None or
                                    callback_object_owner.index != 3 or
                                    image.link_to_linear(0x111D04) != 0x2EBD04 or
                                    slot_fixup is None or slot_fixup.source_type != 0x07 or
                                    slot_fixup.target_object != 1 or
                                    slot_fixup.target_offset != expected_offset):
                                call_ok = False
                            if call_ok:
                                target_link = image.objects[0].base + slot_fixup.target_offset
                                target_obj = image.object_containing(target_link)
                                target_bytes = image.object_data(1)[target_link-image.objects[0].base:][:8]
                                if (target_link != expected_link or target_obj is None or
                                        not target_obj.executable or
                                        target_bytes != bytes.fromhex(prologue)):
                                    call_ok = False
                            if call_ok:
                                verified_indirect_by_site.setdefault(insn.address, set()).add(target_link)
                        # The second creature method (0x4B1F0) dispatches its
                        # entity callback through object 0x111D04 + 0x94. The LE
                        # slot is another object-1 fixup; do not infer its target
                        # from the live address alone.
                        if insn.address == 0x4B2EF:
                            call_ok = bool(
                                insn.mnemonic.lower() == "call" and insn.operands and
                                insn.operands[0].type == X86_OP_MEM and
                                insn.operands[0].mem.base == X86_REG_EDX and
                                not insn.operands[0].mem.index and
                                insn.operands[0].mem.disp == 0x94)
                            callback_object_owner = image.object_containing(0x111D04)
                            slot_fixup = next((f for f in image.fixups
                                               if f.source_link == 0x111D98), None)
                            if (not call_ok or callback_object_owner is None or
                                    callback_object_owner.index != 3 or
                                    image.link_to_linear(0x111D04) != 0x2EBD04 or
                                    slot_fixup is None or slot_fixup.source_type != 0x07 or
                                    slot_fixup.target_object != 1 or
                                    slot_fixup.target_offset != 0x49F60):
                                call_ok = False
                            if call_ok:
                                target_link = image.objects[0].base + slot_fixup.target_offset
                                target_obj = image.object_containing(target_link)
                                target_bytes = image.object_data(1)[target_link-image.objects[0].base:][:8]
                                if (target_link != 0x59F60 or target_obj is None or
                                        not target_obj.executable or
                                        target_bytes != bytes.fromhex("53 51 52 56 57 55 89 E5")):
                                    call_ok = False
                            if call_ok:
                                verified_indirect_by_site.setdefault(insn.address, set()).add(target_link)
                        # FUN_00059F60 uses the same creature action slot after
                        # loading it into EDX from the creature's +0x23 pointer.
                        # Bind this second callsite to the same exact LE fixup.
                        if insn.address == 0x59F91:
                            call_ok = bool(
                                insn.mnemonic.lower() == "call" and insn.operands and
                                insn.operands[0].type == X86_OP_MEM and
                                insn.operands[0].mem.base == X86_REG_EDX and
                                not insn.operands[0].mem.index and
                                insn.operands[0].mem.disp == 0x68)
                            callback_object_owner = image.object_containing(0x111D04)
                            slot_fixup = next((f for f in image.fixups
                                               if f.source_link == 0x111D6C), None)
                            if (not call_ok or callback_object_owner is None or
                                    callback_object_owner.index != 3 or
                                    image.link_to_linear(0x111D04) != 0x2EBD04 or
                                    slot_fixup is None or slot_fixup.source_type != 0x07 or
                                    slot_fixup.target_object != 1 or
                                    slot_fixup.target_offset != 0x5A070):
                                call_ok = False
                            if call_ok:
                                target_link = image.objects[0].base + slot_fixup.target_offset
                                target_obj = image.object_containing(target_link)
                                target_bytes = image.object_data(1)[target_link-image.objects[0].base:][:8]
                                if (target_link != 0x6A070 or target_obj is None or
                                        not target_obj.executable or
                                        target_bytes != bytes.fromhex("80 78 5E 18 0F 93 C0 C3")):
                                    call_ok = False
                            if call_ok:
                                verified_indirect_by_site.setdefault(insn.address, set()).add(target_link)
                        # FUN_00080910 checks a creature's action/status virtual
                        # method. The receiver's +0x23 field points at the
                        # object-3 method table 0x111D04; its +0x5c slot is
                        # fixed by the canonical LE to object-1 link 0x6A230.
                        # Admit only this exact dispatcher site and target.
                        if insn.address == 0x80921:
                            call_ok = bool(
                                insn.mnemonic.lower() == "call" and insn.operands and
                                insn.operands[0].type == X86_OP_MEM and
                                insn.operands[0].mem.base == X86_REG_EDX and
                                not insn.operands[0].mem.index and
                                insn.operands[0].mem.disp == 0x5C)
                            callback_object_owner = image.object_containing(0x111D04)
                            slot_fixup = next((f for f in image.fixups
                                               if f.source_link == 0x111D60), None)
                            if (not call_ok or callback_object_owner is None or
                                    callback_object_owner.index != 3 or
                                    image.link_to_linear(0x111D04) != 0x2EBD04 or
                                    slot_fixup is None or slot_fixup.source_type != 0x07 or
                                    slot_fixup.target_object != 1 or
                                    slot_fixup.target_offset != 0x5A230):
                                call_ok = False
                            if call_ok:
                                target_link = image.objects[0].base + slot_fixup.target_offset
                                target_obj = image.object_containing(target_link)
                                target_bytes = image.object_data(1)[target_link-image.objects[0].base:][:9]
                                if (target_link != 0x6A230 or target_obj is None or
                                        not target_obj.executable or
                                    target_bytes != bytes.fromhex("66 8B 40 49 30 C0 80 E4 08")):
                                    call_ok = False
                            if call_ok:
                                verified_indirect_by_site.setdefault(insn.address, set()).add(target_link)
                        # The following original entity helper reaches a second
                        # method on the same object-3 method table. Its +0xB4
                        # slot is independently fixed by the LE to 0x59D80.
                        if insn.address == 0x5AB28:
                            call_ok = bool(
                                insn.mnemonic.lower() == "call" and insn.operands and
                                insn.operands[0].type == X86_OP_MEM and
                                insn.operands[0].mem.base == X86_REG_EDX and
                                not insn.operands[0].mem.index and
                                insn.operands[0].mem.disp == 0xB4)
                            callback_object_owner = image.object_containing(0x111D04)
                            slot_fixup = next((f for f in image.fixups
                                               if f.source_link == 0x111DB8), None)
                            if (not call_ok or callback_object_owner is None or
                                    callback_object_owner.index != 3 or
                                    image.link_to_linear(0x111D04) != 0x2EBD04 or
                                    slot_fixup is None or slot_fixup.source_type != 0x07 or
                                    slot_fixup.target_object != 1 or
                                    slot_fixup.target_offset != 0x49D80):
                                call_ok = False
                            if call_ok:
                                target_link = image.objects[0].base + slot_fixup.target_offset
                                target_obj = image.object_containing(target_link)
                                target_bytes = image.object_data(1)[target_link-image.objects[0].base:][:8]
                                if (target_link != 0x59D80 or target_obj is None or
                                        not target_obj.executable or
                                        target_bytes != bytes.fromhex("53 51 52 56 57 89 C1 66")):
                                    call_ok = False
                            if call_ok:
                                verified_indirect_by_site.setdefault(insn.address, set()).add(target_link)
                        # FUN_00059D80's world-entity update uses three further
                        # virtual methods on that same LE method table. Admit
                        # the function's complete statically evidenced set as
                        # one bounded group; each live value remains guarded.
                        if insn.address in ENTITY_UPDATE_VTABLE_SLOTS:
                            displacement, slot_link, target_offset, fingerprint = ENTITY_UPDATE_VTABLE_SLOTS[insn.address]
                            call_ok = bool(
                                insn.mnemonic.lower() == "call" and insn.operands and
                                insn.operands[0].type == X86_OP_MEM and
                                insn.operands[0].mem.base == X86_REG_EDX and
                                not insn.operands[0].mem.index and
                                insn.operands[0].mem.disp == displacement)
                            callback_object_owner = image.object_containing(0x111D04)
                            slot_fixup = next((f for f in image.fixups
                                               if f.source_link == slot_link), None)
                            if (not call_ok or callback_object_owner is None or
                                    callback_object_owner.index != 3 or
                                    image.link_to_linear(0x111D04) != 0x2EBD04 or
                                    slot_fixup is None or slot_fixup.source_type != 0x07 or
                                    slot_fixup.target_object != 1 or
                                    slot_fixup.target_offset != target_offset):
                                call_ok = False
                            if call_ok:
                                target_link = image.objects[0].base + slot_fixup.target_offset
                                target_obj = image.object_containing(target_link)
                                target_bytes = image.object_data(1)[target_link-image.objects[0].base:][:8]
                                if (target_obj is None or not target_obj.executable or
                                        target_bytes != bytes.fromhex(fingerprint)):
                                    call_ok = False
                            if call_ok:
                                verified_indirect_by_site.setdefault(insn.address, set()).add(target_link)
                        # FUN_00058330 reaches this entity virtual method with
                        # ECX loaded from [EDI+0x23]. The live run identified
                        # the same object-3 table; admit only its +0xA4 LE slot.
                        if insn.address == 0x58681:
                            call_ok = bool(
                                insn.mnemonic.lower() == "call" and insn.operands and
                                insn.operands[0].type == X86_OP_MEM and
                                insn.operands[0].mem.base == X86_REG_ECX and
                                not insn.operands[0].mem.index and
                                insn.operands[0].mem.disp == 0xA4)
                            callback_object_owner = image.object_containing(0x111D04)
                            slot_fixup = next((f for f in image.fixups
                                               if f.source_link == 0x111DA8), None)
                            if (not call_ok or callback_object_owner is None or
                                    callback_object_owner.index != 3 or
                                    image.link_to_linear(0x111D04) != 0x2EBD04 or
                                    slot_fixup is None or slot_fixup.source_type != 0x07 or
                                    slot_fixup.target_object != 1 or
                                    slot_fixup.target_offset != 0x37D60):
                                call_ok = False
                            if call_ok:
                                target_link = image.objects[0].base + slot_fixup.target_offset
                                target_obj = image.object_containing(target_link)
                                target_bytes = image.object_data(1)[target_link-image.objects[0].base:][:8]
                                if (target_link != 0x47D60 or target_obj is None or
                                        not target_obj.executable or
                                        target_bytes != bytes.fromhex("51 56 57 55 83 EC 0C 89")):
                                    call_ok = False
                            if call_ok:
                                verified_indirect_by_site.setdefault(insn.address, set()).add(target_link)
                        # FUN_00047D60 dispatches an entity method through the
                        # same object-3 LE vtable. Its live callsite at 0x47DC2
                        # loads that table into EBX and calls slot +0x10; the
                        # LE fixup at 0x111D14 is the sole admissible target.
                        if insn.address == 0x47DC2:
                            call_ok = bool(
                                insn.mnemonic.lower() == "call" and insn.operands and
                                insn.operands[0].type == X86_OP_MEM and
                                insn.operands[0].mem.base == X86_REG_EBX and
                                not insn.operands[0].mem.index and
                                insn.operands[0].mem.disp == 0x10)
                            callback_object_owner = image.object_containing(0x111D04)
                            slot_fixup = next((f for f in image.fixups
                                               if f.source_link == 0x111D14), None)
                            if (not call_ok or callback_object_owner is None or
                                    callback_object_owner.index != 3 or
                                    image.link_to_linear(0x111D04) != 0x2EBD04 or
                                    slot_fixup is None or slot_fixup.source_type != 0x07 or
                                    slot_fixup.target_object != 1 or
                                    slot_fixup.target_offset != 0x5A240):
                                call_ok = False
                            if call_ok:
                                target_link = image.objects[0].base + slot_fixup.target_offset
                                target_obj = image.object_containing(target_link)
                                target_bytes = image.object_data(1)[target_link-image.objects[0].base:][:9]
                                if (target_link != 0x6A240 or target_obj is None or
                                        not target_obj.executable or
                                        target_bytes != bytes.fromhex("66 8B 40 49 30 C0 80 E4 04")):
                                    call_ok = False
                            if call_ok:
                                verified_indirect_by_site.setdefault(insn.address, set()).add(target_link)
                        # FUN_00059CF0 advances an entity through its virtual
                        # movement-distance query. This call uses slot +0xB8
                        # of the same object-3 table; admit only the LE-fixed
                        # object-1 implementation at link 0x47700.
                        if insn.address == 0x59D42:
                            call_ok = bool(
                                insn.mnemonic.lower() == "call" and insn.operands and
                                insn.operands[0].type == X86_OP_MEM and
                                insn.operands[0].mem.base == X86_REG_EBX and
                                not insn.operands[0].mem.index and
                                insn.operands[0].mem.disp == 0xB8)
                            callback_object_owner = image.object_containing(0x111D04)
                            slot_fixup = next((f for f in image.fixups
                                               if f.source_link == 0x111DBC), None)
                            if (not call_ok or callback_object_owner is None or
                                    callback_object_owner.index != 3 or
                                    image.link_to_linear(0x111D04) != 0x2EBD04 or
                                    slot_fixup is None or slot_fixup.source_type != 0x07 or
                                    slot_fixup.target_object != 1 or
                                    slot_fixup.target_offset != 0x37700):
                                call_ok = False
                            if call_ok:
                                target_link = image.objects[0].base + slot_fixup.target_offset
                                target_obj = image.object_containing(target_link)
                                target_bytes = image.object_data(1)[target_link-image.objects[0].base:][:8]
                                if (target_link != 0x47700 or target_obj is None or
                                        not target_obj.executable or
                                        target_bytes != bytes.fromhex("53 51 52 56 57 89 C2 8A")):
                                    call_ok = False
                            if call_ok:
                                verified_indirect_by_site.setdefault(insn.address, set()).add(target_link)
                        # The movement-helper branch at 0x4781B uses the same
                        # +0x10 slot on the proven object-3 table as 0x47DC2.
                        # Keep the callsite-specific check while reusing the
                        # same LE target fingerprint and live dispatcher guard.
                        if insn.address == 0x4781B:
                            call_ok = bool(
                                insn.mnemonic.lower() == "call" and insn.operands and
                                insn.operands[0].type == X86_OP_MEM and
                                insn.operands[0].mem.base == X86_REG_EBX and
                                not insn.operands[0].mem.index and
                                insn.operands[0].mem.disp == 0x10)
                            callback_object_owner = image.object_containing(0x111D04)
                            slot_fixup = next((f for f in image.fixups
                                               if f.source_link == 0x111D14), None)
                            if (not call_ok or callback_object_owner is None or
                                    callback_object_owner.index != 3 or
                                    image.link_to_linear(0x111D04) != 0x2EBD04 or
                                    slot_fixup is None or slot_fixup.source_type != 0x07 or
                                    slot_fixup.target_object != 1 or
                                    slot_fixup.target_offset != 0x5A240):
                                call_ok = False
                            if call_ok:
                                target_link = image.objects[0].base + slot_fixup.target_offset
                                target_obj = image.object_containing(target_link)
                                target_bytes = image.object_data(1)[target_link-image.objects[0].base:][:9]
                                if (target_link != 0x6A240 or target_obj is None or
                                        not target_obj.executable or
                                        target_bytes != bytes.fromhex("66 8B 40 49 30 C0 80 E4 04")):
                                    call_ok = False
                            if call_ok:
                                verified_indirect_by_site.setdefault(insn.address, set()).add(target_link)
                        # FUN_00057F60 performs the same entity status query at
                        # its live frontier 0x57F67. The call operand differs
                        # only in using ESI for the already-proven vtable
                        # pointer. Keep this exact instruction, object-3 table,
                        # LE slot fixup, and object-1 implementation bound.
                        if insn.address == 0x57F67:
                            call_ok = bool(
                                insn.mnemonic.lower() == "call" and insn.operands and
                                insn.operands[0].type == X86_OP_MEM and
                                insn.operands[0].mem.base == X86_REG_ESI and
                                not insn.operands[0].mem.index and
                                insn.operands[0].mem.disp == 0x10)
                            callback_object_owner = image.object_containing(0x111D04)
                            slot_fixup = next((f for f in image.fixups
                                               if f.source_link == 0x111D14), None)
                            if (not call_ok or callback_object_owner is None or
                                    callback_object_owner.index != 3 or
                                    image.link_to_linear(0x111D04) != 0x2EBD04 or
                                    slot_fixup is None or slot_fixup.source_type != 0x07 or
                                    slot_fixup.target_object != 1 or
                                    slot_fixup.target_offset != 0x5A240):
                                call_ok = False
                            if call_ok:
                                target_link = image.objects[0].base + slot_fixup.target_offset
                                target_obj = image.object_containing(target_link)
                                target_bytes = image.object_data(1)[target_link-image.objects[0].base:][:9]
                                if (target_link != 0x6A240 or target_obj is None or
                                        not target_obj.executable or
                                        target_bytes != bytes.fromhex("66 8B 40 49 30 C0 80 E4 04")):
                                    call_ok = False
                            if call_ok:
                                verified_indirect_by_site.setdefault(insn.address, set()).add(target_link)
                        # FUN_0004B000 queries the same entity's field at
                        # 0x4B017 through vtable slot +0xAC. The current replay
                        # reaches this exact site with EBX=0x2EBD04, so bind it
                        # to the corresponding object-3 LE slot fixup and its
                        # object-1 implementation only.
                        if insn.address == 0x4B017:
                            call_ok = bool(
                                insn.mnemonic.lower() == "call" and insn.operands and
                                insn.operands[0].type == X86_OP_MEM and
                                insn.operands[0].mem.base == X86_REG_EBX and
                                not insn.operands[0].mem.index and
                                insn.operands[0].mem.disp == 0xAC)
                            callback_object_owner = image.object_containing(0x111D04)
                            slot_fixup = next((f for f in image.fixups
                                               if f.source_link == 0x111DB0), None)
                            if (not call_ok or callback_object_owner is None or
                                    callback_object_owner.index != 3 or
                                    image.link_to_linear(0x111D04) != 0x2EBD04 or
                                    slot_fixup is None or slot_fixup.source_type != 0x07 or
                                    slot_fixup.target_object != 1 or
                                    slot_fixup.target_offset != 0x5A040):
                                call_ok = False
                            if call_ok:
                                target_link = image.objects[0].base + slot_fixup.target_offset
                                target_obj = image.object_containing(target_link)
                                target_bytes = image.object_data(1)[target_link-image.objects[0].base:][:9]
                                if (target_link != 0x6A040 or target_obj is None or
                                        not target_obj.executable or
                                        target_bytes != bytes.fromhex("66 8B 40 49 30 C0 80 E4 02")):
                                    call_ok = False
                            if call_ok:
                                verified_indirect_by_site.setdefault(insn.address, set()).add(target_link)
                        # Admit the remaining fixup-backed virtual calls in the
                        # same live entity helper as one bounded batch. Each
                        # row still requires its exact LE instruction bytes,
                        # vtable slot fixup, and executable target fingerprint.
                        entity_helper_calls = {
                            0x4B034: (0x68, 0x111D6C, 0x5A070,
                                      bytes.fromhex("FF 53 68"),
                                      bytes.fromhex("80 78 5E 18 0F 93 C0 C3")),
                            0x4B04E: (0xAC, 0x111DB0, 0x5A040,
                                      bytes.fromhex("FF 93 AC 00 00 00"),
                                      bytes.fromhex("66 8B 40 49 30 C0 80 E4 02")),
                            0x4B05D: (0xB0, 0x111DB4, 0x5A030,
                                      bytes.fromhex("FF 93 B0 00 00 00"),
                                      bytes.fromhex("66 8B 40 49 30 C0 80 E4 01")),
                            0x4B162: (0x9C, 0x111DA0, 0x48EF0,
                                      bytes.fromhex("FF 93 9C 00 00 00"),
                                      bytes.fromhex("53 51 56 57 55 89 E5 83")),
                        }
                        if insn.address in entity_helper_calls:
                            disp, slot_link, target_offset, call_bytes, target_bytes_expected = entity_helper_calls[insn.address]
                            call_ok = bool(
                                insn.mnemonic.lower() == "call" and insn.operands and
                                insn.operands[0].type == X86_OP_MEM and
                                insn.operands[0].mem.base == X86_REG_EBX and
                                not insn.operands[0].mem.index and
                                insn.operands[0].mem.disp == disp and
                                image.object_data(1)[insn.address-image.objects[0].base:
                                                     insn.address-image.objects[0].base+len(call_bytes)] == call_bytes)
                            callback_object_owner = image.object_containing(0x111D04)
                            slot_fixup = next((f for f in image.fixups if f.source_link == slot_link), None)
                            if (not call_ok or callback_object_owner is None or
                                    callback_object_owner.index != 3 or
                                    image.link_to_linear(0x111D04) != 0x2EBD04 or
                                    slot_fixup is None or slot_fixup.source_type != 0x07 or
                                    slot_fixup.target_object != 1 or
                                    slot_fixup.target_offset != target_offset):
                                call_ok = False
                            if call_ok:
                                target_link = image.objects[0].base + slot_fixup.target_offset
                                target_obj = image.object_containing(target_link)
                                actual_target_bytes = image.object_data(1)[target_link-image.objects[0].base:
                                                                         target_link-image.objects[0].base+len(target_bytes_expected)]
                                if (target_obj is None or not target_obj.executable or
                                        actual_target_bytes != target_bytes_expected):
                                    call_ok = False
                            if call_ok:
                                verified_indirect_by_site.setdefault(insn.address, set()).add(target_link)
                        # FUN_0004AB10's indexed entity-state handlers share
                        # three more vtable methods. Keep every observed
                        # callsite tied to its exact EDX-relative slot and LE
                        # fixup; the cases remain unreachable unless the
                        # original state dispatch selects them.
                        entity_state_method_calls = {
                            0x4AB54: (0x7C, 0x111D80, 0x5A290, "FF 52 7C",
                                      "0F BF 40 39 C1 F8 07 40"),
                            0x4AC41: (0x7C, 0x111D80, 0x5A290, "FF 52 7C",
                                      "0F BF 40 39 C1 F8 07 40"),
                            0x4ADED: (0x7C, 0x111D80, 0x5A290, "FF 52 7C",
                                      "0F BF 40 39 C1 F8 07 40"),
                            0x4AE01: (0x7C, 0x111D80, 0x5A290, "FF 52 7C",
                                      "0F BF 40 39 C1 F8 07 40"),
                            0x4AE21: (0x10, 0x111D14, 0x5A240, "FF 52 10",
                                      "66 8B 40 49 30 C0 80 E4 04"),
                            0x4AE93: (0x04, 0x111D08, 0x5A2E0, "FF 52 04",
                                      "52 89 C2 8B 40 27 2B 42"),
                            0x4AF70: (0x7C, 0x111D80, 0x5A290, "FF 52 7C",
                                      "0F BF 40 39 C1 F8 07 40"),
                        }
                        if insn.address in entity_state_method_calls:
                            disp, slot_link, target_offset, call_hex, target_hex = entity_state_method_calls[insn.address]
                            expected_call=bytes.fromhex(call_hex)
                            expected_target=bytes.fromhex(target_hex)
                            call_ok=bool(
                                insn.mnemonic.lower()=="call" and insn.operands and
                                insn.operands[0].type==X86_OP_MEM and
                                insn.operands[0].mem.base==X86_REG_EDX and
                                not insn.operands[0].mem.index and
                                insn.operands[0].mem.disp==disp and
                                image.object_data(1)[insn.address-image.objects[0].base:
                                                     insn.address-image.objects[0].base+len(expected_call)]==expected_call)
                            callback_object_owner=image.object_containing(0x111D04)
                            slot_fixup=next((f for f in image.fixups if f.source_link==slot_link),None)
                            if (not call_ok or callback_object_owner is None or
                                    callback_object_owner.index!=3 or
                                    image.link_to_linear(0x111D04)!=0x2EBD04 or
                                    slot_fixup is None or slot_fixup.source_type!=0x07 or
                                    slot_fixup.target_object!=1 or slot_fixup.target_offset!=target_offset):
                                call_ok=False
                            if call_ok:
                                target_link=image.objects[0].base+slot_fixup.target_offset
                                target_obj=image.object_containing(target_link)
                                actual_target=image.object_data(1)[target_link-image.objects[0].base:
                                                                   target_link-image.objects[0].base+len(expected_target)]
                                if target_obj is None or not target_obj.executable or actual_target!=expected_target:
                                    call_ok=False
                            if call_ok:
                                verified_indirect_by_site.setdefault(insn.address,set()).add(target_link)
                        # FUN_00078B30's active caller dispatches a state
                        # accessor through the second vtable at link 0x111EA4.
                        # The live frontier supplies EDX=0x2EBEA4; slot +4 is
                        # exactly fixup-backed to the original zero-return
                        # accessor at 0x6EE40.
                        if insn.address == 0x78BA1:
                            call_ok=bool(
                                insn.mnemonic.lower()=="call" and insn.operands and
                                insn.operands[0].type==X86_OP_MEM and
                                insn.operands[0].mem.base==X86_REG_EDX and
                                not insn.operands[0].mem.index and
                                insn.operands[0].mem.disp==0x04 and
                                image.object_data(1)[insn.address-image.objects[0].base:
                                                     insn.address-image.objects[0].base+3]==bytes.fromhex("FF 52 04"))
                            callback_object_owner=image.object_containing(0x111EA4)
                            slot_fixup=next((f for f in image.fixups if f.source_link==0x111EA8),None)
                            if (not call_ok or callback_object_owner is None or
                                    callback_object_owner.index!=3 or
                                    image.link_to_linear(0x111EA4)!=0x2EBEA4 or
                                    slot_fixup is None or slot_fixup.source_type!=0x07 or
                                    slot_fixup.target_object!=1 or slot_fixup.target_offset!=0x5EE40):
                                call_ok=False
                            if call_ok:
                                target_link=image.objects[0].base+slot_fixup.target_offset
                                target_obj=image.object_containing(target_link)
                                target_bytes=image.object_data(1)[target_link-image.objects[0].base:
                                                                  target_link-image.objects[0].base+3]
                                if (target_link!=0x6EE40 or target_obj is None or
                                        not target_obj.executable or target_bytes!=bytes.fromhex("31 C0 C3")):
                                    call_ok=False
                            if call_ok:
                                verified_indirect_by_site.setdefault(insn.address,set()).add(target_link)
                        # FUN_00057640's live entity sweep calls slot +0x64
                        # through the second object-3 vtable. Bind the exact
                        # EDX-relative dispatch at 0x576CF to LE slot 0x111F08
                        # and target 0x57140 only.
                        if insn.address == 0x576CF:
                            call_ok=bool(
                                insn.mnemonic.lower()=="call" and insn.operands and
                                insn.operands[0].type==X86_OP_MEM and
                                insn.operands[0].mem.base==X86_REG_EDX and
                                not insn.operands[0].mem.index and
                                insn.operands[0].mem.disp==0x64 and
                                image.object_data(1)[insn.address-image.objects[0].base:
                                                     insn.address-image.objects[0].base+3]==bytes.fromhex("FF 52 64"))
                            callback_object_owner=image.object_containing(0x111EA4)
                            slot_fixup=next((f for f in image.fixups if f.source_link==0x111F08),None)
                            if (not call_ok or callback_object_owner is None or
                                    callback_object_owner.index!=3 or
                                    image.link_to_linear(0x111EA4)!=0x2EBEA4 or
                                    slot_fixup is None or slot_fixup.source_type!=0x07 or
                                    slot_fixup.target_object!=1 or slot_fixup.target_offset!=0x47140):
                                call_ok=False
                            if call_ok:
                                target_link=image.objects[0].base+slot_fixup.target_offset
                                target_obj=image.object_containing(target_link)
                                target_bytes=image.object_data(1)[target_link-image.objects[0].base:
                                                                  target_link-image.objects[0].base+8]
                                if (target_link!=0x57140 or target_obj is None or
                                        not target_obj.executable or
                                        target_bytes!=bytes.fromhex("53 51 52 56 57 55 83 EC")):
                                    call_ok=False
                            if call_ok:
                                verified_indirect_by_site.setdefault(insn.address,set()).add(target_link)
                        # FUN_00080ED0 tests an entity status at slot +0x68 of
                        # the live vtable 0x2EBEA4. Its LE slot 0x111F0C fixes
                        # to 0x78360; require both the exact caller encoding
                        # and the original target fingerprint.
                        if insn.address == 0x80EF3:
                            call_ok=bool(
                                insn.mnemonic.lower()=="call" and insn.operands and
                                insn.operands[0].type==X86_OP_MEM and
                                insn.operands[0].mem.base==X86_REG_ECX and
                                not insn.operands[0].mem.index and
                                insn.operands[0].mem.disp==0x68 and
                                image.object_data(1)[insn.address-image.objects[0].base:
                                                     insn.address-image.objects[0].base+3]==bytes.fromhex("FF 51 68"))
                            callback_object_owner=image.object_containing(0x111EA4)
                            slot_fixup=next((f for f in image.fixups if f.source_link==0x111F0C),None)
                            if (not call_ok or callback_object_owner is None or
                                    callback_object_owner.index!=3 or
                                    image.link_to_linear(0x111EA4)!=0x2EBEA4 or
                                    slot_fixup is None or slot_fixup.source_type!=0x07 or
                                    slot_fixup.target_object!=1 or slot_fixup.target_offset!=0x68360):
                                call_ok=False
                            if call_ok:
                                target_link=image.objects[0].base+slot_fixup.target_offset
                                target_obj=image.object_containing(target_link)
                                target_bytes=image.object_data(1)[target_link-image.objects[0].base:
                                                                  target_link-image.objects[0].base+9]
                                if (target_link!=0x78360 or target_obj is None or
                                        not target_obj.executable or
                                        target_bytes!=bytes.fromhex("0F BF 40 2C 85 C0 0F 9E C0")):
                                    call_ok=False
                            if call_ok:
                                verified_indirect_by_site.setdefault(insn.address,set()).add(target_link)
                        # FUN_00078B30's live state path performs one more
                        # query through the same vtable base at slot +0x70.
                        # Its LE slot 0x111F14 has one SRC_OFFSET32 fixup to
                        # 0x6EC70; the runtime still guards the live target.
                        if insn.address == 0x78FAA:
                            call_ok=bool(
                                insn.mnemonic.lower()=="call" and insn.operands and
                                insn.operands[0].type==X86_OP_MEM and
                                insn.operands[0].mem.base==X86_REG_ECX and
                                not insn.operands[0].mem.index and
                                insn.operands[0].mem.disp==0x70 and
                                image.object_data(1)[insn.address-image.objects[0].base:
                                                     insn.address-image.objects[0].base+3]==bytes.fromhex("FF 51 70"))
                            callback_object_owner=image.object_containing(0x111EA4)
                            slot_fixup=next((f for f in image.fixups if f.source_link==0x111F14),None)
                            if (not call_ok or callback_object_owner is None or
                                    callback_object_owner.index!=3 or
                                    image.link_to_linear(0x111EA4)!=0x2EBEA4 or
                                    slot_fixup is None or slot_fixup.source_type!=0x07 or
                                    slot_fixup.target_object!=1 or slot_fixup.target_offset!=0x5EC70):
                                call_ok=False
                            if call_ok:
                                target_link=image.objects[0].base+slot_fixup.target_offset
                                target_obj=image.object_containing(target_link)
                                target_bytes=image.object_data(1)[target_link-image.objects[0].base:
                                                                  target_link-image.objects[0].base+8]
                                if (target_link!=0x6EC70 or target_obj is None or
                                        not target_obj.executable or
                                        target_bytes!=bytes.fromhex("51 89 D1 89 DA 83 78 27")):
                                    call_ok=False
                            if call_ok:
                                verified_indirect_by_site.setdefault(insn.address,set()).add(target_link)
                        # FUN_00089380 walks the MAP global
                        # W?bio$n$BioGame$$__effects and invokes its count
                        # accessor. The live class vtable maps link 0x1121E4
                        # to guest 0x2EC1E4; slot 0x112248 fixes to 0x86810.
                        if insn.address == 0x893B2:
                            call_ok=bool(
                                insn.mnemonic.lower()=="call" and insn.operands and
                                insn.operands[0].type==X86_OP_MEM and
                                insn.operands[0].mem.base==X86_REG_ECX and
                                not insn.operands[0].mem.index and
                                insn.operands[0].mem.disp==0x64 and
                                image.object_data(1)[insn.address-image.objects[0].base:
                                                     insn.address-image.objects[0].base+3]==bytes.fromhex("FF 51 64"))
                            callback_object_owner=image.object_containing(0x1121E4)
                            slot_fixup=next((f for f in image.fixups if f.source_link==0x112248),None)
                            if (not call_ok or callback_object_owner is None or
                                    callback_object_owner.index!=3 or
                                    image.link_to_linear(0x1121E4)!=0x2EC1E4 or
                                    slot_fixup is None or slot_fixup.source_type!=0x07 or
                                    slot_fixup.target_object!=1 or slot_fixup.target_offset!=0x76810):
                                call_ok=False
                            if call_ok:
                                target_link=image.objects[0].base+slot_fixup.target_offset
                                target_obj=image.object_containing(target_link)
                                target_bytes=image.object_data(1)[target_link-image.objects[0].base:
                                                                  target_link-image.objects[0].base+8]
                                if (target_link!=0x86810 or target_obj is None or
                                        not target_obj.executable or
                                        target_bytes!=bytes.fromhex("53 51 52 56 57 55 89 E5")):
                                    call_ok=False
                            if call_ok:
                                verified_indirect_by_site.setdefault(insn.address,set()).add(target_link)
                        # FUN_00086810 invokes the class vtable method at +0x94
                        # while processing the global BioGame effects list.
                        # The live vtable is link 0x1121E4/guest 0x2EC1E4 and
                        # its LE slot 0x112278 fixes the exact target 0x58330.
                        if insn.address == 0x8684F:
                            call_ok=bool(
                                insn.mnemonic.lower()=="call" and insn.operands and
                                insn.operands[0].type==X86_OP_MEM and
                                insn.operands[0].mem.base==X86_REG_EDX and
                                not insn.operands[0].mem.index and
                                insn.operands[0].mem.disp==0x94 and
                                image.object_data(1)[insn.address-image.objects[0].base:
                                                     insn.address-image.objects[0].base+6]==bytes.fromhex("FF 92 94 00 00 00"))
                            callback_object_owner=image.object_containing(0x1121E4)
                            slot_fixup=next((f for f in image.fixups if f.source_link==0x112278),None)
                            if (not call_ok or callback_object_owner is None or
                                    callback_object_owner.index!=3 or
                                    image.link_to_linear(0x1121E4)!=0x2EC1E4 or
                                    slot_fixup is None or slot_fixup.source_type!=0x07 or
                                    slot_fixup.target_object!=1 or slot_fixup.target_offset!=0x48330):
                                call_ok=False
                            if call_ok:
                                target_link=image.objects[0].base+slot_fixup.target_offset
                                target_obj=image.object_containing(target_link)
                                target_bytes=image.object_data(1)[target_link-image.objects[0].base:
                                                                  target_link-image.objects[0].base+8]
                                if (target_link!=0x58330 or target_obj is None or
                                        not target_obj.executable or
                                        target_bytes!=bytes.fromhex("53 51 52 56 57 55 89 E5")):
                                    call_ok=False
                            if call_ok:
                                verified_indirect_by_site.setdefault(insn.address,set()).add(target_link)
                        if (args.batch_le_fixup_vtables and
                                insn.address not in deferred_indirect_sites and
                                insn.address not in batch_vtable_postlift_contract_sites and
                                insn.address not in verified_indirect_by_site and
                                insn.mnemonic.lower() == "call" and insn.operands and
                                insn.operands[0].type == X86_OP_MEM and
                                insn.operands[0].mem.base in (X86_REG_EAX,X86_REG_EBX,X86_REG_ECX,
                                    X86_REG_EDX,X86_REG_EBP,X86_REG_ESI,X86_REG_EDI) and
                                not insn.operands[0].mem.index and
                                insn.operands[0].mem.disp >= 0 and
                                insn.operands[0].mem.disp % 4 == 0):
                            slot = insn.operands[0].mem.disp // 4
                            base_register = {X86_REG_EAX:"eax",X86_REG_EBX:"ebx",
                                X86_REG_ECX:"ecx",X86_REG_EDX:"edx",X86_REG_EBP:"ebp",
                                X86_REG_ESI:"esi",X86_REG_EDI:"edi"}[insn.operands[0].mem.base]
                            for table_link, count, selected, entries in le_vtable_candidates_by_slot.get(slot, []):
                                target_link = selected["target_link"]
                                verified_indirect_by_site.setdefault(insn.address, set()).add(target_link)
                                pair_key = (insn.address, table_link, target_link)
                                if pair_key not in batch_vtable_contract_pairs:
                                    verified_le_vtable_calls.setdefault(insn.address, []).append({
                                        "vtable_link": table_link,
                                        "vtable_guest": image.link_to_linear(table_link),
                                        "base_register": base_register,
                                        "count": count,
                                        "slot_index": slot,
                                        "slot_link": selected["source_link"],
                                        "target_link": target_link,
                                        "entries": entries,
                                        "provenance": "batch_le_fixup_backed_object3_pointer_table"})
                                    batch_vtable_contract_pairs.add(pair_key)
                        explicit_targets = verified_indirect_by_site.get(insn.address, set())
                        if explicit_targets:
                            # Confirm this is the requested original indirect call, not
                            # stale mappings copied from another executable layout.
                            # A register-indirect CALL is just as safely bounded as
                            # CALL [mem] when the caller supplied a finite target set:
                            # the generated dispatcher compares the live guest target
                            # against that set before invoking any lifted body. This
                            # is required by Watcom __InitRtns, which loads each
                            # function pointer from its fixup-verified init table into
                            # EAX and executes CALL EAX. Do not admit immediates or
                            # other non-indirect operands here.
                            if (not insn.operands or insn.operands[0].type not in (X86_OP_MEM, X86_OP_REG) or
                                    any((image.object_containing(target) is None or
                                         not image.object_containing(target).executable or
                                         not image.object_containing(target).linear_base_verified)
                                        for target in explicit_targets)):
                                rejections.append(f"verified callback mapping at 0x{insn.address:08X} is not a resolvable original indirect call")
                            else:
                                resolved.extend((image.link_to_linear(target),
                                                 "explicit_original_callback_runtime_allowlist",
                                                 insn.address) for target in sorted(explicit_targets))
                        if insn.address in deferred_indirect_sites:
                            if operand is None or operand.type not in (X86_OP_MEM, X86_OP_REG):
                                rejections.append(f"deferred callsite 0x{insn.address:08X} is not an original indirect call")
                            else:
                                indirect_targets.append({"callsite": f"0x{insn.address:08X}",
                                                         "guest_target": None, "link_target": None,
                                                         "provenance": "deferred_original_runtime_dispatch_must_remain_unreached",
                                                         "source": None})
                        if not resolved:
                            if insn.address not in deferred_indirect_sites:
                                if (args.batch_le_fixup_vtables and insn.address not in harness_exact_indirect_sites and
                                        insn.mnemonic.lower() == "call" and
                                        operand is not None and operand.type in (X86_OP_MEM,X86_OP_REG)):
                                    runtime_le_backed_dispatch_sites.add(insn.address)
                                elif args.runtime_fail_closed:
                                    runtime_frontiers[insn.address] = "unverified indirect call target"
                                else:
                                    rejections.append(f"indirect call at 0x{insn.address:08X} has no verified target set")
                        else:
                            for target_linear, provenance, source in resolved:
                                target_link = image.linear_to_link(target_linear)
                                target_obj = image.object_containing(target_link)
                                indirect_targets.append({"callsite": f"0x{insn.address:08X}",
                                                         "guest_target": f"0x{target_linear:08X}",
                                                         "link_target": f"0x{target_link:08X}",
                                                         "provenance": provenance,
                                                         "source": f"0x{source:08X}"})
                                if target_link not in funcs and target_link not in queue:
                                    queue.append(target_link)
                    else:
                        target = insn.get_branch_target()
                        target_obj = image.object_containing(target) if target is not None else None
                        if target_obj is None or not target_obj.executable or not target_obj.linear_base_verified:
                            rejections.append(f"call at 0x{insn.address:08X} targets unresolved code {target!r}")
                        elif target not in funcs and target not in queue:
                            queue.append(target)
                elif insn.mnemonic.startswith("j"):
                    target = insn.get_branch_target()
                    if insn.mnemonic == "jmp" and target is not None and target not in starts:
                        target_obj = image.object_containing(target)
                        if target_obj is None or not target_obj.executable or not target_obj.linear_base_verified:
                            rejections.append(f"tail jump at 0x{insn.address:08X} targets unresolved code {target!r}")
                        else:
                            tail_transfers.append({"source": f"0x{insn.address:08X}",
                                                   "target": f"0x{target:08X}"})
                            if target not in funcs and target not in queue:
                                queue.append(target)
                    elif target is None and insn.address in indexed_code_jump_tables:
                        table = indexed_code_jump_tables[insn.address]
                        if not set(table["targets"]).issubset(starts):
                            missing_targets = sorted(set(table["targets"]) - starts)
                            rejections.append(f"verified code jump table at 0x{insn.address:08X} escapes function 0x{address:08X}; missing targets {[f'0x{x:08X}' for x in missing_targets]}")
                    elif target is None and insn.address in runtime_indexed_code_jump_tables:
                        # The dynamic table is admitted by an exact LE writer,
                        # index-mask and finite target contract below.
                        pass
                    elif target is None or target not in starts:
                        if (args.batch_le_fixup_vtables and insn.address not in harness_exact_indirect_sites and
                                target is None and insn.operands and
                                insn.operands[0].type in (X86_OP_MEM,X86_OP_REG)):
                            runtime_le_backed_tail_sites.add(insn.address)
                        elif args.runtime_fail_closed and target is None:
                            runtime_frontiers[insn.address] = "unresolved indirect branch target"
                        else:
                            rejections.append(f"branch at 0x{insn.address:08X} leaves the recovered function")
                # LEA computes an effective address but does not dereference
                # it. In particular the DOS/4GW real-mode bridge uses
                # LEA EAX, CS:[ESI*3 + relocated_vector_table] followed by
                # RET to enter the original INT n / RET thunk. Treating the
                # LEA operand as guest memory both rejects the legitimate CS
                # override and falsely asks for backing for executable code.
                if insn.mnemonic.lower() == "lea":
                    continue
                for operand in insn.operands:
                    if operand.type != X86_OP_MEM:
                        continue
                    if insn.address in runtime_frontiers:
                        # Emission replaces this original instruction with an
                        # exact-EIP trap, before evaluating the unresolved
                        # address or fetching an indirect target.
                        continue
                    mem = operand.mem
                    segment_contract = segment_relative_contracts.get(insn.address)
                    if segment_contract is not None:
                        expected_offset, expected_width = segment_contract
                        if (mem.segment != X86_REG_ES or mem.base or mem.index or
                                (mem.disp & 0xFFFFFFFF) != expected_offset or
                                max(1, int(operand.size or 1)) != expected_width):
                            rejections.append(f"segment-relative contract does not match original instruction 0x{insn.address:08X}")
                        else:
                            dynamic_accesses.append({"instruction": f"0x{insn.address:08X}",
                                "operand": insn.op_str, "segment": "ES",
                                "segment_offset": f"0x{expected_offset:08X}",
                                "width": expected_width,
                                "runtime_guard": "exact selector descriptor range validator"})
                            matched_segment_relative_contracts.add(insn.address)
                        continue
                    if mem.base or mem.index:
                        call_table = indexed_code_call_tables.get(insn.address)
                        if call_table is not None:
                            expected_segment = X86_REG_CS if call_table["segment"] == "CS" else 0
                            if (insn.mnemonic.lower() != "call" or mem.segment != expected_segment or
                                    mem.base or mem.index != call_table.get("index_x86", X86_REG_EAX) or mem.scale != 4 or
                                    (mem.disp & 0xFFFFFFFF) != call_table["table_guest"] or
                                    operand.size != 4):
                                rejections.append(f"verified indexed code-call table contract does not match original instruction 0x{insn.address:08X}")
                            else:
                                dynamic_accesses.append({"instruction":f"0x{insn.address:08X}",
                                    "operand":insn.op_str,"segment":call_table["segment"],
                                    "table_link":f"0x{call_table['table_link']:08X}",
                                    "table_guest":f"0x{call_table['table_guest']:08X}",
                                    "count":call_table["count"],
                                    "index_register":call_table["index_reg"],
                                    "target_count":len(call_table["targets"]),
                                    "runtime_guard":f"EAX index 0..{call_table['count']-1}; LE-fixup-backed target allowlist"})
                            continue
                        runtime_jump_table = runtime_indexed_code_jump_tables.get(insn.address)
                        if runtime_jump_table is not None:
                            if (insn.mnemonic.lower() != "jmp" or mem.base or
                                    mem.index != X86_REG_ECX or mem.scale != 4 or
                                    (mem.disp & 0xFFFFFFFF) != runtime_jump_table["table_guest"] or
                                    operand.size != 4):
                                rejections.append(f"runtime-indexed code jump contract does not match original instruction 0x{insn.address:08X}")
                            else:
                                dynamic_accesses.append({"instruction":f"0x{insn.address:08X}",
                                    "operand":insn.op_str,"segment":"DS",
                                    "table_link":f"0x{runtime_jump_table['table_link']:08X}",
                                    "table_guest":f"0x{runtime_jump_table['table_guest']:08X}",
                                    "count":runtime_jump_table["count"],
                                    "index_register":runtime_jump_table["index_reg"],
                                    "targets_link":[f"0x{x:08X}" for x in runtime_jump_table["targets"]],
                                    "runtime_guard":"ECX low-two-bit mask plus per-index live target equality against original _Unsmack MOV table writes"})
                            continue
                        jump_table = indexed_code_jump_tables.get(insn.address)
                        if jump_table is not None:
                            expected_index = {"eax":X86_REG_EAX,"ebx":X86_REG_EBX,"ecx":X86_REG_ECX,
                                              "edx":X86_REG_EDX,"esi":X86_REG_ESI}[jump_table["index_reg"]]
                            if jump_table["addressing"] == "scaled-index":
                                index_matches = (not mem.base and mem.index == expected_index and mem.scale == 4)
                            else:
                                index_matches = (mem.base == expected_index and not mem.index and mem.scale == 1)
                            expected_mem_segment = X86_REG_CS if jump_table["segment"] == "CS" else 0
                            if (insn.mnemonic.lower() != "jmp" or mem.segment != expected_mem_segment or
                                    not index_matches or
                                    (mem.disp & 0xFFFFFFFF) != jump_table["table_guest"] or
                                    operand.size != 4):
                                rejections.append(f"verified code jump table contract does not match original instruction 0x{insn.address:08X}")
                            else:
                                dynamic_accesses.append({"instruction": f"0x{insn.address:08X}",
                                    "operand": insn.op_str, "segment": jump_table["segment"],
                                    "table_link": f"0x{jump_table['table_link']:08X}",
                                    "table_guest": f"0x{jump_table['table_guest']:08X}",
                                    "count": jump_table["count"],
                                    "index_register": jump_table["index_reg"],
                                    "addressing": jump_table["addressing"],
                                    "targets_link": [f"0x{x:08X}" for x in jump_table["targets"]],
                                    "runtime_guard": ("original bounds guard and masked scaled index" if jump_table["addressing"] == "scaled-index"
                                                      else f"original CMP/JA guards index 0..{jump_table['count']-1}; MOVZX and SHL EAX,2; runtime target must match one of {jump_table['count']} verified entries")})
                            continue
                        indexed_table = indexed_cs_tables.get(insn.address)
                        if indexed_table is not None:
                            expected_index = {"eax": X86_REG_EAX, "ebx": X86_REG_EBX,
                                              "ecx": X86_REG_ECX, "edx": X86_REG_EDX,
                                              "esi": X86_REG_ESI, "edi": X86_REG_EDI,
                                              "ebp": X86_REG_EBP}[indexed_table["index_reg"]]
                            expected_patterns = {
                                0xD00F3: (0xD00AA, "edi", "edx", 0xD00EF),
                                0xD0193: (0xD0146, "edi", "edx", 0xD018B),
                            }
                            pattern = expected_patterns.get(insn.address)
                            prior = next(dis.disassemble_at(pattern[3]), None) if pattern else None
                            if (pattern is None or indexed_table["table_link"] != pattern[0] or
                                    indexed_table["base_reg"] != pattern[1] or indexed_table["index_reg"] != pattern[2] or
                                    mem.segment != X86_REG_CS or mem.base != expected_index or mem.index or
                                    (mem.disp & 0xFFFFFFFF) != indexed_table["table_guest"] or
                                    insn.mnemonic.lower() != "mov" or operand.size != 1 or prior is None or
                                    prior.mnemonic.lower() != "div" or not prior.operands or
                                    prior.operands[0].type != X86_OP_MEM or prior.operands[0].mem.base != X86_REG_EBX):
                                rejections.append(f"indexed CS table contract does not match original instruction 0x{insn.address:08X}")
                            else:
                                dynamic_accesses.append({"instruction": f"0x{insn.address:08X}",
                                                         "operand": insn.op_str, "segment": "CS",
                                                         "table_link": f"0x{indexed_table['table_link']:08X}",
                                                         "table_guest": f"0x{indexed_table['table_guest']:08X}",
                                                         "count": indexed_table["count"],
                                                         "base_register": indexed_table["base_reg"],
                                                         "index_register": indexed_table["index_reg"],
                                                         "runtime_guard": "base in 1..count and index < count"})
                                continue
                        selector_guard = selector_guard_contracts.get(insn.address)
                        if selector_guard is not None:
                            expected_base_name, expected_disp, expected_width, allocation_size, purpose = selector_guard
                            expected_base = {"eax":X86_REG_EAX,"ebx":X86_REG_EBX,
                                             "edi":X86_REG_EDI}[expected_base_name]
                            if (mem.segment != X86_REG_GS or mem.base != expected_base or mem.index or
                                    (mem.disp & 0xFFFFFFFF) != expected_disp or
                                    max(1, int(operand.size or 1)) != expected_width or
                                    expected_disp + expected_width > allocation_size):
                                rejections.append(f"selector-backed access contract does not match original instruction 0x{insn.address:08X}")
                            else:
                                dynamic_accesses.append({"instruction":f"0x{insn.address:08X}",
                                    "operand":insn.op_str,"segment":"GS",
                                    "base_register":expected_base_name.upper(),
                                    "segment_offset":f"register+0x{expected_disp:X}",
                                    "width":expected_width,"allocation_limit":f"0x{allocation_size:X}",
                                    "purpose":purpose,
                                    "runtime_guard":"DOS descriptor paragraph limit and actual guest backing"})
                            matched_selector_guard_sites.add(insn.address)
                            continue
                        # Stack-relative operations are allowed under the test's explicit bounded stack.
                        if (mem.base not in (X86_REG_ESP, X86_REG_EBP) or mem.index or
                                mem.segment not in (0, X86_REG_SS)):
                            # Only LbScreenSwap's two byte-verified string-copy sites are
                            # admitted here. Their implicit source/destination registers
                            # must map to distinct caller-declared backed regions.
                            swap_movsd = (insn.address in (0xA0013, 0xA005D) and
                                          insn.mnemonic.lower() == "rep movsd" and
                                          rep_movsd_source is not None and
                                          rep_movsd_destination is not None)
                            if swap_movsd and operand is insn.operands[0]:
                                allowed = mem.segment == X86_REG_ES and mem.base == X86_REG_EDI and not mem.index
                                bound = rep_movsd_destination
                            elif swap_movsd and operand is insn.operands[1]:
                                allowed = mem.segment in (0, X86_REG_DS) and mem.base == X86_REG_ESI and not mem.index
                                bound = rep_movsd_source
                            else:
                                allowed = False
                                bound = None
                            if allowed:
                                dynamic_accesses.append({"instruction": f"0x{insn.address:08X}",
                                                         "operand": insn.op_str,
                                                         "segment": "ES" if mem.segment == X86_REG_ES else "DS",
                                                         "base_register": "EDI" if mem.base == X86_REG_EDI else "ESI",
                                                         "ranges": [[f"0x{bound[0]:08X}", f"0x{bound[1]:08X}"]]})
                            elif (mem.segment in (0, X86_REG_DS, X86_REG_ES) and not dynamic_ranges) or \
                                 (mem.segment == X86_REG_SS and not stack_size) or \
                                 mem.segment not in (0, X86_REG_DS, X86_REG_ES, X86_REG_SS):
                                if args.runtime_fail_closed:
                                    runtime_frontiers[insn.address] = "unbounded dynamic memory operand"
                                else:
                                    rejections.append(f"unbounded dynamic memory operand at 0x{insn.address:08X}")
                            else:
                                dynamic_accesses.append({"instruction": f"0x{insn.address:08X}",
                                                         "operand": insn.op_str,
                                                         "ranges": ([[f"0x{stack_base:08X}",
                                                                      f"0x{stack_base + stack_size:08X}"]]
                                                                    if mem.segment == X86_REG_SS else
                                                                    [[f"0x{a:08X}", f"0x{b:08X}"]
                                                                     for a, b in dynamic_ranges])})
                        continue
                    if mem.segment not in (0, X86_REG_DS, X86_REG_CS):
                        rejections.append(f"non-flat static segment override at 0x{insn.address:08X}")
                    encoded_target = mem.disp & 0xFFFFFFFF
                    if mem.segment == X86_REG_CS:
                        # LE fixups can turn a CS override's encoded displacement
                        # into the measured guest-linear address. Prefer that exact
                        # loaded address; accept a link VA only when it has not been
                        # relocated and has a verified object correspondence.
                        linear_obj = image.object_containing_linear(encoded_target)
                        link_obj = image.object_containing(encoded_target)
                        if linear_obj is not None and linear_obj.linear_base_verified:
                            target, data_obj = encoded_target, linear_obj
                        elif link_obj is not None and link_obj.linear_base_verified:
                            target, data_obj = image.link_to_linear(encoded_target), link_obj
                        else:
                            target, data_obj = encoded_target, None
                            rejections.append(f"CS access at 0x{insn.address:08X} targets unresolved loaded/link address 0x{encoded_target:08X}")
                    else:
                        target = encoded_target
                        data_obj = image.object_containing_linear(target)
                    width = max(1, int(operand.size or 1))
                    access_end = data_obj.linear_end if data_obj else 0
                    if (data_obj is None or not data_obj.linear_base_verified or
                            target + width > access_end):
                        rejections.append(f"static access at 0x{insn.address:08X} targets unresolved guest address 0x{target:08X}")
    unused_segment_contracts = set(segment_relative_contracts) - matched_segment_relative_contracts
    if unused_segment_contracts:
        rejections.extend(f"segment-relative contract at 0x{site:08X} did not match an included original memory operand"
                          for site in sorted(unused_segment_contracts))
    if stop_after_call is not None and not matched_stop_after_call:
        rejections.append(f"stop-after-call site 0x{stop_after_call[0]:08X} was not present in the bounded closure")
    if rejections:
        raise SystemExit("refusing unsafe partial closure:\n  " + "\n  ".join(sorted(set(rejections))))
else:
    discovered = dis.find_functions(code_obj.base, code_obj.end, seeds=roots)
    funcs = {address: discovered[address] for address in roots if address in discovered}
    for address in roots:
        if address not in funcs:
            continue
        name = next(n for n, va in EXPECTED.items() if va == address)
        funcs[address].name = "gw_entry_" + re.sub(r"\W+", "_", name).strip("_")

names = {address: function.name for address, function in funcs.items()}
lifter = Lifter(func_names=names, lifted=set(funcs) if args.partial_root else None)
lifter.jump_targets_by_site = {site:set(table["targets"])
                              for site, table in indexed_code_jump_tables.items()}
emitted, records, missing = [], [], []
observed_indirect_sites = set()
allowlist_arrays = []
le_backed_dispatch_targets = set()
if args.batch_le_fixup_vtables:
    for fix in image.fixups:
        target_link = image.objects[0].base + fix.target_offset if fix.target_object == 1 else None
        target_obj = image.object_containing(target_link) if target_link is not None else None
        if (target_link in funcs and target_obj is not None and target_obj.index == 1 and
                target_obj.executable and target_obj.linear_base_verified):
            first = next(dis.disassemble_at(target_link, max_bytes=16), None) if dis else None
            if first is not None and first.address == target_link and first.mnemonic.lower() not in ("int3","ud2"):
                le_backed_dispatch_targets.add(target_link)
for site, targets in sorted(verified_indirect_by_site.items()):
    guest_targets = [image.link_to_linear(target) for target in sorted(targets)]
    array_name = f"gw_recomp_icall_allow_{site:08X}"
    allowlist_arrays.append(
        f"static const uint32_t {array_name}[] = {{ " +
        ", ".join(f"0x{target:08X}u" for target in guest_targets) + " };"
    )
for site, table in sorted(runtime_indexed_code_jump_tables.items()):
    array_name = f"gw_recomp_itail_allow_{site:08X}"
    allowlist_arrays.append(
        f"static const uint32_t {array_name}[] = {{ " +
        ", ".join(f"0x{target:08X}u" for target in table["targets_guest"]) + " };"
    )
if le_backed_dispatch_targets:
    allowlist_arrays.append(
        "static const uint32_t gw_recomp_le_backed_dispatch_targets[] = { " +
        ", ".join(f"0x{image.link_to_linear(target):08X}u"
                   for target in sorted(le_backed_dispatch_targets)) + " };"
    )
observed_runtime_jump_sites=set()
for address, function in sorted(funcs.items()):
    try:
        body = lifter.lift_function(function)
    except Exception as exc:
        missing.append({"name": function.name, "address": f"0x{address:08X}",
                        "reason": f"lifter exception: {type(exc).__name__}: {exc}"})
        continue
    # The original CS table is relocated in guest memory: its entries contain
    # guest linear VAs, while the emitted function's local labels remain LE
    # link VAs. Match the loaded values, then branch to the verified local label.
    function_sites = {i.address for b in function.blocks.values() for i in b.instructions}
    for site, table in indexed_code_jump_tables.items():
        # A direct thunk can make the first emitted body span both the thunk
        # and its destination method. The destination is also emitted as its
        # own recomp function, so each body that contains the indirect jump
        # must compare the rebase-adjusted values actually stored in the LE
        # table. Restricting this rewrite to function_entry left the standalone
        # method body comparing link VAs against guest-linear table entries.
        if site not in function_sites:
            continue
        site_comment=body.find(f"/* 0x{site:08X}:")
        switch_at=body.find("switch (_jt) {",site_comment) if site_comment>=0 else -1
        switch_end=body.find("} }",switch_at) if switch_at>=0 else -1
        if switch_at<0 or switch_end<0:
            rejections.append(f"could not locate emitted switch body for code jump table at 0x{site:08X}")
            continue
        switch_body=body[switch_at:switch_end]
        for target_link, target_guest in dict.fromkeys(zip(table["targets"], table["targets_guest"])):
            old = f"case 0x{target_link:08X}u: goto L_{target_link:08X};"
            new = f"case 0x{target_guest:08X}u: goto L_{target_link:08X};"
            if switch_body.count(new) == 1:
                # The code disassembler already saw the loaded rebased table
                # bytes, so this arm is already expressed in guest-linear
                # coordinates. Keep the original link-VA label unchanged.
                continue
            if switch_body.count(old) != 1:
                snippet=switch_body[:700]
                rejections.append(f"switch arm 0x{target_link:08X} was not emitted exactly once; emitted={snippet!r}")
            else:
                switch_body = switch_body.replace(old, new, 1)
        body=body[:switch_at]+switch_body+body[switch_end:]
    for site, table in indexed_cs_tables.items():
        function_sites = {i.address for b in function.blocks.values() for i in b.instructions}
        if site in function_sites:
            marker = (f"    recomp_begin_memory_access_ex(RECOMP_SEG_CS, 1u, 0x{site:08X}u, "
                      "RECOMP_MEM_ACCESS_READ, 460u, \"mov\");")
            guard = (f"\n    if (!recomp_check_indexed_table_access(RECOMP_SEG_CS, 0x{table['table_guest']:08X}u, "
                     f"{table['index_reg']}, {table['count']}u, {table['base_reg']}, 1u, 0x{site:08X}u)) "
                     "{ recomp_end_memory_access(); RECOMP_FLAGS_OUT(); return; }")
            if body.count(marker) != 1:
                rejections.append(f"could not instrument exact indexed CS table read at 0x{site:08X}")
            else:
                body = body.replace(marker, marker + guard, 1)
    for site, table in indexed_code_jump_tables.items():
        function_sites = {i.address for b in function.blocks.values() for i in b.instructions}
        if site in function_sites:
            marker = (f"    recomp_begin_memory_access_ex(RECOMP_SEG_{table['segment']}, 4u, 0x{site:08X}u, "
                      "RECOMP_MEM_ACCESS_READ, 172u, \"jmp\");")
            if table["addressing"] == "precomputed-scaled-base":
                # These Watcom switches compute EAX = case_index * 4 before
                # the indirect JMP. EAX is a byte offset into the verified
                # LE table, not the case index. Require alignment and range
                # before the lifted memory read, then validate that 4-byte
                # access against the complete table interval.
                index_expr = f"(uint32_t){table['index_reg']}"
                table_bytes = table["count"] * 4
                guard = (f"\n    if ((({index_expr}) & 3u) != 0u || "
                         f"!recomp_check_indexed_table_access(RECOMP_SEG_{table['segment']}, 0x{table['table_guest']:08X}u, "
                         f"{index_expr}, {table_bytes}u, {table_bytes}u, 4u, 0x{site:08X}u)) "
                         "{ recomp_end_memory_access(); RECOMP_FLAGS_OUT(); return; }")
            else:
                guard = (f"\n    if (!recomp_check_indexed_table_access(RECOMP_SEG_{table['segment']}, 0x{table['table_guest']:08X}u, "
                         f"{table['index_reg']} * 4u, {table['count']*4}u, {table['count']*4}u, 4u, 0x{site:08X}u)) "
                         "{ recomp_end_memory_access(); RECOMP_FLAGS_OUT(); return; }")
            if body.count(marker) != 1:
                rejections.append(f"could not instrument verified code jump table at 0x{site:08X}")
            else:
                body = body.replace(marker, marker + guard, 1)
    for site, table in indexed_code_call_tables.items():
        function_sites = {i.address for b in function.blocks.values() for i in b.instructions}
        if site in function_sites:
            segment_name = "CS" if table["segment"] == "CS" else "DS"
            marker_re = re.compile(
                rf"recomp_begin_memory_access_ex\(RECOMP_SEG_{segment_name}, 4u, 0x{site:08X}u, "
                r"RECOMP_MEM_ACCESS_READ, [0-9]+u, \"call\"\);"
            )
            marker = marker_re.search(body)
            guard = (f"\n    if ((uint32_t){table['index_reg']} >= {table['count']}u || "
                     f"!recomp_check_indexed_table_access(RECOMP_SEG_{segment_name}, 0x{table['table_guest']:08X}u, "
                     f"(uint32_t){table['index_reg']} * 4u, {table['count']*4}u, {table['count']*4}u, 4u, 0x{site:08X}u)) "
                     "{ recomp_end_memory_access(); RECOMP_FLAGS_OUT(); return; }")
            if marker is None:
                rejections.append(f"could not instrument verified code-call table at 0x{site:08X}")
            else:
                body = body[:marker.end()] + guard + body[marker.end():]
    function_sites = {i.address for b in function.blocks.values() for i in b.instructions}
    for site in sorted(verified_indirect_by_site):
        if site not in function_sites:
            continue
        observed_indirect_sites.add(site)
        marker = re.compile(rf"RECOMP_ICALL\(([^;]+)\); /\* 0x{site:08X}:")
        found = marker.search(body)
        if not found:
            rejections.append(f"could not instrument exact verified indirect callsite 0x{site:08X}")
        else:
            array_name = f"gw_recomp_icall_allow_{site:08X}"
            if args.batch_le_fixup_vtables and site not in harness_exact_indirect_sites:
                # A finite per-site vtable census is useful provenance, but it
                # is not exhaustive for polymorphic objects created later in
                # a replay. In batch mode, authorize the *loaded target* only
                # if it is a lifted Object-1 entry backed by a canonical LE
                # code-pointer fixup. This preserves fail-closed dispatch while
                # allowing another verified class to use the shared callsite.
                call_size=next((i.size for b in function.blocks.values()
                                for i in b.instructions if i.address==site),1)
                replacement=(f"GW_RECOMP_ICALL_LE_BACKED_AT(0x{site:08X}u, {found.group(1)}, "
                             f"0x{site+call_size:08X}u, gw_recomp_le_backed_dispatch_targets); /* 0x{site:08X}:")
                runtime_le_backed_verified_dispatch_sites.add(site)
            else:
                replacement = (f"GW_RECOMP_ICALL_ALLOWED(0x{site:08X}u, {found.group(1)}, "
                               f"{array_name}); /* 0x{site:08X}:")
            vtable_contracts = verified_le_vtable_calls.get(site, [])
            if vtable_contracts and not (args.batch_le_fixup_vtables and
                                          site not in harness_exact_indirect_sites):
                # Keep each live vtable base paired with the exact fixup target
                # selected by this CALL's displacement. This matters when a
                # shared virtual callsite is reached through two LE classes.
                pairs=[]
                target_expr=found.group(1)
                for contract in vtable_contracts:
                    target_guest=image.link_to_linear(contract["target_link"])
                    pairs.append(f'((uint32_t){contract["base_register"]} == 0x{contract["vtable_guest"]:08X}u && '
                                 f'(uint32_t)({target_expr}) == 0x{target_guest:08X}u)')
                pair_guard=' || '.join(pairs)
                replacement = (f'if (!({pair_guard})) '
                    f'{{ fprintf(stderr, "TRACE vtable_pair_frontier site=0x{site:08X}u base=0x%08X target=0x%08X\\n", '
                    f'(uint32_t){contract["base_register"]}, (uint32_t)({target_expr})); '
                    f'GW_RECOMP_FRONTIER_AT(0x{site:08X}u, "unexpected LE vtable base/slot pair"); }} '
                    + replacement)
            body = marker.sub(lambda _m: replacement, body, count=1)
    for site in sorted(deferred_indirect_sites):
        if site not in function_sites:
            continue
        marker = re.compile(rf"RECOMP_ICALL\(([^;]+)\); /\* 0x{site:08X}:")
        found = marker.search(body)
        if not found:
            rejections.append(f"could not instrument exact deferred indirect callsite 0x{site:08X}")
        else:
            replacement = (f"gw_record_deferred_indirect(0x{site:08X}u); "
                           f"RECOMP_ICALL({found.group(1)}); /* 0x{site:08X}:")
            body = marker.sub(lambda _m: replacement, body, count=1)
    for site, table in sorted(runtime_indexed_code_jump_tables.items()):
        if site not in function_sites:
            continue
        marker = re.compile(rf"RECOMP_ITAIL\(([^;]+)\);\s*return; /\* 0x{site:08X}:")
        found=marker.search(body)
        if not found:
            rejections.append(f"could not instrument runtime-indexed code jump at 0x{site:08X}")
        else:
            array_name=f"gw_recomp_itail_allow_{site:08X}"
            replacement=(f"GW_RECOMP_ITAIL_INDEXED_ALLOWED(0x{site:08X}u, "
                f"0x{table['table_guest']:08X}u, {table['index_reg']}, {table['count']}u, "
                f"{found.group(1)}, {array_name}); return; /* 0x{site:08X}:")
            body=marker.sub(lambda _m:replacement,body,count=1)
            observed_runtime_jump_sites.add(site)
    for site in sorted(runtime_le_backed_dispatch_sites):
        if site not in function_sites:
            continue
        marker=re.compile(rf"RECOMP_ICALL\(([^;]+)\); /\* 0x{site:08X}:")
        found=marker.search(body)
        if not found:
            rejections.append(f"could not instrument LE-backed runtime indirect CALL at 0x{site:08X}")
        else:
            replacement=(f"GW_RECOMP_ICALL_LE_BACKED_AT(0x{site:08X}u, {found.group(1)}, "
                         f"0x{site+next((i.size for b in function.blocks.values() for i in b.instructions if i.address==site),1):08X}u, "
                         "gw_recomp_le_backed_dispatch_targets); /* ")
            body=marker.sub(lambda _m:replacement+f"0x{site:08X}:",body,count=1)
            observed_indirect_sites.add(site)
    for site in sorted(runtime_le_backed_tail_sites):
        if site not in function_sites or site in runtime_frontiers or site in runtime_indexed_code_jump_tables:
            continue
        marker=re.compile(rf"RECOMP_ITAIL\(([^;]+)\);\s*return; /\* 0x{site:08X}:")
        found=marker.search(body)
        if not found:
            rejections.append(f"could not instrument LE-backed runtime indirect JMP at 0x{site:08X}")
        else:
            replacement=(f"GW_RECOMP_ITAIL_LE_BACKED_AT(0x{site:08X}u, {found.group(1)}, "
                         "gw_recomp_le_backed_dispatch_targets); return; /* ")
            body=marker.sub(lambda _m:replacement+f"0x{site:08X}:",body,count=1)
            observed_runtime_jump_sites.add(site)
    for site, reason in sorted(runtime_frontiers.items()):
        if site not in function_sites:
            continue
        marker = f"/* 0x{site:08X}:"
        lines = body.splitlines()
        index = next((i for i, line in enumerate(lines) if marker in line), None)
        if index is None:
            rejections.append(f"could not instrument runtime fail-closed frontier at 0x{site:08X}")
            continue
        # Remove the memory guard setup and lifted expression together. The
        # trap must occur before evaluating an unresolved pointer or address.
        if index > 0 and f"0x{site:08X}u, RECOMP_MEM_ACCESS_" in lines[index-1]:
            lines.pop(index-1)
            index -= 1
        lines[index] = (f'GW_RECOMP_FRONTIER_AT(0x{site:08X}u, "{reason}"); '
                        f'/* 0x{site:08X}: fail-closed original instruction */')
        # _computed_jump can emit a switch using function-wide candidate
        # targets after its site-specific indirect operand. When this exact
        # site is unresolved, the fail-closed trap replaces that whole branch;
        # retaining its trailing switch leaves a stray _jt use (and would
        # expose unrelated CFG candidates as executable branches).
        if index + 1 < len(lines) and lines[index+1].strip() == "switch (_jt) {":
            switch_end=next((i for i in range(index+2,len(lines))
                             if lines[i].strip() == "} }"),None)
            if switch_end is None:
                rejections.append(f"could not remove residual computed-jump switch at 0x{site:08X}")
            else:
                del lines[index+1:switch_end+1]
        body = "\n".join(lines)
    emitted.append(body)
    raw = code[address - code_obj.base:function.end - code_obj.base]
    records.append({"name": map_rows.get(address, function.name), "lift_name": function.name,
                    "address": f"0x{address:08X}", "end": f"0x{function.end:08X}", "size": len(raw),
                    "bytes": raw.hex(), "blocks": len(function.blocks),
                    "instructions": function.num_instructions,
                    "calls_to": [f"0x{x:08X}" for x in sorted(function.calls_to)]})
if rejections:
    raise SystemExit("refusing unsafe partial closure after instrumentation:\n  " +
                     "\n  ".join(sorted(set(rejections))))
if (runtime_le_backed_dispatch_sites or runtime_le_backed_verified_dispatch_sites or
        runtime_le_backed_tail_sites) and not le_backed_dispatch_targets:
    raise SystemExit("LE-backed indirect dispatcher has callsites but no lifted fixup-backed target set")
# A partial closure must validate every verified indirect call that belongs to
# one of its lifted functions. Contracts for callsites in functions that were
# not selected into that closure are inert metadata: requiring those unrelated
# gameplay/CRT bodies would make (for example) an IFCTitle closure depend on
# the whole game loop. Keep the check strict for every in-scope callsite,
# including one that should have been decoded but was omitted from emitted
# blocks.
def callsite_is_in_lifted_blocks(site: int) -> bool:
    return any(insn.address == site
               for function in funcs.values()
               for block in function.blocks.values()
               for insn in block.instructions)

unobserved_allowlists = sorted(set(verified_indirect_by_site) - observed_indirect_sites)
in_scope_unobserved_allowlists = [site for site in unobserved_allowlists
                                  if callsite_is_in_lifted_blocks(site)]
out_of_scope_allowlists = [site for site in unobserved_allowlists
                           if not callsite_is_in_lifted_blocks(site)]
if in_scope_unobserved_allowlists:
    raise SystemExit("verified indirect callsite instruction is present in lifted blocks but missing from the generated closure: " +
                     ", ".join(f"0x{x:08X}" for x in in_scope_unobserved_allowlists))
unobserved_runtime_jumps=sorted(set(runtime_indexed_code_jump_tables)-observed_runtime_jump_sites)
if unobserved_runtime_jumps:
    raise SystemExit("runtime-indexed code jump table is outside the generated closure: " +
                     ", ".join(f"0x{x:08X}" for x in unobserved_runtime_jumps))
text = "\n\n".join(emitted)
calls = sorted(set(re.findall(r"RECOMP_CALL\(([A-Za-z0-9_]+)\)", text)))
defs = set(re.findall(r"void\s+([A-Za-z0-9_]+)\s*\(", text))
partial = bool(args.partial_root)
wrappers = []
partial_lookup_rows = []
if partial:
    # Lifter emits RECOMP_CALL(recomp_<name>) while the body keeps its stable
    # generated name. Provide the same ABI shim the full dispatcher supplies.
    for function in sorted(funcs.values(), key=lambda f: f.address):
        wrapper = "recomp_" + function.name
        wrappers.append(f"void {wrapper}(void) {{ {function.name}(); }}")
        defs.add(wrapper)
    # Register only original code bodies that are already part of this
    # bounded closure and are selected either from a fixup-backed indexed
    # table or an exact verified-indirect contract. This lets an allowed
    # callback such as SMACKCLOSE's LE-fixed D7220 reach its lifted body, while
    # absent/unlifted destinations remain fail-closed in the runtime.
    table_targets = {target for site in observed_indirect_sites
                     if site in indexed_code_call_tables
                     for target in indexed_code_call_tables[site]["targets"]}
    explicit_targets = {target for targets in verified_indirect_by_site.values()
                        for target in targets}
    lookup_targets = table_targets | {target for target in explicit_targets
                                      if target in funcs}
    for target in sorted(lookup_targets):
        function = funcs.get(target)
        if function is None:
            if target in table_targets:
                raise SystemExit(f"fixup-backed indexed target 0x{target:08X} has no lifted body")
            continue
        partial_lookup_rows.append((image.link_to_linear(target), target,
                                    "recomp_" + function.name))
external = sorted(set(calls) - defs)
declared = sorted(calls) if partial else external
out = (Path(args.output_c).resolve() if args.output_c else
       ROOT / "build" / ("partial_entry_path.c" if partial else "entry_path.c"))
code_maps = [obj for obj in image.objects if obj.executable and obj.linear_base_verified]
map_installer = ""
if partial:
    map_rows_c = ",\n".join(
        f"        {{ 0x{int(obj.linear_base):08X}u, 0x{obj.base:08X}u, 0x{obj.virtual_size:08X}u }}"
        for obj in code_maps)
    map_installer = ("\nint gw_partial_install_code_map(void) {\n"
                     "    static const recomp_code_range ranges[] = {\n" + map_rows_c + "\n    };\n"
                     "    return recomp_code_map_set(ranges, (uint32_t)(sizeof(ranges)/sizeof(ranges[0])));\n"
                     "}\n")
    lookup_rows = []
    for guest_address, link_address, wrapper in partial_lookup_rows:
        lookup_rows.extend(((guest_address, wrapper), (link_address, wrapper)))
    lookup_rows.sort()
    lookup_table = ",\n".join(
        f"        {{ 0x{address:08X}u, {wrapper} }}" for address, wrapper in lookup_rows)
    map_installer += ("\ntypedef struct { uint32_t va; recomp_func_t fn; } gw_partial_dispatch_entry;\n" +
                      "static const gw_partial_dispatch_entry gw_partial_dispatch[] = {\n" +
                      lookup_table +
                      "\n};\nrecomp_func_t gw_partial_lookup_guest(uint32_t va) {\n" +
                      "    uint32_t lo = 0u, hi = (uint32_t)(sizeof(gw_partial_dispatch)/sizeof(gw_partial_dispatch[0]));\n" +
                      "    while (lo < hi) { uint32_t mid = lo + (hi - lo) / 2u; uint32_t key = gw_partial_dispatch[mid].va;\n" +
                      "        if (key == va) return gw_partial_dispatch[mid].fn;\n" +
                      "        if (key < va) lo = mid + 1u; else hi = mid; }\n" +
                      "    return NULL;\n}\n")
    # MapDisplay::Draw and the terrain rasterizer derive their destination
    # pitch from WScreen globals, but six instructions in the terrain pass
    # encode the canonical 640-pixel clip/pitch as immediates. Parameterize
    # only those verified instructions (plus the sprite window's width) from
    # the existing screen-width global. At the canonical width this is
    # byte-for-byte equivalent in value; experimental surfaces can widen the
    # actual world render without changing camera/world coordinates.
    video_width_substitutions = {
        "ecx = 0x280u; /* 0x0007C29C: mov ecx, 0x280 */":
            "ecx = MEM32(DS_BASE + (0x376A78)); /* 0x0007C29C: parameterized screen width */",
        "_flag_a = (uint32_t)(eax); _flag_b = (uint32_t)(0x280u);\n    _cf = (uint32_t)CMP_B(_flag_a, _flag_b);\n    eax = eax - 0x280u; /* 0x0007C2A5: sub eax, 0x280 */":
            "_flag_a = (uint32_t)(eax); _flag_b = MEM32(DS_BASE + (0x376A78));\n    _cf = (uint32_t)CMP_B(_flag_a, _flag_b);\n    eax = eax - MEM32(DS_BASE + (0x376A78)); /* 0x0007C2A5: parameterized screen-width subtraction */",
        "eax = (ecx + (-0x280)); /* 0x0007C347: lea eax, [ecx - 0x280] */":
            "eax = ecx - (int32_t)MEM32(DS_BASE + (0x376A78)); /* 0x0007C347: parameterized screen-width clip edge */",
        "ecx = 0x280u; /* 0x0007C34F: mov ecx, 0x280 */":
            "ecx = MEM32(DS_BASE + (0x376A78)); /* 0x0007C34F: parameterized screen width */",
        "eax = (ecx + (-0x280)); /* 0x0007C3F8: lea eax, [ecx - 0x280] */":
            "eax = ecx - (int32_t)MEM32(DS_BASE + (0x376A78)); /* 0x0007C3F8: parameterized screen-width clip edge */",
        "ecx = 0x280u; /* 0x0007C400: mov ecx, 0x280 */":
            "ecx = MEM32(DS_BASE + (0x376A78)); /* 0x0007C400: parameterized screen width */",
        "ebx = 0x280u; /* 0x000794EB: mov ebx, 0x280 */":
            "ebx = MEM32(DS_BASE + (0x376A78)); /* 0x000794EB: parameterized sprite window width */",
    }
    def lifted_function_containing(site: int):
        return next((function for function in funcs.values()
                     if function.address <= site < function.end), None)

    # These renderer rewrites are global post-processing rules, but this tool
    # also emits deliberately partial closures (for example, only LbDataLoad).
    # Apply each rule only when its original instruction's function is in that
    # closure. If the function is present, retain the exact fail-closed count.
    for original, replacement in video_width_substitutions.items():
        site_match = re.search(r"/\* 0x([0-9A-Fa-f]{8}):", original)
        if site_match is None:
            raise SystemExit("video-surface contract lacks an original instruction address")
        site = int(site_match.group(1), 16)
        count = text.count(original)
        owner = lifted_function_containing(site)
        if owner is None:
            if count:
                raise SystemExit(f"video-surface instruction 0x{site:08X} emitted outside its lifted function")
            continue
        if count != 1:
            raise SystemExit(f"video-surface width contract at 0x{site:08X} expected one lifted instruction, got {count}")
        text = text.replace(original, replacement, 1)
    # The original raster primitives also encode 640 as their row pitch.  A
    # widened WScreen with only the MapDisplay clip widened shears pixels
    # because these row-address increments still use 640.  Parameterize the
    # two verified framebuffer blitters as well; when the descriptor remains
    # 640, their arithmetic is unchanged.  Keep this narrowly scoped to the
    # audited routines and require the expected literal counts so generator
    # drift fails closed.
    def parameterize_framebuffer_pitch(function_entry: str, expected_literals: int) -> None:
        global text
        entry = int(function_entry.removesuffix("u").removeprefix("0x"), 16)
        if entry not in funcs:
            if f"RECOMP_ENTER({function_entry})" in text:
                raise SystemExit(f"video-surface pitch entry {function_entry} appears without a closure function")
            return
        marker = f"RECOMP_ENTER({function_entry})"
        start = text.find(marker)
        if start < 0:
            raise SystemExit(f"video-surface pitch contract missing {function_entry}")
        end = text.find("RECOMP_ENTER(", start + len(marker))
        if end < 0:
            end = len(text)
        block = text[start:end]
        literal_count = 0
        transformed = []
        for line in block.splitlines(keepends=True):
            code, sep, comment = line.partition("/*")
            literal_count += code.count("0x280")
            code = code.replace("0x280u", "MEM32(DS_BASE + (0x376A78))")
            code = code.replace("0x280", "MEM32(DS_BASE + (0x376A78))")
            transformed.append(code + (sep + comment if sep else ""))
        if literal_count != expected_literals:
            raise SystemExit(f"video-surface pitch contract {function_entry} expected {expected_literals} 640 literals, got {literal_count}")
        text = text[:start] + "".join(transformed) + text[end:]

    parameterize_framebuffer_pitch("0x0001C600u", 30)
    parameterize_framebuffer_pitch("0x0001CAE0u", 38)
    # Raster instrumentation is opt-in because most partial closures do not
    # link the graphics-probe callbacks. The dedicated creature probe enables
    # it explicitly; unrelated title/plugin closures remain self-contained.
    wide_raster_probes = os.environ.get("GW_ENABLE_WIDE_RASTER_PROBES") == "1"
    if wide_raster_probes:
        for site in (0x7C526, 0x7C54B):
            marker=f"if (!gw_recomp_guest_instruction(0x{site:08X}u)) return;"
            if text.count(marker)!=1:
                raise SystemExit(f"terrain byte-store probe expected one instruction 0x{site:08X}")
            if site==0x7C526:
                hook=" gw_terrain_byte_store_probe(0x7C526u,DS_BASE+esi+eax+0x376BE4u,LO8(edx));"
            else:
                hook=" gw_terrain_byte_store_probe(0x7C54Bu,DS_BASE+edx+eax+0x376BE4u,LO8(ebx));"
            text=text.replace(marker,marker+hook,1)
        # Focused E19C0 setup/interpolation oracle. This remains opt-in with
        # the raster probes and is filtered by the harness to five selected
        # triangle submissions; it captures IDIV inputs/results, actual
        # indirect-table targets, and the first scanline's packed state.
        e19_start=text.find("void gw_partial_0x000E19C0(void) {")
        if e19_start < 0:
            raise SystemExit("E19C0 setup trace could not find lifted function")
        e19_end=text.find("\n/* gw_lift",e19_start+1)
        if e19_end < 0: e19_end=len(text)
        e19=text[e19_start:e19_end]
        # Capture call-time arguments and the selector state before any of
        # E19C0's prologue/setup instructions can overwrite the registers.
        entry_marker="if (!gw_recomp_guest_instruction(0x000E19C0u)) return;"
        if e19.count(entry_marker)!=1:
            raise SystemExit("E19C0 setup trace expected one entry instruction")
        e19=e19.replace(entry_marker,entry_marker+
            " gw_e19c0_setup_probe(0x000E19C0u,0u,0u,eax,ebx,ecx,edx,esi,edi,ebp,esp);",1)
        recon_sites={}
        # The operand text itself may contain '*' (for example the scaled
        # index in `jmp dword ptr [eax*4 + table]`), so only the closing
        # comment delimiter may terminate the instruction text.
        insn_re=re.compile(r"/\* 0x([0-9A-Fa-f]{8}):\s*(.*?)\s*\*/")
        insns=list(insn_re.finditer(e19))
        for ix,m in enumerate(insns):
            site=int(m.group(1),16); op=m.group(2).strip().lower()
            if op.startswith("idiv ") and ix+1<len(insns):
                recon_sites[site]=(1,0)
                recon_sites[int(insns[ix+1].group(1),16)]=(2,0)
            if op.startswith("jmp dword ptr"):
                target=re.search(r"jmp dword ptr \[[^\]]*?0x([0-9a-fA-F]+)\]",op)
                if target:
                    recon_sites[site]=(3,int(target.group(1),16))
        # Phase 4 is sampled only once per selected primitive by the harness.
        if 0xE4190 not in recon_sites: recon_sites[0xE4190]=(4,0)
        # Keep the setup-source captures separate from the per-pixel table
        # dispatches. E4053 initializes the mode-5 scanline accumulators;
        # E408D is the first scanline-record load after that initialization.
        recon_sites[0xE4053]=(5,0)
        recon_sites[0xE408D]=(6,0)
        for site,(phase,table_base) in sorted(recon_sites.items()):
            marker=f"if (!gw_recomp_guest_instruction(0x{site:08X}u)) return;"
            if marker not in e19:
                continue
            hook=(f" gw_e19c0_setup_probe(0x{site:08X}u,{phase}u,"
                  f"0x{table_base:08X}u,eax,ebx,ecx,edx,esi,edi,ebp,esp);")
            e19=e19.replace(marker,marker+hook,1)
        text=text[:e19_start]+e19+text[e19_end:]
        # REP MOVS is lowered to host memmove, so the guest write observer
        # cannot see the actual framebuffer writes. Capture the exact guest
        # source/destination span at these graphics copy sites instead.
        # This stays opt-in and is limited to the two known terrain/sprite
        # blitters, preserving all normal lifted execution paths.
        framebuffer_copy_sites = (0x1C68D, 0x1C694, 0x1C6A9, 0x1C6B0,
            0x1C71B, 0x1C737, 0x1C7B0, 0x1C7CC, 0x1C84E, 0x1C89A,
            0x1C96E, 0x1CAAA, 0x1C8FF, 0x1C932, 0x1C975, 0x1C9A8,
            0x1CC31, 0x1CD03, 0x1CDBF, 0x1CEA7, 0x1CF62)
        for site in framebuffer_copy_sites:
            marker = f"/* 0x{site:08X}:"
            if marker in text:
                text=text.replace(marker,
                    f"gw_framebuffer_copy_probe(0x{site:08X}u,esi,edi,(uint32_t)_b64,_df); {marker}",1)
            else:
                # Not all instructions are REP strings in every selected
                # closure; only instrument the exact emitted LE sites present.
                continue
        for site in (0x7C610, 0x7C671, 0x7C230, 0x7C43C, 0x7C441,
                     0x665B0, 0xE19C0,
                     0x7C298, 0x7C29A, 0x7C29C, 0x7C347, 0x7C34F,
                     0xE7E69, 0xE7E71, 0xE7F05, 0x7C3DA, 0x7C41C, 0x7C438,
                     0x7C480, 0x65F20, 0x662BE, 0x664CD, 0x6651C, 0x66564,
                     0x66737, 0x667C4, 0x6689F, 0x66B6C, 0x668AA, 0x66B77,
                     0x1C68D, 0x1C694, 0x1C6A9, 0x1C6B0,
                     0x1C71B, 0x1C737, 0x1C7B0, 0x1C7CC,
                     0x1C84E, 0x1C89A, 0x1C96E, 0x1CAAA,
                     0x1C8FF, 0x1C932, 0x1C9A8):
            marker = f"if (!gw_recomp_guest_instruction(0x{site:08X}u)) return;"
            count = text.count(marker)
            if count != 1:
                raise SystemExit(f"video raster probe expected one site 0x{site:X}, got {count}")
            hook = (f" gw_wide_raster_probe(0x{site:08X}u,"
                    "eax,ebx,ecx,edx,esi,edi,ebp,esp);")
            if site == 0x7C43C:
                # Isolated experiment only: the harness changes ECX immediately
                # before the original setup_vecs call. The returned value is
                # gated by its private-surface probe state; normal runs preserve it.
                hook += " ecx=gw_wide_raster_override_clip(0x7C43Cu,ecx);"
            text = text.replace(marker, marker + hook, 1)

        # Capture complete temporary vertex records immediately before their
        # final topology-byte stores and record the exact outcomes of both
        # LE topology branches. Inert unless the one-frame probe is active.
        for site in (0x66737, 0x667C4, 0x6689F, 0x66B6C):
            site_hex=f"0x{site:08X}"
            marker=f"if (!gw_recomp_guest_instruction({site_hex}u)) return;"
            if text.count(marker)!=1:
                raise SystemExit(f"projection node capture expected one store site {site_hex}")
            text=text.replace(marker,
                f"gw_projection_mesh_node({site_hex}u,eax,ebx,ecx,edx,esi,edi,ebp,esp);\n    {marker}",1)
        for site,dest in ((0x668AA,0x66AC3),(0x66B77,0x66D81)):
            branch_re=re.compile(
                rf'(?m)^(    )if \(TEST_Z\(_flag_a, _flag_b\)\) goto L_{dest:08X}; '
                rf'/\* 0x{site:08X}: je 0x{dest:x} \*/$')
            if len(branch_re.findall(text))!=1:
                raise SystemExit(f"projection topology branch {site:#x} changed shape")
            text=branch_re.sub(
                lambda m:(f"{m.group(1)}if (TEST_Z(_flag_a, _flag_b)) {{ "
                          f"gw_projection_branch_capture(0x{site:08X}u,eax,1u); "
                          f"goto L_{dest:08X}; }} else "
                          f"gw_projection_branch_capture(0x{site:08X}u,eax,0u); "
                          f"/* 0x{site:08X}: je 0x{dest:x} */"),text,1)

out.write_text('#define RECOMP_GENERATED_CODE\n#include "recomp_types.h"\n#include "recomp_context.h"\n#include "gw_recomp_stop.h"\n#include "gw_segments.h"\nvoid gw_record_deferred_indirect(uint32_t);\n' +
               ('void gw_wide_raster_probe(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t);\n' +
                'void gw_e19c0_setup_probe(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t);\n' +
                'void gw_terrain_byte_store_probe(uint32_t,uint32_t,uint32_t);\n' +
                'void gw_framebuffer_copy_probe(uint32_t,uint32_t,uint32_t,uint32_t,int32_t);\n' +
                'void gw_projection_mesh_node(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t);\n' +
                'void gw_projection_branch_capture(uint32_t,uint32_t,uint32_t);\n' +
                'uint32_t gw_wide_raster_override_clip(uint32_t,uint32_t);\n' if wide_raster_probes else '') +
               "\n".join(allowlist_arrays) + "\n\n" +
               "\n".join(f"extern void {name}(void);" for name in declared) + "\n\n" +
               text + "\n\n" + "\n".join(wrappers) + map_installer + "\n",
               encoding="utf-8")
report = {"target_sha256": sha, "object_map_mode": args.object_map,
          "closure_mode": "bounded_partial" if partial else "full",
          "address_contract": "MAP/disassembler/dispatcher keys remain LE link VAs; decoded bytes contain per-object loaded fixups; static data operands must map to verified guest objects",
          "object_map": [{"index": obj.index, "link_base": f"0x{obj.base:08X}",
                          "linear_base": f"0x{obj.linear_base:08X}",
                          "linear_base_verified": obj.linear_base_verified,
                          "size": f"0x{obj.virtual_size:08X}"} for obj in image.objects],
          "roots": [{"name": map_rows.get(address), "address": f"0x{address:08X}"} for address in roots],
          "stack_range": (f"0x{stack_base:08X}+0x{stack_size:X}" if args.partial_root else None),
          "dynamic_guest_ranges": [[f"0x{a:08X}", f"0x{b:08X}"] for a, b in dynamic_ranges],
          "rep_movsd_guest_ranges": {
              "source": [f"0x{rep_movsd_source[0]:08X}", f"0x{rep_movsd_source[1]:08X}"] if partial and rep_movsd_source else None,
              "destination": [f"0x{rep_movsd_destination[0]:08X}", f"0x{rep_movsd_destination[1]:08X}"] if partial and rep_movsd_destination else None},
          "dynamic_accesses": dynamic_accesses,
          "segment_relative_contracts": [{"instruction": f"0x{site:08X}",
              "segment": "ES", "offset": f"0x{offset:08X}", "width": width}
              for site, (offset, width) in sorted(segment_relative_contracts.items())],
          "stop_after_call": ({"site": f"0x{stop_after_call[0]:08X}",
              "target": f"0x{stop_after_call[1]:08X}",
              "matched": matched_stop_after_call} if stop_after_call else None),
          "code_pointer_maps": [{"guest_linear_base": f"0x{int(obj.linear_base):08X}",
                                  "link_base": f"0x{obj.base:08X}",
                                  "size": f"0x{obj.virtual_size:08X}",
                                  "object": obj.index} for obj in code_maps],
          "verified_indirect_targets": sorted(indirect_targets,
                                                key=lambda row: (row["callsite"], row["guest_target"])),
          "verified_le_vtable_calls": [
              {"callsite":f"0x{site:08X}","base_register":table["base_register"],
               "vtable_link":f"0x{table['vtable_link']:08X}",
               "vtable_guest":f"0x{table['vtable_guest']:08X}","slot_count":table["count"],
               "selected_slot_index":table["slot_index"],"selected_slot_link":f"0x{table['slot_link']:08X}",
               "selected_target_link":f"0x{table['target_link']:08X}",
               "runtime_guards":[f"live {table['base_register'].upper()} equals relocated LE vtable base",
                                 "indirect target equals selected fixup target"],
               "entries":[{"index":entry["index"],"source_link":f"0x{entry['source_link']:08X}",
                   "target_link":f"0x{entry['target_link']:08X}","target_offset":f"0x{entry['target_offset']:08X}",
                   "target_flags":f"0x{entry['target_flags']:02X}"} for entry in table["entries"]]}
              for site,tables in sorted(verified_le_vtable_calls.items())
              for table in tables],
          "deferred_indirect_call_sites": [f"0x{x:08X}" for x in sorted(deferred_indirect_sites)],
          "runtime_fail_closed_frontiers": [
              {"instruction": f"0x{site:08X}", "reason": reason,
               "behavior": "trap before evaluating the unresolved operand or transferring control"}
              for site, reason in sorted(runtime_frontiers.items())],
          "runtime_le_backed_dispatcher": {
              "enabled": bool(args.batch_le_fixup_vtables),
              "lifted_fixup_backed_code_target_count": len(le_backed_dispatch_targets),
              "indirect_call_sites": [f"0x{x:08X}" for x in sorted(runtime_le_backed_dispatch_sites)],
              "verified_indirect_call_sites_using_le_backed_fallback": [f"0x{x:08X}" for x in sorted(runtime_le_backed_verified_dispatch_sites)],
              "indirect_tail_sites": [f"0x{x:08X}" for x in sorted(runtime_le_backed_tail_sites)],
              "behavior": "actual indirect destination must equal a decoded executable Object-1 code target backed by a canonical LE pointer fixup and present as a lifted function entry; all other values remain runtime fail-closed"},
          "indexed_cs_tables": [{"instruction": f"0x{x:08X}", "table_link": f"0x{t['table_link']:08X}",
                                  "table_guest": f"0x{t['table_guest']:08X}", "count": t["count"],
                                  "bytes": t["raw"].hex(), "runtime_guard": "base in 1..count and index < count"}
                                 for x, t in sorted(indexed_cs_tables.items())],
          "indexed_code_jump_tables": [{"instruction": f"0x{x:08X}",
                                  "table_link": f"0x{t['table_link']:08X}",
                                  "table_guest": f"0x{t['table_guest']:08X}", "count": t["count"],
                                  "segment": t["segment"],
                                  "targets_link": [f"0x{v:08X}" for v in t["targets"]],
                                  "fixup_slots": [{"index":slot["index"],
                                      "source_link":f"0x{slot['source_link']:08X}",
                                      "target_object":slot["target_object"],
                                      "target_offset":f"0x{slot['target_offset']:08X}",
                                      "target_link":f"0x{slot['target_link']:08X}"}
                                      for slot in t["fixup_slots"]],
                                  "bytes": t["raw"].hex(),
                                  "runtime_guard": ("original per-site guards byte-verified plus explicit index bound"
                                      if code_table_contracts[x]["guard"] else "explicit index bound before the exact LE-fixup-backed table read")}
                                 for x, t in sorted(indexed_code_jump_tables.items())],
          "indexed_code_call_tables": [{"instruction": f"0x{x:08X}",
                                  "table_link": f"0x{t['table_link']:08X}",
                                  "table_guest": f"0x{t['table_guest']:08X}",
                                  "count": t["count"], "fixup_backed_target_count": len(t["targets"]),
                                  "targets_link": [f"0x{v:08X}" for v in t["targets"]],
                                  "index_guard":t["index_guard"],
                                  "fixup_slots":t["slots"],
                                  "runtime_guard": f"EAX 0..{t['count']-1}, {t['count']*4}-byte table bounds, exact live target allowlist"}
                                 for x, t in sorted(indexed_code_call_tables.items())],
          "selector_guarded_accesses": [{"instruction": f"0x{x:08X}",
                                  "segment": "GS", "base_register": t[0].upper(),
                                  "segment_offset": f"register+0x{t[1]:X}", "width": t[2],
                                  "allocation_limit": f"0x{t[3]:X}", "purpose": t[4],
                                  "runtime_guard": "actual DPMI DOS descriptor and backing range"}
                                 for x, t in sorted(selector_guard_contracts.items())
                                 if x in matched_selector_guard_sites],
          "runtime_indirect_value_checks_required": [
              {"callsite": f"0x{site:08X}", "link_target": f"0x{target:08X}",
               "guest_target": f"0x{image.link_to_linear(target):08X}",
               "provenance": "generated_exact_site_allowlist_checks_live_guest_pointer"}
              for site, targets in sorted(verified_indirect_by_site.items())
              for target in sorted(targets)],
          "verified_indirect_callsite_scope": {
              "validation": "strict for callsites whose instruction is present in lifted basic blocks; allowlists outside this partial closure are recorded but not required",
              "in_scope_observed_count": len(set(verified_indirect_by_site) & observed_indirect_sites),
              "out_of_scope_unobserved_count": len(out_of_scope_allowlists),
              "out_of_scope_unobserved_sites": [f"0x{x:08X}" for x in out_of_scope_allowlists],
              "in_scope_unobserved_sites": [f"0x{x:08X}" for x in in_scope_unobserved_allowlists]},
          "direct_tail_transfers": sorted(tail_transfers, key=lambda row: (row["source"], row["target"])),
          "lifted": records, "missing_or_unsupported": missing, "unresolved_direct_calls": external,
          "partial_rejections": rejections, "output": str(out.relative_to(ROOT))}
report_path = (Path(args.report).resolve() if args.report else
               ROOT / "evidence" / ("partial_entry_path_lifts.json" if partial else "entry_path_lifts.json"))
report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(json.dumps({k: v for k, v in report.items() if k not in ("lifted",)}, indent=2))
