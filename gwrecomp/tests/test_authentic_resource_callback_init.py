"""Execute the LE-fixed resource-callback install and wildcard callback path."""
import os as _gw_os
from pathlib import Path as _GwPath
_GW_MSYS2=_gw_os.environ.get("MSYS2_ROOT",r"C:\msys64")
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "third_party" / "pcrecomp")]
from le_loader import load_le
from tools.disasm.disasm32 import BasicBlock, Disassembler, Function, Instruction
from tools.pe.pe_analyze import Section
from tools.lift.lift32 import Lifter

TARGET = ROOT / "evidence" / "genewars-1_1.exe"
REBASES = {1: 0x1EB000, 3: 0x1DA000}
EXPECTED_TARGET_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"


def exact_slice(dis, va, count, name, synthetic_ret=False):
    decoded = list(dis.disassemble_at(va, max_bytes=0x100))
    if len(decoded) < count:
        raise AssertionError(f"short decode at {va:#x}")
    ins = [Instruction(x.address, x.size, x.mnemonic, x.op_str,
                       bytes(x.bytes), x.operands) for x in decoded[:count]]
    if synthetic_ret:
        end = ins[-1].address + ins[-1].size
        ins.append(Instruction(end, 1, "ret", "", b"\xc3", []))
    start, end = ins[0].address, ins[-1].address + ins[-1].size
    return Function(start, end, name,
                    {start: BasicBlock(start, end, ins, is_exit=True)},
                    size=end - start)


def manager_callback_stage(dis):
    """Keep the authentic FUN_989EC callback CFG and stop after CMP [path]."""
    full = dis.disassemble_function(0x989EC)
    if full is None:
        raise AssertionError("FUN_000989EC CFG boundary changed")
    wanted = (0x989FB, 0x98A01, 0x98A0A, 0x98A11)
    blocks = {}
    for start in wanted:
        source = full.blocks[0x989EC] if start == 0x989FB else full.blocks[start]
        instructions = [i for i in source.instructions if i.address >= start]
        if start == 0x989FB:
            instructions = [i for i in instructions if i.address < 0x98A01]
            end, successors, is_exit = 0x98A01, [0x98A01, 0x98A0A], False
        elif start == 0x98A01:
            end, successors, is_exit = 0x98A0A, [0x98A11], False
        elif start == 0x98A0A:
            end, successors, is_exit = 0x98A11, [0x98A11], False
        else:
            instructions = [i for i in instructions if i.address < 0x98A27]
            end, successors, is_exit = 0x98A27, [], True
        blocks[start] = BasicBlock(start, end, instructions,
                                   successors=successors, is_exit=is_exit)
    return Function(0x989FB, 0x98A27,
                    "gw_original_resource_manager_callback_stage",
                    blocks, size=0x2C)


def main():
    target_sha256 = hashlib.sha256(TARGET.read_bytes()).hexdigest()
    if target_sha256 != EXPECTED_TARGET_SHA256:
        raise SystemExit(f"protected GeneWars 1.1 target hash mismatch: {target_sha256}")
    image = load_le(TARGET, object_rebases=REBASES)
    obj = image.objects[0]
    text = bytes(image.object_data(1))
    dis = Disassembler(text, 0, [Section(".text", obj.base, obj.virtual_size,
                                         0, obj.virtual_size, 0x20000020)])

    init = exact_slice(dis, 0x14E94, 3,
                       "gw_original_install_resource_callback", synthetic_ret=True)
    setter = exact_slice(dis, 0x989E0, 3, "sub_000989E0")
    callsite = exact_slice(dis, 0x98A18, 3,
                           "gw_original_resource_callback_callsite", synthetic_ret=True)
    # Enter FUN_989EC after its global allocator bootstrap. Execute its
    # authentic callback selection/dispatch and '*' test against the static LE
    # *B_SCREEN record, then stop before invoking the resource allocator.
    manager_stage = manager_callback_stage(dis)
    allocation_check = dis.disassemble_function(0x98B6C)
    if allocation_check is None:
        raise AssertionError("FUN_00098B6C CFG/body boundary changed")
    allocation_check.name = "sub_00098B6C"
    callback = dis.disassemble_function(0x14BB0)
    if callback is None or callback.end != 0x14BEC:
        raise AssertionError("callback CFG/body boundary changed")
    callback.name = "gw_original_resource_path_callback"

    lifted = [Lifter().lift_function(f) for f in
              (init, setter, callback, callsite, manager_stage, allocation_check)]
    init_c, setter_c, callback_c, callsite_c, manager_c, allocation_check_c = lifted
    if "RECOMP_CALL(sub_000989E0)" not in init_c:
        raise AssertionError("initializer no longer calls the authentic callback setter")
    if "MEM32(DS_BASE + (0x2E4804)) = eax" not in setter_c:
        raise AssertionError("setter lift does not write the callback slot")
    if "RECOMP_ICALL(MEM32(DS_BASE + (0x2E4804)))" not in callsite_c:
        raise AssertionError("original indirect callsite was not lifted")
    if "RECOMP_CALL(sub_00096B23)" not in callback_c:
        raise AssertionError("unexpected callback CFG; guarded path boundary changed")
    if "RECOMP_CALL(sub_00098B6C)" not in manager_c or \
            "RECOMP_ICALL(MEM32(DS_BASE + (0x2E4804)))" not in manager_c:
        raise AssertionError("manager stage no longer follows the original callback path")
    if "RECOMP_CALL(sub_00092030)" not in allocation_check_c:
        raise AssertionError("allocation cleanup guard changed unexpectedly")

    generated = ROOT / "build" / "authentic_resource_callback_init_lift.c"
    prologue = (
        '#define RECOMP_GENERATED_CODE\n'
        '#include "recomp_types.h"\n#include "recomp_context.h"\n'
        '#include "gw_recomp_stop.h"\n#include "gw_segments.h"\n'
        'void sub_000989E0(void);\nvoid sub_00096B23(void);\n'
        'void sub_00092030(void);\nvoid sub_00098B6C(void);\n')
    wrapped = []
    for code in lifted:
        code = code.replace(
            "{\n", "{\n    RECOMP_REGS_LOCALS\n", 1)
        wrapped.append(code)
    generated.write_text(prologue + "\n".join(wrapped) + "\n", encoding="utf-8")
    guest_image = ROOT / "build" / "authentic_resource_callback_init_guest.bin"
    guest_image.write_bytes(image.mem)
    harness = ROOT / "tests" / "test_authentic_resource_callback_init.c"
    exe = ROOT / "build" / "test_authentic_resource_callback_init.exe"
    env = {**os.environ,
           "PATH": (_GW_MSYS2 + '\\mingw32\\bin;' + _GW_MSYS2 + '\\usr\\bin;') + os.environ.get("PATH", "")}
    command = [(_GW_MSYS2 + '\\mingw32\\bin\\gcc.exe'), "-std=gnu11", "-m32", "-O0",
               "-I", str(ROOT / "runtime"),
               "-I", str(ROOT / "third_party" / "pcrecomp" / "runtime" / "recomp32"),
               "-o", str(exe), str(harness), str(generated),
               str(ROOT / "runtime" / "recomp_context.c"),
               str(ROOT / "runtime" / "gw_interrupts.c"),
               str(ROOT / "runtime" / "gw_segments.c"),
               str(ROOT / "runtime" / "gw_pit8254.c"),
               str(ROOT / "runtime" / "recomp_bridge.c")]
    compile_result = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True)
    print(compile_result.stdout, end="")
    print(compile_result.stderr, end="")
    if compile_result.returncode:
        raise SystemExit(compile_result.returncode)
    run_result = subprocess.run([str(exe)], cwd=ROOT, env=env, text=True, capture_output=True)
    print(run_result.stdout, end="")
    print(run_result.stderr, end="")
    if run_result.returncode:
        raise SystemExit(run_result.returncode)

    slot = image.link_to_linear(0x10A804)
    cb = image.link_to_linear(0x14BB0)
    desc = image.link_to_linear(0x103554)
    callback_target = int.from_bytes(image.mem[slot-image.mem_base:slot-image.mem_base+4], "little")
    callback_loaded = int.from_bytes(text[0x14E95-obj.base:0x14E99-obj.base], "little")
    resource_allocator = image.link_to_linear(0x91E00)
    if callback_target != image.link_to_linear(0x989E8) or callback_loaded != cb:
        raise AssertionError("LE initial slot or initializer pointer changed")
    if resource_allocator != 0x0027CE00:
        raise AssertionError("FUN_000989EC allocator callback LE fixup changed")

    receipt = {
        "schema": "gw-authentic-resource-callback-init/v1",
        "target_sha256": target_sha256,
        "authority": "shipped GeneWars 1.1 LE bytes; bounded experimental execution context",
        "execution_mode": "original_recompiled_instruction_slices",
        "natural_replay": False,
        "ghidra": {
            "provider": "REA 6.4.0 / Ghidra 12.1.4",
            "config_parser_evidence": "ev_2350e85478b4ef8adcbab6dd3d779a4764938c26c5fa967f2d296344af2a2228",
            "callback_setter_evidence": "ev_05a48a3ac3864558c7348064cfa5018d556af8d24e885eddeff7ed3462ed8e8a",
            "indirect_call_evidence": "ev_ee2750127b20331b0431ae27a3fb771d80bc8d73ae708428f65d7186bf4d02cf",
            "callback_instruction_evidence": [
                "ev_9e0e346a85159559e9e93cdc65a4c7dc052f2587f50eced9685f48ba52f79939",
                "ev_2dd5d153494c3192170742aa427592b97b767a7b0b6618b0f29a61eeedbb1",
                "ev_1e8123c0118ee4288804a2ac6bdcd0c1869fb26ca0a00466a1a801561fd39d00"],
            "instruction_evidence": {
                "initializer": "ev_049979d7430641ab96f315134ae1716c6dd6918c84b06af646c4875d4c2536fa",
                "setter": "ev_0d8961d6eb22cbc9afc0d6ee71fa6645052fad8ac689b0c2720c04d82e63105d",
                "indirect_callsite": "ev_d5af0b75bb04cdecb8d9fcb0e73d6719ddc6b631a7a79c0fa5cc39193da2849f"},
            "manager_callback_stage": "ev_ee2750127b20331b0431ae27a3fb771d80bc8d73ae708428f65d7186bf4d02cf",
            "manager_bootstrap": "ev_b381c14a23444b1753ad6a258cad3c831042037c151ad8098c5597b5c67d4cd5",
            "manager_cleanup_guard": "ev_33b4145d4aa170a176a379c6522aed9e18d2e15a5e8f19fa7524c1ca289319ce",
            "install_chain": "setup_game 0x94AC0 -> FUN_00014BF0 -> 0x14E94 CALL FUN_000989E0",
            "dispatch_chain": "FUN_00014FF0 -> FUN_000989EC; indirect call at 0x98A1A reads [0x10A804]; '*' paths avoid DOS open",
        },
        "object_rebases": {"1": "0x1EB000", "3": "0x1DA000"},
        "executed_original_slices": [
            {"function": "FUN_00014BF0 slice", "link_va": "0x14E94", "original_end_inclusive": "0x14E9F",
             "synthetic_harness_return_at": "0x14EA0",
             "purpose": "load LE-fixed callback address and call original setter"},
            {"function": "FUN_000989E0", "link_va": "0x989E0", "range_end_inclusive": "0x989E8",
             "purpose": "write callback address to the original slot"},
            {"function": "FUN_00014BB0", "link_va": "0x14BB0", "range_end_inclusive": "0x14BEB",
             "purpose": "original '*' path callback; returns input descriptor unchanged"},
            {"function": "FUN_000989EC callsite slice", "link_va": "0x98A18", "original_end_inclusive": "0x98A21",
             "synthetic_harness_return_at": "0x98A22",
             "purpose": "MOV EAX,EBX; CALL [0x10A804]; original post-call byte read"},
            {"function": "FUN_000989EC callback CFG slice", "link_va": "0x989FB",
             "original_end_inclusive": "0x98A26",
             "purpose": "original allocator-kind choice, cleanup guard, indirect callback and comparison of the LE *B_SCREEN path; bounded return before allocator"},
            {"function": "FUN_00098B6C", "link_va": "0x98B6C", "range_end_inclusive": "0x98B90",
             "purpose": "original cleanup guard reads the descriptor's LE-fixed null output cell and skips the free path"}
        ],
        "resource_record": {
            "path": "*B_SCREEN", "link_va": "0x103554", "guest_linear": hex(desc),
            "record_size": "0x2C", "output_pointer_cell_guest_linear": hex(int.from_bytes(
                image.mem[desc-image.mem_base+0x1C:desc-image.mem_base+0x20], "little")),
            "initial_output_pointer": "0x00000000", "flag_byte_0x28": int(image.mem[desc-image.mem_base+0x28]),
            "allocator_callback_selected_by_flags": "FUN_00091E00",
            "allocator_callback_guest_linear": hex(resource_allocator),
            "source": "original 1.1 LE image after verified object fixups"
        },
        "le_vs_carrier": {
            "carrier_instruction_operands": {"initializer_immediate": "0x14BB0", "callback_slot": "0x10A804"},
            "after_verified_object_1_fixup": {"initializer_immediate": hex(cb), "callback_slot": hex(slot)},
            "note": "Ghidra carrier addresses remain link VAs; execution fixture uses bytes loaded and fixed up by le_loader."},
        "addresses": {"callback_slot_guest_linear": hex(slot), "callback_guest_linear": hex(cb),
                      "descriptor_link_va": "0x103554", "descriptor_guest_linear": hex(desc),
                      "descriptor_ascii": "*B_SCREEN", "slot_before": hex(callback_target),
                      "slot_after_expected": hex(callback_loaded)},
        "limitations": [
            "The full FUN_00014BF0 config.ini parsing path was not run in this isolated test.",
            "The authentic callback '*' branch is exercised; its non-wildcard path requires config-initialized path buffers.",
            "The complete FUN_000989EC allocator bootstrap and allocation tail are outside this slice; no allocator result is fabricated.",
            "No file is opened or read yet; the non-wildcard data/iftitle.anb path and DOS VFS remain the next integration boundary.",
            "The experiment does not claim the callback target was observed in an Oracle runtime capture."
        ],
        "build": {"compile_exit": compile_result.returncode, "run_exit": run_result.returncode,
                  "stdout": run_result.stdout.strip(),
                  "generated_c_sha256": hashlib.sha256(generated.read_bytes()).hexdigest(),
                  "test_executable_sha256": hashlib.sha256(exe.read_bytes()).hexdigest()},
        "passed": True
    }
    (ROOT / "evidence" / "authentic_resource_callback_init_isolated.json").write_text(
        json.dumps(receipt, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
