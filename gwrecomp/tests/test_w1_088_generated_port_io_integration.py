"""Compile current lifter output against the real per-context PIT Runtime."""
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import unittest

from capstone import CS_ARCH_X86, CS_MODE_32, Cs

ROOT = pathlib.Path(__file__).resolve().parents[1]
RECOVERY = ROOT / "work" / "recovery" / "W1-088"
LIFT_DIR = ROOT / "third_party" / "pcrecomp" / "tools" / "lift"
sys.path.insert(0, str(LIFT_DIR))
from lift32 import Lifter  # noqa: E402


def lift_sequence(name, address, raw):
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True
    instructions = list(decoder.disasm(raw, address))
    if not instructions or instructions[-1].mnemonic != "ret":
        raise AssertionError("synthetic sequence must end with RET")
    if sum(insn.size for insn in instructions) != len(raw):
        raise AssertionError("Capstone did not decode the complete synthetic sequence")
    lifter = Lifter()
    body = [
        f"void {name}(void) {{",
        "    int _fpu_cmp = 0; (void)_fpu_cmp;",
        "    uint32_t _cf = 0; int _df = 1; (void)_df;",
        "    uint32_t _flag_a = 0, _flag_b = 0, _flag_k = FK_NONE;",
        f"    RECOMP_ENTER(0x{address:08X}u);",
    ]
    for insn in instructions:
        body.extend("    " + line for line in lifter.lift_instruction(insn))
    body.append("}")
    return "\n".join(body)


HARNESS = r'''#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "recomp_context.h"

uint32_t g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,g_cur_func;
uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_fs,g_seg_gs,g_seg_ss,g_fpu_cw;
uint32_t g_fs_base,g_gs_base;
uint32_t g_flag_k,g_flag_a,g_flag_b,g_flag_cf;
ptrdiff_t g_mem_base;
double g_st[8];
int g_fp_top;

void gw_synth_supported_io(void);
void gw_synth_unsupported_io(void);

static void init(gw_recomp_context *c, uint32_t eax) {
    memset(c, 0, sizeof(*c));
    c->eax=eax; c->flag_k=FK_NONE; c->fpu_cw=0x037fu;
}

int main(void) {
    gw_recomp_context supported, unsupported;
    init(&supported, 0xABCD0034u);
    if (gw_recomp_invoke(gw_synth_supported_io, &supported) != GW_RECOMP_OK) return 1;
    if (supported.pit.virtual_cycles != 6u || supported.pit.control_word != 0x34u ||
        supported.pit.write_low[0] != 0x34u || supported.pit.reload[0] != 0x1234u ||
        supported.eax != 0xABCD0033u || supported.port_io_trap.pending) return 2;

    init(&unsupported, 0x12345678u);
    if (gw_recomp_invoke(gw_synth_unsupported_io, &unsupported) != GW_RECOMP_OK) return 3;
    if (unsupported.pit.virtual_cycles != 1u || unsupported.eax != 0x12345678u ||
        !unsupported.port_io_trap.pending ||
        unsupported.port_io_trap.reason != GW_PORT_IO_TRAP_UNSUPPORTED_IO ||
        unsupported.port_io_trap.operation != 0u || unsupported.port_io_trap.port != 0x80u ||
        unsupported.port_io_trap.guest_va != 0x000C4290u) return 4;
    puts("PASS generated lifter -> recomp_context -> PIT, unsupported I/O traps");
    return 0;
}
'''


class GeneratedPortIORuntimeIntegration(unittest.TestCase):
    def test_generated_scalar_io_executes_against_pit_runtime(self):
        RECOVERY.mkdir(parents=True, exist_ok=True)
        scratch = RECOVERY / "generated-port-io"
        scratch.mkdir(parents=True, exist_ok=True)
        evidence_path = ROOT / "evidence" / "native_port_io_integration_w1_088.json"
        target_path = ROOT / "evidence" / "genewars-1_1.exe"
        target_hash = hashlib.sha256(target_path.read_bytes()).hexdigest()
        self.assertEqual(target_hash, "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f")

        supported = lift_sequence(
            "gw_synth_supported_io", 0x000C427A,
            bytes((0xE6, 0x43, 0xE6, 0x40, 0xB0, 0x12, 0xE6, 0x40, 0xE4, 0x40, 0xC3)),
        )
        unsupported = lift_sequence(
            "gw_synth_unsupported_io", 0x000C4290,
            bytes((0xE4, 0x80, 0xC3)),
        )
        generated = (
            '#define RECOMP_GENERATED_CODE\n#include "recomp_context.h"\n'
            + supported + "\n" + unsupported + "\n"
        )
        self.assertIn("gw_recomp_guest_instruction(0x000C427Au)", generated)
        self.assertIn("gw_recomp_port_io(1u", generated)
        self.assertIn("gw_recomp_port_io(0u", generated)

        generated_path = scratch / "generated_port_io.c"
        harness_path = scratch / "harness.c"
        executable = scratch / "generated_port_io.exe"
        generated_path.write_text(generated, encoding="utf-8")
        harness_path.write_text(HARNESS, encoding="utf-8")
        temp = scratch / "tmp"
        temp.mkdir(exist_ok=True)
        env = {
            **os.environ,
            "PYTHONDONTWRITEBYTECODE": "1",
            "TEMP": str(temp), "TMP": str(temp), "TMPDIR": str(temp),
            "PATH": r"E:\msys64\mingw32\bin;E:\msys64\usr\bin;" + os.environ.get("PATH", ""),
        }
        gcc = pathlib.Path(r"E:\msys64\mingw32\bin\gcc.exe")
        command = [
            str(gcc), "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-m32", "-O0",
            "-I", str(ROOT / "runtime"),
            "-I", str(ROOT / "third_party" / "pcrecomp" / "runtime" / "recomp32"),
            "-o", str(executable), str(harness_path), str(generated_path),
            str(ROOT / "runtime" / "recomp_context.c"),
            str(ROOT / "runtime" / "gw_interrupts.c"),
            str(ROOT / "runtime" / "gw_segments.c"),
            str(ROOT / "runtime" / "gw_pit8254.c"),
        ]
        built = subprocess.run(command, cwd=scratch, env=env, text=True, capture_output=True)
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        run = subprocess.run([str(executable)], cwd=scratch, env=env, text=True, capture_output=True)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

        evidence = {
            "task": "W1-088",
            "execution_kind": "SYNTHETIC_PASS",
            "target_sha256": target_hash,
            "synthetic_instructions": ["OUT 0x43,AL", "OUT 0x40,AL", "MOV AL,0x12", "OUT 0x40,AL", "IN AL,0x40", "RET"],
            "native_binary_executed": False,
            "generated_callbacks": ["gw_recomp_guest_instruction", "gw_recomp_port_io"],
            "runtime_sources": ["runtime/recomp_context.c", "runtime/gw_pit8254.c"],
            "compile_command": command,
            "compile_exit": built.returncode,
            "run_exit": run.returncode,
            "stdout": run.stdout,
            "stderr": run.stderr,
            "assertions": ["six deterministic instruction ticks", "PIT control/write/reload state", "AL read preserves upper EAX", "unsupported port traps at guest VA 0x000C4290"],
            "passed": True,
        }
        evidence_path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
