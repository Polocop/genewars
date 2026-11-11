"""Focused W1-091 checks for backed DPMI memory and allocator bounds."""
import os
import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
DPmi_BACKING_TEST = r'''#include "gw_dos_services.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
uint32_t g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,g_cur_func;
uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_ss,g_seg_fs,g_seg_gs;
uint32_t g_fs_base,g_gs_base;
ptrdiff_t g_mem_base;
uint32_t g_flag_k,g_flag_a,g_flag_b,g_flag_cf;
static int request(gw_dos_services *s,uint32_t n) {
    g_eax=0xabcd0501u; g_ebx=0x12340000u|((n>>16)&0xffffu);
    g_ecx=0x56780000u|(n&0xffffu); g_esi=0x9abc1111u; g_edi=0xdef02222u; g_flag_cf=0;
    return gw_dos_services_callback(0x31u,0x000c3cc1u,s)==GW_INTERRUPT_HANDLED;
}
int main(void) {
    gw_dos_services s; memset(&s,0,sizeof s);
    uint8_t *memory=(uint8_t *)calloc(0x0220b000u,1u);
    if (!memory) return 7;
    g_mem_base=(ptrdiff_t)(uintptr_t)memory;
    if (!gw_dos_linear_allocator_configure(&s,0x00209000u,0x0220b000u)) return 1;
    if (!request(&s,0x01001000u) || !g_flag_cf || (g_eax&0xffffu)!=0x8012u || s.allocation_cursor!=0x00209000u) return 2;
    if (!gw_dos_guest_memory_configure(&s,0x0220b000u) || !gw_dos_linear_allocator_configure(&s,0x00209000u,0x0220b000u)) return 3;
    memset(memory+0x00209000u,0xa5u,0x01001000u);
    if (!request(&s,0x01001000u) || g_flag_cf || (g_eax&0xffffu)!=0x0501u || (g_ebx&0xffffu)!=0x0020u || (g_ecx&0xffffu)!=0x9000u || (g_esi&0xffffu)!=0 || (g_edi&0xffffu)!=1u || s.allocation_cursor!=0x0120a000u) return 4;
    if (memory[0x00209000u]!=0 || memory[0x01209fffu]!=0) return 8;
    memset(memory+0x0120a000u,0xa5u,0x01001000u);
    if (!request(&s,0x01001000u) || g_flag_cf || (g_ebx&0xffffu)!=0x0120u || (g_ecx&0xffffu)!=0xa000u || (g_esi&0xffffu)!=0 || (g_edi&0xffffu)!=2u || s.allocation_cursor!=0x0220b000u) return 5;
    if (memory[0x0120a000u]!=0 || memory[0x0220afffu]!=0) return 9;
    if (!request(&s,0x1000u) || !g_flag_cf || (g_eax&0xffffu)!=0x8012u || s.allocation_cursor!=0x0220b000u) return 6;
    puts("PASS: AX=0501 requires backed guest memory, advances generic cursor/handles, and fails closed at map end");
    free(memory);
    return 0;
}
'''


class W1091GuestLinearMemoryTests(unittest.TestCase):
    def test_capacity_is_exactly_derived_from_two_natural_requests(self):
        image_end = 0x001B2000
        allocation_begin = 0x00200000
        cursor = 0x00209000
        sizes = (0x01001000, 0x01001000)
        self.assertLessEqual(image_end, allocation_begin)
        self.assertEqual(cursor % 0x1000, 0)
        self.assertEqual(cursor + sizes[0], 0x0120A000)
        self.assertEqual(cursor + sizes[0] + sizes[1], 0x0220B000)

    def test_runtime_rejects_ax0501_without_backing(self):
        cache = ROOT / "cache"
        cache.mkdir(exist_ok=True)
        source = cache / "test_w1_091_dpmi_backing.c"
        source.write_text(DPmi_BACKING_TEST, encoding="utf-8")
        executable = ROOT / "build" / "test_native_dpmi_alloc.exe"
        env = {
            **os.environ,
            "TEMP": str(cache), "TMP": str(cache), "TMPDIR": str(cache),
            "PATH": r"E:\msys64\mingw32\bin;E:\msys64\usr\bin;" + os.environ.get("PATH", ""),
        }
        gcc = r"E:\msys64\mingw32\bin\gcc.exe"
        completed = subprocess.run(
            [gcc, "-std=gnu11", "-m32", "-O0", "-I", str(ROOT / "runtime"),
             "-I", str(ROOT / "third_party" / "pcrecomp" / "runtime" / "recomp32"),
             "-o", str(executable), str(source),
             str(ROOT / "runtime" / "gw_segments.c"), str(ROOT / "runtime" / "gw_interrupts.c"),
             str(ROOT / "runtime" / "gw_dos_services.c")],
            cwd=ROOT, env=env, text=True, capture_output=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        completed = subprocess.run([str(executable)], cwd=ROOT, env=env,
                                   text=True, capture_output=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

    def test_replay_and_validator_expose_w1_091_mode(self):
        driver = (ROOT / "tests" / "test_native_guest_image.py").read_text(encoding="utf-8")
        harness = (ROOT / "tests" / "test_native_guest_image.c").read_text(encoding="utf-8")
        runtime = (ROOT / "runtime" / "gw_dos_services.c").read_text(encoding="utf-8")
        self.assertIn("--w1-091-host-backed-guest-memory", driver)
        self.assertIn("GW_NATIVE_W1_091_HOST_BACKED_GUEST_MEMORY", driver)
        self.assertIn("static uint8_t guest_memory[0x0220B000u]", harness)
        self.assertIn("NATIVE_DPMI_GUEST_MEMORY_MAP", harness)
        self.assertIn("services->guest_memory_size", runtime)


if __name__ == "__main__":
    unittest.main()
