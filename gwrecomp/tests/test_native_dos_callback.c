#include "recomp_context.h"
#include "gw_dos_services.h"
#include "gw_interrupts.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

void gw_entry_start(void);
#ifndef GW_FULL_CLOSURE_LINK
void sub_000C871C(void) {}
void sub_000C86CD(void) {}
void sub_000C8767(void) {}
#endif

uint32_t g_eax, g_ebx, g_ecx, g_edx, g_esi, g_edi, g_ebp, g_esp;
uint16_t g_seg_cs, g_seg_ds, g_seg_es, g_seg_fs, g_seg_gs, g_seg_ss;
double g_st[8];
int g_fp_top;
uint16_t g_fpu_cw;
uint32_t g_cur_func, g_fs_base, g_gs_base;
ptrdiff_t g_mem_base;

static uint8_t guest_memory[0x200000];
typedef struct native_dos_host {
    gw_dos_services services;
} native_dos_host;

int main(void) {
    memset(guest_memory, 0, sizeof guest_memory);
    memset(guest_memory + 0x10B797, 0xA5, 2);
    native_dos_host host;
    memset(&host, 0, sizeof host);
    host.services.major = 6;
    host.services.minor = 22;
    gw_recomp_context context;
    g_eax = 0xABCD3000u;
    g_flag_cf = 1;
    if (gw_dos_services_callback(0x21u, 0x000AFA09u, &host.services) != GW_INTERRUPT_HANDLED ||
        g_eax != 0xABCD1606u || g_flag_cf != 0u) {
        fprintf(stderr, "direct AH=30h register/CF contract failed eax=%08x cf=%u\n",
                (unsigned)g_eax, (unsigned)g_flag_cf);
        return 2;
    }
    g_eax = 0x1234ff00u; g_edx = 0xabcd0078u; g_flag_cf = 1;
    if (gw_dos_services_callback(0x21u, 0x000AFAA8u, &host.services) != GW_INTERRUPT_HANDLED ||
        g_eax != 0x1234ffffu || g_edx != 0xabcd0078u || g_flag_cf != 0u) {
        fprintf(stderr, "DOS/4G install check contract failed\n");
        return 3;
    }
    g_eax = 0xff00u; g_edx = 0x79u;
    if (gw_dos_services_callback(0x21u, 0x000AFAA8u, &host.services) != GW_INTERRUPT_TRAPPED) {
        fprintf(stderr, "DOS/4G mismatched signature was handled\n");
        return 4;
    }
    g_seg_ds = 0x14; g_ds_base = 0x12345678u;
    g_eax = 0xabcd0006u; g_ebx = 0x11110014u;
    g_ecx = 0xaaaa0000u; g_edx = 0xbbbb0000u; g_flag_cf = 1;
    if (gw_dos_services_callback(0x31u, 0x000AFAC4u, &host.services) != GW_INTERRUPT_HANDLED ||
        g_ecx != 0xaaaa1234u || g_edx != 0xbbbb5678u || g_flag_cf != 0u) {
        fprintf(stderr, "DPMI segment base success contract failed\n");
        return 5;
    }
    g_eax = 0xabcd0006u; g_ebx = 0x11110033u;
    if (gw_dos_services_callback(0x31u, 0x000AFAC4u, &host.services) != GW_INTERRUPT_HANDLED ||
        (uint16_t)g_eax != 0x8022u || g_flag_cf != 1u) {
        fprintf(stderr, "DPMI invalid selector contract failed\n");
        return 6;
    }
    gw_dos_services_init(&host.services);

    memset(&context, 0, sizeof context);
    context.eax = 0xffffffffu;
    context.esp = 0x00080000u;
    context.cs = 0x000c;
    context.ds = context.es = context.ss = 0x0014;
    context.mem_base = (ptrdiff_t)(uintptr_t)guest_memory;
    if (gw_recomp_invoke(gw_entry_start, &context) != GW_RECOMP_OK) return 7;
    gw_interrupt_set_callback(0, 0);

    if (guest_memory[0x10B797] != 6 || guest_memory[0x10B798] != 22) {
        fprintf(stderr, "real entry did not consume DOS version result: %u.%u\n",
                guest_memory[0x10B797], guest_memory[0x10B798]);
        return 8;
    }
    if (!context.interrupt_trap_pending || context.interrupt_vector != 0x21u ||
        context.interrupt_instruction_va != 0x000AFC33u ||
        context.interrupt_function_va != 0x000AF96Cu) {
        fprintf(stderr, "bad next trap pending=%u vector=%02x va=%08x fn=%08x segfault=%u selector=%04x seg=%u ins=%08x\n",
                context.interrupt_trap_pending, context.interrupt_vector,
                context.interrupt_instruction_va, context.interrupt_function_va,
                context.segment_fault_pending, context.segment_fault_selector,
                context.segment_fault_id, context.segment_fault_instruction_va);
        return 9;
    }
    if (context.eax == 0x00003000u || guest_memory[0x10B797] == 0xA5) {
        fprintf(stderr, "guest failed to execute instructions after AH=30h\n");
        return 10;
    }
    if ((uint16_t)context.eax != 0x4c00u) {
        fprintf(stderr, "expected next AH=4Ch terminal trap, eax=%08x\n", context.eax);
        return 11;
    }
    printf("PASS native DOS/DPMI AH=30h+FF00+0006; next vector=%02x INT at %08x\n",
           context.interrupt_vector, context.interrupt_instruction_va);
    return 0;
}
