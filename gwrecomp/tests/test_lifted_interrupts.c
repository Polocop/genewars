#include "recomp_context.h"
#include "gw_interrupts.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void gw_entry_start(void);
#ifndef GW_FULL_CLOSURE_LINK
static int unexpected_call;
void sub_000C871C(void) { unexpected_call = 1; }
void sub_000C86CD(void) { unexpected_call = 1; }
void sub_000C8767(void) { unexpected_call = 1; }
#else
uint32_t g_icall_trace[ICALL_TRACE_SIZE], g_icall_from[ICALL_TRACE_SIZE];
uint32_t g_icall_trace_idx, g_icall_count;
recomp_func_t recomp_lookup(uint32_t va) { (void)va; return NULL; }
recomp_func_t recomp_lookup_manual(uint32_t va) { (void)va; return NULL; }
recomp_func_t recomp_lookup_import(uint32_t va) { (void)va; return NULL; }
#endif

uint32_t g_eax, g_ebx, g_ecx, g_edx, g_esi, g_edi, g_ebp, g_esp;
uint16_t g_seg_cs, g_seg_ds, g_seg_es, g_seg_fs, g_seg_gs, g_seg_ss;
double g_st[8];
int g_fp_top;
uint16_t g_fpu_cw;
uint32_t g_cur_func, g_fs_base, g_gs_base;
ptrdiff_t g_mem_base;

static uint8_t guest_memory[0x200000];
static int callback_seen;

static gw_interrupt_result inspect_interrupt(uint8_t vector, uint32_t va, void *user) {
    (void)user;
    if (vector != 0x21 || va != 0x000AFA09u || g_cur_func != 0x000AF96Cu ||
        g_eax != 0x00003000u || g_esp != 0x00080000u) {
        fprintf(stderr, "bad live INT state: vector=%02x va=%08x fn=%08x eax=%08x esp=%08x\n",
                vector, va, g_cur_func, g_eax, g_esp);
        return GW_INTERRUPT_TRAPPED;
    }
    callback_seen = 1;
    return GW_INTERRUPT_TRAPPED;
}

int main(void) {
    memset(guest_memory, 0, sizeof guest_memory);
    /* The first INT must stop execution before the following MOV stores AL. */
    guest_memory[0x10B797] = 0xA5;
    gw_recomp_context context;
    memset(&context, 0, sizeof context);
    context.eax = 0xFFFFFFFFu;
    context.ebx = 0x12345678u;
    context.esp = 0x00080000u;
    context.cs = context.ds = context.es = context.ss = 0x20;
    context.mem_base = (ptrdiff_t)(uintptr_t)guest_memory;
    g_mem_base = context.mem_base;
    gw_interrupt_set_callback(inspect_interrupt, NULL);
    if (gw_recomp_invoke(gw_entry_start, &context) != GW_RECOMP_OK) return 2;
    gw_interrupt_set_callback(NULL, NULL);
    if (!callback_seen) return 3;
    if (!context.interrupt_trap_pending || context.interrupt_vector != 0x21 ||
        context.interrupt_instruction_va != 0x000AFA09u ||
        context.interrupt_function_va != 0x000AF96Cu) {
        fprintf(stderr, "trap capture mismatch: pending=%u vector=%02x va=%08x fn=%08x\n",
                context.interrupt_trap_pending, context.interrupt_vector,
                context.interrupt_instruction_va, context.interrupt_function_va);
        return 4;
    }
    if (context.eax != 0x00003000u || context.esp != 0x00080000u) return 5;
    if (guest_memory[0x10B797] != 0xA5) return 6;
#ifndef GW_FULL_CLOSURE_LINK
    if (unexpected_call) return 7;
#endif
    puts("PASS callback live CPU state, precise trap capture, and stop-before-fallthrough");
    return 0;
}
