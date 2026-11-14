#include "recomp_context.h"
#include "gw_interrupts.h"
#include "gw_segments.h"
#include <stdio.h>
#include <string.h>

void gw_segment_probe(void);
uint32_t g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,g_cur_func;
uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_fs,g_seg_gs,g_seg_ss,g_fpu_cw;
uint32_t g_fs_base,g_gs_base;
ptrdiff_t g_mem_base;
double g_st[8]; int g_fp_top;
/* The focused lift is linked with the real call wrapper, which references the
 * normal indirect-call trace/lookup ABI even though these two instructions do
 * not make an indirect call. Keep the harness complete and fail closed. */
uint32_t g_icall_trace[ICALL_TRACE_SIZE], g_icall_from[ICALL_TRACE_SIZE];
uint32_t g_icall_trace_idx, g_icall_count;
recomp_func_t recomp_lookup_manual(uint32_t va) { (void)va; return NULL; }
recomp_func_t recomp_lookup(uint32_t va) { (void)va; return NULL; }
recomp_func_t recomp_lookup_import(uint32_t va) { (void)va; return NULL; }
static uint8_t guest_memory[0x400000];

static int resolve(uint16_t selector, uint32_t *base, void *user) {
    (void)user;
    if (selector == 0x24) { *base = 0x2DA000; return 1; }
    if (selector == 0x14 || selector == 0x0c) { *base = 0; return 1; }
    return 0;
}

static gw_recomp_context state(void) {
    gw_recomp_context c;
    memset(&c, 0, sizeof c);
    c.eax=0x12345678; c.ebx=0xDEADBEEF; c.esp=0x80000;
    c.ds=0x14; c.es=0x14; c.ss=0x14;
    c.mem_base=(ptrdiff_t)(uintptr_t)guest_memory;
    *(uint32_t *)(guest_memory + c.esp) = RECOMP_RETADDR;
    return c;
}

int main(void) {
    memset(guest_memory, 0, sizeof guest_memory);
    *(uint16_t *)(guest_memory + 0x2E576C) = 0x24;
    *(uint32_t *)(guest_memory + 0x2DA05C) = 0xC0DEC0DE;
    recomp_set_segment_resolver(resolve, NULL);
    gw_recomp_context c = state();
    if (gw_recomp_invoke(gw_segment_probe, &c) != GW_RECOMP_OK) return 1;
    if (c.es != 0x24 || c.es_base != 0x2DA000 || c.ebx != 0xC0DEC0DE) return 2;
    if (c.segment_fault_pending) return 3;
    if (g_icall_count != 0) return 7;

    *(uint16_t *)(guest_memory + 0x2E576C) = 0x99;
    c = state();
    if (gw_recomp_invoke(gw_segment_probe, &c) != GW_RECOMP_OK) return 4;
    if (!c.segment_fault_pending || c.segment_fault_id != RECOMP_SEG_ES ||
        c.segment_fault_selector != 0x99 || c.segment_fault_instruction_va != 0x000AFA30u) return 5;
    if (c.ebx != 0xDEADBEEF || c.es != 0x14) return 6;
    if (g_icall_count != 0) return 8;
    puts("PASS ES selector base, ES:[0x5c], precise unresolved selector fault");
    return 0;
}
