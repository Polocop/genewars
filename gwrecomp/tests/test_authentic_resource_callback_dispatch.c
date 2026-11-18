#define RECOMP_GENERATED_CODE
#define RECOMP_LOCAL_REGS
#include "recomp_types.h"
#include "gw_recomp_stop.h"
#include "recomp_context.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void recomp_gw_partial_nullsub_4(void);
void recomp_gw_partial_null_int23_exit(void);
int gw_partial_install_code_map(void);

uint32_t g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,g_cur_func;
uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_fs,g_seg_gs,g_seg_ss,g_fpu_cw;
uint32_t g_fs_base,g_gs_base;
ptrdiff_t g_mem_base;
double g_st[8]; int g_fp_top;
uint32_t g_icall_trace[ICALL_TRACE_SIZE],g_icall_from[ICALL_TRACE_SIZE];
uint32_t g_icall_trace_idx,g_icall_count;

recomp_func_t recomp_lookup_manual(uint32_t va) { (void)va; return NULL; }
recomp_func_t recomp_lookup_import(uint32_t va) { (void)va; return NULL; }
recomp_func_t recomp_lookup(uint32_t va) {
    if (va==0x989E8u) return recomp_gw_partial_nullsub_4;
    if (va==0x98C18u) return recomp_gw_partial_null_int23_exit;
    return NULL;
}
static int resolve_stack_selector(uint16_t selector,uint32_t *base,void *user) {
    (void)user;
    if (selector!=0x14u || !base) return 0;
    *base=0; return 1;
}

static void callback_parent(void) {
    RECOMP_REGS_LOCALS
    uint32_t _cf=0,_flag_a=0,_flag_b=0,_flag_k=FK_NONE;
    RECOMP_ENTER(0x00092710u);
    RECOMP_ICALL(0x002839E8u);
    RECOMP_ICALL(0x00283C18u);
    RECOMP_REGS_OUT();
}

int main(void) {
    uint32_t link_va=0;
    uint8_t *memory=(uint8_t *)calloc(0x10000u,1u);
    if (!memory || !gw_partial_install_code_map() ||
        !recomp_code_linear_to_link(0x002839E8u,&link_va) || link_va!=0x989E8u ||
        !recomp_code_linear_to_link(0x00283C18u,&link_va) || link_va!=0x98C18u ||
        recomp_code_linear_to_link(0x000F0000u,&link_va)) return 2;

    gw_recomp_context context; memset(&context,0,sizeof context);
    context.eax=0x4C454649u; context.ebx=0x12345678u;
    context.esp=0xF000u; context.eip=0x92710u; context.cur_func=0x92710u;
    context.ss=0x14u;
    context.mem_base=(ptrdiff_t)(uintptr_t)memory;
    context.mem_guest_base=0; context.mem_size=0x10000u;
    recomp_set_segment_resolver(resolve_stack_selector,0);
    if (gw_recomp_invoke(callback_parent,&context)!=GW_RECOMP_OK ||
        context.interrupt_trap_pending || context.memory_fault.pending ||
        context.segment_fault_pending || context.eax!=0x4C454649u ||
        context.ebx!=0x12345678u || context.esp!=0xF000u ||
        context.cur_func!=0x92710u || g_icall_count!=2u ||
        g_icall_trace[0]!=0x2839E8u || g_icall_trace[1]!=0x283C18u) {
        fprintf(stderr,"rebiased original resource callback dispatch failed eax=%08x esp=%08x cur=%08x icalls=%u targets=%08x,%08x stack=%08x fault=%u\n",
                context.eax,context.esp,context.cur_func,g_icall_count,
                g_icall_trace[0],g_icall_trace[1],*(uint32_t *)(memory+0xEFFCu),
                context.memory_fault.pending);
        free(memory); return 3;
    }
    puts("PASS original 1.1 callback stubs reached through fixup-backed guest-linear ICALL dispatch");
    free(memory);
    return 0;
}
