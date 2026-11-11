#include "recomp_context.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void gw_partial_LbScreenSetGraphicsWindow(void);
int gw_partial_install_code_map(void);
int recomp_code_linear_to_link(uint32_t guest_linear,uint32_t *link_va);

uint32_t g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,g_cur_func;
uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_fs,g_seg_gs,g_seg_ss,g_fpu_cw;
uint32_t g_fs_base,g_gs_base;
ptrdiff_t g_mem_base;
double g_st[8]; int g_fp_top;
uint32_t g_icall_trace[ICALL_TRACE_SIZE], g_icall_from[ICALL_TRACE_SIZE];
uint32_t g_icall_trace_idx, g_icall_count;

recomp_func_t recomp_lookup_manual(uint32_t va) { (void)va; return NULL; }
recomp_func_t recomp_lookup(uint32_t va) { (void)va; return NULL; }
recomp_func_t recomp_lookup_import(uint32_t va) { (void)va; return NULL; }

enum { GUEST_SIZE=0x400000, STACK_TOP=0x3FF000, SCREEN_WIDTH=640, SCREEN_HEIGHT=480 };
enum { BASE_PTR=0x376A5C, WIDTH=0x376A78, HEIGHT=0x376A7C,
       WIN_X=0x376A80, WIN_Y=0x376A84, WIN_W=0x376A88, WIN_H=0x376A8C,
       DRAW_PTR=0x376A68, FB=0x390000 };

int main(void) {
    uint32_t link_va=0;
    if (!gw_partial_install_code_map() ||
        !recomp_code_linear_to_link(0x002839E8u,&link_va) || link_va!=0x000989E8u ||
        recomp_code_linear_to_link(0x000F0000u,&link_va)) {
        fprintf(stderr,"verified partial-code pointer map is inconsistent\n"); return 9;
    }
    uint8_t *memory=(uint8_t *)calloc(GUEST_SIZE,1);
    if (!memory) return 2;
    *(uint32_t *)(memory+BASE_PTR)=FB;
    *(uint32_t *)(memory+WIDTH)=SCREEN_WIDTH;
    *(uint32_t *)(memory+HEIGHT)=SCREEN_HEIGHT;

    gw_recomp_context c; memset(&c,0,sizeof c);
    c.eax=10; c.ebx=100; c.ecx=50; c.edx=20;
    c.esp=STACK_TOP; c.eip=0x96338u; c.cs=0x0C; c.ds=0x14; c.ss=0x14;
    c.mem_base=(ptrdiff_t)(uintptr_t)memory;
    c.mem_guest_base=0; c.mem_size=GUEST_SIZE;
    *(uint32_t *)(memory+STACK_TOP)=RECOMP_RETADDR;

    if (gw_recomp_invoke(gw_partial_LbScreenSetGraphicsWindow,&c)!=GW_RECOMP_OK) return 3;
    if (c.interrupt_trap_pending || c.segment_fault_pending || c.memory_fault.pending) return 4;
    if (*(uint32_t *)(memory+WIN_X)!=10 || *(uint32_t *)(memory+WIN_Y)!=20 ||
        *(uint32_t *)(memory+WIN_W)!=100 || *(uint32_t *)(memory+WIN_H)!=50) return 5;
    if (*(uint32_t *)(memory+DRAW_PTR)!=FB+20*SCREEN_WIDTH+10) return 6;
    if (c.eax!=1 || c.ecx!=10 || c.edx!=100 || c.ebx!=50 ||
        c.esp!=STACK_TOP+4 || c.eip!=0x96338u || c.cur_func!=0x96338u) return 7;
    if (c.esi!=0 || c.edi!=0 || c.ebp!=0) return 8;
    printf("PASS authentic LbScreenSetGraphicsWindow_: window=(%u,%u %ux%u), draw_ptr=0x%08X, EIP=0x%08X\n",
           *(uint32_t *)(memory+WIN_X),*(uint32_t *)(memory+WIN_Y),
           *(uint32_t *)(memory+WIN_W),*(uint32_t *)(memory+WIN_H),
           *(uint32_t *)(memory+DRAW_PTR),c.eip);
    free(memory);
    return 0;
}
