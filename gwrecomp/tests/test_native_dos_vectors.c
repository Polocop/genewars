#include "recomp_context.h"
#include "gw_dos_services.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

uint32_t g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp;
uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_fs,g_seg_gs,g_seg_ss;
double g_st[8]; int g_fp_top; uint16_t g_fpu_cw; uint32_t g_cur_func,g_fs_base,g_gs_base;
ptrdiff_t g_mem_base;
static int check(int ok,const char *text) { if (!ok) fprintf(stderr,"FAIL: %s\n",text); return ok; }

int main(void) {
    gw_dos_services host_a={0},host_b={0};
    gw_dos_services_init(&host_a); gw_dos_services_init(&host_b);
    g_eax=0xaaaa3508u; g_ebx=0xbbbb1234u; g_seg_es=0x7777; g_flag_cf=1;
    if (!check(gw_dos_services_callback(0x21,0x1000,&host_a)==GW_INTERRUPT_HANDLED,"get unassigned vector") ||
        !check(g_seg_es==0 && g_ebx==0xbbbb0000u && !g_flag_cf,"unassigned vector zero/CF/upper BX")) return 2;

    g_seg_ds=0x1234; g_eax=0xcccc2508u; g_edx=0xdeadbeefu; g_flag_cf=1;
    if (!check(gw_dos_services_callback(0x21,0x1001,&host_a)==GW_INTERRUPT_HANDLED && !g_flag_cf,
               "set interrupt vector")) return 3;
    g_eax=0xaaaa3508u; g_ebx=0xbbbb1111u; g_seg_es=0x7777; g_flag_cf=1;
    if (!check(gw_dos_services_callback(0x21,0x1002,&host_a)==GW_INTERRUPT_HANDLED,"get configured vector") ||
        !check(g_seg_es==0x1234 && g_ebx==0xbbbbbeefu && !g_flag_cf,"roundtrip ES:BX and carry")) return 4;

    g_eax=0x3508u; g_ebx=0xaaaa5555u; g_seg_es=0x7777; g_flag_cf=1;
    if (!check(gw_dos_services_callback(0x21,0x1003,&host_b)==GW_INTERRUPT_HANDLED &&
               g_seg_es==0 && g_ebx==0xaaaa0000u && !g_flag_cf,"per-host vector isolation")) return 5;
    g_eax=0xabcd4400u;
    if (!check(gw_dos_services_callback(0x21,0x1004,&host_a)==GW_INTERRUPT_TRAPPED,
               "unknown DOS service remains trapped")) return 6;
    gw_dos_descriptor_clear(&host_a); gw_dos_descriptor_clear(&host_b);
    puts("PASS native DOS AH=35/25 vectors, register halves, carry and host isolation");
    return 0;
}
