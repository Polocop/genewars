#include "recomp_context.h"
#include "gw_dos_services.h"
#include "gw_interrupts.h"
#include <stdint.h>
#include <stdio.h>

uint32_t g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp;
uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_fs,g_seg_gs,g_seg_ss;
double g_st[8]; int g_fp_top; uint16_t g_fpu_cw; uint32_t g_cur_func,g_fs_base,g_gs_base;
ptrdiff_t g_mem_base;

static int check(int ok, const char *name) {
    if (!ok) fprintf(stderr,"FAIL: %s\n",name);
    return ok;
}

int main(void) {
    gw_dos_services host={0};
    gw_dos_services_init(&host);
    gw_dos_real_mode_vector_configure(&host,8,0x1234u,0x5678u);

    g_eax=0xBEEF0200u; g_ebx=0x12340008u; g_ecx=0xAABB0000u;
    g_edx=0xDEADBEEFu; g_esi=0x13572468u; g_edi=0x24681357u;
    g_ebp=0x89ABCDEFu; g_esp=0x10203040u;
    g_seg_cs=0x1111u; g_seg_ds=0x2222u; g_seg_es=0x3333u;
    g_seg_fs=0x4444u; g_seg_gs=0x5555u; g_seg_ss=0x6666u; g_flag_cf=1;
    if (!check(gw_dos_services_callback(0x31u,0xC8CD2u,&host)==GW_INTERRUPT_HANDLED,
               "configured AX=0200 handled") ||
        !check(g_eax==0xBEEF0200u && g_ebx==0x12340008u,"EAX and EBX preserved") ||
        !check(g_ecx==0xAABB1234u && g_edx==0xDEAD5678u,"CX:DX real-mode vector returned") ||
        !check(g_esi==0x13572468u && g_edi==0x24681357u && g_ebp==0x89ABCDEFu &&
               g_esp==0x10203040u,"other general registers preserved") ||
        !check(g_seg_cs==0x1111u && g_seg_ds==0x2222u && g_seg_es==0x3333u &&
               g_seg_fs==0x4444u && g_seg_gs==0x5555u && g_seg_ss==0x6666u,
               "segment registers preserved") ||
        !check(g_flag_cf==0,"success clears carry")) return 2;

    g_eax=0xCAFE0200u; g_ebx=0xABCD0009u; g_ecx=0x87650001u;
    g_edx=0xFFFFFFFFu; g_flag_cf=1;
    if (!check(gw_dos_services_callback(0x31u,0xC8CD2u,&host)==GW_INTERRUPT_HANDLED,
               "unconfigured AX=0200 handled") ||
        !check(g_ecx==0x87650000u && g_edx==0xFFFF0000u,
               "unconfigured vector is empty pair and preserves high EDX") ||
        !check(g_eax==0xCAFE0200u && g_ebx==0xABCD0009u && !g_flag_cf,
               "unconfigured result preserves request and clears carry")) return 3;

    g_eax=0xBEEF0201u; g_ebx=0xABCD0033u;
    g_ecx=0xAAAA000Cu; g_edx=0xBBBB1E74u; g_flag_cf=1;
    if (!check(gw_dos_services_callback(0x31u,0xC8DC1u,&host)==GW_INTERRUPT_HANDLED,
               "AX=0201 stores a real-mode interrupt vector") ||
        !check(g_eax==0xBEEF0201u && g_ebx==0xABCD0033u &&
               g_ecx==0xAAAA000Cu && g_edx==0xBBBB1E74u && !g_flag_cf,
               "AX=0201 preserves request registers and clears carry")) return 6;
    g_eax=0xCAFE0200u; g_ebx=0xABCD0033u;
    g_ecx=0x87650000u; g_edx=0xFFFF0000u; g_flag_cf=1;
    if (!check(gw_dos_services_callback(0x31u,0xC8CD2u,&host)==GW_INTERRUPT_HANDLED,
               "AX=0200 reads the vector written by AX=0201") ||
        !check(g_ecx==0x8765000Cu && g_edx==0xFFFF1E74u && !g_flag_cf,
               "AX=0200 returns the 0201 segment:offset pair")) return 7;

    if (!check(gw_dos_services_callback(0x31u,0xC8CD2u,0)==GW_INTERRUPT_TRAPPED,
               "missing service state traps")) return 4;
    g_eax=0xBEEF0300u;
    if (!check(gw_dos_services_callback(0x31u,0xC8CD2u,&host)==GW_INTERRUPT_TRAPPED,
               "unknown DPMI function remains trapped")) return 5;

    gw_dos_descriptor_clear(&host);
    puts("PASS native DPMI AX=0200 configured/empty vectors, registers, carry and fail-closed traps");
    return 0;
}
