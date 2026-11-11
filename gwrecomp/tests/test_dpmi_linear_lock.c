#include "gw_dos_services.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

uint32_t g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,g_cur_func;
uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_ss,g_seg_fs,g_seg_gs;
uint32_t g_fs_base,g_gs_base;
ptrdiff_t g_mem_base;
uint32_t g_flag_k,g_flag_a,g_flag_b,g_flag_cf;

static int dpmi(uint32_t ax,uint32_t ebx,uint32_t ecx,uint32_t esi,uint32_t edi,
                gw_dos_services *host) {
    g_eax=ax; g_ebx=ebx; g_ecx=ecx; g_esi=esi; g_edi=edi;
    g_edx=0x33334444u; g_ebp=0x77778888u; g_esp=0x9999aaaau;
    g_flag_cf=1;
    return gw_dos_services_callback(0x31u,0x000d23a7u,host)==GW_INTERRUPT_HANDLED;
}

int main(void) {
    gw_dos_services host; memset(&host,0,sizeof host);
    if (!gw_dos_guest_memory_configure(&host,0x00301000u)) return 1;
    /* The original DOS/4GW no-paging host accepts the measured AX=0600
     * linear lock, preserving all registers and clearing only CF. */
    if (!dpmi(0xabcd0600u,0x11110000u,0x22201000u,
              0x55550000u,0x66660020u,&host) ||
        g_eax!=0xabcd0600u || g_ebx!=0x11110000u || g_ecx!=0x22201000u ||
        g_edx!=0x33334444u || g_esi!=0x55550000u || g_edi!=0x66660020u ||
        g_ebp!=0x77778888u || g_esp!=0x9999aaaau || g_flag_cf) return 2;
    if (!dpmi(0xabcd0601u,0x11110000u,0x22201000u,
              0x55550000u,0x66660020u,&host) ||
        g_eax!=0xabcd0601u || g_ecx!=0x22201000u ||
        g_edi!=0x66660020u || g_flag_cf) return 3;
    if (!dpmi(0xabcd0600u,0x11110030u,0x22201000u,
              0x55550000u,0x66660001u,&host) ||
        g_eax!=0xabcd8025u || !g_flag_cf) return 4;
    if (!dpmi(0xabcd0601u,0x11110000u,0x22201000u,
              0x55550000u,0x66660000u,&host) ||
        g_eax!=0xabcd8021u || !g_flag_cf) return 5;
    puts("PASS DPMI AX=0600/0601 no-paging range, preservation, and invalid-range contracts");
    return 0;
}
