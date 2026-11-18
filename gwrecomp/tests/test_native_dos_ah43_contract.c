#include "gw_dos_services.h"
#include "gw_interrupts.h"
#include "gw_segments.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

uint32_t g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,g_cur_func;
uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_ss,g_seg_fs,g_seg_gs;
uint32_t g_fs_base,g_gs_base,g_flag_cf;
ptrdiff_t g_mem_base;

static void request(void) {
    g_eax=0x00004300u; g_ebx=0x12345678u; g_ecx=0x00000000u; g_edx=0x100u;
    g_esi=0x87654321u; g_edi=0x11112222u; g_ebp=0x33334444u; g_esp=0x55556666u;
    g_seg_ds=0x0014u; g_ds_base=0; g_flag_cf=0;
}
static int preserved(uint32_t ebx,uint32_t ecx,uint32_t edx,uint32_t esi,uint32_t edi,uint32_t ebp,uint32_t esp) {
    return g_ebx==ebx&&g_ecx==ecx&&g_edx==edx&&g_esi==esi&&g_edi==edi&&g_ebp==ebp&&g_esp==esp;
}
int main(void) {
    uint8_t memory[0x400]={0}; memcpy(memory+0x100,"gw.err",7);
    gw_dos_services services; memset(&services,0,sizeof services); gw_dos_services_init(&services);
    g_mem_base=(ptrdiff_t)(uintptr_t)memory;
    if (!gw_dos_guest_memory_configure(&services,sizeof memory)) return 2;
    request(); uint32_t b=g_ebx,c=g_ecx,d=g_edx,si=g_esi,di=g_edi,bp=g_ebp,sp=g_esp;
    if (gw_dos_services_callback(0x21,0x000AF93Au,&services)!=GW_INTERRUPT_HANDLED ||
        g_eax!=3u || !g_flag_cf || !preserved(b,c,d,si,di,bp,sp)) return 3;

    memcpy(memory+0x100,"bad.err",8); request();
    uint32_t eax=g_eax; b=g_ebx;c=g_ecx;d=g_edx;si=g_esi;di=g_edi;bp=g_ebp;sp=g_esp;
    if (gw_dos_services_callback(0x21,0x000AF93Au,&services)!=GW_INTERRUPT_TRAPPED ||
        g_eax!=eax || g_flag_cf || !preserved(b,c,d,si,di,bp,sp)) return 4;
    memcpy(memory+0x100,"gw.err",7); request(); eax=g_eax;
    if (gw_dos_services_callback(0x21,0x000AF93Bu,&services)!=GW_INTERRUPT_TRAPPED || g_eax!=eax || g_flag_cf) return 5;
    request(); g_eax=0x00004301u; eax=g_eax;
    if (gw_dos_services_callback(0x21,0x000AF93Au,&services)!=GW_INTERRUPT_TRAPPED || g_eax!=eax || g_flag_cf) return 6;
    request(); g_seg_ds=0x0015u; eax=g_eax;
    if (gw_dos_services_callback(0x21,0x000AF93Au,&services)!=GW_INTERRUPT_TRAPPED || g_eax!=eax || g_flag_cf) return 7;
    request(); g_edx=0x3fbu; eax=g_eax;
    if (gw_dos_services_callback(0x21,0x000AF93Au,&services)!=GW_INTERRUPT_TRAPPED || g_eax!=eax || g_flag_cf) return 8;
    services.guest_memory_configured=0; request(); eax=g_eax;
    if (gw_dos_services_callback(0x21,0x000AF93Au,&services)!=GW_INTERRUPT_TRAPPED || g_eax!=eax || g_flag_cf) return 9;
    gw_dos_descriptor_clear(&services);
    puts("PASS exact DOS AH=43 gw.err missing-path response; unknown path/callsite/subfunction/selector/bounds/config fail closed");
    return 0;
}
