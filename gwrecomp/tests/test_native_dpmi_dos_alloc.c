#include "gw_dos_services.h"
#include "gw_interrupts.h"
#include "gw_segments.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

uint32_t g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,g_cur_func;
uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_ss,g_seg_fs,g_seg_gs;
uint32_t g_fs_base,g_gs_base;
ptrdiff_t g_mem_base;

static int alloc(gw_dos_services *host, uint16_t paragraphs) {
    g_eax=0xaaaa0100u; g_ebx=0xbbbb0000u|paragraphs; g_ecx=0xcccc1234u;
    g_edx=0xdddd5678u; g_flag_cf=0;
    return gw_dos_services_callback(0x31,0x12345678,host)==GW_INTERRUPT_HANDLED;
}
static int free_block(gw_dos_services *host,uint16_t selector) {
    g_eax=0x0101; g_edx=selector; g_flag_cf=0;
    return gw_dos_services_callback(0x31,0,host)==GW_INTERRUPT_HANDLED;
}
static int resize_block(gw_dos_services *host,uint16_t selector,uint16_t paragraphs) {
    g_eax=0x0102; g_edx=selector; g_ebx=paragraphs; g_flag_cf=0;
    return gw_dos_services_callback(0x31,0,host)==GW_INTERRUPT_HANDLED;
}

int main(void) {
    gw_dos_services host; memset(&host,0,sizeof host);
    if (gw_dos_memory_allocator_configure(&host,0x8000,0xa001,0x24,0x1000)) return 2;
    if (!alloc(&host,1) || !g_flag_cf || (uint16_t)g_eax!=8 || (uint16_t)g_ebx!=0) return 3;
    if (!gw_dos_memory_allocator_configure(&host,0x8000,0xa000,0x24,0x1000)) return 4;
    if (!alloc(&host,0x1000) || g_flag_cf || (uint16_t)g_eax!=0x8000 ||
        (uint16_t)g_edx!=0x24 || g_eax!=0xaaaa8000u || g_edx!=0xdddd0024u) return 5;
    uint32_t base=0;
    if (!gw_dos_descriptor_base(0x24,&base,&host) || base!=0x80000u ||
        !gw_dos_descriptor_range(0x24,0xffff,1,&host) ||
        gw_dos_descriptor_range(0x24,0xffff,2,&host)) return 6;
    /* RPL occupies only selector bits 0..1; 0x27 names the same descriptor
       as 0x24 and must preserve its base and limit. */
    if (!gw_dos_descriptor_base(0x27,&base,&host) || base!=0x80000u ||
        !gw_dos_descriptor_range(0x27,0xffff,1,&host) ||
        gw_dos_descriptor_range(0x27,0xffff,2,&host)) return 26;
    if (!alloc(&host,0x1000) || g_flag_cf || (uint16_t)g_eax!=0x9000 ||
        (uint16_t)g_edx!=0x2c) return 7;
    if (!alloc(&host,1) || !g_flag_cf || (uint16_t)g_eax!=8 || (uint16_t)g_ebx!=0) return 8;
    if (!free_block(&host,0x24) || g_flag_cf || gw_dos_descriptor_base(0x24,&base,&host) ||
        gw_dos_descriptor_base(0x27,&base,&host)) return 9;
    if (!alloc(&host,0x1000) || g_flag_cf || (uint16_t)g_eax!=0x8000 || (uint16_t)g_edx!=0x24) return 10;
    if (!free_block(&host,0x24) || g_flag_cf) return 11;
    if (!free_block(&host,0x24) || !g_flag_cf || (uint16_t)g_eax!=0x8022) return 12;
    gw_dos_descriptor_clear(&host);
    memset(&host,0,sizeof host);

    if (!gw_dos_memory_allocator_configure(&host,0x8000,0x9000,0x24,0x1000)) return 13;
    if (!alloc(&host,0x800) || g_flag_cf || (uint16_t)g_eax!=0x8000 ||
        (uint16_t)g_edx!=0x24 || g_eax!=0xaaaa8000u || g_edx!=0xdddd0024u) return 14;
    if (!resize_block(&host,0x24,0x400) || g_flag_cf ||
        !gw_dos_descriptor_range(0x24,0x3fff,1,&host) ||
        gw_dos_descriptor_range(0x24,0x4000,1,&host)) return 15;
    if (!alloc(&host,0x400) || g_flag_cf || (uint16_t)g_eax!=0x8400 || (uint16_t)g_edx!=0x2c) return 16;
    if (!resize_block(&host,0x24,0x800) || !g_flag_cf || (uint16_t)g_eax!=8 || (uint16_t)g_ebx!=0x400) return 17;
    if (!free_block(&host,0x2c) || g_flag_cf) return 18;
    if (!resize_block(&host,0x24,0x800) || g_flag_cf ||
        !gw_dos_descriptor_range(0x24,0x7fff,1,&host)) return 19;
    if (!resize_block(&host,0x7777,0x100) || !g_flag_cf || (uint16_t)g_eax!=0x8022) return 20;
    if (!free_block(&host,0x24) || g_flag_cf) return 21;
    if (!alloc(&host,0x1000) || g_flag_cf || (uint16_t)g_eax!=0x8000) return 22;
    gw_dos_descriptor_clear(&host);
    memset(&host,0,sizeof host);

    if (!gw_dos_memory_allocator_configure(&host,0x8000,0x8010,0xfffc,0x1000)) return 23;
    if (!alloc(&host,1) || g_flag_cf || (uint16_t)g_edx!=0xfffc) return 24;
    if (!alloc(&host,1) || !g_flag_cf || (uint16_t)g_eax!=0x8011) return 25;
    gw_dos_descriptor_clear(&host);
    puts("PASS native DPMI 0100/0101/0102 bounded allocation, selector lifecycle, resize, gap reuse and errors");
    return 0;
}
