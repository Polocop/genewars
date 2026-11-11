#include "gw_dos_services.h"
#include "gw_segments.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint32_t g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,g_cur_func;
uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_ss,g_seg_fs,g_seg_gs;
uint32_t g_fs_base,g_gs_base;
ptrdiff_t g_mem_base;
uint32_t g_flag_k,g_flag_a,g_flag_b,g_flag_cf;

static int allocate(gw_dos_services *services, uint32_t size) {
    g_eax=0x0501u; g_ebx=(size>>16)&0xffffu; g_ecx=size&0xffffu;
    g_edx=0x12345678u; g_esi=0x11112222u; g_edi=0x33334444u;
    g_flag_cf=1;
    return gw_dos_services_callback(0x31u,0x000C3CA9u,services)==GW_INTERRUPT_HANDLED;
}

int main(void) {
    const uint32_t guest_limit=0x00800000u;
    /* Self-contained API fixture, not a claim about unmeasured 1.1 objects. */
    const gw_dos_guest_region occupied[]={
        {0x00000000u,0x00110000u}, /* DOS conventional + VGA/ROM reservation */
        {0x00200000u,0x00220000u},
        {0x00240000u,0x00260000u},
    };
    uint8_t *guest=(uint8_t *)calloc(1,guest_limit);
    if (!guest) return 1;
    gw_dos_services services; memset(&services,0,sizeof services);
    g_mem_base=(ptrdiff_t)(uintptr_t)guest;
    if (!gw_dos_guest_memory_configure(&services,guest_limit)) return 2;
    if (!gw_dos_linear_allocator_configure_from_map(&services,guest_limit,0x00110000u,
                                                     occupied,3u)) return 3;
    if (services.allocation_cursor!=0x00260000u || services.allocation_end!=guest_limit) return 4;
    if (!allocate(&services,0x00100000u) || g_flag_cf || (uint16_t)g_eax!=0x0501u) return 5;
    uint32_t base=((g_ebx&0xffffu)<<16)|(g_ecx&0xffffu);
    if (base!=0x00260000u || ((g_esi&0xffffu)<<16|(g_edi&0xffffu))!=1u) return 6;
    for (uint32_t i=0;i<0x100000u;i++) if (guest[base+i]!=0) return 7;
    if (!allocate(&services,0x00500000u) || !g_flag_cf || (uint16_t)g_eax!=0x8012u) return 8;
    if (services.allocation_cursor!=0x00360000u) return 9;
    const gw_dos_guest_region invalid[]={{0x007ff000u,0x00801000u}};
    if (gw_dos_linear_allocator_configure_from_map(&services,guest_limit,0x00110000u,
                                                    invalid,1u)) return 10;
    free(guest); g_mem_base=0;
    puts("PASS map-derived DPMI range, non-overlap, backing, zero fill, and bounded exhaustion");
    return 0;
}
