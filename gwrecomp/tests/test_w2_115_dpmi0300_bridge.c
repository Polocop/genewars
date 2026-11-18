#include "gw_dos_services.h"
#include "gw_interrupts.h"
#include "gw_segments.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

uint32_t g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,g_cur_func;
uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_fs,g_seg_gs,g_seg_ss;
uint32_t g_fs_base,g_gs_base;
uint32_t g_flag_cf;
ptrdiff_t g_mem_base;

static uint8_t guest[0x4000];
static unsigned provider_calls;

static int measured_6300_provider(void *user, uint8_t vector,
                                  gw_dos_real_mode_registers *r) {
    (void)user;
    provider_calls++;
    if (vector!=0x21u || (uint16_t)r->eax!=0x6300u) return 0;
    r->ds=0x4567u;
    r->esi=(r->esi&0xffff0000u)|0x1234u;
    r->flags=(uint16_t)(r->flags&~1u);
    return 1;
}

static int reject_provider(void *user, uint8_t vector,
                           gw_dos_real_mode_registers *r) {
    (void)user; (void)vector; (void)r;
    provider_calls++;
    return 0;
}

static int check(int value, const char *what) {
    if (!value) fprintf(stderr,"FAIL: %s\n",what);
    return value;
}

static void init_request(uint32_t linear) {
    gw_dos_real_mode_registers r={0};
    r.eax=0x00006300u;
    memcpy(guest+linear,&r,sizeof(r));
    g_eax=0xCAFE0300u; g_ebx=0x00000021u; g_ecx=0;
    g_edx=0x10203040u; g_esi=0x50607080u; g_edi=linear;
    g_ebp=0x90abcdefu; g_esp=0x00123450u; g_flag_cf=1u;
    g_seg_cs=0x1111u; g_seg_ds=0x2222u; g_seg_es=0x0168u;
    g_seg_fs=0x4444u; g_seg_gs=0x5555u; g_seg_ss=0x6666u;
    g_cs_base=g_ds_base=g_es_base=g_fs_base=g_gs_base=g_ss_base=0;
}

static int outer_unchanged(void) {
    return g_eax==0xCAFE0300u && g_ebx==0x21u && g_ecx==0 &&
           g_edx==0x10203040u && g_esi==0x50607080u &&
           g_edi==0x1000u && g_ebp==0x90abcdefu && g_esp==0x00123450u &&
           g_flag_cf==1u && g_seg_cs==0x1111u && g_seg_ds==0x2222u &&
           g_seg_es==0x0168u && g_seg_fs==0x4444u && g_seg_gs==0x5555u &&
           g_seg_ss==0x6666u;
}

int main(void) {
    gw_dos_services services={0};
    gw_dos_services_init(&services);
    if (!check(gw_dos_guest_memory_configure(&services,sizeof(guest)),
               "configure bounded guest memory")) return 1;
    g_mem_base=(ptrdiff_t)(uintptr_t)guest;

    if (!check(gw_dos_real_mode_interrupt_configure(&services,
              measured_6300_provider,0),"configure explicit inner provider")) return 2;
    init_request(0x1000u);
    provider_calls=0;
    if (!check(gw_dos_services_callback(0x31u,0x000BC765u,&services)==GW_INTERRUPT_HANDLED,
               "measured AX=0300 / INT 21h AX=6300 request handled")) return 3;
    gw_dos_real_mode_registers returned;
    memcpy(&returned,guest+0x1000u,sizeof(returned));
    if (!check(provider_calls==1u && (uint16_t)returned.eax==0x6300u &&
               returned.ds==0x4567u && (uint16_t)returned.esi==0x1234u &&
               (returned.flags&1u)==0,"provider frame copied back dynamically") ||
        !check(outer_unchanged(),"outer CPU registers and carry preserved")) return 4;

    /* A failed provider must not partially commit its local frame edits. */
    init_request(0x1000u); provider_calls=0;
    if (!check(gw_dos_real_mode_interrupt_configure(&services,reject_provider,0),
               "configure rejecting provider")) return 5;
    gw_dos_real_mode_registers before;
    memcpy(&before,guest+0x1000u,sizeof(before));
    if (!check(gw_dos_services_callback(0x31u,0xBC765u,&services)==GW_INTERRUPT_TRAPPED,
               "provider rejection remains trapped")) return 6;
    memcpy(&returned,guest+0x1000u,sizeof(returned));
    if (!check(provider_calls==1u && !memcmp(&before,&returned,sizeof(before)) &&
               outer_unchanged(),"provider rejection leaves frame and outer state unchanged")) return 7;

    /* Missing providers and unsupported DPMI stack/CX extensions fail closed. */
    services.real_mode_interrupt=0; init_request(0x1000u);
    if (!check(gw_dos_services_callback(0x31u,0xBC765u,&services)==GW_INTERRUPT_TRAPPED,
               "missing provider traps")) return 8;
    if (!gw_dos_real_mode_interrupt_configure(&services,measured_6300_provider,0)) return 9;
    init_request(0x1000u); g_ebx=0x00000121u;
    if (!check(gw_dos_services_callback(0x31u,0xBC765u,&services)==GW_INTERRUPT_TRAPPED,
               "nonzero BH stack-word request traps")) return 10;
    init_request(0x1000u); g_ecx=1u;
    if (!check(gw_dos_services_callback(0x31u,0xBC765u,&services)==GW_INTERRUPT_TRAPPED,
               "unmeasured CX extension traps")) return 11;
    init_request(0x1000u); g_ebx=0x2fu;
    if (!check(gw_dos_services_callback(0x31u,0xBC765u,&services)==GW_INTERRUPT_TRAPPED,
               "provider rejects unsupported interrupt vector")) return 12;

    /* Descriptor, linear-overflow, and guest-buffer bounds are checked before
     * reading or invoking the provider. */
    init_request(0x1000u); provider_calls=0; g_seg_es=0x7777u;
    if (!gw_dos_descriptor_bind(&services,g_seg_es,0,0x100u)) return 13;
    if (!check(gw_dos_services_callback(0x31u,0xBC765u,&services)==GW_INTERRUPT_TRAPPED &&
               provider_calls==0u,"short ES descriptor traps before provider")) return 13;
    init_request(0x1000u); provider_calls=0; g_es_base=0xfffffff0u; g_edi=0x20u;
    if (!check(gw_dos_services_callback(0x31u,0xBC765u,&services)==GW_INTERRUPT_TRAPPED &&
               provider_calls==0u,"ES base addition overflow traps")) return 14;
    init_request((uint32_t)sizeof(guest)-sizeof(gw_dos_real_mode_registers)+1u);
    provider_calls=0;
    if (!check(gw_dos_services_callback(0x31u,0xBC765u,&services)==GW_INTERRUPT_TRAPPED &&
               provider_calls==0u,"frame crossing guest-memory end traps")) return 15;

    g_mem_base=0; gw_dos_descriptor_clear(&services);
    puts("PASS native DPMI AX=0300 provider bridge, bounded frame, preservation and fail-closed cases");
    return 0;
}
