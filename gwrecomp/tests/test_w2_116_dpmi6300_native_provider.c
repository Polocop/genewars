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

static uint8_t guest[0x100000];

static int check(int value, const char *what) {
    if (!value) fprintf(stderr,"FAIL: %s\n",what);
    return value;
}

static void frame_init(uint32_t address, uint16_t ax) {
    gw_dos_real_mode_registers r={0};
    r.eax=0xABCD0000u|ax;
    r.esi=0x13570000u;
    r.flags=0x0203u;
    memcpy(guest+address,&r,sizeof(r));
}

static void outer_init(uint32_t frame) {
    g_eax=0xCAFE0300u; g_ebx=0x21u; g_ecx=0;
    g_edx=0x10203040u; g_esi=0x50607080u; g_edi=frame;
    g_ebp=0x90abcdefu; g_esp=0x00123450u; g_flag_cf=1u;
    g_seg_cs=0x1111u; g_seg_ds=0x2222u; g_seg_es=0x0168u;
    g_seg_fs=0x4444u; g_seg_gs=0x5555u; g_seg_ss=0x6666u;
    g_cs_base=g_ds_base=g_es_base=g_fs_base=g_gs_base=g_ss_base=0;
}

static int outer_unchanged(uint32_t frame, uint32_t vector) {
    return g_eax==0xCAFE0300u && g_ebx==vector && g_ecx==0 &&
           g_edx==0x10203040u && g_esi==0x50607080u && g_edi==frame &&
           g_ebp==0x90abcdefu && g_esp==0x00123450u && g_flag_cf==1u &&
           g_seg_cs==0x1111u && g_seg_ds==0x2222u && g_seg_es==0x0168u &&
           g_seg_fs==0x4444u && g_seg_gs==0x5555u && g_seg_ss==0x6666u;
}

static int frame_unchanged(uint32_t address, const gw_dos_real_mode_registers *before) {
    gw_dos_real_mode_registers after;
    memcpy(&after,guest+address,sizeof(after));
    return memcmp(&after,before,sizeof(after))==0;
}

int main(void) {
    gw_dos_services services={0};
    static const uint8_t measured_fixture_table[12]={0};
    const uint32_t frame_address=0x1000u;
    const uint32_t table_address=0x23456u;
    gw_dos_services_init(&services);
    if (!check(gw_dos_guest_memory_configure(&services,sizeof(guest)),
               "configure bounded 1 MiB guest memory")) return 1;
    g_mem_base=(ptrdiff_t)(uintptr_t)guest;
    if (!check(gw_dos_dbcs_table_configure(&services,table_address,
                                            measured_fixture_table,
                                            sizeof(measured_fixture_table)),
               "configure caller-supplied measured table at runtime address")) return 2;
    if (!check(memcmp(guest+table_address,measured_fixture_table,
                      sizeof(measured_fixture_table))==0,
               "copy exact provider table to guest memory")) return 3;
    if (!check(gw_dos_real_mode_interrupt_configure(
                   &services,gw_dos_services_real_mode_interrupt,&services),
               "configure built-in DOS 6300 provider")) return 4;

    frame_init(frame_address,0x6300u); outer_init(frame_address);
    if (!check(gw_dos_services_callback(0x31u,0x000BC765u,&services)==GW_INTERRUPT_HANDLED,
               "DPMI AX=0300 dispatches nested INT 21h AX=6300")) return 5;
    gw_dos_real_mode_registers result;
    memcpy(&result,guest+frame_address,sizeof(result));
    if (!check((uint16_t)result.eax==0x6300u && result.ds==(table_address>>4) &&
               (uint16_t)result.esi==(table_address&0x0fu) &&
               (result.flags&1u)==0 && (result.flags&0x0200u)!=0,
               "AX, dynamic RealPt, and CF return match measured shape")) return 6;
    if (!check(outer_unchanged(frame_address,0x21u),"outer registers and carry preserved") ||
        !check(memcmp(guest+table_address,measured_fixture_table,
                      sizeof(measured_fixture_table))==0,"provider bytes remain guest-readable")) return 7;

    /* A second address proves the observed C808 value is not embedded. */
    const uint32_t second_address=0x34567u;
    if (!gw_dos_dbcs_table_configure(&services,second_address,
                                      measured_fixture_table,
                                      sizeof(measured_fixture_table))) return 8;
    frame_init(frame_address,0x6300u); outer_init(frame_address);
    if (!check(gw_dos_services_callback(0x31u,0xBC765u,&services)==GW_INTERRUPT_HANDLED,
               "provider supports per-run table relocation")) return 9;
    memcpy(&result,guest+frame_address,sizeof(result));
    if (!check(result.ds==(second_address>>4) &&
               (uint16_t)result.esi==(second_address&0x0fu),
               "return pointer follows current provider address")) return 10;

    /* Invalid configurations must not replace the last valid table. */
    static const uint8_t odd_table[3]={0x81,0xfe,0};
    static const uint8_t missing_terminator[4]={0x81,0xfe,0x82,0xfe};
    static const uint8_t invalid_range[4]={0x90,0x80,0,0};
    static const uint8_t nonzero_tail[4]={0,0,0,1};
    uint8_t oversized[4098]={0};
    if (!check(!gw_dos_dbcs_table_configure(&services,0x40000u,odd_table,sizeof(odd_table)),
               "reject odd-size table")) return 11;
    if (!check(!gw_dos_dbcs_table_configure(&services,0x40000u,missing_terminator,sizeof(missing_terminator)),
               "reject missing terminator")) return 12;
    if (!check(!gw_dos_dbcs_table_configure(&services,0x40000u,invalid_range,sizeof(invalid_range)),
               "reject reversed lead-byte range")) return 13;
    if (!check(!gw_dos_dbcs_table_configure(&services,0x40000u,nonzero_tail,sizeof(nonzero_tail)),
               "reject nonzero bytes after table terminator")) return 14;
    if (!check(!gw_dos_dbcs_table_configure(&services,0x40000u,oversized,sizeof(oversized)),
               "reject table over 4096-byte limit")) return 15;
    if (!check(!gw_dos_dbcs_table_configure(&services,0xfffffu,measured_fixture_table,
                                            sizeof(measured_fixture_table)),
               "reject real-mode 1 MiB boundary crossing")) return 16;
    if (!gw_dos_guest_memory_configure(&services,0xff005u)) return 17;
    if (!check(!gw_dos_dbcs_table_configure(&services,0xff000u,measured_fixture_table,
                                            sizeof(measured_fixture_table)),
               "reject guest memory out-of-bounds")) return 17;
    if (!gw_dos_guest_memory_configure(&services,sizeof(guest))) return 17;
    if (!check(!gw_dos_dbcs_table_configure(&services,0,measured_fixture_table,
                                            sizeof(measured_fixture_table)),
               "reject null real-mode address")) return 18;
    if (!check(!gw_dos_dbcs_table_configure(&services,UINT32_MAX,measured_fixture_table,
                                            sizeof(measured_fixture_table)),
               "reject overflowing/out-of-range linear address")) return 18;

    frame_init(frame_address,0x6301u); outer_init(frame_address);
    gw_dos_real_mode_registers before;
    memcpy(&before,guest+frame_address,sizeof(before));
    if (!check(gw_dos_services_callback(0x31u,0xBC765u,&services)==GW_INTERRUPT_TRAPPED &&
               frame_unchanged(frame_address,&before) && outer_unchanged(frame_address,0x21u),
               "unsupported AX=6301 traps without partial mutation")) return 19;

    frame_init(frame_address,0x6300u); outer_init(frame_address);
    memcpy(&before,guest+frame_address,sizeof(before));
    services.dbcs_table_configured=0;
    if (!check(gw_dos_services_callback(0x31u,0xBC765u,&services)==GW_INTERRUPT_TRAPPED &&
               frame_unchanged(frame_address,&before) && outer_unchanged(frame_address,0x21u),
               "missing configured table fails closed")) return 20;
    services.dbcs_table_configured=1;
    services.real_mode_interrupt=0;
    frame_init(frame_address,0x6300u); outer_init(frame_address);
    memcpy(&before,guest+frame_address,sizeof(before));
    if (!check(gw_dos_services_callback(0x31u,0xBC765u,&services)==GW_INTERRUPT_TRAPPED &&
               frame_unchanged(frame_address,&before) && outer_unchanged(frame_address,0x21u),
               "missing DPMI provider fails closed")) return 22;

    if (!gw_dos_real_mode_interrupt_configure(&services,
              gw_dos_services_real_mode_interrupt,&services)) return 23;
    frame_init(frame_address,0x6300u); outer_init(frame_address); g_ebx=0x2fu;
    memcpy(&before,guest+frame_address,sizeof(before));
    if (!check(gw_dos_services_callback(0x31u,0xBC765u,&services)==GW_INTERRUPT_TRAPPED &&
               frame_unchanged(frame_address,&before) && outer_unchanged(frame_address,0x2fu),
               "unsupported inner vector fails closed")) return 24;

    gw_dos_services no_memory={0};
    if (!check(!gw_dos_dbcs_table_configure(&no_memory,0x20000u,
                                             measured_fixture_table,
                                             sizeof(measured_fixture_table)),
               "unconfigured guest memory rejects table")) return 25;
    g_mem_base=0;
    gw_dos_descriptor_clear(&services);
    puts("PASS bounded native DPMI AX=0300 / INT 21h AX=6300 DBCS provider");
    return 0;
}
