#include "gw_dos_services.h"
#include "gw_segments.h"
#include <stdio.h>
#include <string.h>

uint32_t g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,g_cur_func;
uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_fs,g_seg_gs,g_seg_ss;
uint32_t g_fs_base,g_gs_base;
ptrdiff_t g_mem_base;

#define GUEST_SIZE 0x120000u
static uint8_t guest[GUEST_SIZE];
typedef struct fixture_file { const char *path; unsigned opens,closes; } fixture_file;
typedef struct fixture_provider { fixture_file sound,other; unsigned invalid_mode; } fixture_provider;

static uint16_t fixture_open(void *user,const char *path,uint8_t mode,void **out) {
    fixture_provider *provider=(fixture_provider *)user;
    fixture_file *file=0;
    if (!provider || !path || !out) return 3u;
    if (mode!=0u) { provider->invalid_mode++; return 12u; }
    if (!strcmp(path,"C:\\GENEWARS\\sound.ini")) file=&provider->sound;
    else if (!strcmp(path,"C:\\GENEWARS\\present.dat")) file=&provider->other;
    else if (!strcmp(path,"C:\\GENEWARS\\missing.dat")) return 2u;
    else return 3u;
    file->opens++;
    *out=file;
    return 0;
}
static uint16_t fixture_close(void *user,void *opaque) {
    (void)user;
    fixture_file *file=(fixture_file *)opaque;
    if (!file) return 6u;
    file->closes++;
    return 0;
}
static uint16_t fixture_read(void *user,void *opaque,uint8_t *buffer,uint16_t requested,
                             uint16_t *transferred) {
    (void)user;(void)opaque;(void)buffer;(void)requested;
    if (transferred) *transferred=0;
    return 0;
}
static gw_interrupt_result call(gw_dos_services *services,uint32_t at) {
    return gw_dos_services_callback(0x21u,at,services);
}

int main(void) {
    static const char gwerr[]="gw.err";
    static const char sound[]="C:\\GENEWARS\\sound.ini";
    static const char present[]="C:\\GENEWARS\\present.dat";
    static const char missing[]="C:\\GENEWARS\\missing.dat";
    static const char invalid[]="../escape.ini";
    const uint32_t gwerr_offset=0x00117520u,sound_offset=0x00117551u;
    const uint32_t present_offset=0x00117600u,missing_offset=0x00117640u;
    const uint32_t invalid_offset=0x00117680u;
    memcpy(guest+gwerr_offset,gwerr,sizeof(gwerr));
    memcpy(guest+sound_offset,sound,sizeof(sound));
    memcpy(guest+present_offset,present,sizeof(present));
    memcpy(guest+missing_offset,missing,sizeof(missing));
    memcpy(guest+invalid_offset,invalid,sizeof(invalid));
    g_seg_ds=0x0014u; g_ds_base=0; g_mem_base=(ptrdiff_t)(uintptr_t)guest;

    fixture_provider provider={0};
    provider.sound.path=sound; provider.other.path=present;
    gw_dos_services services={0}; gw_dos_services_init(&services);
    if (!gw_dos_guest_memory_configure(&services,GUEST_SIZE) ||
        !gw_dos_file_backend_configure(&services,fixture_open,fixture_read,0,0,
                                       fixture_close,&provider)) return 2;

    /* Preserve the independently measured gw.err missing-file response. */
    g_eax=0xABCD4300u; g_ebx=2u; g_ecx=0x11223344u; g_edx=gwerr_offset;
    g_esi=0x55667788u; g_edi=0x99AABBCCu; g_ebp=0x12345678u; g_esp=0x87654321u; g_flag_cf=0;
    if (call(&services,0x000AF93Au)!=GW_INTERRUPT_HANDLED || g_eax!=0xABCD0003u ||
        g_ebx!=2u || g_ecx!=0x11223344u || g_edx!=gwerr_offset ||
        g_esi!=0x55667788u || g_edi!=0x99AABBCCu || g_ebp!=0x12345678u ||
        g_esp!=0x87654321u || !g_flag_cf) return 3;

    /* W1's captured canonical path is resolved by the provider, not a path
     * special-case in the DOS service. Only AX/CX low words and CF change. */
    g_eax=0xABCD4300u; g_ebx=0x11112222u; g_ecx=0x33334444u;
    g_edx=sound_offset; g_esi=0x55667788u; g_edi=0x99AABBCCu;
    g_ebp=0x12345678u; g_esp=0x87654321u; g_flag_cf=1;
    if (call(&services,0x000AF93Au)!=GW_INTERRUPT_HANDLED ||
        g_eax!=0xABCD0020u || g_ecx!=0x33330020u || g_ebx!=0x11112222u ||
        g_edx!=sound_offset || g_esi!=0x55667788u || g_edi!=0x99AABBCCu ||
        g_ebp!=0x12345678u || g_esp!=0x87654321u || g_flag_cf ||
        provider.sound.opens!=1u || provider.sound.closes!=1u || provider.invalid_mode)
        return 4;

    /* A different provider-authorized file takes the same generic path. */
    g_eax=0x00004300u; g_ecx=0xAABBCCDDu; g_edx=present_offset; g_flag_cf=1;
    if (call(&services,0x00012345u)!=GW_INTERRUPT_HANDLED ||
        g_eax!=0x20u || g_ecx!=0xAABB0020u || g_edx!=present_offset || g_flag_cf ||
        provider.other.opens!=1u || provider.other.closes!=1u) return 5;

    /* Missing and rejected paths return deterministic DOS errors via AX/CF. */
    g_eax=0x12344300u; g_ecx=0xAABBCCDDu; g_edx=missing_offset; g_flag_cf=0;
    if (call(&services,0x00012345u)!=GW_INTERRUPT_HANDLED ||
        g_eax!=0x12340002u || g_ecx!=0xAABBCCDDu || !g_flag_cf) return 6;
    g_eax=0x12344300u; g_ecx=0xAABBCCDDu; g_edx=invalid_offset; g_flag_cf=0;
    if (call(&services,0x00012345u)!=GW_INTERRUPT_HANDLED ||
        g_eax!=0x12340003u || g_ecx!=0xAABBCCDDu || !g_flag_cf) return 7;
    g_eax=0x12344300u; g_ecx=0xAABBCCDDu; g_edx=GUEST_SIZE+1u; g_flag_cf=0;
    if (call(&services,0x00012345u)!=GW_INTERRUPT_HANDLED ||
        g_eax!=0x12340003u || g_ecx!=0xAABBCCDDu || !g_flag_cf) return 8;

    /* Without a configured provider, unknown existence is not success. */
    gw_dos_services no_provider={0}; gw_dos_services_init(&no_provider);
    if (!gw_dos_guest_memory_configure(&no_provider,GUEST_SIZE)) return 9;
    g_eax=0x00004300u; g_ecx=0xCAFEBABEu; g_edx=sound_offset; g_flag_cf=1;
    if (call(&no_provider,0x00012345u)!=GW_INTERRUPT_TRAPPED ||
        g_eax!=0x00004300u || g_ecx!=0xCAFEBABEu || g_edx!=sound_offset || !g_flag_cf)
        return 10;

    printf("DOS_AH43_FRONTIER_C_TEST pass=1 gwerr_ax=0003 gwerr_cf=1 sound_ax=0020 sound_cx=0020 sound_cf=0 provider_open_close=1 missing_ax=0002 invalid_ax=0003 no_provider=trapped\\n");
    return 0;
}
