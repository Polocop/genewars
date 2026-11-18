#include "gw_dos_services.h"
#include "gw_interrupts.h"
#include "gw_segments.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

uint32_t g_eax, g_ebx, g_ecx, g_edx, g_esi, g_edi, g_ebp, g_esp, g_cur_func;
uint16_t g_seg_cs, g_seg_ds, g_seg_es, g_seg_fs, g_seg_gs, g_seg_ss;
uint32_t g_fs_base, g_gs_base, g_flag_cf;
ptrdiff_t g_mem_base;

typedef struct fake_file {
    uint8_t bytes[64];
    uint16_t length;
    uint32_t cursor;
    uint16_t close_calls;
    uint16_t create_calls;
} fake_file;

static fake_file file_state;

static uint16_t provider_open(void *user, const char *path, uint8_t mode, void **file) {
    fake_file *f=(fake_file *)user;
    if (!f || strcmp(path,"C:\\fixture.bin")!=0 || mode!=2u || !file) return 3u;
    f->cursor=0;
    *file=f;
    return 0;
}

static uint16_t provider_create(void *user, const char *path, uint16_t attributes,
                                void **file) {
    fake_file *f=(fake_file *)user;
    (void)attributes;
    if (!f || strcmp(path,"C:\\fixture.bin")!=0 || !file) return 3u;
    memset(f->bytes,0,sizeof(f->bytes));
    f->length=0;
    f->cursor=0;
    f->create_calls++;
    *file=f;
    return 0;
}

static uint16_t provider_read(void *user, void *file, uint8_t *buffer,
                              uint16_t requested, uint16_t *transferred) {
    fake_file *f=(fake_file *)user;
    uint32_t available;
    if (!f || file!=f || !buffer || !transferred) return 6u;
    available=f->cursor<f->length ? (uint32_t)f->length-f->cursor : 0u;
    *transferred=(uint16_t)(available<requested ? available : requested);
    memcpy(buffer,f->bytes+f->cursor,*transferred);
    f->cursor+=*transferred;
    return 0;
}

static uint16_t provider_write(void *user, void *file, const uint8_t *buffer,
                               uint16_t requested, uint16_t *transferred) {
    fake_file *f=(fake_file *)user;
    if (!f || file!=f || !transferred || requested>sizeof(f->bytes)-f->cursor)
        return 5u;
    if (requested && !buffer) return 5u;
    memcpy(f->bytes+f->cursor,buffer,requested);
    f->cursor+=requested;
    if (f->cursor>f->length) f->length=(uint16_t)f->cursor;
    *transferred=requested;
    return 0;
}

static uint16_t provider_close(void *user, void *file) {
    fake_file *f=(fake_file *)user;
    if (!f || file!=f) return 6u;
    f->close_calls++;
    return 0;
}

static uint16_t provider_ioctl(void *user, void *file, uint16_t *info) {
    if (user!=file || !info) return 6u;
    *info=2u;
    return 0;
}

static uint16_t provider_seek(void *user, void *file, int32_t displacement,
                              uint8_t origin, uint32_t *position) {
    fake_file *f=(fake_file *)user;
    int64_t base, next;
    if (!f || file!=f || !position || origin>2u) return 1u;
    base=origin==0u ? 0 : origin==1u ? (int64_t)f->cursor : (int64_t)f->length;
    next=base+displacement;
    if (next<0 || next>(int64_t)sizeof(f->bytes)) return 1u;
    f->cursor=(uint32_t)next;
    *position=f->cursor;
    return 0;
}

static int invoke(gw_dos_services *services) {
    return gw_dos_services_callback(0x21u,0x00001234u,services)==GW_INTERRUPT_HANDLED;
}

static void seed_path(uint8_t *memory) {
    static const char path[]="C:\\fixture.bin";
    memcpy(memory+64u,path,sizeof(path));
}

int main(void) {
    uint8_t memory[4096]={0};
    gw_dos_services services;
    memset(&services,0,sizeof(services));
    memset(&file_state,0,sizeof(file_state));
    memcpy(file_state.bytes,"AB",2u); file_state.length=2u;
    g_mem_base=(ptrdiff_t)(uintptr_t)memory;
    g_seg_cs=0x000Cu; g_seg_ds=0x0014u; g_seg_es=0x0024u;
    g_seg_ss=0x0014u; g_seg_fs=0; g_seg_gs=0; g_ds_base=0;
    gw_dos_services_init(&services);
    if (!gw_dos_guest_memory_configure(&services,sizeof(memory)) ||
        !gw_dos_file_backend_configure(&services,provider_open,provider_read,
            provider_create,provider_write,provider_close,&file_state) ||
        !gw_dos_file_ioctl_info_configure(&services,provider_ioctl) ||
        !gw_dos_file_seek_configure(&services,provider_seek)) return 2;
    seed_path(memory);

    /* The default DOS JFT includes the standard handles; closing handle 2
     * succeeds without calling the virtual file provider. */
    g_eax=0xABCD3E00u; g_ebx=2u; g_ecx=0x11223344u; g_edx=0x55667788u;
    g_esi=0x10203040u; g_edi=0x50607080u; g_ebp=0x90A0B0C0u; g_esp=0xD0E0F000u;
    g_flag_cf=1u;
    if (!invoke(&services) || g_eax!=0xABCD3E00u || g_ebx!=2u ||
        g_ecx!=0x11223344u || g_edx!=0x55667788u || g_esi!=0x10203040u ||
        g_edi!=0x50607080u || g_ebp!=0x90A0B0C0u || g_esp!=0xD0E0F000u ||
        g_flag_cf!=0u || file_state.close_calls!=0u || g_seg_cs!=0x000Cu ||
        g_seg_ds!=0x0014u || g_seg_es!=0x0024u || g_seg_ss!=0x0014u ||
        g_seg_fs!=0u || g_seg_gs!=0u) {
        fprintf(stderr,"FAIL configured standard handle close/register preservation\n"); return 3;
    }

    /* An open after that close reuses the lowest free DOS number, 2. */
    g_eax=0xABCD3D02u; g_ebx=0x12345678u; g_edx=64u; g_flag_cf=1u;
    if (!invoke(&services) || g_eax!=0xABCD0002u || g_ebx!=0x12345678u ||
        g_flag_cf!=0u || !services.files[0].active || services.files[0].dos_handle!=2u) {
        fprintf(stderr,"FAIL open reuses closed standard DOS handle\n"); return 4;
    }

    /* AX=4400 now classifies handle 2 as the virtual regular file, not STDERR. */
    g_eax=0xABCD4400u; g_ebx=2u; g_edx=0xAABBCCDDu; g_flag_cf=1u;
    if (!invoke(&services) || g_eax!=0xABCD0002u || g_edx!=0xAABB0002u ||
        g_flag_cf!=0u) { fprintf(stderr,"FAIL IOCTL follows reused file handle\n"); return 5; }

    /* The same handle supports reads, seeks, and writes through its file entry. */
    g_eax=0xABCD3F00u; g_ebx=2u; g_ecx=2u; g_edx=256u; g_flag_cf=1u;
    if (!invoke(&services) || g_eax!=0xABCD0002u || memcmp(memory+256u,"AB",2u)!=0 || g_flag_cf) {
        fprintf(stderr,"FAIL read reused DOS handle\n"); return 6;
    }
    g_eax=0xABCD4200u; g_ebx=2u; g_ecx=0u; g_edx=0u; g_flag_cf=1u;
    if (!invoke(&services) || g_eax!=0xABCD0000u || g_edx!=0u || g_flag_cf) {
        fprintf(stderr,"FAIL seek reused DOS handle\n"); return 7;
    }
    memcpy(memory+300u,"XY",2u);
    g_eax=0xABCD4000u; g_ebx=2u; g_ecx=2u; g_edx=300u; g_flag_cf=1u;
    if (!invoke(&services) || g_eax!=0xABCD0002u || g_flag_cf ||
        file_state.length!=2u || memcmp(file_state.bytes,"XY",2u)!=0) {
        fprintf(stderr,"FAIL write reused DOS handle\n"); return 8;
    }

    g_eax=0xABCD3E00u; g_ebx=2u; g_flag_cf=1u;
    if (!invoke(&services) || g_eax!=0xABCD3E00u || g_flag_cf ||
        file_state.close_calls!=1u || services.files[0].active) {
        fprintf(stderr,"FAIL close reused virtual file handle\n"); return 9;
    }
    g_eax=0xABCD3E00u; g_ebx=2u; g_flag_cf=0u;
    if (!invoke(&services) || g_eax!=0xABCD0006u || !g_flag_cf) {
        fprintf(stderr,"FAIL repeated close reports invalid handle\n"); return 10;
    }

    /* Create shares the same handle allocation and virtual provider. */
    g_eax=0xABCD3C00u; g_ecx=0x20u; g_edx=64u; g_flag_cf=1u;
    if (!invoke(&services) || g_eax!=0xABCD0002u || g_flag_cf ||
        file_state.create_calls!=1u || !services.files[0].active) {
        fprintf(stderr,"FAIL create reuses lowest available DOS handle\n"); return 11;
    }
    g_eax=0xABCD3E00u; g_ebx=2u; g_flag_cf=1u;
    if (!invoke(&services) || g_eax!=0xABCD3E00u || g_flag_cf || file_state.close_calls!=2u) {
        fprintf(stderr,"FAIL close created DOS handle\n"); return 12;
    }

    g_eax=0xABCD3E00u; g_ebx=100u; g_flag_cf=0u;
    if (!invoke(&services) || g_eax!=0xABCD0006u || !g_flag_cf) {
        fprintf(stderr,"FAIL invalid DOS handle error\n"); return 13;
    }

    /* A second standard handle can close independently; absent file providers
     * still leave AH=3D fail-closed and preserve the input state. */
    g_eax=0xABCD3E00u; g_ebx=1u; g_flag_cf=1u;
    if (!invoke(&services) || g_eax!=0xABCD3E00u || g_flag_cf) return 14;
    gw_dos_services no_provider;
    memset(&no_provider,0,sizeof(no_provider)); gw_dos_services_init(&no_provider);
    g_eax=0xABCD3D02u; g_ebx=0x12345678u; g_ecx=0xAABBCCDDu; g_edx=64u;
    g_esi=0x10203040u; g_edi=0x50607080u; g_ebp=0x90A0B0C0u; g_esp=0xD0E0F000u; g_flag_cf=1u;
    if (invoke(&no_provider) || g_eax!=0xABCD3D02u || g_ebx!=0x12345678u ||
        g_ecx!=0xAABBCCDDu || g_edx!=64u || g_esi!=0x10203040u ||
        g_edi!=0x50607080u || g_ebp!=0x90A0B0C0u || g_esp!=0xD0E0F000u || !g_flag_cf) {
        fprintf(stderr,"FAIL provider absence must preserve trapped AH=3D request\n"); return 15;
    }

    puts("PASS DOS handle lifecycle: close std handle, reuse low handle for virtual file, read/write/seek/IOCTL/create/close and errors");
    return 0;
}
