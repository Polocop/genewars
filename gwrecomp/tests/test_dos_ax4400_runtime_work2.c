#include "gw_dos_services.h"
#include "gw_interrupts.h"
#include "gw_segments.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint32_t g_eax, g_ebx, g_ecx, g_edx, g_esi, g_edi, g_ebp, g_esp, g_cur_func;
uint16_t g_seg_cs, g_seg_ds, g_seg_es, g_seg_fs, g_seg_gs, g_seg_ss;
uint32_t g_fs_base, g_gs_base;
ptrdiff_t g_mem_base;

#define MEM_SIZE 512u
#define FILE_CAP 4096u
typedef struct vfile { uint8_t data[FILE_CAP]; uint32_t size; uint16_t info_flags; uint8_t drive_number; int exists, written; } vfile;
typedef struct vopen { vfile *file; uint32_t position; uint8_t mode, active; } vopen;
typedef struct provider { vfile config, address; vopen opens[GW_DOS_MAX_OPEN_FILES];
                         unsigned host_fs_calls; uint16_t last_attributes; char resolved[64]; } provider;

static uint8_t mem[MEM_SIZE];

static int path_equal(const char *a, const char *b) {
    while (*a && *b) {
        if (tolower((unsigned char)*a++) != tolower((unsigned char)*b++)) return 0;
    }
    return *a == *b;
}
static int path_config(const char *path) {
    return path_equal(path, "config.ini") || path_equal(path, "C:\\GENEWARS\\CONFIG.INI");
}
static int path_address(const char *path) {
    return path_equal(path, "C:\\ADDRESS.TXT");
}
static uint16_t vopen_file(void *user, const char *path, uint8_t mode, void **out) {
    provider *p=(provider *)user; vfile *f=0;
    if (!p || !path || !out) return 3u;
    if (path_config(path)) {
        strcpy(p->resolved, "C:\\GENEWARS\\CONFIG.INI"); f=&p->config;
    } else if (path_address(path)) f=&p->address;
    else return 3u; /* exact in-memory allowlist; never touches the host FS */
    if (!f->exists) return 2u;
    if (mode>2u) return 12u;
    if (mode!=0u && f==&p->config) return 5u;
    for (unsigned i=0;i<GW_DOS_MAX_OPEN_FILES;i++) if (!p->opens[i].active) {
        p->opens[i]=(vopen){f,0,mode,1}; *out=&p->opens[i]; return 0;
    }
    return 4u;
}
static uint16_t vcreate_file(void *user, const char *path, uint16_t attrs, void **out) {
    provider *p=(provider *)user;
    if (!p || !path || !out || !path_address(path)) return 5u;
    p->last_attributes=attrs;
    p->address.size=0; p->address.exists=1; p->address.written=0;
    p->address.info_flags=0; p->address.drive_number=2;
    for (unsigned i=0;i<GW_DOS_MAX_OPEN_FILES;i++) if (!p->opens[i].active) {
        p->opens[i]=(vopen){&p->address,0,1,1}; *out=&p->opens[i]; return 0;
    }
    return 4u;
}
static uint16_t vread(void *user, void *opaque, uint8_t *buffer, uint16_t requested,
                      uint16_t *transferred) {
    (void)user; vopen *o=(vopen *)opaque;
    if (!o || !o->active || o->mode==1u || !o->file || !buffer || !transferred) return 6u;
    uint32_t n=o->file->size-o->position;
    if (n>requested) n=requested;
    memcpy(buffer,o->file->data+o->position,n); o->position+=n; *transferred=(uint16_t)n; return 0;
}
static uint16_t vwrite(void *user, void *opaque, const uint8_t *buffer, uint16_t requested,
                       uint16_t *transferred) {
    (void)user; vopen *o=(vopen *)opaque;
    if (!o || !o->active || !o->file || o->mode==0u || !transferred) return 6u;
    if ((uint64_t)o->position+requested>FILE_CAP) return 112u;
    if (requested && !buffer) return 6u;
    if (requested) memcpy(o->file->data+o->position,buffer,requested);
    o->position+=requested; if (o->position>o->file->size) o->file->size=o->position;
    o->file->written=1; *transferred=requested; return 0;
}
static uint16_t vclose(void *user, void *opaque) {
    (void)user; vopen *o=(vopen *)opaque;
    if (!o || !o->active) return 6u;
    memset(o,0,sizeof(*o)); return 0;
}
static uint16_t vioctl(void *user, void *opaque, uint16_t *info) {
    (void)user; vopen *o=(vopen *)opaque;
    if (!o || !o->active || !o->file || !info) return 6u;
    *info=(uint16_t)((o->file->info_flags&0xffe0u)|(o->file->drive_number&0x1fu)); return 0;
}
static uint16_t vseek(void *user, void *opaque, int32_t displacement, uint8_t origin,
                      uint32_t *position) {
    (void)user; vopen *o=(vopen *)opaque;
    if (!o || !o->active || !o->file || !position || origin>2u) return 6u;
    int64_t base=origin==0u?0:(origin==1u?o->position:o->file->size);
    int64_t next=base+displacement; if (next<0 || next>UINT32_MAX) return 1u;
    o->position=(uint32_t)next; *position=o->position; return 0;
}

static int check(int condition, const char *message) {
    if (!condition) { fprintf(stderr,"FAIL %s\n",message); return 0; }
    return 1;
}
static gw_interrupt_result call(gw_dos_services *s, uint32_t ax, uint32_t bx,
                                uint32_t cx, uint32_t dx) {
    g_eax=ax; g_ebx=bx; g_ecx=cx; g_edx=dx; g_flag_cf=1;
    return gw_dos_services_callback(0x21u,0x000C8973u,s);
}

int main(int argc, char **argv) {
    if (argc!=2) return 2;
    provider p; memset(&p,0,sizeof(p));
    FILE *in=fopen(argv[1],"rb"); if (!in) return 3;
    size_t n=fread(p.config.data,1,sizeof(p.config.data),in);
    int extra=fgetc(in); fclose(in);
    if (!n || extra!=EOF) return 4;
    p.config.size=(uint32_t)n; p.config.exists=1; p.config.drive_number=2;

    g_seg_ds=0x14u; g_ds_base=0; g_mem_base=(ptrdiff_t)(uintptr_t)mem;
    gw_dos_services s; memset(&s,0,sizeof(s)); gw_dos_services_init(&s);
    if (!gw_dos_guest_memory_configure(&s,sizeof(mem)) ||
        !gw_dos_file_backend_configure(&s,vopen_file,vread,vcreate_file,vwrite,vclose,&p) ||
        !gw_dos_file_ioctl_info_configure(&s,vioctl) ||
        !gw_dos_file_seek_configure(&s,vseek)) return 5;

    if (!check(call(&s,0xABCD4400u,1u,0x11223344u,0x5566BEEFu)==GW_INTERRUPT_HANDLED &&
               g_eax==0xABCD0082u && g_edx==0x55660082u && !g_flag_cf &&
               g_ebx==1u && g_ecx==0x11223344u,
               "standard output handle reports character device in AX/DX")) return 5;

    memcpy(mem+0x40,"../escape.ini",14);
    if (!check(call(&s,0xABCD3D00u,0,0,0x40u)==GW_INTERRUPT_HANDLED &&
               (uint16_t)g_eax==3u && g_flag_cf,"unapproved path fails with DOS path error")) return 6;
    memcpy(mem,"config.ini",11);
    if (!check(call(&s,0xABCD3D00u,0x12345678u,0x56789ABCu,0u)==GW_INTERRUPT_HANDLED,
               "relative CONFIG.INI open handled")) return 10;
    uint16_t config_handle=(uint16_t)g_eax;
    if (!check(config_handle==5u && !g_flag_cf && (g_eax>>16)==0xABCDu &&
               g_ebx==0x12345678u && g_ecx==0x56789ABCu &&
               path_equal(p.resolved,"C:\\GENEWARS\\CONFIG.INI"),"CONFIG.INI maps to fixture CWD and handle 5")) return 11;

    /* AX=4400 is output in DX; the request's DX value is deliberately distinct. */
    if (!check(call(&s,0xABCD4400u,config_handle,0xCAFEBABEu,0x1234BEEFu)==GW_INTERRUPT_HANDLED,
               "AX=4400 valid file handled")) return 12;
    g_esi=0x11111111u; g_edi=0x22222222u; g_ebp=0x33333333u; g_esp=0x44444444u;
    /* Reissue with sentinels to verify all non-output general registers survive. */
    if (!check(call(&s,0xABCD4400u,config_handle,0xCAFEBABEu,0x1234BEEFu)==GW_INTERRUPT_HANDLED,
               "AX=4400 repeated valid file handled")) return 12;
    if (!check(g_eax==0xABCD0002u && g_ebx==config_handle && g_ecx==0xCAFEBABEu &&
               g_edx==0x12340002u && !g_flag_cf && g_esi==0x11111111u &&
               g_edi==0x22222222u && g_ebp==0x33333333u && g_esp==0x44444444u,
               "AX=4400 measured DOS result in AX/DX, preserved registers")) return 13;

    if (!check(call(&s,0xABCD4400u,4u,0xCAFEBABEu,0x1234BEEFu)==GW_INTERRUPT_HANDLED,
               "AX=4400 invalid file handle reports DOS error")) return 14;
    if (!check((uint16_t)g_eax==6u && g_edx==0x1234BEEFu && g_ebx==4u &&
               g_ecx==0xCAFEBABEu && g_flag_cf,"invalid handle AX=6 CF=1 and DX unchanged")) return 15;

    /* Read the authentic fixture through AH=3F, then close it. */
    g_eax=0xABCD3F00u; g_ebx=config_handle; g_ecx=(uint32_t)n; g_edx=0x100u; g_flag_cf=1;
    if (!check(gw_dos_services_callback(0x21u,0x000D2137u,&s)==GW_INTERRUPT_HANDLED &&
               !g_flag_cf && (uint16_t)g_eax==n && memcmp(mem+0x100,p.config.data,n)==0,
               "read returns exact CONFIG.INI bytes")) return 16;
    g_eax=0xABCD3E00u; g_ebx=config_handle; g_flag_cf=1;
    if (!check(gw_dos_services_callback(0x21u,0x000BA805u,&s)==GW_INTERRUPT_HANDLED &&
               !g_flag_cf && g_eax==0xABCD3E00u,"close CONFIG.INI handle")) return 17;
    if (!check(call(&s,0xABCD4400u,config_handle,0,0x1234BEEFu)==GW_INTERRUPT_HANDLED &&
               (uint16_t)g_eax==6u && g_flag_cf,"closed handle returns DOS error 6")) return 18;

    /* The previous open has been closed, so create gets the first DOS file slot (5). */
    memcpy(mem+0x20,"C:\\ADDRESS.TXT",15);
    if (!check(call(&s,0xABCD3D00u,0,0,0x20u)==GW_INTERRUPT_HANDLED &&
               (uint16_t)g_eax==2u && g_flag_cf,"ADDRESS.TXT starts absent")) return 19;
    g_eax=0xABCD3C00u; g_ebx=0x11112222u; g_ecx=0x20u; g_edx=0x20u; g_flag_cf=1;
    if (!check(gw_dos_services_callback(0x21u,0x000AFDA7u,&s)==GW_INTERRUPT_HANDLED &&
               (uint16_t)g_eax==5u && !g_flag_cf && g_ebx==0x11112222u && g_ecx==0x20u,
               "AH=3C creates bounded ADDRESS.TXT and returns handle 5")) return 20;
    if (!check(call(&s,0xABCD4400u,5u,0,0x00000005u)==GW_INTERRUPT_HANDLED &&
               g_eax==0xABCD0002u && g_edx==0x00000002u && !g_flag_cf,
               "new empty C-drive regular file returns measured drive metadata in AX/DX")) return 21;
    if (!check(p.last_attributes==0x20u,"AH=3C attributes reach provider")) return 21;

    memcpy(mem+0x80,"XY",2);
    g_eax=0xABCD4000u; g_ebx=5u; g_ecx=2u; g_edx=0x80u; g_flag_cf=1;
    if (!check(gw_dos_services_callback(0x21u,0x000D219Cu,&s)==GW_INTERRUPT_HANDLED &&
               (uint16_t)g_eax==2u && !g_flag_cf && p.address.size==2u &&
               memcmp(p.address.data,"XY",2)==0,"created handle writes into bounded virtual file")) return 22;
    if (!check(call(&s,0xABCD4400u,5u,0,0xFFFF0005u)==GW_INTERRUPT_HANDLED &&
               g_eax==0xABCD0002u && g_edx==0xFFFF0002u && !g_flag_cf,"AX=4400 reports provider metadata in AX/DX")) return 23;

    gw_dos_services unconfigured; memset(&unconfigured,0,sizeof(unconfigured));
    if (!gw_dos_file_backend_configure(&unconfigured,vopen_file,vread,vcreate_file,vwrite,vclose,&p)) return 24;
    /* Active entry copied from the configured service, but deliberately no info callback. */
    unconfigured.files[0]=s.files[0];
    uint32_t old_eax=0xABCD4400u,old_edx=0x1234BEEFu;
    g_eax=old_eax; g_ebx=5u; g_ecx=0x11223344u; g_edx=old_edx; g_flag_cf=1;
    if (!check(gw_dos_services_callback(0x21u,0x000C8973u,&unconfigured)==GW_INTERRUPT_TRAPPED &&
               g_eax==old_eax && g_edx==old_edx && g_flag_cf,
               "unconfigured IOCTL metadata callback fails closed without register mutation")) return 25;
    if (!check(p.host_fs_calls==0u,"provider did not access arbitrary host filesystem")) return 26;

    printf("DOS_AX4400_C_RUNTIME_TEST pass=1 config_size=%u config_path=C:\\GENEWARS\\CONFIG.INI created_handle=5 created_empty_ax_dx=0002 invalid_ax=0006 closed_ax=0006 wrote=2 attrs=%04x invalid_path=dos_error host_fs_provider_calls=%u unconfigured=trapped\n",
           (unsigned)n,p.last_attributes,p.host_fs_calls);
    g_eax=0x00003E00u; g_ebx=5u;
    (void)gw_dos_services_callback(0x21u,0x000BA805u,&s);
    gw_dos_descriptor_clear(&s);
    return 0;
}
