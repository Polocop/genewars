#include "gw_dos_services.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "gw_segments.h"
uint32_t g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,g_cur_func;
uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_ss,g_seg_fs,g_seg_gs;
uint32_t g_fs_base,g_gs_base;
ptrdiff_t g_mem_base;
uint32_t g_flag_k,g_flag_a,g_flag_b,g_flag_cf;

typedef struct fixture_file {
    char name[32];
    uint8_t bytes[17];
    uint32_t size;
    uint16_t attributes;
    uint8_t written;
} fixture_file;
typedef struct fixture_open_state { fixture_file *file; uint32_t position; uint8_t active, mode; } fixture_open_state;
static fixture_file fixture_files[4];
static fixture_open_state fixture_opens[GW_DOS_MAX_OPEN_FILES];
static uint32_t fixture_total_bytes;
static uint16_t fixture_last_attributes;
static const uint32_t FIXTURE_FILE_QUOTA=16u, FIXTURE_TOTAL_QUOTA=30u;

static int ascii_case_equal(const char *a,const char *b) {
    while (*a && *b) {
        char x=*a++,y=*b++;
        if (x>='A'&&x<='Z') x=(char)(x-'A'+'a');
        if (y>='A'&&y<='Z') y=(char)(y-'A'+'a');
        if (x!=y) return 0;
    }
    return *a==*b;
}
static int fixture_path(const char *path,char name[32]);
static fixture_file *fixture_find(const char *name);
static uint16_t fixture_open(void *user,const char *dos_path,uint8_t mode,void **file) {
    (void)user;
    if (!dos_path || !file || mode>2u) return 12u;
    *file=0;
    if (strstr(dos_path,"..") || strchr(dos_path,'/')) return 5u;
    if (dos_path[0] && (dos_path[0]=='D'||dos_path[0]=='d') && dos_path[1]==':') return 15u;
    if (ascii_case_equal(dos_path,"C:\\address.txt")) return 2u;
    char name[32]={0};
    if (!fixture_path(dos_path,name)) return 5u;
    fixture_file *f=fixture_find(name);
    if (!f) return 2u;
    for (unsigned i=0;i<GW_DOS_MAX_OPEN_FILES;i++) if (!fixture_opens[i].active) {
        fixture_opens[i]=(fixture_open_state){f,0,1,mode}; *file=&fixture_opens[i]; return 0;
    }
    return 4u;
}
static uint16_t fixture_read(void *user,void *file,uint8_t *buffer,
                             uint16_t requested,uint16_t *transferred) {
    (void)user;
    fixture_open_state *open=(fixture_open_state *)file;
    if (!open || !open->active || open->mode==1u || !buffer || !transferred) return 6u;
    uint32_t remaining=open->file->size-open->position;
    uint16_t count=requested<remaining?requested:(uint16_t)remaining;
    memcpy(buffer,open->file->bytes+open->position,count);
    open->position+=count; *transferred=count; return 0;
}
static int fixture_path(const char *path,char name[32]) {
    const char *leaf=path;
    if (ascii_case_equal(path,"C:\\GENEWARS\\FIXTURE.TXT")) leaf="fixture.txt";
    else if (ascii_case_equal(path,"C:\\GENEWARS\\QUOTA.TXT")) leaf="quota.txt";
    else if (ascii_case_equal(path,"C:\\GENEWARS\\GLOBAL1.TXT")) leaf="global1.txt";
    else if (ascii_case_equal(path,"C:\\GENEWARS\\GLOBAL2.TXT")) leaf="global2.txt";
    else if (strchr(path,':') || strchr(path,'\\') || strchr(path,'/') || strstr(path,"..")) return 0;
    if (!ascii_case_equal(leaf,"fixture.txt") && !ascii_case_equal(leaf,"quota.txt") &&
        !ascii_case_equal(leaf,"global1.txt") && !ascii_case_equal(leaf,"global2.txt")) return 0;
    for (unsigned i=0;leaf[i] && i<31u;i++) { char c=leaf[i]; name[i]=(c>='A'&&c<='Z')?(char)(c-'A'+'a'):c; name[i+1u]=0; }
    return 1;
}
static fixture_file *fixture_find(const char *name) {
    for (unsigned i=0;i<4;i++) if (fixture_files[i].name[0] && ascii_case_equal(fixture_files[i].name,name)) return &fixture_files[i];
    return 0;
}
static uint16_t fixture_create(void *user,const char *path,uint16_t attributes,void **file) {
    (void)user;
    if (path && (path[0]=='D'||path[0]=='d') && path[1]==':') return 15u;
    char name[32]={0}; if (!file || !fixture_path(path,name)) return 5u;
    fixture_file *f=fixture_find(name);
    if (!f) for (unsigned i=0;i<4;i++) if (!fixture_files[i].name[0]) { f=&fixture_files[i]; break; }
    if (!f) return 112u;
    fixture_total_bytes-=f->size; f->size=0; memset(f->bytes,0,sizeof f->bytes);
    f->written=0;
    strcpy(f->name,name); f->attributes=attributes; fixture_last_attributes=attributes;
    for (unsigned i=0;i<GW_DOS_MAX_OPEN_FILES;i++) if (!fixture_opens[i].active) {
        fixture_opens[i]=(fixture_open_state){f,0,1,1}; *file=&fixture_opens[i]; return 0;
    }
    return 4u;
}
static uint16_t fixture_write(void *user,void *file,const uint8_t *buffer,
                              uint16_t requested,uint16_t *transferred) {
    (void)user; fixture_open_state *open=(fixture_open_state *)file;
    if (!open || !open->active || open->mode==0u || !transferred) return 6u;
    if (!requested) {
        if (open->position<open->file->size) {
            fixture_total_bytes-=open->file->size-open->position;
            open->file->size=open->position;
        }
        *transferred=0; return 0;
    }
    if (!buffer) return 6u;
    uint64_t end=(uint64_t)open->position+requested;
    if (end>FIXTURE_FILE_QUOTA || end>sizeof open->file->bytes) return 112u;
    uint32_t old_size=open->file->size, new_size=(uint32_t)end;
    uint32_t growth=new_size>old_size?new_size-old_size:0;
    if ((uint64_t)fixture_total_bytes+growth>FIXTURE_TOTAL_QUOTA) return 112u;
    if (requested) memcpy(open->file->bytes+open->position,buffer,requested);
    open->position=new_size;
    if (new_size>old_size) { open->file->size=new_size; fixture_total_bytes+=growth; }
    open->file->written=1;
    *transferred=requested; return 0;
}
static uint16_t fixture_close(void *user,void *file) {
    (void)user;
    fixture_open_state *open=(fixture_open_state *)file;
    if (!open || !open->active) return 6u;
    memset(open,0,sizeof(*open)); return 0;
}
static uint16_t fixture_ioctl_info(void *user,void *file,uint16_t *info) {
    (void)user; fixture_open_state *open=(fixture_open_state *)file;
    if (!open || !open->active || !open->file || !info) return 6u;
    if (open->file->attributes==0xffffu) return 5u;
    *info=(uint16_t)(2u | (open->file->written ? 0u : 0x40u));
    return 0;
}
static uint16_t fixture_seek(void *user,void *file,int32_t displacement,uint8_t origin,uint32_t *position) {
    (void)user; fixture_open_state *open=(fixture_open_state *)file;
    if (!open || !open->active || !open->file || !position) return 6u;
    int64_t base=origin==0u?0:(origin==1u?open->position:open->file->size);
    int64_t next=base+displacement;
    if (origin>2u || next<0 || next>UINT32_MAX) return 1u;
    open->position=(uint32_t)next; *position=open->position; return 0;
}
static uint16_t fixture_stream_read(void *user,uint8_t *buffer,uint16_t requested,uint16_t *done) {
    (void)user; (void)buffer; if (!done) return 6u; *done=requested; return 0;
}
static uint16_t fixture_stream_write(void *user,const uint8_t *buffer,uint16_t requested,uint16_t *done) {
    (void)user; (void)buffer; if (!done) return 6u; *done=requested; return 0;
}
static int alloc(gw_dos_services *host,uint32_t bytes) {
    g_eax=0xaaaa0501u; g_ebx=0xbbbb0000u | (bytes>>16); g_ecx=0xcccc0000u | (bytes&0xffffu);
    g_esi=0xdddd1111u; g_edi=0xeeee2222u; g_flag_cf=0;
    return gw_dos_services_callback(0x31,0x12345678,host)==GW_INTERRUPT_HANDLED;
}

static int set_guest_path(uint8_t *memory,uint32_t size,const char *path) {
    size_t n=strlen(path)+1u;
    if (0x100u+n>size) return 0;
    memcpy(memory+0x100u,path,n); return 1;
}
static int open_path(gw_dos_services *host,const char *path,uint8_t mode,
                     uint32_t memory_size,uint32_t *handle) {
    if (!set_guest_path((uint8_t *)(uintptr_t)g_mem_base,memory_size,path)) return 0;
    g_eax=0x3d00u|mode; g_ebx=0x12345678u; g_ecx=0x87654321u;
    g_edx=0x100u; g_esi=0x11112222u; g_edi=0x33334444u; g_flag_cf=1;
    if (gw_dos_services_callback(0x21u,0x1234u,host)!=GW_INTERRUPT_HANDLED) return 0;
    if (g_flag_cf) return 0;
    *handle=(uint16_t)g_eax;
    return g_ebx==0x12345678u && g_ecx==0x87654321u &&
           g_edx==0x100u && g_esi==0x11112222u && g_edi==0x33334444u;
}
static int test_native_ah3d_contract(void) {
    const uint32_t memory_size=0x20000u;
    uint8_t *memory=(uint8_t *)calloc(memory_size,1);
    gw_dos_services host; memset(&host,0,sizeof host);
    if (!memory) return 0;
    memset(fixture_files,0,sizeof fixture_files); memset(fixture_opens,0,sizeof fixture_opens);
    memset(&fixture_last_attributes,0,sizeof fixture_last_attributes); fixture_total_bytes=0;
    strcpy(fixture_files[0].name,"fixture.txt");
    memcpy(fixture_files[0].bytes,"native fixture!",15u); fixture_files[0].size=15u;
    fixture_total_bytes=15u; g_mem_base=(ptrdiff_t)(uintptr_t)memory;
    g_seg_ds=0x14u; g_ds_base=0; g_seg_cs=g_seg_es=g_seg_ss=0x14u;
    recomp_set_memory_bounds(0,memory_size); recomp_clear_memory_fault();
    if (!gw_dos_guest_memory_configure(&host,memory_size) ||
        !gw_dos_file_backend_configure(&host,fixture_open,fixture_read,fixture_create,
                                       fixture_write,fixture_close,0) ||
        !gw_dos_file_ioctl_info_configure(&host,fixture_ioctl_info) ||
        !gw_dos_file_seek_configure(&host,fixture_seek)) {
        free(memory); return 0;
    }
    uint32_t handle=0;
    if (!open_path(&host,"fixture.txt",0,memory_size,&handle) || handle!=5u) goto fail;
    g_eax=0x4200u; g_ebx=handle; g_ecx=0; g_edx=3; g_esi=0x11112222u;
    g_flag_cf=1;
    if (gw_dos_services_callback(0x21u,0x1235u,&host)!=GW_INTERRUPT_HANDLED ||
        g_eax!=3u || g_edx!=0u || g_ebx!=handle || g_ecx!=0u ||
        g_esi!=0x11112222u || g_flag_cf) goto fail;
    g_eax=0x4201u; g_ebx=handle; g_ecx=0xffffu; g_edx=0xffffu; g_flag_cf=0;
    if (gw_dos_services_callback(0x21u,0x1235u,&host)!=GW_INTERRUPT_HANDLED ||
        g_flag_cf || (uint16_t)g_eax!=2u) goto fail;
    g_eax=0x4202u; g_ebx=handle; g_ecx=0; g_edx=0; g_flag_cf=1;
    if (gw_dos_services_callback(0x21u,0x1235u,&host)!=GW_INTERRUPT_HANDLED ||
        g_flag_cf || (uint16_t)g_eax!=15u) goto fail;
    g_eax=0x4203u; g_ebx=handle; g_ecx=0; g_edx=0;
    if (gw_dos_services_callback(0x21u,0x1235u,&host)!=GW_INTERRUPT_HANDLED ||
        !g_flag_cf || (uint16_t)g_eax!=1u) goto fail;
    g_eax=0x4200u; g_ebx=0xffffu; g_ecx=0; g_edx=0; g_flag_cf=0;
    if (gw_dos_services_callback(0x21u,0x1235u,&host)!=GW_INTERRUPT_HANDLED ||
        !g_flag_cf || (uint16_t)g_eax!=6u) goto fail;
    g_eax=0x4200u; g_ebx=handle; g_ecx=0; g_edx=0; g_flag_cf=1;
    if (gw_dos_services_callback(0x21u,0x1235u,&host)!=GW_INTERRUPT_HANDLED || g_flag_cf ||
        (uint16_t)g_eax!=0u || (uint16_t)g_edx!=0u) goto fail;
    g_eax=0xabcd4400u; g_ebx=handle; g_ecx=0x87654321u; g_edx=0x12340005u;
    g_esi=0x11112222u; g_edi=0x33334444u; g_ebp=0x55556666u;
    g_flag_cf=1; g_flag_k=7; g_flag_a=8; g_flag_b=9;
    /* DOS INT 21h/4400 returns the information word in DX; AX is
     * documented as changed, so do not require the incoming AX value. */
    if (gw_dos_services_callback(0x21u,0x1235u,&host)!=GW_INTERRUPT_HANDLED ||
        g_ebx!=handle || g_ecx!=0x87654321u || g_edx!=0x12340042u ||
        g_esi!=0x11112222u || g_edi!=0x33334444u || g_ebp!=0x55556666u || g_flag_cf ||
        g_flag_k!=7 || g_flag_a!=8 || g_flag_b!=9) goto fail;
    gw_dos_services no_ioctl=host; no_ioctl.file_ioctl_info=0;
    g_eax=0x4400u; g_ebx=handle; g_edx=5; g_flag_cf=0;
    if (gw_dos_services_callback(0x21u,0x1235u,&no_ioctl)!=GW_INTERRUPT_TRAPPED) goto fail;
    /* Configured standard streams are character devices; distinguish input
     * from output through the documented low classification bits. */
    gw_dos_services stdio_host; memset(&stdio_host,0,sizeof stdio_host);
    if (!gw_dos_stream_configure(&stdio_host,0,fixture_stream_read,0,0,1) ||
        !gw_dos_stream_configure(&stdio_host,1,0,fixture_stream_write,0,1)) goto fail;
    g_eax=0x4400u; g_ebx=0; g_edx=0x11110005u; g_flag_cf=1;
    if (gw_dos_services_callback(0x21u,0x1235u,&stdio_host)!=GW_INTERRUPT_HANDLED ||
        g_flag_cf || g_edx!=0x11110081u) goto fail;
    g_eax=0x4400u; g_ebx=1; g_edx=0x22220005u; g_flag_cf=1;
    if (gw_dos_services_callback(0x21u,0x1235u,&stdio_host)!=GW_INTERRUPT_HANDLED ||
        g_flag_cf || g_edx!=0x22220082u) goto fail;
    g_eax=0x4400u; g_ebx=2; g_edx=0; g_flag_cf=0;
    if (gw_dos_services_callback(0x21u,0x1235u,&stdio_host)!=GW_INTERRUPT_HANDLED ||
        g_flag_cf || g_edx!=0x0082u) goto fail;
    fixture_find("fixture.txt")->attributes=0xffffu;
    g_eax=0x4400u; g_ebx=handle; g_edx=7u; g_flag_cf=0;
    if (gw_dos_services_callback(0x21u,0x1235u,&host)!=GW_INTERRUPT_HANDLED ||
        !g_flag_cf || (uint16_t)g_eax!=5u || g_edx!=7u) goto fail;
    fixture_find("fixture.txt")->attributes=0;
    g_eax=0x4400u; g_ebx=0xffffu; g_edx=0x55u; g_flag_cf=0;
    if (gw_dos_services_callback(0x21u,0x1235u,&host)!=GW_INTERRUPT_HANDLED ||
        !g_flag_cf || (uint16_t)g_eax!=6u || g_edx!=0x55u) goto fail;
    g_eax=0x3f00u; g_ebx=handle; g_ecx=8u; g_edx=0x10200u; g_flag_cf=1;
    if (gw_dos_services_callback(0x21u,0x1235u,&host)!=GW_INTERRUPT_HANDLED ||
        g_flag_cf || (uint16_t)g_eax!=8u || memcmp(memory+0x10200u,"native f",8u)) goto fail;
    g_eax=0x3e00u; g_ebx=handle; g_flag_cf=1;
    if (gw_dos_services_callback(0x21u,0x1236u,&host)!=GW_INTERRUPT_HANDLED || g_flag_cf) goto fail;
    g_eax=0x3e00u; g_ebx=handle; g_flag_cf=0;
    if (gw_dos_services_callback(0x21u,0x1236u,&host)!=GW_INTERRUPT_HANDLED ||
        !g_flag_cf || (uint16_t)g_eax!=6u) goto fail;
    g_eax=0x4400u; g_ebx=handle; g_edx=0x12340005u; g_flag_cf=0;
    if (gw_dos_services_callback(0x21u,0x1236u,&host)!=GW_INTERRUPT_HANDLED ||
        !g_flag_cf || (uint16_t)g_eax!=6u || g_edx!=0x12340005u) goto fail;

    if (!open_path(&host,"C:\\GENEWARS\\fixture.txt",1,memory_size,&handle) || handle!=5u) goto fail;
    g_eax=0x3f00u; g_ebx=handle; g_ecx=1; g_edx=0x200; g_flag_cf=0;
    if (gw_dos_services_callback(0x21u,0x1235u,&host)!=GW_INTERRUPT_HANDLED ||
        !g_flag_cf || (uint16_t)g_eax!=5u) goto fail;
    g_eax=0x3e00u; g_ebx=handle;
    if (gw_dos_services_callback(0x21u,0x1236u,&host)!=GW_INTERRUPT_HANDLED || g_flag_cf) goto fail;

    /* AH=3C creates a new allowlisted memory-only file, carries CX attributes,
     * returns the DOS handle, and feeds AH=40 then AH=3F after close/reopen. */
    if (!set_guest_path(memory,memory_size,"quota.txt")) goto fail;
    g_eax=0x3c00u; g_ecx=0x0022u; g_edx=0x100u; g_flag_cf=1;
    if (gw_dos_services_callback(0x21u,0x1237u,&host)!=GW_INTERRUPT_HANDLED ||
        g_flag_cf || (uint16_t)g_eax!=5u || fixture_last_attributes!=0x22u) goto fail;
    handle=(uint16_t)g_eax; memcpy(memory+0x300u,"quota-data",10u);
    g_eax=0x4400u; g_ebx=handle; g_edx=0x12340005u; g_flag_cf=1;
    if (gw_dos_services_callback(0x21u,0x1237u,&host)!=GW_INTERRUPT_HANDLED ||
        g_flag_cf || g_edx!=0x12340042u) goto fail;
    g_eax=0x4000u; g_ebx=handle; g_ecx=10u; g_edx=0x300u; g_flag_cf=1;
    if (gw_dos_services_callback(0x21u,0x1238u,&host)!=GW_INTERRUPT_HANDLED || g_flag_cf || (uint16_t)g_eax!=10u) goto fail;
    g_eax=0x4400u; g_ebx=handle; g_edx=5u; g_flag_cf=1;
    if (gw_dos_services_callback(0x21u,0x1238u,&host)!=GW_INTERRUPT_HANDLED ||
        g_flag_cf || g_edx!=2u) goto fail;
    g_eax=0x3e00u; g_ebx=handle;
    if (gw_dos_services_callback(0x21u,0x1239u,&host)!=GW_INTERRUPT_HANDLED || g_flag_cf) goto fail;
    if (!open_path(&host,"quota.txt",0,memory_size,&handle)) goto fail;
    g_eax=0x3f00u; g_ebx=handle; g_ecx=10u; g_edx=0x400u; g_flag_cf=1;
    if (gw_dos_services_callback(0x21u,0x123au,&host)!=GW_INTERRUPT_HANDLED || g_flag_cf ||
        (uint16_t)g_eax!=10u || memcmp(memory+0x400u,"quota-data",10u)) goto fail;
    g_eax=0x3e00u; g_ebx=handle;
    if (gw_dos_services_callback(0x21u,0x123bu,&host)!=GW_INTERRUPT_HANDLED || g_flag_cf) goto fail;
    /* Creating an existing name truncates it. */
    if (!set_guest_path(memory,memory_size,"quota.txt")) goto fail;
    g_eax=0x3c00u; g_ecx=0x0001u; g_edx=0x100u; g_flag_cf=1;
    if (gw_dos_services_callback(0x21u,0x123cu,&host)!=GW_INTERRUPT_HANDLED || g_flag_cf ||
        fixture_find("quota.txt")->size!=0u || fixture_last_attributes!=1u) goto fail;
    handle=(uint16_t)g_eax; g_eax=0x3e00u; g_ebx=handle;
    if (gw_dos_services_callback(0x21u,0x1236u,&host)!=GW_INTERRUPT_HANDLED || g_flag_cf) goto fail;

    /* A write larger than per-file quota fails atomically with disk-full 112. */
    if (!set_guest_path(memory,memory_size,"quota.txt")) goto fail;
    g_eax=0x3c00u; g_ecx=0; g_edx=0x100u;
    if (gw_dos_services_callback(0x21u,0x123du,&host)!=GW_INTERRUPT_HANDLED || g_flag_cf) goto fail;
    handle=(uint16_t)g_eax; memset(memory+0x500u,'Q',17u);
    g_eax=0x4000u; g_ebx=handle; g_ecx=17u; g_edx=0x500u; g_flag_cf=0;
    if (gw_dos_services_callback(0x21u,0x123eu,&host)!=GW_INTERRUPT_HANDLED || !g_flag_cf ||
        (uint16_t)g_eax!=112u || fixture_find("quota.txt")->size!=0u) goto fail;
    g_eax=0x3e00u; g_ebx=handle;
    if (gw_dos_services_callback(0x21u,0x123fu,&host)!=GW_INTERRUPT_HANDLED || g_flag_cf) goto fail;

    /* Global quota: fixture.txt uses 15 bytes and the per-file limit is 16.
     * A 16-byte write would fit per-file but exceed the provider total of 30. */
    if (!set_guest_path(memory,memory_size,"global1.txt")) goto fail;
    g_eax=0x3c00u; g_ecx=0; g_edx=0x100u;
    if (gw_dos_services_callback(0x21u,0x1240u,&host)!=GW_INTERRUPT_HANDLED || g_flag_cf) goto fail;
    handle=(uint16_t)g_eax; memset(memory+0x600u,'G',16u);
    g_eax=0x4000u; g_ebx=handle; g_ecx=16u; g_edx=0x600u;
    if (gw_dos_services_callback(0x21u,0x1241u,&host)!=GW_INTERRUPT_HANDLED || !g_flag_cf || (uint16_t)g_eax!=112u) goto fail;
    g_eax=0x3e00u; g_ebx=handle;
    if (gw_dos_services_callback(0x21u,0x1242u,&host)!=GW_INTERRUPT_HANDLED || g_flag_cf) goto fail;

    /* DOS's 32-slot handle table returns error 4 without corrupting slots. */
    for (unsigned i=0;i<GW_DOS_MAX_OPEN_FILES;i++) {
        if (!open_path(&host,"fixture.txt",0,memory_size,&handle)) goto fail;
    }
    if (!set_guest_path(memory,memory_size,"fixture.txt")) goto fail;
    g_eax=0x3c00u; g_ecx=0; g_edx=0x100u; g_flag_cf=0;
    if (gw_dos_services_callback(0x21u,0x1243u,&host)!=GW_INTERRUPT_HANDLED || !g_flag_cf || (uint16_t)g_eax!=4u) goto fail;
    for (unsigned i=0;i<GW_DOS_MAX_OPEN_FILES;i++) {
        g_eax=0x3e00u; g_ebx=(uint16_t)(5u+i);
        if (gw_dos_services_callback(0x21u,0x1244u,&host)!=GW_INTERRUPT_HANDLED || g_flag_cf) goto fail;
    }
    if (!open_path(&host,"fixture.txt",2,memory_size,&handle) || handle!=5u) goto fail;
    g_eax=0x3e00u; g_ebx=handle;
    if (gw_dos_services_callback(0x21u,0x1236u,&host)!=GW_INTERRUPT_HANDLED || g_flag_cf) goto fail;

    if (!set_guest_path(memory,memory_size,"C:\\address.txt")) goto fail;
    g_eax=0x3d01u; g_edx=0x100u; g_flag_cf=0;
    if (gw_dos_services_callback(0x21u,0x000afcc4u,&host)!=GW_INTERRUPT_HANDLED ||
        !g_flag_cf || (uint16_t)g_eax!=2u) goto fail;
    if (!set_guest_path(memory,memory_size,"D:\\fixture.txt")) goto fail;
    g_eax=0x3d00u; g_edx=0x100u; g_flag_cf=0;
    if (gw_dos_services_callback(0x21u,0x1234u,&host)!=GW_INTERRUPT_HANDLED ||
        !g_flag_cf || (uint16_t)g_eax!=15u) goto fail;
    if (!set_guest_path(memory,memory_size,"..\\escape.txt")) goto fail;
    g_eax=0x3c00u; g_ecx=0; g_edx=0x100u; g_flag_cf=0;
    if (gw_dos_services_callback(0x21u,0x1234u,&host)!=GW_INTERRUPT_HANDLED ||
        !g_flag_cf || (uint16_t)g_eax!=5u) goto fail;
    if (!set_guest_path(memory,memory_size,"..\\escape.txt")) goto fail;
    g_eax=0x3d00u; g_edx=0x100u; g_flag_cf=0;
    if (gw_dos_services_callback(0x21u,0x1234u,&host)!=GW_INTERRUPT_HANDLED ||
        !g_flag_cf || (uint16_t)g_eax!=5u) goto fail;
    if (!set_guest_path(memory,memory_size,"D:\\fixture.txt")) goto fail;
    g_eax=0x3c00u; g_ecx=0; g_edx=0x100u; g_flag_cf=0;
    if (gw_dos_services_callback(0x21u,0x1234u,&host)!=GW_INTERRUPT_HANDLED ||
        !g_flag_cf || (uint16_t)g_eax!=15u) goto fail;
    if (!set_guest_path(memory,memory_size,"fixture.txt")) goto fail;
    g_eax=0x3d03u; g_edx=0x100u; g_flag_cf=0;
    if (gw_dos_services_callback(0x21u,0x1234u,&host)!=GW_INTERRUPT_HANDLED ||
        !g_flag_cf || (uint16_t)g_eax!=12u) goto fail;
    g_eax=0x3d00u; g_edx=memory_size+8u; g_flag_cf=0;
    if (gw_dos_services_callback(0x21u,0x1234u,&host)!=GW_INTERRUPT_HANDLED ||
        !g_flag_cf || (uint16_t)g_eax!=3u) goto fail;
    g_eax=0x3c00u; g_ecx=0; g_edx=0x20008u; g_flag_cf=0;
    if (gw_dos_services_callback(0x21u,0x1234u,&host)!=GW_INTERRUPT_HANDLED ||
        !g_flag_cf || (uint16_t)g_eax!=3u) goto fail;
    gw_dos_services unconfigured; memset(&unconfigured,0,sizeof unconfigured);
    g_eax=0x3c00u; g_ecx=0; g_edx=0x100u;
    if (gw_dos_services_callback(0x21u,0x1234u,&unconfigured)!=GW_INTERRUPT_TRAPPED) goto fail;
    g_eax=0x3f00u; g_ebx=0x777u; g_ecx=1; g_edx=0x200; g_flag_cf=0;
    if (gw_dos_services_callback(0x21u,0x1235u,&host)!=GW_INTERRUPT_HANDLED ||
        !g_flag_cf || (uint16_t)g_eax!=6u) goto fail;
    free(memory); g_mem_base=0; return 1;
fail:
    free(memory); g_mem_base=0; return 0;
}
int main(void) {
    gw_dos_services h; memset(&h,0,sizeof h);
    static uint8_t allocation_memory[0x301000u];
    if (!test_native_ah3d_contract()) return 12;
    gw_dos_services unmapped; memset(&unmapped,0,sizeof unmapped);
    if (!gw_dos_linear_allocator_configure(&unmapped,0x200000u,0x301000u)) return 13;
    if (!alloc(&unmapped,0x1000u) || !g_flag_cf || (uint16_t)g_eax!=0x8012u ||
        unmapped.allocation_cursor!=0x200000u) return 14;
    g_mem_base=(ptrdiff_t)(uintptr_t)allocation_memory;
    recomp_set_memory_bounds(0,sizeof allocation_memory);
    if (!gw_dos_guest_memory_configure(&h,0x301000u)) return 15;
    if (!gw_dos_linear_allocator_configure(&h,0x200123,0x203000)) return 2;
    if (!alloc(&h,0x1000)||g_flag_cf || g_eax!=0xaaaa0501u ||
        g_ebx!=0xbbbb0020u || g_ecx!=0xcccc1000u || g_esi!=0xdddd0000u || g_edi!=0xeeee0001u) return 3;
    if (allocation_memory[0x201000u]!=0 || allocation_memory[0x201fffu]!=0) return 17;
    allocation_memory[0x201000u]=0xA5u;
    if (!alloc(&h,0x1000)||g_flag_cf || g_ebx!=0xbbbb0020u || g_ecx!=0xcccc2000u || g_edi!=0xeeee0002u) return 4;
    if (allocation_memory[0x202000u]!=0 || allocation_memory[0x202fffu]!=0) return 18;
    if (h.allocation_cursor!=0x203000u || h.next_allocation_handle!=3u) return 5;
    if (!alloc(&h,1)||!g_flag_cf || (uint16_t)g_eax!=0x8012u ||
        g_ebx!=0xbbbb0000u || g_ecx!=0xcccc0001u ||
        g_esi!=0xdddd1111u || g_edi!=0xeeee2222u) return 6;
    if (gw_dos_linear_allocator_configure(&h,0x1000,0x2000)==0) return 7;
    if (!gw_dos_linear_allocator_configure(&h,0xfffff000u,0xffffffffu)) return 8;
    if (!alloc(&h,0x1000u)||!g_flag_cf || (uint16_t)g_eax!=0x8012u ||
        h.allocation_cursor!=0xfffff000u) return 16;
    if (!alloc(&h,0x2000)||!g_flag_cf || (uint16_t)g_eax!=0x8012u ||
        g_ebx!=0xbbbb0000u || g_ecx!=0xcccc2000u ||
        g_esi!=0xdddd1111u || g_edi!=0xeeee2222u) return 9;
    if (!gw_dos_linear_allocator_configure(&h,0x300000,0x301000)) return 10;
    if (!alloc(&h,0)||!g_flag_cf || (uint16_t)g_eax!=0x8021u ||
        g_ebx!=0xbbbb0000u || g_ecx!=0xcccc0000u ||
        g_esi!=0xdddd1111u || g_edi!=0xeeee2222u) return 11;
    puts("PASS DPMI 0501 allocator and DOS AH=3D/3C/3F/40/3E bounded virtual-file lifecycle");
    return 0;
}
