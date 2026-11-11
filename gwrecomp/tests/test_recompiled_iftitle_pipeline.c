#define RECOMP_GENERATED_CODE
#define RECOMP_LOCAL_REGS
#include "recomp_types.h"
#include "recomp_context.h"
#include "gw_interrupts.h"
#include "gw_dos_services.h"
#include "gw_segments.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void gw_partial_LbFileOpen(void);
void gw_partial_LbFileRead(void);
void gw_partial_UnpackM1(void);
void recomp_gw_partial_W_init_n_v(void);
void recomp_gw_partial_W_init_n_v_0(void);
void recomp_gw_partial_W_init_n_v_1(void);
int gw_recomp_guest_instruction(unsigned int guest_va);

uint32_t g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,g_cur_func;
uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_fs,g_seg_gs,g_seg_ss,g_fpu_cw;
uint32_t g_fs_base,g_gs_base;
ptrdiff_t g_mem_base;
double g_st[8]; int g_fp_top;
uint32_t g_icall_trace[ICALL_TRACE_SIZE],g_icall_from[ICALL_TRACE_SIZE];
uint32_t g_icall_trace_idx,g_icall_count;

enum { GUEST_SIZE=0x400000u, IMAGE_BASE=0xF0000u, LIST=0x2DFEE8u,
       STACK=0x3FE000u, FILE_BUFFER=0x390000u };

typedef struct { FILE *fp; } host_file;
typedef struct {
    gw_dos_services dos;
    const char *root;
    unsigned opens,reads,closes;
    char opened_path[260];
    uint8_t opened_access;
} fixture_vfs;

static fixture_vfs vfs;

recomp_func_t recomp_lookup_manual(uint32_t va) { (void)va; return NULL; }
recomp_func_t recomp_lookup_import(uint32_t va) { (void)va; return NULL; }
recomp_func_t recomp_lookup(uint32_t va) { (void)va; return NULL; }

static int in_guest(uint16_t selector,uint32_t offset,uint32_t width,void *user) {
    (void)user;
    if (selector!=0x14u || !width || offset>GUEST_SIZE || width>GUEST_SIZE-offset) return 0;
    if (offset>=0x2DA000u && offset+width<=0x382C50u) return 1;
    if (offset>=LIST && offset+width<=LIST+4u*44u) return 1;
    if (offset>=FILE_BUFFER && offset+width<=FILE_BUFFER+0x10000u) return 1;
    if (offset>=0x3A0000u && offset+width<=0x3B0000u) return 1;
    if (offset>=0x3FD000u && offset+width<=GUEST_SIZE) return 1;
    return 0;
}

static uint16_t host_open(void *user,const char *path,uint8_t access,void **out) {
    fixture_vfs *s=(fixture_vfs *)user;
    if (!s || !path || !out || access!=0u ||
        (_stricmp(path,"data/iftitle.anb") && _stricmp(path,"data/titlescr.pal") &&
         _stricmp(path,"data/font2.dat") && _stricmp(path,"data/font2.tab"))) return 2u;
    host_file *h=(host_file *)calloc(1,sizeof *h);
    if (!h) return 8u;
    char full[512];
    if (_snprintf(full,sizeof full,"%s\\DATA\\%s",s->root,path+5)<0) { free(h); return 3u; }
    for (char *p=full;*p;p++) if (*p=='/') *p='\\';
    h->fp=fopen(full,"rb");
    if (!h->fp) { free(h); return 2u; }
    s->opens++; s->opened_access=access;
    strncpy(s->opened_path,path,sizeof s->opened_path-1u);
    *out=h;
    return 0;
}

static uint16_t host_read(void *user,void *file,uint8_t *buffer,uint16_t requested,uint16_t *done) {
    fixture_vfs *s=(fixture_vfs *)user; host_file *h=(host_file *)file;
    if (!s || !h || !h->fp || !buffer || !done) return 6u;
    *done=(uint16_t)fread(buffer,1,requested,h->fp); s->reads++;
    return ferror(h->fp)?5u:0u;
}

static uint16_t host_close(void *user,void *file) {
    fixture_vfs *s=(fixture_vfs *)user; host_file *h=(host_file *)file;
    if (!s || !h || !h->fp) return 6u;
    fclose(h->fp); h->fp=NULL; free(h); s->closes++;
    return 0;
}

static uint16_t host_ioctl(void *user,void *file,uint16_t *info) {
    (void)user; if (!file || !info) return 6u;
    *info=0; /* regular disk file: DOS device bit clear */
    return 0;
}

static int run_original(void (*fn)(void),gw_recomp_context *c,uint32_t entry,uint8_t *memory,
                        uint32_t eax,uint32_t ebx,uint32_t edx) {
    memset(c,0,sizeof *c); c->esp=STACK; c->eip=entry;
    c->eax=eax; c->ebx=ebx; c->edx=edx;
    c->cs=0x0Cu; c->ds=0x14u; c->es=0x14u; c->ss=0x14u;
    c->mem_base=(ptrdiff_t)(uintptr_t)memory; c->mem_guest_base=0; c->mem_size=GUEST_SIZE;
    c->pit_initialized=1; *(uint32_t *)(memory+STACK)=RECOMP_RETADDR;
    return gw_recomp_invoke(fn,c)==GW_RECOMP_OK && !c->memory_fault.pending &&
           !c->segment_fault_pending && !c->interrupt_trap_pending;
}

static int find_active_handle(uint8_t *handle) {
    for (unsigned i=0;i<GW_DOS_MAX_OPEN_FILES;i++) if (vfs.dos.files[i].active) {
        *handle=vfs.dos.files[i].dos_handle; return 1;
    }
    return 0;
}

int main(int argc,char **argv) {
    if (argc!=3) { fprintf(stderr,"usage: test_recompiled_file_open <guest-image.bin> <1.1-install-root>\n"); return 2; }
    uint8_t *memory=(uint8_t *)calloc(GUEST_SIZE,1u); if (!memory) return 3;
    FILE *image=fopen(argv[1],"rb"); if (!image) { free(memory); return 4; }
    if (fseek(image,0,SEEK_END) || ftell(image)<0) { fclose(image); free(memory); return 5; }
    long image_size=ftell(image); rewind(image);
    if ((uint64_t)IMAGE_BASE+(uint64_t)image_size>GUEST_SIZE ||
        fread(memory+IMAGE_BASE,1,(size_t)image_size,image)!=(size_t)image_size) {
        fclose(image); free(memory); return 6;
    }
    fclose(image);
    if (strcmp((char *)(memory+LIST),"data/iftitle.anb") ||
        strcmp((char *)(memory+LIST+44u),"data/titlescr.pal")) {
        fprintf(stderr,"LE titleGfx_files first records differ from expected 1.1 data\n"); free(memory); return 7;
    }
    vfs.root=argv[2]; memset(&vfs.dos,0,sizeof vfs.dos);
    gw_dos_services_init(&vfs.dos);
    if (!gw_dos_guest_memory_configure(&vfs.dos,GUEST_SIZE) ||
        !gw_dos_file_backend_configure(&vfs.dos,host_open,host_read,NULL,NULL,host_close,&vfs) ||
        !gw_dos_file_ioctl_info_configure(&vfs.dos,host_ioctl)) { free(memory); return 8; }
    recomp_set_segment_range_validator(in_guest,NULL);
    recomp_code_range code={0x1FB000u,0x10000u,0xDE930u};
    if (!recomp_code_map_set(&code,1u)) { free(memory); return 9; }

    /* These three Watcom priority-0A __InitRtns entries install the original
     * I/O mode tables consumed by the original sopen/open helpers. */
    gw_recomp_context c;
    const struct { void (*fn)(void); uint32_t va; } init[] = {
        {recomp_gw_partial_W_init_n_v,0xBC1F6u},
        {recomp_gw_partial_W_init_n_v_0,0xC3584u},
        {recomp_gw_partial_W_init_n_v_1,0xC3882u}
    };
    for (unsigned i=0;i<sizeof init/sizeof init[0];i++)
        if (!run_original(init[i].fn,&c,init[i].va,memory,0,0,0)) {
            fprintf(stderr,"original Watcom I/O init %08X failed\n",init[i].va); free(memory); return 10;
        }

    if (!run_original(gw_partial_LbFileOpen,&c,0x98C70u,memory,LIST,0,2u)) {
        fprintf(stderr,"original LbFileOpen faulted at eip=%08X int=%u/%u memory=%u insn=%08X/%08X segment=%u/%04X\n",
                c.eip,c.interrupt_trap_pending,c.interrupt_instruction_va,c.memory_fault.pending,
                c.memory_fault.instruction_va,c.memory_fault.linear,c.segment_fault_pending,c.segment_fault_selector);
        free(memory); return 11;
    }
    uint8_t handle=0;
    if (vfs.opens<2u || vfs.closes!=1u || !find_active_handle(&handle) ||
        strcmp(vfs.opened_path,"data/iftitle.anb") || vfs.opened_access!=0u ||
        (uint16_t)c.eax!=handle) {
        fprintf(stderr,"original LbFileOpen did not produce expected VFS handle/path: opens=%u path='%s' mode=%u eax=%08X\n",
                vfs.opens,vfs.opened_path,vfs.opened_access,c.eax); free(memory); return 12;
    }
    printf("PASS recompiled GeneWars 1.1 LbFileOpen 0x98C70 opened titleGfx_files[0] (TbLoadFiles) path='%s' via DOS AH=3D handle=%u access=%u\n",
           vfs.opened_path,handle,vfs.opened_access);
    memset(memory+FILE_BUFFER,0xCC,0x7562u);
    if (!run_original(gw_partial_LbFileRead,&c,0x98D70u,memory,
                      handle,0x7562u,FILE_BUFFER)) {
        fprintf(stderr,"original LbFileRead_ faulted at eip=%08X int=%u/%u memory=%u insn=%08X/%08X\n",
                c.eip,c.interrupt_trap_pending,c.interrupt_instruction_va,c.memory_fault.pending,
                c.memory_fault.instruction_va,c.memory_fault.linear); free(memory); return 14;
    }
    if (vfs.reads==0u || c.eax!=0x7562u ||
        memcmp(memory+FILE_BUFFER,"RNC\x01",4u)!=0 ||
        *(uint32_t *)(memory+FILE_BUFFER+4u)!=0x49E30000u) {
        fprintf(stderr,"original LbFileRead_ did not return verified IFTITLE bytes: eax=%08X reads=%u header=%02X%02X%02X%02X size=%02X%02X%02X%02X\n",
                c.eax,vfs.reads,memory[FILE_BUFFER],memory[FILE_BUFFER+1u],memory[FILE_BUFFER+2u],memory[FILE_BUFFER+3u],
                memory[FILE_BUFFER+4u],memory[FILE_BUFFER+5u],memory[FILE_BUFFER+6u],memory[FILE_BUFFER+7u]);
        free(memory); return 15;
    }
    FILE *capture=fopen("work\\recompiled_file_open_readback.bin","wb");
    if (!capture || fwrite(memory+FILE_BUFFER,1,0x7562u,capture)!=0x7562u) {
        if (capture) fclose(capture); free(memory); return 16;
    }
    fclose(capture);
    printf("PASS recompiled GeneWars 1.1 LbFileRead_ 0x98D70 read %u bytes to guest 0x%08X from handle %u\n",
           c.eax,FILE_BUFFER,handle);
    enum { OUTPUT=0x3A0000u, OUTPUT_SIZE=0xE349u, GUARD=32u };
    memset(memory+OUTPUT-GUARD,0xA7,GUARD);
    memset(memory+OUTPUT,0xCC,0x10000u);
    memset(memory+OUTPUT+OUTPUT_SIZE,0xA7,GUARD);
    if (!run_original(gw_partial_UnpackM1,&c,0xB9CFCu,memory,FILE_BUFFER,0,OUTPUT)) {
        fprintf(stderr,"original RNC1 UnpackM1 faulted at eip=%08X memory=%u/%08X\n",
                c.eip,c.memory_fault.pending,c.memory_fault.linear); free(memory); return 17;
    }
    unsigned changed=0;
    for (unsigned i=0;i<OUTPUT_SIZE;i++) if (memory[OUTPUT+i]!=0xCCu) changed++;
    int guard_ok=1;
    for (unsigned i=0;i<GUARD;i++)
        if (memory[OUTPUT-GUARD+i]!=0xA7u || memory[OUTPUT+OUTPUT_SIZE+i]!=0xA7u)
            guard_ok=0;
    if (c.eax!=OUTPUT_SIZE || changed<OUTPUT_SIZE/2u || !guard_ok) {
        fprintf(stderr,"original RNC1 decode mismatch eax=%08X changed=%u guard=%02X/%02X ok=%u\n",
                c.eax,changed,memory[OUTPUT-GUARD],memory[OUTPUT+OUTPUT_SIZE],guard_ok); free(memory); return 18;
    }
    FILE *decoded=fopen("work\\recompiled_original_iftitle_decoded.bin","wb");
    if (!decoded || fwrite(memory+OUTPUT,1,OUTPUT_SIZE,decoded)!=OUTPUT_SIZE) {
        if (decoded) fclose(decoded); free(memory); return 19;
    }
    fclose(decoded);
    printf("PASS original GeneWars 1.1 UnpackM1 0xB9CFC decoded the VFS-read IFTITLE.ANB to guest 0x%08X (%u bytes)\n",
           OUTPUT,OUTPUT_SIZE);
    printf("TRACE opens=%u reads=%u closes_before_cleanup=%u active_handles=%u EAX=%08X ESP=%08X\n",
           vfs.opens,vfs.reads,vfs.closes,1u,c.eax,c.esp);

    /* Close through DOS services as test cleanup; the opening itself was done
     * by original recompiled code and no file bytes were modified. */
    g_eax=0x3E00u; g_ebx=handle; g_flag_cf=0;
    if (gw_dos_services_callback(0x21u,0xAFC8Du,&vfs.dos)!=GW_INTERRUPT_HANDLED ||
        g_flag_cf || vfs.dos.files[0].active) {
        fprintf(stderr,"DOS VFS cleanup failed for handle %u\n",handle); free(memory); return 13;
    }
    free(memory);
    puts("PASS read-only VFS close released the opened resource handle");
    return 0;
}
