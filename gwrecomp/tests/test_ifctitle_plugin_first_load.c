#include "recomp_context.h"
#include "gw_dos_services.h"
#include "gw_interrupts.h"
#include "gw_segments.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void gw_partial_LbDataLoad(void);
void gw_partial_LbDataLoadAll(void);
void gw_partial_LbMemorySetup(void);
void gw_partial_LbMemoryAlloc(void);
void gw_partial_LbMemoryAllocLow(void);
void gw_partial_UnpackM1(void);
void gw_partial_0x00092670(void);
void gw_partial_0x00014BB0(void);
void gw_partial_mem_putc(void);
void gw_partial_0x000830F0(void);
void gw_partial_0x0002C3D0(void);
void gw_partial_0x0002C520(void);
void gw_partial_0x0002C560(void);
void gw_partial_0x00034F50(void);
void gw_partial_0x000834A0(void);
void gw_partial_0x000957B0(void);
void gw_partial_0x00069C80(void);
void gw_partial_0x000957C0(void);
void gw_partial_0x000957E0(void);
void gw_partial_0x000957D0(void);
void gw_partial_0x00095830(void);
void gw_partial_0x00095880(void);
void gw_partial_0x00095890(void);
void gw_partial_0x000958E0(void);
void gw_original_ifctitle_plugin_first_load(void);
void gw_original_install_resource_callback(void);
int gw_partial_install_code_map(void);

uint32_t g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,g_cur_func;
uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_fs,g_seg_gs,g_seg_ss,g_fpu_cw;
uint32_t g_fs_base,g_gs_base;
ptrdiff_t g_mem_base;
double g_st[8]; int g_fp_top;
uint32_t g_flag_k,g_flag_a,g_flag_b,g_flag_cf;
uint32_t g_icall_trace[ICALL_TRACE_SIZE],g_icall_from[ICALL_TRACE_SIZE];
uint32_t g_icall_trace_idx,g_icall_count;

enum { GUEST_LIMIT=0x03002000u, IMAGE_BASE=0x000F0000u,
       STACK_TOP=0x003FF000u, TITLE_LIST=0x002DFEE8u,
       BLOCKS=0x00360C40u, ARENAS=0x00361840u, MAX_ENTRIES=256u,
       BLOCK_SIZE=12u, ARENA_SIZE=18u, FLAT_HEAP_BEGIN=0x01000000u,
       RNC_SOURCE=0x02200000u, RNC_OUT=0x02210000u,
       RNC_INPLACE=0x02220000u };

typedef struct { FILE *fp; int capture_rnc; } host_file;
typedef struct {
    gw_dos_services dos;
    const char *root;
    unsigned opens,reads,closes,denied;
    long read_pos[8];
    uint16_t read_requested[8], read_done[8];
    uint32_t read_guest[8];
    char last_path[260], first_path[260];
} fixture_vfs;

static fixture_vfs vfs;
static uint8_t *guest_memory;
static unsigned comparator_calls, dos_ed_calls, dos_4a_calls, dos_4a_failures;
static uint32_t rnc_call_eax, rnc_call_ecx, rnc_call_edx;
static int rnc_capture_pending;
static int capture_current_resource;
static void original_int31_thunk(void);

void gw_capture_lbdataload_rnc_args(uint32_t eax,uint32_t ecx,uint32_t edx) {
    if (!capture_current_resource) return;
    rnc_call_eax=eax; rnc_call_ecx=ecx; rnc_call_edx=edx;
    rnc_capture_pending=1;
}
void gw_capture_lbdataload_relocated_payload(uint32_t guest_va) {
    if(!rnc_capture_pending) return;
    rnc_capture_pending=0;
    uint32_t packed=*(uint32_t *)(guest_memory+0x002E56ECu);
    if(guest_va>GUEST_LIMIT || packed>GUEST_LIMIT-guest_va) return;
    FILE *f=fopen("work\\lbdataload_relocated_rnc_payload.bin","wb");
    if(!f) return;
    fwrite(guest_memory+guest_va,1,packed,f);
    fclose(f);
}

static int in_guest(uint16_t selector,uint32_t offset,uint32_t width,void *user) {
    (void)user;
    if (selector!=0x14u || !width || offset>GUEST_LIMIT || width>GUEST_LIMIT-offset) return 0;
    if ((offset>=0x001FB000u && offset+width<=0x002D9930u) ||
        (offset>=0x002DA000u && offset+width<=0x00382C50u) ||
        (offset>=FLAT_HEAP_BEGIN && offset+width<=GUEST_LIMIT) ||
        (offset>=STACK_TOP-0x3000u && offset+width<=GUEST_LIMIT)) return 1;
    for (uint32_t i=0;i<vfs.dos.dos_block_count;i++) {
        uint32_t begin=(uint32_t)vfs.dos.dos_blocks[i].segment<<4;
        uint32_t end=begin+((uint32_t)vfs.dos.dos_blocks[i].paragraphs<<4);
        if (offset>=begin && offset+width<=end) return 1;
    }
    return 0;
}

static uint16_t host_open(void *user,const char *path,uint8_t access,void **out) {
    fixture_vfs *s=(fixture_vfs *)user;
    static const struct { const char *guest,*host; int capture; } allowed[]={
        {"data/iftitle.anb","IFTITLE.ANB",1},
        {"data/titlescr.pal","TITLESCR.PAL",0},
        {"data/font2.dat","FONT2.DAT",0},
        {"data/font2.tab","FONT2.TAB",0}
    };
    const char *host_name=NULL; int capture=0;
    for (unsigned i=0;i<sizeof allowed/sizeof allowed[0];i++)
        if (path && !_stricmp(path,allowed[i].guest)) { host_name=allowed[i].host; capture=allowed[i].capture; break; }
    capture_current_resource=capture;
    if (!s || !path || !out || access!=0u || !host_name) {
        if (s) { s->denied++; if(path) strncpy(s->last_path,path,sizeof s->last_path-1u); }
        return 2u;
    }
    host_file *h=(host_file *)calloc(1,sizeof *h); if (!h) return 8u;
    char full[512];
    if (_snprintf(full,sizeof full,"%s\\DATA\\%s",s->root,host_name)<0) { free(h); return 3u; }
    h->fp=fopen(full,"rb");
    if (!h->fp) { free(h); return 2u; }
    h->capture_rnc=capture; s->opens++;
    if (!s->first_path[0]) strncpy(s->first_path,path,sizeof s->first_path-1u);
    strncpy(s->last_path,path,sizeof s->last_path-1u); *out=h; return 0;
}
static uint16_t host_read(void *user,void *file,uint8_t *buffer,uint16_t requested,uint16_t *done) {
    fixture_vfs *s=(fixture_vfs *)user; host_file *h=(host_file *)file;
    if (!s || !h || !h->fp || !buffer || !done) return 6u;
    unsigned slot=s->reads;
    long file_pos=ftell(h->fp);
    *done=(uint16_t)fread(buffer,1,requested,h->fp); s->reads++;
    if (slot<8u) {
        s->read_pos[slot]=file_pos;
        s->read_requested[slot]=requested;
        s->read_done[slot]=*done;
        s->read_guest[slot]=(uint32_t)((uintptr_t)buffer-(uintptr_t)guest_memory);
        if (h->capture_rnc && *done>4096u) {
            if (*done>GUEST_LIMIT-RNC_SOURCE) return 5u;
            memcpy(guest_memory+RNC_SOURCE,buffer,*done);
            FILE *capture=fopen("work\\lbdataload_compressed_capture.bin","wb");
            if (!capture || fwrite(buffer,1,*done,capture)!=*done) {
                if (capture) fclose(capture);
                return 5u;
            }
            fclose(capture);
        }
    }
    return ferror(h->fp)?5u:0u;
}
static uint16_t host_close(void *user,void *file) {
    fixture_vfs *s=(fixture_vfs *)user; host_file *h=(host_file *)file;
    if (!s || !h || !h->fp) return 6u;
    fclose(h->fp); h->fp=NULL; free(h); s->closes++; return 0;
}
static uint16_t host_ioctl(void *user,void *file,uint16_t *info) {
    (void)user; if (!file || !info) return 6u; *info=0; return 0;
}

recomp_func_t recomp_lookup(uint32_t va) {
    if (va==0x0002C3D0u) return gw_partial_0x0002C3D0;
    if (va==0x0002C520u) return gw_partial_0x0002C520;
    if (va==0x0002C560u) return gw_partial_0x0002C560;
    if (va==0x00034F50u) return gw_partial_0x00034F50;
    if (va==0x000834A0u) return gw_partial_0x000834A0;
    if (va==0x000957B0u) return gw_partial_0x000957B0;
    if (va==0x00069C80u) return gw_partial_0x00069C80;
    if (va==0x000957C0u) return gw_partial_0x000957C0;
    if (va==0x000957E0u) return gw_partial_0x000957E0;
    if (va==0x000957D0u) return gw_partial_0x000957D0;
    if (va==0x00095830u) return gw_partial_0x00095830;
    if (va==0x00095880u) return gw_partial_0x00095880;
    if (va==0x00095890u) return gw_partial_0x00095890;
    if (va==0x000958E0u) return gw_partial_0x000958E0;
    if (va==0x00092670u) { comparator_calls++; return gw_partial_0x00092670; }
    if (va==0x00091E00u) return gw_partial_LbMemoryAlloc;
    if (va==0x00091E90u) return gw_partial_LbMemoryAllocLow;
    /* Original 0x96B23 stores the object-1-relocated address 0x281B10 in
     * ECX; the code-range map resolves that guest pointer back to this LE VA. */
    if (va==0x00096B10u) return gw_partial_mem_putc;
    if (va==0x00014BB0u || va==0x001FFBB0u) return gw_partial_0x00014BB0;
    if ((va==0x000D23A7u || va==0x002BD3A7u) && guest_memory &&
        guest_memory[0x002BD3A7u]==0xCDu && guest_memory[0x002BD3A8u]==0x31u &&
        guest_memory[0x002BD3A9u]==0xC3u) return original_int31_thunk;
    return NULL;
}
recomp_func_t recomp_lookup_manual(uint32_t va) { return recomp_lookup(va); }
recomp_func_t recomp_lookup_import(uint32_t va) { (void)va; return NULL; }

static void original_int31_thunk(void) {
    if (gw_interrupt_dispatch(0x31u,0x000D23A7u)!=GW_INTERRUPT_HANDLED) return;
    if (*(const uint32_t *)(guest_memory+g_esp)!=RECOMP_RETADDR) return;
    g_esp+=4u;
}
static gw_interrupt_result dispatch(uint8_t vector,uint32_t instruction_va,void *user) {
    gw_interrupt_result r=gw_dos_services_callback(vector,instruction_va,user);
    if (vector==0x21u && instruction_va==0x000D7144u) dos_ed_calls++;
    if (vector==0x21u && (instruction_va==0x000D715Du || instruction_va==0x000D7170u)) {
        dos_4a_calls++; if (g_flag_cf) dos_4a_failures++;
    }
    return r;
}

static int invoke(void (*fn)(void),gw_recomp_context *c,uint32_t entry,
                  uint8_t *memory,uint32_t eax,uint32_t edx) {
    memset(c,0,sizeof *c); c->eip=entry; c->cur_func=entry; c->eax=eax; c->edx=edx;
    c->esp=STACK_TOP; c->cs=0x0Cu; c->ds=0x14u; c->es=0x14u; c->ss=0x14u;
    c->mem_base=(ptrdiff_t)(uintptr_t)memory; c->mem_guest_base=0; c->mem_size=GUEST_LIMIT;
    c->pit_initialized=1; c->fpu_cw=0x127Fu; *(uint32_t *)(memory+STACK_TOP)=RECOMP_RETADDR;
    return gw_recomp_invoke(fn,c)==GW_RECOMP_OK && !c->memory_fault.pending &&
           !c->segment_fault_pending && !c->interrupt_trap_pending && !c->port_io_trap.pending;
}

int main(int argc,char **argv) {
    if(argc!=3) return 2;
    uint8_t *memory=(uint8_t *)calloc(GUEST_LIMIT,1u); if(!memory) return 3;
    guest_memory=memory;
    FILE *img=fopen(argv[1],"rb"); if(!img) { free(memory); return 4; }
    if(fseek(img,0,SEEK_END)) { fclose(img); free(memory); return 5; }
    long n=ftell(img); rewind(img);
    if(n<0 || IMAGE_BASE+(uint64_t)n>GUEST_LIMIT || fread(memory+IMAGE_BASE,1,(size_t)n,img)!=(size_t)n) {
        fclose(img); free(memory); return 6;
    }
    fclose(img);
    if(strcmp((char *)(memory+TITLE_LIST),"data/iftitle.anb")) { free(memory); return 7; }
    if(!gw_partial_install_code_map()) { free(memory); return 8; }
    g_mem_base=(ptrdiff_t)(uintptr_t)memory; recomp_set_memory_bounds(0,GUEST_LIMIT);
    recomp_set_segment_range_validator(in_guest,NULL);
    gw_recomp_context c;
    if(!invoke(gw_partial_0x000830F0,&c,0x830F0u,memory,0,0) ||
       c.esp!=STACK_TOP+4u || g_icall_count!=2156u ||
       *(uint32_t *)(memory+0x0035EAB8u)!=0x002EBA98u) {
        fprintf(stderr,"original Watcom init did not construct IFCTitle: eip=%08x esp=%08x icalls=%u obj=%08x\n",
                c.eip,c.esp,g_icall_count,*(uint32_t *)(memory+0x0035EAB8u));
        free(memory); return 26;
    }
    /* Isolated decoder control: start from the untouched guest image and put
     * the authenticated RNC bytes in an explicitly experimental backed area.
     * This does not count as a manager/VFS load; it tests only the original
     * decoder's overlap branch against the already verified separate-buffer
     * result. */
    uint8_t *pristine=(uint8_t *)calloc(GUEST_LIMIT,1u);
    if(!pristine) { free(memory); return 21; }
    memcpy(pristine,memory,GUEST_LIMIT);
    char fixture_path[512];
    if(_snprintf(fixture_path,sizeof fixture_path,"%s\\DATA\\IFTITLE.ANB",argv[2])<0) {
        free(pristine); free(memory); return 22;
    }
    FILE *fixture=fopen(fixture_path,"rb");
    if(!fixture || fread(pristine+RNC_INPLACE,1,30050u,fixture)!=30050u) {
        if(fixture) fclose(fixture); free(pristine); free(memory); return 23;
    }
    fclose(fixture);
    guest_memory=pristine;
    gw_recomp_context pristine_context;
    if(!invoke(gw_partial_UnpackM1,&pristine_context,0xB9CFCu,pristine,
               RNC_INPLACE,RNC_INPLACE) || pristine_context.eax!=0xE349u) {
        fprintf(stderr,"pristine in-place original RNC control failed eax=%08x eip=%08x mem=%u/%08x\n",
                pristine_context.eax,pristine_context.eip,
                pristine_context.memory_fault.pending,pristine_context.memory_fault.linear);
        guest_memory=memory; free(pristine); free(memory); return 24;
    }
    FILE *control=fopen("work\\lbdataload_rnc_pristine_in_place.bin","wb");
    if(!control || fwrite(pristine+RNC_INPLACE,1,0xE349u,control)!=0xE349u) {
        if(control) fclose(control); guest_memory=memory; free(pristine); free(memory); return 25;
    }
    fclose(control);
    guest_memory=memory; free(pristine);
    memset(&vfs,0,sizeof vfs); vfs.root=argv[2]; gw_dos_services_init(&vfs.dos);
    if(!gw_dos_guest_memory_configure(&vfs.dos,GUEST_LIMIT) ||
       !gw_dos_memory_allocator_configure(&vfs.dos,0x0906u,0x1000u,0x0054u,0x0800u) ||
       !gw_dos4gw_flat_heap_configure(&vfs.dos,0x0014u) ||
       !gw_dos_file_backend_configure(&vfs.dos,host_open,host_read,NULL,NULL,host_close,&vfs) ||
       !gw_dos_file_ioctl_info_configure(&vfs.dos,host_ioctl)) { free(memory); return 9; }
    gw_interrupt_set_callback(dispatch,&vfs.dos);
    /* The range map is flat for this explicit experimental profile. */
    g_seg_cs=0x0Cu; g_seg_ds=g_seg_es=g_seg_ss=0x14u;
    if(!invoke(gw_partial_LbMemorySetup,&c,0x921F0u,memory,0,0) || c.eax!=1u) {
        fprintf(stderr,"LbMemorySetup failed eax=%08x eip=%08x mem=%u/%08x int=%u/%08x\n",
                c.eax,c.eip,c.memory_fault.pending,c.memory_fault.linear,
                c.interrupt_trap_pending,c.interrupt_instruction_va); free(memory); return 10;
    }
    if(!invoke(gw_original_install_resource_callback,&c,0x14E94u,memory,0,0)) {
        fprintf(stderr,"original callback init slice faulted mem=%u/%08x\n",
                c.memory_fault.pending,c.memory_fault.linear); free(memory); return 11;
    }
    if (*(uint32_t *)(memory+0x002F0CA0u)!=0u) {
        fprintf(stderr,"unexpected b_screen precondition in isolated title load: %08x\n",
                *(uint32_t *)(memory+0x002F0CA0u)); free(memory); return 28;
    }
    const uint32_t record=TITLE_LIST;
    const uint32_t start_cell=*(uint32_t *)(memory+record+28u);
    const uint32_t end_cell=*(uint32_t *)(memory+record+32u);
    if(!start_cell || start_cell+4u>GUEST_LIMIT ||
       (end_cell && end_cell+4u>GUEST_LIMIT) || *(uint32_t *)(memory+start_cell)!=0 ||
       *(uint32_t *)(memory+0x2E4804u)!=0x001FFBB0u) {
        fprintf(stderr,"pre-load LE record/callback state mismatch startcell=%08x endcell=%08x cb=%08x\n",
                start_cell,end_cell,*(uint32_t *)(memory+0x2E4804u)); free(memory); return 12;
    }
    g_icall_trace_idx=g_icall_count=0;
    if(!invoke(gw_original_ifctitle_plugin_first_load,&c,0x70D10u,memory,0x0035EAB8u,0) ||
       c.esp!=STACK_TOP+4u || c.eax!=0u ||
       *(uint8_t *)(memory+0x0035EAB8u+0x20u)!=2u || vfs.denied!=0u ||
       *(uint8_t *)(memory+0x002F165Cu)!=4u) {
        fprintf(stderr,"original IFCTitle::PlugIn first-load path failed eax=%08x eip=%08x esp=%08x int=%u/%08x mem=%u/%08x stop=%u reason=%u guest=%08x target=%08x icalls=%u target0=%08x from0=%08x path='%s' opens=%u reads=%u closes=%u\n",
                c.eax,c.eip,c.esp,c.interrupt_trap_pending,c.interrupt_instruction_va,
                c.memory_fault.pending,c.memory_fault.linear,c.port_io_trap.pending,
                c.port_io_trap.reason,c.port_io_trap.guest_va,c.port_io_trap.value,
                g_icall_count,g_icall_trace[0],g_icall_from[0],vfs.last_path,
                vfs.opens,vfs.reads,vfs.closes); free(memory); return 13;
    }
    uint32_t start=*(uint32_t *)(memory+start_cell),end=*(uint32_t *)(memory+end_cell);
    uint32_t length=*(uint32_t *)(memory+record+36u);
    if(vfs.opens==0 || vfs.reads==0 || vfs.closes==0 || strcmp(vfs.first_path,"data/iftitle.anb") ||
       !start || length!=0xE349u || start<FLAT_HEAP_BEGIN || start+length>GUEST_LIMIT ||
       (end_cell && *(uint32_t *)(memory+end_cell)!=start+length)) {
        fprintf(stderr,"loaded record mismatch path='%s' io=%u/%u/%u start=%08x end=%08x length=%u\n",
                vfs.last_path,vfs.opens,vfs.reads,vfs.closes,start,end,length); free(memory); return 14;
    }
    static const char *resource_names[]={"data/iftitle.anb","data/titlescr.pal","data/font2.dat","data/font2.tab"};
    for (unsigned i=0;i<4u;i++) {
        uint32_t r=TITLE_LIST+i*44u, cell=*(uint32_t *)(memory+r+28u);
        uint32_t ptr=cell?*(uint32_t *)(memory+cell):0;
        uint32_t bytes=*(uint32_t *)(memory+r+36u);
        if (strcmp((char *)(memory+r),resource_names[i]) || !ptr || !bytes ||
            ptr<FLAT_HEAP_BEGIN || ptr>GUEST_LIMIT || bytes>GUEST_LIMIT-ptr) {
            fprintf(stderr,"PlugIn title resource[%u] was not committed by the original loader: name='%s' cell=%08x ptr=%08x bytes=%u\n",
                    i,(char *)(memory+r),cell,ptr,bytes); free(memory); return 27;
        }
        printf("TRACE title_resource[%u] path=%s guest=%08x bytes=%u\n",i,resource_names[i],ptr,bytes);
    }
    FILE *out=fopen("work\\lbdataload_iftitle.bin","wb");
    if(!out || fwrite(memory+start,1,length,out)!=length) { if(out) fclose(out); free(memory); return 15; }
    fclose(out);
    /* Differentially exercise the same original RNC decoder both with
     * separate buffers and with the in-place layout used by FUN_989EC. */
    if(RNC_OUT+length>GUEST_LIMIT || RNC_INPLACE+length>GUEST_LIMIT) { free(memory); return 16; }
    memset(memory+RNC_OUT-16u,0xA5,16u);
    memset(memory+RNC_OUT+length,0x5A,16u);
    if(!invoke(gw_partial_UnpackM1,&c,0xB9CFCu,memory,RNC_SOURCE,RNC_OUT) || c.eax!=length) {
        fprintf(stderr,"out-of-place original RNC decode failed eax=%08x eip=%08x mem=%u/%08x\n",
                c.eax,c.eip,c.memory_fault.pending,c.memory_fault.linear); free(memory); return 17;
    }
    out=fopen("work\\lbdataload_rnc_out_of_place.bin","wb");
    if(!out || fwrite(memory+RNC_OUT,1,length,out)!=length) { if(out) fclose(out); free(memory); return 18; }
    fclose(out);
    memcpy(memory+RNC_INPLACE,memory+RNC_SOURCE,30050u);
    if(!invoke(gw_partial_UnpackM1,&c,0xB9CFCu,memory,RNC_INPLACE,RNC_INPLACE) || c.eax!=length) {
        fprintf(stderr,"in-place original RNC decode failed eax=%08x eip=%08x mem=%u/%08x\n",
                c.eax,c.eip,c.memory_fault.pending,c.memory_fault.linear); free(memory); return 19;
    }
    out=fopen("work\\lbdataload_rnc_in_place.bin","wb");
    if(!out || fwrite(memory+RNC_INPLACE,1,length,out)!=length) { if(out) fclose(out); free(memory); return 20; }
    fclose(out);
    printf("TRACE RNC differential: source=%08x expanded=%08x bytes; manager=%08x out_of_place=%08x in_place=%08x\n",
           RNC_SOURCE,length,start,RNC_OUT,RNC_INPLACE);
    printf("TRACE original FUN_97E9C -> UnpackM1 args EAX=%08x ECX=%08x EDX=%08x; expected source=dest=%08x\n",
           rnc_call_eax,rnc_call_ecx,rnc_call_edx,start);
    printf("PASS original LbMemorySetup_ experimental budget=%08x blocks; original callback initializer installed %08x\n",
           GUEST_LIMIT,*(uint32_t *)(memory+0x2E4804u));
    printf("PASS original init -> IFCTitle::PlugIn 0x70D10 -> LbDataLoadAll_ 0x15090 -> LbDataLoad_ 0x14FF0 loaded %s through DOS/VFS: opens=%u reads=%u closes=%u start=%08x end=%08x bytes=%u\n",
           vfs.last_path,vfs.opens,vfs.reads,vfs.closes,start,end,length);
    printf("TRACE next original PlugIn call=LbFileLoadAt_ 0x150D0 path=data/titlescr.dat b_screen[link 0x114CA0/guest 0x002F0CA0]=%08x; not entered without screen setup\n",
           *(uint32_t *)(memory+0x002F0CA0u));
    printf("TRACE allocations: DOS_AH4A=%u failures=%u AH_ED=%u deferred_exit_calls=%u\n",
           dos_4a_calls,dos_4a_failures,dos_ed_calls,g_icall_count);
    for (unsigned i=0;i<vfs.reads && i<8u;i++)
        printf("TRACE read[%u] file+%08lx requested=%u done=%u guest=%08x\n",
               i,vfs.read_pos[i],vfs.read_requested[i],vfs.read_done[i],vfs.read_guest[i]);
    gw_dos_descriptor_clear(&vfs.dos); gw_interrupt_set_callback(NULL,NULL); free(memory); return 0;
}
