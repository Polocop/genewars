#include "recomp_context.h"
#include "gw_interrupts.h"
#include "gw_segments.h"
#include "gw_dos_services.h"
#include "gw_vbe_provider.h"
#define SDL_MAIN_HANDLED
#include <SDL.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void gw_partial_UnpackM1(void);
void gw_partial_LbPaletteSet(void);
void gw_partial_LbScreenSetup(void);
void gw_partial_LbScreenSetGraphicsWindow(void);
void gw_partial_LbScreenSwap(void);
void recomp_gw_partial_0x000D2344(void);
void recomp_gw_partial_0x000D23A7(void);
void recomp_trace_enter(uint32_t va);

uint32_t g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,g_cur_func;
uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_fs,g_seg_gs,g_seg_ss,g_fpu_cw;
uint32_t g_fs_base,g_gs_base;
ptrdiff_t g_mem_base;
double g_st[8]; int g_fp_top;
uint32_t g_icall_trace[ICALL_TRACE_SIZE],g_icall_from[ICALL_TRACE_SIZE];
uint32_t g_icall_trace_idx,g_icall_count;
uint32_t g_enter_trace[RECOMP_ENTER_SIZE],g_enter_idx;
static uint32_t decoder_entry_count,window_entry_count,swap_entry_count,page_entry_count;
static uint32_t setup_entry_count,setup_any_mode_entry_count;

/* D226E's original LEA+RET enters these exact relocated INT n / RET entries.
 * Resolve only the two vectors needed by this measured setup route. */
recomp_func_t recomp_lookup_manual(uint32_t va) {
    if (va==0x002BD344u) return recomp_gw_partial_0x000D2344;
    if (va==0x002BD3A7u) return recomp_gw_partial_0x000D23A7;
    return NULL;
}
recomp_func_t recomp_lookup(uint32_t va) { (void)va; return NULL; }
recomp_func_t recomp_lookup_import(uint32_t va) { (void)va; return NULL; }
void recomp_trace_enter(uint32_t va) {
    g_enter_trace[g_enter_idx++&(RECOMP_ENTER_SIZE-1u)]=va;
    if (va==0xB9CFCu) decoder_entry_count++;
    if (va==0x96338u) window_entry_count++;
    if (va==0x9FFE0u) swap_entry_count++;
    if (va==0xA3A5Cu) page_entry_count++;
    if (va==0x962F0u) setup_entry_count++;
    if (va==0x9FD40u) setup_any_mode_entry_count++;
}

static int trace_has(uint32_t va) {
    uint32_t n=g_enter_idx<RECOMP_ENTER_SIZE?g_enter_idx:RECOMP_ENTER_SIZE;
    for (uint32_t i=0;i<n;i++) if (g_enter_trace[i]==va) return 1;
    return 0;
}

enum { GUEST_SIZE=0x400000, STACK_TOP=0x3FF000, SRC_DST=0x390000,
       FB_WIDTH=640, FB_HEIGHT=480, FB_BYTES=FB_WIDTH*FB_HEIGHT,
       VIDEO_APERTURE=0xA0000, BANK_BYTES=0x10000, VIDEO_BYTES=FB_BYTES,
       LB_DISPLAY=0x376A58, WSCREEN=0x376A5C, WIDTH=0x376A78,
       HEIGHT=0x376A7C, VESA_ACTIVE=0x376ABE, WINDOW_X=0x376A80,
       WINDOW_Y=0x376A84, WINDOW_W=0x376A88, WINDOW_H=0x376A8C,
       VBE_PAGE_GRAN_KB=0x37948A, GUARD=32, CANARY=0xA7 };

typedef struct vbe_state {
    gw_vbe_device device;
    uint32_t transfer_count;
    uint32_t transfer_bytes;
    uint32_t transfer_bank[8];
    uint32_t transfer_size[8];
    uint8_t *video;
    uint8_t *memory;
    uint8_t dac_palette[768];
    uint32_t dac_index_writes, dac_component_writes;
    uint8_t dac_index, dac_component, dac_mask;
} vbe_state;

static vbe_state vbe;
static gw_dos_services dos_services;

static int guest_range(uint16_t selector,uint32_t offset,uint32_t width,void *user) {
    (void)user;
    uint64_t end=(uint64_t)offset+width;
    if (!width || end>GUEST_SIZE || selector!=0x14u) return 0;
    if (offset>=0x002DA000u && end<=0x00385C50u) return 1;
    if (offset>=SRC_DST && end<=0x003FE000u) return 1;
    if (offset>=0x003FE000u && end<=GUEST_SIZE) return 1;
    if (offset>=VIDEO_APERTURE && end<=VIDEO_APERTURE+BANK_BYTES) return 1;
    if (offset>=0x00090000u && end<=0x000BB000u) return 1;
    return 0;
}

static uintptr_t translate_video(uint32_t linear,uint32_t width,
                                uintptr_t default_host,void *user) {
    vbe_state *s=(vbe_state *)user;
    if (linear<VIDEO_APERTURE || linear>=VIDEO_APERTURE+BANK_BYTES) return default_host;
    uint64_t offset=(uint64_t)s->device.bank[0]*BANK_BYTES+(linear-VIDEO_APERTURE);
    if (offset+width>VIDEO_BYTES) return 0;
    return (uintptr_t)(s->video+offset);
}

static int backing_validator(uintptr_t host,uint32_t linear,uint32_t width,
                             uint8_t access,void *user) {
    vbe_state *s=(vbe_state *)user;
    if (!width || linear>GUEST_SIZE || width>GUEST_SIZE-linear) return 0;
    if (linear>=VIDEO_APERTURE && linear<VIDEO_APERTURE+BANK_BYTES) {
        uint64_t offset=(uint64_t)s->device.bank[0]*BANK_BYTES+(linear-VIDEO_APERTURE);
        if (offset+width>VIDEO_BYTES || host!=(uintptr_t)(s->video+offset)) return 0;
        if (access&RECOMP_MEM_ACCESS_WRITE) {
            if (s->transfer_count>=8u) return 0;
            s->transfer_bank[s->transfer_count]=s->device.bank[0];
            s->transfer_size[s->transfer_count]=width;
            s->transfer_count++;
            s->transfer_bytes+=width;
        }
        return 1;
    }
    return host==(uintptr_t)(s->memory+linear);
}

static gw_interrupt_result interrupt_provider(uint8_t vector,uint32_t instruction_va,
                                                void *user) {
    (void)user;
    if (vector==0x31u) {
        gw_interrupt_result dpmi=gw_dos_services_callback(vector,instruction_va,
                                                            &dos_services);
        if (dpmi==GW_INTERRUPT_HANDLED) return dpmi;
    }
    return gw_vbe_interrupt(vector,instruction_va,&vbe.device);
}

/* Controlled legacy VGA DAC device: original palette writes are captured and
 * the default six-bit DAC keeps the low six bits. This is explicit fixture
 * state; the natural W3-100 run did not capture DAC width. */
static int vga_palette_port(unsigned int operation,unsigned int port,
                            unsigned int width,unsigned int value,
                            unsigned int guest_va,unsigned int *value_out,
                            void *user) {
    vbe_state *s=(vbe_state *)user;
    (void)guest_va; (void)value_out;
    if (operation!=1u || width!=1u) return 0;
    if (port==0x3C6u) {
        s->dac_mask=(uint8_t)value;
        return 1;
    }
    if (port==0x3C8u) {
        if (value>255u) return 0;
        s->dac_index=(uint8_t)value;
        s->dac_component=0;
        s->dac_index_writes++;
        return 1;
    }
    if (port==0x3C9u) {
        s->dac_palette[(uint32_t)s->dac_index*3u+s->dac_component]=
            (uint8_t)(value&0x3Fu);
        s->dac_component_writes++;
        if (++s->dac_component==3u) {
            s->dac_component=0;
            s->dac_index++;
        }
        return 1;
    }
    return 0;
}

static int read_file(const char *path,uint8_t **data,size_t *size) {
    FILE *f=fopen(path,"rb"); if (!f) return 0;
    if (fseek(f,0,SEEK_END)!=0) { fclose(f); return 0; }
    long n=ftell(f); if (n<18 || fseek(f,0,SEEK_SET)!=0) { fclose(f); return 0; }
    uint8_t *p=(uint8_t *)malloc((size_t)n); if (!p) { fclose(f); return 0; }
    int ok=fread(p,1,(size_t)n,f)==(size_t)n; fclose(f);
    if (!ok) { free(p); return 0; }
    *data=p; *size=(size_t)n; return 1;
}

static int save_bytes(const char *path,const uint8_t *data,size_t size) {
    FILE *f=fopen(path,"wb"); if (!f) return 0;
    int ok=fwrite(data,1,size,f)==size;
    if (fclose(f)!=0) ok=0;
    return ok;
}

static int invoke_unpack(uint8_t *memory,uint32_t expected_size) {
    gw_recomp_context c; memset(&c,0,sizeof c);
    c.eax=SRC_DST; c.edx=SRC_DST; c.esp=STACK_TOP; c.eip=0xB9CFCu;
    *(uint32_t *)(memory+STACK_TOP)=RECOMP_RETADDR;
    c.cs=0x0C; c.ds=0x14; c.es=0x14; c.ss=0x14;
    c.mem_base=(ptrdiff_t)(uintptr_t)memory; c.mem_guest_base=0; c.mem_size=GUEST_SIZE;
    c.pit_initialized=1;
    if (gw_recomp_invoke(gw_partial_UnpackM1,&c)!=GW_RECOMP_OK ||
        c.interrupt_trap_pending || c.segment_fault_pending || c.memory_fault.pending ||
        c.port_io_trap.pending || c.eax!=expected_size) {
        fprintf(stderr,"original RNC1 decoder failed: eax=%08X memory_fault=%u at %08X/%08X int=%u\n",
                c.eax,c.memory_fault.pending,c.memory_fault.instruction_va,
                c.memory_fault.linear,c.interrupt_trap_pending);
        return 0;
    }
    if (!decoder_entry_count) {
        fprintf(stderr,"original title-resource decoder entry 0xB9CFC missing from trace\n");
        return 0;
    }
    return 1;
}

static int configure_window(uint8_t *memory) {
    gw_recomp_context c; memset(&c,0,sizeof c);
    c.eax=0; c.ebx=FB_WIDTH; c.ecx=FB_HEIGHT; c.edx=0;
    c.esp=STACK_TOP; c.eip=0x96338u; c.cs=0x0C; c.ds=0x14; c.es=0x14; c.ss=0x14;
    *(uint32_t *)(memory+STACK_TOP)=RECOMP_RETADDR;
    c.mem_base=(ptrdiff_t)(uintptr_t)memory; c.mem_guest_base=0; c.mem_size=GUEST_SIZE;
    c.pit_initialized=1;
    if (gw_recomp_invoke(gw_partial_LbScreenSetGraphicsWindow,&c)!=GW_RECOMP_OK ||
        c.interrupt_trap_pending || c.segment_fault_pending || c.memory_fault.pending) return 0;
    if (!window_entry_count) return 0;
    return *(uint32_t *)(memory+WINDOW_X)==0 && *(uint32_t *)(memory+WINDOW_Y)==0 &&
           *(uint32_t *)(memory+WINDOW_W)==FB_WIDTH && *(uint32_t *)(memory+WINDOW_H)==FB_HEIGHT &&
           *(uint32_t *)(memory+0x376A68)==SRC_DST;
}

static int invoke_original_screen_setup(uint8_t *memory) {
    gw_recomp_context c; memset(&c,0,sizeof c);
    /* W3-100 observed the original setup asking for mode-table slot 13 and
     * VBE mode 0x101. Feed that observed slot through LbScreenSetup_ itself;
     * the host provider still decides which modes it advertises. */
    c.eax=13u; c.ecx=SRC_DST; c.edx=FB_WIDTH; c.ebx=FB_HEIGHT;
    c.esp=STACK_TOP; c.eip=0x962F0u; c.cs=0x0C; c.ds=0x14; c.es=0x14; c.ss=0x14;
    *(uint32_t *)(memory+STACK_TOP)=RECOMP_RETADDR;
    c.mem_base=(ptrdiff_t)(uintptr_t)memory; c.mem_guest_base=0; c.mem_size=GUEST_SIZE;
    c.pit_initialized=1;
    if (gw_recomp_invoke(gw_partial_LbScreenSetup,&c)!=GW_RECOMP_OK ||
        c.interrupt_trap_pending || c.segment_fault_pending || c.memory_fault.pending ||
        c.port_io_trap.pending) {
        fprintf(stderr,"original LbScreenSetup failed: eip=%08X int=%u/%08X segment=%u memory=%u at %08X/%08X port=%X\n",
                c.eip,c.interrupt_trap_pending,c.interrupt_instruction_va,
                c.segment_fault_pending,c.memory_fault.pending,
                c.memory_fault.instruction_va,c.memory_fault.linear,c.port_io_trap.port);
        return 0;
    }
    if (!setup_entry_count || !setup_any_mode_entry_count) return 0;
    if (c.eax!=1u) {
        fprintf(stderr,"original setup did not return success: eax=%08X VBE 4F00/01/02=%u/%u/%u 0F=%u\n",
                c.eax,vbe.device.controller_info_calls,vbe.device.mode_info_calls,
                vbe.device.set_mode_calls,vbe.device.legacy_mode_query_calls);
        return 0;
    }
    const uint8_t *mode_info=memory+0x00090000u;
    if (*(uint16_t *)(memory+0x00090200u)!=0x0101u ||
        *(uint16_t *)(memory+0x00090202u)!=0xffffu ||
        *(uint16_t *)(mode_info+0u)!=0x001bu ||
        mode_info[2]!=0x07u ||
        *(uint16_t *)(mode_info+4u)!=64u ||
        *(uint16_t *)(mode_info+6u)!=64u ||
        *(uint16_t *)(mode_info+8u)!=0xA000u ||
        *(uint16_t *)(mode_info+16u)!=FB_WIDTH ||
        *(uint16_t *)(mode_info+18u)!=FB_WIDTH ||
        *(uint16_t *)(mode_info+20u)!=FB_HEIGHT ||
        mode_info[22]!=8u || mode_info[23]!=16u || mode_info[24]!=1u ||
        mode_info[25]!=8u || mode_info[26]!=5u || mode_info[27]!=4u ||
        mode_info[28]!=64u || *(uint32_t *)(mode_info+40u)!=0u ||
        !vbe.device.mode_active ||
        *(uint32_t *)(memory+LB_DISPLAY)!=VIDEO_APERTURE ||
        *(uint32_t *)(memory+WIDTH)!=FB_WIDTH ||
        *(uint32_t *)(memory+HEIGHT)!=FB_HEIGHT ||
        memory[VESA_ACTIVE]!=1u ||
        *(uint32_t *)(memory+WSCREEN)!=SRC_DST ||
        *(uint32_t *)(memory+0x376A68u)!=SRC_DST ||
        *(uint16_t *)(memory+0x37947Cu)!=FB_WIDTH ||
        *(uint16_t *)(memory+0x37947Eu)!=FB_WIDTH ||
        *(uint16_t *)(memory+0x379480u)!=FB_HEIGHT ||
        *(uint16_t *)(memory+VBE_PAGE_GRAN_KB)!=64u) {
        fprintf(stderr,"original setup returned inconsistent mode/surface state: display=%08X logical=%u/%u vesa=%u window=%08X pitch=%u res=%u/%u gran=%u\n",
                *(uint32_t *)(memory+LB_DISPLAY),*(uint32_t *)(memory+WIDTH),
                *(uint32_t *)(memory+HEIGHT),memory[VESA_ACTIVE],
                *(uint32_t *)(memory+WSCREEN),*(uint16_t *)(memory+0x37947Cu),
                *(uint16_t *)(memory+0x37947Eu),*(uint16_t *)(memory+0x379480u),
                *(uint16_t *)(memory+VBE_PAGE_GRAN_KB));
        return 0;
    }
    return 1;
}

static int apply_original_palette(uint8_t *memory) {
    gw_recomp_context c; memset(&c,0,sizeof c);
    c.esp=STACK_TOP; c.eip=0xADEACu; c.cs=0x0C; c.ds=0x14; c.es=0x14; c.ss=0x14;
    c.mem_base=(ptrdiff_t)(uintptr_t)memory; c.mem_guest_base=0; c.mem_size=GUEST_SIZE;
    c.pit_initialized=1;
    *(uint32_t *)(memory+STACK_TOP)=RECOMP_RETADDR;
    *(uint32_t *)(memory+STACK_TOP+4u)=SRC_DST;
    if (gw_recomp_invoke(gw_partial_LbPaletteSet,&c)!=GW_RECOMP_OK ||
        c.interrupt_trap_pending || c.segment_fault_pending || c.memory_fault.pending ||
        c.port_io_trap.pending) {
        fprintf(stderr,"original palette writer failed: port=%X eip=%08X\n",
                c.port_io_trap.port,c.port_io_trap.guest_va);
        return 0;
    }
    if (vbe.dac_mask!=0xFFu || vbe.dac_index_writes!=256u ||
        vbe.dac_component_writes!=768u || vbe.dac_index!=0u || vbe.dac_component!=0u) {
        fprintf(stderr,"palette writer emitted incomplete VGA DAC stream: mask=%02X indices=%u components=%u\n",
                vbe.dac_mask,vbe.dac_index_writes,vbe.dac_component_writes);
        return 0;
    }
    return 1;
}

static int invoke_swap(uint8_t *memory) {
    gw_recomp_context c; memset(&c,0,sizeof c);
    c.esp=STACK_TOP; c.eip=0x9FFE0u; c.cs=0x0C; c.ds=0x14; c.es=0x14; c.ss=0x14;
    *(uint32_t *)(memory+STACK_TOP)=RECOMP_RETADDR;
    c.mem_base=(ptrdiff_t)(uintptr_t)memory; c.mem_guest_base=0; c.mem_size=GUEST_SIZE;
    c.pit_initialized=1;
    if (gw_recomp_invoke(gw_partial_LbScreenSwap,&c)!=GW_RECOMP_OK ||
        c.interrupt_trap_pending || c.segment_fault_pending || c.memory_fault.pending ||
        c.port_io_trap.pending) {
        fprintf(stderr,"original LbScreenSwap failed: int=%u segment=%u memory=%u at %08X/%08X\n",
                c.interrupt_trap_pending,c.segment_fault_pending,c.memory_fault.pending,
                c.memory_fault.instruction_va,c.memory_fault.linear);
        return 0;
    }
    if (!swap_entry_count || !page_entry_count) {
        fprintf(stderr,"original screen-swap/VESA-page entry missing from trace\n");
        return 0;
    }
    return 1;
}

static int present_sdl(const uint8_t *pixels,const uint8_t *palette) {
    if (SDL_Init(SDL_INIT_VIDEO)!=0) { fprintf(stderr,"SDL_Init: %s\n",SDL_GetError()); return 0; }
    SDL_SetHint(SDL_HINT_RENDER_SCALE_QUALITY,"0");
    SDL_Window *window=SDL_CreateWindow("GeneWars 1.1 — título auténtico (aislado)",
        SDL_WINDOWPOS_CENTERED,SDL_WINDOWPOS_CENTERED,1280,960,SDL_WINDOW_SHOWN);
    SDL_Renderer *renderer=window?SDL_CreateRenderer(window,-1,SDL_RENDERER_SOFTWARE):NULL;
    SDL_Texture *texture=renderer?SDL_CreateTexture(renderer,SDL_PIXELFORMAT_ARGB8888,
        SDL_TEXTUREACCESS_STATIC,FB_WIDTH,FB_HEIGHT):NULL;
    uint32_t *rgba=(uint32_t *)malloc(FB_BYTES*sizeof(uint32_t));
    if (!window || !renderer || !texture || !rgba) {
        fprintf(stderr,"SDL setup: %s\n",SDL_GetError()); return 0;
    }
    for (uint32_t i=0;i<FB_BYTES;i++) {
        uint32_t index=pixels[i];
        uint32_t r=(uint32_t)palette[index*3u+0u]*255u/63u;
        uint32_t g=(uint32_t)palette[index*3u+1u]*255u/63u;
        uint32_t b=(uint32_t)palette[index*3u+2u]*255u/63u;
        rgba[i]=0xFF000000u|(r<<16)|(g<<8)|b;
    }
    if (SDL_UpdateTexture(texture,NULL,rgba,FB_WIDTH*4)!=0 ||
        SDL_RenderClear(renderer)!=0 || SDL_RenderCopy(renderer,texture,NULL,NULL)!=0) {
        fprintf(stderr,"SDL draw: %s\n",SDL_GetError()); return 0;
    }
    SDL_RenderPresent(renderer);
    uint32_t *capture=(uint32_t *)malloc(1280u*960u*sizeof(uint32_t));
    if (!capture || SDL_RenderReadPixels(renderer,NULL,SDL_PIXELFORMAT_ARGB8888,
            capture,1280*4)!=0) { fprintf(stderr,"SDL capture: %s\n",SDL_GetError()); return 0; }
    SDL_Surface *surface=SDL_CreateRGBSurfaceWithFormatFrom(capture,1280,960,32,
        1280*4,SDL_PIXELFORMAT_ARGB8888);
    if (!surface || SDL_SaveBMP(surface,"evidence/genewars_11_titlescreen_sdl.bmp")!=0) {
        fprintf(stderr,"SDL BMP: %s\n",SDL_GetError()); return 0;
    }
    printf("PASS SDL presents authentic post-swap 640x480 indexed title bytes; palette is the decoded original TITLESCR.PAL\n");
    printf("SDL window visible for 3 seconds; capture evidence/genewars_11_titlescreen_sdl.bmp\n");
    SDL_Delay(3000);
    SDL_FreeSurface(surface); free(capture); free(rgba);
    SDL_DestroyTexture(texture); SDL_DestroyRenderer(renderer); SDL_DestroyWindow(window); SDL_Quit();
    return 1;
}

int main(int argc,char **argv) {
    if (argc!=4) { fprintf(stderr,"usage: test_authentic_titlescreen <titlescr.pal> <titlescr.dat> <rebased-le-object3>\n"); return 2; }
    uint8_t *pal_file=NULL,*image_file=NULL,*setup_seed=NULL;
    size_t pal_size=0,image_size=0,setup_seed_size=0;
    if (!read_file(argv[1],&pal_file,&pal_size) ||
        !read_file(argv[2],&image_file,&image_size) ||
        !read_file(argv[3],&setup_seed,&setup_seed_size)) return 3;
    if (memcmp(pal_file,"RNC\x01",4) || memcmp(image_file,"RNC\x01",4) ||
        pal_file[4]!=0 || pal_file[5]!=0 || pal_file[6]!=3 || pal_file[7]!=0 ||
        image_file[4]!=0 || image_file[5]!=4 || image_file[6]!=0xB0 || image_file[7]!=0) {
        fprintf(stderr,"unexpected authenticated RNC1 unpacked-size header\n"); return 4;
    }
    uint8_t *memory=(uint8_t *)calloc(GUEST_SIZE,1u);
    enum { VIDEO_MEMORY_BYTES=5u*BANK_BYTES };
    uint8_t *video_storage=(uint8_t *)malloc(VIDEO_MEMORY_BYTES+2u*GUARD);
    if (!memory || !video_storage) return 5;
    if (setup_seed_size!=0xA8C50u || 0x2DA000u+setup_seed_size>GUEST_SIZE) {
        fprintf(stderr,"verified LE object 3 seed has invalid extent: %u\n",
                (unsigned)setup_seed_size); return 5;
    }
    /* This is the authentic, loader-rebased object 3 containing GeneWars'
     * mode table and graphics setup globals. Install it before the provider's
     * caller-owned conventional scratch pointer is set below. */
    memcpy(memory+0x2DA000u,setup_seed,setup_seed_size);
    vbe.memory=memory; vbe.video=video_storage+GUARD;
    memset(vbe.video-GUARD,CANARY,GUARD); memset(vbe.video,0xCC,VIDEO_MEMORY_BYTES);
    memset(vbe.video+VIDEO_MEMORY_BYTES,CANARY,GUARD);
    memset(memory+SRC_DST-GUARD,CANARY,GUARD);
    memset(memory+SRC_DST+FB_BYTES,CANARY,GUARD);
    memset(memory+0x38FFF0,CANARY,16);

    memcpy(memory+SRC_DST,pal_file,pal_size);
    *(uint32_t *)(memory+0x379484u)=0x00090000u; /* caller-owned conventional VBE block */
    *(uint32_t *)(memory+WSCREEN)=SRC_DST; /* explicitly backed host-owned logical surface */
    if (!gw_vbe_device_configure(&vbe.device,memory,GUEST_SIZE,0x00090000u,
            0x0101u,FB_WIDTH,FB_HEIGHT,FB_WIDTH,8u,64u,64u,0xA000u,
            VIDEO_MEMORY_BYTES)) {
        fprintf(stderr,"could not configure bounded VBE 0x101 device profile\n"); return 5;
    }
    gw_recomp_context init; memset(&init,0,sizeof init);
    init.esp=STACK_TOP; init.cs=0x0C; init.ds=0x14; init.es=0x14; init.ss=0x14;
    init.mem_base=(ptrdiff_t)(uintptr_t)memory; init.mem_guest_base=0; init.mem_size=GUEST_SIZE;
    init.pit_initialized=1;
    gw_dos_services_init(&dos_services);
    if (!gw_dos_guest_memory_configure(&dos_services,GUEST_SIZE) ||
        !gw_dos_real_mode_interrupt_configure(&dos_services,
                    gw_vbe_real_mode_interrupt,&vbe.device)) return 5;
    recomp_memory_diag_enable(1);
    recomp_memory_diag_set_guest_range(0x00090000u,0x000BA001u);
    recomp_memory_diag_set_backing_validator(backing_validator,&vbe);
    recomp_set_segment_range_validator(guest_range,NULL);
    recomp_set_memory_translator(translate_video,&vbe);
    gw_interrupt_set_callback(interrupt_provider,&dos_services);
    gw_recomp_set_port_io_provider(vga_palette_port,&vbe);
    if (!invoke_unpack(memory,768u)) return 6;
    uint8_t palette[768]; memcpy(palette,memory+SRC_DST,sizeof palette);
    if (!invoke_original_screen_setup(memory)) return 7;
    if (vbe.device.controller_info_calls<1u || vbe.device.set_mode_calls!=1u ||
        vbe.device.mode_info_calls<1u || vbe.dac_mask!=0xFFu ||
        vbe.dac_index_writes!=256u || vbe.dac_component_writes!=768u) {
        fprintf(stderr,"setup did not complete VBE/controller/mode/palette path: 4F00=%u 4F01=%u 4F02=%u DAC=%u/%u\n",
                vbe.device.controller_info_calls,vbe.device.mode_info_calls,
                vbe.device.set_mode_calls,vbe.dac_index_writes,vbe.dac_component_writes);
        return 7;
    }
    printf("VBECOUNTS 4F00=%u 4F01=%u 4F02=%u 4F05=%u 0F=%u\n",
           vbe.device.controller_info_calls,vbe.device.mode_info_calls,
           vbe.device.set_mode_calls,vbe.device.set_page_calls,
           vbe.device.legacy_mode_query_calls);
    if (!save_bytes("evidence/genewars_11_titlescreen_dac6.raw",vbe.dac_palette,sizeof vbe.dac_palette)) return 7;
    /* Guard immediately after the expected decode extent before the authentic
     * decompressor runs; checking only after resetting this canary would hide
     * an overrun. */
    memset(memory+SRC_DST+FB_BYTES,CANARY,GUARD);
    memcpy(memory+SRC_DST,image_file,image_size);
    if (!invoke_unpack(memory,FB_BYTES)) return 8;
    uint8_t *pixels=memory+SRC_DST;
    if (!save_bytes("evidence/genewars_11_titlescreen_palette.raw",palette,sizeof palette) ||
        !save_bytes("evidence/genewars_11_titlescreen_dac6.raw",vbe.dac_palette,sizeof vbe.dac_palette) ||
        !save_bytes("evidence/genewars_11_titlescreen_surface.raw",pixels,FB_BYTES)) return 9;

    if (!invoke_swap(memory)) return 11;
    if (vbe.transfer_count!=5u || vbe.transfer_bytes!=VIDEO_BYTES ||
        vbe.device.set_page_calls!=8u || vbe.device.bank[0]!=4u || vbe.device.bank[1]!=4u) {
        fprintf(stderr,"unexpected banked transfer: chunks=%u bytes=%u set_calls=%u A=%u B=%u\n",
                vbe.transfer_count,vbe.transfer_bytes,vbe.device.set_page_calls,
                vbe.device.bank[0],vbe.device.bank[1]); return 12;
    }
    for (uint32_t i=0;i<5u;i++) {
        uint32_t expected_bank=i;
        uint32_t expected_size=i==4u?VIDEO_BYTES-4u*BANK_BYTES:BANK_BYTES;
        uint32_t page_index=i?2u*(i-1u):0u;
        if (vbe.transfer_bank[i]!=expected_bank || vbe.transfer_size[i]!=expected_size ||
            (i && (vbe.device.page_log[page_index]!=expected_bank ||
                   vbe.device.window_log[page_index]!=0u ||
                   vbe.device.page_log[page_index+1u]!=expected_bank ||
                   vbe.device.window_log[page_index+1u]!=1u))) {
            fprintf(stderr,"transfer %u bank/length %u/%u expected %u/%u; page trace starts at %u\n",i,
                    vbe.transfer_bank[i],vbe.transfer_size[i],expected_bank,expected_size,
                    i?vbe.device.page_log[page_index]:0u); return 13;
        }
    }
    for (uint32_t i=0;i<VIDEO_BYTES;i++) if (vbe.video[i]!=pixels[i]) {
        fprintf(stderr,"post-swap mismatch at pixel byte %u: %02X != %02X\n",i,vbe.video[i],pixels[i]); return 14;
    }
    for (unsigned i=0;i<GUARD;i++) if (vbe.video[-(int)GUARD+i]!=CANARY ||
        vbe.video[VIDEO_MEMORY_BYTES+i]!=CANARY || memory[SRC_DST-GUARD+i]!=CANARY ||
        memory[SRC_DST+FB_BYTES+i]!=CANARY) return 15;
    if (!save_bytes("evidence/genewars_11_titlescreen_video.raw",vbe.video,VIDEO_BYTES)) return 16;
    printf("PASS original FUN_000B9CFC decoded TITLESCR.PAL=768 and TITLESCR.DAT=307200 in place\n");
    printf("PASS original LbScreenSetup_ 0x962F0 -> LbScreenSetupAnyMode_ 0x9FD40; host VBE 4F00=%u 4F02=%u 4F01=%u initialized 640x480x8 pitch=%u gran=%u KiB\n",
           vbe.device.controller_info_calls,vbe.device.set_mode_calls,
           vbe.device.mode_info_calls,*(uint16_t *)(memory+0x37947Cu),
           *(uint16_t *)(memory+VBE_PAGE_GRAN_KB));
    printf("PASS original FUN_000ADEAC wrote 256 palette entries/768 DAC bytes; six-bit VGA device profile applied\n");
    printf("PASS original LbScreenSetGraphicsWindow_ 0x96338 and LbScreenSwap_ 0x9FFE0; mode-0x101 VBE bank profile: ");
    for (uint32_t i=0;i<vbe.device.set_page_calls;i++) printf("%s%u:%c",i?",":"",vbe.device.page_log[i],vbe.device.window_log[i]?'B':'A');
    printf("; writes=%u bytes=%u exact\n",vbe.transfer_count,vbe.transfer_bytes);
    if (!present_sdl(vbe.video,vbe.dac_palette)) return 17;
    free(pal_file); free(image_file); free(video_storage); free(memory);
    return 0;
}
