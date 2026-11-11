#include "recomp_context.h"
#define SDL_MAIN_HANDLED
#include <SDL.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void gw_partial_LbScreenSetGraphicsWindow(void);
void gw_partial_LbScreenClearGraphicsWindow(void);
void gw_partial_LbScreenSwap(void);
void recomp_trace_enter(uint32_t va);

uint32_t g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,g_cur_func;
uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_fs,g_seg_gs,g_seg_ss,g_fpu_cw;
uint32_t g_fs_base,g_gs_base;
ptrdiff_t g_mem_base;
double g_st[8]; int g_fp_top;
uint32_t g_icall_trace[ICALL_TRACE_SIZE], g_icall_from[ICALL_TRACE_SIZE];
uint32_t g_icall_trace_idx, g_icall_count;
uint32_t g_enter_trace[RECOMP_ENTER_SIZE],g_enter_idx;

static uint32_t pixel_writes[2048],pixel_write_count;
static recomp_memory_diagnostic pixel_prior_access;
static recomp_memory_diagnostic swap_source_access;
static uint32_t swap_source_bytes,swap_video_bytes;
static int track_swap_access;

recomp_func_t recomp_lookup_manual(uint32_t va) { (void)va; return NULL; }
recomp_func_t recomp_lookup(uint32_t va) { (void)va; return NULL; }
recomp_func_t recomp_lookup_import(uint32_t va) { (void)va; return NULL; }

void recomp_trace_enter(uint32_t va) {
    g_enter_trace[g_enter_idx++ & (RECOMP_ENTER_SIZE-1u)]=va;
}

enum { GUEST_SIZE=0x400000, STACK_TOP=0x3FF000,
       /* Explicitly experimental host surface; no natural mode is claimed. */
       SCREEN_WIDTH=320, SCREEN_HEIGHT=200, SURFACE_BYTES=SCREEN_WIDTH*SCREEN_HEIGHT,
       LB_DISPLAY=0x376A58, BASE_PTR=0x376A5C, DRAW_PTR=0x376A68,
       WIDTH=0x376A78, HEIGHT=0x376A7C, VESA_IS_SETUP=0x376ABE,
       WIN_X=0x376A80, WIN_Y=0x376A84, WIN_W=0x376A88, WIN_H=0x376A8C,
       FB=0x390000, VIDEO_FB=0x000A0000, GUARD=16, COLOR=0x5A, INITIAL=0x11, CANARY=0xA5,
       DRAW_X=10, DRAW_Y=20, DRAW_W=64, DRAW_H=32 };

static int trace_has(uint32_t va) {
    uint32_t n=g_enter_idx<RECOMP_ENTER_SIZE?g_enter_idx:RECOMP_ENTER_SIZE;
    for (uint32_t i=0;i<n;i++) if (g_enter_trace[i]==va) return 1;
    return 0;
}
static int pixel_address(uint32_t a) {
    if (a<FB || a>=FB+SURFACE_BYTES) return 0;
    uint32_t offset=a-FB, x=offset%SCREEN_WIDTH, y=offset/SCREEN_WIDTH;
    return x>=DRAW_X && x<DRAW_X+DRAW_W && y>=DRAW_Y && y<DRAW_Y+DRAW_H;
}
static int backing_validator(uintptr_t host,uint32_t linear,uint32_t width,
                             uint8_t access,void *user) {
    uint8_t *memory=(uint8_t *)user;
    if (host!=(uintptr_t)(memory+linear) || linear>GUEST_SIZE || width>GUEST_SIZE-linear)
        return 0;
    if (track_swap_access && (access&RECOMP_MEM_ACCESS_READ) &&
        linear>=FB && (uint64_t)linear+width<=(uint64_t)FB+SURFACE_BYTES)
        swap_source_bytes+=width;
    if (track_swap_access && (access&RECOMP_MEM_ACCESS_WRITE) &&
        linear>=VIDEO_FB && (uint64_t)linear+width<=(uint64_t)VIDEO_FB+SURFACE_BYTES) {
        swap_video_bytes+=width;
        /* The backing callback runs before remember_access records the output;
           at this point the immediately preceding checked access is the source. */
        swap_source_access=recomp_memory_diag_last_access();
    }
    if ((access&RECOMP_MEM_ACCESS_WRITE) && linear>=FB && linear<FB+SURFACE_BYTES) {
        for (uint32_t i=0;i<width;i++) {
            if (pixel_write_count>=2048u) return 0;
            pixel_writes[pixel_write_count++]=linear+i;
        }
        /* The runtime records the current access just after this validator. */
        pixel_prior_access=recomp_memory_diag_last_access();
    }
    return 1;
}

static int guest_segment_range(uint16_t selector,uint32_t offset,uint32_t width,void *user) {
    (void)user;
    uint64_t end=(uint64_t)offset+width;
    if (width==0 || end>0x100000000ull) return 0;
    if (selector==0x14u) {
        /* Verified object 3 plus the two explicitly backed experimental surfaces. */
        if (offset>=0x002DA000u && end<=0x00385C50u) return 1;
        if (offset>=FB && end<=(uint64_t)FB+SURFACE_BYTES) return 1;
        if (offset>=VIDEO_FB && end<=(uint64_t)VIDEO_FB+SURFACE_BYTES) return 1;
        if (offset>=0x003FE000u && end<=0x00400000u) return 1;
    }
    return 0;
}

int main(void) {
    uint8_t *memory=(uint8_t *)calloc(GUEST_SIZE,1u);
    uint8_t *before=(uint8_t *)malloc(GUEST_SIZE);
    if (!memory || !before) return 2;

    memset(memory+FB-GUARD,CANARY,GUARD);
    memset(memory+FB,INITIAL,SURFACE_BYTES);
    memset(memory+FB+SURFACE_BYTES,CANARY,GUARD);
    memset(memory+VIDEO_FB-GUARD,CANARY,GUARD);
    memset(memory+VIDEO_FB,0xCC,SURFACE_BYTES);
    memset(memory+VIDEO_FB+SURFACE_BYTES,CANARY,GUARD);
    *(uint32_t *)(memory+LB_DISPLAY)=VIDEO_FB;
    *(uint32_t *)(memory+BASE_PTR)=FB;
    *(uint32_t *)(memory+WIDTH)=SCREEN_WIDTH;
    *(uint32_t *)(memory+HEIGHT)=SCREEN_HEIGHT;
    memory[VESA_IS_SETUP]=0; /* controlled conventional VGA branch, not a VESA claim */
    *(uint32_t *)(memory+STACK_TOP)=RECOMP_RETADDR;

    gw_recomp_context c; memset(&c,0,sizeof c);
    c.eax=DRAW_X; c.ebx=DRAW_W; c.ecx=DRAW_H; c.edx=DRAW_Y;
    c.esp=STACK_TOP; c.eip=0x96338u; c.cs=0x0C; c.ds=0x14; c.es=0x14; c.ss=0x14;
    c.mem_base=(ptrdiff_t)(uintptr_t)memory;
    c.mem_guest_base=0; c.mem_size=GUEST_SIZE;
    c.pit_initialized=1;

    recomp_memory_diag_enable(1);
    /* Capture the optimized dword stores but omit the following POP's stack read. */
    recomp_memory_diag_set_guest_range(0xB7050u,0xB70F3u);
    recomp_memory_diag_set_backing_validator(backing_validator,memory);
    recomp_set_segment_range_validator(guest_segment_range,NULL);

    if (gw_recomp_invoke(gw_partial_LbScreenSetGraphicsWindow,&c)!=GW_RECOMP_OK) return 3;
    if (c.interrupt_trap_pending || c.segment_fault_pending || c.memory_fault.pending) return 4;
    if (*(uint32_t *)(memory+WIN_X)!=DRAW_X || *(uint32_t *)(memory+WIN_Y)!=DRAW_Y ||
        *(uint32_t *)(memory+WIN_W)!=DRAW_W || *(uint32_t *)(memory+WIN_H)!=DRAW_H ||
        *(uint32_t *)(memory+DRAW_PTR)!=FB+DRAW_Y*SCREEN_WIDTH+DRAW_X) return 5;

    memcpy(before,memory,GUEST_SIZE);
    *(uint32_t *)(memory+STACK_TOP)=RECOMP_RETADDR;
    *(uint32_t *)(memory+STACK_TOP+4u)=COLOR;
    c.eip=0x9FEB0u; c.esp=STACK_TOP;
    if (gw_recomp_invoke(gw_partial_LbScreenClearGraphicsWindow,&c)!=GW_RECOMP_OK) return 6;
    if (c.interrupt_trap_pending || c.segment_fault_pending || c.memory_fault.pending) return 7;
    if (c.eax!=1u || c.esp!=STACK_TOP+4u || c.eip!=0x9FEB0u ||
        c.cur_func!=0x9FEB0u) return 8;

    for (uint32_t y=0;y<SCREEN_HEIGHT;y++) for (uint32_t x=0;x<SCREEN_WIDTH;x++) {
        uint8_t expected=(x>=DRAW_X && x<DRAW_X+DRAW_W && y>=DRAW_Y && y<DRAW_Y+DRAW_H)
                         ? COLOR : INITIAL;
        if (memory[FB+y*SCREEN_WIDTH+x]!=expected) {
            fprintf(stderr,"surface mismatch at (%u,%u): %02X != %02X\n",
                    x,y,memory[FB+y*SCREEN_WIDTH+x],expected);
            return 9;
        }
    }
    for (uint32_t i=0;i<GUARD;i++)
        if (memory[FB-GUARD+i]!=CANARY || memory[FB+SURFACE_BYTES+i]!=CANARY) return 10;

    for (uint32_t a=0;a<GUEST_SIZE;a++) {
        if (memory[a]==before[a]) continue;
        if (pixel_address(a)) continue;
        if (a>=STACK_TOP-0x100u && a<STACK_TOP+8u) continue;
        fprintf(stderr,"unexpected guest-memory delta at 0x%08X: %02X -> %02X\n",
                a,before[a],memory[a]);
        return 11;
    }
    if (pixel_write_count!=DRAW_W*DRAW_H) {
        fprintf(stderr,"expected %u byte stores to the surface, observed %u\n",
                DRAW_W*DRAW_H,pixel_write_count);
        return 12;
    }
    for (uint32_t i=0;i<pixel_write_count;i++) {
        uint32_t expected=FB+(DRAW_Y+i/DRAW_W)*SCREEN_WIDTH+DRAW_X+(i%DRAW_W);
        if (pixel_writes[i]!=expected) {
            fprintf(stderr,"surface write %u at 0x%08X, expected 0x%08X\n",
                    i,pixel_writes[i],expected);
            return 13;
        }
    }
    recomp_memory_diagnostic last=pixel_prior_access;
    if (!last.valid || last.instruction_va<0xB7050u || last.instruction_va>=0xB70F3u ||
        last.access!=RECOMP_MEM_ACCESS_WRITE || !pixel_address(last.linear) ||
        (last.width!=1u && last.width!=4u)) {
        fprintf(stderr,"last fill access unexpected: valid=%u insn=0x%08X access=%u linear=0x%08X width=%u\n",
                last.valid,last.instruction_va,last.access,last.linear,last.width);
        return 14;
    }
    if (!trace_has(0x96338u) || !trace_has(0x9FEB0u) || !trace_has(0xBBB10u) ||
        !trace_has(0xB7050u) || !trace_has(0xB7087u)) return 15;

    FILE *raw=fopen("evidence/partial_graphics_pixel_surface.raw","wb");
    if (!raw) return 16;
    if (fwrite(memory+FB,1u,SURFACE_BYTES,raw)!=SURFACE_BYTES || fclose(raw)!=0) return 17;

    /* Isolated state: the original VGA copy path uses width*height bytes and
       REP MOVSD. The destination is a separately backed guest region at A0000. */
    *(uint32_t *)(memory+STACK_TOP)=RECOMP_RETADDR;
    memcpy(before,memory,GUEST_SIZE);
    c.eip=0x9FFE0u; c.esp=STACK_TOP;
    uint32_t saved_ecx=c.ecx, saved_esi=c.esi, saved_edi=c.edi;
    recomp_memory_diag_set_guest_range(0xA0013u,0xA0014u);
    track_swap_access=1;
    if (gw_recomp_invoke(gw_partial_LbScreenSwap,&c)!=GW_RECOMP_OK) return 24;
    track_swap_access=0;
    if (c.interrupt_trap_pending || c.segment_fault_pending || c.memory_fault.pending) return 25;
    if (c.eax!=1u || c.esp!=STACK_TOP+4u || c.eip!=0x9FFE0u ||
        c.cur_func!=0x9FFE0u || c.ecx!=saved_ecx ||
        c.esi!=saved_esi || c.edi!=saved_edi) return 26;
    if (swap_source_bytes!=SURFACE_BYTES || swap_video_bytes!=SURFACE_BYTES) {
        fprintf(stderr,"swap range accounting: source=%u video=%u expected=%u\n",
                swap_source_bytes,swap_video_bytes,SURFACE_BYTES);
        return 27;
    }
    recomp_memory_diagnostic swap_video_access=recomp_memory_diag_last_access();
    if (!swap_source_access.valid || swap_source_access.instruction_va!=0xA0013u ||
        swap_source_access.linear!=FB || swap_source_access.width!=SURFACE_BYTES ||
        swap_source_access.access!=RECOMP_MEM_ACCESS_READ ||
        swap_source_access.backing!=RECOMP_MEM_BACKING_COMMITTED ||
        swap_source_access.host_address!=(uintptr_t)(memory+FB) ||
        !swap_video_access.valid || swap_video_access.instruction_va!=0xA0013u ||
        swap_video_access.segment!=RECOMP_SEG_ES || swap_video_access.selector!=0x14u ||
        swap_video_access.linear!=VIDEO_FB || swap_video_access.width!=SURFACE_BYTES ||
        swap_video_access.access!=RECOMP_MEM_ACCESS_WRITE ||
        swap_video_access.backing!=RECOMP_MEM_BACKING_COMMITTED ||
        swap_video_access.host_address!=(uintptr_t)(memory+VIDEO_FB)) {
        fprintf(stderr,"swap access context mismatch: src eip=%08X linear=%08X width=%u access=%u backing=%u; dst eip=%08X seg=%u selector=%04X linear=%08X width=%u access=%u backing=%u\n",
                swap_source_access.instruction_va,
                swap_source_access.linear,swap_source_access.width,swap_source_access.access,swap_source_access.backing,
                swap_video_access.instruction_va,swap_video_access.segment,swap_video_access.selector,
                swap_video_access.linear,swap_video_access.width,swap_video_access.access,swap_video_access.backing);
        return 33;
    }
    for (uint32_t i=0;i<GUARD;i++)
        if (memory[VIDEO_FB-GUARD+i]!=CANARY ||
            memory[VIDEO_FB+SURFACE_BYTES+i]!=CANARY) return 28;
    if (memcmp(memory+VIDEO_FB,memory+FB,SURFACE_BYTES)!=0) {
        fprintf(stderr,"video destination differs from WScreen after original swap\n");
        return 29;
    }
    for (uint32_t a=0;a<GUEST_SIZE;a++) {
        if (a>=VIDEO_FB && a<VIDEO_FB+SURFACE_BYTES) continue;
        if (a>=STACK_TOP-0x100u && a<STACK_TOP+8u) continue;
        /* The screen swap's lock/overlay helpers restore their transient state. */
        if (a==0x378E5Cu) continue;
        if (memory[a]!=before[a]) {
            fprintf(stderr,"unexpected swap memory delta at 0x%08X: %02X -> %02X\n",
                    a,before[a],memory[a]);
            return 30;
        }
    }
    raw=fopen("evidence/partial_graphics_pixel_video.raw","wb");
    if (!raw) return 31;
    if (fwrite(memory+VIDEO_FB,1u,SURFACE_BYTES,raw)!=SURFACE_BYTES || fclose(raw)!=0) return 32;
    SDL_SetMainReady();
    if (SDL_Init(SDL_INIT_VIDEO)!=0) {
        fprintf(stderr,"SDL_Init failed: %s\n",SDL_GetError()); return 18;
    }
    SDL_Window *window=SDL_CreateWindow("GeneWars 1.1 recomp — experimental authentic swapped video buffer",
        SDL_WINDOWPOS_CENTERED,SDL_WINDOWPOS_CENTERED,SCREEN_WIDTH*3,SCREEN_HEIGHT*3,0);
    if (!window) { fprintf(stderr,"SDL_CreateWindow failed: %s\n",SDL_GetError()); return 19; }
    SDL_Renderer *renderer=SDL_CreateRenderer(window,-1,SDL_RENDERER_SOFTWARE);
    if (!renderer) { fprintf(stderr,"SDL_CreateRenderer failed: %s\n",SDL_GetError()); return 20; }
    SDL_Texture *texture=SDL_CreateTexture(renderer,SDL_PIXELFORMAT_ARGB8888,
        SDL_TEXTUREACCESS_STREAMING,SCREEN_WIDTH,SCREEN_HEIGHT);
    uint32_t *diagnostic_rgba=(uint32_t *)malloc(SURFACE_BYTES*sizeof(uint32_t));
    if (!texture || !diagnostic_rgba) { fprintf(stderr,"SDL texture/buffer allocation failed: %s\n",SDL_GetError()); return 21; }
    /* SDL displays the post-swap guest video destination. The grayscale
       conversion is diagnostic only; GeneWars' instructions performed the copy. */
    SDL_PixelFormat *argb=SDL_AllocFormat(SDL_PIXELFORMAT_ARGB8888);
    if (!argb) { fprintf(stderr,"SDL_AllocFormat failed: %s\n",SDL_GetError()); return 22; }
    for (uint32_t i=0;i<SURFACE_BYTES;i++) {
        uint8_t value=memory[VIDEO_FB+i];
        diagnostic_rgba[i]=SDL_MapRGBA(argb,value,value,value,255);
    }
    SDL_FreeFormat(argb);
    if (SDL_UpdateTexture(texture,NULL,diagnostic_rgba,SCREEN_WIDTH*4)!=0 ||
        SDL_RenderClear(renderer)!=0 || SDL_RenderCopy(renderer,texture,NULL,NULL)!=0) {
        fprintf(stderr,"SDL present failed: %s\n",SDL_GetError()); return 22;
    }
    SDL_RenderPresent(renderer);
    uint32_t *capture=(uint32_t *)malloc((size_t)SCREEN_WIDTH*3u*SCREEN_HEIGHT*3u*sizeof(uint32_t));
    if (!capture || SDL_RenderReadPixels(renderer,NULL,SDL_PIXELFORMAT_ARGB8888,capture,
                                         SCREEN_WIDTH*3*4)!=0) {
        fprintf(stderr,"SDL_RenderReadPixels failed: %s\n",SDL_GetError()); return 23;
    }
    SDL_Surface *capture_surface=SDL_CreateRGBSurfaceWithFormatFrom(capture,SCREEN_WIDTH*3,
        SCREEN_HEIGHT*3,32,SCREEN_WIDTH*3*4,SDL_PIXELFORMAT_ARGB8888);
    if (!capture_surface || SDL_SaveBMP(capture_surface,"evidence/partial_graphics_pixel_sdl_present.bmp")!=0) {
        fprintf(stderr,"SDL_SaveBMP failed: %s\n",SDL_GetError()); return 23;
    }
    printf("PASS SDL presents the post-LbScreenSwap_ guest video region with diagnostic grayscale (not game palette)\n");
    printf("SDL window visible for 5 seconds; captured evidence/partial_graphics_pixel_sdl_present.bmp\n");
    SDL_Delay(5000);
    SDL_FreeSurface(capture_surface); free(capture); free(diagnostic_rgba);
    SDL_DestroyTexture(texture); SDL_DestroyRenderer(renderer); SDL_DestroyWindow(window); SDL_Quit();
    printf("PASS authentic GeneWars clear+swap: draw=0x%08X video=0x%08X, experimental %ux%u byte-indexed surface, rect=%u,%u %ux%u color=0x%02X, fill_stores=%u swap_src_bytes=%u swap_video_bytes=%u\n",
           *(uint32_t *)(memory+DRAW_PTR),VIDEO_FB,SCREEN_WIDTH,SCREEN_HEIGHT,DRAW_X,DRAW_Y,DRAW_W,DRAW_H,COLOR,
           pixel_write_count,swap_source_bytes,swap_video_bytes);
    printf("SWAP_ACCESS source=eip:%08X selector:%04X segment:DS linear:%08X host:%p width:%u read backing:committed; destination=eip:%08X selector:%04X segment:ES linear:%08X host:%p width:%u write backing:committed\n",
           swap_source_access.instruction_va,swap_source_access.selector,swap_source_access.linear,
           (void *)swap_source_access.host_address,swap_source_access.width,
           swap_video_access.instruction_va,swap_video_access.selector,swap_video_access.linear,
           (void *)swap_video_access.host_address,swap_video_access.width);
    printf("TRACE");
    for (uint32_t i=0;i<g_enter_idx && i<RECOMP_ENTER_SIZE;i++) printf(" 0x%08X",g_enter_trace[i]);
    printf("\n");
    free(before); free(memory); return 0;
}
