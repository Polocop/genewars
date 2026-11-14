#define RECOMP_GENERATED_CODE
#define RECOMP_LOCAL_REGS
#include "recomp_types.h"
#include "recomp_context.h"
#include "gw_interrupts.h"
#include "gw_segments.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void gw_original_title_loadall(void);
void sub_00014FF0(void);
int gw_recomp_guest_instruction(unsigned int guest_va);

uint32_t g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,g_cur_func;
uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_fs,g_seg_gs,g_seg_ss,g_fpu_cw;
uint32_t g_fs_base,g_gs_base;
ptrdiff_t g_mem_base;
double g_st[8]; int g_fp_top;
uint32_t g_icall_trace[ICALL_TRACE_SIZE],g_icall_from[ICALL_TRACE_SIZE];
uint32_t g_icall_trace_idx,g_icall_count;

static uint32_t observed[8];
static unsigned load_calls;

void sub_00014FF0(void) {
    if (load_calls < 8u) observed[load_calls] = g_edx;
    load_calls++;
    /* Explicit boundary: resource load not executed. Return 0 (failure),
       and consume the synthetic guest return pushed by RECOMP_CALL. */
    g_eax = 0;
    g_esp += 4u;
}

recomp_func_t recomp_lookup_manual(uint32_t va) { (void)va; return NULL; }
recomp_func_t recomp_lookup_import(uint32_t va) { (void)va; return NULL; }
recomp_func_t recomp_lookup(uint32_t va) { (void)va; return NULL; }

static int resolve(uint16_t selector, uint32_t *base, void *user) {
    (void)user;
    if (!base || (selector != 0x160u && selector != 0x168u &&
                  selector != 0x14u && selector != 0x24u)) return 0;
    *base = 0;
    return 1;
}

static int check(int ok, const char *message) {
    if (!ok) fprintf(stderr, "FAIL %s\n", message);
    return ok;
}

int main(void) {
    enum { GUEST_SIZE=0x400000u, IMAGE_BASE=0xF0000u,
           IMAGE_SIZE=0x293000u, LIST=0x2DFEE8u, STACK=0x3F0000u,
           ENTRY_COUNT=4u, STRIDE=0x2Cu };
    static const char *names[ENTRY_COUNT] = {
        "data/iftitle.anb", "data/titlescr.pal", "data/font2.dat", "data/font2.tab"
    };
    uint8_t *memory=(uint8_t *)calloc(GUEST_SIZE,1);
    if (!memory) return 2;
    const char *guest_path = getenv("GW_TITLE_LOADALL_GUEST");
    FILE *f=fopen(guest_path ? guest_path : "build/authentic_title_loadall_guest.bin","rb");
    if (!f) { free(memory); return 3; }
    if (fread(memory+IMAGE_BASE,1,IMAGE_SIZE,f)!=IMAGE_SIZE) {
        fclose(f); free(memory); return 4;
    }
    fclose(f);
    uint8_t before[ENTRY_COUNT*STRIDE];
    memcpy(before,memory+LIST,sizeof before);
    for (unsigned i=0;i<ENTRY_COUNT;i++) {
        if (!check(strcmp((char *)(memory+LIST+i*STRIDE),names[i])==0,
                   "LE title resource path and 44-byte record stride")) {
            free(memory); return 5;
        }
    }
    if (!check(memory[LIST+ENTRY_COUNT*STRIDE]==0,"original zero-name list terminator")) {
        free(memory); return 6;
    }
    recomp_code_range range={0x1FB000u,0x10000u,0xDE930u};
    if (!recomp_code_map_set(&range,1)) { free(memory); return 7; }
    recomp_set_segment_resolver(resolve,NULL);

    gw_recomp_context c; memset(&c,0,sizeof c);
    c.eax=0x117498u; c.edx=LIST; c.esp=STACK;
    c.cs=0x160u; c.ds=0x168u; c.es=0x168u; c.ss=0x168u;
    c.mem_base=(ptrdiff_t)(uintptr_t)memory;
    c.mem_guest_base=0; c.mem_size=GUEST_SIZE;
    *(uint32_t *)(memory+STACK)=RECOMP_RETADDR;
    if (gw_recomp_invoke(gw_original_title_loadall,&c)!=GW_RECOMP_OK ||
        c.memory_fault.pending || c.segment_fault_pending || c.esp!=STACK+4u ||
        c.eax!=ENTRY_COUNT || load_calls!=ENTRY_COUNT ||
        memcmp(memory+LIST,before,sizeof before)!=0) {
        fprintf(stderr,"LbDataLoadAll_ failed eax=%08x esp=%08x calls=%u memfault=%u segfault=%u\n",
                c.eax,c.esp,load_calls,c.memory_fault.pending,c.segment_fault_pending);
        free(memory); return 8;
    }
    for (unsigned i=0;i<ENTRY_COUNT;i++) {
        if (observed[i]!=LIST+i*STRIDE) {
            fprintf(stderr,"record %u passed as %08x expected %08x\n",i,observed[i],LIST+i*STRIDE);
            free(memory); return 9;
        }
    }
    puts("PASS original recompiled LbDataLoadAll_ walks the four authentic titleGfx_files LE records at 0x2c stride");
    puts("PASS original error-count path totals four bounded load failures; no file-open or resource-load success is fabricated");
    free(memory);
    return 0;
}
