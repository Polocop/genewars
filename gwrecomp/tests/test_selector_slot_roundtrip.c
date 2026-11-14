#include "recomp_context.h"
#include "gw_interrupts.h"
#include "gw_segments.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void gw_original_save_ds(void);
void gw_original_restore_ds(void);
uint32_t g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,g_cur_func;
uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_fs,g_seg_gs,g_seg_ss,g_fpu_cw;
uint32_t g_fs_base,g_gs_base;
ptrdiff_t g_mem_base;
double g_st[8]; int g_fp_top;
uint32_t g_icall_trace[ICALL_TRACE_SIZE],g_icall_from[ICALL_TRACE_SIZE];
uint32_t g_icall_trace_idx,g_icall_count;

recomp_func_t recomp_lookup_manual(uint32_t va) { (void)va; return NULL; }
recomp_func_t recomp_lookup(uint32_t va) { (void)va; return NULL; }
recomp_func_t recomp_lookup_import(uint32_t va) { (void)va; return NULL; }

#define GUEST_SIZE 0x02A00000u
#define SLOT 0x0029AC41u
static uint8_t *guest;

static int resolve(uint16_t selector, uint32_t *base, void *user) {
    (void)user;
    if (!base) return 0;
    if (selector == 0x160u || selector == 0x168u || selector == 0x14u ||
        selector == 0x24u) {
        *base = 0; /* isolated flat-model descriptor fixture */
        return 1;
    }
    return 0;
}

static gw_recomp_context initial(uint16_t ds) {
    gw_recomp_context c;
    memset(&c, 0, sizeof c);
    c.eax=0x12345678u; c.ebx=0xDEADBEEFu; c.ecx=0xAABBCCDDu;
    c.edx=0x87654321u; c.esp=0x10000u; c.cs=0x160u; c.ds=ds;
    c.es=0x168u; c.ss=0x168u;
    c.mem_base=(ptrdiff_t)(uintptr_t)guest;
    c.mem_guest_base=0; c.mem_size=GUEST_SIZE;
    *(uint32_t *)(guest+c.esp)=RECOMP_RETADDR;
    return c;
}

int main(void) {
    static const uint16_t cases[] = {0x24u, 0x168u};
    guest=(uint8_t *)calloc(GUEST_SIZE,1);
    if (!guest) return 10;
    recomp_set_segment_resolver(resolve,NULL);
    for (unsigned i=0;i<sizeof(cases)/sizeof(cases[0]);i++) {
        memset(guest+SLOT-2,0xA5,6);
        gw_recomp_context c=initial(cases[i]);
        if (gw_recomp_invoke(gw_original_save_ds,&c)!=GW_RECOMP_OK ||
            c.memory_fault.pending || c.segment_fault_pending ||
            *(uint16_t *)(guest+SLOT)!=cases[i] || guest[SLOT-1]!=0xA5 || guest[SLOT+2]!=0xA5)
            return 1;
        c=initial(0x14u); /* a distinct pre-read DS in this experimental fixture */
        if (gw_recomp_invoke(gw_original_restore_ds,&c)!=GW_RECOMP_OK ||
            c.memory_fault.pending || c.segment_fault_pending || c.ds!=cases[i] ||
            c.eax!=0x12345678u || c.ebx!=0xDEADBEEFu || c.ecx!=0xAABBCCDDu ||
            c.edx!=0x87654321u || c.esp!=0x10004u)
            return 2;
    }
    if (g_icall_count!=0) return 3;
    puts("PASS original LE-fixed ES save and CS restore share one flat slot; DS is preserved");
    free(guest);
    return 0;
}
