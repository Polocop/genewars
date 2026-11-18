#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../runtime/gw_segments.h"

uint32_t g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,g_cur_func;
uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_fs,g_seg_gs,g_seg_ss,g_fpu_cw;
uint32_t g_fs_base,g_gs_base;
ptrdiff_t g_mem_base;
double g_st[8]; int g_fp_top;

static uint8_t memory[16];
static uint32_t descriptor_limit=15;
static int resolve(uint16_t selector,uint32_t *base,void *user) {
    (void)user;
    if (selector==0) { *base=0; return 1; }
    if (selector==0x30) { *base=0x1000; return 1; }
    return 0;
}
static int validate(uint16_t selector,uint32_t offset,uint32_t width,void *user) {
    (void)user;
    return selector==0x30 && (uint64_t)offset+width <= (uint64_t)descriptor_limit+1u;
}

int main(void) {
    memset(memory,0,sizeof memory);
    g_mem_base=(ptrdiff_t)(uintptr_t)memory-(ptrdiff_t)0x1000;
    g_seg_ds=0x30; g_ds_base=0x1000;
    recomp_set_segment_resolver(resolve,NULL);
    recomp_set_segment_range_validator(validate,NULL);
    recomp_set_memory_bounds(0x1000, sizeof memory);

    recomp_begin_memory_access(RECOMP_SEG_DS,4,0x12345678);
    MEM32(0x1000)=0xA1B2C3D4u;
    if (recomp_memory_fault_pending() || *(uint32_t*)memory!=0xA1B2C3D4u) return 10;
    recomp_end_memory_access();

    recomp_begin_memory_access(RECOMP_SEG_DS,4,0x12345679);
    MEM32(0x100E)=0xFFFFFFFFu;
    recomp_memory_fault fault=recomp_get_memory_fault();
    if (!fault.pending || fault.segment!=RECOMP_SEG_DS || fault.selector!=0x30 ||
        fault.offset!=14 || fault.width!=4 || fault.instruction_va!=0x12345679 ||
        memory[14]!=0 || memory[15]!=0) return 11;

    descriptor_limit=0xFFFF;
    recomp_clear_memory_fault();
    recomp_set_memory_bounds(0x1000, sizeof memory);
    recomp_begin_memory_access(RECOMP_SEG_DS,2,0x1234567A);
    (void)MEM16(0x100F);
    fault=recomp_get_memory_fault();
    if (!fault.pending || fault.offset!=15 || fault.width!=2 || fault.instruction_va!=0x1234567A) return 12;

    recomp_clear_memory_fault();
    if (!recomp_write_segment(RECOMP_SEG_DS,0,0x1234567B) || g_seg_ds!=0) return 13;
    recomp_begin_memory_access(RECOMP_SEG_DS,1,0x1234567C);
    (void)MEM8(0);
    fault=recomp_get_memory_fault();
    if (!fault.pending || fault.selector!=0 || fault.instruction_va!=0x1234567C) return 14;

    puts("PASS segment limit, mapped range, null selector, and precise access fault");
    return 0;
}
