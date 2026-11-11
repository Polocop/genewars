#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../runtime/gw_segments.h"

uint32_t g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,g_cur_func;
uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_fs,g_seg_gs,g_seg_ss,g_fpu_cw;
uint32_t g_fs_base,g_gs_base;
ptrdiff_t g_mem_base;
double g_st[8]; int g_fp_top;

int main(void) {
    uint8_t guest[0x1000]={0};
    guest[5]=0x73;
    guest[0x330]=0x5a;
    guest[0xfff]=0xa5;
    guest[0x46b]=0x11; guest[0x46c]=0x22; guest[0x46d]=0x33; guest[0x46e]=0x44;
    g_mem_base=(ptrdiff_t)(uintptr_t)guest;
    g_seg_ds=0x14u; g_ds_base=0;
    g_eax=0x11111111u; g_ebx=0x22222222u; g_ecx=0x33333333u;
    g_edx=0x44444444u; g_esi=0x55555555u; g_edi=0x66666666u;
    g_ebp=0x77777777u; g_esp=0x88888888u;
    recomp_set_memory_bounds(0u,sizeof guest);
    recomp_memory_diag_enable(1);
    recomp_memory_diag_set_guest_eip(0x215d5u);
    recomp_memory_diag_note_instruction(0x215d5u,0x8au,"mov",RECOMP_SEG_DS,
        RECOMP_MEM_ACCESS_READ,g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp);
    recomp_null_ds_read_diag_enable(1);
    recomp_begin_memory_access_ex(RECOMP_SEG_DS,1u,0x215d5u,
        RECOMP_MEM_ACCESS_READ,0x8au,"mov");
    uint8_t observed=MEM8(5u);
    recomp_end_memory_access();
    recomp_null_ds_read_diagnostic d=recomp_null_ds_read_diag_last();
    if (observed!=0x73u || d.count!=1u || d.guest_eip!=0x215d5u ||
        d.instruction_va!=0x215d5u || d.instruction_id!=0x8au ||
        d.selector!=0x14u || d.segment_base!=0 || d.linear!=5u ||
        d.offset!=5u || d.width!=1u || d.access!=RECOMP_MEM_ACCESS_READ ||
        strcmp(d.mnemonic,"mov") || d.eax!=g_eax || d.ebx!=g_ebx ||
        d.ecx!=g_ecx || d.edx!=g_edx || d.esi!=g_esi || d.edi!=g_edi ||
        d.ebp!=g_ebp || d.esp!=g_esp || guest[5]!=0x73u) return 10;

    /* The requested IVT read is recorded without changing guest state. */
    recomp_begin_memory_access_ex(RECOMP_SEG_DS,1u,0x21380u,
        RECOMP_MEM_ACCESS_READ,0x8au,"mov");
    observed=MEM8(0x330u);
    recomp_end_memory_access();
    d=recomp_null_ds_read_diag_last();
    if (observed!=0x5au || d.count!=2u || d.linear!=0x330u ||
        d.guest_eip!=0x21380u || guest[0x330]!=0x5au) return 14;

    /* Do not misclassify the BIOS tick counter, even for a crossing read. */
    recomp_begin_memory_access_ex(RECOMP_SEG_DS,1u,0x21380u,
        RECOMP_MEM_ACCESS_READ,0x8au,"mov");
    (void)MEM8(0x46cu);
    recomp_end_memory_access();
    recomp_begin_memory_access_ex(RECOMP_SEG_DS,4u,0x21380u,
        RECOMP_MEM_ACCESS_READ,0x8bu,"mov");
    (void)MEM32(0x46bu);
    recomp_end_memory_access();
    if (recomp_null_ds_read_diag_count()!=2u || guest[0x46c]!=0x22u ||
        guest[0x46d]!=0x33u) return 15;

    recomp_begin_memory_access_ex(RECOMP_SEG_DS,1u,0x21380u,
        RECOMP_MEM_ACCESS_READ,0x8au,"mov");
    observed=MEM8(0xfffu);
    recomp_end_memory_access();
    d=recomp_null_ds_read_diag_last();
    if (observed!=0xa5u || d.count!=3u || d.linear!=0xfffu ||
        guest[0xfff]!=0xa5u) return 16;

    recomp_begin_memory_access_ex(RECOMP_SEG_DS,1u,0x21380u,
        RECOMP_MEM_ACCESS_READ,0x8au,"mov");
    (void)MEM8(0x1000u); /* backing fault: outside the probed 4 KiB window */
    recomp_end_memory_access();
    if (recomp_null_ds_read_diag_count()!=3u) return 17;
    recomp_clear_memory_fault();

    recomp_begin_memory_access_ex(RECOMP_SEG_DS,1u,0x215d5u,
        RECOMP_MEM_ACCESS_WRITE,0x88u,"mov");
    MEM8(6u)=0x4au;
    recomp_end_memory_access();
    if (recomp_null_ds_read_diag_count()!=3u || guest[6]!=0x4au) return 11;

    recomp_null_ds_read_diag_enable(0);
    recomp_memory_diag_enable(0);
    recomp_null_ds_read_diag_enable(1);
    recomp_begin_memory_access_ex(RECOMP_SEG_DS,1u,0x215d5u,
        RECOMP_MEM_ACCESS_READ,0x8au,"mov");
    observed=MEM8(5u);
    recomp_end_memory_access();
    d=recomp_null_ds_read_diag_last();
    if (observed!=0x73u || recomp_null_ds_read_diag_count()!=1u ||
        d.guest_eip!=0x215d5u || d.linear!=5u || d.selector!=0x14u ||
        guest[5]!=0x73u) return 12;
    recomp_null_ds_read_diag_enable(0);
    recomp_begin_memory_access_ex(RECOMP_SEG_DS,1u,0x215d5u,
        RECOMP_MEM_ACCESS_READ,0x8au,"mov");
    observed=MEM8(5u);
    recomp_end_memory_access();
    if (observed!=0x73u || recomp_null_ds_read_diag_count()!=0u ||
        guest[5]!=0x73u) return 13;

    puts("PASS opt-in DS=14 low-read trace preserves guest read, registers and memory");
    return 0;
}
