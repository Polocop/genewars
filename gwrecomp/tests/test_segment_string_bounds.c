#define RECOMP_GENERATED_CODE
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../runtime/gw_segments.h"
int gw_recomp_guest_instruction(unsigned int guest_va);
#include "segment_string_lifts.c"

uint32_t g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,g_cur_func;
uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_fs,g_seg_gs,g_seg_ss,g_fpu_cw;
uint32_t g_fs_base,g_gs_base;
uint32_t g_icall_trace[ICALL_TRACE_SIZE],g_icall_from[ICALL_TRACE_SIZE];
uint32_t g_icall_trace_idx,g_icall_count;
ptrdiff_t g_mem_base;
double g_st[8]; int g_fp_top;
static uint8_t memory[32];

int gw_recomp_guest_instruction(unsigned int guest_va) { (void)guest_va; return 1; }
static void test_return(void) {}
recomp_func_t recomp_lookup(uint32_t va) { (void)va; return NULL; }
recomp_func_t recomp_lookup_manual(uint32_t va) { return va==RECOMP_RETADDR ? test_return : NULL; }
recomp_func_t recomp_lookup_import(uint32_t va) { (void)va; return NULL; }

static int resolve(uint16_t selector,uint32_t *base,void *user) {
    (void)user;
    if (selector==0) { *base=0; return 1; }
    if (selector==0x30 || selector==0x40 || selector==0x50 || selector==0x60) { *base=0x1000; return 1; }
    return 0;
}
static int validate(uint16_t selector,uint32_t offset,uint32_t width,void *user) {
    (void)user;
    if (selector==0x60) return offset>=0x1018u && (uint64_t)offset+width<=0x1020u;
    return (selector==0x30 || selector==0x40 || selector==0x50) && (uint64_t)offset+width<=16;
}
static void reset(void) {
    memset(memory,0,sizeof memory); g_mem_base=(ptrdiff_t)(uintptr_t)memory-0x1000;
    *(uint32_t *)(memory+24)=RECOMP_RETADDR;
    g_seg_ds=0x30; g_seg_es=0x40; g_seg_ss=0x60; g_ds_base=g_es_base=0x1000; g_ss_base=0;
    g_eax=g_ebx=g_ecx=g_edx=g_esi=g_edi=g_ebp=0; g_esp=0x1018;
    recomp_clear_memory_fault();
    g_flag_k=FK_NONE; g_flag_a=g_flag_b=g_flag_cf=0;
}

int main(void) {
    recomp_set_segment_resolver(resolve,NULL); recomp_set_segment_range_validator(validate,NULL);
    recomp_set_memory_bounds(0x1000,sizeof memory);

    reset(); memory[0]=0x5a; g_esi=0; g_edi=8; movsb();
    if (memory[8]!=0x5a || g_esi!=1 || g_edi!=9 || recomp_memory_fault_pending()) return 10;
    reset(); memory[2]=0x6c; g_seg_ds=0; g_seg_fs=0x50; g_fs_base=0x1000; g_esi=2; g_edi=8; fs_movsb();
    if (memory[8]!=0x6c || g_esi!=3 || g_edi!=9 || recomp_memory_fault_pending()) {
        fprintf(stderr,"fs movsb: dst=%02x esi=%08x edi=%08x fault=%u\n",memory[8],g_esi,g_edi,recomp_memory_fault_pending()); return 23;
    }

    reset(); memory[0]=1; memory[1]=2; memory[2]=3; memory[3]=4; g_ecx=4; g_esi=3; g_edi=7;
    std_rep_movsb();
    if (memcmp(memory+4,"\1\2\3\4",4) || g_esi!=UINT32_MAX || g_edi!=3 || g_ecx!=0 || recomp_memory_fault_pending()) return 11;

    /* REP MOVSB performs sequential byte copies. LZ back-references rely on
     * newly written bytes feeding later reads; memmove would copy a snapshot. */
    reset(); memset(memory,0,sizeof memory); *(uint32_t *)(memory+24)=RECOMP_RETADDR; memory[0]=0x7c; g_ecx=6; g_esi=0; g_edi=1;
    rep_movsb();
    for (unsigned i=0;i<7;i++) if (memory[i]!=0x7c) return 24;
    if (g_esi!=6 || g_edi!=7 || g_ecx!=0 || recomp_memory_fault_pending()) return 25;

    reset(); memset(memory,0,sizeof memory); *(uint32_t *)(memory+24)=RECOMP_RETADDR; memory[7]=0x39; g_ecx=6; g_esi=7; g_edi=6;
    std_rep_movsb();
    for (unsigned i=1;i<8;i++) if (memory[i]!=0x39) return 26;
    if (g_esi!=1 || g_edi!=0 || g_ecx!=0 || recomp_memory_fault_pending()) return 27;

    reset(); memory[0]=1; memory[1]=2; memory[2]=3; memory[3]=4; g_ecx=4; g_esi=0; g_edi=14;
    rep_movsb();
    recomp_memory_fault f=recomp_get_memory_fault();
    if (!f.pending || f.segment!=RECOMP_SEG_ES || f.offset!=14 || f.width!=4 || f.instruction_va!=0x14000010 ||
        g_ecx!=4 || memory[14]!=0 || memory[15]!=0) return 12;

    reset(); g_eax=0x0000007bu; g_ecx=3; g_edi=4; rep_stosb();
    if (memory[4]!=0x7b || memory[5]!=0x7b || memory[6]!=0x7b || g_ecx!=0 || recomp_memory_fault_pending()) return 13;
    reset(); g_edi=15; stosw(); f=recomp_get_memory_fault();
    if (!f.pending || f.segment!=RECOMP_SEG_ES || f.offset!=15 || f.width!=2 || f.instruction_va!=0x14000090 || g_edi!=15) return 14;

    reset(); memory[2]=0x66; g_esi=2; lodsb();
    if ((g_eax&0xff)!=0x66 || g_esi!=3 || recomp_memory_fault_pending()) return 15;
    reset(); g_esi=15; g_eax=0x1234abcd; lodsw(); f=recomp_get_memory_fault();
    if (!f.pending || f.segment!=RECOMP_SEG_DS || f.offset!=15 || f.width!=2 || f.instruction_va!=0x140000A0 || g_esi!=15 || g_eax!=0x1234abcd) return 16;

    reset(); memory[1]=memory[2]=0x40; g_esi=1; g_edi=2; cmpsb();
    if (recomp_memory_fault_pending() || (g_flag_k==FK_NONE)) return 17;
    reset(); g_esi=0; g_edi=15; cmpsw(); f=recomp_get_memory_fault();
    if (!f.pending || f.segment!=RECOMP_SEG_ES || f.offset!=15 || f.width!=2 || f.instruction_va!=0x140000B0) return 18;
    reset(); memory[0]=0x5a; g_eax=0x5a; g_edi=0; g_ecx=1; repne_scasb();
    if (recomp_memory_fault_pending()) return 19;
    reset(); g_eax=0x1234; g_edi=15; scasw(); f=recomp_get_memory_fault();
    if (!f.pending || f.segment!=RECOMP_SEG_ES || f.offset!=15 || f.width!=2 || f.instruction_va!=0x140000C0) return 20;

    reset(); memory[15]=0x22; memory[0]=0x22; g_ecx=2; g_esi=15; g_edi=0;
    repe_cmpsb(); f=recomp_get_memory_fault();
    if (!f.pending || f.segment!=RECOMP_SEG_DS || f.offset!=16 || f.instruction_va!=0x14000060 ||
        g_ecx!=1 || g_esi!=16 || g_edi!=1 || g_flag_k!=FK_CMP || g_flag_a!=0x22 || g_flag_b!=0x22) return 21;

    reset(); memory[15]=0x22; g_eax=0x11; g_ecx=2; g_edi=15;
    repne_scasb(); f=recomp_get_memory_fault();
    if (!f.pending || f.segment!=RECOMP_SEG_ES || f.offset!=16 || f.instruction_va!=0x14000080 ||
        g_ecx!=1 || g_edi!=16 || g_flag_k!=FK_CMP || g_flag_a!=0x11 || g_flag_b!=0x22) return 22;

    puts("PASS implicit string source/destination bounds, REP/DF, and precise faults");
    return 0;
}
