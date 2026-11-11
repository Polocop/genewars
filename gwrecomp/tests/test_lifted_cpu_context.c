#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "recomp_context.h"
#include "recomp_bridge.h"

uint32_t g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,g_cur_func;
uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_fs,g_seg_gs,g_seg_ss,g_fpu_cw;
uint32_t g_fs_base,g_gs_base;
ptrdiff_t g_mem_base;
double g_st[8]; int g_fp_top;
extern void gw_lift_0000(void);
static gw_recomp_context *nested_context;
static gw_recomp_status nested_result;
static void nested_probe(void) { nested_result=gw_recomp_invoke(nested_probe,nested_context); }
static unsigned char direct_mem[4096], context_mem[4096];
static const recomp_dispatch_entry_t test_dispatch[] = {
    {0x00015570u, gw_lift_0000},
    {0xf0015570u, gw_lift_0000}
};
static gw_recomp_context direct_state, context_state;
static void init(gw_recomp_context *c,unsigned char *mem) {
    memset(c,0,sizeof(*c)); c->eax=0x00100100; c->ebx=0x12345678; c->ecx=0x23456789;
    c->edx=0x3456789a; c->esi=0x456789ab; c->edi=0x56789abc; c->ebp=0x6789abcd; c->esp=0x00102000;
    c->eip=0x00015570; c->cs=0x0c; c->ds=0x14; c->es=0x14; c->fs=0; c->gs=0; c->ss=0x14;
    c->flag_k=FK_NONE; c->flag_a=0x11111111; c->flag_b=0x22222222; c->flag_cf=1;
    for(int i=0;i<8;i++) c->st[i]=(double)i+0.25;
    c->fp_top=3; c->fpu_cw=0x037f; c->cur_func=0x00015570; c->cs_base=0x10; c->ds_base=0x20; c->es_base=0x30; c->fs_base=0x40; c->gs_base=0x50; c->ss_base=0x60;
    c->mem_base=(ptrdiff_t)(uintptr_t)mem-0x00100000;
}
int main(void) {
    memset(direct_mem,0xA5,sizeof(direct_mem)); memset(context_mem,0xA5,sizeof(context_mem));
    init(&direct_state,direct_mem); init(&context_state,context_mem);
    g_eax=direct_state.eax; g_ebx=direct_state.ebx; g_ecx=direct_state.ecx; g_edx=direct_state.edx;
    g_esi=direct_state.esi; g_edi=direct_state.edi; g_ebp=direct_state.ebp; g_esp=direct_state.esp;
    g_seg_cs=direct_state.cs; g_seg_ds=direct_state.ds; g_seg_es=direct_state.es; g_seg_fs=direct_state.fs; g_seg_gs=direct_state.gs; g_seg_ss=direct_state.ss;
    g_flag_k=direct_state.flag_k; g_flag_a=direct_state.flag_a; g_flag_b=direct_state.flag_b; g_flag_cf=direct_state.flag_cf;
    memcpy(g_st,direct_state.st,sizeof(g_st)); g_fp_top=direct_state.fp_top; g_fpu_cw=direct_state.fpu_cw; g_cur_func=direct_state.cur_func;
    g_cs_base=direct_state.cs_base; g_ds_base=direct_state.ds_base; g_es_base=direct_state.es_base;
    g_fs_base=direct_state.fs_base; g_gs_base=direct_state.gs_base; g_ss_base=direct_state.ss_base; g_mem_base=direct_state.mem_base;
    gw_lift_0000();
    direct_state.eax=g_eax; direct_state.ebx=g_ebx; direct_state.ecx=g_ecx; direct_state.edx=g_edx;
    direct_state.esi=g_esi; direct_state.edi=g_edi; direct_state.ebp=g_ebp; direct_state.esp=g_esp;
    direct_state.cs=g_seg_cs; direct_state.ds=g_seg_ds; direct_state.es=g_seg_es; direct_state.fs=g_seg_fs; direct_state.gs=g_seg_gs; direct_state.ss=g_seg_ss;
    direct_state.flag_k=g_flag_k; direct_state.flag_a=g_flag_a; direct_state.flag_b=g_flag_b; direct_state.flag_cf=g_flag_cf;
    memcpy(direct_state.st,g_st,sizeof(g_st)); direct_state.fp_top=g_fp_top; direct_state.fpu_cw=g_fpu_cw; direct_state.cur_func=g_cur_func;
    direct_state.cs_base=g_cs_base; direct_state.ds_base=g_ds_base; direct_state.es_base=g_es_base;
    direct_state.fs_base=g_fs_base; direct_state.gs_base=g_gs_base; direct_state.ss_base=g_ss_base;
    if(gw_recomp_dispatch(test_dispatch,2,0xf0015570u,&context_state)!=GW_DISPATCH_OK) return 10;
    if(context_state.eip!=0xf0015570u || context_state.esp!=direct_state.esp || context_state.eax!=direct_state.eax) return 11;
    if(context_state.ebx!=direct_state.ebx || context_state.ecx!=direct_state.ecx || context_state.edx!=direct_state.edx || context_state.esi!=direct_state.esi || context_state.edi!=direct_state.edi || context_state.ebp!=direct_state.ebp) return 12;
    if(context_state.flag_k!=direct_state.flag_k || context_state.flag_a!=direct_state.flag_a || context_state.flag_b!=direct_state.flag_b || context_state.flag_cf!=direct_state.flag_cf) return 13;
    if(context_state.cs!=direct_state.cs || context_state.ds!=direct_state.ds || context_state.es!=direct_state.es || context_state.fs!=direct_state.fs || context_state.gs!=direct_state.gs || context_state.ss!=direct_state.ss) return 14;
    if(context_state.cs_base!=direct_state.cs_base || context_state.ds_base!=direct_state.ds_base || context_state.es_base!=direct_state.es_base || context_state.fs_base!=direct_state.fs_base || context_state.gs_base!=direct_state.gs_base || context_state.ss_base!=direct_state.ss_base) return 22;
    if(memcmp(context_state.st,direct_state.st,sizeof(g_st)) || context_state.fp_top!=direct_state.fp_top || context_state.fpu_cw!=direct_state.fpu_cw) return 15;
    if(memcmp(direct_mem,context_mem,sizeof(direct_mem)) || direct_mem[0x106]!=0 || context_mem[0x106]!=0) return 16;
    if(gw_recomp_dispatch(test_dispatch,2,0x70015570u,&context_state)!=GW_DISPATCH_NOT_FOUND) return 17;
    if(gw_recomp_dispatch(NULL,0,0,&context_state)!=GW_DISPATCH_INVALID) return 19;
    if(gw_recomp_invoke(NULL,&context_state)!=GW_RECOMP_INVALID) return 20;
    nested_context=&context_state; nested_result=GW_RECOMP_OK;
    if(gw_recomp_invoke(nested_probe,&context_state)!=GW_RECOMP_OK || nested_result!=GW_RECOMP_BUSY) return 21;
    puts("PASS real lift direct/global vs explicit CPU context"); return 0;
}
