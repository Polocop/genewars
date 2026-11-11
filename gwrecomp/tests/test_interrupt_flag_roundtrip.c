#include "gw_interrupts.h"
#include <stdio.h>

uint32_t g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,g_cur_func;
uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_fs,g_seg_gs,g_seg_ss;
uint32_t g_fs_base,g_gs_base;
ptrdiff_t g_mem_base;

void recomp_memory_diag_set_dpmi_state(uint32_t a,uint32_t b,uint32_t c,uint32_t d,
    uint32_t e,uint32_t f,uint32_t g,uint32_t h,uint32_t cf) {
    (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;(void)cf;
}

static uint32_t service_cf;
static gw_interrupt_result handled_interrupt(uint8_t vector,uint32_t site,void *user) {
    (void)site;(void)user;
    if(vector!=0x21u) return GW_INTERRUPT_TRAPPED;
    g_flag_cf=service_cf;
    return GW_INTERRUPT_HANDLED;
}

int main(void) {
    gw_interrupt_set_callback(handled_interrupt,NULL);

    /* D72C9 compares its chunk length with 0xffff before INT 21h. That old
       comparison has CF=1, but a successful DOS read returns CF=0. */
    g_flag_k=FK_CMP; g_flag_a=0x68u; g_flag_b=0xffffu; g_flag_cf=1u;
    service_cf=0u;
    if(gw_interrupt_dispatch(0x21u,0x000d72edu)!=GW_INTERRUPT_HANDLED ||
       g_flag_k!=FK_EFLAGS ||
       recomp_cond_cf(g_flag_k,g_flag_a,g_flag_b,CC_B,g_flag_cf) ||
       recomp_cond(g_flag_k,g_flag_a,g_flag_b,CC_E)) {
        fputs("FAIL handled DOS interrupt kept stale pre-INT carry\n",stderr);
        return 1;
    }

    /* A DOS error returns CF=1 while preserving the prior ZF from CMP. */
    g_flag_k=FK_CMP; g_flag_a=0x1234u; g_flag_b=0x1234u; g_flag_cf=0u;
    service_cf=1u;
    if(gw_interrupt_dispatch(0x21u,0x000d72edu)!=GW_INTERRUPT_HANDLED ||
       !recomp_cond_cf(g_flag_k,g_flag_a,g_flag_b,CC_B,g_flag_cf) ||
       !recomp_cond(g_flag_k,g_flag_a,g_flag_b,CC_E)) {
        fputs("FAIL handled DOS interrupt did not publish returned CF/preserve ZF\n",stderr);
        return 2;
    }
    gw_interrupt_set_callback(NULL,NULL);
    puts("PASS INT bridge materializes preserved flags and DOS carry");
    return 0;
}
