#include "gw_dos_services.h"
#include "gw_interrupts.h"
#include "gw_segments.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

uint32_t g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,g_cur_func;
uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_ss,g_seg_fs,g_seg_gs;
uint32_t g_fs_base,g_gs_base;
uint32_t g_flag_cf;
ptrdiff_t g_mem_base;

static void regs(const char *phase) {
    printf("{\"phase\":\"%s\",\"eax\":\"0x%08x\",\"ebx\":\"0x%08x\",\"ecx\":\"0x%08x\",\"edx\":\"0x%08x\",\"esi\":\"0x%08x\",\"edi\":\"0x%08x\",\"ebp\":\"0x%08x\",\"esp\":\"0x%08x\",\"cf\":%u,\"es\":\"0x%04x\",\"es_base\":\"0x%08x\"}\n",
        phase,(unsigned)g_eax,(unsigned)g_ebx,(unsigned)g_ecx,(unsigned)g_edx,
        (unsigned)g_esi,(unsigned)g_edi,(unsigned)g_ebp,(unsigned)g_esp,
        (unsigned)g_flag_cf,(unsigned)g_seg_es,(unsigned)g_es_base);
}

static int same_regs(uint32_t eax,uint32_t ebx,uint32_t ecx,uint32_t edx,
                     uint32_t esi,uint32_t edi,uint32_t ebp,uint32_t esp) {
    return g_eax==eax&&g_ebx==ebx&&g_ecx==ecx&&g_edx==edx&&g_esi==esi&&
           g_edi==edi&&g_ebp==ebp&&g_esp==esp;
}

int main(void) {
    gw_dos_services host; memset(&host,0,sizeof(host));
    gw_dos_services_init(&host);
    g_seg_cs=0x000c; g_seg_ds=0x0014; g_seg_es=0x0014; g_seg_ss=0x0014;
    g_cs_base=0; g_ds_base=0; g_es_base=0; g_ss_base=0;
    g_eax=0xA5A54800u; g_ebx=0x5A5A0001u; g_ecx=0x00008000u;
    g_edx=0x00000000u; g_esi=0x11223344u; g_edi=0x55667788u;
    g_ebp=0x99AABBCCu; g_esp=0x001A8B08u; g_flag_cf=1;
    const uint32_t in_eax=g_eax,in_ebx=g_ebx,in_ecx=g_ecx,in_edx=g_edx;
    const uint32_t in_esi=g_esi,in_edi=g_edi,in_ebp=g_ebp,in_esp=g_esp;
    regs("before_ah48");
    gw_interrupt_result alloc=gw_dos_services_callback(0x21,0x000C3D21u,&host);
    if (alloc!=GW_INTERRUPT_HANDLED || (uint16_t)g_eax!=0x004cu || g_flag_cf!=0 ||
        !same_regs(0xA5A5004Cu,in_ebx,in_ecx,in_edx,in_esi,in_edi,in_ebp,in_esp)) return 2;
    printf("{\"phase\":\"ah48_state\",\"result\":\"handled\",\"descriptor_count\":%u,\"dos_block_count\":%u,\"measured_active\":%u,\"measured_value\":\"0x%04x\",\"allocator_configured\":%u,\"mcb_bytes_available\":false}\n",
        (unsigned)host.descriptor_count,(unsigned)host.dos_block_count,
        (unsigned)host.measured_ah48_active,(unsigned)host.measured_ah48_segment,
        (unsigned)host.dos_allocator_configured);
    regs("after_ah48");

    /* This is intentionally the current resolver attempt. No measured descriptor
       contract is injected here; the harness must remain undecided pre-W3-059. */
    const int es_loaded=recomp_write_segment(RECOMP_SEG_ES,(uint16_t)g_eax,0x000C3D42u);
    recomp_segment_fault sf=recomp_get_segment_fault();
    printf("{\"phase\":\"mov_es\",\"accepted\":%s,\"fault_pending\":%u,\"fault_selector\":\"0x%04x\",\"fault_eip\":\"0x%08x\",\"es\":\"0x%04x\",\"es_base\":\"0x%08x\"}\n",
        es_loaded?"true":"false",(unsigned)sf.pending,(unsigned)sf.selector,
        (unsigned)sf.instruction_va,(unsigned)g_seg_es,(unsigned)g_es_base);

    g_eax=0xA5A5494Cu; g_ebx=0x80000008u; g_ecx=0x00008000u;
    g_edx=0x0000004Cu; g_esi=0x80000008u; g_edi=0x00000008u;
    g_ebp=0x0010B4D0u; g_esp=0x001A8B04u; g_flag_cf=1;
    const uint32_t f_eax=g_eax,f_ebx=g_ebx,f_ecx=g_ecx,f_edx=g_edx;
    const uint32_t f_esi=g_esi,f_edi=g_edi,f_ebp=g_ebp,f_esp=g_esp;
    regs("before_ah49");
    gw_interrupt_result released=gw_dos_services_callback(0x21,0x000C3D46u,&host);
    printf("{\"phase\":\"ah49\",\"result\":\"%s\",\"registers_preserved\":%s,\"cf\":%u,\"descriptor_count\":%u,\"dos_block_count\":%u,\"measured_active\":%u,\"mcb_bytes_available\":false}\n",
        released==GW_INTERRUPT_HANDLED?"handled":"trapped",
        same_regs(f_eax,f_ebx,f_ecx,f_edx,f_esi,f_edi,f_ebp,f_esp)?"true":"false",
        (unsigned)g_flag_cf,(unsigned)host.descriptor_count,(unsigned)host.dos_block_count,
        (unsigned)host.measured_ah48_active);
    regs("after_ah49");
    gw_dos_descriptor_clear(&host);
    return (!es_loaded && released==GW_INTERRUPT_TRAPPED && host.descriptor_count==0) ? 0 : 3;
}


