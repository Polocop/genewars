#include "gw_dos_services.h"
#include "gw_interrupts.h"
#include "gw_segments.h"
#include <stdint.h>
#include <stdio.h>

uint32_t g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,g_cur_func;
uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_ss,g_seg_fs,g_seg_gs;
uint32_t g_fs_base,g_gs_base,g_flag_cf;
ptrdiff_t g_mem_base;

typedef struct {
    uint32_t eax,ebx,ecx,edx,esi,edi,ebp,esp,cf;
    uint16_t cs,ds,es,ss,fs,gs;
} cpu_state;

static cpu_state capture(void) {
    cpu_state s={g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,g_flag_cf,
                 g_seg_cs,g_seg_ds,g_seg_es,g_seg_ss,g_seg_fs,g_seg_gs};
    return s;
}
static int same(cpu_state s) {
    return s.eax==g_eax&&s.ebx==g_ebx&&s.ecx==g_ecx&&s.edx==g_edx&&
      s.esi==g_esi&&s.edi==g_edi&&s.ebp==g_ebp&&s.esp==g_esp&&s.cf==g_flag_cf&&
      s.cs==g_seg_cs&&s.ds==g_seg_ds&&s.es==g_seg_es&&s.ss==g_seg_ss&&
      s.fs==g_seg_fs&&s.gs==g_seg_gs;
}
static void exact_frontier(void) {
    g_eax=0x00004400;g_ebx=2;g_ecx=0;g_edx=1;g_esi=0x0010A83C;
    g_edi=0x001A8C44;g_ebp=0;g_esp=0x001A8B28;g_flag_cf=0;
    g_seg_cs=0x000C;g_seg_ds=0x0014;g_seg_es=0x0014;g_seg_ss=0x0014;
    g_seg_fs=0;g_seg_gs=0;g_ds_base=0;
}
int main(void) {
    gw_dos_services services;gw_dos_services_init(&services);
    exact_frontier();cpu_state s=capture();
    if(gw_dos_services_callback(0x21,0x000C8973,&services)!=GW_INTERRUPT_HANDLED||
       g_eax!=s.eax||g_ebx!=s.ebx||g_ecx!=s.ecx||g_edx!=0x82u||
       g_esi!=s.esi||g_edi!=s.edi||g_ebp!=s.ebp||g_esp!=s.esp||g_flag_cf!=0||
       g_seg_cs!=s.cs||g_seg_ds!=s.ds||g_seg_es!=s.es||g_seg_ss!=s.ss||
       g_seg_fs!=s.fs||g_seg_gs!=s.gs)return 2;
    exact_frontier();g_eax=0x00004401;s=capture();
    if(gw_dos_services_callback(0x21,0x000C8973,&services)!=GW_INTERRUPT_TRAPPED||!same(s))return 3;
    exact_frontier();s=capture();
    if(gw_dos_services_callback(0x31,0x000C8973,&services)!=GW_INTERRUPT_TRAPPED||!same(s))return 4;
    gw_dos_descriptor_clear(&services);
    puts("PASS AX=4400 standard-handle response; unsupported AX=44 and neighboring contexts remain fail closed");
    return 0;
}
