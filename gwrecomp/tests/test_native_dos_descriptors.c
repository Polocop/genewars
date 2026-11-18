#include "gw_dos_services.h"
#include "gw_interrupts.h"
#include "gw_segments.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

uint32_t g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp;
uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_ss,g_seg_fs,g_seg_gs;
uint32_t g_fs_base,g_gs_base,g_cur_func;
ptrdiff_t g_mem_base;

typedef struct { uint8_t psp[256]; uint8_t env[64]; } process_memory;
int main(void) {
    gw_dos_services host; memset(&host,0,sizeof host);
    process_memory mem; memset(&mem,0,sizeof mem);
    uint16_t envsel=0x0900; memcpy(mem.psp+0x2c,&envsel,2);
    if (!gw_dos_descriptor_bind(&host,0x0800,0x8000,0xff) ||
        !gw_dos_descriptor_bind(&host,0x0900,0x9000,0x3f)) return 2;
    g_seg_cs=0x0c; g_cs_base=0; g_seg_ds=0x14; g_ds_base=0;
    gw_dos_services_init(&host);
    if (!recomp_write_segment(RECOMP_SEG_ES,0x0800,0x12345678)) return 3;
    if (g_es_base != 0x8000) return 4;
    uint16_t observed=0; memcpy(&observed, mem.psp+0x2c,2);
    if (observed != 0x0900) return 5;
    uint32_t base=0;
    if (!gw_dos_descriptor_base(observed,&base,&host) || base != 0x9000) return 6;
    g_eax=0xaaaa0006; g_ebx=0xbbbb0900; g_ecx=0xcccc0000; g_edx=0xdddd0000; g_flag_cf=1;
    if (gw_dos_services_callback(0x31,0x1234,&host)!=GW_INTERRUPT_HANDLED ||
        g_ecx!=0xcccc0000 || g_edx!=0xdddd9000 || g_flag_cf) return 7;
    /* DOS AH=48h returns an active conventional-memory paragraph segment.
       GeneWars loads it into ES before AH=49h, so the Runtime must resolve
       exactly that live allocation and its byte extent, then revoke it. */
    uint8_t *lowmem=(uint8_t *)calloc(0x100000u,1u);
    if(!lowmem) return 10;
    g_mem_base=(ptrdiff_t)(uintptr_t)lowmem;
    if(!gw_dos_guest_memory_configure(&host,0x100000u) ||
       !gw_dos_memory_allocator_configure(&host,0x0907u,0x1000u,0x1104u,0x0800u)) return 11;
    lowmem[0x09060u]='Z';
    lowmem[0x09061u]=0; lowmem[0x09062u]=0;
    lowmem[0x09063u]=0xF9u; lowmem[0x09064u]=0x06u;
    g_seg_es=0x0014u; g_es_base=0;
    recomp_set_segment_resolver(gw_dos_descriptor_base,&host);
    recomp_set_segment_range_validator(gw_dos_descriptor_range,&host);
    g_eax=0x00004800u; g_ebx=1u; g_flag_cf=0;
    if(gw_dos_services_callback(0x21,0x000C3D21u,&host)!=GW_INTERRUPT_HANDLED ||
       (uint16_t)g_eax!=0x0907u || g_flag_cf) return 12;
    uint32_t dos_base=0;
    if(!gw_dos_descriptor_base(0x0907u,&dos_base,&host) || dos_base!=0x09070u ||
       !gw_dos_descriptor_range(0x0907u,0u,16u,&host) ||
       gw_dos_descriptor_range(0x0907u,16u,1u,&host) ||
       !recomp_write_segment(RECOMP_SEG_ES,0x0907u,0x000C3D42u) || g_es_base!=0x09070u)
        return 13;
    g_eax=0x00004900u;
    gw_interrupt_result free_result=gw_dos_services_callback(0x21,0x000C3D46u,&host);
    if(free_result!=GW_INTERRUPT_HANDLED || g_flag_cf) {
        fprintf(stderr,"AH49 alias free result=%u AX=%04x CF=%u ES=%04x blocks=%u base_resolves=%u base=%08x MCB=%c/%04x/%04x\n",
            free_result,(unsigned)(g_eax&0xffffu),g_flag_cf,g_seg_es,host.dos_block_count,
            gw_dos_descriptor_base(0x0907u,&dos_base,&host),dos_base,
            lowmem[0x09060u],(unsigned)(lowmem[0x09061u]|((uint16_t)lowmem[0x09062u]<<8)),
            (unsigned)(lowmem[0x09063u]|((uint16_t)lowmem[0x09064u]<<8)));
        return 14;
    }
    if(!recomp_write_segment(RECOMP_SEG_ES,0x0014u,0x000C3D4Cu) || g_es_base!=0u ||
       gw_dos_descriptor_base(0x0907u,&dos_base,&host)) return 15;
    /* DPMI 0100 and DOS AH=48 must share the guest MCB chain. The free
       paragraph at 0907 is followed by a PSP-owned block whose MCB is at
       0908; a private first-fit ledger used to hand out 0907..0A07 and let
       the caller overwrite that MCB. */
    memset(lowmem+0x09060u,0,16u);
    lowmem[0x09060u]='M'; lowmem[0x09063u]=1u;
    memset(lowmem+0x09080u,0,16u);
    lowmem[0x09080u]='M'; lowmem[0x09081u]=0x00u; lowmem[0x09082u]=0x08u;
    lowmem[0x09083u]=0x00u; lowmem[0x09084u]=0x06u;
    memset(lowmem+0x0F090u,0,16u);
    lowmem[0x0F090u]='Z'; lowmem[0x0F093u]=0xF6u;
    if(!gw_dos_memory_allocator_configure(&host,0x0907u,0x1000u,0x1104u,0x0800u)) return 18;
    g_eax=0x00000100u; g_ebx=0x100u; g_edx=0; g_flag_cf=0;
    if(gw_dos_services_callback(0x31,0x00092100u,&host)!=GW_INTERRUPT_HANDLED ||
       !g_flag_cf || (uint16_t)g_eax!=8u || (uint16_t)g_ebx!=0xF6u ||
       host.dos_block_count!=0u || lowmem[0x09080u]!='M' ||
       lowmem[0x09081u]!=0u || lowmem[0x09082u]!=8u ||
       lowmem[0x09083u]!=0u || lowmem[0x09084u]!=6u ||
       lowmem[0x0F090u]!='Z') return 19;
    g_eax=0x00000100u; g_ebx=0x80u; g_edx=0; g_flag_cf=1;
    if(gw_dos_services_callback(0x31,0x00092100u,&host)!=GW_INTERRUPT_HANDLED ||
       g_flag_cf || (uint16_t)g_eax!=0x0F0Au || (uint16_t)g_edx!=0x1104u ||
       host.dos_block_count!=1u ||
       !gw_dos_descriptor_base(0x1104u,&dos_base,&host) || dos_base!=0x0F0A0u ||
       !gw_dos_descriptor_range(0x1104u,0u,0x800u,&host) ||
       gw_dos_descriptor_range(0x1104u,0u,0x801u,&host) ||
       lowmem[0x09080u]!='M' || lowmem[0x09081u]!=0u || lowmem[0x09082u]!=8u ||
       lowmem[0x0F090u]!='M' || lowmem[0x0F091u]!=0u ||
       lowmem[0x0F092u]!=8u || lowmem[0x0F093u]!=0x80u) return 20;
    /* Resize must edit the same MCB chain and selector limit. A failed grow
       reports only contiguous free memory and leaves both unchanged. */
    g_eax=0x00000102u; g_ebx=0x100u; g_edx=0x1104u; g_flag_cf=0;
    if(gw_dos_services_callback(0x31,0x00092130u,&host)!=GW_INTERRUPT_HANDLED ||
       !g_flag_cf || (uint16_t)g_eax!=8u || (uint16_t)g_ebx!=0xF6u ||
       !gw_dos_descriptor_range(0x1104u,0u,0x800u,&host) ||
       lowmem[0x0F090u]!='M' || lowmem[0x0F093u]!=0x80u) return 22;
    g_eax=0x00000102u; g_ebx=0x60u; g_edx=0x1104u; g_flag_cf=1;
    if(gw_dos_services_callback(0x31,0x00092130u,&host)!=GW_INTERRUPT_HANDLED || g_flag_cf ||
       !gw_dos_descriptor_range(0x1104u,0u,0x600u,&host) ||
       gw_dos_descriptor_range(0x1104u,0u,0x601u,&host) ||
       lowmem[0x0F090u]!='M' || lowmem[0x0F093u]!=0x60u ||
       lowmem[0x0F6A0u]!='Z' || lowmem[0x0F6A3u]!=0x95u) return 23;
    g_eax=0x00000102u; g_ebx=0x80u; g_edx=0x1104u; g_flag_cf=1;
    if(gw_dos_services_callback(0x31,0x00092130u,&host)!=GW_INTERRUPT_HANDLED || g_flag_cf ||
       !gw_dos_descriptor_range(0x1104u,0u,0x800u,&host) ||
       gw_dos_descriptor_range(0x1104u,0u,0x801u,&host) ||
       lowmem[0x0F090u]!='M' || lowmem[0x0F093u]!=0x80u ||
       lowmem[0x0F8A0u]!='Z' || lowmem[0x0F8A3u]!=0x75u) return 24;
    g_eax=0x00000101u; g_edx=0x1104u; g_flag_cf=1;
    if(gw_dos_services_callback(0x31,0x00092120u,&host)!=GW_INTERRUPT_HANDLED ||
       g_flag_cf || host.dos_block_count!=0u ||
       gw_dos_descriptor_base(0x1104u,&dos_base,&host) ||
       lowmem[0x0F090u]!='Z' || lowmem[0x0F091u]!=0u ||
       lowmem[0x0F092u]!=0u || lowmem[0x0F093u]!=0xF6u ||
       lowmem[0x09080u]!='M' || lowmem[0x09081u]!=0u || lowmem[0x09082u]!=8u ||
       lowmem[0x09083u]!=0u || lowmem[0x09084u]!=6u) return 21;
    /* Preserve the separately evidenced W1-092 one-paragraph fixture path:
       the provider owns selector 0x004c only until the original AH=49 call. */
    g_eax=0x00004800u; g_ebx=1u; g_ecx=0x00008000u; g_edx=0u; g_flag_cf=0;
    if(gw_dos_services_callback(0x21,0x000C3D21u,&host)!=GW_INTERRUPT_HANDLED ||
       (uint16_t)g_eax!=0x004Cu || g_flag_cf ||
       !gw_dos_descriptor_base(0x004Cu,&dos_base,&host) || dos_base!=0x4C0u ||
       !gw_dos_descriptor_range(0x004Cu,0u,16u,&host) ||
       gw_dos_descriptor_range(0x004Cu,16u,1u,&host) ||
       !recomp_write_segment(RECOMP_SEG_ES,0x004Cu,0x000C3D42u)) return 16;
    g_eax=0x00004900u;
    if(gw_dos_services_callback(0x21,0x000C3D46u,&host)!=GW_INTERRUPT_HANDLED || g_flag_cf ||
       !recomp_write_segment(RECOMP_SEG_ES,0x0014u,0x000C3D4Cu) ||
       gw_dos_descriptor_base(0x004Cu,&dos_base,&host)) return 17;
    free(lowmem); g_mem_base=0;
    if (recomp_write_segment(RECOMP_SEG_ES,0x3333,0x87654321) ||
        !recomp_get_segment_fault().pending || recomp_get_segment_fault().selector!=0x3333 ||
        recomp_get_segment_fault().instruction_va!=0x87654321) return 8;
    if (gw_dos_descriptor_bind(&host,0x2222,0xfffffff0,0x40)) return 9;
    gw_dos_descriptor_clear(&host); recomp_set_segment_resolver(0,0); gw_interrupt_set_callback(0,0);
    puts("PASS PSP:2Ch, DPMI descriptor, AH=48 live DOS segment ES load/AH=49 revoke, unknown selector fault");
    return 0;
}
