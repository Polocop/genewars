#include "recomp_context.h"
#include "gw_dos_services.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

uint32_t g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp;
uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_fs,g_seg_gs,g_seg_ss;
double g_st[8]; int g_fp_top; uint16_t g_fpu_cw; uint32_t g_cur_func,g_fs_base,g_gs_base;
ptrdiff_t g_mem_base;

typedef struct stream_state {
    const uint8_t *input;
    uint16_t input_size,input_pos;
    uint8_t output[64];
    uint16_t output_size,short_count,error,read_calls,write_calls;
} stream_state;
static uint8_t guest_memory[0x300000];

static uint16_t stream_read(void *user,uint8_t *buffer,uint16_t requested,uint16_t *transferred) {
    stream_state *s=(stream_state *)user; s->read_calls++;
    if (s->error) return s->error;
    uint16_t available=(uint16_t)(s->input_size-s->input_pos);
    uint16_t count=requested<available?requested:available;
    if (s->short_count && count>s->short_count) count=s->short_count;
    if (count) memcpy(buffer,s->input+s->input_pos,count);
    s->input_pos=(uint16_t)(s->input_pos+count); *transferred=count; return 0;
}
static uint16_t stream_write(void *user,const uint8_t *buffer,uint16_t requested,uint16_t *transferred) {
    stream_state *s=(stream_state *)user; s->write_calls++;
    if (s->error) return s->error;
    uint16_t count=requested;
    if (s->short_count && count>s->short_count) count=s->short_count;
    if (count>sizeof(s->output)-s->output_size) return 8;
    memcpy(s->output+s->output_size,buffer,count); s->output_size=(uint16_t)(s->output_size+count);
    *transferred=count; return 0;
}
static int check(int ok,const char *message) { if (!ok) fprintf(stderr,"FAIL: %s\n",message); return ok; }

int main(void) {
    gw_dos_services services; memset(&services,0,sizeof services);
    stream_state input={0},output={0};
    static const uint8_t payload[]="abc"; input.input=payload; input.input_size=3;
    input.short_count=2; output.short_count=3;
    g_seg_ds=0x14; g_ds_base=0; g_mem_base=(ptrdiff_t)(uintptr_t)guest_memory;
    recomp_set_memory_bounds(0,sizeof guest_memory); recomp_clear_memory_fault();
    gw_dos_services_init(&services);
    if (!gw_dos_guest_memory_configure(&services,sizeof guest_memory) ||
        !gw_dos_stream_memory_configure(&services,0,sizeof guest_memory)) return 1;

    /* A standard handle without an injected provider must remain fail-closed. */
    g_eax=0xaaaa4000u; g_ebx=1; g_ecx=2; g_edx=0x002000d0u; g_flag_cf=1;
    if (!check(gw_dos_services_callback(0x21,0x1236,&services)==GW_INTERRUPT_TRAPPED,
               "stdout without adapter remains trapped")) return 2;

    if (!gw_dos_stream_configure(&services,0,stream_read,0,&input,1) ||
        !gw_dos_stream_configure(&services,1,0,stream_write,&output,1)) return 3;

    g_eax=0xaaaa3f00u; g_ebx=0; g_ecx=8; g_edx=0x100; g_flag_cf=1;
    if (!check(gw_dos_services_callback(0x21,0x1234,&services)==GW_INTERRUPT_HANDLED,"read dispatch") ||
        !check((uint16_t)g_eax==2 && !g_flag_cf,"short read count/CF") ||
        !check(!memcmp(guest_memory+0x100,"ab",2),"read data reaches DS:DX")) return 3;
    g_eax=0x3f00u; g_ebx=0; g_ecx=8; g_edx=0x100;
    if (!check(gw_dos_services_callback(0x21,0x1235,&services)==GW_INTERRUPT_HANDLED &&
               (uint16_t)g_eax==1 && !g_flag_cf,"final short read")) return 4;
    g_eax=0x3f00u; g_ebx=0; g_ecx=8; g_edx=0x100;
    if (!check(gw_dos_services_callback(0x21,0x1236,&services)==GW_INTERRUPT_HANDLED &&
               (uint16_t)g_eax==0 && !g_flag_cf,"EOF returns zero bytes")) return 5;

    memcpy(guest_memory+0x200,"wxyz",4);
    g_eax=0xbbbb4000u; g_ebx=1; g_ecx=4; g_edx=0x200; g_flag_cf=1;
    if (!check(gw_dos_services_callback(0x21,0x1237,&services)==GW_INTERRUPT_HANDLED &&
               (uint16_t)g_eax==3 && !g_flag_cf,"short write count/CF") ||
        !check(output.output_size==3 && !memcmp(output.output,"wxy",3),"write callback bytes")) return 6;

    /* DOS/4GW uses a 32-bit DS:EDX offset here.  The low-DX decoy deliberately
     * differs so a 16-bit truncation cannot accidentally pass this check. */
    guest_memory[0x00d0]='X'; guest_memory[0x00d1]='Y';
    guest_memory[0x2000d0]='\r'; guest_memory[0x2000d1]='\n';
    output.short_count=0;
    g_eax=0xaaaa4002u; g_ebx=1; g_ecx=2; g_edx=0x002000d0u;
    g_esi=0x11223344u; g_edi=0x55667788u; g_ebp=0x99aabbccu; g_esp=0x12345678u;
    g_flag_cf=1; g_flag_k=0x13579bdfu; g_flag_a=0x2468ace0u; g_flag_b=0xfedcba98u;
    gw_interrupt_result ah40_result=gw_dos_services_callback(0x21,0x000d219cu,&services);
    if (ah40_result!=GW_INTERRUPT_HANDLED)
        fprintf(stderr,"AH40 diagnostic result=%u eax=%08x cf=%u writes=%u memory_fault=%u selector=%04x offset=%08x linear=%08x\n",
                (unsigned)ah40_result,g_eax,(unsigned)g_flag_cf,output.write_calls,
                (unsigned)recomp_memory_fault_pending(),recomp_get_memory_fault().selector,
                recomp_get_memory_fault().offset,recomp_get_memory_fault().linear);
    if (!check(ah40_result==GW_INTERRUPT_HANDLED,
               "AH=40 writes measured full-width DS:EDX pointer") ||
        !check(g_eax==2 && !g_flag_cf,
               "AH=40 returns DOS/4GW zero-extended transferred count and CF") ||
        !check(output.output_size==5 && !memcmp(output.output+3,"\r\n",2),
               "AH=40 captured exact CRLF bytes from full-width pointer") ||
        !check(g_ebx==1 && g_ecx==2 && g_edx==0x002000d0u && g_esi==0x11223344u &&
               g_edi==0x55667788u && g_ebp==0x99aabbccu && g_esp==0x12345678u &&
               g_flag_k==0x13579bdfu && g_flag_a==0x2468ace0u && g_flag_b==0xfedcba98u,
               "AH=40 preserves non-result registers and non-CF flags")) return 12;

    output.error=5;
    g_eax=0x4000u; g_ebx=1; g_ecx=2; g_edx=0x2000d0u; g_flag_cf=0;
    if (!check(gw_dos_services_callback(0x21,0x1237,&services)==GW_INTERRUPT_HANDLED &&
               (uint16_t)g_eax==5 && g_flag_cf,
               "stream write DOS error returns AX and sets CF")) return 19;
    output.error=0;

    /* A redirected standard handle still goes through the configured provider,
     * with its classification carried by the existing stream entry. */
    if (!gw_dos_stream_configure(&services,1,0,stream_write,&output,0)) return 13;
    g_eax=0x4000u; g_ebx=1; g_ecx=2; g_edx=0x2000d0u; g_flag_cf=1;
    if (!check(gw_dos_services_callback(0x21,0x1237,&services)==GW_INTERRUPT_HANDLED &&
               (uint16_t)g_eax==2 && !g_flag_cf && output.output_size==7,
               "redirected standard handle routes to the same stream provider")) return 14;
    if (!gw_dos_stream_configure(&services,1,0,stream_write,&output,1)) return 15;

    uint16_t prior_writes=output.write_calls;
    g_eax=0x4000u; g_ebx=1; g_ecx=2; g_edx=0x2fffffu; g_flag_cf=0;
    if (!check(gw_dos_services_callback(0x21,0x1238,&services)==GW_INTERRUPT_TRAPPED,
               "out-of-range full-width DS:EDX traps") ||
        !check(output.write_calls==prior_writes,"invalid buffer never reaches stream")) return 16;

    /* Quota overflow returns deterministic DOS disk-full and stores no partial
     * prefix of this atomic write. */
    output.output_size=(uint16_t)(sizeof output.output-1u);
    g_eax=0x4000u; g_ebx=1; g_ecx=2; g_edx=0x2000d0u; g_flag_cf=0;
    if (!check(gw_dos_services_callback(0x21,0x1239,&services)==GW_INTERRUPT_HANDLED &&
               (uint16_t)g_eax==8 && g_flag_cf && output.output_size==sizeof output.output-1u,
               "bounded stream quota reports deterministic DOS error without overflow")) return 17;

    input.error=5; uint16_t prior_reads=input.read_calls;
    g_eax=0x3f00u; g_ebx=0; g_ecx=4; g_edx=0x100;
    if (!check(gw_dos_services_callback(0x21,0x1238,&services)==GW_INTERRUPT_HANDLED &&
               (uint16_t)g_eax==5 && g_flag_cf,"read callback DOS error") ||
        !check(input.read_calls==prior_reads+1,"callback invoked once")) return 7;

    g_eax=0x4000u; g_ebx=7; g_ecx=2; g_edx=0x2000d0u;
    if (!check(gw_dos_services_callback(0x21,0x123au,&services)==GW_INTERRUPT_HANDLED &&
               (uint16_t)g_eax==6 && g_flag_cf,"invalid write handle returns DOS error 6")) return 18;
    g_eax=0x3f00u; g_ebx=7; g_ecx=4; g_edx=0x100;
    if (!check(gw_dos_services_callback(0x21,0x123b,&services)==GW_INTERRUPT_HANDLED &&
               (uint16_t)g_eax==6 && g_flag_cf,"invalid DOS handle")) return 8;
    g_eax=0x4000u; g_ebx=2; g_ecx=2; g_edx=0x2000d0u;
    if (!check(gw_dos_services_callback(0x21,0x123c,&services)==GW_INTERRUPT_TRAPPED,
               "unconfigured standard handle remains trapped")) return 9;

    /* Reproduce the OPTIONS replay's standard-handle write from a buffer near
     * the end of a successful 4 KiB DPMI AX=0501 allocation.  The static stream
     * window deliberately excludes this address: only the live allocation
     * ledger may authorize it. */
    stream_state dos_stderr={0};
    if (!gw_dos_stream_memory_configure(&services,0x00200000u,0x1000u) ||
        !gw_dos_linear_allocator_configure(&services,0x00280000u,
                                            (uint32_t)sizeof guest_memory) ||
        !gw_dos_stream_configure(&services,2,0,stream_write,&dos_stderr,1)) return 20;
    g_eax=0x00000501u; g_ebx=0; g_ecx=0x1000u; g_edx=0;
    if (!check(gw_dos_services_callback(0x31,0x000c3cc1u,&services)==GW_INTERRUPT_HANDLED &&
               !g_flag_cf && g_ebx==0x0028u && g_ecx==0 &&
               services.linear_allocation_count==1 &&
               services.linear_allocations[0].active &&
               services.linear_allocations[0].base==0x00280000u &&
               services.linear_allocations[0].size==0x1000u,
               "DPMI allocation is recorded only after grant and backing")) return 21;
    guest_memory[0x00280ff4u]='E';
    g_eax=0xa5a54002u; g_ebx=2; g_ecx=1; g_edx=0x00280ff4u;
    g_esi=0x11223344u; g_edi=0x55667788u; g_flag_cf=1;
    gw_interrupt_result dpmi_stream_result=
        gw_dos_services_callback(0x21,0x000d219cu,&services);
    if (!check(dpmi_stream_result==GW_INTERRUPT_HANDLED && g_eax==1 && !g_flag_cf &&
               g_ebx==2 && g_ecx==1 && g_edx==0x00280ff4u &&
               g_esi==0x11223344u && g_edi==0x55667788u &&
               dos_stderr.output_size==1 && dos_stderr.output[0]=='E',
               "AH=40 accepts backed active DPMI buffer with full DOS result semantics")) return 22;
    uint16_t stderr_writes=dos_stderr.write_calls;
    g_eax=0x4002u; g_ebx=2; g_ecx=1; g_edx=0x00281000u; g_flag_cf=0;
    if (!check(gw_dos_services_callback(0x21,0x000d219cu,&services)==GW_INTERRUPT_TRAPPED &&
               dos_stderr.write_calls==stderr_writes,
               "AH=40 rejects the first byte past the live DPMI allocation")) return 23;
    if (!gw_dos_linear_allocator_configure(&services,0x00280000u,
                                           (uint32_t)sizeof guest_memory) ||
        !check(services.linear_allocation_count==0 &&
               !services.linear_allocations[0].active,
               "new DPMI arena clears stale allocation authorization")) return 25;
    g_eax=0x4002u; g_ebx=2; g_ecx=1; g_edx=0x00280ff4u;
    if (!check(gw_dos_services_callback(0x21,0x000d219cu,&services)==GW_INTERRUPT_TRAPPED &&
               dos_stderr.write_calls==stderr_writes,
               "AH=40 cannot use a DPMI range from a previous arena")) return 26;
    if (!gw_dos_stream_memory_configure(&services,0,sizeof guest_memory)) return 24;

    prior_reads=input.read_calls; g_eax=0x3f00u; g_ebx=0; g_ecx=16; g_edx=0x2ffff8;
    if (!check(gw_dos_services_callback(0x21,0x123d,&services)==GW_INTERRUPT_TRAPPED,
               "out-of-range DS:DX remains trapped") ||
        !check(input.read_calls==prior_reads,"invalid buffer never reaches stream")) return 10;
    if (!gw_dos_stream_configure(&services,2,stream_read,stream_write,&output,1)) return 11;
    gw_dos_descriptor_clear(&services);
    puts("PASS native DOS AH=3F/40 streams, full DS:EDX bounds, short I/O, EOF, errors, quota and redirects");
    return 0;
}
