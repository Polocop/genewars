#define RECOMP_GENERATED_CODE
#define RECOMP_LOCAL_REGS
#include "recomp_types.h"
#include "recomp_context.h"
#include "gw_interrupts.h"
#include "gw_segments.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void gw_original_install_resource_callback(void);
void gw_original_resource_path_callback(void);
void gw_original_resource_callback_callsite(void);
void gw_original_resource_manager_callback_stage(void);
void sub_000989E0(void);
int gw_recomp_guest_instruction(unsigned int guest_va);

uint32_t g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,g_cur_func;
uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_fs,g_seg_gs,g_seg_ss,g_fpu_cw;
uint32_t g_fs_base,g_gs_base;
ptrdiff_t g_mem_base;
double g_st[8]; int g_fp_top;
uint32_t g_icall_trace[ICALL_TRACE_SIZE],g_icall_from[ICALL_TRACE_SIZE];
uint32_t g_icall_trace_idx,g_icall_count;

static unsigned unexpected_path_calls, unexpected_cleanup_calls;
void sub_00096B23(void) { unexpected_path_calls++; }
void sub_00092030(void) { unexpected_cleanup_calls++; }

recomp_func_t recomp_lookup_manual(uint32_t va) { (void)va; return NULL; }
recomp_func_t recomp_lookup_import(uint32_t va) { (void)va; return NULL; }
recomp_func_t recomp_lookup(uint32_t va) {
    return va == 0x14BB0u ? gw_original_resource_path_callback : NULL;
}

static int resolve(uint16_t selector, uint32_t *base, void *user) {
    (void)user;
    if (!base || (selector != 0x160u && selector != 0x168u &&
                  selector != 0x14u && selector != 0x24u)) return 0;
    *base = 0; /* explicit flat-selector fixture; not an Oracle capture */
    return 1;
}

static void seed_context(gw_recomp_context *c, uint8_t *memory, uint32_t size) {
    memset(c, 0, sizeof *c);
    c->eax=0x11111111u; c->ebx=0; c->ecx=0x22222222u; c->edx=0x33333333u;
    c->esi=0x100000u; c->edi=0x44444444u; c->ebp=0x55555555u;
    c->esp=0x3F0000u; c->cs=0x160u; c->ds=0x168u; c->es=0x168u; c->ss=0x168u;
    c->mem_base=(ptrdiff_t)(uintptr_t)memory;
    c->mem_guest_base=0; c->mem_size=size;
    *(uint32_t *)(memory+c->esp)=RECOMP_RETADDR;
}

int main(void) {
    enum { GUEST_SIZE=0x400000u, SLOT=0x2E4804u, DESC=0x2DD554u,
           CALLBACK=0x1FFBB0u, INITIAL_STUB=0x2839E8u,
           RESOURCE_ALLOCATOR=0x0027CE00u };
    uint8_t *memory=(uint8_t *)calloc(GUEST_SIZE,1);
    if (!memory) return 10;
    FILE *f=fopen("build/authentic_resource_callback_init_guest.bin","rb");
    if (!f) { free(memory); return 11; }
    if (fread(memory+0xF0000,1,0x293000,f)!=0x293000u) {
        fclose(f); free(memory); return 12;
    }
    fclose(f);
    if (memcmp(memory+DESC,"*B_SCREEN\0",10)!=0 ||
        *(uint32_t *)(memory+SLOT)!=INITIAL_STUB) {
        fprintf(stderr,"authentic LE fixture mismatch descriptor=%.*s slot=%08x\n",
                10,memory+DESC,*(uint32_t *)(memory+SLOT));
        free(memory); return 13;
    }
    uint8_t descriptor_before[32]; memcpy(descriptor_before,memory+DESC,sizeof descriptor_before);
    uint8_t slot_guards_before[8];
    memcpy(slot_guards_before,memory+SLOT-4,4);
    memcpy(slot_guards_before+4,memory+SLOT+4,4);
    recomp_code_range range={0x1FB000u,0x10000u,0xDE930u};
    if (!recomp_code_map_set(&range,1)) { free(memory); return 14; }
    recomp_set_segment_resolver(resolve,NULL);

    gw_recomp_context c; seed_context(&c,memory,GUEST_SIZE);
    if (gw_recomp_invoke(gw_original_install_resource_callback,&c)!=GW_RECOMP_OK ||
        c.memory_fault.pending || c.segment_fault_pending || c.esp!=0x3F0004u ||
        c.eax!=CALLBACK || c.ebx!=0x100000u ||
        *(uint32_t *)(memory+SLOT)!=CALLBACK || unexpected_path_calls ||
        memcmp(memory+SLOT-4,slot_guards_before,4)!=0 ||
        memcmp(memory+SLOT+4,slot_guards_before+4,4)!=0) {
        fprintf(stderr,"original callback install failed slot=%08x esp=%08x fault=%u/%u\n",
                *(uint32_t *)(memory+SLOT),c.esp,c.memory_fault.pending,c.segment_fault_pending);
        free(memory); return 15;
    }

    g_icall_trace_idx=0; g_icall_count=0; unexpected_path_calls=0;
    seed_context(&c,memory,GUEST_SIZE); c.ebx=DESC;
    if (gw_recomp_invoke(gw_original_resource_callback_callsite,&c)!=GW_RECOMP_OK ||
        c.memory_fault.pending || c.segment_fault_pending || c.esp!=0x3F0004u ||
        c.eax!=DESC || c.ebx!=DESC || (c.edx&0xFFu)!='*' ||
        g_icall_count!=1u ||
        g_icall_trace[0]!=CALLBACK || g_icall_from[0]!=0x98A18u ||
        unexpected_path_calls) {
        fprintf(stderr,"original wildcard callback path failed eax=%08x ebx=%08x edx=%08x esp=%08x icalls=%u target=%08x from=%08x fault=%u/%u unexpected=%u\n",
                c.eax,c.ebx,c.edx,c.esp,g_icall_count,g_icall_trace[0],g_icall_from[0],
                c.memory_fault.pending,c.segment_fault_pending,unexpected_path_calls);
        free(memory); return 16;
    }
    if (memcmp(memory+DESC,descriptor_before,sizeof descriptor_before)!=0 ||
        *(uint32_t *)(memory+SLOT)!=CALLBACK) {
        free(memory); return 17;
    }

    /* Run original FUN_989EC instructions through callback dispatch and the
       wildcard comparison, starting after its separate global allocator
       bootstrap. The LE descriptor's output cell is originally null, so the
       authentic FUN_98B6C cleanup guard must skip its free callback. Stop at
       CMP before the allocation branch; no allocator result is fabricated. */
    const uint32_t output_cell=*(uint32_t *)(memory+DESC+0x1Cu);
    if (output_cell==0 || output_cell+4u>GUEST_SIZE ||
        *(uint32_t *)(memory+output_cell)!=0) {
        fprintf(stderr,"LE *B_SCREEN output cell is not in its original null state: %08x\n",output_cell);
        free(memory); return 18;
    }
    g_icall_trace_idx=0; g_icall_count=0; unexpected_path_calls=0;
    memset(&c,0,sizeof c);
    c.eax=DESC; c.ebx=DESC; c.ecx=0x22334455u; c.edx=0x33445566u;
    c.esi=0x44556677u; c.edi=0x55667788u; c.ebp=0x66778899u;
    c.esp=0x3F0000u; c.cs=0x160u; c.ds=0x168u; c.es=0x168u; c.ss=0x168u;
    c.mem_base=(ptrdiff_t)(uintptr_t)memory; c.mem_guest_base=0; c.mem_size=GUEST_SIZE;
    if (gw_recomp_invoke(gw_original_resource_manager_callback_stage,&c)!=GW_RECOMP_OK ||
        c.memory_fault.pending || c.segment_fault_pending || c.eax!=DESC ||
        (c.edx&0xFFu)!='*' || c.esp!=0x3F0000u || g_icall_count!=1u ||
        g_icall_trace[0]!=CALLBACK || g_icall_from[0]!=0x989FBu ||
        *(uint32_t *)(memory+c.esp)!=RESOURCE_ALLOCATOR ||
        unexpected_path_calls || unexpected_cleanup_calls ||
        *(uint32_t *)(memory+output_cell)!=0) {
        fprintf(stderr,"original manager callback stage failed eax=%08x edx=%08x esp=%08x icalls=%u target=%08x from=%08x fault=%u/%u mem=%u selector=%04x offset=%08x width=%u linear=%08x insn=%08x cleanup=%u\n",
                c.eax,c.edx,c.esp,g_icall_count,g_icall_trace[0],g_icall_from[0],
                c.memory_fault.pending,c.segment_fault_pending,c.memory_fault.pending,
                c.memory_fault.selector,c.memory_fault.offset,c.memory_fault.width,
                c.memory_fault.linear,c.memory_fault.instruction_va,unexpected_cleanup_calls);
        free(memory); return 19;
    }
    puts("PASS original setup callback install -> FUN_989EC original indirect callback and '*' decision on the LE descriptor");
    puts("PASS original FUN_98B6C observes the LE null output cell; execution stops before allocation or DOS open");
    free(memory);
    return 0;
}
