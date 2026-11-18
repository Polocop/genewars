#define RECOMP_GENERATED_CODE
#define RECOMP_LOCAL_REGS
#include "recomp_types.h"
#include "gw_recomp_stop.h"
#include "recomp_context.h"
#include "gw_interrupts.h"
#include <stdio.h>
#include <string.h>

uint32_t g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,g_cur_func;
uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_fs,g_seg_gs,g_seg_ss,g_fpu_cw;
uint32_t g_fs_base,g_gs_base;
ptrdiff_t g_mem_base;
double g_st[8];
int g_fp_top;
uint32_t g_icall_trace[ICALL_TRACE_SIZE],g_icall_from[ICALL_TRACE_SIZE];
uint32_t g_icall_trace_idx,g_icall_count;

static uint8_t guest_stack[0x10000];
static unsigned direct_after,indirect_after,tail_after,child_after;
static void trap_child(void);

recomp_func_t recomp_lookup_manual(uint32_t va) { (void)va; return NULL; }
recomp_func_t recomp_lookup(uint32_t va) { return va==0x200u ? trap_child : NULL; }
recomp_func_t recomp_lookup_import(uint32_t va) { (void)va; return NULL; }

static void trap_child(void) {
    RECOMP_REGS_LOCALS
    uint32_t _cf=0, _flag_a=0, _flag_b=0, _flag_k=FK_NONE;
    RECOMP_ENTER(0x200u);
    eax=0xC0DE1234u;
    ebx=0xB16B00B5u;
    esi=0x51515151u;
    edi=0xD1D1D1D1u;
    RECOMP_REGS_OUT();
    RECOMP_FLAGS_OUT();
    gw_interrupt_result result=gw_interrupt_dispatch(0x31u,0x12345678u);
    RECOMP_REGS_IN();
    RECOMP_FLAGS_IN();
    if(result!=GW_INTERRUPT_HANDLED) return;
    child_after++;
    RECOMP_REGS_OUT();
}

static void direct_parent(void) {
    RECOMP_REGS_LOCALS
    uint32_t _cf=0, _flag_a=0, _flag_b=0, _flag_k=FK_NONE;
    RECOMP_ENTER(0x100u);
    RECOMP_CALL(trap_child);
    direct_after++;
    RECOMP_REGS_OUT();
}

static void indirect_parent(void) {
    RECOMP_REGS_LOCALS
    uint32_t _cf=0, _flag_a=0, _flag_b=0, _flag_k=FK_NONE;
    RECOMP_ENTER(0x101u);
    RECOMP_ICALL(0x200u);
    indirect_after++;
    RECOMP_REGS_OUT();
}

static void rebased_indirect_parent(void) {
    RECOMP_REGS_LOCALS
    uint32_t _cf=0, _flag_a=0, _flag_b=0, _flag_k=FK_NONE;
    RECOMP_ENTER(0x104u);
    RECOMP_ICALL(0x1200u); /* measured guest-linear alias for link VA 0x200 */
    indirect_after++;
    RECOMP_REGS_OUT();
}

static void indirect_tail_parent(void) {
    RECOMP_REGS_LOCALS
    uint32_t _cf=0, _flag_a=0, _flag_b=0, _flag_k=FK_NONE;
    RECOMP_ENTER(0x102u);
    eax=1u;
    if (eax) RECOMP_ITAIL(0x200u);
    tail_after++;
    RECOMP_REGS_OUT();
}

static void unresolved_indirect_tail_parent(void) {
    RECOMP_REGS_LOCALS
    uint32_t _cf=0, _flag_a=0, _flag_b=0, _flag_k=FK_NONE;
    RECOMP_ENTER(0x105u);
    eax=0xBAD0BAD0u;
    RECOMP_ITAIL(0x300u);
    tail_after++;
    RECOMP_REGS_OUT();
}

static void stack_indirect_parent(void) {
    RECOMP_REGS_LOCALS
    uint32_t _cf=0, _flag_a=0, _flag_b=0, _flag_k=FK_NONE;
    RECOMP_ENTER(0x103u);
    RECOMP_ICALL(MEM32(esp + 4u));
    indirect_after++;
    RECOMP_REGS_OUT();
}

static void seed_context(gw_recomp_context *context,uint32_t entry_va) {
    memset(context,0,sizeof(*context));
    context->eax=0x11111111u; context->ebx=0x22222222u;
    context->ecx=0x33333333u; context->edx=0x44444444u;
    context->esi=0x55555555u; context->edi=0x66666666u;
    context->ebp=0x77777777u; context->esp=0x9000u;
    context->eip=entry_va; context->cur_func=entry_va;
    context->flag_k=FK_TEST; context->flag_a=0x89ABCDEFu;
    context->flag_b=0x76543210u; context->flag_cf=1u;
    context->fpu_cw=0x037fu;
    context->mem_base=(ptrdiff_t)(uintptr_t)guest_stack-0x8000;
    context->mem_guest_base=0x8000u; context->mem_size=sizeof(guest_stack);
}

static int run_case(recomp_func_t entry,uint32_t entry_va,unsigned indirect) {
    gw_recomp_context context;
    seed_context(&context,entry_va);
    child_after=direct_after=indirect_after=0;
    if(gw_recomp_invoke(entry,&context)!=GW_RECOMP_OK) return 10;
    if(!context.interrupt_trap_pending || context.interrupt_vector!=0x31u ||
       context.interrupt_instruction_va!=0x12345678u || context.interrupt_function_va!=0x200u) return 11;
    if(context.eax!=0xC0DE1234u || context.ebx!=0xB16B00B5u || context.esi!=0x51515151u ||
       context.ecx!=0x33333333u || context.edx!=0x44444444u ||
       context.edi!=0xD1D1D1D1u || context.ebp!=0x77777777u) return 12;
    if(context.esp!=0x8FFCu || context.eip!=entry_va || context.cur_func!=entry_va) return 13;
    if(context.flag_k!=FK_TEST || context.flag_a!=0x89ABCDEFu ||
       context.flag_b!=0x76543210u || context.flag_cf!=1u) return 15;
    if(child_after || (indirect ? (indirect_after || direct_after) : (direct_after || indirect_after))) return 14;
    return 0;
}

static int run_tail_case(void) {
    gw_recomp_context context;
    seed_context(&context,0x102u);
    child_after=direct_after=indirect_after=tail_after=0;
    if(gw_recomp_invoke(indirect_tail_parent,&context)!=GW_RECOMP_OK) return 20;
    if(!context.interrupt_trap_pending || context.interrupt_vector!=0x31u ||
       context.interrupt_instruction_va!=0x12345678u || context.interrupt_function_va!=0x200u) return 21;
    if(context.eax!=0xC0DE1234u || context.ebx!=0xB16B00B5u || context.esi!=0x51515151u ||
       context.ecx!=0x33333333u || context.edx!=0x44444444u ||
       context.edi!=0xD1D1D1D1u || context.ebp!=0x77777777u) return 22;
    if(context.esp!=0x9000u || context.eip!=0x102u || context.cur_func!=0x200u) return 23;
    if(context.flag_k!=FK_TEST || context.flag_a!=0x89ABCDEFu ||
       context.flag_b!=0x76543210u || context.flag_cf!=1u) return 25;
    if(child_after || direct_after || indirect_after || tail_after) return 24;
    return 0;
}

static int run_unresolved_tail_case(void) {
    gw_recomp_context context;
    seed_context(&context,0x105u);
    tail_after=0;
    if(gw_recomp_invoke(unresolved_indirect_tail_parent,&context)!=GW_RECOMP_OK) return 40;
    if(!context.port_io_trap.pending ||
       context.port_io_trap.reason!=GW_PORT_IO_TRAP_UNRESOLVED_INDIRECT_CALL ||
       context.port_io_trap.value!=0x300u) {
        fprintf(stderr,"unresolved tail trap pending=%u reason=%u value=%08x\\n",
                context.port_io_trap.pending,context.port_io_trap.reason,
                context.port_io_trap.value);
        return 41;
    }
    if(tail_after || context.eax!=0xBAD0BAD0u || context.esp!=0x9000u ||
       context.cur_func!=0x105u) {
        fprintf(stderr,"unresolved tail post state count=%u eax=%08x esp=%08x cur=%08x\\n",
                tail_after,context.eax,context.esp,context.cur_func); return 42;
    }
    return 0;
}

int main(void) {
    const recomp_code_range measured_map[]={{0x1200u,0x200u,1u}};
    const recomp_code_range overlapping_map[]={{0x1200u,0x200u,1u},{0x1200u,0x300u,1u}};
    uint32_t mapped_link=0;
    if(!recomp_code_map_set(measured_map,1u) ||
       !recomp_code_linear_to_link(0x1200u,&mapped_link) || mapped_link!=0x200u ||
       recomp_code_linear_to_link(0x1201u,&mapped_link) ||
       recomp_code_map_set(overlapping_map,2u)) {
        fprintf(stderr,"verified code-map validation failed\n"); return 30;
    }
    int rc=run_case(direct_parent,0x100u,0);
    if(rc){fprintf(stderr,"direct propagation failed: %d\\n",rc);return rc;}
    rc=run_case(indirect_parent,0x101u,1);
    if(rc){fprintf(stderr,"indirect propagation failed: %d\\n",rc);return rc;}
    rc=run_case(rebased_indirect_parent,0x104u,1);
    if(rc){fprintf(stderr,"rebased guest-linear indirect propagation failed: %d\\n",rc);return rc;}
    rc=run_tail_case();
    if(rc){fprintf(stderr,"indirect tail propagation failed: %d\\n",rc);return rc;}
    rc=run_unresolved_tail_case();
    if(rc){fprintf(stderr,"unresolved indirect tail did not fail closed: %d\\n",rc);return rc;}
    /* A stack-indirect call must load its target from pre-push [ESP+4]. */
    *(uint32_t *)(guest_stack + 0x1004u)=0x200u;
    rc=run_case(stack_indirect_parent,0x103u,1);
    if(rc){fprintf(stderr,"stack-indirect propagation failed: %d\\n",rc);return rc;}
    puts("PASS nested direct, link/guest-linear indirect, stack-indirect, indirect-tail guest-trap propagation, and unresolved tail fail-closed preservation");
    return 0;
}
