#include "gw_interrupts.h"
#include "../third_party/pcrecomp/runtime/recomp32/recomp_types.h"

static gw_interrupt_callback active_callback;
static void *active_user;
static gw_interrupt_trap last_trap;

static uint32_t interrupt_saved_eflags(void) {
    uint32_t flags=0x2u;
    if (recomp_cond(g_flag_k,g_flag_a,g_flag_b,CC_P)) flags|=1u<<2;
    if (recomp_cond(g_flag_k,g_flag_a,g_flag_b,CC_E)) flags|=1u<<6;
    if (recomp_cond(g_flag_k,g_flag_a,g_flag_b,CC_S)) flags|=1u<<7;
    if (recomp_cond(g_flag_k,g_flag_a,g_flag_b,CC_O)) flags|=1u<<11;
    flags=(flags&~1u)|(g_flag_cf&1u);
    return flags;
}

void gw_interrupt_set_callback(gw_interrupt_callback callback, void *user) {
    active_callback = callback;
    active_user = user;
}

void gw_interrupt_clear_trap(void) {
    last_trap.pending = 0;
    last_trap.vector = 0;
    last_trap.reserved = 0;
    last_trap.instruction_va = 0;
    last_trap.guest_function_va = 0;
}

gw_interrupt_trap gw_interrupt_get_trap(void) {
    return last_trap;
}

gw_interrupt_result gw_interrupt_dispatch(uint8_t vector, uint32_t instruction_va) {
    uint32_t request_eax=g_eax,request_ebx=g_ebx,request_ecx=g_ecx,request_edx=g_edx;
    uint32_t caller=g_cur_func;
    uint32_t saved_eflags=interrupt_saved_eflags();
    if (active_callback) {
        gw_interrupt_result result = active_callback(vector, instruction_va, active_user);
        if (vector==0x31u)
            recomp_memory_diag_set_dpmi_state(request_eax,request_ebx,request_ecx,request_edx,
                g_eax,g_ebx,g_ecx,g_edx,g_flag_cf);
        if (result == GW_INTERRUPT_HANDLED) {
            /* DOS/BIOS/DPMI providers expose carry as their explicit status
             * result. Publish that returned carry together with the other
             * flags preserved across INT. Keeping the caller's lazy CMP/TEST
             * operands here makes a following Jcc recompute stale flags. */
            saved_eflags=(saved_eflags&~1u)|(g_flag_cf&1u);
            g_flag_k=FK_EFLAGS;
            g_flag_a=saved_eflags;
            g_flag_b=0u;
            g_flag_cf=saved_eflags&1u;
            return result;
        }
    }
    last_trap.pending = 1;
    last_trap.vector = vector;
    last_trap.reserved = 0;
    last_trap.instruction_va = instruction_va;
    last_trap.guest_function_va = g_cur_func;
    return GW_INTERRUPT_TRAPPED;
}
