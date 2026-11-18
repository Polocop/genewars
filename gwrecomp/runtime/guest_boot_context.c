#include "guest_boot_context.h"
#include <string.h>

int gw_guest_boot_context_init(gw_recomp_context *context,
                               const gw_guest_boot_seed *seed) {
    if (!context || !seed || !seed->guest_memory_host || seed->guest_memory_size > UINT32_MAX ||
        seed->entry_va >= seed->guest_memory_size ||
        seed->stack_va < sizeof(uint32_t) ||
        seed->stack_va > seed->guest_memory_size ||
        (seed->unknown_registers & ~GW_BOOT_UNKNOWN_ALL))
        return 0;

    memset(context, 0, sizeof(*context));
    context->eip = seed->entry_va;
    context->esp = seed->stack_va;
    context->cs = seed->cs;
    context->ds = seed->ds;
    context->es = seed->es;
    context->ss = seed->ss;
    context->cur_func = seed->entry_va;
    context->flag_k = FK_NONE;
    context->fpu_cw = 0x037fu;
    context->mem_base = (ptrdiff_t)seed->guest_memory_host;
    context->mem_guest_base = 0;
    context->mem_size = (uint32_t)seed->guest_memory_size;
    return 1;
}
