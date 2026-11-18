#include "../runtime/recomp_context.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

uint32_t g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,g_cur_func;
uint32_t g_icall_trace[ICALL_TRACE_SIZE],g_icall_from[ICALL_TRACE_SIZE];
uint32_t g_icall_trace_idx,g_icall_count;
uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_fs,g_seg_gs,g_seg_ss,g_fpu_cw;
uint32_t g_flag_k,g_flag_a,g_flag_b,g_flag_cf;
uint32_t g_fs_base,g_gs_base;
ptrdiff_t g_mem_base;
double g_st[8];
int g_fp_top;

static unsigned bad_operation, bad_port, bad_width, bad_value;
static unsigned *bad_output;
static uint8_t *clock_guest_memory;

static void lifted_supported_sequence(void) {
    unsigned value = 0;
    if (!gw_recomp_guest_instruction(0x00001000u)) return;
    if (!gw_recomp_port_io(1u, 0x43u, 1u, 0x34u, 0x00001000u, 0)) return;
    if (!gw_recomp_guest_instruction(0x00001001u)) return;
    if (!gw_recomp_port_io(1u, 0x40u, 1u, 0x34u, 0x00001001u, 0)) return;
    if (!gw_recomp_guest_instruction(0x00001002u)) return;
    if (!gw_recomp_port_io(1u, 0x40u, 1u, 0x12u, 0x00001002u, 0)) return;
    if (!gw_recomp_guest_instruction(0x00001003u)) return;
    if (!gw_recomp_port_io(0u, 0x40u, 1u, 0u, 0x00001003u, &value)) return;
    g_eax = (g_eax & 0xffffff00u) | value;
}

static void lifted_one_instruction(void) {
    (void)gw_recomp_guest_instruction(0x00001100u);
}

static void lifted_bios_clock_periods(void) {
    if (!gw_recomp_guest_instruction(0x00004000u)) return;
    if (!gw_recomp_port_io(1u,0x43u,1u,0x34u,0x00004000u,0)) return;
    if (!gw_recomp_guest_instruction(0x00004001u)) return;
    if (!gw_recomp_port_io(1u,0x40u,1u,0x00u,0x00004001u,0)) return;
    if (!gw_recomp_guest_instruction(0x00004002u)) return;
    if (!gw_recomp_port_io(1u,0x40u,1u,0x00u,0x00004002u,0)) return;
    for (uint32_t i=0;i<131072u;i++) {
        if (!gw_recomp_guest_instruction(0x00004003u+i)) return;
    }
}

static void lifted_bad_io(void) {
    if (!gw_recomp_guest_instruction(0x00002000u)) return;
    if (!gw_recomp_port_io(bad_operation, bad_port, bad_width, bad_value,
                           0x00002001u, bad_output)) return;
    g_eax = 0xdeadbeefu;
}

static void lifted_unsupported_child(void) {
    if (!gw_recomp_guest_instruction(0x00003000u)) return;
    if (!gw_recomp_port_io(3u, 0x43u, 1u, 0u, 0x00003001u, 0)) return;
    g_eax = 0xeeeeeeeeu;
}

static void lifted_parent_after_child(void) {
    lifted_unsupported_child();
    if (!gw_recomp_guest_instruction(0x00003002u)) return;
    g_eax = 0xddddddddu;
}

static int invoke(gw_recomp_context *context, recomp_func_t function) {
    return gw_recomp_invoke(function, context) == GW_RECOMP_OK;
}

static void init_context(gw_recomp_context *context, uint32_t eax) {
    memset(context, 0, sizeof(*context));
    context->eax = eax;
    context->flag_k = FK_NONE;
    context->fpu_cw = 0x037fu;
    context->cur_func = 0x00001000u;
}

static int assert_bad(unsigned operation, unsigned port, unsigned width,
                      unsigned *output, unsigned reason) {
    gw_recomp_context context;
    init_context(&context, 0x12345678u);
    bad_operation = operation;
    bad_port = port;
    bad_width = width;
    bad_value = 0xa5u;
    bad_output = output;
    if (!invoke(&context, lifted_bad_io)) return 10;
    if (!context.port_io_trap.pending || context.port_io_trap.reason != reason ||
        context.port_io_trap.operation != operation ||
        context.port_io_trap.port != port || context.port_io_trap.width != width ||
        context.port_io_trap.guest_va != 0x00002001u || context.eax != 0x12345678u)
        return 11;
    return 0;
}

int main(void) {
    gw_recomp_context first, second, overflow, clock_context;
    uint8_t bda[0x500]={0};
    gw_port_io_trap trap;
    unsigned out = 0;
    int rc;

    init_context(&first, 0x12345600u);
    if (!invoke(&first, lifted_supported_sequence)) return 1;
    if (first.port_io_trap.pending || first.pit.virtual_cycles != 4u ||
        first.pit.reload[0] != 0x1234u || (first.eax & 0xffu) != 0x33u)
        return 2;
    if (!invoke(&first, lifted_one_instruction) || first.pit.virtual_cycles != 5u)
        return 3;

    clock_guest_memory=bda;
    memset(&clock_context,0,sizeof clock_context);
    clock_context.mem_base=(ptrdiff_t)(uintptr_t)clock_guest_memory;
    clock_context.mem_guest_base=0u; clock_context.mem_size=sizeof bda;
    clock_context.fpu_cw=0x037fu;
    if(!invoke(&clock_context,lifted_bios_clock_periods)) return 15;
    if(clock_context.port_io_trap.pending ||
       clock_context.pit.reload[0]!=0x10000u ||
       clock_context.pit.virtual_cycles!=131075u ||
       *(uint32_t *)(void *)(bda+0x46cu)!=2u) return 16;
    printf("TRACE BDA timer ticks=%u PIT_divisor=%u guest_instructions=%llu\n",
        *(uint32_t *)(void *)(bda+0x46cu),clock_context.pit.reload[0],
        (unsigned long long)clock_context.pit.virtual_cycles);

    init_context(&second, 0x87654321u);
    if (!invoke(&second, lifted_one_instruction) ||
        second.pit.virtual_cycles != 1u || second.pit.reload[0] != 0u ||
        first.pit.virtual_cycles != 5u)
        return 4;

    init_context(&second, 0x12345678u);
    if (!invoke(&second, lifted_parent_after_child)) return 5;
    if (!second.port_io_trap.pending ||
        second.port_io_trap.reason != GW_PORT_IO_TRAP_UNSUPPORTED_IO ||
        second.port_io_trap.operation != 3u || second.port_io_trap.port != 0x43u ||
        second.port_io_trap.width != 1u ||
        second.port_io_trap.guest_va != 0x00003001u ||
        second.pit.virtual_cycles != 1u || second.eax != 0x12345678u)
        return 6;

    rc = assert_bad(0u, 0x40u, 2u, &out, GW_PORT_IO_TRAP_UNSUPPORTED_IO);
    if (rc) return rc;
    rc = assert_bad(2u, 0x40u, 1u, 0, GW_PORT_IO_TRAP_UNSUPPORTED_IO);
    if (rc) return rc;
    rc = assert_bad(0u, 0x43u, 1u, &out, GW_PORT_IO_TRAP_UNSUPPORTED_IO);
    if (rc) return rc;
    rc = assert_bad(1u, 0x70u, 1u, 0, GW_PORT_IO_TRAP_UNSUPPORTED_IO);
    if (rc) return rc;
    rc = assert_bad(4u, 0x40u, 1u, 0, GW_PORT_IO_TRAP_UNSUPPORTED_IO);
    if (rc) return rc;
    rc = assert_bad(0u, 0x40u, 1u, 0, GW_PORT_IO_TRAP_MISSING_READ_OUTPUT);
    if (rc) return rc;

    init_context(&overflow, 0u);
    overflow.pit_initialized = 1u;
    overflow.pit.virtual_cycles = UINT64_MAX;
    if (!invoke(&overflow, lifted_one_instruction) ||
        !overflow.port_io_trap.pending ||
        overflow.port_io_trap.reason != GW_PORT_IO_TRAP_PIT_TICK_OVERFLOW ||
        overflow.port_io_trap.guest_va != 0x00001100u ||
        overflow.pit.virtual_cycles != UINT64_MAX)
        return 12;

    gw_recomp_clear_port_io_trap();
    if (gw_recomp_guest_instruction(0x00007777u)) return 13;
    trap = gw_recomp_get_port_io_trap();
    if (!trap.pending || trap.reason != GW_PORT_IO_TRAP_NO_ACTIVE_CONTEXT ||
        trap.guest_va != 0x00007777u)
        return 14;

    printf("PASS W2-123 synthetic callback ABI; ticks=4,5,1; read=33; unsupported I/O trapped; contexts isolated\n");
    return 0;
}
