#include "gw_recomp_trace.h"

int main(void) {
    gw_recomp_trace_set_enabled(1);
    for (uint32_t i = 0; i < 40u; ++i)
        gw_recomp_trace_call(0x1000u + i, 0x2000u, 0x3000u + i,
                             0x4000u + i, (uint8_t)(i & 1u));
    for (uint32_t i = 0; i < 100u; ++i)
        gw_recomp_trace_branch(0x5000u + i, 0x6000u, 0x7000u + i,
                               0x202u + i, (uint8_t)(i & 1u));
    gw_recomp_trace_call(0x70F05u, 0x70EB0u, 0x98C19u, 0x70F0Au, 0u);
    gw_recomp_trace_interrupt(0x21u, 0x1234u, 0x1200u,
        0x3D00u, 1u, 0u, 0u, 0u, 0u, 0x14u, 0x14u,
        0x0008u, 0x0033u, 0u, 0u, 1u);
    gw_recomp_trace_interrupt(0x31u, 0x5678u, 0x5600u,
        0x0501u, 0u, 0u, 0x01000000u, 0u, 0u, 0x14u, 0x14u,
        0x8012u, 0u, 0u, 0u, 1u);
    if (gw_recomp_trace_last_return_to(0x98C19u) != 0x70F0Au) return 1;
    gw_recomp_trace_set_boundary_stop(1);
    /* The DOS interrupt trampoline is a live dependency of this path, not an
     * exit boundary. Observe it without stopping; stop only at CRT exit. */
    if (gw_recomp_trace_stop_before_target(0xD226Eu) ||
        gw_recomp_trace_boundary_hit()) return 2;
    if (!gw_recomp_trace_stop_before_target(0x98C19u) ||
        !gw_recomp_trace_boundary_hit()) return 3;
    gw_recomp_trace_set_boundary_stop(1);
    if (!gw_recomp_trace_stop_before_target(0x98C31u) ||
        !gw_recomp_trace_boundary_hit()) return 4;
    gw_recomp_trace_checkpoint(0x98C19u, 0x70EB0u);
    return 0;
}
