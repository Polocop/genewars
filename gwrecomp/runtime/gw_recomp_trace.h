#ifndef GW_RECOMP_TRACE_H
#define GW_RECOMP_TRACE_H

#include <stdint.h>

void gw_recomp_trace_set_enabled(int enabled);
int gw_recomp_trace_enabled(void);
void gw_recomp_trace_set_boundary_stop(int enabled);
int gw_recomp_trace_boundary_hit(void);
int gw_recomp_trace_stop_before_target(uint32_t target_link_va);
/* Small, fixed-size diagnostics for original guest CALL and DOS/DPMI history.
 * It does not affect dispatch, registers, flags, or guest memory. */
void gw_recomp_trace_call(uint32_t callsite, uint32_t caller,
                          uint32_t target, uint32_t return_va, uint8_t indirect);
void gw_recomp_trace_branch(uint32_t callsite, uint32_t caller,
                            uint32_t target, uint32_t eflags, uint8_t taken);
void gw_recomp_trace_watch_branch(uint32_t callsite);
void gw_recomp_trace_interrupt(uint8_t vector, uint32_t instruction_va,
                               uint32_t guest_function_va,
                               uint32_t request_eax, uint32_t request_ebx,
                               uint32_t request_ecx, uint32_t request_edx,
                               uint32_t request_esi, uint32_t request_edi,
                               uint32_t request_ds, uint32_t request_es,
                               uint32_t response_eax, uint32_t response_ebx,
                               uint32_t response_ecx, uint32_t response_edx,
                               uint32_t carry);
void gw_recomp_trace_checkpoint(uint32_t target, uint32_t caller);
uint32_t gw_recomp_trace_last_return_to(uint32_t target);
void gw_recomp_trace_boundary_state(uint32_t callsite, uint32_t caller,
    uint32_t target, uint32_t return_va, uint32_t eax, uint32_t ebx, uint32_t ecx, uint32_t edx,
    uint32_t esi, uint32_t edi, uint32_t ebp, uint32_t esp, uint32_t eflags);

#endif
