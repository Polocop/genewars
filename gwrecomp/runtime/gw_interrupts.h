#ifndef GW_INTERRUPTS_H
#define GW_INTERRUPTS_H
#include <stdint.h>
#include "../third_party/pcrecomp/runtime/recomp32/recomp_types.h"

typedef gw_interrupt_result (*gw_interrupt_callback)(uint8_t vector,
                                                       uint32_t instruction_va,
                                                       void *user);
typedef struct gw_interrupt_trap {
    uint8_t pending;
    uint8_t vector;
    uint16_t reserved;
    uint32_t instruction_va;
    uint32_t guest_function_va;
} gw_interrupt_trap;

void gw_interrupt_set_callback(gw_interrupt_callback callback, void *user);
void gw_interrupt_clear_trap(void);
gw_interrupt_trap gw_interrupt_get_trap(void);
gw_interrupt_result gw_interrupt_dispatch(uint8_t vector, uint32_t instruction_va);

#endif
