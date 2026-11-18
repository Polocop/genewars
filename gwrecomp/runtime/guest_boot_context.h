#ifndef GW_GUEST_BOOT_CONTEXT_H
#define GW_GUEST_BOOT_CONTEXT_H

#include <stddef.h>
#include <stdint.h>
#include "recomp_context.h"

/* The first DOS/4G entry trace measures EIP/ESP and these flat selectors.
 * General registers plus FS/GS are not known at this boundary; their zero
 * values are deterministic harness seeds, not recovered guest state. */
enum {
    GW_BOOT_UNKNOWN_EAX = 1u << 0,
    GW_BOOT_UNKNOWN_EBX = 1u << 1,
    GW_BOOT_UNKNOWN_ECX = 1u << 2,
    GW_BOOT_UNKNOWN_EDX = 1u << 3,
    GW_BOOT_UNKNOWN_ESI = 1u << 4,
    GW_BOOT_UNKNOWN_EDI = 1u << 5,
    GW_BOOT_UNKNOWN_EBP = 1u << 6,
    GW_BOOT_UNKNOWN_FS = 1u << 7,
    GW_BOOT_UNKNOWN_GS = 1u << 8,
    GW_BOOT_UNKNOWN_ALL = (1u << 9) - 1
};

typedef struct gw_guest_boot_seed {
    uint32_t entry_va;
    uint32_t stack_va;
    uint16_t cs, ds, es, ss;
    uint32_t unknown_registers;
    uintptr_t guest_memory_host;
    size_t guest_memory_size;
} gw_guest_boot_seed;

/* Initialize a clean first-entry context for fixed-link-VA lifted code.
 * Segment bases start at zero; DOS/4G may replace them as services run. */
int gw_guest_boot_context_init(gw_recomp_context *context,
                               const gw_guest_boot_seed *seed);

#endif
