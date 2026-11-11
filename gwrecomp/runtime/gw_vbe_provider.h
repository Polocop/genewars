#ifndef GW_VBE_PROVIDER_H
#define GW_VBE_PROVIDER_H

#include <stdint.h>
#include "gw_dos_services.h"
#include "gw_interrupts.h"

/* Explicit host-emulated VBE profile. This is a device capability offered to
 * the guest; it is not a claim about the historical DOSBox VBE response. */
typedef struct gw_vbe_device {
    uint8_t *guest_memory;
    uint32_t guest_memory_size;
    uint32_t info_buffer_linear;
    uint32_t video_memory_bytes;
    uint16_t mode, width, height, pitch;
    uint16_t granularity_kb, window_size_kb, window_a_segment;
    uint8_t bits_per_pixel, memory_model;
    uint8_t mode_active;
    uint8_t reserved[2];
    uint32_t bank[2];
    uint32_t legacy_mode_query_calls;
    uint32_t set_mode_calls, mode_info_calls, controller_info_calls;
    uint32_t set_page_calls;
    uint32_t page_log[32];
    uint8_t window_log[32];
} gw_vbe_device;

int gw_vbe_device_configure(gw_vbe_device *device, uint8_t *guest_memory,
                            uint32_t guest_memory_size,
                            uint32_t info_buffer_linear, uint16_t mode,
                            uint16_t width, uint16_t height, uint16_t pitch,
                            uint8_t bits_per_pixel, uint16_t granularity_kb,
                            uint16_t window_size_kb,
                            uint16_t window_a_segment,
                            uint32_t video_memory_bytes);

/* DPMI AX=0300 callback and direct guest INT 10h provider share the same
 * contract/state. Only the VBE services actually used by the setup/title path
 * (4F00/4F01/4F02/4F05) are implemented. */
int gw_vbe_real_mode_interrupt(void *user, uint8_t vector,
                               gw_dos_real_mode_registers *registers);
gw_interrupt_result gw_vbe_interrupt(uint8_t vector, uint32_t instruction_va,
                                     void *user);

#endif
