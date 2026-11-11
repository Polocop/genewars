#ifndef GW_VSB16_H
#define GW_VSB16_H
/* V20: "virtual SB16" implementation of the Miles AIL3DIG digital driver ABI (INT 66h function level).
 *
 * The game links the Miles Sound System 3.03 library statically.  Its 32-bit code (sample handles, WAVE parsing,
 * volume/pan/rate/loop, and the software MIXER) stays the ORIGINAL guest code.  Only the real-mode SB16.DIG
 * driver is replaced: this module implements what the driver does to the shared data area (driver segment) when the
 * library calls it through DPMI AX=0300 -> INT 66h, and plays the DMA double buffer that the original mixer fills
 * through an SDL2 audio queue.  No Sound Blaster ports, DMA controller or PIC are emulated.
 * Contract reference: SB16.DIG (SHA-256 c8a1e7a0...6b38), V20 diagnostics. */
#include <stdint.h>
#include <stddef.h>

typedef struct gw_vsb16_stats {
    int enabled, device_open, state;
    unsigned rate, format;
    uint32_t dma_start, half_bytes;
    uint64_t calls, starts, stops, halves, bytes_pushed, service_calls, service_failures;
    uint64_t nonzero_halves, peak_abs, sum_abs, full_scale_endpoint_samples;
    uint64_t queue_failures, dma_range_failures, allocation_failures, underruns, queue_observations;
    uint32_t max_queued_bytes, min_queued_bytes_when_pumped;
} gw_vsb16_stats;

void gw_vsb16_log(const char *text);   /* stderr + GW_VSB16_LOG file */
void gw_vsb16_configure(int enabled);
int  gw_vsb16_enabled(void);
/* Handles driver functions 0x302,0x304,0x305,0x306,0x400-0x405 (0x300/0x301/0x303 stay in the harness).
 * mem/mem_size: guest memory; drv_base: linear address of the driver segment (segment*16).
 * Registers are the DPMI real-mode frame (AX,BX,CX,DX,SI,DI). Returns 1 when handled (AX etc updated). */
int  gw_vsb16_driver_call(uint8_t *mem, uint32_t mem_size, uint32_t drv_base, uint16_t fn,
                          uint16_t *ax, uint16_t *bx, uint16_t *cx, uint16_t *dx);
/* Called by the simulation thread between guest ticks. `service` runs the ORIGINAL guest mixer service routine once
 * (AIL timer callback registered by the library); it must return 1 on success. */
void gw_vsb16_pump(uint8_t *mem, uint32_t mem_size, int (*service)(void *user), void *user);
void gw_vsb16_close(void);
const gw_vsb16_stats *gw_vsb16_get_stats(void);
#endif
