#ifndef GW_PIT8254_H
#define GW_PIT8254_H

#include <stdint.h>

typedef struct gw_pit8254 {
    uint8_t control_word;
    uint8_t write_low_valid[3];
    uint8_t write_low[3];
    uint8_t write_high_next[3];
    uint8_t write_access[3];
    uint8_t read_access[3];
    uint8_t read_high_next[3];
    uint8_t latch_pending[3];
    uint32_t reload[3];
    uint32_t read_latch[3];
    uint64_t virtual_cycles;
    uint64_t reload_cycle[3];
} gw_pit8254;

void gw_pit8254_init(gw_pit8254 *pit);
int gw_pit8254_advance(gw_pit8254 *pit, uint64_t cycles);
int gw_pit8254_write(gw_pit8254 *pit, uint16_t port, uint8_t value,
                     unsigned width_bytes);
int gw_pit8254_read(gw_pit8254 *pit, uint16_t port, unsigned width_bytes,
                    uint8_t *value_out);

#endif
