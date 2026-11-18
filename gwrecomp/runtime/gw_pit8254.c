#include "gw_pit8254.h"

#include <limits.h>
#include <string.h>

static uint32_t current_count(const gw_pit8254 *pit, unsigned channel) {
    const uint32_t period = pit->reload[channel];
    uint64_t elapsed;
    uint64_t count;
    unsigned mode;

    if (period == 0u) return 0u;
    elapsed = pit->virtual_cycles >= pit->reload_cycle[channel]
        ? pit->virtual_cycles - pit->reload_cycle[channel] : 0u;
    mode = (pit->control_word >> 1) & 7u;
    if (mode == 2u || mode == 3u || mode == 6u || mode == 7u)
        count = (uint64_t)period - (elapsed % period);
    else
        count = elapsed >= period ? 0u : (uint64_t)period - elapsed;
    return (uint32_t)(count & 0xffffu);
}

void gw_pit8254_init(gw_pit8254 *pit) {
    unsigned i;
    if (!pit) return;
    memset(pit, 0, sizeof(*pit));
    for (i = 0; i < 3u; ++i) {
        pit->write_access[i] = 3u;
        pit->read_access[i] = 3u;
    }
}

int gw_pit8254_advance(gw_pit8254 *pit, uint64_t cycles) {
    if (!pit || cycles > UINT64_MAX - pit->virtual_cycles) return 0;
    pit->virtual_cycles += cycles;
    return 1;
}

int gw_pit8254_write(gw_pit8254 *pit, uint16_t port, uint8_t value,
                     unsigned width_bytes) {
    unsigned channel;
    unsigned access;
    if (!pit || width_bytes != 1u) return 0;
    if (port == 0x43u) {
        pit->control_word = value;
        channel = (value >> 6) & 3u;
        access = (value >> 4) & 3u;
        if (channel == 3u) return 0; /* Read-back command is unsupported. */
        if (access == 0u) {
            pit->read_latch[channel] = current_count(pit, channel);
            pit->latch_pending[channel] = 1u;
            pit->read_high_next[channel] = 0u;
            return 1;
        }
        pit->latch_pending[channel] = 0u;
        pit->read_latch[channel] = 0u;
        pit->write_access[channel] = (uint8_t)access;
        pit->read_access[channel] = (uint8_t)access;
        pit->write_high_next[channel] = 0u;
        pit->read_high_next[channel] = (uint8_t)(access == 2u);
        return 1;
    }
    if (port < 0x40u || port > 0x42u) return 0;
    channel = (unsigned)(port - 0x40u);
    access = pit->write_access[channel];
    if (access == 3u && pit->write_high_next[channel]) {
        const uint32_t low = pit->write_low_valid[channel]
            ? pit->write_low[channel] : 0u;
        pit->reload[channel] = (((uint32_t)value << 8) | low) & 0xffffu;
        if (pit->reload[channel] == 0u) pit->reload[channel] = 0x10000u;
        pit->reload_cycle[channel] = pit->virtual_cycles;
        pit->write_low_valid[channel] = 0u;
        pit->write_high_next[channel] = 0u;
    } else if (access == 3u) {
        pit->write_low[channel] = value;
        pit->write_low_valid[channel] = 1u;
        pit->write_high_next[channel] = 1u;
    } else if (access == 2u) {
        pit->reload[channel] = (((uint32_t)value << 8) |
                                (pit->reload[channel] & 0xffu)) & 0xffffu;
        if (pit->reload[channel] == 0u) pit->reload[channel] = 0x10000u;
        pit->reload_cycle[channel] = pit->virtual_cycles;
    } else {
        pit->reload[channel] = value ? value : 0x10000u;
        pit->reload_cycle[channel] = pit->virtual_cycles;
    }
    return 1;
}

int gw_pit8254_read(gw_pit8254 *pit, uint16_t port, unsigned width_bytes,
                    uint8_t *value_out) {
    unsigned channel;
    uint32_t count;
    uint8_t value;
    if (!pit || !value_out || width_bytes != 1u ||
        port < 0x40u || port > 0x42u)
        return 0;
    channel = (unsigned)(port - 0x40u);
    count = pit->latch_pending[channel]
        ? pit->read_latch[channel] : current_count(pit, channel);
    if (pit->read_access[channel] == 2u) {
        value = (uint8_t)((count >> 8) & 0xffu);
        pit->read_latch[channel] = 0u;
        pit->latch_pending[channel] = 0u;
    } else if (pit->read_high_next[channel]) {
        value = (uint8_t)((count >> 8) & 0xffu);
        pit->read_high_next[channel] = 0u;
        if (pit->latch_pending[channel]) {
            pit->read_latch[channel] = 0u;
            pit->latch_pending[channel] = 0u;
        }
    } else {
        value = (uint8_t)(count & 0xffu);
        if (pit->read_access[channel] == 3u)
            pit->read_high_next[channel] = 1u;
        else {
            pit->read_latch[channel] = 0u;
            pit->latch_pending[channel] = 0u;
        }
    }
    *value_out = value;
    return 1;
}
