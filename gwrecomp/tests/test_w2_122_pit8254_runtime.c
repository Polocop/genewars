#include "../runtime/gw_pit8254.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>

static int read_byte(gw_pit8254 *pit, uint8_t *out) {
    return gw_pit8254_read(pit, 0x40u, 1u, out);
}

int main(void) {
    gw_pit8254 pit, other;
    uint8_t lo = 0, hi = 0, other_value = 0, untouched = 0xA5u;
    uint8_t channel1 = 0, channel2_lo = 0, channel2_hi = 0;

    gw_pit8254_init(&pit);
    gw_pit8254_init(&other);
    /* Synthetic execution of W3-270's static OUT 0x43,0 / IN 0x40 x2. */
    if (!gw_pit8254_write(&pit, 0x43u, 0x00u, 1u) ||
        !read_byte(&pit, &lo) || !read_byte(&pit, &hi)) return 1;
    printf("poll=%02X,%02X\n", (unsigned)lo, (unsigned)hi);

    /* Channel 0, low/high access, mode 2, reload 0x1234. */
    if (!gw_pit8254_write(&pit, 0x43u, 0x34u, 1u) ||
        !gw_pit8254_write(&pit, 0x40u, 0x34u, 1u) ||
        !gw_pit8254_write(&pit, 0x40u, 0x12u, 1u) ||
        !gw_pit8254_advance(&pit, 1u) ||
        !gw_pit8254_write(&pit, 0x43u, 0x00u, 1u) ||
        !read_byte(&pit, &lo) || !read_byte(&pit, &hi)) return 2;
    printf("latched=%02X,%02X\n", (unsigned)lo, (unsigned)hi);

    /* Channel 1 low-byte-only reload, periodic mode. */
    if (!gw_pit8254_write(&pit, 0x43u, 0x56u, 1u) ||
        !gw_pit8254_write(&pit, 0x41u, 9u, 1u) ||
        !gw_pit8254_advance(&pit, 2u) ||
        !gw_pit8254_read(&pit, 0x41u, 1u, &channel1)) return 8;
    printf("channel1=%02X\n", (unsigned)channel1);

    /* Channel 2 low/high periodic reload, exercising another channel. */
    if (!gw_pit8254_write(&pit, 0x43u, 0xB4u, 1u) ||
        !gw_pit8254_write(&pit, 0x42u, 100u, 1u) ||
        !gw_pit8254_write(&pit, 0x42u, 0u, 1u) ||
        !gw_pit8254_advance(&pit, 3u) ||
        !gw_pit8254_read(&pit, 0x42u, 1u, &channel2_lo) ||
        !gw_pit8254_read(&pit, 0x42u, 1u, &channel2_hi)) return 9;
    printf("channel2=%02X,%02X\n", (unsigned)channel2_lo,
           (unsigned)channel2_hi);

    /* A second instance starts independently at the default count state. */
    if (!read_byte(&other, &other_value) || other_value != 0u) return 3;
    if (gw_pit8254_read(&pit, 0x40u, 2u, &untouched) || untouched != 0xA5u)
        return 4;
    if (gw_pit8254_write(&pit, 0x43u, 0xC0u, 1u)) return 5;
    if (gw_pit8254_read(&pit, 0x43u, 1u, &untouched)) return 6;
    if (!gw_pit8254_advance(&pit, 0u)) return 7;
    if (!gw_pit8254_advance(&other, UINT64_MAX)) return 10;
    if (gw_pit8254_advance(&other, 1u)) return 11;
    puts("PASS synthetic C PIT8254");
    return 0;
}
