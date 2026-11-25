#ifndef GW_ENTITY_COVERAGE_H
#define GW_ENTITY_COVERAGE_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef struct gw_entity_coverage {
    uint8_t *pixels;
    uint32_t base, pitch, bytes, hud_width;
} gw_entity_coverage;

/* Caller checks that the host buffer spans pitch * height and the guest
   surface is mapped. Entries are one-based atlas slots for this frame. */
static inline void gw_entity_coverage_begin(gw_entity_coverage *coverage,
        uint8_t *pixels,uint32_t base,uint32_t pitch,uint32_t height,uint32_t hud_width) {
    *coverage=(gw_entity_coverage){pixels,base,pitch,pitch*height,hud_width};
    memset(pixels,0,coverage->bytes);
}

/* Last observed writer wins even when the new palette index is identical.
   Any non-entity writer uses slot 0 to retain its pixel in the 2D frame. */
static inline void gw_entity_coverage_write(const gw_entity_coverage *coverage,
        uint32_t address,uint32_t width,unsigned slot) {
    if(!width || address<coverage->base || slot>255u) return;
    const uint32_t offset=address-coverage->base;
    if(offset>=coverage->bytes) return;
    if(width>coverage->bytes-offset) width=coverage->bytes-offset;
    if(!slot) {
        memset(coverage->pixels+offset,0,width);
        return;
    }
    uint32_t current=offset;
    const uint32_t end=offset+width;
    while(current<end) {
        const uint32_t column=current%coverage->pitch;
        const uint32_t remaining=coverage->pitch-column;
        const uint32_t span=end-current<remaining?end-current:remaining;
        const uint32_t skip=column>=coverage->hud_width?0:coverage->hud_width-column;
        if(skip<span) memset(coverage->pixels+current+skip,(int)slot,span-skip);
        current+=span;
    }
}

#endif
