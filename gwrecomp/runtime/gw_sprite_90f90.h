#ifndef GW_SPRITE_90F90_H
#define GW_SPRITE_90F90_H

#include "gw_indexed_sprite.h"

enum gw_sprite_blit_kind {
    GW_SPRITE_BLIT_UNSUPPORTED,
    GW_SPRITE_BLIT_SOURCE,
    GW_SPRITE_BLIT_DESTINATION
};

static inline enum gw_sprite_blit_kind gw_sprite_90f90_kind(unsigned flags) {
    /* 0x90FDB / 0x90FF2 and 0x91056. Higher bits have separate contracts. */
    if(flags & ~15u) return GW_SPRITE_BLIT_UNSUPPORTED;
    return flags & 12u ? GW_SPRITE_BLIT_DESTINATION : GW_SPRITE_BLIT_SOURCE;
}

/* Selectors replace the C0â€“CF source band before the 256-entry remap.
   For host texture preparation, the caller provides the palette in 8-bit channels. */
static inline int gw_decode_sprite_90f90(const uint8_t *source,size_t source_size,
        unsigned width,unsigned height,const uint8_t palette[768],
        const uint8_t guest_remap[256],unsigned flags,unsigned selector,
        uint8_t *rgba,size_t rgba_size) {
    const enum gw_sprite_blit_kind kind=gw_sprite_90f90_kind(flags);
    if(!guest_remap || kind==GW_SPRITE_BLIT_UNSUPPORTED) return 0;
    uint8_t remap[256];
    for(unsigned i=0;i<256;i++) {
        const unsigned index=(i>=0xc0u && i<=0xcfu)?(selector+(i&15u))&255u:i;
        remap[i]=guest_remap[index];
    }
    if(!gw_decode_indexed_sprite(source,source_size,width,height,palette,remap,
                                 flags&1u,flags&2u,rgba,rgba_size)) return 0;
    /* A destination-dependent call gets the requested translucent fallback.
       Skipped spans stay transparent. The renderer must disable depth writes. */
    if(kind==GW_SPRITE_BLIT_DESTINATION)
        for(size_t i=3;i<(size_t)width*height*4u;i+=4u)
            if(rgba[i]) rgba[i]=140;
    return 1;
}
#endif
