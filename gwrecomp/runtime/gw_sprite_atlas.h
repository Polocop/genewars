#ifndef GW_SPRITE_ATLAS_H
#define GW_SPRITE_ATLAS_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

enum {
    GW_SPRITE_ATLAS_SIZE=1024,
    GW_SPRITE_ATLAS_BLOCK=16,
    GW_SPRITE_ATLAS_GRID=GW_SPRITE_ATLAS_SIZE/GW_SPRITE_ATLAS_BLOCK,
    GW_SPRITE_ATLAS_MAX=512
};

typedef struct gw_sprite_atlas_key {
    uint32_t sprite,remap;
    uint16_t width,height;
    uint8_t flip,blend;
    /* Fingerprint of decoded RGBA, including changes made by palette/remap. */
    uint64_t image;
} gw_sprite_atlas_key;

typedef struct gw_sprite_atlas_rect { uint16_t x,y,w,h; } gw_sprite_atlas_rect;

typedef struct gw_sprite_atlas {
    struct {
        gw_sprite_atlas_key key;
        gw_sprite_atlas_rect rect;
    } slots[GW_SPRITE_ATLAS_MAX];
    uint64_t used[GW_SPRITE_ATLAS_GRID];
    size_t count;
} gw_sprite_atlas;

typedef int (*gw_sprite_atlas_upload)(void *,gw_sprite_atlas_rect,const uint8_t *);

static inline void gw_sprite_atlas_reset(gw_sprite_atlas *atlas) {
    atlas->count=0;
    memset(atlas->used,0,sizeof atlas->used);
}

static inline uint64_t gw_sprite_atlas_image(const uint8_t *rgba,size_t bytes) {
    uint64_t hash=UINT64_C(14695981039346656037);
    for(size_t i=0;i<bytes;i++)
        hash=(hash^rgba[i])*UINT64_C(1099511628211);
    return hash;
}

static inline int gw_sprite_atlas_key_equal(const gw_sprite_atlas_key *a,
                                           const gw_sprite_atlas_key *b) {
    return a->sprite==b->sprite && a->remap==b->remap && a->width==b->width &&
           a->height==b->height && a->flip==b->flip && a->blend==b->blend &&
           a->image==b->image;
}

/* Returns 1 for a usable rectangle. A miss that exceeds the upload budget
   or available space is left to the caller for a later frame or fallback.
   The allocator never evicts another sprite that a draw already references. */
static inline int gw_sprite_atlas_get(gw_sprite_atlas *atlas,gw_sprite_atlas_key key,
        const uint8_t *rgba,size_t rgba_bytes,size_t *upload_remaining,
        gw_sprite_atlas_upload upload,void *user,gw_sprite_atlas_rect *rect) {
    if(!key.width || !key.height || key.width>255 || key.height>255) return 0;
    for(size_t i=0;i<atlas->count;i++) {
        if(gw_sprite_atlas_key_equal(&atlas->slots[i].key,&key)) {
            *rect=atlas->slots[i].rect;
            return 1;
        }
    }
    const size_t bytes=(size_t)key.width*key.height*4u;
    if(!rgba || rgba_bytes<bytes || !upload || *upload_remaining<bytes ||
       atlas->count>=GW_SPRITE_ATLAS_MAX) return 0;
    const unsigned blocks_x=(key.width+GW_SPRITE_ATLAS_BLOCK-1)/GW_SPRITE_ATLAS_BLOCK;
    const unsigned blocks_y=(key.height+GW_SPRITE_ATLAS_BLOCK-1)/GW_SPRITE_ATLAS_BLOCK;
    const uint64_t bits=(UINT64_C(1)<<blocks_x)-1;
    for(unsigned row=0;row+blocks_y<=GW_SPRITE_ATLAS_GRID;row++) {
        uint64_t occupied=0;
        for(unsigned dy=0;dy<blocks_y;dy++) occupied|=atlas->used[row+dy];
        for(unsigned col=0;col+blocks_x<=GW_SPRITE_ATLAS_GRID;col++) {
            const uint64_t mask=bits<<col;
            if(occupied&mask) continue;
            const gw_sprite_atlas_rect next={(uint16_t)(col*GW_SPRITE_ATLAS_BLOCK),
                (uint16_t)(row*GW_SPRITE_ATLAS_BLOCK),key.width,key.height};
            if(!upload(user,next,rgba)) return 0;
            for(unsigned dy=0;dy<blocks_y;dy++) atlas->used[row+dy]|=mask;
            atlas->slots[atlas->count].key=key;
            atlas->slots[atlas->count++].rect=next;
            *upload_remaining-=bytes;
            *rect=next;
            return 1;
        }
    }
    return 0;
}
#endif
