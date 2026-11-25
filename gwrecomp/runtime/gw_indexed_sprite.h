#ifndef GW_INDEXED_SPRITE_H
#define GW_INDEXED_SPRITE_H

#include <stddef.h>
#include <stdint.h>

/* One signed-span stream per row. Positive tokens carry that many palette
   indices, negative tokens skip transparent pixels, and zero ends the row.
   The source and its bounds are supplied by the host resource owner. */
static inline int gw_decode_indexed_sprite(const uint8_t *source,size_t source_size,
        unsigned width,unsigned height,const uint8_t palette[768],const uint8_t *remap,
        unsigned flip_x,unsigned flip_y,uint8_t *rgba,size_t rgba_size) {
    if(!source || !palette || !rgba || !width || !height || width>255 || height>255 ||
       rgba_size<(size_t)width*height*4u) return 0;
    size_t offset=0;
    for(unsigned row=0;row<height;row++) {
        unsigned x=0;
        const unsigned y=flip_y?height-1-row:row;
        for(;;) {
            if(offset==source_size) return 0;
            const unsigned token=source[offset++];
            if(token==0) break;
            const int opaque=token<128;
            const unsigned span=opaque?token:256u-token;
            if(span>width-x || (opaque && span>source_size-offset)) return 0;
            for(unsigned i=0;i<span;i++,x++) {
                const unsigned column=flip_x?width-1-x:x;
                uint8_t *pixel=rgba+((size_t)y*width+column)*4u;
                if(opaque) {
                    const unsigned index=source[offset++];
                    const uint8_t *rgb=palette+3u*(remap?remap[index]:index);
                    pixel[0]=rgb[0]; pixel[1]=rgb[1]; pixel[2]=rgb[2]; pixel[3]=255;
                } else {
                    pixel[0]=pixel[1]=pixel[2]=pixel[3]=0;
                }
            }
        }
        /* A row may end after its last opaque pixel. */
        while(x<width) {
            const unsigned column=flip_x?width-1-x:x;
            uint8_t *pixel=rgba+((size_t)y*width+column)*4u;
            pixel[0]=pixel[1]=pixel[2]=pixel[3]=0;
            x++;
        }
    }
    return 1;
}
#endif
