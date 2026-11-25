#include <stdio.h>
#include <string.h>

#include "gw_indexed_sprite.h"

int main(void) {
    static const uint8_t stream[]={255,2,0,1,0,1,2,0};
    uint8_t pal[768]={0},remap[256]={0},rgba[24]={0};
    pal[3*3]=11;
    pal[4*3+1]=22;
    pal[5*3+2]=33;
    remap[0]=3; remap[1]=4; remap[2]=5;
    static const uint8_t expected[]={
        0,0,0,0, 0,0,0,0, 0,0,33,255,
        0,22,0,255, 11,0,0,255, 0,0,0,0
    };
    if(!gw_decode_indexed_sprite(stream,sizeof stream,3,2,pal,remap,1,1,rgba,sizeof rgba)) return 1;
    if(memcmp(rgba,expected,sizeof rgba)) return 2;
    if(gw_decode_indexed_sprite(stream,sizeof stream-1,3,2,pal,NULL,0,0,rgba,sizeof rgba)) return 3;
    if(gw_decode_indexed_sprite(stream,sizeof stream,2,2,pal,NULL,0,0,rgba,sizeof rgba)) return 4;
    if(gw_decode_indexed_sprite(stream,sizeof stream,3,2,pal,NULL,0,0,rgba,sizeof rgba-1)) return 5;
    puts("PASS spans, transparency, remap, flip, truncated input, row and output bounds");
    return 0;
}
