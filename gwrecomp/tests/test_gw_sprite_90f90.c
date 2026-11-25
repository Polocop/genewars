#include <stdio.h>
#include <string.h>
#include "gw_sprite_90f90.h"

int main(void) {
    const uint8_t samples[]={3,0xc3,0x03,0xc0,0};
    uint8_t palette[768]={0},remap[256]={0},rgba[12]={0};
    remap[19]=5; remap[3]=7; remap[16]=10;
    palette[5*3]=85; palette[7*3+1]=115; palette[10*3+2]=170;
    const uint8_t expected[]={0,0,170,255, 0,115,0,255, 85,0,0,255};
    if(!gw_decode_sprite_90f90(samples,sizeof samples,3,1,palette,remap,1,16,rgba,sizeof rgba))
        return 1;
    if(memcmp(rgba,expected,sizeof rgba)) return 2;
    const uint8_t sparse[]={255,1,0xc3,0};
    for(unsigned flags=4;flags<=8;flags+=4) {
        if(!gw_decode_sprite_90f90(sparse,sizeof sparse,3,1,palette,remap,flags,16,rgba,sizeof rgba)) return 3;
        if(rgba[3] || rgba[4]!=85 || rgba[7]!=140 || rgba[11]) return 6;
    }
    if(gw_sprite_90f90_kind(0x80)!=GW_SPRITE_BLIT_UNSUPPORTED) return 4;
    if(gw_sprite_90f90_kind(0x0d)!=GW_SPRITE_BLIT_DESTINATION) return 5;
    puts("PASS remap order, selector band, flip and translucent fallbacks");
    return 0;
}
