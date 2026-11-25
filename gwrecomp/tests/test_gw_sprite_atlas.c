#include <stdio.h>
#include "gw_sprite_atlas.h"

typedef struct uploader { unsigned count; int fail; } uploader;

static int checked_upload(void *user,gw_sprite_atlas_rect rect,const uint8_t *rgba) {
    uploader *state=user;
    if(state->fail || !rgba || rect.x+rect.w>GW_SPRITE_ATLAS_SIZE ||
       rect.y+rect.h>GW_SPRITE_ATLAS_SIZE) return 0;
    state->count++;
    return 1;
}

int main(void) {
    gw_sprite_atlas atlas={0};
    uploader state={0};
    uint8_t rgba[17*17*4]={0};
    gw_sprite_atlas_key key={.sprite=1,.remap=8,.width=17,.height=17,
                             .image=gw_sprite_atlas_image(rgba,sizeof rgba)};
    gw_sprite_atlas_rect first,second;
    size_t budget=2*sizeof rgba;
    if(!gw_sprite_atlas_get(&atlas,key,rgba,sizeof rgba,&budget,checked_upload,&state,&first)) return 1;
    if(!gw_sprite_atlas_get(&atlas,key,NULL,0,&budget,checked_upload,&state,&second) ||
       second.x!=first.x || second.y!=first.y || state.count!=1 || budget!=sizeof rgba) return 2;
    key.flip=1;
    state.fail=1;
    if(gw_sprite_atlas_get(&atlas,key,rgba,sizeof rgba,&budget,checked_upload,&state,&second) ||
       atlas.count!=1 || budget!=sizeof rgba) return 3;
    state.fail=0;
    if(!gw_sprite_atlas_get(&atlas,key,rgba,sizeof rgba,&budget,checked_upload,&state,&second) ||
       (first.x+first.w>second.x && first.y+first.h>second.y)) return 4;
    rgba[0]=1;
    key.image=gw_sprite_atlas_image(rgba,sizeof rgba);
    if(gw_sprite_atlas_get(&atlas,key,rgba,sizeof rgba,&budget,checked_upload,&state,&second) ||
       atlas.count!=2 || budget!=0) return 5;
    gw_sprite_atlas_reset(&atlas);
    budget=sizeof rgba;
    if(!gw_sprite_atlas_get(&atlas,key,rgba,sizeof rgba,&budget,checked_upload,&state,&second) ||
       second.x || second.y || state.count!=3) return 6;
    puts("PASS sprite atlas cache hits, upload limits and failures, placement and reset");
    return 0;
}
