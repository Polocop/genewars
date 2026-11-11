#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "gw_video_surface.h"

int main(void) {
    uint8_t storage[5u * 16u];
    memset(storage, 0xA5, sizeof storage);
    gw_video_surface s={storage,11,5,16,1,{1,1,9,3}};
    assert(gw_video_surface_valid(&s));
    assert(gw_video_surface_row(&s,0)==storage);
    assert(gw_video_surface_row(&s,4)==storage+64);
    assert(gw_video_surface_row(&s,-1)==0);
    assert(gw_video_surface_row(&s,5)==0);
    gw_video_surface bad=s;
    bad.pitch_bytes=10;
    assert(!gw_video_surface_valid(&bad));
    bad=s; bad.clip.x=3; bad.clip.w=9;
    assert(!gw_video_surface_valid(&bad));

    int x=-1,y=-1;
    gw_video_rect output={100,50,2200,1350};
    assert(gw_video_window_to_surface(100,50,2560,1440,output,&s,&x,&y));
    assert(x==0 && y==0);
    assert(gw_video_window_to_surface(2299,1399,2560,1440,output,&s,&x,&y));
    assert(x==10 && y==4);
    assert(!gw_video_window_to_surface(99,50,2560,1440,output,&s,&x,&y));
    assert(!gw_video_window_to_surface(2300,1399,2560,1440,output,&s,&x,&y));
    assert(!gw_video_window_to_surface(100,50,0,1440,output,&s,&x,&y));

    gw_video_surface wide={storage,16,9,20,1,{0,0,16,9}};
    gw_video_rect native_2k={0,0,2560,1440};
    assert(gw_video_window_to_surface(2559,1439,2560,1440,native_2k,&wide,&x,&y));
    assert(x==15 && y==8);
    assert(!gw_video_window_to_surface(2560,1439,2560,1440,native_2k,&wide,&x,&y));

    gw_video_surface legacy={storage,640,480,640,1,{0,0,640,480}};
    gw_video_rect fitted={200,0,1200,900};
    assert(gw_video_window_to_surface(200,0,1600,900,fitted,&legacy,&x,&y));
    assert(x==0 && y==0);
    assert(gw_video_window_to_surface(1399,899,1600,900,fitted,&legacy,&x,&y));
    assert(x==639 && y==479);
    assert(!gw_video_window_to_surface(199,450,1600,900,fitted,&legacy,&x,&y));
    assert(!gw_video_window_to_surface(1400,450,1600,900,fitted,&legacy,&x,&y));
    return 0;
}
