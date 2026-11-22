#ifndef GW_TERRAIN_VISIBLE_MESH_H
#define GW_TERRAIN_VISIBLE_MESH_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "gw_terrain_gpu_fixture.h"
#include "gw_terrain_mesh_projection.h"

/* Guest addresses for the relocated DOS 1.1 image. The view is immutable.
   The map origin is MapDisplay +0/+2, as copied by 0x7839D/0x783A6
   and 0x79FFC/0x7A005. Ring +8/+0x0A are storage offsets only. */
enum {
    GW_TERRAIN_MAP = 0x002F4F86,
    GW_TERRAIN_MAP_DISPLAY = 0x00346D70,
    GW_TERRAIN_B32_TABLE = 0x002EEA08,
    GW_TERRAIN_COMPLEMENT_TABLE = 0x002EEC7C,
    GW_TERRAIN_UV_TABLE = 0x002DFBF8,
    GW_TERRAIN_CELL_STEP_X = 0x0035EAA4,
    GW_TERRAIN_CELL_STEP_Y = 0x0035EAA8,
    GW_TERRAIN_HEIGHT_SCALE = 0x0035EAB4
};

typedef struct gw_terrain_visible_triangle {
    gw_terrain_gpu_vertex vertex[3];
    uint32_t texture;
    uint8_t mode;
    int16_t wc[3],wr[3];   /* world cell of each corner relative to the display origin (unwrapped) */
} gw_terrain_visible_triangle;

static inline int16_t gw_terrain_read_i16(const uint8_t *p) {
    int16_t value;
    memcpy(&value,p,sizeof value);
    return value;
}

static inline uint32_t gw_terrain_read_u32(const uint8_t *p) {
    uint32_t value;
    memcpy(&value,p,sizeof value);
    return value;
}

static inline const uint8_t *gw_terrain_cell(const uint8_t *map,int col,int row) {
    return map+14u*(((unsigned)row&127u)*128u+((unsigned)col&127u));
}

static inline gw_terrain_gpu_vertex gw_terrain_corner(const uint8_t *cell,int x,int y,int scale) {
    const int height=gw_terrain_mesh_height_step(gw_terrain_read_i16(cell+2));
    /* 0x66040 scales the signed lighting word by the unsigned byte,
       then adds the 16.16 half-step. The product is already divisible by 64. */
    return (gw_terrain_gpu_vertex){x,y-height*scale,0,0,32768+4*gw_terrain_read_i16(cell)*cell[12],height};
}

static inline int gw_terrain_emit_visible(const uint8_t *ds,const uint8_t *tile,const uint8_t *extra,
                                         gw_terrain_gpu_vertex a,gw_terrain_gpu_vertex b,
                                         gw_terrain_gpu_vertex c,unsigned second,int height,
                                         int wcol,int wrow,
                                         gw_terrain_visible_triangle *out,size_t capacity,size_t *n) {
    if((a.y<0 && b.y<0 && c.y<0) || (a.y>=height && b.y>=height && c.y>=height)) return 1;
    const uint8_t *uv=ds+GW_TERRAIN_UV_TABLE+((unsigned)tile[5]&0x70u)*2u;
    const unsigned b_uv=second?8u:16u,c_uv=second?16u:24u;
    a.u=(int32_t)gw_terrain_read_u32(uv); a.v=(int32_t)gw_terrain_read_u32(uv+4);
    b.u=(int32_t)gw_terrain_read_u32(uv+b_uv); b.v=(int32_t)gw_terrain_read_u32(uv+b_uv+4);
    c.u=(int32_t)gw_terrain_read_u32(uv+c_uv); c.v=(int32_t)gw_terrain_read_u32(uv+c_uv+4);
    if(*n==capacity) return 0;
    /* corners: first triangle (col,row) (col+1,row+1) (col,row+1); second (col,row+1) (col+1,row+1) (col+1,row+2) */
    const int16_t wc0=(int16_t)wcol,wc1=(int16_t)(wcol+1),wr0=(int16_t)(second?wrow+1:wrow),wr1=(int16_t)(wrow+1),wr2=(int16_t)(second?wrow+2:wrow+1);
    const uint32_t texture=gw_terrain_read_u32(ds+GW_TERRAIN_B32_TABLE+4u*tile[4]);
    out[(*n)++]=(gw_terrain_visible_triangle){{a,b,c},texture,
        (uint8_t)((a.light || b.light || c.light)?5u:0u),{wc0,wc1,second?wc1:wc0},{wr0,wr1,wr2}};
    const unsigned kind=extra[13];
    if(kind<=1u) return 1;
    if(*n==capacity) return 0;
    const unsigned bank=kind>=97u?2u:(kind-1u)/32u;
    out[(*n)++]=(gw_terrain_visible_triangle){{a,b,c},
        gw_terrain_read_u32(ds+GW_TERRAIN_COMPLEMENT_TABLE+4u*bank),6u,{wc0,wc1,second?wc1:wc0},{wr0,wr1,wr2}};
    return 1;
}

/* Back-to-front order of the full redraw: columns left to right, then
   each pair down its strip. Each iteration advances both map indices
   by one after emitting the two triangles (0x66143, 0x6636A).
   Callers use the display origin and canvas rectangle, independent of
   the physical destination addresses used for incremental redraws. */
static inline size_t gw_terrain_build_visible(const uint8_t *ds,unsigned width,unsigned height,
                                               gw_terrain_visible_triangle *out,size_t capacity) {
    const uint8_t *display=ds+GW_TERRAIN_MAP_DISPLAY;
    const uint8_t *map=ds+GW_TERRAIN_MAP;
    const int dx=(int)gw_terrain_read_u32(ds+GW_TERRAIN_CELL_STEP_X);
    const int dy=(int)gw_terrain_read_u32(ds+GW_TERRAIN_CELL_STEP_Y);
    const int scale=(int)gw_terrain_read_u32(ds+GW_TERRAIN_HEIGHT_SCALE);
    const int left=gw_terrain_read_i16(display+0x1D);
    /* IFCMain normal terrain modes only. A special camera pass may tint or
       annotate a strip. Leave its original rendering to the compositor. */
    if(dx!=32 || dy!=16 || scale<0 || scale>4 || left<0 || left%dx ||
       width<=(unsigned)left || width>1152u || height==0 || height>640u || (display[0x1C]&0x40u)) return 0;
    const int view_col=gw_terrain_read_i16(display);
    const int view_row=gw_terrain_read_i16(display+2);
    size_t n=0;

    for(int x=left;x<(int)width;x+=dx) {
        const int column=x/dx;
        int col=view_col+column/2;
        int row=view_row-column/2-1-(column&1);
        int y=-dy*(1+(column&1));
        const uint8_t *a=gw_terrain_cell(map,col,row);
        const uint8_t *b=gw_terrain_cell(map,col,row+1);
        gw_terrain_gpu_vertex va=gw_terrain_corner(a,x+dx,y,scale);
        gw_terrain_gpu_vertex vb=gw_terrain_corner(b,x,y+dy,scale);

        for(unsigned pair=0;pair<128u;pair++) {
            const uint8_t *c=gw_terrain_cell(map,col+1,row+1);
            const uint8_t *d=gw_terrain_cell(map,col+1,row+2);
            const gw_terrain_gpu_vertex vc=gw_terrain_corner(c,x+dx,y+dy*2,scale);
            const gw_terrain_gpu_vertex vd=gw_terrain_corner(d,x,y+dy*3,scale);
            const int wcol=col-view_col,wrow=row-view_row;
            if(!gw_terrain_emit_visible(ds,a,a,va,vc,vb,0,(int)height,wcol,wrow,out,capacity,&n) ||
               !gw_terrain_emit_visible(ds,b,b,vb,vc,vd,1,(int)height,wcol,wrow,out,capacity,&n)) return 0;
            /* 0x66583/0x66592 compare the two advancing strip edges. */
            if(vc.y>=(int)height && vd.y>=(int)height) break;
            col++; row++; y+=dy*2;
            a=c; b=d; va=vc; vb=vd;
        }
    }
    return n;
}

/* Packed draw data is copied with the visual snapshot. The atlas uses one
   stable address key per live B32 tile in this frame, across both passes. */
enum { GW_MESH_TILES=259, GW_MESH_ATLAS_COLS=16, GW_MESH_ATLAS_W=512 };

typedef struct gw_terrain_mesh_vertex {
    float x,y,depth,u,v,light,tile,mode;
    float wx,wy,wz;   /* world cell relative to the display origin, height in screen pixels (step x scale) */
} gw_terrain_mesh_vertex;

typedef struct gw_terrain_mesh_draw {
    unsigned count,tiles;
    /* the whole planet's height grid (cell +2, raw signed), the display origin and the projection's height scale:
       lighting, shadows and water depth of the 3D terrain (presentation only) */
    int16_t planet_h[128u*128u];
    int view_col,view_row,height_scale;
    gw_terrain_mesh_vertex vertex[3u*GW_TERRAIN_GPU_FIXTURE_CAP];
    uint8_t texels[GW_MESH_TILES][1024];
    uint8_t fade[64u*256u];
} gw_terrain_mesh_draw;

static inline void gw_terrain_prepare_draw(const uint8_t *ds,size_t bound,unsigned width,unsigned height,
                                           gw_terrain_mesh_draw *draw) {
    static gw_terrain_visible_triangle mesh[GW_TERRAIN_GPU_FIXTURE_CAP];
    uint32_t tile_address[GW_MESH_TILES];
    const size_t count=gw_terrain_build_visible(ds,width,height,mesh,GW_TERRAIN_GPU_FIXTURE_CAP);
    unsigned tiles=0;
    draw->count=0;
    draw->height_scale=(int)gw_terrain_read_u32(ds+GW_TERRAIN_HEIGHT_SCALE);
    draw->view_col=gw_terrain_read_i16(ds+GW_TERRAIN_MAP_DISPLAY);
    draw->view_row=gw_terrain_read_i16(ds+GW_TERRAIN_MAP_DISPLAY+2);
    if(count) {
        const uint8_t *map=ds+GW_TERRAIN_MAP;
        for(unsigned i=0;i<128u*128u;i++) draw->planet_h[i]=gw_terrain_read_i16(map+14u*i+2u);
    }
    for(size_t i=0;i<count;i++) {
        const gw_terrain_visible_triangle *tri=&mesh[i];
        const uint32_t tex=tri->texture;
        unsigned slot=0;
        while(slot<tiles && tile_address[slot]!=tex) slot++;
        if(slot==tiles) {
            if(!tex || tex>bound-(31u*256u+32u) || tiles==GW_MESH_TILES) return;
            tile_address[tiles++]=tex;
            for(unsigned row=0;row<32;row++)
                memcpy(draw->texels[slot]+32u*row,ds+tex+256u*row,32u);
        }
        for(unsigned k=0;k<3;k++) {
            const gw_terrain_gpu_vertex *v=&tri->vertex[k];
            draw->vertex[3*i+k]=(gw_terrain_mesh_vertex){
                (float)v->x,(float)v->y,0.75f-(float)i/(float)GW_TERRAIN_GPU_FIXTURE_CAP,
                v->u/65536.0f,v->v/65536.0f,v->light/65536.0f,(float)slot,(float)tri->mode,
                (float)tri->wc[k],(float)tri->wr[k],(float)v->height*(float)draw->height_scale
            };
        }
    }
    if(count) memcpy(draw->fade,ds+0x00362A54u,sizeof draw->fade);
    draw->tiles=tiles;
    draw->count=(unsigned)count*3u;
}

#endif
