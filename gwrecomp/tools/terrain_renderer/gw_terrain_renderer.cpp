#include "gw_terrain_renderer.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <windows.h>

namespace {
constexpr int kMapSide = 128;
constexpr int kRecordStride = 14;
constexpr std::size_t kAtlasBytes = 160u * 32u * 32u;

struct Tile {
    int wx, wy, block, height, sx, sy;
    std::size_t tex_base;
};

int signed_height(const uint8_t *cell) {
    const uint16_t raw=static_cast<uint16_t>(cell[2] | (uint16_t(cell[3]) << 8));
    return static_cast<int16_t>(raw);
}
int sar6(int value) {
    return value >= 0 ? value / 64 : -(((-value) + 63) / 64);
}
int wrap_delta(int world_q8, int camera_q8) {
    int d=world_q8-camera_q8;
    while(d < -(64*256)) d += 128*256;
    while(d >= 64*256) d -= 128*256;
    return d;
}
bool tile_order(const Tile &a, const Tile &b) {
    if(a.sy!=b.sy) return a.sy<b.sy;
    if(a.sx!=b.sx) return a.sx<b.sx;
    if(a.wy!=b.wy) return a.wy<b.wy;
    return a.wx<b.wx;
}
uint64_t perf_counter() {
    LARGE_INTEGER value;
    QueryPerformanceCounter(&value);
    return static_cast<uint64_t>(value.QuadPart);
}
double elapsed_ms(uint64_t start,uint64_t end) {
    LARGE_INTEGER frequency;
    QueryPerformanceFrequency(&frequency);
    return frequency.QuadPart>0?
        1000.0*static_cast<double>(end-start)/static_cast<double>(frequency.QuadPart):0.0;
}
}

struct gw_terrain_renderer { Tile *tiles; };

extern "C" gw_terrain_renderer *gw_terrain_renderer_create(void) {
    gw_terrain_renderer *renderer=static_cast<gw_terrain_renderer *>(std::calloc(1,sizeof(*renderer)));
    if(!renderer) return nullptr;
    renderer->tiles=static_cast<Tile *>(std::malloc(sizeof(Tile)*kMapSide*kMapSide));
    if(!renderer->tiles) { std::free(renderer); return nullptr; }
    return renderer;
}

extern "C" void gw_terrain_renderer_destroy(gw_terrain_renderer *renderer) {
    if(!renderer) return;
    std::free(renderer->tiles);
    std::free(renderer);
}

extern "C" int gw_terrain_renderer_render_with_offset(gw_terrain_renderer *renderer,
    const uint8_t *world_records, const uint8_t *b32_atlas,
    int width, int height, int viewport_left, int viewport_center_x,
    int viewport_center_y_offset,
    int camera_x_q8, int camera_y_q8, int scale_x, int scale_y,
    int height_scale, uint8_t *indexed, uint8_t *coverage,
    gw_terrain_metrics *metrics) {
    if(!renderer || !renderer->tiles || !world_records || !b32_atlas ||
       !indexed || !coverage || !metrics || width<320 || width>4096 ||
       height<200 || height>2304 || viewport_left<0 || viewport_left>=width ||
       viewport_center_x<viewport_left || viewport_center_x>=width ||
       scale_x<1 || scale_y<1 || scale_x>2048 || scale_y>1080 ||
       scale_x%2 || scale_y%2 || height_scale<0)
        return 0;
    const uint64_t geometry_start=perf_counter();
    std::memset(indexed,0,static_cast<std::size_t>(width)*height);
    for(int y=0;y<height;++y)
        std::memset(coverage+static_cast<std::size_t>(y)*width+viewport_left,0,
                    static_cast<std::size_t>(width-viewport_left));
    std::memset(metrics,0,sizeof(*metrics));
    int tile_count=0;
    for(int wy=0;wy<kMapSide;++wy) for(int wx=0;wx<kMapSide;++wx) {
        const uint8_t *cell=world_records+(static_cast<std::size_t>(wy)*kMapSide+wx)*kRecordStride;
        const int block=cell[4];
        if(block>=160) continue;
        const int dx=wrap_delta(wx*256,camera_x_q8);
        const int dy=wrap_delta(wy*256,camera_y_q8);
        const int h=signed_height(cell);
        const int sx=viewport_center_x+((dx-dy)*scale_x)/256;
        const int sy=height/2+viewport_center_y_offset+
            ((dx+dy)*scale_y)/256-sar6(h)*height_scale;
        if(sx < viewport_left-32 || sx>=width+32 || sy < -16 || sy>=height+16) continue;
        const std::size_t tex_base=static_cast<std::size_t>(block/8)*0x2000u+
            static_cast<std::size_t>(block%8)*0x20u;
        renderer->tiles[tile_count++]={wx,wy,block,h,sx,sy,tex_base};
    }
    std::sort(renderer->tiles,renderer->tiles+tile_count,
              [](const Tile &a,const Tile &b) { return tile_order(a,b); });
    const uint64_t geometry_end=perf_counter();
    metrics->visible_cells=static_cast<uint32_t>(tile_count);
    const int half_w=scale_x,half_h=scale_y;
    const std::size_t pixel_count=static_cast<std::size_t>(width)*height;
    int tex_lookup[4097];
    for(int i=0;i<=2*half_w;++i) tex_lookup[i]=(i*31)/(2*half_w);
    const uint64_t raster_start=perf_counter();
    for(int ti=0;ti<tile_count;++ti) {
        const Tile &tile=renderer->tiles[ti];
        for(int ly=-half_h;ly<=half_h;++ly) {
            const int py=tile.sy+ly;
            if(py<0 || py>=height) continue;
            const int span=(half_w*(half_h-std::abs(ly)))/half_h;
            int lx0=-span,lx1=span;
            if(tile.sx+lx0<viewport_left) lx0=viewport_left-tile.sx;
            if(tile.sx+lx1>=width) lx1=width-1-tile.sx;
            if(lx0>lx1) continue;
            const int row_term=(half_w*ly)/half_h;
            int u=half_w+lx0+row_term;
            int v=half_w-lx0+row_term;
            std::size_t dst=static_cast<std::size_t>(py)*width+
                            static_cast<std::size_t>(tile.sx+lx0);
            for(int lx=lx0;lx<=lx1;++lx,++u,--v,++dst) {
                const std::size_t src=tile.tex_base+
                    static_cast<std::size_t>(tex_lookup[v])*256u+
                    static_cast<std::size_t>(tex_lookup[u]);
                if(dst>=pixel_count || src>=kAtlasBytes) return 0;
                if(coverage[dst]) ++metrics->overdraw;
                else ++metrics->covered_pixels;
                const uint8_t color=b32_atlas[src];
                if(color) ++metrics->nonzero_texels;
                indexed[dst]=color;
                coverage[dst]=1;
                ++metrics->write_ops;
            }
        }
    }
    const uint64_t raster_end=perf_counter();
    metrics->geometry_ms=elapsed_ms(geometry_start,geometry_end);
    metrics->raster_ms=elapsed_ms(raster_start,raster_end);
    return tile_count>0 && metrics->covered_pixels>0;
}

extern "C" int gw_terrain_renderer_render(gw_terrain_renderer *renderer,
    const uint8_t *world_records, const uint8_t *b32_atlas,
    int width, int height, int viewport_left, int viewport_center_x,
    int camera_x_q8, int camera_y_q8, int scale_x, int scale_y,
    int height_scale, uint8_t *indexed, uint8_t *coverage,
    gw_terrain_metrics *metrics) {
    return gw_terrain_renderer_render_with_offset(renderer, world_records,
        b32_atlas, width, height, viewport_left, viewport_center_x, 0,
        camera_x_q8, camera_y_q8, scale_x, scale_y, height_scale,
        indexed, coverage, metrics);
}
