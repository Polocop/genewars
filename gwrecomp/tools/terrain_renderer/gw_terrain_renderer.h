#ifndef GW_TERRAIN_RENDERER_H
#define GW_TERRAIN_RENDERER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct gw_terrain_renderer gw_terrain_renderer;
typedef struct gw_terrain_metrics {
    uint32_t visible_cells;
    uint64_t write_ops;
    uint64_t overdraw;
    uint64_t covered_pixels;
    uint64_t nonzero_texels;
    double geometry_ms;
    double raster_ms;
} gw_terrain_metrics;

gw_terrain_renderer *gw_terrain_renderer_create(void);
void gw_terrain_renderer_destroy(gw_terrain_renderer *renderer);
int gw_terrain_renderer_render(gw_terrain_renderer *renderer,
    const uint8_t *world_records, const uint8_t *b32_atlas,
    int width, int height, int viewport_left, int viewport_center_x,
    int camera_x_q8, int camera_y_q8, int scale_x, int scale_y,
    int height_scale, uint8_t *indexed, uint8_t *coverage,
    gw_terrain_metrics *metrics);
int gw_terrain_renderer_render_with_offset(gw_terrain_renderer *renderer,
    const uint8_t *world_records, const uint8_t *b32_atlas,
    int width, int height, int viewport_left, int viewport_center_x,
    int viewport_center_y_offset,
    int camera_x_q8, int camera_y_q8, int scale_x, int scale_y,
    int height_scale, uint8_t *indexed, uint8_t *coverage,
    gw_terrain_metrics *metrics);

#ifdef __cplusplus
}
#endif
#endif
