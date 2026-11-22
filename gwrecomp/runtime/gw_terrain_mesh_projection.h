#ifndef GW_TERRAIN_MESH_PROJECTION_H
#define GW_TERRAIN_MESH_PROJECTION_H

#include <stdint.h>

/* E19C0's destination is a byte pointer for its local (0,0), not the start
   of the ring. A strip can start a row before the ring; Euclidean division
   keeps the x offset nonnegative in that case. */
typedef struct gw_terrain_mesh_window {
    int32_t x, y;
    uint32_t pitch, width, height;
} gw_terrain_mesh_window;

static inline int gw_terrain_mesh_window_init(gw_terrain_mesh_window *out,
    uint32_t ring, uint32_t destination, uint32_t pitch, uint32_t width, uint32_t height) {
    if (!pitch || pitch > 1152u || !width || width > pitch || !height || height > 640u)
        return 0;
    int64_t offset = (int64_t)destination - ring;
    int64_t x = offset % pitch;
    int64_t y = offset / pitch;
    if (x < 0) {
        x += pitch;
        --y;
    }
    if (y < -(int64_t)height || y >= 640)
        return 0;
    out->x = (int32_t)x;
    out->y = (int32_t)y;
    out->pitch = pitch;
    out->width = width;
    out->height = height;
    return 1;
}

static inline unsigned gw_terrain_mesh_cell_index(int32_t world_x_q8, int32_t world_y_q8) {
    const unsigned x = ((uint32_t)world_x_q8 >> 8) & 127u;
    const unsigned y = ((uint32_t)world_y_q8 >> 8) & 127u;
    return y * 128u + x;
}

static inline int32_t gw_terrain_mesh_height_step(int16_t raw_height) {
    /* SAR 6; negative heights round down, including substeps below zero. */
    return raw_height >= 0 ? raw_height / 64 : ((int32_t)raw_height - 63) / 64;
}

static inline uint32_t gw_terrain_mesh_ring_coord(int32_t pixel, uint32_t period) {
    const int32_t residue = pixel % (int32_t)period;
    return (uint32_t)(residue < 0 ? residue + (int32_t)period : residue);
}

#endif
