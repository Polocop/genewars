#ifndef GW_TERRAIN_GPU_FIXTURE_H
#define GW_TERRAIN_GPU_FIXTURE_H

#include <stdint.h>

/* Local differential fixture. Coordinates are relative to E19C0's window.
   Texture bytes are the 32x32 addressed subimage of the live B32 bank. */
#define GW_TERRAIN_GPU_FIXTURE_MAGIC UINT32_C(0x31544747)
#define GW_TERRAIN_GPU_FIXTURE_CAP 8192u

typedef struct gw_terrain_gpu_vertex {
    int32_t x, y, u, v, light, height;
} gw_terrain_gpu_vertex;

typedef struct gw_terrain_gpu_triangle {
    uint32_t mode;
    gw_terrain_gpu_vertex vertex[3];
    uint8_t texels[32u * 32u];
} gw_terrain_gpu_triangle;

typedef struct gw_terrain_gpu_fixture_header {
    uint32_t magic, width, height, count, turn;
    int32_t origin_x, origin_y, height_scale;
} gw_terrain_gpu_fixture_header;

#endif
