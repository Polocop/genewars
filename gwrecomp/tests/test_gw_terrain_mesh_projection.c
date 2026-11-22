#include "../runtime/gw_terrain_mesh_projection.h"

#include <assert.h>
#include <stdio.h>

int main(void) {
    const uint32_t ring = 0x0276edd4u;
    gw_terrain_mesh_window clip;
    assert(gw_terrain_mesh_window_init(&clip, ring, ring - 1152u + 128u, 1152u, 32u, 640u));
    assert(clip.x == 128 && clip.y == -1);
    assert(gw_terrain_mesh_window_init(&clip, ring, ring - 1u, 1152u, 32u, 640u));
    assert(clip.x == 1151 && clip.y == -1);
    assert(gw_terrain_mesh_window_init(&clip, ring, ring + 864u + 128u, 864u, 32u, 480u));
    assert(clip.x == 128 && clip.y == 1);
    assert(!gw_terrain_mesh_window_init(&clip, ring, ring, 1152u, 1153u, 640u));
    assert(!gw_terrain_mesh_window_init(&clip, ring, ring, 0u, 32u, 640u));
    assert(gw_terrain_mesh_cell_index(0, 0) == 0u);
    assert(gw_terrain_mesh_cell_index(-1, -1) == 128u * 128u - 1u);
    assert(gw_terrain_mesh_cell_index(32768, -32768) == 0u);
    assert(gw_terrain_mesh_cell_index(32768 + 256, -32768 + 512) == 257u);
    assert(gw_terrain_mesh_height_step(-65) == -2);
    assert(gw_terrain_mesh_height_step(-64) == -1);
    assert(gw_terrain_mesh_height_step(-1) == -1);
    assert(gw_terrain_mesh_height_step(63) == 0);
    assert(gw_terrain_mesh_height_step(64) == 1);
    assert(gw_terrain_mesh_ring_coord(-1, 1024u) == 1023u);
    assert(gw_terrain_mesh_ring_coord(-1, 640u) == 639u);
    assert(gw_terrain_mesh_ring_coord(1024, 1024u) == 0u);
    puts("PASS E19C0 ring origin, map seam and signed MapHeight");
    return 0;
}
