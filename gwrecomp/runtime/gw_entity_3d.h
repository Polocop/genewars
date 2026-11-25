#ifndef GW_ENTITY_3D_H
#define GW_ENTITY_3D_H

#include <stddef.h>
#include <stdint.h>

#include "gw_terrain_mesh_projection.h"

enum {
    GW_ENTITY_CREATURE=1, GW_ENTITY_PLANT, GW_ENTITY_SPECIALIST,
    GW_ENTITY_BUILDING, GW_ENTITY_EFFECT,
    GW_ENTITY_3D_CAPACITY=300+512+20+256+200,
    GW_ENTITY_MAP_HEIGHT=0x002F4F86
};

/* Resident objects are candidates. A live render association must still
   establish visibility, animation, remap and vertical position. */
typedef struct gw_entity_3d_t {
    uint32_t guest_address;
    int16_t world_x_q8, world_y_q8;
    int32_t ground_q6, world_z_q6; /* unscaled map ground, scaled draw elevation */
    uint8_t type, owner, z_valid;
} gw_entity_3d_t;

typedef struct gw_entity_3d_snapshot {
    size_t count;
    gw_entity_3d_t entities[GW_ENTITY_3D_CAPACITY];
} gw_entity_3d_snapshot;

static inline int32_t gw_entity_read_s16(const uint8_t *p) {
    uint32_t value=(uint32_t)p[0]+((uint32_t)p[1]<<8);
    return value>=0x8000u?(int32_t)value-0x10000:(int32_t)value;
}

static inline uint32_t gw_entity_read_u32(const uint8_t *p) {
    return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
}

static inline int32_t gw_entity_read_s32(const uint8_t *p) {
    const uint32_t value=gw_entity_read_u32(p);
    return value<0x80000000u?(int32_t)value:(int32_t)((int64_t)value-0x100000000ll);
}

static inline int32_t gw_entity_ground_q6(const uint8_t *map,int32_t x,int32_t y,unsigned scale) {
    const unsigned cell=gw_terrain_mesh_cell_index(x,y);
    const unsigned east=(cell&~127u)|((cell+1u)&127u);
    const unsigned south=(cell+128u)&16383u;
    const unsigned southeast=(east+128u)&16383u;
    const int32_t fx=(int32_t)((unsigned)x&255u),fy=(int32_t)((unsigned)y&255u);
    const int32_t h00=gw_entity_read_s16(map+14u*cell+2u);
    const int32_t h11=gw_entity_read_s16(map+14u*southeast+2u);
    int32_t delta;
    /* MapDisplay projection 0x65630 splits the cell along (0,0)-(1,1).
       Evaluate in unscaled q6, using SAR rounding for negative slopes. */
    if(fx>=fy) {
        const int32_t h10=gw_entity_read_s16(map+14u*east+2u);
        delta=fx*(h10-h00)+fy*(h11-h10);
    } else {
        const int32_t h01=gw_entity_read_s16(map+14u*south+2u);
        delta=fy*(h01-h00)+fx*(h11-h01);
    }
    const int32_t divisor=scale==2?128:256;
    return h00*(int32_t)scale+(delta>=0?delta/divisor:(delta-(divisor-1))/divisor);
}

static inline int gw_entity_3d_read(const uint8_t *memory,size_t size,
                                  gw_entity_3d_snapshot *out) {
    static const struct {
        uint32_t base;
        uint16_t slots, stride;
        uint8_t type;
    } pools[]={
        {0x0032CF86u,300,0x7C,GW_ENTITY_CREATURE},
        {0x003360D6u,512,0x31,GW_ENTITY_PLANT},
        {0x0033C2D6u, 20,0xC8,GW_ENTITY_SPECIALIST},
        {0x0033D276u,256,0x43,GW_ENTITY_BUILDING},
        {0x00341576u,200,0x51,GW_ENTITY_EFFECT}
    };
    out->count=0;
    if(!memory || size<GW_ENTITY_MAP_HEIGHT+128u*128u*14u) return 0;
    for(size_t bank=0;bank<sizeof pools/sizeof pools[0];bank++) {
        if(size<=0x0035EAB7u || size<pools[bank].base+(size_t)pools[bank].slots*pools[bank].stride)
            return 0;
    }
    const unsigned scale=gw_entity_read_u32(memory+0x0035EAB4u);
    for(size_t bank=0;bank<sizeof pools/sizeof pools[0];bank++) {
        for(unsigned slot=0;slot<pools[bank].slots;slot++) {
            const uint32_t address=pools[bank].base+slot*(uint32_t)pools[bank].stride;
            const uint8_t *object=memory+address;
            if(object[6]!=pools[bank].type) continue;
            const int16_t x=(int16_t)gw_entity_read_s16(object+7);
            const int16_t y=(int16_t)gw_entity_read_s16(object+9);
            const int32_t ground=gw_entity_ground_q6(memory+GW_ENTITY_MAP_HEIGHT,x,y,1);
            gw_entity_3d_t entity={
                .guest_address=address,.world_x_q8=x,.world_y_q8=y,.ground_q6=ground,
                .type=pools[bank].type,.owner=object[0x18]
            };
            const uint32_t vtable=gw_entity_read_u32(object+0x23);
            if((scale==1 || scale==2) && vtable && (size_t)vtable<=size-8u) {
                const uint32_t height_fn=gw_entity_read_u32(memory+vtable+4);
                /* The two height contracts seen in all five pools in the
                   reference snapshots. Unknown targets stay unclassified. */
                const int32_t draw_ground=gw_entity_ground_q6(memory+GW_ENTITY_MAP_HEIGHT,x,y,scale);
                if(height_fn==0x002552E0u && pools[bank].stride>=0x2Bu) {
                    /* 0x6A2E0 returns the stored elevation minus its ground
                       reference. 0x78BA8 applies it to the current terrain projection. */
                    const int64_t offset=(int64_t)gw_entity_read_s32(object+0x27)-
                                         gw_entity_read_s32(object+0x11);
                    const int64_t elevation=(int64_t)draw_ground+offset;
                    if(elevation>=INT32_MIN && elevation<=INT32_MAX) {
                        entity.world_z_q6=(int32_t)elevation;
                        entity.z_valid=1;
                    }
                } else if(height_fn==0x00259E40u) {
                    entity.world_z_q6=draw_ground;
                    entity.z_valid=1;
                }
            }
            out->entities[out->count++]=entity;
        }
    }
    return 1;
}

#endif
