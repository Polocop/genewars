#ifndef GW_SPRITE_ATLAS_GL_H
#define GW_SPRITE_ATLAS_GL_H

#include <SDL_opengl.h>
#include "gw_sprite_atlas.h"
#include "gw_sprite_90f90.h"

typedef struct gw_sprite_atlas_gl_api {
    void (APIENTRY *gen)(GLsizei,GLuint *);
    void (APIENTRY *del)(GLsizei,const GLuint *);
    void (APIENTRY *bind)(GLenum,GLuint);
    void (APIENTRY *parameter)(GLenum,GLenum,GLint);
    void (APIENTRY *pixel_store)(GLenum,GLint);
    void (APIENTRY *image)(GLenum,GLint,GLint,GLsizei,GLsizei,GLint,GLenum,GLenum,const void *);
    void (APIENTRY *sub_image)(GLenum,GLint,GLint,GLint,GLsizei,GLsizei,GLenum,GLenum,const void *);
} gw_sprite_atlas_gl_api;

typedef struct gw_sprite_atlas_gl {
    const gw_sprite_atlas_gl_api *api;
    gw_sprite_atlas slots;
    GLuint texture;
    size_t upload_remaining;
    uint64_t mission_generation;
} gw_sprite_atlas_gl;

/* Call on the GL thread with its own texture unit and unpack state. */
static inline void gw_sprite_atlas_gl_release(gw_sprite_atlas_gl *atlas) {
    if(atlas->texture) atlas->api->del(1,&atlas->texture);
    atlas->texture=0;
    atlas->upload_remaining=0;
    gw_sprite_atlas_reset(&atlas->slots);
}

static inline void gw_sprite_atlas_gl_begin(gw_sprite_atlas_gl *atlas,
                                           uint64_t mission_generation,size_t budget) {
    if(atlas->mission_generation!=mission_generation) {
        gw_sprite_atlas_gl_release(atlas);
        atlas->mission_generation=mission_generation;
    }
    atlas->upload_remaining=budget;
}

static inline int gw_sprite_atlas_gl_upload(void *user,gw_sprite_atlas_rect rect,
                                            const uint8_t *rgba) {
    gw_sprite_atlas_gl *a=user;
    const gw_sprite_atlas_gl_api *gl=a->api;
    if(!gl) return 0;
    gl->pixel_store(GL_UNPACK_ROW_LENGTH,0);
    gl->pixel_store(GL_UNPACK_ALIGNMENT,1);
    if(!a->texture) {
        gl->gen(1,&a->texture);
        if(!a->texture) return 0;
        gl->bind(GL_TEXTURE_2D,a->texture);
        gl->parameter(GL_TEXTURE_2D,GL_TEXTURE_MIN_FILTER,GL_NEAREST);
        gl->parameter(GL_TEXTURE_2D,GL_TEXTURE_MAG_FILTER,GL_NEAREST);
        gl->parameter(GL_TEXTURE_2D,GL_TEXTURE_WRAP_S,GL_CLAMP_TO_EDGE);
        gl->parameter(GL_TEXTURE_2D,GL_TEXTURE_WRAP_T,GL_CLAMP_TO_EDGE);
        gl->image(GL_TEXTURE_2D,0,GL_RGBA8,GW_SPRITE_ATLAS_SIZE,GW_SPRITE_ATLAS_SIZE,
                  0,GL_RGBA,GL_UNSIGNED_BYTE,NULL);
    } else {
        gl->bind(GL_TEXTURE_2D,a->texture);
    }
    gl->sub_image(GL_TEXTURE_2D,0,rect.x,rect.y,rect.w,rect.h,GL_RGBA,GL_UNSIGNED_BYTE,rgba);
    return 1;
}

static inline int gw_sprite_atlas_gl_get(gw_sprite_atlas_gl *atlas,gw_sprite_atlas_key key,
                                         const uint8_t *pixels,size_t bytes,gw_sprite_atlas_rect *rect) {
    return gw_sprite_atlas_get(&atlas->slots,key,pixels,bytes,&atlas->upload_remaining,
                               gw_sprite_atlas_gl_upload,atlas,rect);
}
/* Decode on the producer side before passing pixels to the GL thread in
   production. This synchronous entry point is for callers with a bounded
   source and scratch buffer already available on the render thread. */
static inline int gw_sprite_atlas_gl_add_90f90(gw_sprite_atlas_gl *atlas,
        uint32_t sprite,uint32_t remap_id,const uint8_t *source,size_t source_size,
        unsigned w,unsigned h,unsigned flags,unsigned selector,const uint8_t palette[768],
        const uint8_t remap[256],uint8_t *scratch,size_t capacity,gw_sprite_atlas_rect *out) {
    if(!gw_decode_sprite_90f90(source,source_size,w,h,palette,remap,flags,selector,scratch,capacity))
        return 0;
    const size_t size=(size_t)w*h*4u;
    const gw_sprite_atlas_key key={.sprite=sprite,.remap=remap_id,.width=(uint16_t)w,
        .height=(uint16_t)h,.flip=(uint8_t)(flags&3u),.blend=(uint8_t)gw_sprite_90f90_kind(flags),
        .image=gw_sprite_atlas_image(scratch,size)};
    return gw_sprite_atlas_gl_get(atlas,key,scratch,size,out);
}
#endif
