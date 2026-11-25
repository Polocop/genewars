#include <stdio.h>
#include "gw_sprite_atlas_gl.h"

static unsigned deletes,uploads,flags;

static void APIENTRY gen(GLsizei n,GLuint *t) { if(n==1) *t=12; }
static void APIENTRY del(GLsizei n,const GLuint *t) { if(n==1 && *t==12) deletes++; }
static void APIENTRY bind(GLenum target,GLuint t) { if(target==GL_TEXTURE_2D && t==12) flags|=1u; }
static void APIENTRY param(GLenum target,GLenum key,GLint val) {
    if(target!=GL_TEXTURE_2D || val!=GL_NEAREST) return;
    if(key==GL_TEXTURE_MIN_FILTER) flags|=2u;
    if(key==GL_TEXTURE_MAG_FILTER) flags|=4u;
}
static void APIENTRY store(GLenum key,GLint val) {
    if(key==GL_UNPACK_ROW_LENGTH && val==0) flags|=8u;
    if(key==GL_UNPACK_ALIGNMENT && val==1) flags|=16u;
}
static void APIENTRY image(GLenum t,GLint level,GLint internal,GLsizei w,GLsizei h,
                          GLint border,GLenum format,GLenum type,const void *p) {
    if(t==GL_TEXTURE_2D && level==0 && internal==GL_RGBA8 && w==1024 && h==1024 &&
       !border && format==GL_RGBA && type==GL_UNSIGNED_BYTE && !p) flags|=32u;
}
static void APIENTRY sub(GLenum t,GLint level,GLint x,GLint y,GLsizei w,GLsizei h,
                        GLenum format,GLenum type,const void *p) {
    const uint8_t *rgba=p;
    if(t!=GL_TEXTURE_2D || level || x<0 || y<0 || w!=1 || h!=1 ||
       format!=GL_RGBA || type!=GL_UNSIGNED_BYTE || !rgba || rgba[0]!=123) return;
    if((uploads==0 && rgba[3]==255) || (uploads==1 && rgba[3]==140)) uploads++;
}

int main(void) {
    static const gw_sprite_atlas_gl_api api={gen,del,bind,param,store,image,sub};
    gw_sprite_atlas_gl atlas={.api=&api};
    gw_sprite_atlas_rect rect;
    const uint8_t stream[]={1,3,0};
    uint8_t remap[256]={0},palette[768]={0},pixels[4];
    remap[3]=8;
    palette[8*3]=123;
    gw_sprite_atlas_gl_begin(&atlas,1,8);
    if(!gw_sprite_atlas_gl_add_90f90(&atlas,9,11,stream,sizeof stream,1,1,0,0,
                                    palette,remap,pixels,sizeof pixels,&rect)) return 1;
    if(!gw_sprite_atlas_gl_add_90f90(&atlas,9,11,stream,sizeof stream,1,1,0,0,
                                    palette,remap,pixels,sizeof pixels,&rect)) return 2;
    if(uploads!=1 || flags!=63 || atlas.upload_remaining!=4) return 3;
    if(!gw_sprite_atlas_gl_add_90f90(&atlas,9,11,stream,sizeof stream,1,1,4,0,
                                    palette,remap,pixels,sizeof pixels,&rect)) return 4;
    if(uploads!=2 || atlas.slots.count!=2 || atlas.upload_remaining) return 5;
    gw_sprite_atlas_gl_begin(&atlas,2,4);
    if(deletes!=1 || atlas.texture || atlas.slots.count || atlas.upload_remaining!=4) return 6;
    gw_sprite_atlas_gl_release(&atlas);
    if(deletes!=1) return 7;
    puts("PASS RGBA8, nearest, unpack layout, opaque/translucent separation and mission cleanup");
    return 0;
}
