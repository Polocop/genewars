/* Offline differential of a complete native IFCMain redraw. The source
   fixture is local test data and comes from the original E19C0 submissions. */
#define SDL_MAIN_HANDLED
#include <SDL.h>
#include <SDL_opengl.h>
#include "../../runtime/gw_terrain_gpu_fixture.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { TILE_SIDE=32, ATLAS_COLS=128, ATLAS_ROWS=64 };
typedef struct vertex {
    float x, flat_y, z, u, v, light, tile, mode;
} vertex;

#define GL_FUNCTIONS(X) \
    X(PFNGLGENBUFFERSPROC,GenBuffers) \
    X(PFNGLDELETEBUFFERSPROC,DeleteBuffers) \
    X(PFNGLBINDBUFFERPROC,BindBuffer) \
    X(PFNGLBUFFERDATAPROC,BufferData) \
    X(PFNGLBUFFERSUBDATAPROC,BufferSubData) \
    X(PFNGLCREATESHADERPROC,CreateShader) \
    X(PFNGLSHADERSOURCEPROC,ShaderSource) \
    X(PFNGLCOMPILESHADERPROC,CompileShader) \
    X(PFNGLGETSHADERIVPROC,GetShaderiv) \
    X(PFNGLGETSHADERINFOLOGPROC,GetShaderInfoLog) \
    X(PFNGLDELETESHADERPROC,DeleteShader) \
    X(PFNGLCREATEPROGRAMPROC,CreateProgram) \
    X(PFNGLATTACHSHADERPROC,AttachShader) \
    X(PFNGLBINDATTRIBLOCATIONPROC,BindAttribLocation) \
    X(PFNGLLINKPROGRAMPROC,LinkProgram) \
    X(PFNGLGETPROGRAMIVPROC,GetProgramiv) \
    X(PFNGLDELETEPROGRAMPROC,DeleteProgram) \
    X(PFNGLUSEPROGRAMPROC,UseProgram) \
    X(PFNGLGETUNIFORMLOCATIONPROC,GetUniformLocation) \
    X(PFNGLUNIFORM1IPROC,Uniform1i) \
    X(PFNGLUNIFORM1FPROC,Uniform1f) \
    X(PFNGLUNIFORM2FPROC,Uniform2f) \
    X(PFNGLENABLEVERTEXATTRIBARRAYPROC,EnableVertexAttribArray) \
    X(PFNGLVERTEXATTRIBPOINTERPROC,VertexAttribPointer) \
    X(PFNGLGENFRAMEBUFFERSPROC,GenFramebuffers) \
    X(PFNGLBINDFRAMEBUFFERPROC,BindFramebuffer) \
    X(PFNGLFRAMEBUFFERTEXTURE2DPROC,FramebufferTexture2D) \
    X(PFNGLCHECKFRAMEBUFFERSTATUSPROC,CheckFramebufferStatus) \
    X(PFNGLDELETEFRAMEBUFFERSPROC,DeleteFramebuffers) \
    X(PFNGLACTIVETEXTUREPROC,ActiveTexture)
#define DECLARE(type,name) static type gw##name;
GL_FUNCTIONS(DECLARE)
#undef DECLARE

static int load_gl(void) {
#define LOAD(type,name) gw##name=(type)SDL_GL_GetProcAddress("gl" #name); if(!gw##name) return 0;
    GL_FUNCTIONS(LOAD)
#undef LOAD
    return 1;
}

static GLuint compile_shader(GLenum kind, const char *source) {
    GLuint shader=gwCreateShader(kind);
    gwShaderSource(shader,1,&source,NULL);
    gwCompileShader(shader);
    GLint ok=0;
    gwGetShaderiv(shader,GL_COMPILE_STATUS,&ok);
    if(!ok) {
        char message[2048];
        gwGetShaderInfoLog(shader,sizeof message,NULL,message);
        fprintf(stderr,"%s\n",message);
        gwDeleteShader(shader);
        return 0;
    }
    return shader;
}

static GLuint program(void) {
    const char *vs=
        "#version 120\n"
        "attribute vec3 world; attribute vec3 material; attribute vec2 tile_mode;\n"
        "uniform vec2 size, origin; uniform float height_scale;\n"
        "varying vec3 uv_light; varying vec2 bank;\n"
        "void main(){\n"
        "  vec2 p=vec2(world.x,world.y-world.z*height_scale)+origin;\n"
        "  gl_Position=vec4(p*2.0/size-1.0,clamp(-world.z/1024.0,-1.0,1.0),1.0);\n"
        "  uv_light=material; bank=tile_mode;\n"
        "}\n";
    const char *fs=
        "#version 120\n"
        "uniform sampler2D tiles, fade;\n"
        "varying vec3 uv_light; varying vec2 bank;\n"
        "void main(){\n"
        "  float tile=floor(bank.x+0.5);\n"
        "  vec2 base=vec2(mod(tile,128.0),floor(tile/128.0))*32.0;\n"
        "  vec2 texel=base+clamp(floor(uv_light.xy),0.0,31.0);\n"
        "  float index=floor(texture2D(tiles,(texel+0.5)/vec2(4096.0,2048.0)).r*255.0+0.5);\n"
        /* E44A3 tests the original texel. Mode 5 writes shaded index zero
           like any other index. Mode 6 skips a zero before consulting FADE. */
        "  if(bank.y>5.5 && index==0.0) discard;\n"
        "  float shade=clamp(floor(uv_light.z),0.0,63.0);\n"
        "  float color=texture2D(fade,(vec2(index,shade)+0.5)/vec2(256.0,64.0)).r;\n"
        "  gl_FragColor=vec4(color,1.0,0.0,1.0);\n"
        "}\n";
    const GLuint v=compile_shader(GL_VERTEX_SHADER,vs);
    const GLuint f=compile_shader(GL_FRAGMENT_SHADER,fs);
    GLuint p=0;
    if(v && f) {
        p=gwCreateProgram();
        gwAttachShader(p,v); gwAttachShader(p,f);
        gwBindAttribLocation(p,0,"world");
        gwBindAttribLocation(p,1,"material");
        gwBindAttribLocation(p,2,"tile_mode");
        gwLinkProgram(p);
        GLint ok=0; gwGetProgramiv(p,GL_LINK_STATUS,&ok);
        if(!ok) { gwDeleteProgram(p); p=0; }
    }
    if(v) gwDeleteShader(v);
    if(f) gwDeleteShader(f);
    return p;
}

static GLuint texture(GLint internal, GLenum format, int width, int height,const void *data) {
    GLuint id=0;
    glGenTextures(1,&id); glBindTexture(GL_TEXTURE_2D,id);
    glTexParameteri(GL_TEXTURE_2D,GL_TEXTURE_MIN_FILTER,GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D,GL_TEXTURE_MAG_FILTER,GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D,GL_TEXTURE_WRAP_S,GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D,GL_TEXTURE_WRAP_T,GL_CLAMP_TO_EDGE);
    glTexImage2D(GL_TEXTURE_2D,0,internal,width,height,0,format,GL_UNSIGNED_BYTE,data);
    return id;
}

static int replay(const gw_terrain_gpu_fixture_header *h,const vertex *vertices,
                  unsigned n,const uint8_t *tiles,const uint8_t *fade,uint8_t *result,
                  const float sample_offset[2]) {
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION,2);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION,1);
    SDL_Window *w=SDL_CreateWindow("Terrain GPU differential",SDL_WINDOWPOS_UNDEFINED,
        SDL_WINDOWPOS_UNDEFINED,64,64,SDL_WINDOW_OPENGL|SDL_WINDOW_HIDDEN);
    if(!w) return 0;
    SDL_GLContext ctx=SDL_GL_CreateContext(w);
    GLuint p=0, fbo=0, buffers[2]={0}, textures[3]={0};
    int ok=0;
    if(!ctx || !load_gl()) goto cleanup;
    p=program();
    if(!p) goto cleanup;
    glPixelStorei(GL_UNPACK_ALIGNMENT,1);
    textures[0]=texture(GL_R8,GL_RED,TILE_SIDE*ATLAS_COLS,TILE_SIDE*ATLAS_ROWS,tiles);
    textures[1]=texture(GL_R8,GL_RED,256,64,fade);
    textures[2]=texture(GL_RGBA8,GL_RGBA,h->width,h->height,NULL);
    gwGenFramebuffers(1,&fbo);
    gwBindFramebuffer(GL_FRAMEBUFFER,fbo);
    gwFramebufferTexture2D(GL_FRAMEBUFFER,GL_COLOR_ATTACHMENT0,GL_TEXTURE_2D,textures[2],0);
    if(gwCheckFramebufferStatus(GL_FRAMEBUFFER)!=GL_FRAMEBUFFER_COMPLETE) goto cleanup;
    const unsigned max_vertices=3u*GW_TERRAIN_GPU_FIXTURE_CAP;
    uint16_t *indices=(uint16_t *)malloc(max_vertices*sizeof *indices);
    if(!indices) goto cleanup;
    for(unsigned i=0;i<max_vertices;i++) indices[i]=(uint16_t)i;
    gwGenBuffers(2,buffers);
    gwBindBuffer(GL_ELEMENT_ARRAY_BUFFER,buffers[1]);
    gwBufferData(GL_ELEMENT_ARRAY_BUFFER,max_vertices*sizeof *indices,indices,GL_STATIC_DRAW);
    free(indices);
    gwBindBuffer(GL_ARRAY_BUFFER,buffers[0]);
    gwBufferData(GL_ARRAY_BUFFER,max_vertices*sizeof *vertices,NULL,GL_DYNAMIC_DRAW);
    gwBufferSubData(GL_ARRAY_BUFFER,0,n*sizeof *vertices,vertices);
    gwUseProgram(p);
    gwUniform2f(gwGetUniformLocation(p,"size"),(float)h->width,(float)h->height);
    gwUniform2f(gwGetUniformLocation(p,"origin"),
                (float)h->origin_x+sample_offset[0],(float)h->origin_y+sample_offset[1]);
    gwUniform1f(gwGetUniformLocation(p,"height_scale"),(float)h->height_scale);
    for(int i=0;i<2;i++) {
        gwActiveTexture(GL_TEXTURE0+i);
        glBindTexture(GL_TEXTURE_2D,textures[i]);
        gwUniform1i(gwGetUniformLocation(p,i?"fade":"tiles"),i);
    }
    gwEnableVertexAttribArray(0); gwEnableVertexAttribArray(1); gwEnableVertexAttribArray(2);
    gwVertexAttribPointer(0,3,GL_FLOAT,GL_FALSE,sizeof(vertex),0);
    gwVertexAttribPointer(1,3,GL_FLOAT,GL_FALSE,sizeof(vertex),(const void *)(3u*sizeof(float)));
    gwVertexAttribPointer(2,2,GL_FLOAT,GL_FALSE,sizeof(vertex),(const void *)(6u*sizeof(float)));
    glViewport(0,0,h->width,h->height);
    glDisable(GL_DEPTH_TEST); glDisable(GL_BLEND); glDisable(GL_CULL_FACE); glDisable(GL_DITHER);
    glClearColor(0.0f,0.0f,0.0f,1.0f);
    glClear(GL_COLOR_BUFFER_BIT);
    glDrawElements(GL_TRIANGLES,(GLsizei)n,GL_UNSIGNED_SHORT,0);
    glReadPixels(0,0,h->width,h->height,GL_RGBA,GL_UNSIGNED_BYTE,result);
    ok=glGetError()==GL_NO_ERROR;
cleanup:
    if(p) gwDeleteProgram(p);
    if(fbo) gwDeleteFramebuffers(1,&fbo);
    if(buffers[0]) gwDeleteBuffers(2,buffers);
    if(ctx) {
        glDeleteTextures(3,textures);
        SDL_GL_DeleteContext(ctx);
    }
    SDL_DestroyWindow(w);
    return ok;
}

int main(int argc,char **argv) {
    if(argc!=3 && argc!=5) {
        fprintf(stderr,"usage: terrain_gpu_replay fixture.bin result.ppm [sample_dx sample_dy]\n");
        return 2;
    }
    float sample_offset[2]={0.0f,0.0f};
    if(argc==5) {
        for(unsigned i=0;i<2u;i++) {
            char *end;
            sample_offset[i]=strtof(argv[3+i],&end);
            if(end==argv[3+i] || *end || !isfinite(sample_offset[i])) return 2;
        }
    }
    FILE *f=fopen(argv[1],"rb");
    gw_terrain_gpu_fixture_header h;
    if(!f || fread(&h,sizeof h,1,f)!=1 || h.magic!=GW_TERRAIN_GPU_FIXTURE_MAGIC ||
       h.width!=1152u || h.height!=640u || !h.count || h.count>GW_TERRAIN_GPU_FIXTURE_CAP) return 3;
    const size_t pixels=(size_t)h.width*h.height;
    uint8_t palette[768], fade[64u*256u];
    uint8_t *reference=malloc(pixels), *result=malloc(pixels*4u);
    uint8_t *atlas=calloc(ATLAS_COLS*ATLAS_ROWS,TILE_SIDE*TILE_SIDE);
    gw_terrain_gpu_triangle *triangles=malloc(h.count*sizeof *triangles);
    vertex *vertices=malloc(h.count*3u*sizeof *vertices);
    if(!reference || !result || !atlas || !triangles || !vertices ||
       fread(palette,1,sizeof palette,f)!=sizeof palette ||
       fread(fade,1,sizeof fade,f)!=sizeof fade ||
       fread(reference,1,pixels,f)!=pixels ||
       fread(triangles,sizeof *triangles,h.count,f)!=h.count || fgetc(f)!=EOF) return 3;
    fclose(f);
    /* Keep the pass order. Sharing an atlas slot never reorders triangles. */
    for(unsigned i=0;i<h.count;i++) {
        const gw_terrain_gpu_triangle *t=&triangles[i];
        if(t->mode!=5u && t->mode!=6u) {
            fprintf(stderr,"unsupported mode %u at triangle %u\n",t->mode,i); return 4;
        }
        const unsigned base=(i%ATLAS_COLS)*TILE_SIDE+(i/ATLAS_COLS)*ATLAS_COLS*TILE_SIDE*TILE_SIDE;
        for(unsigned row=0;row<TILE_SIDE;row++)
            memcpy(atlas+base+row*ATLAS_COLS*TILE_SIDE,t->texels+row*TILE_SIDE,TILE_SIDE);
        for(unsigned j=0;j<3u;j++) {
            const gw_terrain_gpu_vertex *v=&t->vertex[j];
            if(v->height==INT32_MIN) { fprintf(stderr,"missing source height\n"); return 4; }
            vertices[3u*i+j]=(vertex){(float)v->x,(float)v->y+(float)v->height*h.height_scale,
                (float)v->height,v->u/65536.0f,v->v/65536.0f,v->light/65536.0f,(float)i,(float)t->mode};
        }
    }
    SDL_SetMainReady();
    if(SDL_Init(SDL_INIT_VIDEO)!=0 || !replay(&h,vertices,3u*h.count,atlas,fade,result,sample_offset)) {
        fprintf(stderr,"OpenGL replay failed: %s\n",SDL_GetError()); return 5;
    }
    SDL_Quit();
    unsigned covered=0, same=0, missing=0, added=0, nonzero=0;
    f=fopen(argv[2],"wb");
    if(!f) return 6;
    fprintf(f,"P6\n%u %u\n255\n",h.width,h.height);
    for(size_t i=0;i<pixels;i++) {
        const uint8_t index=result[i*4u];
        covered+=result[i*4u+1u]!=0;
        same+=index==reference[i];
        missing+=index==0 && reference[i]!=0;
        added+=index!=0 && reference[i]==0;
        nonzero+=reference[i]!=0;
        uint8_t rgb[3];
        for(unsigned k=0;k<3u;k++) rgb[k]=(uint8_t)(palette[3u*index+k]*255u/63u);
        if(fwrite(rgb,1,sizeof rgb,f)!=sizeof rgb) return 6;
    }
    if(fclose(f)!=0) return 6;
    printf("turn=%u triangles=%u pixels=%zu covered=%u equal=%u reference_nonzero=%u missing=%u added=%u\n",
           h.turn,h.count,pixels,covered,same,nonzero,missing,added);
    free(vertices); free(triangles); free(atlas); free(result); free(reference);
    return 0;
}
