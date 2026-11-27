#ifndef GW_TERRAIN_MESH_GL_H
#define GW_TERRAIN_MESH_GL_H

/* Included by the OpenGL compositor. This pass borrows its GL context and
   attribute locations. It outputs an indexed screen-space layer to pack. */
static struct {
    GLuint fbo,depth,color,tiles,fade,program,vbo,ibo;
    GLint u_tiles,u_fade,u_geometric;
    void (APIENTRYP ColorMask)(GLboolean,GLboolean,GLboolean,GLboolean);
    int failed,fade_ready,tiles_ready;
    uint32_t last_tiles_n,last_tile_addr[259];
    uint8_t last_fade[64u*256u];
    void (APIENTRYP DrawElements)(GLenum,GLsizei,GLenum,const void *);
    void (APIENTRYP PushAttrib)(GLbitfield);
    void (APIENTRYP PopAttrib)(void);
    void (APIENTRYP DepthFunc)(GLenum);
    void (APIENTRYP DepthMask)(GLboolean);
    void (APIENTRYP ClearDepth)(GLclampd);
    void (APIENTRYP PolygonOffset)(GLfloat,GLfloat);
    PFNGLGENRENDERBUFFERSPROC GenRenderbuffers;
    PFNGLBINDRENDERBUFFERPROC BindRenderbuffer;
    PFNGLRENDERBUFFERSTORAGEPROC RenderbufferStorage;
    PFNGLFRAMEBUFFERRENDERBUFFERPROC FramebufferRenderbuffer;
} g_gl_mesh;

static int terrain_gl_init(void) {
    if(g_gl_mesh.failed) return 0;
    if(g_gl_mesh.program) return 1;
    static const char *vs=
        "#version 120\n"
        "attribute vec3 a_pos; attribute vec3 a_uv; attribute vec2 a_suv;\n"
        "varying vec3 v_material; varying vec2 v_tile_mode;\n"
        "attribute vec3 a_world; uniform float u_geometric;\n"
        "void main(){\n"
        /* E8963 stores destination minus pitch. The scanline loop adds that
           pitch back before the first write. GL samples at half pixels. */
        "  gl_Position=vec4((a_pos.xy+0.5)*2.0/vec2(1152.0,640.0)-1.0,a_pos.z,1.0);\n"
        "  if(u_geometric>0.5) gl_Position.z=-dot(a_world,vec3(0.004,0.004,0.00025));\n"
        "  v_material=a_uv; v_tile_mode=a_suv;\n"
        "}\n";
    static const char *fs=
        "#version 120\n"
        "uniform sampler2D u_tiles; uniform sampler2D u_fade;\n"
        "varying vec3 v_material; varying vec2 v_tile_mode;\n"
        "void main(){\n"
        "  float tile=floor(v_tile_mode.x+0.5);\n"
        "  vec2 base=vec2(mod(tile,16.0),floor(tile/16.0))*32.0;\n"
        "  vec2 p=base+clamp(floor(v_material.xy),0.0,31.0);\n"
        "  float src=texture2D(u_tiles,(p+0.5)/vec2(512.0,544.0)).r;\n"
        "  float idx=floor(src*255.0+0.5);\n"
        "  if(v_tile_mode.y>5.5 && idx==0.0) discard;\n"
        "  float shade=clamp(floor(v_material.z),0.0,63.0);\n"
        "  if(v_tile_mode.y>0.5) src=texture2D(u_fade,(vec2(idx,shade)+0.5)/vec2(256.0,64.0)).r;\n"
        "  gl_FragColor=vec4(src,1.0,0.0,1.0);\n"
        "}\n";
    #define GW_MESH_GL(n) do { *(void **)&g_gl_mesh.n=SDL_GL_GetProcAddress("gl" #n); if(!g_gl_mesh.n) goto fail; } while(0)
    GW_MESH_GL(DrawElements); GW_MESH_GL(PushAttrib); GW_MESH_GL(PopAttrib);
    GW_MESH_GL(DepthFunc); GW_MESH_GL(DepthMask); GW_MESH_GL(ClearDepth); GW_MESH_GL(ColorMask); GW_MESH_GL(PolygonOffset);
    GW_MESH_GL(GenRenderbuffers); GW_MESH_GL(BindRenderbuffer);
    GW_MESH_GL(RenderbufferStorage); GW_MESH_GL(FramebufferRenderbuffer);
    #undef GW_MESH_GL
    g_gl_mesh.program=bloom_link_program(vs,fs);
    if(!g_gl_mesh.program) goto fail;
    g_gl_mesh.u_tiles=g_bloom.GetUniformLocation(g_gl_mesh.program,"u_tiles");
    g_gl_mesh.u_fade=g_bloom.GetUniformLocation(g_gl_mesh.program,"u_fade");
    g_gl_mesh.u_geometric=g_bloom.GetUniformLocation(g_gl_mesh.program,"u_geometric");
    g_gl_mesh.tiles=gm_tex(512,544,GL_R8,GL_RED);
    g_gl_mesh.fade=gm_tex(256,64,GL_R8,GL_RED);
    g_gl_mesh.color=gm_tex(1152,640,GL_RG8,GL_RG);
    g_bloom.GenFramebuffers(1,&g_gl_mesh.fbo);
    g_bloom.BindFramebuffer(GL_FRAMEBUFFER,g_gl_mesh.fbo);
    g_bloom.FramebufferTexture2D(GL_FRAMEBUFFER,GL_COLOR_ATTACHMENT0,GL_TEXTURE_2D,g_gl_mesh.color,0);
    g_gl_mesh.GenRenderbuffers(1,&g_gl_mesh.depth);
    g_gl_mesh.BindRenderbuffer(GL_RENDERBUFFER,g_gl_mesh.depth);
    g_gl_mesh.RenderbufferStorage(GL_RENDERBUFFER,GL_DEPTH_COMPONENT16,1152,640);
    g_gl_mesh.BindRenderbuffer(GL_RENDERBUFFER,0);
    g_gl_mesh.FramebufferRenderbuffer(GL_FRAMEBUFFER,GL_DEPTH_ATTACHMENT,GL_RENDERBUFFER,g_gl_mesh.depth);
    if(g_bloom.CheckFramebufferStatus(GL_FRAMEBUFFER)!=GL_FRAMEBUFFER_COMPLETE) goto fail;
    const unsigned capacity=3u*GW_TERRAIN_GPU_FIXTURE_CAP;
    uint16_t *index=malloc(capacity*sizeof *index);
    if(!index) goto fail;
    for(unsigned i=0;i<capacity;i++) index[i]=(uint16_t)i;
    g_bloom.GenBuffers(1,&g_gl_mesh.vbo);
    g_bloom.GenBuffers(1,&g_gl_mesh.ibo);
    g_bloom.BindBuffer(GL_ELEMENT_ARRAY_BUFFER,g_gl_mesh.ibo);
    g_bloom.BufferData(GL_ELEMENT_ARRAY_BUFFER,capacity*sizeof *index,index,GL_STATIC_DRAW);
    g_bloom.BindBuffer(GL_ELEMENT_ARRAY_BUFFER,0);
    free(index);
    gw_flag_trace("TRACE terrain_3d GPU initialized%c",10);
    return 1;
fail:
    g_gl_mesh.failed=1;
    gw_flag_trace("TRACE terrain_3d unavailable, using software terrain%c",10);
    return 0;
}

static int terrain_gl_render(const gw_terrain_mesh_draw *draw,int geometric_depth) {
    if(!draw || !draw->count || !terrain_gl_init()) return 0;
    enum { atlas_w=GW_MESH_ATLAS_W, atlas_cols=GW_MESH_ATLAS_COLS };
    static uint8_t atlas[atlas_w*544];
    const unsigned tn=draw->tiles<259u?draw->tiles:259u;
    int tiles_changed=!g_gl_mesh.tiles_ready || g_gl_mesh.last_tiles_n!=tn ||
                      memcmp(g_gl_mesh.last_tile_addr,draw->tile_addr,tn*sizeof(uint32_t))!=0;
    if(tiles_changed) {
        for(unsigned i=0;i<draw->tiles;i++) {
            uint8_t *slot=atlas+32u*(i%atlas_cols)+32u*atlas_w*(i/atlas_cols);
            for(unsigned row=0;row<32u;row++)
                memcpy(slot+row*atlas_w,draw->texels[i]+row*32u,32u);
        }
        g_gl_mesh.last_tiles_n=tn;
        memcpy(g_gl_mesh.last_tile_addr,draw->tile_addr,tn*sizeof(uint32_t));
        g_gl_mesh.tiles_ready=1;
    }
    g_bloom.UseProgram(g_gl_mesh.program);
    g_bloom.Uniform1f(g_gl_mesh.u_geometric,0.0f);
    g_bloom.ActiveTexture(GL_TEXTURE0);
    g_bloom.BindTexture(GL_TEXTURE_2D,g_gl_mesh.tiles);
    g_bloom.Uniform1i(g_gl_mesh.u_tiles,0);
    if(tiles_changed) {
        g_bloom.TexSubImage2D(GL_TEXTURE_2D,0,0,0,atlas_w,
            (GLsizei)(32u*((draw->tiles+atlas_cols-1u)/atlas_cols)),GL_RED,GL_UNSIGNED_BYTE,atlas);
    }
    g_bloom.ActiveTexture(GL_TEXTURE1);
    g_bloom.BindTexture(GL_TEXTURE_2D,g_gl_mesh.fade);
    g_bloom.Uniform1i(g_gl_mesh.u_fade,1);
    if(!g_gl_mesh.fade_ready || memcmp(draw->fade,g_gl_mesh.last_fade,sizeof draw->fade)) {
        g_bloom.TexSubImage2D(GL_TEXTURE_2D,0,0,0,256,64,GL_RED,GL_UNSIGNED_BYTE,draw->fade);
        memcpy(g_gl_mesh.last_fade,draw->fade,sizeof draw->fade);
        g_gl_mesh.fade_ready=1;
    }
    g_bloom.BindFramebuffer(GL_FRAMEBUFFER,g_gl_mesh.fbo);
    g_bloom.Viewport(0,0,1152,640);
    g_gl_mesh.PushAttrib(GL_DEPTH_BUFFER_BIT|GL_ENABLE_BIT|GL_COLOR_BUFFER_BIT);
    g_bloom.Enable(GL_DEPTH_TEST);
    g_bloom.Disable(GL_CULL_FACE);
    g_bloom.Disable(GL_DITHER);
    g_gl_mesh.DepthFunc(GL_LESS);
    g_gl_mesh.DepthMask(GL_TRUE);
    g_gl_mesh.ClearDepth(1.0);
    g_bloom.ClearColor(0.0f,0.0f,0.0f,1.0f);
    g_bloom.Clear(GL_COLOR_BUFFER_BIT|GL_DEPTH_BUFFER_BIT);
    g_bloom.BindBuffer(GL_ARRAY_BUFFER,g_gl_mesh.vbo);
    g_bloom.BufferData(GL_ARRAY_BUFFER,draw->count*sizeof draw->vertex[0],draw->vertex,GL_STREAM_DRAW);
    g_bloom.BindBuffer(GL_ELEMENT_ARRAY_BUFFER,g_gl_mesh.ibo);
    const GLsizei stride=sizeof draw->vertex[0];
    g_bloom.VertexAttribPointer(0,3,GL_FLOAT,GL_FALSE,stride,(const void *)offsetof(gw_terrain_mesh_vertex,x));
    g_bloom.VertexAttribPointer(1,3,GL_FLOAT,GL_FALSE,stride,(const void *)offsetof(gw_terrain_mesh_vertex,u));
    g_bloom.VertexAttribPointer(2,2,GL_FLOAT,GL_FALSE,stride,(const void *)offsetof(gw_terrain_mesh_vertex,tile));
    g_gl_mesh.DrawElements(GL_TRIANGLES,(GLsizei)draw->count,GL_UNSIGNED_SHORT,0);
    if(geometric_depth) {
        /* Keep indexed terrain material precedence from its original draw.
           Build scene depth separately from the same world geometry. */
        g_gl_mesh.ColorMask(GL_FALSE,GL_FALSE,GL_FALSE,GL_FALSE);
        g_bloom.Clear(GL_DEPTH_BUFFER_BIT);
        g_bloom.Uniform1f(g_gl_mesh.u_geometric,1.0f);
        g_bloom.EnableVertexAttribArray(3);
        g_bloom.VertexAttribPointer(3,3,GL_FLOAT,GL_FALSE,stride,(const void *)offsetof(gw_terrain_mesh_vertex,wx));
        g_gl_mesh.DrawElements(GL_TRIANGLES,(GLsizei)draw->count,GL_UNSIGNED_SHORT,0);
        g_bloom.DisableVertexAttribArray(3);
    }
    g_bloom.BindBuffer(GL_ELEMENT_ARRAY_BUFFER,0);
    g_gl_mesh.PopAttrib();
    g_bloom.BindBuffer(GL_ARRAY_BUFFER,g_bloom.vbo);
    g_bloom.VertexAttribPointer(0,2,GL_FLOAT,GL_FALSE,6*sizeof(float),(const void *)0);
    g_bloom.VertexAttribPointer(1,2,GL_FLOAT,GL_FALSE,6*sizeof(float),(const void *)(2*sizeof(float)));
    g_bloom.VertexAttribPointer(2,2,GL_FLOAT,GL_FALSE,6*sizeof(float),(const void *)(4*sizeof(float)));
    g_bloom.ActiveTexture(GL_TEXTURE0);
    return 1;
}

#endif
