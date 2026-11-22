#ifndef GW_TERRAIN_LIT_GL_H
#define GW_TERRAIN_LIT_GL_H

/* Terrain 3D, batch 2: the same visible mesh as gw_terrain_mesh_gl.h (identical screen positions, B32 texels and
   draw order, so sprites, buildings and mouse picking stay aligned to the pixel), rasterised once per game frame at
   up to 4x the canvas resolution with real lighting:
     - smooth per-pixel normals from the planet height grid (128 x 128, bilinear with GL_REPEAT: the planet wrap has
       no lighting seam), plus a subtle micro-relief from the luminance gradient of each tile's texels;
     - a directional sun and a sky/ground hemisphere light calibrated per biome, a touch of specular on rock;
     - a directional shadow map of the terrain around the view (FBO, 3x3 PCF), never darker than a tactical floor;
     - water: depth from the height grid (distance from land through the sea cells), coastal colour, and a code in
       alpha that the per-frame map pass turns into 120 Hz waves, Fresnel, sun glints and shore foam (GOOP: glow).
   Output, per canvas layer: RGBA8, RGB = lit colour, A = 1 land, 0.75 GOOP, 0.1..0.5 water (0.1 + 0.4 depth),
   0 not covered. Presentation only: read from the published snapshot, nothing is written to guest memory. */

#ifndef GL_DEPTH_COMPONENT16
#define GL_DEPTH_COMPONENT16 0x81A5
#endif
#ifndef GL_REPEAT
#define GL_REPEAT 0x2901
#endif

enum { TL_SHADOW=2048, TL_GRID=64 };
static void bloom_draw_quad(float x0,float y0,float x1,float y1,float u0,float v0,float u1,float v1,
                            float su0,float sv0,float su1,float sv1);

static struct {
    int failed,ready,scale,w,h,biome,nrm_ok,hs_last;
    GLuint prog_lit,prog_sh,prog_bump;
    GLuint lit[3],fbo,depth_rb;
    GLuint sh_tex,sh_fbo,sh_rb,nrm_tex,bump_tex,bump_fbo,grid_vbo,grid_ibo;
    int lview[3][2],lhave[3];            /* per canvas layer: display origin (mod 128) and whether it holds a lit frame */
    GLint l_tiles,l_fade,l_lut,l_kind,l_nrm,l_sh,l_bump,l_view,l_lx,l_ly,l_lz,l_zs,l_sun,l_sunc,l_sky,l_gnd,l_shon,l_wton,l_mix;
    GLint s_lx,s_ly,s_lz,s_zs;
    GLint b_tiles,b_lut;
    float lx[4],ly[4],lz[4];
    float sun[3],sunc[3],sky[3],gnd[3];
    int16_t last_h[128u*128u];
    void (APIENTRYP Uniform3f)(GLint,GLfloat,GLfloat,GLfloat);
    void (APIENTRYP Uniform4f)(GLint,GLfloat,GLfloat,GLfloat,GLfloat);
} g_t3;

/* world units: one cell = 1; heights in screen pixels -> cells (2:1 projection, 30 degree camera: the 45.25 px cell
   side times cos 30) */
#define TL_ZS (1.0f/39.19f)

static GLuint tl_link(const char *vs_src,const char *fs_src) {
    GLuint vs=bloom_compile_shader(GL_VERTEX_SHADER,vs_src),fs=bloom_compile_shader(GL_FRAGMENT_SHADER,fs_src);
    if(!vs || !fs) { if(vs) g_bloom.DeleteShader(vs); if(fs) g_bloom.DeleteShader(fs); return 0; }
    GLuint p=g_bloom.CreateProgram();
    g_bloom.AttachShader(p,vs); g_bloom.AttachShader(p,fs);
    typedef void (APIENTRYP PFN_BAL)(GLuint,GLuint,const GLchar *);
    PFN_BAL bal=(PFN_BAL)SDL_GL_GetProcAddress("glBindAttribLocation");
    if(bal) { bal(p,0,"a_pos"); bal(p,1,"a_uv"); bal(p,2,"a_suv"); bal(p,3,"a_world"); }
    g_bloom.LinkProgram(p);
    g_bloom.DeleteShader(vs); g_bloom.DeleteShader(fs);
    GLint ok=0; g_bloom.GetProgramiv(p,GL_LINK_STATUS,&ok);
    if(!ok) {
        char log[512]; GLsizei n=0; g_bloom.GetProgramInfoLog(p,sizeof log,&n,log);
        gw_flag_trace("TRACE terrain_3d link_err: %s%c",log,10);
        g_bloom.DeleteProgram(p); return 0;
    }
    return p;
}

/* sun (towards the light), colours per biome: 0 organic, 1 arid, 2 volcanic, 3 icy */
static void tl_biome(int bi) {
    if(bi<0 || bi>3) bi=0;
    g_t3.biome=bi;
    static const float az[4][2]={{-1.0f,-0.35f},{-1.0f,-0.25f},{-1.0f,-0.45f},{-1.0f,-0.30f}};
    static const float el[4]={0.62f,0.70f,0.55f,0.52f};   /* elevation (rad) */
    static const float sc[4][3]={{1.00f,0.93f,0.80f},{1.00f,0.86f,0.66f},{1.00f,0.70f,0.50f},{0.90f,0.96f,1.06f}};
    static const float sk[4][3]={{0.52f,0.66f,0.95f},{0.66f,0.68f,0.86f},{0.55f,0.44f,0.62f},{0.58f,0.74f,1.02f}};
    static const float gd[4][3]={{0.34f,0.36f,0.26f},{0.44f,0.34f,0.24f},{0.36f,0.22f,0.18f},{0.42f,0.46f,0.54f}};
    const float hx=az[bi][0],hy=az[bi][1],hl=sqrtf(hx*hx+hy*hy),c=cosf(el[bi]),s=sinf(el[bi]);
    g_t3.sun[0]=hx/hl*c; g_t3.sun[1]=hy/hl*c; g_t3.sun[2]=s;
    for(int i=0;i<3;i++) { g_t3.sunc[i]=sc[bi][i]; g_t3.sky[i]=sk[bi][i]; g_t3.gnd[i]=gd[bi][i]; }
}

static GLuint tl_tex(int w,int h,GLenum filter,GLenum wrap) {
    GLuint t=0; g_bloom.GenTextures(1,&t); g_bloom.BindTexture(GL_TEXTURE_2D,t);
    g_bloom.TexParameteri(GL_TEXTURE_2D,GL_TEXTURE_MIN_FILTER,(GLint)filter); g_bloom.TexParameteri(GL_TEXTURE_2D,GL_TEXTURE_MAG_FILTER,(GLint)filter);
    g_bloom.TexParameteri(GL_TEXTURE_2D,GL_TEXTURE_WRAP_S,(GLint)wrap); g_bloom.TexParameteri(GL_TEXTURE_2D,GL_TEXTURE_WRAP_T,(GLint)wrap);
    g_bloom.TexImage2D(GL_TEXTURE_2D,0,GL_RGBA8,w,h,0,GL_RGBA,GL_UNSIGNED_BYTE,NULL);
    return t;
}

#define TL_GLSL_COMMON \
    "#version 120\n" \
    "float rd8(sampler2D t,vec2 p,vec2 sz){ return floor(texture2D(t,(p+0.5)/sz).r*255.0+0.5); }\n" \
    "vec3 lut(sampler2D t,float k){ return texture2D(t,vec2((k+0.5)/256.0,0.25)).rgb; }\n"

static int tl_init(void) {
    if(g_t3.failed) return 0;
    if(g_t3.ready) return 1;
    *(void **)&g_t3.Uniform3f=SDL_GL_GetProcAddress("glUniform3f");
    *(void **)&g_t3.Uniform4f=SDL_GL_GetProcAddress("glUniform4f");
    if(!g_t3.Uniform3f || !g_t3.Uniform4f) goto fail;
    {
    static const char *vs_lit=
        "#version 120\n"
        "attribute vec3 a_pos; attribute vec3 a_uv; attribute vec2 a_suv; attribute vec3 a_world;\n"
        "uniform float u_zs;\n"
        "varying vec3 v_material; varying vec2 v_tile_mode; varying vec3 v_world;\n"
        "void main(){\n"
        /* the layer texture covers canvas x 128..1151; the same half-pixel sample centre as the index pass */
        "  gl_Position=vec4(((a_pos.x+0.5)-128.0)*2.0/1024.0-1.0,(a_pos.y+0.5)*2.0/640.0-1.0,a_pos.z,1.0);\n"
        "  v_material=a_uv; v_tile_mode=a_suv; v_world=vec3(a_world.xy,a_world.z*u_zs);\n"
        "}\n";
    static const char *fs_lit= TL_GLSL_COMMON
        "uniform sampler2D u_tiles,u_fade,u_lut,u_kind,u_nrm,u_sh,u_bump;\n"
        "uniform vec2 u_view; uniform vec4 u_lx,u_ly,u_lz;\n"
        "uniform vec3 u_sun,u_sunc,u_sky,u_gnd; uniform float u_shon,u_wton,u_mix,u_zs;\n"
        "varying vec3 v_material; varying vec2 v_tile_mode; varying vec3 v_world;\n"
        "float shdec(vec2 uv){ vec4 t=texture2D(u_sh,uv); return t.r+t.g/255.0; }\n"
        "void main(){\n"
        "  float tile=floor(v_tile_mode.x+0.5);\n"
        "  vec2 base=vec2(mod(tile,16.0),floor(tile/16.0))*32.0;\n"
        "  vec2 tp=clamp(floor(v_material.xy),0.0,31.0);\n"
        "  float idx=rd8(u_tiles,base+tp,vec2(512.0,544.0));\n"
        "  if(v_tile_mode.y>5.5 && idx==0.0) discard;\n"
        "  float shade=clamp(floor(v_material.z),0.0,63.0);\n"
        "  float i2=idx; if(v_tile_mode.y>0.5) i2=floor(texture2D(u_fade,(vec2(idx,shade)+0.5)/vec2(256.0,64.0)).r*255.0+0.5);\n"
        "  vec3 c2=lut(u_lut,i2), alb=lut(u_lut,idx);\n"
        "  float kind=floor(texture2D(u_kind,vec2((idx+0.5)/256.0,0.5)).r*255.0+0.5);\n"
        /* smooth normal of the planet grid at this point (texel centres = grid vertices, wrap by GL_REPEAT) */
        "  vec4 nt=texture2D(u_nrm,(v_world.xy+u_view+0.5)/128.0);\n"
        "  vec3 N=normalize(nt.xyz*2.0-1.0);\n"
        /* micro-relief: luminance gradient of the tile (texel space) taken to the surface by the cotangent frame */
        "  vec3 bm=texture2D(u_bump,(base+clamp(v_material.xy,0.5,31.5))/vec2(512.0,544.0)).rgb;\n"
        "  vec2 gr=bm.gb*2.0-1.0;\n"
        "  vec3 dp1=dFdx(v_world), dp2=dFdy(v_world); vec2 du1=dFdx(v_material.xy), du2=dFdy(v_material.xy);\n"
        "  vec3 p2=cross(dp2,N), p1=cross(N,dp1);\n"
        "  vec3 T=p2*du1.x+p1*du2.x, B=p2*du1.y+p1*du2.y;\n"
        "  float im=inversesqrt(max(max(dot(T,T),dot(B,B)),1e-12));\n"
        "  float water=(u_wton>0.5 && kind==1.0)?1.0:0.0;\n"
        "  vec3 Nm=normalize(N-(1.0-water)*0.9*(gr.x*T+gr.y*B)*im);\n"
        /* shadow map, 3x3 PCF; normal offset against acne */
        "  float sh=1.0;\n"
        "  if(u_shon>0.5){\n"
        "    vec4 P=vec4(v_world+N*0.06,1.0);\n"
        "    vec3 l=vec3(dot(u_lx,P),dot(u_ly,P),dot(u_lz,P))*0.5+0.5;\n"
        "    float d=l.z-0.0018, s=0.0;\n"
        "    for(int j=-1;j<=1;j++) for(int i=-1;i<=1;i++) s+=(shdec(l.xy+vec2(float(i),float(j))*(1.3/2048.0))<d)?0.0:1.0;\n"
        "    sh=(l.x>0.0 && l.x<1.0 && l.y>0.0 && l.y<1.0)?s/9.0:1.0;\n"
        "  }\n"
        "  float ndl=max(dot(Nm,u_sun),0.0);\n"
        "  vec3 hemi=mix(u_gnd,u_sky,Nm.z*0.5+0.5);\n"
        /* tactical floor: a shadowed slope keeps the sky light and a share of the sun */
        "  float vis=mix(0.30,1.0,sh);\n"
        "  vec3 light=hemi*0.62+u_sunc*(ndl*vis*0.95);\n"
        "  vec3 V=vec3(0.6124,0.6124,0.5);\n"
        "  float sat=max(alb.r,max(alb.g,alb.b))-min(alb.r,min(alb.g,alb.b));\n"
        "  float rock=clamp(1.0-sat*3.0,0.0,1.0);\n"
        "  vec3 H=normalize(u_sun+V);\n"
        "  float spec=pow(max(dot(Nm,H),0.0),28.0)*0.16*rock*sh;\n"
        "  vec3 lit=alb*light*1.08+u_sunc*spec;\n"
        "  vec3 col=mix(c2,lit,u_mix);\n"
        "  float a=1.0;\n"
        "  if(water>0.5){\n"
        /* depth: the game raises the shallows towards the coast (sea surface cells at height 0 are open sea), and
           the distance from real land; the original shading (horizon fade) is kept by the luminance ratio */
        "    float hpx=v_world.z/u_zs;\n"
        "    float dep=clamp(clamp(1.0-hpx/22.0,0.0,1.0)*0.55+0.45*nt.a,0.0,1.0);\n"
        "    float l2=dot(c2,vec3(0.3,0.59,0.11)), la=max(dot(alb,vec3(0.3,0.59,0.11)),0.02);\n"
        "    float fs=clamp(l2/la,0.0,1.15);\n"
        "    vec3 shallow=alb*vec3(0.92,1.06,1.03)+vec3(0.00,0.05,0.05);\n"
        "    vec3 deep=alb*vec3(0.58,0.68,0.86);\n"
        "    col=mix(shallow,deep,smoothstep(0.0,1.0,dep))*mix(0.65,1.0,sh)*fs;\n"
        "    a=0.1+0.4*dep;\n"
        "  } else if(u_wton>0.5 && kind==2.0) a=0.75;\n"
        "  gl_FragColor=vec4(clamp(col,0.0,1.0),a);\n"
        "}\n";
    static const char *vs_sh=
        "#version 120\n attribute vec3 a_pos; uniform vec4 u_lx,u_ly,u_lz; uniform float u_zs; varying float v_d;\n"
        "void main(){ vec4 P=vec4(a_pos.xy,a_pos.z*u_zs,1.0); vec3 l=vec3(dot(u_lx,P),dot(u_ly,P),dot(u_lz,P));\n"
        "  gl_Position=vec4(l,1.0); v_d=l.z*0.5+0.5; }\n";
    static const char *fs_sh=
        "#version 120\n varying float v_d;\n"
        "void main(){ float d=clamp(v_d,0.0,1.0)*255.0; gl_FragColor=vec4(floor(d)/255.0,fract(d),0.0,1.0); }\n";
    /* luminance and its gradient inside each 32 x 32 tile of the atlas (wrapping inside the tile) */
    static const char *vs_q=
        "#version 120\n attribute vec2 a_pos;\n void main(){ gl_Position=vec4(a_pos,0.0,1.0); }\n";
    static const char *fs_bump= TL_GLSL_COMMON
        "uniform sampler2D u_tiles,u_lut;\n"
        "float L(vec2 p){ return dot(lut(u_lut,rd8(u_tiles,p,vec2(512.0,544.0))),vec3(0.30,0.59,0.11)); }\n"
        "void main(){ vec2 p=floor(gl_FragCoord.xy); vec2 b=floor(p/32.0)*32.0, q=p-b;\n"
        "  float xl=L(b+vec2(mod(q.x+31.0,32.0),q.y)), xr=L(b+vec2(mod(q.x+1.0,32.0),q.y));\n"
        "  float yd=L(b+vec2(q.x,mod(q.y+31.0,32.0))), yu=L(b+vec2(q.x,mod(q.y+1.0,32.0)));\n"
        "  gl_FragColor=vec4(L(p),clamp((xr-xl)*0.5+0.5,0.0,1.0),clamp((yu-yd)*0.5+0.5,0.0,1.0),1.0); }\n";
    g_t3.prog_lit=tl_link(vs_lit,fs_lit);
    g_t3.prog_sh=tl_link(vs_sh,fs_sh);
    g_t3.prog_bump=tl_link(vs_q,fs_bump);
    if(!g_t3.prog_lit || !g_t3.prog_sh || !g_t3.prog_bump) goto fail;
    #define TLU(prog,var,name) g_t3.var=g_bloom.GetUniformLocation(g_t3.prog,name)
    TLU(prog_lit,l_tiles,"u_tiles"); TLU(prog_lit,l_fade,"u_fade"); TLU(prog_lit,l_lut,"u_lut"); TLU(prog_lit,l_kind,"u_kind");
    TLU(prog_lit,l_nrm,"u_nrm"); TLU(prog_lit,l_sh,"u_sh"); TLU(prog_lit,l_bump,"u_bump"); TLU(prog_lit,l_view,"u_view");
    TLU(prog_lit,l_lx,"u_lx"); TLU(prog_lit,l_ly,"u_ly"); TLU(prog_lit,l_lz,"u_lz"); TLU(prog_lit,l_zs,"u_zs");
    TLU(prog_lit,l_sun,"u_sun"); TLU(prog_lit,l_sunc,"u_sunc"); TLU(prog_lit,l_sky,"u_sky"); TLU(prog_lit,l_gnd,"u_gnd");
    TLU(prog_lit,l_shon,"u_shon"); TLU(prog_lit,l_wton,"u_wton"); TLU(prog_lit,l_mix,"u_mix");
    TLU(prog_sh,s_lx,"u_lx"); TLU(prog_sh,s_ly,"u_ly"); TLU(prog_sh,s_lz,"u_lz"); TLU(prog_sh,s_zs,"u_zs");
    TLU(prog_bump,b_tiles,"u_tiles"); TLU(prog_bump,b_lut,"u_lut");
    #undef TLU
    }
    /* shadow map: packed 16-bit depth in RG, nearest */
    g_t3.sh_tex=tl_tex(TL_SHADOW,TL_SHADOW,GL_NEAREST,GL_CLAMP_TO_EDGE);
    g_bloom.GenFramebuffers(1,&g_t3.sh_fbo);
    g_bloom.BindFramebuffer(GL_FRAMEBUFFER,g_t3.sh_fbo);
    g_bloom.FramebufferTexture2D(GL_FRAMEBUFFER,GL_COLOR_ATTACHMENT0,GL_TEXTURE_2D,g_t3.sh_tex,0);
    g_gl_mesh.GenRenderbuffers(1,&g_t3.sh_rb);
    g_gl_mesh.BindRenderbuffer(GL_RENDERBUFFER,g_t3.sh_rb);
    g_gl_mesh.RenderbufferStorage(GL_RENDERBUFFER,GL_DEPTH_COMPONENT16,TL_SHADOW,TL_SHADOW);
    g_gl_mesh.BindRenderbuffer(GL_RENDERBUFFER,0);
    g_gl_mesh.FramebufferRenderbuffer(GL_FRAMEBUFFER,GL_DEPTH_ATTACHMENT,GL_RENDERBUFFER,g_t3.sh_rb);
    if(g_bloom.CheckFramebufferStatus(GL_FRAMEBUFFER)!=GL_FRAMEBUFFER_COMPLETE) goto fail;
    /* normals + sea depth of the planet grid, bilinear, wrapping */
    g_t3.nrm_tex=tl_tex(128,128,GL_LINEAR,GL_REPEAT);
    /* bump atlas (same layout as the tile atlas), bilinear inside a tile */
    g_t3.bump_tex=tl_tex(512,544,GL_LINEAR,GL_CLAMP_TO_EDGE);
    g_bloom.GenFramebuffers(1,&g_t3.bump_fbo);
    g_bloom.BindFramebuffer(GL_FRAMEBUFFER,g_t3.bump_fbo);
    g_bloom.FramebufferTexture2D(GL_FRAMEBUFFER,GL_COLOR_ATTACHMENT0,GL_TEXTURE_2D,g_t3.bump_tex,0);
    if(g_bloom.CheckFramebufferStatus(GL_FRAMEBUFFER)!=GL_FRAMEBUFFER_COMPLETE) goto fail;
    /* shadow casters: a 65 x 65 vertex grid of the terrain around the view, quads split like the game's strips */
    {   static uint16_t ib[TL_GRID*TL_GRID*6];
        unsigned n=0;
        for(unsigned j=0;j<TL_GRID;j++) for(unsigned i=0;i<TL_GRID;i++) {
            const uint16_t a=(uint16_t)(j*(TL_GRID+1)+i),b=(uint16_t)(a+1),c=(uint16_t)(a+TL_GRID+1),d=(uint16_t)(c+1);
            ib[n++]=a; ib[n++]=d; ib[n++]=c; ib[n++]=a; ib[n++]=b; ib[n++]=d;
        }
        g_bloom.GenBuffers(1,&g_t3.grid_vbo); g_bloom.GenBuffers(1,&g_t3.grid_ibo);
        g_bloom.BindBuffer(GL_ELEMENT_ARRAY_BUFFER,g_t3.grid_ibo);
        g_bloom.BufferData(GL_ELEMENT_ARRAY_BUFFER,sizeof ib,ib,GL_STATIC_DRAW);
        g_bloom.BindBuffer(GL_ELEMENT_ARRAY_BUFFER,0);
    }
    g_bloom.GenFramebuffers(1,&g_t3.fbo);
    g_bloom.BindFramebuffer(GL_FRAMEBUFFER,0);
    tl_biome(0);
    g_t3.hs_last=-1000; g_t3.ready=1;
    gw_flag_trace("TRACE terrain_3d lighting on (normals, sun + sky, shadow map %d, 3D water)%c",TL_SHADOW,10);
    return 1;
fail:
    g_t3.failed=1;
    g_bloom.BindFramebuffer(GL_FRAMEBUFFER,0);
    gw_flag_trace("TRACE terrain_3d lighting unavailable (flat 3D terrain kept)%c",10);
    return 0;
}

/* lit layer textures at scale s (s x the canvas resolution), reallocated when the window's scale changes */
static int tl_size(int s) {
    if(s<1) s=1;
    if(s>4) s=4;
    if(s==g_t3.scale && g_t3.lit[0]) return 1;
    for(int i=0;i<3;i++) if(g_t3.lit[i]) { g_bloom.DeleteTextures(1,&g_t3.lit[i]); g_t3.lit[i]=0; g_t3.lhave[i]=0; }
    g_t3.w=1024*s; g_t3.h=640*s; g_t3.scale=s;
    for(int i=0;i<3;i++) g_t3.lit[i]=tl_tex(g_t3.w,g_t3.h,GL_LINEAR,GL_CLAMP_TO_EDGE);
    if(!g_t3.depth_rb) g_gl_mesh.GenRenderbuffers(1,&g_t3.depth_rb);
    g_gl_mesh.BindRenderbuffer(GL_RENDERBUFFER,g_t3.depth_rb);
    g_gl_mesh.RenderbufferStorage(GL_RENDERBUFFER,GL_DEPTH_COMPONENT16,g_t3.w,g_t3.h);
    g_gl_mesh.BindRenderbuffer(GL_RENDERBUFFER,0);
    g_bloom.BindFramebuffer(GL_FRAMEBUFFER,g_t3.fbo);
    g_gl_mesh.FramebufferRenderbuffer(GL_FRAMEBUFFER,GL_DEPTH_ATTACHMENT,GL_RENDERBUFFER,g_t3.depth_rb);
    g_bloom.FramebufferTexture2D(GL_FRAMEBUFFER,GL_COLOR_ATTACHMENT0,GL_TEXTURE_2D,g_t3.lit[1],0);
    const int ok=g_bloom.CheckFramebufferStatus(GL_FRAMEBUFFER)==GL_FRAMEBUFFER_COMPLETE;
    g_bloom.BindFramebuffer(GL_FRAMEBUFFER,0);
    gw_flag_trace("TRACE terrain_3d lit layers %dx%d (x%d) ok=%d%c",g_t3.w,g_t3.h,s,ok,10);
    if(!ok) { g_t3.failed=1; return 0; }
    return 1;
}

/* the canvas layers rotate on each new game frame ([0] previous, [1] current, [2] spare): the lit layers follow */
static void tl_rotate(void) {
    GLuint t=g_t3.lit[0]; g_t3.lit[0]=g_t3.lit[1]; g_t3.lit[1]=g_t3.lit[2]; g_t3.lit[2]=t;
    int a=g_t3.lview[0][0],b=g_t3.lview[0][1],h=g_t3.lhave[0];
    g_t3.lview[0][0]=g_t3.lview[1][0]; g_t3.lview[0][1]=g_t3.lview[1][1]; g_t3.lhave[0]=g_t3.lhave[1];
    g_t3.lview[1][0]=g_t3.lview[2][0]; g_t3.lview[1][1]=g_t3.lview[2][1]; g_t3.lhave[1]=g_t3.lhave[2];
    g_t3.lview[2][0]=a; g_t3.lview[2][1]=b; g_t3.lhave[2]=h;
    g_t3.lhave[1]=0;
}

static inline int tl_hpx(const gw_terrain_mesh_draw *d,int col,int row) {
    return gw_terrain_mesh_height_step(d->planet_h[((unsigned)row&127u)*128u+((unsigned)col&127u)])*d->height_scale;
}

/* normals (smooth: central differences of the grid, wrapping) and sea depth (distance from land through the cells at
   or below the sea surface, in cells, 0 at the shore .. 1 at 5 cells), only when the grid changes */
static void tl_planet(const gw_terrain_mesh_draw *d) {
    if(g_t3.nrm_ok && g_t3.hs_last==d->height_scale && !memcmp(g_t3.last_h,d->planet_h,sizeof g_t3.last_h)) return;
    memcpy(g_t3.last_h,d->planet_h,sizeof g_t3.last_h); g_t3.hs_last=d->height_scale;
    static uint8_t px[128u*128u*4u]; static uint8_t dist[128u*128u]; static uint16_t q[128u*128u];
    unsigned qh=0,qt=0;
    for(int r=0;r<128;r++) for(int c=0;c<128;c++) {
        const unsigned i=(unsigned)r*128u+(unsigned)c;
        if(gw_terrain_mesh_height_step(d->planet_h[i])>=8) { dist[i]=0; q[qt++]=(uint16_t)i; } else dist[i]=255;
    }
    while(qh<qt) {
        const unsigned i=q[qh++],r=i>>7,c=i&127u; const uint8_t nd=(uint8_t)(dist[i]+1u);
        const unsigned nb[4]={((r+1u)&127u)*128u+c,((r+127u)&127u)*128u+c,r*128u+((c+1u)&127u),r*128u+((c+127u)&127u)};
        for(int k=0;k<4;k++) if(dist[nb[k]]==255 && nd<255) { dist[nb[k]]=nd; q[qt++]=(uint16_t)nb[k]; }
    }
    const float ex=1.5f*TL_ZS;   /* relief of the normals: a little stronger than the projection's */
    for(int r=0;r<128;r++) for(int c=0;c<128;c++) {
        const float dx=(float)(tl_hpx(d,c+1,r)-tl_hpx(d,c-1,r))*0.5f*ex,dy=(float)(tl_hpx(d,c,r+1)-tl_hpx(d,c,r-1))*0.5f*ex;
        float nx=-dx,ny=-dy,nz=1.0f; const float il=1.0f/sqrtf(nx*nx+ny*ny+nz*nz); nx*=il; ny*=il; nz*=il;
        uint8_t *o=px+((size_t)r*128u+(size_t)c)*4u;
        o[0]=(uint8_t)(nx*127.5f+127.5f); o[1]=(uint8_t)(ny*127.5f+127.5f); o[2]=(uint8_t)(nz*127.5f+127.5f);
        const unsigned dd=dist[(unsigned)r*128u+(unsigned)c];
        const float dep=dd>=5u?1.0f:(float)dd/5.0f;
        o[3]=(uint8_t)(dep*255.0f+0.5f);
    }
    g_bloom.BindTexture(GL_TEXTURE_2D,g_t3.nrm_tex);
    g_bloom.TexSubImage2D(GL_TEXTURE_2D,0,0,0,128,128,GL_RGBA,GL_UNSIGNED_BYTE,px);
    g_t3.nrm_ok=1;
}

/* the shadow casters around the view and the light's orthographic projection fitted to them */
static void tl_shadow(const gw_terrain_mesh_draw *d) {
    static float vb[(TL_GRID+1)*(TL_GRID+1)*3];
    const int c0=-12,r0=-30;
    const float *L=g_t3.sun;
    float rl[3]={L[1],-L[0],0.0f};   /* right = cross(-L, up) normalised */
    { const float n=sqrtf(rl[0]*rl[0]+rl[1]*rl[1]); rl[0]/=n; rl[1]/=n; }
    /* up = cross(right, forward), forward = -L */
    const float fw[3]={-L[0],-L[1],-L[2]};
    const float up[3]={rl[1]*fw[2]-rl[2]*fw[1],rl[2]*fw[0]-rl[0]*fw[2],rl[0]*fw[1]-rl[1]*fw[0]};
    float mn[3]={1e9f,1e9f,1e9f},mx[3]={-1e9f,-1e9f,-1e9f};
    unsigned n=0;
    for(int j=0;j<=TL_GRID;j++) for(int i=0;i<=TL_GRID;i++) {
        const float x=(float)(c0+i),y=(float)(r0+j),hz=(float)tl_hpx(d,d->view_col+c0+i,d->view_row+r0+j);
        vb[n++]=x; vb[n++]=y; vb[n++]=hz;
        const float z=hz*TL_ZS;
        const float a=x*rl[0]+y*rl[1]+z*rl[2],b=x*up[0]+y*up[1]+z*up[2],c=-(x*L[0]+y*L[1]+z*L[2]);
        if(a<mn[0]) mn[0]=a;
        if(a>mx[0]) mx[0]=a;
        if(b<mn[1]) mn[1]=b;
        if(b>mx[1]) mx[1]=b;
        if(c<mn[2]) mn[2]=c;
        if(c>mx[2]) mx[2]=c;
    }
    for(int k=0;k<3;k++) { mn[k]-=0.5f; mx[k]+=0.5f; }
    const float sx=2.0f/(mx[0]-mn[0]),sy=2.0f/(mx[1]-mn[1]),sz=2.0f/(mx[2]-mn[2]);
    g_t3.lx[0]=rl[0]*sx; g_t3.lx[1]=rl[1]*sx; g_t3.lx[2]=rl[2]*sx; g_t3.lx[3]=-mn[0]*sx-1.0f;
    g_t3.ly[0]=up[0]*sy; g_t3.ly[1]=up[1]*sy; g_t3.ly[2]=up[2]*sy; g_t3.ly[3]=-mn[1]*sy-1.0f;
    g_t3.lz[0]=-L[0]*sz; g_t3.lz[1]=-L[1]*sz; g_t3.lz[2]=-L[2]*sz; g_t3.lz[3]=-mn[2]*sz-1.0f;
    g_bloom.BindFramebuffer(GL_FRAMEBUFFER,g_t3.sh_fbo);
    g_bloom.Viewport(0,0,TL_SHADOW,TL_SHADOW);
    g_bloom.ClearColor(1.0f,1.0f,0.0f,1.0f);
    g_bloom.Clear(GL_COLOR_BUFFER_BIT|GL_DEPTH_BUFFER_BIT);
    g_bloom.UseProgram(g_t3.prog_sh);
    g_t3.Uniform4f(g_t3.s_lx,g_t3.lx[0],g_t3.lx[1],g_t3.lx[2],g_t3.lx[3]);
    g_t3.Uniform4f(g_t3.s_ly,g_t3.ly[0],g_t3.ly[1],g_t3.ly[2],g_t3.ly[3]);
    g_t3.Uniform4f(g_t3.s_lz,g_t3.lz[0],g_t3.lz[1],g_t3.lz[2],g_t3.lz[3]);
    g_bloom.Uniform1f(g_t3.s_zs,TL_ZS);
    g_bloom.BindBuffer(GL_ARRAY_BUFFER,g_t3.grid_vbo);
    g_bloom.BufferData(GL_ARRAY_BUFFER,sizeof vb,vb,GL_STREAM_DRAW);
    g_bloom.BindBuffer(GL_ELEMENT_ARRAY_BUFFER,g_t3.grid_ibo);
    g_bloom.DisableVertexAttribArray(1); g_bloom.DisableVertexAttribArray(2);
    g_bloom.VertexAttribPointer(0,3,GL_FLOAT,GL_FALSE,3*(GLsizei)sizeof(float),(const void *)0);
    g_gl_mesh.DrawElements(GL_TRIANGLES,TL_GRID*TL_GRID*6,GL_UNSIGNED_SHORT,0);
    g_bloom.BindBuffer(GL_ELEMENT_ARRAY_BUFFER,0);
    g_bloom.EnableVertexAttribArray(1); g_bloom.EnableVertexAttribArray(2);
    g_bloom.ClearColor(0.0f,0.0f,0.0f,1.0f);
}

/* once per game frame, after terrain_gl_render (the tile atlas and the mesh VBO are current): the lit layer */
static int tl_render(const gw_terrain_mesh_draw *d,int scale) {
    if(!d || !d->count || !tl_init() || !tl_size(scale)) return 0;
    g_gl_mesh.PushAttrib(GL_DEPTH_BUFFER_BIT|GL_ENABLE_BIT|GL_VIEWPORT_BIT);
    g_bloom.Disable(GL_CULL_FACE); g_bloom.Disable(GL_DITHER); g_bloom.Disable(GL_BLEND); g_bloom.Disable(GL_SCISSOR_TEST);
    g_bloom.Enable(GL_DEPTH_TEST);
    g_gl_mesh.DepthFunc(GL_LESS); g_gl_mesh.DepthMask(GL_TRUE); g_gl_mesh.ClearDepth(1.0);
    tl_planet(d);
    const int shadows=g_ini_terrain_3d_shadows!=0;
    if(shadows) tl_shadow(d);
    /* bump atlas from the tile atlas just uploaded */
    g_bloom.Disable(GL_DEPTH_TEST);
    g_bloom.BindFramebuffer(GL_FRAMEBUFFER,g_t3.bump_fbo);
    g_bloom.Viewport(0,0,512,544);
    g_bloom.UseProgram(g_t3.prog_bump);
    g_bloom.ActiveTexture(GL_TEXTURE1); g_bloom.BindTexture(GL_TEXTURE_2D,g_bloom.lut_tex); g_bloom.Uniform1i(g_t3.b_lut,1);
    g_bloom.ActiveTexture(GL_TEXTURE0); g_bloom.BindTexture(GL_TEXTURE_2D,g_gl_mesh.tiles); g_bloom.Uniform1i(g_t3.b_tiles,0);
    g_bloom.BindBuffer(GL_ARRAY_BUFFER,g_bloom.vbo);
    g_bloom.VertexAttribPointer(0,2,GL_FLOAT,GL_FALSE,6*sizeof(float),(const void *)0);
    g_bloom.VertexAttribPointer(1,2,GL_FLOAT,GL_FALSE,6*sizeof(float),(const void *)(2*sizeof(float)));
    g_bloom.VertexAttribPointer(2,2,GL_FLOAT,GL_FALSE,6*sizeof(float),(const void *)(4*sizeof(float)));
    bloom_draw_quad(-1.0f,-1.0f,1.0f,1.0f, 0.0f,0.0f,1.0f,1.0f, 0.0f,0.0f,1.0f,1.0f);
    g_bloom.Enable(GL_DEPTH_TEST);
    /* the lit mesh into the current layer */
    g_bloom.BindFramebuffer(GL_FRAMEBUFFER,g_t3.fbo);
    g_bloom.FramebufferTexture2D(GL_FRAMEBUFFER,GL_COLOR_ATTACHMENT0,GL_TEXTURE_2D,g_t3.lit[1],0);
    g_bloom.Viewport(0,0,g_t3.w,g_t3.h);
    g_bloom.ClearColor(0.0f,0.0f,0.0f,0.0f);
    g_bloom.Clear(GL_COLOR_BUFFER_BIT|GL_DEPTH_BUFFER_BIT);
    g_bloom.ClearColor(0.0f,0.0f,0.0f,1.0f);
    g_bloom.UseProgram(g_t3.prog_lit);
    g_bloom.ActiveTexture(GL_TEXTURE0); g_bloom.BindTexture(GL_TEXTURE_2D,g_gl_mesh.tiles); g_bloom.Uniform1i(g_t3.l_tiles,0);
    g_bloom.ActiveTexture(GL_TEXTURE1); g_bloom.BindTexture(GL_TEXTURE_2D,g_gl_mesh.fade); g_bloom.Uniform1i(g_t3.l_fade,1);
    g_bloom.ActiveTexture(GL_TEXTURE2); g_bloom.BindTexture(GL_TEXTURE_2D,g_bloom.lut_tex); g_bloom.Uniform1i(g_t3.l_lut,2);
    g_bloom.ActiveTexture(GL_TEXTURE3); g_bloom.BindTexture(GL_TEXTURE_2D,g_gm.t_kind); g_bloom.Uniform1i(g_t3.l_kind,3);
    g_bloom.ActiveTexture(GL_TEXTURE4); g_bloom.BindTexture(GL_TEXTURE_2D,g_t3.nrm_tex); g_bloom.Uniform1i(g_t3.l_nrm,4);
    g_bloom.ActiveTexture(GL_TEXTURE5); g_bloom.BindTexture(GL_TEXTURE_2D,g_t3.sh_tex); g_bloom.Uniform1i(g_t3.l_sh,5);
    g_bloom.ActiveTexture(GL_TEXTURE6); g_bloom.BindTexture(GL_TEXTURE_2D,g_t3.bump_tex); g_bloom.Uniform1i(g_t3.l_bump,6);
    g_bloom.ActiveTexture(GL_TEXTURE0);
    const int vc=d->view_col&127,vr=d->view_row&127;
    g_bloom.Uniform2f(g_t3.l_view,(float)vc,(float)vr);
    g_t3.Uniform4f(g_t3.l_lx,g_t3.lx[0],g_t3.lx[1],g_t3.lx[2],g_t3.lx[3]);
    g_t3.Uniform4f(g_t3.l_ly,g_t3.ly[0],g_t3.ly[1],g_t3.ly[2],g_t3.ly[3]);
    g_t3.Uniform4f(g_t3.l_lz,g_t3.lz[0],g_t3.lz[1],g_t3.lz[2],g_t3.lz[3]);
    g_bloom.Uniform1f(g_t3.l_zs,TL_ZS);
    g_t3.Uniform3f(g_t3.l_sun,g_t3.sun[0],g_t3.sun[1],g_t3.sun[2]);
    g_t3.Uniform3f(g_t3.l_sunc,g_t3.sunc[0],g_t3.sunc[1],g_t3.sunc[2]);
    g_t3.Uniform3f(g_t3.l_sky,g_t3.sky[0],g_t3.sky[1],g_t3.sky[2]);
    g_t3.Uniform3f(g_t3.l_gnd,g_t3.gnd[0],g_t3.gnd[1],g_t3.gnd[2]);
    g_bloom.Uniform1f(g_t3.l_shon,shadows?1.0f:0.0f);
    g_bloom.Uniform1f(g_t3.l_wton,g_ini_terrain_3d_water?1.0f:0.0f);
    g_bloom.Uniform1f(g_t3.l_mix,0.80f);
    g_bloom.BindBuffer(GL_ARRAY_BUFFER,g_gl_mesh.vbo);   /* uploaded by terrain_gl_render this game frame */
    g_bloom.BindBuffer(GL_ELEMENT_ARRAY_BUFFER,g_gl_mesh.ibo);
    const GLsizei stride=sizeof d->vertex[0];
    g_bloom.VertexAttribPointer(0,3,GL_FLOAT,GL_FALSE,stride,(const void *)offsetof(gw_terrain_mesh_vertex,x));
    g_bloom.VertexAttribPointer(1,3,GL_FLOAT,GL_FALSE,stride,(const void *)offsetof(gw_terrain_mesh_vertex,u));
    g_bloom.VertexAttribPointer(2,2,GL_FLOAT,GL_FALSE,stride,(const void *)offsetof(gw_terrain_mesh_vertex,tile));
    g_bloom.EnableVertexAttribArray(3);
    g_bloom.VertexAttribPointer(3,3,GL_FLOAT,GL_FALSE,stride,(const void *)offsetof(gw_terrain_mesh_vertex,wx));
    g_gl_mesh.DrawElements(GL_TRIANGLES,(GLsizei)d->count,GL_UNSIGNED_SHORT,0);
    g_bloom.DisableVertexAttribArray(3);
    g_bloom.BindBuffer(GL_ELEMENT_ARRAY_BUFFER,0);
    g_gl_mesh.PopAttrib();
    g_bloom.BindBuffer(GL_ARRAY_BUFFER,g_bloom.vbo);
    g_bloom.VertexAttribPointer(0,2,GL_FLOAT,GL_FALSE,6*sizeof(float),(const void *)0);
    g_bloom.VertexAttribPointer(1,2,GL_FLOAT,GL_FALSE,6*sizeof(float),(const void *)(2*sizeof(float)));
    g_bloom.VertexAttribPointer(2,2,GL_FLOAT,GL_FALSE,6*sizeof(float),(const void *)(4*sizeof(float)));
    g_bloom.ActiveTexture(GL_TEXTURE0);
    {   /* QA trace: the view crossed the planet's wrap (origin column or row jumped across 0/127) */
        static int pvc=-1,pvr=-1;
        if(pvc>=0 && ((pvc>96 && vc<32) || (pvc<32 && vc>96) || (pvr>96 && vr<32) || (pvr<32 && vr>96)))
            gw_flag_trace("TRACE terrain_3d wrap crossed origin %d,%d -> %d,%d%c",pvc,pvr,vc,vr,10);
        pvc=vc; pvr=vr;
        static unsigned nt; if(++nt%80u==0u) gw_flag_trace("TRACE terrain_3d origin %d,%d%c",vc,vr,10); }
    g_t3.lview[1][0]=vc; g_t3.lview[1][1]=vr; g_t3.lhave[1]=1;
    return 1;
}

#endif
