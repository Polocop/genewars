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

#include "gw_png.h"
#include "gw_terrain_atmosphere.h"
enum { TL_SHADOW=2048, TL_GRID=64, TL_LIGHTS=16 };
static void bloom_draw_quad(float x0,float y0,float x1,float y1,float u0,float v0,float u1,float v1,
                            float su0,float sv0,float su1,float sv1);

static struct {
    int failed,ready,scale,w,h,biome,nrm_ok,hs_last;
    GLuint prog_lit,prog_sh,prog_bump,prog_sky,prog_wave;
    GLuint wave_fbo,wave_tex,wave_vbo[3];
    unsigned wave_n[3];
    GLint wave_time;
    uint8_t sea_dist[128u*128u];
    GLuint refl[3],refl_fbo,refl_rb;
    int refl_have[3],refl_failed;
    GLint l_reflect,l_water_plane,l_ring,l_ring_off;
    GLint l_time_of_day,l_flash,sky_phase,sky_dir,sky_color;
    float layer_night[3],layer_sun[3][3],layer_sunc[3][3],layer_sky[3][3];
    float day_sun[3],day_sunc[3],day_sky[3],day_gnd[3],night;
    GLuint lit[3],fbo,depth_rb;
    GLuint ao_tex,sh_tex,sh_fbo,sh_rb,nrm_tex,bump_tex,bump_fbo,grid_vbo,grid_ibo;
    int lview[3][2],lhave[3];            /* per canvas layer: display origin (mod 128) and whether it holds a lit frame */
    GLint l_ao,l_tiles,l_fade,l_lut,l_kind,l_nrm,l_sh,l_bump,l_view,l_lx,l_ly,l_lz,l_zs,l_sun,l_sunc,l_sky,l_gnd,l_shon,l_wton,l_mix;
    GLint s_lx,s_ly,s_lz,s_zs;
    GLint l_plp,l_plc,l_pln,l_hd,l_hdmap,l_hdon,l_hdsz,l_hdm,l_aos,l_wtint;
    float aos,wtint[3],expo,shfloor,knorm;   /* biome: valley AO, liquid tint, exposure, shadow floor, brightness hold */
    GLint l_expo,l_shfloor,l_knorm;
    /* terrain_3d_lights: this game frame's point lights, world space relative to the display origin (xyz, radius in
       cells) and colour x intensity; filled by pl_extract, sent by tl_render */
    float pl_pos[TL_LIGHTS][4],pl_col[TL_LIGHTS][4]; int pl_n;
    void (APIENTRYP Uniform4fv)(GLint,GLsizei,const GLfloat *);
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

/* sun (towards the light) and light colours per biome: 0 organic (Exceland, the validated balance), 1 arid (Brown:
   grazing amber-gold sun, dark warm-violet shadow light, deeper valley AO, warmer murky liquids), 2 volcanic (low
   orange sun, red-brown shadows), 3 icy (cool pale sun, blue shadows), 4 = 0, 5 toxic / alien (sickly yellow sun,
   teal-olive shadows, yellow-green liquids). Shadows keep a tactical floor in every preset. */
static void tl_biome(int bi) {
    if(bi<0 || bi>5) bi=0;
    g_t3.biome=bi;
    static const float az[6][2]={{-1.0f,-0.35f},{-1.0f,-0.20f},{-1.0f,-0.45f},{-1.0f,-0.30f},{-1.0f,-0.35f},{-1.0f,-0.30f}};
    static const float el[6]={0.44f,0.36f,0.38f,0.38f,0.44f,0.42f};   /* elevation (rad): a low sun sculpts the relief */
    static const float sc[6][3]={{1.05f,0.95f,0.78f},{1.14f,0.86f,0.52f},{1.10f,0.70f,0.46f},{0.94f,0.99f,1.08f},{1.05f,0.95f,0.78f},{1.02f,1.04f,0.74f}};
    static const float sk[6][3]={{0.46f,0.62f,1.00f},{0.62f,0.50f,0.74f},{0.54f,0.40f,0.60f},{0.52f,0.70f,1.06f},{0.46f,0.62f,1.00f},{0.40f,0.62f,0.56f}};
    static const float gd[6][3]={{0.34f,0.36f,0.26f},{0.46f,0.32f,0.24f},{0.38f,0.20f,0.16f},{0.42f,0.46f,0.54f},{0.34f,0.36f,0.26f},{0.36f,0.40f,0.24f}};
    static const float ao[6]={1.0f,1.25f,1.15f,0.95f,1.0f,1.05f};
    static const float shf[6]={0.14f,0.40f,0.32f,0.18f,0.14f,0.22f};   /* light left in cast shadows (tactical floor) */
    /* exposure, measured: mean brightness of the 3D map within a few % of the 2D frame in every biome (the screens
       keep their brightness; the low sun only moves light from shadowed to lit slopes) */
    static const float ex[6]={1.04f,1.75f,1.55f,1.10f,1.04f,1.25f};
    /* brightness hold: how far each pixel's lit brightness is pulled back towards the 2D frame's own brightness there
       (0 = free 3D light, the validated organic look; 0.5 = half way): long low-sun shadows stay visible but never
       sink the screen */
    static const float kn[6]={0.0f,0.55f,0.50f,0.25f,0.0f,0.40f};
    static const float wt[6][3]={{1.0f,1.0f,1.0f},{1.05f,0.95f,0.80f},{1.0f,0.85f,0.80f},{0.92f,1.0f,1.08f},{1.0f,1.0f,1.0f},{0.95f,1.05f,0.80f}};
    const float hx=az[bi][0],hy=az[bi][1],hl=sqrtf(hx*hx+hy*hy),c=cosf(el[bi]),s=sinf(el[bi]);
    g_t3.sun[0]=hx/hl*c; g_t3.sun[1]=hy/hl*c; g_t3.sun[2]=s;
    for(int i=0;i<3;i++) { g_t3.sunc[i]=sc[bi][i]; g_t3.sky[i]=sk[bi][i]; g_t3.gnd[i]=gd[bi][i]; g_t3.wtint[i]=wt[bi][i]; }
    memcpy(g_t3.day_sun,g_t3.sun,sizeof g_t3.sun);
    memcpy(g_t3.day_sunc,g_t3.sunc,sizeof g_t3.sunc);
    memcpy(g_t3.day_sky,g_t3.sky,sizeof g_t3.sky);
    memcpy(g_t3.day_gnd,g_t3.gnd,sizeof g_t3.gnd);
    g_t3.aos=ao[bi]; g_t3.shfloor=shf[bi];
    g_t3.expo=ex[bi]; g_t3.knorm=kn[bi];
    gw_flag_trace("TRACE terrain_3d biome preset %d exposure %.2f%c",bi,(double)g_t3.expo,10);
}

static void tl_atmosphere(void) {
    const float phase=g_atmosphere.time_of_day;
    const float orbit=phase*6.283185307f;
    const float h=cosf(orbit);
    const float gold=1.0f-atm_smooth(0.04f,0.63f,fabsf(h));
    g_t3.night=atm_smooth(0.0f,0.66f,-h);
    const float angle=atan2f(g_t3.day_sun[1],g_t3.day_sun[0])+orbit;
    const float noon=asinf(g_t3.day_sun[2]);
    const float elev=0.105f+(noon-0.105f)*fmaxf(h,0.0f)+0.32f*g_t3.night;
    g_t3.sun[0]=cosf(angle)*cosf(elev);
    g_t3.sun[1]=sinf(angle)*cosf(elev);
    g_t3.sun[2]=sinf(elev);
    if(phase==0.0f) memcpy(g_t3.sun,g_t3.day_sun,sizeof g_t3.sun);
    static const float sunset[3]={1.34f,0.77f,0.34f}, moon[3]={0.32f,0.43f,0.62f};
    static const float dusk_sky[3]={0.43f,0.47f,0.79f}, moon_sky[3]={0.29f,0.38f,0.58f};
    static const float dusk_gnd[3]={0.29f,0.27f,0.43f}, moon_gnd[3]={0.19f,0.25f,0.36f};
    for(int i=0;i<3;i++) {
        const float n=g_t3.night;
        g_t3.sunc[i]=(g_t3.day_sunc[i]*(1.0f-gold)+sunset[i]*gold)*(1.0f-n)+moon[i]*n;
        g_t3.sky[i]=(g_t3.day_sky[i]*(1.0f-gold)+dusk_sky[i]*gold)*(1.0f-n)+moon_sky[i]*n;
        g_t3.gnd[i]=(g_t3.day_gnd[i]*(1.0f-gold)+dusk_gnd[i]*gold)*(1.0f-n)+moon_gnd[i]*n;
    }
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
    *(void **)&g_t3.Uniform4fv=SDL_GL_GetProcAddress("glUniform4fv");
    if(!g_t3.Uniform3f || !g_t3.Uniform4f || !g_t3.Uniform4fv) goto fail;
    {
    static const char *vs_lit=
        "#version 120\n"
        "attribute vec3 a_pos; attribute vec3 a_uv; attribute vec2 a_suv; attribute vec3 a_world;\n"
        "uniform float u_zs,u_reflect,u_water_plane;\n"
        "varying vec3 v_material; varying vec2 v_tile_mode; varying vec3 v_world; varying vec2 v_screen;\n"
        "void main(){\n"
        /* the layer texture covers canvas x 128..1151; the same half-pixel sample centre as the index pass */
        "  v_screen=a_pos.xy;\n"
        "  float y=a_pos.y, z=a_pos.z;\n"
        "  if(u_reflect>0.5){\n"
        "    y+=2.0*(a_world.z-u_water_plane);\n"
        "    z=clamp(-0.025*(a_world.x+a_world.y)+0.001*a_world.z,-0.99,0.99);\n"
        "  }\n"
        "  gl_Position=vec4(((a_pos.x+0.5)-128.0)*2.0/1024.0-1.0,(y+0.5)*2.0/640.0-1.0,z,1.0);\n"
        "  v_material=a_uv; v_tile_mode=a_suv; v_world=vec3(a_world.xy,a_world.z*u_zs);\n"
        "}\n";
    static const char *fs_lit= TL_GLSL_COMMON
        "uniform sampler2D u_tiles,u_fade,u_lut,u_kind,u_nrm,u_sh,u_bump,u_ao;\n"
        "uniform vec2 u_view; uniform vec4 u_lx,u_ly,u_lz;\n"
        "uniform vec3 u_sun,u_sunc,u_sky,u_gnd; uniform float u_shon,u_wton,u_mix,u_zs;\n"
        "uniform vec4 u_pt_light_pos_rad[16]; uniform vec4 u_pt_light_col_int[16]; uniform int u_pt_light_count;\n"
        "uniform sampler2D u_hd,u_hdmap; uniform float u_hdon,u_hdm; uniform vec2 u_hdsz;\n"
        "uniform float u_aos,u_expo,u_shfloor,u_knorm; uniform vec3 u_wtint;\n"
        "uniform sampler2D u_ring; uniform vec2 u_ring_off;\n"
        "uniform float u_reflect,u_water_plane,u_time_of_day,u_flash;\n"
        "varying vec3 v_material; varying vec2 v_tile_mode; varying vec3 v_world; varying vec2 v_screen;\n"
        "float shdec(vec2 uv){ vec4 t=texture2D(u_sh,uv); return t.b>0.5?t.r+t.g/255.0:1.0; }\n"
        "float hh(vec2 q){ vec3 p3=fract(vec3(q.xyx)*0.1031); p3+=dot(p3,p3.yzx+33.33); return fract((p3.x+p3.y)*p3.z); }\n"
        "float vn(vec2 p,float P){ vec2 i=floor(p), f=fract(p); f=f*f*(3.0-2.0*f);\n"
        "  float a=hh(mod(i,P)), b=hh(mod(i+vec2(1.0,0.0),P)), c=hh(mod(i+vec2(0.0,1.0),P)), d=hh(mod(i+vec2(1.0,1.0),P));\n"
        "  return mix(mix(a,b,f.x),mix(c,d,f.x),f.y); }\n"
        "float det(vec2 W){ return 0.5*vn(W*24.0,3072.0)+0.3*vn(W*56.0,7168.0)+0.2*vn(W*120.0,15360.0); }\n"
        "float texel(vec2 base,vec2 t,float shade,out float raw){\n"
        "  raw=rd8(u_tiles,base+clamp(t,0.0,31.0),vec2(512.0,544.0));\n"
        "  float i2=raw; if(v_tile_mode.y>0.5) i2=floor(texture2D(u_fade,(vec2(raw,shade)+0.5)/vec2(256.0,64.0)).r*255.0+0.5);\n"
        "  return i2; }\n"
        "void main(){\n"
        "  float tile=floor(v_tile_mode.x+0.5);\n"
        "  vec2 base=vec2(mod(tile,16.0),floor(tile/16.0))*32.0;\n"
        "  vec2 tp=clamp(floor(v_material.xy),0.0,31.0);\n"
        "  float idx=rd8(u_tiles,base+tp,vec2(512.0,544.0));\n"
        "  if(v_tile_mode.y>5.5 && idx==0.0) discard;\n"
        "  float kind=floor(texture2D(u_kind,vec2((idx+0.5)/256.0,0.5)).r*255.0+0.5);\n"
        "  if(u_reflect>0.5){\n"
        "    if(v_world.z/u_zs<u_water_plane || kind==1.0 || v_screen.x<128.0 || v_screen.x>=1152.0 || v_screen.y<0.0 || v_screen.y>=640.0) discard;\n"
        "    vec2 p=mod(floor(v_screen+0.5)-vec2(128.0,0.0)+u_ring_off,vec2(1024.0,640.0))+vec2(128.0,0.0);\n"
        "    if(rd8(u_ring,p,vec2(1152.0,640.0))==0.0) discard;\n"
        "  }\n"
        "  float shade=clamp(floor(v_material.z),0.0,63.0);\n"
        "  /* sharp bilinear of the B32 texels: solid texel interiors, a one-pixel antialiased seam between texels */\n"
        "  vec2 pt=v_material.xy-0.5; vec2 i0=floor(pt); vec2 fw=max(fwidth(v_material.xy),vec2(1e-4));\n"
        "  vec2 f=clamp((fract(pt)-0.5)/fw+0.5,0.0,1.0);\n"
        "  vec3 c2,alb;\n"
        "  if(u_reflect>0.5){ float raw; c2=lut(u_lut,texel(base,tp,shade,raw)); alb=lut(u_lut,idx); }\n"
        "  else {\n"
        "  float r00,r10,r01,r11;\n"
        "  float t00=texel(base,i0,shade,r00), t10=texel(base,i0+vec2(1.0,0.0),shade,r10);\n"
        "  float t01=texel(base,i0+vec2(0.0,1.0),shade,r01), t11=texel(base,i0+vec2(1.0,1.0),shade,r11);\n"
        "  c2=mix(mix(lut(u_lut,t00),lut(u_lut,t10),f.x),mix(lut(u_lut,t01),lut(u_lut,t11),f.x),f.y);\n"
        "  alb=mix(mix(lut(u_lut,r00),lut(u_lut,r10),f.x),mix(lut(u_lut,r01),lut(u_lut,r11),f.x),f.y);\n"
        "  }\n"
        "  if(v_tile_mode.y>5.5){ vec3 cc=lut(u_lut,idx); float i2=idx;\n"
        "    i2=floor(texture2D(u_fade,(vec2(idx,shade)+0.5)/vec2(256.0,64.0)).r*255.0+0.5); c2=lut(u_lut,i2); alb=cc; }\n"
        /* HD override: the albedo of this tile's texels from the HD atlas (bank layout, linear + mipmaps), the shaded
           2D colour scaled by the same ratio; water / GOOP / heights keep coming from the original indices */
        "  float hdon=0.0;\n"
        "  if(u_hdon>0.5 && v_tile_mode.y<5.5){\n"
        "    vec4 hm=texture2D(u_hdmap,vec2((tile+0.5)/259.0,0.5));\n"
        "    if(hm.a>0.5){\n"
        "      vec2 o=vec2(floor(hm.r*255.0+0.5),floor(hm.g*255.0+0.5)+256.0*floor(hm.b*255.0+0.5));\n"
        "      vec3 hd=texture2D(u_hd,(o+clamp(v_material.xy,vec2(u_hdm),vec2(32.0-u_hdm)))/u_hdsz).rgb;\n"
        "      float lo=dot(alb,vec3(0.3,0.59,0.11)), lc=dot(c2,vec3(0.3,0.59,0.11));\n"
        "      c2=hd*clamp(lc/max(lo,0.02),0.0,1.5); alb=hd; hdon=1.0;\n"
        "    }\n"
        "  }\n"
        "  vec2 W=v_world.xy+u_view;\n"
        "  vec4 nt=texture2D(u_nrm,(W+0.5)/128.0);\n"
        "  float ao=clamp(1.0-(1.0-texture2D(u_ao,(W+0.5)/128.0).r)*u_aos,0.25,1.0);\n"
        "  vec3 N=normalize(nt.xyz*2.0-1.0), Nm=N;\n"
        "  float water=(u_wton>0.5 && kind==1.0)?1.0:0.0;\n"
        "  if(u_reflect<0.5){\n"
        "  vec3 bm=texture2D(u_bump,(base+clamp(v_material.xy,0.5,31.5))/vec2(512.0,544.0)).rgb;\n"
        "  vec2 gr=bm.gb*2.0-1.0;\n"
        "  vec3 dp1=dFdx(v_world), dp2=dFdy(v_world); vec2 du1=dFdx(v_material.xy), du2=dFdy(v_material.xy);\n"
        "  vec3 p2=cross(dp2,N), p1=cross(N,dp1);\n"
        "  vec3 T=p2*du1.x+p1*du2.x, B=p2*du1.y+p1*du2.y;\n"
        "  float im=inversesqrt(max(max(dot(T,T),dot(B,B)),1e-12));\n"
        "  /* 4K micro-detail in world coordinates (periodic over the 128-cell planet): albedo +-10 %, normal relief */\n"
        "  float dn=det(W), dx=det(W+vec2(0.004,0.0))-dn, dy=det(W+vec2(0.0,0.004))-dn;\n"
        "  Nm=normalize(N-(1.0-water)*(0.9*(gr.x*T+gr.y*B)*im+vec3(dx,dy,0.0)*1.4));\n"
        "  alb*=1.0+(1.0-water)*0.32*(1.0-0.6*hdon)*(dn-0.5);\n"
        "  }\n"
        "  float sh=1.0;\n"
        "  if(u_shon>0.5){\n"
        "    vec4 P=vec4(v_world+N*0.06,1.0);\n"
        "    vec3 l=vec3(dot(u_lx,P),dot(u_ly,P),dot(u_lz,P))*0.5+0.5;\n"
        "    float d=l.z-0.0018, s=0.0;\n"
        "    if(l.x>0.0 && l.x<1.0 && l.y>0.0 && l.y<1.0){\n"
        "      if(u_reflect>0.5) sh=step(d,shdec(l.xy));\n"
        "      else {\n"
        "        for(int j=-1;j<=1;j++) for(int i=-1;i<=1;i++) s+=(shdec(l.xy+vec2(float(i),float(j))*(1.3/2048.0))<d)?0.0:1.0;\n"
        "        sh=s/9.0;\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "  float ndl=max(dot(Nm,u_sun),0.0);\n"
        "  vec3 hemi=mix(u_gnd,u_sky,Nm.z*0.5+0.5);\n"
        "  /* low warm sun against a cooler, deeper sky light; valley/cavity AO from the height grid; shadows never black */\n"
        "  float vis=mix(u_shfloor,1.0,sh);\n"
        "  vec3 light=(hemi*(0.40*ao)+u_sunc*(ndl*vis*1.30*mix(0.65,1.0,ao)))*u_expo;\n"
        "  vec3 V=vec3(0.6124,0.6124,0.5);\n"
        "  float sat=max(alb.r,max(alb.g,alb.b))-min(alb.r,min(alb.g,alb.b));\n"
        "  float rock=clamp(1.0-sat*3.0,0.0,1.0);\n"
        "  vec3 H=normalize(u_sun+V);\n"
        "  float spec=pow(max(dot(Nm,H),0.0),32.0)*0.20*rock*sh;\n"
        "  vec3 lit=alb*light*1.12+u_sunc*spec;\n"
        /* dynamic point lights: real 3D normal, (1 - d/r)^2 falloff to exactly 0 at the radius, soft knee so they
           lift the scene without burning it to white; only where the mesh draws terrain (never the undrawn black) */
        "  float night=smoothstep(0.0,0.66,-cos(u_time_of_day*6.283185307));\n"
        "  vec3 pl=vec3(0.0), pls=vec3(0.0);\n"
        "  for(int i=0;i<16;i++){\n"
        "    if(i>=u_pt_light_count) break;\n"
        "    vec4 pr=u_pt_light_pos_rad[i]; pr.w*=1.0+0.28*night; vec3 Lv=pr.xyz-v_world; Lv.xy=mod(Lv.xy+64.0,128.0)-64.0;\n"
        "    float d=length(Lv); if(d>=pr.w) continue;\n"
        "    vec3 Ld=Lv/max(d,1e-3); float at=1.0-d/pr.w; at*=at;\n"
        "    vec3 lc=u_pt_light_col_int[i].rgb*(u_pt_light_col_int[i].w*at*(1.0+0.44*night));\n"
        "    pl+=lc*(max(dot(Nm,Ld),0.0)*0.85+0.15);\n"
        "    pls+=lc*pow(max(dot(Nm,normalize(Ld+V)),0.0),24.0);\n"
        "  }\n"
        "  pl=pl/(1.0+0.45*pl);\n"
        "  lit+=alb*pl*1.15*mix(0.7,1.0,ao)+pls*0.30*rock;\n"
        "  vec3 col=mix(c2*mix(0.75,1.0,ao),lit,u_mix);\n"
        /* soft shoulder above 0.8: identity below it (the validated organic look), no clipped highlights above */
        "  if(u_knorm>0.0){ float L2=dot(c2,vec3(0.3,0.59,0.11)), L3=dot(col,vec3(0.3,0.59,0.11));\n"
        "    col*=pow(clamp((L2+0.01)/(L3+0.01),0.5,2.5),u_knorm); }\n"
        "  col=mix(col,0.8+0.2*(1.0-exp(-(col-0.8)/0.2)),step(0.8,col));\n"
        "  col=mix(col,max(col*0.78,c2*vec3(0.39,0.44,0.53)),night);\n"
        "  if(u_reflect>0.5 && kind==2.0) col+=alb*0.28;\n"
        "  if(u_reflect>0.5) col+=alb*vec3(0.40,0.46,0.62)*u_flash*(0.24+0.76*max(dot(Nm,vec3(-0.39,-0.50,0.77)),0.0));\n"
        "  float a=1.0;\n"
        "  if(water>0.5){\n"
        "    float hpx=v_world.z/u_zs;\n"
        "    float dep=clamp(1.0-hpx/22.0,0.0,1.0)*0.55+0.45*nt.a;\n"
        "    dep=clamp(dep+(vn(W*2.5,320.0)-0.5)*0.30+(vn(W*7.0,896.0)-0.5)*0.12,0.0,1.0);\n"
        "    vec3 shallow=alb*vec3(0.90,1.08,1.04)+vec3(0.00,0.045,0.045);\n"
        "    vec3 deep=alb*vec3(0.30,0.40,0.60);\n"
        "    col=mix(shallow,deep,smoothstep(0.0,1.0,dep))*mix(0.55,1.0,sh)*u_wtint;\n"
        "    a=0.1+0.4*dep;\n"
        "    col+=(alb*0.55+vec3(0.06,0.08,0.09))*pl+pls*0.45;\n"
        "  } else if(u_wton>0.5 && kind==2.0) a=0.75;\n"
        "  gl_FragColor=vec4(clamp(col,0.0,1.0),a);\n"
        "}\n";
    static const char *vs_sh=
        "#version 120\n attribute vec3 a_pos; uniform vec4 u_lx,u_ly,u_lz; uniform float u_zs; varying float v_d;\n"
        "void main(){ vec4 P=vec4(a_pos.xy,a_pos.z*u_zs,1.0); vec3 l=vec3(dot(u_lx,P),dot(u_ly,P),dot(u_lz,P));\n"
        "  gl_Position=vec4(l,1.0); v_d=l.z*0.5+0.5; }\n";
    static const char *fs_sh=
        "#version 120\n varying float v_d;\n"
        "void main(){ float d=clamp(v_d,0.0,1.0)*255.0; gl_FragColor=vec4(floor(d)/255.0,fract(d),1.0,1.0); }\n";
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
    static const char *fs_sky=
        "#version 120\n"
        "uniform float u_time_of_day; uniform vec3 u_sun,u_sunc;\n"
        "void main(){\n"
        "  vec2 uv=gl_TexCoord[0].xy;\n"
        "  float h=cos(u_time_of_day*6.283185307);\n"
        "  float dusk=1.0-smoothstep(0.04,0.68,abs(h)), night=smoothstep(0.0,0.66,-h);\n"
        "  vec3 horizon=mix(mix(vec3(0.14,0.27,0.36),vec3(0.56,0.24,0.13),dusk),vec3(0.09,0.15,0.28),night);\n"
        "  vec3 zenith=mix(vec3(0.09,0.20,0.34),vec3(0.034,0.062,0.145),night);\n"
        "  vec2 at=vec2(0.50+0.30*(u_sun.x-u_sun.y),0.25+u_sun.z*0.46);\n"
        "  float d=length((uv-at)*vec2(1.6,1.0));\n"
        "  float halo=0.12*exp(-17.0*d)+0.61*(1.0-smoothstep(0.010,0.020,d));\n"
        "  gl_FragColor=vec4(mix(horizon,zenith,smoothstep(0.0,1.0,uv.y))+u_sunc*halo,1.0);\n"
        "}\n";
    static const char *vs_sky=
        "#version 120\n attribute vec2 a_pos,a_uv;\n"
        "void main(){ gl_Position=vec4(a_pos,0.0,1.0); gl_TexCoord[0]=vec4(a_uv,0.0,1.0); }\n";
    static const char *vs_wave=
        "#version 120\n"
        "attribute vec3 a_pos,a_uv; uniform float u_time; varying float v_rise;\n"
        "void main(){\n"
        "  vec2 q=a_uv.xy*(6.283185307/128.0);\n"
        "  v_rise=a_uv.z*(0.51*sin(dot(q,vec2(25.0,11.0))+u_time*1.9)\n"
        "                +0.28*sin(dot(q,vec2(-13.0,21.0))-u_time*1.6));\n"
        "  vec2 p=a_pos.xy+vec2(-127.5,0.5-v_rise);\n"
        "  gl_Position=vec4(p*2.0/vec2(1024.0,640.0)-1.0,a_pos.z,1.0);\n"
        "}\n";
    static const char *fs_wave=
        "#version 120\n varying float v_rise;\n"
        "void main(){ gl_FragColor=vec4(0.5+0.5*v_rise,1.0,0.0,1.0); }\n";
    g_t3.prog_wave=tl_link(vs_wave,fs_wave);
    g_t3.prog_sky=tl_link(vs_sky,fs_sky);
    g_t3.prog_lit=tl_link(vs_lit,fs_lit);
    g_t3.prog_sh=tl_link(vs_sh,fs_sh);
    g_t3.prog_bump=tl_link(vs_q,fs_bump);
    if(!g_t3.prog_lit || !g_t3.prog_sh || !g_t3.prog_bump) goto fail;
    #define TLU(prog,var,name) g_t3.var=g_bloom.GetUniformLocation(g_t3.prog,name)
    TLU(prog_lit,l_tiles,"u_tiles"); TLU(prog_lit,l_fade,"u_fade"); TLU(prog_lit,l_lut,"u_lut"); TLU(prog_lit,l_kind,"u_kind");
    TLU(prog_lit,l_nrm,"u_nrm"); TLU(prog_lit,l_sh,"u_sh"); TLU(prog_lit,l_bump,"u_bump"); TLU(prog_lit,l_view,"u_view");
    TLU(prog_lit,l_lx,"u_lx"); TLU(prog_lit,l_ly,"u_ly"); TLU(prog_lit,l_lz,"u_lz"); TLU(prog_lit,l_zs,"u_zs");
    TLU(prog_lit,l_sun,"u_sun"); TLU(prog_lit,l_sunc,"u_sunc"); TLU(prog_lit,l_sky,"u_sky"); TLU(prog_lit,l_gnd,"u_gnd");
    TLU(prog_lit,l_shon,"u_shon"); TLU(prog_lit,l_wton,"u_wton"); TLU(prog_lit,l_mix,"u_mix"); TLU(prog_lit,l_ao,"u_ao");
    TLU(prog_lit,l_plp,"u_pt_light_pos_rad"); TLU(prog_lit,l_plc,"u_pt_light_col_int"); TLU(prog_lit,l_pln,"u_pt_light_count");
    TLU(prog_lit,l_hd,"u_hd"); TLU(prog_lit,l_hdmap,"u_hdmap"); TLU(prog_lit,l_hdon,"u_hdon"); TLU(prog_lit,l_hdsz,"u_hdsz"); TLU(prog_lit,l_hdm,"u_hdm");
    TLU(prog_lit,l_aos,"u_aos"); TLU(prog_lit,l_expo,"u_expo"); TLU(prog_lit,l_shfloor,"u_shfloor"); TLU(prog_lit,l_knorm,"u_knorm"); TLU(prog_lit,l_wtint,"u_wtint");
    TLU(prog_sh,s_lx,"u_lx"); TLU(prog_sh,s_ly,"u_ly"); TLU(prog_sh,s_lz,"u_lz"); TLU(prog_sh,s_zs,"u_zs");
    TLU(prog_bump,b_tiles,"u_tiles"); TLU(prog_bump,b_lut,"u_lut");
    TLU(prog_lit,l_reflect,"u_reflect"); TLU(prog_lit,l_water_plane,"u_water_plane");
    TLU(prog_lit,l_ring,"u_ring"); TLU(prog_lit,l_ring_off,"u_ring_off");
    TLU(prog_lit,l_time_of_day,"u_time_of_day"); TLU(prog_lit,l_flash,"u_flash");
    if(g_t3.prog_sky) {
        TLU(prog_sky,sky_phase,"u_time_of_day"); TLU(prog_sky,sky_dir,"u_sun"); TLU(prog_sky,sky_color,"u_sunc");
    } else g_t3.refl_failed=1;
    if(g_t3.prog_wave) { TLU(prog_wave,wave_time,"u_time"); }
    #undef TLU
    }
    if(g_t3.prog_wave && g_ini_terrain_3d_water && g_ini_terrain_3d_water_reflections) {
        if(bloom_make_fbo(&g_t3.wave_fbo,&g_t3.wave_tex,1024,640,GL_RGBA8))
            g_bloom.GenBuffers(3,g_t3.wave_vbo);
        else {
            g_bloom.DeleteFramebuffers(1,&g_t3.wave_fbo);
            g_bloom.DeleteTextures(1,&g_t3.wave_tex);
            g_t3.wave_fbo=g_t3.wave_tex=0;
        }
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
    g_t3.ao_tex=tl_tex(128,128,GL_LINEAR,GL_REPEAT);
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

static int tl_reflection_size(void) {
    if(g_t3.refl_failed) return 0;
    if(g_t3.refl_fbo) return 1;
    const int w=g_t3.w/2,h=g_t3.h/2;
    for(int i=0;i<3;i++) g_t3.refl[i]=tl_tex(w,h,GL_LINEAR,GL_CLAMP_TO_EDGE);
    g_bloom.GenFramebuffers(1,&g_t3.refl_fbo);
    g_bloom.BindFramebuffer(GL_FRAMEBUFFER,g_t3.refl_fbo);
    g_bloom.FramebufferTexture2D(GL_FRAMEBUFFER,GL_COLOR_ATTACHMENT0,GL_TEXTURE_2D,g_t3.refl[1],0);
    if(!g_t3.refl_rb) g_gl_mesh.GenRenderbuffers(1,&g_t3.refl_rb);
    g_gl_mesh.BindRenderbuffer(GL_RENDERBUFFER,g_t3.refl_rb);
    g_gl_mesh.RenderbufferStorage(GL_RENDERBUFFER,GL_DEPTH_COMPONENT16,w,h);
    g_gl_mesh.BindRenderbuffer(GL_RENDERBUFFER,0);
    g_gl_mesh.FramebufferRenderbuffer(GL_FRAMEBUFFER,GL_DEPTH_ATTACHMENT,GL_RENDERBUFFER,g_t3.refl_rb);
    g_t3.refl_failed=g_bloom.CheckFramebufferStatus(GL_FRAMEBUFFER)!=GL_FRAMEBUFFER_COMPLETE;
    gw_flag_trace("TRACE terrain_3d planar reflection %dx%d ok=%d%c",w,h,!g_t3.refl_failed,10);
    return !g_t3.refl_failed;
}

/* lit layer textures at scale s (s x the canvas resolution), reallocated when the window's scale changes */
static int tl_size(int s) {
    if(s<1) s=1;
    if(s>4) s=4;
    if(s==g_t3.scale && g_t3.lit[0]) return 1;
    for(int i=0;i<3;i++) if(g_t3.lit[i]) { g_bloom.DeleteTextures(1,&g_t3.lit[i]); g_t3.lit[i]=0; g_t3.lhave[i]=0; }
    for(int i=0;i<3;i++) {
        if(g_t3.refl[i]) g_bloom.DeleteTextures(1,&g_t3.refl[i]);
        g_t3.refl[i]=0; g_t3.refl_have[i]=0;
    }
    if(g_t3.refl_fbo) g_bloom.DeleteFramebuffers(1,&g_t3.refl_fbo);
    g_t3.refl_fbo=0;
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
    t=g_t3.refl[0]; g_t3.refl[0]=g_t3.refl[1]; g_t3.refl[1]=g_t3.refl[2]; g_t3.refl[2]=t;
    g_t3.refl_have[0]=g_t3.refl_have[1]; g_t3.refl_have[1]=0;
    t=g_t3.wave_vbo[0]; g_t3.wave_vbo[0]=g_t3.wave_vbo[1]; g_t3.wave_vbo[1]=g_t3.wave_vbo[2]; g_t3.wave_vbo[2]=t;
    g_t3.wave_n[0]=g_t3.wave_n[1]; g_t3.wave_n[1]=0;
    g_t3.layer_night[0]=g_t3.layer_night[1];
    memcpy(g_t3.layer_sun[0],g_t3.layer_sun[1],sizeof g_t3.layer_sun[0]);
    memcpy(g_t3.layer_sunc[0],g_t3.layer_sunc[1],sizeof g_t3.layer_sunc[0]);
    memcpy(g_t3.layer_sky[0],g_t3.layer_sky[1],sizeof g_t3.layer_sky[0]);
}

static inline int tl_hpx(const gw_terrain_mesh_draw *d,int col,int row) {
    return gw_terrain_mesh_height_step(d->planet_h[((unsigned)row&127u)*128u+((unsigned)col&127u)])*d->height_scale;
}

/* normals (smooth: central differences of the grid, wrapping) and sea depth (distance from land through the cells at
   or below the sea surface, in cells, 0 at the shore .. 1 at 5 cells), only when the grid changes */
static void tl_planet(const gw_terrain_mesh_draw *d) {
    if(g_t3.nrm_ok && g_t3.hs_last==d->height_scale && !memcmp(g_t3.last_h,d->planet_h,sizeof g_t3.last_h)) return;
    memcpy(g_t3.last_h,d->planet_h,sizeof g_t3.last_h); g_t3.hs_last=d->height_scale;
    static uint8_t px[128u*128u*4u]; static uint16_t q[128u*128u];
    uint8_t *dist=g_t3.sea_dist;
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
    /* cavity / valley AO: how far the surrounding terrain (rings of radius 1, 2 and 3 cells) rises above the cell */
    static uint8_t aopx[128u*128u*4u];
    for(int r=0;r<128;r++) for(int c=0;c<128;c++) {
        const float h=(float)tl_hpx(d,c,r); float occ=0.0f;
        static const float wr[4]={0.0f,0.50f,0.32f,0.18f};
        for(int k=1;k<=3;k++) {
            float m=0.0f; int n=0;
            for(int j=-k;j<=k;j++) for(int i=-k;i<=k;i++) if((i==-k||i==k||j==-k||j==k)) { m+=(float)tl_hpx(d,c+i,r+j); n++; }
            const float rise=m/(float)n-h;
            if(rise>0.0f) occ+=wr[k]*rise/(float)k;
        }
        float v=1.0f-occ*0.075f; if(v<0.30f) v=0.30f;
        if(v>1.0f) v=1.0f;
        uint8_t *o=aopx+((size_t)r*128u+(size_t)c)*4u; o[0]=o[1]=o[2]=(uint8_t)(v*255.0f+0.5f); o[3]=255;
    }
    g_bloom.BindTexture(GL_TEXTURE_2D,g_t3.ao_tex);
    g_bloom.TexSubImage2D(GL_TEXTURE_2D,0,0,0,128,128,GL_RGBA,GL_UNSIGNED_BYTE,aopx);
    g_t3.nrm_ok=1;
}

/* The water surface follows the terrain mesh's shared vertices. Store only triangles touching
   deep water, and keep the two snapshots used by the interpolated camera. */
static void tl_wave_upload(const gw_terrain_mesh_draw *d) {
    if(!g_t3.wave_vbo[1]) return;
    static float data[3u*GW_TERRAIN_GPU_FIXTURE_CAP][6];
    unsigned n=0;
    for(unsigned i=0;i<d->count;i+=3) {
        const gw_terrain_mesh_vertex *tri=d->vertex+i;
        if(tri->mode>5.5f) continue;
        float depth[3];
        for(int j=0;j<3;j++) {
            const unsigned c=(unsigned)((int)tri[j].wx+d->view_col)&127u;
            const unsigned r=(unsigned)((int)tri[j].wy+d->view_row)&127u;
            depth[j]=atm_smooth(2.0f,5.0f,(float)g_t3.sea_dist[r*128u+c]);
        }
        if(depth[0]+depth[1]+depth[2]==0.0f) continue;
        for(int j=0;j<3;j++,n++) {
            data[n][0]=tri[j].x; data[n][1]=tri[j].y; data[n][2]=tri[j].depth;
            data[n][3]=tri[j].wx+(float)(d->view_col&127);
            data[n][4]=tri[j].wy+(float)(d->view_row&127);
            data[n][5]=depth[j];
        }
    }
    g_t3.wave_n[1]=n;
    if(n) {
        g_bloom.BindBuffer(GL_ARRAY_BUFFER,g_t3.wave_vbo[1]);
        g_bloom.BufferData(GL_ARRAY_BUFFER,n*sizeof data[0],data,GL_STREAM_DRAW);
    }
}

/* The displacement field is rasterised from the moving vertices at presentation rate.
   It carries screen-space height in R and coverage in G. Black decodes to zero height. */
static int tl_wave_render(int layer,float time) {
    if(!g_t3.wave_n[layer]) return 0;
    g_bloom.BindFramebuffer(GL_FRAMEBUFFER,g_t3.wave_fbo);
    g_bloom.Viewport(0,0,1024,640);
    g_bloom.Disable(GL_SCISSOR_TEST);
    g_bloom.ClearColor(0.0f,0.0f,0.0f,1.0f);
    g_bloom.Clear(GL_COLOR_BUFFER_BIT);
    g_bloom.UseProgram(g_t3.prog_wave);
    g_bloom.Uniform1f(g_t3.wave_time,time);
    g_bloom.BindBuffer(GL_ARRAY_BUFFER,g_t3.wave_vbo[layer]);
    const GLsizei stride=6*(GLsizei)sizeof(float);
    g_bloom.VertexAttribPointer(0,3,GL_FLOAT,GL_FALSE,stride,(const void *)0);
    g_bloom.VertexAttribPointer(1,3,GL_FLOAT,GL_FALSE,stride,(const void *)(3*sizeof(float)));
    g_bloom.DrawArrays(GL_TRIANGLES,0,(GLsizei)g_t3.wave_n[layer]);
    g_bloom.BindBuffer(GL_ARRAY_BUFFER,g_bloom.vbo);
    g_bloom.VertexAttribPointer(0,2,GL_FLOAT,GL_FALSE,stride,(const void *)0);
    g_bloom.VertexAttribPointer(1,2,GL_FLOAT,GL_FALSE,stride,(const void *)(2*sizeof(float)));
    return 1;
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
    g_bloom.ClearColor(0.0f,0.0f,0.0f,1.0f);
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

/* ---- terrain_3d_hd_tiles: optional HD overrides of the B32 terrain tiles -----------------------------------------
   <dir>/<BANK>/atlas.png (8 tiles wide, square tiles of S px, bank order) or <dir>/<BANK>/tile_NNN.png, dir =
   terrain_3d_hd_dir or hd_textures next to the exe. Decoded, assembled and mipmapped on a worker thread; uploaded a
   few rows per game frame (no stall); until then, and when absent, the original B32 texels are used unchanged. */
#ifndef GL_TEXTURE_MAX_LEVEL
#define GL_TEXTURE_MAX_LEVEL 0x813D
#endif
#ifndef GL_LINEAR_MIPMAP_LINEAR
#define GL_LINEAR_MIPMAP_LINEAR 0x2703
#endif
#ifndef GL_TEXTURE_MAX_ANISOTROPY_EXT
#define GL_TEXTURE_MAX_ANISOTROPY_EXT 0x84FE
#endif
enum { HD_MAX_TILE=256, HD_MAX_TILES=512, HD_LEVELS=10 };
static struct {
    int state;                 /* 0 idle, 1 loading (worker), 2 uploading, 3 ready, 4 none for this bank */
    char bank[8],path[640];
    SDL_atomic_t done;         /* worker result: 1 ok, -1 nothing usable */
    int S,rows,levels,up_level,up_row;
    uint8_t *mip[HD_LEVELS]; int mw[HD_LEVELS],mh[HD_LEVELS];
    uint8_t valid[HD_MAX_TILES];
    GLuint tex,map_tex;
    uint32_t map_key[259]; int map_valid;
} g_hd;
static void hd_free_cpu(void) { for(int i=0;i<HD_LEVELS;i++) { free(g_hd.mip[i]); g_hd.mip[i]=NULL; } }
/* box-resamples a w x h RGBA image to S x S into dst (tile of the atlas, stride sw pixels) */
static void hd_put_tile(uint8_t *dst,int sw,const uint8_t *src,int w,int h,int S) {
    for(int y=0;y<S;y++) for(int x=0;x<S;x++) {
        const int x0=x*w/S,x1=((x+1)*w+S-1)/S,y0=y*h/S,y1=((y+1)*h+S-1)/S; unsigned acc[4]={0,0,0,0},n=0;
        for(int yy=y0;yy<y1;yy++) for(int xx=x0;xx<x1;xx++) { const uint8_t *p=src+((size_t)yy*w+xx)*4u; for(int c=0;c<4;c++) acc[c]+=p[c]; n++; }
        uint8_t *o=dst+((size_t)y*sw+x)*4u; for(int c=0;c<4;c++) o[c]=(uint8_t)((acc[c]+n/2u)/n);
    }
}
static int SDLCALL hd_worker(void *unused) {
    (void)unused;
    char fn[700]; int w=0,h=0,S=0,rows=0;
    uint8_t *atlas=NULL;
    snprintf(fn,sizeof fn,"%s\\atlas.png",g_hd.path);
    uint8_t *img=gw_png_load(fn,&w,&h);
    memset(g_hd.valid,0,sizeof g_hd.valid);
    if(img && w%8==0 && h%(w/8)==0) {
        const int src_s=w/8; rows=h/src_s; S=src_s>HD_MAX_TILE?HD_MAX_TILE:src_s;
        if(rows*8>HD_MAX_TILES) rows=HD_MAX_TILES/8;
        if(S==src_s) { atlas=img; img=NULL; }
        else if((atlas=(uint8_t *)malloc((size_t)8*S*rows*S*4u))) {
            uint8_t *tile=(uint8_t *)malloc((size_t)src_s*src_s*4u);
            for(int t=0;tile && t<rows*8;t++) {
                for(int y=0;y<src_s;y++) memcpy(tile+(size_t)y*src_s*4u,img+(((size_t)(t/8)*src_s+y)*w+(size_t)(t%8)*src_s)*4u,(size_t)src_s*4u);
                hd_put_tile(atlas+(((size_t)(t/8)*S)*8u*S+(size_t)(t%8)*S)*4u,8*S,tile,src_s,src_s,S);
            }
            free(tile);
        }
        memset(g_hd.valid,1,(size_t)rows*8);
    } else {
        int last=-1;
        for(int t=0;t<HD_MAX_TILES;t++) {
            snprintf(fn,sizeof fn,"%s\\tile_%03d.png",g_hd.path,t);
            int tw=0,th=0; uint8_t *ti=gw_png_load(fn,&tw,&th);
            if(!ti) continue;
            if(!S) { S=tw<th?tw:th; if(S>HD_MAX_TILE) S=HD_MAX_TILE; if(S<8) { free(ti); S=0; break; }
                rows=HD_MAX_TILES/8; atlas=(uint8_t *)calloc((size_t)8*S*rows*S,4u); if(!atlas) { free(ti); break; } }
            hd_put_tile(atlas+(((size_t)(t/8)*S)*8u*S+(size_t)(t%8)*S)*4u,8*S,ti,tw,th,S);
            free(ti); g_hd.valid[t]=1; last=t;
        }
        rows=last>=0?last/8+1:0;
    }
    free(img);
    if(!atlas || !S || !rows) { free(atlas); SDL_AtomicSet(&g_hd.done,-1); return 0; }
    /* mip chain (2x2 box), down to 4 px per tile so neighbouring tiles never blend */
    int lw=8*S,lh=rows*S,n=0; g_hd.mip[0]=atlas; g_hd.mw[0]=lw; g_hd.mh[0]=lh;
    while(n+1<HD_LEVELS && (S>>(n+1))>=4) {
        const int nw=lw/2,nh=lh/2; uint8_t *m=(uint8_t *)malloc((size_t)nw*nh*4u); if(!m) break;
        const uint8_t *s=g_hd.mip[n];
        for(int y=0;y<nh;y++) for(int x=0;x<nw;x++) for(int c=0;c<4;c++) {
            const uint8_t *p=s+((size_t)(2*y)*lw+2*x)*4u+c;
            m[((size_t)y*nw+x)*4u+c]=(uint8_t)((p[0]+p[4]+p[(size_t)lw*4u]+p[(size_t)lw*4u+4u]+2)>>2);
        }
        n++; g_hd.mip[n]=m; g_hd.mw[n]=nw; g_hd.mh[n]=nh; lw=nw; lh=nh;
    }
    g_hd.levels=n+1; g_hd.S=S; g_hd.rows=rows;
    SDL_AtomicSet(&g_hd.done,1);
    return 0;
}
/* once per game frame: start loading the bank's HD pack, upload a slice, or nothing */
static void hd_service(const gw_terrain_mesh_draw *d) {
    if(!g_ini_terrain_3d_hd_tiles || !d->b32_name[0]) return;
    if(strcmp(g_hd.bank,d->b32_name)) {
        if(g_hd.state==1) return;                          /* the worker finishes the previous bank first */
        hd_free_cpu(); g_hd.state=4; g_hd.map_valid=0;
        snprintf(g_hd.bank,sizeof g_hd.bank,"%s",d->b32_name);
        char base[600];
        if(g_ini_terrain_3d_hd_dir[0]) snprintf(base,sizeof base,"%s",g_ini_terrain_3d_hd_dir);
        else { char exe[MAX_PATH]; DWORD n=GetModuleFileNameA(NULL,exe,MAX_PATH); while(n && exe[n-1]!='\\' && exe[n-1]!='/') n--;
            exe[n]=0; snprintf(base,sizeof base,"%shd_textures",exe); }
        snprintf(g_hd.path,sizeof g_hd.path,"%s\\%s",base,g_hd.bank);
        const DWORD at=GetFileAttributesA(g_hd.path);
        if(at==INVALID_FILE_ATTRIBUTES || !(at&FILE_ATTRIBUTE_DIRECTORY)) {
            gw_flag_trace("TRACE terrain_3d hd_tiles none for %s (%s)%c",g_hd.bank,g_hd.path,10); return; }
        SDL_AtomicSet(&g_hd.done,0); g_hd.state=1;
        SDL_Thread *th=SDL_CreateThread(hd_worker,"gw_hd_tiles",NULL);
        if(th) SDL_DetachThread(th); else g_hd.state=4;
        gw_flag_trace("TRACE terrain_3d hd_tiles loading %s%c",g_hd.path,10);
        return;
    }
    if(g_hd.state==1) {
        const int r=SDL_AtomicGet(&g_hd.done);
        if(!r) return;
        if(r<0) { g_hd.state=4; gw_flag_trace("TRACE terrain_3d hd_tiles nothing usable in %s%c",g_hd.path,10); return; }
        if(!g_hd.tex) g_bloom.GenTextures(1,&g_hd.tex);
        g_bloom.BindTexture(GL_TEXTURE_2D,g_hd.tex);
        g_bloom.PixelStorei(GL_UNPACK_ALIGNMENT,4); g_bloom.PixelStorei(GL_UNPACK_ROW_LENGTH,0);
        for(int l=0;l<g_hd.levels;l++) g_bloom.TexImage2D(GL_TEXTURE_2D,l,GL_RGBA8,g_hd.mw[l],g_hd.mh[l],0,GL_RGBA,GL_UNSIGNED_BYTE,NULL);
        g_bloom.TexParameteri(GL_TEXTURE_2D,GL_TEXTURE_MAX_LEVEL,g_hd.levels-1);
        g_bloom.TexParameteri(GL_TEXTURE_2D,GL_TEXTURE_MIN_FILTER,GL_LINEAR_MIPMAP_LINEAR); g_bloom.TexParameteri(GL_TEXTURE_2D,GL_TEXTURE_MAG_FILTER,GL_LINEAR);
        g_bloom.TexParameteri(GL_TEXTURE_2D,GL_TEXTURE_WRAP_S,GL_CLAMP_TO_EDGE); g_bloom.TexParameteri(GL_TEXTURE_2D,GL_TEXTURE_WRAP_T,GL_CLAMP_TO_EDGE);
        if(SDL_GL_ExtensionSupported("GL_EXT_texture_filter_anisotropic")) g_bloom.TexParameteri(GL_TEXTURE_2D,GL_TEXTURE_MAX_ANISOTROPY_EXT,8);
        g_hd.up_level=0; g_hd.up_row=0; g_hd.state=2;
        gw_flag_trace("TRACE terrain_3d hd_tiles %s decoded: tile %dpx, %d rows, %d mip levels%c",g_hd.bank,g_hd.S,g_hd.rows,g_hd.levels,10);
        return;
    }
    if(g_hd.state==2) {   /* about 2 MB per game frame */
        g_bloom.BindTexture(GL_TEXTURE_2D,g_hd.tex);
        g_bloom.PixelStorei(GL_UNPACK_ALIGNMENT,4); g_bloom.PixelStorei(GL_UNPACK_ROW_LENGTH,0);
        size_t budget=2u<<20;
        while(budget && g_hd.up_level<g_hd.levels) {
            const int l=g_hd.up_level,w=g_hd.mw[l],h=g_hd.mh[l];
            int n=(int)(budget/((size_t)w*4u)); if(n<1) n=1;
            if(n>h-g_hd.up_row) n=h-g_hd.up_row;
            g_bloom.TexSubImage2D(GL_TEXTURE_2D,l,0,g_hd.up_row,w,n,GL_RGBA,GL_UNSIGNED_BYTE,g_hd.mip[l]+(size_t)g_hd.up_row*w*4u);
            g_hd.up_row+=n; budget=budget>(size_t)n*w*4u?budget-(size_t)n*w*4u:0;
            if(g_hd.up_row>=h) { g_hd.up_level++; g_hd.up_row=0; }
        }
        if(g_hd.up_level>=g_hd.levels) { hd_free_cpu(); g_hd.state=3; g_hd.map_valid=0;
            gw_flag_trace("TRACE terrain_3d hd_tiles %s ready (%dx%d)%c",g_hd.bank,8*g_hd.S,g_hd.rows*g_hd.S,10); }
    }
}
/* per atlas slot: where its texels sit in the bank (x, y in bank pixels) when the HD pack has that tile */
static void hd_slot_map(const gw_terrain_mesh_draw *d) {
    if(!g_hd.map_tex) { g_hd.map_tex=tl_tex(259,1,GL_NEAREST,GL_CLAMP_TO_EDGE); g_hd.map_valid=0; }
    if(g_hd.map_valid && !memcmp(g_hd.map_key,d->tile_addr,sizeof(uint32_t)*(d->tiles<259u?d->tiles:259u))) return;
    uint8_t m[259u*4u]; memset(m,0,sizeof m);
    const uint32_t bank_bytes=(uint32_t)g_hd.rows*32u*256u;
    for(unsigned i=0;i<d->tiles && i<259u;i++) {
        const uint32_t a=d->tile_addr[i];
        if(a<d->b32_base || a-d->b32_base>=bank_bytes) continue;
        const uint32_t rel=a-d->b32_base,x=rel%256u,y=rel/256u;
        if(x+32u>256u || y+32u>(uint32_t)g_hd.rows*32u || !g_hd.valid[(y/32u)*8u+x/32u]) continue;
        m[i*4u]=(uint8_t)x; m[i*4u+1]=(uint8_t)(y&255u); m[i*4u+2]=(uint8_t)(y>>8); m[i*4u+3]=255u;
    }
    g_bloom.BindTexture(GL_TEXTURE_2D,g_hd.map_tex);
    g_bloom.PixelStorei(GL_UNPACK_ALIGNMENT,4); g_bloom.PixelStorei(GL_UNPACK_ROW_LENGTH,0);
    g_bloom.TexSubImage2D(GL_TEXTURE_2D,0,0,0,259,1,GL_RGBA,GL_UNSIGNED_BYTE,m);
    memcpy(g_hd.map_key,d->tile_addr,sizeof(uint32_t)*(d->tiles<259u?d->tiles:259u)); g_hd.map_valid=1;
}

/* once per game frame, after terrain_gl_render (the tile atlas and the mesh VBO are current): the lit layer */
static int tl_render(const gw_terrain_mesh_draw *d,int scale) {
    if(!d || !d->count || !tl_init() || !tl_size(scale)) return 0;
    g_gl_mesh.PushAttrib(GL_DEPTH_BUFFER_BIT|GL_ENABLE_BIT|GL_VIEWPORT_BIT);
    g_bloom.Disable(GL_CULL_FACE); g_bloom.Disable(GL_DITHER); g_bloom.Disable(GL_BLEND); g_bloom.Disable(GL_SCISSOR_TEST);
    g_bloom.Enable(GL_DEPTH_TEST);
    g_gl_mesh.DepthFunc(GL_LESS); g_gl_mesh.DepthMask(GL_TRUE); g_gl_mesh.ClearDepth(1.0);
    g_bloom.ActiveTexture(GL_TEXTURE0);
    g_bloom.PixelStorei(GL_UNPACK_ROW_LENGTH,0);
    const int waves=g_ini_terrain_3d_water && g_ini_terrain_3d_water_reflections;
    const int reflection=waves && tl_reflection_size();
    tl_atmosphere();
    tl_planet(d);
    tl_wave_upload(d);
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
    g_t3.refl_have[1]=reflection;
    g_bloom.BindFramebuffer(GL_FRAMEBUFFER,g_t3.fbo);
    g_bloom.FramebufferTexture2D(GL_FRAMEBUFFER,GL_COLOR_ATTACHMENT0,GL_TEXTURE_2D,g_t3.lit[1],0);
    g_bloom.Viewport(0,0,g_t3.w,g_t3.h);
    g_bloom.Clear(GL_DEPTH_BUFFER_BIT);
    bloom_fill_buffer(0.0f,0.0f);
    if(reflection) {
        g_bloom.BindFramebuffer(GL_FRAMEBUFFER,g_t3.refl_fbo);
        g_bloom.FramebufferTexture2D(GL_FRAMEBUFFER,GL_COLOR_ATTACHMENT0,GL_TEXTURE_2D,g_t3.refl[1],0);
        g_bloom.Viewport(0,0,g_t3.w/2,g_t3.h/2);
        g_bloom.ClearColor(0.0f,0.0f,0.0f,1.0f);
        g_bloom.Clear(GL_COLOR_BUFFER_BIT|GL_DEPTH_BUFFER_BIT);
        g_bloom.UseProgram(g_t3.prog_sky);
        g_bloom.Uniform1f(g_t3.sky_phase,g_atmosphere.time_of_day);
        g_t3.Uniform3f(g_t3.sky_dir,g_t3.sun[0],g_t3.sun[1],g_t3.sun[2]);
        g_t3.Uniform3f(g_t3.sky_color,g_t3.sunc[0],g_t3.sunc[1],g_t3.sunc[2]);
        bloom_draw_quad(-1.0f,-1.0f,1.0f,1.0f, 0.0f,0.0f,1.0f,1.0f, 0.0f,0.0f,1.0f,1.0f);
    }
    g_bloom.Enable(GL_DEPTH_TEST);
    g_bloom.UseProgram(g_t3.prog_lit);
    g_bloom.ActiveTexture(GL_TEXTURE0); g_bloom.BindTexture(GL_TEXTURE_2D,g_gl_mesh.tiles); g_bloom.Uniform1i(g_t3.l_tiles,0);
    g_bloom.ActiveTexture(GL_TEXTURE1); g_bloom.BindTexture(GL_TEXTURE_2D,g_gl_mesh.fade); g_bloom.Uniform1i(g_t3.l_fade,1);
    g_bloom.ActiveTexture(GL_TEXTURE2); g_bloom.BindTexture(GL_TEXTURE_2D,g_bloom.lut_tex); g_bloom.Uniform1i(g_t3.l_lut,2);
    g_bloom.ActiveTexture(GL_TEXTURE3); g_bloom.BindTexture(GL_TEXTURE_2D,g_gm.t_kind); g_bloom.Uniform1i(g_t3.l_kind,3);
    g_bloom.ActiveTexture(GL_TEXTURE4); g_bloom.BindTexture(GL_TEXTURE_2D,g_t3.nrm_tex); g_bloom.Uniform1i(g_t3.l_nrm,4);
    g_bloom.ActiveTexture(GL_TEXTURE5); g_bloom.BindTexture(GL_TEXTURE_2D,g_t3.sh_tex); g_bloom.Uniform1i(g_t3.l_sh,5);
    g_bloom.ActiveTexture(GL_TEXTURE6); g_bloom.BindTexture(GL_TEXTURE_2D,g_t3.bump_tex); g_bloom.Uniform1i(g_t3.l_bump,6);
    g_bloom.ActiveTexture(GL_TEXTURE7); g_bloom.BindTexture(GL_TEXTURE_2D,g_t3.ao_tex); g_bloom.Uniform1i(g_t3.l_ao,7);
    g_bloom.ActiveTexture(GL_TEXTURE0+10); g_bloom.BindTexture(GL_TEXTURE_2D,g_gm.t_ring);
    g_bloom.Uniform1i(g_t3.l_ring,10);
    g_bloom.Uniform2f(g_t3.l_ring_off,(float)(g_gm.ring_x-128),(float)g_gm.ring_y);
    g_bloom.Uniform1f(g_t3.l_water_plane,8.0f*(float)d->height_scale);
    g_bloom.Uniform1f(g_t3.l_time_of_day,g_atmosphere.time_of_day);
    g_bloom.Uniform1f(g_t3.l_flash,g_atmosphere.flash);
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
    g_bloom.Uniform1f(g_t3.l_mix,0.90f);
    g_bloom.Uniform1f(g_t3.l_aos,g_t3.aos); g_bloom.Uniform1f(g_t3.l_expo,g_t3.expo); g_bloom.Uniform1f(g_t3.l_shfloor,g_t3.shfloor); g_bloom.Uniform1f(g_t3.l_knorm,g_t3.knorm);
    g_t3.Uniform3f(g_t3.l_wtint,g_t3.wtint[0],g_t3.wtint[1],g_t3.wtint[2]);
    {   /* HD overrides */
        hd_service(d);
        const int hd=g_hd_on && g_ini_terrain_3d_hd_tiles && g_hd.state==3 && !strcmp(g_hd.bank,d->b32_name);
        if(hd) { hd_slot_map(d);
            g_bloom.ActiveTexture(GL_TEXTURE8); g_bloom.BindTexture(GL_TEXTURE_2D,g_hd.tex); g_bloom.Uniform1i(g_t3.l_hd,8);
            g_bloom.ActiveTexture(GL_TEXTURE9); g_bloom.BindTexture(GL_TEXTURE_2D,g_hd.map_tex); g_bloom.Uniform1i(g_t3.l_hdmap,9);
            g_bloom.ActiveTexture(GL_TEXTURE0);
            g_bloom.Uniform2f(g_t3.l_hdsz,256.0f,(float)(g_hd.rows*32));
            g_bloom.Uniform1f(g_t3.l_hdm,16.0f/(float)g_hd.S); }
        g_bloom.Uniform1f(g_t3.l_hdon,hd?1.0f:0.0f);
        /* point lights */
        const int n=(g_pl_on && g_ini_terrain_3d_lights)?g_t3.pl_n:0;
        if(n) { g_t3.Uniform4fv(g_t3.l_plp,n,&g_t3.pl_pos[0][0]); g_t3.Uniform4fv(g_t3.l_plc,n,&g_t3.pl_col[0][0]); }
        g_bloom.Uniform1i(g_t3.l_pln,n);
        g_bloom.ActiveTexture(GL_TEXTURE0); g_bloom.BindTexture(GL_TEXTURE_2D,g_gl_mesh.tiles);
    }
    /* HD streaming can bind its own target while servicing a new atlas. */
    if(reflection) g_bloom.BindFramebuffer(GL_FRAMEBUFFER,g_t3.refl_fbo);
    g_bloom.BindBuffer(GL_ARRAY_BUFFER,g_gl_mesh.vbo);   /* uploaded by terrain_gl_render this game frame */
    g_bloom.BindBuffer(GL_ELEMENT_ARRAY_BUFFER,g_gl_mesh.ibo);
    const GLsizei stride=sizeof d->vertex[0];
    g_bloom.VertexAttribPointer(0,3,GL_FLOAT,GL_FALSE,stride,(const void *)offsetof(gw_terrain_mesh_vertex,x));
    g_bloom.VertexAttribPointer(1,3,GL_FLOAT,GL_FALSE,stride,(const void *)offsetof(gw_terrain_mesh_vertex,u));
    g_bloom.VertexAttribPointer(2,2,GL_FLOAT,GL_FALSE,stride,(const void *)offsetof(gw_terrain_mesh_vertex,tile));
    g_bloom.EnableVertexAttribArray(3);
    g_bloom.VertexAttribPointer(3,3,GL_FLOAT,GL_FALSE,stride,(const void *)offsetof(gw_terrain_mesh_vertex,wx));
    if(reflection) {
        g_bloom.Uniform1f(g_t3.l_reflect,1.0f);
        g_gl_mesh.DrawElements(GL_TRIANGLES,(GLsizei)d->count,GL_UNSIGNED_SHORT,0);
    }
    g_bloom.BindFramebuffer(GL_FRAMEBUFFER,g_t3.fbo);
    g_bloom.Viewport(0,0,g_t3.w,g_t3.h);
    g_bloom.Uniform1f(g_t3.l_reflect,0.0f);
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
    g_t3.layer_night[1]=g_t3.night;
    memcpy(g_t3.layer_sun[1],g_t3.sun,sizeof g_t3.sun);
    memcpy(g_t3.layer_sunc[1],g_t3.sunc,sizeof g_t3.sunc);
    memcpy(g_t3.layer_sky[1],g_t3.sky,sizeof g_t3.sky);
    g_t3.lview[1][0]=vc; g_t3.lview[1][1]=vr; g_t3.lhave[1]=1;
    return 1;
}

#endif
