#ifndef GW_FREECAM_GL_H
#define GW_FREECAM_GL_H

/* 360-degree Populous-style free camera, planetary horizon curve, starry sky,
   cylindrical 3D entity billboards, reprojected world indicators, and exact 3D
   mouse raycasting. All state lives on the host; zero writes to guest RAM. */

#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

typedef struct gw_fc_pick_quad {
    float cx,cy,cz;        /* curved bottom-center world position */
    float hw,hh;           /* half-width along cam_right, full height along +Z */
    float draw_cx,draw_cy; /* classic 1152x640 canvas pick coordinate */
    float u0,v0,u1,v1;     /* atlas UV for alpha hit-test if needed */
    uint32_t entity_address;
} gw_fc_pick_quad;

typedef struct gw_fc_tvert {
    float wx,wy,wz;
    float u,v;
    float tile,mode,shade,explore;
} gw_fc_tvert;

typedef struct gw_fc_evert {
    float wx,wy,wz;
    float right_off,up_off;
    float u,v,mode;
} gw_fc_evert;

typedef struct gw_fc_ivert {
    float wx,wy,wz;
    float right_off,up_off;
    float iu,iv;
} gw_fc_ivert;

enum {
    GW_FC_RADIUS = 40,
    GW_FC_MAX_TVERTS = (2*GW_FC_RADIUS+1)*(2*GW_FC_RADIUS+1)*12,
    GW_FC_MAX_EVERTS = 65536,
    GW_FC_MAX_IVERTS = 512*6,
    GW_FC_MAX_PICKS = 384
};

static struct {
    int loaded,ready,failed;
    double yaw_deg,yaw_target;
    double pitch_deg,pitch_target;
    uint64_t anim_t;
    int dragging,alt_drag,last_x,last_y;
    LONG hold_mask; /* bit0:Q(ccw) bit1:E(cw) bit2:R(up) bit3:F(down) */
    int qa_stage;
    char qa_name[96];

    /* Camera basis & projection from last rendered frame (also used by 3D raycasting) */
    float eye[3],fwd[3],right[3],up[3],tgt[3];
    float dist,fov_tan,aspect,curve_k,mvp[16];
    float view_col,view_row;
    int has_cam,last_vw,last_mw,last_mh;
    gw_fc_pick_quad picks[GW_FC_MAX_PICKS];
    int pick_n;

    /* GL resources */
    GLuint fbo,color_tex,depth_rb;
    int fbo_w,fbo_h;
    GLuint terrain_vbo,entity_vbo,ind_vbo;
    GLuint b32_tex,uv_tex,explore_tex,hd_map_tex;
    uint32_t bank_ver,hd_map_ver;
    uint64_t terrain_gen,explore_gen;
    int terrain_ic,terrain_ir,terrain_nverts;

    GLuint prog_sky,prog_terrain,prog_entity,prog_ind,prog_blit;
    GLint sk_right,sk_up,sk_fwd,sk_fov,sk_asp;
    GLint tr_mvp,tr_cc,tr_ck,tr_zs,tr_view,tr_tiles,tr_fade,tr_lut,tr_kind,tr_nrm,tr_ao,tr_sh,tr_bump;
    GLint tr_lx,tr_ly,tr_lz,tr_sun,tr_sunc,tr_sky,tr_gnd,tr_wtint,tr_aos,tr_expo,tr_shfloor,tr_knorm;
    GLint tr_shon,tr_wton,tr_hdon,tr_hd,tr_hdmap,tr_hdsz,tr_hdm,tr_plp,tr_plc,tr_pln;
    GLint tr_camr,tr_curve_rim,tr_time;
    GLint en_mvp,en_cc,en_ck,en_camr,en_sprites,en_explore,en_vorig;
    GLint in_mvp,in_cc,in_ck,in_camr,in_idx,in_lut;
    GLint bl_tex;

    void (APIENTRYP UniformMatrix4fv)(GLint,GLsizei,GLboolean,const GLfloat *);
    void (APIENTRYP DeleteRenderbuffers)(GLsizei,const GLuint *);
} g_fc = { .pitch_deg = 30.0, .pitch_target = 30.0 };

static int freecam_is_alt_drag(void) { return g_fc.alt_drag; }

static int freecam_enabled(void) {
    return g_cli_play_mode && !g_terrain_modern_backend && g_terrain_3d && g_native_entities &&
           g_ini_terrain_3d_freecam && g_canvas_live;
}

static int freecam_active_angle(void) {
    return freecam_enabled() && (fabs(g_fc.yaw_deg)>0.02 || fabs(g_fc.pitch_deg-30.0)>0.02);
}

static int freecam_active(void) {
    return freecam_active_angle() && g_fc.ready && g_gm.lit_applied && !g_fc.failed;
}

static void freecam_wrap_yaw(double *y) {
    while(*y>=180.0) *y-=360.0;
    while(*y<-180.0) *y+=360.0;
}

static void freecam_reset(void) {
    g_fc.yaw_target=0.0;
    g_fc.pitch_target=30.0;
}

static void freecam_snap_now(double yaw,double pitch) {
    freecam_wrap_yaw(&yaw);
    if(pitch<12.0) pitch=12.0; if(pitch>65.0) pitch=65.0;
    g_fc.yaw_deg=g_fc.yaw_target=yaw;
    g_fc.pitch_deg=g_fc.pitch_target=pitch;
}

static double freecam_yaw_deg(void) { return g_fc.yaw_deg; }

static void freecam_tick(void) {
    static int qa_init;
    if(!qa_init) {
        qa_init=1;
        const char *sy=getenv("GW_QA_YAW_DEG"),*sp=getenv("GW_QA_PITCH_DEG");
        if((sy && sy[0]) || (sp && sp[0])) {
            const double y=sy&&sy[0]?atof(sy):0.0, p=sp&&sp[0]?atof(sp):30.0;
            freecam_snap_now(y,p);
            gw_flag_trace("TRACE freecam qa_angle yaw=%.2f pitch=%.2f%c",g_fc.yaw_deg,g_fc.pitch_deg,10);
        }
    }
    const uint64_t now=SDL_GetPerformanceCounter();
    double dt=g_fc.anim_t && g_interactive_perf_frequency?(double)(now-g_fc.anim_t)/(double)g_interactive_perf_frequency:0.0;
    g_fc.anim_t=now;
    if(dt>0.08) dt=0.08;
    if(!freecam_enabled()) {
        InterlockedExchange(&g_fc_want_expanded,0);
        return;
    }
    const LONG h=InterlockedCompareExchange(&g_fc.hold_mask,0,0);
    if(h && dt>0.0) {
        if(h&1L) g_fc.yaw_target-=95.0*dt;
        if(h&2L) g_fc.yaw_target+=95.0*dt;
        if(h&4L) g_fc.pitch_target+=42.0*dt;
        if(h&8L) g_fc.pitch_target-=42.0*dt;
        freecam_wrap_yaw(&g_fc.yaw_target);
        if(g_fc.pitch_target<12.0) g_fc.pitch_target=12.0;
        if(g_fc.pitch_target>65.0) g_fc.pitch_target=65.0;
    }
    if(dt>0.0) {
        const double k=fmin(1.0,dt*18.0);
        double dy=g_fc.yaw_target-g_fc.yaw_deg;
        while(dy>180.0) dy-=360.0;
        while(dy<-180.0) dy+=360.0;
        g_fc.yaw_deg+=dy*k;
        freecam_wrap_yaw(&g_fc.yaw_deg);
        g_fc.pitch_deg+=(g_fc.pitch_target-g_fc.pitch_deg)*k;
        if(fabs(dy)<0.015 && fabs(g_fc.yaw_target)<0.015 && !(h&3L)) g_fc.yaw_deg=0.0;
        if(fabs(g_fc.pitch_target-g_fc.pitch_deg)<0.015 && fabs(g_fc.pitch_target-30.0)<0.015 && !(h&12L))
            g_fc.pitch_deg=30.0;
    }
    InterlockedExchange(&g_fc_want_expanded,freecam_active_angle()?1L:0L);
}

static int freecam_controls_event(const SDL_Event *ev,int map) {
    if(ev->type==SDL_WINDOWEVENT && ev->window.event==SDL_WINDOWEVENT_FOCUS_LOST) {
        InterlockedExchange(&g_fc.hold_mask,0);
        g_fc.dragging=g_fc.alt_drag=0;
        return 0;
    }
    if(ev->type==SDL_MOUSEBUTTONUP && g_fc.dragging &&
       ev->button.button==(g_fc.alt_drag?SDL_BUTTON_LEFT:SDL_BUTTON_MIDDLE)) {
        g_fc.dragging=g_fc.alt_drag=0;
        return 1;
    }
    if(!g_ini_terrain_3d_freecam || !g_terrain_3d || !g_native_entities) return 0;
    if(ev->type==SDL_KEYDOWN || ev->type==SDL_KEYUP) {
        const SDL_Keycode k=ev->key.keysym.sym;
        const int down=ev->type==SDL_KEYDOWN;
        const SDL_Keymod mod=ev->key.keysym.mod;
        LONG bit=0;
        if(k==SDLK_q) bit=1L;
        else if(k==SDLK_e) bit=2L;
        else if(k==SDLK_r) bit=4L;
        else if(k==SDLK_f) bit=8L;
        else if((mod&KMOD_ALT)!=0) {
            if(k==SDLK_LEFT) bit=1L;
            else if(k==SDLK_RIGHT) bit=2L;
            else if(k==SDLK_UP) bit=4L;
            else if(k==SDLK_DOWN) bit=8L;
        }
        if(bit) {
            if(map) {
                if(ev->key.repeat) return 1;
                if(down) InterlockedOr(&g_fc.hold_mask,bit); else InterlockedAnd(&g_fc.hold_mask,~bit);
                return 1;
            }
            if(!down) InterlockedAnd(&g_fc.hold_mask,~bit);
            return 0;
        }
        if(k==SDLK_HOME && map) {
            if(down && !ev->key.repeat) {
                freecam_reset();
                if(g_zoom_target!=1.0) host_zoom_set_target(1.0,128.0,0.0);
                gw_flag_trace("TRACE freecam reset_home%c",10);
            }
            return 1;
        }
        return 0;
    }
    if(ev->type==SDL_MOUSEBUTTONDOWN || ev->type==SDL_MOUSEBUTTONUP) {
        const int down=ev->type==SDL_MOUSEBUTTONDOWN;
        const SDL_Keymod mod=SDL_GetModState();
        const int mid=ev->button.button==SDL_BUTTON_MIDDLE && !(mod&KMOD_SHIFT);
        const int alt_left=ev->button.button==SDL_BUTTON_LEFT && (mod&KMOD_ALT)!=0;
        if(down && map && !g_selection_pointer_held && !g_fc.dragging && (mid || alt_left)) {
            double lx=0.0,ly=0.0;
            if(!host_window_logical(ev->button.x,ev->button.y,&lx,&ly,NULL) || lx<128.0) return 0;
            g_fc.dragging=1;
            g_fc.alt_drag=alt_left;
            g_fc.last_x=ev->button.x;
            g_fc.last_y=ev->button.y;
            return 1;
        }
    }
    if(ev->type==SDL_MOUSEMOTION && g_fc.dragging) {
        if(!map) { g_fc.dragging=g_fc.alt_drag=0; return 0; }
        double x0=0,y0=0,x1=0,y1=0;
        if(host_window_logical(g_fc.last_x,g_fc.last_y,&x0,&y0,NULL) &&
           host_window_logical(ev->motion.x,ev->motion.y,&x1,&y1,NULL)) {
            g_fc.yaw_target+=(x1-x0)*0.42;
            g_fc.pitch_target-=(y1-y0)*0.22;
            freecam_wrap_yaw(&g_fc.yaw_target);
            if(g_fc.pitch_target<12.0) g_fc.pitch_target=12.0;
            if(g_fc.pitch_target>65.0) g_fc.pitch_target=65.0;
        }
        g_fc.last_x=ev->motion.x;
        g_fc.last_y=ev->motion.y;
        return 1;
    }
    return 0;
}

static float freecam_ground_hpx(const gw_terrain_mesh_draw *m,float rx,float ry) {
    return native_ground_hpx(m,rx,ry);
}

/* Exact 3D raycasting onto active cylindrical entity billboards and curved MapHeight. */
static int freecam_raycast(double lx,double ly,int vw,double *out_cx,double *out_cy) {
    const gw_terrain_mesh_draw *m=g_gm.mesh;
    if(!g_fc.has_cam || !m || vw<=128 || lx<128.0) return 0;
    const double u_ndc=((lx-128.0)/(double)(vw-128))*2.0-1.0;
    const double v_ndc=(ly/480.0)*2.0-1.0;
    const float rx_s=(float)(u_ndc*(double)g_fc.aspect*(double)g_fc.fov_tan);
    const float ry_s=(float)(-v_ndc*(double)g_fc.fov_tan);
    float dx=g_fc.fwd[0]+g_fc.right[0]*rx_s+g_fc.up[0]*ry_s;
    float dy=g_fc.fwd[1]+g_fc.right[1]*rx_s+g_fc.up[1]*ry_s;
    float dz=g_fc.fwd[2]+g_fc.right[2]*rx_s+g_fc.up[2]*ry_s;
    const float dl=sqrtf(dx*dx+dy*dy+dz*dz);
    if(dl<1e-6f) return 0;
    dx/=dl; dy/=dl; dz/=dl;
    const float ox=g_fc.eye[0],oy=g_fc.eye[1],oz=g_fc.eye[2];

    /* 1. Test upright cylindrical entity billboards first (closest hit in world units). */
    float best_t=1e9f; int best_pick=-1;
    const float nx=g_fc.fwd[0],ny=g_fc.fwd[1]; /* plane normal horizontal facing camera */
    const float denom=dx*nx+dy*ny;
    if(fabsf(denom)>1e-4f) {
        for(int i=0;i<g_fc.pick_n;i++) {
            const gw_fc_pick_quad *q=&g_fc.picks[i];
            const float t=((q->cx-ox)*nx+(q->cy-oy)*ny)/denom;
            if(t<=0.5f || t>=best_t) continue;
            const float hx=ox+dx*t-q->cx,hy=oy+dy*t-q->cy,hz=oz+dz*t-q->cz;
            const float rx_hit=hx*g_fc.right[0]+hy*g_fc.right[1];
            if(rx_hit<-q->hw*0.80f || rx_hit>q->hw*0.80f) continue;
            if(hz<0.04f*q->hh || hz>q->hh*0.96f) continue;
            best_t=t; best_pick=i;
        }
    }

    /* 2. Raymarch curved terrain surface and check whether terrain occludes any billboard hit. */
    float prev_t=0.5f,prev_diff=1.0f; int prev_set=0;
    float ter_t=1e9f,hit_rx=0.0f,hit_ry=0.0f,hit_h=0.0f;
    for(float t=0.5f;t<=96.0f;t+=0.35f) {
        const float px=ox+dx*t,py=oy+dy*t,pz=oz+dz*t;
        const float gx=px-g_fc.tgt[0],gy=py-g_fc.tgt[1];
        const float gh=freecam_ground_hpx(m,px,py)*TL_ZS - g_fc.curve_k*(gx*gx+gy*gy);
        const float diff=pz-gh;
        if(prev_set && prev_diff>0.0f && diff<=0.0f) {
            float lo=prev_t,hi=t;
            for(int it=0;it<12;it++) {
                const float mid=0.5f*(lo+hi);
                const float mx=ox+dx*mid,my=oy+dy*mid,mz=oz+dz*mid;
                const float ddx=mx-g_fc.tgt[0],ddy=my-g_fc.tgt[1];
                const float mgh=freecam_ground_hpx(m,mx,my)*TL_ZS - g_fc.curve_k*(ddx*ddx+ddy*ddy);
                if(mz>mgh) lo=mid; else hi=mid;
            }
            ter_t=0.5f*(lo+hi);
            hit_rx=ox+dx*ter_t; hit_ry=oy+dy*ter_t;
            hit_h=freecam_ground_hpx(m,hit_rx,hit_ry);
            break;
        }
        prev_t=t; prev_diff=diff; prev_set=1;
    }

    if(best_pick>=0 && best_t<=ter_t+0.15f) {
        *out_cx=g_fc.picks[best_pick].draw_cx;
        *out_cy=g_fc.picks[best_pick].draw_cy;
        return 1;
    }
    if(ter_t<1e8f) {
        *out_cx=32.0*(double)(hit_rx-hit_ry)+0.5;
        *out_cy=16.0*(double)(hit_rx+hit_ry)-(double)hit_h+0.5;
        return 1;
    }
    return 0;
}

/* Use the center of the rendered billboard in the same curved world
   coordinates and clip space as the entity vertex shader. */
static int freecam_drag_contains(const gw_fc_pick_quad *q,double x0,double y0,double x1,double y1) {
    const float *m=g_fc.mvp;
    const float z=q->cz+0.5f*q->hh;
    const float w=m[3]*q->cx+m[7]*q->cy+m[11]*z+m[15];
    if(w<=0.0f) return 0;
    const float depth=m[2]*q->cx+m[6]*q->cy+m[10]*z+m[14];
    if(depth < -w || depth > w) return 0;
    const float x=(m[0]*q->cx+m[4]*q->cy+m[8]*z+m[12])/w;
    const float y=(m[1]*q->cx+m[5]*q->cy+m[9]*z+m[13])/w;
    if(x < -1.0f || x > 1.0f || y < -1.0f || y > 1.0f) return 0;
    const double lx=128.0+(x+1.0)*0.5*(g_fc.last_vw-128);
    const double ly=(y+1.0)*240.0;
    return lx>=x0 && lx<=x1 && ly>=y0 && ly<=y1;
}

static GLuint freecam_tex(int w,int h,GLenum ifmt,GLenum fmt,GLenum filter,GLenum wrap) {
    GLuint t=0; g_bloom.GenTextures(1,&t); g_bloom.BindTexture(GL_TEXTURE_2D,t);
    g_bloom.TexParameteri(GL_TEXTURE_2D,GL_TEXTURE_MIN_FILTER,(GLint)filter);
    g_bloom.TexParameteri(GL_TEXTURE_2D,GL_TEXTURE_MAG_FILTER,(GLint)filter);
    g_bloom.TexParameteri(GL_TEXTURE_2D,GL_TEXTURE_WRAP_S,(GLint)wrap);
    g_bloom.TexParameteri(GL_TEXTURE_2D,GL_TEXTURE_WRAP_T,(GLint)wrap);
    g_bloom.TexImage2D(GL_TEXTURE_2D,0,(GLint)ifmt,w,h,0,fmt,GL_UNSIGNED_BYTE,NULL);
    return t;
}

static int freecam_init_gl(void) {
    if(g_fc.ready) return 1;
    if(g_fc.failed || g_bloom.failed || !g_t3.ready) return 0;
    g_fc.loaded=1;
    *(void **)&g_fc.UniformMatrix4fv=SDL_GL_GetProcAddress("glUniformMatrix4fv");
    *(void **)&g_fc.DeleteRenderbuffers=SDL_GL_GetProcAddress("glDeleteRenderbuffers");
    if(!g_fc.UniformMatrix4fv || !g_fc.DeleteRenderbuffers) { g_fc.failed=1; return 0; }

    /* 1. Starry black sky background behind the curved horizon */
    static const char *vs_sky=
        "#version 120\n"
        "attribute vec2 a_pos;\n varying vec2 v_ndc;\n"
        "void main(){ gl_Position=vec4(a_pos,0.9999,1.0); v_ndc=a_pos; }\n";
    static const char *fs_sky=
        "#version 120\n"
        "uniform vec3 u_right,u_up,u_fwd; uniform float u_fov,u_asp;\n"
        "varying vec2 v_ndc;\n"
        "float h2(vec2 p){ vec3 q=fract(vec3(p.xyx)*vec3(123.34,234.34,345.65)); q+=dot(q,q+34.45); return fract(q.x*q.y*q.z); }\n"
        "void main(){\n"
        "  vec3 dir=normalize(u_fwd + u_right*(v_ndc.x*u_asp*u_fov) - u_up*(v_ndc.y*u_fov));\n"
        "  float yaw_a=atan(dir.y,dir.x), pitch_a=asin(clamp(dir.z,-1.0,1.0));\n"
        "  vec2 sg=vec2(yaw_a*58.0,pitch_a*58.0);\n"
        "  vec2 cid=floor(sg), cf=fract(sg)-0.5;\n"
        "  float r=h2(cid);\n"
        "  float star=0.0;\n"
        "  if(r>0.972){ vec2 off=vec2(h2(cid+1.3),h2(cid+7.1))-0.5; float d=length(cf-off*0.55);\n"
        "    star=smoothstep(0.16,0.0,d)*(0.45+0.55*h2(cid+19.7)); }\n"
        "  vec3 col=mix(vec3(0.75,0.82,1.0),vec3(1.0,0.92,0.82),h2(cid+31.2))*star;\n"
        "  gl_FragColor=vec4(col,1.0);\n"
        "}\n";

    /* 2. Curved 3D lit terrain with B32 tiles, HD overrides, directional shadows, water, GOOP, point lights, fog */
    static const char *vs_ter=
        "#version 120\n"
        "attribute vec3 a_pos; attribute vec2 a_uv; attribute vec2 a_suv; attribute vec2 a_world;\n"
        "uniform mat4 u_mvp; uniform vec2 u_cc; uniform float u_ck,u_zs;\n"
        "varying vec3 v_uv; varying vec4 v_meta; varying vec3 v_world;\n"
        "void main(){\n"
        "  vec2 d=a_pos.xy-u_cc;\n"
        "  vec3 p=vec3(a_pos.xy,a_pos.z*u_zs - u_ck*dot(d,d));\n"
        "  gl_Position=u_mvp*vec4(p,1.0);\n"
        "  v_uv=vec3(a_uv,a_world.x); v_meta=vec4(a_suv,a_world.xy);\n"
        "  v_world=vec3(a_pos.xy,a_pos.z*u_zs);\n"
        "}\n";
    static const char *fs_ter= TL_GLSL_COMMON
        "uniform sampler2D u_tiles,u_fade,u_lut,u_kind,u_nrm,u_sh,u_bump,u_ao,u_hd,u_hdmap;\n"
        "uniform vec2 u_view,u_cc,u_hdsz; uniform vec4 u_lx,u_ly,u_lz;\n"
        "uniform vec3 u_sun,u_sunc,u_sky,u_gnd,u_wtint;\n"
        "uniform float u_shon,u_wton,u_zs,u_aos,u_expo,u_shfloor,u_knorm,u_hdon,u_hdm,u_rim,u_time;\n"
        "uniform vec4 u_plp[16]; uniform vec4 u_plc[16]; uniform int u_pln;\n"
        "varying vec3 v_uv; varying vec4 v_meta; varying vec3 v_world;\n"
        "float shdec(vec2 uv){ vec4 t=texture2D(u_sh,uv); return t.r+t.g/255.0; }\n"
        "float hh(vec2 q){ vec3 p3=fract(vec3(q.xyx)*0.1031); p3+=dot(p3,p3.yzx+33.33); return fract((p3.x+p3.y)*p3.z); }\n"
        "float vn(vec2 p,float P){ vec2 i=floor(p),f=fract(p); f=f*f*(3.0-2.0*f);\n"
        "  return mix(mix(hh(mod(i,P)),hh(mod(i+vec2(1.0,0.0),P)),f.x),mix(hh(mod(i+vec2(0.0,1.0),P)),hh(mod(i+vec2(1.0,1.0),P)),f.x),f.y); }\n"
        "float det(vec2 W){ return 0.5*vn(W*24.0,3072.0)+0.3*vn(W*56.0,7168.0)+0.2*vn(W*120.0,15360.0); }\n"
        "float texel(vec2 base,vec2 t,float shade,out float raw){\n"
        "  raw=rd8(u_tiles,base+clamp(t,0.0,31.0),vec2(512.0,544.0));\n"
        "  return floor(texture2D(u_fade,(vec2(raw,shade)+0.5)/vec2(256.0,64.0)).r*255.0+0.5);\n"
        "}\n"
        "void main(){\n"
        "  float tile=floor(v_meta.x+0.5);\n"
        "  vec2 base=vec2(mod(tile,16.0),floor(tile/16.0))*32.0;\n"
        "  vec2 tp=clamp(floor(v_uv.xy),0.0,31.0);\n"
        "  float idx=rd8(u_tiles,base+tp,vec2(512.0,544.0));\n"
        "  if(v_meta.y>5.5 && idx==0.0) discard;\n"
        "  if(v_meta.w<0.02){ gl_FragColor=vec4(0.0,0.0,0.0,1.0); return; }\n"
        "  float shade=clamp(floor(v_uv.z),0.0,63.0);\n"
        "  vec2 pt=v_uv.xy-0.5; vec2 i0=floor(pt); vec2 fw=max(fwidth(v_uv.xy),vec2(1e-3));\n"
        "  vec2 f=clamp((fract(pt)-0.5)/fw+0.5,0.0,1.0);\n"
        "  float r00,r10,r01,r11;\n"
        "  float t00=texel(base,i0,shade,r00),t10=texel(base,i0+vec2(1.0,0.0),shade,r10);\n"
        "  float t01=texel(base,i0+vec2(0.0,1.0),shade,r01),t11=texel(base,i0+vec2(1.0,1.0),shade,r11);\n"
        "  vec3 c2=mix(mix(lut(u_lut,t00),lut(u_lut,t10),f.x),mix(lut(u_lut,t01),lut(u_lut,t11),f.x),f.y);\n"
        "  vec3 alb=mix(mix(lut(u_lut,r00),lut(u_lut,r10),f.x),mix(lut(u_lut,r01),lut(u_lut,r11),f.x),f.y);\n"
        "  float hdon=0.0;\n"
        "  if(u_hdon>0.5 && v_meta.y<5.5){\n"
        "    vec4 hm=texture2D(u_hdmap,vec2((tile+0.5)/259.0,0.5));\n"
        "    if(hm.a>0.5){\n"
        "      vec2 o=vec2(floor(hm.r*255.0+0.5),floor(hm.g*255.0+0.5)+256.0*floor(hm.b*255.0+0.5));\n"
        "      vec3 hd=texture2D(u_hd,(o+clamp(v_uv.xy,vec2(u_hdm),vec2(32.0-u_hdm)))/u_hdsz).rgb;\n"
        "      float lo=dot(alb,vec3(0.3,0.59,0.11)), lc=dot(c2,vec3(0.3,0.59,0.11));\n"
        "      c2=hd*clamp(lc/max(lo,0.02),0.0,1.5); alb=hd; hdon=1.0;\n"
        "    }\n"
        "  }\n"
        "  float kind=floor(texture2D(u_kind,vec2((idx+0.5)/256.0,0.5)).r*255.0+0.5);\n"
        "  vec2 W=v_world.xy+u_view;\n"
        "  vec4 nt=texture2D(u_nrm,(W+0.5)/128.0);\n"
        "  float ao=clamp(1.0-(1.0-texture2D(u_ao,(W+0.5)/128.0).r)*u_aos,0.25,1.0);\n"
        "  vec3 N=normalize(nt.xyz*2.0-1.0);\n"
        "  float dn=det(W);\n"
        "  float water=(u_wton>0.5 && kind==1.0)?1.0:0.0;\n"
        "  vec3 Nm=normalize(N-(1.0-water)*vec3(det(W+vec2(0.004,0.0))-dn,det(W+vec2(0.0,0.004))-dn,0.0)*1.3);\n"
        "  alb*=1.0+(1.0-water)*0.26*(1.0-0.6*hdon)*(dn-0.5);\n"
        "  float sh=1.0;\n"
        "  if(u_shon>0.5){\n"
        "    vec4 P=vec4(v_world+N*0.06,1.0);\n"
        "    vec3 l=vec3(dot(u_lx,P),dot(u_ly,P),dot(u_lz,P))*0.5+0.5;\n"
        "    float d=l.z-0.0020;\n"
        "    sh=(l.x>0.0&&l.x<1.0&&l.y>0.0&&l.y<1.0)?((shdec(l.xy)<d)?0.0:1.0):1.0;\n"
        "  }\n"
        "  float ndl=max(dot(Nm,u_sun),0.0);\n"
        "  vec3 hemi=mix(u_gnd,u_sky,Nm.z*0.5+0.5);\n"
        "  float vis=mix(u_shfloor,1.0,sh);\n"
        "  vec3 light=(hemi*(0.40*ao)+u_sunc*(ndl*vis*1.30*mix(0.65,1.0,ao)))*u_expo;\n"
        "  vec3 lit=alb*light*1.12;\n"
        "  vec3 pl=vec3(0.0);\n"
        "  for(int i=0;i<16;i++){\n"
        "    if(i>=u_pln) break;\n"
        "    vec4 pr=u_plp[i]; vec3 Lv=pr.xyz-v_world; Lv.xy=mod(Lv.xy+64.0,128.0)-64.0;\n"
        "    float dd=length(Lv); if(dd>=pr.w) continue;\n"
        "    float at=1.0-dd/pr.w; at*=at;\n"
        "    pl+=u_plc[i].rgb*(u_plc[i].w*at)*(max(dot(Nm,Lv/max(dd,1e-3)),0.0)*0.85+0.15);\n"
        "  }\n"
        "  pl=pl/(1.0+0.45*pl);\n"
        "  lit+=alb*pl*1.15*mix(0.7,1.0,ao);\n"
        "  vec3 col=mix(c2*mix(0.75,1.0,ao),lit,1.0);\n"
        "  if(u_knorm>0.0){ float L2=dot(c2,vec3(0.3,0.59,0.11)), L3=dot(col,vec3(0.3,0.59,0.11));\n"
        "    col*=pow(clamp((L2+0.01)/(L3+0.01),0.5,2.5),u_knorm); }\n"
        "  col=mix(col,0.8+0.2*(1.0-exp(-(col-0.8)/0.2)),step(0.8,col));\n"
        "  if(water>0.5){\n"
        "    float hpx=v_world.z/u_zs;\n"
        "    float dep=clamp(1.0-hpx/22.0,0.0,1.0)*0.55+0.45*nt.a;\n"
        "    vec3 shallow=alb*vec3(0.90,1.08,1.04)+vec3(0.0,0.045,0.045);\n"
        "    vec3 deep=alb*vec3(0.30,0.40,0.60);\n"
        "    float wv=sin(W.x*6.0+u_time*2.2)*cos(W.y*6.0-u_time*1.7)*0.5+0.5;\n"
        "    col=mix(shallow,deep,smoothstep(0.0,1.0,dep))*mix(0.55,1.0,sh)*u_wtint;\n"
        "    col+=vec3(0.04,0.06,0.08)*pow(wv,3.0)*(1.0-dep*0.4);\n"
        "    col+=(alb*0.55+vec3(0.06,0.08,0.09))*pl;\n"
        "  }\n"
        "  col*=clamp(v_meta.w*4.0,0.0,1.0);\n"
        "  float dist_r=length(v_world.xy-u_cc);\n"
        "  float limb=1.0-smoothstep(u_rim-3.5,u_rim,dist_r);\n"
        "  gl_FragColor=vec4(clamp(col*limb,0.0,1.0),1.0);\n"
        "}\n";

    /* 3. Curved 3D entity shadows + cylindrical billboards */
    static const char *vs_ent=
        "#version 120\n"
        "attribute vec3 a_pos; attribute vec3 a_uv; attribute vec2 a_suv;\n"
        "uniform mat4 u_mvp; uniform vec2 u_cc; uniform float u_ck; uniform vec3 u_camr;\n"
        "varying vec2 v_uv; varying float v_mode; varying vec2 v_wpos;\n"
        "void main(){\n"
        "  vec2 d=a_pos.xy-u_cc;\n"
        "  vec3 base=vec3(a_pos.xy,a_pos.z - u_ck*dot(d,d));\n"
        "  vec3 wp=base + u_camr*a_uv.x + vec3(0.0,0.0,a_uv.y);\n"
        "  gl_Position=u_mvp*vec4(wp,1.0);\n"
        "  v_uv=vec2(a_uv.z,a_suv.x); v_mode=a_suv.y; v_wpos=a_pos.xy;\n"
        "}\n";
    static const char *fs_ent=
        "#version 120\n"
        "uniform sampler2D u_sprites,u_explore; uniform vec2 u_vorig;\n"
        "varying vec2 v_uv; varying float v_mode; varying vec2 v_wpos;\n"
        "float exp_at(vec2 p){ return texture2D(u_explore,(floor(u_vorig+p)+0.5)/128.0).r; }\n"
        "void main(){\n"
        "  if(v_mode<0.0){\n"
        "    if(exp_at(v_wpos)<0.25) discard;\n"
        "    float r2=dot(v_uv,v_uv); if(r2>=1.0) discard;\n"
        "    float f=1.0-smoothstep(0.05,1.0,r2);\n"
        "    gl_FragColor=vec4(0.0,0.0,0.0,(-v_mode)*pow(f,1.35));\n"
        "  } else {\n"
        "    if(exp_at(v_wpos)<0.25) discard;\n"
        "    vec4 c=texture2D(u_sprites,v_uv); if(c.a<=0.05) discard;\n"
        "    gl_FragColor=c;\n"
        "  }\n"
        "}\n";

    /* 4. Reprojected world-space indicators (e.g. growth % / selection markers) */
    static const char *vs_ind=
        "#version 120\n"
        "attribute vec3 a_pos; attribute vec3 a_uv; attribute vec2 a_suv;\n"
        "uniform mat4 u_mvp; uniform vec2 u_cc; uniform float u_ck; uniform vec3 u_camr;\n"
        "varying vec2 v_iuv;\n"
        "void main(){\n"
        "  vec2 d=a_pos.xy-u_cc;\n"
        "  vec3 base=vec3(a_pos.xy,a_pos.z - u_ck*dot(d,d));\n"
        "  vec3 wp=base + u_camr*a_uv.x + vec3(0.0,0.0,a_uv.y);\n"
        "  gl_Position=u_mvp*vec4(wp,1.0);\n"
        "  v_iuv=a_suv;\n"
        "}\n";
    static const char *fs_ind=
        "#version 120\n"
        "uniform sampler2D u_idx,u_lut;\n"
        "varying vec2 v_iuv;\n"
        "void main(){\n"
        "  vec4 px=texture2D(u_idx,v_iuv);\n"
        "  if(px.a<0.5) discard;\n"
        "  float g=floor(px.g*255.0+0.5);\n"
        "  if(mod(floor(g/2.0),2.0)>0.5) discard;\n"
        "  float k=floor(px.r*255.0+0.5);\n"
        "  if(k<=0.5) discard;\n"
        "  gl_FragColor=vec4(texture2D(u_lut,vec2((k+0.5)/256.0,0.25)).rgb,1.0);\n"
        "}\n";
    static const char *vs_blit=
        "#version 120\n"
        "attribute vec2 a_pos; attribute vec2 a_uv; attribute vec2 a_suv;\n"
        "varying vec2 v_uv;\n"
        "void main(){ gl_Position=vec4(a_pos,0.0,1.0); v_uv=a_uv; }\n";
    static const char *fs_blit=
        "#version 120\n"
        "uniform sampler2D u_tex;\n"
        "varying vec2 v_uv;\n"
        "void main(){ gl_FragColor=texture2D(u_tex,v_uv); }\n";

    g_fc.prog_sky=bloom_link_program(vs_sky,fs_sky);
    g_fc.prog_terrain=bloom_link_program(vs_ter,fs_ter);
    g_fc.prog_entity=bloom_link_program(vs_ent,fs_ent);
    g_fc.prog_ind=bloom_link_program(vs_ind,fs_ind);
    g_fc.prog_blit=bloom_link_program(vs_blit,fs_blit);
    if(!g_fc.prog_sky||!g_fc.prog_terrain||!g_fc.prog_entity||!g_fc.prog_ind||!g_fc.prog_blit) { g_fc.failed=1; return 0; }

    #define FCU(f,p,n) g_fc.f=g_bloom.GetUniformLocation(g_fc.p,n)
    FCU(sk_right,prog_sky,"u_right"); FCU(sk_up,prog_sky,"u_up"); FCU(sk_fwd,prog_sky,"u_fwd");
    FCU(sk_fov,prog_sky,"u_fov"); FCU(sk_asp,prog_sky,"u_asp");

    FCU(tr_mvp,prog_terrain,"u_mvp"); FCU(tr_cc,prog_terrain,"u_cc"); FCU(tr_ck,prog_terrain,"u_ck");
    FCU(tr_zs,prog_terrain,"u_zs"); FCU(tr_view,prog_terrain,"u_view"); FCU(tr_tiles,prog_terrain,"u_tiles");
    FCU(tr_fade,prog_terrain,"u_fade"); FCU(tr_lut,prog_terrain,"u_lut"); FCU(tr_kind,prog_terrain,"u_kind");
    FCU(tr_nrm,prog_terrain,"u_nrm"); FCU(tr_ao,prog_terrain,"u_ao"); FCU(tr_sh,prog_terrain,"u_sh");
    FCU(tr_bump,prog_terrain,"u_bump"); FCU(tr_lx,prog_terrain,"u_lx"); FCU(tr_ly,prog_terrain,"u_ly");
    FCU(tr_lz,prog_terrain,"u_lz"); FCU(tr_sun,prog_terrain,"u_sun"); FCU(tr_sunc,prog_terrain,"u_sunc");
    FCU(tr_sky,prog_terrain,"u_sky"); FCU(tr_gnd,prog_terrain,"u_gnd"); FCU(tr_wtint,prog_terrain,"u_wtint");
    FCU(tr_aos,prog_terrain,"u_aos"); FCU(tr_expo,prog_terrain,"u_expo"); FCU(tr_shfloor,prog_terrain,"u_shfloor");
    FCU(tr_knorm,prog_terrain,"u_knorm"); FCU(tr_shon,prog_terrain,"u_shon"); FCU(tr_wton,prog_terrain,"u_wton");
    FCU(tr_hdon,prog_terrain,"u_hdon"); FCU(tr_hd,prog_terrain,"u_hd"); FCU(tr_hdmap,prog_terrain,"u_hdmap");
    FCU(tr_hdsz,prog_terrain,"u_hdsz"); FCU(tr_hdm,prog_terrain,"u_hdm"); FCU(tr_plp,prog_terrain,"u_plp");
    FCU(tr_plc,prog_terrain,"u_plc"); FCU(tr_pln,prog_terrain,"u_pln"); FCU(tr_curve_rim,prog_terrain,"u_rim");
    FCU(tr_time,prog_terrain,"u_time");

    FCU(en_mvp,prog_entity,"u_mvp"); FCU(en_cc,prog_entity,"u_cc"); FCU(en_ck,prog_entity,"u_ck");
    FCU(en_camr,prog_entity,"u_camr"); FCU(en_sprites,prog_entity,"u_sprites");
    FCU(en_explore,prog_entity,"u_explore"); FCU(en_vorig,prog_entity,"u_vorig");

    FCU(in_mvp,prog_ind,"u_mvp"); FCU(in_cc,prog_ind,"u_cc"); FCU(in_ck,prog_ind,"u_ck");
    FCU(in_camr,prog_ind,"u_camr"); FCU(in_idx,prog_ind,"u_idx"); FCU(in_lut,prog_ind,"u_lut");
    FCU(bl_tex,prog_blit,"u_tex");
    #undef FCU

    g_bloom.GenBuffers(1,&g_fc.terrain_vbo);
    g_bloom.GenBuffers(1,&g_fc.entity_vbo);
    g_bloom.GenBuffers(1,&g_fc.ind_vbo);
    g_fc.b32_tex=freecam_tex(512,544,GL_R8,GL_RED,GL_NEAREST,GL_CLAMP_TO_EDGE);
    g_fc.explore_tex=freecam_tex(128,128,GL_R8,GL_RED,GL_NEAREST,GL_REPEAT);
    g_fc.hd_map_tex=freecam_tex(259,1,GL_RGBA8,GL_RGBA,GL_NEAREST,GL_CLAMP_TO_EDGE);
    g_fc.ready=1;
    gw_flag_trace("TRACE freecam GL initialized%c",10);
    return 1;
}

static int freecam_ensure_fbo(int w,int h) {
    if(g_fc.fbo && g_fc.fbo_w==w && g_fc.fbo_h==h) return 1;
    if(g_fc.fbo) {
        g_bloom.DeleteFramebuffers(1,&g_fc.fbo);
        g_bloom.DeleteTextures(1,&g_fc.color_tex);
        g_fc.DeleteRenderbuffers(1,&g_fc.depth_rb);
        g_fc.fbo=g_fc.color_tex=g_fc.depth_rb=0;
    }
    g_fc.color_tex=freecam_tex(w,h,GL_RGBA8,GL_RGBA,GL_LINEAR,GL_CLAMP_TO_EDGE);
    g_bloom.GenFramebuffers(1,&g_fc.fbo);
    g_bloom.BindFramebuffer(GL_FRAMEBUFFER,g_fc.fbo);
    g_bloom.FramebufferTexture2D(GL_FRAMEBUFFER,GL_COLOR_ATTACHMENT0,GL_TEXTURE_2D,g_fc.color_tex,0);
    g_gl_mesh.GenRenderbuffers(1,&g_fc.depth_rb);
    g_gl_mesh.BindRenderbuffer(GL_RENDERBUFFER,g_fc.depth_rb);
    g_gl_mesh.RenderbufferStorage(GL_RENDERBUFFER,GL_DEPTH_COMPONENT24,w,h);
    if(g_bloom.GetError()!=GL_NO_ERROR)
        g_gl_mesh.RenderbufferStorage(GL_RENDERBUFFER,GL_DEPTH_COMPONENT16,w,h);
    g_gl_mesh.BindRenderbuffer(GL_RENDERBUFFER,0);
    g_gl_mesh.FramebufferRenderbuffer(GL_FRAMEBUFFER,GL_DEPTH_ATTACHMENT,GL_RENDERBUFFER,g_fc.depth_rb);
    if(g_bloom.CheckFramebufferStatus(GL_FRAMEBUFFER)!=GL_FRAMEBUFFER_COMPLETE) {
        g_fc.failed=1;
        return 0;
    }
    g_fc.fbo_w=w; g_fc.fbo_h=h;
    return 1;
}

static void freecam_upload_bank(void) {
    if(!g_fc_bank.valid) return;
    if(g_fc_bank.version!=g_fc.bank_ver) {
        static uint8_t atlas[512u*544u];
        memset(atlas,0,sizeof atlas);
        for(unsigned i=0;i<259u;i++) {
            uint8_t *slot=atlas+32u*(i%16u)+32u*512u*(i/16u);
            for(unsigned r=0;r<32u;r++)
                memcpy(slot+r*512u,g_fc_bank.tiles[i]+r*32u,32u);
        }
        g_bloom.ActiveTexture(GL_TEXTURE0);
        g_bloom.BindTexture(GL_TEXTURE_2D,g_fc.b32_tex);
        g_bloom.TexSubImage2D(GL_TEXTURE_2D,0,0,0,512,544,GL_RED,GL_UNSIGNED_BYTE,atlas);
        g_fc.bank_ver=g_fc_bank.version;
        g_fc.hd_map_ver=0;
    }
    if(g_hd.state==3 && g_fc.hd_map_ver!=g_fc_bank.version) {
        uint8_t hm[259u*4u]; memset(hm,0,sizeof hm);
        const uint32_t bank_bytes=(uint32_t)g_hd.rows*32u*256u;
        for(unsigned i=0;i<256u;i++) {
            const uint32_t a=g_fc_bank.tile_addr[i];
            if(!g_fc_bank.b32_base || a<g_fc_bank.b32_base || a-g_fc_bank.b32_base>=bank_bytes) continue;
            const uint32_t rel=a-g_fc_bank.b32_base,x=rel%256u,y=rel/256u;
            if(x+32u>256u || y+32u>(uint32_t)g_hd.rows*32u || !g_hd.valid[(y/32u)*8u+x/32u]) continue;
            hm[i*4u]=(uint8_t)x; hm[i*4u+1]=(uint8_t)(y&255u); hm[i*4u+2]=(uint8_t)(y>>8); hm[i*4u+3]=255u;
        }
        g_bloom.ActiveTexture(GL_TEXTURE0);
        g_bloom.BindTexture(GL_TEXTURE_2D,g_fc.hd_map_tex);
        g_bloom.TexSubImage2D(GL_TEXTURE_2D,0,0,0,259,1,GL_RGBA,GL_UNSIGNED_BYTE,hm);
        g_fc.hd_map_ver=g_fc_bank.version;
    }
}

static void freecam_upload_explore(const gw_interactive_visual_snapshot *v) {
    if(v->generation==g_fc.explore_gen) return;
    static uint8_t ex[128u*128u];
    for(unsigned i=0;i<128u*128u;i++)
        ex[i]=v->world[14u*i+12u]?255u:0u;
    g_bloom.ActiveTexture(GL_TEXTURE0);
    g_bloom.BindTexture(GL_TEXTURE_2D,g_fc.explore_tex);
    g_bloom.TexSubImage2D(GL_TEXTURE_2D,0,0,0,128,128,GL_RED,GL_UNSIGNED_BYTE,ex);
    g_fc.explore_gen=v->generation;
}

static void freecam_build_terrain(const gw_interactive_visual_snapshot *v,const gw_terrain_mesh_draw *m,
                                  int ic,int ir) {
    static gw_fc_tvert verts[GW_FC_MAX_TVERTS];
    if(!g_fc_bank.valid) return;
    if(v->generation==g_fc.terrain_gen && ic==g_fc.terrain_ic && ir==g_fc.terrain_ir && g_fc.terrain_nverts>0)
        return;
    int n=0;
    const int vc=m->view_col,vr=m->view_row,hs=m->height_scale;
    const int R=GW_FC_RADIUS;
    for(int dr=-R;dr<R;dr++) {
        for(int dc=-R;dc<R;dc++) {
            const float cx=(float)dc+0.5f,cy=(float)dr+0.5f;
            if(cx*cx+cy*cy>(float)(R*R)) continue;
            if(n+12>GW_FC_MAX_TVERTS) break;
            const int wc=ic+dc,wr=ir+dr;
            const unsigned c00=((unsigned)wr&127u)*128u+((unsigned)wc&127u);
            const unsigned c10=((unsigned)wr&127u)*128u+((unsigned)(wc+1)&127u);
            const unsigned c01=((unsigned)(wr+1)&127u)*128u+((unsigned)wc&127u);
            const unsigned c11=((unsigned)(wr+1)&127u)*128u+((unsigned)(wc+1)&127u);
            const uint8_t *m00=v->world+14u*c00,*m10=v->world+14u*c10;
            const uint8_t *m01=v->world+14u*c01,*m11=v->world+14u*c11;
            const float h00=(float)(gw_terrain_mesh_height_step(gw_terrain_read_i16(m00+2))*hs);
            const float h10=(float)(gw_terrain_mesh_height_step(gw_terrain_read_i16(m10+2))*hs);
            const float h01=(float)(gw_terrain_mesh_height_step(gw_terrain_read_i16(m01+2))*hs);
            const float h11=(float)(gw_terrain_mesh_height_step(gw_terrain_read_i16(m11+2))*hs);
            const int32_t L00=32768+4*gw_terrain_read_i16(m00)*m00[12];
            const int32_t L10=32768+4*gw_terrain_read_i16(m10)*m10[12];
            const int32_t L01=32768+4*gw_terrain_read_i16(m01)*m01[12];
            const int32_t L11=32768+4*gw_terrain_read_i16(m11)*m11[12];
            const float l00=(float)L00/65536.0f,l10=(float)L10/65536.0f;
            const float l01=(float)L01/65536.0f,l11=(float)L11/65536.0f;
            const float e00=m00[12]?(float)m00[12]/63.0f:0.0f;
            const float e10=m10[12]?(float)m10[12]/63.0f:0.0f;
            const float e01=m01[12]?(float)m01[12]/63.0f:0.0f;
            const float e11=m11[12]?(float)m11[12]/63.0f:0.0f;
            const float x0=(float)(wc-vc),x1=x0+1.0f,y0=(float)(wr-vr),y1=y0+1.0f;
            const unsigned ori=(unsigned)(m00[5]&0x70u)>>4u;
            const float *uv=g_fc_bank.uv[ori&7u];
            const float tile=(float)m00[4];
            const float mode=(L00||L10||L01||L11)?5.0f:0.0f;
            const float s00=(31.0f*l00),s10=(31.0f*l10),s01=(31.0f*l01),s11=(31.0f*l11);
            /* Split along (0,0)-(1,1) diagonal matching 0x65630 exact height interpolation */
            verts[n++]=(gw_fc_tvert){x0,y0,h00,uv[0],uv[1],tile,mode,s00,e00};
            verts[n++]=(gw_fc_tvert){x1,y0,h10,uv[2],uv[3],tile,mode,s10,e10};
            verts[n++]=(gw_fc_tvert){x1,y1,h11,uv[4],uv[5],tile,mode,s11,e11};
            verts[n++]=(gw_fc_tvert){x0,y0,h00,uv[0],uv[1],tile,mode,s00,e00};
            verts[n++]=(gw_fc_tvert){x1,y1,h11,uv[4],uv[5],tile,mode,s11,e11};
            verts[n++]=(gw_fc_tvert){x0,y1,h01,uv[6],uv[7],tile,mode,s01,e01};
            const unsigned kind=m00[13];
            if(kind>1u) {
                const unsigned bank=kind>=97u?2u:(kind-1u)/32u;
                const float ct=(float)(256u+bank);
                verts[n++]=(gw_fc_tvert){x0,y0,h00,uv[0],uv[1],ct,6.0f,s00,e00};
                verts[n++]=(gw_fc_tvert){x1,y0,h10,uv[2],uv[3],ct,6.0f,s10,e10};
                verts[n++]=(gw_fc_tvert){x1,y1,h11,uv[4],uv[5],ct,6.0f,s11,e11};
                verts[n++]=(gw_fc_tvert){x0,y0,h00,uv[0],uv[1],ct,6.0f,s00,e00};
                verts[n++]=(gw_fc_tvert){x1,y1,h11,uv[4],uv[5],ct,6.0f,s11,e11};
                verts[n++]=(gw_fc_tvert){x0,y1,h01,uv[6],uv[7],ct,6.0f,s01,e01};
            }
        }
    }
    g_bloom.BindBuffer(GL_ARRAY_BUFFER,g_fc.terrain_vbo);
    g_bloom.BufferData(GL_ARRAY_BUFFER,(size_t)n*sizeof verts[0],verts,GL_DYNAMIC_DRAW);
    g_fc.terrain_gen=v->generation;
    g_fc.terrain_ic=ic;
    g_fc.terrain_ir=ir;
    g_fc.terrain_nverts=n;
}

static void freecam_add_shadow(gw_fc_evert **out,const gw_fc_evert *limit,const gw_terrain_mesh_draw *m,
                               float cx,float cy,float dx,float dy,float length,float width,float opacity) {
    const float rx=-dy,ry=dx;
    const float radius=fmaxf(length,width);
    const int steps=(radius>0.85f)?4:(radius>0.40f?3:2);
    if(*out+(size_t)steps*steps*6u>limit) return;
    const float ds=2.0f/(float)steps;
    for(int iy=0;iy<steps;iy++) {
        const float v0=-1.0f+(float)iy*ds,v1=v0+ds;
        for(int ix=0;ix<steps;ix++) {
            const float u0=-1.0f+(float)ix*ds,u1=u0+ds;
            const float ax[4]={
                cx+dx*length*u0+rx*width*v0, cx+dx*length*u1+rx*width*v0,
                cx+dx*length*u0+rx*width*v1, cx+dx*length*u1+rx*width*v1
            };
            const float ay[4]={
                cy+dy*length*u0+ry*width*v0, cy+dy*length*u1+ry*width*v0,
                cy+dy*length*u0+ry*width*v1, cy+dy*length*u1+ry*width*v1
            };
            const float au[4]={u0,u1,u0,u1},av[4]={v0,v0,v1,v1};
            gw_fc_evert q[4];
            for(int k=0;k<4;k++) {
                const float hz=freecam_ground_hpx(m,ax[k],ay[k])*TL_ZS+0.025f;
                q[k]=(gw_fc_evert){ax[k],ay[k],hz,0.0f,0.0f,au[k],av[k],-opacity};
            }
            gw_fc_evert *p=*out;
            p[0]=q[0]; p[1]=q[1]; p[2]=q[2];
            p[3]=q[2]; p[4]=q[1]; p[5]=q[3];
            *out+=6;
        }
    }
}

static void freecam_add_billboard(gw_fc_evert **out,const gw_fc_evert *limit,
                                  const gw_native_draw *d,gw_sprite_atlas_rect rect,
                                  float rx,float ry,float wz,float sink_px) {
    if(*out+6>limit) return;
    const float w_world=(float)rect.w/45.254834f;
    const float h_world=(float)rect.h*TL_ZS;
    const float px=32.0f*(rx-ry),py=16.0f*(rx+ry)-wz*39.1918f;
    const float x_off_world=(((float)d->x+0.5f*(float)rect.w)-px)/45.254834f;
    const float y_bot_world=(((float)d->y+sink_px+(float)rect.h)-py)*TL_ZS;
    const float base_z=wz-y_bot_world;
    const float sc=1.0f/GW_SPRITE_ATLAS_SIZE;
    const float u0=(float)rect.x*sc,v0=(float)rect.y*sc,u1=(float)(rect.x+rect.w)*sc,v1=(float)(rect.y+rect.h)*sc;
    const float hw=0.5f*w_world;
    gw_fc_evert *p=*out;
    p[0]=(gw_fc_evert){rx,ry,base_z,x_off_world-hw,h_world,u0,v0,1.0f};
    p[1]=(gw_fc_evert){rx,ry,base_z,x_off_world+hw,h_world,u1,v0,1.0f};
    p[2]=(gw_fc_evert){rx,ry,base_z,x_off_world-hw,0.0f,   u0,v1,1.0f};
    p[3]=(gw_fc_evert){rx,ry,base_z,x_off_world-hw,0.0f,   u0,v1,1.0f};
    p[4]=(gw_fc_evert){rx,ry,base_z,x_off_world+hw,h_world,u1,v0,1.0f};
    p[5]=(gw_fc_evert){rx,ry,base_z,x_off_world+hw,0.0f,   u1,v1,1.0f};
    *out+=6;

    if(g_fc.pick_n<GW_FC_MAX_PICKS) {
        const float dx=rx-g_fc.tgt[0],dy=ry-g_fc.tgt[1];
        const float cz_c=base_z-g_fc.curve_k*(dx*dx+dy*dy);
        const float cx_c=rx+g_fc.right[0]*x_off_world,cy_c=ry+g_fc.right[1]*x_off_world;
        g_fc.picks[g_fc.pick_n++]=(gw_fc_pick_quad){
            cx_c,cy_c,cz_c,hw,h_world,(float)d->x+0.5f*(float)rect.w,(float)d->y+0.5f*(float)rect.h,u0,v0,u1,v1,d->entity.guest_address
        };
    }
}

static int freecam_render(const gw_interactive_visual_snapshot *v,const gw_present_geo *geo,double interp_a) {
    (void)geo;
    if(!freecam_init_gl() || !g_gm.mesh || !g_fc_bank.valid) return 0;
    const gw_terrain_mesh_draw *m=g_gm.mesh;
    const int vw=g_present_w;
    const int map_px_x=(int)(128.0*(double)g_gm.map_w/(double)vw);
    const int map_px_w=g_gm.map_w-map_px_x;
    const int map_px_h=g_gm.map_h;
    if(map_px_w<=0 || map_px_h<=0 || !freecam_ensure_fbo(map_px_w,map_px_h)) return 0;

    /* Compute camera target matching center of classic visible map viewport */
    const double z=g_zoom>0.1?g_zoom:1.0;
    const int idx=(g_bloom.canvas_ready>=2 && (g_interp_dx||g_interp_dy) && interp_a<1.0)?g_interp_dx:0;
    const int idy=(g_bloom.canvas_ready>=2 && (g_interp_dx||g_interp_dy) && interp_a<1.0)?g_interp_dy:0;
    const double center_cx=(double)GW_CANVAS_VX0+g_zoom_x+(1.0-interp_a)*(double)idx+((double)(vw-128))*0.5/z;
    const double center_cy=(double)GW_CANVAS_VY0+g_zoom_y+(1.0-interp_a)*(double)idy+240.0/z;
    const double diff=center_cx/32.0;
    double tx=0.5*((center_cy/16.0)+diff),ty=0.5*((center_cy/16.0)-diff);
    for(int it=0;it<2;it++) {
        const double h=freecam_ground_hpx(m,(float)tx,(float)ty);
        const double sum=(center_cy+h)/16.0;
        tx=0.5*(sum+diff); ty=0.5*(sum-diff);
    }
    const float h_tgt=freecam_ground_hpx(m,(float)tx,(float)ty);
    const float tz=h_tgt*TL_ZS;

    const double ang=(225.0+g_fc.yaw_deg)*(M_PI/180.0);
    const double pch=g_fc.pitch_deg*(M_PI/180.0);
    const float fx0=(float)cos(ang),fy0=(float)sin(ang);
    const float cosp=(float)cos(pch),sinp=(float)sin(pch);
    const float F[3]={cosp*fx0,cosp*fy0,-sinp};
    const float R[3]={-fy0,fx0,0.0f};
    const float U[3]={sinp*fx0,sinp*fy0,cosp};
    const float dist=(float)(17.346/z);
    const float E[3]={(float)tx-F[0]*dist,(float)ty-F[1]*dist,tz-F[2]*dist};
    const float fov_tan=tanf((float)(17.0*M_PI/180.0));
    const float aspect=(float)(vw-128)/480.0f;
    const float n=1.0f,f=200.0f;
    const float a_x=1.0f/(fov_tan*aspect),a_y=1.0f/fov_tan;
    const float za=(f+n)/(f-n),zb=-(2.0f*f*n)/(f-n);
    const float curve_k=g_ini_terrain_3d_planet_curve?0.0070f:0.0f;

    /* Column-major OpenGL MVP with inverted U row (-U) to match top-down g_gm.map_fbo (NDC y=-1 top). */
    const float re=R[0]*E[0]+R[1]*E[1]+R[2]*E[2];
    const float ue=U[0]*E[0]+U[1]*E[1]+U[2]*E[2];
    const float fe=F[0]*E[0]+F[1]*E[1]+F[2]*E[2];
    const float mvp[16]={
        R[0]*a_x, -U[0]*a_y, F[0]*za, F[0],
        R[1]*a_x, -U[1]*a_y, F[1]*za, F[1],
        R[2]*a_x, -U[2]*a_y, F[2]*za, F[2],
       -re*a_x,    ue*a_y,  -fe*za+zb,-fe
    };

    for(int k=0;k<3;k++) { g_fc.eye[k]=E[k]; g_fc.fwd[k]=F[k]; g_fc.right[k]=R[k]; g_fc.up[k]=U[k]; }
    g_fc.tgt[0]=(float)tx; g_fc.tgt[1]=(float)ty; g_fc.tgt[2]=tz;
    g_fc.dist=dist; g_fc.fov_tan=fov_tan; g_fc.aspect=aspect; g_fc.curve_k=curve_k;
    memcpy(g_fc.mvp,mvp,sizeof mvp);
    g_fc.view_col=(float)m->view_col; g_fc.view_row=(float)m->view_row;
    g_fc.last_vw=vw; g_fc.last_mw=map_px_w; g_fc.last_mh=map_px_h; g_fc.has_cam=1;

    freecam_upload_bank();
    freecam_upload_explore(v);
    freecam_build_terrain(v,m,m->view_col+(int)floor(tx),m->view_row+(int)floor(ty));

    /* Setup fc_fbo & render 3D sky -> curved terrain -> shadows -> cylindrical billboards -> indicators */
    g_gl_mesh.PushAttrib(GL_DEPTH_BUFFER_BIT|GL_ENABLE_BIT|GL_COLOR_BUFFER_BIT|GL_VIEWPORT_BIT);
    g_bloom.BindFramebuffer(GL_FRAMEBUFFER,g_fc.fbo);
    g_bloom.Viewport(0,0,map_px_w,map_px_h);
    g_bloom.Disable(GL_SCISSOR_TEST);
    g_bloom.Disable(GL_CULL_FACE);
    g_bloom.Disable(GL_DITHER);
    g_gl_mesh.DepthMask(GL_TRUE);
    g_gl_mesh.ClearDepth(1.0);
    g_bloom.ClearColor(0.0f,0.0f,0.0f,1.0f);
    g_bloom.Clear(GL_COLOR_BUFFER_BIT|GL_DEPTH_BUFFER_BIT);

    /* Pass 0: Starry pure black sky */
    g_bloom.Disable(GL_DEPTH_TEST);
    g_gl_mesh.DepthMask(GL_FALSE);
    g_bloom.Disable(GL_BLEND);
    g_bloom.UseProgram(g_fc.prog_sky);
    g_t3.Uniform3f(g_fc.sk_right,R[0],R[1],R[2]);
    g_t3.Uniform3f(g_fc.sk_up,U[0],U[1],U[2]);
    g_t3.Uniform3f(g_fc.sk_fwd,F[0],F[1],F[2]);
    g_bloom.Uniform1f(g_fc.sk_fov,fov_tan);
    g_bloom.Uniform1f(g_fc.sk_asp,aspect);
    g_bloom.BindBuffer(GL_ARRAY_BUFFER,g_bloom.vbo);
    g_bloom.VertexAttribPointer(0,2,GL_FLOAT,GL_FALSE,6*(GLsizei)sizeof(float),(const void *)0);
    g_bloom.VertexAttribPointer(1,2,GL_FLOAT,GL_FALSE,6*(GLsizei)sizeof(float),(const void *)(2*sizeof(float)));
    g_bloom.VertexAttribPointer(2,2,GL_FLOAT,GL_FALSE,6*(GLsizei)sizeof(float),(const void *)(4*sizeof(float)));
    bloom_draw_quad(-1.0f,-1.0f,1.0f,1.0f,0.0f,0.0f,1.0f,1.0f,0.0f,0.0f,1.0f,1.0f);

    /* Pass 1: Curved 3D Terrain disk */
    g_bloom.Enable(GL_DEPTH_TEST);
    g_gl_mesh.DepthFunc(GL_LESS);
    g_gl_mesh.DepthMask(GL_TRUE);
    g_bloom.UseProgram(g_fc.prog_terrain);
    g_fc.UniformMatrix4fv(g_fc.tr_mvp,1,GL_FALSE,mvp);
    g_bloom.Uniform2f(g_fc.tr_cc,(float)tx,(float)ty);
    g_bloom.Uniform1f(g_fc.tr_ck,curve_k);
    g_bloom.Uniform1f(g_fc.tr_zs,TL_ZS);
    g_bloom.Uniform2f(g_fc.tr_view,(float)m->view_col,(float)m->view_row);
    g_bloom.Uniform1f(g_fc.tr_curve_rim,(float)GW_FC_RADIUS);
    {   const uint64_t fq=SDL_GetPerformanceFrequency(),tc=SDL_GetPerformanceCounter();
        g_bloom.Uniform1f(g_fc.tr_time,fq?(float)fmod((double)tc/(double)fq,62.831853):0.0f); }
    g_bloom.ActiveTexture(GL_TEXTURE0); g_bloom.BindTexture(GL_TEXTURE_2D,g_fc.b32_tex); g_bloom.Uniform1i(g_fc.tr_tiles,0);
    g_bloom.ActiveTexture(GL_TEXTURE1); g_bloom.BindTexture(GL_TEXTURE_2D,g_gl_mesh.fade); g_bloom.Uniform1i(g_fc.tr_fade,1);
    g_bloom.ActiveTexture(GL_TEXTURE2); g_bloom.BindTexture(GL_TEXTURE_2D,g_bloom.lut_tex); g_bloom.Uniform1i(g_fc.tr_lut,2);
    g_bloom.ActiveTexture(GL_TEXTURE3); g_bloom.BindTexture(GL_TEXTURE_2D,g_gm.t_kind); g_bloom.Uniform1i(g_fc.tr_kind,3);
    g_bloom.ActiveTexture(GL_TEXTURE4); g_bloom.BindTexture(GL_TEXTURE_2D,g_t3.nrm_tex); g_bloom.Uniform1i(g_fc.tr_nrm,4);
    g_bloom.ActiveTexture(GL_TEXTURE5); g_bloom.BindTexture(GL_TEXTURE_2D,g_t3.sh_tex); g_bloom.Uniform1i(g_fc.tr_sh,5);
    g_bloom.ActiveTexture(GL_TEXTURE6); g_bloom.BindTexture(GL_TEXTURE_2D,g_t3.bump_tex); g_bloom.Uniform1i(g_fc.tr_bump,6);
    g_bloom.ActiveTexture(GL_TEXTURE7); g_bloom.BindTexture(GL_TEXTURE_2D,g_t3.ao_tex); g_bloom.Uniform1i(g_fc.tr_ao,7);
    const int hd_on=(g_ini_terrain_3d_hd_tiles && g_hd_on && g_hd.state==3 && g_fc.hd_map_ver==g_fc_bank.version);
    g_bloom.ActiveTexture(GL_TEXTURE8); g_bloom.BindTexture(GL_TEXTURE_2D,hd_on?g_hd.tex:0u); g_bloom.Uniform1i(g_fc.tr_hd,8);
    g_bloom.ActiveTexture(GL_TEXTURE9); g_bloom.BindTexture(GL_TEXTURE_2D,hd_on?g_fc.hd_map_tex:0u); g_bloom.Uniform1i(g_fc.tr_hdmap,9);
    g_bloom.Uniform1f(g_fc.tr_hdon,hd_on?1.0f:0.0f);
    if(hd_on) {
        g_bloom.Uniform2f(g_fc.tr_hdsz,256.0f,(float)(g_hd.rows*32));
        g_bloom.Uniform1f(g_fc.tr_hdm,16.0f/(float)g_hd.S);
    }
    g_t3.Uniform4f(g_fc.tr_lx,g_t3.lx[0],g_t3.lx[1],g_t3.lx[2],g_t3.lx[3]);
    g_t3.Uniform4f(g_fc.tr_ly,g_t3.ly[0],g_t3.ly[1],g_t3.ly[2],g_t3.ly[3]);
    g_t3.Uniform4f(g_fc.tr_lz,g_t3.lz[0],g_t3.lz[1],g_t3.lz[2],g_t3.lz[3]);
    g_t3.Uniform3f(g_fc.tr_sun,g_t3.sun[0],g_t3.sun[1],g_t3.sun[2]);
    g_t3.Uniform3f(g_fc.tr_sunc,g_t3.sunc[0],g_t3.sunc[1],g_t3.sunc[2]);
    g_t3.Uniform3f(g_fc.tr_sky,g_t3.sky[0],g_t3.sky[1],g_t3.sky[2]);
    g_t3.Uniform3f(g_fc.tr_gnd,g_t3.gnd[0],g_t3.gnd[1],g_t3.gnd[2]);
    g_t3.Uniform3f(g_fc.tr_wtint,g_t3.wtint[0],g_t3.wtint[1],g_t3.wtint[2]);
    g_bloom.Uniform1f(g_fc.tr_aos,g_t3.aos);
    g_bloom.Uniform1f(g_fc.tr_expo,g_t3.expo);
    g_bloom.Uniform1f(g_fc.tr_shfloor,g_t3.shfloor);
    g_bloom.Uniform1f(g_fc.tr_knorm,g_t3.knorm);
    g_bloom.Uniform1f(g_fc.tr_shon,g_ini_terrain_3d_shadows?1.0f:0.0f);
    g_bloom.Uniform1f(g_fc.tr_wton,g_ini_terrain_3d_water?1.0f:0.0f);
    const int npl=(g_pl_on && g_ini_terrain_3d_lights)?g_t3.pl_n:0;
    g_bloom.Uniform1i(g_fc.tr_pln,npl);
    if(npl) {
        g_t3.Uniform4fv(g_fc.tr_plp,npl,&g_t3.pl_pos[0][0]);
        g_t3.Uniform4fv(g_fc.tr_plc,npl,&g_t3.pl_col[0][0]);
    }
    g_bloom.BindBuffer(GL_ARRAY_BUFFER,g_fc.terrain_vbo);
    g_bloom.EnableVertexAttribArray(3);
    const GLsizei ts=(GLsizei)sizeof(gw_fc_tvert);
    g_bloom.VertexAttribPointer(0,3,GL_FLOAT,GL_FALSE,ts,(const void *)offsetof(gw_fc_tvert,wx));
    g_bloom.VertexAttribPointer(1,2,GL_FLOAT,GL_FALSE,ts,(const void *)offsetof(gw_fc_tvert,u));
    g_bloom.VertexAttribPointer(2,2,GL_FLOAT,GL_FALSE,ts,(const void *)offsetof(gw_fc_tvert,tile));
    g_bloom.VertexAttribPointer(3,2,GL_FLOAT,GL_FALSE,ts,(const void *)offsetof(gw_fc_tvert,shade));
    g_bloom.DrawArrays(GL_TRIANGLES,0,g_fc.terrain_nverts);
    g_bloom.DisableVertexAttribArray(3);

    /* Pass 2: Build curved shadows + upright cylindrical billboards */
    static gw_fc_evert everts[GW_FC_MAX_EVERTS];
    const gw_fc_evert *elimit=everts+GW_FC_MAX_EVERTS;
    gw_fc_evert *eend=everts;
    g_fc.pick_n=0;

    if(v->atlas_active && g_atlas_probe_gl.texture && v->atlas_probe.draw_count) {
        const gw_atlas_probe_frame *af=&v->atlas_probe;
        const float sl=sqrtf(g_t3.sun[0]*g_t3.sun[0]+g_t3.sun[1]*g_t3.sun[1]);
        const float sdx=sl>1e-4f?-g_t3.sun[0]/sl:1.0f,sdy=sl>1e-4f?-g_t3.sun[1]/sl:0.0f;
        uint32_t seen[GW_NATIVE_DRAWS]; unsigned seen_n=0;
        for(unsigned i=0;i<af->draw_count && i<GW_NATIVE_DRAWS;i++) {
            const gw_native_draw *d=&af->draws[i];
            if(!d->slot || d->slot>af->count || !g_native_uploaded[d->slot-1u]) continue;
            if(d->entity.type==GW_ENTITY_EFFECT) continue;
            unsigned j=0; while(j<seen_n && seen[j]!=d->entity.guest_address) j++;
            if(j<seen_n) continue;
            seen[seen_n++]=d->entity.guest_address;
            const gw_sprite_atlas_key *key=&af->items[d->slot-1u].key;
            const float rx=native_relative(d->entity.world_x_q8,m->view_col);
            const float ry=native_relative(d->entity.world_y_q8,m->view_row);
            float r_ao=0.35f;
            if(d->entity.type==GW_ENTITY_PLANT) r_ao=fminf(0.80f,fmaxf(0.28f,key->width/70.0f));
            else if(d->entity.type==GW_ENTITY_BUILDING) r_ao=fminf(1.35f,fmaxf(0.48f,key->width/54.0f));
            else r_ao=fminf(0.42f,fmaxf(0.22f,key->width/54.0f));
            const float h=fmaxf(0.0f,(d->entity.world_z_q6-d->entity.ground_q6*m->height_scale)/64.0f);
            const float cast=fminf(2.4f,fmaxf(0.28f,(h+key->height*0.42f)*sl/(39.19f*fmaxf(0.30f,g_t3.sun[2]))));
            if(h<6.0f) {
                const float ao_base=(d->entity.type==GW_ENTITY_PLANT||d->entity.type==GW_ENTITY_BUILDING)?0.48f:0.42f;
                freecam_add_shadow(&eend,elimit,m,rx,ry,sdx,sdy,r_ao,r_ao,ao_base*(1.0f-h/6.0f));
            }
            const float air_shift=h>=6.0f?(h*sl/(39.19f*fmaxf(0.30f,g_t3.sun[2])))*0.55f:0.0f;
            freecam_add_shadow(&eend,elimit,m,rx+sdx*(cast*0.42f+air_shift),ry+sdy*(cast*0.42f+air_shift),
                               sdx,sdy,cast*0.58f+r_ao*0.70f,r_ao*0.80f,0.34f);
        }
        const int shadow_verts=(int)(eend-everts);

        float cdist[GW_NATIVE_DRAWS];
        unsigned trans[GW_NATIVE_DRAWS],nt=0;
        for(unsigned i=0;i<af->draw_count && i<GW_NATIVE_DRAWS;i++) {
            const gw_native_draw *d=&af->draws[i];
            if(!d->slot || d->slot>af->count || !g_native_uploaded[d->slot-1u]) continue;
            const unsigned slot=d->slot-1u;
            const float rx=native_relative(d->entity.world_x_q8,m->view_col);
            const float ry=native_relative(d->entity.world_y_q8,m->view_row);
            const float wz=(d->entity.world_z_q6/64.0f)*TL_ZS;
            cdist[i]=(rx-E[0])*F[0]+(ry-E[1])*F[1]+(wz-E[2])*F[2];
            if(af->items[slot].key.blend==GW_SPRITE_BLIT_DESTINATION) {
                unsigned k=nt++;
                while(k && cdist[trans[k-1u]]<cdist[i]) { trans[k]=trans[k-1u]; k--; }
                trans[k]=i;
            } else {
                const float sink=native_slope_sink_px(m,&d->entity,g_native_rects[slot].w,rx,ry);
                freecam_add_billboard(&eend,elimit,d,g_native_rects[slot],rx,ry,wz,sink);
            }
        }
        const int opaque_verts=(int)(eend-everts);
        for(unsigned k=0;k<nt;k++) {
            const unsigned i=trans[k];
            const gw_native_draw *d=&af->draws[i];
            const unsigned slot=d->slot-1u;
            const float rx=native_relative(d->entity.world_x_q8,m->view_col);
            const float ry=native_relative(d->entity.world_y_q8,m->view_row);
            const float wz=(d->entity.world_z_q6/64.0f)*TL_ZS;
            const float sink=native_slope_sink_px(m,&d->entity,g_native_rects[slot].w,rx,ry);
            freecam_add_billboard(&eend,elimit,d,g_native_rects[slot],rx,ry,wz,sink);
        }
        const int total_everts=(int)(eend-everts);

        if(total_everts>0) {
        g_bloom.Enable(GL_BLEND);
        g_bloom.BlendFuncSeparate(GL_SRC_ALPHA,GL_ONE_MINUS_SRC_ALPHA,GL_ZERO,GL_ONE);
        g_bloom.UseProgram(g_fc.prog_entity);
        g_fc.UniformMatrix4fv(g_fc.en_mvp,1,GL_FALSE,mvp);
        g_bloom.Uniform2f(g_fc.en_cc,(float)tx,(float)ty);
        g_bloom.Uniform1f(g_fc.en_ck,curve_k);
        g_t3.Uniform3f(g_fc.en_camr,R[0],R[1],R[2]);
        g_bloom.ActiveTexture(GL_TEXTURE0); g_bloom.BindTexture(GL_TEXTURE_2D,g_atlas_probe_gl.texture); g_bloom.Uniform1i(g_fc.en_sprites,0);
        g_bloom.ActiveTexture(GL_TEXTURE1); g_bloom.BindTexture(GL_TEXTURE_2D,g_fc.explore_tex); g_bloom.Uniform1i(g_fc.en_explore,1);
        g_bloom.Uniform2f(g_fc.en_vorig,(float)m->view_col,(float)m->view_row);
        g_bloom.BindBuffer(GL_ARRAY_BUFFER,g_fc.entity_vbo);
        g_bloom.BufferData(GL_ARRAY_BUFFER,(size_t)total_everts*sizeof everts[0],everts,GL_STREAM_DRAW);
        const GLsizei es=(GLsizei)sizeof everts[0];
        g_bloom.VertexAttribPointer(0,3,GL_FLOAT,GL_FALSE,es,(const void *)offsetof(gw_fc_evert,wx));
        g_bloom.VertexAttribPointer(1,3,GL_FLOAT,GL_FALSE,es,(const void *)offsetof(gw_fc_evert,right_off));
        g_bloom.VertexAttribPointer(2,2,GL_FLOAT,GL_FALSE,es,(const void *)offsetof(gw_fc_evert,v));

        if(shadow_verts>0) {
            g_gl_mesh.DepthFunc(GL_LEQUAL);
            g_gl_mesh.DepthMask(GL_FALSE);
            g_bloom.Enable(GL_POLYGON_OFFSET_FILL);
            g_gl_mesh.PolygonOffset(-4.0f,-4.0f);
            g_bloom.DrawArrays(GL_TRIANGLES,0,shadow_verts);
            g_bloom.Disable(GL_POLYGON_OFFSET_FILL);
            g_gl_mesh.DepthFunc(GL_LESS);
        }
        if(opaque_verts>shadow_verts) {
            g_gl_mesh.DepthMask(GL_TRUE);
            g_bloom.DrawArrays(GL_TRIANGLES,shadow_verts,opaque_verts-shadow_verts);
        }
        if(total_everts>opaque_verts) {
            g_gl_mesh.DepthMask(GL_FALSE);
            g_bloom.DrawArrays(GL_TRIANGLES,opaque_verts,total_everts-opaque_verts);
        }
        }

        /* Pass 3: Reproject floating world-space UI indicators (e.g. growth %, selection bars) above entities */
        if(v->spr_valid && v->entity_coverage_bytes) {
            static gw_fc_ivert iverts[GW_FC_MAX_IVERTS];
            int ivn=0;
            uint32_t seen_i[GW_NATIVE_DRAWS]; unsigned seen_in=0;
            for(unsigned i=0;i<af->draw_count && i<GW_NATIVE_DRAWS && ivn+6<=GW_FC_MAX_IVERTS;i++) {
                const gw_native_draw *d=&af->draws[i];
                if(d->extra || !d->slot || d->slot>af->count || !g_native_uploaded[d->slot-1u]) continue;
                if(d->entity.type==GW_ENTITY_EFFECT) continue;
                unsigned jj=0; while(jj<seen_in && seen_i[jj]!=d->entity.guest_address) jj++;
                if(jj<seen_in) continue;
                seen_i[seen_in++]=d->entity.guest_address;
                const gw_sprite_atlas_rect r0=g_native_rects[d->slot-1u];
                const int sx0=(d->x+(int)r0.w/2)-20,sx1=sx0+40;
                const int sy0=d->y-18,sy1=d->y-1;
                if(sx0<176 || sx1>=(int)GW_CANVAS_W || sy0<0 || sy1>=(int)GW_CANVAS_H) continue;
                int bx0=sx1,bx1=sx0,by0=sy1,by1=sy0,cnt=0;
                for(int py=sy0;py<=sy1;py++) for(int px=sx0;px<=sx1;px++) {
                    const size_t idx_c=(size_t)py*GW_CANVAS_W+(size_t)px;
                    if(v->spr_mask[idx_c]==1u && !v->entity_coverage[idx_c]) {
                        if(px<bx0) bx0=px; if(px>bx1) bx1=px;
                        if(py<by0) by0=py; if(py>by1) by1=py;
                        cnt++;
                    }
                }
                if(cnt<3) continue;
                const float rx=native_relative(d->entity.world_x_q8,m->view_col);
                const float ry=native_relative(d->entity.world_y_q8,m->view_row);
                const float wz=(d->entity.world_z_q6/64.0f)*TL_ZS;
                const float hw=(float)(bx1-bx0+1)/90.51f,hh=(float)(by1-by0+1)*TL_ZS;
                const float base_z=wz+(float)r0.h*TL_ZS+0.08f;
                const float iu0=(float)(bx0-128)/(float)GW_CANVAS_TEX_W,iu1=(float)(bx1+1-128)/(float)GW_CANVAS_TEX_W;
                const float iv0=(float)by0/(float)GW_CANVAS_H,iv1=(float)(by1+1)/(float)GW_CANVAS_H;
                iverts[ivn++]=(gw_fc_ivert){rx,ry,base_z,-hw,hh,iu0,iv0};
                iverts[ivn++]=(gw_fc_ivert){rx,ry,base_z, hw,hh,iu1,iv0};
                iverts[ivn++]=(gw_fc_ivert){rx,ry,base_z,-hw,0.0f,iu0,iv1};
                iverts[ivn++]=(gw_fc_ivert){rx,ry,base_z,-hw,0.0f,iu0,iv1};
                iverts[ivn++]=(gw_fc_ivert){rx,ry,base_z, hw,hh,iu1,iv0};
                iverts[ivn++]=(gw_fc_ivert){rx,ry,base_z, hw,0.0f,iu1,iv1};
            }
            if(ivn>0) {
                g_gl_mesh.DepthMask(GL_FALSE);
                g_bloom.UseProgram(g_fc.prog_ind);
                g_fc.UniformMatrix4fv(g_fc.in_mvp,1,GL_FALSE,mvp);
                g_bloom.Uniform2f(g_fc.in_cc,(float)tx,(float)ty);
                g_bloom.Uniform1f(g_fc.in_ck,curve_k);
                g_t3.Uniform3f(g_fc.in_camr,R[0],R[1],R[2]);
                g_bloom.ActiveTexture(GL_TEXTURE0); g_bloom.BindTexture(GL_TEXTURE_2D,g_bloom.canvas_tex[1]); g_bloom.Uniform1i(g_fc.in_idx,0);
                g_bloom.ActiveTexture(GL_TEXTURE1); g_bloom.BindTexture(GL_TEXTURE_2D,g_bloom.lut_tex); g_bloom.Uniform1i(g_fc.in_lut,1);
                g_bloom.BindBuffer(GL_ARRAY_BUFFER,g_fc.ind_vbo);
                g_bloom.BufferData(GL_ARRAY_BUFFER,(size_t)ivn*sizeof iverts[0],iverts,GL_STREAM_DRAW);
                const GLsizei is=(GLsizei)sizeof iverts[0];
                g_bloom.VertexAttribPointer(0,3,GL_FLOAT,GL_FALSE,is,(const void *)offsetof(gw_fc_ivert,wx));
                g_bloom.VertexAttribPointer(1,3,GL_FLOAT,GL_FALSE,is,(const void *)offsetof(gw_fc_ivert,right_off));
                g_bloom.VertexAttribPointer(2,2,GL_FLOAT,GL_FALSE,is,(const void *)offsetof(gw_fc_ivert,iu));
                g_bloom.DrawArrays(GL_TRIANGLES,0,ivn);
            }
        }
    }

    g_gl_mesh.PopAttrib();
    /* Blit fc.color_tex into the map region of g_gm.map_fbo (x >= 128) and restore quad VBO/attribs */
    g_bloom.BindFramebuffer(GL_FRAMEBUFFER,g_gm.map_fbo);
    g_bloom.Viewport(0,0,g_gm.map_w,g_gm.map_h);
    g_bloom.Disable(GL_DEPTH_TEST);
    g_gl_mesh.DepthMask(GL_FALSE);
    g_bloom.Disable(GL_BLEND);
    g_bloom.Disable(GL_SCISSOR_TEST);
    g_bloom.UseProgram(g_fc.prog_blit);
    g_bloom.ActiveTexture(GL_TEXTURE0);
    g_bloom.BindTexture(GL_TEXTURE_2D,g_fc.color_tex);
    g_bloom.Uniform1i(g_fc.bl_tex,0);
    g_bloom.BindBuffer(GL_ARRAY_BUFFER,g_bloom.vbo);
    g_bloom.VertexAttribPointer(0,2,GL_FLOAT,GL_FALSE,6*(GLsizei)sizeof(float),(const void *)0);
    g_bloom.VertexAttribPointer(1,2,GL_FLOAT,GL_FALSE,6*(GLsizei)sizeof(float),(const void *)(2*sizeof(float)));
    g_bloom.VertexAttribPointer(2,2,GL_FLOAT,GL_FALSE,6*(GLsizei)sizeof(float),(const void *)(4*sizeof(float)));
    {
        const float x0=128.0f/(float)vw*2.0f-1.0f;
        bloom_draw_quad(x0,-1.0f,1.0f,1.0f, 0.0f,0.0f,1.0f,1.0f, 0.0f,0.0f,1.0f,1.0f);
    }
    return 1;
}
#endif
