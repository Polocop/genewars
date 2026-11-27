#ifndef GW_NATIVE_ENTITIES_GL_H
#define GW_NATIVE_ENTITIES_GL_H

/* Included by the host compositor after the terrain and atlas definitions. */
typedef struct gw_native_vertex {
    float x,y,z,u,v,owner,wx,wy,wz,effect;
} gw_native_vertex;

static struct {
    GLuint shader,mask,layers[3];
    GLint sprites,ownership,ring,offset,light_on,sun,sunc,sky,plpos,plcol,plcount,reflect;
    int failed,valid[3];
} g_native_gl;

static int native_gl_init(void) {
    if(g_native_gl.failed) return 0;
    if(g_native_gl.shader) return 1;
    static const char *vs=
        "#version 120\n"
        "attribute vec3 a_pos; attribute vec2 a_uv; attribute float a_suv; attribute vec4 a_world;\n"
        "uniform float u_reflect;\n"
        "varying vec2 uv,canvas; varying float owner,effect; varying vec3 world;\n"
        "void main(){ vec3 p=a_pos; canvas=p.xy; world=a_world.xyz; effect=a_world.w;\n"
        "  if(u_reflect>0.5){ float h=world.z*39.19-22.0; p.y+=2.0*h; p.x=(p.x-128.0)*1.125; p.z+=0.0005*h; }\n"
        "  gl_Position=vec4(p.xy*2.0/vec2(1152.0,640.0)-1.0,p.z,1.0); uv=a_uv; owner=a_suv; }\n";
    static const char *fs=
        "#version 120\n"
        "uniform sampler2D u_sprites,u_ownership,u_ring; uniform vec2 u_offset;\n"
        "uniform float u_light_on,u_reflect; uniform vec3 u_sun,u_sunc,u_sky;"
        "uniform vec4 u_plpos[16],u_plcol[16]; uniform int u_plcount;\n"
        "varying vec2 uv,canvas; varying float owner,effect; varying vec3 world;\n"
        "void main(){ vec2 p=floor(u_reflect>0.5?canvas:gl_FragCoord.xy), sz=vec2(1152.0,640.0);"
        " if(u_reflect>0.5 && world.z<22.0/39.19) discard;"
        " if(p.x<128.0) discard;"
        " vec2 r=vec2(128.0+mod(p.x-256.0+u_offset.x,1024.0),mod(p.y+u_offset.y,640.0));"
        " if(texture2D(u_ring,(r+0.5)/sz).r<0.002) discard;"
        " if(owner<0.0){"
        "   float r2=dot(uv,uv); if(r2>=1.0) discard;"
        "   float f=1.0-smoothstep(0.04,1.0,r2);"
        "   float grad=mix(1.0,0.62,smoothstep(-0.45,0.85,uv.x));"
        "   gl_FragColor=vec4(0.0,0.0,0.0,(-owner)*pow(f,1.35)*grad);"
        " } else {"
        "   vec4 c=texture2D(u_sprites,uv); if(c.a<=0.0) discard;"
        "   if(u_light_on>0.5 && effect<0.5){"
        "     float mx=max(c.r,max(c.g,c.b)), mn=min(c.r,min(c.g,c.b));"
        "     float emissive=smoothstep(0.80,0.96,mx)*smoothstep(0.54,0.82,mx-mn)*(1.0-smoothstep(0.28,0.44,mn));"
        "     vec3 point=vec3(0.0);"
        "     if(u_plcount>0){"
        "       for(int i=0;i<16;i++){ if(i>=u_plcount) break;"
        "         vec3 d=u_plpos[i].xyz-world; d.xy=mod(d.xy+64.0,128.0)-64.0;"
        "         float a=max(0.0,1.0-length(d)/max(0.01,u_plpos[i].w));"
        "         point+=u_plcol[i].rgb*(u_plcol[i].w*a*a); }"
        "     }"
        "     vec3 tint=vec3(0.84)+0.11*u_sky+0.11*u_sunc;"
        "     vec3 lit=c.rgb*tint+(vec3(1.0)-c.rgb)*(0.26*point/(vec3(1.0)+point));"
        "     c.rgb=mix(lit,c.rgb,emissive);"
        "   } gl_FragColor=c;"
        " } }\n";
    g_native_gl.shader=tl_link(vs,fs);
    if(!g_native_gl.shader) { g_native_gl.failed=1; return 0; }
    g_native_gl.sprites=g_bloom.GetUniformLocation(g_native_gl.shader,"u_sprites");
    g_native_gl.ownership=g_bloom.GetUniformLocation(g_native_gl.shader,"u_ownership");
    g_native_gl.ring=g_bloom.GetUniformLocation(g_native_gl.shader,"u_ring");
    g_native_gl.offset=g_bloom.GetUniformLocation(g_native_gl.shader,"u_offset");
    g_native_gl.light_on=g_bloom.GetUniformLocation(g_native_gl.shader,"u_light_on");
    g_native_gl.sun=g_bloom.GetUniformLocation(g_native_gl.shader,"u_sun");
    g_native_gl.sunc=g_bloom.GetUniformLocation(g_native_gl.shader,"u_sunc");
    g_native_gl.sky=g_bloom.GetUniformLocation(g_native_gl.shader,"u_sky");
    g_native_gl.plpos=g_bloom.GetUniformLocation(g_native_gl.shader,"u_plpos");
    g_native_gl.plcol=g_bloom.GetUniformLocation(g_native_gl.shader,"u_plcol");
    g_native_gl.plcount=g_bloom.GetUniformLocation(g_native_gl.shader,"u_plcount");
    g_native_gl.reflect=g_bloom.GetUniformLocation(g_native_gl.shader,"u_reflect");
    g_native_gl.mask=gm_tex(1152,640,GL_R8,GL_RED);
    for(unsigned i=0;i<3;i++) g_native_gl.layers[i]=gm_tex(1152,640,GL_RGBA8,GL_RGBA);
    g_bloom.BindFramebuffer(GL_FRAMEBUFFER,g_gl_mesh.fbo);
    for(unsigned i=0;i<3;i++) {
        g_bloom.FramebufferTexture2D(GL_FRAMEBUFFER,GL_COLOR_ATTACHMENT0,GL_TEXTURE_2D,g_native_gl.layers[i],0);
        if(!g_native_gl.layers[i] || g_bloom.CheckFramebufferStatus(GL_FRAMEBUFFER)!=GL_FRAMEBUFFER_COMPLETE)
            g_native_gl.failed=1;
    }
    g_bloom.FramebufferTexture2D(GL_FRAMEBUFFER,GL_COLOR_ATTACHMENT0,GL_TEXTURE_2D,g_gl_mesh.color,0);
    if(!g_native_gl.mask) g_native_gl.failed=1;
    if(g_native_gl.failed) {
        g_bloom.DeleteTextures(1,&g_native_gl.mask);
        g_bloom.DeleteTextures(3,g_native_gl.layers);
        g_bloom.DeleteProgram(g_native_gl.shader);
        return 0;
    }
    return 1;
}

static float native_relative(int16_t q8,int origin) {
    const unsigned q=(unsigned)((int)q8-(origin&127)*256+16384)&32767u;
    return ((int)q-16384)/256.0f;
}

static float native_depth(float x,float y,float height) {
    return -0.004f*(x+y)-0.00025f*height;
}

static void native_quad(gw_native_vertex **out,gw_native_vertex a,gw_native_vertex b,
                        gw_native_vertex c,gw_native_vertex d) {
    gw_native_vertex *p=*out;
    p[0]=a; p[1]=b; p[2]=c;
    p[3]=c; p[4]=b; p[5]=d;
    *out+=6;
}

static float native_ground_hpx(const gw_terrain_mesh_draw *mesh,float rx,float ry) {
    const float cx=floorf(rx),cy=floorf(ry);
    const float fx=rx-cx,fy=ry-cy;
    const int c0=mesh->view_col+(int)cx,r0=mesh->view_row+(int)cy;
    const float h00=(float)tl_hpx(mesh,c0,r0);
    const float h11=(float)tl_hpx(mesh,c0+1,r0+1);
    if(fx>=fy) {
        const float h10=(float)tl_hpx(mesh,c0+1,r0);
        return h00+fx*(h10-h00)+fy*(h11-h10);
    }
    const float h01=(float)tl_hpx(mesh,c0,r0+1);
    return h00+fy*(h01-h00)+fx*(h11-h01);
}

static float native_slope_sink_px(const gw_terrain_mesh_draw *mesh,const gw_entity_3d_t *ent,
        unsigned w,float x,float y) {
    (void)mesh; (void)ent; (void)w; (void)x; (void)y;
    /* Anchor entities exactly at MapHeight without burying them into slopes. */
    return 0.0f;
}

static void native_billboard(gw_native_vertex **out,const gw_native_draw *draw,
        gw_sprite_atlas_rect rect,unsigned owner,float depth,float sink_px,float wx,float wy) {
    const float x0=(float)draw->x,y0=(float)draw->y+sink_px,x1=x0+rect.w,y1=y0+rect.h;
    float r_cells=0.45f;
    if(draw->entity.type==GW_ENTITY_PLANT) r_cells=fminf(0.95f,fmaxf(0.45f,(float)rect.w/52.0f));
    else if(draw->entity.type==GW_ENTITY_BUILDING) r_cells=fminf(1.60f,fmaxf(0.75f,(float)rect.w/44.0f));
    else if(draw->entity.type==GW_ENTITY_EFFECT) r_cells=1.20f;
    else r_cells=fminf(0.65f,fmaxf(0.42f,(float)rect.w/48.0f));
    /* Controlled camera-facing depth bias proportional to base radius so slopes
       never slice through a standing entity while foreground hills still occlude it. */
    const float bias=0.004f*(r_cells*1.35f)+0.0022f+(float)owner*0.000002f;
    const float z1=depth-bias;
    const float z0=z1-(float)rect.h*0.00025f;
    const float scale=1.0f/GW_SPRITE_ATLAS_SIZE;
    const float u0=rect.x*scale,v0=rect.y*scale,u1=(rect.x+rect.w)*scale,v1=(rect.y+rect.h)*scale;
    const float n=(float)owner;
    const float bottom=(draw->entity.world_z_q6/64.0f-sink_px)*TL_ZS;
    const float top=bottom+(float)rect.h*TL_ZS;
    const float effect=draw->entity.type==GW_ENTITY_EFFECT?1.0f:0.0f;
    native_quad(out,(gw_native_vertex){x0,y0,z0,u0,v0,n,wx,wy,top,effect},
        (gw_native_vertex){x1,y0,z0,u1,v0,n,wx,wy,top,effect},
        (gw_native_vertex){x0,y1,z1,u0,v1,n,wx,wy,bottom,effect},
        (gw_native_vertex){x1,y1,z1,u1,v1,n,wx,wy,bottom,effect});
}

static gw_native_vertex native_shadow_vertex(const gw_terrain_mesh_draw *mesh,
        float x,float y,float cx,float cy,float dx,float dy,float length,float width,float opacity) {
    const float h=native_ground_hpx(mesh,x,y);
    const float sx=x-cx,sy=y-cy;
    return (gw_native_vertex){32.0f*(x-y)+0.5f,16.0f*(x+y)-h+0.5f,
        native_depth(x,y,h)-0.0008f,
        (sx*dx+sy*dy)/length,(sy*dx-sx*dy)/width,-opacity};
}

enum { GW_NATIVE_SHADOW_VERTICES=32768 };
static void native_shadow(gw_native_vertex **out,gw_native_vertex *limit,
        const gw_terrain_mesh_draw *mesh,float cx,float cy,float dx,float dy,
        float length,float width,float opacity) {
    const float rx=fabsf(dx)*length+fabsf(dy)*width;
    const float ry=fabsf(dy)*length+fabsf(dx)*width;
    const int x0=(int)floorf((cx-rx)*2.0f),y0=(int)floorf((cy-ry)*2.0f);
    const int x1=(int)ceilf((cx+rx)*2.0f),y1=(int)ceilf((cy+ry)*2.0f);
    for(int iy=y0;iy<y1;iy++) for(int ix=x0;ix<x1;ix++) {
        if(limit-*out<6) return;
        const float fx=(float)ix*0.5f,fy=(float)iy*0.5f;
        const gw_native_vertex a=native_shadow_vertex(mesh,fx,fy,cx,cy,dx,dy,length,width,opacity);
        const gw_native_vertex b=native_shadow_vertex(mesh,fx+0.5f,fy,cx,cy,dx,dy,length,width,opacity);
        const gw_native_vertex c=native_shadow_vertex(mesh,fx,fy+0.5f,cx,cy,dx,dy,length,width,opacity);
        const gw_native_vertex d=native_shadow_vertex(mesh,fx+0.5f,fy+0.5f,cx,cy,dx,dy,length,width,opacity);
        native_quad(out,b,d,a,c);
    }
}

static void native_bind(int unit,GLuint tex,GLint loc) {
    g_bloom.ActiveTexture(GL_TEXTURE0+(GLenum)unit);
    g_bloom.BindTexture(GL_TEXTURE_2D,tex);
    g_bloom.Uniform1i(loc,unit);
}

/* The original observer supplies the exact last writer. Confirm direct
   RGBA conversions on those pixels before discarding their legacy colour.
   Tolerates isolated 2D overlays (cursor, selection arrows, drag box, horizon
   clean-up) by leaving mismatched pixels in 2D instead of rejecting the whole
   entity and causing flicker/jumps. */
static unsigned native_validate(const gw_interactive_visual_snapshot *v,uint8_t *owned,
                                uint8_t *accepted) {
    const gw_atlas_probe_frame *f=&v->atlas_probe;
    uint32_t hits[GW_NATIVE_DRAWS]={0};
    uint32_t misses[GW_NATIVE_DRAWS]={0};
    memset(owned,0,v->entity_coverage_bytes);
    for(unsigned i=0;i<f->draw_count;i++) accepted[i]=(uint8_t)(!f->draws[i].extra && g_native_uploaded[f->draws[i].slot-1u]);
    for(size_t p=0;p<v->entity_coverage_bytes;p++) {
        const unsigned ref=v->entity_coverage[p];
        if(!ref || ref>f->draw_count || !accepted[ref-1u]) continue;
        const gw_native_draw *d=&f->draws[ref-1u];
        const unsigned slot=d->slot-1u;
        const gw_sprite_atlas_key *k=&f->items[slot].key;
        const int x=(int)(p%GW_CANVAS_W)-d->x,y=(int)(p/GW_CANVAS_W)-d->y;
        if(x<0 || y<0 || x>=k->width || y>=k->height) {
            misses[ref-1u]++;
            continue;
        }
        const uint8_t *rgba=f->pixels+f->items[slot].offset+4u*((unsigned)y*k->width+(unsigned)x);
        const uint8_t *pal=v->palette+3u*v->canvas[p];
        if(!rgba[3] || (rgba[3]==255u &&
           (rgba[0]!=pal[0]*255u/63u || rgba[1]!=pal[1]*255u/63u || rgba[2]!=pal[2]*255u/63u))) {
            misses[ref-1u]++;
            continue;
        }
        hits[ref-1u]++;
        owned[p]=(uint8_t)ref;
    }
    unsigned count=0,rejected=0;
    for(unsigned i=0;i<f->draw_count;i++) {
        const int ok=accepted[i] && hits[i]>0u && hits[i]*3u>=misses[i];
        if(accepted[i] && !ok) rejected=1;
        accepted[i]=(uint8_t)ok;
        count+=accepted[i];
    }
    if(rejected) {
        for(size_t p=0;p<v->entity_coverage_bytes;p++) {
            const unsigned o=owned[p];
            if(o && o<=f->draw_count && !accepted[o-1u]) owned[p]=0u;
        }
    }
    return count;
}

static int native_gl_render(const gw_interactive_visual_snapshot *v,const gw_terrain_mesh_draw *mesh) {
    g_native_gl.valid[1]=0;
    if(!v || !v->atlas_active || v->entity_coverage_bytes!=GW_CANVAS_W*GW_CANVAS_H ||
       !v->atlas_probe.draw_count || !g_atlas_probe_gl.texture) return 0;
    static uint8_t ownership[GW_CANVAS_W*GW_CANVAS_H];
    const gw_atlas_probe_frame *f=&v->atlas_probe;
    uint8_t accepted[GW_NATIVE_DRAWS]={0};
    const unsigned ready=native_validate(v,ownership,accepted);
    static unsigned reports;
    if(reports++<12u)
        gw_flag_trace("TRACE native entities turn=%u stride=%u verified=%u/%u%c",
                      f->turn,GW_CANVAS_W,ready,f->draw_count,10);
    if(!ready || !native_gl_init()) return 0;
    g_bloom.ActiveTexture(GL_TEXTURE0);
    g_bloom.BindTexture(GL_TEXTURE_2D,g_native_gl.mask);
    g_bloom.PixelStorei(GL_UNPACK_ROW_LENGTH,0);
    g_bloom.TexSubImage2D(GL_TEXTURE_2D,0,0,0,1152,640,GL_RED,GL_UNSIGNED_BYTE,ownership);

    static gw_native_vertex vertices[GW_NATIVE_SHADOW_VERTICES+6u*GW_NATIVE_DRAWS];
    gw_native_vertex *end=vertices;
    uint32_t seen[GW_NATIVE_DRAWS];
    unsigned seen_count=0;
    const float sun_len=sqrtf(g_t3.sun[0]*g_t3.sun[0]+g_t3.sun[1]*g_t3.sun[1]);
    const float dx=sun_len>0.01f?-g_t3.sun[0]/sun_len:1.0f;
    const float dy=sun_len>0.01f?-g_t3.sun[1]/sun_len:0.0f;
    for(unsigned i=0;i<f->draw_count;i++) {
        if(!accepted[i]) continue;
        const gw_native_draw *d=&f->draws[i];
        if(d->entity.type==GW_ENTITY_EFFECT ||
           f->items[d->slot-1u].key.blend==GW_SPRITE_BLIT_DESTINATION) continue;
        unsigned j=0;
        while(j<seen_count && seen[j]!=d->entity.guest_address) j++;
        if(j<seen_count) continue;
        seen[seen_count++]=d->entity.guest_address;
        const gw_sprite_atlas_key *key=&f->items[d->slot-1u].key;
        const float x=native_relative(d->entity.world_x_q8,mesh->view_col);
        const float y=native_relative(d->entity.world_y_q8,mesh->view_row);
        float r_ao=0.35f;
        if(d->entity.type==GW_ENTITY_PLANT) r_ao=fminf(0.80f,fmaxf(0.28f,key->width/70.0f));
        else if(d->entity.type==GW_ENTITY_BUILDING) r_ao=fminf(1.35f,fmaxf(0.48f,key->width/54.0f));
        else r_ao=fminf(0.42f,fmaxf(0.22f,key->width/54.0f));
        const float h=fmaxf(0.0f,(d->entity.world_z_q6-d->entity.ground_q6*mesh->height_scale)/64.0f);
        const float cast=fminf(2.4f,fmaxf(0.28f,(h+key->height*0.42f)*sun_len/
                         (39.19f*fmaxf(0.30f,g_t3.sun[2]))));
        /* Single unified 3D shadow per entity (no overlapping AO + cast double-darkening):
           anchored at feet when grounded, shifting smoothly along sun direction and softening with altitude. */
        const float air_shift=h>=4.0f?(h*sun_len/(39.19f*fmaxf(0.30f,g_t3.sun[2])))*0.50f:0.0f;
        const float alt_soft=1.0f/(1.0f+h*0.016f);
        const float base_op=(d->entity.type==GW_ENTITY_BUILDING)?0.44f:(d->entity.type==GW_ENTITY_PLANT?0.40f:0.38f);
        const float sh_len=r_ao*0.85f+cast*0.52f;
        const float sh_wid=r_ao*(0.88f+0.14f*fminf(1.0f,h/36.0f));
        native_shadow(&end,vertices+GW_NATIVE_SHADOW_VERTICES,mesh,
                      x+dx*(cast*0.36f+air_shift),y+dy*(cast*0.36f+air_shift),
                      dx,dy,sh_len,sh_wid,base_op*alt_soft);
    }
    /* Ethereal ship / landing rocket shadow (caller k=1, ev_ship): project a single clean 3D shadow
       on MapHeight when its 2D shadow is suppressed and no entity shadow already covers it. */
    if(v->ev_ship_n>30 && mesh->count) {
        float sx_w=0.0f,sy_w=0.0f,sz_w=0.0f;
        const float scx=v->ev_ship_x+v->ev_ship_w*0.5f,scy=v->ev_ship_y+v->ev_ship_h*0.5f;
        /* Convert screen centre to local grid using the terrain mesh */
        const float dd=scx/32.0f,ss=scy/16.0f;
        float gx=(ss+dd)*0.5f,gy=(ss-dd)*0.5f;
        /* Refine height once for isometric y = 16*(x+y) - h */
        const float gh=native_ground_hpx(mesh,gx,gy);
        const float ss2=(scy+gh)/16.0f;
        sx_w=(ss2+dd)*0.5f; sy_w=(ss2-dd)*0.5f;
        (void)sz_w;
        const float rx_s=fminf(2.2f,fmaxf(0.55f,(float)v->ev_ship_w/58.0f));
        const float ry_s=fminf(1.8f,fmaxf(0.45f,(float)v->ev_ship_h/38.0f));
        native_shadow(&end,vertices+GW_NATIVE_SHADOW_VERTICES,mesh,
                      sx_w,sy_w,dx,dy,rx_s,ry_s,0.38f);
    }
    const GLsizei shadows=(GLsizei)(end-vertices);
    float depth[GW_NATIVE_DRAWS];
    unsigned translucent[GW_NATIVE_DRAWS],nt=0;
    for(unsigned i=0;i<f->draw_count;i++) {
        if(!accepted[i]) continue;
        const gw_native_draw *d=&f->draws[i];
        const unsigned slot=d->slot-1u;
        const float rx=native_relative(d->entity.world_x_q8,mesh->view_col);
        const float ry=native_relative(d->entity.world_y_q8,mesh->view_row);
        depth[i]=native_depth(rx,ry,d->entity.world_z_q6/64.0f);
        if(f->items[slot].key.blend==GW_SPRITE_BLIT_DESTINATION) {
            unsigned j=nt++;
            while(j && depth[translucent[j-1u]]<depth[i]) {
                translucent[j]=translucent[j-1u];
                j--;
            }
            translucent[j]=i;
        } else {
            const float sink=native_slope_sink_px(mesh,&d->entity,g_native_rects[slot].w,rx,ry);
            native_billboard(&end,d,g_native_rects[slot],i+1u,depth[i],sink,rx,ry);
        }
    }
    const GLsizei opaque=(GLsizei)(end-vertices);
    for(unsigned j=0;j<nt;j++) {
        const unsigned i=translucent[j];
        const gw_native_draw *d=&f->draws[i];
        const unsigned slot=d->slot-1u;
        const float rx=native_relative(d->entity.world_x_q8,mesh->view_col);
        const float ry=native_relative(d->entity.world_y_q8,mesh->view_row);
        const float sink=native_slope_sink_px(mesh,&d->entity,g_native_rects[slot].w,rx,ry);
        native_billboard(&end,d,g_native_rects[slot],i+1u,depth[i],sink,rx,ry);
    }

    g_bloom.BindFramebuffer(GL_FRAMEBUFFER,g_gl_mesh.fbo);
    g_bloom.FramebufferTexture2D(GL_FRAMEBUFFER,GL_COLOR_ATTACHMENT0,GL_TEXTURE_2D,g_native_gl.layers[1],0);
    g_gl_mesh.PushAttrib(GL_DEPTH_BUFFER_BIT|GL_ENABLE_BIT|GL_COLOR_BUFFER_BIT);
    g_bloom.Viewport(0,0,1152,640);
    g_bloom.Disable(GL_CULL_FACE); g_bloom.Disable(GL_DITHER);
    g_bloom.ClearColor(0.0f,0.0f,0.0f,1.0f); g_bloom.Clear(GL_COLOR_BUFFER_BIT);
    g_bloom.Enable(GL_DEPTH_TEST);
    g_gl_mesh.DepthFunc(GL_LEQUAL);
    g_gl_mesh.DepthMask(GL_TRUE);
    g_bloom.Enable(GL_BLEND);
    /* Store premultiplied colour and remaining background in alpha. */
    g_bloom.BlendFuncSeparate(GL_SRC_ALPHA,GL_ONE_MINUS_SRC_ALPHA,GL_ZERO,GL_ONE_MINUS_SRC_ALPHA);
    g_bloom.UseProgram(g_native_gl.shader);
    g_bloom.Uniform1f(g_native_gl.reflect,0.0f);
    g_bloom.Uniform1f(g_native_gl.light_on,g_t3.ready && g_ini_terrain_3d_entity_lighting?1.0f:0.0f);
    int lights=0;
    if(g_t3.ready) {
        g_t3.Uniform3f(g_native_gl.sun,g_t3.sun[0],g_t3.sun[1],g_t3.sun[2]);
        g_t3.Uniform3f(g_native_gl.sunc,g_t3.sunc[0],g_t3.sunc[1],g_t3.sunc[2]);
        g_t3.Uniform3f(g_native_gl.sky,g_t3.sky[0],g_t3.sky[1],g_t3.sky[2]);
        if(g_pl_on && g_ini_terrain_3d_lights && g_ini_terrain_3d_entity_lighting) lights=g_t3.pl_n;
        if(lights) {
            g_t3.Uniform4fv(g_native_gl.plpos,lights,&g_t3.pl_pos[0][0]);
            g_t3.Uniform4fv(g_native_gl.plcol,lights,&g_t3.pl_col[0][0]);
        }
    }
    g_bloom.Uniform1i(g_native_gl.plcount,lights);
    native_bind(0,g_atlas_probe_gl.texture,g_native_gl.sprites);
    native_bind(1,g_native_gl.mask,g_native_gl.ownership);
    native_bind(2,g_gm.t_ring,g_native_gl.ring);
    g_bloom.Uniform2f(g_native_gl.offset,(float)g_gm.ring_x,(float)g_gm.ring_y);
    g_bloom.BindBuffer(GL_ARRAY_BUFFER,g_bloom.vbo);
    g_bloom.BufferData(GL_ARRAY_BUFFER,(size_t)(end-vertices)*sizeof *vertices,vertices,GL_STREAM_DRAW);
    g_bloom.VertexAttribPointer(0,3,GL_FLOAT,GL_FALSE,sizeof *vertices,(const void *)0);
    g_bloom.VertexAttribPointer(1,2,GL_FLOAT,GL_FALSE,sizeof *vertices,(const void *)offsetof(gw_native_vertex,u));
    g_bloom.VertexAttribPointer(2,1,GL_FLOAT,GL_FALSE,sizeof *vertices,(const void *)offsetof(gw_native_vertex,owner));
    g_bloom.EnableVertexAttribArray(3);
    g_bloom.VertexAttribPointer(3,4,GL_FLOAT,GL_FALSE,sizeof *vertices,(const void *)offsetof(gw_native_vertex,wx));
    g_gl_mesh.DepthMask(GL_FALSE);
    g_bloom.Enable(GL_POLYGON_OFFSET_FILL);
    g_gl_mesh.PolygonOffset(-2.0f,-2.0f);
    g_bloom.DrawArrays(GL_TRIANGLES,0,shadows);
    g_bloom.Disable(GL_POLYGON_OFFSET_FILL);
    g_gl_mesh.DepthMask(GL_TRUE);
    g_bloom.DrawArrays(GL_TRIANGLES,shadows,opaque-shadows);
    g_gl_mesh.DepthMask(GL_FALSE);
    g_bloom.DrawArrays(GL_TRIANGLES,opaque,(GLsizei)(end-vertices)-opaque);
    if(g_t3.reflected[1]) {
        g_bloom.BindFramebuffer(GL_FRAMEBUFFER,g_t3.reflect_fbo);
        g_bloom.Viewport(0,0,TL_REFLECT_W,TL_REFLECT_H);
        g_bloom.Uniform1f(g_native_gl.reflect,1.0f);
        g_gl_mesh.DepthMask(GL_TRUE);
        g_bloom.DrawArrays(GL_TRIANGLES,shadows,opaque-shadows);
        g_gl_mesh.DepthMask(GL_FALSE);
        g_bloom.DrawArrays(GL_TRIANGLES,opaque,(GLsizei)(end-vertices)-opaque);
        g_bloom.BindFramebuffer(GL_FRAMEBUFFER,g_gl_mesh.fbo);
    }
    g_bloom.DisableVertexAttribArray(3);
    g_bloom.VertexAttribPointer(0,2,GL_FLOAT,GL_FALSE,6*sizeof(float),(const void *)0);
    g_bloom.VertexAttribPointer(1,2,GL_FLOAT,GL_FALSE,6*sizeof(float),(const void *)(2*sizeof(float)));
    g_bloom.VertexAttribPointer(2,2,GL_FLOAT,GL_FALSE,6*sizeof(float),(const void *)(4*sizeof(float)));
    g_gl_mesh.PopAttrib();
    g_bloom.FramebufferTexture2D(GL_FRAMEBUFFER,GL_COLOR_ATTACHMENT0,GL_TEXTURE_2D,g_gl_mesh.color,0);
    g_bloom.ActiveTexture(GL_TEXTURE0);
    return g_native_gl.valid[1]=1;
}

static void native_gl_rotate(void) {
    const GLuint t=g_native_gl.layers[0];
    g_native_gl.layers[0]=g_native_gl.layers[1];
    g_native_gl.layers[1]=g_native_gl.layers[2];
    g_native_gl.layers[2]=t;
    g_native_gl.valid[0]=g_native_gl.valid[1];
    g_native_gl.valid[1]=0;
}

#endif
