#ifndef GW_TERRAIN_ATMOSPHERE_H
#define GW_TERRAIN_ATMOSPHERE_H

/* Host presentation weather. No simulation clock, guest writes or shared PRNG. */
static struct {
    uint64_t start,last;
    float weather,weather_time;
} g_atmosphere;

static float atm_smooth(float lo,float hi,float x) {
    const float t=fminf(1.0f,fmaxf(0.0f,(x-lo)/(hi-lo)));
    return t*t*(3.0f-2.0f*t);
}

static void atm_update(int biome) {
    const uint64_t now=SDL_GetPerformanceCounter(),freq=SDL_GetPerformanceFrequency();
    if(!g_atmosphere.start) g_atmosphere.start=g_atmosphere.last=now;
    const double elapsed=(double)(now-g_atmosphere.start)/(double)freq;
    const float dt=(float)((double)(now-g_atmosphere.last)/(double)freq);
    g_atmosphere.last=now;
    static const float intensity[ATM_MODES]={0.0f,0.0f,0.48f,1.0f,0.0f};
    float weather=intensity[g_weather_mode];
    if(g_weather_mode==ATM_AUTO && g_ini_terrain_3d_weather) {
        const float front=0.5f-0.5f*cosf((float)fmod(elapsed,110.0)*(6.2831853f/110.0f)+0.47f*biome);
        weather=atm_smooth(0.22f,0.90f,front);
    }
    if(g_weather_mode==ATM_OFF || (g_weather_mode==ATM_AUTO && !g_ini_terrain_3d_weather))
        g_atmosphere.weather=0.0f;
    else g_atmosphere.weather+=(weather-g_atmosphere.weather)*(1.0f-expf(-dt*2.5f));
    g_atmosphere.weather_time=(float)elapsed;
}

/* Three world-space layers at different heights. x/y are canvas pixels; the layer's height is projected
   along the viewing ray into the isometric world. Independent velocities and cell sizes distinguish depth.
   Coordinates wrap over the same 128-cell world as the terrain. */
#define ATM_GLSL_WEATHER \
    "float weather_layer(vec2 W,float time,float biome,float layer){\n" \
    "  float cells=64.0+layer*32.0, size=cells/128.0;\n" \
    "  vec2 wind=vec2(0.44,0.18)*(1.0+layer*0.37);\n" \
    "  if(biome==1.0) wind*=3.5; else if(biome==3.0) wind*=0.32;\n" \
    "  vec2 grid=(W+vec2(layer*2.3,layer*2.3)-time*wind)*size;\n" \
    "  vec2 id=mod(floor(grid),cells*0.25), p=fract(grid);\n" \
    "  float seed=hh(id+layer*53.0);\n" \
    "  float fall=fract(seed+time*(biome==3.0?0.28+layer*0.10:0.77+layer*0.25));\n" \
    "  vec2 center=vec2(0.24+0.52*hh(id.yx+31.0),0.21+0.58*fall);\n" \
    "  vec2 d=p-center; float life=smoothstep(0.0,0.14,fall)*(1.0-smoothstep(0.85,1.0,fall));\n" \
    "  if(biome==1.0){\n" \
    "    float ember=1.0-smoothstep(0.018,0.066,length(d));\n" \
    "    return life*ember*0.68*smoothstep(0.37,0.9,seed);\n" \
    "  }\n" \
    "  if(biome==3.0) return life*(1.0-smoothstep(0.015,0.095,length(d)))*(0.6+0.4*seed);\n" \
    "  if(biome==5.0 && seed>0.69) return life*(1.0-smoothstep(0.018,0.12,length(d)))*0.9;\n" \
    "  float along=(d.x+d.y)*0.71, across=(d.x-d.y)*0.71;\n" \
    "  return life*(1.0-smoothstep(0.006,0.034,abs(across)))*(1.0-smoothstep(0.08,0.24,abs(along)));\n" \
    "}\n"

#endif
