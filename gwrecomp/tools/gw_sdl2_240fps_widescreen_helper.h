#ifndef GW_SDL2_240FPS_WIDESCREEN_HELPER_H
#define GW_SDL2_240FPS_WIDESCREEN_HELPER_H

#include <SDL.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef _WIN32
#include <windows.h>
#include <mmsystem.h>
#endif

typedef struct {
    uint64_t perf_freq;
    uint64_t target_frame_ticks;
    uint64_t last_frame_time;
    double target_fps;
    bool time_period_active;
} GWPacer;

typedef struct {
    int logical_w;
    int logical_h;
    int viewport_x;
    int viewport_y;
    int viewport_w;
    int viewport_h;
    float scale;
    bool widescreen_mode;
} GWViewport;

static inline void gw_pacer_init(GWPacer *pacer, double target_fps) {
    pacer->perf_freq = SDL_GetPerformanceFrequency();
    pacer->target_fps = target_fps;
    pacer->target_frame_ticks = (uint64_t)((double)pacer->perf_freq / target_fps);
    pacer->last_frame_time = SDL_GetPerformanceCounter();
    pacer->time_period_active = false;
#ifdef _WIN32
    if (timeBeginPeriod(1) == TIMERR_NOERROR) {
        pacer->time_period_active = true;
    }
#endif
}

static inline void gw_pacer_cleanup(GWPacer *pacer) {
#ifdef _WIN32
    if (pacer->time_period_active) {
        timeEndPeriod(1);
        pacer->time_period_active = false;
    }
#endif
}

static inline void gw_pacer_wait(GWPacer *pacer) {
    uint64_t now = SDL_GetPerformanceCounter();
    uint64_t elapsed = now - pacer->last_frame_time;

    if (elapsed < pacer->target_frame_ticks) {
        uint64_t remaining_ticks = pacer->target_frame_ticks - elapsed;
        double remaining_ms = ((double)remaining_ticks * 1000.0) / (double)pacer->perf_freq;

        if (remaining_ms > 1.5) {
            SDL_Delay((Uint32)(remaining_ms - 1.0));
        }

        while ((SDL_GetPerformanceCounter() - pacer->last_frame_time) < pacer->target_frame_ticks) {
#if defined(_MSC_VER) || defined(__GNUC__)
            #if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
            __builtin_ia32_pause();
            #endif
#endif
        }
    }
    pacer->last_frame_time = SDL_GetPerformanceCounter();
}

static inline void gw_viewport_update(GWViewport *vp, int window_w, int window_h, bool widescreen_16_9) {
    vp->logical_w = 640;
    vp->logical_h = 480;
    vp->widescreen_mode = widescreen_16_9;

    if (widescreen_16_9) {
        vp->viewport_x = 0;
        vp->viewport_y = 0;
        vp->viewport_w = window_w;
        vp->viewport_h = window_h;
        vp->scale = (float)window_w / (float)vp->logical_w;
    } else {
        float aspect_target = 4.0f / 3.0f;
        float window_aspect = (float)window_w / (float)window_h;

        if (window_aspect > aspect_target) {
            vp->viewport_h = window_h;
            vp->viewport_w = (int)((float)window_h * aspect_target);
            vp->viewport_x = (window_w - vp->viewport_w) / 2;
            vp->viewport_y = 0;
            vp->scale = (float)vp->viewport_h / (float)vp->logical_h;
        } else {
            vp->viewport_w = window_w;
            vp->viewport_h = (int)((float)window_w / aspect_target);
            vp->viewport_x = 0;
            vp->viewport_y = (window_h - vp->viewport_h) / 2;
            vp->scale = (float)vp->viewport_w / (float)vp->logical_w;
        }
    }
}

static inline bool gw_mouse_to_logical(const GWViewport *vp, int window_x, int window_y, int *out_game_x, int *out_game_y) {
    if (window_x < vp->viewport_x || window_x >= (vp->viewport_x + vp->viewport_w) ||
        window_y < vp->viewport_y || window_y >= (vp->viewport_y + vp->viewport_h)) {
        return false;
    }

    int rel_x = window_x - vp->viewport_x;
    int rel_y = window_y - vp->viewport_y;

    *out_game_x = (int)((float)rel_x * (float)vp->logical_w / (float)vp->viewport_w);
    *out_game_y = (int)((float)rel_y * (float)vp->logical_h / (float)vp->viewport_h);

    if (*out_game_x < 0) *out_game_x = 0;
    if (*out_game_x >= vp->logical_w) *out_game_x = vp->logical_w - 1;
    if (*out_game_y < 0) *out_game_y = 0;
    if (*out_game_y >= vp->logical_h) *out_game_y = vp->logical_h - 1;

    return true;
}

#endif