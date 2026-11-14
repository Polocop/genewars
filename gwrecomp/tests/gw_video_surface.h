#ifndef GW_VIDEO_SURFACE_H
#define GW_VIDEO_SURFACE_H

#include <stdint.h>
#include <stddef.h>

typedef struct gw_video_rect {
    int x, y, w, h;
} gw_video_rect;

typedef struct gw_video_surface {
    uint8_t *pixels;
    int width;
    int height;
    int pitch_bytes;
    int format; /* 1 = indexed 8-bit; 2 = ARGB8888 */
    gw_video_rect clip;
} gw_video_surface;

static inline int gw_video_surface_valid(const gw_video_surface *s) {
    return s && s->pixels && s->width > 0 && s->height > 0 &&
        s->pitch_bytes >= s->width && s->format == 1 &&
        s->clip.x >= 0 && s->clip.y >= 0 && s->clip.w >= 0 && s->clip.h >= 0 &&
        s->clip.x <= s->width && s->clip.y <= s->height &&
        s->clip.w <= s->width - s->clip.x &&
        s->clip.h <= s->height - s->clip.y;
}

static inline const uint8_t *gw_video_surface_row(const gw_video_surface *s, int y) {
    return (s && s->pixels && y >= 0 && y < s->height) ?
        s->pixels + (size_t)y * (size_t)s->pitch_bytes : 0;
}

static inline int gw_video_window_to_surface(int wx, int wy, int window_w, int window_h,
                                               gw_video_rect output,
                                               const gw_video_surface *surface,
                                               int *sx, int *sy) {
    if (!surface || !sx || !sy || window_w <= 0 || window_h <= 0 ||
        output.w <= 0 || output.h <= 0 || wx < 0 || wy < 0 ||
        wx >= window_w || wy >= window_h) return 0;
    /* SDL event coordinates and this rectangle use window-point coordinates.
       The caller must map to that same coordinate space (renderer output
       pixels are a separate space on HiDPI displays). */
    if (wx < output.x || wy < output.y || wx >= output.x+output.w || wy >= output.y+output.h)
        return 0;
    *sx=(int)((int64_t)(wx-output.x)*surface->width/output.w);
    *sy=(int)((int64_t)(wy-output.y)*surface->height/output.h);
    return *sx>=0 && *sx<surface->width && *sy>=0 && *sy<surface->height;
}

#endif
