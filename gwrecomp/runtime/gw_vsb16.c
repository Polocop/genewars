#include "gw_vsb16.h"
#include <SDL.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

/* Offsets inside the AIL3DIG driver data area (SB16.DIG, verified against its machine code):
   0x16 IO base, 0x18 IRQ, 0x1A DMA8, 0x1C DMA16 (IO_PARMS)    0x4FC/0x4FE/0x500 DMA buffer: start offset, segment, second-half offset
   0x504 current DMA half (0/1, 0xFFFF idle; toggled by the driver ISR)    0x57A DSP version    0x58C hardware volume
   0x590 playback state: 0 idle, 2 ending (stop requested), 3 playing */
enum { OFF_IO = 0x16, OFF_IRQ = 0x18, OFF_DMA8 = 0x1A, OFF_DMA16 = 0x1C, OFF_DST_START = 0x4FC, OFF_DST_SEG = 0x4FE,
       OFF_DST_MID = 0x500, OFF_HALF = 0x504, OFF_DSPVER = 0x57A, OFF_HWVOL = 0x58C, OFF_STATE = 0x590 };

static struct {
    int enabled;
    SDL_AudioDeviceID dev;
    int sdl_audio_ok;
    unsigned rate, fmt;                 /* fmt: 0 u8 mono, 1 s16 mono, 2 u8 stereo, 3 s16 stereo (driver table @0x556) */
    uint32_t dma_start_lin, half_bytes, drv_base;
    FILE *capture;
    gw_vsb16_stats st;
    int pump_disabled;
    int had_queue_this_playback;
} g;

static int range_ok(uint32_t sz, uint32_t at, uint32_t len) { return at <= sz && len <= sz - at; }
static uint16_t rd16(const uint8_t *m, uint32_t sz, uint32_t at) { return (m && range_ok(sz, at, 2u)) ? (uint16_t)(m[at] | (m[at + 1] << 8)) : 0xFFFFu; }
static void wr16(uint8_t *m, uint32_t sz, uint32_t at, uint16_t v) { if (m && range_ok(sz, at, 2u)) { m[at] = (uint8_t)v; m[at + 1] = (uint8_t)(v >> 8); } }

#include <stdarg.h>
static FILE *g_logf; static int g_logf_init;
static void vlog(const char *fmt, ...) {
    va_list ap; char buf[512];
    va_start(ap, fmt); vsnprintf(buf, sizeof buf, fmt, ap); va_end(ap);
    fputs(buf, stderr);
    if (!g_logf_init) { const char *p = getenv("GW_VSB16_LOG"); g_logf_init = 1; if (p && *p) g_logf = fopen(p, "ab"); }
    if (g_logf) { fputs(buf, g_logf); fflush(g_logf); }
}
void gw_vsb16_log(const char *text) { vlog("%s", text); }
static uint32_t rd32(const uint8_t *m, uint32_t sz, uint32_t at) { return (m && range_ok(sz, at, 4u)) ? (uint32_t)(m[at] | (m[at + 1] << 8) | (m[at + 2] << 16) | ((uint32_t)m[at + 3] << 24)) : 0u; }

/* Read-only observer of the game's sound state (guest addresses = link VA + 0x1DA000, V20 diagnostics):
 * SoundInstalled 0x37A6C8, slot count 0x2E54E4, slot table 0x37A3A4 (25 B/slot: +0 HSAMPLE, +4 vol, +8 pitch, +0xA pan,
 * +0xE owner, +0x12 id), sample table ptr 0x37A6CC (32 B/entry), HSAMPLE status at +4 (1 free,2 done,4 playing,8 stopped). */
static void observe(const uint8_t *m, uint32_t sz) {
    static uint8_t last_inst = 0xFF; static uint32_t last_st[64], last_id[64];
    const uint8_t inst = (0x37A6C8u < sz) ? m[0x37A6C8u] : 0xFF;
    if (inst != last_inst) { last_inst = inst; vlog("TRACE vsb16 observe SoundInstalled=%u dig=%08x\n", inst, rd32(m, sz, 0x37A6DCu)); }
    if (!inst) return;
    uint32_t n = rd16(m, sz, 0x2E54E4u); if (n > 64) n = 64;
    const uint32_t tbl = rd32(m, sz, 0x37A6CCu);
    for (uint32_t i = 0; i < n; i++) {
        const uint32_t s = 0x37A3A4u + i * 0x19u, h = rd32(m, sz, s);
        if (!h || !range_ok(sz, h, 0x48u)) continue;
        const uint32_t st = rd32(m, sz, h + 4u), id = rd16(m, sz, s + 0x12u);
        if (st == last_st[i] && id == last_id[i]) continue;
        last_st[i] = st; last_id[i] = id;
        char name[20] = "?"; const uint32_t table_bytes = (id + 1u) * 32u;
        if (tbl && range_ok(sz, tbl, table_bytes)) { memcpy(name, m + tbl + id * 32u, 16); name[16] = 0; }
        vlog("TRACE vsb16 observe slot=%u hsample=%08x status=%u id=%u name='%s' vol=%u pitch=%u pan=%u owner=%04x rate=%u dig_vol=%u dig_pan=%u\n",
             i, h, st, id, name, m[s + 4u], rd16(m, sz, s + 8u), m[s + 0xAu], rd16(m, sz, s + 0xEu), rd32(m, sz, h + 0x3Cu), rd32(m, sz, h + 0x40u), rd32(m, sz, h + 0x44u));
        if (id) { char hx[400]; int o = 0; for (uint32_t k = 0; k < 0x60u && o < 380; k += 4) o += snprintf(hx + o, sizeof hx - o, "%08x ", rd32(m, sz, h + k)); vlog("TRACE vsb16 observe   hsample dump %s\n", hx); }
    }
}

void gw_vsb16_configure(int enabled) { g.enabled = enabled; g.st.enabled = enabled; }
int gw_vsb16_enabled(void) { return g.enabled; }
const gw_vsb16_stats *gw_vsb16_get_stats(void) { return &g.st; }

static void sink_close(void) {
    if (g.dev) { SDL_ClearQueuedAudio(g.dev); SDL_CloseAudioDevice(g.dev); g.dev = 0; }
    g.st.device_open = 0;
}
void gw_vsb16_close(void) {
    sink_close();
    if (g.capture) { fclose(g.capture); g.capture = NULL; }
    if (g.enabled) vlog("TRACE vsb16 close calls=%llu starts=%llu stops=%llu halves=%llu bytes=%llu service_calls=%llu service_failures=%llu nonzero_halves=%llu peak=%llu full_scale_endpoints=%llu queue_failures=%llu dma_range_failures=%llu alloc_failures=%llu underruns=%llu queue_min=%u queue_max=%u\n",
        (unsigned long long)g.st.calls, (unsigned long long)g.st.starts, (unsigned long long)g.st.stops, (unsigned long long)g.st.halves,
        (unsigned long long)g.st.bytes_pushed, (unsigned long long)g.st.service_calls, (unsigned long long)g.st.service_failures,
        (unsigned long long)g.st.nonzero_halves, (unsigned long long)g.st.peak_abs,
        (unsigned long long)g.st.full_scale_endpoint_samples, (unsigned long long)g.st.queue_failures,
        (unsigned long long)g.st.dma_range_failures, (unsigned long long)g.st.allocation_failures,
        (unsigned long long)g.st.underruns, g.st.min_queued_bytes_when_pumped, g.st.max_queued_bytes);
}

static int sink_open(unsigned rate) {
    if (g.dev) return 1;
    if (!g.sdl_audio_ok) {
        if (SDL_InitSubSystem(SDL_INIT_AUDIO) != 0) { vlog("TRACE vsb16 SDL audio init failed: %s\n", SDL_GetError()); return 0; }
        g.sdl_audio_ok = 1;
    }
    SDL_AudioSpec want, have; SDL_zero(want);
    want.freq = (int)rate; want.format = AUDIO_S16SYS; want.channels = 2; want.samples = 1024; want.callback = NULL;
    g.dev = SDL_OpenAudioDevice(NULL, 0, &want, &have, 0);   /* no allowed changes: SDL converts to the device format internally */
    if (!g.dev) { vlog("TRACE vsb16 SDL_OpenAudioDevice failed: %s\n", SDL_GetError()); return 0; }
    SDL_PauseAudioDevice(g.dev, 0);
    g.st.device_open = 1;
    vlog("TRACE vsb16 sink open driver=%s requested=%dHz/s16/2ch obtained=%dHz fmt=0x%x ch=%d\n",
        SDL_GetCurrentAudioDriver() ? SDL_GetCurrentAudioDriver() : "?", want.freq, have.freq, (unsigned)have.format, have.channels);
    const char *cap = getenv("GW_VSB16_CAPTURE");
    if (cap && cap[0] && !g.capture) { g.capture = fopen(cap, "wb"); if (g.capture) vlog("TRACE vsb16 local PCM capture (s16 stereo %uHz) -> %s\n", rate, cap); }
    return 1;
}

int gw_vsb16_driver_call(uint8_t *m, uint32_t sz, uint32_t base, uint16_t fn, uint16_t *ax, uint16_t *bx, uint16_t *cx, uint16_t *dx) {
    (void)bx;
    if (!g.enabled || !m || !range_ok(sz, base, 0x600u)) return 0;
    g.st.calls++; g.drv_base = base;
    switch (fn) {
    case 0x302: *ax = 1; break;                                   /* DRV_SERVE: no-op in the driver (mov ax,1; ret) */
    case 0x304:                                                   /* DRV_VERIFY_IO: virtual SB16 profile */
        wr16(m, sz, base + OFF_IRQ, 5); wr16(m, sz, base + OFF_DMA8, 1); wr16(m, sz, base + OFF_DMA16, 5);
        wr16(m, sz, base + OFF_DSPVER, 0x0405);
        *ax = 0x0405;                                             /* driver returns the DSP version (>=0x400 = SB16) on success */
        vlog("TRACE vsb16 AX0304 VERIFY_IO profile=virtual-sb16 IO=%04x IRQ=5 DMA8=1 DMA16=5 DSP=4.05 result_AX=0405\n", rd16(m, sz, base + OFF_IO));
        break;
    case 0x305: wr16(m, sz, base + OFF_HWVOL, 0x6464); *ax = 1; vlog("TRACE vsb16 AX0305 INIT_DEV ok\n"); break;
    case 0x306:
        if (rd16(m, sz, base + OFF_STATE) != 0) { wr16(m, sz, base + OFF_STATE, 0); wr16(m, sz, base + OFF_HALF, 0xFFFF); g.st.stops++; }
        g.st.state = 0; sink_close(); *ax = 1; vlog("TRACE vsb16 AX0306 SHUTDOWN_DEV\n"); break;
    case 0x400:
        if (*dx != 0xFFFF) { uint16_t v = (uint16_t)((*dx << 1) & 0xFF); wr16(m, sz, base + OFF_HWVOL, (uint16_t)((v << 8) | v)); }
        *ax = (uint16_t)((rd16(m, sz, base + OFF_HWVOL) & 0xFF) >> 1); break;
    case 0x401: {                                                 /* DIG_START_PLAYBACK: DX=format index, CX=sample rate */
        if (*dx >= 4) { *ax = 0xFFFF; break; }
        const uint16_t st = rd16(m, sz, base + OFF_STATE);
        g.rate = *cx ? *cx : 22050u; g.fmt = *dx;
        if (st != 2 && st != 3) {                                 /* fresh start: DMA double buffer published by the library in the DST */
            const uint32_t seg = rd16(m, sz, base + OFF_DST_SEG), off = rd16(m, sz, base + OFF_DST_START), mid = rd16(m, sz, base + OFF_DST_MID);
            if (mid < off) { *ax = 0xFFFF; vlog("TRACE vsb16 AX0401 rejected non-monotonic DMA offsets start=%04x mid=%04x\n", off, mid); break; }
            g.half_bytes = (uint16_t)(mid - off);
            const unsigned bps = (*dx & 1u) ? 2u : 1u, channels = (*dx & 2u) ? 2u : 1u;
            const unsigned frame_bytes = bps * channels;
            const uint64_t dma = (uint64_t)seg * 16u + off;
            const uint64_t dma_bytes = (uint64_t)2u * g.half_bytes;
            if (g.half_bytes == 0 || g.half_bytes > 0x8000u || g.half_bytes % frame_bytes != 0u ||
                dma > UINT32_MAX || dma_bytes > UINT32_MAX || !range_ok(sz, (uint32_t)dma, (uint32_t)dma_bytes)) {
                *ax = 0xFFFF;
                vlog("TRACE vsb16 AX0401 rejected dma=%08llx half=%u fmt=%u guest_size=%u\n",
                    (unsigned long long)dma, g.half_bytes, *dx, sz);
                break;
            }
            g.dma_start_lin = (uint32_t)dma;
            if (!sink_open(g.rate)) { *ax = 0xFFFF; break; }
            wr16(m, sz, base + OFF_HALF, 0);
            g.had_queue_this_playback = 0;
            g.st.starts++;
            vlog("TRACE vsb16 AX0401 START_PLAYBACK fmt=%u (%s %s) rate=%u dma=%08x half_bytes=%u\n", g.fmt,
                (g.fmt & 1) ? "s16" : "u8", (g.fmt & 2) ? "stereo" : "mono", g.rate, g.dma_start_lin, g.half_bytes);
        }
        g.st.rate = g.rate; g.st.format = g.fmt; g.st.dma_start = g.dma_start_lin; g.st.half_bytes = g.half_bytes; g.st.state = 3;
        wr16(m, sz, base + OFF_STATE, 3); *ax = 1; break; }
    case 0x402:                                                   /* DIG_END_PLAYBACK: ends at the next half boundary (driver ISR) */
        if (rd16(m, sz, base + OFF_STATE) == 3) { wr16(m, sz, base + OFF_STATE, 2); *ax = 1; vlog("TRACE vsb16 AX0402 END_PLAYBACK requested\n"); } else *ax = 0;
        break;
    case 0x403: case 0x404: *ax = 1; break;
    case 0x400 + 5: *ax = 0xFFFF; break;                          /* 0x405: driver reports unsupported */
    default: return 0;
    }
    return 1;
}

static int push_half(const uint8_t *m, uint32_t sz, uint32_t half_index) {
    const uint64_t at64 = (uint64_t)g.dma_start_lin + (uint64_t)half_index * g.half_bytes;
    const uint32_t at = at64 <= UINT32_MAX ? (uint32_t)at64 : UINT32_MAX;
    const unsigned bps = (g.fmt & 1) ? 2u : 1u, ch = (g.fmt & 2) ? 2u : 1u, frame = bps * ch;
    const unsigned frames = g.half_bytes / frame;
    if (!m || !g.dev || at64 > UINT32_MAX || !range_ok(sz, at, g.half_bytes) || !frames || frames > SIZE_MAX / 4u) {
        g.st.dma_range_failures++;
        g.pump_disabled = 1;
        vlog("TRACE vsb16 pump stopped: invalid DMA half at=%08x bytes=%u guest_size=%u\n", at, g.half_bytes, sz);
        return 0;
    }
    int16_t *out = (int16_t *)malloc((size_t)frames * 4u);
    if (!out) {
        g.st.allocation_failures++;
        g.pump_disabled = 1;
        vlog("TRACE vsb16 pump stopped: PCM conversion allocation failed bytes=%u\n", frames * 4u);
        return 0;
    }
    uint64_t sum = 0, peak = 0;
    for (unsigned i = 0; i < frames; i++) {
        int32_t l, r;
        const uint8_t *p = m + at + (size_t)i * frame;
        if (bps == 2) { l = (int16_t)(p[0] | (p[1] << 8)); r = ch == 2 ? (int16_t)(p[2] | (p[3] << 8)) : l; }
        else { l = ((int)p[0] - 128) * 256; r = ch == 2 ? ((int)p[1] - 128) * 256 : l; }
        out[2 * i] = (int16_t)l; out[2 * i + 1] = (int16_t)r;
        uint32_t a = (uint32_t)(l < 0 ? -l : l); sum += a; if (a > peak) peak = a;
        if (l == INT16_MIN || l == INT16_MAX) g.st.full_scale_endpoint_samples++;
        if (r == INT16_MIN || r == INT16_MAX) g.st.full_scale_endpoint_samples++;
    }
    const uint32_t bytes = frames * 4u;
    if (SDL_QueueAudio(g.dev, out, bytes) != 0) {
        const char *error = SDL_GetError();
        g.st.queue_failures++;
        g.pump_disabled = 1;
        vlog("TRACE vsb16 pump stopped: SDL_QueueAudio failed bytes=%u error='%s'\n", bytes, error ? error : "unknown");
        free(out);
        return 0;
    }
    if (g.capture) {
        const size_t written = fwrite(out, 1u, bytes, g.capture);
        if (written != bytes) {
            vlog("TRACE vsb16 PCM capture stopped short_write=%u expected=%u\n", (unsigned)written, bytes);
            fclose(g.capture); g.capture = NULL;
        }
    }
    g.st.bytes_pushed += frames * 4u; g.st.halves++; g.st.sum_abs += sum;
    g.had_queue_this_playback = 1;
    if (peak) g.st.nonzero_halves++;
    if (peak > g.st.peak_abs) g.st.peak_abs = peak;
    free(out);
    return 1;
}

void gw_vsb16_pump(uint8_t *m, uint32_t sz, int (*service)(void *), void *user) {
    if (!m) return;
    if (g.enabled) { static unsigned tick; if ((++tick % 400u) == 1u) { const uint32_t d = rd32(m, sz, 0x37A6DCu); if (d && d + 0x70u < sz) { char hx[500]; int o = 0; for (uint32_t k = 0; k < 0x6Cu; k += 4) o += snprintf(hx + o, sizeof hx - o, "%08x ", rd32(m, sz, d + k)); vlog("TRACE vsb16 digdump[%u] reent=%08x %s\n", tick, rd32(m, sz, 0x2E6654u), hx); } } }
    if (g.enabled) observe(m, sz);
    if (!g.enabled || g.pump_disabled || !g.dev || !service || !g.drv_base) return;
    const uint32_t base = g.drv_base;
    for (int it = 0; it < 16; it++) {
        const uint16_t state = rd16(m, sz, base + OFF_STATE), half = rd16(m, sz, base + OFF_HALF);
        if (state == 0 || half > 1) return;
        const uint32_t queued = SDL_GetQueuedAudioSize(g.dev), target = g.rate * 4u / 10u;   /* keep ~100 ms ahead */
        if (g.st.queue_observations == 0u || queued < g.st.min_queued_bytes_when_pumped)
            g.st.min_queued_bytes_when_pumped = queued;
        g.st.queue_observations++;
        if (queued > g.st.max_queued_bytes) g.st.max_queued_bytes = queued;
        if (queued == 0u && g.had_queue_this_playback) g.st.underruns++;
        if (queued >= target) return;
        g.st.service_calls++;
        if (!service(user)) { g.st.service_failures++; if (g.st.service_failures >= 3) { g.pump_disabled = 1; vlog("TRACE vsb16 mixer service failed 3 times; pump disabled\n"); } return; }
        if (!push_half(m, sz, half)) return;
        const uint32_t queued_after = SDL_GetQueuedAudioSize(g.dev);
        if (queued_after > g.st.max_queued_bytes) g.st.max_queued_bytes = queued_after;
        if (state == 2) { wr16(m, sz, base + OFF_STATE, 0); wr16(m, sz, base + OFF_HALF, 0xFFFF); g.st.stops++; g.st.state = 0; vlog("TRACE vsb16 playback ended (idle)\n"); return; }
        wr16(m, sz, base + OFF_HALF, (uint16_t)(half ^ 1u));
    }
}
