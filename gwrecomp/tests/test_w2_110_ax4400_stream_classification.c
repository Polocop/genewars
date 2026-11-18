#include "gw_dos_services.h"
#include "gw_interrupts.h"
#include "gw_segments.h"
#include <stdint.h>
#include <stdio.h>

uint32_t g_eax, g_ebx, g_ecx, g_edx, g_esi, g_edi, g_ebp, g_esp, g_cur_func;
uint16_t g_seg_cs, g_seg_ds, g_seg_es, g_seg_fs, g_seg_gs, g_seg_ss;
uint32_t g_fs_base, g_gs_base, g_flag_cf;
ptrdiff_t g_mem_base;

typedef struct {
    uint32_t eax, ebx, ecx, edx, esi, edi, ebp, esp, cf;
    uint16_t cs, ds, es, fs, gs, ss;
} cpu_snapshot;

static cpu_snapshot capture(void) {
    cpu_snapshot s = {g_eax, g_ebx, g_ecx, g_edx, g_esi, g_edi, g_ebp,
                      g_esp, g_flag_cf, g_seg_cs, g_seg_ds, g_seg_es,
                      g_seg_fs, g_seg_gs, g_seg_ss};
    return s;
}

static int unchanged(cpu_snapshot s) {
    return s.eax == g_eax && s.ebx == g_ebx && s.ecx == g_ecx &&
           s.edx == g_edx && s.esi == g_esi && s.edi == g_edi &&
           s.ebp == g_ebp && s.esp == g_esp && s.cf == g_flag_cf &&
           s.cs == g_seg_cs && s.ds == g_seg_ds && s.es == g_seg_es &&
           s.fs == g_seg_fs && s.gs == g_seg_gs && s.ss == g_seg_ss;
}

static uint16_t sink_write(void *user, const uint8_t *buffer,
                           uint16_t requested, uint16_t *transferred) {
    (void)user;
    (void)buffer;
    *transferred = requested;
    return 0;
}

static void seed_cpu(void) {
    g_eax = 0xA5A54400u;
    g_ebx = 1u;
    g_ecx = 0xC1C2C3C4u;
    g_edx = 0xD1D2D3D4u;
    g_esi = 0x51525354u;
    g_edi = 0x61626364u;
    g_ebp = 0x71727374u;
    g_esp = 0x81828384u;
    g_flag_cf = 1u;
    g_seg_cs = 0x000Cu;
    g_seg_ds = 0x0014u;
    g_seg_es = 0x0024u;
    g_seg_fs = 0x0034u;
    g_seg_gs = 0x0044u;
    g_seg_ss = 0x0054u;
}

int main(void) {
    gw_dos_services services;
    gw_dos_services_init(&services);

    if (!gw_dos_stream_configure(&services, 1u, 0, sink_write, 0, 1)) return 2;
    seed_cpu();
    cpu_snapshot request = capture();
    gw_interrupt_result result =
        gw_dos_services_callback(0x21u, 0x000C8973u, &services);
    if (result != GW_INTERRUPT_HANDLED || g_eax != 0xA5A50082u ||
        g_edx != 0xD1D20082u || g_flag_cf != 0u || g_ebx != request.ebx ||
        g_ecx != request.ecx || g_esi != request.esi || g_edi != request.edi ||
        g_ebp != request.ebp || g_esp != request.esp ||
        g_seg_cs != request.cs || g_seg_ds != request.ds ||
        g_seg_es != request.es || g_seg_fs != request.fs ||
        g_seg_gs != request.gs || g_seg_ss != request.ss) {
        fprintf(stderr, "FAIL configured character stream result/preservation\n");
        return 3;
    }

    gw_dos_services_init(&services);
    if (!gw_dos_stream_configure(&services, 1u, 0, sink_write, 0, 0)) return 4;
    seed_cpu();
    request = capture();
    result = gw_dos_services_callback(0x21u, 0x000C8973u, &services);
    if (result != GW_INTERRUPT_TRAPPED || !unchanged(request)) {
        fprintf(stderr, "FAIL redirected stream without IOCTL metadata must trap unchanged\n");
        return 5;
    }

    puts("PASS synthetic AX=4400 BX=1: configured device AX/DX=0x82 CF=0; redirected stream traps unchanged");
    return 0;
}
