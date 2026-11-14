#ifndef GW_FAST_HOOKS_H
#define GW_FAST_HOOKS_H
/* Inline fast paths for the per-instruction hooks of generated (lifted) code. Included by gw_recomp_stop.h
 * only when RECOMP_GENERATED_CODE is defined. Each fast path does exactly what the out-of-line runtime
 * function would do in the state it tests for, and calls that function in every other state, so guest
 * results, faults, traps, watches and diagnostics are unchanged:
 *
 *  - gw_recomp_guest_instruction: with no memory diagnostic, an active realtime-PIT context, no latched
 *    port-I/O trap and an EIP other than the instruction watch, the function only records the EIP and
 *    returns 1 (recomp_context.c keeps g_gw_instr_fast in step with that state).
 *  - gw_recomp_trace_branch: does nothing while the trace is disabled; the macro skips the call and the
 *    evaluation of its arguments (recomp_eflags).
 *  - recomp_begin_memory_access_ex / recomp_end_memory_access / recomp_memory_fault_pending: without the
 *    memory diagnostic they only store or read the access state, done inline on the same variables.
 *  - MEM8..MEMD: an access inside a validated window of its segment register (gw_segments.c) is one the
 *    full check accepts with no other effect, so it is translated inline; anything else takes the full
 *    check (recomp_checked_mem_addr), which also fills the windows.
 */
#include "gw_segments.h"
#include "gw_recomp_trace.h"

#ifndef GW_LIKELY
#define GW_LIKELY(x) __builtin_expect(!!(x), 1)
#define GW_UNLIKELY(x) __builtin_expect(!!(x), 0)
#endif

extern int g_gw_instr_fast;
extern uint32_t g_gw_instr_watch_va;
extern uint32_t g_gw_last_guest_va;
extern int g_gw_trace_enabled;
extern uint16_t g_seg_fs, g_seg_gs;
extern uint32_t g_fs_base, g_gs_base;

static inline __attribute__((always_inline)) int gw_recomp_guest_instruction_fast(unsigned int guest_va) {
    if (GW_LIKELY(g_gw_instr_fast && !g_recomp_memory_diag_on && guest_va != g_gw_instr_watch_va)) {
        g_gw_last_guest_va = guest_va;
        return 1;
    }
    return (gw_recomp_guest_instruction)(guest_va);
}
#define gw_recomp_guest_instruction(va) gw_recomp_guest_instruction_fast(va)

#define gw_recomp_trace_branch(callsite, caller, target, eflags, taken) \
    ((void)(GW_UNLIKELY(g_gw_trace_enabled) ? \
        ((gw_recomp_trace_branch)((callsite), (caller), (target), (eflags), (taken)), 0) : 0))

static inline __attribute__((always_inline)) void gw_recomp_begin_memory_access_fast(recomp_segment_id segment, uint32_t width,
        uint32_t instruction_va, uint8_t access, uint32_t instruction_id, const char *mnemonic) {
    if (GW_LIKELY(!g_recomp_memory_diag_on)) {
        g_recomp_access.segment = segment; g_recomp_access.width = width;
        g_recomp_access.instruction_va = instruction_va; g_recomp_access.instruction_id = instruction_id;
        g_recomp_access.kind = access; g_recomp_access.active = 1;
        g_recomp_access.mnemonic = mnemonic ? mnemonic : "";
        return;
    }
    (recomp_begin_memory_access_ex)(segment, width, instruction_va, access, instruction_id, mnemonic);
}
#define recomp_begin_memory_access_ex(seg, w, va, acc, id, mn) \
    gw_recomp_begin_memory_access_fast((seg), (w), (va), (acc), (id), (mn))
#define recomp_end_memory_access() ((void)(g_recomp_access.active = 0, g_recomp_access.width = 0u))
#define recomp_memory_fault_pending() (g_recomp_memory_fault.pending != 0)

static inline __attribute__((always_inline)) uint16_t gw_fast_seg_selector(recomp_segment_id segment) {
    switch (segment) {
    case RECOMP_SEG_CS: return g_seg_cs;
    case RECOMP_SEG_DS: return g_seg_ds;
    case RECOMP_SEG_ES: return g_seg_es;
    case RECOMP_SEG_FS: return g_seg_fs;
    case RECOMP_SEG_GS: return g_seg_gs;
    case RECOMP_SEG_SS: return g_seg_ss;
    default: return 0u;
    }
}
static inline __attribute__((always_inline)) uint32_t gw_fast_seg_base(recomp_segment_id segment) {
    switch (segment) {
    case RECOMP_SEG_CS: return g_cs_base;
    case RECOMP_SEG_DS: return g_ds_base;
    case RECOMP_SEG_ES: return g_es_base;
    case RECOMP_SEG_FS: return g_fs_base;
    case RECOMP_SEG_GS: return g_gs_base;
    case RECOMP_SEG_SS: return g_ss_base;
    default: return 0u;
    }
}

static inline __attribute__((always_inline)) uintptr_t gw_fast_mem_addr(uint32_t linear, uint32_t width) {
    const recomp_segment_id segment = g_recomp_access.segment;
    if (GW_LIKELY(g_recomp_fastmem_ok && g_recomp_access.active && (unsigned)segment < 8u)) {
        const gw_recomp_seg_window *w = &g_recomp_seg_windows[(unsigned)segment];
        if (GW_LIKELY(w->gen == g_recomp_seg_window_gen && linear >= w->lo &&
                      (uint64_t)linear + width <= w->hi &&
                      w->selector == gw_fast_seg_selector(segment) &&
                      w->base == gw_fast_seg_base(segment))) {
#ifdef RECOMP_FLAT_MEMORY
            return (uintptr_t)linear;
#else
            return (uintptr_t)linear + (uintptr_t)g_mem_base;
#endif
        }
    }
    return recomp_checked_mem_addr(linear, width);
}
#undef MEM8
#undef MEM16
#undef MEM32
#undef MEM64
#undef MEMF
#undef MEMD
#define MEM8(addr)   (*(volatile uint8_t  *)gw_fast_mem_addr((uint32_t)(addr),1u))
#define MEM16(addr)  (*(volatile uint16_t *)gw_fast_mem_addr((uint32_t)(addr),2u))
#define MEM32(addr)  (*(volatile uint32_t *)gw_fast_mem_addr((uint32_t)(addr),4u))
#define MEM64(addr)  (*(volatile uint64_t *)gw_fast_mem_addr((uint32_t)(addr),8u))
#define MEMF(addr)   (*(volatile float    *)gw_fast_mem_addr((uint32_t)(addr),4u))
#define MEMD(addr)   (*(volatile double   *)gw_fast_mem_addr((uint32_t)(addr),8u))

#endif
