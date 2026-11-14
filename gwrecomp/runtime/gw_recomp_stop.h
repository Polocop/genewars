#ifndef GW_RECOMP_STOP_H
#define GW_RECOMP_STOP_H

#include "gw_interrupts.h"
#include "gw_segments.h"
#include "recomp_context.h"
#include "gw_recomp_trace.h"

/* Narrow replay-only probe implemented by the native harness. It runs just
 * before the authenticated original BioGame effect dispatch. */
void gw_trace_biogame_effect_call(uint32_t callsite,uint32_t target,
    uint32_t slot_base,uint32_t eax,uint32_t ebx,uint32_t ecx,uint32_t edx,
    uint32_t esi,uint32_t edi,uint32_t ebp,uint32_t esp);

/* Generated only for a partial closure whose unresolved original instruction
 * must remain dormant unless the live guest reaches that exact EIP. */
#define GW_RECOMP_FRONTIER_AT(site_va, reason_text) do { \
    RECOMP_FLAGS_OUT(); \
    RECOMP_REGS_OUT(); \
    gw_recomp_latch_runtime_frontier((uint32_t)(site_va), (reason_text), \
        g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp, \
        (uint32_t)recomp_eflags(_flag_k,_flag_a,_flag_b,_cf,_df)); \
    return; \
} while (0)

/* A lifted INT returns from the function containing it. Keep that guest stop
 * from being mistaken for an ordinary C return by the caller's call wrapper. */
static inline int gw_recomp_guest_trap_pending(void) {
    return gw_interrupt_get_trap().pending != 0 ||
           gw_recomp_get_port_io_trap().pending != 0 ||
           gw_recomp_trace_boundary_hit();
}

static inline uint32_t gw_recomp_trace_link_target(uint32_t target) {
    uint32_t link = target;
    (void)recomp_code_linear_to_link(target, &link);
    return link;
}

/* Selected indirect-call sites can run tens of thousands of times during
 * MapDisplay sweeps. In the default fast-boundary build, retain one row per
 * distinct (site,target) pair; GW_FULL_TRACE_BUILD keeps the full stream. */
static inline int gw_recomp_icall_trace_should_emit(uint32_t site,
                                                    uint32_t target) {
#if defined(GW_FULL_TRACE_BUILD) && GW_FULL_TRACE_BUILD
    extern int g_full_instruction_trace;
    if (g_full_instruction_trace) return 1;
#endif
    typedef struct gw_icall_trace_key {
        uint32_t site;
        uint32_t target;
        uint32_t used;
    } gw_icall_trace_key;
    static gw_icall_trace_key keys[512];
    uint32_t hash=(site*0x9e3779b1u)^(target+0x85ebca6bu);
    uint32_t index=(hash^(hash>>16))&511u;
    for (uint32_t probe=0;probe<512u;probe++) {
        gw_icall_trace_key *key=&keys[(index+probe)&511u];
        if (!key->used) {
            key->site=site;
            key->target=target;
            key->used=1u;
            return 1;
        }
        if (key->site==site && key->target==target) return 0;
    }
    return 0;
}

static inline int gw_recomp_trace_call_at(uint32_t site, uint32_t target,
                                           uint32_t return_va, uint8_t indirect) {
    if (!gw_recomp_trace_enabled()) return 0;
    uint32_t link_target = gw_recomp_trace_link_target(target);
    gw_recomp_trace_call(site, g_cur_func, link_target, return_va, indirect);
    if (link_target == 0x00098C19u || link_target == 0x00098C31u ||
        link_target == 0x000C8767u || link_target == 0x000C8A3Bu)
        gw_recomp_trace_checkpoint(link_target, g_cur_func);
    return gw_recomp_trace_stop_before_target(link_target);
}

#undef RECOMP_CALL
#define RECOMP_CALL(func) do { \
    if (gw_recomp_guest_trap_pending()) return; \
    uint32_t _caller = g_cur_func; \
    uint32_t _callsite = gw_recomp_last_guest_instruction(); \
    PUSH32(esp, RECOMP_RETADDR); \
    RECOMP_FLAGS_OUT(); \
    RECOMP_REGS_OUT(); \
    uint32_t _saved_ebp = g_ebp, _saved_esp = g_esp + 4u; \
    func(); \
    if (!gw_recomp_dispatch_pending_tail_calls()) { \
        RECOMP_REGS_IN(); g_cur_func = _caller; return; \
    } \
    RECOMP_REGS_IN(); \
    if (_caller == 0x00094AC0u && (g_ebp != _saved_ebp || g_esp != _saved_esp)) \
        fprintf(stderr,"TRACE setup_game call-frame mismatch site=%08x callee=%08x ebp=%08x->%08x esp=%08x->%08x last=%08x\n", \
            _callsite,g_cur_func,_saved_ebp,g_ebp,_saved_esp,g_esp,gw_recomp_last_guest_instruction()); \
    g_cur_func = _caller; \
    if (gw_recomp_guest_trap_pending()) return; \
} while (0)

#define GW_RECOMP_CALL_AT(callsite_va, target_va, return_va, func) do { \
    if (gw_recomp_trace_call_at((uint32_t)(callsite_va), (uint32_t)(target_va), \
                            (uint32_t)(return_va), 0u)) { \
        gw_recomp_trace_boundary_state((uint32_t)(callsite_va),g_cur_func,gw_recomp_trace_link_target((uint32_t)(target_va)), \
            (uint32_t)(return_va),eax,ebx,ecx,edx,esi,edi,ebp,esp,recomp_eflags(_flag_k,_flag_a,_flag_b,_cf,_df)); \
        RECOMP_FLAGS_OUT(); RECOMP_REGS_OUT(); return; \
    } \
    RECOMP_CALL(func); \
} while (0)

#undef RECOMP_ICALL
#define RECOMP_ICALL(target_va) do { \
    if (gw_recomp_guest_trap_pending()) return; \
    uint32_t _va = (uint32_t)(target_va); \
    g_icall_trace[g_icall_trace_idx & (ICALL_TRACE_SIZE-1)] = _va; \
    g_icall_from[g_icall_trace_idx & (ICALL_TRACE_SIZE-1)] = g_cur_func; \
    g_icall_trace_idx++; \
    g_icall_count++; \
    recomp_func_t _fn = recomp_lookup_manual(_va); \
    uint32_t _link_va = 0; \
    int _has_link_va = recomp_code_linear_to_link(_va, &_link_va); \
    if (!_fn && _has_link_va) _fn = recomp_lookup_manual(_link_va); \
    if (!_fn && _has_link_va) _fn = recomp_lookup(_link_va); \
    if (!_fn) _fn = recomp_lookup(_va); \
    if (!_fn) _fn = recomp_lookup_import(_va); \
    if (!_fn && _has_link_va) _fn = recomp_lookup_import(_link_va); \
    if (_fn) { \
        uint32_t _caller = g_cur_func; \
        PUSH32(esp, RECOMP_RETADDR); \
        RECOMP_FLAGS_OUT(); \
        RECOMP_REGS_OUT(); \
        _fn(); \
        if (!gw_recomp_dispatch_pending_tail_calls()) { \
            RECOMP_REGS_IN(); g_cur_func = _caller; return; \
        } \
        RECOMP_REGS_IN(); \
        g_cur_func = _caller; \
        if (gw_recomp_guest_trap_pending()) return; \
    } else { \
        if (gw_recomp_interactive_resilient_enabled()) { \
            gw_recomp_log_interactive_unresolved(gw_recomp_last_guest_instruction(),_va, \
                g_eax,g_ecx,g_edx,g_ebx,g_esi,g_edi,g_ebp,g_esp); \
            g_eax=0u; \
            RECOMP_REGS_IN(); \
        } else { \
        fprintf(stderr, "ICALL: unresolved VA 0x%08X from 0x%08X\\n", _va, g_cur_func); \
        RECOMP_FLAGS_OUT(); \
        RECOMP_REGS_OUT(); \
        gw_recomp_latch_unresolved_indirect(_va); \
        return; \
        } \
    } \
} while (0)

#define GW_RECOMP_ICALL_AT(callsite_va, target_va, return_va) do { \
    uint32_t _gw_trace_target = (uint32_t)(target_va); \
    if (gw_recomp_trace_call_at((uint32_t)(callsite_va), _gw_trace_target, \
                            (uint32_t)(return_va), 1u)) { \
        gw_recomp_trace_boundary_state((uint32_t)(callsite_va),g_cur_func,gw_recomp_trace_link_target(_gw_trace_target), \
            (uint32_t)(return_va),eax,ebx,ecx,edx,esi,edi,ebp,esp,recomp_eflags(_flag_k,_flag_a,_flag_b,_cf,_df)); \
        RECOMP_FLAGS_OUT(); RECOMP_REGS_OUT(); return; \
    } \
    RECOMP_ICALL(_gw_trace_target); \
} while (0)

#define GW_RECOMP_ICALL_ALLOWED_AT(callsite_va, target_va, return_va, allowed_targets) do { \
    uint32_t _gw_icall_target = (uint32_t)(target_va); \
    int _gw_icall_allowed = 0; \
    for (size_t _gw_i = 0; \
         _gw_i < sizeof(allowed_targets) / sizeof((allowed_targets)[0]); \
         ++_gw_i) { \
        if (_gw_icall_target == (allowed_targets)[_gw_i]) { \
            _gw_icall_allowed = 1; \
            break; \
        } \
    } \
    if (!_gw_icall_allowed) { \
        fprintf(stderr, "ICALL: denied VA 0x%08X at 0x%08X from 0x%08X EAX=%08X EBX=%08X ECX=%08X EDX=%08X ESI=%08X EDI=%08X EBP=%08X ESP=%08X\n", \
                _gw_icall_target, (uint32_t)(callsite_va), g_cur_func, \
                g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp); \
        RECOMP_FLAGS_OUT(); RECOMP_REGS_OUT(); \
        gw_recomp_latch_unresolved_indirect(_gw_icall_target); \
        return; \
    } \
    if (((uint32_t)(callsite_va) == 0x00078ba1u || \
        (uint32_t)(callsite_va) == 0x00082f77u || \
        (uint32_t)(callsite_va) == 0x00050164u || \
        (uint32_t)(callsite_va) == 0x0005017eu || \
        (uint32_t)(callsite_va) == 0x00047a9eu || \
        (uint32_t)(callsite_va) == 0x00080f86u || \
        (uint32_t)(callsite_va) == 0x00056f3bu || \
        (uint32_t)(callsite_va) == 0x00079218u || \
        (uint32_t)(callsite_va) == 0x0005a2f5u || \
        (uint32_t)(callsite_va) == 0x0005a70du || \
        (uint32_t)(callsite_va) == 0x0005a9a0u || \
        (uint32_t)(callsite_va) == 0x0005a9b2u || \
        (uint32_t)(callsite_va) == 0x0005ab28u || \
        (uint32_t)(callsite_va) == 0x00047c01u || \
        (uint32_t)(callsite_va) == 0x00047c15u || \
        (uint32_t)(callsite_va) == 0x00047dc2u || \
        (uint32_t)(callsite_va) == 0x00080a3au || \
        (uint32_t)(callsite_va) == 0x00054904u || \
        (uint32_t)(callsite_va) == 0x000502e1u || \
        (uint32_t)(callsite_va) == 0x00088146u || \
        (uint32_t)(callsite_va) == 0x000561e9u || \
        (uint32_t)(callsite_va) == 0x000791e9u || \
        (uint32_t)(callsite_va) == 0x00079459u || \
        (uint32_t)(callsite_va) == 0x000793ecu || \
        (uint32_t)(callsite_va) == 0x000793bdu || \
        (uint32_t)(callsite_va) == 0x00085fc8u || \
        (uint32_t)(callsite_va) == 0x0006ed7du || \
        (uint32_t)(callsite_va) == 0x0004a5dcu || \
        (uint32_t)(callsite_va) == 0x0004a6eeu || \
        (uint32_t)(callsite_va) == 0x0004a89bu || \
        (uint32_t)(callsite_va) == 0x00058bbdu || \
        (uint32_t)(callsite_va) == 0x00058bd4u || \
        (uint32_t)(callsite_va) == 0x00058be0u || \
        (uint32_t)(callsite_va) == 0x0004459eu || \
        (uint32_t)(callsite_va) == 0x00059f91u || \
        (uint32_t)(callsite_va) == 0x00058681u || \
        (uint32_t)(callsite_va) == 0x00059d42u || \
        (uint32_t)(callsite_va) == 0x00059ba6u || \
        (uint32_t)(callsite_va) == 0x00044932u) && \
        gw_recomp_icall_trace_should_emit((uint32_t)(callsite_va),_gw_icall_target)) { \
        uint32_t _gw_slot_base = \
            ((uint32_t)(callsite_va) == 0x00058bbdu) ? g_ebx : \
            ((uint32_t)(callsite_va) == 0x00047c15u) ? g_ebx : \
            ((uint32_t)(callsite_va) == 0x00047dc2u) ? g_ebx : \
            ((uint32_t)(callsite_va) == 0x00080f86u) ? g_ecx : \
            ((uint32_t)(callsite_va) == 0x00056f3bu) ? g_ecx : \
            ((uint32_t)(callsite_va) == 0x00080a3au) ? g_ecx : \
            ((uint32_t)(callsite_va) == 0x0006ed7du) ? g_edi : \
            ((uint32_t)(callsite_va) == 0x0004459eu || \
             (uint32_t)(callsite_va) == 0x00059f91u) ? g_edx : \
            ((uint32_t)(callsite_va) == 0x00058681u) ? g_ecx : \
            ((uint32_t)(callsite_va) == 0x00059d42u || \
             (uint32_t)(callsite_va) == 0x00059ba6u) ? g_ebx : \
            ((uint32_t)(callsite_va) == 0x00044932u) ? g_edx : \
            (((uint32_t)(callsite_va) == 0x000793ecu) || \
             ((uint32_t)(callsite_va) == 0x000793bdu)) ? g_ebp : g_edx; \
        uint32_t _gw_slot_offset = \
            ((uint32_t)(callsite_va) == 0x00058bbdu) ? 0x88u : \
            ((uint32_t)(callsite_va) == 0x00050164u) ? 0xb0u : \
            ((uint32_t)(callsite_va) == 0x0005017eu) ? 0x8cu : \
            ((uint32_t)(callsite_va) == 0x00047a9eu) ? 0x10u : \
            ((uint32_t)(callsite_va) == 0x0005a2f5u) ? 0x10u : \
            ((uint32_t)(callsite_va) == 0x0005a70du) ? 0x10u : \
            ((uint32_t)(callsite_va) == 0x0005a9a0u) ? 0xb4u : \
            ((uint32_t)(callsite_va) == 0x0005a9b2u) ? 0x10u : \
            ((uint32_t)(callsite_va) == 0x0005ab28u) ? 0xb4u : \
            ((uint32_t)(callsite_va) == 0x00047c01u) ? 0x10u : \
            ((uint32_t)(callsite_va) == 0x00047c15u) ? 0x8cu : \
            ((uint32_t)(callsite_va) == 0x00047dc2u) ? 0x10u : \
            ((uint32_t)(callsite_va) == 0x00080f86u) ? 0x68u : \
            ((uint32_t)(callsite_va) == 0x00056f3bu) ? 0x70u : \
            ((uint32_t)(callsite_va) == 0x00079218u) ? 0x1cu : \
            ((uint32_t)(callsite_va) == 0x00080a3au) ? 0x10u : \
            ((uint32_t)(callsite_va) == 0x00054904u) ? 0x68u : \
            ((uint32_t)(callsite_va) == 0x000502e1u) ? 0x80u : \
            ((uint32_t)(callsite_va) == 0x00082f77u) ? 0x00u : \
            ((uint32_t)(callsite_va) == 0x000561e9u) ? 0x68u : \
            ((uint32_t)(callsite_va) == 0x0004a5dcu) ? 0x68u : \
            ((uint32_t)(callsite_va) == 0x0004a6eeu) ? 0xb0u : \
            ((uint32_t)(callsite_va) == 0x0004a89bu) ? 0x10u : \
            ((uint32_t)(callsite_va) == 0x0006ed7du) ? 0x18u : \
            ((uint32_t)(callsite_va) == 0x0004459eu) ? 0x94u : \
            ((uint32_t)(callsite_va) == 0x00059f91u) ? 0x68u : \
            ((uint32_t)(callsite_va) == 0x00058681u) ? 0xa4u : \
            ((uint32_t)(callsite_va) == 0x00059d42u) ? 0xb8u : \
            ((uint32_t)(callsite_va) == 0x00059ba6u) ? 0x10u : \
            ((uint32_t)(callsite_va) == 0x00044932u) ? 0x80u : \
            (((uint32_t)(callsite_va) == 0x000793ecu) || \
             ((uint32_t)(callsite_va) == 0x000793bdu)) ? 0x24u : \
            (((uint32_t)(callsite_va) == 0x000791e9u) || \
             ((uint32_t)(callsite_va) == 0x00079459u)) ? 0x6cu : 4u; \
        fprintf(stderr,"TRACE ICALL_CALL site=%08X target=%08X slot_base=%08X slot_address=%08X EAX=%08X EBX=%08X ECX=%08X EDX=%08X ESI=%08X EDI=%08X EBP=%08X ESP=%08X\n", \
            (uint32_t)(callsite_va),_gw_icall_target,_gw_slot_base,_gw_slot_base+_gw_slot_offset, \
            g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp); \
        if ((uint32_t)(callsite_va)==0x00088146u) \
            gw_trace_biogame_effect_call((uint32_t)(callsite_va),_gw_icall_target, \
                _gw_slot_base,g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp); \
    } \
    if (gw_recomp_trace_call_at((uint32_t)(callsite_va), _gw_icall_target, \
                            (uint32_t)(return_va), 1u)) { \
        gw_recomp_trace_boundary_state((uint32_t)(callsite_va),g_cur_func,gw_recomp_trace_link_target(_gw_icall_target), \
            (uint32_t)(return_va),eax,ebx,ecx,edx,esi,edi,ebp,esp,recomp_eflags(_flag_k,_flag_a,_flag_b,_cf,_df)); \
        RECOMP_FLAGS_OUT(); RECOMP_REGS_OUT(); return; \
    } \
    RECOMP_ICALL(_gw_icall_target); \
} while (0)

/* Broad LE-backed fallback for callsites that do not have a site-specific
 * vtable contract. The target must still be a lifted function entry reached
 * by at least one canonical LE code-pointer fixup. The original operand
 * expression is evaluated once, so CALL [reg+disp] keeps its memory
 * dereference semantics. */
static inline int gw_recomp_le_target_member(uint32_t target,
        const uint32_t *targets, size_t count) {
    size_t lo = 0, hi = count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2u;
        if (targets[mid] < target) lo = mid + 1u;
        else hi = mid;
    }
    return lo < count && targets[lo] == target;
}

#define GW_RECOMP_ICALL_LE_BACKED_AT(callsite_va, target_va, return_va, allowed_targets) do { \
    uint32_t _gw_icall_target = (uint32_t)(target_va); \
    int _gw_icall_allowed = gw_recomp_le_target_member(_gw_icall_target, \
        (allowed_targets), sizeof(allowed_targets) / sizeof((allowed_targets)[0])); \
    if (!_gw_icall_allowed && !gw_recomp_interactive_resilient_enabled()) { \
        fprintf(stderr, "ICALL: denied non-LE target 0x%08X at 0x%08X from 0x%08X EAX=%08X EBX=%08X ECX=%08X EDX=%08X ESI=%08X EDI=%08X EBP=%08X ESP=%08X\\n", \
                _gw_icall_target, (uint32_t)(callsite_va), g_cur_func, \
                g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp); \
        RECOMP_FLAGS_OUT(); RECOMP_REGS_OUT(); \
        gw_recomp_latch_runtime_frontier((uint32_t)(callsite_va), \
            "indirect target is not a fixup-backed lifted LE entry", \
            g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp, \
            (uint32_t)recomp_eflags(_flag_k,_flag_a,_flag_b,_cf,_df)); \
        return; \
    } \
    gw_recomp_dispatch_hit_record((uint32_t)(callsite_va),_gw_icall_target); \
    if (gw_recomp_trace_call_at((uint32_t)(callsite_va),_gw_icall_target, \
            (uint32_t)(return_va),1u)) { \
        gw_recomp_trace_boundary_state((uint32_t)(callsite_va),g_cur_func, \
            gw_recomp_trace_link_target(_gw_icall_target),(uint32_t)(return_va), \
            eax,ebx,ecx,edx,esi,edi,ebp,esp, \
            recomp_eflags(_flag_k,_flag_a,_flag_b,_cf,_df)); \
        RECOMP_FLAGS_OUT(); RECOMP_REGS_OUT(); return; \
    } \
    RECOMP_ICALL(_gw_icall_target); \
} while (0)

#define GW_RECOMP_ITAIL_LE_BACKED_AT(site_va, target_va, allowed_targets) do { \
    uint32_t _gw_tail_target = (uint32_t)(target_va); \
    int _gw_tail_allowed = gw_recomp_le_target_member(_gw_tail_target, \
        (allowed_targets), sizeof(allowed_targets) / sizeof((allowed_targets)[0])); \
    if (!_gw_tail_allowed && !gw_recomp_interactive_resilient_enabled()) { \
        RECOMP_FLAGS_OUT(); RECOMP_REGS_OUT(); \
        gw_recomp_latch_runtime_frontier((uint32_t)(site_va), \
            "indirect tail target is not a fixup-backed lifted LE entry", \
            g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,0u); \
        return; \
    } \
    gw_recomp_dispatch_hit_record((uint32_t)(site_va),_gw_tail_target); \
    (void)gw_recomp_trace_call_at((uint32_t)(site_va),_gw_tail_target,0u,1u); \
    RECOMP_ITAIL(_gw_tail_target); return; \
} while (0)

/* Used only by a generated closure that has hash-bound callback targets for
 * one exact original callsite. The pointer is still read from guest memory;
 * this guard rejects anything outside the finite, verified target set. */
#define GW_RECOMP_ICALL_ALLOWED(callsite_va, target_va, allowed_targets) do { \
    uint32_t _gw_icall_target = (uint32_t)(target_va); \
    int _gw_icall_allowed = 0; \
    for (size_t _gw_i = 0; \
         _gw_i < sizeof(allowed_targets) / sizeof((allowed_targets)[0]); \
         ++_gw_i) { \
        if (_gw_icall_target == (allowed_targets)[_gw_i]) { \
            _gw_icall_allowed = 1; \
            break; \
        } \
    } \
    if (!_gw_icall_allowed && !gw_recomp_interactive_resilient_enabled()) { \
        fprintf(stderr, "ICALL: denied VA 0x%08X at 0x%08X from 0x%08X " \
                "EAX=%08X EBX=%08X ECX=%08X EDX=%08X ESI=%08X EDI=%08X " \
                "EBP=%08X ESP=%08X\\n", \
                _gw_icall_target, (uint32_t)(callsite_va), g_cur_func, \
                g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp); \
        RECOMP_FLAGS_OUT(); \
        RECOMP_REGS_OUT(); \
        gw_recomp_latch_unresolved_indirect(_gw_icall_target); \
        return; \
    } \
    gw_recomp_trace_call_at((uint32_t)(callsite_va), _gw_icall_target, 0u, 1u); \
    RECOMP_ICALL(_gw_icall_target); \
} while (0)

/* A hash-bound mutable Smacker jump table: the index is masked by original
 * code, the host checks the backing interval before reading, and the selected
 * live pointer must equal the expected original target for that index. */
#define GW_RECOMP_ITAIL_INDEXED_ALLOWED(site_va, table_offset, index, count, target_expr, expected_targets) do { \
    uint32_t _gw_index = (uint32_t)(index); \
    if (!recomp_check_indexed_table_access(RECOMP_SEG_DS, (uint32_t)(table_offset), \
            _gw_index * 4u, (uint32_t)(count) * 4u, (uint32_t)(count) * 4u, 4u, \
            (uint32_t)(site_va))) { \
        recomp_end_memory_access(); RECOMP_FLAGS_OUT(); RECOMP_REGS_OUT(); return; \
    } \
    uint32_t _gw_target = (uint32_t)(target_expr); \
    recomp_end_memory_access(); \
    if (_gw_index >= (uint32_t)(count) || \
        _gw_target != (expected_targets)[_gw_index]) { \
        RECOMP_FLAGS_OUT(); RECOMP_REGS_OUT(); \
        gw_recomp_latch_runtime_frontier((uint32_t)(site_va), \
            "Smacker jump-table target outside original initialized variant", \
            g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp, \
            (uint32_t)recomp_eflags(_flag_k,_flag_a,_flag_b,_cf,_df)); \
        return; \
    } \
    gw_recomp_dispatch_hit_record((uint32_t)(site_va),_gw_target); \
    RECOMP_ITAIL(_gw_target); \
} while (0)

#undef RECOMP_ITAIL
#define RECOMP_ITAIL(target_va) do { \
    if (gw_recomp_guest_trap_pending()) return; \
    uint32_t _va = (uint32_t)(target_va); \
    g_icall_trace[g_icall_trace_idx & (ICALL_TRACE_SIZE-1)] = _va; \
    g_icall_from[g_icall_trace_idx & (ICALL_TRACE_SIZE-1)] = g_cur_func; \
    g_icall_trace_idx++; \
    g_icall_count++; \
    recomp_func_t _fn = recomp_lookup_manual(_va); \
    uint32_t _link_va = 0; \
    int _has_link_va = recomp_code_linear_to_link(_va, &_link_va); \
    if (!_fn && _has_link_va) _fn = recomp_lookup_manual(_link_va); \
    if (!_fn && _has_link_va) _fn = recomp_lookup(_link_va); \
    if (!_fn) _fn = recomp_lookup(_va); \
    if (!_fn) _fn = recomp_lookup_import(_va); \
    if (!_fn && _has_link_va) _fn = recomp_lookup_import(_link_va); \
    if (_fn || _va == RECOMP_RETADDR) { \
        RECOMP_FLAGS_OUT(); \
        RECOMP_REGS_OUT(); \
        gw_recomp_queue_tail_call(_va); \
    } else { \
        if (gw_recomp_interactive_resilient_enabled()) { \
            gw_recomp_log_interactive_unresolved(gw_recomp_last_guest_instruction(),_va, \
                g_eax,g_ecx,g_edx,g_ebx,g_esi,g_edi,g_ebp,g_esp); \
        } else { \
        RECOMP_FLAGS_OUT(); \
        RECOMP_REGS_OUT(); \
        fprintf(stderr, "ITAIL: unresolved VA 0x%08X from 0x%08X EAX=%08X EBX=%08X ECX=%08X EDX=%08X ESI=%08X EDI=%08X EBP=%08X ESP=%08X CS=%04X DS=%04X ES=%04X SS=%04X\\n", \
                _va,g_cur_func,g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp, \
                g_seg_cs,g_seg_ds,g_seg_es,g_seg_ss); \
        gw_recomp_latch_runtime_frontier(gw_recomp_last_guest_instruction(), \
            "unresolved original indirect tail transfer",g_eax,g_ebx,g_ecx,g_edx, \
            g_esi,g_edi,g_ebp,g_esp,recomp_eflags(g_flag_k,g_flag_a,g_flag_b,g_flag_cf,1u)); \
        return; \
        } \
    } \
} while (0)

#endif
