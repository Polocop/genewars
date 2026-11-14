#ifndef GW_RECOMP_CONTEXT_H
#define GW_RECOMP_CONTEXT_H
#include <stddef.h>
#include <stdint.h>
#include "../third_party/pcrecomp/runtime/recomp32/recomp_types.h"
#include "gw_pit8254.h"

typedef enum gw_port_io_trap_reason {
    GW_PORT_IO_TRAP_NONE = 0,
    GW_PORT_IO_TRAP_NO_ACTIVE_CONTEXT = 1,
    GW_PORT_IO_TRAP_PIT_TICK_OVERFLOW = 2,
    GW_PORT_IO_TRAP_UNSUPPORTED_IO = 3,
    GW_PORT_IO_TRAP_MISSING_READ_OUTPUT = 4,
    GW_PORT_IO_TRAP_REPEATED_GUEST_STATE = 5,
    GW_PORT_IO_TRAP_UNRESOLVED_INDIRECT_CALL = 6
} gw_port_io_trap_reason;

typedef struct gw_port_io_trap {
    uint8_t pending;
    uint8_t reason;
    uint32_t port;
    uint32_t operation;
    uint32_t width;
    uint32_t value;
    uint32_t guest_va;
} gw_port_io_trap;

typedef int (*gw_port_io_provider_fn)(unsigned int operation,
                                     unsigned int port,
                                     unsigned int width,
                                     unsigned int value,
                                     unsigned int guest_va,
                                     unsigned int *value_out,
                                     void *user);
void gw_recomp_set_port_io_provider(gw_port_io_provider_fn provider,
                                    void *user);

typedef struct gw_recomp_context {
    uint32_t eax, ebx, ecx, edx, esi, edi, ebp, esp;
    uint32_t eip; /* dispatch-owned: identifies the guest entry VA; lifted RET returns to the host */
    uint16_t cs, ds, es, fs, gs, ss;
    uint32_t flag_k, flag_a, flag_b, flag_cf; /* pcrecomp lazy flag representation */
    double st[8];
    int32_t fp_top;
    uint16_t fpu_cw;
    uint32_t cur_func, cs_base, ds_base, es_base, fs_base, gs_base, ss_base;
    ptrdiff_t mem_base; /* host pointer minus guest VA, valid only for this mapped image */
    uint32_t mem_guest_base, mem_size; /* optional checked guest memory range */
    uint8_t interrupt_trap_pending;
    uint8_t interrupt_vector;
    uint16_t interrupt_reserved;
    uint32_t interrupt_instruction_va;
    uint32_t interrupt_function_va;
    uint8_t segment_fault_pending;
    uint8_t segment_fault_id;
    uint16_t segment_fault_selector;
    uint32_t segment_fault_instruction_va;
    recomp_memory_fault memory_fault;
    gw_pit8254 pit;
    uint8_t pit_initialized;
    uint8_t bios_tick_sync_initialized;
    uint8_t port_io_reserved[2];
    uint64_t bios_tick_last_reload_cycle;
    uint64_t bios_tick_periods_applied;
    uint64_t bios_tick_next_period_cycle;
    uint32_t bios_tick_last_reload;
    gw_port_io_trap port_io_trap;
} gw_recomp_context;

typedef enum gw_recomp_status { GW_RECOMP_OK=0, GW_RECOMP_BUSY=1, GW_RECOMP_INVALID=2 } gw_recomp_status;
/* Global-ABI lifts are process-global and non-reentrant. A concurrent or nested
 * wrapper call returns BUSY before touching globals. Normal-return only: faults
 * must be handled by the host's fault boundary. eip stays dispatch-owned. */
gw_recomp_status gw_recomp_invoke(recomp_func_t function, gw_recomp_context *context);
/* Capture the active lifted CPU state and release the non-reentrant context
 * lock when a host-owned setjmp/longjmp intentionally yields mid-invocation. */
void gw_recomp_yield_active_context(void);
/* Interactive host pacing may synchronize the guest PIT to a monotonic host
 * counter. Deterministic/headless runs leave instruction-based advancement in
 * place. The counter unit is supplied by the caller (e.g. SDL performance
 * counter ticks). */
int gw_recomp_pit_realtime_start(gw_recomp_context *context,
                                 uint64_t host_counter,
                                 uint64_t host_frequency);
int gw_recomp_pit_realtime_sync(gw_recomp_context *context,
                                uint64_t host_counter);
void gw_recomp_pit_realtime_stop(gw_recomp_context *context);

/* ABI consumed by generated code from the W1-087 port-I/O lifter. */
int gw_recomp_guest_instruction(unsigned int guest_va);
uint32_t gw_recomp_last_guest_instruction(void);
/* Opt-in diagnostic hook (G-GP-004). The callback runs when lifted guest code
   reaches guest_va; guest_va 0 or a NULL callback leaves it disabled. It must
   only observe state and must not write guest memory or registers. */
typedef void (*gw_recomp_instruction_watch_fn)(uint32_t guest_va);
void gw_recomp_set_instruction_watch(uint32_t guest_va,
                                     gw_recomp_instruction_watch_fn fn);
void gw_recomp_queue_tail_call(uint32_t target_va);
int gw_recomp_dispatch_pending_tail_calls(void);
int gw_recomp_port_io(unsigned int operation, unsigned int port,
                      unsigned int width, unsigned int value,
                      unsigned int guest_va, unsigned int *value_out);
gw_port_io_trap gw_recomp_get_port_io_trap(void);
void gw_recomp_clear_port_io_trap(void);
/* Fail closed when original code reaches a dynamic target outside the lifted
 * closure; continuing with EAX=0 fabricates guest behavior and can loop. */
void gw_recomp_latch_unresolved_indirect(uint32_t target_va);
/* Interactive-only recovery for guest indirect targets outside the lifted
 * closure. Regression/replay callers remain fail-closed by default. */
int gw_recomp_interactive_resilient_enabled(void);
void gw_recomp_log_interactive_unresolved(uint32_t callsite_eip,
    uint32_t target_va,uint32_t eax,uint32_t ecx,uint32_t edx,uint32_t ebx,
    uint32_t esi,uint32_t edi,uint32_t ebp,uint32_t esp);
void gw_recomp_latch_runtime_frontier(uint32_t guest_eip, const char *reason,
    uint32_t eax,uint32_t ebx,uint32_t ecx,uint32_t edx,
    uint32_t esi,uint32_t edi,uint32_t ebp,uint32_t esp,uint32_t eflags);
/* Compact hit accounting for successful LE-backed indirect dispatches.
 * The fixed hash table keeps this O(1) and avoids per-frame text I/O. */
void gw_recomp_dispatch_hits_reset(void);
void gw_recomp_dispatch_hit_record(uint32_t callsite_eip,uint32_t target_va);
uint32_t gw_recomp_dispatch_hits_count(void);
int gw_recomp_dispatch_hits_get(uint32_t ordinal,uint32_t *callsite_eip,
                                uint32_t *target_va,uint64_t *hit_count);
typedef struct gw_recomp_dispatch_hit_snapshot_row {
    uint32_t callsite_eip, target_va;
    uint64_t hit_count;
} gw_recomp_dispatch_hit_snapshot_row;
int gw_recomp_dispatch_hits_export(gw_recomp_dispatch_hit_snapshot_row *rows,
                                   uint32_t capacity,uint32_t *count_out);
int gw_recomp_dispatch_hits_import(const gw_recomp_dispatch_hit_snapshot_row *rows,
                                   uint32_t count);
#endif
