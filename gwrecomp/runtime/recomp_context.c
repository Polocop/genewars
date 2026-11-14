#include "recomp_context.h"
#include "gw_interrupts.h"
#include "gw_segments.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static atomic_flag gw_context_busy = ATOMIC_FLAG_INIT;
static gw_recomp_context *active_context;
static gw_pit8254 *active_pit;
static gw_port_io_trap last_port_io_trap;
static uint32_t last_guest_instruction_va;
/* Opt-in instruction watch (G-GP-004). Disabled while instruction_watch_va is 0. */
static uint32_t instruction_watch_va;
static gw_recomp_instruction_watch_fn instruction_watch_fn;
static uint32_t pending_tail_call_va;
static int pending_tail_call_valid;
static int interactive_resilient_checked;
static int interactive_resilient_value;
typedef struct gw_dispatch_hit_row {
    uint32_t callsite;
    uint32_t target;
    uint64_t count;
    uint8_t used;
} gw_dispatch_hit_row;
#define GW_DISPATCH_HIT_CAPACITY 32768u
static gw_dispatch_hit_row dispatch_hits[GW_DISPATCH_HIT_CAPACITY];
static uint32_t dispatch_hit_distinct;
static gw_port_io_provider_fn port_io_provider;
static void *port_io_provider_user;
static gw_recomp_context *realtime_pit_context;
static uint64_t realtime_pit_host_base;
static uint64_t realtime_pit_frequency;
static uint64_t realtime_pit_cycle_base;
#if defined(GW_NATIVE_W1_092_HOST_BACKED_GUEST_MEMORY)
static uint64_t w1_092_guest_instruction_count;
extern void gw_native_w1_092_instruction_observer(uint64_t count,
                                                  unsigned int guest_va);
extern int gw_native_w1_093_repeat_guard(unsigned int guest_va);
#endif

static void latch_port_io_trap(gw_port_io_trap_reason reason,
                               unsigned int operation, unsigned int port,
                               unsigned int width, unsigned int value,
                               unsigned int guest_va) {
    if (last_port_io_trap.pending) return;
    last_port_io_trap.pending = 1u;
    last_port_io_trap.reason = (uint8_t)reason;
    last_port_io_trap.port = port;
    last_port_io_trap.operation = operation;
    last_port_io_trap.width = width;
    last_port_io_trap.value = value;
    last_port_io_trap.guest_va = guest_va;
    if (active_context) active_context->port_io_trap = last_port_io_trap;
}
static void apply_context(const gw_recomp_context *c) {
    g_eax=c->eax; g_ebx=c->ebx; g_ecx=c->ecx; g_edx=c->edx;
    g_esi=c->esi; g_edi=c->edi; g_ebp=c->ebp; g_esp=c->esp;
    g_seg_cs=c->cs; g_seg_ds=c->ds; g_seg_es=c->es;
    g_seg_fs=c->fs; g_seg_gs=c->gs; g_seg_ss=c->ss;
    g_flag_k=c->flag_k; g_flag_a=c->flag_a; g_flag_b=c->flag_b; g_flag_cf=c->flag_cf;
    for (int i=0;i<8;i++) g_st[i]=c->st[i];
    g_fp_top=c->fp_top; g_fpu_cw=c->fpu_cw; g_cur_func=c->cur_func;
    g_cs_base=c->cs_base; g_ds_base=c->ds_base; g_es_base=c->es_base;
    g_fs_base=c->fs_base; g_gs_base=c->gs_base; g_ss_base=c->ss_base; g_mem_base=c->mem_base;
    recomp_set_memory_bounds(c->mem_guest_base,c->mem_size);
}
static void capture_context(gw_recomp_context *c) {
    c->eax=g_eax; c->ebx=g_ebx; c->ecx=g_ecx; c->edx=g_edx;
    c->esi=g_esi; c->edi=g_edi; c->ebp=g_ebp; c->esp=g_esp;
    c->cs=g_seg_cs; c->ds=g_seg_ds; c->es=g_seg_es;
    c->fs=g_seg_fs; c->gs=g_seg_gs; c->ss=g_seg_ss;
    c->flag_k=g_flag_k; c->flag_a=g_flag_a; c->flag_b=g_flag_b; c->flag_cf=g_flag_cf;
    for (int i=0;i<8;i++) c->st[i]=g_st[i];
    c->fp_top=g_fp_top; c->fpu_cw=g_fpu_cw; c->cur_func=g_cur_func;
    c->cs_base=g_cs_base; c->ds_base=g_ds_base; c->es_base=g_es_base;
    c->fs_base=g_fs_base; c->gs_base=g_gs_base; c->ss_base=g_ss_base; c->mem_base=g_mem_base;
    gw_interrupt_trap trap = gw_interrupt_get_trap();
    c->interrupt_trap_pending=trap.pending; c->interrupt_vector=trap.vector;
    c->interrupt_reserved=trap.reserved; c->interrupt_instruction_va=trap.instruction_va;
    c->interrupt_function_va=trap.guest_function_va;
    recomp_segment_fault segment_fault = recomp_get_segment_fault();
    c->segment_fault_pending=segment_fault.pending; c->segment_fault_id=segment_fault.segment;
    c->segment_fault_selector=segment_fault.selector;
    c->segment_fault_instruction_va=segment_fault.instruction_va;
    c->memory_fault=recomp_get_memory_fault();
    c->port_io_trap=last_port_io_trap;
}

/* DOS/4GW's BIOS timer callback reads the BDA tick counter at 0040:006C.
 * The guest-visible PIT model advances once per lifted guest instruction;
 * when channel 0 is programmed in a periodic mode, mirror its completed
 * periods into the BDA so original timer code observes elapsed guest time.
 * This is deliberately bounded to the backed conventional-memory range. */
static void sync_bios_data_area_tick_for(gw_recomp_context *context,
                                         gw_pit8254 *pit) {
    const uint32_t bda_tick_linear=0x0000046Cu;
    const uint32_t bda_midnight_linear=0x00000470u;
    const uint64_t ticks_per_day=0x001800B0ull;
    uint64_t elapsed,periods,delta,region_end,next_period;
    uint32_t period,mode,current;
    uint8_t *bda;
    if(!context || !pit) return;
    if((uint64_t)bda_tick_linear<context->mem_guest_base) return;
    region_end=(uint64_t)context->mem_guest_base+context->mem_size;
    if((uint64_t)bda_midnight_linear+1u>region_end) return;
    period=pit->reload[0];
    mode=(pit->control_word>>1)&7u;
    if(!period || (mode!=2u && mode!=3u)) return;
    if(!context->bios_tick_sync_initialized ||
       context->bios_tick_last_reload_cycle!=pit->reload_cycle[0] ||
       context->bios_tick_last_reload!=period) {
        context->bios_tick_sync_initialized=1u;
        context->bios_tick_last_reload_cycle=pit->reload_cycle[0];
        context->bios_tick_last_reload=period;
        context->bios_tick_periods_applied=0u;
        next_period=pit->reload_cycle[0]>(UINT64_MAX-(uint64_t)period)
            ? UINT64_MAX : pit->reload_cycle[0]+(uint64_t)period;
        context->bios_tick_next_period_cycle=next_period;
    }
    /* Most lifted instructions occur between PIT periods. Avoid a 64-bit
       division on every instruction while keeping the guest-visible BDA
       update at the exact same virtual cycle as the original calculation. */
    if(pit->virtual_cycles<context->bios_tick_next_period_cycle) return;
    elapsed=pit->virtual_cycles>=pit->reload_cycle[0]
        ? pit->virtual_cycles-pit->reload_cycle[0] : 0u;
    periods=elapsed/period;
    if(periods<=context->bios_tick_periods_applied) return;
    delta=periods-context->bios_tick_periods_applied;
    bda=(uint8_t *)(uintptr_t)(context->mem_base+(ptrdiff_t)bda_tick_linear);
    memcpy(&current,bda,sizeof current);
    if((uint64_t)current+delta>=ticks_per_day) {
        uint8_t midnight;
        current=(uint32_t)(((uint64_t)current+delta)%ticks_per_day);
        memcpy(&midnight,(uint8_t *)(uintptr_t)(context->mem_base+
            (ptrdiff_t)bda_midnight_linear),sizeof midnight);
        midnight|=1u;
        memcpy((uint8_t *)(uintptr_t)(context->mem_base+
            (ptrdiff_t)bda_midnight_linear),&midnight,sizeof midnight);
    } else {
        current+=(uint32_t)delta;
    }
    memcpy(bda,&current,sizeof current);
    context->bios_tick_periods_applied=periods;
    next_period=periods==UINT64_MAX ||
        periods+1u>(UINT64_MAX-pit->reload_cycle[0])/(uint64_t)period
        ? UINT64_MAX
        : pit->reload_cycle[0]+(periods+1u)*(uint64_t)period;
    context->bios_tick_next_period_cycle=next_period;
}

static void sync_bios_data_area_tick(void) {
    if(active_context && active_pit)
        sync_bios_data_area_tick_for(active_context,active_pit);
}

int gw_recomp_pit_realtime_start(gw_recomp_context *context,
                                 uint64_t host_counter,
                                 uint64_t host_frequency) {
    if(!context || !context->pit_initialized || !host_frequency) return 0;
    realtime_pit_context=context;
    realtime_pit_host_base=host_counter;
    realtime_pit_frequency=host_frequency;
    realtime_pit_cycle_base=context->pit.virtual_cycles;
    return 1;
}

int gw_recomp_pit_realtime_sync(gw_recomp_context *context,
                                uint64_t host_counter) {
    uint64_t delta,seconds,remainder,cycles,desired;
    const uint64_t pit_hz=1193182u;
    if(!context || context!=realtime_pit_context || !realtime_pit_frequency ||
       host_counter<realtime_pit_host_base) return 0;
    delta=host_counter-realtime_pit_host_base;
    seconds=delta/realtime_pit_frequency;
    remainder=delta%realtime_pit_frequency;
    if(seconds>(UINT64_MAX-realtime_pit_cycle_base)/pit_hz) return 0;
    cycles=seconds*pit_hz;
    if(remainder>UINT64_MAX/pit_hz) return 0;
    cycles+=(remainder*pit_hz)/realtime_pit_frequency;
    if(cycles>UINT64_MAX-realtime_pit_cycle_base) return 0;
    desired=realtime_pit_cycle_base+cycles;
    if(desired>context->pit.virtual_cycles)
        context->pit.virtual_cycles=desired;
    sync_bios_data_area_tick_for(context,&context->pit);
    return 1;
}

void gw_recomp_pit_realtime_stop(gw_recomp_context *context) {
    if(context && realtime_pit_context==context) {
        realtime_pit_context=0;
        realtime_pit_host_base=0;
        realtime_pit_frequency=0;
        realtime_pit_cycle_base=0;
    }
}

/* Host-driven guest clock for a bounded host loop (Smacker video): while held, guest
   instructions do not advance the PIT; the host advances it from wall time instead. */
static int pit_host_hold;
void gw_recomp_pit_host_hold(int hold) { pit_host_hold=hold!=0; }
uint64_t gw_recomp_pit_cycles_now(void) { return active_pit?active_pit->virtual_cycles:0u; }
int gw_recomp_pit_host_advance(uint64_t cycles) {
    if(!active_pit) return 0;
    if(!gw_pit8254_advance(active_pit,cycles)) return 0;
    sync_bios_data_area_tick();
    return 1;
}

int gw_recomp_guest_instruction(unsigned int guest_va) {
    /* Stop dispatching lifted code at the first controlled guest-memory fault.
     * Generated functions may return one frame before control reaches here. */
    if (recomp_memory_diag_enabled() && recomp_memory_fault_pending()) return 0;
    recomp_memory_diag_set_guest_eip(guest_va);
    /* The watch runs before last_guest_instruction_va is updated, so the
       callback can read the previous guest instruction (the call site). */
    if(instruction_watch_va && guest_va==instruction_watch_va)
        instruction_watch_fn(guest_va);
    last_guest_instruction_va=guest_va;
#if defined(GW_NATIVE_W1_092_HOST_BACKED_GUEST_MEMORY)
    ++w1_092_guest_instruction_count;
    if (gw_native_w1_093_repeat_guard(guest_va)) {
        latch_port_io_trap(GW_PORT_IO_TRAP_REPEATED_GUEST_STATE,
                           UINT32_MAX, 0u, 0u, 0u, guest_va);
        return 0;
    }
    if ((w1_092_guest_instruction_count&0x0fffffffu)==0u)
        gw_native_w1_092_instruction_observer(w1_092_guest_instruction_count,
                                              guest_va);
#endif
    if (last_port_io_trap.pending) return 0;
    if (!active_context || !active_pit) {
        latch_port_io_trap(GW_PORT_IO_TRAP_NO_ACTIVE_CONTEXT,
                           UINT32_MAX, 0u, 0u, 0u, guest_va);
        return 0;
    }
    if (active_context==realtime_pit_context) {
        /* Host frame boundaries advance the PIT in realtime mode. Per-
           instruction advancement would make the guest clock run at the
           recompiler's instruction throughput instead of wall time. */
        return 1;
    }
    if (pit_host_hold) return 1;
    if (!gw_pit8254_advance(active_pit, 1u)) {
        latch_port_io_trap(GW_PORT_IO_TRAP_PIT_TICK_OVERFLOW,
                           UINT32_MAX, 0u, 0u, 0u, guest_va);
        return 0;
    }
    sync_bios_data_area_tick();
    return 1;
}

uint32_t gw_recomp_last_guest_instruction(void) {
    return last_guest_instruction_va;
}

void gw_recomp_set_instruction_watch(uint32_t guest_va,
                                     gw_recomp_instruction_watch_fn fn) {
    instruction_watch_va=fn?guest_va:0u;
    instruction_watch_fn=fn;
}

void gw_recomp_dispatch_hits_reset(void) {
    memset(dispatch_hits,0,sizeof dispatch_hits);
    dispatch_hit_distinct=0u;
}

void gw_recomp_dispatch_hit_record(uint32_t callsite_eip,uint32_t target_va) {
    uint32_t hash=(callsite_eip*0x9E3779B1u)^(target_va+0x85EBCA6Bu);
    uint32_t slot=(hash^(hash>>16))&(GW_DISPATCH_HIT_CAPACITY-1u);
    for(uint32_t n=0;n<GW_DISPATCH_HIT_CAPACITY;n++,slot=(slot+1u)&(GW_DISPATCH_HIT_CAPACITY-1u)) {
        gw_dispatch_hit_row *row=&dispatch_hits[slot];
        if(!row->used) {
            row->used=1u; row->callsite=callsite_eip; row->target=target_va;
            row->count=1u; dispatch_hit_distinct++; return;
        }
        if(row->callsite==callsite_eip && row->target==target_va) {
            if(row->count!=UINT64_MAX) row->count++;
            return;
        }
    }
    /* Saturation remains observable through the distinct count mismatch only;
       it never changes guest control flow. */
}

uint32_t gw_recomp_dispatch_hits_count(void) { return dispatch_hit_distinct; }

int gw_recomp_dispatch_hits_get(uint32_t ordinal,uint32_t *callsite_eip,
                                uint32_t *target_va,uint64_t *hit_count) {
    if(ordinal>=dispatch_hit_distinct) return 0;
    uint32_t seen=0u;
    for(uint32_t i=0;i<GW_DISPATCH_HIT_CAPACITY;i++) if(dispatch_hits[i].used) {
        if(seen++==ordinal) {
            if(callsite_eip) *callsite_eip=dispatch_hits[i].callsite;
            if(target_va) *target_va=dispatch_hits[i].target;
            if(hit_count) *hit_count=dispatch_hits[i].count;
            return 1;
        }
    }
    return 0;
}

int gw_recomp_dispatch_hits_export(gw_recomp_dispatch_hit_snapshot_row *rows,
                                   uint32_t capacity,uint32_t *count_out) {
    const uint32_t count=dispatch_hit_distinct;
    if(count_out) *count_out=count;
    if(count>capacity || (count && !rows)) return 0;
    uint32_t out=0u;
    for(uint32_t i=0;i<GW_DISPATCH_HIT_CAPACITY;i++) if(dispatch_hits[i].used) {
        if(out>=count) return 0;
        rows[out].callsite_eip=dispatch_hits[i].callsite;
        rows[out].target_va=dispatch_hits[i].target;
        rows[out].hit_count=dispatch_hits[i].count;
        out++;
    }
    return out==count;
}

int gw_recomp_dispatch_hits_import(const gw_recomp_dispatch_hit_snapshot_row *rows,
                                   uint32_t count) {
    if(count>GW_DISPATCH_HIT_CAPACITY || (count && !rows)) return 0;
    gw_recomp_dispatch_hits_reset();
    for(uint32_t i=0;i<count;i++) {
        if(!rows[i].hit_count) { gw_recomp_dispatch_hits_reset(); return 0; }
        uint32_t hash=(rows[i].callsite_eip*0x9E3779B1u)^
                      (rows[i].target_va+0x85EBCA6Bu);
        uint32_t slot=(hash^(hash>>16))&(GW_DISPATCH_HIT_CAPACITY-1u);
        int inserted=0;
        for(uint32_t n=0;n<GW_DISPATCH_HIT_CAPACITY;
            n++,slot=(slot+1u)&(GW_DISPATCH_HIT_CAPACITY-1u)) {
            gw_dispatch_hit_row *row=&dispatch_hits[slot];
            if(!row->used) {
                row->used=1u; row->callsite=rows[i].callsite_eip;
                row->target=rows[i].target_va; row->count=rows[i].hit_count;
                dispatch_hit_distinct++; inserted=1; break;
            }
            if(row->callsite==rows[i].callsite_eip &&
               row->target==rows[i].target_va) {
                gw_recomp_dispatch_hits_reset(); return 0;
            }
        }
        if(!inserted) { gw_recomp_dispatch_hits_reset(); return 0; }
    }
    return 1;
}

void gw_recomp_queue_tail_call(uint32_t target_va) {
    if (pending_tail_call_valid) {
        fprintf(stderr,"TAIL_QUEUE: nested pending target old=%08X new=%08X at guest=%08X\n",
            pending_tail_call_va,target_va,last_guest_instruction_va);
        gw_recomp_latch_runtime_frontier(last_guest_instruction_va,
            "nested tail transfer queued before previous tail dispatch",
            g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,
            recomp_eflags(g_flag_k,g_flag_a,g_flag_b,g_flag_cf,1u));
        return;
    }
    pending_tail_call_va=target_va;
    pending_tail_call_valid=1;
}

int gw_recomp_dispatch_pending_tail_calls(void) {
    uint32_t dispatches=0u;
    while(pending_tail_call_valid) {
        uint32_t target=pending_tail_call_va;
        pending_tail_call_va=0u;
        pending_tail_call_valid=0;
        if(target==RECOMP_RETADDR) continue;
        recomp_func_t fn=recomp_lookup_manual(target);
        uint32_t link_target=0u;
        int has_link=recomp_code_linear_to_link(target,&link_target);
        if(!fn && has_link) fn=recomp_lookup_manual(link_target);
        if(!fn && has_link) fn=recomp_lookup(link_target);
        if(!fn) fn=recomp_lookup(target);
        if(!fn) fn=recomp_lookup_import(target);
        if(!fn && has_link) fn=recomp_lookup_import(link_target);
        if(!fn) {
            gw_recomp_latch_runtime_frontier(last_guest_instruction_va,
                "unresolved original tail-transfer target",g_eax,g_ebx,g_ecx,g_edx,
                g_esi,g_edi,g_ebp,g_esp,
                recomp_eflags(g_flag_k,g_flag_a,g_flag_b,g_flag_cf,1u));
            return 0;
        }
        if(++dispatches>0x01000000u) {
            gw_recomp_latch_runtime_frontier(last_guest_instruction_va,
                "tail-transfer trampoline dispatch budget exhausted",g_eax,g_ebx,g_ecx,
                g_edx,g_esi,g_edi,g_ebp,g_esp,
                recomp_eflags(g_flag_k,g_flag_a,g_flag_b,g_flag_cf,1u));
            return 0;
        }
        fn();
        if(last_port_io_trap.pending || recomp_memory_fault_pending() ||
           gw_interrupt_get_trap().pending) return 0;
    }
    return 1;
}

void gw_recomp_latch_unresolved_indirect(uint32_t target_va) {
    latch_port_io_trap(GW_PORT_IO_TRAP_UNRESOLVED_INDIRECT_CALL,
                       UINT32_MAX,target_va,0u,target_va,last_guest_instruction_va);
}

int gw_recomp_interactive_resilient_enabled(void) {
    if(!interactive_resilient_checked) {
        const char *value=getenv("GW_INTERACTIVE_RESILIENT");
        interactive_resilient_value=value && strcmp(value,"1")==0;
        interactive_resilient_checked=1;
    }
    return interactive_resilient_value;
}

void gw_recomp_log_interactive_unresolved(uint32_t callsite_eip,
    uint32_t target_va,uint32_t eax,uint32_t ecx,uint32_t edx,uint32_t ebx,
    uint32_t esi,uint32_t edi,uint32_t ebp,uint32_t esp) {
    FILE *out=fopen("unresolved_calls.log","ab");
    uint32_t link=0u;
    const int has_link=recomp_code_linear_to_link(target_va,&link);
    if(!out) return;
    fprintf(out,"unresolved_indirect_call callsite_eip=0x%08X target_va=0x%08X target_link=%s0x%08X mapped_function=no recovery=synthetic_ret_eax_0 regs=eax:%08X ecx:%08X edx:%08X ebx:%08X esi:%08X edi:%08X ebp:%08X esp:%08X\n",
        callsite_eip,target_va,has_link?"":"unmapped/",has_link?link:target_va,
        eax,ecx,edx,ebx,esi,edi,ebp,esp);
    fclose(out);
}

static int frontier_read_guest(uint32_t address, void *out, uint32_t size) {
    if (!active_context || !out || !size || !g_mem_base ||
        address < active_context->mem_guest_base ||
        (uint64_t)address + size >
            (uint64_t)active_context->mem_guest_base + active_context->mem_size)
        return 0;
    uintptr_t host=(uintptr_t)((intptr_t)g_mem_base+(intptr_t)(uint64_t)address);
    memcpy(out,(const void *)host,size);
    return 1;
}

static void frontier_dump_bytes(const char *label,uint32_t address,uint32_t size) {
    uint8_t bytes[40];
    if (size>sizeof bytes || !frontier_read_guest(address,bytes,size)) {
        fprintf(stderr,"RUNTIME_FRONTIER_MEM label=%s guest=%08X size=%u readable=0\n",
                label,address,size);
        return;
    }
    fprintf(stderr,"RUNTIME_FRONTIER_MEM label=%s guest=%08X size=%u readable=1 bytes=",
            label,address,size);
    for (uint32_t i=0;i<size;i++) fprintf(stderr,"%s%02X",i?" ":"",bytes[i]);
    fputc('\n',stderr);
}

static void frontier_dump_bytes_128(const char *label,uint32_t address) {
    uint8_t bytes[128];
    if (!frontier_read_guest(address,bytes,sizeof bytes)) {
        fprintf(stderr,"RUNTIME_FRONTIER_MEM label=%s guest=%08X size=%u readable=0\n",
                label,address,(unsigned)sizeof bytes);
        return;
    }
    fprintf(stderr,"RUNTIME_FRONTIER_MEM label=%s guest=%08X size=%u readable=1 bytes=",
            label,address,(unsigned)sizeof bytes);
    for (uint32_t i=0;i<sizeof bytes;i++) fprintf(stderr,"%s%02X",i?" ":"",bytes[i]);
    fputc('\n',stderr);
}

static void frontier_dump_stack(uint32_t ebp,uint32_t esp) {
    uint32_t words[8];
    for (uint32_t i=0;i<8;i++) {
        uint32_t address=esp+i*4u;
        if (!frontier_read_guest(address,&words[i],sizeof words[i])) break;
        fprintf(stderr,"RUNTIME_FRONTIER_STACK esp+%02X guest=%08X value=%08X\n",
                i*4u,address,words[i]);
    }
    uint32_t frame=ebp;
    for (uint32_t depth=0;depth<8 && frame;depth++) {
        uint32_t pair[2];
        if (!frontier_read_guest(frame,pair,sizeof pair)) break;
        fprintf(stderr,"RUNTIME_FRONTIER_FRAME depth=%u ebp=%08X saved_ebp=%08X return=%08X\n",
                depth,frame,pair[0],pair[1]);
        if (pair[0]<=frame || pair[0]-frame>0x10000u) break;
        frame=pair[0];
    }
}

void gw_recomp_latch_runtime_frontier(uint32_t guest_eip, const char *reason,
    uint32_t eax,uint32_t ebx,uint32_t ecx,uint32_t edx,
    uint32_t esi,uint32_t edi,uint32_t ebp,uint32_t esp,uint32_t eflags) {
    if (!last_port_io_trap.pending) {
        latch_port_io_trap(GW_PORT_IO_TRAP_UNRESOLVED_INDIRECT_CALL,
                           UINT32_MAX,guest_eip,0u,guest_eip,guest_eip);
    }
    fprintf(stderr,
        "RUNTIME_FRONTIER eip=%08X reason=%s EAX=%08X EBX=%08X ECX=%08X EDX=%08X "
        "ESI=%08X EDI=%08X EBP=%08X ESP=%08X EFLAGS=%08X CS=%04X DS=%04X ES=%04X SS=%04X "
        "icall_count=%u ring_begin=%u cur_func=%08X\n",
        guest_eip,reason ? reason : "unresolved",eax,ebx,ecx,edx,esi,edi,ebp,esp,eflags,
        g_seg_cs,g_seg_ds,g_seg_es,g_seg_ss,g_icall_count,
        g_icall_trace_idx > 32u ? g_icall_trace_idx-32u : 0u,g_cur_func);
    if (guest_eip==0x00088146u) {
        frontier_dump_bytes("EDX-8_to_EDX+24",edx-8u,33u);
        if ((uint64_t)edx+8u<=0x100000000ull) {
            uint32_t slot_target=0u;
            int slot_read=frontier_read_guest(edx+4u,&slot_target,4u);
            fprintf(stderr,"RUNTIME_FRONTIER_CALL_OPERAND site=00088146 operand=[EDX+4] slot=%08X readable=%u target=%08X\n",
                    edx+4u,slot_read,slot_read?slot_target:0u);
            if (slot_read) frontier_dump_bytes("call_target_code",slot_target,16u);
        }
        frontier_dump_stack(ebp,esp);
    } else if (guest_eip==0x00088179u) {
        frontier_dump_bytes("EDI-8_to_EDI+27",edi-8u,40u);
        frontier_dump_bytes("EDI+28_to_EDI+47",edi+0x28u,32u);
        if ((uint64_t)edi+0x48u<=0x100000000ull) {
            uint32_t slot_target=0u;
            int slot_read=frontier_read_guest(edi+0x44u,&slot_target,4u);
            fprintf(stderr,"RUNTIME_FRONTIER_CALL_OPERAND site=00088179 operand=[EDI+44] slot=%08X readable=%u target=%08X\n",
                    edi+0x44u,slot_read,slot_read?slot_target:0u);
            if (slot_read) frontier_dump_bytes("call_target_code",slot_target,16u);
        }
        frontier_dump_stack(ebp,esp);
    } else if (guest_eip==0x00056F3Bu) {
        if ((uint64_t)ecx+0x74u<=0x100000000ull) {
            uint32_t slot_target=0u;
            int slot_read=frontier_read_guest(ecx+0x70u,&slot_target,4u);
            fprintf(stderr,"RUNTIME_FRONTIER_CALL_OPERAND site=00056F3B operand=[ECX+70] slot=%08X readable=%u target=%08X\n",
                    ecx+0x70u,slot_read,slot_read?slot_target:0u);
            if (slot_read) frontier_dump_bytes("call_target_code",slot_target,16u);
        }
        frontier_dump_stack(ebp,esp);
    } else if (guest_eip==0x00079218u) {
        if ((uint64_t)edx+0x20u<=0x100000000ull) {
            uint32_t slot_target=0u;
            int slot_read=frontier_read_guest(edx+0x1cu,&slot_target,4u);
            fprintf(stderr,"RUNTIME_FRONTIER_CALL_OPERAND site=00079218 operand=[EDX+1C] slot=%08X readable=%u target=%08X\n",
                    edx+0x1cu,slot_read,slot_read?slot_target:0u);
            if (slot_read) frontier_dump_bytes("call_target_code",slot_target,16u);
        }
        frontier_dump_stack(ebp,esp);
    } else if (guest_eip==0x0007925Bu) {
        uint32_t slot_target=0u;
        int slot_read=frontier_read_guest(edi+0x24u,&slot_target,sizeof slot_target);
        fprintf(stderr,"RUNTIME_FRONTIER_CALL_OPERAND site=0007925B operand=[EDI+24] slot=%08X readable=%u target=%08X expected_vtable_111DFC=%08X expected_target_6ED40=%08X\n",
                edi+0x24u,slot_read,slot_read?slot_target:0u,0x002EBDFCu,0x00259D40u);
        frontier_dump_bytes("drawmap_vtable_candidate",edi,0x28u);
        frontier_dump_bytes("drawmap_receiver_candidate",eax,0x50u);
        frontier_dump_stack(ebp,esp);
    } else if (guest_eip==0x0004459Eu) {
        frontier_dump_bytes("EDX_vtable_0x94_slot",edx+0x94u,4u);
        if ((uint64_t)edx+0x98u<=0x100000000ull) {
            uint32_t slot_target=0u;
            int slot_read=frontier_read_guest(edx+0x94u,&slot_target,4u);
            fprintf(stderr,"RUNTIME_FRONTIER_CALL_OPERAND site=0004459E operand=[EDX+94] slot=%08X readable=%u target=%08X\n",
                    edx+0x94u,slot_read,slot_read?slot_target:0u);
            if (slot_read) frontier_dump_bytes("call_target_code",slot_target,16u);
        }
        frontier_dump_stack(ebp,esp);
    } else if (guest_eip==0x000258F3u) {
        /* FUN_000256E0's rectangle callback. Keep the exact live vtable slot
         * and receiver bytes when its original indirect dispatch is not yet
         * admitted; this distinguishes a valid LE method pointer from a
         * damaged/dynamic receiver without guessing from the host PC. */
        uint32_t slot_target=0u,receiver_vptr=0u;
        int slot_read=frontier_read_guest(edx,&slot_target,sizeof slot_target);
        int vptr_read=frontier_read_guest(ebx+0x2fu,&receiver_vptr,sizeof receiver_vptr);
        fprintf(stderr,"RUNTIME_FRONTIER_CALL_OPERAND site=000258F3 operand=[EDX] slot=%08X readable=%u target=%08X receiver=%08X receiver_vptr_readable=%u\n",
                edx,slot_read,slot_read?slot_target:0u,ebx,vptr_read);
        frontier_dump_bytes("callback_vtable_head",edx,32u);
        frontier_dump_bytes("callback_receiver",ebx,56u);
        if(slot_read) frontier_dump_bytes("callback_target_code_or_data",slot_target,24u);
        if(vptr_read) frontier_dump_bytes("callback_receiver_vptr",receiver_vptr,24u);
        frontier_dump_stack(ebp,esp);
    } else if (guest_eip==0x00010243u) {
        /* ProcessSounds reached an original entity callback late in a long
           native game() run. The call is intentionally still fail-closed;
           capture its dynamic table cell and the owning record before any
           decision about admitting the destination. */
        uint32_t slot=0u,record_cb=0u;
        int slot_read=frontier_read_guest(edi+0x78u,&slot,sizeof slot);
        int record_read=frontier_read_guest(esi+0x23u,&record_cb,sizeof record_cb);
        fprintf(stderr,"RUNTIME_FRONTIER_CALL_OPERAND site=00010243 operand=[EDI+78] slot=%08X readable=%u target=%08X record=%08X record_cb_readable=%u\n",
                edi+0x78u,slot_read,slot_read?slot:0u,esi+0x23u,record_read);
        frontier_dump_bytes("audio_or_entity_receiver",esi,0x66u);
        if(record_read) frontier_dump_bytes("callback_interface",record_cb,0xA0u);
        if(slot_read) frontier_dump_bytes("callback_target_code",slot,24u);
        frontier_dump_stack(ebp,esp);
    } else if (guest_eip==0x000392B6u) {
        /* Building completion attempted a virtual dispatch through a dynamic
         * record at EDI+0x44. Preserve the complete Building record and the
         * actual indirect slot so data/code confusion remains diagnosable. */
        uint32_t slot_target=0u;
        int slot_read=frontier_read_guest(edi+0x44u,&slot_target,sizeof slot_target);
        fprintf(stderr,"RUNTIME_FRONTIER_CALL_OPERAND site=000392B6 operand=[EDI+44] slot=%08X readable=%u target=%08X building=%08X\n",
                edi+0x44u,slot_read,slot_read?slot_target:0u,esi);
        frontier_dump_bytes_128("building_record_128",esi);
        frontier_dump_bytes("indirect_receiver_edi",edi,0x50u);
        if (slot_read) frontier_dump_bytes("indirect_target_bytes",slot_target,16u);
        frontier_dump_stack(ebp,esp);
    }
    uint32_t begin = g_icall_trace_idx > 32u ? g_icall_trace_idx-32u : 0u;
    for (uint32_t sequence=begin; sequence<g_icall_trace_idx; ++sequence) {
        uint32_t slot = sequence & (ICALL_TRACE_SIZE-1u);
        fprintf(stderr,"RUNTIME_FRONTIER_CALL seq=%u target=%08X caller=%08X\n",
                sequence,g_icall_trace[slot],g_icall_from[slot]);
    }
}

int gw_recomp_port_io(unsigned int operation, unsigned int port,
                      unsigned int width, unsigned int value,
                      unsigned int guest_va, unsigned int *value_out) {
    uint8_t byte_value;
    if (last_port_io_trap.pending) return 0;
    if (!active_context || !active_pit) {
        latch_port_io_trap(GW_PORT_IO_TRAP_NO_ACTIVE_CONTEXT, operation,
                           port, width, value, guest_va);
        return 0;
    }
    if (port_io_provider &&
        port_io_provider(operation,port,width,value,guest_va,value_out,
                         port_io_provider_user))
        return 1;
    if (operation == 0u) {
        if (!value_out) {
            latch_port_io_trap(GW_PORT_IO_TRAP_MISSING_READ_OUTPUT,
                               operation, port, width, value, guest_va);
            return 0;
        }
        if (width != 1u || port < 0x40u || port > 0x42u ||
            !gw_pit8254_read(active_pit, (uint16_t)port, width,
                             &byte_value)) {
            latch_port_io_trap(GW_PORT_IO_TRAP_UNSUPPORTED_IO, operation,
                               port, width, value, guest_va);
            return 0;
        }
        *value_out = byte_value;
        return 1;
    }
    if (operation == 1u && width == 1u && port >= 0x40u && port <= 0x43u &&
        gw_pit8254_write(active_pit, (uint16_t)port, (uint8_t)value, width))
        return 1;
    latch_port_io_trap(GW_PORT_IO_TRAP_UNSUPPORTED_IO, operation,
                       port, width, value, guest_va);
    return 0;
}

void gw_recomp_set_port_io_provider(gw_port_io_provider_fn provider,void *user) {
    port_io_provider=provider;
    port_io_provider_user=user;
}

gw_port_io_trap gw_recomp_get_port_io_trap(void) {
    return last_port_io_trap;
}

void gw_recomp_clear_port_io_trap(void) {
    last_port_io_trap.pending = 0u;
    last_port_io_trap.reason = GW_PORT_IO_TRAP_NONE;
    last_port_io_trap.port = 0u;
    last_port_io_trap.operation = 0u;
    last_port_io_trap.width = 0u;
    last_port_io_trap.value = 0u;
    last_port_io_trap.guest_va = 0u;
    if (active_context) active_context->port_io_trap = last_port_io_trap;
}

gw_recomp_status gw_recomp_invoke(recomp_func_t function, gw_recomp_context *context) {
    if (!function || !context) return GW_RECOMP_INVALID;
    if (atomic_flag_test_and_set_explicit(&gw_context_busy,memory_order_acquire)) return GW_RECOMP_BUSY;
    if (!context->pit_initialized) {
        gw_pit8254_init(&context->pit);
        context->pit_initialized=1u;
    }
    active_context=context;
    active_pit=&context->pit;
    gw_recomp_clear_port_io_trap();
    gw_interrupt_clear_trap();
    recomp_clear_segment_fault();
    recomp_clear_memory_fault();
    pending_tail_call_va=0u;
    pending_tail_call_valid=0;
    apply_context(context);
    function();
    (void)gw_recomp_dispatch_pending_tail_calls();
    capture_context(context);
    active_pit=0;
    active_context=0;
    atomic_flag_clear_explicit(&gw_context_busy,memory_order_release);
    return GW_RECOMP_OK;
}

void gw_recomp_yield_active_context(void) {
    if (!active_context) return;
    capture_context(active_context);
    active_pit=0;
    active_context=0;
    atomic_flag_clear_explicit(&gw_context_busy,memory_order_release);
}
