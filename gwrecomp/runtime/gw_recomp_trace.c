#include "gw_recomp_trace.h"
#include "../third_party/pcrecomp/runtime/recomp32/recomp_types.h"

#include <stdio.h>

#define CALL_RING_SIZE 32u
#define INTERRUPT_RING_SIZE 8u

typedef struct {
    uint32_t sequence, callsite, caller, target, return_va;
    uint8_t indirect;
} call_record;

typedef struct {
    uint32_t sequence, callsite, caller, target, eflags;
    uint8_t taken;
} branch_record;

typedef struct {
    uint32_t sequence, callsite, caller, target, eflags;
    uint8_t kind, indirect, taken;
} control_record;

typedef struct {
    uint32_t sequence, instruction_va, guest_function_va;
    uint32_t request_eax, request_ebx, request_ecx, request_edx;
    uint32_t request_esi, request_edi, request_ds, request_es;
    uint32_t response_eax, response_ebx, response_ecx, response_edx;
    uint32_t carry;
    uint8_t vector;
} interrupt_record;

static call_record calls[CALL_RING_SIZE];
static branch_record branches[CALL_RING_SIZE];
static control_record controls[CALL_RING_SIZE];
static interrupt_record interrupts[INTERRUPT_RING_SIZE];
static interrupt_record last_dos, last_dpmi;
static uint32_t call_sequence, branch_sequence, control_sequence, interrupt_sequence;
static int trace_enabled;
static int boundary_stop_enabled, boundary_was_hit;
static int have_last_dos, have_last_dpmi;
#define WATCHED_BRANCH_SITES 24u
static uint32_t watched_branch_sites[WATCHED_BRANCH_SITES];
static uint32_t watched_branch_count;

void gw_recomp_trace_set_enabled(int enabled) { trace_enabled = enabled != 0; }
int gw_recomp_trace_enabled(void) { return trace_enabled; }
void gw_recomp_trace_set_boundary_stop(int enabled) {
    boundary_stop_enabled = enabled != 0;
    boundary_was_hit = 0;
}
int gw_recomp_trace_boundary_hit(void) { return boundary_was_hit; }
int gw_recomp_trace_stop_before_target(uint32_t target_link_va) {
    if (!trace_enabled || !boundary_stop_enabled ||
        (target_link_va != 0x00098C19u && target_link_va != 0x00098C31u))
        return 0;
    boundary_was_hit=1;
    return 1;
}

void gw_recomp_trace_call(uint32_t callsite, uint32_t caller,
                          uint32_t target, uint32_t return_va, uint8_t indirect) {
    if (!trace_enabled) return;
    /* LbFileLoadAt_ takes its destination in EBX. Capture the original
       caller as soon as it supplies NULL, before path preparation and DOS
       reads replace the short CALL history. This is observation only. */
    if (target == 0x000150D0u && g_ebx == 0u)
        fprintf(stderr,"TRACE LbFileLoadAt null-destination callsite=%08x caller=%08x target=%08x EAX=%08x EBX=%08x ECX=%08x EDX=%08x ESI=%08x EDI=%08x EBP=%08x ESP=%08x indirect=%u\n",
                callsite,caller,target,g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,
                (unsigned)(indirect!=0));
    call_record *r = &calls[call_sequence & (CALL_RING_SIZE - 1u)];
    r->sequence = call_sequence++;
    r->callsite = callsite;
    r->caller = caller;
    r->target = target;
    r->return_va = return_va;
    r->indirect = indirect != 0;
    control_record *c = &controls[control_sequence & (CALL_RING_SIZE - 1u)];
    c->sequence = control_sequence++;
    c->callsite = callsite; c->caller = caller; c->target = target;
    c->eflags = 0; c->kind = 0; c->indirect = indirect != 0; c->taken = 1;
}

void gw_recomp_trace_branch(uint32_t callsite, uint32_t caller,
                            uint32_t target, uint32_t eflags, uint8_t taken) {
    if (!trace_enabled) return;
    branch_record *r = &branches[branch_sequence & (CALL_RING_SIZE - 1u)];
    r->sequence = branch_sequence++;
    r->callsite = callsite;
    r->caller = caller;
    r->target = target;
    r->eflags = eflags;
    r->taken = taken != 0;
    control_record *c = &controls[control_sequence & (CALL_RING_SIZE - 1u)];
    c->sequence = control_sequence++;
    c->callsite = callsite; c->caller = caller; c->target = target;
    c->eflags = eflags; c->kind = 1; c->indirect = 0; c->taken = taken != 0;
    for (uint32_t i=0;i<watched_branch_count;i++) {
        if (callsite == watched_branch_sites[i]) {
            fprintf(stderr, "TRACE guest-branch-watch site=%08x caller=%08x kind=jcc-%s target=%08x eflags=%08x\n",
                    callsite, caller, taken ? "taken" : "fallthrough", target, eflags);
            break;
        }
    }
}

void gw_recomp_trace_watch_branch(uint32_t callsite) {
    if (!callsite) { watched_branch_count=0; return; }
    for (uint32_t i=0;i<watched_branch_count;i++)
        if (watched_branch_sites[i]==callsite) return;
    if (watched_branch_count < WATCHED_BRANCH_SITES)
        watched_branch_sites[watched_branch_count++]=callsite;
}

void gw_recomp_trace_interrupt(uint8_t vector, uint32_t instruction_va,
                               uint32_t guest_function_va,
                               uint32_t request_eax, uint32_t request_ebx,
                               uint32_t request_ecx, uint32_t request_edx,
                               uint32_t request_esi, uint32_t request_edi,
                               uint32_t request_ds, uint32_t request_es,
                               uint32_t response_eax, uint32_t response_ebx,
                               uint32_t response_ecx, uint32_t response_edx,
                               uint32_t carry) {
    if (!trace_enabled) return;
    interrupt_record *r = &interrupts[interrupt_sequence & (INTERRUPT_RING_SIZE - 1u)];
    r->sequence = interrupt_sequence++;
    r->instruction_va = instruction_va;
    r->guest_function_va = guest_function_va;
    r->request_eax = request_eax; r->request_ebx = request_ebx;
    r->request_ecx = request_ecx; r->request_edx = request_edx;
    r->request_esi = request_esi; r->request_edi = request_edi;
    r->request_ds = request_ds; r->request_es = request_es;
    r->response_eax = response_eax; r->response_ebx = response_ebx;
    r->response_ecx = response_ecx; r->response_edx = response_edx;
    r->carry = carry; r->vector = vector;
    if(vector==0x21u) { last_dos=*r; have_last_dos=1; }
    if(vector==0x31u) { last_dpmi=*r; have_last_dpmi=1; }
}

void gw_recomp_trace_checkpoint(uint32_t target, uint32_t caller) {
    uint32_t control_count = control_sequence < CALL_RING_SIZE ? control_sequence : CALL_RING_SIZE;
    uint32_t control_first = control_sequence - control_count;
    fprintf(stderr, "TRACE guest-control checkpoint target=%08x caller=%08x transfers=%u\n",
            target, caller, control_count);
    for (uint32_t n = control_first; n < control_sequence; ++n) {
        const control_record *r = &controls[n & (CALL_RING_SIZE - 1u)];
        if (r->kind == 0)
            fprintf(stderr, "TRACE guest-control-history seq=%u kind=call-%s site=%08x caller=%08x target=%08x\n",
                    r->sequence, r->indirect ? "indirect" : "direct", r->callsite,
                    r->caller, r->target);
        else
            fprintf(stderr, "TRACE guest-control-history seq=%u kind=jcc-%s site=%08x caller=%08x target=%08x eflags=%08x\n",
                    r->sequence, r->taken ? "taken" : "fallthrough", r->callsite,
                    r->caller, r->target, r->eflags);
    }
    uint32_t count = call_sequence < CALL_RING_SIZE ? call_sequence : CALL_RING_SIZE;
    uint32_t first = call_sequence - count;
    fprintf(stderr, "TRACE guest-call checkpoint target=%08x caller=%08x calls=%u\n",
            target, caller, count);
    for (uint32_t n = first; n < call_sequence; ++n) {
        const call_record *r = &calls[n & (CALL_RING_SIZE - 1u)];
        fprintf(stderr, "TRACE guest-call-history seq=%u kind=call-%s site=%08x caller=%08x target=%08x return=%08x\n",
                r->sequence, r->indirect ? "indirect" : "direct", r->callsite,
                r->caller, r->target, r->return_va);
    }
    uint32_t branch_count = branch_sequence < CALL_RING_SIZE ? branch_sequence : CALL_RING_SIZE;
    uint32_t branch_first = branch_sequence - branch_count;
    fprintf(stderr, "TRACE guest-branch checkpoint branches=%u\n", branch_count);
    for (uint32_t n = branch_first; n < branch_sequence; ++n) {
        const branch_record *r = &branches[n & (CALL_RING_SIZE - 1u)];
        fprintf(stderr, "TRACE guest-branch-history seq=%u kind=jcc-%s site=%08x caller=%08x target=%08x eflags=%08x\n",
                r->sequence, r->taken ? "taken" : "fallthrough", r->callsite,
                r->caller, r->target, r->eflags);
    }
    if (!interrupt_sequence) {
        fprintf(stderr, "TRACE guest-call last-dos-dpmi=none\n");
        return;
    }
    if (have_last_dos)
        fprintf(stderr, "TRACE guest-call last-dos seq=%u int=21 site=%08x func=%08x req=%08x/%08x/%08x/%08x esi=%08x edi=%08x ds=%04x es=%04x ret=%08x/%08x/%08x/%08x cf=%u\n",
                last_dos.sequence, last_dos.instruction_va,
                last_dos.guest_function_va, last_dos.request_eax,
                last_dos.request_ebx, last_dos.request_ecx,
                last_dos.request_edx, last_dos.request_esi,
                last_dos.request_edi, last_dos.request_ds,
                last_dos.request_es, last_dos.response_eax,
                last_dos.response_ebx, last_dos.response_ecx,
                last_dos.response_edx, last_dos.carry);
    if (have_last_dpmi)
        fprintf(stderr, "TRACE guest-call last-dpmi seq=%u int=31 site=%08x func=%08x req=%08x/%08x/%08x/%08x esi=%08x edi=%08x ds=%04x es=%04x ret=%08x/%08x/%08x/%08x cf=%u\n",
                last_dpmi.sequence, last_dpmi.instruction_va,
                last_dpmi.guest_function_va, last_dpmi.request_eax,
                last_dpmi.request_ebx, last_dpmi.request_ecx,
                last_dpmi.request_edx, last_dpmi.request_esi,
                last_dpmi.request_edi, last_dpmi.request_ds,
                last_dpmi.request_es, last_dpmi.response_eax,
                last_dpmi.response_ebx, last_dpmi.response_ecx,
                last_dpmi.response_edx, last_dpmi.carry);
}

void gw_recomp_trace_boundary_state(uint32_t callsite, uint32_t caller,
    uint32_t target, uint32_t return_va, uint32_t eax, uint32_t ebx, uint32_t ecx, uint32_t edx,
    uint32_t esi, uint32_t edi, uint32_t ebp, uint32_t esp, uint32_t eflags) {
    if (!trace_enabled || !boundary_stop_enabled) return;
    uint32_t link_target=target;
    if (link_target!=0x00098C19u && link_target!=0x00098C31u) return;
    boundary_was_hit=1;
    fprintf(stderr,"TRACE guest-exit-boundary site=%08x caller=%08x target=%08x original_return=%08x EAX=%08x EBX=%08x ECX=%08x EDX=%08x ESI=%08x EDI=%08x EBP=%08x ESP_before_call=%08x native_entry_ESP=%08x native_entry_stack_top=%08x EFLAGS=%08x action=stop-before-original-call\n",
        callsite,caller,link_target,return_va,eax,ebx,ecx,edx,esi,edi,ebp,esp,esp-4u,return_va,eflags);
}

uint32_t gw_recomp_trace_last_return_to(uint32_t target) {
    if (!call_sequence) return 0;
    uint32_t count=call_sequence<CALL_RING_SIZE?call_sequence:CALL_RING_SIZE;
    for(uint32_t n=call_sequence;n>call_sequence-count;--n) {
        const call_record *r=&calls[(n-1u)&(CALL_RING_SIZE-1u)];
        if(r->target==target)
            return r->return_va;
    }
    return 0;
}
