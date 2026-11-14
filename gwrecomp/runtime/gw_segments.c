#include "gw_segments.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef RECOMP_TRACE_LOW_WRITES
#include <stdio.h>
#endif

uint32_t g_cs_base, g_ds_base, g_es_base, g_ss_base;
static recomp_segment_resolver_fn active_resolver;
static void *active_user;
static recomp_segment_fault last_fault;
static recomp_segment_range_fn active_range_validator;
static void *active_range_user;
static recomp_memory_fault memory_fault;
static uint32_t memory_begin, memory_size;
static uint32_t access_instruction_va, access_width;
static uint32_t access_instruction_id;
static uint8_t access_kind;
static recomp_segment_id access_segment=RECOMP_SEG_DS;
static char access_mnemonic[16];
static int access_active;
static union { uint64_t align; uint8_t bytes[16]; } fault_sink;
static int memory_diag_enabled;
static recomp_memory_backing_fn memory_backing_validator;
static void *memory_backing_user;
static recomp_memory_translate_fn memory_translator;
static void *memory_translator_user;
static recomp_guest_write_observer_fn guest_write_observer;
static void *guest_write_observer_user;
static recomp_memory_diagnostic current_instruction, last_access;
static recomp_memory_diagnostic dpmi_state;
static uint32_t current_guest_eip;
static uint32_t memory_diag_guest_begin, memory_diag_guest_end;
#define RECOMP_CODE_MAP_MAX 16u
static recomp_code_range code_ranges[RECOMP_CODE_MAP_MAX];
static uint32_t code_range_count;
static int null_ds_read_diag_enabled;
static uint32_t null_ds_read_diag_sequence;
static uint32_t null_ds_read_diag_printed;
static recomp_null_ds_read_diagnostic null_ds_read_diag_last_record;

void recomp_null_ds_read_diag_enable(int enabled) {
    null_ds_read_diag_enabled=enabled!=0;
    if (!enabled) {
        null_ds_read_diag_sequence=0;
        null_ds_read_diag_printed=0;
        memset(&null_ds_read_diag_last_record,0,sizeof null_ds_read_diag_last_record);
    }
}

uint32_t recomp_null_ds_read_diag_count(void) { return null_ds_read_diag_sequence; }

recomp_null_ds_read_diagnostic recomp_null_ds_read_diag_last(void) {
    return null_ds_read_diag_last_record;
}

static void note_null_ds_read(uint32_t guest_eip,uint32_t instruction_va,
    uint32_t instruction_id,recomp_segment_id segment,uint16_t selector,
    uint32_t base,uint32_t linear,uint32_t offset,uint32_t width,uint8_t access,
    const char *mnemonic) {
    recomp_null_ds_read_diagnostic *d=&null_ds_read_diag_last_record;
    /* Track the full real-mode IVT/BIOS data window for the protected flat
     * guest. 0x46c..0x46d is the BIOS tick counter alias and is intentionally
     * excluded from the null/low-pointer signal. */
    if (!null_ds_read_diag_enabled || segment!=RECOMP_SEG_DS || selector!=0x14u ||
        linear>=0x1000u || width==0u ||
        (linear<0x46eu && (uint64_t)linear+width>0x46cu) ||
        (access!=RECOMP_MEM_ACCESS_READ && access!=RECOMP_MEM_ACCESS_READWRITE)) return;
    null_ds_read_diag_sequence++;
    memset(d,0,sizeof(*d));
    d->count=null_ds_read_diag_sequence; d->guest_eip=guest_eip;
    d->instruction_va=instruction_va; d->instruction_id=instruction_id;
    d->linear=linear; d->offset=offset; d->width=width;
    d->eax=g_eax; d->ebx=g_ebx; d->ecx=g_ecx; d->edx=g_edx;
    d->esi=g_esi; d->edi=g_edi; d->ebp=g_ebp; d->esp=g_esp;
    d->selector=selector; d->segment_base=base; d->access=access;
    if (mnemonic) strncpy(d->mnemonic,mnemonic,sizeof d->mnemonic-1u);
    /* Bound host logging while preserving the latest complete event for the
     * test/runtime consumer. The guest operation and register state are not
     * changed by this observer. */
    if (null_ds_read_diag_printed<256u) {
        fprintf(stderr,"TRACE guest-null-read count=%u eip=%08x insn=%08x id=%u mnemonic=%s seg=DS sel=%04x base=%08x linear=%08x offset=%08x width=%u access=%u regs=%08x/%08x/%08x/%08x/%08x/%08x/%08x/%08x\n",
            d->count,d->guest_eip,d->instruction_va,d->instruction_id,
            d->mnemonic,d->selector,d->segment_base,d->linear,d->offset,
            d->width,d->access,d->eax,d->ebx,d->ecx,d->edx,
            d->esi,d->edi,d->ebp,d->esp);
        null_ds_read_diag_printed++;
    }
}

int recomp_code_map_set(const recomp_code_range *ranges,uint32_t count) {
    uint32_t i,j;
    if (count>RECOMP_CODE_MAP_MAX || (count && !ranges)) return 0;
    for (i=0;i<count;i++) {
        uint64_t guest_end=(uint64_t)ranges[i].guest_linear_base+ranges[i].size;
        uint64_t link_end=(uint64_t)ranges[i].link_base+ranges[i].size;
        if (!ranges[i].size || guest_end>0x100000000ull || link_end>0x100000000ull) return 0;
        for (j=0;j<i;j++) {
            uint64_t other_guest_end=(uint64_t)ranges[j].guest_linear_base+ranges[j].size;
            uint64_t other_link_end=(uint64_t)ranges[j].link_base+ranges[j].size;
            if ((ranges[i].guest_linear_base<other_guest_end && ranges[j].guest_linear_base<guest_end) ||
                (ranges[i].link_base<other_link_end && ranges[j].link_base<link_end)) return 0;
        }
    }
    if (count) memcpy(code_ranges,ranges,count*sizeof(*ranges));
    code_range_count=count;
    return 1;
}

int recomp_code_linear_to_link(uint32_t guest_linear,uint32_t *link_va) {
    uint32_t i;
    if (!link_va) return 0;
    for (i=0;i<code_range_count;i++) {
        const recomp_code_range *range=&code_ranges[i];
        if (guest_linear>=range->guest_linear_base &&
            (uint64_t)guest_linear<(uint64_t)range->guest_linear_base+range->size) {
            *link_va=range->link_base+(guest_linear-range->guest_linear_base);
            return 1;
        }
    }
    return 0;
}

static int memory_diag_matches(uint32_t guest_eip) {
    return memory_diag_enabled &&
        (memory_diag_guest_end<=memory_diag_guest_begin ||
         (guest_eip>=memory_diag_guest_begin && guest_eip<memory_diag_guest_end));
}

static void snapshot_guest_registers(void) {
    current_instruction.register_snapshot_valid=1;
    current_instruction.eax=g_eax; current_instruction.ebx=g_ebx;
    current_instruction.ecx=g_ecx; current_instruction.edx=g_edx;
    current_instruction.esi=g_esi; current_instruction.edi=g_edi;
    current_instruction.ebp=g_ebp; current_instruction.esp=g_esp;
}

static void segment_state(recomp_segment_id segment,uint16_t *selector,uint32_t *base) {
    *selector=0; *base=0;
    switch(segment) {
    case RECOMP_SEG_CS: *selector=g_seg_cs; *base=g_cs_base; break;
    case RECOMP_SEG_DS: *selector=g_seg_ds; *base=g_ds_base; break;
    case RECOMP_SEG_ES: *selector=g_seg_es; *base=g_es_base; break;
    case RECOMP_SEG_FS: *selector=g_seg_fs; *base=g_fs_base; break;
    case RECOMP_SEG_GS: *selector=g_seg_gs; *base=g_gs_base; break;
    case RECOMP_SEG_SS: *selector=g_seg_ss; *base=g_ss_base; break;
    default: break;
    }
}

void recomp_memory_diag_enable(int enabled) { memory_diag_enabled=enabled!=0; }
int recomp_memory_diag_enabled(void) { return memory_diag_enabled; }
void recomp_memory_diag_set_guest_range(uint32_t begin,uint32_t end) {
    memory_diag_guest_begin=begin; memory_diag_guest_end=end;
}
void recomp_memory_diag_set_guest_eip(uint32_t guest_eip) {
    if (!memory_diag_enabled) return;
    current_guest_eip=guest_eip;
    last_access.guest_eip=guest_eip;
}
void recomp_memory_diag_note_guest_instruction(uint32_t guest_eip,
    uint32_t eax,uint32_t ebx,uint32_t ecx,uint32_t edx,
    uint32_t esi,uint32_t edi,uint32_t ebp,uint32_t esp) {
    if (!memory_diag_enabled) return;
    current_guest_eip=guest_eip;
    memset(&current_instruction,0,sizeof current_instruction);
    current_instruction.valid=1;
    current_instruction.instruction_va=guest_eip;
    current_instruction.register_snapshot_valid=1;
    current_instruction.eax=eax; current_instruction.ebx=ebx;
    current_instruction.ecx=ecx; current_instruction.edx=edx;
    current_instruction.esi=esi; current_instruction.edi=edi;
    current_instruction.ebp=ebp; current_instruction.esp=esp;
    last_access.guest_eip=guest_eip;
}
void recomp_memory_diag_set_backing_validator(recomp_memory_backing_fn validator,void *user) {
    memory_backing_validator=validator; memory_backing_user=user;
}
void recomp_memory_diag_set_dpmi_state(uint32_t req_eax,uint32_t req_ebx,
    uint32_t req_ecx,uint32_t req_edx,uint32_t res_eax,uint32_t res_ebx,
    uint32_t res_ecx,uint32_t res_edx,uint32_t carry) {
    dpmi_state.dpmi_req_eax=req_eax; dpmi_state.dpmi_req_ebx=req_ebx;
    dpmi_state.dpmi_req_ecx=req_ecx; dpmi_state.dpmi_req_edx=req_edx;
    dpmi_state.dpmi_res_eax=res_eax; dpmi_state.dpmi_res_ebx=res_ebx;
    dpmi_state.dpmi_res_ecx=res_ecx; dpmi_state.dpmi_res_edx=res_edx;
    dpmi_state.dpmi_carry=carry;
}
void recomp_memory_diag_note_instruction(uint32_t instruction_va,uint32_t instruction_id,
    const char *mnemonic,recomp_segment_id segment,uint8_t access,
    uint32_t eax,uint32_t ebx,uint32_t ecx,uint32_t edx,
    uint32_t esi,uint32_t edi,uint32_t ebp,uint32_t esp) {
    if (!memory_diag_enabled) return;
    memset(&current_instruction,0,sizeof current_instruction);
    current_instruction.valid=1; current_instruction.instruction_va=instruction_va;
    current_instruction.register_snapshot_valid=1;
    current_instruction.instruction_id=instruction_id; current_instruction.segment=(uint8_t)segment;
    current_instruction.access=access; current_instruction.eax=eax; current_instruction.ebx=ebx;
    current_instruction.ecx=ecx; current_instruction.edx=edx; current_instruction.esi=esi;
    current_instruction.edi=edi; current_instruction.ebp=ebp; current_instruction.esp=esp;
    if (mnemonic) { strncpy(current_instruction.mnemonic,mnemonic,sizeof current_instruction.mnemonic-1u); }
}
recomp_memory_diagnostic recomp_memory_diag_last_access(void) { return last_access; }

static void remember_access(recomp_segment_id segment,uint16_t selector,uint32_t base,
    uint32_t instruction_va,uint32_t linear,uint32_t width,uint8_t access,
    uintptr_t host_address,int backing) {
    memset(&last_access,0,sizeof last_access);
    last_access.guest_eip=current_guest_eip;
    last_access.valid=1; last_access.access=access; last_access.segment=(uint8_t)segment;
    last_access.selector=selector; last_access.instruction_va=instruction_va;
    last_access.segment_base=base; last_access.linear=linear; last_access.offset=linear-base;
    last_access.width=width; last_access.host_address=host_address;
    last_access.backing=(uint8_t)(backing>0?RECOMP_MEM_BACKING_COMMITTED:
        backing==0?RECOMP_MEM_BACKING_UNCOMMITTED:RECOMP_MEM_BACKING_UNKNOWN);
    if (current_instruction.valid) {
        last_access.register_snapshot_valid=current_instruction.register_snapshot_valid;
        last_access.instruction_id=current_instruction.instruction_id;
        memcpy(last_access.mnemonic,current_instruction.mnemonic,sizeof last_access.mnemonic);
        last_access.eax=current_instruction.eax; last_access.ebx=current_instruction.ebx;
        last_access.ecx=current_instruction.ecx; last_access.edx=current_instruction.edx;
        last_access.esi=current_instruction.esi; last_access.edi=current_instruction.edi;
        last_access.ebp=current_instruction.ebp; last_access.esp=current_instruction.esp;
        if (!instruction_va) last_access.instruction_va=current_instruction.instruction_va;
        if (access==RECOMP_MEM_ACCESS_UNKNOWN) last_access.access=current_instruction.access;
    }
    last_access.dpmi_req_eax=dpmi_state.dpmi_req_eax;
    last_access.dpmi_req_ebx=dpmi_state.dpmi_req_ebx;
    last_access.dpmi_req_ecx=dpmi_state.dpmi_req_ecx;
    last_access.dpmi_req_edx=dpmi_state.dpmi_req_edx;
    last_access.dpmi_res_eax=dpmi_state.dpmi_res_eax;
    last_access.dpmi_res_ebx=dpmi_state.dpmi_res_ebx;
    last_access.dpmi_res_ecx=dpmi_state.dpmi_res_ecx;
    last_access.dpmi_res_edx=dpmi_state.dpmi_res_edx;
    last_access.dpmi_carry=dpmi_state.dpmi_carry;
}

static void set_memory_fault(recomp_segment_id segment,uint16_t selector,uint32_t base,
    uint32_t instruction_va,uint32_t linear,uint32_t width) {
    if (memory_fault.pending) return;
    memory_fault.pending=1; memory_fault.segment=(uint8_t)segment; memory_fault.selector=selector;
    memory_fault.offset=linear-base; memory_fault.width=width; memory_fault.linear=linear;
    memory_fault.instruction_va=instruction_va;
}

void recomp_set_segment_range_validator(recomp_segment_range_fn validator, void *user) {
    active_range_validator=validator; active_range_user=user;
}
void recomp_set_memory_bounds(uint32_t begin, uint32_t size) {
    memory_begin=begin; memory_size=size;
}
void recomp_begin_memory_access(recomp_segment_id segment, uint32_t width, uint32_t instruction_va) {
    recomp_begin_memory_access_ex(segment,width,instruction_va,
                                  RECOMP_MEM_ACCESS_UNKNOWN,0,0);
}

void recomp_begin_memory_access_ex(recomp_segment_id segment, uint32_t width,
    uint32_t instruction_va,uint8_t access,uint32_t instruction_id,
    const char *mnemonic) {
    access_segment=segment; access_width=width; access_instruction_va=instruction_va;
    access_instruction_id=instruction_id; access_kind=access; access_active=1;
    memset(access_mnemonic,0,sizeof access_mnemonic);
    if (mnemonic) strncpy(access_mnemonic,mnemonic,sizeof access_mnemonic-1u);
    if (memory_diag_enabled) {
        uint16_t selector=0; uint32_t base=0;
        segment_state(segment,&selector,&base);
        if (!current_instruction.valid || current_instruction.instruction_va!=instruction_va) {
            memset(&current_instruction,0,sizeof current_instruction);
            current_instruction.valid=1; current_instruction.instruction_va=instruction_va;
        }
        current_instruction.segment=(uint8_t)segment; current_instruction.selector=selector;
        current_instruction.segment_base=base; current_instruction.width=width;
        current_instruction.access=access;
        current_instruction.instruction_id=instruction_id;
        snapshot_guest_registers();
        if (mnemonic) {
            strncpy(current_instruction.mnemonic,mnemonic,
                    sizeof current_instruction.mnemonic-1u);
        }
        if (memory_diag_matches(instruction_va)) {
            last_access.guest_eip=current_guest_eip;
            last_access.instruction_va=instruction_va; last_access.segment=(uint8_t)segment;
            last_access.selector=selector; last_access.segment_base=base; last_access.width=width;
        }
    }
}

int recomp_check_indexed_table_access(recomp_segment_id segment,
    uint32_t table_offset,uint32_t index,uint32_t table_count,
    uint32_t divisor,uint32_t width,uint32_t instruction_va) {
    uint16_t selector=0; uint32_t base=0;
    uint64_t offset=(uint64_t)table_offset+(uint64_t)index;
    uint64_t linear;
    segment_state(segment,&selector,&base);
    linear=(uint64_t)base+offset;
    if (table_count && divisor>0 && divisor<=table_count &&
        index<divisor && (uint64_t)index+width<=table_count &&
        linear<=UINT32_MAX && width>0) return 1;

    if (linear>UINT32_MAX) linear=UINT32_MAX;
    if (memory_diag_enabled) {
        if (!current_instruction.valid || current_instruction.instruction_va!=instruction_va) {
            memset(&current_instruction,0,sizeof current_instruction);
            current_instruction.valid=1; current_instruction.instruction_va=instruction_va;
            current_instruction.segment=(uint8_t)segment; current_instruction.access=RECOMP_MEM_ACCESS_READ;
        }
        snapshot_guest_registers();
        remember_access(segment,selector,base,instruction_va,(uint32_t)linear,width,
                        RECOMP_MEM_ACCESS_READ,0,RECOMP_MEM_BACKING_UNKNOWN);
    }
    set_memory_fault(segment,selector,base,instruction_va,(uint32_t)linear,width);
    return 0;
}

void recomp_end_memory_access(void) { access_active=0; access_width=0; }
void recomp_clear_memory_fault(void) { memset(&memory_fault,0,sizeof(memory_fault)); }
int recomp_memory_fault_pending(void) { return memory_fault.pending!=0; }
recomp_memory_fault recomp_get_memory_fault(void) { return memory_fault; }

/* Opt-in write-path census (G-GP-002). Enabled only when GWRECOMP_WRITE_CENSUS=1
 * is set in the environment at the first checked guest address. Every checked
 * request is counted by entry point, host/guest scope, announced access kind
 * and outcome. The census never changes the returned address, the fault state
 * or whether the observer runs. Printed once at exit as "TRACE write_census". */
enum { CENSUS_ENTRY_MEM=0, CENSUS_ENTRY_SEG=1, CENSUS_ENTRIES=2 };
enum { CENSUS_SCOPE_GUEST=0, CENSUS_SCOPE_HOST=1, CENSUS_SCOPES=2 };
enum { CENSUS_KIND_UNKNOWN=0, CENSUS_KIND_READ=1, CENSUS_KIND_WRITE=2,
       CENSUS_KIND_READWRITE=3, CENSUS_KIND_OTHER=4, CENSUS_KINDS=5 };
enum { CENSUS_EARLY=0, CENSUS_SEG_REJECT=1, CENSUS_FAULT_SUPPRESSED=2,
       CENSUS_INVALID=3, CENSUS_CHECKED_NO_OBSERVER=4, CENSUS_OBSERVED=5,
       CENSUS_OUTCOMES=6 };
static const char *const census_entry_names[CENSUS_ENTRIES]={"mem","seg"};
static const char *const census_scope_names[CENSUS_SCOPES]={"guest","host"};
static const char *const census_kind_names[CENSUS_KINDS]={"UNKNOWN","READ","WRITE","READWRITE","OTHER"};
static const char *const census_outcome_names[CENSUS_OUTCOMES]={"early","seg_reject",
    "fault_suppressed","invalid","checked_no_observer","observed"};
static int census_state;          /* 0 = not read yet, 1 = off, 2 = on */
static int census_via_segment;    /* set while recomp_checked_segment_addr calls the core */
static int census_scope_host;
static uint32_t census_counts[CENSUS_ENTRIES][CENSUS_SCOPES][2][CENSUS_KINDS][CENSUS_OUTCOMES];

void recomp_write_census_dump(const char *tag) {
    int e,s,a,k,o;
    if (census_state!=2) return;
    for (e=0;e<CENSUS_ENTRIES;e++)
    for (s=0;s<CENSUS_SCOPES;s++)
    for (a=0;a<2;a++)
    for (k=0;k<CENSUS_KINDS;k++)
    for (o=0;o<CENSUS_OUTCOMES;o++) {
        uint32_t n=census_counts[e][s][a][k][o];
        if (!n) continue;
        if (tag) fprintf(stderr,"TRACE write_census tag=%s ",tag);
        else fprintf(stderr,"TRACE write_census ");
        fprintf(stderr,"entry=%s scope=%s active=%d kind=%s outcome=%s count=%u\n",
            census_entry_names[e],census_scope_names[s],a,census_kind_names[k],
            census_outcome_names[o],n);
    }
}

void recomp_write_census_clear(void) { memset(census_counts,0,sizeof census_counts); }

static void census_eip_dump(void);
static void census_dump_at_exit(void) { recomp_write_census_dump(NULL); census_eip_dump(); }

static void census_init(void) {
    const char *env;
    if (census_state) return;
    env=getenv("GWRECOMP_WRITE_CENSUS");
    census_state=(env && env[0]=='1')?2:1;
    if (census_state==2) atexit(census_dump_at_exit);
}

static void census_note(int entry,int outcome,int active,uint8_t access) {
    int kind=CENSUS_KIND_UNKNOWN;
    if (census_state!=2) return;
    if (active) kind=access<=RECOMP_MEM_ACCESS_READWRITE?(int)access:CENSUS_KIND_OTHER;
    census_counts[entry][census_scope_host][active!=0][kind][outcome]++;
}

/* Per-instruction attribution (same GWRECOMP_WRITE_CENSUS=1 gate). Keyed by
 * (instruction VA, entry, scope, announced kind, outcome) for the two outcomes
 * that reach the observer decision. Cumulative over the process: it is not
 * cleared by recomp_write_census_clear, so the exit dump covers every row. The
 * mnemonic is recorded only for announced guest accesses; generic segmented
 * addresses carry no mnemonic. Count-only; it never changes the result. */
#define CENSUS_EIP_SLOTS 65536u
#define CENSUS_EIP_MAX_PROBE 64u
#define CENSUS_EIP_DUMP_LIMIT 40000u
typedef struct {
    uint32_t eip, count;
    uint8_t used, entry, scope, kind, outcome;
    char mnemonic[16];
} census_eip_slot;
static census_eip_slot census_eip[CENSUS_EIP_SLOTS];
static uint32_t census_eip_overflow;

static void census_eip_note(uint32_t eip,int entry,int outcome,int active,uint8_t access,
                            const char *mnemonic) {
    uint32_t h,probe;
    int kind=CENSUS_KIND_UNKNOWN;
    if (census_state!=2) return;
    if (outcome!=CENSUS_CHECKED_NO_OBSERVER && outcome!=CENSUS_OBSERVED) return;
    if (active) kind=access<=RECOMP_MEM_ACCESS_READWRITE?(int)access:CENSUS_KIND_OTHER;
    h=(eip*2654435761u)^((uint32_t)entry<<20)^((uint32_t)census_scope_host<<19)^
      ((uint32_t)kind<<16)^((uint32_t)outcome<<12);
    /* Bounded probe: a full table must not make every lookup scan all slots. */
    for (probe=0;probe<CENSUS_EIP_MAX_PROBE;probe++) {
        census_eip_slot *s=&census_eip[(h+probe)&(CENSUS_EIP_SLOTS-1u)];
        if (!s->used) {
            s->used=1; s->eip=eip; s->count=1;
            s->entry=(uint8_t)entry; s->scope=(uint8_t)census_scope_host;
            s->kind=(uint8_t)kind; s->outcome=(uint8_t)outcome;
            if (mnemonic) strncpy(s->mnemonic,mnemonic,sizeof s->mnemonic-1u);
            return;
        }
        if (s->eip==eip && s->entry==entry && s->scope==census_scope_host &&
            s->kind==kind && s->outcome==outcome) {
            s->count++;
            return;
        }
    }
    census_eip_overflow++;
}

static int census_eip_order(const void *a,const void *b) {
    const census_eip_slot *x=*(census_eip_slot *const *)a;
    const census_eip_slot *y=*(census_eip_slot *const *)b;
    if (x->count!=y->count) return x->count<y->count?1:-1;
    return x->eip<y->eip?-1:(x->eip>y->eip);
}

/* Dumps the silent rows only (outcome checked_no_observer, the blind set), largest
 * first, so the dump is complete for the question asked. Observed rows are covered
 * by the exact bucket lines. The summary reports all distinct rows and overflow. */
static void census_eip_dump(void) {
    static census_eip_slot *order[CENSUS_EIP_SLOTS];
    uint32_t n=0,i,shown,distinct=0;
    if (census_state!=2) return;
    for (i=0;i<CENSUS_EIP_SLOTS;i++) {
        if (!census_eip[i].used) continue;
        distinct++;
        if (census_eip[i].outcome==CENSUS_CHECKED_NO_OBSERVER) order[n++]=&census_eip[i];
    }
    qsort(order,n,sizeof order[0],census_eip_order);
    shown=n<CENSUS_EIP_DUMP_LIMIT?n:CENSUS_EIP_DUMP_LIMIT;
    fprintf(stderr,"TRACE write_census_eip_summary distinct=%u silent=%u shown=%u overflow=%u\n",
            (unsigned)distinct,(unsigned)n,(unsigned)shown,(unsigned)census_eip_overflow);
    for (i=0;i<shown;i++) {
        const census_eip_slot *s=order[i];
        fprintf(stderr,"TRACE write_census_eip eip=%08x entry=%s scope=%s kind=%s outcome=%s count=%u mnemonic=%s\n",
            s->eip,census_entry_names[s->entry],census_scope_names[s->scope],
            census_kind_names[s->kind],census_outcome_names[s->outcome],s->count,
            s->mnemonic[0]?s->mnemonic:"-");
    }
}

void recomp_write_census_set_host_scope(int host) { census_scope_host=host!=0; }

uintptr_t recomp_checked_mem_addr(uint32_t segmented_linear, uint32_t width) {
    int census_entry=census_via_segment?CENSUS_ENTRY_SEG:CENSUS_ENTRY_MEM;
    census_init();
    /* Preserve the first-fault context. A lifted callee may continue executing
     * within the current C frame before control reaches its next guest hook;
     * in diagnostic mode, suppress subsequent dereferences instead of
     * replacing the instruction/register snapshot that caused the fault. */
    if (memory_diag_enabled && memory_fault.pending && width!=0u) {
        census_note(census_entry,CENSUS_FAULT_SUPPRESSED,access_active,access_kind);
        memset(fault_sink.bytes,0,sizeof fault_sink.bytes);
        return (uintptr_t)fault_sink.bytes;
    }
    /* ADDR() asks only for a translated pointer (width zero); it is not the
     * dereference and must not be reported as an access in diagnostic mode. */
    uint32_t candidate_eip=access_active?access_instruction_va:current_guest_eip;
    int diagnose=memory_diag_matches(candidate_eip);
    if (!access_active && (!diagnose || width==0u)) {
        census_note(census_entry,CENSUS_EARLY,0,0);
#ifdef RECOMP_FLAT_MEMORY
        return (uintptr_t)segmented_linear;
#else
        return (uintptr_t)segmented_linear+(uintptr_t)g_mem_base;
#endif
    }
    if (!width) width=access_width;
    recomp_segment_id segment=access_active?access_segment:(recomp_segment_id)current_instruction.segment;
    uint32_t instruction_va=access_active?access_instruction_va:current_instruction.instruction_va;
    if (diagnose && !access_active) {
        if (!current_instruction.valid || current_instruction.instruction_va!=current_guest_eip) {
            memset(&current_instruction,0,sizeof current_instruction);
            current_instruction.valid=1;
            current_instruction.instruction_va=current_guest_eip;
            current_instruction.segment=(uint8_t)segment;
        }
        instruction_va=current_guest_eip;
        snapshot_guest_registers();
    }
    uint8_t access=diagnose?current_instruction.access:RECOMP_MEM_ACCESS_UNKNOWN;
    uint16_t selector; uint32_t base; segment_state(segment,&selector,&base);
    uint32_t offset=segmented_linear-base;
    uint64_t end=(uint64_t)segmented_linear+(uint64_t)width;
    int valid=width!=0 && segmented_linear>=base && end<=0x100000000ull;
    if (access_active && selector==0) valid=0;
    if (valid && active_range_validator && !active_range_validator(selector,offset,width,active_range_user)) valid=0;
    if (valid && memory_size) {
        uint64_t region_end=(uint64_t)memory_begin+memory_size;
        if (segmented_linear<memory_begin || end>region_end) valid=0;
    }
    uintptr_t host_address;
#ifdef RECOMP_FLAT_MEMORY
    host_address=(uintptr_t)segmented_linear;
#else
    host_address=(uintptr_t)segmented_linear+(uintptr_t)g_mem_base;
#endif
    if (valid && memory_translator) {
        uintptr_t translated=memory_translator(segmented_linear,width,host_address,
                                               memory_translator_user);
        if (!translated) valid=0;
        else host_address=translated;
    }
    if (access_active) {
        note_null_ds_read(instruction_va,instruction_va,access_instruction_id,
            segment,selector,base,segmented_linear,offset,width,access_kind,
            access_mnemonic);
    }
    int backing=-1;
#ifdef RECOMP_TRACE_LOW_WRITES
    if (access_active && access_kind==RECOMP_MEM_ACCESS_WRITE && segmented_linear<0x100u) {
        fprintf(stderr,"TRACE guest-low-write eip=%08x id=%u seg=%u sel=%04x base=%08x linear=%08x width=%u regs=%08x/%08x/%08x/%08x/%08x/%08x/%08x/%08x\n",
                instruction_va,access_instruction_id,(unsigned)segment,selector,base,
                segmented_linear,width,g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp);
    }
#endif
    if (diagnose && memory_backing_validator) {
        backing=memory_backing_validator(host_address,segmented_linear,width,access,memory_backing_user);
        if (!backing) valid=0;
    }
    if (diagnose)
        remember_access(segment,selector,base,instruction_va,segmented_linear,width,access,host_address,backing);
    if (!valid) {
        census_note(census_entry,CENSUS_INVALID,access_active,access_kind);
        set_memory_fault(segment,selector,base,instruction_va,segmented_linear,width);
        memset(fault_sink.bytes,0,sizeof(fault_sink.bytes));
        return (uintptr_t)fault_sink.bytes;
    }
    int outcome=CENSUS_CHECKED_NO_OBSERVER;
    if (access_active &&
        (access_kind==RECOMP_MEM_ACCESS_WRITE || access_kind==RECOMP_MEM_ACCESS_READWRITE) &&
        guest_write_observer) {
        guest_write_observer(instruction_va,segment,selector,base,
                             segmented_linear,width,guest_write_observer_user);
        outcome=CENSUS_OBSERVED;
    }
    census_note(census_entry,outcome,access_active,access_kind);
    census_eip_note(instruction_va,census_entry,outcome,access_active,access_kind,
                    census_via_segment?NULL:access_mnemonic);
    return host_address;
}

void recomp_set_memory_translator(recomp_memory_translate_fn translate,void *user) {
    memory_translator=translate;
    memory_translator_user=user;
}

void recomp_set_guest_write_observer(recomp_guest_write_observer_fn observer,
                                     void *user) {
    guest_write_observer=observer;
    guest_write_observer_user=user;
}

uintptr_t recomp_checked_segment_addr(recomp_segment_id segment, uint32_t offset,
                                      uint64_t width, uint32_t instruction_va) {
    uint16_t selector=0; uint32_t base=0; segment_state(segment,&selector,&base);
    census_init();
    /* This generic segmented-address API does not know whether the generated
     * memory operand is a read or write. Do not inherit direction metadata
     * from the previous lifted instruction (for example SCASB's ES:EDI read). */
    access_segment=segment; access_instruction_va=instruction_va;
    access_width=width<=UINT32_MAX?(uint32_t)width:UINT32_MAX;
    access_instruction_id=0; access_kind=RECOMP_MEM_ACCESS_UNKNOWN; access_active=1;
    if (memory_diag_enabled) {
        current_instruction.valid=1; current_instruction.instruction_va=instruction_va;
        current_instruction.segment=(uint8_t)segment; current_instruction.selector=selector;
        current_instruction.segment_base=base; current_instruction.width=access_width;
        current_instruction.instruction_id=0; current_instruction.access=RECOMP_MEM_ACCESS_UNKNOWN;
        snapshot_guest_registers();
    }
    uint64_t linear=(uint64_t)base+(uint64_t)offset;
    if (width==0 || width>UINT32_MAX || linear>UINT32_MAX || memory_fault.pending) {
        census_note(CENSUS_ENTRY_SEG,CENSUS_SEG_REJECT,1,RECOMP_MEM_ACCESS_UNKNOWN);
        if (!memory_fault.pending) {
            set_memory_fault(segment,selector,base,instruction_va,(uint32_t)linear,access_width);
        }
        memset(fault_sink.bytes,0,sizeof(fault_sink.bytes)); access_active=0;
        return (uintptr_t)fault_sink.bytes;
    }
    census_via_segment=1;
    uintptr_t result=recomp_checked_mem_addr((uint32_t)linear,(uint32_t)width);
    census_via_segment=0;
    access_active=0; access_width=0;
    return result;
}

void recomp_set_segment_resolver(recomp_segment_resolver_fn resolver, void *user) {
    active_resolver = resolver;
    active_user = user;
}

void recomp_clear_segment_fault(void) {
    last_fault.pending = 0;
    last_fault.segment = 0;
    last_fault.selector = 0;
    last_fault.instruction_va = 0;
}

recomp_segment_fault recomp_get_segment_fault(void) { return last_fault; }

static uint16_t *selector_slot(recomp_segment_id segment) {
    switch (segment) {
    case RECOMP_SEG_CS: return &g_seg_cs;
    case RECOMP_SEG_DS: return &g_seg_ds;
    case RECOMP_SEG_ES: return &g_seg_es;
    case RECOMP_SEG_FS: return &g_seg_fs;
    case RECOMP_SEG_GS: return &g_seg_gs;
    case RECOMP_SEG_SS: return &g_seg_ss;
    default: return 0;
    }
}

static uint32_t *base_slot(recomp_segment_id segment) {
    switch (segment) {
    case RECOMP_SEG_CS: return &g_cs_base;
    case RECOMP_SEG_DS: return &g_ds_base;
    case RECOMP_SEG_ES: return &g_es_base;
    case RECOMP_SEG_FS: return &g_fs_base;
    case RECOMP_SEG_GS: return &g_gs_base;
    case RECOMP_SEG_SS: return &g_ss_base;
    default: return 0;
    }
}

int recomp_write_segment(recomp_segment_id segment, uint16_t selector, uint32_t instruction_va) {
    uint16_t *selector_out = selector_slot(segment);
    uint32_t *base_out = base_slot(segment);
    if (!selector_out || !base_out) return 0;
    uint32_t base = *base_out;
    if (active_resolver) {
        if (!active_resolver(selector, &base, active_user)) {
            last_fault.pending = 1;
            last_fault.segment = (uint8_t)segment;
            last_fault.selector = selector;
            last_fault.instruction_va = instruction_va;
            return 0;
        }
    } else if (selector != *selector_out) {
        base = 0; /* flat-host default until a descriptor resolver is installed */
    }
    *selector_out = selector;
    *base_out = base;
    recomp_clear_segment_fault();
    return 1;
}
