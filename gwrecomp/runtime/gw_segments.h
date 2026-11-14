#ifndef GW_SEGMENTS_H
#define GW_SEGMENTS_H
#include <stdint.h>
#include "../third_party/pcrecomp/runtime/recomp32/recomp_types.h"

/* State behind the inline hooks of generated code (gw_fast_hooks.h); owned by gw_segments.c. */
typedef struct gw_recomp_access_state {
    uint32_t instruction_va, width, instruction_id;
    recomp_segment_id segment;
    uint8_t kind;
    int active;
    const char *mnemonic;   /* a string literal of the generated code, never copied */
} gw_recomp_access_state;
extern gw_recomp_access_state g_recomp_access;
extern recomp_memory_fault g_recomp_memory_fault;
extern int g_recomp_memory_diag_on;
typedef struct gw_recomp_seg_window {
    uint32_t gen;
    uint16_t selector;
    uint32_t base;
    uint32_t lo;
    uint64_t hi;
} gw_recomp_seg_window;
extern gw_recomp_seg_window g_recomp_seg_windows[8];
extern uint32_t g_recomp_seg_window_gen;
extern int g_recomp_fastmem_ok;
/* Companion of a segment range validator: for a selector the validator would judge, store in *end_offset
   the exclusive end E such that validator(selector,offset,width) == (width!=0 && offset+width <= E) for
   every offset and width, and return 1; return 0 when no such E describes the selector. Registered after
   the validator it describes (recomp_set_segment_range_validator clears it). */
typedef int (*recomp_segment_limit_fn)(uint16_t selector, uint64_t *end_offset, void *user);
void recomp_set_segment_limit_query(recomp_segment_limit_fn query, void *user);
/* Called whenever state a validator or its limit query reads changes (descriptor tables, DOS blocks). */
void recomp_segment_windows_invalidate(void);

/* Optional guest-physical aperture translation (for banked VGA/VBE windows).
 * Return the host backing for this one guest access, or 0 to reject it. */
typedef uintptr_t (*recomp_memory_translate_fn)(uint32_t guest_linear,
                                               uint32_t width,
                                               uintptr_t default_host,
                                               void *user);
void recomp_set_memory_translator(recomp_memory_translate_fn translate,
                                  void *user);

/* Optional write observer for narrow replay diagnostics. Called only after
 * segment, backing, and translation checks have accepted an instrumented
 * guest write. The callback runs immediately before the generated store. */
typedef void (*recomp_guest_write_observer_fn)(uint32_t instruction_va,
                                               recomp_segment_id segment,
                                               uint16_t selector,
                                               uint32_t segment_base,
                                               uint32_t guest_linear,
                                               uint32_t width,
                                               void *user);
void recomp_set_guest_write_observer(recomp_guest_write_observer_fn observer,
                                     void *user);
/* Opt-in write-path census (GWRECOMP_WRITE_CENSUS=1). Host services set the
 * scope around guest-buffer accesses so the census can separate them from
 * translated code. Has no effect on the guest address check. */
void recomp_write_census_set_host_scope(int host);
void recomp_write_census_dump(const char *tag);
void recomp_write_census_clear(void);

/* Opt-in diagnostic for DS=14h reads in linear 00000000h..00000FFFh,
 * excluding the BIOS tick-counter bytes 0000046Ch..0000046Dh. */
typedef struct recomp_null_ds_read_diagnostic {
    uint32_t count;
    uint32_t guest_eip;
    uint32_t instruction_va;
    uint32_t instruction_id;
    uint32_t linear;
    uint32_t offset;
    uint32_t width;
    uint32_t eax,ebx,ecx,edx,esi,edi,ebp,esp;
    uint16_t selector;
    uint32_t segment_base;
    uint8_t access;
    char mnemonic[16];
} recomp_null_ds_read_diagnostic;
void recomp_null_ds_read_diag_enable(int enabled);
uint32_t recomp_null_ds_read_diag_count(void);
recomp_null_ds_read_diagnostic recomp_null_ds_read_diag_last(void);

/* Runtime bound for byte-table reads admitted by a hash-bound partial lift.
 * The divisor/base must be nonzero and no larger than the original table;
 * index must be inside that table. On violation, record a guest memory fault
 * at the original instruction and return false before the host dereference. */
int recomp_check_indexed_table_access(recomp_segment_id segment,
                                      uint32_t table_offset,
                                      uint32_t index,
                                      uint32_t table_count,
                                      uint32_t divisor,
                                      uint32_t width,
                                      uint32_t instruction_va);

/* Verified LE executable ranges used to translate rebased guest function
 * pointers back to the link-space keys in the generated dispatcher. */
typedef struct recomp_code_range {
    uint32_t guest_linear_base;
    uint32_t link_base;
    uint32_t size;
} recomp_code_range;
int recomp_code_map_set(const recomp_code_range *ranges, uint32_t count);
int recomp_code_linear_to_link(uint32_t guest_linear, uint32_t *link_va);

#endif
