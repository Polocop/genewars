#include "recomp_context.h"
#include "gw_dos_services.h"
#include "gw_interrupts.h"
#include "gw_segments.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void gw_partial_LbMemorySetup(void);
void gw_partial_0x00092670(void);
int gw_partial_install_code_map(void);

uint32_t g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,g_cur_func;
uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_fs,g_seg_gs,g_seg_ss,g_fpu_cw;
uint32_t g_fs_base,g_gs_base;
ptrdiff_t g_mem_base;
double g_st[8]; int g_fp_top;
uint32_t g_flag_k,g_flag_a,g_flag_b,g_flag_cf;
uint32_t g_icall_trace[ICALL_TRACE_SIZE],g_icall_from[ICALL_TRACE_SIZE];
uint32_t g_icall_trace_idx,g_icall_count;

enum {
    GUEST_LIMIT=0x03002000u, /* smallest page-aligned flat map covering __brk's 0x03001000 request */
    STACK_TOP=0x003FF000u,
    BLOCKS=0x00360C40u, /* link 0x186C40 + verified object-3 delta */
    ARENAS=0x00361840u, /* link 0x187840 + verified object-3 delta */
    FLAT_HEAP_BEGIN=0x01000000u,
    MAX_ENTRIES=256u,
    BLOCK_SIZE=12u,
    ARENA_SIZE=18u
};

static unsigned comparator_calls;
static unsigned dos_ed_calls,dos_4a_calls,dos_4a_failures,dpmi_0501_calls,dpmi_0501_successes;
static gw_dos_services services;
static uint8_t *guest_memory;

/* The original Watcom int386x bridge returns into its authentic CD 31 C3
 * thunk at link VA 0xD23A7.  Dispatch only after the loaded 1.1 bytes prove
 * that exact INT 31h; RET sequence. */
static void original_int31_thunk(void) {
    if (gw_interrupt_dispatch(0x31u,0x000D23A7u)!=GW_INTERRUPT_HANDLED) return;
    /* The original bytes are INT 31h; RET.  The RET consumes the nested
     * lifted-call sentinel placed by RECOMP_CALL at the thunk boundary. */
    if (*(const uint32_t *)(guest_memory+g_esp)!=RECOMP_RETADDR) {
        fprintf(stderr,"INT31 thunk return mismatch esp=%08x value=%08x\n",
                g_esp,*(const uint32_t *)(guest_memory+g_esp));
        return;
    }
    g_esp+=4u;
}

recomp_func_t recomp_lookup(uint32_t va) {
    if (va==0x92670u) { ++comparator_calls; return gw_partial_0x00092670; }
    if ((va==0x002BD3A7u || va==0x000D23A7u) && guest_memory &&
        guest_memory[0x002BD3A7u]==0xCDu && guest_memory[0x002BD3A8u]==0x31u &&
        guest_memory[0x002BD3A9u]==0xC3u) return original_int31_thunk;
    return NULL;
}
recomp_func_t recomp_lookup_manual(uint32_t va) { return recomp_lookup(va); }
recomp_func_t recomp_lookup_import(uint32_t va) { (void)va; return NULL; }

static gw_interrupt_result dispatch(uint8_t vector,uint32_t instruction_va,void *user) {
    uint32_t request_eax=g_eax,request_ebx=g_ebx,request_ecx=g_ecx,request_edx=g_edx;
    gw_interrupt_result result=gw_dos_services_callback(vector,instruction_va,user);
    if (vector==0x21u && instruction_va==0x000D7144u) ++dos_ed_calls;
    if (vector==0x21u && (instruction_va==0x000D715Du || instruction_va==0x000D7170u)) {
        ++dos_4a_calls; if (g_flag_cf) ++dos_4a_failures;
    }
    if (vector==0x31u && (uint16_t)request_eax==0x0501u) {
        ++dpmi_0501_calls;
        if (result==GW_INTERRUPT_HANDLED && !g_flag_cf) ++dpmi_0501_successes;
    }
    return result;
}

static int load_guest_image(uint8_t *memory,const char *path,uint32_t guest_base) {
    FILE *file=fopen(path,"rb"); if (!file) return 0;
    if (fseek(file,0,SEEK_END)) { fclose(file); return 0; }
    long length=ftell(file); rewind(file);
    if (length<0 || guest_base+(uint64_t)length>GUEST_LIMIT ||
        fread(memory+guest_base,1,(size_t)length,file)!=(size_t)length) {
        fclose(file); return 0;
    }
    fclose(file); return 1;
}

static int test_arena_tables(const uint8_t *memory,unsigned *blocks_out,unsigned *arenas_out) {
    unsigned block_count=0,arena_count=0;
    for (unsigned i=0;i<MAX_ENTRIES;i++) {
        const uint8_t *b=memory+BLOCKS+i*BLOCK_SIZE;
        uint32_t ptr=*(const uint32_t *)(b+0), size=*(const uint32_t *)(b+8);
        if (!ptr && !size) continue;
        if (!ptr || !size || ptr>GUEST_LIMIT || size>GUEST_LIMIT-ptr) return 0;
        if (ptr<0x000A0000u && services.dos_block_count) {
            int in_dos_block=0;
            for (uint32_t d=0;d<services.dos_block_count;d++) {
                uint32_t begin=(uint32_t)services.dos_blocks[d].segment<<4;
                uint32_t end=begin+((uint32_t)services.dos_blocks[d].paragraphs<<4);
                if (ptr>=begin && ptr+size<=end) { in_dos_block=1; break; }
            }
            if (!in_dos_block) return 0;
        } else if (ptr<FLAT_HEAP_BEGIN) return 0;
        if (ptr<0x00382C50u && 0x001FB000u<ptr+size) return 0; /* LE code/data objects */
        if (ptr<0x00382C50u && 0x002DA000u<ptr+size) return 0;
        ++block_count;
    }
    for (unsigned i=0;i<MAX_ENTRIES;i++) {
        const uint8_t *a=memory+ARENAS+i*ARENA_SIZE;
        uint32_t ptr=*(const uint32_t *)(a+0), size=*(const uint32_t *)(a+4);
        uint32_t child=*(const uint32_t *)(a+8), parent=*(const uint32_t *)(a+12);
        if (!ptr && !size && !child && !parent && !a[16] && !a[17]) continue;
        if (!ptr || !size || ptr>GUEST_LIMIT || size>GUEST_LIMIT-ptr) return 0;
        uint32_t expected_parent=i ? ARENAS+(i-1)*ARENA_SIZE : 0;
        uint32_t expected_child=i+1<block_count ? ARENAS+(i+1)*ARENA_SIZE : 0;
        if (parent!=expected_parent || child!=expected_child || a[16]!=0 || a[17]!=(uint8_t)i) return 0;
        ++arena_count;
    }
    if (block_count!=arena_count || !block_count || block_count>MAX_ENTRIES) return 0;
    /* The original table is sorted by its comparator; independently reject any overlap. */
    for (unsigned i=0;i<MAX_ENTRIES;i++) {
        const uint8_t *a=memory+ARENAS+i*ARENA_SIZE;
        uint32_t ap=*(const uint32_t *)(a+0), as=*(const uint32_t *)(a+4);
        if (!ap || !as) continue;
        for (unsigned j=i+1;j<MAX_ENTRIES;j++) {
            const uint8_t *b=memory+ARENAS+j*ARENA_SIZE;
            uint32_t bp=*(const uint32_t *)(b+0), bs=*(const uint32_t *)(b+4);
            if (!bp || !bs) continue;
            if (ap<bp+bs && bp<ap+as) return 0;
        }
    }
    *blocks_out=block_count; *arenas_out=arena_count; return 1;
}

int main(int argc,char **argv) {
    if (argc!=3) return 2;
    char *end=NULL;
    unsigned long parsed_base=strtoul(argv[2],&end,0);
    if (!end || *end || parsed_base>GUEST_LIMIT) return 2;
    uint8_t *memory=(uint8_t *)calloc(GUEST_LIMIT,1u);
    if (!memory || !load_guest_image(memory,argv[1],(uint32_t)parsed_base)) { free(memory); return 3; }
    guest_memory=memory;
    if (!gw_partial_install_code_map()) { free(memory); return 4; }
    g_mem_base=(ptrdiff_t)(uintptr_t)memory;
    recomp_set_memory_bounds(0,GUEST_LIMIT);
    memset(&services,0,sizeof services);
    gw_dos_services_init(&services);
    if (!gw_dos_guest_memory_configure(&services,GUEST_LIMIT) ||
        !gw_dos_memory_allocator_configure(&services,0x0906u,0x1000u,0x0054u,0x0800u)) {
        free(memory); return 5;
    }
    if (!gw_dos4gw_flat_heap_configure(&services,0x0014u)) {
        free(memory); return 5;
    }
    gw_interrupt_set_callback(dispatch,&services);
    gw_recomp_context context; memset(&context,0,sizeof context);
    context.esp=STACK_TOP; context.eip=0x921F0u; context.cur_func=0x921F0u;
    context.cs=0x0Cu; context.ds=0x14u; context.es=0x14u; context.ss=0x14u;
    context.mem_base=(ptrdiff_t)(uintptr_t)memory; context.mem_guest_base=0; context.mem_size=GUEST_LIMIT;
    context.pit_initialized=1; context.fpu_cw=0x127Fu;
    *(uint32_t *)(memory+STACK_TOP)=RECOMP_RETADDR;
    if (gw_recomp_invoke(gw_partial_LbMemorySetup,&context)!=GW_RECOMP_OK ||
        context.interrupt_trap_pending || context.memory_fault.pending ||
        context.segment_fault_pending || context.port_io_trap.pending || context.eax!=1u) {
        gw_interrupt_trap trap=gw_interrupt_get_trap();
        fprintf(stderr,"original LbMemorySetup_ failed eax=%08x eip=%08x int=%u/%u vec=%02x trapva=%08x fn=%08x mem=%u/%08x seg=%u/%04x\n",
                context.eax,context.eip,context.interrupt_trap_pending,context.interrupt_instruction_va,
                trap.vector,trap.instruction_va,trap.guest_function_va,
                context.memory_fault.pending,context.memory_fault.linear,
                context.segment_fault_pending,context.segment_fault_selector);
        gw_dos_descriptor_clear(&services); free(memory); return 7;
    }
    unsigned block_count=0,arena_count=0;
    if (!test_arena_tables(memory,&block_count,&arena_count) || comparator_calls==0u) {
        fprintf(stderr,"original heap tables invalid blocks=%u arenas=%u comparator_calls=%u\n",
                block_count,arena_count,comparator_calls);
        for (unsigned i=0;i<4;i++)
            fprintf(stderr,"entry%u block=%08x/%08x arena=%08x/%08x child=%08x parent=%08x used=%u id=%u\n",
                    i,*(uint32_t *)(memory+BLOCKS+i*BLOCK_SIZE),*(uint32_t *)(memory+BLOCKS+i*BLOCK_SIZE+8),
                    *(uint32_t *)(memory+ARENAS+i*ARENA_SIZE),*(uint32_t *)(memory+ARENAS+i*ARENA_SIZE+4),
                    *(uint32_t *)(memory+ARENAS+i*ARENA_SIZE+8),*(uint32_t *)(memory+ARENAS+i*ARENA_SIZE+12),
                    memory[ARENAS+i*ARENA_SIZE+16],memory[ARENAS+i*ARENA_SIZE+17]);
        fprintf(stderr,"service_counts ah_ed=%u ah4a=%u ah4a_fail=%u dpmi0501=%u/%u cursor=%08x end=%08x\n",
                dos_ed_calls,dos_4a_calls,dos_4a_failures,dpmi_0501_successes,dpmi_0501_calls,
                services.allocation_cursor,services.allocation_end);
        gw_dos_descriptor_clear(&services); free(memory); return 8;
    }
    printf("MEMORY_SETUP_RESULT result=%u block_count=%u arena_count=%u comparator_calls=%u guest_limit=%08x flat_heap_begin=%08x ah_ed=%u ah4a=%u ah4a_fail=%u dpmi0501=%u dos_blocks=%u\n",
           context.eax,block_count,arena_count,comparator_calls,GUEST_LIMIT,FLAT_HEAP_BEGIN,
           dos_ed_calls,dos_4a_calls,dos_4a_failures,dpmi_0501_calls,services.dos_block_count);
    gw_dos_descriptor_clear(&services); gw_interrupt_set_callback(NULL,NULL); free(memory);
    return 0;
}
