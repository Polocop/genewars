#include "recomp_context.h"
#include "guest_boot_context.h"
#include "gw_interrupts.h"
#include "gw_dos_services.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "native_lift_boot_seed.h"

void gw_entry_start(void);
uint32_t g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,g_cur_func;
uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_fs,g_seg_gs,g_seg_ss,g_fpu_cw;
uint32_t g_fs_base,g_gs_base;
uint32_t g_icall_trace[ICALL_TRACE_SIZE], g_icall_from[ICALL_TRACE_SIZE];
uint32_t g_icall_trace_idx, g_icall_count;
ptrdiff_t g_mem_base;
double g_st[8]; int g_fp_top;
#if defined(GW_NATIVE_W1_092_HOST_BACKED_GUEST_MEMORY)
static uint8_t *guest_memory;
static uint32_t guest_memory_capacity;
static uint32_t native_dpmi_dos_memory_count,native_dpmi_dos_alloc_count,native_dpmi_dos_free_count;
static uint32_t native_dpmi_dos_last_req_eax,native_dpmi_dos_last_req_ebx,native_dpmi_dos_last_req_edx;
static uint32_t native_dpmi_dos_last_res_eax,native_dpmi_dos_last_res_ebx,native_dpmi_dos_last_res_edx;
static uint32_t native_dpmi_dos_last_carry;
static int native_guest_committed_word(uint32_t address,uint32_t *value) {
    MEMORY_BASIC_INFORMATION info;
    if (!guest_memory || !value || (uint64_t)address+sizeof *value>guest_memory_capacity ||
        VirtualQuery(guest_memory+address,&info,sizeof info)!=sizeof info ||
        info.State!=MEM_COMMIT) return 0;
    memcpy(value,guest_memory+address,sizeof *value);
    return 1;
}
int gw_native_w1_093_repeat_guard(unsigned int guest_va) {
    typedef struct repeat_key {
        uint32_t cur_func,eax,ebx,ecx,edx,esi,edi,ebp,esp;
        uint32_t cs_base,ds_base,es_base,ss_base,flag_k,flag_a,flag_b,flag_cf;
        uint16_t cs,ds,es,ss;
    } repeat_key;
    /* Keep exact states in an open-addressed table so the guard remains
     * cheap while walking the allocator's many real 4 KiB heap blocks. The
     * hard cap is 32768 distinct states; the former linear scan/cap stopped
     * partway through the naturally linked DPMI heaps. */
    static repeat_key seen_states[32768];
    static uint32_t seen_slots[65536];
    static uint32_t seen_count;
    static uint32_t last_guest_va;
    static uint8_t watched[0x30];
    static int watch_armed;
    /* Sample only the small DOS heap boundary window once the original
     * allocator path starts. Comparing at adjacent instruction callbacks
     * attributes each change to the preceding guest instruction. */
    if (!watch_armed && (guest_va==0x000921F0u || guest_va==0x000AE078u)) {
        memcpy(watched,guest_memory+0x0000EFF0u,sizeof watched);
        watch_armed=1;
        printf("NATIVE_W1_093_HEAP_WINDOW_ARM eip=%08x ds=%04x ds_base=%08x cs=%04x cs_base=%08x ss=%04x ss_base=%08x linear=0000eff0 bytes=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
            guest_va,g_seg_ds,g_ds_base,g_seg_cs,g_cs_base,g_seg_ss,g_ss_base,
            watched[0],watched[1],watched[2],watched[3],watched[4],watched[5],
            watched[6],watched[7],watched[8],watched[9],watched[10],watched[11]);
    } else if (watch_armed) {
        uint8_t current_window[sizeof watched];
        memcpy(current_window,guest_memory+0x0000EFF0u,sizeof current_window);
        if (memcmp(current_window,watched,sizeof watched)!=0) {
            printf("NATIVE_W1_093_HEAP_WINDOW_WRITE writer_eip=%08x next_eip=%08x ds=%04x ds_base=%08x cs=%04x cs_base=%08x ebx=%08x edi=%08x esp=%08x before=",
                last_guest_va,guest_va,g_seg_ds,g_ds_base,g_seg_cs,g_cs_base,g_ebx,g_edi,g_esp);
            for (unsigned i=0;i<sizeof watched;++i) printf("%02x",watched[i]);
            printf(" after=");
            for (unsigned i=0;i<sizeof current_window;++i) printf("%02x",current_window[i]);
            putchar('\n'); fflush(stdout);
            memcpy(watched,current_window,sizeof watched);
        }
    }
    last_guest_va=guest_va;
    if (guest_va!=0x000AE137u) return 0;
    repeat_key current={0};
    current.cur_func=g_cur_func; current.eax=g_eax; current.ebx=g_ebx;
    current.ecx=g_ecx; current.edx=g_edx; current.esi=g_esi;
    current.edi=g_edi; current.ebp=g_ebp; current.esp=g_esp;
    current.cs_base=g_cs_base; current.ds_base=g_ds_base;
    current.es_base=g_es_base; current.ss_base=g_ss_base;
    current.flag_k=g_flag_k; current.flag_a=g_flag_a;
    current.flag_b=g_flag_b; current.flag_cf=g_flag_cf;
    current.cs=g_seg_cs; current.ds=g_seg_ds; current.es=g_seg_es; current.ss=g_seg_ss;
    uint32_t hash=2166136261u;
    const uint8_t *key_bytes=(const uint8_t *)&current;
    for (size_t i=0;i<sizeof current;++i) hash=(hash^key_bytes[i])*16777619u;
    uint32_t repeat_index=UINT32_MAX;
    uint32_t slot=hash&65535u;
    for (uint32_t probes=0;probes<65536u;++probes) {
        uint32_t entry=seen_slots[slot];
        if (!entry) {
            if (seen_count<sizeof seen_states/sizeof seen_states[0]) {
                seen_states[seen_count]=current;
                seen_slots[slot]=seen_count+1u;
                ++seen_count;
            } else repeat_index=seen_count;
            break;
        }
        uint32_t prior_index=entry-1u;
        if (memcmp(&current,&seen_states[prior_index],sizeof current)==0) {
            repeat_index=prior_index;
            break;
        }
        slot=(slot+1u)&65535u;
    }
    uint32_t header=0,at_end=0,end_mcb=0,esi_next=0;
    int header_valid=native_guest_committed_word(g_ebx,&header);
    int end_valid=native_guest_committed_word(g_edi,&at_end);
    int mcb_valid=g_edi>=4u && native_guest_committed_word(g_edi-4u,&end_mcb);
    int next_valid=native_guest_committed_word(g_esi+8u,&esi_next);
    if (repeat_index==UINT32_MAX) return 0;
    printf("NATIVE_W1_093_REPEAT_GUARD stop=%s eip=%08x state_index=%u states_seen=%u function=%08x eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x esi_next=%08x next_valid=%u edi=%08x header=%08x header_valid=%u edi_minus4=%08x mcb_valid=%u edi_word=%08x end_valid=%u ebp=%08x esp=%08x cs=%04x cs_base=%08x ds=%04x ds_base=%08x es=%04x es_base=%08x ss=%04x ss_base=%08x flags=%08x/%08x/%08x cf=%u\n",
        repeat_index<seen_count?"identical_state_repeated":"state_budget",
        guest_va,repeat_index,seen_count,g_cur_func,g_eax,g_ebx,g_ecx,g_edx,g_esi,esi_next,(unsigned)next_valid,
        g_edi,header,(unsigned)header_valid,end_mcb,(unsigned)mcb_valid,at_end,(unsigned)end_valid,
        g_ebp,g_esp,g_seg_cs,g_cs_base,g_seg_ds,g_ds_base,g_seg_es,g_es_base,g_seg_ss,g_ss_base,
        g_flag_k,g_flag_a,g_flag_b,g_flag_cf);
    fflush(stdout);
    return 1;
}
void gw_native_w1_092_instruction_observer(uint64_t count,
                                           unsigned int guest_va) {
    printf("NATIVE_W1_092_PROGRESS guest_instructions=%llu eip=%08x function=%08x eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x ebp=%08x esp=%08x flags=%08x/%08x/%08x cf=%u\n",
        (unsigned long long)count,guest_va,g_cur_func,g_eax,g_ebx,g_ecx,g_edx,
        g_esi,g_edi,g_ebp,g_esp,g_flag_k,g_flag_a,g_flag_b,g_flag_cf);
    if (guest_va>=0x000AE0B0u && guest_va<=0x000AE23Eu) {
        uint32_t root=0,node=0,next=0,tail=0,count_nodes=0,cycle_at=UINT32_MAX;
        uint32_t block_size=0,block0=0,block1=0,block2=0,block3=0;
        uint32_t edx0=0,edx1=0,edx2=0,edx3=0,esi0=0,esi1=0,esi2=0,esi3=0;
        uint32_t seen[1024];
        const char *stop="null";
        native_guest_committed_word(g_ebx,&block_size);
        native_guest_committed_word(g_edi,&block0);
        native_guest_committed_word(g_edi+4u,&block1);
        native_guest_committed_word(g_edi+8u,&block2);
        native_guest_committed_word(g_edi+12u,&block3);
        native_guest_committed_word(g_edx,&edx0);
        native_guest_committed_word(g_edx+4u,&edx1);
        native_guest_committed_word(g_edx+8u,&edx2);
        native_guest_committed_word(g_edx+12u,&edx3);
        native_guest_committed_word(g_esi,&esi0);
        native_guest_committed_word(g_esi+4u,&esi1);
        native_guest_committed_word(g_esi+8u,&esi2);
        native_guest_committed_word(g_esi+12u,&esi3);
        if (!native_guest_committed_word(0x0010B4D0u,&root)) stop="head_uncommitted";
        node=root;
        while (node && count_nodes<1024u) {
            if (!native_guest_committed_word(node+8u,&next)) { stop="node_uncommitted"; break; }
            for (uint32_t i=0;i<count_nodes;i++) if (seen[i]==node) { cycle_at=i; stop="cycle"; break; }
            if (cycle_at!=UINT32_MAX) break;
            seen[count_nodes++]=node; tail=node;
            node=next;
        }
        if (node && count_nodes==1024u && cycle_at==UINT32_MAX) stop="over_1024_nodes";
        printf("NATIVE_W1_092_HEAP_LIST root=%08x nodes=%u tail=%08x next=%08x stop=%s cycle_at=%u\n",
            root,count_nodes,tail,next,stop,cycle_at);
        printf("NATIVE_W1_093_BLOCK_SNAPSHOT eip=%08x ebx=%08x header=%08x edi=%08x words=%08x/%08x/%08x/%08x edx=%08x words=%08x/%08x/%08x/%08x esi=%08x words=%08x/%08x/%08x/%08x\n",
            guest_va,g_ebx,block_size,g_edi,block0,block1,block2,block3,
            g_edx,edx0,edx1,edx2,edx3,g_esi,esi0,esi1,esi2,esi3);
    }
    fflush(stdout);
}
#endif
recomp_func_t recomp_lookup_manual(uint32_t va);
recomp_func_t recomp_lookup_import(uint32_t va) { (void)va; return NULL; }

#if defined(GW_NATIVE_W1_092_HOST_BACKED_GUEST_MEMORY)
/* Reserve one contiguous guest linear range in this process and commit the
 * image plus each successful AX=0501 block on demand. The reservation ends at
 * the largest free 32-bit process range Windows can provide; physical backing
 * is granted only when VirtualAlloc(MEM_COMMIT) succeeds. */
#define GW_NATIVE_GUEST_MEMORY_SIZE guest_memory_capacity
#define GW_NATIVE_DPMI_ARENA_LABEL "host_backed_demand_commit"
#elif defined(GW_NATIVE_W1_091_HOST_BACKED_GUEST_MEMORY)
/* One-run host-backed guest linear map. The bound is derived from the
 * authenticated image extent, the observed 0x209000 cursor, and natural
 * request sizes; it is released with this harness process. */
static uint8_t guest_memory[0x0220B000u];
#define GW_NATIVE_GUEST_MEMORY_SIZE sizeof guest_memory
#define GW_NATIVE_DPMI_ARENA_LABEL "host_backed"
#elif defined(GW_NATIVE_CONTINUE_DPMI_LINEAR_SUCCESS)
/* Legacy bounded synthetic arena retained for its existing isolated mode. */
static uint8_t guest_memory[0x400000];
#define GW_NATIVE_GUEST_MEMORY_SIZE sizeof guest_memory
#define GW_NATIVE_DPMI_ARENA_LABEL "synthetic"
#else
static uint8_t guest_memory[0x200000];
#define GW_NATIVE_GUEST_MEMORY_SIZE sizeof guest_memory
#define GW_NATIVE_DPMI_ARENA_LABEL "synthetic"
#endif

/* The LE image stores INT vector stubs as guest bytes. FUN_000D226E RETs into
 * the INT 31h entry at 0xD23A7; the lifted dynamic RET dispatches that verified
 * thunk here. The actual request still goes through the configured provider. */
static void native_dpmi_int31_stub(void) {
    const uint32_t va=0x000D23A7u;
    if (!gw_recomp_guest_instruction(va)) return;
    uint32_t req_eax=g_eax,req_ebx=g_ebx,req_ecx=g_ecx;
    uint32_t req_edx=g_edx,req_esi=g_esi,req_edi=g_edi;
    static uint32_t linear_lock_ordinal;
    gw_interrupt_result result=gw_interrupt_dispatch(0x31u,va);
    if ((uint16_t)req_eax==0x0600u || (uint16_t)req_eax==0x0601u) {
        uint32_t ordinal=++linear_lock_ordinal;
        if (ordinal<=16u) {
            printf("NATIVE_DPMI_LINEAR_LOCK ordinal=%u function=%04x request_eax=%08x request_ebx=%08x request_ecx=%08x request_edx=%08x request_esi=%08x request_edi=%08x response_eax=%08x response_ebx=%08x response_ecx=%08x response_edx=%08x response_esi=%08x response_edi=%08x cf=%u handled=%u cs=%04x cs_base=%08x ds=%04x ds_base=%08x ss=%04x ss_base=%08x\n",
                ordinal,(unsigned)(uint16_t)req_eax,req_eax,req_ebx,req_ecx,req_edx,req_esi,req_edi,
                g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,(unsigned)g_flag_cf,
                (unsigned)(result==GW_INTERRUPT_HANDLED),g_seg_cs,g_cs_base,g_seg_ds,g_ds_base,g_seg_ss,g_ss_base);
            fflush(stdout);
        }
    }
    if (result==GW_INTERRUPT_HANDLED)
        g_esp+=4u; /* execute the thunk's following RET to its translated caller */
}
recomp_func_t recomp_lookup_manual(uint32_t va) {
    if (va!=0x000D23A7u || !guest_memory ||
        (uint64_t)va+2u>GW_NATIVE_GUEST_MEMORY_SIZE ||
        guest_memory[va]!=0xCDu || guest_memory[va+1u]!=0x31u ||
        guest_memory[va+2u]!=0xC3u) return NULL;
    return native_dpmi_int31_stub;
}

#if defined(GW_NATIVE_W1_092_HOST_BACKED_GUEST_MEMORY)
/* Seed the conventional DOS MCB chain for this LE-entry boot fixture. The
 * Python DosHost post-DOS/4GW profile derives these exact spans from PSP,
 * environment and the 0xA000 conventional-memory ceiling. */
static int native_seed_post_dos4gw_mcb(void) {
    uint32_t psp=(uint32_t)(GW_BOOT_PSP>>4);
    uint32_t env=GW_BOOT_ENV_SEG;
    uint32_t env_bytes=GW_BOOT_ENV_LIMIT+1u;
    uint32_t psp_mcb=psp-1u;
    uint32_t psp_paragraphs=env-1u-psp;
    uint32_t env_paragraphs=(env_bytes+15u)/16u;
    if (!env_paragraphs) env_paragraphs=1u;
    uint32_t free_mcb=env+env_paragraphs;
    /* The native fixed-link guest image occupies the same flat address map as
     * conventional DOS memory. Keep the MCB provider below the first image
     * paragraph so an AH=48 result can never alias and overwrite lifted code
     * or image data. The normal DOS ceiling is retained in the seed header;
     * this cap is a property of this guest address-space layout. */
    uint32_t top=GW_BOOT_DOS_ALLOCATOR_END_SEGMENT;
    if (top>GW_BOOT_IMAGE_BEGIN_SEGMENT) top=GW_BOOT_IMAGE_BEGIN_SEGMENT;
    if (psp<1u || env<=psp+1u || psp_paragraphs<0x10u ||
        env_bytes==0u || free_mcb>=top || top-free_mcb<=1u ||
        (free_mcb<<4)+16u>GW_NATIVE_GUEST_MEMORY_SIZE ||
        ((uint64_t)top<<4)>GW_NATIVE_GUEST_MEMORY_SIZE ||
        free_mcb+1u!=GW_BOOT_DOS_ALLOCATOR_BEGIN_SEGMENT) return 0;
    uint16_t psp_end=(uint16_t)(psp+psp_paragraphs);
    memcpy(guest_memory+GW_BOOT_PSP+2u,&psp_end,sizeof psp_end);
    uint8_t *mcb=guest_memory+(psp_mcb<<4);
    memset(mcb,0,16u); mcb[0]='M'; memcpy(mcb+1,&(uint16_t){(uint16_t)psp},2);
    memcpy(mcb+3,&(uint16_t){(uint16_t)psp_paragraphs},2);
    mcb=guest_memory+((env-1u)<<4);
    memset(mcb,0,16u); mcb[0]='M'; memcpy(mcb+1,&(uint16_t){(uint16_t)psp},2);
    memcpy(mcb+3,&(uint16_t){(uint16_t)env_paragraphs},2);
    mcb=guest_memory+(free_mcb<<4);
    uint16_t free_paragraphs=(uint16_t)(top-free_mcb-1u);
    memset(mcb,0,16u); mcb[0]='Z';
    memcpy(mcb+3,&free_paragraphs,2);
    printf("NATIVE_DOS_MCB_SEED profile=post_dos4gw_flat_link_safe psp=%04x psp_mcb=%04x psp_paragraphs=%04x env=%04x env_paragraphs=%04x free_mcb=%04x free_data=%04x free_paragraphs=%04x top=%04x provider=guest_memory\n",
        (unsigned)psp,(unsigned)psp_mcb,(unsigned)psp_paragraphs,(unsigned)env,
        (unsigned)env_paragraphs,(unsigned)free_mcb,(unsigned)(free_mcb+1u),
        (unsigned)free_paragraphs,(unsigned)top);
    return 1;
}
#endif
#if defined(GW_NATIVE_W1_092_HOST_BACKED_GUEST_MEMORY)
static int native_guest_memory_reserve(void) {
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    uintptr_t min=(uintptr_t)info.lpMinimumApplicationAddress;
    uintptr_t max=(uintptr_t)info.lpMaximumApplicationAddress;
    uint64_t available=max>min?(uint64_t)(max-min):0;
    #if defined(_WIN64)
    /* A 64-bit host can reserve almost the complete 32-bit guest linear space. */
    uint32_t candidate=(uint32_t)(UINT32_MAX & ~0xffffu);
#else
    uint32_t candidate=0x7f000000u;
#endif
    if (available<candidate) candidate=(uint32_t)available;
    candidate &= ~0xffffu;
    while (candidate>=0x10000000u) {
        uint8_t *map=(uint8_t *)VirtualAlloc(NULL,candidate,MEM_RESERVE,PAGE_READWRITE);
        if (map) {
            fprintf(stderr,"NATIVE_GUEST_RESERVE reserved capacity=%08x base=%p\n",candidate,(void *)map);
            const uint32_t boot_commit_size=0x00400000u; /* includes the highest observed pre-DPMI guest access at 0x00300000 */
            void *committed=VirtualAlloc(map,boot_commit_size,MEM_COMMIT,PAGE_READWRITE);
            fprintf(stderr,"NATIVE_GUEST_RESERVE boot_commit size=%08x result=%p error=%lu\n",boot_commit_size,committed,(unsigned long)GetLastError());
            if ((uintptr_t)committed==(uintptr_t)map) {
                guest_memory=map;
                guest_memory_capacity=candidate;
                return 1;
            }
            fprintf(stderr,"NATIVE_GUEST_RESERVE commit_failed capacity=%08x error=%lu\n",candidate,(unsigned long)GetLastError());
            VirtualFree(map,0,MEM_RELEASE);
        } else {
            fprintf(stderr,"NATIVE_GUEST_RESERVE reserve_failed capacity=%08x error=%lu\n",candidate,(unsigned long)GetLastError());
        }
        if (candidate<0x04000000u) break;
        candidate-=0x04000000u;
    }
    return 0;
}
static int native_guest_memory_prepare(void *user,uint32_t linear,uint32_t size) {
    uint8_t *map=(uint8_t *)user;
    if (!map || !size || (uint64_t)linear+size>guest_memory_capacity) return 0;
    uint32_t begin=linear&~0xfffu;
    uint64_t end=((uint64_t)linear+size+0xfffu)&~0xfffull;
    if (end>guest_memory_capacity || end-begin>UINT32_MAX) return 0;
    return VirtualAlloc(map+begin,(SIZE_T)(end-begin),MEM_COMMIT,PAGE_READWRITE)==map+begin;
}
static int native_guest_memory_backed(uintptr_t host,uint32_t linear,uint32_t width,
                                     uint8_t access,void *user) {
    uintptr_t map=(uintptr_t)user, end;
    if (!map || !width || linear>guest_memory_capacity ||
        width>guest_memory_capacity-linear || host!=map+(uintptr_t)linear ||
        host>UINTPTR_MAX-width) return 0;
    end=host+width;
    for (uintptr_t at=host;at<end;) {
        MEMORY_BASIC_INFORMATION info;
        if (VirtualQuery((const void *)at,&info,sizeof info)!=sizeof info ||
            info.State!=MEM_COMMIT || (info.Protect&(PAGE_GUARD|PAGE_NOACCESS))) return 0;
        DWORD protection=info.Protect&0xffu;
        if (access==RECOMP_MEM_ACCESS_WRITE || access==RECOMP_MEM_ACCESS_READWRITE) {
            if (protection==PAGE_READONLY || protection==PAGE_EXECUTE ||
                protection==PAGE_EXECUTE_READ) return 0;
        }
        uintptr_t region_end=(uintptr_t)info.BaseAddress+(uintptr_t)info.RegionSize;
        if (region_end<=at) return 0;
        at=region_end<end?region_end:end;
    }
    return 1;
}
static int native_guest_memory_zero_sample(uint32_t linear,uint32_t size) {
    if (!guest_memory || !size || (uint64_t)linear+size>guest_memory_capacity) return 0;
    /* VirtualAlloc guarantees zero contents for newly committed pages. Check
     * both range boundaries without reading every page, which would fault in
     * and retain gigabytes of otherwise demand-zero guest memory. */
    return guest_memory[linear]==0 && guest_memory[linear+size-1u]==0;
}
#endif
#ifdef GW_NATIVE_CAPTURE_CRT_STARTUP
static uint32_t w1_crt_dynamic_ordinal;
static uint32_t w1_setup_event_ordinal;
static uint32_t w1_crt_ax4400_ordinal;
static uint32_t w1_ah44_callsite_ordinal;
static uint32_t w1_ah44_helper_entry_ordinal;
static uint32_t w1_ah44_request_ordinal;
static uint32_t w1_ah44_bx1_sample_count;
#ifdef GW_NATIVE_CAPTURE_ALLOC_CHAIN
static uint32_t w1_alloc_chain_ordinal;
void gw_native_capture_alloc_callsite(uint32_t caller, uint32_t target, uint32_t site) {
    static uint32_t native_nmalloc_callsites;
    if (target==0x000ADF95u) { if (native_nmalloc_callsites++>=32u) return; }
    else if (!((site==0x000DFE0Du && target==0x000ADF95u) ||
          (site==0x000AE038u && target==0x000C3E2Au) ||
          (site==0x000AE287u && target==0x000C3E2Au) ||
          (site==0x000C3E54u && target==0x000C3D7Au) ||
          (site==0x000C3D98u && target==0x000C3F76u) ||
          (site==0x000C3DB0u && target==0x000C3CA9u))) return;
    uint32_t stack[8]={0};
    uint32_t valid=(g_esp<=GW_NATIVE_GUEST_MEMORY_SIZE-sizeof stack);
    if (valid) memcpy(stack,guest_memory+g_esp,sizeof stack);
    printf("NATIVE_ALLOC_CALLSITE ordinal=%u caller=%08x target=%08x site=%08x cs=%04x eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x ebp=%08x esp=%08x flags_k=%u flags_a=%08x flags_b=%08x cf=%u ds=%04x es=%04x ss=%04x valid=%u",
           w1_alloc_chain_ordinal++,caller,target,site,g_seg_cs,g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,
           g_flag_k,g_flag_a,g_flag_b,g_flag_cf,g_seg_ds,g_seg_es,g_seg_ss,valid);
    for (uint32_t i=0;i<8u;++i) printf(" stack%u=%08x",i,stack[i]);
    printf("\n");
}
void gw_native_capture_alloc_block(uint32_t site) {
    if (site!=0x000DFE04u && site!=0x000DFE08u) return;
    uint32_t stack[4]={0};
    uint32_t valid=(g_esp<=GW_NATIVE_GUEST_MEMORY_SIZE-sizeof stack);
    if (valid) memcpy(stack,guest_memory+g_esp,sizeof stack);
    printf("NATIVE_ADF95_BRANCH site=%08x caller_func=%08x cs=%04x eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x ebp=%08x esp=%08x flags_k=%u flags_a=%08x flags_b=%08x cf=%u ds=%04x es=%04x ss=%04x valid=%u stack0=%08x stack1=%08x stack2=%08x stack3=%08x\n",
           site,g_cur_func,g_seg_cs,g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,
           g_flag_k,g_flag_a,g_flag_b,g_flag_cf,g_seg_ds,g_seg_es,g_seg_ss,valid,
           stack[0],stack[1],stack[2],stack[3]);
}
void gw_native_capture_alloc_return(uint32_t site) {
    uint32_t stack[4]={0};
    uint32_t valid=(g_esp<=GW_NATIVE_GUEST_MEMORY_SIZE-sizeof stack);
    if (valid) memcpy(stack,guest_memory+g_esp,sizeof stack);
    printf("NATIVE_ALLOC_RETURN ordinal=%u site=%08x current_func=%08x eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x ebp=%08x esp=%08x flags_k=%u flags_a=%08x flags_b=%08x cf=%u ds=%04x es=%04x ss=%04x valid=%u stack0=%08x stack1=%08x stack2=%08x stack3=%08x global_10b78e=%08x global_10c824=%08x global_10c828=%08x global_10b760=%08x\n",
           w1_alloc_chain_ordinal++,site,g_cur_func,g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,
           g_flag_k,g_flag_a,g_flag_b,g_flag_cf,g_seg_ds,g_seg_es,g_seg_ss,valid,
           stack[0],stack[1],stack[2],stack[3],
           *(uint32_t *)(guest_memory+0x0010B78Eu),
           *(uint32_t *)(guest_memory+0x0010C824u),
           *(uint32_t *)(guest_memory+0x0010C828u),
           *(uint32_t *)(guest_memory+0x0010B760u));
}
#endif
void gw_native_capture_callsite(uint32_t caller, uint32_t target, uint32_t site) {
    if (target!=0x000C896Au) return;
    uint32_t s0=(g_esp<GW_NATIVE_GUEST_MEMORY_SIZE-4u)?*(uint32_t *)(guest_memory+g_esp):0;
    uint32_t s1=(g_esp+4u<GW_NATIVE_GUEST_MEMORY_SIZE-4u)?*(uint32_t *)(guest_memory+g_esp+4u):0;
    uint32_t s2=(g_esp+8u<GW_NATIVE_GUEST_MEMORY_SIZE-4u)?*(uint32_t *)(guest_memory+g_esp+8u):0;
    printf("W1_AH44_CALLSITE ordinal=%u caller=%08x target=%08x site=%08x cs=%04x eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x ebp=%08x esp=%08x flags_k=%u flags_a=%08x flags_b=%08x cf=%u ds=%04x ds_base=%08x es=%04x ss=%04x stack0=%08x stack1=%08x stack2=%08x\n",
           w1_ah44_callsite_ordinal++,caller,target,site,g_seg_cs,g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,
           g_flag_k,g_flag_a,g_flag_b,g_flag_cf,g_seg_ds,g_ds_base,g_seg_es,g_seg_ss,s0,s1,s2);
}
void gw_native_capture_block(uint32_t va) {
    if (va==0x000DFE12u) {
        uint32_t stack[4]={0};
        uint32_t valid=(g_esp<=GW_NATIVE_GUEST_MEMORY_SIZE-sizeof stack);
        if (valid) memcpy(stack,guest_memory+g_esp,sizeof stack);
        printf("NATIVE_ADF95_RETURN link_va=%08x caller_func=%08x cs=%04x eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x ebp=%08x esp=%08x flags_k=%u flags_a=%08x flags_b=%08x cf=%u ds=%04x es=%04x ss=%04x valid=%u stack0=%08x stack1=%08x stack2=%08x stack3=%08x\n",
               va,g_cur_func,g_seg_cs,g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,
               g_flag_k,g_flag_a,g_flag_b,g_flag_cf,g_seg_ds,g_seg_es,g_seg_ss,valid,
               stack[0],stack[1],stack[2],stack[3]);
    }
#ifdef GW_NATIVE_CAPTURE_ALLOC_CHAIN
    if (va==0x000ADF95u || va==0x000C3E2Au || va==0x000C3D7Au || va==0x000C3F76u || va==0x000C3CA9u) {
        uint32_t stack[8]={0};
        uint32_t valid=(g_esp<=GW_NATIVE_GUEST_MEMORY_SIZE-sizeof stack);
        if (valid) memcpy(stack,guest_memory+g_esp,sizeof stack);
        printf("NATIVE_ALLOC_ENTRY ordinal=%u va=%08x current_func=%08x return_address=%08x cs=%04x eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x ebp=%08x esp=%08x flags_k=%u flags_a=%08x flags_b=%08x cf=%u ds=%04x es=%04x ss=%04x valid=%u global_10b78e=%08x global_10c824=%08x global_10c828=%08x global_10b760=%08x",
               w1_alloc_chain_ordinal++,va,g_cur_func,stack[0],g_seg_cs,g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,
               g_flag_k,g_flag_a,g_flag_b,g_flag_cf,g_seg_ds,g_seg_es,g_seg_ss,valid,
               *(uint32_t *)(guest_memory+0x0010B78Eu),
               *(uint32_t *)(guest_memory+0x0010C824u),
               *(uint32_t *)(guest_memory+0x0010C828u),
               *(uint32_t *)(guest_memory+0x0010B760u));
        for (uint32_t i=0;i<8u;++i) printf(" stack%u=%08x",i,stack[i]);
        printf("\n");
    }
#endif
    if (va==0x000C3D9Du) {
        uint32_t stack[4]={0};
        uint32_t valid=(g_esp<=GW_NATIVE_GUEST_MEMORY_SIZE-sizeof stack);
        if (valid) memcpy(stack,guest_memory+g_esp,sizeof stack);
        printf("NATIVE_ALLOC_POINT va=%08x current_func=%08x eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x ebp=%08x esp=%08x flags_k=%u flags_a=%08x flags_b=%08x cf=%u ds=%04x es=%04x ss=%04x stack0=%08x stack1=%08x stack2=%08x stack3=%08x global_10b78e=%08x global_10c824=%08x global_10b760=%08x\n",
               va,g_cur_func,g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,
               g_flag_k,g_flag_a,g_flag_b,g_flag_cf,g_seg_ds,g_seg_es,g_seg_ss,
               stack[0],stack[1],stack[2],stack[3],
               *(uint32_t *)(guest_memory+0x0010B78Eu),
               *(uint32_t *)(guest_memory+0x0010C824u),
               *(uint32_t *)(guest_memory+0x0010B760u));
    }
    if (va==0x000C896Au) {
        uint32_t ret=(g_esp<GW_NATIVE_GUEST_MEMORY_SIZE-4u)?*(uint32_t *)(guest_memory+g_esp):0;
        uint32_t s1=(g_esp+4u<GW_NATIVE_GUEST_MEMORY_SIZE-4u)?*(uint32_t *)(guest_memory+g_esp+4u):0;
        uint32_t s2=(g_esp+8u<GW_NATIVE_GUEST_MEMORY_SIZE-4u)?*(uint32_t *)(guest_memory+g_esp+8u):0;
        uint32_t caller=(ret>=5u && ret<=GW_NATIVE_GUEST_MEMORY_SIZE)?ret-5u:0;
        printf("W1_AH44_HELPER_ENTRY ordinal=%u cs=%04x eip=%08x caller_func=%08x return_address=%08x callsite=%08x eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x ebp=%08x esp=%08x flags_k=%u flags_a=%08x flags_b=%08x cf=%u ds=%04x ds_base=%08x es=%04x ss=%04x stack0=%08x stack1=%08x stack2=%08x\n",
               w1_ah44_helper_entry_ordinal++,g_seg_cs,va,g_cur_func,ret,caller,g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,
               g_flag_k,g_flag_a,g_flag_b,g_flag_cf,g_seg_ds,g_ds_base,g_seg_es,g_seg_ss,ret,s1,s2);
    }
    int main_point=(va==0x00093F30u || va==0x00093F51u || va==0x00093F62u ||
                    va==0x00093F7Eu || va==0x00093FB3u || va==0x00093FE0u ||
                    va==0x000940C0u || va==0x000941D2u || va==0x00098602u ||
                    va==0x000AFC69u || va==0x000AFC8Du || va==0x00098658u ||
                    va==0x00098679u || va==0x00098616u || va==0x00098623u ||
                    va==0x0009432Fu || va==0x0009433Du || va==0x00094AC0u ||
                    va==0x00094360u || va==0x000943F8u);
    int crt_target=-1;
    for (uint32_t i=0;i<19u;++i) {
        uint32_t entry=0x001126B8u+i*6u;
        if (entry+6u<=GW_NATIVE_GUEST_MEMORY_SIZE && guest_memory[entry]==0u &&
            *(uint32_t *)(guest_memory+entry+2u)==va) { crt_target=(int)i; break; }
    }
    if (va==0x0009433Du || va==0x00094AC0u || va==0x00094AD9u ||
        va==0x00014BF0u || va==0x00094AECu || va==0x000AE930u ||
        va==0x00094B07u || va==0x000AF200u || va==0x00094B12u || va==0x00097B60u ||
        va==0x00098602u || va==0x00098658u || va==0x00098679u ||
        va==0x00098616u || va==0x00098623u || va==0x000AFC69u || va==0x000AFC8Du) {
        uint32_t s0=(g_esp<GW_NATIVE_GUEST_MEMORY_SIZE-4u)?*(uint32_t *)(guest_memory+g_esp):0;
        uint32_t s1=(g_esp+4u<GW_NATIVE_GUEST_MEMORY_SIZE-4u)?*(uint32_t *)(guest_memory+g_esp+4u):0;
        uint32_t s2=(g_esp+8u<GW_NATIVE_GUEST_MEMORY_SIZE-4u)?*(uint32_t *)(guest_memory+g_esp+8u):0;
        printf("W1_SETUP_EVENT ordinal=%u kind=%s cs=%04x eip=%08x cur_func=%08x eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x ebp=%08x esp=%08x stack0=%08x stack1=%08x stack2=%08x target=%08x\n",
               w1_setup_event_ordinal++,va==0x0009433Du?"callsite":
               (va==0x00094AC0u || va==0x00014BF0u || va==0x000AE930u || va==0x000AF200u || va==0x00097B60u || va==0x000AFC69u || va==0x000AFC8Du || va==0x00098658u)?"entry":"internal_callsite",
               g_seg_cs,va,g_cur_func,g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,s0,s1,s2,
               va==0x0009433Du?0x00094AC0u:va==0x00094AD9u?0x00014BF0u:va==0x00094AECu?0x000AE930u:va==0x00094B07u?0x000AF200u:va==0x00094B12u?0x00097B60u:
               (va==0x00014BF0u || va==0x000AE930u || va==0x000AF200u || va==0x00097B60u || va==0x000AFC69u || va==0x000AFC8Du || va==0x00098658u)?va:
               va==0x00098602u?0x000AFC8Du:va==0x00098679u?0x00098594u:va==0x00094AC0u?0x00094AC0u:0u);
    }
    if (!main_point && va!=0x000C871Cu && crt_target<0) return;
    if (va==0x000C871Cu)
        printf("W1_INITRTNS_ENTRY eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x ebp=%08x esp=%08x\n",
               g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp);
    if (crt_target>=0)
        printf("W1_CRT_CALLBACK_DYNAMIC ordinal=%u index=%d priority=%u target=%08x eax=%08x edx=%08x esp=%08x\n",
               w1_crt_dynamic_ordinal++,(int)crt_target,guest_memory[0x001126B8u+(uint32_t)crt_target*6u+1u],
               va,g_eax,g_edx,g_esp);
    if (!main_point) return;
    uint32_t a64=0,a68=0,argc=0,argv=0,option_arg=0,option_char=0;
    if (g_esp+0x69u<GW_NATIVE_GUEST_MEMORY_SIZE) {
        a64=guest_memory[g_esp+0x64u]; a68=guest_memory[g_esp+0x68u];
        argc=*(uint32_t *)(guest_memory+g_esp+0x5Cu);
        argv=*(uint32_t *)(guest_memory+g_esp+0x54u);
    }
    if (va==0x000941D2u && g_esp+0x5Cu<GW_NATIVE_GUEST_MEMORY_SIZE) {
        uint32_t arg_slot=*(uint32_t *)(guest_memory+g_esp+0x58u);
        uint32_t ptr=arg_slot<GW_NATIVE_GUEST_MEMORY_SIZE ? *(uint32_t *)(guest_memory+arg_slot) : 0;
        if (ptr<GW_NATIVE_GUEST_MEMORY_SIZE) { option_arg=ptr; option_char=guest_memory[ptr+1u]; }
    }
    char frame_hex[65];
    for (uint32_t i=0;i<32u;++i) {
        uint8_t b=(g_esp+i<GW_NATIVE_GUEST_MEMORY_SIZE)?guest_memory[g_esp+i]:0;
        sprintf(frame_hex+i*2u,"%02x",b);
    }
    frame_hex[64]=0;
    printf("W1_MAIN_BLOCK va=%08x eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x ebp=%08x esp=%08x eflags_k=%u eflags_a=%08x eflags_b=%08x cf=%u argc_local=%u argv_local=%08x local64=%u local68=%u global188a4c=%08x option_arg=%08x option_char=%02x frame_hex=%s\n",
           va,g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,g_flag_k,g_flag_a,g_flag_b,g_flag_cf,
           argc,argv,a64,a68,*(uint32_t *)(guest_memory+0x00188A4Cu),option_arg,option_char,frame_hex);
}
#endif
static int write_frontier_memory_if_requested(void) {
    const char *path=getenv("GW_FRONTIER_SNAPSHOT_MEMORY");
    if (!path || !*path) return 1;
    FILE *out=fopen(path,"wb");
    if (!out) return 0;
    size_t written=fwrite(guest_memory,1,GW_NATIVE_GUEST_MEMORY_SIZE,out);
    int ok=(written==GW_NATIVE_GUEST_MEMORY_SIZE && fclose(out)==0);
    return ok;
}
static int saw_first_version_service;
static int saw_dos4g_install_check;
static int saw_selector_base_query;
static int saw_time_query;
static uint32_t time_request_eax, time_request_ebx, time_request_ecx, time_request_edx;
static uint32_t time_query_eax, time_query_ebx, time_query_ecx, time_query_edx;
static uint8_t time_query_carry;
static int saw_dpmi_linear_alloc;
static uint32_t w1_090_dpmi_sequence_count;
static int w1_090_dpmi_sequence_failed;
#ifdef GW_NATIVE_CAPTURE_CRT_STARTUP
static struct { uint32_t req_eax,req_ebx,req_ecx,req_edx,res_eax,res_ebx,res_ecx,res_edx,res_esi,res_edi,size,base,handle; } w1_crt_allocs[32];
static uint32_t w1_crt_alloc_count;
static uint32_t w1_crt_dpmi0300_count,w1_crt_dpmi0300_frame,w1_crt_dpmi0300_inner_eax,w1_crt_dpmi0300_inner_ds,w1_crt_dpmi0300_inner_si;
static uint8_t w1_crt_virtual_second;
#endif
static uint32_t alloc_success_base, alloc_success_size, alloc_success_handle;
static int saw_native_ah3d;
static uint32_t ah3d_req_eax, ah3d_req_ebx, ah3d_req_ecx, ah3d_req_edx;
static uint32_t ah3d_req_esi, ah3d_req_edi, ah3d_req_ebp, ah3d_req_esp;
static uint32_t ah3d_res_eax, ah3d_res_ebx, ah3d_res_ecx, ah3d_res_edx;
static uint32_t ah3d_res_esi, ah3d_res_edi, ah3d_res_ebp, ah3d_res_esp;
static uint8_t ah3d_req_cf, ah3d_res_cf;
static char ah3d_path[260];
static char ah3d_resolved_path[260];
static int saw_native_ah3c;
static uint32_t ah3c_req_eax,ah3c_req_ebx,ah3c_req_ecx,ah3c_req_edx;
static uint32_t ah3c_res_eax,ah3c_res_ebx,ah3c_res_ecx,ah3c_res_edx;
static uint8_t ah3c_req_cf,ah3c_res_cf;
static char ah3c_path[260];
#ifdef GW_NATIVE_CONTINUE_DOS_AX4400
static int saw_native_ax4400;
static unsigned native_ax4400_call_count;
static uint32_t ax4400_req_eax,ax4400_req_ebx,ax4400_req_ecx,ax4400_req_edx;
static uint32_t ax4400_res_eax,ax4400_res_ebx,ax4400_res_ecx,ax4400_res_edx;
static uint8_t ax4400_req_cf,ax4400_res_cf;
static int saw_native_ah42;
static unsigned native_ah42_call_count;
static uint32_t ah42_req_eax,ah42_req_ebx,ah42_req_ecx,ah42_req_edx;
static uint32_t ah42_res_eax,ah42_res_ebx,ah42_res_ecx,ah42_res_edx;
static uint8_t ah42_req_cf,ah42_res_cf;
static int saw_native_ah3e;
static uint32_t ah3e_req_eax,ah3e_req_ebx,ah3e_res_eax,ah3e_res_ebx;
static uint8_t ah3e_req_cf,ah3e_res_cf;
static int saw_native_standard_ioctl;
static unsigned native_standard_ioctl_count;
static unsigned native_ax4400_console_provider_count;
#ifdef GW_NATIVE_CONTINUE_DPMI_AX0200
static unsigned native_dpmi_ax0200_count;
static unsigned native_dos_ah35_count;
static unsigned native_dos_ah25_count;
#endif
static uint32_t stdio_ioctl_req_eax,stdio_ioctl_req_ebx,stdio_ioctl_req_edx;
static uint32_t stdio_ioctl_res_eax,stdio_ioctl_res_ebx,stdio_ioctl_res_edx;
static uint8_t stdio_ioctl_req_cf,stdio_ioctl_res_cf;
#ifdef GW_NATIVE_CONTINUE_DOS_AH40
static int saw_native_ah40;
static unsigned native_ah40_call_count;
static uint32_t ah40_req_eax,ah40_req_ebx,ah40_req_ecx,ah40_req_edx;
static uint32_t ah40_res_eax,ah40_res_ebx,ah40_res_ecx,ah40_res_edx;
static uint32_t ah40_req_esi,ah40_req_edi,ah40_req_ebp,ah40_req_esp;
static uint32_t ah40_res_esi,ah40_res_edi,ah40_res_ebp,ah40_res_esp;
static uint32_t ah40_req_ds_base;
static uint16_t ah40_req_ds;
static uint8_t ah40_req_cf,ah40_res_cf;
static uint8_t native_stdout_bytes[1024];
static uint32_t native_stdout_size;
static uint16_t native_stdout_write(void *user,const uint8_t *buffer,
                                    uint16_t requested,uint16_t *transferred) {
    (void)user;
    if ((uint64_t)native_stdout_size+requested>sizeof(native_stdout_bytes)) return 8u;
    if (requested) memcpy(native_stdout_bytes+native_stdout_size,buffer,requested);
    native_stdout_size+=requested;
    *transferred=requested;
    return 0;
}
#endif
#endif
#define NATIVE_VFILE_CAP 4096u
typedef struct native_virtual_file {
    uint8_t bytes[NATIVE_VFILE_CAP];
    uint32_t size;
    uint16_t ioctl_info_flags;
    uint8_t exists;
    uint8_t drive_number;
    uint8_t written;
} native_virtual_file;
typedef struct native_virtual_open { uint32_t position; uint8_t active,mode; native_virtual_file *owner; } native_virtual_open;
static native_virtual_file native_address_file;
static native_virtual_file native_gwerr_file;
static native_virtual_open native_address_opens[GW_DOS_MAX_OPEN_FILES];
#ifdef GW_NATIVE_SERVE_W3_SOUND_INI
#include "native_w3_sound_ini_fixture_work1.h"
static native_virtual_file native_w3_sound_ini_file;
#endif
#ifdef GW_NATIVE_SERVE_W3_ADDRESS_SEED
#include "native_w3_address_seed_work1.h"
static int saw_native_seeded_address_open;
#endif
#ifdef GW_NATIVE_SERVE_W3_CONFIG
#include "native_w3_config_fixture_work2.h"
static native_virtual_file native_w3_config_file;
static uint32_t native_w3_config_read_total;
static uint8_t native_w3_config_read_bytes[NATIVE_W3_CONFIG_SIZE];
static int saw_native_w3_config_open;
static int native_w3_config_handle_active(gw_dos_services *services,uint32_t handle) {
    for (uint32_t i=0;i<GW_DOS_MAX_OPEN_FILES;i++) {
        gw_dos_file_handle *entry=&services->files[i];
        if (entry->active && entry->dos_handle==handle && entry->file &&
            ((native_virtual_open *)entry->file)->owner==&native_w3_config_file) return 1;
    }
    return 0;
}
#endif

static void native_normalize_dos_path(const char *path,char *out,size_t capacity) {
    size_t used=0; int previous_separator=0;
    while (*path && used+1u<capacity) {
        char ch=*path++;
        if (ch=='/') ch='\\';
        if (ch=='\\') {
            if (previous_separator) continue;
            previous_separator=1;
        } else previous_separator=0;
        out[used++]=ch;
    }
    out[used]=0;
}

#ifdef GW_NATIVE_CONTINUE_DOS_AH3D
static uint16_t native_replay_file_open(void *user, const char *path,
                                        uint8_t access_mode, void **file) {
    (void)user;
    if (!path) return 3u;
    strncpy(ah3d_path,path,sizeof(ah3d_path)-1u);
    ah3d_path[sizeof(ah3d_path)-1u]=0;
    native_normalize_dos_path(path,ah3d_resolved_path,sizeof(ah3d_resolved_path));
#ifdef GW_NATIVE_SERVE_W3_CONFIG
    if (_stricmp(path,"config.ini")==0)
        strncpy(ah3d_resolved_path,"c:\\genewars\\config.ini",sizeof(ah3d_resolved_path)-1u);
#endif
#ifdef GW_NATIVE_CAPTURE_CRT_STARTUP
    printf("W1_CRT_VFILE_OPEN path=%s normalized=%s\n",path,ah3d_resolved_path);
#endif
    native_virtual_file *owner=NULL;
    if (_stricmp(ah3d_resolved_path,"C:\\address.txt")==0) owner=&native_address_file;
    else if (_stricmp(path,"gw.err")==0 || _stricmp(ah3d_resolved_path,"C:\\GENEWARS\\gw.err")==0) owner=&native_gwerr_file;
#ifdef GW_NATIVE_SERVE_W3_CONFIG
    else if (_stricmp(path,"config.ini")==0 ||
             _stricmp(ah3d_resolved_path,"C:\\GENEWARS\\config.ini")==0) {
        if (access_mode!=0u) return 5u;
        owner=&native_w3_config_file;
    }
#endif
#ifdef GW_NATIVE_SERVE_W3_SOUND_INI
    else if (_stricmp(ah3d_resolved_path,"C:\\GENEWARS\\sound.ini")==0) {
        if (access_mode!=0u) return 5u;
        owner=&native_w3_sound_ini_file;
    }
#endif
    if (!owner) return 3u;
    /* These paths exist only as bounded memory objects in this diagnostic fixture. */
    if (!owner->exists) return 2u;
    if (access_mode>2u) return 12u;
    for (unsigned i=0;i<GW_DOS_MAX_OPEN_FILES;i++) if (!native_address_opens[i].active) {
        native_address_opens[i]=(native_virtual_open){0,1,access_mode,owner};
        *file=&native_address_opens[i];
#ifdef GW_NATIVE_SERVE_W3_SOUND_INI
        if (owner==&native_w3_sound_ini_file)
            printf("NATIVE_W1_SOUND_PROVIDER_OPEN path=C:\\GENEWARS\\sound.ini access=read-only bytes=%u sha256=%s provider=bounded-memory fixture=tests/fixtures/w3_069_sound_ini_work1.bin\n",
                native_w3_sound_ini_file.size,NATIVE_W1_SOUND_INI_SHA256);
#endif
        return 0;
    }
    return 4u;
}
static uint16_t native_replay_file_read(void *user, void *file, uint8_t *buffer,
                                        uint16_t requested, uint16_t *transferred) {
    (void)user; native_virtual_open *open=(native_virtual_open *)file;
    if (!open || !open->active || open->mode==1u || !buffer || !transferred) return 6u;
    if (!open->owner || open->position>open->owner->size) return 6u;
    uint32_t remaining=open->owner->size-open->position;
    uint16_t n=requested<remaining?requested:(uint16_t)remaining;
    memcpy(buffer,open->owner->bytes+open->position,n); open->position+=n; *transferred=n; return 0;
}
static uint16_t native_replay_file_create(void *user,const char *path,uint16_t attrs,void **file) {
    (void)user; (void)attrs;
    if (!path) return 5u;
    native_virtual_file *owner=NULL;
    if (_stricmp(path,"c:\\address.txt")==0) owner=&native_address_file;
    else if (_stricmp(path,"gw.err")==0 || _stricmp(path,"c:\\genewars\\gw.err")==0) owner=&native_gwerr_file;
    if (!owner) return 5u;
    owner->size=0; owner->exists=1; owner->written=0;
    owner->ioctl_info_flags=0; owner->drive_number=2; /* C: writable virtual backing */
    for (unsigned i=0;i<GW_DOS_MAX_OPEN_FILES;i++) if (!native_address_opens[i].active) {
        native_address_opens[i]=(native_virtual_open){0,1,1,owner}; *file=&native_address_opens[i]; return 0;
    }
    return 4u;
}
static uint16_t native_replay_file_write(void *user,void *file,const uint8_t *buffer,
                                         uint16_t requested,uint16_t *transferred) {
    (void)user; native_virtual_open *open=(native_virtual_open *)file;
    if (!open || !open->active || !open->owner || open->mode==0u || !transferred) return 6u;
    if (!requested) { open->owner->size=open->position; *transferred=0; return 0; }
    if (!buffer) return 6u;
    uint64_t end=(uint64_t)open->position+requested;
    if (end>NATIVE_VFILE_CAP || end>0xffffffffu) return 112u;
    if (requested) memcpy(open->owner->bytes+open->position,buffer,requested);
    open->position=(uint32_t)end;
    if (open->position>open->owner->size) open->owner->size=open->position;
    open->owner->written=1;
    *transferred=requested; return 0;
}
static uint16_t native_replay_file_close(void *user, void *file) {
    (void)user; native_virtual_open *open=(native_virtual_open *)file;
    if (!open || !open->active) return 6u;
#ifdef GW_NATIVE_SERVE_W3_SOUND_INI
    if (open->owner==&native_w3_sound_ini_file)
        printf("NATIVE_W1_SOUND_PROVIDER_CLOSE path=C:\\GENEWARS\\sound.ini probe=1 result=0\n");
#endif
    memset(open,0,sizeof(*open)); return 0;
}
static uint16_t native_replay_file_ioctl_info(void *user,void *file,uint16_t *info) {
    (void)user; native_virtual_open *open=(native_virtual_open *)file;
    if (!open || !open->active || !open->owner || !info) return 6u;
    *info=(uint16_t)((open->owner->ioctl_info_flags&0xffe0u)|
                     (open->owner->drive_number&0x1fu)); return 0;
}
static uint16_t native_replay_file_seek(void *user,void *file,int32_t displacement,
                                        uint8_t origin,uint32_t *position) {
    (void)user; native_virtual_open *open=(native_virtual_open *)file;
    if (!open || !open->active || !open->owner || !position) return 6u;
    int64_t base=origin==0u?0:(origin==1u?open->position:open->owner->size);
    int64_t next=base+displacement;
    if (origin>2u || next<0 || next>UINT32_MAX) return 1u;
    open->position=(uint32_t)next; *position=open->position; return 0;
}
#ifdef GW_NATIVE_SERVE_W3_CONFIG
static int test_native_w3_config_provider(gw_dos_services *services) {
    const uint32_t path_offset=0x00300000u, buffer_offset=0x00300100u;
    const char path[]="config.ini", denied[]="not-authorized.ini";
    if (GW_NATIVE_GUEST_MEMORY_SIZE<0x00300200u) return 0;
    uint8_t saved_memory[0x200];
    memcpy(saved_memory,guest_memory+path_offset,sizeof saved_memory);
    uint32_t saved_eax=g_eax,saved_ebx=g_ebx,saved_ecx=g_ecx,saved_edx=g_edx;
    uint32_t saved_esi=g_esi,saved_edi=g_edi,saved_ebp=g_ebp,saved_esp=g_esp;
    uint16_t saved_ds=g_seg_ds; uint32_t saved_ds_base=g_ds_base;
    ptrdiff_t saved_mem_base=g_mem_base; uint32_t saved_cf=g_flag_cf;
    memcpy(guest_memory+path_offset,path,sizeof path);
    memcpy(guest_memory+path_offset+0x40u,denied,sizeof denied);
    g_seg_ds=GW_BOOT_DS; g_ds_base=0; g_mem_base=(ptrdiff_t)guest_memory;

    g_eax=0x00003d00u; g_ebx=0x11223344u; g_ecx=0x55667788u;
    g_edx=path_offset; g_flag_cf=1;
    if (gw_dos_services_callback(0x21u,0x000AFCC4u,services)!=GW_INTERRUPT_HANDLED ||
        g_flag_cf || (uint16_t)g_eax<5u || (uint16_t)g_eax>=5u+GW_DOS_MAX_OPEN_FILES ||
        g_ebx!=0x11223344u || g_ecx!=0x55667788u || g_edx!=path_offset) return 0;
    uint16_t handle=(uint16_t)g_eax;

    g_eax=0x00004200u; g_ebx=handle; g_ecx=0; g_edx=0; g_flag_cf=1;
    if (gw_dos_services_callback(0x21u,0x000AFCC4u,services)!=GW_INTERRUPT_HANDLED ||
        g_flag_cf || (uint16_t)g_eax!=0u || (uint16_t)g_edx!=0u) return 0;
    g_eax=0x00003f00u; g_ebx=handle; g_ecx=NATIVE_W3_CONFIG_SIZE; g_edx=buffer_offset; g_flag_cf=1;
    if (gw_dos_services_callback(0x21u,0x000AFCC4u,services)!=GW_INTERRUPT_HANDLED ||
        g_flag_cf || (uint16_t)g_eax!=NATIVE_W3_CONFIG_SIZE ||
        memcmp(guest_memory+buffer_offset,native_w3_config_fixture,NATIVE_W3_CONFIG_SIZE)!=0) return 0;

    g_eax=0x00004200u; g_ebx=handle; g_ecx=0; g_edx=5u; g_flag_cf=1;
    if (gw_dos_services_callback(0x21u,0x000AFCC4u,services)!=GW_INTERRUPT_HANDLED ||
        g_flag_cf || (uint16_t)g_eax!=5u) return 0;
    g_eax=0x00003f00u; g_ebx=handle; g_ecx=7u; g_edx=buffer_offset; g_flag_cf=1;
    if (gw_dos_services_callback(0x21u,0x000AFCC4u,services)!=GW_INTERRUPT_HANDLED ||
        g_flag_cf || (uint16_t)g_eax!=7u ||
        memcmp(guest_memory+buffer_offset,native_w3_config_fixture+5u,7u)!=0) return 0;
    g_eax=0x00003e00u; g_ebx=handle; g_flag_cf=1;
    if (gw_dos_services_callback(0x21u,0x000AFCC4u,services)!=GW_INTERRUPT_HANDLED ||
        g_flag_cf || services->files[handle-5u].active) return 0;

    g_eax=0x00003d01u; g_ebx=0; g_ecx=0; g_edx=path_offset; g_flag_cf=0;
    if (gw_dos_services_callback(0x21u,0x000AFCC4u,services)!=GW_INTERRUPT_HANDLED ||
        !g_flag_cf || (uint16_t)g_eax!=5u) return 0;
    memcpy(guest_memory+path_offset,denied,sizeof denied);
    g_eax=0x00003d00u; g_edx=path_offset; g_flag_cf=0;
    if (gw_dos_services_callback(0x21u,0x000AFCC4u,services)!=GW_INTERRUPT_HANDLED ||
        !g_flag_cf || (uint16_t)g_eax!=3u) return 0;
    memcpy(guest_memory+path_offset,path,sizeof path);
    g_eax=0x00003c00u; g_ecx=0; g_edx=path_offset; g_flag_cf=0;
    if (gw_dos_services_callback(0x21u,0x000AFCC4u,services)!=GW_INTERRUPT_HANDLED ||
        !g_flag_cf || (uint16_t)g_eax!=5u) return 0;

    g_eax=0x00003d00u; g_edx=path_offset; g_flag_cf=0;
    if (gw_dos_services_callback(0x21u,0x000AFCC4u,services)!=GW_INTERRUPT_HANDLED || g_flag_cf) return 0;
    handle=(uint16_t)g_eax;
    g_eax=0x00003f00u; g_ebx=handle; g_ecx=8u; g_edx=(uint32_t)GW_NATIVE_GUEST_MEMORY_SIZE-4u; g_flag_cf=0;
    if (gw_dos_services_callback(0x21u,0x000AFCC4u,services)!=GW_INTERRUPT_TRAPPED ||
        !services->files[handle-5u].active) return 0;
    g_eax=0x00003e00u; g_ebx=handle; g_flag_cf=0;
    if (gw_dos_services_callback(0x21u,0x000AFCC4u,services)!=GW_INTERRUPT_HANDLED ||
        g_flag_cf || services->files[handle-5u].active) return 0;

    g_eax=0x00003f00u; g_ebx=0xffffu; g_ecx=1u; g_edx=buffer_offset; g_flag_cf=0;
    if (gw_dos_services_callback(0x21u,0x000AFCC4u,services)!=GW_INTERRUPT_HANDLED ||
        !g_flag_cf || (uint16_t)g_eax!=6u) return 0;
    memcpy(guest_memory+path_offset,saved_memory,sizeof saved_memory);
    g_eax=saved_eax; g_ebx=saved_ebx; g_ecx=saved_ecx; g_edx=saved_edx;
    g_esi=saved_esi; g_edi=saved_edi; g_ebp=saved_ebp; g_esp=saved_esp;
    g_seg_ds=saved_ds; g_ds_base=saved_ds_base; g_mem_base=saved_mem_base; g_flag_cf=saved_cf;
    printf("NATIVE_W3_CONFIG_PROVIDER_TEST success=1 bytes=%u full_read=1 partial_read=1 seek=1 close=1 readonly=1 missing_path=1 create_denied=1 invalid_buffer_trapped=1 invalid_handle=1 host_fs=unused\n",
        NATIVE_W3_CONFIG_SIZE);
    return 1;
}
#endif
#endif
static uint32_t alloc_req_eax, alloc_req_ebx, alloc_req_ecx, alloc_req_edx, alloc_req_esi, alloc_req_edi, alloc_req_ebp, alloc_req_esp;
static uint32_t alloc_res_eax, alloc_res_ebx, alloc_res_ecx, alloc_res_edx, alloc_res_esi, alloc_res_edi, alloc_res_ebp, alloc_res_esp;
static uint8_t alloc_res_carry;
static uint32_t alloc_req_flag_k, alloc_req_flag_a, alloc_req_flag_b, alloc_req_flag_cf;
static uint32_t alloc_req_cs_base, alloc_req_ds_base, alloc_req_es_base, alloc_req_ss_base;
static uint32_t alloc_stack_words[8];
static uint16_t alloc_req_cs, alloc_req_ds, alloc_req_es, alloc_req_ss;
static int saw_dos_ah48;
static uint32_t dos48_req_eax, dos48_req_ebx, dos48_req_ecx, dos48_req_edx, dos48_req_esi, dos48_req_edi, dos48_req_ebp, dos48_req_esp;
static uint32_t dos48_res_eax, dos48_res_ebx, dos48_res_ecx, dos48_res_edx, dos48_res_esi, dos48_res_edi, dos48_res_ebp, dos48_res_esp;
static uint8_t dos48_res_carry;
static int saw_dos_ah48_retry;
static int saw_native_ah49_frontier;
static uint16_t native_ah49_es;
static uint32_t native_ah49_eax, native_ah49_ebx, native_ah49_ecx, native_ah49_edx;
static uint32_t dos48r_req_eax, dos48r_req_ebx, dos48r_req_ecx, dos48r_req_edx, dos48r_req_esi, dos48r_req_edi, dos48r_req_ebp, dos48r_req_esp;
static uint32_t dos48r_res_eax, dos48r_res_ebx, dos48r_res_ecx, dos48r_res_edx, dos48r_res_esi, dos48r_res_edi, dos48r_res_ebp, dos48r_res_esp;
static uint8_t dos48r_res_carry;
static uint16_t dpmi_query_ax, dpmi_query_selector, dpmi_query_cx, dpmi_query_dx;
static uint32_t dpmi_query_ds_base;
static uint8_t dpmi_query_carry;
static uint16_t dpmi_query_es_selector, dpmi_query_env_slot;
static uint32_t dpmi_query_es_base;

#ifdef GW_NATIVE_CONTINUE_DPMI_AX6300
#define NATIVE_AX6300_DBCS_TABLE_SIZE 12u
typedef struct native_ax6300_provider_state {
    gw_dos_services *services;
    uint32_t calls;
    uint16_t segment;
    uint16_t selector;
    uint32_t linear;
} native_ax6300_provider_state;
static native_ax6300_provider_state native_ax6300_state;

static int native_dos_real_mode_interrupt(void *user, uint8_t vector,
                                           gw_dos_real_mode_registers *registers) {
    native_ax6300_provider_state *state=(native_ax6300_provider_state *)user;
    if (!state || !state->services || !registers) return 0;
    /* The authenticated original-byte replay at D23A7 invokes the DOS
     * MSCDEX installation check with an empty CD inventory. Keep this
     * provider deliberately narrow: only INT 2Fh AX=1500/BX=0 is measured
     * here; it reports zero drives and does not claim MSCDEX is resident. */
    if (vector==0x2fu && (uint16_t)registers->eax==0x1500u &&
        (uint16_t)registers->ebx==0u) {
        registers->ebx&=0xffff0000u;
        registers->ecx&=0xffff0000u;
        registers->flags=(uint16_t)(registers->flags&~1u);
        state->calls++;
        return 1;
    }
    if (vector!=0x21u || (uint16_t)registers->eax!=0x6300u) return 0;

    if (!state->segment) {
        uint32_t saved_eax=g_eax,saved_ebx=g_ebx,saved_ecx=g_ecx,saved_edx=g_edx;
        uint32_t saved_esi=g_esi,saved_edi=g_edi,saved_ebp=g_ebp,saved_esp=g_esp;
        uint32_t saved_cur_func=g_cur_func,saved_flag_k=g_flag_k,saved_flag_a=g_flag_a;
        uint32_t saved_flag_b=g_flag_b,saved_flag_cf=g_flag_cf;
        uint16_t saved_cs=g_seg_cs,saved_ds=g_seg_ds,saved_es=g_seg_es,saved_ss=g_seg_ss;
        uint16_t saved_fs=g_seg_fs,saved_gs=g_seg_gs;
        g_eax=0x0100u; g_ebx=1u; g_edx=0u; g_flag_cf=1u;
        gw_interrupt_result allocated=gw_dos_services_callback(0x31u,0u,state->services);
        uint16_t segment=(uint16_t)g_eax,selector=(uint16_t)g_edx;
        uint32_t linear=(uint32_t)segment<<4;
        int allocation_valid=allocated==GW_INTERRUPT_HANDLED && !g_flag_cf && segment && selector &&
            linear<=GW_NATIVE_GUEST_MEMORY_SIZE && NATIVE_AX6300_DBCS_TABLE_SIZE<=GW_NATIVE_GUEST_MEMORY_SIZE-linear;
        g_eax=saved_eax; g_ebx=saved_ebx; g_ecx=saved_ecx; g_edx=saved_edx;
        g_esi=saved_esi; g_edi=saved_edi; g_ebp=saved_ebp; g_esp=saved_esp;
        g_cur_func=saved_cur_func; g_flag_k=saved_flag_k; g_flag_a=saved_flag_a;
        g_flag_b=saved_flag_b; g_flag_cf=saved_flag_cf;
        g_seg_cs=saved_cs; g_seg_ds=saved_ds; g_seg_es=saved_es; g_seg_ss=saved_ss;
        g_seg_fs=saved_fs; g_seg_gs=saved_gs;
        if (!allocation_valid) return 0;
        state->segment=segment; state->selector=selector; state->linear=linear;
    }

    if ((uint64_t)state->segment*16u!=state->linear ||
        state->linear>GW_NATIVE_GUEST_MEMORY_SIZE ||
        NATIVE_AX6300_DBCS_TABLE_SIZE>GW_NATIVE_GUEST_MEMORY_SIZE-state->linear) return 0;
    static const uint8_t measured_dbcs_table[NATIVE_AX6300_DBCS_TABLE_SIZE]={0};
    if (!state->services->dbcs_table_configured &&
        !gw_dos_dbcs_table_configure(state->services,state->linear,
                                     measured_dbcs_table,
                                     (uint16_t)sizeof measured_dbcs_table)) return 0;
    if (!gw_dos_services_real_mode_interrupt(state->services,vector,registers)) return 0;
    state->calls++;
    return 1;
}

static int test_native_ax6300_provider_rejects_unsupported(void) {
    gw_dos_real_mode_registers registers={0};
    if (native_dos_real_mode_interrupt(&native_ax6300_state,0x2fu,&registers)) return 0;
    registers.eax=0x6301u;
    if (native_dos_real_mode_interrupt(&native_ax6300_state,0x21u,&registers)) return 0;
    return native_ax6300_state.calls==0u && native_ax6300_state.segment==0u &&
        native_ax6300_state.services && native_ax6300_state.services->dos_block_count==0u;
}

static int test_native_mscdex_install_check_provider(void) {
    gw_dos_real_mode_registers registers={0};
    registers.eax=0x1500u; registers.ebx=0x12340000u;
    registers.ecx=0x56780001u; registers.flags=1u;
    uint32_t calls=native_ax6300_state.calls;
    if (!native_dos_real_mode_interrupt(&native_ax6300_state,0x2fu,&registers) ||
        registers.eax!=0x1500u || registers.ebx!=0x12340000u ||
        registers.ecx!=0x56780000u || (registers.flags&1u) ||
        native_ax6300_state.calls!=calls+1u) return 0;
    registers.eax=0x1501u;
    if (native_dos_real_mode_interrupt(&native_ax6300_state,0x2fu,&registers)) return 0;
    registers.eax=0x1500u; registers.ebx=1u;
    if (native_dos_real_mode_interrupt(&native_ax6300_state,0x2fu,&registers)) return 0;
    return native_ax6300_state.calls==calls+1u;
}
#endif

static void native_print_memory_diagnostic(FILE *stream,const char *reason) {
    recomp_memory_diagnostic d=recomp_memory_diag_last_access();
    fprintf(stream,
        "NATIVE_MEMORY_ACCESS_DIAGNOSTIC reason=%s guest_eip=%08x access_eip=%08x access_valid=%u reg_snapshot_valid=%u instruction_id=%u mnemonic=%s segment=%u selector=%04x segment_base=%08x offset=%08x linear=%08x host=%p width=%u access=%u backing=%u eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x ebp=%08x esp=%08x dpmi_req=%08x/%08x/%08x/%08x dpmi_res=%08x/%08x/%08x/%08x dpmi_cf=%u\n",
        reason?reason:"unknown",d.guest_eip,d.instruction_va,d.valid,d.register_snapshot_valid,d.instruction_id,d.mnemonic,
        d.segment,d.selector,d.segment_base,d.offset,d.linear,(void *)d.host_address,
        d.width,d.access,d.backing,d.eax,d.ebx,d.ecx,d.edx,d.esi,d.edi,d.ebp,d.esp,
        d.dpmi_req_eax,d.dpmi_req_ebx,d.dpmi_req_ecx,d.dpmi_req_edx,
        d.dpmi_res_eax,d.dpmi_res_ebx,d.dpmi_res_ecx,d.dpmi_res_edx,d.dpmi_carry);
    fflush(stream);
}

static LONG WINAPI capture_native_exception(EXCEPTION_POINTERS *exception) {
    EXCEPTION_RECORD *record = exception->ExceptionRecord;
    CONTEXT *cpu = exception->ContextRecord;
    recomp_memory_fault fault = recomp_get_memory_fault();
    gw_interrupt_trap trap = gw_interrupt_get_trap();
    uintptr_t module_base=(uintptr_t)GetModuleHandleA(NULL);
#if defined(_WIN64)
    uintptr_t host_pc=(uintptr_t)cpu->Rip;
    uintptr_t host_sp=(uintptr_t)cpu->Rsp;
#else
    uintptr_t host_pc=(uintptr_t)cpu->Eip;
    uintptr_t host_sp=(uintptr_t)cpu->Esp;
#endif
    uintptr_t host_pc_rva=host_pc>=module_base?host_pc-module_base:host_pc;
    uint32_t stack_return0=0, stack_return4=0;
    SIZE_T copied=0;
    ReadProcessMemory(GetCurrentProcess(), (const void *)host_sp, &stack_return0, sizeof stack_return0, &copied);
    copied=0;
    ReadProcessMemory(GetCurrentProcess(), (const void *)(host_sp+4u), &stack_return4, sizeof stack_return4, &copied);
#if defined(_WIN64)
    uint32_t host_eax=(uint32_t)cpu->Rax, host_ebx=(uint32_t)cpu->Rbx;
    uint32_t host_ecx=(uint32_t)cpu->Rcx, host_edx=(uint32_t)cpu->Rdx;
    uint32_t host_esi=(uint32_t)cpu->Rsi, host_edi=(uint32_t)cpu->Rdi;
    uint32_t host_ebp=(uint32_t)cpu->Rbp;
#else
    uint32_t host_eax=cpu->Eax, host_ebx=cpu->Ebx, host_ecx=cpu->Ecx, host_edx=cpu->Edx;
    uint32_t host_esi=cpu->Esi, host_edi=cpu->Edi, host_ebp=cpu->Ebp;
#endif
    uint32_t slot = (g_icall_trace_idx - 1u) & (ICALL_TRACE_SIZE - 1u);
    uintptr_t fault_address=record->NumberParameters>1 ?
        (uintptr_t)record->ExceptionInformation[1] : 0u;
    uintptr_t map_base=(uintptr_t)guest_memory;
    uint64_t guest_offset=(fault_address>=map_base &&
        fault_address-map_base<(uint64_t)GW_NATIVE_GUEST_MEMORY_SIZE) ?
        (uint64_t)(fault_address-map_base) : UINT64_MAX;
    MEMORY_BASIC_INFORMATION fault_info={0};
    SIZE_T fault_info_size=fault_address ? VirtualQuery((const void *)fault_address,
        &fault_info,sizeof fault_info) : 0u;
    native_print_memory_diagnostic(stderr,"unexpected_host_exception");
    fprintf(stderr,
        "NATIVE_EXCEPTION code=%08lx pc=%08lx sp=%08lx fault_addr=%08lx fault_host=%p guest_map_base=%p guest_offset=%08llx fault_state=%08lx fault_protect=%08lx access_kind=%08lx module_base=%08lx pc_rva=%08lx host_eax=%08lx host_ebx=%08lx host_ecx=%08lx host_edx=%08lx host_esi=%08lx host_edi=%08lx host_ebp=%08lx stack_return0=%08x stack_return4=%08x guest_func=%08x eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x ebp=%08x esp=%08x cs=%04x/%08x ds=%04x/%08x es=%04x/%08x fs=%04x/%08x gs=%04x/%08x ss=%04x/%08x mem_base=%p icall_count=%u icall_last=%08x icall_from=%08x trap_pending=%u trap_vector=%02x trap_va=%08x mem_pending=%u mem_segment=%u mem_selector=%04x mem_offset=%08x mem_width=%u mem_linear=%08x mem_instruction=%08x dpmi_dos_events=%u dpmi0100=%u dpmi0101=%u dpmi_last_req=%08x/%08x/%08x dpmi_last_rsp=%08x/%08x/%08x cf=%u\n",
        (unsigned long)record->ExceptionCode, (unsigned long)host_pc,
        (unsigned long)host_sp,
        (unsigned long)(record->NumberParameters > 1 ? record->ExceptionInformation[1] : 0),
        (void *)fault_address,(void *)map_base,(unsigned long long)guest_offset,
        (unsigned long)(fault_info_size==sizeof fault_info ? fault_info.State : 0u),
        (unsigned long)(fault_info_size==sizeof fault_info ? fault_info.Protect : 0u),
        (unsigned long)(record->NumberParameters > 0 ? record->ExceptionInformation[0] : 0),
        (unsigned long)module_base, (unsigned long)host_pc_rva,
        (unsigned long)host_eax, (unsigned long)host_ebx,
        (unsigned long)host_ecx, (unsigned long)host_edx,
        (unsigned long)host_esi, (unsigned long)host_edi,
        (unsigned long)host_ebp,
        stack_return0, stack_return4, g_cur_func, g_eax, g_ebx, g_ecx,
        g_edx, g_esi, g_edi, g_ebp, g_esp,
        g_seg_cs,g_cs_base,g_seg_ds,g_ds_base,g_seg_es,g_es_base,
        g_seg_fs,g_fs_base,g_seg_gs,g_gs_base,g_seg_ss,g_ss_base,(void *)g_mem_base,
        g_icall_count,
        g_icall_count ? g_icall_trace[slot] : 0, g_icall_count ? g_icall_from[slot] : 0,
        trap.pending, trap.vector, trap.instruction_va, fault.pending,
        fault.segment, fault.selector, fault.offset, fault.width, fault.linear,
        fault.instruction_va,
#if defined(GW_NATIVE_W1_092_HOST_BACKED_GUEST_MEMORY)
        native_dpmi_dos_memory_count,native_dpmi_dos_alloc_count,native_dpmi_dos_free_count,
        native_dpmi_dos_last_req_eax,native_dpmi_dos_last_req_ebx,native_dpmi_dos_last_req_edx,
        native_dpmi_dos_last_res_eax,native_dpmi_dos_last_res_ebx,native_dpmi_dos_last_res_edx,
        native_dpmi_dos_last_carry
#else
        0u,0u,0u,0u,0u,0u,0u,0u,0u,0u
#endif
        );
    fflush(stderr);
    return EXCEPTION_EXECUTE_HANDLER;
}

#ifdef GW_NATIVE_TEST_DOS_AH49
static int test_measured_ah49_contract(gw_dos_services *services) {
    g_eax=0x4800u; g_ebx=1u; g_ecx=0x8000u; g_edx=0u;
    g_flag_cf=0;
    if (gw_dos_services_callback(0x21u,0x000C3D21u,services)!=GW_INTERRUPT_HANDLED ||
        g_eax!=0x004cu || g_flag_cf) return 0;
    g_eax=0x494cu; g_ebx=0x80000008u; g_ecx=0x8000u; g_edx=0x4cu;
    g_esi=0x80000008u; g_edi=0x170u; g_ebp=0x10b4d0u; g_esp=0x1a8b04u;
    g_seg_es=0x004cu; g_flag_cf=1;
    if (gw_dos_services_callback(0x21u,0x000C3D46u,services)!=GW_INTERRUPT_HANDLED ||
        g_eax!=0x494cu || g_ebx!=0x80000008u || g_ecx!=0x8000u || g_edx!=0x4cu ||
        g_esi!=0x80000008u || g_edi!=0x170u || g_ebp!=0x10b4d0u ||
        g_esp!=0x1a8b04u || g_flag_cf) return 0;

    /* Re-arm the measured block and prove the divergent native ES=0x14 state
     * remains fail-closed instead of being accepted as the oracle's ES=0x4c. */
    g_eax=0x4800u; g_ebx=1u; g_ecx=0x8000u; g_edx=0u; g_flag_cf=0;
    if (gw_dos_services_callback(0x21u,0x000C3D21u,services)!=GW_INTERRUPT_HANDLED) return 0;
    g_eax=0x494cu; g_ebx=0x80000008u; g_ecx=0x8000u; g_edx=0x4cu;
    g_seg_es=0x0014u; g_flag_cf=1;
    if (gw_dos_services_callback(0x21u,0x000C3D46u,services)!=GW_INTERRUPT_TRAPPED ||
        g_eax!=0x494cu || g_ebx!=0x80000008u || g_ecx!=0x8000u ||
        g_edx!=0x4cu || !g_flag_cf) return 0;
    return 1;
}
#endif

static gw_interrupt_result native_dos_callback(uint8_t vector, uint32_t va, void *user) {
    gw_dos_services *services = (gw_dos_services *)user;
    if (vector==0x31u && ((uint16_t)g_eax==0x0600u ||
                         (uint16_t)g_eax==0x0601u))
        return gw_dos_services_callback(vector,va,services);
#if defined(GW_NATIVE_W1_092_HOST_BACKED_GUEST_MEMORY)
    if (vector==0x31u && ((uint16_t)g_eax==0x0100u || (uint16_t)g_eax==0x0101u)) {
        uint32_t req_eax=g_eax,req_ebx=g_ebx,req_edx=g_edx;
        uint16_t function=(uint16_t)g_eax;
        native_dpmi_dos_memory_count++;
        if (function==0x0100u) native_dpmi_dos_alloc_count++;
        else native_dpmi_dos_free_count++;
        gw_interrupt_result result=gw_dos_services_callback(vector,va,services);
        native_dpmi_dos_last_req_eax=req_eax; native_dpmi_dos_last_req_ebx=req_ebx;
        native_dpmi_dos_last_req_edx=req_edx; native_dpmi_dos_last_res_eax=g_eax;
        native_dpmi_dos_last_res_ebx=g_ebx; native_dpmi_dos_last_res_edx=g_edx;
        native_dpmi_dos_last_carry=g_flag_cf;
        if (native_dpmi_dos_memory_count<=8u || !g_flag_cf || function==0x0101u) {
            printf("NATIVE_DPMI_DOS_MEMORY ordinal=%u function=%04x request_eax=%08x request_ebx=%08x request_edx=%08x response_eax=%08x response_ebx=%08x response_edx=%08x cf=%u handled=%u selector_count=%u block_count=%u provider=gw_dos_services_callback\n",
                native_dpmi_dos_memory_count,function,req_eax,req_ebx,req_edx,g_eax,g_ebx,g_edx,
                (unsigned)g_flag_cf,(unsigned)(result==GW_INTERRUPT_HANDLED),
                services->descriptor_count,services->dos_block_count);
            fflush(stdout);
        }
        return result;
    }
    if (vector==0x21u && (va==0x000C3D21u || va==0x000C3D35u || va==0x000C3D46u))
        printf("NATIVE_DOS_AH48_DISPATCH eip=%08x eax=%08x ebx=%08x ecx=%08x edx=%08x first_seen=%u retry_seen=%u time_seen=%u\n",
            va,g_eax,g_ebx,g_ecx,g_edx,(unsigned)saw_dos_ah48,
            (unsigned)saw_dos_ah48_retry,(unsigned)saw_time_query);
#endif
#ifdef GW_NATIVE_CONTINUE_DPMI_LINEAR_SEQUENCE
    if (vector==0x31u && va==0x000C3CC1u && (uint16_t)g_eax==0x0501u)
        printf("NATIVE_W1_090_AX0501_DISPATCH_PROBE ah25_count=%u time_seen=%u eax=%08x ebx=%08x ecx=%08x\n",
               native_dos_ah25_count,(unsigned)saw_time_query,g_eax,g_ebx,g_ecx);
#endif
#ifdef GW_NATIVE_CAPTURE_W1_077_LIFECYCLE
    static uint32_t w1_077_event_ordinal;
    static uint32_t w1_077_ax4400_count;
    static uint32_t w1_077_context_printed;
    if (!w1_077_context_printed) {
        w1_077_context_printed=1u;
        printf("W1_077_PROCESS_CONTEXT model=single-native-guest harness_psp_selector=%04x harness_psp_linear=%08x\n",
               (unsigned)GW_BOOT_PSP_SELECTOR,(unsigned)GW_BOOT_PSP);
    }
    if (vector==0x21u && va==0x000C8973u && (uint16_t)g_eax==0x4400u)
        ++w1_077_ax4400_count;
    if (vector==0x21u && w1_077_ax4400_count<9u && w1_077_event_ordinal<32u) {
        uint8_t ah=(uint8_t)(g_eax>>8);
        const char *kind=ah==0x3du?"open":ah==0x3cu?"create":ah==0x3eu?"close":
                         ah==0x46u?"dup":ah==0x43u?"attributes":ah==0x5au?"temp_create":0;
        if (kind) {
            uint32_t handle_a=(ah==0x3eu || ah==0x46u)?g_ebx:0u;
            uint32_t handle_b=ah==0x46u?g_ecx:0u;
            uint32_t active_a=0u,active_b=0u;
            if (handle_a>=5u && handle_a<5u+GW_DOS_MAX_OPEN_FILES)
                active_a=services->files[handle_a-5u].active;
            if (handle_b>=5u && handle_b<5u+GW_DOS_MAX_OPEN_FILES)
                active_b=services->files[handle_b-5u].active;
            char path_hex[257]="";
            uint32_t path_length=0u,path_valid=0u,path_terminated=0u;
            if (ah==0x3du || ah==0x3cu || ah==0x43u || ah==0x5au) {
                uint64_t linear=(uint64_t)g_ds_base+g_edx;
                if (linear<GW_NATIVE_GUEST_MEMORY_SIZE) {
                    path_valid=1u;
                    static const char digits[]="0123456789abcdef";
                    while (path_length<128u && linear+path_length<GW_NATIVE_GUEST_MEMORY_SIZE) {
                        uint8_t ch=guest_memory[linear+path_length];
                        if (!ch) { path_terminated=1u; break; }
                        path_hex[path_length*2u]=digits[ch>>4];
                        path_hex[path_length*2u+1u]=digits[ch&15u];
                        ++path_length;
                    }
                    path_hex[path_length*2u]='\0';
                }
            }
            printf("W1_077_DOS_FILE_REQUEST ordinal=%u kind=%s eip=%08x caller=%08x psp_selector=%04x psp_linear=%08x eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x ebp=%08x esp=%08x flags_k=%08x flags_a=%08x flags_b=%08x cf=%u ds=%04x ds_base=%08x es=%04x ss=%04x path_valid=%u path_length=%u path_terminated=%u path_hex=%s handle_a=%08x handle_a_active=%u handle_b=%08x handle_b_active=%u\n",
                   w1_077_event_ordinal++,kind,va,g_cur_func,(unsigned)GW_BOOT_PSP_SELECTOR,
                   (unsigned)GW_BOOT_PSP,g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,
                   g_flag_k,g_flag_a,g_flag_b,g_flag_cf,g_seg_ds,g_ds_base,g_seg_es,g_seg_ss,
                   path_valid,path_length,path_terminated,path_hex,handle_a,active_a,handle_b,active_b);
        }
    }
    if (vector==0x21u && (uint8_t)(g_eax>>8)==0x46u) {
        uint32_t req_eax=g_eax,req_ebx=g_ebx,req_ecx=g_ecx;
        uint8_t req_cf=(uint8_t)g_flag_cf;
        gw_interrupt_result result=gw_dos_services_callback(vector,va,services);
        printf("W1_077_DOS_DUP_RESULT eip=%08x eax_in=%08x ebx_in=%08x ecx_in=%08x eax_out=%08x ebx_out=%08x ecx_out=%08x cf_in=%u cf_out=%u handled=%u\n",
               va,req_eax,req_ebx,req_ecx,g_eax,g_ebx,g_ecx,(unsigned)req_cf,
               (unsigned)g_flag_cf,(unsigned)(result==GW_INTERRUPT_HANDLED));
        return result;
    }
#endif
#ifdef GW_NATIVE_CAPTURE_W1_079_AX4400_HANDLE2
    if (vector==0x21u && va==0x000C8973u &&
        (uint16_t)g_eax==0x4400u && g_ebx==2u) {
        static uint32_t w1_079_event_count;
        if (!w1_079_event_count) {
            uint32_t req_eax=g_eax,req_ebx=g_ebx,req_ecx=g_ecx,req_edx=g_edx;
            uint32_t req_esi=g_esi,req_edi=g_edi,req_ebp=g_ebp,req_esp=g_esp;
            uint32_t req_flags_k=g_flag_k,req_flags_a=g_flag_a,req_flags_b=g_flag_b;
            uint32_t req_caller=g_cur_func,slot=GW_DOS_MAX_OPEN_FILES;
            const char *owner_name="unmapped";
            gw_interrupt_result result=GW_INTERRUPT_TRAPPED;
            uint8_t req_cf=(uint8_t)g_flag_cf;
            for (uint32_t i=0;i<GW_DOS_MAX_OPEN_FILES;i++) {
                if (services->files[i].active && services->files[i].dos_handle==2u &&
                    services->files[i].file) {
                    slot=i;
                    native_virtual_open *open=(native_virtual_open *)services->files[i].file;
                    if (open->owner==&native_gwerr_file) owner_name="gwerr";
                    else if (open->owner==&native_address_file) owner_name="address";
#ifdef GW_NATIVE_SERVE_W3_CONFIG
                    else if (open->owner==&native_w3_config_file) owner_name="config";
#endif
#ifdef GW_NATIVE_SERVE_W3_SOUND_INI
                    else if (open->owner==&native_w3_sound_ini_file) owner_name="sound_ini";
#endif
                    result=gw_dos_services_callback(vector,va,services);
                    break;
                }
            }
            printf("W1_079_AX4400_HANDLE2 ordinal=%u caller=%08x eip=%08x slot=%u mapping_active=%u owner=%s callback_invoked=%u eax_in=%08x ebx_in=%08x ecx_in=%08x edx_in=%08x esi_in=%08x edi_in=%08x ebp_in=%08x esp_in=%08x flags_k_in=%08x flags_a_in=%08x flags_b_in=%08x cf_in=%u cs=%04x ds=%04x es=%04x ss=%04x eax_out=%08x ebx_out=%08x ecx_out=%08x edx_out=%08x esi_out=%08x edi_out=%08x ebp_out=%08x esp_out=%08x flags_k_out=%08x flags_a_out=%08x flags_b_out=%08x cf_out=%u callback_handled=%u\n",
                w1_079_event_count++,req_caller,va,slot,
                slot<GW_DOS_MAX_OPEN_FILES && services->files[slot].active,
                owner_name,slot<GW_DOS_MAX_OPEN_FILES,
                req_eax,req_ebx,req_ecx,req_edx,req_esi,req_edi,req_ebp,req_esp,
                req_flags_k,req_flags_a,req_flags_b,req_cf,g_seg_cs,g_seg_ds,g_seg_es,g_seg_ss,
                g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,
                g_flag_k,g_flag_a,g_flag_b,g_flag_cf,result==GW_INTERRUPT_HANDLED);
            return result;
        }
    }
#endif
#ifdef GW_NATIVE_CAPTURE_W1_080_AX4400_ACTIVE_FILE
    if (vector==0x21u && va==0x000C8973u &&
        (uint16_t)g_eax==0x4400u && g_ebx==2u) {
        static uint32_t w1_080_event_count;
        if (w1_080_event_count<4u) {
            uint32_t req_eax=g_eax,req_ebx=g_ebx,req_ecx=g_ecx,req_edx=g_edx;
            uint32_t req_esi=g_esi,req_edi=g_edi,req_ebp=g_ebp,req_esp=g_esp;
            uint32_t req_flags_k=g_flag_k,req_flags_a=g_flag_a,req_flags_b=g_flag_b;
            uint32_t req_caller=g_cur_func,slot=GW_DOS_MAX_OPEN_FILES;
            const char *owner_name="unmapped";
            gw_interrupt_result result=GW_INTERRUPT_TRAPPED;
            uint8_t req_cf=(uint8_t)g_flag_cf;
            for (uint32_t i=0;i<GW_DOS_MAX_OPEN_FILES;i++) {
                if (services->files[i].active && services->files[i].dos_handle==2u &&
                    services->files[i].file) {
                    slot=i;
                    native_virtual_open *open=(native_virtual_open *)services->files[i].file;
                    if (open->owner==&native_gwerr_file) owner_name="gwerr";
                    else if (open->owner==&native_address_file) owner_name="address";
#ifdef GW_NATIVE_SERVE_W3_CONFIG
                    else if (open->owner==&native_w3_config_file) owner_name="config";
#endif
#ifdef GW_NATIVE_SERVE_W3_SOUND_INI
                    else if (open->owner==&native_w3_sound_ini_file) owner_name="sound_ini";
#endif
                    result=gw_dos_services_callback(vector,va,services);
                    break;
                }
            }
            printf("W1_080_AX4400_ACTIVE_FILE ordinal=%u caller=%08x eip=%08x slot=%u mapping_active=%u owner=%s callback_invoked=%u eax_in=%08x ebx_in=%08x ecx_in=%08x edx_in=%08x esi_in=%08x edi_in=%08x ebp_in=%08x esp_in=%08x flags_k_in=%08x flags_a_in=%08x flags_b_in=%08x cf_in=%u cs=%04x ds=%04x es=%04x ss=%04x eax_out=%08x ebx_out=%08x ecx_out=%08x edx_out=%08x esi_out=%08x edi_out=%08x ebp_out=%08x esp_out=%08x flags_k_out=%08x flags_a_out=%08x flags_b_out=%08x cf_out=%u callback_handled=%u\n",
                w1_080_event_count++,req_caller,va,slot,
                slot<GW_DOS_MAX_OPEN_FILES && services->files[slot].active,
                owner_name,slot<GW_DOS_MAX_OPEN_FILES,
                req_eax,req_ebx,req_ecx,req_edx,req_esi,req_edi,req_ebp,req_esp,
                req_flags_k,req_flags_a,req_flags_b,req_cf,g_seg_cs,g_seg_ds,g_seg_es,g_seg_ss,
                g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,
                g_flag_k,g_flag_a,g_flag_b,g_flag_cf,result==GW_INTERRUPT_HANDLED);
            return result;
        }
    }
#endif
#ifdef GW_NATIVE_CAPTURE_W1_081_AH40_ACTIVE_FILE
    if (vector==0x21u && va==0x000D219Cu &&
        (uint16_t)g_eax==0x4002u && g_ebx==2u) {
        static uint32_t w1_081_event_count;
        if (g_ecx<=64u && w1_081_event_count<2u) {
            uint32_t req_eax=g_eax,req_ebx=g_ebx,req_ecx=g_ecx,req_edx=g_edx;
            uint32_t req_esi=g_esi,req_edi=g_edi,req_ebp=g_ebp,req_esp=g_esp;
            uint32_t req_flags_k=g_flag_k,req_flags_a=g_flag_a,req_flags_b=g_flag_b;
            uint32_t req_caller=g_cur_func,slot=GW_DOS_MAX_OPEN_FILES;
            const char *owner_name="unmapped";
            gw_interrupt_result result=GW_INTERRUPT_TRAPPED;
            uint8_t req_cf=(uint8_t)g_flag_cf;
            uint32_t sample_len=req_ecx;
            uint64_t linear=(uint64_t)g_ds_base+(uint64_t)req_edx;
            uint32_t sample_valid=linear+sample_len<=GW_NATIVE_GUEST_MEMORY_SIZE;
            char sample_hex[129];
            sample_hex[0]='\0';
            if (sample_valid) {
                static const char digits[]="0123456789abcdef";
                for (uint32_t i=0;i<sample_len;i++) {
                    uint8_t byte=guest_memory[(size_t)linear+i];
                    sample_hex[i*2u]=digits[byte>>4];
                    sample_hex[i*2u+1u]=digits[byte&15u];
                }
                sample_hex[sample_len*2u]='\0';
            }
            for (uint32_t i=0;i<GW_DOS_MAX_OPEN_FILES;i++) {
                if (services->files[i].active && services->files[i].dos_handle==2u &&
                    services->files[i].file) {
                    slot=i;
                    native_virtual_open *open=(native_virtual_open *)services->files[i].file;
                    if (open->owner==&native_gwerr_file) owner_name="gwerr";
                    else if (open->owner==&native_address_file) owner_name="address";
#ifdef GW_NATIVE_SERVE_W3_CONFIG
                    else if (open->owner==&native_w3_config_file) owner_name="config";
#endif
#ifdef GW_NATIVE_SERVE_W3_SOUND_INI
                    else if (open->owner==&native_w3_sound_ini_file) owner_name="sound_ini";
#endif
                    if (sample_valid) result=gw_dos_services_callback(vector,va,services);
                    break;
                }
            }
            printf("W1_081_AH40_ACTIVE_FILE ordinal=%u caller=%08x eip=%08x slot=%u mapping_active=%u owner=%s callback_invoked=%u eax_in=%08x ebx_in=%08x ecx_in=%08x edx_in=%08x esi_in=%08x edi_in=%08x ebp_in=%08x esp_in=%08x flags_k_in=%08x flags_a_in=%08x flags_b_in=%08x cf_in=%u cs=%04x ds=%04x es=%04x ss=%04x sample_valid=%u sample_length=%u sample_hex=%s eax_out=%08x ebx_out=%08x ecx_out=%08x edx_out=%08x esi_out=%08x edi_out=%08x ebp_out=%08x esp_out=%08x flags_k_out=%08x flags_a_out=%08x flags_b_out=%08x cf_out=%u callback_handled=%u\n",
                w1_081_event_count++,req_caller,va,slot,
                slot<GW_DOS_MAX_OPEN_FILES && services->files[slot].active,
                owner_name,slot<GW_DOS_MAX_OPEN_FILES,
                req_eax,req_ebx,req_ecx,req_edx,req_esi,req_edi,req_ebp,req_esp,
                req_flags_k,req_flags_a,req_flags_b,req_cf,g_seg_cs,g_seg_ds,g_seg_es,g_seg_ss,
                sample_valid,sample_len,sample_hex,g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,
                g_flag_k,g_flag_a,g_flag_b,g_flag_cf,result==GW_INTERRUPT_HANDLED);
            return result;
        }
        return GW_INTERRUPT_TRAPPED;
    }
#endif
#ifdef GW_NATIVE_STOP_AT_FIRST_AX0501
    if (vector==0x31u && va==0x000C3CC1u && (uint16_t)g_eax==0x0501u) {
        uint32_t stack[8]={0};
        uint32_t valid=(g_esp<=GW_NATIVE_GUEST_MEMORY_SIZE-sizeof stack);
        if (valid) memcpy(stack,guest_memory+g_esp,sizeof stack);
        printf("NATIVE_DPMI_AX0501_STRICT_FRONTIER ordinal=0 vector=%02x eip=%08x caller_func=%08x eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x ebp=%08x esp=%08x flag_k=%08x flag_a=%08x flag_b=%08x cf=%u cs=%04x ds=%04x es=%04x fs=%04x gs=%04x ss=%04x valid=%u",
               vector,va,g_cur_func,g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,
               g_flag_k,g_flag_a,g_flag_b,g_flag_cf,g_seg_cs,g_seg_ds,g_seg_es,g_seg_fs,g_seg_gs,g_seg_ss,valid);
        for (uint32_t i=0;i<8u;++i) printf(" stack%u=%08x",i,stack[i]);
        printf(" response_count=0\n");
        return GW_INTERRUPT_TRAPPED;
    }
#endif
#ifdef GW_NATIVE_CAPTURE_CRT_STARTUP
    if (vector==0x21u && va==0x000C8973u && (uint16_t)g_eax==0x4400u) {
        uint32_t s0=(g_esp<GW_NATIVE_GUEST_MEMORY_SIZE-4u)?*(uint32_t *)(guest_memory+g_esp):0;
        uint32_t s1=(g_esp+4u<GW_NATIVE_GUEST_MEMORY_SIZE-4u)?*(uint32_t *)(guest_memory+g_esp+4u):0;
        uint32_t s2=(g_esp+8u<GW_NATIVE_GUEST_MEMORY_SIZE-4u)?*(uint32_t *)(guest_memory+g_esp+8u):0;
        uint32_t s3=(g_esp+12u<GW_NATIVE_GUEST_MEMORY_SIZE-4u)?*(uint32_t *)(guest_memory+g_esp+12u):0;
        char sample_hex[65]="";
        uint32_t sample_length=0;
        uint32_t sample_valid=0;
        if ((uint16_t)g_ebx==1u && w1_ah44_bx1_sample_count==0u &&
            g_edx<=GW_NATIVE_GUEST_MEMORY_SIZE && 32u<=GW_NATIVE_GUEST_MEMORY_SIZE-g_edx) {
            static const char digits[]="0123456789abcdef";
            const uint8_t *sample=guest_memory+g_edx;
            for (uint32_t i=0;i<32u;++i) {
                sample_hex[i*2u]=digits[sample[i]>>4];
                sample_hex[i*2u+1u]=digits[sample[i]&15u];
            }
            sample_hex[64]='\0';
            sample_length=32u;
            sample_valid=1u;
            ++w1_ah44_bx1_sample_count;
        }
        printf("W1_AH44_REQUEST ordinal=%u cs=%04x eip=%08x caller_func=%08x eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x ebp=%08x esp=%08x flags_k=%u flags_a=%08x flags_b=%08x cf=%u ds=%04x ds_base=%08x es=%04x ss=%04x stack0=%08x stack1=%08x stack2=%08x stack3=%08x helper_ordinal=%u sample_address=%08x sample_valid=%u sample_length=%u sample_hex=%s\n",
               w1_ah44_request_ordinal++,g_seg_cs,va,g_cur_func,g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,
               g_flag_k,g_flag_a,g_flag_b,g_flag_cf,g_seg_ds,g_ds_base,g_seg_es,g_seg_ss,s0,s1,s2,s3,
               w1_ah44_helper_entry_ordinal-1u,g_edx,sample_valid,sample_length,sample_hex);
    }
#endif
    /* Keep the default probe bounded to one response. The opt-in frontier
     * probe also serves the exact DOS/4G install check already measured by
     * the original entry trace, then traps at the next request. */
#ifndef GW_NATIVE_CONTINUE_KNOWN
    if (saw_first_version_service) return GW_INTERRUPT_TRAPPED;
#endif
#ifdef GW_NATIVE_CAPTURE_CRT_STARTUP
    /* Bounded synthetic success for allocations requested by early CRT
     * initializers. Request sizes come from guest registers; no measured
     * size/base/handle is injected. The regular later AX=0501 gate remains
     * independently checked by the existing success-frontier assertions. */
    if (
#ifdef GW_NATIVE_CONTINUE_DPMI_LINEAR_SEQUENCE
        native_dos_ah25_count==0u &&
#else
        !saw_time_query &&
#endif
        vector==0x31u && va==0x000C3CC1u &&
        (uint16_t)g_eax==0x0501u) {
        if (w1_crt_alloc_count>=32u) return GW_INTERRUPT_TRAPPED;
        uint32_t req_eax=g_eax,req_ebx=g_ebx,req_ecx=g_ecx,req_edx=g_edx;
        uint32_t req_esi=g_esi,req_edi=g_edi,req_ebp=g_ebp,req_esp=g_esp;
        uint32_t size=((req_ebx&0xffffu)<<16)|(req_ecx&0xffffu);
        gw_interrupt_result result=gw_dos_services_callback(vector,va,services);
        uint32_t base=((g_ebx&0xffffu)<<16)|(g_ecx&0xffffu);
        uint32_t handle=((g_esi&0xffffu)<<16)|(g_edi&0xffffu);
        if (result!=GW_INTERRUPT_HANDLED || g_flag_cf || g_eax!=req_eax || !size || !handle ||
            base<0x00200000u || base>GW_NATIVE_GUEST_MEMORY_SIZE || size>GW_NATIVE_GUEST_MEMORY_SIZE-base ||
            g_edx!=req_edx || g_ebp!=req_ebp || g_esp!=req_esp) return GW_INTERRUPT_TRAPPED;
        if (!native_guest_memory_zero_sample(base,size)) return GW_INTERRUPT_TRAPPED;
        uint32_t n=w1_crt_alloc_count++;
        w1_crt_allocs[n].req_eax=req_eax; w1_crt_allocs[n].req_ebx=req_ebx;
        w1_crt_allocs[n].req_ecx=req_ecx; w1_crt_allocs[n].req_edx=req_edx;
        w1_crt_allocs[n].res_eax=g_eax; w1_crt_allocs[n].res_ebx=g_ebx;
        w1_crt_allocs[n].res_ecx=g_ecx; w1_crt_allocs[n].res_edx=g_edx;
        w1_crt_allocs[n].res_esi=g_esi; w1_crt_allocs[n].res_edi=g_edi;
        w1_crt_allocs[n].size=size; w1_crt_allocs[n].base=base; w1_crt_allocs[n].handle=handle;
        (void)req_esi; (void)req_edi;
        return result;
    }
#ifdef GW_NATIVE_CONTINUE_DPMI_AX6300
    /* Original-byte W2-047 records this exact DPMI 0300 -> INT 2Fh AX=1500,
     * BX=0 request and its empty-inventory response AX=1500, BX=CX=0.
     * Validate the guest frame before delegating; other multiplex requests
     * remain trapped. */
    if (vector==0x31u && va==0x000D23A7u &&
        (uint16_t)g_eax==0x0300u) {
        uint64_t frame64=(uint64_t)g_es_base+(uint64_t)g_edi;
        if (frame64>GW_NATIVE_GUEST_MEMORY_SIZE-0x32u)
            return GW_INTERRUPT_TRAPPED;
        uint32_t frame=(uint32_t)frame64;
        if ((g_ebx&0xffffu)!=0x002fu || (g_ecx&0xffffu)!=0u ||
            *(uint32_t *)(guest_memory+frame+0x1cu)!=0x00001500u ||
            *(uint32_t *)(guest_memory+frame+0x10u)!=0u)
            return GW_INTERRUPT_TRAPPED;
        gw_interrupt_result result=gw_dos_services_callback(vector,va,services);
        gw_dos_real_mode_registers inner;
        memcpy(&inner,guest_memory+frame,sizeof inner);
        printf("NATIVE_DPMI0300_INT2F1500 eip=%08x frame=%08x outer_ebx=%08x outer_ecx=%08x inner_eax=%08x inner_ebx=%08x inner_ecx=%08x inner_flags=%04x handled=%u cf=%u inventory_drives=0 source=original_byte_w2_047\n",
            va,frame,g_ebx,g_ecx,inner.eax,inner.ebx,inner.ecx,inner.flags,
            (unsigned)(result==GW_INTERRUPT_HANDLED),(unsigned)g_flag_cf);
        if (result!=GW_INTERRUPT_HANDLED || (uint16_t)inner.eax!=0x1500u ||
            (uint16_t)inner.ebx!=0u || (uint16_t)inner.ecx!=0u ||
            (inner.flags&1u) || g_flag_cf) return GW_INTERRUPT_TRAPPED;
        return result;
    }
    /* Only the measured INT 21h AX=6300 frame is delegated. The provider
     * allocates a guest real-mode block and returns DS:SI to its 12-byte
     * DBCS table; the captured original segment is never reused. */
    if (vector==0x31u && va==0x000BC765u && (uint16_t)g_eax==0x0300u) {
        uint32_t frame=g_es_base+g_edi;
        uint32_t frame_valid=frame<=GW_NATIVE_GUEST_MEMORY_SIZE-0x32u;
        if ((g_ebx&0xffu)!=0x21u || (g_ebx>>8)!=0 || (g_ecx&0xffffu)!=0 ||
            !frame_valid || *(uint32_t *)(guest_memory+frame+0x1cu)!=0x00006300u)
            return GW_INTERRUPT_TRAPPED;
        uint8_t before[0x32u],after[0x32u];
        memcpy(before,guest_memory+frame,sizeof before);
        gw_interrupt_result result=gw_dos_services_callback(vector,va,services);
        memcpy(after,guest_memory+frame,sizeof after);
        gw_dos_real_mode_registers inner;
        memcpy(&inner,after,sizeof inner);
        uint32_t table_linear=((uint32_t)inner.ds<<4)+(inner.esi&0xffffu);
        uint32_t table_valid=table_linear==native_ax6300_state.linear &&
            table_linear<=GW_NATIVE_GUEST_MEMORY_SIZE &&
            NATIVE_AX6300_DBCS_TABLE_SIZE<=GW_NATIVE_GUEST_MEMORY_SIZE-table_linear;
        uint32_t table_zero=table_valid;
        if (table_valid) for (uint32_t i=0;i<NATIVE_AX6300_DBCS_TABLE_SIZE;i++)
            if (guest_memory[table_linear+i]) table_zero=0;
        static const char hex[]="0123456789abcdef";
        char before_hex[sizeof before*2u+1u],after_hex[sizeof after*2u+1u];
        for (uint32_t i=0;i<sizeof before;i++) {
            before_hex[i*2u]=hex[before[i]>>4]; before_hex[i*2u+1u]=hex[before[i]&15u];
            after_hex[i*2u]=hex[after[i]>>4]; after_hex[i*2u+1u]=hex[after[i]&15u];
        }
        before_hex[sizeof before*2u]=0; after_hex[sizeof after*2u]=0;
        printf("NATIVE_DPMI0300_AX6300 ordinal=%u caller=%08x eip=%08x vector=%02x outer_eax=%08x outer_ebx=%08x outer_ecx=%08x outer_edx=%08x outer_esi=%08x outer_edi=%08x outer_ebp=%08x outer_esp=%08x cf_in=%u frame=%08x frame_before=%s frame_after=%s result=%u inner_eax=%08x inner_ds=%04x inner_si=%04x inner_cf=%u table_linear=%08x table_size=%u table_zero=%u alloc_segment=%04x alloc_selector=%04x alloc_calls=%u dos_cursor=%04x\n",
            w1_crt_dpmi0300_count+1u,g_cur_func,va,vector,g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,g_flag_cf,
            frame,before_hex,after_hex,(unsigned)result,inner.eax,inner.ds,(uint16_t)inner.esi,inner.flags&1u,
            table_linear,NATIVE_AX6300_DBCS_TABLE_SIZE,table_zero,native_ax6300_state.segment,
            native_ax6300_state.selector,native_ax6300_state.calls,services->dos_segment_cursor);
        if (result!=GW_INTERRUPT_HANDLED || !table_zero || (inner.flags&1u) ||
            (uint16_t)inner.eax!=0x6300u || (uint16_t)inner.esi!=0u) return GW_INTERRUPT_TRAPPED;
        w1_crt_dpmi0300_count++;
        w1_crt_dpmi0300_frame=frame;
        w1_crt_dpmi0300_inner_eax=inner.eax;
        w1_crt_dpmi0300_inner_ds=inner.ds;
        w1_crt_dpmi0300_inner_si=(uint16_t)inner.esi;
        return result;
    }
#endif
#endif
#ifdef GW_NATIVE_CONTINUE_DOS_AH48
    if (saw_dos_ah48 && !saw_dos_ah48_retry && vector == 0x21 &&
        va == 0x000C3D35u && (uint8_t)(g_eax >> 8) == 0x48u) {
        dos48r_req_eax=g_eax; dos48r_req_ebx=g_ebx; dos48r_req_ecx=g_ecx;
        dos48r_req_edx=g_edx; dos48r_req_esi=g_esi; dos48r_req_edi=g_edi;
        dos48r_req_ebp=g_ebp; dos48r_req_esp=g_esp;
#if defined(GW_NATIVE_W1_092_HOST_BACKED_GUEST_MEMORY)
        if (!g_ebx) return GW_INTERRUPT_TRAPPED;
        printf("NATIVE_DOS_AH48_REQUEST ordinal=2 eip=%08x request_eax=%08x request_ebx=%08x request_ecx=%08x request_edx=%08x first_seen=%u retry_seen=%u\n",
            va,g_eax,g_ebx,g_ecx,g_edx,(unsigned)saw_dos_ah48,(unsigned)saw_dos_ah48_retry);
#else
        if (g_eax != 0x0000484cu || g_ebx != 0x00000800u || g_ecx != 0x00008000u || g_edx != 0x0000004cu)
            return GW_INTERRUPT_TRAPPED;
#endif
        gw_interrupt_result result=gw_dos_services_callback(vector,va,services);
        dos48r_res_eax=g_eax; dos48r_res_ebx=g_ebx; dos48r_res_ecx=g_ecx;
        dos48r_res_edx=g_edx; dos48r_res_esi=g_esi; dos48r_res_edi=g_edi;
        dos48r_res_ebp=g_ebp; dos48r_res_esp=g_esp; dos48r_res_carry=(uint8_t)g_flag_cf;
#if defined(GW_NATIVE_W1_092_HOST_BACKED_GUEST_MEMORY)
        printf("NATIVE_DOS_AH48 ordinal=2 request_eax=%08x request_ebx=%08x request_ecx=%08x request_edx=%08x response_eax=%08x response_ebx=%08x cf=%u handled=%u provider=guest_mcb\n",
            dos48r_req_eax,dos48r_req_ebx,dos48r_req_ecx,dos48r_req_edx,
            g_eax,g_ebx,(unsigned)g_flag_cf,(unsigned)(result==GW_INTERRUPT_HANDLED));
        fflush(stdout);
        if (result==GW_INTERRUPT_HANDLED && !g_flag_cf && g_eax &&
            g_eax>=services->dos_segment_begin &&
            (uint32_t)g_eax+(uint32_t)dos48r_req_ebx<=services->dos_segment_end)
            saw_dos_ah48_retry=1;
        else if (result==GW_INTERRUPT_HANDLED && g_flag_cf &&
            (uint16_t)g_eax==8u && (uint16_t)g_ebx<=(uint16_t)dos48r_req_ebx &&
            g_ecx==dos48r_req_ecx && g_edx==dos48r_req_edx &&
            g_esi==dos48r_req_esi && g_edi==dos48r_req_edi &&
            g_ebp==dos48r_req_ebp && g_esp==dos48r_req_esp)
            /* The MCB provider's real insufficient-memory result is part of
             * the guest execution. Let GeneWars consume AX=8/CF=1 and choose
             * its own error path instead of stopping at the service edge. */
            saw_dos_ah48_retry=1;
        else return GW_INTERRUPT_TRAPPED;
#else
        if (result==GW_INTERRUPT_HANDLED && g_eax==8u && g_ebx==0x34u && g_flag_cf==1 &&
            g_ecx==dos48r_req_ecx && g_edx==dos48r_req_edx && g_esi==dos48r_req_esi &&
            g_edi==dos48r_req_edi && g_ebp==dos48r_req_ebp && g_esp==dos48r_req_esp)
            saw_dos_ah48_retry=1;
#endif
        return result;
    }
    if (
#if defined(GW_NATIVE_W1_092_HOST_BACKED_GUEST_MEMORY)
        saw_time_query &&
#else
        saw_dpmi_linear_alloc &&
#endif
        !saw_dos_ah48 && vector == 0x21 &&
        va == 0x000C3D21u && (uint8_t)(g_eax >> 8) == 0x48u) {
        dos48_req_eax=g_eax; dos48_req_ebx=g_ebx; dos48_req_ecx=g_ecx;
        dos48_req_edx=g_edx; dos48_req_esi=g_esi; dos48_req_edi=g_edi;
        dos48_req_ebp=g_ebp; dos48_req_esp=g_esp;
#if defined(GW_NATIVE_W1_092_HOST_BACKED_GUEST_MEMORY)
        if (!g_ebx) return GW_INTERRUPT_TRAPPED;
#else
        if (g_eax != 0x00004800u || g_ebx != 1u || g_ecx != 0x00008000u || g_edx != 0u)
            return GW_INTERRUPT_TRAPPED;
#endif
        gw_interrupt_result result=gw_dos_services_callback(vector,va,services);
        dos48_res_eax=g_eax; dos48_res_ebx=g_ebx; dos48_res_ecx=g_ecx;
        dos48_res_edx=g_edx; dos48_res_esi=g_esi; dos48_res_edi=g_edi;
        dos48_res_ebp=g_ebp; dos48_res_esp=g_esp; dos48_res_carry=(uint8_t)g_flag_cf;
#if defined(GW_NATIVE_W1_092_HOST_BACKED_GUEST_MEMORY)
        printf("NATIVE_DOS_AH48 ordinal=1 request_eax=%08x request_ebx=%08x request_ecx=%08x request_edx=%08x response_eax=%08x response_ebx=%08x cf=%u handled=%u provider=guest_mcb\n",
            dos48_req_eax,dos48_req_ebx,dos48_req_ecx,dos48_req_edx,
            g_eax,g_ebx,(unsigned)g_flag_cf,(unsigned)(result==GW_INTERRUPT_HANDLED));
        fflush(stdout);
        if (result==GW_INTERRUPT_HANDLED && !g_flag_cf && g_eax &&
            g_eax>=services->dos_segment_begin &&
            (uint32_t)g_eax+(uint32_t)dos48_req_ebx<=services->dos_segment_end)
            saw_dos_ah48=1;
        else if (result!=GW_INTERRUPT_HANDLED || g_flag_cf) return GW_INTERRUPT_TRAPPED;
#else
        if (result==GW_INTERRUPT_HANDLED && g_eax==0x0000004cu && !g_flag_cf &&
            g_ebx==dos48_req_ebx && g_ecx==dos48_req_ecx && g_edx==dos48_req_edx &&
            g_esi==dos48_req_esi && g_edi==dos48_req_edi && g_ebp==dos48_req_ebp &&
            g_esp==dos48_req_esp) saw_dos_ah48=1;
#endif
        return result;
    }
#endif
#ifdef GW_NATIVE_CONTINUE_DPMI_LINEAR
    if (saw_time_query && !saw_dpmi_linear_alloc && vector == 0x31 &&
        va == 0x000C3CC1u && (uint16_t)g_eax == 0x0501u) {
        alloc_req_eax=g_eax; alloc_req_ebx=g_ebx; alloc_req_ecx=g_ecx;
        alloc_req_edx=g_edx; alloc_req_esi=g_esi; alloc_req_edi=g_edi;
        alloc_req_ebp=g_ebp; alloc_req_esp=g_esp;
        alloc_req_flag_k=g_flag_k; alloc_req_flag_a=g_flag_a;
        alloc_req_flag_b=g_flag_b; alloc_req_flag_cf=g_flag_cf;
        alloc_req_cs=g_seg_cs; alloc_req_ds=g_seg_ds;
        alloc_req_es=g_seg_es; alloc_req_ss=g_seg_ss;
        alloc_req_cs_base=g_cs_base; alloc_req_ds_base=g_ds_base;
        alloc_req_es_base=g_es_base; alloc_req_ss_base=g_ss_base;
        for (unsigned i=0;i<8;i++) {
            uint32_t address=g_esp+i*4u;
            alloc_stack_words[i]=address+4u<=GW_NATIVE_GUEST_MEMORY_SIZE ?
                *(uint32_t *)(guest_memory+address) : 0xffffffffu;
        }
        if (g_eax != 0x00000501u ||
            (((g_ebx & 0xffffu) << 16) | (g_ecx & 0xffffu)) == 0u || g_edx != 0u)
            return GW_INTERRUPT_TRAPPED;
        gw_interrupt_result result=gw_dos_services_callback(vector,va,services);
        alloc_res_eax=g_eax; alloc_res_ebx=g_ebx; alloc_res_ecx=g_ecx;
        alloc_res_edx=g_edx; alloc_res_esi=g_esi; alloc_res_edi=g_edi;
        alloc_res_ebp=g_ebp; alloc_res_esp=g_esp; alloc_res_carry=(uint8_t)g_flag_cf;
        if (result==GW_INTERRUPT_HANDLED && g_eax==0x00008012u && g_ebx==0u &&
            g_ecx==0x00008000u && g_edx==0u && g_esi==alloc_req_esi &&
            g_edi==alloc_req_edi && g_ebp==alloc_req_ebp && g_esp==alloc_req_esp &&
            g_flag_cf==1 && g_flag_k==alloc_req_flag_k && g_flag_a==alloc_req_flag_a &&
            g_flag_b==alloc_req_flag_b && g_seg_cs==alloc_req_cs && g_seg_ds==alloc_req_ds &&
            g_seg_es==alloc_req_es && g_seg_ss==alloc_req_ss && g_cs_base==alloc_req_cs_base &&
            g_ds_base==alloc_req_ds_base && g_es_base==alloc_req_es_base && g_ss_base==alloc_req_ss_base)
            saw_dpmi_linear_alloc=1;
        return result;
    }
#endif
#if defined(GW_NATIVE_CONTINUE_DPMI_LINEAR_SUCCESS) && !defined(GW_NATIVE_CONTINUE_DPMI_LINEAR_SEQUENCE)
    if (saw_time_query && !saw_dpmi_linear_alloc && vector == 0x31 &&
        va == 0x000C3CC1u && (uint16_t)g_eax == 0x0501u) {
        alloc_req_eax=g_eax; alloc_req_ebx=g_ebx; alloc_req_ecx=g_ecx;
        alloc_req_edx=g_edx; alloc_req_esi=g_esi; alloc_req_edi=g_edi;
        alloc_req_ebp=g_ebp; alloc_req_esp=g_esp;
        alloc_req_flag_k=g_flag_k; alloc_req_flag_a=g_flag_a;
        alloc_req_flag_b=g_flag_b; alloc_req_flag_cf=g_flag_cf;
        alloc_req_cs=g_seg_cs; alloc_req_ds=g_seg_ds;
        alloc_req_es=g_seg_es; alloc_req_ss=g_seg_ss;
        alloc_req_cs_base=g_cs_base; alloc_req_ds_base=g_ds_base;
        alloc_req_es_base=g_es_base; alloc_req_ss_base=g_ss_base;
        for (unsigned i=0;i<8;i++) {
            uint32_t address=g_esp+i*4u;
            alloc_stack_words[i]=address+4u<=GW_NATIVE_GUEST_MEMORY_SIZE ?
                *(uint32_t *)(guest_memory+address) : 0xffffffffu;
        }
        if (g_eax != 0x00000501u ||
            (((g_ebx & 0xffffu) << 16) | (g_ecx & 0xffffu)) == 0u || g_edx != 0u)
            return GW_INTERRUPT_TRAPPED;
        gw_interrupt_result result=gw_dos_services_callback(vector,va,services);
        alloc_res_eax=g_eax; alloc_res_ebx=g_ebx; alloc_res_ecx=g_ecx;
        alloc_res_edx=g_edx; alloc_res_esi=g_esi; alloc_res_edi=g_edi;
        alloc_res_ebp=g_ebp; alloc_res_esp=g_esp; alloc_res_carry=(uint8_t)g_flag_cf;
        alloc_success_base=((g_ebx & 0xffffu)<<16)|(g_ecx & 0xffffu);
        alloc_success_size=((alloc_req_ebx & 0xffffu)<<16)|(alloc_req_ecx & 0xffffu);
        alloc_success_handle=((g_esi & 0xffffu)<<16)|(g_edi & 0xffffu);
        if (result==GW_INTERRUPT_HANDLED && !g_flag_cf && g_eax==alloc_req_eax &&
            alloc_success_size && alloc_success_handle &&
            alloc_success_base>=0x00200000u &&
            alloc_success_base<=GW_NATIVE_GUEST_MEMORY_SIZE &&
            alloc_success_size<=GW_NATIVE_GUEST_MEMORY_SIZE-alloc_success_base &&
            g_edx==alloc_req_edx && g_ebp==alloc_req_ebp && g_esp==alloc_req_esp &&
            g_flag_k==alloc_req_flag_k && g_flag_a==alloc_req_flag_a &&
            g_flag_b==alloc_req_flag_b && g_seg_cs==alloc_req_cs &&
            g_seg_ds==alloc_req_ds && g_seg_es==alloc_req_es && g_seg_ss==alloc_req_ss &&
            g_cs_base==alloc_req_cs_base && g_ds_base==alloc_req_ds_base &&
            g_es_base==alloc_req_es_base && g_ss_base==alloc_req_ss_base) {
            int zero_filled=1;
            for (uint32_t i=0;i<alloc_success_size;i++)
                if (guest_memory[alloc_success_base+i] != 0) { zero_filled=0; break; }
            if (zero_filled) saw_dpmi_linear_alloc=1;
        }
        return result;
    }
#endif
#ifdef GW_NATIVE_CONTINUE_DPMI_LINEAR_SEQUENCE
    if (native_dos_ah25_count>0u && vector==0x31u && va==0x000C3CC1u &&
        (uint16_t)g_eax==0x0501u) {
#if defined(GW_NATIVE_W1_092_HOST_BACKED_GUEST_MEMORY)
        /* LbMemorySetup_ descends through 4096 page-size candidates after a
         * failed expansion. Add a full 32-bit guest-map allocation budget for
         * repeated successful heaps; this is a safety ceiling, not a reply. */
        if (w1_090_dpmi_sequence_count>=8192u) return GW_INTERRUPT_TRAPPED;
#else
        if (w1_090_dpmi_sequence_failed || w1_090_dpmi_sequence_count>=16u)
            return GW_INTERRUPT_TRAPPED;
#endif
        uint32_t req_eax=g_eax,req_ebx=g_ebx,req_ecx=g_ecx,req_edx=g_edx;
        uint32_t req_esi=g_esi,req_edi=g_edi,req_ebp=g_ebp,req_esp=g_esp;
        uint32_t req_flag_k=g_flag_k,req_flag_a=g_flag_a,req_flag_b=g_flag_b;
        uint32_t req_cs=g_seg_cs,req_ds=g_seg_ds,req_es=g_seg_es,req_ss=g_seg_ss;
        uint32_t req_cs_base=g_cs_base,req_ds_base=g_ds_base;
        uint32_t req_es_base=g_es_base,req_ss_base=g_ss_base;
        uint32_t size=((req_ebx&0xffffu)<<16)|(req_ecx&0xffffu);
        uint32_t cursor_before=services->allocation_cursor;
        if (req_eax!=0x00000501u || !size || req_edx!=0u)
            return GW_INTERRUPT_TRAPPED;
        gw_interrupt_result result=gw_dos_services_callback(vector,va,services);
        uint32_t res_eax=g_eax,res_ebx=g_ebx,res_ecx=g_ecx,res_edx=g_edx;
        uint32_t res_esi=g_esi,res_edi=g_edi,res_ebp=g_ebp,res_esp=g_esp;
        uint32_t res_flag_k=g_flag_k,res_flag_a=g_flag_a,res_flag_b=g_flag_b;
        uint32_t carry=(uint32_t)g_flag_cf,cursor_after=services->allocation_cursor;
        uint32_t base=((res_ebx&0xffffu)<<16)|(res_ecx&0xffffu);
        uint32_t handle=((res_esi&0xffffu)<<16)|(res_edi&0xffffu);
        int preserved=(res_edx==req_edx && res_ebp==req_ebp && res_esp==req_esp &&
            res_flag_k==req_flag_k && res_flag_a==req_flag_a && res_flag_b==req_flag_b &&
            g_seg_cs==req_cs && g_seg_ds==req_ds && g_seg_es==req_es && g_seg_ss==req_ss &&
            g_cs_base==req_cs_base && g_ds_base==req_ds_base &&
            g_es_base==req_es_base && g_ss_base==req_ss_base &&
            (res_ebx&0xffff0000u)==(req_ebx&0xffff0000u) &&
            (res_ecx&0xffff0000u)==(req_ecx&0xffff0000u) &&
            (res_esi&0xffff0000u)==(req_esi&0xffff0000u) &&
            (res_edi&0xffff0000u)==(req_edi&0xffff0000u));
        int success=(result==GW_INTERRUPT_HANDLED && !carry && res_eax==req_eax &&
            preserved && handle && base>=0x00200000u && base<GW_NATIVE_GUEST_MEMORY_SIZE &&
            size<=GW_NATIVE_GUEST_MEMORY_SIZE-base && services->guest_memory_configured &&
            services->guest_memory_size==GW_NATIVE_GUEST_MEMORY_SIZE && cursor_after==base+size);
        int unavailable=(result==GW_INTERRUPT_HANDLED && carry &&
            (res_eax&0xffffu)==0x8012u && (res_eax&0xffff0000u)==(req_eax&0xffff0000u) &&
            preserved && res_ebx==req_ebx && res_ecx==req_ecx &&
            res_esi==req_esi && res_edi==req_edi && cursor_after==cursor_before);
        int zero_filled=success;
#if defined(GW_NATIVE_W1_092_HOST_BACKED_GUEST_MEMORY)
        /* MEM_COMMIT is zero-initialized by Windows; confirm range endpoints
         * while the OS guarantee covers untouched interior pages. */
        if (success) zero_filled=native_guest_memory_zero_sample(base,size);
#else
        if (success) for (uint32_t i=0;i<size;i++)
            if (guest_memory[base+i]!=0) { zero_filled=0; break; }
#endif
        /* Keep every success and a bounded failure sample.  The full callback
         * count remains encoded by the terminal ordinal; printing thousands
         * of identical 4 KiB retry failures slowed the interpreted guest. */
        if (success || (w1_090_dpmi_sequence_count%256u)==0u ||
            (unavailable && size==0x00010000u))
            printf("NATIVE_DPMI_AX0501_SEQUENCE ordinal=%u vector=%02x eip=%08x request_eax=%08x request_ebx=%08x request_ecx=%08x request_edx=%08x request_esi=%08x request_edi=%08x request_ebp=%08x request_esp=%08x response_eax=%08x response_ebx=%08x response_ecx=%08x response_edx=%08x response_esi=%08x response_edi=%08x response_ebp=%08x response_esp=%08x request_flag_k=%08x response_flag_k=%08x request_flag_a=%08x response_flag_a=%08x request_flag_b=%08x response_flag_b=%08x carry=%u handled=%u cursor_before=%08x cursor_after=%08x size=%08x base=%08x handle=%08x guest_capacity=%08x success=%u unavailable=%u zero_filled=%u preserved=%u provider=gw_dos_services_callback arena=%s\n",
                w1_090_dpmi_sequence_count,vector,va,req_eax,req_ebx,req_ecx,req_edx,
                req_esi,req_edi,req_ebp,req_esp,res_eax,res_ebx,res_ecx,res_edx,
                res_esi,res_edi,res_ebp,res_esp,req_flag_k,res_flag_k,req_flag_a,res_flag_a,
                req_flag_b,res_flag_b,carry,(unsigned)(result==GW_INTERRUPT_HANDLED),
                cursor_before,cursor_after,size,success?base:0u,success?handle:0u,
                (uint32_t)GW_NATIVE_GUEST_MEMORY_SIZE,(unsigned)success,(unsigned)unavailable,
                (unsigned)zero_filled,(unsigned)preserved,GW_NATIVE_DPMI_ARENA_LABEL);
        if (!success && !unavailable) return GW_INTERRUPT_TRAPPED;
        if (success && !zero_filled) return GW_INTERRUPT_TRAPPED;
        ++w1_090_dpmi_sequence_count;
        if (success) saw_dpmi_linear_alloc=1;
        if (unavailable) w1_090_dpmi_sequence_failed=1;
        return result;
    }
#endif
    if (vector == 0x21 && va == 0x000AFA09u && g_eax == 0x00003000u) {
        if (g_cur_func != GW_BOOT_ENTRY || g_ebx != 0x50484152u || g_esp != GW_BOOT_ESP) {
            fprintf(stderr, "DOS AH=30 context differs: fn=%08x ebx=%08x esp=%08x\n",
                    g_cur_func, g_ebx, g_esp);
            return GW_INTERRUPT_TRAPPED;
        }
        gw_interrupt_result result = gw_dos_services_callback(vector, va, services);
        if (result == GW_INTERRUPT_HANDLED && g_eax == 0x00001606u) saw_first_version_service = 1;
        return result;
    }
#ifdef GW_NATIVE_CONTINUE_KNOWN
    if (saw_first_version_service && !saw_dos4g_install_check &&
        vector == 0x21 && va == 0x000AFAA8u && g_eax == 0x0000FF00u &&
        g_edx == 0x00000078u) {
        gw_interrupt_result result = gw_dos_services_callback(vector, va, services);
        if (result == GW_INTERRUPT_HANDLED && g_eax == 0x0000FFFFu && !g_flag_cf)
            saw_dos4g_install_check = 1;
        return result;
    }
#endif
#ifdef GW_NATIVE_CONTINUE_SELECTOR_QUERY
    if (saw_dos4g_install_check && !saw_selector_base_query &&
        vector == 0x31 && va == 0x000AFAC4u &&
        (uint16_t)g_eax == 0x0006u && (uint16_t)g_ebx == 0x0014u) {
        if (g_ds_base != 0) {
            fprintf(stderr, "DPMI AX=0006 expected flat DS base zero, got %08x\n", g_ds_base);
            return GW_INTERRUPT_TRAPPED;
        }
        gw_interrupt_result result = gw_dos_services_callback(vector, va, services);
        dpmi_query_ax = (uint16_t)g_eax;
        dpmi_query_selector = (uint16_t)g_ebx;
        dpmi_query_cx = (uint16_t)g_ecx;
        dpmi_query_dx = (uint16_t)g_edx;
        dpmi_query_ds_base = g_ds_base;
        dpmi_query_es_selector = g_seg_es;
        dpmi_query_es_base = g_es_base;
        dpmi_query_env_slot = *(uint16_t *)(guest_memory + 0x10B795u);
        dpmi_query_carry = (uint8_t)g_flag_cf;
        if (result == GW_INTERRUPT_HANDLED && dpmi_query_cx == 0 &&
            dpmi_query_dx == 0 && !dpmi_query_carry)
            saw_selector_base_query = 1;
        return result;
    }
#endif
#ifdef GW_NATIVE_CONTINUE_TIME_QUERY
    if (saw_selector_base_query && !saw_time_query && vector == 0x21 &&
        va == 0x000D5B24u && (uint8_t)(g_eax >> 8) == 0x2cu) {
        time_request_eax = g_eax; time_request_ebx = g_ebx;
        time_request_ecx = g_ecx; time_request_edx = g_edx;
        if (!gw_dos_time_configure(services, 0, 0, 0, 5)) return GW_INTERRUPT_TRAPPED;
        gw_interrupt_result result = gw_dos_services_callback(vector, va, services);
        time_query_eax = g_eax; time_query_ebx = g_ebx;
        time_query_ecx = g_ecx; time_query_edx = g_edx;
        time_query_carry = (uint8_t)g_flag_cf;
        if (result == GW_INTERRUPT_HANDLED && g_eax == time_request_eax &&
            g_ebx == time_request_ebx && (uint16_t)g_ecx == 0u &&
            (uint16_t)g_edx == 5u && !g_flag_cf)
            saw_time_query = 1;
        return result;
    }
#endif
#ifdef GW_NATIVE_CONTINUE_DOS_AH3D
    if (
#ifdef GW_NATIVE_CAPTURE_CRT_STARTUP
        (saw_dpmi_linear_alloc || w1_crt_alloc_count>0u) &&
#else
        saw_dpmi_linear_alloc &&
#endif
        !saw_native_ah3d && vector==0x21u &&
        va==0x000AFCC4u && (uint8_t)(g_eax>>8)==0x3du) {
        ah3d_req_eax=g_eax; ah3d_req_ebx=g_ebx; ah3d_req_ecx=g_ecx;
        ah3d_req_edx=g_edx; ah3d_req_esi=g_esi; ah3d_req_edi=g_edi;
        ah3d_req_ebp=g_ebp; ah3d_req_esp=g_esp; ah3d_req_cf=(uint8_t)g_flag_cf;
        gw_interrupt_result result=gw_dos_services_callback(vector,va,services);
#ifdef GW_NATIVE_SERVE_W3_ADDRESS_SEED
        if (_stricmp(ah3d_resolved_path,"C:\\address.txt")==0 &&
            result==GW_INTERRUPT_HANDLED && ah3d_req_eax==0x00003d01u && !g_flag_cf &&
            (uint16_t)g_eax>=5u && (uint16_t)g_eax<5u+GW_DOS_MAX_OPEN_FILES &&
            services->files[(uint16_t)g_eax-5u].active && services->files[(uint16_t)g_eax-5u].file &&
            ((native_virtual_open *)services->files[(uint16_t)g_eax-5u].file)->owner==&native_address_file &&
            native_address_file.exists && native_address_file.size==NATIVE_W1_ADDRESS_SIZE &&
            memcmp(native_address_file.bytes,native_w1_address_seed,NATIVE_W1_ADDRESS_SIZE)==0) {
            saw_native_seeded_address_open=1;
            saw_native_ah3d=1;
            printf("NATIVE_W1_ADDRESS_OPEN eip=%08x path=C:\\ADDRESS.TXT access=write-only handle=%u bytes=%u sha256=%s cf=0 handled=1 provider=seeded-virtual-memory\n",
                va,(unsigned)(uint16_t)g_eax,native_address_file.size,NATIVE_W1_ADDRESS_SHA256);
        }
#endif
#ifdef GW_NATIVE_SERVE_W3_CONFIG
        if (_stricmp(ah3d_path,"config.ini")==0) {
            uint16_t handle=(uint16_t)g_eax;
            if (result!=GW_INTERRUPT_HANDLED || ah3d_req_eax!=0x00003D00u ||
                ah3d_resolved_path[0]==0 || ah3d_resolved_path[0]=='\0' ||
                g_flag_cf || handle<5u || handle>=5u+GW_DOS_MAX_OPEN_FILES ||
                !native_w3_config_handle_active(services,handle))
                return GW_INTERRUPT_TRAPPED;
            saw_native_w3_config_open=1;
            printf("NATIVE_W3_CONFIG_OPEN eip=%08x path=%s resolved_path=%s access=read-only handle=%u size=%u sha256=e7a4728ff07332c2f04320fda202ac5521818a47453e670f9f2842767ef36798 cf=%u handled=1 provider=bounded-embedded-functional-fixture cwd=C:\\GENEWARS\n",
                va,ah3d_path,ah3d_resolved_path,handle,native_w3_config_file.size,(unsigned)g_flag_cf);
            return result;
        }
#endif
        ah3d_res_eax=g_eax; ah3d_res_ebx=g_ebx; ah3d_res_ecx=g_ecx;
        ah3d_res_edx=g_edx; ah3d_res_esi=g_esi; ah3d_res_edi=g_edi;
        ah3d_res_ebp=g_ebp; ah3d_res_esp=g_esp; ah3d_res_cf=(uint8_t)g_flag_cf;
        if (result==GW_INTERRUPT_HANDLED && ah3d_req_eax==0x00003d01u &&
            _stricmp(ah3d_resolved_path,"C:\\address.txt")==0 && ah3d_res_eax==2u &&
            ah3d_res_cf && ah3d_res_ebx==ah3d_req_ebx &&
            ah3d_res_ecx==ah3d_req_ecx && ah3d_res_edx==ah3d_req_edx &&
            ah3d_res_esi==ah3d_req_esi && ah3d_res_edi==ah3d_req_edi &&
            ah3d_res_ebp==ah3d_req_ebp && ah3d_res_esp==ah3d_req_esp) saw_native_ah3d=1;
        printf("NATIVE_DOS_AH3D vector=21 eip=%08x request_eax=%08x request_ebx=%08x request_ecx=%08x request_edx=%08x request_esi=%08x request_edi=%08x request_ebp=%08x request_esp=%08x ds=%04x ds_base=%08x path=%s resolved_path=%s response_eax=%08x response_ebx=%08x response_ecx=%08x response_edx=%08x response_esi=%08x response_edi=%08x response_ebp=%08x response_esp=%08x cf_in=%u cf_out=%u handled=%u matched_original_fixture=%u\n",
               va,(unsigned)ah3d_req_eax,(unsigned)ah3d_req_ebx,(unsigned)ah3d_req_ecx,
               (unsigned)ah3d_req_edx,(unsigned)ah3d_req_esi,(unsigned)ah3d_req_edi,
               (unsigned)ah3d_req_ebp,(unsigned)ah3d_req_esp,(unsigned)g_seg_ds,(unsigned)g_ds_base,ah3d_path,ah3d_resolved_path,
               (unsigned)ah3d_res_eax,(unsigned)ah3d_res_ebx,(unsigned)ah3d_res_ecx,
               (unsigned)ah3d_res_edx,(unsigned)ah3d_res_esi,(unsigned)ah3d_res_edi,
               (unsigned)ah3d_res_ebp,(unsigned)ah3d_res_esp,(unsigned)ah3d_req_cf,
               (unsigned)ah3d_res_cf,(unsigned)(result==GW_INTERRUPT_HANDLED),
               (unsigned)saw_native_ah3d);
        return result;
    }
#endif
#ifdef GW_NATIVE_CONTINUE_DOS_AH3C
    if (saw_native_ah3d && !saw_native_ah3c && vector==0x21u &&
        va==0x000AFDA7u && (uint8_t)(g_eax>>8)==0x3cu) {
        ah3c_req_eax=g_eax; ah3c_req_ebx=g_ebx; ah3c_req_ecx=g_ecx; ah3c_req_edx=g_edx;
        ah3c_req_cf=(uint8_t)g_flag_cf;
        uint64_t linear=(uint64_t)g_ds_base+g_edx; size_t n=0;
        while (linear+n<GW_NATIVE_GUEST_MEMORY_SIZE && n+1u<sizeof ah3c_path && guest_memory[linear+n]) {
            ah3c_path[n]=(char)guest_memory[linear+n]; n++;
        }
        ah3c_path[n]=0;
        gw_interrupt_result result=gw_dos_services_callback(vector,va,services);
        ah3c_res_eax=g_eax; ah3c_res_ebx=g_ebx; ah3c_res_ecx=g_ecx; ah3c_res_edx=g_edx;
        ah3c_res_cf=(uint8_t)g_flag_cf;
        if (result==GW_INTERRUPT_HANDLED && ah3c_req_eax==0x00003c80u &&
            ah3c_req_ebx==2u && ah3c_req_ecx==0u && _stricmp(ah3c_path,"c:\\address.txt")==0 &&
            ah3c_res_eax==5u && ah3c_res_cf==0u) saw_native_ah3c=1;
        printf("NATIVE_DOS_AH3C eip=%08x request_eax=%08x request_ebx=%08x request_ecx=%08x request_edx=%08x path=%s attributes=%04x response_eax=%08x response_ebx=%08x response_ecx=%08x response_edx=%08x cf_in=%u cf_out=%u handled=%u matched_original_request=%u fixture_kind=bounded_memory_only\n",
            va,ah3c_req_eax,ah3c_req_ebx,ah3c_req_ecx,ah3c_req_edx,ah3c_path,
            (unsigned)(uint16_t)ah3c_req_ecx,ah3c_res_eax,ah3c_res_ebx,ah3c_res_ecx,ah3c_res_edx,
            ah3c_req_cf,ah3c_res_cf,result==GW_INTERRUPT_HANDLED,saw_native_ah3c);
        return result;
    }
#endif
#ifdef GW_NATIVE_CAPTURE_CRT_STARTUP
    if (vector==0x21u && (uint8_t)(g_eax>>8)==0x3Du) {
        uint32_t req_eax=g_eax,req_ebx=g_ebx,req_ecx=g_ecx,req_edx=g_edx;
        char guest_path[128]; size_t path_len=0;
        uint64_t path_linear=(uint64_t)g_ds_base+req_edx;
        while(path_linear+path_len<GW_NATIVE_GUEST_MEMORY_SIZE && path_len+1u<sizeof guest_path && guest_memory[path_linear+path_len]) {
            guest_path[path_len]=(char)guest_memory[path_linear+path_len]; path_len++;
        }
        guest_path[path_len]=0;
        uint32_t stack0=(g_esp<GW_NATIVE_GUEST_MEMORY_SIZE-4u)?*(uint32_t *)(guest_memory+g_esp):0;
        uint32_t stack1=(g_esp+4u<GW_NATIVE_GUEST_MEMORY_SIZE-4u)?*(uint32_t *)(guest_memory+g_esp+4u):0;
        gw_interrupt_result result=gw_dos_services_callback(vector,va,services);
#ifdef GW_NATIVE_SERVE_W3_CONFIG
        if (va==0x000AFCC4u && req_eax==0x00003D00u &&
            _stricmp(guest_path,"config.ini")==0 && result==GW_INTERRUPT_HANDLED &&
            !g_flag_cf && (uint16_t)g_eax>=5u &&
            (uint16_t)g_eax<5u+GW_DOS_MAX_OPEN_FILES &&
            native_w3_config_handle_active(services,(uint16_t)g_eax)) {
            saw_native_w3_config_open=1;
            printf("NATIVE_W3_CONFIG_OPEN eip=%08x path=%s resolved_path=%s access=read-only handle=%u size=%u sha256=e7a4728ff07332c2f04320fda202ac5521818a47453e670f9f2842767ef36798 cf=%u handled=1 provider=bounded-embedded-functional-fixture cwd=C:\\GENEWARS\n",
                va,guest_path,ah3d_resolved_path,(unsigned)(uint16_t)g_eax,
                native_w3_config_file.size,(unsigned)g_flag_cf);
        }
#endif
        printf("W1_CRT_DOS_AH3D_GENERIC cs=%04x eip=%08x cur_func=%08x eax_in=%08x ebx_in=%08x ecx_in=%08x edx_in=%08x ds=%04x ds_base=%08x pathname=%s stack0=%08x stack1=%08x ebp=%08x esp=%08x eax_out=%08x ebx_out=%08x ecx_out=%08x edx_out=%08x carry=%u handled=%u\n",
               g_seg_cs,va,g_cur_func,req_eax,req_ebx,req_ecx,req_edx,g_seg_ds,g_ds_base,guest_path,stack0,stack1,g_ebp,g_esp,g_eax,g_ebx,g_ecx,g_edx,
               (unsigned)g_flag_cf,(unsigned)(result==GW_INTERRUPT_HANDLED));
        return result;
    }
    if (vector==0x21u && (uint8_t)(g_eax>>8)==0x3Cu) {
        uint32_t req_eax=g_eax,req_ebx=g_ebx,req_ecx=g_ecx,req_edx=g_edx;
        gw_interrupt_result result=gw_dos_services_callback(vector,va,services);
        printf("W1_CRT_DOS_AH3C_GENERIC eip=%08x eax_in=%08x ebx_in=%08x ecx_in=%08x edx_in=%08x eax_out=%08x ebx_out=%08x ecx_out=%08x edx_out=%08x carry=%u handled=%u\n",
               va,req_eax,req_ebx,req_ecx,req_edx,g_eax,g_ebx,g_ecx,g_edx,
               (unsigned)g_flag_cf,(unsigned)(result==GW_INTERRUPT_HANDLED));
        return result;
    }
#endif
#ifdef GW_NATIVE_CAPTURE_CRT_STARTUP
    if (vector==0x21u && (uint16_t)g_eax==0x4400u && g_ebx>2u) {
        uint32_t req_eax=g_eax,req_ebx=g_ebx,req_ecx=g_ecx,req_edx=g_edx;
        uint32_t req_esi=g_esi,req_edi=g_edi,req_ebp=g_ebp,req_esp=g_esp;
        uint32_t req_flags_k=g_flag_k,req_flags_a=g_flag_a,req_flags_b=g_flag_b;
        uint32_t caller=g_cur_func;
        uint8_t req_cf=(uint8_t)g_flag_cf;
        uint32_t stack0=(g_esp<GW_NATIVE_GUEST_MEMORY_SIZE-4u)?*(uint32_t *)(guest_memory+g_esp):0;
        uint32_t stack1=(g_esp+4u<GW_NATIVE_GUEST_MEMORY_SIZE-4u)?*(uint32_t *)(guest_memory+g_esp+4u):0;
        uint32_t stack2=(g_esp+8u<GW_NATIVE_GUEST_MEMORY_SIZE-4u)?*(uint32_t *)(guest_memory+g_esp+8u):0;
        if (va==0x000C8973u && g_ebx==5u)
            printf("W1_CRT_AX4400_CONTEXT ordinal=%u caller=%08x cs=%04x eip=%08x eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x ebp=%08x esp=%08x eflags_k=%u eflags_a=%08x eflags_b=%08x cf=%u ds=%04x ds_base=%08x es=%04x ss=%04x stack0=%08x stack1=%08x stack2=%08x\n",
                w1_crt_ax4400_ordinal, caller, g_seg_cs, va, g_eax, g_ebx, g_ecx, g_edx,
                g_esi, g_edi, g_ebp, g_esp, g_flag_k, g_flag_a, g_flag_b, g_flag_cf,
                g_seg_ds, g_ds_base, g_seg_es, g_seg_ss, stack0, stack1, stack2);
        w1_crt_ax4400_ordinal++;
        const char *fixture_path="unknown";
        for (uint32_t i=0;i<GW_DOS_MAX_OPEN_FILES;i++) {
            if (!services->files[i].active || services->files[i].dos_handle!=req_ebx || !services->files[i].file) continue;
            native_virtual_open *open=(native_virtual_open *)services->files[i].file;
            if (open->owner==&native_address_file) fixture_path="C:\\ADDRESS.TXT";
#ifdef GW_NATIVE_SERVE_W3_CONFIG
            else if (open->owner==&native_w3_config_file) fixture_path="C:\\GENEWARS\\CONFIG.INI";
#endif
            break;
        }
        gw_interrupt_result result=gw_dos_services_callback(vector,va,services);
        printf("W1_CRT_DOS_AX4400_FILE eip=%08x path=%s eax_in=%08x ebx_in=%08x ecx_in=%08x edx_in=%08x eax_out=%08x ebx_out=%08x ecx_out=%08x edx_out=%08x carry=%u handled=%u ordinal=%u caller=%08x esi_in=%08x edi_in=%08x ebp_in=%08x esp_in=%08x flags_k_in=%08x flags_a_in=%08x flags_b_in=%08x cf_in=%u esi_out=%08x edi_out=%08x ebp_out=%08x esp_out=%08x flags_k_out=%08x flags_a_out=%08x flags_b_out=%08x\n",
               va,fixture_path,req_eax,req_ebx,req_ecx,req_edx,g_eax,g_ebx,g_ecx,g_edx,
               (unsigned)g_flag_cf,(unsigned)(result==GW_INTERRUPT_HANDLED),w1_crt_ax4400_ordinal-1u,caller,
               req_esi,req_edi,req_ebp,req_esp,req_flags_k,req_flags_a,req_flags_b,req_cf,
               g_esi,g_edi,g_ebp,g_esp,g_flag_k,g_flag_a,g_flag_b);
        return result;
    }
#endif
#ifdef GW_NATIVE_CONTINUE_DOS_AX4400
    if (saw_native_ah3c && native_ax4400_call_count<4u && vector==0x21u &&
        va==0x000C8973u && (uint16_t)g_eax==0x4400u) {
        if ((native_ax4400_call_count==0u && (g_ebx!=5u || g_ecx!=0x4000u || g_edx!=5u)) ||
            (native_ax4400_call_count==1u && (g_ebx!=5u || g_ecx!=0u || g_edx!=0x4000u)) ||
            (native_ax4400_call_count==2u && (g_ebx!=5u || g_ecx!=0x0010a88au || g_edx!=0x0010a88au)) ||
            (native_ax4400_call_count==3u && (g_ebx!=5u || g_ecx!=0u || g_edx!=0x0010a88au)))
            return GW_INTERRUPT_TRAPPED;
        native_ax4400_call_count++;
        ax4400_req_eax=g_eax; ax4400_req_ebx=g_ebx; ax4400_req_ecx=g_ecx;
        ax4400_req_edx=g_edx; ax4400_req_cf=(uint8_t)g_flag_cf;
        gw_interrupt_result result=gw_dos_services_callback(vector,va,services);
        ax4400_res_eax=g_eax; ax4400_res_ebx=g_ebx; ax4400_res_ecx=g_ecx;
        ax4400_res_edx=g_edx; ax4400_res_cf=(uint8_t)g_flag_cf;
        if (result==GW_INTERRUPT_HANDLED && ax4400_req_ebx==5u &&
            ax4400_res_eax==ax4400_req_eax && ax4400_res_ebx==ax4400_req_ebx &&
            ax4400_res_ecx==ax4400_req_ecx && (ax4400_res_edx>>16)==(ax4400_req_edx>>16) &&
            ax4400_res_cf==0u) saw_native_ax4400=1;
        printf("NATIVE_DOS_AX4400 call=%u eip=%08x request_eax=%08x request_ebx=%08x request_ecx=%08x request_edx=%08x response_eax=%08x response_ebx=%08x response_ecx=%08x response_edx=%08x cf_in=%u cf_out=%u handled=%u fixture_kind=bounded_memory_only\n",
            native_ax4400_call_count,va,ax4400_req_eax,ax4400_req_ebx,ax4400_req_ecx,ax4400_req_edx,
            ax4400_res_eax,ax4400_res_ebx,ax4400_res_ecx,ax4400_res_edx,
            ax4400_req_cf,ax4400_res_cf,result==GW_INTERRUPT_HANDLED);
        return result;
    }
#endif
#ifdef GW_NATIVE_CONTINUE_DOS_AH40
    if (vector==0x21u && va==0x000D219Cu && (uint16_t)g_eax==0x4002u && g_ebx>2u) {
        uint32_t req_eax=g_eax,req_ebx=g_ebx,req_ecx=g_ecx,req_edx=g_edx,req_esp=g_esp;
        gw_interrupt_result result=gw_dos_services_callback(vector,va,services);
        printf("W1_CRT_DOS_AH40_FILE eax_in=%08x ebx_in=%08x ecx_in=%08x edx_in=%08x eax_out=%08x ebx_out=%08x ecx_out=%08x edx_out=%08x esp_in=%08x esp_out=%08x carry=%u handled=%u\n",
               req_eax,req_ebx,req_ecx,req_edx,g_eax,g_ebx,g_ecx,g_edx,req_esp,g_esp,
               (unsigned)g_flag_cf,(unsigned)(result==GW_INTERRUPT_HANDLED));
        return result;
    }
    if (native_standard_ioctl_count==3u && native_ah40_call_count<16u && vector==0x21u &&
        va==0x000D219Cu && (uint16_t)g_eax==0x4002u) {
        ah40_req_eax=g_eax; ah40_req_ebx=g_ebx; ah40_req_ecx=g_ecx;
        ah40_req_edx=g_edx; ah40_req_esi=g_esi; ah40_req_edi=g_edi;
        ah40_req_ebp=g_ebp; ah40_req_esp=g_esp; ah40_req_ds=g_seg_ds;
        ah40_req_ds_base=g_ds_base; ah40_req_cf=(uint8_t)g_flag_cf;
        uint64_t linear=(uint64_t)g_ds_base+g_edx;
        if (g_ebx!=1u || !g_ecx || (uint64_t)linear+g_ecx>GW_NATIVE_GUEST_MEMORY_SIZE)
            return GW_INTERRUPT_TRAPPED;
        uint32_t sample_size=g_ecx<64u?g_ecx:64u;
        char sample_hex[129];
        for (uint32_t i=0;i<sample_size;i++)
            sprintf(sample_hex+i*2u,"%02x",guest_memory[(size_t)linear+i]);
        sample_hex[sample_size*2u]=0;
        gw_interrupt_result result=gw_dos_services_callback(vector,va,services);
        ah40_res_eax=g_eax; ah40_res_ebx=g_ebx; ah40_res_ecx=g_ecx;
        ah40_res_edx=g_edx; ah40_res_esi=g_esi; ah40_res_edi=g_edi;
        ah40_res_ebp=g_ebp; ah40_res_esp=g_esp; ah40_res_cf=(uint8_t)g_flag_cf;
        if (result==GW_INTERRUPT_HANDLED && g_ebx==ah40_req_ebx &&
            g_ecx==ah40_req_ecx && g_edx==ah40_req_edx &&
            g_esi==ah40_req_esi && g_edi==ah40_req_edi && g_ebp==ah40_req_ebp &&
            g_esp==ah40_req_esp) {
            if (native_ah40_call_count==0u && g_eax==2u && !g_flag_cf &&
                sample_size==2u && sample_hex[0]=='0' && sample_hex[1]=='d' &&
                sample_hex[2]=='0' && sample_hex[3]=='a' && native_stdout_size==2u)
                saw_native_ah40=1;
            native_ah40_call_count++;
        }
        printf("NATIVE_DOS_AH40_STD call=%u eip=%08x request_eax=%08x request_ebx=%08x request_ecx=%08x request_edx=%08x ds=%04x ds_base=%08x effective_linear=%08llx sample_bytes=%u sample_hex=%s response_eax=%08x response_ebx=%08x response_ecx=%08x response_edx=%08x response_esi=%08x response_edi=%08x response_ebp=%08x response_esp=%08x cf_in=%u cf_out=%u handled=%u captured_total=%u provider=bounded_virtual_stdout\n",
            native_ah40_call_count,va,ah40_req_eax,ah40_req_ebx,ah40_req_ecx,ah40_req_edx,ah40_req_ds,
            ah40_req_ds_base,(unsigned long long)linear,sample_size,sample_hex,
            ah40_res_eax,ah40_res_ebx,ah40_res_ecx,ah40_res_edx,ah40_res_esi,ah40_res_edi,
            ah40_res_ebp,ah40_res_esp,ah40_req_cf,ah40_res_cf,result==GW_INTERRUPT_HANDLED,
            native_stdout_size);
        return result;
    }
#endif
#ifdef GW_NATIVE_CAPTURE_CRT_STARTUP
#ifdef GW_NATIVE_SERVE_W3_CONFIG
    if (vector==0x21u && (uint8_t)(g_eax>>8)==0x3Fu) {
        uint32_t req_eax=g_eax,req_ebx=g_ebx,req_ecx=g_ecx,req_edx=g_edx;
        uint64_t linear=(uint64_t)g_ds_base+req_edx;
        int is_config=0;
        if (native_w3_config_handle_active(services,req_ebx))
            is_config=1;
        if (is_config) {
            gw_interrupt_result result=gw_dos_services_callback(vector,va,services);
            uint16_t transferred=(uint16_t)g_eax;
            if (result==GW_INTERRUPT_HANDLED && !g_flag_cf && transferred<=req_ecx &&
                linear+transferred<=services->guest_memory_size &&
                native_w3_config_read_total+transferred<=sizeof native_w3_config_read_bytes) {
                memcpy(native_w3_config_read_bytes+native_w3_config_read_total,
                    guest_memory+(size_t)linear,transferred);
                native_w3_config_read_total+=transferred;
                printf("NATIVE_W3_CONFIG_READ eip=%08x handle=%u request=%u transferred=%u data_hex=",
                    va,(unsigned)req_ebx,(unsigned)req_ecx,(unsigned)transferred);
                for (uint16_t i=0;i<transferred;i++) printf("%02x",guest_memory[(size_t)linear+i]);
                printf(" cf=%u handled=1 total=%u\n",(unsigned)g_flag_cf,native_w3_config_read_total);
            } else return GW_INTERRUPT_TRAPPED;
            return result;
        }
    }
#endif
    if (vector==0x21u && (uint8_t)(g_eax>>8)==0x40u && g_ebx>2u) {
        uint32_t req_eax=g_eax,req_ebx=g_ebx,req_ecx=g_ecx,req_edx=g_edx;
        const char *fixture_path="unknown";
        if (req_ebx<5u+GW_DOS_MAX_OPEN_FILES && services->files[req_ebx-5u].active && services->files[req_ebx-5u].file) {
            native_virtual_open *open=(native_virtual_open *)services->files[req_ebx-5u].file;
            if (open->owner==&native_address_file) fixture_path="C:\\ADDRESS.TXT";
#ifdef GW_NATIVE_SERVE_W3_CONFIG
            else if (open->owner==&native_w3_config_file) fixture_path="C:\\GENEWARS\\CONFIG.INI";
#endif
        }
        gw_interrupt_result result=gw_dos_services_callback(vector,va,services);
        printf("NATIVE_W1_DOS_AH40_FILE eip=%08x path=%s eax_in=%08x ebx_in=%08x ecx_in=%08x edx_in=%08x eax_out=%08x ebx_out=%08x ecx_out=%08x edx_out=%08x carry=%u handled=%u\n",
            va,fixture_path,req_eax,req_ebx,req_ecx,req_edx,g_eax,g_ebx,g_ecx,g_edx,
            (unsigned)g_flag_cf,(unsigned)(result==GW_INTERRUPT_HANDLED));
        return result;
    }
    if (vector==0x21u && (uint8_t)(g_eax>>8)==0x42u) {
        uint32_t req_eax=g_eax,req_ebx=g_ebx,req_ecx=g_ecx,req_edx=g_edx,req_esp=g_esp;
#ifdef GW_NATIVE_SERVE_W3_CONFIG
        int is_config=native_w3_config_handle_active(services,req_ebx);
#endif
        gw_interrupt_result result=gw_dos_services_callback(vector,va,services);
        printf("W1_CRT_DOS_AH42_FILE eax_in=%08x ebx_in=%08x ecx_in=%08x edx_in=%08x eax_out=%08x ebx_out=%08x ecx_out=%08x edx_out=%08x esp_in=%08x esp_out=%08x carry=%u handled=%u\n",
               req_eax,req_ebx,req_ecx,req_edx,g_eax,g_ebx,g_ecx,g_edx,req_esp,g_esp,
               (unsigned)g_flag_cf,(unsigned)(result==GW_INTERRUPT_HANDLED));
#ifdef GW_NATIVE_SERVE_W3_CONFIG
        if (is_config) printf("NATIVE_W3_CONFIG_SEEK eip=%08x handle=%u origin=%u displacement=%08x result=%08x cf=%u handled=%u\n",
            va,req_ebx,(unsigned)(uint8_t)req_eax,((req_ecx&0xffffu)<<16)|(req_edx&0xffffu),
            g_edx,g_flag_cf,result==GW_INTERRUPT_HANDLED);
#endif
        return result;
    }
    if (vector==0x21u && (uint8_t)(g_eax>>8)==0x3Eu) {
        uint32_t req_eax=g_eax,req_ebx=g_ebx,req_esp=g_esp;
#ifdef GW_NATIVE_SERVE_W3_CONFIG
        int is_config=native_w3_config_handle_active(services,req_ebx);
#endif
        gw_interrupt_result result=gw_dos_services_callback(vector,va,services);
        printf("W1_CRT_DOS_AH3E_FILE eax_in=%08x ebx_in=%08x eax_out=%08x ebx_out=%08x esp_in=%08x esp_out=%08x carry=%u handled=%u\n",
               req_eax,req_ebx,g_eax,g_ebx,req_esp,g_esp,(unsigned)g_flag_cf,
               (unsigned)(result==GW_INTERRUPT_HANDLED));
#ifdef GW_NATIVE_SERVE_W3_CONFIG
        if (is_config) printf("NATIVE_W3_CONFIG_CLOSE eip=%08x handle=%u ax=%08x cf=%u handled=%u total=%u\n",
            va,req_ebx,g_eax,g_flag_cf,result==GW_INTERRUPT_HANDLED,native_w3_config_read_total);
#endif
        return result;
    }
#endif
#ifdef GW_NATIVE_CONTINUE_DOS_AX4400
    if (native_ax4400_call_count==4u && native_ah42_call_count<2u && vector==0x21u &&
        va==0x000BA7CDu && (uint16_t)g_eax==0x4200u+(native_ah42_call_count==0u?1u:0u)) {
        ah42_req_eax=g_eax; ah42_req_ebx=g_ebx; ah42_req_ecx=g_ecx;
        ah42_req_edx=g_edx; ah42_req_cf=(uint8_t)g_flag_cf;
        if (g_ebx!=5u || g_ecx!=0u || g_edx!=0u) return GW_INTERRUPT_TRAPPED;
        gw_interrupt_result result=gw_dos_services_callback(vector,va,services);
        ah42_res_eax=g_eax; ah42_res_ebx=g_ebx; ah42_res_ecx=g_ecx;
        ah42_res_edx=g_edx; ah42_res_cf=(uint8_t)g_flag_cf;
        if (result==GW_INTERRUPT_HANDLED && !ah42_res_cf &&
            ah42_res_ebx==ah42_req_ebx && ah42_res_ecx==ah42_req_ecx) { saw_native_ah42=1; native_ah42_call_count++; }
        printf("NATIVE_DOS_AH42 call=%u eip=%08x request_eax=%08x request_ebx=%08x request_ecx=%08x request_edx=%08x response_eax=%08x response_ebx=%08x response_ecx=%08x response_edx=%08x cf_in=%u cf_out=%u handled=%u fixture_kind=bounded_memory_only\n",
            native_ah42_call_count,va,ah42_req_eax,ah42_req_ebx,ah42_req_ecx,ah42_req_edx,ah42_res_eax,
            ah42_res_ebx,ah42_res_ecx,ah42_res_edx,ah42_req_cf,ah42_res_cf,result==GW_INTERRUPT_HANDLED);
        return result;
    }
#endif
#ifdef GW_NATIVE_CONTINUE_DOS_AX4400
    if (native_ah42_call_count==2u && !saw_native_ah3e && vector==0x21u &&
        va==0x000BA805u && (uint16_t)g_eax==0x3e05u) {
        ah3e_req_eax=g_eax; ah3e_req_ebx=g_ebx; ah3e_req_cf=(uint8_t)g_flag_cf;
        if (g_ebx!=5u) return GW_INTERRUPT_TRAPPED;
        gw_interrupt_result result=gw_dos_services_callback(vector,va,services);
        ah3e_res_eax=g_eax; ah3e_res_ebx=g_ebx; ah3e_res_cf=(uint8_t)g_flag_cf;
        if (result==GW_INTERRUPT_HANDLED && !ah3e_res_cf &&
            ah3e_res_eax==ah3e_req_eax && ah3e_res_ebx==ah3e_req_ebx) saw_native_ah3e=1;
        printf("NATIVE_DOS_AH3E eip=%08x request_eax=%08x request_ebx=%08x response_eax=%08x response_ebx=%08x cf_in=%u cf_out=%u handled=%u fixture_kind=bounded_memory_only\n",
            va,ah3e_req_eax,ah3e_req_ebx,ah3e_res_eax,ah3e_res_ebx,ah3e_req_cf,ah3e_res_cf,result==GW_INTERRUPT_HANDLED);
        return result;
    }
#endif
#if defined(GW_NATIVE_CONTINUE_DOS_AX4400) && !defined(GW_NATIVE_CONTINUE_DOS_AX4400_CONSOLE)
    if (saw_native_ah3e && native_standard_ioctl_count<3u && vector==0x21u &&
        va==0x000C8973u && (uint16_t)g_eax==0x4400u && g_ebx<=2u) {
        stdio_ioctl_req_eax=g_eax; stdio_ioctl_req_ebx=g_ebx;
        stdio_ioctl_req_edx=g_edx; stdio_ioctl_req_cf=(uint8_t)g_flag_cf;
        gw_interrupt_result result=gw_dos_services_callback(vector,va,services);
        stdio_ioctl_res_eax=g_eax; stdio_ioctl_res_ebx=g_ebx;
        stdio_ioctl_res_edx=g_edx; stdio_ioctl_res_cf=(uint8_t)g_flag_cf;
        if (result==GW_INTERRUPT_HANDLED && stdio_ioctl_res_eax==stdio_ioctl_req_eax &&
            stdio_ioctl_res_ebx==stdio_ioctl_req_ebx && (uint16_t)stdio_ioctl_res_edx==(stdio_ioctl_req_ebx==0u?0x81u:0x82u) &&
            !stdio_ioctl_res_cf) { saw_native_standard_ioctl=1; native_standard_ioctl_count++; }
        printf("NATIVE_DOS_AX4400_STD call=%u eip=%08x request_eax=%08x request_ebx=%08x request_edx=%08x response_eax=%08x response_ebx=%08x response_edx=%08x cf_in=%u cf_out=%u handled=%u\n",
            native_standard_ioctl_count,va,stdio_ioctl_req_eax,stdio_ioctl_req_ebx,stdio_ioctl_req_edx,stdio_ioctl_res_eax,
            stdio_ioctl_res_ebx,stdio_ioctl_res_edx,stdio_ioctl_req_cf,stdio_ioctl_res_cf,result==GW_INTERRUPT_HANDLED);
        return result;
    }
#endif
#ifdef GW_NATIVE_CONTINUE_DOS_AX4400_CONSOLE
    /* The original CRT can redirect DOS handle 2 to the active gw.err file
     * before it queries the configured console stream.  Reuse the Runtime's
     * file_ioctl_info callback for that real mapping; do not synthesize a
     * standard-device result for a redirected handle. */
    if (vector==0x21u && va==0x000C8973u && (uint16_t)g_eax==0x4400u && g_ebx==2u) {
        for (uint32_t i=0;i<GW_DOS_MAX_OPEN_FILES;i++) {
            if (services->files[i].active && services->files[i].dos_handle==2u &&
                services->files[i].file) {
                uint32_t req_eax=g_eax,req_ebx=g_ebx,req_ecx=g_ecx,req_edx=g_edx;
                uint8_t req_cf=(uint8_t)g_flag_cf;
                gw_interrupt_result result=gw_dos_services_callback(vector,va,services);
                printf("NATIVE_DOS_AX4400_ACTIVE_FILE eip=%08x slot=%u owner=runtime_file_provider request_eax=%08x request_ebx=%08x request_ecx=%08x request_edx=%08x response_eax=%08x response_ebx=%08x response_ecx=%08x response_edx=%08x cf_in=%u cf_out=%u handled=%u provider=file_ioctl_info\n",
                    va,i,req_eax,req_ebx,req_ecx,req_edx,g_eax,g_ebx,g_ecx,g_edx,
                    req_cf,(unsigned)g_flag_cf,(unsigned)(result==GW_INTERRUPT_HANDLED));
                return result;
            }
        }
    }
    /* GeneWars writes its startup diagnostics through the same redirected
     * guest file handle.  The existing DOS file provider owns the bytes and
     * bounds the write; keep it in guest memory and never mirror to the host. */
    if (vector==0x21u && va==0x000D219Cu && (uint16_t)g_eax==0x4002u && g_ebx==2u) {
        for (uint32_t i=0;i<GW_DOS_MAX_OPEN_FILES;i++) {
            if (services->files[i].active && services->files[i].dos_handle==2u &&
                services->files[i].file) {
                uint32_t req_eax=g_eax,req_ebx=g_ebx,req_ecx=g_ecx,req_edx=g_edx;
                uint8_t req_cf=(uint8_t)g_flag_cf;
                gw_interrupt_result result=gw_dos_services_callback(vector,va,services);
                printf("NATIVE_DOS_AH40_ACTIVE_FILE eip=%08x slot=%u owner=runtime_file_provider request_eax=%08x request_ebx=%08x request_ecx=%08x request_edx=%08x response_eax=%08x response_ebx=%08x response_ecx=%08x response_edx=%08x cf_in=%u cf_out=%u handled=%u host_write=0 provider=virtual_file_write\n",
                    va,i,req_eax,req_ebx,req_ecx,req_edx,g_eax,g_ebx,g_ecx,g_edx,
                    req_cf,(unsigned)g_flag_cf,(unsigned)(result==GW_INTERRUPT_HANDLED));
                return result;
            }
        }
    }
    if (vector==0x21u && va==0x000C8973u && (uint16_t)g_eax==0x4400u && g_ebx==1u &&
        services->streams[g_ebx].configured && services->streams[g_ebx].device &&
        services->streams[g_ebx].ioctl_info_configured) {
        native_ax4400_console_provider_count++;
        uint32_t req_eax=g_eax,req_ebx=g_ebx,req_ecx=g_ecx,req_edx=g_edx;
        uint32_t req_esi=g_esi,req_edi=g_edi,req_ebp=g_ebp,req_esp=g_esp;
        uint32_t req_flags_k=g_flag_k,req_flags_a=g_flag_a,req_flags_b=g_flag_b;
        uint16_t req_cs=g_seg_cs,req_ds=g_seg_ds,req_es=g_seg_es,req_ss=g_seg_ss;
        uint16_t req_info=services->streams[g_ebx].ioctl_device_info;
        uint8_t req_cf=(uint8_t)g_flag_cf;
        gw_interrupt_result result=gw_dos_services_callback(vector,va,services);
        printf("NATIVE_DOS_AX4400_STD_PROVIDER ordinal=%u eip=%08x request_eax=%08x request_ebx=%08x request_ecx=%08x request_edx=%08x request_esi=%08x request_edi=%08x request_ebp=%08x request_esp=%08x request_flags_k=%08x request_flags_a=%08x request_flags_b=%08x request_cs=%04x request_ds=%04x request_es=%04x request_ss=%04x configured_device_info=%04x response_eax=%08x response_ebx=%08x response_ecx=%08x response_edx=%08x response_esi=%08x response_edi=%08x response_ebp=%08x response_esp=%08x response_flags_k=%08x response_flags_a=%08x response_flags_b=%08x response_cs=%04x response_ds=%04x response_es=%04x response_ss=%04x cf_in=%u cf_out=%u handled=%u provider=configured-standard-stream\n",
            native_ax4400_console_provider_count,va,req_eax,req_ebx,req_ecx,req_edx,req_esi,req_edi,req_ebp,req_esp,
            req_flags_k,req_flags_a,req_flags_b,req_cs,req_ds,req_es,req_ss,req_info,
            g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,
            g_flag_k,g_flag_a,g_flag_b,g_seg_cs,g_seg_ds,g_seg_es,g_seg_ss,
            req_cf,(unsigned)g_flag_cf,(unsigned)(result==GW_INTERRUPT_HANDLED));
        return result;
    }
#endif
#ifdef GW_NATIVE_CONTINUE_DPMI_AX0200
    if (vector==0x31u && va==0x000C8CD2u && (uint16_t)g_eax==0x0200u && (g_ebx&0xffu)==8u) {
        native_dpmi_ax0200_count++;
        uint32_t req_eax=g_eax,req_ebx=g_ebx,req_ecx=g_ecx,req_edx=g_edx;
        uint32_t req_esi=g_esi,req_edi=g_edi,req_ebp=g_ebp,req_esp=g_esp;
        uint32_t req_flags_k=g_flag_k,req_flags_a=g_flag_a,req_flags_b=g_flag_b;
        uint16_t req_cs=g_seg_cs,req_ds=g_seg_ds,req_es=g_seg_es,req_fs=g_seg_fs,req_gs=g_seg_gs,req_ss=g_seg_ss;
        uint8_t req_cf=(uint8_t)g_flag_cf;
        gw_interrupt_result result=gw_dos_services_callback(vector,va,services);
        printf("NATIVE_DPMI_AX0200_PROVIDER ordinal=%u vector=%02x eip=%08x request_eax=%08x request_ebx=%08x request_ecx=%08x request_edx=%08x request_esi=%08x request_edi=%08x request_ebp=%08x request_esp=%08x request_flags_k=%08x request_flags_a=%08x request_flags_b=%08x request_cs=%04x request_ds=%04x request_es=%04x request_fs=%04x request_gs=%04x request_ss=%04x response_eax=%08x response_ebx=%08x response_ecx=%08x response_edx=%08x response_esi=%08x response_edi=%08x response_ebp=%08x response_esp=%08x response_flags_k=%08x response_flags_a=%08x response_flags_b=%08x response_cs=%04x response_ds=%04x response_es=%04x response_fs=%04x response_gs=%04x response_ss=%04x cf_in=%u cf_out=%u handled=%u provider=gw_dos_services_callback\n",
            native_dpmi_ax0200_count,vector,va,req_eax,req_ebx,req_ecx,req_edx,req_esi,req_edi,req_ebp,req_esp,
            req_flags_k,req_flags_a,req_flags_b,req_cs,req_ds,req_es,req_fs,req_gs,req_ss,
            g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,
            g_flag_k,g_flag_a,g_flag_b,g_seg_cs,g_seg_ds,g_seg_es,g_seg_fs,g_seg_gs,g_seg_ss,
            req_cf,(unsigned)g_flag_cf,(unsigned)(result==GW_INTERRUPT_HANDLED));
        return result;
    }
#endif
#ifdef GW_NATIVE_CONTINUE_DOS_AH35
    if (saw_first_version_service && vector==0x21u && va==0x000C8CDFu &&
        (uint16_t)g_eax==0x3508u && (uint16_t)g_ebx==8u) {
        native_dos_ah35_count++;
        uint32_t req_eax=g_eax,req_ebx=g_ebx,req_ecx=g_ecx,req_edx=g_edx;
        uint32_t req_esi=g_esi,req_edi=g_edi,req_ebp=g_ebp,req_esp=g_esp;
        uint32_t req_flags_k=g_flag_k,req_flags_a=g_flag_a,req_flags_b=g_flag_b;
        uint16_t req_cs=g_seg_cs,req_ds=g_seg_ds,req_es=g_seg_es,req_fs=g_seg_fs,req_gs=g_seg_gs,req_ss=g_seg_ss;
        uint8_t req_cf=(uint8_t)g_flag_cf;
        gw_interrupt_result result=gw_dos_services_callback(vector,va,services);
        printf("NATIVE_DOS_AH35_PROVIDER ordinal=%u vector=%02x eip=%08x request_eax=%08x request_ebx=%08x request_ecx=%08x request_edx=%08x request_esi=%08x request_edi=%08x request_ebp=%08x request_esp=%08x request_flags_k=%08x request_flags_a=%08x request_flags_b=%08x request_cs=%04x request_ds=%04x request_es=%04x request_fs=%04x request_gs=%04x request_ss=%04x response_eax=%08x response_ebx=%08x response_ecx=%08x response_edx=%08x response_esi=%08x response_edi=%08x response_ebp=%08x response_esp=%08x response_flags_k=%08x response_flags_a=%08x response_flags_b=%08x response_cs=%04x response_ds=%04x response_es=%04x response_fs=%04x response_gs=%04x response_ss=%04x cf_in=%u cf_out=%u handled=%u provider=gw_dos_services_callback\n",
            native_dos_ah35_count,vector,va,req_eax,req_ebx,req_ecx,req_edx,req_esi,req_edi,req_ebp,req_esp,
            req_flags_k,req_flags_a,req_flags_b,req_cs,req_ds,req_es,req_fs,req_gs,req_ss,
            g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,
            g_flag_k,g_flag_a,g_flag_b,g_seg_cs,g_seg_ds,g_seg_es,g_seg_fs,g_seg_gs,g_seg_ss,
            req_cf,(unsigned)g_flag_cf,(unsigned)(result==GW_INTERRUPT_HANDLED));
        return result;
    }
#endif
#ifdef GW_NATIVE_CONTINUE_DOS_AH25
    if (saw_first_version_service && vector==0x21u && va==0x000C8D0Cu &&
        (uint16_t)g_eax==0x2508u && (uint8_t)g_eax==8u) {
        native_dos_ah25_count++;
        uint32_t req_eax=g_eax,req_ebx=g_ebx,req_ecx=g_ecx,req_edx=g_edx;
        uint32_t req_esi=g_esi,req_edi=g_edi,req_ebp=g_ebp,req_esp=g_esp;
        uint32_t req_flags_k=g_flag_k,req_flags_a=g_flag_a,req_flags_b=g_flag_b;
        uint16_t req_cs=g_seg_cs,req_ds=g_seg_ds,req_es=g_seg_es,req_fs=g_seg_fs,req_gs=g_seg_gs,req_ss=g_seg_ss;
        uint8_t req_cf=(uint8_t)g_flag_cf;
        gw_interrupt_result result=gw_dos_services_callback(vector,va,services);
        printf("NATIVE_DOS_AH25_PROVIDER ordinal=%u vector=%02x eip=%08x request_eax=%08x request_ebx=%08x request_ecx=%08x request_edx=%08x request_esi=%08x request_edi=%08x request_ebp=%08x request_esp=%08x request_flags_k=%08x request_flags_a=%08x request_flags_b=%08x request_cs=%04x request_ds=%04x request_es=%04x request_fs=%04x request_gs=%04x request_ss=%04x response_eax=%08x response_ebx=%08x response_ecx=%08x response_edx=%08x response_esi=%08x response_edi=%08x response_ebp=%08x response_esp=%08x response_flags_k=%08x response_flags_a=%08x response_flags_b=%08x response_cs=%04x response_ds=%04x response_es=%04x response_fs=%04x response_gs=%04x response_ss=%04x cf_in=%u cf_out=%u handled=%u provider=gw_dos_services_callback\n",
            native_dos_ah25_count,vector,va,req_eax,req_ebx,req_ecx,req_edx,req_esi,req_edi,req_ebp,req_esp,
            req_flags_k,req_flags_a,req_flags_b,req_cs,req_ds,req_es,req_fs,req_gs,req_ss,
            g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,
            g_flag_k,g_flag_a,g_flag_b,g_seg_cs,g_seg_ds,g_seg_es,g_seg_fs,g_seg_gs,g_seg_ss,
            req_cf,(unsigned)g_flag_cf,(unsigned)(result==GW_INTERRUPT_HANDLED));
        return result;
    }
#endif
    if (saw_dos_ah48_retry && vector == 0x21 && va == 0x000C3D46u) {
        saw_native_ah49_frontier=1; native_ah49_es=g_seg_es;
        native_ah49_eax=g_eax; native_ah49_ebx=g_ebx; native_ah49_ecx=g_ecx; native_ah49_edx=g_edx;
#if defined(GW_NATIVE_W1_092_HOST_BACKED_GUEST_MEMORY)
        gw_interrupt_result result=gw_dos_services_callback(vector,va,services);
        printf("NATIVE_DOS_AH49 request_es=%04x request_eax=%08x response_eax=%08x cf=%u handled=%u provider=guest_mcb remaining_blocks=%u\n",
            native_ah49_es,native_ah49_eax,g_eax,(unsigned)g_flag_cf,
            (unsigned)(result==GW_INTERRUPT_HANDLED),services->dos_block_count);
        fflush(stdout);
        /* A valid DOS AH=49 rejection (AX=9/CF=1 for an unknown block) is
         * guest-visible allocator state. Do not turn that DOS result into a
         * harness trap; let RationalAlloc_ consume it and choose its own path. */
        if (result!=GW_INTERRUPT_HANDLED) return GW_INTERRUPT_TRAPPED;
        saw_native_ah49_frontier=0;
        return result;
#else
        printf("NATIVE_AH49_FRONTIER es=%04x eax=%08x ebx=%08x ecx=%08x edx=%08x\n", native_ah49_es, native_ah49_eax, native_ah49_ebx, native_ah49_ecx, native_ah49_edx);
        return GW_INTERRUPT_TRAPPED;
#endif
    }
    if (saw_first_version_service && vector==0x21 && va==0x000AF93Au) {
        uint32_t in_eax=g_eax,in_ebx=g_ebx,in_ecx=g_ecx,in_edx=g_edx;
        uint32_t in_esi=g_esi,in_edi=g_edi,in_ebp=g_ebp,in_esp=g_esp;
        uint16_t in_ds=g_seg_ds; uint32_t in_ds_base=g_ds_base; uint8_t in_cf=(uint8_t)g_flag_cf;
        uint16_t in_cs=g_seg_cs; uint32_t in_flag_k=g_flag_k,in_flag_a=g_flag_a,in_flag_b=g_flag_b;
        char path[32]; size_t n=0; uint64_t off=(uint64_t)g_ds_base+g_edx;
        while(off+n<GW_NATIVE_GUEST_MEMORY_SIZE && n+1<sizeof path && guest_memory[off+n]) { path[n]=(char)guest_memory[off+n]; n++; }
        path[n]=0;
        gw_interrupt_result result=gw_dos_services_callback(vector,va,services);
        printf("NATIVE_DOS_AH43 vector=21 eip=%08x cs=%04x request_eax=%08x request_ebx=%08x request_ecx=%08x request_edx=%08x request_esi=%08x request_edi=%08x request_ebp=%08x request_esp=%08x ds=%04x ds_base=%08x request_flag_k=%08x request_flag_a=%08x request_flag_b=%08x path=%s response_eax=%08x response_ebx=%08x response_ecx=%08x response_edx=%08x response_esi=%08x response_edi=%08x response_ebp=%08x response_esp=%08x response_flag_k=%08x response_flag_a=%08x response_flag_b=%08x cf_in=%u cf_out=%u handled=%u\n",
               va,in_cs,in_eax,in_ebx,in_ecx,in_edx,in_esi,in_edi,in_ebp,in_esp,in_ds,in_ds_base,in_flag_k,in_flag_a,in_flag_b,path,
               g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,g_flag_k,g_flag_a,g_flag_b,in_cf,(unsigned)g_flag_cf,(unsigned)(result==GW_INTERRUPT_HANDLED));
        return result;
    }
#ifdef GW_NATIVE_CAPTURE_CRT_STARTUP
    if (saw_time_query && vector==0x21u && (uint8_t)(g_eax>>8)==0x2cu) {
        w1_crt_virtual_second=(uint8_t)((w1_crt_virtual_second+1u)%60u);
        if (!gw_dos_time_configure(services,0,0,w1_crt_virtual_second,5)) return GW_INTERRUPT_TRAPPED;
        return gw_dos_services_callback(vector,va,services);
    }
#endif
    if (saw_first_version_service) return GW_INTERRUPT_TRAPPED;
    return gw_dos_services_callback(vector, va, services);
}

int main(void) {
    SetUnhandledExceptionFilter(capture_native_exception);
#if defined(GW_NATIVE_W1_092_HOST_BACKED_GUEST_MEMORY)
    if (!native_guest_memory_reserve()) return 49;
    if (getenv("GWRECOMP_MEMORY_DIAG")) {
        recomp_memory_diag_enable(1);
        recomp_memory_diag_set_backing_validator(native_guest_memory_backed,guest_memory);
        const char *diag_begin=getenv("GWRECOMP_MEMORY_DIAG_GUEST_START");
        const char *diag_end=getenv("GWRECOMP_MEMORY_DIAG_GUEST_END");
        if (diag_begin && diag_end) {
            char *begin_end=0,*end_end=0;
            unsigned long long begin=strtoull(diag_begin,&begin_end,0);
            unsigned long long end=strtoull(diag_end,&end_end,0);
            if (!begin_end || *begin_end || !end_end || *end_end || end<=begin ||
                begin>0xffffffffull || end>0xffffffffull) return 51;
            recomp_memory_diag_set_guest_range((uint32_t)begin,(uint32_t)end);
            printf("NATIVE_MEMORY_DIAGNOSTICS enabled=1 backing=VirtualQuery stop=first_guest_fault guest_range=%08llx-%08llx\n",begin,end);
        } else {
            puts("NATIVE_MEMORY_DIAGNOSTICS enabled=1 backing=VirtualQuery stop=first_guest_fault guest_range=all");
        }
    }
#endif
    FILE *f = fopen("build/native_lift_boot.bin", "rb");
    if (!f) return 10;
    size_t got = fread(guest_memory, 1, GW_BOOT_MEM_SIZE, f);
    int extra = fgetc(f);
    fclose(f);
    if (got != GW_BOOT_MEM_SIZE || extra != EOF) return 11;
    if (*(uint16_t *)(guest_memory + GW_BOOT_PSP + 0x2C) != GW_BOOT_ENV_PSP_SELECTOR) return 12;
    if (guest_memory[GW_BOOT_PSP + 0x80] != GW_BOOT_TAIL_LENGTH ||
        memcmp(guest_memory + GW_BOOT_PSP + 0x81, GW_BOOT_TAIL, GW_BOOT_TAIL_LENGTH) != 0 ||
        guest_memory[GW_BOOT_PSP + 0x81 + GW_BOOT_TAIL_LENGTH] != 0x0D) return 18;
    gw_recomp_context context;
    const gw_guest_boot_seed seed = {
        GW_BOOT_ENTRY, GW_BOOT_ESP, GW_BOOT_CS, GW_BOOT_DS,
        GW_BOOT_ES, GW_BOOT_SS, GW_BOOT_UNKNOWN_ALL,
        (uintptr_t)guest_memory, GW_NATIVE_GUEST_MEMORY_SIZE
    };
    if (!gw_guest_boot_context_init(&context, &seed)) return 16;
    /* This native process seed uses the documented synthetic PSP selector
     * alias; preload the ES cache base because the initial ES selector is
     * already active before a lifted MOV ES can ask the resolver. */
    context.es_base = GW_BOOT_PSP;
    if (context.eip != GW_BOOT_ENTRY || context.esp != GW_BOOT_ESP ||
        context.flag_k != FK_NONE || context.fpu_cw != 0x037fu ||
        context.fs || context.gs || context.cur_func != GW_BOOT_ENTRY) return 17;
    gw_dos_services services = {0};
    gw_dos_services_init(&services);
#ifdef GW_NATIVE_SERVE_W3_CONFIG
    if (sizeof native_w3_config_fixture!=NATIVE_W3_CONFIG_SIZE ||
        NATIVE_W3_CONFIG_SIZE>sizeof native_w3_config_file.bytes) return 41;
    memcpy(native_w3_config_file.bytes,native_w3_config_fixture,sizeof native_w3_config_fixture);
    native_w3_config_file.size=(uint32_t)sizeof native_w3_config_fixture;
    native_w3_config_file.exists=1u;
    native_w3_config_file.ioctl_info_flags=0u;
    native_w3_config_file.drive_number=2u; /* original replay's writable C: drive */
#endif
#ifdef GW_NATIVE_SERVE_W3_ADDRESS_SEED
    if (sizeof native_w1_address_seed!=NATIVE_W1_ADDRESS_SIZE || NATIVE_W1_ADDRESS_SIZE>sizeof native_address_file.bytes) return 44;
    memcpy(native_address_file.bytes,native_w1_address_seed,sizeof native_w1_address_seed);
    native_address_file.size=(uint32_t)sizeof native_w1_address_seed;
    native_address_file.exists=1u;
    native_address_file.ioctl_info_flags=0u;
    native_address_file.drive_number=2u;
    native_address_file.written=0u;
    printf("NATIVE_W1_ADDRESS_SEED provider=virtual-memory initial_visibility=present path=C:\\ADDRESS.TXT bytes=%u sha256=%s drive=2 writable=1 source=tests/fixtures/w3_067_address_seed_work1.bin\n",
        NATIVE_W1_ADDRESS_SIZE,NATIVE_W1_ADDRESS_SHA256);
#endif
#ifdef GW_NATIVE_SERVE_W3_SOUND_INI
    if (sizeof native_w3_sound_ini_fixture!=NATIVE_W1_SOUND_INI_SIZE ||
        NATIVE_W1_SOUND_INI_SIZE>sizeof native_w3_sound_ini_file.bytes) return 45;
    memcpy(native_w3_sound_ini_file.bytes,native_w3_sound_ini_fixture,sizeof native_w3_sound_ini_fixture);
    native_w3_sound_ini_file.size=(uint32_t)sizeof native_w3_sound_ini_fixture;
    native_w3_sound_ini_file.exists=1u;
    native_w3_sound_ini_file.ioctl_info_flags=0u;
    native_w3_sound_ini_file.drive_number=2u;
    native_w3_sound_ini_file.written=0u;
    printf("NATIVE_W1_SOUND_INI_SEED provider=virtual-memory initial_visibility=present path=C:\\GENEWARS\\sound.ini bytes=%u sha256=%s access=read-only source=tests/fixtures/w3_069_sound_ini_work1.bin\n",
        NATIVE_W1_SOUND_INI_SIZE,NATIVE_W1_SOUND_INI_SHA256);
#endif
    if (!gw_dos_guest_memory_configure(&services, (uint32_t)GW_NATIVE_GUEST_MEMORY_SIZE)) return 29;
#if defined(GW_NATIVE_W1_092_HOST_BACKED_GUEST_MEMORY)
    if (!gw_dos_guest_memory_backing_configure(&services,native_guest_memory_prepare,guest_memory)) return 50;
#endif
#ifdef GW_NATIVE_CONTINUE_DPMI_AX6300
    {
        uint32_t env_bytes=GW_BOOT_ENV_LIMIT+1u;
        uint32_t free_segment=GW_BOOT_DOS_ALLOCATOR_BEGIN_SEGMENT;
        uint32_t conventional_top=GW_BOOT_DOS_ALLOCATOR_END_SEGMENT;
        if (!env_bytes || free_segment<(uint32_t)GW_BOOT_ENV_SEG+
                (env_bytes+15u)/16u+1u || free_segment<(GW_BOOT_PSP>>4) || free_segment>=conventional_top ||
            conventional_top>UINT16_MAX ||
#if defined(GW_NATIVE_W1_092_HOST_BACKED_GUEST_MEMORY)
            !native_seed_post_dos4gw_mcb() ||
#endif
            !gw_dos_memory_allocator_configure(&services,(uint16_t)free_segment,
                (uint16_t)conventional_top,GW_BOOT_PSP_SELECTOR,(uint16_t)(GW_BOOT_PSP>>4))) return 47;
        native_ax6300_state.services=&services;
        if (!gw_dos_real_mode_interrupt_configure(&services,
                native_dos_real_mode_interrupt,&native_ax6300_state)) return 48;
        if (!test_native_ax6300_provider_rejects_unsupported()) return 49;
        if (!test_native_mscdex_install_check_provider()) return 51;
        printf("NATIVE_AX6300_PROVIDER_SETUP env_segment=%04x env_bytes=%u free_segment=%04x conventional_top=%04x selector_search_start=%04x api=gw_dos_dbcs_table_configure callback=gw_dos_services_real_mode_interrupt\n",
            GW_BOOT_ENV_SEG,env_bytes,(unsigned)free_segment,(unsigned)conventional_top,GW_BOOT_PSP_SELECTOR);
        puts("NATIVE_AX6300_PROVIDER_REGRESSION unsupported_vector=trapped unsupported_ax=trapped no_allocation=1");
        puts("NATIVE_MSCDEX_INSTALL_CHECK_REGRESSION int2f_ax1500_bx0=zero_drives unsupported_ax_and_bx=trapped source=original_byte_w2_047");
    }
#endif
#ifdef GW_NATIVE_CONTINUE_DOS_AH40
    if (!gw_dos_stream_memory_configure(&services,0u,(uint32_t)GW_NATIVE_GUEST_MEMORY_SIZE) ||
        !gw_dos_stream_configure(&services,1u,0,native_stdout_write,0,1)) return 40;
#ifdef GW_NATIVE_CONTINUE_DOS_AX4400_CONSOLE
    /* W3-091 measured this device-information word for the configured CON
     * stream at the original BX=1 request. Supply it through the provider API. */
    if (!gw_dos_stream_ioctl_info_configure(&services,1u,0x80D3u)) return 46;
    printf("NATIVE_W1_AX4400_CONSOLE_PROVIDER_SETUP handle=1 device_info=80d3 source=W3-091:BX=1:CON\n");
#endif
#endif
#if defined(GW_NATIVE_CONTINUE_DPMI_LINEAR_SEQUENCE) || defined(GW_NATIVE_CONTINUE_DPMI_LINEAR_SUCCESS)
#ifndef GW_NATIVE_DPMI_ALLOCATOR_END
#define GW_NATIVE_DPMI_ALLOCATOR_END GW_NATIVE_GUEST_MEMORY_SIZE
#endif
    if (!gw_dos_linear_allocator_configure(&services, 0x00200000u,
                                           (uint32_t)GW_NATIVE_DPMI_ALLOCATOR_END)) return 30;
#ifdef GW_NATIVE_DPMI_ALLOCATOR_END_EXPERIMENTAL
    printf("NATIVE_DPMI_BUDGET kind=explicit_experiment begin=00200000 end=%08x bytes=%u original_equivalence=0\n",
           (uint32_t)GW_NATIVE_DPMI_ALLOCATOR_END,
           (uint32_t)GW_NATIVE_DPMI_ALLOCATOR_END-0x00200000u);
#endif
#endif
#if defined(GW_NATIVE_W1_092_HOST_BACKED_GUEST_MEMORY)
    printf("NATIVE_DPMI_GUEST_MEMORY_MAP kind=host_backed guest_begin=00000000 guest_end=%08x guest_capacity=%08x image_end=001b2000 allocation_begin=00200000 allocation_end=%08x lifetime=process_virtual_reservation backing=VirtualAlloc_commit_on_allocate\n",
           (uint32_t)GW_NATIVE_GUEST_MEMORY_SIZE,(uint32_t)GW_NATIVE_GUEST_MEMORY_SIZE,services.allocation_end);
#elif defined(GW_NATIVE_W1_091_HOST_BACKED_GUEST_MEMORY)
    printf("NATIVE_DPMI_GUEST_MEMORY_MAP kind=host_backed guest_begin=00000000 guest_end=%08x guest_capacity=%08x image_end=001b2000 allocation_begin=00200000 allocation_end=%08x lifetime=process_zeroed backing=guest_memory\n",
           (uint32_t)GW_NATIVE_GUEST_MEMORY_SIZE,(uint32_t)GW_NATIVE_GUEST_MEMORY_SIZE,services.allocation_end);
#endif
#ifdef GW_NATIVE_CONTINUE_DOS_AH3D
    if (!gw_dos_file_backend_configure(&services,native_replay_file_open,
            native_replay_file_read,native_replay_file_create,native_replay_file_write,
            native_replay_file_close,0)) return 31;
#ifdef GW_NATIVE_CONTINUE_DOS_AX4400
    if (!gw_dos_file_ioctl_info_configure(&services,native_replay_file_ioctl_info)) return 34;
    if (!gw_dos_file_seek_configure(&services,native_replay_file_seek)) return 36;
#endif
#endif
#ifdef GW_NATIVE_SERVE_W3_CONFIG
    if (!gw_dos_file_seek_configure(&services,native_replay_file_seek)) return 42;
#endif
    if (!gw_dos_descriptor_bind(&services, GW_BOOT_ENV_SELECTOR,
                                GW_BOOT_ENV_ADDRESS, GW_BOOT_ENV_LIMIT)) return 21;
    if (!gw_dos_descriptor_bind(&services, GW_BOOT_PSP_SELECTOR,
                                GW_BOOT_PSP, 0xFFu)) return 22;
    services.major = 6;
    services.minor = 22;
#ifdef GW_NATIVE_SERVE_W3_CONFIG
    if (!test_native_w3_config_provider(&services)) return 43;
#endif
#ifdef GW_NATIVE_TEST_DOS_AH49
    if (!test_measured_ah49_contract(&services)) return 27;
    puts("NATIVE_DOS_AH49_CONTRACT success=1 wrong_es_trapped=1 oracle_es=004c native_es=0014");
#endif
    gw_interrupt_set_callback(native_dos_callback, &services);
    gw_recomp_status status = gw_recomp_invoke(gw_entry_start, &context);
    if (recomp_memory_diag_enabled() && context.memory_fault.pending) {
        native_print_memory_diagnostic(stderr,"controlled_guest_memory_fault");
        fprintf(stderr,"NATIVE_MEMORY_FAULT eip=%08x segment=%u selector=%04x offset=%08x linear=%08x width=%u status=%u\n",
            context.memory_fault.instruction_va,context.memory_fault.segment,
            context.memory_fault.selector,context.memory_fault.offset,
            context.memory_fault.linear,context.memory_fault.width,(unsigned)status);
        return 80;
    }
    recomp_segment_fault segment_fault = recomp_get_segment_fault();
    if (segment_fault.pending) printf("NATIVE_SEGMENT_FAULT segment=%u selector=%04x eip=%08x\n", segment_fault.segment, segment_fault.selector, segment_fault.instruction_va);
#ifdef GW_NATIVE_CAPTURE_CRT_STARTUP
    {
        uint32_t argc = *(uint32_t *)(guest_memory + 0x001A6BBCu);
        uint32_t argv = *(uint32_t *)(guest_memory + 0x001A6BC0u);
        gw_interrupt_trap trap=gw_interrupt_get_trap();
        printf("W1_CRT_SUMMARY status=%u eip=%08x esp=%08x argc=%u argv=%08x icall_count=%u cur_func=%08x eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x ebp=%08x trap_pending=%u trap_vector=%02x trap_va=%08x segment_fault=%u segment_eip=%08x segment_selector=%04x\n",
               (unsigned)status, context.eip, context.esp, argc, argv, g_icall_count,
               g_cur_func,g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,
               trap.pending,trap.vector,trap.instruction_va,
               segment_fault.pending, segment_fault.instruction_va, segment_fault.selector);
        printf("NATIVE_NEXT_TRAP vector=%02x eip=%08x function=%08x eax=%08x ebx=%08x ecx=%08x edx=%08x esp=%08x\n",
               trap.vector,trap.instruction_va,context.interrupt_function_va,context.eax,context.ebx,
               context.ecx,context.edx,context.esp);
        printf("NATIVE_FRONTIER_CPU eip=%08x eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x ebp=%08x esp=%08x flag_k=%08x flag_a=%08x flag_b=%08x flag_cf=%u cs=%04x ds=%04x es=%04x fs=%04x gs=%04x ss=%04x cs_base=%08x ds_base=%08x es_base=%08x fs_base=%08x gs_base=%08x ss_base=%08x fpu_cw=%04x fp_top=%d trap_vector=%02x trap_eip=%08x\n",
               context.interrupt_instruction_va,context.eax,context.ebx,context.ecx,context.edx,
               context.esi,context.edi,context.ebp,context.esp,context.flag_k,context.flag_a,
               context.flag_b,context.flag_cf,context.cs,context.ds,context.es,context.fs,
               context.gs,context.ss,context.cs_base,context.ds_base,context.es_base,context.fs_base,
               context.gs_base,context.ss_base,context.fpu_cw,context.fp_top,trap.vector,trap.instruction_va);
#ifdef GW_NATIVE_CAPTURE_AX0501_STACK
        if (trap.pending && trap.vector==0x31u && trap.instruction_va==0x000C3CC1u) {
            uint32_t sp=context.esp;
            uint32_t words[12]={0};
            uint32_t valid=(sp<=GW_NATIVE_GUEST_MEMORY_SIZE- sizeof words);
            if (valid) for (uint32_t i=0;i<12u;++i) memcpy(&words[i],guest_memory+sp+i*4u,4u);
            printf("NATIVE_AX0501_STACK trap_va=%08x function=%08x esp=%08x ebp=%08x valid=%u",
                   trap.instruction_va,context.interrupt_function_va,sp,context.ebp,valid);
            for (uint32_t i=0;i<12u;++i) printf(" word%u=%08x",i,words[i]);
            printf(" segment_fault=%u segment_fault_eip=%08x segment_fault_selector=%04x\n",
                   segment_fault.pending,segment_fault.instruction_va,segment_fault.selector);
        }
#endif
        if (argc<=16u && argv<GW_NATIVE_GUEST_MEMORY_SIZE) for (uint32_t i=0;i<argc;i++) {
            uint64_t slot=(uint64_t)argv+i*4u;
            if (slot+4u>GW_NATIVE_GUEST_MEMORY_SIZE) break;
            uint32_t pointer=*(uint32_t *)(guest_memory+(size_t)slot);
            char value[256]; size_t n=0;
            while ((uint64_t)pointer+n<GW_NATIVE_GUEST_MEMORY_SIZE && n+1u<sizeof value && guest_memory[pointer+n]) { value[n]=(char)guest_memory[pointer+n]; n++; }
            value[n]=0;
            printf("W1_CRT_ARG index=%u pointer=%08x value=%s\n",i,pointer,value);
        }
#ifdef GW_NATIVE_CAPTURE_CRT_STARTUP
        for (uint32_t i=0;i<w1_crt_alloc_count;++i)
            printf("W1_CRT_ALLOC ordinal=%u request_eax=%08x request_ebx=%08x request_ecx=%08x request_edx=%08x response_eax=%08x response_ebx=%08x response_ecx=%08x response_edx=%08x response_esi=%08x response_edi=%08x size=%08x base=%08x handle=%08x\n",
                   i,w1_crt_allocs[i].req_eax,w1_crt_allocs[i].req_ebx,w1_crt_allocs[i].req_ecx,w1_crt_allocs[i].req_edx,
                   w1_crt_allocs[i].res_eax,w1_crt_allocs[i].res_ebx,w1_crt_allocs[i].res_ecx,w1_crt_allocs[i].res_edx,
                   w1_crt_allocs[i].res_esi,w1_crt_allocs[i].res_edi,w1_crt_allocs[i].size,w1_crt_allocs[i].base,w1_crt_allocs[i].handle);
        printf("W1_CRT_DPMI0300 count=%u frame=%08x inner_eax=%08x inner_ds=%04x inner_si=%04x fixture_semantics=empty_dbcs_table\n",
               w1_crt_dpmi0300_count,w1_crt_dpmi0300_frame,w1_crt_dpmi0300_inner_eax,
               w1_crt_dpmi0300_inner_ds,w1_crt_dpmi0300_inner_si);
#endif
        for (uint32_t i=0; i<19; ++i) {
            uint32_t entry=0x001126B8u+i*6u;
            printf("W1_CRT_TABLE index=%u state=%u priority=%u target=%08x\n",
                   i,guest_memory[entry],guest_memory[entry+1],*(uint32_t *)(guest_memory+entry+2));
        }
        uint32_t retained=g_icall_trace_idx<ICALL_TRACE_SIZE?g_icall_trace_idx:ICALL_TRACE_SIZE;
        uint32_t first=g_icall_trace_idx-retained;
        uint32_t ordinal=0;
        for (uint32_t i=first;i<g_icall_trace_idx;++i) {
            uint32_t slot=i&(ICALL_TRACE_SIZE-1u);
            if (g_icall_from[slot]==0x000C871Cu)
                printf("W1_CRT_CALLBACK ordinal=%u target=%08x\n",ordinal++,g_icall_trace[slot]);
        }
        if (argc<=32u && argv && argv<GW_NATIVE_GUEST_MEMORY_SIZE) {
            for (uint32_t i=0;i<argc;++i) {
                uint64_t slot=(uint64_t)argv+i*4u;
                if (slot+4u>GW_NATIVE_GUEST_MEMORY_SIZE) break;
                uint32_t ptr=*(uint32_t *)(guest_memory+(size_t)slot);
                printf("W1_MAIN_ARG index=%u pointer=%08x text=",i,ptr);
                if (ptr<GW_NATIVE_GUEST_MEMORY_SIZE) {
                    for (uint32_t j=0;j<256u && ptr+j<GW_NATIVE_GUEST_MEMORY_SIZE && guest_memory[ptr+j];++j)
                        putchar(guest_memory[ptr+j]);
                }
                putchar('\n');
            }
        }
    }
#endif
#ifdef GW_NATIVE_CAPTURE_CRT_STARTUP
    gw_interrupt_set_callback(NULL, NULL);
    return (status==GW_RECOMP_OK && saw_first_version_service) ? 0 : 13;
#endif
    gw_interrupt_set_callback(NULL, NULL);
    if (status != GW_RECOMP_OK || !saw_first_version_service) return 13;
#ifdef GW_NATIVE_CONTINUE_KNOWN
    if (!saw_dos4g_install_check) {
        fprintf(stderr, "expected measured DOS/4G install check to return AX=FFFF CF=0\n");
        return 19;
    }
#endif
#ifdef GW_NATIVE_CONTINUE_SELECTOR_QUERY
    if (!saw_selector_base_query) {
        fprintf(stderr, "expected measured DPMI AX=0006 selector query to return base 0 and CF=0\n");
        return 20;
    }
#endif
#ifdef GW_NATIVE_CONTINUE_TIME_QUERY
    if (!saw_time_query) {
        fprintf(stderr, "expected measured DOS AH=2Ch response\n");
        return 23;
    }
#endif
#ifdef GW_NATIVE_CONTINUE_DPMI_LINEAR
    if (!saw_dpmi_linear_alloc) {
        fprintf(stderr, "expected measured DPMI AX=0501 unavailable response\n");
        return 24;
    }
#endif
#if defined(GW_NATIVE_CONTINUE_DPMI_LINEAR_SUCCESS) && !defined(GW_NATIVE_CONTINUE_DPMI_LINEAR_SEQUENCE)
    if (!saw_dpmi_linear_alloc) {
        fprintf(stderr, "expected AX=0501 success inside the synthetic bounded guest-memory arena\n");
        return 31;
    }
#endif
#ifdef GW_NATIVE_CONTINUE_DOS_AH3D
    if (!saw_native_ah3d) {
        fprintf(stderr,"expected measured DOS AH=3D C:\\address.txt missing-file response\n");
        return 32;
    }
#endif
#ifdef GW_NATIVE_CONTINUE_DOS_AH3C
#ifdef GW_NATIVE_SERVE_W3_ADDRESS_SEED
    if (!saw_native_seeded_address_open) { fprintf(stderr,"expected authenticated ADDRESS.TXT to be visible in the bounded virtual provider\n"); return 33; }
#else
    if (!saw_native_ah3c) { fprintf(stderr,"expected measured DOS AH=3C c:\\address.txt create/truncate response\n"); return 33; }
#endif
#endif
#ifdef GW_NATIVE_CONTINUE_DOS_AX4400
#ifndef GW_NATIVE_CAPTURE_CRT_STARTUP
    if (!saw_native_ax4400) { fprintf(stderr,"expected DOS AX=4400 on active virtual file handle\n"); return 35; }
    if (!saw_native_ah42) { fprintf(stderr,"expected DOS AH=42 after four AX=4400 requests\n"); return 37; }
    if (!saw_native_ah3e) { fprintf(stderr,"expected DOS AH=3E after two AH=42 seeks\n"); return 38; }
    if (!saw_native_standard_ioctl) { fprintf(stderr,"expected DOS AX=4400 standard handle 2\n"); return 39; }
#endif
#endif
#ifdef GW_NATIVE_CONTINUE_DOS_AH40
#ifndef GW_NATIVE_CAPTURE_CRT_STARTUP
    if (!saw_native_ah40) { fprintf(stderr,"expected bounded AH=40 stdout at link VA 0x000D219C with captured guest bytes\n"); return 41; }
#endif
#endif
#ifdef GW_NATIVE_CONTINUE_DOS_AH48
    if (!saw_dos_ah48) {
        fprintf(stderr, "expected DOS AH=48 provider response\n");
        return 25;
    }
#endif
#ifdef GW_NATIVE_CONTINUE_DOS_AH48_RETRY
    if (!saw_dos_ah48_retry) {
        fprintf(stderr, "expected second DOS AH=48 provider response\n");
        return 26;
    }
#endif
#ifdef GW_NATIVE_CONTINUE_DPMI_LINEAR
    printf("NATIVE_DPMI_LINEAR vector=31 eip=000c3cc1 request_eax=%08x request_ebx=%08x request_ecx=%08x request_edx=%08x request_esi=%08x request_edi=%08x request_ebp=%08x request_esp=%08x response_eax=%08x response_ebx=%08x response_ecx=%08x response_edx=%08x response_esi=%08x response_edi=%08x response_ebp=%08x response_esp=%08x carry=%u handled=%u\n",
           (unsigned)alloc_req_eax,(unsigned)alloc_req_ebx,(unsigned)alloc_req_ecx,
           (unsigned)alloc_req_edx,(unsigned)alloc_req_esi,(unsigned)alloc_req_edi,
           (unsigned)alloc_req_ebp,(unsigned)alloc_req_esp,(unsigned)alloc_res_eax,
           (unsigned)alloc_res_ebx,(unsigned)alloc_res_ecx,(unsigned)alloc_res_edx,
           (unsigned)alloc_res_esi,(unsigned)alloc_res_edi,(unsigned)alloc_res_ebp,
           (unsigned)alloc_res_esp,(unsigned)alloc_res_carry,(unsigned)saw_dpmi_linear_alloc);
    printf("NATIVE_DPMI_LINEAR_STATE function=%08x flag_k=%08x flag_a=%08x flag_b=%08x flag_cf=%08x cs=%04x ds=%04x es=%04x ss=%04x cs_base=%08x ds_base=%08x es_base=%08x ss_base=%08x stack0=%08x stack1=%08x stack2=%08x stack3=%08x stack4=%08x stack5=%08x stack6=%08x stack7=%08x\n",
           (unsigned)0x000C3CA9u,(unsigned)alloc_req_flag_k,(unsigned)alloc_req_flag_a,
           (unsigned)alloc_req_flag_b,(unsigned)alloc_req_flag_cf,(unsigned)alloc_req_cs,
           (unsigned)alloc_req_ds,(unsigned)alloc_req_es,(unsigned)alloc_req_ss,
           (unsigned)alloc_req_cs_base,(unsigned)alloc_req_ds_base,(unsigned)alloc_req_es_base,
           (unsigned)alloc_req_ss_base,(unsigned)alloc_stack_words[0],(unsigned)alloc_stack_words[1],
           (unsigned)alloc_stack_words[2],(unsigned)alloc_stack_words[3],(unsigned)alloc_stack_words[4],
           (unsigned)alloc_stack_words[5],(unsigned)alloc_stack_words[6],(unsigned)alloc_stack_words[7]);
#endif
#if defined(GW_NATIVE_CONTINUE_DPMI_LINEAR_SUCCESS) && !defined(GW_NATIVE_CONTINUE_DPMI_LINEAR_SEQUENCE)
    printf("NATIVE_DPMI_LINEAR_SUCCESS vector=31 eip=000c3cc1 request_eax=%08x request_ebx=%08x request_ecx=%08x request_edx=%08x request_esi=%08x request_edi=%08x request_ebp=%08x request_esp=%08x response_eax=%08x response_ebx=%08x response_ecx=%08x response_edx=%08x response_esi=%08x response_edi=%08x response_ebp=%08x response_esp=%08x carry=%u handled=%u synthetic_base=%08x synthetic_size=%08x synthetic_handle=%08x\n",
           (unsigned)alloc_req_eax,(unsigned)alloc_req_ebx,(unsigned)alloc_req_ecx,
           (unsigned)alloc_req_edx,(unsigned)alloc_req_esi,(unsigned)alloc_req_edi,
           (unsigned)alloc_req_ebp,(unsigned)alloc_req_esp,(unsigned)alloc_res_eax,
           (unsigned)alloc_res_ebx,(unsigned)alloc_res_ecx,(unsigned)alloc_res_edx,
           (unsigned)alloc_res_esi,(unsigned)alloc_res_edi,(unsigned)alloc_res_ebp,
           (unsigned)alloc_res_esp,(unsigned)alloc_res_carry,(unsigned)saw_dpmi_linear_alloc,
           (unsigned)alloc_success_base,(unsigned)alloc_success_size,(unsigned)alloc_success_handle);
    printf("NATIVE_DPMI_LINEAR_STATE function=%08x flag_k=%08x flag_a=%08x flag_b=%08x flag_cf=%08x cs=%04x ds=%04x es=%04x ss=%04x cs_base=%08x ds_base=%08x es_base=%08x ss_base=%08x stack0=%08x stack1=%08x stack2=%08x stack3=%08x stack4=%08x stack5=%08x stack6=%08x stack7=%08x\n",
           (unsigned)0x000C3CA9u,(unsigned)alloc_req_flag_k,(unsigned)alloc_req_flag_a,
           (unsigned)alloc_req_flag_b,(unsigned)alloc_req_flag_cf,(unsigned)alloc_req_cs,
           (unsigned)alloc_req_ds,(unsigned)alloc_req_es,(unsigned)alloc_req_ss,
           (unsigned)alloc_req_cs_base,(unsigned)alloc_req_ds_base,(unsigned)alloc_req_es_base,
           (unsigned)alloc_req_ss_base,(unsigned)alloc_stack_words[0],(unsigned)alloc_stack_words[1],
           (unsigned)alloc_stack_words[2],(unsigned)alloc_stack_words[3],(unsigned)alloc_stack_words[4],
           (unsigned)alloc_stack_words[5],(unsigned)alloc_stack_words[6],(unsigned)alloc_stack_words[7]);
#endif
#ifdef GW_NATIVE_CONTINUE_DOS_AH48
    printf("NATIVE_DOS_AH48 vector=21 eip=000c3d21 request_eax=%08x request_ebx=%08x request_ecx=%08x request_edx=%08x request_esi=%08x request_edi=%08x request_ebp=%08x request_esp=%08x response_eax=%08x response_ebx=%08x response_ecx=%08x response_edx=%08x response_esi=%08x response_edi=%08x response_ebp=%08x response_esp=%08x carry=%u handled=%u\n",
           (unsigned)dos48_req_eax,(unsigned)dos48_req_ebx,(unsigned)dos48_req_ecx,(unsigned)dos48_req_edx,
           (unsigned)dos48_req_esi,(unsigned)dos48_req_edi,(unsigned)dos48_req_ebp,(unsigned)dos48_req_esp,
           (unsigned)dos48_res_eax,(unsigned)dos48_res_ebx,(unsigned)dos48_res_ecx,(unsigned)dos48_res_edx,
           (unsigned)dos48_res_esi,(unsigned)dos48_res_edi,(unsigned)dos48_res_ebp,(unsigned)dos48_res_esp,
           (unsigned)dos48_res_carry,(unsigned)saw_dos_ah48);
#endif
#ifdef GW_NATIVE_CONTINUE_DOS_AH48_RETRY
    printf("NATIVE_DOS_AH48_RETRY vector=21 eip=000c3d35 request_eax=%08x request_ebx=%08x request_ecx=%08x request_edx=%08x request_esi=%08x request_edi=%08x request_ebp=%08x request_esp=%08x response_eax=%08x response_ebx=%08x response_ecx=%08x response_edx=%08x response_esi=%08x response_edi=%08x response_ebp=%08x response_esp=%08x carry=%u handled=%u\n",
           (unsigned)dos48r_req_eax,(unsigned)dos48r_req_ebx,(unsigned)dos48r_req_ecx,(unsigned)dos48r_req_edx,
           (unsigned)dos48r_req_esi,(unsigned)dos48r_req_edi,(unsigned)dos48r_req_ebp,(unsigned)dos48r_req_esp,
           (unsigned)dos48r_res_eax,(unsigned)dos48r_res_ebx,(unsigned)dos48r_res_ecx,(unsigned)dos48r_res_edx,
           (unsigned)dos48r_res_esi,(unsigned)dos48r_res_edi,(unsigned)dos48r_res_ebp,(unsigned)dos48r_res_esp,
           (unsigned)dos48r_res_carry,(unsigned)saw_dos_ah48_retry);
#endif
#ifdef GW_NATIVE_CONTINUE_KNOWN
    puts("NATIVE_DOS_SERVICE vector=21 eip=000afaa8 request_ax=0000ff00 edx=00000078 response_ax=0000ffff carry=0 handled=1");
#endif
#ifdef GW_NATIVE_CONTINUE_SELECTOR_QUERY
    printf("NATIVE_DPMI_SERVICE vector=31 eip=000afac4 request_ax=%04x selector=%04x ds_base=%08x response_cx=%04x response_dx=%04x carry=%u handled=1 es_selector=%04x es_base=%08x env_slot=%04x psp_env=%04x\n",
           (unsigned)dpmi_query_ax, (unsigned)dpmi_query_selector,
           (unsigned)dpmi_query_ds_base, (unsigned)dpmi_query_cx,
           (unsigned)dpmi_query_dx, (unsigned)dpmi_query_carry,
           (unsigned)dpmi_query_es_selector, (unsigned)dpmi_query_es_base,
           (unsigned)dpmi_query_env_slot,
           (unsigned)*(uint16_t *)(guest_memory + GW_BOOT_PSP + 0x2C));
#endif
#ifdef GW_NATIVE_CONTINUE_TIME_QUERY
    printf("NATIVE_DOS_TIME vector=21 eip=000d5b24 request_eax=%08x request_ebx=%08x request_ecx=%08x request_edx=%08x response_eax=%08x response_ebx=%08x response_ecx=%08x response_edx=%08x carry=%u handled=%u\n",
           (unsigned)time_request_eax, (unsigned)time_request_ebx,
           (unsigned)time_request_ecx, (unsigned)time_request_edx,
           (unsigned)time_query_eax, (unsigned)time_query_ebx,
           (unsigned)time_query_ecx, (unsigned)time_query_edx,
           (unsigned)time_query_carry, (unsigned)saw_time_query);
#endif
#ifdef GW_NATIVE_CONTINUE_DOS_AH3D
    printf("NATIVE_DOS_AH3D_FINAL request_eax=%08x request_ebx=%08x request_ecx=%08x request_edx=%08x response_eax=%08x response_ebx=%08x response_ecx=%08x response_edx=%08x response_esi=%08x response_edi=%08x response_ebp=%08x response_esp=%08x cf_in=%u cf_out=%u handled=%u path=%s\n",
           (unsigned)ah3d_req_eax,(unsigned)ah3d_req_ebx,(unsigned)ah3d_req_ecx,
           (unsigned)ah3d_req_edx,(unsigned)ah3d_res_eax,(unsigned)ah3d_res_ebx,
           (unsigned)ah3d_res_ecx,(unsigned)ah3d_res_edx,(unsigned)ah3d_res_esi,
           (unsigned)ah3d_res_edi,(unsigned)ah3d_res_ebp,(unsigned)ah3d_res_esp,
           (unsigned)ah3d_req_cf,(unsigned)ah3d_res_cf,(unsigned)saw_native_ah3d,ah3d_path);
#endif
    if (!context.interrupt_trap_pending || context.interrupt_instruction_va == 0x000AFA09u) {
#ifdef GW_NATIVE_CONTINUE_SELECTOR_QUERY
        if (saw_selector_base_query && !context.interrupt_trap_pending) {
            printf("NATIVE_RETURN_AFTER_DPMI vector=31 eip=000afac4 function=%08x eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x esp=%08x ds=%04x memory_fault=%u memory_instruction=%08x memory_segment=%u memory_selector=%04x memory_offset=%08x memory_width=%u memory_linear=%08x segment_fault=%u segment_instruction=%08x segment_selector=%04x\n",
                   g_cur_func, g_eax, g_ebx, g_ecx, g_edx, g_esi, g_esp, g_seg_ds,
                   context.memory_fault.pending, context.memory_fault.instruction_va,
                   context.memory_fault.segment, context.memory_fault.selector,
                   context.memory_fault.offset, context.memory_fault.width,
                   context.memory_fault.linear, context.segment_fault_pending,
                   context.segment_fault_instruction_va, context.segment_fault_selector);
            puts("NATIVE_FRONTIER generated entry returned with bounded CPU/fault state captured");
            return 0;
        }
#endif
        fprintf(stderr, "expected next interrupt trap pending=%u vector=%02x eip=%08x function=%08x status=%d\n",
                context.interrupt_trap_pending, context.interrupt_vector,
                context.interrupt_instruction_va, context.interrupt_function_va, (int)status);
        return 14;
    }
    if (guest_memory[0x10B797] != 6 || guest_memory[0x10B798] != 22) return 15;
#ifdef GW_NATIVE_CONTINUE_DOS_AH40
    if (native_stdout_size>sizeof native_stdout_bytes) return 42;
    printf("NATIVE_DOS_STDOUT_CAPTURE size=%u hex=",native_stdout_size);
    for (uint32_t i=0;i<native_stdout_size;i++) printf("%02x",native_stdout_bytes[i]);
    putchar('\n');
#endif
    printf("NATIVE_NEXT_TRAP vector=%02x eip=%08x function=%08x eax=%08x ebx=%08x ecx=%08x edx=%08x esp=%08x\n",
           context.interrupt_vector, context.interrupt_instruction_va,
           context.interrupt_function_va, context.eax, context.ebx,
           context.ecx, context.edx, context.esp);
    printf("NATIVE_TRAP_STATE esi=%08x edi=%08x ebp=%08x flag_k=%08x flag_a=%08x flag_b=%08x flag_cf=%u cs=%04x ds=%04x es=%04x ss=%04x\n",
           context.esi, context.edi, context.ebp, context.flag_k,
           context.flag_a, context.flag_b, context.flag_cf,
           context.cs, context.ds, context.es, context.ss);
    printf("NATIVE_FRONTIER_CPU eip=%08x eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x ebp=%08x esp=%08x flag_k=%08x flag_a=%08x flag_b=%08x flag_cf=%u cs=%04x ds=%04x es=%04x fs=%04x gs=%04x ss=%04x cs_base=%08x ds_base=%08x es_base=%08x fs_base=%08x gs_base=%08x ss_base=%08x fpu_cw=%04x fp_top=%d trap_vector=%02x trap_eip=%08x\n",
           context.interrupt_instruction_va,context.eax,context.ebx,context.ecx,context.edx,
           context.esi,context.edi,context.ebp,context.esp,context.flag_k,context.flag_a,
           context.flag_b,context.flag_cf,context.cs,context.ds,context.es,context.fs,
           context.gs,context.ss,context.cs_base,context.ds_base,context.es_base,
           context.fs_base,context.gs_base,context.ss_base,context.fpu_cw,context.fp_top,
           context.interrupt_vector,context.interrupt_instruction_va);
    for (uint32_t i=0;i<services.descriptor_count;i++) { const gw_dos_descriptor *d=&services.descriptors[i]; printf("NATIVE_FRONTIER_DESCRIPTOR selector=%04x base=%08x limit=%08x\n",d->selector,d->base,d->limit); }
    for (uint32_t i=0;i<services.dos_block_count;i++) { const gw_dos_memory_block *b=&services.dos_blocks[i]; printf("NATIVE_FRONTIER_DOS_BLOCK selector=%04x segment=%04x paragraphs=%04x\n",b->selector,b->segment,b->paragraphs); }
    printf("NATIVE_FRONTIER_ALLOC dos_configured=%u dos_begin=%04x dos_end=%04x dos_cursor=%04x selector_begin=%04x selector_cursor=%04x linear_configured=%u linear_cursor=%08x linear_end=%08x next_handle=%08x measured_ah48_active=%u measured_ah48_value=%04x streams_configured=%u\n",
           services.dos_allocator_configured,services.dos_segment_begin,services.dos_segment_end,
           services.dos_segment_cursor,services.dos_selector_begin,services.dos_selector_cursor,
           services.allocation_configured,services.allocation_cursor,services.allocation_end,
           services.next_allocation_handle,services.measured_ah48_active,services.measured_ah48_segment,
           services.stream_memory_configured);
    if (!write_frontier_memory_if_requested()) { fprintf(stderr,"frontier memory snapshot write failed\n"); return 28; }
#ifdef GW_NATIVE_CONTINUE_KNOWN
#ifdef GW_NATIVE_CONTINUE_SELECTOR_QUERY
    puts("PASS native fixed-link entry handled DOS AH=30, DOS/4G install check, DPMI selector-base query, then resumed to next bounded host trap");
#else
    puts("PASS native fixed-link entry handled DOS AH=30 and measured DOS/4G install check, then resumed to next bounded host trap");
#endif
#else
    puts("PASS native fixed-link entry handled DOS AH=30, wrote guest version bytes, resumed generated code, and reached next host trap");
#endif
    return 0;
}






