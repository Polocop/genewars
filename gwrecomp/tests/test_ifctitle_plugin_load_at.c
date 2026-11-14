#include "recomp_context.h"
#include "gw_dos_services.h"
#include "gw_interrupts.h"
#include "gw_recomp_trace.h"
#include "gw_segments.h"
#include "gw_vbe_provider.h"
#define SDL_MAIN_HANDLED
#include <SDL.h>
#include <windows.h>
#include <bcrypt.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <direct.h>

/* The generated closure defines this original entry in a separate C unit;
   the exact indirect dispatcher below needs its declaration here. */
extern void gw_partial_LbMemoryFree(void);
extern void recomp_gw_partial_W_setup_host_n_v(void);
/* These are the eight original, no-argument setup_game world-array
   initializers called at 0x95434..0x95457. The closure already contains
   their exact LE bodies; keep them as original calls, not host-side memset. */
extern void recomp_gw_partial_W_InitArray_Creature_n_v(void);
extern void recomp_gw_partial_W_InitArray_Plant_n_v(void);
extern void recomp_gw_partial_W_InitArray_PlSpec_n_v(void);
extern void recomp_gw_partial_W_InitArray_Building_n_v(void);
extern void recomp_gw_partial_W_InitArray_Effect_n_v(void);
extern void recomp_gw_partial_W_InitArray_Event_n_v(void);
extern void recomp_gw_partial_W_InitArray_Drone_n_v(void);
extern void recomp_gw_partial_W_InitArray_UnknArr01_n_v(void);

#define DOS_CONVENTIONAL_TOP 0x0000A000u

static int guest_path_has_suffix(const char *path,const char *suffix);

/* Keep a compact guest/host location when a deep original call chain exhausts
   the native thread stack. This is diagnostic only and does not resume the
   guest or convert the exception into success. */
static LONG WINAPI gw_capture_unhandled_exception(EXCEPTION_POINTERS *info) {
    if (!info || !info->ExceptionRecord || !info->ContextRecord)
        return EXCEPTION_EXECUTE_HANDLER;
    const EXCEPTION_RECORD *record=info->ExceptionRecord;
    const CONTEXT *context=info->ContextRecord;
    fprintf(stderr,
        "HOST_EXCEPTION code=%08lx host_pc=%08lx host_sp=%08lx host_bp=%08lx guest_eip=%08x "
        "guest_func=%08x regs=%08x/%08x/%08x/%08x/%08x/%08x/%08x/%08x "
        "icalls=%u ring_begin=%u\n",
        (unsigned long)record->ExceptionCode,(unsigned long)(uintptr_t)record->ExceptionAddress,
        (unsigned long)context->Esp,(unsigned long)context->Ebp,
        gw_recomp_last_guest_instruction(),g_cur_func,
        g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,g_icall_count,
        g_icall_trace_idx>16u?g_icall_trace_idx-16u:0u);
    uintptr_t frame=(uintptr_t)context->Ebp;
    for(uint32_t depth=0;depth<24u && frame;depth++) {
        MEMORY_BASIC_INFORMATION info;
        if(!VirtualQuery((const void *)frame,&info,sizeof info) ||
           info.State!=MEM_COMMIT || frame+2u*sizeof(uintptr_t)>
               (uintptr_t)info.BaseAddress+(uintptr_t)info.RegionSize) break;
        const uintptr_t *words=(const uintptr_t *)frame;
        uintptr_t next=words[0],ret=words[1];
        fprintf(stderr,"HOST_FRAME depth=%u ebp=%08lx return=%08lx next=%08lx\n",
            depth,(unsigned long)frame,(unsigned long)ret,(unsigned long)next);
        if(next<=frame || next-frame>0x00100000u) break;
        frame=next;
    }
    uint32_t begin=g_icall_trace_idx>16u?g_icall_trace_idx-16u:0u;
    for(uint32_t sequence=begin;sequence<g_icall_trace_idx;sequence++) {
        uint32_t slot=sequence&(ICALL_TRACE_SIZE-1u);
        fprintf(stderr,"HOST_EXCEPTION_CALL seq=%u target=%08x caller=%08x\n",
            sequence,g_icall_trace[slot],g_icall_from[slot]);
    }
    fflush(stderr);
    return EXCEPTION_EXECUTE_HANDLER;
}

void gw_partial_LbDataLoad(void);
void gw_partial_LbDataLoadAll(void);
void gw_original_getconfigs_entry(void);
void gw_original_text_parser_entry(void);
void gw_original_text_clip_entry(void);
void gw_original_setup_input_state_entry(void);
void gw_original_setup_game_color_lookups_entry(void);
void gw_original_setup_game_prefix_entry(void);
void gw_original_setup_game_record_table_entry(void);
void gw_original_setup_game_startup_resources_entry(void);
void gw_original_setup_game_font_initializers_entry(void);
void gw_original_setup_game_vector_init_entry(void);
void recomp_gw_partial_W_setup_game_n_v(void);
void gw_original_draw_game_level_palette_fade_entry(void);
void gw_original_setup_controller_entry(void);
void gw_original_game_frame_timer_tick_entry(void);
void gw_partial_LbMemorySetup(void);
void gw_partial_LbMemoryAlloc(void);
void gw_partial_LbMemoryAllocLow(void);
void gw_partial_UnpackM1(void);
void gw_partial_0x00092670(void);
void gw_partial_0x00014BB0(void);
void gw_partial_mem_putc(void);
void gw_partial_0x000830F0(void);
void gw_partial_InitRtns(void);
void gw_partial_0x000AF9E4(void);
void gw_partial_0x0001C440(void);
void gw_partial_delay_init(void);
void gw_partial_setEFGfmt(void);
void gw_partial_j___sys_init_387_emulator(void);
void gw_partial_chk8087(void);
void gw_partial_clock_init(void);
void gw_partial_0x000AC3B4(void);
void gw_partial_Init_Argv(void);
void gw_partial_InitFiles(void);
void gw_partial_W_init_n_v(void);
void gw_partial_checkIsDBCS(void);
void gw_partial_W_init_n_v_0(void);
void gw_partial_W_init_n_v_1(void);
void gw_partial_0x000D21EE(void);
void gw_partial_init(void);
void gw_partial_setenvp(void);
void gw_partial_W_longjmpInit_n_v(void);
void gw_partial_verify_pentium_fdiv_bug(void);
void gw_partial_0x0002C3D0(void);
void gw_partial_0x0002C520(void);
void gw_partial_0x0002C560(void);
void gw_partial_0x00034F50(void);
void gw_partial_0x000834A0(void);
void gw_partial_0x000957B0(void);
void gw_partial_0x00069C80(void);
void gw_partial_0x000957C0(void);
void gw_partial_0x000957E0(void);
void gw_partial_0x000957D0(void);
void gw_partial_0x00095830(void);
void gw_partial_0x00095880(void);
void gw_partial_0x00095890(void);
void gw_partial_0x000958E0(void);
void gw_partial_0x0001B650(void);
void gw_partial_0x0001B640(void);
void gw_partial_0x0001B630(void);
void gw_partial_0x0001B620(void);
void gw_partial_W_PlugIn_IFCLevel_n_v(void);
void gw_partial_W_PullOut_IFCLevel_n_v(void);
void gw_partial_W_Draw_IFCLevel_n_v(void);
void gw_partial_W_Update_IFCLevel_n_v(void);
void gw_partial_file_putc(void);
void gw_partial_W_PlugIn_IFCTitle_n_v(void);
void gw_partial_W_PullOut_IFCTitle_n_v(void);
void gw_original_bscreen_alloc_store(void);
void gw_original_ifctitle_update_adjustment_thunk(void);
void gw_original_control_game_update_dispatch(void);
void recomp_gw_partial_W_control_game_n_v(void);
void recomp_gw_partial_W_process_packets_n_v(void);
void gw_original_game_interface_transition_entry(void);
void gw_original_ifctitle_pullout_adjustment_thunk(void);
void gw_original_ifctitle_return_plugin_adjustment_thunk(void);
void gw_original_ifcoptions_plugin_adjustment_thunk(void);
void gw_original_ifcoptions_update_adjustment_thunk(void);
void gw_original_ifcoptions_draw_adjustment_thunk(void);
void gw_original_ifcoptions_pullout_adjustment_thunk(void);
void gw_original_ifctitle_draw_adjustment_thunk(void);
void gw_original_draw_game_draw_dispatch(void);
void gw_partial_0x00070EB0(void);
void gw_partial_0x0006A3D0(void);
void gw_partial_0x0006AB30(void);
void gw_partial_0x0006A700(void);
void gw_partial_0x0006A600(void);
void gw_partial_0x000710B0(void);
void gw_partial_LbPaletteSet(void);
void gw_original_install_resource_callback(void);
int gw_partial_install_code_map(void);
recomp_func_t gw_partial_lookup_guest(uint32_t va);
void gw_original_null_callback_98c18(void);
void gw_partial_LbScreenSetup(void);
void recomp_gw_partial_0x000D2344(void);
void recomp_gw_partial_0x000D23A7(void);
void recomp_gw_partial_0x000D23AD(void);
void recomp_gw_partial_0x000D71E0(void);
void recomp_gw_partial_0x000D7230(void);
void gw_partial_SmackInternal010(void);
void gw_partial_SmackInternal011(void);
void gw_partial_SmackInternal012(void);
void gw_partial_SmackInternal013(void);
void gw_partial_SmackInternalSwitch1_case000(void);
void gw_partial_0x000EC040(void);
void gw_partial_0x000EBFD0(void);
void gw_partial_0x000EC5C4(void);
void gw_partial_0x000EC000(void);
void gw_partial_0x000ECC04(void);
void gw_partial_SmackInternalSwitch1_case255(void);
void gw_partial_0x000EC284(void);
void gw_partial_0x000EC030(void);

uint32_t g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,g_cur_func;
uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_fs,g_seg_gs,g_seg_ss,g_fpu_cw;
uint32_t g_fs_base,g_gs_base;
ptrdiff_t g_mem_base;
double g_st[8]; int g_fp_top;
uint32_t g_flag_k,g_flag_a,g_flag_b,g_flag_cf;
uint32_t g_icall_trace[ICALL_TRACE_SIZE],g_icall_from[ICALL_TRACE_SIZE];
uint32_t g_icall_trace_idx,g_icall_count;
static uint32_t g_ifclevel_draw_dispatch_target,g_ifclevel_draw_dispatch_caller;
static uint32_t g_ifclevel_draw_dispatch_count;
void gw_test_ifclevel_draw_dispatch(uint32_t target) {
    g_ifclevel_draw_dispatch_target=target;
    g_ifclevel_draw_dispatch_caller=g_cur_func;
    g_ifclevel_draw_dispatch_count++;
}
static int g_rational_stack_trace_armed;
static uint32_t g_rational_stack_trace_rows;
static uint32_t g_rational_ah48_failures,g_rational_ah49_frees;
static uint32_t g_rational_blocks_before_free,g_rational_blocks_after_free;
static int g_rational_fallback_waiting_for_free,g_rational_ret_marker_seen;
static int g_rational_stack_capture_done;
static uint32_t g_ah48_trace_rows;
static uint32_t g_int33_user_callback_linear;
static uint32_t g_int33_user_callback_link;
static uint16_t g_int33_user_callback_mask;
static unsigned g_int33_user_callback_registrations;
typedef struct { uint32_t stage,target; } transition_dispatch_observation;
static transition_dispatch_observation g_transition_dispatch[8];
static uint32_t g_transition_dispatch_count;
static int g_transition_dispatch_enabled;
void gw_capture_original_transition_dispatch(uint32_t stage,uint32_t target) {
    if(!g_transition_dispatch_enabled || g_transition_dispatch_count>=8u) return;
    g_transition_dispatch[g_transition_dispatch_count].stage=stage;
    g_transition_dispatch[g_transition_dispatch_count].target=target;
    g_transition_dispatch_count++;
}
void gw_trace_heap_step(uint32_t site,uint32_t eax,uint32_t ebx,uint32_t ecx,
    uint32_t edx,uint32_t esi,uint32_t edi,uint32_t ebp,uint32_t esp,uint32_t stackword) {
    static struct { uint32_t site, count; } seen[24];
    static uint32_t seen_count;
    for (uint32_t i=0;i<seen_count;i++) {
        if (seen[i].site==site) {
            if (seen[i].count++>=4u) return;
            goto emit;
        }
    }
    if (seen_count<sizeof(seen)/sizeof(seen[0])) {
        seen[seen_count].site=site; seen[seen_count].count=1; seen_count++;
    } else return;
emit:
    fprintf(stderr,"TRACE HEAP site=%08x eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x ebp=%08x esp=%08x top=%08x\n",
        site,eax,ebx,ecx,edx,esi,edi,ebp,esp,stackword);
}
void gw_trace_stack_remaining(uint32_t site,uint32_t remaining,uint32_t esp) {
    static uint32_t count;
    if(count++>=16u) return;
    fprintf(stderr,"TRACE original stack guard site=%08x D21E4_remaining=%08x ESP=%08x threshold=000000b0\n",
        site,remaining,esp);
}
void gw_trace_fatal_message(uint32_t message_va,uint32_t mode) {
    fprintf(stderr,"TRACE original Watcom fatal-message callsite=C8A3B message_link=%08x mode=%08x\n",
        message_va,mode);
}
static uint32_t stack_word_at(uint64_t address);
void gw_trace_do_exit(uint32_t eax,uint32_t edx,uint32_t esp) {
    fprintf(stderr,"TRACE original Watcom do_exit_with_msg entry eax=%08x edx=%08x esp=%08x return=%08x\n",
        eax,edx,esp,stack_word_at(esp));
}
void gw_trace_fini_rtns(uint32_t eax,uint32_t edx,uint32_t esp) {
    fprintf(stderr,"TRACE original Watcom FiniRtns entry eax=%08x edx=%08x esp=%08x return=%08x\n",
        eax,edx,esp,stack_word_at(esp));
}
void gw_trace_control_entry(uint32_t target,uint32_t eax,uint32_t ebp,uint32_t esp);
static uint64_t startup_budget_remaining,startup_budget_executed;
static uint32_t startup_budget_last_va,startup_budget_last_func;
static int startup_budget_exhausted;
int g_full_instruction_trace;
static uint8_t *guest_memory;
/* Opt-in capture of the original MapDisplay candidate/picking function.
   The lifted function calls this observer at 0x78B30 entry; it never alters
   guest state or registers. */
static int g_map_pick_trace_active;
static uint32_t g_map_pick_trace_tick;
static uint32_t g_map_pick_raw_calls,g_map_pick_first_map,g_map_pick_first_candidate;
static uint32_t g_map_pick_calls,g_map_pick_ttype5,g_map_pick_field2d_eq5;
static uint32_t g_map_pick_type_counts[16];
static uint32_t g_map_pick_first5,g_map_pick_first5_x,g_map_pick_first5_y;
#define GW_MAP_CENSUS_CAP 4096u
typedef struct gw_map_census_row {
    uint32_t ptr,first_tick,last_tick,calls,projected_count;
    int32_t screen_x,screen_y;
    uint8_t thing_type,field_2d,field_45,field_46,field_4c;
    int16_t world_x,world_y;
    const char *array_name;
    uint32_t array_index;
} gw_map_census_row;
static gw_map_census_row g_map_census[GW_MAP_CENSUS_CAP];
static uint32_t g_map_census_count;
static gw_map_census_row *gw_map_census_find(uint32_t p) {
    gw_map_census_row *r=NULL;
    for(uint32_t i=0;i<g_map_census_count;i++) if(g_map_census[i].ptr==p) { r=&g_map_census[i]; break; }
    if(!r) {
        if(g_map_census_count>=GW_MAP_CENSUS_CAP) return NULL;
        r=&g_map_census[g_map_census_count++];
        memset(r,0,sizeof(*r)); r->ptr=p; r->first_tick=g_map_pick_trace_tick;
        r->last_tick=g_map_pick_trace_tick; r->screen_x=r->screen_y=INT32_MIN;
        r->array_name="not-in-known-BioGame-array";
        /* These extents and strides are from exact 1.1 MAP/InitArray_* evidence. */
        struct range { uint32_t start,end,stride; const char *name; };
        static const struct range ranges[]={
            {0x0032DF86u,0x003360D6u,0x7Cu,"BioGame::__creatures"},
            {0x003360D6u,0x0033C2D6u,0x31u,"BioGame::__plants"},
            {0x0033C2D6u,0x0033D276u,0xC8u,"BioGame::__team"},
            {0x0033D276u,0x00341576u,0x43u,"BioGame::__buildings"},
            {0x00341576u,0x003454BEu,0x51u,"BioGame::__effects"},
            {0x003454BEu,0x00345ADEu,0x31u,"BioGame::__events"},
            {0x00345ADEu,0x003466FEu,0x61u,"BioGame::__drones"},
            {0x003466FEu,0x00346CFEu,0x66u,"BioGame::__unkarr01"}
        };
        for(unsigned i=0;i<sizeof(ranges)/sizeof(ranges[0]);i++) if(p>=ranges[i].start&&p<ranges[i].end) {
            uint32_t off=p-ranges[i].start; r->array_name=ranges[i].name;
            r->array_index=off/ranges[i].stride;
            if(off%ranges[i].stride) r->array_name="array-interior-pointer";
            break;
        }
    }
    /* Refresh the sample at each encounter; state fields can evolve over ticks. */
    if(guest_memory && p<=0x03002000u-0x80u) {
        r->thing_type=guest_memory[p+6u]; r->field_2d=guest_memory[p+0x2Du];
        r->field_45=guest_memory[p+0x45u]; r->field_46=guest_memory[p+0x46u];
        r->field_4c=guest_memory[p+0x4Cu];
        r->world_x=(int16_t)(guest_memory[p+7u]|((uint16_t)guest_memory[p+8u]<<8));
        r->world_y=(int16_t)(guest_memory[p+9u]|((uint16_t)guest_memory[p+10u]<<8));
    }
    return r;
}
void gw_test_mapdisplay_pick_candidate(uint32_t map,uint32_t candidate) {
    if(!g_map_pick_trace_active) return;
    g_map_pick_raw_calls++;
    if(g_map_pick_raw_calls==1u) {
        g_map_pick_first_map=map; g_map_pick_first_candidate=candidate;
        fprintf(stderr,"TRACE mapdisplay_pick_call tick=%u EAX_map=%08x EDX_candidate=%08x candidate_backed=%d map_backed=%d\n",
            g_map_pick_trace_tick,map,candidate,
            guest_memory&&candidate&&candidate<=0x03002000u-0x60u,
            guest_memory&&map<=0x03002000u-0x1200u);
    }
    if(!guest_memory || !candidate ||
       candidate>0x03002000u-0x60u || map>0x03002000u-0x1200u) return;
    g_map_pick_calls++;
    gw_map_census_row *census=gw_map_census_find(candidate);
    if(census) { census->last_tick=g_map_pick_trace_tick; census->calls++; }
    uint8_t type=guest_memory[candidate+6u];
    if(type<16u) g_map_pick_type_counts[type]++;
    if(guest_memory[candidate+0x2Du]==5u) g_map_pick_field2d_eq5++;
    if(type==5u) {
        g_map_pick_ttype5++;
        int16_t raw_x=(int16_t)(guest_memory[candidate+7u]|((uint16_t)guest_memory[candidate+8u]<<8));
        int16_t raw_y=(int16_t)(guest_memory[candidate+9u]|((uint16_t)guest_memory[candidate+10u]<<8));
        int cursor_x=(int16_t)(guest_memory[0x002F1465u]|((uint16_t)guest_memory[0x002F1466u]<<8));
        int cursor_y=(int16_t)(guest_memory[0x002F1467u]|((uint16_t)guest_memory[0x002F1468u]<<8));
        fprintf(stderr,"TRACE mapdisplay_candidate tick=%u ptr=%08x type=%u field2d=%u x=%d y=%d f15=%02x f17=%02x f1c=%02x f1f=%04x f45=%02x f46=%02x f4c=%02x vptr=%08x cursor=%d,%d\n",
            g_map_pick_trace_tick,candidate,type,guest_memory[candidate+0x2Du],raw_x,raw_y,
            guest_memory[candidate+0x15u],guest_memory[candidate+0x17u],guest_memory[candidate+0x1Cu],
            (unsigned)(guest_memory[map+0x1Fu]|((uint16_t)guest_memory[map+0x20u]<<8)),
            guest_memory[candidate+0x45u],guest_memory[candidate+0x46u],guest_memory[candidate+0x4Cu],
            *(uint32_t *)(guest_memory+candidate+0x23u),cursor_x,cursor_y);
        if(!g_map_pick_first5) {
            g_map_pick_first5=candidate;
            g_map_pick_first5_x=(uint32_t)(int32_t)(int16_t)(guest_memory[candidate+7u]|
                ((uint16_t)guest_memory[candidate+8u]<<8));
            g_map_pick_first5_y=(uint32_t)(int32_t)(int16_t)(guest_memory[candidate+9u]|
                ((uint16_t)guest_memory[candidate+10u]<<8));
        }
        fprintf(stderr,"TRACE mapdisplay_ttype5_candidate tick=%u ptr=%08x ttype=5 effect_type=%02x effect_state=%02x power=%02x xy=%d,%d cursor=%d,%d\n",
            g_map_pick_trace_tick,candidate,guest_memory[candidate+0x45u],guest_memory[candidate+0x46u],
            guest_memory[candidate+0x4Cu],raw_x,raw_y,cursor_x,cursor_y);
    }
}
void gw_test_mapdisplay_pick_projected(uint32_t candidate,int32_t screen_x,int32_t screen_y,uint32_t height_q6) {
    if(!g_map_pick_trace_active||!guest_memory||!candidate||candidate>0x03002000u-0x60u) return;
    gw_map_census_row *census=gw_map_census_find(candidate);
    if(census) { census->screen_x=screen_x; census->screen_y=screen_y-(int32_t)(height_q6>>6); census->projected_count++; }
    if(guest_memory[candidate+6u]!=5u) return;
    int cursor_x=(int16_t)(guest_memory[0x002F1465u]|((uint16_t)guest_memory[0x002F1466u]<<8));
    int cursor_y=(int16_t)(guest_memory[0x002F1467u]|((uint16_t)guest_memory[0x002F1468u]<<8));
    fprintf(stderr,"TRACE mapdisplay_projection tick=%u ptr=%08x ttype=%u screen=%d,%d z_q6=%u cursor=%d,%d\n",
        g_map_pick_trace_tick,candidate,guest_memory[candidate+6u],screen_x,
        screen_y-(int32_t)(height_q6>>6),height_q6,cursor_x,cursor_y);
}
static void gw_test_mapdisplay_pick_begin(uint32_t tick) {
    g_map_pick_raw_calls=0; g_map_pick_first_map=0; g_map_pick_first_candidate=0;
    g_map_pick_trace_tick=tick; g_map_pick_calls=0; g_map_pick_field2d_eq5=0;
    g_map_pick_ttype5=0; g_map_pick_first5=0; g_map_pick_first5_x=0; g_map_pick_first5_y=0;
    memset(g_map_pick_type_counts,0,sizeof g_map_pick_type_counts);
    g_map_pick_trace_active=1;
}
static void gw_test_mapdisplay_pick_finish(uint32_t map) {
    g_map_pick_trace_active=0;
    if(!guest_memory || map>0x03002000u-0x1200u) return;
    uint32_t picked=*(uint32_t *)(guest_memory+map+0x37u);
    uint32_t selected=*(uint32_t *)(guest_memory+map+0x18u);
    int cursor_x=(int16_t)(guest_memory[0x002F1465u]|((uint16_t)guest_memory[0x002F1466u]<<8));
    int cursor_y=(int16_t)(guest_memory[0x002F1467u]|((uint16_t)guest_memory[0x002F1468u]<<8));
    fprintf(stderr,"TRACE mapdisplay_pick tick=%u raw_calls=%u calls=%u first_map=%08x first_candidate=%08x field2d_eq5=%u ttype5=%u first_ttype5=%08x world=%d,%d cursor=%d,%d map37=%08x map18=%08x types=0:%u,1:%u,2:%u,3:%u,4:%u,5:%u,6:%u,7:%u,8:%u,9:%u,10:%u,11:%u,12:%u,13:%u,14:%u,15:%u\n",
        g_map_pick_trace_tick,g_map_pick_raw_calls,g_map_pick_calls,g_map_pick_first_map,
        g_map_pick_first_candidate,g_map_pick_field2d_eq5,g_map_pick_ttype5,
        g_map_pick_first5,(int32_t)g_map_pick_first5_x,(int32_t)g_map_pick_first5_y,
        cursor_x,cursor_y,picked,selected,
        g_map_pick_type_counts[0],g_map_pick_type_counts[1],g_map_pick_type_counts[2],g_map_pick_type_counts[3],
        g_map_pick_type_counts[4],g_map_pick_type_counts[5],g_map_pick_type_counts[6],g_map_pick_type_counts[7],
        g_map_pick_type_counts[8],g_map_pick_type_counts[9],g_map_pick_type_counts[10],g_map_pick_type_counts[11],
        g_map_pick_type_counts[12],g_map_pick_type_counts[13],g_map_pick_type_counts[14],g_map_pick_type_counts[15]);
    /* Follow the exact world Thing seen at the live tick-32 projection even
       when it falls outside MapDisplay's current pick/draw buckets. For a
       ThingType::TT_EFFECT record, offsets +0x45/+0x46/+0x4c are Effect::type,
       Effect::state, and Effect::power. This observer never mutates guest
       bytes or registers. */
    const uint32_t watch=0x00341CBDu;
    if(watch<=0x03002000u-0x60u) {
        int16_t x=(int16_t)(guest_memory[watch+7u]|((uint16_t)guest_memory[watch+8u]<<8));
        int16_t y=(int16_t)(guest_memory[watch+9u]|((uint16_t)guest_memory[watch+10u]<<8));
        fprintf(stderr,"TRACE watched_effect_fields tick=%u ptr=%08x thing_type=%02x effect_type=%02x effect_state=%02x x=%d y=%d pix_count=%04x power=%02x tflags=%02x vptr=%08x\n",
            g_map_pick_trace_tick,watch,guest_memory[watch+6u],
            guest_memory[watch+0x45u],guest_memory[watch+0x46u],x,y,
            (unsigned)(guest_memory[watch+0x4Au]|((uint16_t)guest_memory[watch+0x4Bu]<<8)),
            guest_memory[watch+0x4Cu],
            (unsigned)(guest_memory[watch+0x15u]|((uint16_t)guest_memory[watch+0x16u]<<8)),
            *(uint32_t *)(guest_memory+watch+0x23u));
    }
    const uint32_t smuggler=0x00341576u;
    if(smuggler<=0x03002000u-0x60u) {
        int16_t x=(int16_t)(guest_memory[smuggler+7u]|((uint16_t)guest_memory[smuggler+8u]<<8));
        int16_t y=(int16_t)(guest_memory[smuggler+9u]|((uint16_t)guest_memory[smuggler+10u]<<8));
        fprintf(stderr,"TRACE effect_state_tick tick=%u ptr=%08x ttype=%02x effect_type=%02x state=%02x power=%02x xy=%d,%d\n",
            g_map_pick_trace_tick,smuggler,guest_memory[smuggler+6u],guest_memory[smuggler+0x45u],
            guest_memory[smuggler+0x46u],guest_memory[smuggler+0x4Cu],x,y);
    }
}
static void gw_test_mapdisplay_census_dump(void) {
    fprintf(stderr,"TRACE mapdisplay_census_summary unique=%u capacity=%u ticks=40 scope=0x78B30-entry-through-original-Draw\n",
        g_map_census_count,GW_MAP_CENSUS_CAP);
    for(uint32_t i=0;i<g_map_census_count;i++) {
        const gw_map_census_row *r=&g_map_census[i];
        fprintf(stderr,"TRACE mapdisplay_census ptr=%08x array=%s index=%u first_tick=%u last_tick=%u calls=%u projections=%u screen=%d,%d world=%d,%d ttype=%02x field2d=%02x field45=%02x field46=%02x field4c=%02x\n",
            r->ptr,r->array_name,r->array_index,r->first_tick,r->last_tick,r->calls,r->projected_count,
            r->screen_x,r->screen_y,r->world_x,r->world_y,r->thing_type,r->field_2d,
            r->field_45,r->field_46,r->field_4c);
    }
}
void gw_test_effect_type_store(uint32_t eax,uint32_t ebx,uint32_t ecx,uint32_t edx,
    uint32_t esi,uint32_t edi,uint32_t ebp,uint32_t esp,uint32_t guest_function) {
    if(!g_map_pick_trace_active || (eax&0xFFu)!=0x06u || !guest_memory ||
       edx>0x03002000u-0x60u) return;
    uint32_t index=UINT32_MAX;
    if(edx>=0x00341576u && edx<0x003454BEu && (edx-0x00341576u)%0x51u==0)
        index=(edx-0x00341576u)/0x51u;
    fprintf(stderr,"TRACE effect_type_store tick=%u writer_link=00083E08 object_guest=%08x effects_index=%u ttype=%02x effect_type=%02x state=%02x power=%02x regs=%08x/%08x/%08x/%08x/%08x/%08x/%08x/%08x function=%08x\n",
        g_map_pick_trace_tick,edx,index,guest_memory[edx+6u],guest_memory[edx+0x45u],
        guest_memory[edx+0x46u],guest_memory[edx+0x4Cu],eax,ebx,ecx,edx,esi,edi,ebp,esp,guest_function);
    /* This checkpoint follows the actual LE store; its ring preserves the
       dynamic parent chain without relying on the host C stack. */
    gw_recomp_trace_checkpoint(0x00083E08u,guest_function);
}
void gw_test_effect_spawn_origin(uint32_t parent,uint32_t eax,uint32_t ebx,
    uint32_t ecx,uint32_t edx,uint32_t ebp,uint32_t esp) {
    if(!g_map_pick_trace_active || g_map_pick_trace_tick!=22u || !guest_memory ||
       parent<0x00341576u || parent>=0x003454BEu ||
       (parent-0x00341576u)%0x51u) return;
    int16_t parent_x=(int16_t)((uint16_t)guest_memory[parent+7u]|
        ((uint16_t)guest_memory[parent+8u]<<8));
    int16_t parent_y=(int16_t)((uint16_t)guest_memory[parent+9u]|
        ((uint16_t)guest_memory[parent+10u]<<8));
    fprintf(stderr,"TRACE effect_spawn_origin tick=22 callsite=0008812A caller=00086810 parent_guest=%08x effects_index=%u parent_ttype=%02x parent_type=%02x parent_state=%02x parent_power=%02x parent_x=%d parent_y=%d factory_args=%08x/%08x/%08x/%08x ebp=%08x esp=%08x\n",
        parent,(parent-0x00341576u)/0x51u,guest_memory[parent+6u],
        guest_memory[parent+0x45u],guest_memory[parent+0x46u],
        guest_memory[parent+0x4Cu],parent_x,parent_y,eax,ebx,ecx,edx,ebp,esp);
    gw_recomp_trace_checkpoint(0x0008812Au,0x00086810u);
}
/* Keep provenance for two disputed pointer cells while preserving the
   test's phase-specific guest-write observers. */
static recomp_guest_write_observer_fn guest_write_observer_downstream;
static void *guest_write_observer_downstream_user;
static uint32_t watched_cell_writes[2],watched_cell_last_eip[2];
static uint32_t watched_cell_last_linear[2],watched_cell_last_width[2];
static const uint32_t watched_cell_guest[2]={0x002EBCF8u,0x00346D88u};
static void capture_watched_guest_write(uint32_t instruction_va,
    recomp_segment_id segment,uint16_t selector,uint32_t segment_base,
    uint32_t guest_linear,uint32_t width,void *user) {
    (void)user;
    if(width) for(unsigned i=0;i<2u;i++) {
        uint64_t end=(uint64_t)guest_linear+width;
        if(guest_linear>=watched_cell_guest[i]+4u || end<=watched_cell_guest[i]) continue;
        uint32_t n=++watched_cell_writes[i];
        watched_cell_last_eip[i]=instruction_va;
        watched_cell_last_linear[i]=guest_linear;
        watched_cell_last_width[i]=width;
        fprintf(stderr,"TRACE watched_guest_cell_write cell=%u count=%u eip=%08x guest=%08x width=%u old=%08x regs=%08x/%08x/%08x/%08x/%08x/%08x/%08x/%08x seg=%u sel=%04x base=%08x\n",
            i,n,instruction_va,guest_linear,width,
            guest_memory?*(uint32_t *)(guest_memory+watched_cell_guest[i]):0u,
            g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,
            (unsigned)segment,selector,segment_base);
    }
    if(guest_write_observer_downstream)
        guest_write_observer_downstream(instruction_va,segment,selector,
            segment_base,guest_linear,width,guest_write_observer_downstream_user);
}
static void set_guest_write_observer(recomp_guest_write_observer_fn observer,void *user) {
    guest_write_observer_downstream=observer;
    guest_write_observer_downstream_user=user;
    recomp_set_guest_write_observer(capture_watched_guest_write,NULL);
}
static uint32_t guest_u32_for_trace(uint32_t address);
static void trace_guest_heap_covering(uint32_t guest_address,const char *phase);
static uint32_t g_dpmi_0501_trace_count;
static uint32_t g_smacker_dos_read_trace_count;
static uint32_t g_play_smacker_graphics_trace_count;
void gw_test_instruction_budget_step(uint32_t guest_va) {
    startup_budget_last_va=guest_va; startup_budget_last_func=g_cur_func;
    if ((guest_va==0x000929D0u || guest_va==0x000929F0u ||
         guest_va==0x00092A00u || guest_va==0x00092A4Fu ||
         guest_va==0x00092A71u || guest_va==0x00092A8Fu ||
         guest_va==0x00092AEBu || guest_va==0x00092AF4u ||
         guest_va==0x00092B05u || guest_va==0x00092B18u ||
         guest_va==0x00092B2Bu || guest_va==0x00092B5Au ||
         guest_va==0x00092B6Bu || guest_va==0x00092B71u ||
         guest_va==0x00092B82u || guest_va==0x00092B87u ||
         guest_va==0x00015808u || guest_va==0x0001580Du ||
         guest_va==0x00015875u || guest_va==0x00015887u ||
         guest_va==0x0001588Cu) &&
        g_play_smacker_graphics_trace_count<128u) {
        g_play_smacker_graphics_trace_count++;
        fprintf(stderr,"TRACE original PlaySmacker graphics site=%08x func=%08x EAX=%08x EBX=%08x ECX=%08x EDX=%08x dims=%u/%u b_screen=%08x screen_flags=%02x/%02x mode_state=%02x\n",
            guest_va,g_cur_func,g_eax,g_ebx,g_ecx,g_edx,
            guest_memory?guest_u32_for_trace(0x00376A78u):0u,
            guest_memory?guest_u32_for_trace(0x00376A7Cu):0u,
            guest_memory?guest_u32_for_trace(0x002EECA0u):0u,
            guest_memory?guest_memory[0x002F1660u]:0u,
            guest_memory?guest_memory[0x002F1661u]:0u,
            guest_memory?guest_memory[0x002F6D6Fu]:0u);
        if (guest_va>=0x00015800u && guest_va<=0x0001588Cu && guest_memory) {
            const uint32_t bs=guest_u32_for_trace(0x002EECA0u);
            fprintf(stderr,"TRACE original IFCLevel mode-lifecycle site=%08x EAX=%08x EBX=%08x ECX=%08x EDX=%08x dims=%u/%u mode_id=%08x b_screen=%08x flags=%02x/%02x\n",
                guest_va,g_eax,g_ebx,g_ecx,g_edx,
                guest_u32_for_trace(0x00376A78u),guest_u32_for_trace(0x00376A7Cu),
                guest_u32_for_trace(0x00376A6Cu),bs,
                guest_memory[0x002F1660u],guest_memory[0x002F1661u]);
            trace_guest_heap_covering(bs,"IFCLevel_PlugIn_mode_lifecycle");
        }
    }
    if(!g_full_instruction_trace) return;
    if(!startup_budget_remaining || startup_budget_exhausted) return;
    startup_budget_executed++;
    if(--startup_budget_remaining==0u) {
        startup_budget_exhausted=1;
        fprintf(stderr,"TRACE bounded guest-instruction budget exhausted count=%llu last_eip=%08x current_func=%08x\n",
                (unsigned long long)startup_budget_executed,guest_va,g_cur_func);
        /* Do not unwind the guest stack as if this partial return were a
           normal callee result. Stop every parent dispatcher at this exact
           original EIP before it executes another guest instruction. */
        gw_recomp_latch_runtime_frontier(guest_va,"bounded-instruction-budget",
            g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,0u);
    }
}
void gw_test_init_my_anim_bank_step(uint32_t site,uint32_t eax,uint32_t ebx,
    uint32_t ecx,uint32_t edx,uint32_t esi,uint32_t edi,uint32_t ebp,uint32_t esp) {
    static uint32_t samples;
    if(site!=0x0009745Eu || !guest_memory) return;
    samples++;
    if(samples>8u && (samples%1000u)!=0u) return;
    fprintf(stderr,"TRACE InitMyAnimBank live sample=%u site=%08x regs=%08x/%08x/%08x/%08x/%08x/%08x/%08x/%08x bank_count=%u bank_fields=%08x/%08x/%08x/%08x cursor=%08x end=%08x bytes_left=%08x return=%08x\n",
        samples,site,eax,ebx,ecx,edx,esi,edi,ebp,esp,
        ecx<=0x03002000u-2u?*(uint16_t *)(guest_memory+ecx):0u,
        guest_u32_for_trace(ecx+2u),guest_u32_for_trace(ecx+6u),
        guest_u32_for_trace(ecx+10u),guest_u32_for_trace(ecx+14u),
        eax,esi,esi-eax,guest_u32_for_trace(esp+24u));
    if(eax<=0x03002000u && 16u<=0x03002000u-eax) {
        fprintf(stderr,"TRACE InitMyAnimBank live record sample=%u bytes=",samples);
        for(unsigned i=0;i<16u;i++) fprintf(stderr,"%02x",guest_memory[eax+i]);
        fprintf(stderr,"\n");
    }
}
void gw_test_setup_game_epilogue(uint32_t site,uint32_t eax,uint32_t ebx,
    uint32_t ecx,uint32_t edx,uint32_t esi,uint32_t edi,uint32_t ebp,uint32_t esp) {
    if(site!=0x00095484u || !guest_memory) return;
    uint32_t frame_top=ebp+0x82u;
    fprintf(stderr,"TRACE setup_game epilogue site=%08x regs=%08x/%08x/%08x/%08x/%08x/%08x/%08x/%08x frame_top=%08x frame_saved=%08x/%08x/%08x/%08x/%08x/%08x ret=%08x\n",
        site,eax,ebx,ecx,edx,esi,edi,ebp,esp,frame_top,
        guest_u32_for_trace(frame_top),guest_u32_for_trace(frame_top+4u),
        guest_u32_for_trace(frame_top+8u),guest_u32_for_trace(frame_top+12u),
        guest_u32_for_trace(frame_top+16u),guest_u32_for_trace(frame_top+20u),
        guest_u32_for_trace(frame_top+24u));
    fprintf(stderr,"TRACE setup_game epilogue entry_stack=%08x stack_at_esp=%08x low_stack=%08x/%08x/%08x\n",
        0x003FF000u,guest_u32_for_trace(esp),guest_u32_for_trace(0x90u),
        guest_u32_for_trace(0x94u),guest_u32_for_trace(0x98u));
}
void gw_test_strstr_segment_pop(uint32_t site,uint32_t eax,uint32_t ebx,
    uint32_t ecx,uint32_t edx,uint32_t esi,uint32_t edi,uint32_t ebp,
    uint32_t esp,uint32_t stack_value) {
    static uint32_t seen;
    if(site!=0x000AA0CCu || !guest_memory || ++seen>8u) return;
    fprintf(stderr,"TRACE strstr pop-es site=%08x regs=%08x/%08x/%08x/%08x/%08x/%08x/%08x/%08x stack=%08x es=%04x ds=%04x ss=%04x\n",
        site,eax,ebx,ecx,edx,esi,edi,ebp,esp,stack_value,
        g_seg_es,g_seg_ds,g_seg_ss);
}
void gw_trace_strstr_stack(uint32_t site,uint32_t eax,uint32_t ebx,
    uint32_t ecx,uint32_t edx,uint32_t esi,uint32_t edi,uint32_t ebp,
    uint32_t esp,uint32_t stack_value) {
    static uint32_t seen;
    if(!guest_memory || ++seen>64u) return;
    fprintf(stderr,"TRACE strstr stack site=%08x regs=%08x/%08x/%08x/%08x/%08x/%08x/%08x/%08x top=%08x\n",
        site,eax,ebx,ecx,edx,esi,edi,ebp,esp,stack_value);
}
int gw_test_instruction_budget_exhausted(void) { return startup_budget_exhausted; }
static uint32_t guest_u32_for_trace(uint32_t address);
static uint32_t smacker_zero_progress_count;
static uint32_t smacker_read_count_store_count;
void gw_trace_dos_read_count_store(uint32_t site,uint32_t address,
    uint32_t value,uint32_t esp) {
    if(smacker_read_count_store_count>=16u) return;
    fprintf(stderr,"TRACE DOS read-count store site=%08x linear=%08x value=%08x observed=%08x esp=%08x\n",
        site,address,value,guest_u32_for_trace(address),esp);
    smacker_read_count_store_count++;
}
void gw_trace_smacker_read_result(uint32_t return_eip,uint32_t bytes_read,
    uint32_t remaining,uint32_t destination,uint32_t object,
    uint32_t eax,uint32_t ebx,uint32_t ecx,uint32_t edx,
    uint32_t esi,uint32_t edi,uint32_t ebp,uint32_t esp) {
    if(bytes_read) return;
    smacker_zero_progress_count++;
    fprintf(stderr,"TRACE Smacker read made no progress site=%08x count=%u bytes=0 remaining=%08x destination=%08x object=%08x handle=%08x buffer=%08x end=%08x cursor=%08x buffer_cursor=%08x buffered=%08x buffer_size=%08x bytes_read_total=%08x stream_consumed=%08x registers=%08x/%08x/%08x/%08x/%08x/%08x/%08x esp=%08x\n",
        return_eip,smacker_zero_progress_count,remaining,destination,object,
        guest_u32_for_trace(object+0x394u),guest_u32_for_trace(object+0x42cu),
        guest_u32_for_trace(object+0x430u),guest_u32_for_trace(object+0x434u),
        guest_u32_for_trace(object+0x438u),guest_u32_for_trace(object+0x43cu),
        guest_u32_for_trace(object+0x440u),guest_u32_for_trace(object+0x444u),
        guest_u32_for_trace(object+0x448u),eax,ebx,ecx,edx,esi,edi,ebp,esp);
    /* The original loop retries a zero-byte read without consuming its
       requested length. Preserve the exact first no-progress state and stop
       this diagnostic replay before it can spin. */
    gw_recomp_latch_runtime_frontier(return_eip,"smacker-read-zero-progress",
        eax,ebx,ecx,edx,esi,edi,ebp,esp,0u);
}
static uint32_t g_deferred_draw_sites[3];
static uint32_t g_watcom_f304_calls;
void gw_record_deferred_indirect(uint32_t site) {
    if(site==0xA8D43u) g_deferred_draw_sites[0]++;
    else if(site==0xA8D95u) g_deferred_draw_sites[1]++;
    else if(site==0xA8DB4u) g_deferred_draw_sites[2]++;
}
typedef struct { uint32_t target,count; } ctor_target_count;
static ctor_target_count g_ctor_targets[32];
static uint32_t g_ctor_target_kinds,g_ctor_dispatch_count;
void gw_record_ctor_array_target(uint32_t callsite,uint32_t target) {
    if(callsite!=0x000A9F3Bu) return;
    g_ctor_dispatch_count++;
    for(uint32_t i=0;i<g_ctor_target_kinds;i++) {
        if(g_ctor_targets[i].target==target) { g_ctor_targets[i].count++; return; }
    }
    if(g_ctor_target_kinds<32u) {
        g_ctor_targets[g_ctor_target_kinds].target=target;
        g_ctor_targets[g_ctor_target_kinds].count=1;
        g_ctor_target_kinds++;
    }
}

enum { GUEST_LIMIT=0x03002000u, IMAGE_BASE=0x000F0000u,
       STACK_TOP=0x003FF000u, TITLE_LIST=0x002DFEE8u,
       BLOCKS=0x00360C40u, ARENAS=0x00361840u, MAX_ENTRIES=256u,
       BLOCK_SIZE=12u, ARENA_SIZE=18u, FLAT_HEAP_BEGIN=0x01000000u,
       RNC_SOURCE=0x02200000u, RNC_OUT=0x02210000u,
       RNC_INPLACE=0x02220000u };

typedef struct { FILE *fp; int capture_rnc; unsigned reads; unsigned eof_reads; char path[260]; } host_file;
typedef struct { char sha256[65]; char path[512]; } vfs_manifest_record;
typedef struct {
    gw_dos_services dos;
    const char *root;
    unsigned opens,reads,closes,denied,missing_save_slots,save_slot_open_attempts[7],title_screen_reads,title_screen_bytes;
    unsigned text_reads,text_bytes,text_payload_reads,text_payload_bytes,text_seeks;
    unsigned system1_reads,system1_eof_reads;
    long system1_last_offset;
    uint16_t system1_last_requested,system1_last_done;
    uint32_t text_payload_guest;
    long read_pos[8];
    uint16_t read_requested[8], read_done[8];
    uint32_t read_guest[8];
    long title_read_pos[4];
    uint16_t title_read_requested[4],title_read_done[4];
    uint32_t title_read_guest[4];
    uint32_t title_dos_ax[4],title_dos_bx[4],title_dos_cx[4],title_dos_dx[4];
    char last_path[260], first_path[260];
    uint8_t stdout_capture[4096];
    uint32_t stdout_capture_size;
    uint8_t stderr_capture[4096];
    uint32_t stderr_capture_size;
    vfs_manifest_record *manifest;
    uint32_t manifest_count;
} fixture_vfs;

static int sdl_input_initialized;
static int present_draw_sdl(const uint8_t *pixels,const uint8_t *palette,
                            const char *window_title,const char *capture_path) {
    if(!sdl_input_initialized && SDL_Init(SDL_INIT_VIDEO)!=0) { fprintf(stderr,"SDL_Init: %s\n",SDL_GetError()); return 0; }
    sdl_input_initialized=1;
    SDL_SetHint(SDL_HINT_RENDER_SCALE_QUALITY,"0");
    SDL_Window *window=SDL_CreateWindow(window_title,
        SDL_WINDOWPOS_CENTERED,SDL_WINDOWPOS_CENTERED,1280,960,SDL_WINDOW_SHOWN);
    SDL_Renderer *renderer=window?SDL_CreateRenderer(window,-1,SDL_RENDERER_SOFTWARE):NULL;
    SDL_Texture *texture=renderer?SDL_CreateTexture(renderer,SDL_PIXELFORMAT_ARGB8888,
        SDL_TEXTUREACCESS_STATIC,640,480):NULL;
    uint32_t *rgba=(uint32_t *)malloc(640u*480u*sizeof(uint32_t));
    uint32_t *capture=(uint32_t *)malloc(1280u*960u*sizeof(uint32_t));
    if(!window || !renderer || !texture || !rgba || !capture) {
        fprintf(stderr,"SDL setup: %s\n",SDL_GetError()); return 0;
    }
    for(uint32_t i=0;i<640u*480u;i++) {
        uint32_t k=pixels[i];
        uint32_t r=(uint32_t)palette[k*3u+0u]*255u/63u;
        uint32_t g=(uint32_t)palette[k*3u+1u]*255u/63u;
        uint32_t b=(uint32_t)palette[k*3u+2u]*255u/63u;
        rgba[i]=0xFF000000u|(r<<16)|(g<<8)|b;
    }
    int ok=SDL_UpdateTexture(texture,NULL,rgba,640*4)==0 && SDL_RenderClear(renderer)==0 &&
           SDL_RenderCopy(renderer,texture,NULL,NULL)==0;
    if(ok) SDL_RenderPresent(renderer);
    if(ok) ok=SDL_RenderReadPixels(renderer,NULL,SDL_PIXELFORMAT_ARGB8888,capture,1280*4)==0;
    SDL_Surface *surface=ok?SDL_CreateRGBSurfaceWithFormatFrom(capture,1280,960,32,
        1280*4,SDL_PIXELFORMAT_ARGB8888):NULL;
    if(!surface || SDL_SaveBMP(surface,capture_path)!=0) {
        fprintf(stderr,"SDL present/capture: %s\n",SDL_GetError()); ok=0;
    }
    if(ok) { printf("PASS SDL presents the captured WScreen bytes from the original interface Draw; window visible 2s path=%s\n",capture_path); SDL_Delay(2000); }
    if(surface) SDL_FreeSurface(surface);
    free(capture); free(rgba);
    if(texture) SDL_DestroyTexture(texture); if(renderer) SDL_DestroyRenderer(renderer);
    if(window) SDL_DestroyWindow(window); SDL_Quit(); sdl_input_initialized=0; return ok;
}

static fixture_vfs vfs;
static gw_vbe_device vbe_device;
static uint8_t vga_dac[768],vga_dac_index,vga_dac_component;
static uint8_t vga_dac_read_index,vga_dac_read_component;
static uint32_t vga_dac_index_writes,vga_dac_component_writes;
static uint32_t original_main_palette_guest;
static uint32_t vga_dac_read_index_writes,vga_dac_component_reads;
static uint32_t vga_retrace_status_reads;
static uint32_t remap_sprite_call_count,remap_sprite_return_count;
static uint8_t mscdex_audio_volume[4];
static uint32_t mscdex_audio_volume_updates;
static uint32_t mscdex_audio_start_lba;
static uint32_t mscdex_audio_sector_count;
static int mscdex_audio_playing;
static int mscdex_audio_paused;
/* The original PlugIn reuses its low DPMI scratch area during Update. Keep
   only the exact compressed bytes captured immediately after its original
   VFS read, then feed those bytes back through the original UnpackM1_ later. */
static uint8_t ifclevel_palette_capture[768];
static int ifclevel_palette_capture_valid;
static uint8_t ifclevel_interface_palette_capture[768];
static uint32_t ifclevel_interface_palette_guest;
static int ifclevel_interface_palette_capture_valid;
static uint32_t ifclevel_palette_store_base;
static uint8_t ifclevel_palette_store_seen[768];
static uint32_t ifclevel_palette_store_events;
static uint32_t ifclevel_palette_store_first_eip;
typedef struct ifclevel_member_write_capture {
    uint32_t c7_address,c8_address;
    uint32_t c7_writes,c8_writes;
    uint32_t c7_last_eip,c8_last_eip;
    uint32_t c7_last_address,c8_last_address;
    uint32_t effect_slot_address,effect_slot_writes,effect_slot_last_eip;
    uint32_t effect_slot_last_address;
    uint32_t effect_slot_eax,effect_slot_ebx,effect_slot_ecx,effect_slot_edx;
} ifclevel_member_write_capture;
static ifclevel_member_write_capture ifclevel_member_writes;
static void capture_ifclevel_member_write(uint32_t instruction_va,
    recomp_segment_id segment,uint16_t selector,uint32_t segment_base,
    uint32_t guest_linear,uint32_t width,void *user) {
    ifclevel_member_write_capture *capture=(ifclevel_member_write_capture *)user;
    uint64_t end=(uint64_t)guest_linear+width;
    (void)segment; (void)selector; (void)segment_base;
    if(!capture || !width) return;
    if(guest_linear< capture->c7_address+1u && end>capture->c7_address) {
        capture->c7_writes++; capture->c7_last_eip=instruction_va;
        capture->c7_last_address=guest_linear;
    }
    if(guest_linear< capture->c8_address+4u && end>capture->c8_address) {
        capture->c8_writes++; capture->c8_last_eip=instruction_va;
        capture->c8_last_address=guest_linear;
    }
    if(capture->effect_slot_address &&
       guest_linear<capture->effect_slot_address+4u && end>capture->effect_slot_address) {
        capture->effect_slot_writes++;
        capture->effect_slot_last_eip=instruction_va;
        capture->effect_slot_last_address=guest_linear;
        capture->effect_slot_eax=g_eax; capture->effect_slot_ebx=g_ebx;
        capture->effect_slot_ecx=g_ecx; capture->effect_slot_edx=g_edx;
        fprintf(stderr,"TRACE watched_effect_slot_write eip=%08x guest=%08x width=%u eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x ebp=%08x esp=%08x\n",
            instruction_va,guest_linear,width,g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp);
    }
}
static void capture_ifclevel_palette_guest_write(uint32_t instruction_va,
    recomp_segment_id segment,uint16_t selector,uint32_t segment_base,
    uint32_t guest_linear,uint32_t width,void *user) {
    (void)segment; (void)selector; (void)segment_base; (void)user;
    if(!width || guest_linear>=ifclevel_palette_store_base+768u ||
       (uint64_t)guest_linear+width<=ifclevel_palette_store_base) return;
    uint32_t begin=guest_linear>ifclevel_palette_store_base?
        guest_linear-ifclevel_palette_store_base:0u;
    uint64_t end=(uint64_t)guest_linear+width;
    uint32_t stop=end>ifclevel_palette_store_base+768u?768u:
        (uint32_t)(end-ifclevel_palette_store_base);
    for(uint32_t i=begin;i<stop;i++) ifclevel_palette_store_seen[i]=1u;
    if(!ifclevel_palette_store_events) ifclevel_palette_store_first_eip=instruction_va;
    ifclevel_palette_store_events++;
}
enum { LOW_WRITE_CAPTURE_LIMIT=0x000A0000u };
static uint32_t *low_write_last_eip;
static uint8_t *low_write_live_mcb;
static uint8_t *low_write_kind;
static uint16_t *low_write_source;
static uint32_t low_write_capture_events;
static int low_write_capture_enabled;
static uint32_t low_write_current_eip;
static char low_write_sources[16][128];
static uint16_t low_write_source_count;
enum { LOW_WRITER_NONE=0u, LOW_WRITER_GUEST=1u, LOW_WRITER_DOS_READ=2u };
static uint16_t low_write_source_id(const char *path) {
    if(!path || !*path) return 0u;
    for(uint16_t i=0;i<low_write_source_count;i++)
        if(_stricmp(low_write_sources[i],path)==0) return (uint16_t)(i+1u);
    if(low_write_source_count>=16u) return 0u;
    uint16_t id=(uint16_t)(++low_write_source_count);
    strncpy(low_write_sources[id-1u],path,sizeof low_write_sources[0]-1u);
    return id;
}
static int guest_address_in_active_dos_block(uint32_t address) {
    if(address>=LOW_WRITE_CAPTURE_LIMIT) return 0;
    for(uint32_t i=0;i<vfs.dos.dos_block_count;i++) {
        const gw_dos_memory_block *block=&vfs.dos.dos_blocks[i];
        uint32_t begin=(uint32_t)block->segment<<4;
        uint64_t end=(uint64_t)begin+((uint64_t)block->paragraphs<<4);
        if(end>begin && address>=begin && (uint64_t)address<end) return 1;
    }
    /* DPMI AX=0501 allocations have a separate lifetime ledger. They usually
       live above conventional memory, but include them here so the audit's
       event-time backing decision follows the provider contract rather than
       only the DOS MCB list. */
    for(uint32_t i=0;i<GW_DOS_MAX_LINEAR_ALLOCATIONS;i++) {
        const gw_dos_linear_allocation *allocation=&vfs.dos.linear_allocations[i];
        if(allocation->active && address>=allocation->base &&
           (uint64_t)address<(uint64_t)allocation->base+allocation->size) return 1;
    }
    return 0;
}
static void capture_low_provider_write(uint32_t instruction_va,uint32_t guest_linear,
    uint32_t width,uint8_t kind,uint16_t source_id) {
    if(!low_write_capture_enabled || !low_write_last_eip || !width ||
       guest_linear>=LOW_WRITE_CAPTURE_LIMIT) return;
    uint64_t end=(uint64_t)guest_linear+width;
    if(end>LOW_WRITE_CAPTURE_LIMIT) end=LOW_WRITE_CAPTURE_LIMIT;
    for(uint32_t at=guest_linear;at<(uint32_t)end;at++) {
        low_write_last_eip[at]=instruction_va;
        low_write_live_mcb[at]=(uint8_t)guest_address_in_active_dos_block(at);
        if(low_write_kind) low_write_kind[at]=kind;
        if(low_write_source) low_write_source[at]=source_id;
    }
    low_write_capture_events++;
}
static int guest_address_in_live_mcb(uint32_t address) {
    if(!guest_memory || address>=LOW_WRITE_CAPTURE_LIMIT || !vfs.dos.dos_allocator_configured)
        return 0;
    /* DOS starts the chain at the MCB immediately before the first allocatable
       data paragraph. dos_segment_begin names that data segment (0x0907), not
       the MCB header (0x0906). */
    uint32_t segment=vfs.dos.dos_segment_begin-1u;
    uint32_t limit=vfs.dos.dos_segment_end;
    for(uint32_t guard=0;guard<4096u && segment<limit;guard++) {
        uint64_t header64=(uint64_t)segment*16u;
        if(header64+16u>GUEST_LIMIT) return 0;
        uint32_t header=(uint32_t)header64;
        uint8_t tag=guest_memory[header];
        uint16_t owner=(uint16_t)(guest_memory[header+1u]|((uint16_t)guest_memory[header+2u]<<8));
        uint16_t paragraphs=(uint16_t)(guest_memory[header+3u]|((uint16_t)guest_memory[header+4u]<<8));
        if((tag!='M' && tag!='Z') || !paragraphs) return 0;
        uint64_t begin=(uint64_t)(segment+1u)*16u;
        uint64_t end=begin+(uint64_t)paragraphs*16u;
        if(owner && address>=begin && (uint64_t)address<end) return 1;
        uint32_t next=segment+(uint32_t)paragraphs+1u;
        if(next<=segment || next>limit) return 0;
        if(tag=='Z') return 0;
        segment=next;
    }
    return 0;
}
static void capture_guest_low_write(uint32_t instruction_va,recomp_segment_id segment,
    uint16_t selector,uint32_t segment_base,uint32_t guest_linear,uint32_t width,void *user) {
    (void)segment; (void)selector; (void)segment_base; (void)user;
    if(!low_write_capture_enabled || !low_write_last_eip || !width ||
       guest_linear>=LOW_WRITE_CAPTURE_LIMIT) return;
    uint64_t end=(uint64_t)guest_linear+width;
    if(end>LOW_WRITE_CAPTURE_LIMIT) end=LOW_WRITE_CAPTURE_LIMIT;
    for(uint32_t at=guest_linear;at<(uint32_t)end;at++) {
        low_write_last_eip[at]=instruction_va;
        low_write_live_mcb[at]=(uint8_t)guest_address_in_active_dos_block(at);
        if(low_write_kind) low_write_kind[at]=LOW_WRITER_GUEST;
        if(low_write_source) low_write_source[at]=0u;
    }
    low_write_capture_events++;
}
static uint32_t guest_u32_for_trace(uint32_t address);
void gw_test_init_my_anim_enter(uint32_t site,uint32_t object,uint32_t bank) {
    uint32_t sprite_table=guest_memory&&bank<=GUEST_LIMIT-6u?guest_u32_for_trace(bank+2u):0xFFFFFFFFu;
    fprintf(stderr,"TRACE original InitMyAnimBank enter site=%08x object=%08x bank=%08x header=",
        site,object,bank);
    if(guest_memory&&bank<=GUEST_LIMIT-18u) {
        for(uint32_t i=0;i<18u;i++) fprintf(stderr,"%02x",guest_memory[bank+i]);
        fprintf(stderr," count=%04x sprites=%08x elements=%08x frames=%08x mysprites=%08x\n",
            (uint32_t)guest_memory[bank]|((uint32_t)guest_memory[bank+1u]<<8),sprite_table,
            guest_u32_for_trace(bank+6u),guest_u32_for_trace(bank+10u),guest_u32_for_trace(bank+14u));
    } else fputs("<outside-guest-memory>\n",stderr);
}
void gw_test_init_my_anim_return(uint32_t site,uint32_t object,uint32_t result) {
    fprintf(stderr,"TRACE original InitMyAnimBank return site=%08x object=%08x result=%08x bank=%08x sprite_table=%08x\n",
        site,object,result,
        guest_memory&&object<=GUEST_LIMIT-8u?guest_u32_for_trace(object+4u):0xFFFFFFFFu,
        guest_memory&&object<=GUEST_LIMIT-20u?guest_u32_for_trace(guest_u32_for_trace(object+4u)+2u):0xFFFFFFFFu);
}
void gw_test_remap_sprite_enter(uint32_t site,uint32_t eax,uint32_t ebx,
    uint32_t ecx,uint32_t edx,uint32_t esi,uint32_t edi,uint32_t ebp,
    uint32_t esp,uint32_t caller) {
    uint32_t n=++remap_sprite_call_count;
    if(n>64u) return;
    uint32_t object_bank=guest_memory&&edi<=GUEST_LIMIT-20u?guest_u32_for_trace(edi+4u):0xFFFFFFFFu;
    uint32_t object_mysprites=guest_memory&&edi<=GUEST_LIMIT-16u?guest_u32_for_trace(edi+12u):0xFFFFFFFFu;
    uint32_t object_sprites=guest_memory&&edi<=GUEST_LIMIT-20u?guest_u32_for_trace(edi+16u):0xFFFFFFFFu;
    fprintf(stderr,"TRACE original W_DrawMyRemapSpriteHR enter seq=%u caller=%08x site=%08x EAX=%08x EDX=%08x EBX=%08x ECX=%08x ESI=%08x EDI=%08x EBP=%08x ESP=%08x SS=%04x SS_BASE=%08x data_field=%08x data_word=%08x dims=%02x/%02x\n",
        n,caller,site,eax,edx,ebx,ecx,esi,edi,ebp,esp,g_seg_ss,g_ss_base,
        ebx,guest_memory&&ebx<=0x03002000u-4u?guest_u32_for_trace(ebx):0xFFFFFFFFu,
        guest_memory&&ebx<=0x03002000u-6u?guest_memory[ebx+4u]:0u,
        guest_memory&&ebx<=0x03002000u-6u?guest_memory[ebx+5u]:0u);
    fprintf(stderr,"TRACE IFCLevel sprite source object=%08x bank=%08x bank_sprites=%08x object_mysprites=%08x object_sprites=%08x\n",
        edi,object_bank,
        guest_memory&&object_bank<=GUEST_LIMIT-6u?guest_u32_for_trace(object_bank+2u):0xFFFFFFFFu,
        object_mysprites,object_sprites);
    if(guest_memory&&object_bank<=GUEST_LIMIT-18u) {
        fprintf(stderr,"TRACE IFCLevel MyAnimBank header guest=%08x bytes=",object_bank);
        for(uint32_t i=0;i<18u;i++) fprintf(stderr,"%02x",guest_memory[object_bank+i]);
        fprintf(stderr,"\n");
    }
    if(guest_memory) {
        uint32_t base=ebx>=12u?ebx-12u:ebx;
        fprintf(stderr,"TRACE remap sprite record guest=%08x bytes=",base);
        for(uint32_t i=0;i<32u && base+i<0x03002000u;i++) fprintf(stderr,"%02x",guest_memory[base+i]);
        fprintf(stderr," stack=");
        for(uint32_t i=0;i<8u;i++) fprintf(stderr,"%08x/",stack_word_at((uint64_t)esp+i*4u));
        fputc('\n',stderr);
    }
}
void gw_test_remap_sprite_return(uint32_t site) {
    int fault=recomp_memory_fault_pending();
    if(!fault) remap_sprite_return_count++;
    if(remap_sprite_call_count<=64u)
        fprintf(stderr,"TRACE original W_DrawMyRemapSpriteHR return-hook seq=%u site=%08x completed=%u pending_guest_fault=%d\n",
            remap_sprite_call_count,site,!fault, fault);
}
static uint32_t guest_u32_for_trace(uint32_t address) {
    if(!guest_memory || address>GUEST_LIMIT || 4u>GUEST_LIMIT-address) return 0xFFFFFFFFu;
    return (uint32_t)guest_memory[address] |
        ((uint32_t)guest_memory[address+1u]<<8) |
        ((uint32_t)guest_memory[address+2u]<<16) |
        ((uint32_t)guest_memory[address+3u]<<24);
}
static void guest_hex_for_trace(uint32_t address,uint32_t count,char *out,size_t cap) {
    static const char hex[]="0123456789abcdef";
    if(!out || cap==0u) return;
    size_t at=0;
    if(!guest_memory || address>GUEST_LIMIT || count>GUEST_LIMIT-address) {
        out[0]='?'; out[1]='\0'; return;
    }
    for(uint32_t i=0;i<count && at+2u<cap;i++) {
        uint8_t b=guest_memory[address+i];
        out[at++]=hex[b>>4]; out[at++]=hex[b&15u];
    }
    out[at]='\0';
}
void gw_trace_biogame_effect_call(uint32_t callsite,uint32_t target,
    uint32_t slot_base,uint32_t eax,uint32_t ebx,uint32_t ecx,uint32_t edx,
    uint32_t esi,uint32_t edi,uint32_t ebp,uint32_t esp) {
    if(callsite!=0x00088146u) return;
    char vtable[2u*33u+1u],object[2u*32u+1u];
    guest_hex_for_trace(edx-8u,33u,vtable,sizeof vtable);
    guest_hex_for_trace(eax,32u,object,sizeof object);
    fprintf(stderr,"TRACE BIOGAME_EFFECT_CALL eip=%08x target=%08x slot_base=%08x slot=%08x regs=%08x/%08x/%08x/%08x/%08x/%08x/%08x/%08x edx_window_start=%08x edx_window_len=33 edx_window_hex=%s object_guest=%08x object_len=32 object_hex=%s\n",
        callsite,target,slot_base,slot_base+4u,eax,ebx,ecx,edx,esi,edi,ebp,esp,
        edx-8u,vtable,eax,object);
    fflush(stderr);
}
static uint32_t stack_word_at(uint64_t address) {
    if (!guest_memory || address+4u>GUEST_LIMIT) return 0xFFFFFFFFu;
    return (uint32_t)guest_memory[address] |
           ((uint32_t)guest_memory[address+1u]<<8) |
           ((uint32_t)guest_memory[address+2u]<<16) |
           ((uint32_t)guest_memory[address+3u]<<24);
}
void gw_trace_control_entry(uint32_t target,uint32_t eax,uint32_t ebp,uint32_t esp) {
    uint64_t at=(uint64_t)g_ss_base+(uint64_t)esp;
    uint32_t raw_return=stack_word_at(at);
    uint32_t logical_return=gw_recomp_trace_last_return_to(target);
    fprintf(stderr,"TRACE original control-entry target=%08x caller_func=%08x EAX=%08x EBX=%08x ECX=%08x EDX=%08x ESI=%08x EDI=%08x EBP=%08x ESP=%08x SS=%04x SS_BASE=%08x stack_return=%08x logical_return_link=%08x\n",
        target,g_cur_func,eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,ebp,esp,
        g_seg_ss,g_ss_base,raw_return,logical_return);
}
typedef struct {
    uint32_t site,regs[8],esp,ss_base,cf,eflags,flat[4],segmented[4];
    uint16_t ss;
    char insn[48];
} rational_stack_row;
static rational_stack_row g_rational_stack_ring[128];
static uint32_t g_rational_stack_ring_next,g_rational_stack_ring_count;
static void emit_rational_stack_row(const rational_stack_row *r) {
    fprintf(stderr,"TRACE RATIONAL STACK eip_link=%08x eip_guest=%08x insn=\"%s\" ESP=%08x SS=%04x SS_BASE=%08x CF=%u EFLAGS=%08x EAX=%08x EBX=%08x ECX=%08x EDX=%08x ESI=%08x EDI=%08x EBP=%08x RETflat=%08x RETss=%08x flat=[%08x,%08x,%08x,%08x] ss=[%08x,%08x,%08x,%08x]\n",
        r->site,r->site+0x001EB000u,r->insn,r->esp,r->ss,r->ss_base,r->cf&1u,r->eflags,
        r->regs[0],r->regs[1],r->regs[2],r->regs[3],r->regs[4],r->regs[5],r->regs[6],
        r->flat[0],r->segmented[0],r->flat[0],r->flat[1],r->flat[2],r->flat[3],
        r->segmented[0],r->segmented[1],r->segmented[2],r->segmented[3]);
}
void gw_trace_rational_stack(uint32_t site,const char *insn,
    uint32_t eax,uint32_t ebx,uint32_t ecx,uint32_t edx,
    uint32_t esi,uint32_t edi,uint32_t ebp,uint32_t esp,
    uint16_t ss,uint32_t ss_base,uint32_t cf,uint32_t eflags) {
    uint64_t flat=(uint64_t)esp, segmented=(uint64_t)ss_base+esp;
    rational_stack_row *r=&g_rational_stack_ring[g_rational_stack_ring_next];
    memset(r,0,sizeof *r); r->site=site; r->regs[0]=eax; r->regs[1]=ebx;
    r->regs[2]=ecx; r->regs[3]=edx; r->regs[4]=esi; r->regs[5]=edi; r->regs[6]=ebp;
    r->esp=esp; r->ss=ss; r->ss_base=ss_base; r->cf=cf; r->eflags=eflags;
    snprintf(r->insn,sizeof r->insn,"%s",insn?insn:"");
    for(uint32_t i=0;i<4u;i++) {
        r->flat[i]=stack_word_at(flat+4u*i);
        r->segmented[i]=stack_word_at(segmented+4u*i);
    }
    if(site==0x000C3D79u && r->flat[0]==0xDEAD0000u)
        g_rational_ret_marker_seen=1;
    g_rational_stack_ring_next=(g_rational_stack_ring_next+1u)%128u;
    if(g_rational_stack_ring_count<128u) g_rational_stack_ring_count++;
    if(g_rational_stack_trace_armed && g_rational_stack_trace_rows<128u) {
        emit_rational_stack_row(r); g_rational_stack_trace_rows++;
    }
}
static void dump_rational_stack_ring(void) {
    uint32_t start=(g_rational_stack_ring_next+128u-g_rational_stack_ring_count)%128u;
    for(uint32_t i=0;i<g_rational_stack_ring_count;i++)
        emit_rational_stack_row(&g_rational_stack_ring[(start+i)%128u]);
}
typedef struct { uint32_t va, eax, ebp, esp, stack_word; uint16_t cw; int fp_top; } x87_trace_row;
static x87_trace_row g_x87_trace[16];
static uint32_t g_x87_trace_count;
void gw_capture_x87(uint32_t va) {
    if (g_x87_trace_count >= 16u) return;
    x87_trace_row *r=&g_x87_trace[g_x87_trace_count++];
    r->va=va; r->eax=g_eax; r->ebp=g_ebp; r->esp=g_esp;
    r->cw=g_fpu_cw; r->fp_top=g_fp_top; r->stack_word=0xFFFFFFFFu;
    uint64_t at=(uint64_t)g_ss_base+g_esp;
    if(guest_memory && at+2u<=GUEST_LIMIT)
        r->stack_word=(uint32_t)guest_memory[at] | ((uint32_t)guest_memory[at+1u]<<8);
}
static void dump_x87_trace(void) {
    for(uint32_t i=0;i<g_x87_trace_count;i++) {
        const x87_trace_row *r=&g_x87_trace[i];
        fprintf(stderr,"X87_STEP eip=%08x EAX=%08x EBP=%08x ESP=%08x stack16=%04x CW=%04x top=%d\n",
                r->va,r->eax,r->ebp,r->esp,r->stack_word,r->cw,r->fp_top);
    }
}
static uint8_t title_text_surface_before[0x4B000u];
static uint32_t title_text_active_site,title_text_active_surface;
static int title_text_snapshot_valid;
static unsigned comparator_calls, dos_ed_calls, dos_4a_calls, dos_4a_failures;

static void trace_dos_mcb_chain(const char *label,const uint8_t *memory) {
    uint32_t seg=0x0906u;
    fprintf(stderr,"TRACE DOS MCB %s:",label);
    for(unsigned step=0;step<8u && seg<DOS_CONVENTIONAL_TOP;step++) {
        uint32_t a=seg<<4;
        uint8_t tag=memory[a];
        uint16_t owner=(uint16_t)(memory[a+1u]|((uint16_t)memory[a+2u]<<8));
        uint16_t size=(uint16_t)(memory[a+3u]|((uint16_t)memory[a+4u]<<8));
        fprintf(stderr," [%04x:%c owner=%04x size=%04x]",seg,tag,owner,size);
        if(tag=='Z' || !size) break;
        seg+=(uint32_t)size+1u;
    }
    fputc('\n',stderr);
}
static int validate_dos_mcb_chain(const uint8_t *memory,uint16_t end_segment) {
    uint32_t seg=0x0906u;
    /* The bounded replay can leave hundreds of small file/service blocks;
       validate the complete paragraph chain instead of stopping at an
       arbitrary header-count limit. */
    for(unsigned step=0;step<0x10000u && seg<end_segment;step++) {
        uint64_t a64=(uint64_t)seg<<4;
        if(a64+16u>GUEST_LIMIT) return 0;
        uint32_t a=(uint32_t)a64;
        uint8_t tag=memory[a];
        uint16_t size=(uint16_t)(memory[a+3u]|((uint16_t)memory[a+4u]<<8));
        if((tag!='M' && tag!='Z') || !size || (uint64_t)seg+1u+size>end_segment)
            return 0;
        uint32_t next=seg+(uint32_t)size+1u;
        if(tag=='Z') return next==end_segment;
        if(next<=seg) return 0;
        seg=next;
    }
    return 0;
}
static uint16_t dos_mcb_largest_free(const uint8_t *memory) {
    uint32_t seg=0x0906u, largest=0;
    for(unsigned step=0;step<64u && seg<DOS_CONVENTIONAL_TOP;step++) {
        uint32_t a=seg<<4;
        uint8_t tag=memory[a];
        uint16_t owner=(uint16_t)(memory[a+1u]|((uint16_t)memory[a+2u]<<8));
        uint16_t size=(uint16_t)(memory[a+3u]|((uint16_t)memory[a+4u]<<8));
        if((tag!='M'&&tag!='Z') || (uint32_t)seg+1u+size>DOS_CONVENTIONAL_TOP) return 0;
        if(owner==0u && size>largest) largest=size;
        if(tag=='Z') return (uint16_t)largest;
        seg+=(uint32_t)size+1u;
    }
    return 0;
}
void gw_trace_dos_mcb_chain_current(const char *label) {
    trace_dos_mcb_chain(label,guest_memory);
}
static uint32_t read_guest_u32(uint32_t address) {
    if (!guest_memory || address>GUEST_LIMIT || 4u>GUEST_LIMIT-address)
        return 0xFFFFFFFFu;
    return (uint32_t)guest_memory[address] |
        ((uint32_t)guest_memory[address+1u]<<8) |
        ((uint32_t)guest_memory[address+2u]<<16) |
        ((uint32_t)guest_memory[address+3u]<<24);
}
static void trace_guest_heap_list(const char *phase) {
    uint32_t node=0x00361840u;
    fprintf(stderr,"TRACE original guest heap list phase=%s head=%08x\n",phase,node);
    for(uint32_t i=0;i<256u && node;i++) {
        if(node>GUEST_LIMIT-0x12u) {
            fprintf(stderr,"TRACE original guest heap list invalid-node index=%u node=%08x\n",i,node);
            break;
        }
        uint32_t base=read_guest_u32(node),size=read_guest_u32(node+4u),next=read_guest_u32(node+8u);
        uint32_t prev=read_guest_u32(node+12u);
        uint32_t allocated=guest_memory[node+0x10u],heap_type=guest_memory[node+0x11u];
        if(size || allocated || heap_type)
            fprintf(stderr,"TRACE original guest heap node index=%u node=%08x base=%08x size=%08x end=%09llx allocated=%u type=%u prev=%08x next=%08x\n",
                i,node,base,size,(unsigned long long)base+size,allocated,heap_type,prev,next);
        if(next==node) { fprintf(stderr,"TRACE original guest heap list self-link index=%u node=%08x\n",i,node); break; }
        node=next;
    }
}
static void trace_guest_heap_covering(uint32_t guest_address,const char *phase) {
    uint32_t node=0x00361840u;
    for(uint32_t i=0;i<256u && node;i++) {
        if(node>GUEST_LIMIT-0x12u) break;
        uint32_t base=read_guest_u32(node),size=read_guest_u32(node+4u),next=read_guest_u32(node+8u);
        if(size && guest_address>=base && (uint64_t)guest_address<(uint64_t)base+size) {
            fprintf(stderr,"TRACE original heap owner phase=%s guest=%08x node=%08x base=%08x size=%08x end=%09llx offset=%08x allocated=%u type=%u\n",
                phase,guest_address,node,base,size,(unsigned long long)base+size,
                guest_address-base,guest_memory[node+0x10u],guest_memory[node+0x11u]);
            return;
        }
        if(next==node) break;
        node=next;
    }
    fprintf(stderr,"TRACE original heap owner phase=%s guest=%08x result=untracked\n",phase,guest_address);
}
static const char *host_read_backing(uint32_t guest_address,uint32_t width,
    uint32_t *owner_base,uint32_t *owner_size) {
    uint64_t end=(uint64_t)guest_address+width;
    *owner_base=0u; *owner_size=0u;
    if(!width || end>GUEST_LIMIT) return "outside-guest-memory";
    for(uint32_t i=0;i<vfs.dos.dos_block_count;i++) {
        const gw_dos_memory_block *block=&vfs.dos.dos_blocks[i];
        uint32_t base=(uint32_t)block->segment<<4;
        uint64_t limit=(uint64_t)base+((uint64_t)block->paragraphs<<4);
        if(limit>base && guest_address>=base && end<=limit) {
            *owner_base=base; *owner_size=(uint32_t)(limit-base); return "live-dos-mcb";
        }
    }
    for(uint32_t i=0;i<GW_DOS_MAX_LINEAR_ALLOCATIONS;i++) {
        const gw_dos_linear_allocation *allocation=&vfs.dos.linear_allocations[i];
        uint64_t limit=(uint64_t)allocation->base+allocation->size;
        if(allocation->active && guest_address>=allocation->base && end<=limit) {
            *owner_base=allocation->base; *owner_size=allocation->size; return "live-dpmi-linear";
        }
    }
    uint32_t node=0x00361840u;
    for(uint32_t i=0;i<256u && node;i++) {
        if(node>GUEST_LIMIT-0x12u) break;
        uint32_t base=read_guest_u32(node),size=read_guest_u32(node+4u),next=read_guest_u32(node+8u);
        uint64_t limit=(uint64_t)base+size;
        if(size && guest_memory[node+0x10u] && guest_address>=base && end<=limit) {
            *owner_base=base; *owner_size=size; return "live-game-heap";
        }
        if(next==node) break;
        node=next;
    }
    if(guest_address>=0x003F0000u && end<=0x00400000u) {
        *owner_base=0x003F0000u; *owner_size=0x10000u; return "guest-stack";
    }
    return "guest-memory-unclassified";
}
void gw_trace_lbm_free_store(uint32_t site,uint32_t ds_base,
    uint32_t edx,uint32_t eax) {
    uint64_t linear=(uint64_t)ds_base+edx+0x10u;
    if (linear<0x9000u || linear>=0x9200u) return;
    uint32_t descriptor_head=read_guest_u32(0x00361840u);
    uint32_t node_next=(edx<=GUEST_LIMIT-8u)?read_guest_u32(edx+8u):0xFFFFFFFFu;
    fprintf(stderr,"TRACE LbMemoryFree store site=%08x DS_BASE=%08x EDX=%08x EAX=%08x write=%08llx descriptor_head[361840]=%08x node_next=%08x node_flag=%02x\n",
        site,ds_base,edx,eax,(unsigned long long)linear,descriptor_head,node_next,
        edx+0x10u<GUEST_LIMIT?guest_memory[edx+0x10u]:0xFFu);
    trace_dos_mcb_chain("immediately_after_LbMemoryFree_store",guest_memory);
}
void gw_trace_gadget_free_store(uint32_t site,uint32_t linear,
    uint32_t edx,uint32_t ebx,uint32_t esi,uint32_t edi) {
    if (linear>=0x9100u || linear+4u<=0x9000u) return;
    fprintf(stderr,"TRACE FreeMyGadgets store site=%08x linear=%08x EDX=%08x EBX=%08x ESI=%08x EDI=%08x bytes=%02x%02x%02x%02x\n",
        site,linear,edx,ebx,esi,edi,
        linear<GUEST_LIMIT?guest_memory[linear]:0xFFu,
        linear+1u<GUEST_LIMIT?guest_memory[linear+1u]:0xFFu,
        linear+2u<GUEST_LIMIT?guest_memory[linear+2u]:0xFFu,
        linear+3u<GUEST_LIMIT?guest_memory[linear+3u]:0xFFu);
    trace_dos_mcb_chain("immediately_after_FreeMyGadgets_store",guest_memory);
}
void gw_trace_gadget_lbm_call(uint32_t site,uint32_t phase,
    uint32_t eax,uint32_t edx,uint32_t ebx) {
    static unsigned calls;
    if (calls++>=16u) return;
    fprintf(stderr,"TRACE FreeMyGadgets LbMemoryFree site=%08x phase=%u EAX=%08x EDX=%08x EBX=%08x list_head[3794B8]=%08x memory_head[361840]=%08x\n",
        site,phase,eax,edx,ebx,read_guest_u32(0x003794B8u),read_guest_u32(0x00361840u));
    trace_dos_mcb_chain(phase?"after_FreeMyGadgets_LbMemoryFree":"before_FreeMyGadgets_LbMemoryFree",guest_memory);
}
static uint32_t rnc_call_eax, rnc_call_ecx, rnc_call_edx;
static uint32_t title_rnc_eax,title_rnc_ecx,title_rnc_edx;
static uint32_t title_rnc_calls;
static int rnc_capture_pending;
static int capture_current_resource;
static void original_int31_thunk(void);

static uint8_t mcb_watch_snapshot[0x30u];
static uint32_t mcb_watch_previous_va;
static uint32_t mcb_watch_memset_site,mcb_watch_memset_eax,mcb_watch_memset_ebx,mcb_watch_memset_edx;
static unsigned mcb_watch_events;
static int mcb_watch_active,mcb_watch_snapshot_valid;
void gw_mcb_watch_arm(const char *label) {
    mcb_watch_active=1; mcb_watch_snapshot_valid=0; mcb_watch_previous_va=0;
    mcb_watch_memset_site=mcb_watch_memset_eax=mcb_watch_memset_ebx=mcb_watch_memset_edx=0;
    mcb_watch_events=0;
    fprintf(stderr,"TRACE MCB watch begin label=%s range=00009060..000090df\n",label?label:"(null)");
    trace_dos_mcb_chain("watch_baseline",guest_memory);
}
void gw_watch_memset_call(uint32_t site,uint32_t eax,uint32_t ebx,uint32_t edx) {
    if(!mcb_watch_active) return;
    mcb_watch_memset_site=site; mcb_watch_memset_eax=eax;
    mcb_watch_memset_ebx=ebx; mcb_watch_memset_edx=edx;
}
void gw_mcb_watch_disarm(const char *label) {
    fprintf(stderr,"TRACE MCB watch end label=%s events=%u\n",label?label:"(null)",mcb_watch_events);
    mcb_watch_active=0; mcb_watch_snapshot_valid=0;
}
void gw_watch_mcb_instruction(uint32_t current_va,uint32_t eax,uint32_t ebx,
    uint32_t ecx,uint32_t edx,uint32_t esp) {
    if(!mcb_watch_active || !guest_memory) return;
    static const uint32_t bases[3]={0x00009060u,0x00009080u,0x0000F090u};
    uint8_t current[sizeof mcb_watch_snapshot];
    for(unsigned b=0;b<3u;b++) memcpy(current+b*16u,guest_memory+bases[b],16u);
    if(!mcb_watch_snapshot_valid) {
        memcpy(mcb_watch_snapshot,current,sizeof mcb_watch_snapshot);
        mcb_watch_snapshot_valid=1; mcb_watch_previous_va=current_va; return;
    }
    uint32_t first=UINT32_MAX,last=0; unsigned changes=0;
    for(uint32_t i=0;i<sizeof mcb_watch_snapshot;i++) {
        if(mcb_watch_snapshot[i]!=current[i]) {
            const uint32_t address=bases[i/16u]+(i%16u);
            if(first==UINT32_MAX) first=address;
            last=address; changes++;
        }
    }
    if(changes && mcb_watch_events<64u) {
        const uint32_t first_i=(first>=0xF090u?32u:first>=0x9080u?16u:0u)+(first&0xFu);
        uint32_t stack[5];
        for(unsigned k=0;k<5u;k++) stack[k]=(esp+4u*k+4u<=GUEST_LIMIT)?read_guest_u32(esp+4u*k):0xFFFFFFFFu;
        fprintf(stderr,"TRACE MCB first-change previous_eip=%08x next_eip=%08x first=%08x last=%08x bytes=%u old=%02x new=%02x EAX=%08x EBX=%08x ECX=%08x EDX=%08x ESP=%08x stack=%08x/%08x/%08x/%08x/%08x memset_call=%08x(%08x,%08x,%08x)\n",
            mcb_watch_previous_va,current_va,first,last,changes,
            mcb_watch_snapshot[first_i],guest_memory[first],eax,ebx,ecx,edx,esp,
            stack[0],stack[1],stack[2],stack[3],stack[4],mcb_watch_memset_site,
            mcb_watch_memset_eax,mcb_watch_memset_ebx,mcb_watch_memset_edx);
        trace_dos_mcb_chain("instruction_boundary",guest_memory);
        mcb_watch_events++;
    }
    memcpy(mcb_watch_snapshot,current,sizeof mcb_watch_snapshot);
    mcb_watch_previous_va=current_va;
}

static void dump_guest_ascii(uint32_t address,char *out,size_t capacity) {
    if (!out || capacity==0) return;
    size_t n=0;
    if (guest_memory && address<GUEST_LIMIT) {
        while (n+1<capacity && address+n<GUEST_LIMIT) {
            unsigned char c=guest_memory[address+n];
            if (c==0) break;
            out[n++]=(c>=32 && c<127)?(char)c:'.';
        }
    }
    out[n]=0;
}

void gw_trace_title_text_call(uint32_t site,uint32_t eax,uint32_t edx,
                              uint32_t ecx,uint32_t ebx) {
    char text[49];
    dump_guest_ascii(ecx,text,sizeof text);
    uint32_t glyph_table=(guest_memory && eax<=GUEST_LIMIT && 4u<=GUEST_LIMIT-eax)?
        *(uint32_t *)(guest_memory+eax):0u;
    uint32_t font_flags=(guest_memory && eax<=GUEST_LIMIT && 0x14u<=GUEST_LIMIT-eax)?
        *(uint32_t *)(guest_memory+eax+0x10u):0u;
    static const uint32_t title_text_globals[]={0x002EF0A8u,0x002EF0B0u,
                                                 0x002EF0B4u,0x002EF0B8u};
    printf("TRACE title_text_call site=%08x eax=%08x edx=%08x ecx=%08x ebx=%08x "
           "text_ascii=\"%s\" font_object_glyph_table=%08x font_flags=%08x text_globals=",
           site,eax,edx,ecx,ebx,text,glyph_table,font_flags);
    for (unsigned i=0;i<sizeof title_text_globals/sizeof title_text_globals[0];i++)
        printf("%s%08x",i?"/":"",guest_memory && title_text_globals[i]+4u<=GUEST_LIMIT?
               *(uint32_t *)(guest_memory+title_text_globals[i]):0u);
    printf("\n");
}

void gw_trace_title_text_begin(uint32_t site) {
    title_text_active_site=site;
    title_text_active_surface=guest_memory && 0x00376A60u<=GUEST_LIMIT?
        *(uint32_t *)(guest_memory+0x00376A5Cu):0u;
    title_text_snapshot_valid=title_text_active_surface<=GUEST_LIMIT &&
        0x4B000u<=GUEST_LIMIT-title_text_active_surface;
    if(title_text_snapshot_valid)
        memcpy(title_text_surface_before,guest_memory+title_text_active_surface,0x4B000u);
}

void gw_trace_title_text_end(uint32_t site) {
    if(site!=title_text_active_site || !title_text_snapshot_valid) {
        printf("TRACE original title glyph write site=%08x invalid-surface=%08x\n",
               site,title_text_active_surface); title_text_snapshot_valid=0; return;
    }
    uint32_t changed=0,first=0,last=0;
    for(uint32_t i=0;i<0x4B000u;i++) {
        if(title_text_surface_before[i]!=guest_memory[title_text_active_surface+i]) {
            if(!changed) first=i;
            last=i; changed++;
        }
    }
    printf("TRACE original title glyph write site=%08x surface=%08x changed=%u range=%08x..%08x\n",
           site,title_text_active_surface,changed,changed?first:0u,changed?last:0u);
    title_text_snapshot_valid=0;
}

void gw_capture_lbdataload_rnc_args(uint32_t eax,uint32_t ecx,uint32_t edx) {
    if (capture_current_resource) {
        rnc_call_eax=eax; rnc_call_ecx=ecx; rnc_call_edx=edx;
        rnc_capture_pending=1;
    } else if (guest_path_has_suffix(vfs.last_path,"data/titlescr.dat")) {
        title_rnc_eax=eax; title_rnc_ecx=ecx; title_rnc_edx=edx;
        title_rnc_calls++;
        if (eax<=GUEST_LIMIT && 139405u<=GUEST_LIMIT-eax) {
            FILE *f=fopen("work\\ifctitle_plugin_titlescr_input.bin","wb");
            if (f) { fwrite(guest_memory+eax,1,139405u,f); fclose(f); }
        }
    }
}
void gw_capture_lbdataload_relocated_payload(uint32_t guest_va) {
    if(!rnc_capture_pending) return;
    rnc_capture_pending=0;
    uint32_t packed=*(uint32_t *)(guest_memory+0x002E56ECu);
    if(guest_va>GUEST_LIMIT || packed>GUEST_LIMIT-guest_va) return;
    FILE *f=fopen("work\\lbdataload_relocated_rnc_payload.bin","wb");
    if(!f) return;
    fwrite(guest_memory+guest_va,1,packed,f);
    fclose(f);
}

static int in_guest(uint16_t selector,uint32_t offset,uint32_t width,void *user) {
    (void)user;
    if (!width) return 0;
    /* The bounded Watcom startup profile uses ES=0x24 for the PSP at
       linear 0x8000. Trust only the descriptor installed below, not the
       selector value alone. */
    if (selector==0x24u)
        return gw_dos_descriptor_range(selector,offset,width,&vfs.dos);
    if ((selector & 0xFFFCu)!=(0x14u & 0xFFFCu) ||
        offset>GUEST_LIMIT || width>GUEST_LIMIT-offset) return 0;
    if ((offset>=0x00090000u && offset+width<=0x000B0000u) ||
        (offset>=0x001FB000u && offset+width<=0x002D9930u) ||
        (offset>=0x002DA000u && offset+width<=0x00382C50u) ||
        (offset>=0x00390000u && offset+width<=0x003FE000u) ||
        (offset>=FLAT_HEAP_BEGIN && offset+width<=GUEST_LIMIT) ||
        (offset>=STACK_TOP-0x3000u && offset+width<=GUEST_LIMIT)) return 1;
    for (uint32_t i=0;i<vfs.dos.dos_block_count;i++) {
        uint32_t begin=(uint32_t)vfs.dos.dos_blocks[i].segment<<4;
        uint32_t end=begin+((uint32_t)vfs.dos.dos_blocks[i].paragraphs<<4);
        if (offset>=begin && offset+width<=end) return 1;
    }
    return 0;
}

static int make_confined_path(char *out,size_t out_size,const char *root,const char *dos_path) {
    char relative[512],root_full[512],candidate[1024],full[1024];
    if(!out||!out_size||!root||!dos_path||!dos_path[0]) return 0;
    const char *p=dos_path;
    if(((p[0]>='A'&&p[0]<='Z')||(p[0]>='a'&&p[0]<='z'))&&p[1]==':') p+=2;
    while(*p=='\\'||*p=='/') p++;
    if(!_strnicmp(p,"GENEWARS\\",9u)) p+=9u;
    else if(!_strnicmp(p,"GAME\\",5u)) p+=5u;
    size_t n=0;
    for(;*p && n+1<sizeof relative;p++) {
        char c=*p=='/'?'\\':*p;
        if(c==':'||c=='\0') return 0;
        relative[n++]=c;
    }
    if(*p||!n) return 0;
    relative[n]=0;
    for(size_t i=0;i<n;i++) {
        if((relative[i]=='\\') &&
           ((i+1<n&&relative[i+1]=='\\') ||
            (i==0&&i+1<n&&relative[i+1]=='.'))) return 0;
    }
    for(const char *q=relative;*q;) {
        const char *end=strchr(q,'\\'); size_t len=end?(size_t)(end-q):strlen(q);
        if((len==2&&q[0]=='.'&&q[1]=='.') || (len==1&&q[0]=='.')) return 0;
        q=end?end+1:q+len;
    }
    if(!_fullpath(root_full,root,sizeof root_full)) return 0;
    if(_snprintf(candidate,sizeof candidate,"%s\\%s",root_full,relative)<0) return 0;
    if(!_fullpath(full,candidate,sizeof full)) return 0;
    size_t root_len=strlen(root_full);
    while(root_len>3&&(root_full[root_len-1]=='\\'||root_full[root_len-1]=='/')) root_full[--root_len]=0;
    if(_strnicmp(full,root_full,root_len)!=0 ||
       (full[root_len] && full[root_len]!='\\' && full[root_len]!='/')) return 0;
    return _snprintf(out,out_size,"%s",full)>=0;
}

static int load_vfs_manifest(fixture_vfs *s,const char *path) {
    if(!s||!path) return 0;
    FILE *fp=fopen(path,"rb"); if(!fp) return 0;
    uint32_t capacity=0; char line[1100];
    while(fgets(line,sizeof line,fp)) {
        char *nl=strpbrk(line,"\r\n"); if(nl) *nl=0;
        char *tab=strchr(line,'\t');
        if(!tab||tab-line!=64||!tab[1]) { fclose(fp); return 0; }
        if(s->manifest_count==capacity) {
            uint32_t next=capacity?capacity*2u:128u;
            vfs_manifest_record *grown=(vfs_manifest_record *)realloc(s->manifest,
                (size_t)next*sizeof *grown);
            if(!grown) { fclose(fp); return 0; }
            s->manifest=grown; capacity=next;
        }
        *tab++=0;
        vfs_manifest_record *record=&s->manifest[s->manifest_count++];
        memcpy(record->sha256,line,64); record->sha256[64]=0;
        if(strlen(tab)>=sizeof record->path) { fclose(fp); return 0; }
        strncpy(record->path,tab,sizeof record->path-1u);
        record->path[sizeof record->path-1u]=0;
        for(char *c=record->path;*c;c++) {
            if(*c=='\\') *c='/';
            if(*c>='A'&&*c<='Z') *c=(char)(*c-'A'+'a');
        }
    }
    fclose(fp);
    return s->manifest_count>0;
}

static const vfs_manifest_record *manifest_find(fixture_vfs *s,const char *root,
                                                 const char *source) {
    char root_full[512],relative[1024];
    if(!s||!_fullpath(root_full,root,sizeof root_full)) return NULL;
    size_t root_len=strlen(root_full);
    while(root_len>3&&(root_full[root_len-1]=='\\'||root_full[root_len-1]=='/'))
        root_full[--root_len]=0;
    if(_strnicmp(source,root_full,root_len)!=0 ||
       (source[root_len]!='\\'&&source[root_len]!='/')) return NULL;
    const char *rel=source+root_len+1u;
    if(strlen(rel)>=sizeof relative) return NULL;
    strcpy(relative,rel);
    for(char *c=relative;*c;c++) {
        if(*c=='\\') *c='/';
        if(*c>='A'&&*c<='Z') *c=(char)(*c-'A'+'a');
    }
    for(uint32_t i=0;i<s->manifest_count;i++)
        if(!_stricmp(s->manifest[i].path,relative)) return &s->manifest[i];
    return NULL;
}

static int verify_manifest_file(const vfs_manifest_record *record,const char *path) {
    if(!record||!path) return 0;
    BCRYPT_ALG_HANDLE algorithm=NULL; BCRYPT_HASH_HANDLE hash=NULL;
    DWORD object_size=0,hash_size=0,cb=0; PUCHAR object=NULL;
    NTSTATUS status=BCryptOpenAlgorithmProvider(&algorithm,BCRYPT_SHA256_ALGORITHM,NULL,0);
    if(status<0) return 0;
    status=BCryptGetProperty(algorithm,BCRYPT_OBJECT_LENGTH,(PUCHAR)&object_size,
                             sizeof object_size,&cb,0);
    if(status>=0) status=BCryptGetProperty(algorithm,BCRYPT_HASH_LENGTH,(PUCHAR)&hash_size,
                                           sizeof hash_size,&cb,0);
    if(status<0||hash_size!=32u) { BCryptCloseAlgorithmProvider(algorithm,0); return 0; }
    object=(PUCHAR)malloc(object_size?object_size:1u);
    if(!object) { BCryptCloseAlgorithmProvider(algorithm,0); return 0; }
    status=BCryptCreateHash(algorithm,&hash,object,object_size,NULL,0,0);
    FILE *fp=status>=0?fopen(path,"rb"):NULL;
    if(!fp) status=-1;
    uint8_t buffer[32768]; size_t got;
    while(status>=0&&(got=fread(buffer,1,sizeof buffer,fp))!=0)
        status=BCryptHashData(hash,buffer,(ULONG)got,0);
    if(fp&&ferror(fp)) status=-1;
    uint8_t digest[32];
    if(status>=0) status=BCryptFinishHash(hash,digest,sizeof digest,0);
    if(fp) fclose(fp);
    if(hash) BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm,0); free(object);
    if(status<0) return 0;
    char hex[65];
    for(unsigned i=0;i<32;i++) _snprintf(hex+i*2u,3u,"%02x",digest[i]);
    hex[64]=0;
    return !_stricmp(hex,record->sha256);
}

static int ensure_parent_directories(const char *path) {
    char parent[1024]; size_t n=strlen(path);
    if(n>=sizeof parent) return 0;
    memcpy(parent,path,n+1);
    for(size_t i=0;i<n;i++) if(parent[i]=='\\'||parent[i]=='/') {
        char save=parent[i]; parent[i]=0;
        if(parent[0] && _mkdir(parent)!=0 && errno!=EEXIST) { parent[i]=save; return 0; }
        parent[i]=save;
    }
    return 1;
}

/* DOS may pass a relative resource name or the same name after GetConfigs has
   made C:\\GENEWARS the current directory. Match only the exact final path
   component sequence, with slash spelling treated equivalently. */
static int guest_path_has_suffix(const char *path,const char *suffix) {
    if(!path||!suffix) return 0;
    size_t path_len=strlen(path),suffix_len=strlen(suffix);
    if(path_len<suffix_len) return 0;
    const char *tail=path+path_len-suffix_len;
    char actual[64],expected[64];
    if(suffix_len>=sizeof actual) return 0;
    for(size_t i=0;i<suffix_len;i++) {
        actual[i]=(tail[i]=='/')?'\\':tail[i];
        expected[i]=(suffix[i]=='/')?'\\':suffix[i];
    }
    actual[suffix_len]=expected[suffix_len]=0;
    if(_stricmp(actual,expected)) return 0;
    return path_len==suffix_len || path[path_len-suffix_len-1u]=='\\' ||
           path[path_len-suffix_len-1u]=='/';
}

static int missing_save_slot_index(const char *path) {
    char suffix[32];
    for(int slot=1;slot<=7;slot++) {
        _snprintf(suffix,sizeof suffix,"SAVE/SAVE%d.SAV",slot);
        if(guest_path_has_suffix(path,suffix)) return slot-1;
    }
    return -1;
}

static uint16_t host_open(void *user,const char *path,uint8_t access,void **out) {
    fixture_vfs *s=(fixture_vfs *)user;
    int capture=guest_path_has_suffix(path,"data/iftitle.anb");
    char source[1024],overlay[1024];
    if(path && (!_stricmp(path,"config.ini") ||
                !_stricmp(path,"c:\\genewars\\") ||
                !_stricmp(path,"d:\\game\\"))) {
        if(!s||!make_confined_path(source,sizeof source,s->root,"CONFIG.INI")) return 3u;
    } else if(path && (!_stricmp(path,"c:\\genewars\\sound.ini") ||
                       !_stricmp(path,"d:\\game\\sound.ini"))) {
        if(!s||!make_confined_path(source,sizeof source,s->root,"SOUND.INI")) return 3u;
    } else if(path && (!_stricmp(path,"c:\\genewars\\intro\\biointro.smk") ||
                       !_stricmp(path,"d:\\game\\intro\\biointro.smk"))) {
        if(!s||!make_confined_path(source,sizeof source,s->root,"INTRO\\BIOINTRO.SMK")) return 3u;
    } else if(s && path && !make_confined_path(source,sizeof source,s->root,path)) {
        fprintf(stderr,"TRACE original VFS open path='%s' access=%u result=5 path_escape\n",path,access);
        s->denied++; return 5u;
    }
    int missing_slot=missing_save_slot_index(path);
    if(missing_slot>=0) {
        /* The exact local SAVE directory was checked and contains SAVE0.SAV
           only. Match the normalized suffix so both relative names and DOS
           absolute C:\\GENEWARS\\SAVE\\ names produce the same real DOS
           file-not-found response. */
        if(s) {
            s->missing_save_slots++;
            s->save_slot_open_attempts[missing_slot]++;
            strncpy(s->last_path,path,sizeof s->last_path-1u);
        }
        fprintf(stderr,"TRACE original VFS open path='%s' access=%u result=2 missing_verified_save_slot=%d\n",
                path,access,missing_slot+1);
        return 2u;
    }
    if(!s||!path||!out||access>2u) return 5u;
    capture_current_resource=capture;
    FILE *source_probe=fopen(source,"rb");
    int source_exists=source_probe!=NULL;
    if(source_probe) fclose(source_probe);
    const vfs_manifest_record *manifest=source_exists?manifest_find(s,s->root,source):NULL;
    if(source_exists && (!manifest || !verify_manifest_file(manifest,source))) {
        fprintf(stderr,"TRACE original VFS manifest-deny path='%s' source='%s' listed=%u verified=0\n",
                path,source,manifest!=NULL);
        s->denied++; return 5u;
    }
    if(!source_exists && access==0u) {
        fprintf(stderr,"TRACE original VFS open path='%s' access=%u result=2 missing_file\n",path,access);
        return 2u;
    }
    FILE *fp=NULL;
    if(access==0u) fp=fopen(source,"rb");
    else {
        if(!make_confined_path(overlay,sizeof overlay,"work\\dos_vfs_overlay",path) ||
           !ensure_parent_directories(overlay)) return 5u;
        FILE *existing_overlay=fopen(overlay,"rb");
        if(existing_overlay) fclose(existing_overlay);
        else {
            FILE *original=fopen(source,"rb");
            if(original) {
                FILE *copy=fopen(overlay,"wb");
                if(!copy) { fclose(original); return 5u; }
                char buf[16384]; size_t got;
                while((got=fread(buf,1,sizeof buf,original))!=0)
                    if(fwrite(buf,1,got,copy)!=got) { fclose(copy); fclose(original); return 5u; }
                fclose(copy); fclose(original);
            }
        }
        fp=fopen(overlay,"r+b");
    }
    if(!fp) {
        fprintf(stderr,"TRACE original VFS open path='%s' access=%u result=2 source='%s'\n",path,access,source);
        return 2u;
    }
    host_file *h=(host_file *)calloc(1,sizeof *h); if (!h) return 8u;
    h->fp=fp;
    h->capture_rnc=capture; s->opens++;
    strncpy(h->path,path,sizeof h->path-1u);
    if (!s->first_path[0]) strncpy(s->first_path,path,sizeof s->first_path-1u);
    strncpy(s->last_path,path,sizeof s->last_path-1u); *out=h;
    fprintf(stderr,"TRACE original VFS open path='%s' access=%u result=0 handle=%u source='%s' mode=%s manifest_sha256=%s\n",path,access,s->opens,access?overlay:source,access?"overlay-rw":"install-ro",access?"overlay-only":manifest->sha256);
    return 0;
}
static uint16_t host_read(void *user,void *file,uint8_t *buffer,uint16_t requested,uint16_t *done) {
    fixture_vfs *s=(fixture_vfs *)user; host_file *h=(host_file *)file;
    if (!s || !h || !h->fp || !buffer || !done) return 6u;
    unsigned slot=s->reads;
    long file_pos=ftell(h->fp);
    *done=(uint16_t)fread(buffer,1,requested,h->fp); s->reads++; h->reads++;
    if(*done) {
        uintptr_t host=(uintptr_t)buffer,base=(uintptr_t)guest_memory;
        uint64_t guest=(host>=base)?(uint64_t)(host-base):UINT64_MAX;
        uint32_t owner_base=0u,owner_size=0u;
        const char *backing=(guest<=UINT32_MAX)?host_read_backing((uint32_t)guest,*done,
            &owner_base,&owner_size):"host-outside-guest";
        fprintf(stderr,"TRACE host AH3F write eip=%08x path='%s' file_offset=%08lx requested=%u done=%u guest=%08llx range_end=%08llx backing=%s owner=%08x+%08x\n",
            low_write_current_eip,h->path,file_pos,requested,*done,
            (unsigned long long)guest,(unsigned long long)(guest+*done),backing,owner_base,owner_size);
        if(low_write_capture_enabled && guest<=UINT32_MAX && guest<LOW_WRITE_CAPTURE_LIMIT) {
            uint32_t dst=(uint32_t)guest;
            uint16_t source=low_write_source_id(h->path);
            capture_low_provider_write(low_write_current_eip,dst,*done,
                LOW_WRITER_DOS_READ,source);
        }
    }
    int is_system1=guest_path_has_suffix(h->path,"anims/system1.smk");
    if(is_system1) {
        s->system1_reads++;
        if(!*done) s->system1_eof_reads++;
        s->system1_last_offset=file_pos;
        s->system1_last_requested=requested;
        s->system1_last_done=*done;
    }
    if(!is_system1 || h->reads<=16u || (h->reads%4096u)==0u ||
       (is_system1 && !*done && h->eof_reads<4u)) {
        fprintf(stderr,"TRACE original VFS read path='%s' offset=%08lx requested=%u done=%u guest=%08x%s\n",
            h->path,file_pos,requested,*done,
            (uint32_t)((uintptr_t)buffer-(uintptr_t)guest_memory),
            is_system1?" sampled":"");
    }
    if(is_system1 && !*done) h->eof_reads++;
    if (guest_path_has_suffix(h->path,"data/text.dat")) {
        s->text_reads++;
        s->text_bytes+=*done;
        if(requested>8u && *done) {
            s->text_payload_reads++;
            s->text_payload_bytes+=*done;
            s->text_payload_guest=(uint32_t)((uintptr_t)buffer-(uintptr_t)guest_memory);
        }
        fprintf(stderr,"TRACE text.dat read[%u] file+%08lx request=%u done=%u guest=%08x\n",
                s->text_reads-1u,file_pos,requested,*done,
                (uint32_t)((uintptr_t)buffer-(uintptr_t)guest_memory));
    }
    if (guest_path_has_suffix(h->path,"data/titlescr.dat")) {
        if (s->title_screen_reads<4u) {
            unsigned t=s->title_screen_reads;
            s->title_read_pos[t]=file_pos;
            s->title_read_requested[t]=requested;
            s->title_read_done[t]=*done;
            s->title_read_guest[t]=(uint32_t)((uintptr_t)buffer-(uintptr_t)guest_memory);
        }
        fprintf(stderr,"TRACE titlescr read[%u] file+%08lx request=%u done=%u guest=%08x\n",
                s->title_screen_reads,file_pos,requested,*done,
                (uint32_t)((uintptr_t)buffer-(uintptr_t)guest_memory));
        s->title_screen_reads++;
        s->title_screen_bytes+=*done;
    }
    if (slot<8u) {
        s->read_pos[slot]=file_pos;
        s->read_requested[slot]=requested;
        s->read_done[slot]=*done;
        s->read_guest[slot]=(uint32_t)((uintptr_t)buffer-(uintptr_t)guest_memory);
        if (h->capture_rnc && *done>4096u) {
            if (*done>GUEST_LIMIT-RNC_SOURCE) return 5u;
            memcpy(guest_memory+RNC_SOURCE,buffer,*done);
            FILE *capture=fopen("work\\lbdataload_compressed_capture.bin","wb");
            if (!capture || fwrite(buffer,1,*done,capture)!=*done) {
                if (capture) fclose(capture);
                return 5u;
            }
            fclose(capture);
        }
    }
    return ferror(h->fp)?5u:0u;
}
static uint16_t host_create(void *user,const char *path,uint16_t attributes,void **out) {
    fixture_vfs *s=(fixture_vfs *)user;
    if(!s || !path || !out) return 5u;
    host_file *h=(host_file *)calloc(1,sizeof *h); if(!h) return 8u;
    char overlay[1024];
    if(!make_confined_path(overlay,sizeof overlay,"work\\dos_vfs_overlay",path) ||
       !ensure_parent_directories(overlay)) { free(h); return 5u; }
    h->fp=fopen(overlay,"w+b");
    if(!h->fp) { free(h); return 5u; }
    strncpy(h->path,path,sizeof h->path-1u); *out=h;
    s->opens++; strncpy(s->last_path,path,sizeof s->last_path-1u);
    fprintf(stderr,"TRACE original VFS create path='%s' overlay='%s' attributes=%04x result=0\n",path,overlay,attributes);
    return 0u;
}
static uint16_t host_write(void *user,void *file,const uint8_t *buffer,
                           uint16_t requested,uint16_t *done) {
    fixture_vfs *s=(fixture_vfs *)user; host_file *h=(host_file *)file;
    if(!s || !h || !h->fp || (!buffer && requested) || !done) return 6u;
    *done=(uint16_t)fwrite(buffer,1,requested,h->fp);
    if(ferror(h->fp)) return 5u;
    fprintf(stderr,"TRACE original VFS write path='%s' requested=%u done=%u overlay=work/dos_vfs_overlay\n",
            h->path,requested,*done);
    return *done==requested?0u:5u;
}
static uint16_t host_close(void *user,void *file) {
    fixture_vfs *s=(fixture_vfs *)user; host_file *h=(host_file *)file;
    if (!s || !h || !h->fp) return 6u;
    fclose(h->fp); h->fp=NULL; free(h); s->closes++; return 0;
}
static uint16_t host_stderr_write(void *user,const uint8_t *buffer,
                                  uint16_t requested,uint16_t *transferred) {
    fixture_vfs *s=(fixture_vfs *)user;
    if(!s || (!buffer && requested) || !transferred) return 6u;
    uint32_t available=(uint32_t)sizeof s->stderr_capture-s->stderr_capture_size;
    uint16_t copied=(uint16_t)(requested>available?available:requested);
    if(copied) memcpy(s->stderr_capture+s->stderr_capture_size,buffer,copied);
    s->stderr_capture_size+=copied; *transferred=copied;
    return copied==requested?0u:5u;
}

static uint16_t host_stdout_write(void *user,const uint8_t *buffer,
                                  uint16_t requested,uint16_t *transferred) {
    fixture_vfs *s=(fixture_vfs *)user;
    if(!s || (!buffer && requested) || !transferred) return 6u;
    uint32_t available=(uint32_t)sizeof s->stdout_capture-s->stdout_capture_size;
    uint16_t copied=(uint16_t)(requested>available?available:requested);
    if(copied) memcpy(s->stdout_capture+s->stdout_capture_size,buffer,copied);
    s->stdout_capture_size+=copied; *transferred=copied;
    return copied==requested?0u:5u;
}

static void trace_resource_records(const uint8_t *memory,uint32_t records,
                                   const char *phase) {
    fprintf(stderr,"TRACE original TbLoadFiles %s base=%08x stride=44\n",phase,records);
    for(unsigned i=0;i<32u;i++) {
        uint32_t at=records+i*44u;
        if(at>=GUEST_LIMIT || 44u>GUEST_LIMIT-at) break;
        const char *name=(const char *)(memory+at);
        if(!name[0]) { fprintf(stderr,"TRACE original TbLoadFiles[%u] terminator\n",i); break; }
        uint32_t cell=*(const uint32_t *)(memory+at+28u);
        uint32_t packed=*(const uint32_t *)(memory+at+32u);
        uint32_t unpacked=*(const uint32_t *)(memory+at+36u);
        fprintf(stderr,"TRACE original TbLoadFiles[%u] name='%.*s' cell=%08x packed=%08x unpacked=%08x\n",
                i,28,name,cell,packed,unpacked);
    }
}

void gw_trace_options_fileload(uint32_t site,uint32_t phase,uint32_t eax,
                              uint32_t ebx,uint32_t edx) {
    static uint32_t attempts_481,attempts_495;
    uint32_t *attempts=site==0x6A481u?&attempts_481:&attempts_495;
    if(!phase) (*attempts)++;
    uint32_t attempt=*attempts;
    if(phase && eax!=0xFFFFFFFFu) *attempts=0;
    if(!(attempt<=2u || attempt%25u==0u || (phase && eax!=0xFFFFFFFFu))) return;
    char name[96];
    if(!edx) strcpy(name,"<null>"); else dump_guest_ascii(edx,name,sizeof name);
    fprintf(stderr,"TRACE original OPTIONS LbFileLoadAt site=%08x attempt=%u phase=%u EAX=%08x EBX=%08x EDX=%08x name='%s' return=%08x\n",
            site,attempt,phase,eax,ebx,edx,name,phase?eax:0u);
}

void gw_trace_options_load_attempt(uint32_t phase,uint32_t attempt,
                                   uint32_t eax,uint32_t ebx,uint32_t edx) {
    if(!(attempt<2u || attempt%25u==0u || (phase && eax!=0xFFFFFFFFu))) return;
    char name[96];
    if(phase) name[0]=0;
    else if(!eax) strcpy(name,"<null>");
    else dump_guest_ascii(eax,name,sizeof name);
    fprintf(stderr,"TRACE original OPTIONS load_attempt=%u phase=%u EAX=%08x EBX=%08x EDX=%08x path='%s' result=%08x\n",
            attempt,phase,eax,ebx,edx,phase?"":name,phase?eax:0u);
}
static uint16_t host_seek(void *user,void *file,int32_t displacement,
                          uint8_t origin,uint32_t *position) {
    fixture_vfs *s=(fixture_vfs *)user; host_file *h=(host_file *)file;
    if(!s || !h || !h->fp || !position || origin>2u) return 1u;
    int whence=origin==0u?SEEK_SET:(origin==1u?SEEK_CUR:SEEK_END);
    if(fseek(h->fp,(long)displacement,whence)!=0) return 1u;
    long current=ftell(h->fp);
    if(current<0) return 1u;
    *position=(uint32_t)current;
    if(guest_path_has_suffix(h->path,"data/text.dat")) {
        s->text_seeks++;
        fprintf(stderr,"TRACE text.dat seek[%u] displacement=%ld origin=%u result=%08x\n",
                s->text_seeks-1u,(long)displacement,origin,*position);
    }
    return 0u;
}
static uint16_t host_ioctl(void *user,void *file,uint16_t *info) {
    (void)user; if (!file || !info) return 6u; *info=0; return 0;
}

recomp_func_t recomp_lookup(uint32_t va) {
    /* The bounded, live-verified _Unsmack table at LE 0x10C950 selects one
       of these four original helpers after its index is masked to 0..3.
       The generated closure's runtime guard validates the exact entry value. */
    if (va==0x002D7CF0u || va==0x000ECCF0u) return gw_partial_SmackInternal010;
    if (va==0x002D8030u || va==0x000ED030u) return gw_partial_SmackInternal011;
    if (va==0x002D8840u || va==0x000ED840u) return gw_partial_SmackInternal012;
    if (va==0x002D8990u || va==0x000ED990u) return gw_partial_SmackInternal013;
    /* RADFREE reaches LbMemoryFree_ through the Smacker allocator slot at
       0x10C4E0. Its live value is guarded by the generated exact-callsite
       allowlist at 0xAE65C; expose the already lifted original routine to
       the common dispatcher in both LE and rebased object-1 coordinates. */
    if (va==0x00092030u || va==0x0027D030u) return gw_partial_LbMemoryFree;
    if (va==0x00098C18u) return gw_original_null_callback_98c18;
    if (va==0x000AF9E4u) return gw_partial_0x000AF9E4;
    if (va==0x000013620u) return gw_original_ifcoptions_plugin_adjustment_thunk;
    if (va==0x000013600u) return gw_original_ifcoptions_update_adjustment_thunk;
    if (va==0x0000135F0u) return gw_original_ifcoptions_draw_adjustment_thunk;
    if (va==0x000013610u) return gw_original_ifcoptions_pullout_adjustment_thunk;
    if (va==0x000013700u) return gw_original_ifctitle_update_adjustment_thunk;
    if (va==0x000013710u) return gw_original_ifctitle_pullout_adjustment_thunk;
    if (va==0x000013720u) return gw_original_ifctitle_return_plugin_adjustment_thunk;
    if (va==0x0000136F0u) return gw_original_ifctitle_draw_adjustment_thunk;
    if (va==0x0001B650u) return gw_partial_0x0001B650;
    if (va==0x0001B640u) return gw_partial_0x0001B640;
    if (va==0x0001B630u) return gw_partial_0x0001B630;
    if (va==0x0001B620u) return gw_partial_0x0001B620;
    if (va==0x00015710u) return gw_partial_W_PlugIn_IFCLevel_n_v;
    if (va==0x00015CF0u) return gw_partial_W_PullOut_IFCLevel_n_v;
    if (va==0x000177C0u) return gw_partial_W_Draw_IFCLevel_n_v;
    if (va==0x000179F0u) return gw_partial_W_Update_IFCLevel_n_v;
    if (va==0x000070EB0u) return gw_partial_0x00070EB0;
    if (va==0x000070D10u) return gw_partial_W_PlugIn_IFCTitle_n_v;
    if (va==0x000070E30u) return gw_partial_W_PullOut_IFCTitle_n_v;
    if (va==0x0006A3D0u) return gw_partial_0x0006A3D0;
    if (va==0x0006AB30u) return gw_partial_0x0006AB30;
    if (va==0x0006A700u) return gw_partial_0x0006A700;
    if (va==0x0006A600u) return gw_partial_0x0006A600;
    if (va==0x0000710B0u) return gw_partial_0x000710B0;
    if (va==0x0002C3D0u) return gw_partial_0x0002C3D0;
    if (va==0x0002C520u) return gw_partial_0x0002C520;
    if (va==0x0002C560u) return gw_partial_0x0002C560;
    if (va==0x00034F50u) return gw_partial_0x00034F50;
    if (va==0x000834A0u) return gw_partial_0x000834A0;
    if (va==0x000957B0u) return gw_partial_0x000957B0;
    if (va==0x00069C80u) return gw_partial_0x00069C80;
    if (va==0x000957C0u) return gw_partial_0x000957C0;
    if (va==0x000957E0u) return gw_partial_0x000957E0;
    if (va==0x000957D0u) return gw_partial_0x000957D0;
    if (va==0x00095830u) return gw_partial_0x00095830;
    if (va==0x00095880u) return gw_partial_0x00095880;
    if (va==0x00095890u) return gw_partial_0x00095890;
    if (va==0x000958E0u) return gw_partial_0x000958E0;
    if (va==0x00092670u) { comparator_calls++; return gw_partial_0x00092670; }
    if (va==0x00091E00u) return gw_partial_LbMemoryAlloc;
    if (va==0x00091E90u) return gw_partial_LbMemoryAllocLow;
    /* Original 0x96B23 stores the object-1-relocated address 0x281B10 in
     * ECX; the code-range map resolves that guest pointer back to this LE VA. */
    if (va==0x00096B10u) return gw_partial_mem_putc;
    if (va==0x000BA9FEu) return gw_partial_file_putc;
    if (va==0x00014BB0u || va==0x001FFBB0u) return gw_partial_0x00014BB0;
    if ((va==0x000D23A7u || va==0x002BD3A7u) && guest_memory &&
        guest_memory[0x002BD3A7u]==0xCDu && guest_memory[0x002BD3A8u]==0x31u &&
        guest_memory[0x002BD3A9u]==0xC3u) return original_int31_thunk;
    recomp_func_t partial = gw_partial_lookup_guest(va);
    if (partial) return partial;
    return NULL;
}
recomp_func_t recomp_lookup_manual(uint32_t va) {
    /* Exact object-1 callbacks admitted from the canonical LE SRC_OFFSET32
       fixups at object-3 slot 0x10C830 and D71E0 immediate 0xD71E1. */
    if (va==0x000D71E0u || va==0x002C21E0u) return recomp_gw_partial_0x000D71E0;
    if (va==0x000D7230u || va==0x002C2230u) return recomp_gw_partial_0x000D7230;
    if (va==0x002BD344u) return recomp_gw_partial_0x000D2344;
    if (va==0x002BD3A7u) return recomp_gw_partial_0x000D23A7;
    if (va==0x002BD3ADu) return recomp_gw_partial_0x000D23AD;
    /* __InitRtns dispatches only this finite, fixup-verified original LE
     * table. Keep its 19 targets available to the same indirect dispatcher. */
    if (va==0x0001C440u) return gw_partial_0x0001C440;
    if (va==0x000830F0u) return gw_partial_0x000830F0;
    if (va==0x000BAAC2u) return gw_partial_delay_init;
    if (va==0x000BBE29u) return gw_partial_setEFGfmt;
    if (va==0x000A38DCu) return gw_partial_j___sys_init_387_emulator;
    if (va==0x000BC0E3u) return gw_partial_chk8087;
    if (va==0x000BC19Fu) return gw_partial_clock_init;
    if (va==0x000AC3B4u) return gw_partial_0x000AC3B4;
    if (va==0x000C87B6u) return gw_partial_Init_Argv;
    if (va==0x000D1FBCu) return gw_partial_InitFiles;
    if (va==0x000BC1F6u) return gw_partial_W_init_n_v;
    if (va==0x000BC65Du) return gw_partial_checkIsDBCS;
    if (va==0x000C3584u) return gw_partial_W_init_n_v_0;
    if (va==0x000C3882u) return gw_partial_W_init_n_v_1;
    if (va==0x000D21EEu) return gw_partial_0x000D21EE;
    if (va==0x000D5DB5u) return gw_partial_init;
    if (va==0x000DFDC1u) return gw_partial_setenvp;
    if (va==0x000DCED5u) return gw_partial_W_longjmpInit_n_v;
    if (va==0x000E165Eu) return gw_partial_verify_pentium_fdiv_bug;
    return recomp_lookup(va);
}
recomp_func_t recomp_lookup_import(uint32_t va) { (void)va; return NULL; }

static void original_int31_thunk(void) {
    if (gw_interrupt_dispatch(0x31u,0x000D23A7u)!=GW_INTERRUPT_HANDLED) return;
    if (*(const uint32_t *)(guest_memory+g_esp)!=RECOMP_RETADDR) return;
    g_esp+=4u;
}
static const char *dos_handle_path(uint32_t dos_handle) {
    for(uint32_t i=0;i<GW_DOS_MAX_OPEN_FILES;i++) {
        gw_dos_file_handle *entry=&vfs.dos.files[i];
        if(entry->active && entry->dos_handle==(uint8_t)dos_handle) {
            host_file *hf=(host_file *)entry->file;
            return hf?hf->path:"<no-host-file>";
        }
    }
    return "<unknown-handle>";
}
static void trace_pl1_read_callstack(uint32_t instruction_va) {
    uint64_t linear=(uint64_t)g_ss_base+g_esp;
    fprintf(stderr,"TRACE pl1 read_ entry eip=%08x func=%08x AX=%08x BX=%08x CX=%08x DX=%08x SI=%08x DI=%08x BP=%08x SP=%08x SS=%04x SS_BASE=%08x DS=%04x DS_BASE=%08x CF=%u EFLAGS=%08x host_path='%s'\n",
        instruction_va,g_cur_func,g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,
        g_seg_ss,g_ss_base,g_seg_ds,g_ds_base,(unsigned)(g_flag_cf&1u),
        recomp_eflags(g_flag_k,g_flag_a,g_flag_b,g_flag_cf,1u),dos_handle_path(g_ebx));
    if(linear<GUEST_LIMIT) {
        uint32_t n=(uint32_t)((GUEST_LIMIT-linear)/4u); if(n>16u)n=16u;
        fprintf(stderr,"TRACE pl1 stack_words linear=%08x count=%u",(uint32_t)linear,n);
        for(uint32_t i=0;i<n;i++) fprintf(stderr," %08x",*(const uint32_t *)(guest_memory+(uint32_t)linear+i*4u));
        fputc('\n',stderr);
    }
    uint32_t frame=g_ebp;
    for(uint32_t depth=0;depth<12u;depth++) {
        uint64_t at=(uint64_t)g_ss_base+frame;
        if(!frame || at+8u>GUEST_LIMIT) break;
        uint32_t previous=*(const uint32_t *)(guest_memory+(uint32_t)at);
        uint32_t ret=*(const uint32_t *)(guest_memory+(uint32_t)at+4u);
        uint32_t ret_link=0; int mapped=recomp_code_linear_to_link(ret,&ret_link);
        fprintf(stderr,"TRACE pl1 guest_frame depth=%u ebp=%08x linear=%08llx saved_ebp=%08x return_guest=%08x return_link=%08x mapped=%u args=%08x/%08x/%08x/%08x\n",
            depth,frame,(unsigned long long)at,previous,ret,ret_link,(unsigned)mapped,
            *(const uint32_t *)(guest_memory+(uint32_t)at+8u),
            *(const uint32_t *)(guest_memory+(uint32_t)at+12u),
            *(const uint32_t *)(guest_memory+(uint32_t)at+16u),
            *(const uint32_t *)(guest_memory+(uint32_t)at+20u));
        if(previous<=frame || previous-frame>0x00100000u) break;
        frame=previous;
    }
    /* Generated CALLs cross C dispatcher frames rather than retaining a
       native guest return chain. The lifter's 32-entry ring is the authoritative
       logical caller history at this DOS read boundary. */
    gw_recomp_trace_checkpoint(instruction_va,g_cur_func);
}
static gw_interrupt_result dispatch(uint8_t vector,uint32_t instruction_va,void *user) {
    uint32_t request_eax=g_eax,request_ebx=g_ebx,request_ecx=g_ecx,request_edx=g_edx;
    uint32_t request_esi=g_esi,request_edi=g_edi,request_ds=g_seg_ds,request_es=g_seg_es;
    if(vector==0x33u) {
        fprintf(stderr,"TRACE original INT33 request eip=%08x AX=%08x BX=%08x CX=%08x DX=%08x SI=%08x DI=%08x DS=%04x ES=%04x caller=%08x\n",
            instruction_va,g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_seg_ds,g_seg_es,g_cur_func);
        if((uint16_t)g_eax==0u) {
            /* Standard INT 33h reset/detect response for the explicitly
               configured two-button DOS mouse profile. Other functions stay
               unsupported and reach the existing interrupt trap. */
            g_eax=(g_eax&0xFFFF0000u)|0xFFFFu;
            g_ebx=(g_ebx&0xFFFF0000u)|2u;
            fprintf(stderr,"TRACE original INT33 response AX=%04x buttons=%u profile=experimental-two-button-mouse\n",
                (unsigned)(g_eax&0xFFFFu),(unsigned)(g_ebx&0xFFFFu));
            return GW_INTERRUPT_HANDLED;
        }
        if((uint16_t)g_eax==0x000Cu) {
            uint32_t es_base=0, callback_link=0;
            uint64_t callback_linear=0;
            int selector_ok=gw_dos_descriptor_base(g_seg_es,&es_base,&vfs.dos);
            /* The original Watcom client builds a 32-bit DPMI register frame
               and stores the relocated callback as a dword. Keep the full
               EDX value here; truncating to real-mode DX would discard the
               object's verified rebase and misidentify this code pointer. */
            if(selector_ok) callback_linear=(uint64_t)es_base+g_edx;
            int code_ok=selector_ok && callback_linear<=UINT32_MAX &&
                recomp_code_linear_to_link((uint32_t)callback_linear,&callback_link);
            /* LbMouseSetup_ at 0xA1AB4 constructs this exact original
               INT 33h/0Ch request: mask 0x007f, ES copied from CS, and
               callback W?MouseHandler256$f at link 0xA1E74. Admit this
               request only when the guest descriptor and code map prove
               that same target; all other callbacks remain fail-closed. */
            if((uint16_t)g_ecx==0x007Fu && g_seg_es==g_seg_cs && code_ok &&
               callback_link==0x000A1E74u && g_int33_user_callback_registrations==0u) {
                g_int33_user_callback_linear=(uint32_t)callback_linear;
                g_int33_user_callback_link=callback_link;
                g_int33_user_callback_mask=(uint16_t)g_ecx;
                g_int33_user_callback_registrations++;
                fprintf(stderr,"TRACE original INT33 register-user-handler eip=%08x mask=%04x ES=%04x ES_BASE=%08x DX=%08x linear=%08llx link=%08x callback=MouseHandler256 registrations=%u result=registered experimental-profile=no-events-dispatched\n",
                    instruction_va,(unsigned)(g_ecx&0xFFFFu),g_seg_es,es_base,
                    g_edx,(unsigned long long)callback_linear,callback_link,
                    g_int33_user_callback_registrations);
                return GW_INTERRUPT_HANDLED;
            }
            fprintf(stderr,"TRACE original INT33 unsupported-user-handler eip=%08x mask=%04x ES=%04x ES_BASE=%08x DX=%08x linear=%08llx mapped=%u link=%08x expected=000A1E74\n",
                instruction_va,(unsigned)(g_ecx&0xFFFFu),g_seg_es,es_base,g_edx,
                (unsigned long long)callback_linear,code_ok?1u:0u,callback_link);
        }
    }
    int trace_0501=vector==0x31u && (uint16_t)g_eax==0x0501u && g_dpmi_0501_trace_count<32u;
    int trace_set_real_vector=vector==0x31u && (uint16_t)g_eax==0x0201u;
    int trace_ah48=vector==0x21u && (uint8_t)(g_eax>>8)==0x48u;
    int trace_ah48_verbose=trace_ah48 && g_ah48_trace_rows<64u;
    if(trace_ah48_verbose) g_ah48_trace_rows++;
    int trace_ah49=vector==0x21u && instruction_va==0x000C3D46u &&
                   (uint8_t)(g_eax>>8)==0x49u;
    if (vector==0x10u) return gw_vbe_interrupt(vector,instruction_va,&vbe_device);
    int trace_setup_lock=vector==0x31u && instruction_va==0x000D23A7u &&
        ((uint16_t)g_eax==0x0600u || (uint16_t)g_eax==0x0100u ||
         (uint16_t)g_eax==0x0300u);
    int trace_simulate_rm=vector==0x31u && (uint16_t)g_eax==0x0300u;
    if(trace_simulate_rm) {
        uint32_t base=0; (void)gw_dos_descriptor_base(g_seg_es,&base,&vfs.dos);
        uint64_t linear=(uint64_t)base+g_edi;
        const gw_dos_real_mode_registers *rm=(linear+sizeof(*rm)<=GUEST_LIMIT)
            ?(const gw_dos_real_mode_registers *)(guest_memory+(uint32_t)linear):NULL;
        fprintf(stderr,"TRACE setup_game DPMI 0300 frame vector=%02x ES=%04x base=%08x EDI=%08x linear=%08llx frame=%s",
            (unsigned)(g_ebx&0xffu),g_seg_es,base,g_edi,(unsigned long long)linear,rm?"valid":"outside-guest");
        if(rm) fprintf(stderr," AX=%08x BX=%08x CX=%08x DX=%08x SI=%08x DI=%08x DS=%04x ES=%04x FLAGS=%04x",
            rm->eax,rm->ebx,rm->ecx,rm->edx,rm->esi,rm->edi,rm->ds,rm->es,rm->flags);
        fputc('\n',stderr);
        if((g_ebx&0xffu)==0x66u) {
            uint16_t seg=vfs.dos.dpmi_real_vector_segment[0x66u];
            uint16_t off=vfs.dos.dpmi_real_vector_offset[0x66u];
            uint32_t handler=(uint32_t)seg*16u+off;
            fprintf(stderr,"TRACE DPMI 0300 vector66 target=%04x:%04x linear=%08x frame_bytes=",
                seg,off,handler);
            if(rm) {
                const uint8_t *p=(const uint8_t *)rm;
                for(size_t i=0;i<sizeof(*rm);i++) fprintf(stderr,"%02x",p[i]);
            }
            fprintf(stderr," handler_bytes=");
            if((uint64_t)handler+128u<=GUEST_LIMIT) {
                for(uint32_t i=0;i<128u;i++) fprintf(stderr,"%02x",guest_memory[handler+i]);
            } else fprintf(stderr,"outside-guest");
            fprintf(stderr," driver_segment_bytes=");
            uint32_t driver_base=(uint32_t)seg*16u;
            if((uint64_t)driver_base+0x200u<=GUEST_LIMIT) {
                for(uint32_t i=0;i<0x200u;i++) fprintf(stderr,"%02x",guest_memory[driver_base+i]);
            } else fprintf(stderr,"outside-guest");
            fputc('\n',stderr);
        }
    }
    if(trace_setup_lock) fprintf(stderr,
        "TRACE setup_game DPMI entry site=%08x AX=%04x EBX=%08x ECX=%08x ESI=%08x EDI=%08x user=%p memory=%08x\n",
        instruction_va,(unsigned)(g_eax&0xffffu),g_ebx,g_ecx,g_esi,g_edi,user,
        vfs.dos.guest_memory_size);
    int trace_smacker_dos_read=vector==0x21u && instruction_va==0x000D72EDu &&
        (uint8_t)(g_eax>>8)==0x3fu && g_smacker_dos_read_trace_count<16u;
    if(trace_smacker_dos_read) {
        gw_dos_file_handle *entry=NULL;
        for(uint32_t i=0;i<GW_DOS_MAX_OPEN_FILES;i++)
            if(vfs.dos.files[i].active && vfs.dos.files[i].dos_handle==(uint8_t)g_ebx) {
                entry=&vfs.dos.files[i]; break;
            }
        host_file *hf=entry?(host_file *)entry->file:NULL;
        fprintf(stderr,"TRACE Smacker DOS read request n=%u AX=%08x handle=%u CX=%08x DS=%04x DX=%08x buffer_linear=%08x file_active=%u file_access=%u file_path='%s' file_offset=%08lx\n",
            g_smacker_dos_read_trace_count,g_eax,(unsigned)(g_ebx&0xffffu),g_ecx,
            g_seg_ds,g_edx,(uint32_t)((uint64_t)g_ds_base+g_edx),entry?1u:0u,
            entry?(unsigned)entry->access_mode:0u,hf?hf->path:"",
            hf&&hf->fp?ftell(hf->fp):-1L);
        g_smacker_dos_read_trace_count++;
    }
    if(trace_0501) {
        fprintf(stderr,"TRACE CRT DPMI 0501 request n=%u eip=%08x eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x cursor=%08x..%08x\n",
                g_dpmi_0501_trace_count,instruction_va,g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,
                vfs.dos.allocation_cursor,vfs.dos.allocation_end);
        g_dpmi_0501_trace_count++;
    }
    if(trace_set_real_vector) fprintf(stderr,
        "TRACE setup_game DPMI AX0201 set-real-vector entry eip=%08x vector=%02x CX_segment=%04x DX_offset=%04x DS=%04x ES=%04x\n",
        instruction_va,(unsigned)(g_ebx&0xffu),(unsigned)(g_ecx&0xffffu),
        (unsigned)(g_edx&0xffffu),g_seg_ds,g_seg_es);
    if (vector==0x21u && instruction_va==0x000BBEE6u) {
        g_watcom_f304_calls++;
        fprintf(stderr,"TRACE Watcom CRT extender INT21 frontier eip=%08x AX=%04x EAX=%08x EBX=%08x ECX=%08x EDX=%08x DS=%04x ES=%04x\n",
                instruction_va,(unsigned)(g_eax&0xFFFFu),g_eax,g_ebx,g_ecx,g_edx,g_seg_ds,g_seg_es);
    }
    if(trace_ah48_verbose) {
        uint32_t mcb_linear=((uint32_t)(vfs.dos.dos_segment_begin-1u))<<4;
        const uint8_t *mcb=(mcb_linear+5u<=GUEST_LIMIT)?guest_memory+mcb_linear:NULL;
        fprintf(stderr,"TRACE DOS AH48 request site=%08x eax=%08x ebx_paras=%04x mcb=%04x tag=%c owner=%04x size=%04x blocks=%u range=%04x..%04x\n",
            instruction_va,g_eax,(unsigned)(g_ebx&0xffffu),vfs.dos.dos_segment_begin-1u,
            mcb?(char)mcb[0]:'?',mcb?(unsigned)(mcb[1]|((uint16_t)mcb[2]<<8)):0,
            mcb?(unsigned)(mcb[3]|((uint16_t)mcb[4]<<8)):0,vfs.dos.dos_block_count,
            vfs.dos.dos_segment_begin,vfs.dos.dos_segment_end);
    }
    if(vector==0x21u && instruction_va==0x000D219Cu) {
        uint32_t linear=g_ds_base+g_edx;
        char sample[65]; unsigned n=0;
        while(n<64u && linear+n<GUEST_LIMIT && guest_memory[linear+n]) {
            unsigned char ch=guest_memory[linear+n];
            sample[n++]=(ch>=32u && ch<127u)?(char)ch:'.';
        }
        sample[n]=0;
        printf("TRACE original DOS AH=40 at D219C AX=%08x BX(handle)=%08x CX(bytes)=%08x DX=%08x DS=%04x base=%08x linear=%08x data=\"%s\"\\n",
               g_eax,g_ebx,g_ecx,g_edx,g_seg_ds,g_ds_base,linear,sample);
    }
    if (vector==0x21u && (uint8_t)(g_eax>>8)==0x3fu &&
        guest_path_has_suffix(vfs.last_path,"data/titlescr.dat") && vfs.title_screen_reads<4u) {
        unsigned i=vfs.title_screen_reads;
        vfs.title_dos_ax[i]=g_eax; vfs.title_dos_bx[i]=g_ebx;
        vfs.title_dos_cx[i]=g_ecx; vfs.title_dos_dx[i]=g_edx;
        fprintf(stderr,"TRACE titlescr DOS AH=3F[%u] AX=%08x BX=%08x CX=%08x DX=%08x\n",
                i,g_eax,g_ebx,g_ecx,g_edx);
    }
    if(trace_ah49) fprintf(stderr,"TRACE DOS AH49 request site=%08x eax=%08x ES=%04x ss=%04x esp=%08x\n",
        instruction_va,g_eax,g_seg_es,g_seg_ss,g_esp);
    if(trace_ah49 && g_rational_fallback_waiting_for_free)
        g_rational_blocks_before_free=vfs.dos.dos_block_count;
    if(vector==0x21u && (uint8_t)(request_eax>>8)==0x3Fu) {
        low_write_current_eip=instruction_va;
        const char *path=dos_handle_path(request_ebx);
        if(guest_path_has_suffix(path,"data/pl1.dat") && request_edx==0u)
            trace_pl1_read_callstack(instruction_va);
    }
    gw_interrupt_result r=gw_dos_services_callback(vector,instruction_va,user);
    if(vector==0x21u && (uint8_t)(request_eax>>8)==0x3Fu) low_write_current_eip=0u;
    if(low_write_capture_enabled && vector==0x31u &&
       (uint16_t)request_eax==0x0100u) {
        fprintf(stderr,"TRACE low DPMI AX0100 eip=%08x requested_paragraphs=%04x result=%u AX=%04x selector=%04x CF=%u active_blocks=%u\n",
            instruction_va,(unsigned)(request_ebx&0xffffu),(unsigned)r,
            (unsigned)(g_eax&0xffffu),(unsigned)(g_edx&0xffffu),
            (unsigned)(g_flag_cf&1u),vfs.dos.dos_block_count);
    } else if(low_write_capture_enabled && vector==0x31u &&
              (uint16_t)request_eax==0x0101u) {
        uint16_t selector=(uint16_t)request_edx; uint32_t segment=0,paras=0;
        for(uint32_t i=0;i<vfs.dos.dos_block_count;i++)
            if(vfs.dos.dos_blocks[i].selector==selector) {
                segment=vfs.dos.dos_blocks[i].segment;
                paras=vfs.dos.dos_blocks[i].paragraphs; break;
            }
        fprintf(stderr,"TRACE low DPMI AX0101 eip=%08x selector=%04x ledger_range=%08x..%08x paragraphs=%u result=%u AX=%04x CF=%u active_blocks=%u\n",
            instruction_va,selector,segment<<4,(segment+paras)<<4,paras,(unsigned)r,
            (unsigned)(g_eax&0xffffu),(unsigned)(g_flag_cf&1u),vfs.dos.dos_block_count);
    }
    if(trace_smacker_dos_read)
        fprintf(stderr,"TRACE Smacker DOS read response n=%u handled=%u AX=%08x CF=%u\n",
            g_smacker_dos_read_trace_count-1u,(unsigned)r,g_eax,(unsigned)(g_flag_cf&1u));
    if(trace_setup_lock) fprintf(stderr,
        "TRACE setup_game DPMI result=%u AX=%04x CF=%u\n",r,
        (unsigned)(g_eax&0xffffu),(unsigned)(g_flag_cf&1u));
    if(trace_set_real_vector) fprintf(stderr,
        "TRACE setup_game DPMI AX0201 set-real-vector result=%u AX=%04x CF=%u\n",
        r,(unsigned)(g_eax&0xffffu),(unsigned)(g_flag_cf&1u));
    if(vector==0x21u || vector==0x31u)
        gw_recomp_trace_interrupt(vector,instruction_va,g_cur_func,
            request_eax,request_ebx,request_ecx,request_edx,
            request_esi,request_edi,request_ds,request_es,
            g_eax,g_ebx,g_ecx,g_edx,g_flag_cf);
    if(trace_ah48) {
        if(trace_ah48_verbose) {
        fprintf(stderr,"TRACE DOS AH48 response site=%08x eax=%08x ebx=%08x cf=%u handled=%u blocks=%u\n",
            instruction_va,g_eax,g_ebx,g_flag_cf,r,vfs.dos.dos_block_count);
        }
        if (r==GW_INTERRUPT_TRAPPED) {
            trace_dos_mcb_chain("AH48_trapped",guest_memory);
            fprintf(stderr,"TRACE DOS AH48 backing guest=%p runtime=%p size=%08x\n",
                (void *)guest_memory,(void *)(uintptr_t)g_mem_base,vfs.dos.guest_memory_size);
            if ((const uint8_t *)(uintptr_t)g_mem_base!=guest_memory)
                trace_dos_mcb_chain("AH48_runtime_backing",(const uint8_t *)(uintptr_t)g_mem_base);
        }
        if(instruction_va==0x000C3D35u && (g_flag_cf&1u) &&
           (uint16_t)g_eax==8u) {
            uint16_t largest=dos_mcb_largest_free(guest_memory);
            if((uint16_t)g_ebx!=largest) {
                fprintf(stderr,"TRACE RATIONAL invalid AH48 largest response AX=%04x BX=%04x MCB_largest=%04x\n",
                    (unsigned)(g_eax&0xFFFFu),(unsigned)(g_ebx&0xFFFFu),largest);
            } else {
            g_rational_ah48_failures++;
            g_rational_fallback_waiting_for_free=1;
            fprintf(stderr,"TRACE RATIONAL ARM reason=AH48_failure site_link=%08x site_guest=%08x AX=%04x BX=%04x MCB_largest=%04x SS=%04x SS_BASE=%08x ESP=%08x\n",
                instruction_va,instruction_va+0x001EB000u,
                (unsigned)(g_eax&0xFFFFu),(unsigned)(g_ebx&0xFFFFu),largest,
                g_seg_ss,g_ss_base,g_esp);
            if(!g_rational_stack_capture_done) {
                g_rational_stack_capture_done=1;
                g_rational_stack_trace_armed=1;
                g_rational_stack_trace_rows=0;
                dump_rational_stack_ring();
            }
            }
        }
    }
    if(trace_ah49) fprintf(stderr,"TRACE DOS AH49 response site=%08x eax=%08x cf=%u handled=%u blocks=%u\n",
        instruction_va,g_eax,g_flag_cf,r,vfs.dos.dos_block_count);
    if(trace_ah49 && g_rational_fallback_waiting_for_free &&
       r==GW_INTERRUPT_HANDLED && !(g_flag_cf&1u)) {
        g_rational_ah49_frees++;
        g_rational_blocks_after_free=vfs.dos.dos_block_count;
        g_rational_fallback_waiting_for_free=0;
    }
    if(trace_0501) {
        fprintf(stderr,"TRACE CRT DPMI response eip=%08x eax=%08x ebx=%08x ecx=%08x esi=%08x edi=%08x cf=%u cursor=%08x result=%u\n",
                instruction_va,g_eax,g_ebx,g_ecx,g_esi,g_edi,g_flag_cf,vfs.dos.allocation_cursor,r);
        if (r==GW_INTERRUPT_HANDLED && !(g_flag_cf&1u)) {
            uint32_t base=((g_ebx&0xffffu)<<16)|(g_ecx&0xffffu);
            uint32_t handle=((g_esi&0xffffu)<<16)|(g_edi&0xffffu);
            for (uint32_t i=0;i<GW_DOS_MAX_LINEAR_ALLOCATIONS;i++) {
                const gw_dos_linear_allocation *a=&vfs.dos.linear_allocations[i];
                if (a->active && a->base==base && a->handle==handle) {
                    fprintf(stderr,"TRACE CRT DPMI live-ledger base=%08x size=%08x handle=%08x active=%u count=%u\n",
                            a->base,a->size,a->handle,a->active,vfs.dos.linear_allocation_count);
                    break;
                }
            }
        }
    }
    if(vector==0x21u && instruction_va==0x000D219Cu) {
        uint32_t linear=g_ds_base+g_edx;
        uint32_t requested=g_ecx;
        int contained=0;
        for(uint32_t i=0;i<GW_DOS_MAX_LINEAR_ALLOCATIONS;i++) {
            const gw_dos_linear_allocation *a=&vfs.dos.linear_allocations[i];
            if(a->active && linear>=a->base &&
               (uint64_t)linear+requested<=(uint64_t)a->base+a->size) {
                contained=1;
                fprintf(stderr,"TRACE DOS AH40 ledger base=%08x size=%08x handle=%08x active=%u buffer=%08x+%x contained=1\n",
                        a->base,a->size,a->handle,a->active,linear,requested);
                break;
            }
        }
        const uint16_t handle=(uint16_t)g_ebx;
        const uint8_t *captured=handle==1u?vfs.stdout_capture:vfs.stderr_capture;
        const uint32_t captured_size=handle==1u?vfs.stdout_capture_size:vfs.stderr_capture_size;
        printf("TRACE original DOS AH=40 result=%u AX=%08x CF=%u handled=%u handle=%u linear=%08x bytes=%u ledger_contained=%u captured=%u data=",
               r,g_eax,g_flag_cf,r,handle,linear,requested,contained,captured_size);
        for(uint32_t i=0;i<captured_size && i<16u;i++) printf("%02x",captured[i]);
        printf("\\n");
    }
    if (vector==0x21u && instruction_va==0x000D7144u) dos_ed_calls++;
    if (vector==0x21u && (instruction_va==0x000D715Du || instruction_va==0x000D7170u)) {
        dos_4a_calls++; if (g_flag_cf) dos_4a_failures++;
    }
    return r;
}

/* The Watcom CRT's original __checkIsDBCS_ asks DOS through DPMI AX=0300,
   INT 21h AX=6300. Reuse the Runtime's bounded provider and allocate its
   empty, terminated DBCS table from the configured DOS conventional pool. */
/* Original-driver bytes are not stored in this repository. Each region is
   identified by its length and SHA-256; it is checked against the user's own
   locally provided guest image. */
typedef struct { size_t length; const char *sha256_hex; } gw_hashed_region;
static int gw_region_sha256_matches(const uint8_t *data,const gw_hashed_region *expected) {
    BCRYPT_ALG_HANDLE algorithm=NULL; BCRYPT_HASH_HANDLE hash=NULL;
    uint8_t digest[32]; char hex[65]; int ok=0;
    if(!data || !expected || BCryptOpenAlgorithmProvider(&algorithm,BCRYPT_SHA256_ALGORITHM,NULL,0)<0) return 0;
    if(BCryptCreateHash(algorithm,&hash,NULL,0,NULL,0,0)>=0 &&
       BCryptHashData(hash,(PUCHAR)data,(ULONG)expected->length,0)>=0 &&
       BCryptFinishHash(hash,digest,(ULONG)sizeof(digest),0)>=0) {
        for(int i=0;i<32;i++) sprintf(hex+2*i,"%02x",digest[i]);
        ok=strcmp(hex,expected->sha256_hex)==0;
    }
    if(hash) BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm,0);
    return ok;
}
static uint16_t guest_u16_at(uint32_t address) {
    if(!guest_memory || address>GUEST_LIMIT || 2u>GUEST_LIMIT-address) return 0xffffu;
    return (uint16_t)(guest_memory[address]|((uint16_t)guest_memory[address+1u]<<8));
}
static int sb16_dig_parse_io_base(uint32_t base,uint16_t *io_base) {
    static const gw_hashed_region handler={87,"10f68dfe4b611c88ca37915a5b42d99d8936daa58587e4f63283ab7a91ea57bf"};
    static const gw_hashed_region parser={96,"476163c8c7c681e1d99e73530cc91fa2c4b88633817342ea66ce7881783246d8"};
    if(!guest_memory || !io_base || base>GUEST_LIMIT || GUEST_LIMIT-base<0x844u ||
       !gw_region_sha256_matches(guest_memory+base+0x07edu,&handler) ||
       !gw_region_sha256_matches(guest_memory+base+0x02a0u,&parser))
        return 0;
    /* Exact effects of SB16.DIG 07ED: fill its 24-byte scratch area, shift the
       configuration string right by one byte, prefix it with a space, then
       scan and parse the Axxx token through its verified 02A0 parser. */
    memset(guest_memory+base+0x16u,0xff,0x18u);
    for(int i=0xb8;i>=0x3a;i--) guest_memory[base+(uint32_t)i+1u]=guest_memory[base+(uint32_t)i];
    guest_memory[base+0x3au]=0x20u;
    uint16_t value=0xffffu; int found=0;
    for(uint32_t i=0;i<0x80u && guest_memory[base+0x3au+i];i++) {
        uint16_t token=(uint16_t)(guest_memory[base+0x3au+i] |
            ((uint16_t)guest_memory[base+0x3bu+i]<<8));
        if(token!=0x4120u && token!=0x6120u) continue;
        uint32_t p=base+0x3cu+i; uint32_t parsed=0; unsigned digits=0;
        while(p<base+0xbbu) {
            uint8_t c=guest_memory[p++];
            if(!c || c==' ') break;
            unsigned d;
            if(c>='0'&&c<='9') d=(unsigned)(c-'0');
            else if(c>='A'&&c<='F') d=(unsigned)(c-'A'+10);
            else if(c>='a'&&c<='f') d=(unsigned)(c-'a'+10);
            else { parsed=0xffffffffu; break; }
            if(parsed>0xffffu/16u) { parsed=0xffffffffu; break; }
            parsed=parsed*16u+d; digits++;
        }
        value=(digits && parsed<=0xffffu)?(uint16_t)parsed:0xffffu;
        guest_memory[base+0x16u]=(uint8_t)value;
        guest_memory[base+0x17u]=(uint8_t)(value>>8);
        found=1;
    }
    value=(uint16_t)(guest_memory[base+0x16u]|((uint16_t)guest_memory[base+0x17u]<<8));
    guest_memory[base+0x124u]=(uint8_t)value;
    guest_memory[base+0x125u]=(uint8_t)(value>>8);
    *io_base=value;
    return found && value!=0xffffu;
}
/* Narrow adapter for the exact first DPMI-simulated call made by the original
   SB16.DIG AIL3DIG handler. Its byte path was run independently as 16-bit
   x86 with Unicorn against the hash-verified installed driver. Keep every
   other vector/function fail-closed. */
static int startup_sb16_dig_ax0300(gw_dos_services *services,
                                   gw_dos_real_mode_registers *registers) {
    static const gw_hashed_region handler_prefix={40,"bb202b3aea8f7948c747e6d9be4268adead16260c56499d02be0b071cfd6da38"};
    static const gw_hashed_region init_entry_prefix={24,"5085d2cd7103bd3502a95d11a5df1851b194fdf6380419909246940314859d20"};
    const uint16_t driver_call=(uint16_t)(registers?registers->eax:0u);
    if(!services || !registers ||
       (uint16_t)registers->ebx!=0u || !services->guest_memory_configured ||
       !guest_memory || !g_mem_base) return 0;
    uint16_t segment=services->dpmi_real_vector_segment[0x66u];
    uint16_t offset=services->dpmi_real_vector_offset[0x66u];
    uint32_t base=(uint32_t)segment*16u;
    if(!segment || offset!=0x016au || base>services->guest_memory_size ||
       services->guest_memory_size-base<0x5a0u ||
       memcmp(guest_memory+base,"AIL3DIG",7u)!=0 ||
       guest_u16_at(base+0x010au)!=0x079du ||
       guest_u16_at(base+0x0032u)!=0u || guest_u16_at(base+0x0030u)!=0u ||
       !gw_region_sha256_matches(guest_memory+base+0x016au,&handler_prefix) ||
       !gw_region_sha256_matches(guest_memory+base+0x079du,&init_entry_prefix))
        return 0;
    if(driver_call==0x0304u) {
        /* Table entry 4 in this exact, hash-verified SB16.DIG is the hardware
           probe at offset 0x0844. Capstone confirms it initializes saved AX
           to zero, calls the DSP probe at 0x0623, and returns that zero via
           0x0992 when the probe fails (0x0855). This harness profile has no
           emulated Sound Blaster ports, so report the driver's documented
           detection failure in the real-mode frame. This is an explicit
           headless no-device profile; it is not an observed DOSBox result.
           Other AIL function numbers remain fail-closed. */
        static const gw_hashed_region detect_entry={17,"06d6763955516dbd5d8727c66ae3197412c53037cc95d6ef5f914f2d3db7e0c3"};
        if(guest_u16_at(base+0x0112u)!=0x0844u ||
           !gw_region_sha256_matches(guest_memory+base+0x0844u,&detect_entry))
            return 0;
        registers->eax&=0xffff0000u;
        fprintf(stderr,"TRACE native SB16.DIG INT66 AX0304 table[4]=0844 result_AX=0000 profile=headless-no-device basis=verified-driver-probe-failure\n");
        return 1;
    }
    if(driver_call==0x0303u) {
        uint16_t io_base=0xffffu;
        if(guest_u16_at(base+0x0110u)!=0x07edu ||
           !sb16_dig_parse_io_base(base,&io_base)) return 0;
        registers->eax=(registers->eax&0xffff0000u)|io_base;
        fprintf(stderr,"TRACE native SB16.DIG INT66 AX0303 executed-verified-entry seg=%04x handler=016a table[3]=07ed config=A220 result_AX=%04x contract=driver-byte-exact\n",
            segment,io_base);
        return 1;
    }
    if(driver_call!=0x0300u && driver_call!=0x0301u) return 0;
    if(driver_call==0x0301u) {
        /* The original SB16.DIG dispatch table's second entry is 0x07d1.
           Its exact bytes publish the driver's CS and two buffer offsets into
           the interrupt handler's register-save area. */
        static const gw_hashed_region query_entry={21,"d5b8b6ba2ab2617dc186abcde87df2b2918d50bb7a6327a0643970fc476992c6"};
        if(guest_u16_at(base+0x010cu)!=0x07d1u ||
           guest_u16_at(base+0x0030u)!=0u || guest_u16_at(base+0x0032u)!=0u ||
           !gw_region_sha256_matches(guest_memory+base+0x07d1u,&query_entry))
            return 0;
        const uint16_t offsets[]={0x0124u,0x0126u,0x0128u,0x012au,
                                  0x012cu,0x012eu};
        const uint16_t values[]={0x040cu,0x04fcu,segment,segment,
                                 (uint16_t)registers->esi,(uint16_t)registers->edi};
        for(size_t i=0;i<sizeof(offsets)/sizeof(offsets[0]);i++) {
            uint32_t at=base+offsets[i];
            guest_memory[at]=(uint8_t)values[i];
            guest_memory[at+1u]=(uint8_t)(values[i]>>8);
        }
        registers->eax=(registers->eax&0xffff0000u)|0x040cu;
        registers->ebx=(registers->ebx&0xffff0000u)|0x04fcu;
        registers->ecx=(registers->ecx&0xffff0000u)|segment;
        registers->edx=(registers->edx&0xffff0000u)|segment;
        fprintf(stderr,"TRACE native SB16.DIG INT66 AX0301 executed-verified-entry seg=%04x handler=016a table[1]=07d1 result_AX=040c BX=04fc CX=DX=%04x\n",
            segment,segment);
        return 1;
    }
    const uint16_t offsets[]={0x0124u,0x0126u,0x0128u,0x012au,0x012cu,0x012eu,
                              0x0504u,0x000eu,0x0014u,0x000cu,0x0010u,0x0012u,
                              0x002eu,0x058cu,0x058eu,0x0590u};
    const uint16_t values[]={0x0001u,(uint16_t)registers->ebx,
        (uint16_t)registers->ecx,(uint16_t)registers->edx,
        (uint16_t)registers->esi,(uint16_t)registers->edi,0xffffu,segment,
        segment,0x050eu,0x0003u,0x0506u,0xffffu,0x0064u,0u,0u};
    for(size_t i=0;i<sizeof(offsets)/sizeof(offsets[0]);i++) {
        uint32_t at=base+offsets[i];
        guest_memory[at]=(uint8_t)values[i];
        guest_memory[at+1u]=(uint8_t)(values[i]>>8);
    }
    registers->eax=(registers->eax&0xffff0000u)|1u;
    fprintf(stderr,"TRACE native SB16.DIG INT66 AX0300 executed-verified-entry seg=%04x handler=016a table[0]=079d result_AX=0001\n",
        segment);
    return 1;
}
static int startup_real_mode_interrupt(void *user,uint8_t vector,
                                       gw_dos_real_mode_registers *registers) {
    if (vector==0x10u)
        return gw_vbe_real_mode_interrupt(&vbe_device,vector,registers);
    if(vector==0x66u)
        return startup_sb16_dig_ax0300((gw_dos_services *)user,registers);
    /* Controlled, read-only MSCDEX profile from the locally verified GeneWars
       disc CUE. The Python preflight checks the CUE digest and derives these
       track values with runtime/dos_cdrom.py before this native replay. */
    if(vector==0x2fu && registers) {
        uint16_t ax=(uint16_t)registers->eax;
        if(ax==0x1500u && (uint16_t)registers->ebx==0u) {
            registers->ebx=(registers->ebx&0xffff0000u)|1u; /* one D: drive */
            registers->ecx=(registers->ecx&0xffff0000u)|3u; /* D is index 3 */
            return 1;
        }
        if(ax==0x150cu && (uint16_t)registers->ebx==0u) {
            registers->ebx=(registers->ebx&0xffff0000u)|0x0217u; /* MSCDEX 2.23 profile */
            return 1;
        }
        if(ax==0x1510u && (uint16_t)registers->ecx==3u) {
            uint64_t packet64=((uint64_t)registers->es<<4)+(uint16_t)registers->ebx;
            if(packet64>GUEST_LIMIT || GUEST_LIMIT-packet64<26u) {
                fprintf(stderr,"TRACE MSCDEX AX1510 rejected frame BX=%04x CX=%04x DS:DX=%04x:%04x ES:BX=%04x:%04x packet=%08llx reason=packet-outside-guest\n",
                    (unsigned)(uint16_t)registers->ebx,(unsigned)(uint16_t)registers->ecx,
                    (unsigned)registers->ds,(unsigned)(uint16_t)registers->edx,
                    (unsigned)registers->es,(unsigned)(uint16_t)registers->ebx,
                    (unsigned long long)packet64);
                return 0;
            }
            uint8_t *packet=guest_memory+(uint32_t)packet64;
            /* MSCDEX CD-audio STOP (DOS device request command 85h) and
               RESUME (88h) use the short 0Dh request packet. This device
               profile models the state transition only; it has no CDDA
               renderer. Preserve the last validated play range while
               paused so the original RESUME request can succeed. */
            if(packet[0]==0x0du && packet[1]==0u && packet[2]==0x85u) {
                packet[1]=0;                 /* drive unit 0 (D:) */
                packet[3]=0; packet[4]=1;    /* request complete, status 0100h */
                mscdex_audio_paused=mscdex_audio_playing &&
                    mscdex_audio_sector_count!=0u;
                mscdex_audio_playing=0;
                if(!mscdex_audio_paused) {
                    mscdex_audio_start_lba=0;
                    mscdex_audio_sector_count=0;
                }
                registers->flags=(uint16_t)(registers->flags&~1u);
                fprintf(stderr,"TRACE native MSCDEX INT2F AX=1510 CD_AUDIO_STOP packet=%08llx request_length=0d command=85 unit=0 request_status=0100 logical_paused=%d resume_range=%08x+%08x renderer=absent\n",
                    (unsigned long long)packet64,mscdex_audio_paused,
                    mscdex_audio_start_lba,mscdex_audio_sector_count);
                return 1;
            }
            if(packet[0]==0x0du && packet[1]==0u && packet[2]==0x88u) {
                if(mscdex_audio_paused && mscdex_audio_sector_count!=0u &&
                   (uint64_t)mscdex_audio_start_lba+mscdex_audio_sector_count<=UINT32_MAX) {
                    packet[1]=0;
                    packet[3]=0; packet[4]=1;
                    mscdex_audio_paused=0;
                    mscdex_audio_playing=1;
                    registers->flags=(uint16_t)(registers->flags&~1u);
                    fprintf(stderr,"TRACE native MSCDEX INT2F AX=1510 CD_AUDIO_RESUME packet=%08llx request_length=0d command=88 unit=0 request_status=0100 logical_state=playing HSG_start=%u sectors=%u renderer=absent\n",
                        (unsigned long long)packet64,mscdex_audio_start_lba,
                        mscdex_audio_sector_count);
                } else {
                    packet[3]=0x0c; packet[4]=0x80;
                    registers->flags=(uint16_t)(registers->flags|1u);
                    fprintf(stderr,"TRACE native MSCDEX INT2F AX=1510 CD_AUDIO_RESUME rejected packet=%08llx paused=%d playing=%d HSG_start=%u sectors=%u request_status=800c\n",
                        (unsigned long long)packet64,mscdex_audio_paused,
                        mscdex_audio_playing,mscdex_audio_start_lba,
                        mscdex_audio_sector_count);
                }
                return 1;
            }
            /* MSCDEX PLAY AUDIO (84h) uses a 16h-byte packet.  The CUE
               profile is derived and hash-checked by the Python preflight;
               accept only HSG ranges wholly inside its contiguous AUDIO
               tracks.  This records the requested playback state without
               pretending to render CDDA samples. */
            if(packet[0]==0x16u && packet[2]==0x84u) {
#if defined(MSCDEX_AUDIO_BEGIN) && defined(MSCDEX_AUDIO_END)
                uint32_t start=(uint32_t)packet[0x0e]|
                    ((uint32_t)packet[0x0f]<<8)|((uint32_t)packet[0x10]<<16)|
                    ((uint32_t)packet[0x11]<<24);
                uint32_t count=(uint32_t)packet[0x12]|
                    ((uint32_t)packet[0x13]<<8)|((uint32_t)packet[0x14]<<16)|
                    ((uint32_t)packet[0x15]<<24);
                uint64_t end=(uint64_t)start+(uint64_t)count;
                if(packet[1]!=0u || packet[0x0d]!=0u || count==0u ||
                   start<MSCDEX_AUDIO_BEGIN || end>MSCDEX_AUDIO_END ||
                   end>UINT32_MAX) {
                    fprintf(stderr,"TRACE MSCDEX AX1510 rejected PLAY_AUDIO unit=%u mode=%u start=%08x count=%08x CUE_audio=%08x..%08x\n",
                        packet[1],packet[0x0d],start,count,
                        (uint32_t)MSCDEX_AUDIO_BEGIN,(uint32_t)MSCDEX_AUDIO_END);
                    return 0;
                }
                packet[1]=0; packet[3]=0; packet[4]=1;
                mscdex_audio_start_lba=start;
                mscdex_audio_sector_count=count;
                mscdex_audio_playing=1;
                mscdex_audio_paused=0;
                registers->flags=(uint16_t)(registers->flags&~1u);
                fprintf(stderr,"TRACE native MSCDEX INT2F AX=1510 PLAY_AUDIO packet=%08llx HSG_start=%u sectors=%u CUE_audio=%u..%u logical_state=playing renderer=absent request_status=0100\n",
                    (unsigned long long)packet64,start,count,
                    (uint32_t)MSCDEX_AUDIO_BEGIN,(uint32_t)MSCDEX_AUDIO_END);
                return 1;
#else
                return 0;
#endif
            }
            fprintf(stderr,"TRACE MSCDEX AX1510 request frame AX=%04x BX=%04x CX=%04x DX=%04x SI=%04x DI=%04x DS=%04x ES=%04x packet=%08llx bytes=",
                ax,(unsigned)(uint16_t)registers->ebx,(unsigned)(uint16_t)registers->ecx,
                (unsigned)(uint16_t)registers->edx,(unsigned)(uint16_t)registers->esi,
                (unsigned)(uint16_t)registers->edi,(unsigned)registers->ds,(unsigned)registers->es,
                (unsigned long long)packet64);
            for(unsigned i=0;i<26u;i++) fprintf(stderr,"%02x",packet[i]);
            fputc('\n',stderr);
            if(packet[0]!=0x1au || (packet[2]!=0x03u && packet[2]!=0x0cu)) {
                fprintf(stderr,"TRACE MSCDEX AX1510 rejected request-header length=%02x reserved=%02x command=%02x\n",
                    packet[0],packet[1],packet[2]);
                if(packet[0]==0x1au && packet[2]==0x0cu) {
                    uint16_t off=(uint16_t)(packet[0x0e]|((uint16_t)packet[0x0f]<<8));
                    uint16_t seg=(uint16_t)(packet[0x10]|((uint16_t)packet[0x11]<<8));
                    uint64_t at=((uint64_t)seg<<4)+off;
                    fprintf(stderr,"TRACE MSCDEX AX1510 IOCTL-output-buffer ES:BX=%04x:%04x transfer=%04x:%04x linear=%08llx bytes=",
                        (unsigned)registers->es,(unsigned)(uint16_t)registers->ebx,seg,off,
                        (unsigned long long)at);
                    if(at<=GUEST_LIMIT && GUEST_LIMIT-at>=16u)
                        for(unsigned i=0;i<16u;i++) fprintf(stderr,"%02x",guest_memory[(uint32_t)at+i]);
                    else fputs("<outside-guest>",stderr);
                    fputc('\n',stderr);
                }
                return 0;
            }
            uint16_t transfer_off=(uint16_t)(packet[0x0e]|((uint16_t)packet[0x0f]<<8));
            uint16_t transfer_seg=(uint16_t)(packet[0x10]|((uint16_t)packet[0x11]<<8));
            uint16_t transfer_size=(uint16_t)(packet[0x12]|((uint16_t)packet[0x13]<<8));
            uint64_t transfer64=((uint64_t)transfer_seg<<4)+transfer_off;
            if(transfer64>GUEST_LIMIT || transfer_size>GUEST_LIMIT-transfer64 ||
               transfer_size>11u) {
                fprintf(stderr,"TRACE MSCDEX AX1510 rejected transfer offset=%04x segment=%04x size=%u linear=%08llx reason=transfer-range\n",
                    transfer_off,transfer_seg,transfer_size,(unsigned long long)transfer64);
                return 0;
            }
            uint8_t *transfer=guest_memory+(uint32_t)transfer64;
            if(packet[2]==0x0cu) {
                /* MSCDEX IOCTL OUTPUT command 0Ch. The original request in
                   this replay is function 03h: set four CD-audio channel
                   volumes. Parse the exact 9-byte buffer and preserve the
                   requested mixer state; no disc bytes or playback are
                   fabricated. */
                if(transfer_size!=9u || transfer[0]!=0x03u) {
                    fprintf(stderr,"TRACE MSCDEX IOCTL OUTPUT rejected function=%02x size=%u\n",
                        transfer[0],transfer_size);
                    return 0;
                }
                for(unsigned channel=0;channel<4u;channel++) {
                    uint16_t word=(uint16_t)(transfer[1u+channel*2u]|
                        ((uint16_t)transfer[2u+channel*2u]<<8));
                    if((uint8_t)word!=channel) return 0;
                    mscdex_audio_volume[channel]=(uint8_t)(word>>8);
                }
                mscdex_audio_volume_updates++;
                packet[1]=0; packet[3]=0; packet[4]=1;
                registers->flags=(uint16_t)(registers->flags&~1u);
                fprintf(stderr,"TRACE native MSCDEX INT2F AX=1510 IOCTL_OUTPUT function=03 channels=%u/%u/%u/%u request_status=0100 profile=CUE-backed-device\n",
                    mscdex_audio_volume[0],mscdex_audio_volume[1],
                    mscdex_audio_volume[2],mscdex_audio_volume[3]);
                return 1;
            }
            uint8_t out[11]={0};
            if(transfer_size) memcpy(out,transfer,transfer_size);
            switch(transfer[0]) {
            case 0x0a: /* Disc-info derived from the verified CUE lead-out. */
                if(transfer_size!=7u) return 0;
                out[1]=1; out[2]=5; out[3]=60; out[4]=38; out[5]=59; out[6]=0;
                break;
            case 0x0b: { /* Track start/type derived from CUE track files. */
                static const uint8_t track_info[5][5]={
                    {1,0,2,0,0x40},{2,26,38,22,0},{3,3,45,31,0},
                    {4,2,38,41,0},{5,42,52,54,0}};
                if(transfer_size!=7u || transfer[1]<1u || transfer[1]>5u) return 0;
                const uint8_t *t=track_info[transfer[1]-1u];
                out[2]=t[1]; out[3]=t[2]; out[4]=t[3]; out[5]=0; out[6]=t[4];
                break;
            }
            case 0x0c: /* Initial idle subchannel is at track 1 INDEX 01. */
                if(transfer_size!=11u) return 0;
                out[1]=0x40; out[2]=1; out[3]=1;
                out[4]=0; out[5]=0; out[6]=0; out[7]=0;
                out[8]=0; out[9]=2; out[10]=0;
                break;
            case 0x04: /* Default audio routing: all channels muted. */
                if(transfer_size!=9u) return 0;
                memset(out+1,0,8u);
                break;
            default:
                fprintf(stderr,"TRACE MSCDEX AX1510 rejected command=%02x transfer_size=%u transfer_linear=%08llx reason=unimplemented-command\n",
                    transfer[0],transfer_size,(unsigned long long)transfer64);
                return 0;
            }
            memcpy(transfer,out,transfer_size);
            packet[1]=0; packet[3]=0; packet[4]=1; /* unit 0, request complete */
            registers->flags=(uint16_t)(registers->flags&~1u);
            fprintf(stderr,"TRACE native MSCDEX INT2F AX=1510 CUE request=%02x packet=%08llx transfer=%08llx bytes=%u\n",
                transfer[0],(unsigned long long)packet64,(unsigned long long)transfer64,transfer_size);
            return 1;
        }
        return 0;
    }
    if (vector!=0x21u || !registers || (uint16_t)registers->eax!=0x6300u)
        return 0;
    if (!vfs.dos.dbcs_table_configured) {
        uint32_t saved_eax=g_eax,saved_ebx=g_ebx,saved_ecx=g_ecx,saved_edx=g_edx;
        uint32_t saved_esi=g_esi,saved_edi=g_edi,saved_ebp=g_ebp,saved_esp=g_esp;
        uint32_t saved_cf=g_flag_cf;
        g_eax=0x0100u; g_ebx=1u; g_edx=0u; g_flag_cf=0u;
        gw_interrupt_result allocated=gw_dos_services_callback(0x31u,0u,&vfs.dos);
        uint16_t segment=(uint16_t)g_eax,selector=(uint16_t)g_edx;
        uint32_t linear=(uint32_t)segment<<4;
        static const uint8_t empty_dbcs_table[12]={0};
        int configured=allocated==GW_INTERRUPT_HANDLED && !g_flag_cf && segment && selector &&
            gw_dos_dbcs_table_configure(&vfs.dos,linear,empty_dbcs_table,
                                        (uint16_t)sizeof empty_dbcs_table);
        g_eax=saved_eax; g_ebx=saved_ebx; g_ecx=saved_ecx; g_edx=saved_edx;
        g_esi=saved_esi; g_edi=saved_edi; g_ebp=saved_ebp; g_esp=saved_esp;
        g_flag_cf=saved_cf;
        if(!configured) return 0;
        fprintf(stderr,"TRACE CRT DPMI AX=0100 DBCS-table segment=%04x selector=%04x linear=%08x bytes=12 contents=empty\n",
                segment,selector,linear);
    }
    return gw_dos_services_real_mode_interrupt(&vfs.dos,vector,registers);
}

static int vga_palette_io(unsigned int operation,unsigned int port,unsigned int width,
                          unsigned int value,unsigned int guest_va,
                          unsigned int *value_out,void *user) {
    (void)guest_va; (void)user;
    if (width!=1u) return 0;
    /* The bounded setup profile presents the VGA vertical-retrace interval
       as active. This is host emulation, not a claim about an Oracle timing
       sample; the guest's original wait routine still performs the IN/test. */
    if (operation==0u && port==0x3DAu && value_out) {
        *value_out=0x08u; vga_retrace_status_reads++; return 1;
    }
    /* VGA DAC port contract: 3C7 selects the read index, 3C8 selects the
       write index, and 3C9 streams three 6-bit components per palette entry.
       The read stream is backed by values previously written by the original
       palette loader into this emulated VGA device. */
    if (operation==1u && port==0x3C7u && value<=255u) {
        vga_dac_read_index=(uint8_t)value; vga_dac_read_component=0;
        vga_dac_read_index_writes++; return 1;
    }
    if (operation==0u && port==0x3C9u && value_out &&
        vga_dac_read_index<256u && vga_dac_read_component<3u) {
        *value_out=vga_dac[(uint32_t)vga_dac_read_index*3u+vga_dac_read_component++];
        vga_dac_component_reads++;
        if (vga_dac_read_component==3u) { vga_dac_read_component=0; vga_dac_read_index++; }
        return 1;
    }
    if (operation!=1u) return 0;
    if (port==0x3C6u) return 1;
    if (port==0x3C8u && value<=255u) {
        vga_dac_index=(uint8_t)value; vga_dac_component=0; vga_dac_index_writes++; return 1;
    }
    if (port==0x3C9u && vga_dac_index<256u && vga_dac_component<3u) {
        vga_dac[(uint32_t)vga_dac_index*3u+vga_dac_component++]=(uint8_t)(value&0x3Fu);
        vga_dac_component_writes++;
        if (vga_dac_component==3u) { vga_dac_component=0; vga_dac_index++; }
        return 1;
    }
    return 0;
}

static int invoke_screen_setup(uint8_t *memory) {
    gw_recomp_context c; memset(&c,0,sizeof c);
    c.eax=13u; c.ebx=480u; c.ecx=0x00390000u; c.edx=640u;
    c.esp=STACK_TOP; c.eip=0x962F0u; c.cs=0x0Cu; c.ds=0x14u; c.es=0x14u; c.ss=0x14u;
    *(uint32_t *)(memory+STACK_TOP)=RECOMP_RETADDR;
    c.mem_base=(ptrdiff_t)(uintptr_t)memory; c.mem_guest_base=0; c.mem_size=GUEST_LIMIT;
    c.pit_initialized=1;
    if (gw_recomp_invoke(gw_partial_LbScreenSetup,&c)!=GW_RECOMP_OK ||
        c.eax!=1u || c.interrupt_trap_pending || c.segment_fault_pending ||
        c.memory_fault.pending || c.port_io_trap.pending) {
        fprintf(stderr,"original LbScreenSetup failed eax=%08x eip=%08x int=%u/%08x mem=%u/%08x port=%x\n",
            c.eax,c.eip,c.interrupt_trap_pending,c.interrupt_instruction_va,
            c.memory_fault.pending,c.memory_fault.linear,c.port_io_trap.port);
        return 0;
    }
    return *(uint32_t *)(memory+0x00376A78u)==640u &&
           *(uint32_t *)(memory+0x00376A7Cu)==480u;
}

static int invoke(void (*fn)(void),gw_recomp_context *c,uint32_t entry,
                  uint8_t *memory,uint32_t eax,uint32_t edx) {
    memset(c,0,sizeof *c); c->eip=entry; c->cur_func=entry; c->eax=eax; c->edx=edx;
    c->esp=STACK_TOP; c->cs=0x0Cu; c->ds=0x14u; c->es=0x14u; c->ss=0x14u;
    c->mem_base=(ptrdiff_t)(uintptr_t)memory; c->mem_guest_base=0; c->mem_size=GUEST_LIMIT;
    c->pit_initialized=1; c->fpu_cw=0x127Fu; *(uint32_t *)(memory+STACK_TOP)=RECOMP_RETADDR;
    gw_recomp_status status=gw_recomp_invoke(fn,c);
    int ok=status==GW_RECOMP_OK && !c->memory_fault.pending &&
           !c->segment_fault_pending && !c->interrupt_trap_pending && !c->port_io_trap.pending;
    if(!ok && (entry==0x92819u || entry==0x5AF12u)) {
        uint32_t stack_floor=read_guest_u32(0x002F6770u);
        fprintf(stderr,"TRACE invoke failure entry=%08x status=%u eip=%08x cur=%08x eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x ebp=%08x esp=%08x stack_floor_10b770=%08x stack_remaining=%08x flags=%08x/%08x/%08x mem=%u:%08x seg=%u:%04x:%08x int=%u:%02x:%08x port=%u:%u:%08x\n",
                entry,status,c->eip,c->cur_func,c->eax,c->ebx,c->ecx,c->edx,
                c->esi,c->edi,c->ebp,c->esp,stack_floor,c->esp-stack_floor,c->flag_cf,c->flag_k,c->flag_a,
                c->memory_fault.pending,c->memory_fault.linear,c->segment_fault_pending,
                c->segment_fault_selector,c->segment_fault_instruction_va,
                c->interrupt_trap_pending,c->interrupt_vector,c->interrupt_instruction_va,c->port_io_trap.pending,
                c->port_io_trap.reason,c->port_io_trap.value);
        for(unsigned i=0;i<6u;i++) {
            uint32_t at=c->esp+4u*i;
            fprintf(stderr,"TRACE invoke stack[%u] guest=%08x value=%08x\n",i,at,
                at<=GUEST_LIMIT && 4u<=GUEST_LIMIT-at?read_guest_u32(at):0xFFFFFFFFu);
        }
        uint32_t first=g_icall_count>8u?g_icall_count-8u:0u;
        for(uint32_t i=first;i<g_icall_count;i++) {
            uint32_t slot=i&(ICALL_TRACE_SIZE-1u);
            fprintf(stderr,"TRACE invoke icall[%u] from=%08x target=%08x\n",i,
                g_icall_from[slot],g_icall_trace[slot]);
        }
    }
    return ok;
}

/* SDL events terminate at the existing lbDisplay device boundary. The
   original setup_controller and IFCTitle::Update do all game-state work. */
static int push_sdl_motion(int host_x,int host_y) {
    SDL_Event ev; memset(&ev,0,sizeof ev); ev.type=SDL_MOUSEMOTION;
    ev.motion.x=host_x; ev.motion.y=host_y; return SDL_PushEvent(&ev)==1;
}
static int push_sdl_button(uint32_t type,int host_x,int host_y) {
    SDL_Event ev; memset(&ev,0,sizeof ev); ev.type=type;
    ev.button.button=SDL_BUTTON_LEFT;
    ev.button.state=type==SDL_MOUSEBUTTONDOWN?SDL_PRESSED:SDL_RELEASED;
    ev.button.x=host_x; ev.button.y=host_y; return SDL_PushEvent(&ev)==1;
}
static int push_sdl_key(uint32_t type,SDL_Keycode key) {
    SDL_Event ev; memset(&ev,0,sizeof ev); ev.type=type;
    ev.key.state=type==SDL_KEYDOWN?SDL_PRESSED:SDL_RELEASED;
    ev.key.repeat=0; ev.key.keysym.sym=key; return SDL_PushEvent(&ev)==1;
}
static uint8_t lbinkey_scan_code(SDL_Keycode key) {
    /* MAP names 0x19CBF0 as lbInkey; IFCLevel::Update compares DOS scan
       codes 01h (Esc), 1Ch (Enter), and 1Fh (S) at its original entry. */
    if(key==SDLK_ESCAPE) return 0x01u;
    if(key==SDLK_RETURN || key==SDLK_KP_ENTER) return 0x1Cu;
    if(key==SDLK_s) return 0x1Fu;
    return 0u;
}
static unsigned poll_sdl_into_lbdisplay(uint8_t *memory) {
    SDL_Event ev; unsigned n=0;
    while(SDL_PollEvent(&ev)) {
        if(ev.type==SDL_MOUSEMOTION || ev.type==SDL_MOUSEBUTTONDOWN || ev.type==SDL_MOUSEBUTTONUP) {
            int hx=ev.type==SDL_MOUSEMOTION?ev.motion.x:ev.button.x;
            int hy=ev.type==SDL_MOUSEMOTION?ev.motion.y:ev.button.y;
            int x=hx/2,y=hy/2; /* 1280x960 host window to 640x480 logical screen */
            if(x<0)x=0; if(x>639)x=639; if(y<0)y=0; if(y>479)y=479;
            *(int32_t *)(memory+0x00376AA8u)=x; /* lbDisplay.MMouseX */
            *(int32_t *)(memory+0x00376AACu)=y; /* lbDisplay.MMouseY */
            if(ev.type==SDL_MOUSEBUTTONDOWN && ev.button.button==SDL_BUTTON_LEFT) {
                memory[0x00376ABFu]=1; /* lbDisplay.LeftButton event edge */
                memory[0x00376AC2u]=1; /* lbDisplay.MLeftButton held state */
            } else if(ev.type==SDL_MOUSEBUTTONUP && ev.button.button==SDL_BUTTON_LEFT) {
                memory[0x00376ABFu]=0; memory[0x00376AC2u]=0;
            }
            n++;
        } else if((ev.type==SDL_KEYDOWN || ev.type==SDL_KEYUP) && !ev.key.repeat) {
            uint8_t scan=lbinkey_scan_code(ev.key.keysym.sym);
            if(scan) {
                const uint32_t lbinkey_guest=0x00376BF0u; /* MAP 0x19CBF0 translated to guest linear */
                if(ev.type==SDL_KEYDOWN) memory[lbinkey_guest]=scan;
                else if(memory[lbinkey_guest]==scan) memory[lbinkey_guest]=0u;
                n++;
            }
        }
    }
    return n;
}
static int original_ui_cycle(uint8_t *memory,const char *label,unsigned events) {
    uint32_t gadgets=*(uint32_t *)(memory+0x00379490u), option=gadgets+2u*40u;
    gw_recomp_context input_ctx,update_ctx;
    printf("TRACE SDL device boundary cycle=%s lbDisplay.MMouse=%d,%d LeftButton=%u MLeftButton=%u\n",
        label,*(int32_t *)(memory+0x00376AA8u),*(int32_t *)(memory+0x00376AACu),
        memory[0x00376ABFu],memory[0x00376AC2u]);
    if(!invoke(gw_original_setup_controller_entry,&input_ctx,0x5B170u,memory,0,0)) {
        fprintf(stderr,"original setup_controller failed during %s eip=%08x fault=%u\n",label,input_ctx.eip,input_ctx.memory_fault.pending); return 0;
    }
    int16_t x=*(int16_t *)(memory+0x002F1465u),y=*(int16_t *)(memory+0x002F1467u);
    uint8_t state=memory[0x002F1469u],f0=memory[0x002F146Du],f1=memory[0x002F146Eu];
    uint8_t pressed=memory[option+38u],draw=memory[option+39u];
    uint32_t before=*(uint32_t *)(memory+0x002EF816u);
    uint32_t transition_fn_before=*(uint32_t *)(memory+0x002EF7ECu);
    uint32_t transition_obj_before=*(uint32_t *)(memory+0x002EF7F0u);
    if(!invoke(gw_original_control_game_update_dispatch,&update_ctx,0x5AF12u,memory,0,0)) {
        fprintf(stderr,"original IFCTitle::Update failed during %s eip=%08x fault=%u\n",label,update_ctx.eip,update_ctx.memory_fault.pending); return 0;
    }
    printf("TRACE SDL input cycle=%s events=%u game_xy=%d,%d state=%02x flags=%02x/%02x OPCIONES_pressed=%u->%u draw=%u->%u selected=%08x result=%08x->%08x transition=%08x/%08x->%08x/%08x eip=%08x\n",
        label,events,x,y,state,f0,f1,pressed,memory[option+38u],draw,memory[option+39u],
        *(uint32_t *)(memory+0x00379494u),before,*(uint32_t *)(memory+0x002EF816u),
        transition_fn_before,transition_obj_before,*(uint32_t *)(memory+0x002EF7ECu),
        *(uint32_t *)(memory+0x002EF7F0u),update_ctx.eip);
    return 1;
}
static int original_interface_ui_cycle(uint8_t *memory,const char *label,
                                       unsigned events,unsigned gadget_index) {
    uint32_t gadgets=*(uint32_t *)(memory+0x00379490u);
    uint32_t p=gadgets+gadget_index*40u;
    if(!gadgets || p+40u>GUEST_LIMIT) {
        fprintf(stderr,"original UI gadget index %u is outside guest backing during %s\n",gadget_index,label); return 0;
    }
    printf("TRACE SDL interface input cycle=%s events=%u gadget_index=%u id=%d bounds=%d,%d..%d,%d pressed=%u draw=%u current=%08x pending=%08x pullOut=%08x\n",
        label,events,gadget_index,*(int16_t *)(memory+p+12u),
        *(int16_t *)(memory+p+4u),*(int16_t *)(memory+p+6u),
        *(int16_t *)(memory+p+4u)+*(int16_t *)(memory+p+8u),
        *(int16_t *)(memory+p+6u)+*(int16_t *)(memory+p+10u),
        memory[p+38u],memory[p+39u],*(uint32_t *)(memory+0x002EF7E8u),
        *(uint32_t *)(memory+0x002EF7ECu),*(uint32_t *)(memory+0x002EF7F0u));
    gw_recomp_context input_ctx,update_ctx;
    if(!invoke(gw_original_setup_controller_entry,&input_ctx,0x5B170u,memory,0,0)) {
        fprintf(stderr,"original setup_controller failed during %s eip=%08x\n",label,input_ctx.eip); return 0;
    }
    uint32_t before=g_icall_count,trace=g_icall_trace_idx;
    if(!invoke(gw_original_control_game_update_dispatch,&update_ctx,0x5AF12u,memory,0,0) ||
       gw_recomp_trace_boundary_hit()) {
        if(gw_recomp_trace_boundary_hit()) return 0;
        fprintf(stderr,"original interface Update failed during %s eip=%08x esp=%08x\n",label,update_ctx.eip,update_ctx.esp); return 0;
    }
    if(update_ctx.eip!=0x5AF12u || update_ctx.esp!=STACK_TOP+4u ||
       update_ctx.memory_fault.pending || update_ctx.segment_fault_pending ||
       update_ctx.interrupt_trap_pending || update_ctx.port_io_trap.pending ||
       g_icall_count-before<2u) {
        fprintf(stderr,"original interface Update failed during %s eip=%08x esp=%08x\n",label,update_ctx.eip,update_ctx.esp); return 0;
    }
    printf("TRACE SDL interface Update cycle=%s eip=%08x esp=%08x target=%08x/%08x gadget=%u/%u current=%08x pending=%08x pullOut=%08x\n",
        label,update_ctx.eip,update_ctx.esp,g_icall_trace[trace&(ICALL_TRACE_SIZE-1u)],
        g_icall_trace[(trace+1u)&(ICALL_TRACE_SIZE-1u)],memory[p+38u],memory[p+39u],
        *(uint32_t *)(memory+0x002EF7E8u),*(uint32_t *)(memory+0x002EF7ECu),
        *(uint32_t *)(memory+0x002EF7F0u));
    return 1;
}

static int invoke_text_clip(uint8_t *memory,gw_recomp_context *c) {
    memset(c,0,sizeof *c); c->eip=0x6EE60u; c->cur_func=0x6EE60u;
    c->eax=0u; c->ebx=640u; c->ecx=480u; c->edx=0u;
    c->esp=STACK_TOP; c->cs=0x0Cu; c->ds=0x14u; c->es=0x14u; c->ss=0x14u;
    c->mem_base=(ptrdiff_t)(uintptr_t)memory; c->mem_guest_base=0; c->mem_size=GUEST_LIMIT;
    c->pit_initialized=1; c->fpu_cw=0x127Fu; *(uint32_t *)(memory+STACK_TOP)=RECOMP_RETADDR;
    return gw_recomp_invoke(gw_original_text_clip_entry,c)==GW_RECOMP_OK &&
           !c->memory_fault.pending && !c->segment_fault_pending &&
           !c->interrupt_trap_pending && !c->port_io_trap.pending;
}

static int invoke_with_ebx(void (*fn)(void),gw_recomp_context *c,uint32_t entry,
                           uint8_t *memory,uint32_t eax,uint32_t ebx,uint32_t edx) {
    memset(c,0,sizeof *c); c->eip=entry; c->cur_func=entry;
    c->eax=eax; c->ebx=ebx; c->edx=edx;
    c->esp=STACK_TOP; c->cs=0x0Cu; c->ds=0x14u; c->es=0x14u; c->ss=0x14u;
    c->mem_base=(ptrdiff_t)(uintptr_t)memory; c->mem_guest_base=0; c->mem_size=GUEST_LIMIT;
    c->pit_initialized=1; c->fpu_cw=0x127Fu; *(uint32_t *)(memory+STACK_TOP)=RECOMP_RETADDR;
    return gw_recomp_invoke(fn,c)==GW_RECOMP_OK && !c->memory_fault.pending &&
           !c->segment_fault_pending && !c->interrupt_trap_pending && !c->port_io_trap.pending;
}

static int invoke_with_ebx_esi(void (*fn)(void),gw_recomp_context *c,uint32_t entry,
                               uint8_t *memory,uint32_t eax,uint32_t ebx,
                               uint32_t esi,uint32_t edx) {
    memset(c,0,sizeof *c); c->eip=entry; c->cur_func=entry;
    c->eax=eax; c->ebx=ebx; c->esi=esi; c->edx=edx;
    c->esp=STACK_TOP; c->cs=0x0Cu; c->ds=0x14u; c->es=0x14u; c->ss=0x14u;
    c->mem_base=(ptrdiff_t)(uintptr_t)memory; c->mem_guest_base=0; c->mem_size=GUEST_LIMIT;
    c->pit_initialized=1; c->fpu_cw=0x127Fu; *(uint32_t *)(memory+STACK_TOP)=RECOMP_RETADDR;
    return gw_recomp_invoke(fn,c)==GW_RECOMP_OK && !c->memory_fault.pending &&
           !c->segment_fault_pending && !c->interrupt_trap_pending && !c->port_io_trap.pending;
}

/* Execute the authentic Watcom startup caller with the captured environment
 * bytes and the existing bounded PSP/environment selector profile. The lifted
 * stream returns at the first original instruction after __InitRtns, before
 * the CRT proceeds into its application/main path. */
static int invoke_original_startup_prefix(gw_recomp_context *c,uint8_t *memory) {
    memset(c,0,sizeof *c); c->eip=0xAF9E4u; c->cur_func=0xAF9E4u;
    c->esp=0x001A8C50u; c->cs=0x0Cu; c->ds=0x14u; c->es=0x24u; c->ss=0x14u;
    c->es_base=0x00008000u; c->mem_base=(ptrdiff_t)(uintptr_t)memory;
    c->mem_guest_base=0; c->mem_size=GUEST_LIMIT; c->pit_initialized=1; c->fpu_cw=0x037Fu;
    recomp_func_t startup=recomp_lookup(0xAF9E4u);
    startup_budget_remaining=110000000u; startup_budget_executed=0;
    startup_budget_last_va=0; startup_budget_last_func=0; startup_budget_exhausted=0;
    int ok=startup && gw_recomp_invoke(startup,c)==GW_RECOMP_OK &&
           !c->memory_fault.pending && !c->segment_fault_pending &&
           !c->interrupt_trap_pending && !c->port_io_trap.pending;
    startup_budget_remaining=0;
    if(ok && startup_budget_last_va!=0x000AFBF4u) return 0;
    return ok;
}

int main(int argc,char **argv) {
    g_full_instruction_trace=(getenv("GW_FULL_TRACE") &&
        strcmp(getenv("GW_FULL_TRACE"),"1")==0);
    fprintf(stderr,"TRACE native_trace_mode=%s\n",g_full_instruction_trace?"GW_FULL_TRACE":"FAST_BOUNDARY_PROBE");
    ULONG stack_guarantee=64u*1024u;
    (void)SetThreadStackGuarantee(&stack_guarantee);
    SetUnhandledExceptionFilter(gw_capture_unhandled_exception);
    if(argc!=4) return 2;
    uint8_t *memory=(uint8_t *)calloc(GUEST_LIMIT,1u); if(!memory) return 3;
    guest_memory=memory;
    FILE *img=fopen(argv[1],"rb"); if(!img) { free(memory); return 4; }
    if(fseek(img,0,SEEK_END)) { fclose(img); free(memory); return 5; }
    long n=ftell(img); rewind(img);
    if(n<0 || IMAGE_BASE+(uint64_t)n>GUEST_LIMIT || fread(memory+IMAGE_BASE,1,(size_t)n,img)!=(size_t)n) {
        fclose(img); free(memory); return 6;
    }
    fclose(img);
    FILE *boot=fopen("work\\ifctitle_startup_lowmem.bin","rb");
    if(!boot || fread(memory,1,0x10000u,boot)!=0x10000u || fgetc(boot)!=EOF) {
        if(boot) fclose(boot); free(memory); return 76;
    }
    fclose(boot);
    /* This startup fixture carries the same post-DOS/4GW MCB seed produced
       by runtime.dos_services.DosHost. Verify the PSP, authenticated
       environment extent, and free conventional block before the original
       CRT or LbMemorySetup can issue AH=48. */
    const uint8_t *psp_mcb=memory+(0x07FFu<<4);
    const uint8_t *env_mcb=memory+(0x08FFu<<4);
    const uint8_t *free_mcb=memory+(0x0906u<<4);
    uint16_t psp_end=(uint16_t)(memory[0x8002u]|((uint16_t)memory[0x8003u]<<8));
    uint16_t psp_paragraphs=(uint16_t)(psp_mcb[3]|((uint16_t)psp_mcb[4]<<8));
    uint16_t env_paragraphs=(uint16_t)(env_mcb[3]|((uint16_t)env_mcb[4]<<8));
    uint16_t free_paragraphs=(uint16_t)(free_mcb[3]|((uint16_t)free_mcb[4]<<8));
    if(psp_mcb[0]!='M' || psp_mcb[1]!=0x00u || psp_mcb[2]!=0x08u ||
       env_mcb[0]!='M' || env_mcb[1]!=0x00u || env_mcb[2]!=0x08u ||
       free_mcb[0]!='Z' || free_mcb[1]!=0u || free_mcb[2]!=0u ||
       psp_end!=0x08FFu || psp_paragraphs!=0x00FFu ||
       env_paragraphs!=0x0006u || free_paragraphs!=(uint16_t)(DOS_CONVENTIONAL_TOP-0x0907u) ||
       (uint32_t)(0x0906u+1u+free_paragraphs)!=DOS_CONVENTIONAL_TOP ||
       ((uint32_t)IMAGE_BASE)<(DOS_CONVENTIONAL_TOP<<4)) {
        fprintf(stderr,"post-DOS/4GW MCB fixture invalid psp_end=%04x psp_paras=%04x env_paras=%04x free_paras=%04x tags=%c/%c/%c image=%08x top=%08x\n",
            psp_end,psp_paragraphs,env_paragraphs,free_paragraphs,
            psp_mcb[0],env_mcb[0],free_mcb[0],IMAGE_BASE,DOS_CONVENTIONAL_TOP<<4);
        free(memory); return 77;
    }
    printf("TRACE DOS MCB profile=post_dos4gw_le_entry experimental=bounded-640KiB-conventional psp=0800 psp_mcb=07ff psp_paras=%04x env=0900 env_paras=%04x free_mcb=0906 free_data=0907 free_paras=%04x top=%04x image_begin=%08x\n",
        psp_paragraphs,env_paragraphs,free_paragraphs,DOS_CONVENTIONAL_TOP,IMAGE_BASE);
    if(strcmp((char *)(memory+TITLE_LIST),"data/iftitle.anb")) { free(memory); return 7; }
    if(!gw_partial_install_code_map()) { free(memory); return 8; }
    set_guest_write_observer(NULL,NULL);
    fprintf(stderr,"TRACE watched_guest_cell_initial packet_slot_guest=%08x value=%08x mapDisplay_field_guest=%08x value=%08x\n",
        watched_cell_guest[0],*(uint32_t *)(memory+watched_cell_guest[0]),
        watched_cell_guest[1],*(uint32_t *)(memory+watched_cell_guest[1]));
    uint32_t null_callback_link=0;
    const uint32_t null_callback_target=*(const uint32_t *)(memory+0x002E4A1Cu);
    if(null_callback_target!=0x00283C18u ||
       !recomp_code_linear_to_link(null_callback_target,&null_callback_link) ||
       null_callback_link!=0x00098C18u) {
        fprintf(stderr,"LE callback fixup/map mismatch slot=002e4a1c value=%08x link=%08x\n",
            null_callback_target,null_callback_link);
        free(memory); return 8;
    }
    printf("TRACE original file callback fixup slot=002e4a1c target=%08x link=%08x instruction=c3 dispatch=original-recompiled-ret\n",
        null_callback_target,null_callback_link);
    const uint32_t exit_handler_target=*(const uint32_t *)(memory+0x002EC738u);
    if(*(const uint8_t *)(memory+0x002EC737u)!=0x28u ||
       exit_handler_target!=0x002AE518u) {
        fprintf(stderr,"LE exit-handler fixup mismatch row=002ec736 priority=%02x target=%08x\n",
            *(const uint8_t *)(memory+0x002EC737u),exit_handler_target);
        free(memory); return 8;
    }
    printf("TRACE original Watcom exit-handler table row=002ec736 priority=28 target=%08x link=000c3518 callback=LE-fixup-verified\n",
        exit_handler_target);
    g_mem_base=(ptrdiff_t)(uintptr_t)memory; recomp_set_memory_bounds(0,GUEST_LIMIT);
    recomp_set_segment_range_validator(in_guest,NULL);
    gw_recomp_context c;
    /* Isolated decoder control: start from the untouched guest image and put
     * the authenticated RNC bytes in an explicitly experimental backed area.
     * This does not count as a manager/VFS load; it tests only the original
     * decoder's overlap branch against the already verified separate-buffer
     * result. */
    uint8_t *pristine=(uint8_t *)calloc(GUEST_LIMIT,1u);
    if(!pristine) { free(memory); return 21; }
    memcpy(pristine,memory,GUEST_LIMIT);
    char fixture_path[512];
    if(_snprintf(fixture_path,sizeof fixture_path,"%s\\DATA\\IFTITLE.ANB",argv[2])<0) {
        free(pristine); free(memory); return 22;
    }
    FILE *fixture=fopen(fixture_path,"rb");
    if(!fixture || fread(pristine+RNC_INPLACE,1,30050u,fixture)!=30050u) {
        if(fixture) fclose(fixture); free(pristine); free(memory); return 23;
    }
    fclose(fixture);
    guest_memory=pristine;
    gw_recomp_context pristine_context;
    if(!invoke(gw_partial_UnpackM1,&pristine_context,0xB9CFCu,pristine,
               RNC_INPLACE,RNC_INPLACE) || pristine_context.eax!=0xE349u) {
        fprintf(stderr,"pristine in-place original RNC control failed eax=%08x eip=%08x mem=%u/%08x\n",
                pristine_context.eax,pristine_context.eip,
                pristine_context.memory_fault.pending,pristine_context.memory_fault.linear);
        guest_memory=memory; free(pristine); free(memory); return 24;
    }
    FILE *control=fopen("work\\lbdataload_rnc_pristine_in_place.bin","wb");
    if(!control || fwrite(pristine+RNC_INPLACE,1,0xE349u,control)!=0xE349u) {
        if(control) fclose(control); guest_memory=memory; free(pristine); free(memory); return 25;
    }
    fclose(control);
    guest_memory=memory; free(pristine);
    memset(&vfs,0,sizeof vfs); vfs.root=argv[2];
    if(!load_vfs_manifest(&vfs,argv[3])) {
        fprintf(stderr,"GeneWars install SHA-256 manifest is unavailable or malformed: %s\n",argv[3]);
        free(memory); return 9;
    }
    printf("TRACE original VFS manifest files=%u policy=sha256-verified-install-read-only overlay=work/dos_vfs_overlay\n",
        vfs.manifest_count);
    gw_dos_services_init(&vfs.dos);
    vfs.dos.major=6u; vfs.dos.minor=22u;
    if(!gw_dos_descriptor_bind(&vfs.dos,0x0024u,0x00008000u,0x000000FFu)) { free(memory); return 76; }
    if(!gw_dos_descriptor_bind(&vfs.dos,0x1100u,0x00009000u,0x55u)) { free(memory); return 76; }
    time_t host_now=time(NULL); struct tm host_tm; localtime_s(&host_tm,&host_now);
    if (!gw_dos_time_configure(&vfs.dos,(uint8_t)host_tm.tm_hour,
            (uint8_t)host_tm.tm_min,(uint8_t)host_tm.tm_sec,0u) ||
        !gw_dos_time_realtime_enable(&vfs.dos)) { free(memory); return 36; }
    if(!gw_dos_guest_memory_configure(&vfs.dos,GUEST_LIMIT) ||
       !gw_dos_memory_allocator_configure(&vfs.dos,0x0907u,DOS_CONVENTIONAL_TOP,0x0054u,0x0800u) ||
       /* Reuse the already backed experimental DPMI arena used by the
          graphics/resource harness. It is bounded by GUEST_LIMIT and starts
          above all verified image objects; failure remains a real 8012. */
       !gw_dos_linear_allocator_configure(&vfs.dos,0x01000000u,GUEST_LIMIT) ||
       !gw_dos4gw_flat_heap_configure(&vfs.dos,0x0014u) ||
       !gw_dos_file_backend_configure(&vfs.dos,host_open,host_read,host_create,host_write,host_close,&vfs) ||
       !gw_dos_file_seek_configure(&vfs.dos,host_seek) ||
       !gw_dos_file_ioctl_info_configure(&vfs.dos,host_ioctl)) { free(memory); return 9; }
    /* OPTIONS PlugIn writes diagnostics through DOS handle 2. The original
       TITLE New Game path has now shown a DOS stdout write through handle 1.
       Capture both bounded standard streams; other handles remain fail-closed. */
    if(!gw_dos_stream_configure(&vfs.dos,1u,NULL,host_stdout_write,&vfs,1)) {
        fprintf(stderr,"could not configure DOS stdout capture\\n"); free(memory); return 73;
    }
    if(!gw_dos_stream_ioctl_info_configure(&vfs.dos,1u,0x8000u)) {
        fprintf(stderr,"could not mark DOS stdout as character device\\n"); free(memory); return 73;
    }
    if(!gw_dos_stream_configure(&vfs.dos,2u,NULL,host_stderr_write,&vfs,1)) {
        fprintf(stderr,"could not configure DOS stderr write callback\\n"); free(memory); return 73;
    }
    if(!gw_dos_stream_ioctl_info_configure(&vfs.dos,2u,0x8000u)) {
        fprintf(stderr,"could not mark DOS stderr as character device\\n"); free(memory); return 73;
    }
    if(!gw_dos_stream_memory_configure(&vfs.dos,0x002DA000u,0x000A8C50u)) {
        fprintf(stderr,"could not constrain DOS stderr guest buffer\\n"); free(memory); return 73;
    }
    if (!gw_vbe_device_configure(&vbe_device,memory,GUEST_LIMIT,0x00090000u,
            0x0101u,640u,480u,640u,8u,64u,64u,0xA000u,0x4B000u) ||
        !gw_dos_real_mode_interrupt_configure(&vfs.dos,
            startup_real_mode_interrupt,&vfs.dos)) { free(memory); return 29; }
    *(uint32_t *)(memory+0x00379484u)=0x00090000u;
    *(uint32_t *)(memory+0x00376A5Cu)=0x00390000u;
    gw_interrupt_set_callback(dispatch,&vfs.dos);
    gw_recomp_set_port_io_provider(vga_palette_io,NULL);
    /* The range map is flat for this explicit experimental profile. */
    g_seg_cs=0x0Cu; g_seg_ds=g_seg_es=g_seg_ss=0x14u;
    uint32_t ctor_dispatch_before=g_ctor_dispatch_count;
    uint32_t init_trace_before=g_icall_trace_idx;
    int startup_ok=invoke_original_startup_prefix(&c,memory);
    if(startup_budget_exhausted) {
        fprintf(stderr,"bounded original Watcom startup exceeded guest budget count=%llu last_eip=%08x current_func=%08x esp=%08x icalls=%u DBCS=%u/%08x/%04x\n",
                (unsigned long long)startup_budget_executed,startup_budget_last_va,
                startup_budget_last_func,c.esp,g_icall_count,vfs.dos.dbcs_table_configured,
                vfs.dos.dbcs_table_linear,vfs.dos.dbcs_table_size);
        free(memory); return 75;
    }
    if(!startup_ok ||
       startup_budget_last_va!=0xAFBF4u || c.memory_fault.pending || c.segment_fault_pending ||
       c.interrupt_trap_pending || c.port_io_trap.pending ||
       g_ctor_dispatch_count==ctor_dispatch_before ||
       *(uint32_t *)(memory+0x0035EAB8u)!=0x002EBA98u) {
        fprintf(stderr,"original __InitRtns(0xff) failed or did not construct IFCTitle: context_eip=%08x last_guest_eip=%08x esp=%08x icalls=%u ctor=%u object=%08x global_this=%08x regs=%08x/%08x/%08x/%08x/%08x/%08x/%08x/%08x cw=%04x top=%d status_traps mem=%u:%08x inst=%08x sel=%04x off=%08x width=%u seg=%u:%04x:%08x int=%u:%08x port=%u:%u:%08x last_icall=%08x from=%08x f304=%u\n",
                c.eip,startup_budget_last_va,c.esp,g_icall_count,g_ctor_dispatch_count-ctor_dispatch_before,
                *(uint32_t *)(memory+0x0035EAB8u),*(uint32_t *)(memory+0x002EECA8u),
                c.eax,c.ebx,c.ecx,c.edx,c.esi,c.edi,c.ebp,c.esp,c.fpu_cw,c.fp_top,
                c.memory_fault.pending,c.memory_fault.linear,c.memory_fault.instruction_va,
                c.memory_fault.selector,c.memory_fault.offset,c.memory_fault.width,c.segment_fault_pending,
                c.segment_fault_selector,c.segment_fault_instruction_va,
                c.interrupt_trap_pending,c.interrupt_instruction_va,c.port_io_trap.pending,
                c.port_io_trap.reason,c.port_io_trap.value,
                g_icall_trace[(g_icall_trace_idx-1u)&(ICALL_TRACE_SIZE-1u)],
                g_icall_from[(g_icall_trace_idx-1u)&(ICALL_TRACE_SIZE-1u)],g_watcom_f304_calls);
        dump_x87_trace();
        for(uint32_t i=init_trace_before;i<g_icall_trace_idx;i++)
            fprintf(stderr,"INIT_ICALL index=%u target=%08x from=%08x\n",i-init_trace_before,
                    g_icall_trace[i&(ICALL_TRACE_SIZE-1u)],g_icall_from[i&(ICALL_TRACE_SIZE-1u)]);
        free(memory); return 75;
    }
    const uint32_t ifclevel_static_interface=0x00360A11u;
    const uint32_t ifclevel_static_vptr=*(uint32_t *)(memory+ifclevel_static_interface+7u);
    const uint32_t ifclevel_static_vtable_link=0x00111AD4u;
    const uint32_t ifclevel_vtable_guest=0x002EBAD4u;
    const uint32_t ifclevel_static_slots[8]={0x00206650u,0x00206640u,0x00206630u,0x00206620u,
        0x00200710u,0x00200CF0u,0x002027C0u,0x002029F0u};
    if(ifclevel_static_vptr!=ifclevel_vtable_guest ||
       ifclevel_static_vtable_link+32u>=GUEST_LIMIT) {
        fprintf(stderr,"original CRT constructors did not initialize IFCLevel subobject vptr: guest=%08x vptr=%08x expected=%08x\n",
            ifclevel_static_interface,ifclevel_static_vptr,ifclevel_vtable_guest); free(memory); return 75;
    }
    for(unsigned i=0;i<8u;i++) if(*(uint32_t *)(memory+ifclevel_vtable_guest+i*4u)!=ifclevel_static_slots[i]) {
        fprintf(stderr,"original CRT constructor vtable/fixup slot mismatch index=%u value=%08x expected=%08x\n",
            i,*(uint32_t *)(memory+ifclevel_vtable_guest+i*4u),ifclevel_static_slots[i]); free(memory); return 75;
    }
    printf("TRACE original IFCLevel constructor state source=Watcom __InitRtns guest_object=003609F1 interface=00360A11 vptr=%08x map_symbol=0003:00111AE4 fixup_slots=8\n",
        ifclevel_static_vptr);
    printf("TRACE original Watcom startup-prefix entry=0xAF9E4 post_init=0xAFBF4 ctor_dispatches=%u global_this_pre_memory_table=%08x title_object=%08x env_selector=%04x env_bytes=86 source=W3-140\n",
           g_ctor_dispatch_count-ctor_dispatch_before,*(uint32_t *)(memory+0x002EECA8u),
           *(uint32_t *)(memory+0x0035EAB8u),0x1100u);
    for(uint32_t i=0;i<g_ctor_target_kinds;i++) {
        uint32_t link=0;
        int mapped=recomp_code_linear_to_link(g_ctor_targets[i].target,&link);
        printf("TRACE ctor_array {\"callsite\":\"0x000A9F3B\",\"target_linear\":\"0x%08X\",\"target_link\":\"0x%08X\",\"mapped_code\":%s,\"count\":%u}\n",
               g_ctor_targets[i].target,link,mapped?"true":"false",g_ctor_targets[i].count);
    }
    if(*(uint32_t *)(memory+0x002EECA8u)!=0u) {
        fprintf(stderr,"unexpected pre-setup value for original *SCRATCH destination this=%08x\n",
                *(uint32_t *)(memory+0x002EECA8u)); free(memory); return 76;
    }
    if(!invoke(gw_partial_LbMemorySetup,&c,0x921F0u,memory,0,0) || c.eax!=1u) {
        fprintf(stderr,"LbMemorySetup failed eax=%08x ebx=%08x ecx=%08x edx=%08x eip=%08x last_guest=%08x func=%08x esp=%08x mem=%u/%08x seg=%u:%04x:%08x int=%u/%08x vector=%02x dpmi_cursor=%08x..%08x next_handle=%u dos_blocks=%u stack=%08x/%08x/%08x/%08x\n",
                c.eax,c.ebx,c.ecx,c.edx,c.eip,startup_budget_last_va,startup_budget_last_func,c.esp,c.memory_fault.pending,c.memory_fault.linear,
                c.segment_fault_pending,c.segment_fault_selector,c.segment_fault_instruction_va,
                c.interrupt_trap_pending,c.interrupt_instruction_va,c.interrupt_vector,
                vfs.dos.allocation_cursor,vfs.dos.allocation_end,vfs.dos.next_allocation_handle,
                vfs.dos.dos_block_count,
                c.esp+16u<=GUEST_LIMIT?*(uint32_t *)(memory+c.esp):0u,
                c.esp+16u<=GUEST_LIMIT?*(uint32_t *)(memory+c.esp+4u):0u,
                c.esp+16u<=GUEST_LIMIT?*(uint32_t *)(memory+c.esp+8u):0u,
                c.esp+16u<=GUEST_LIMIT?*(uint32_t *)(memory+c.esp+12u):0u);
        uint32_t first=g_icall_trace_idx>8u?g_icall_trace_idx-8u:0u;
        for(uint32_t i=first;i<g_icall_trace_idx;i++)
            fprintf(stderr,"MEMSETUP_ICALL index=%u target=%08x from=%08x\n",i,
                g_icall_trace[i&(ICALL_TRACE_SIZE-1u)],g_icall_from[i&(ICALL_TRACE_SIZE-1u)]);
        free(memory); return 10;
    }
    if(!g_rational_ah48_failures || !g_rational_ah49_frees ||
       g_rational_blocks_after_free+1u!=g_rational_blocks_before_free ||
       !g_rational_ret_marker_seen) {
        fprintf(stderr,"original RationalAlloc fallback regression failed: AH48_fail=%u AH49_free=%u blocks=%u->%u\n",
            g_rational_ah48_failures,g_rational_ah49_frees,
            g_rational_blocks_before_free,g_rational_blocks_after_free);
        free(memory); return 16;
    }
    printf("TRACE original RationalAlloc fallback AH48_FAIL=%u AH49_FREE=%u dos_blocks=%u->%u result=0 stack_return=balanced synthetic_ret_marker=%08x\n",
        g_rational_ah48_failures,g_rational_ah49_frees,
        g_rational_blocks_before_free,g_rational_blocks_after_free,0xDEAD0000u);
    const int initial_mcb_chain_valid=validate_dos_mcb_chain(memory,vfs.dos.dos_segment_end);
    if(!initial_mcb_chain_valid) {
        fprintf(stderr,"DOS MCB chain was invalid at the start of setup_game, after LbMemorySetup\n");
        free(memory); return 117;
    }
    fprintf(stderr,"PASS DOS MCB chain valid at setup_game entry range=00009060..000090DF\n");
    trace_dos_mcb_chain("after_initial_LbMemorySetup",memory);
    gw_mcb_watch_arm("LbMemorySetup_to_TITLE_OPTIONS");
    const char *gameplay_continue_env=getenv("GWRECOMP_IFCLEVEL_CONTINUE");
    const int gameplay_continue=gameplay_continue_env && strcmp(gameplay_continue_env,"1")==0;
    const uint32_t intro_gate_guest=0x002F1662u;
    uint32_t bscreen=0u;
    if(gameplay_continue) {
        /* Gameplay path: execute setup_game as one original function so its
           Watcom EBP locals remain alive through the late animation/fade
           initializers. The instruction budget is a hard stop, not an
           emulated success or an allocation-policy change. */
        gw_recomp_context full_setup={0};
        const uint8_t gate_before=memory[intro_gate_guest];
        const unsigned opens_before=vfs.opens;
        const uint32_t icalls_before=g_icall_count;
        startup_budget_remaining=120000000u;
        startup_budget_executed=0u; startup_budget_last_va=0u;
        startup_budget_last_func=0u; startup_budget_exhausted=0;
        gw_recomp_trace_set_enabled(1);
        gw_recomp_trace_set_boundary_stop(1);
        int full_setup_ok=invoke(recomp_gw_partial_W_setup_game_n_v,
            &full_setup,0x94AC0u,memory,0u,0u);
        int full_setup_exit_boundary=gw_recomp_trace_boundary_hit();
        startup_budget_remaining=0u;
        gw_recomp_trace_set_boundary_stop(0);
        bscreen=*(uint32_t *)(memory+0x002EECA0u);
        const uint32_t main_palette_cell=*(uint32_t *)(memory+0x002DD554u+44u+28u);
        original_main_palette_guest=main_palette_cell && main_palette_cell+4u<=GUEST_LIMIT?
            *(uint32_t *)(memory+main_palette_cell):0u;
        /* This instruction-level dispatcher records the invoked entry in
           context.eip and models a synthetic RET by consuming its stack word;
           there is no live guest EIP register to overwrite with DEAD0000.
           The authentic completion check is therefore a balanced native
           Watcom frame plus the return sentinel removed from guest SS. */
        if(!full_setup_ok || startup_budget_exhausted ||
           full_setup.eip!=0x94AC0u || full_setup.esp!=STACK_TOP+4u ||
           full_setup.memory_fault.pending || full_setup.segment_fault_pending ||
           full_setup.interrupt_trap_pending || full_setup.port_io_trap.pending ||
           full_setup_exit_boundary || !(memory[intro_gate_guest]&1u) ||
           vfs.opens<=opens_before || !bscreen ||
           !in_guest(0x14u,bscreen,640u*480u,NULL) ||
           !original_main_palette_guest ||
           !in_guest(0x14u,original_main_palette_guest,768u,NULL) ||
           !validate_dos_mcb_chain(memory,vfs.dos.dos_segment_end)) {
            fprintf(stderr,"original full setup_game failed ok=%d budget=%d/%llu last=%08x func=%08x eip=%08x esp=%08x gate=%02x->%02x opens=%u->%u current=%08x pending=%08x bscreen=%08x palette=%08x icalls=%u faults=%u/%08x seg=%u:%04x:%08x int=%u:%02x:%08x port=%u:%04x:%08x boundary=%u\n",
                full_setup_ok,startup_budget_exhausted,
                (unsigned long long)startup_budget_executed,startup_budget_last_va,
                startup_budget_last_func,full_setup.eip,full_setup.esp,
                gate_before,memory[intro_gate_guest],opens_before,vfs.opens,
                *(uint32_t *)(memory+0x002EF7E8u),*(uint32_t *)(memory+0x002EF7ECu),
                bscreen,original_main_palette_guest,g_icall_count-icalls_before,
                full_setup.memory_fault.pending,full_setup.memory_fault.linear,
                full_setup.segment_fault_pending,full_setup.segment_fault_selector,
                full_setup.segment_fault_instruction_va,full_setup.interrupt_trap_pending,
                full_setup.interrupt_vector,full_setup.interrupt_instruction_va,
                full_setup.port_io_trap.pending,full_setup.port_io_trap.port,
                full_setup.port_io_trap.guest_va,full_setup_exit_boundary);
            uint32_t first=g_icall_count>12u?g_icall_count-12u:icalls_before;
            for(uint32_t i=first;i<g_icall_count;i++) {
                uint32_t k=i&(ICALL_TRACE_SIZE-1u);
                fprintf(stderr,"FULL_SETUP_ICALL index=%u from=%08x target=%08x\n",
                    i,g_icall_from[k],g_icall_trace[k]);
            }
            free(memory); return 133;
        }
        printf("PASS original setup_game continuous entry=00094ac0 return=%08x stack=%08x instructions=%llu BIOINTRO=%02x->%02x files=%u WScreen=%08x main_palette=%08x MCB_chain=valid\n",
            full_setup.eip,full_setup.esp,(unsigned long long)startup_budget_executed,
            gate_before,memory[intro_gate_guest],vfs.opens-opens_before,bscreen,
            original_main_palette_guest);
    } else {
    /* Execute setup_game from its real entry with the authentic scratch pointer
       produced by LbMemorySetup. Stop at 0x94C93, immediately after the
       original BIOINTRO.SMK size check and close. The guard keeps a failed
       startup branch from entering Watcom's process-exit destructor chain. */
    const uint8_t intro_gate_before=memory[intro_gate_guest];
    const unsigned biointro_opens_before=vfs.opens;
    gw_recomp_trace_set_enabled(1);
    gw_recomp_trace_set_boundary_stop(1);
    gw_recomp_context setup_prefix_context;
    int setup_prefix_ok=invoke(gw_original_setup_game_prefix_entry,
        &setup_prefix_context,0x94AC0u,memory,0u,0u);
    if(!setup_prefix_ok || setup_prefix_context.memory_fault.pending ||
       setup_prefix_context.segment_fault_pending ||
       setup_prefix_context.interrupt_trap_pending ||
       setup_prefix_context.port_io_trap.pending ||
       !(memory[intro_gate_guest]&1u) || vfs.opens<=biointro_opens_before ||
       _stricmp(vfs.last_path,"d:\\game\\intro\\biointro.smk") &&
       _stricmp(vfs.last_path,"c:\\genewars\\intro\\biointro.smk")) {
        fprintf(stderr,"original setup_game BIOINTRO prefix failed ok=%u eip=%08x gate=%02x->%02x opens=%u->%u path='%s' mem=%u/%08x seg=%u:%04x:%08x int=%u:%02x:%08x regs=%08x/%08x/%08x/%08x/%08x port=%u:%u:%08x\n",
            (unsigned)setup_prefix_ok,setup_prefix_context.eip,intro_gate_before,
            memory[intro_gate_guest],biointro_opens_before,vfs.opens,vfs.last_path,
            setup_prefix_context.memory_fault.pending,setup_prefix_context.memory_fault.linear,
            setup_prefix_context.segment_fault_pending,setup_prefix_context.segment_fault_selector,
            setup_prefix_context.segment_fault_instruction_va,
            setup_prefix_context.interrupt_trap_pending,setup_prefix_context.interrupt_vector,
            setup_prefix_context.interrupt_instruction_va,setup_prefix_context.eax,
            setup_prefix_context.ebx,setup_prefix_context.ecx,setup_prefix_context.esi,
            setup_prefix_context.edi,
            setup_prefix_context.port_io_trap.pending,setup_prefix_context.port_io_trap.reason,
            setup_prefix_context.port_io_trap.value);
        free(memory); return 104;
    }
    printf("PASS original setup_game 0x94AC0 prefix checked INTRO/BIOINTRO.SMK: bytes=24897308 gate=%02x->%02x opens=%u->%u path='%s' stop=0x94C93\n",
        intro_gate_before,memory[intro_gate_guest],biointro_opens_before,vfs.opens,vfs.last_path);
    if(!invoke(gw_original_install_resource_callback,&c,0x14E94u,memory,0,0)) {
        fprintf(stderr,"original callback init slice faulted before TEXT.DAT load mem=%u/%08x\n",
                c.memory_fault.pending,c.memory_fault.linear); free(memory); return 11;
    }
    /* Exact setup_game call inputs from 0x94C9A..0x94CAA: the original
     * LbDataLoadAll_ walks the real LE record at 0x104104 (object-3 guest
     * address 0x2DE104) and opens DATA/TEXT.DAT through the DOS/VFS path. */
    const uint32_t text_record=0x002DE104u, text_start_cell=0x002EECA4u;
    const uint32_t text_pointer_table=0x002EECACu;
    if(strcmp((char *)(memory+text_record),"data/text.dat") ||
       *(uint32_t *)(memory+text_record+28u)!=text_start_cell ||
       *(uint32_t *)(memory+text_start_cell)!=0u) {
        fprintf(stderr,"authentic TEXT.DAT LE record/cell mismatch name='%s' cell=%08x start=%08x\n",
                (char *)(memory+text_record),*(uint32_t *)(memory+text_record+28u),
                *(uint32_t *)(memory+text_start_cell)); free(memory); return 49;
    }
    if(!invoke(gw_partial_LbDataLoadAll,&c,0x15090u,memory,0x002EF498u,text_record) ||
       (c.eax&0xffu)!=0u) {
        fprintf(stderr,"original TEXT.DAT LbDataLoadAll failed eax=%08x eip=%08x fault=%u/%08x path='%s' denied=%u\n",
                c.eax,c.eip,c.memory_fault.pending,c.memory_fault.linear,vfs.last_path,vfs.denied);
        free(memory); return 50;
    }
    const uint32_t text_guest=*(uint32_t *)(memory+text_start_cell);
    const uint32_t text_length=*(uint32_t *)(memory+text_record+36u);
    const uint32_t text_end_cell=*(uint32_t *)(memory+text_record+32u);
    if(!text_guest || text_length!=38632u || text_guest<FLAT_HEAP_BEGIN ||
       text_guest>GUEST_LIMIT || text_length>GUEST_LIMIT-text_guest ||
       (text_end_cell && *(uint32_t *)(memory+text_end_cell)!=text_guest+text_length) ||
       vfs.text_reads<2u || vfs.text_payload_reads!=1u ||
       vfs.text_payload_bytes!=text_length || vfs.text_payload_guest!=text_guest ||
       vfs.text_seeks==0u ||
       !guest_path_has_suffix(vfs.last_path,"data/text.dat")) {
        fprintf(stderr,"original TEXT.DAT load result invalid path='%s' reads=%u/%u payload=%u/%u@%08x seeks=%u guest=%08x bytes=%u end=%08x\n",
                vfs.last_path,vfs.text_reads,vfs.text_bytes,vfs.text_payload_reads,
                vfs.text_payload_bytes,vfs.text_payload_guest,vfs.text_seeks,text_guest,text_length,
                text_end_cell?*(uint32_t *)(memory+text_end_cell):0u); free(memory); return 51;
    }
    FILE *text_capture=fopen("work\\ifctitle_textdat_loaded.bin","wb");
    if(!text_capture || fwrite(memory+text_guest,1,text_length,text_capture)!=text_length) {
        if(text_capture) fclose(text_capture); free(memory); return 55;
    }
    fclose(text_capture);
    printf("TRACE original TEXT.DAT load path=%s reads=%u payload_reads=%u payload_bytes=%u seeks=%u result=%08x guest=%08x record=002DE104 cell=002EECA4\n",
           vfs.last_path,vfs.text_reads,vfs.text_payload_reads,vfs.text_payload_bytes,
           vfs.text_seeks,c.eax,text_guest);
    uint32_t text_globals[4]={0x002EF0A8u,0x002EF0B0u,0x002EF0B4u,0x002EF0B8u};
    uint32_t text_before[4];
    for(unsigned i=0;i<4u;i++) text_before[i]=*(uint32_t *)(memory+text_globals[i]);
    gw_recomp_context text_parser_context;
    if(!invoke_with_ebx(gw_original_text_parser_entry,&text_parser_context,0x955E0u,memory,
                        text_guest,626u,text_pointer_table)) {
        fprintf(stderr,"original FUN_000955E0 TEXT.DAT parser faulted eax=%08x ebx=%08x edx=%08x eip=%08x memory=%u/%08x segment=%u/%08x\n",
                text_parser_context.eax,text_parser_context.ebx,text_parser_context.edx,
                text_parser_context.eip,text_parser_context.memory_fault.pending,
                text_parser_context.memory_fault.linear,text_parser_context.segment_fault_pending,
                text_parser_context.segment_fault_instruction_va); free(memory); return 52;
    }
    for(unsigned i=0;i<4u;i++) {
        uint32_t ptr=*(uint32_t *)(memory+text_globals[i]);
        if(ptr<text_guest || ptr>=text_guest+text_length) {
            fprintf(stderr,"original TEXT.DAT parser left menu string[%u] invalid: before=%08x after=%08x range=%08x..%08x\n",
                    i,text_before[i],ptr,text_guest,text_guest+text_length); free(memory); return 53;
        }
        uint32_t end=ptr;
        while(end<text_guest+text_length && memory[end]) end++;
        if(end==text_guest+text_length) {
            fprintf(stderr,"original TEXT.DAT parser string[%u] is not NUL-terminated in loaded resource\n",i);
            free(memory); return 54;
        }
        char text[96]; dump_guest_ascii(ptr,text,sizeof text);
        printf("TRACE original TEXT.DAT string[%u] global=%08x before=%08x after=%08x value=\"%s\"\n",
               i,text_globals[i],text_before[i],ptr,text);
    }
    if (!invoke_screen_setup(memory)) { free(memory); return 30; }
    /* setup_game's original call at 0x94DBC passes the static 44-byte record
       list beginning at link 0x104054 to LbDataLoadAll_.  Its third record is
       the original *SCRATCH request: the LE fixup in that record points to
       the real global slot at link 0x114CA8 and asks for 0x2000 bytes.  Let
       GeneWars allocate and publish that pointer; never seed the slot here. */
    {
        const uint32_t memory_records=0x002DE054u; /* 0x104054 + data-object delta 0x1DA000 */
        const uint32_t scratch_record=memory_records+2u*44u;
        const uint32_t scratch_slot=0x002EECA8u;   /* 0x114CA8 + data-object delta */
        const uint32_t vesa_slot=0x00377484u;      /* 0x19F484 + 0x1DA000 data-object delta */
        const uint32_t wscreen_slot=0x00376A5Cu;   /* 0x19CA5C + data-object delta */
        if(strcmp((char *)(memory+memory_records),"*W_SCREEN") ||
           strcmp((char *)(memory+memory_records+44u),"*VESA") ||
           strcmp((char *)(memory+scratch_record),"*SCRATCH") ||
           *(uint32_t *)(memory+scratch_record+28u)!=scratch_slot ||
           *(uint32_t *)(memory+scratch_record+36u)!=0x2000u ||
           *(uint32_t *)(memory+scratch_slot)!=0u) {
            fprintf(stderr,"original setup_game memory descriptor/fixup mismatch names='%s'/'%s'/'%s' slot=%08x expected=%08x bytes=%08x\n",
                    (char *)(memory+memory_records),(char *)(memory+memory_records+44u),
                    (char *)(memory+scratch_record),*(uint32_t *)(memory+scratch_record+28u),
                    scratch_slot,*(uint32_t *)(memory+scratch_record+36u));
            free(memory); return 77;
        }
        gw_recomp_context memory_load_context;
        uint32_t opens_before=vfs.opens,denied_before=vfs.denied;
        if(!invoke(gw_partial_LbDataLoadAll,&memory_load_context,0x15090u,memory,
                   0x002EF498u,memory_records) || memory_load_context.eax!=0u ||
           memory_load_context.memory_fault.pending || memory_load_context.segment_fault_pending ||
           memory_load_context.interrupt_trap_pending || memory_load_context.port_io_trap.pending) {
            fprintf(stderr,"original setup_game LbDataLoadAll memory table failed eax=%08x eip=%08x mem=%u/%08x seg=%u/%08x int=%u port=%u names='%s'/'%s'/'%s'\n",
                    memory_load_context.eax,memory_load_context.eip,
                    memory_load_context.memory_fault.pending,memory_load_context.memory_fault.linear,
                    memory_load_context.segment_fault_pending,memory_load_context.segment_fault_instruction_va,
                    memory_load_context.interrupt_trap_pending,memory_load_context.port_io_trap.pending,
                    (char *)(memory+memory_records),(char *)(memory+memory_records+44u),
                    (char *)(memory+scratch_record));
            free(memory); return 78;
        }
        uint32_t scratch=*(uint32_t *)(memory+scratch_slot);
        uint32_t wscreen=*(uint32_t *)(memory+wscreen_slot);
        uint32_t vesa=*(uint32_t *)(memory+vesa_slot);
        int scratch_backed=in_guest(0x14u,scratch,0x2000u,NULL);
        int wscreen_backed=wscreen && in_guest(0x14u,wscreen,640u*480u,NULL);
        int vesa_backed=vesa && in_guest(0x14u,vesa,0x100u,NULL);
        if(!scratch || !scratch_backed || !wscreen_backed ||
           (vesa && !vesa_backed) ||
           vfs.opens!=opens_before || vfs.denied!=denied_before) {
            fprintf(stderr,"original *SCRATCH/*VESA/*W_SCREEN allocations invalid scratch=%08x wscreen=%08x vesa=%08x io=%u/%u denied=%u\n",
                    scratch,wscreen,vesa,vfs.opens-opens_before,vfs.closes,vfs.denied-denied_before);
            for(uint32_t i=0;i<vfs.dos.dos_block_count;i++)
                fprintf(stderr,"original DOS backing block[%u]=%04x..%04x paragraphs=%04x\n",i,
                    vfs.dos.dos_blocks[i].segment,
                    vfs.dos.dos_blocks[i].segment+vfs.dos.dos_blocks[i].paragraphs,
                    vfs.dos.dos_blocks[i].paragraphs);
            free(memory); return 79;
        }
        printf("TRACE original setup_game 0x94DBC -> LbDataLoadAll_ 0x15090 records=%08x entries=3 result=0 scratch_slot=002EECA8 scratch=%08x bytes=00002000 scratch_DOS_backing=%u WScreen=%08x WScreen_backing=%u VESA=%08x VESA_backing=%u file_opens=%u denied=%u provenance=LE-fixup+original-loader\n",
               memory_records,scratch,scratch_backed,wscreen,wscreen_backed,vesa,vesa_backed,
               vfs.opens-opens_before,vfs.denied-denied_before);
    }
    /* The bounded setup_game prefix above stops after BIOINTRO at 0x94C93.
       Its original continuation calls FUN_00093BD0 at 0x94DC1, which sets up
       the graphics manager used by IFCLevel's post-Smacker mode restoration.
       Execute that original function here with the verified startup resource
       table and VBE provider already live; do not seed its mode-state global. */
    {
        gw_recomp_context graphics_init_context;
        uint32_t mode_ready_before=read_guest_u32(0x00376E28u);
        int graphics_init_returned=invoke(recomp_gw_partial_W_setup_host_n_v,
            &graphics_init_context,0x93BD0u,memory,0u,0u);
        uint8_t run_flags=guest_memory[0x002F1661u];
        int audio_frontier_after_graphics=
            !graphics_init_returned && graphics_init_context.interrupt_trap_pending &&
            graphics_init_context.interrupt_vector==0x31u &&
            graphics_init_context.interrupt_instruction_va==0x000C9172u &&
            (graphics_init_context.eax&0xffffu)==0x0300u &&
            (graphics_init_context.ebx&0xffu)==0x66u &&
            read_guest_u32(0x00376E28u)==1u && (run_flags&0x40u)!=0u;
        if((!graphics_init_returned && !audio_frontier_after_graphics) ||
           read_guest_u32(0x00376E28u)!=1u || (run_flags&0x40u)==0u) {
            recomp_memory_diagnostic diag=recomp_memory_diag_last_access();
            fprintf(stderr,"original setup_game graphics initializer 0x94DC1 -> FUN_00093BD0 failed eax=%08x eip=%08x mode_ready=%08x->%08x runFlags_117661=%02x mem=%u/%08x seg=%u:%04x:%08x int=%u:%02x:%08x port=%u:%u:%08x\n",
                graphics_init_context.eax,graphics_init_context.eip,mode_ready_before,
                read_guest_u32(0x00376E28u),guest_memory[0x002F1661u],graphics_init_context.memory_fault.pending,
                graphics_init_context.memory_fault.linear,graphics_init_context.segment_fault_pending,
                graphics_init_context.segment_fault_selector,graphics_init_context.segment_fault_instruction_va,
                graphics_init_context.interrupt_trap_pending,graphics_init_context.interrupt_vector,
                graphics_init_context.interrupt_instruction_va,graphics_init_context.port_io_trap.pending,
                graphics_init_context.port_io_trap.reason,graphics_init_context.port_io_trap.value);
            fprintf(stderr,"TRACE setup_game graphics memory-fault seg=%u selector=%04x offset=%08x width=%u instruction=%08x access_diag_valid=%u diag_eip=%08x diag_insn=%08x mnemonic=%s base=%08x offset=%08x linear=%08x width=%u access=%u backing=%u regs=%08x/%08x/%08x/%08x/%08x/%08x/%08x/%08x\n",
                graphics_init_context.memory_fault.segment,graphics_init_context.memory_fault.selector,
                graphics_init_context.memory_fault.offset,graphics_init_context.memory_fault.width,
                graphics_init_context.memory_fault.instruction_va,diag.valid,diag.guest_eip,
                diag.instruction_id,diag.mnemonic,diag.segment_base,diag.offset,diag.linear,
                diag.width,diag.access,diag.backing,graphics_init_context.eax,
                graphics_init_context.ebx,graphics_init_context.ecx,graphics_init_context.edx,
                graphics_init_context.esi,graphics_init_context.edi,graphics_init_context.ebp,
                graphics_init_context.esp);
            free(memory); return 80;
        }
        if(audio_frontier_after_graphics)
            fprintf(stderr,"TRACE original setup_game graphics prefix site=00094DC1 function=00093BD0 stopped_at_unrelated_audio_frontier=INT31/0300 vector66/AX0303 mode_ready=1 runFlags_117661=%02x profile=isolated-graphics-continuation\n",run_flags);
        else
            fprintf(stderr,"PASS original setup_game graphics initializer site=00094DC1 function=00093BD0 result=%08x mode_ready=%08x->%08x runFlags_117661=%02x dims=%u/%u\n",
            graphics_init_context.eax,mode_ready_before,read_guest_u32(0x00376E28u),run_flags,
            read_guest_u32(0x00376A78u),read_guest_u32(0x00376A7Cu));
    }
    /* Continue the original setup_game table-preparation block at 0x94DD0.
       Its incoming EBX/ESI are the LE data table bounds established at
       0x94DA6/0x94DB6; supply their verified object-3 guest translations. */
    {
        const uint32_t records=0x002DE2C4u, records_end=0x002DE729u;
        const uint32_t record_bytes=records_end-records;
        if(record_bytes!=0x465u || record_bytes%0x2Du!=0u ||
           !in_guest(0x14u,records,record_bytes,NULL)) {
            fprintf(stderr,"setup_game record-table extent is not backed: %08x..%08x bytes=%x\n",
                records,records_end,record_bytes); free(memory); return 124;
        }
        for(uint32_t at=records;at<records_end;at+=0x2Du) {
            if(memory[at+0x1Au]==0u) {
                fprintf(stderr,"setup_game record-table divisor is zero at %08x\n",at+0x1Au);
                free(memory); return 125;
            }
        }
        gw_recomp_context table_context;
        if(!invoke_with_ebx_esi(gw_original_setup_game_record_table_entry,&table_context,
                0x94DD0u,memory,0u,records,records_end,0u) ||
           table_context.ebx!=records_end || table_context.esi!=records_end ||
           table_context.memory_fault.pending || table_context.segment_fault_pending ||
           table_context.interrupt_trap_pending || table_context.port_io_trap.pending) {
            fprintf(stderr,"original setup_game record-table block failed eip=%08x ebx=%08x esi=%08x mem=%u/%08x seg=%u:%04x:%08x int=%u/%02x port=%u\n",
                table_context.eip,table_context.ebx,table_context.esi,
                table_context.memory_fault.pending,table_context.memory_fault.linear,
                table_context.segment_fault_pending,table_context.segment_fault_selector,
                table_context.segment_fault_instruction_va,table_context.interrupt_trap_pending,
                table_context.interrupt_vector,table_context.port_io_trap.pending);
            free(memory); return 126;
        }
        unsigned mismatches=0u;
        for(uint32_t at=records;at<records_end;at+=0x2Du) {
            int32_t half=*(int32_t *)(memory+at+0x0Au)/2;
            int32_t quotient=half/(int32_t)memory[at+0x1Au];
            if(*(int32_t *)(memory+at+0x25u)!=half ||
               *(int32_t *)(memory+at+0x29u)!=quotient) mismatches++;
        }
        if(mismatches || !validate_dos_mcb_chain(memory,vfs.dos.dos_segment_end)) {
            fprintf(stderr,"original setup_game record-table outputs differ from guest formula mismatches=%u\n",mismatches);
            free(memory); return 127;
        }
        printf("PASS original setup_game record-table initializer link=94DD0 guest=002DE2C4 records=31 bytes=1125 end=002DE729 host_events=0 MCB_chain_valid=1\n");
    }
    /* setup_game calls original FUN_0006EE60 with the active screen bounds.
       The isolated 640x480 profile supplies those registers; the guest code
       itself writes the text-window globals used by the glyph blitter. */
    if (!invoke_text_clip(memory,&c) ||
        *(uint32_t *)(memory+0x002EE8E4u)!=0u ||
        *(uint32_t *)(memory+0x002EE8E8u)!=640u ||
        *(uint32_t *)(memory+0x002EE8ECu)!=0u ||
        *(uint32_t *)(memory+0x002EE8F0u)!=480u ||
        *(uint32_t *)(memory+0x002EE8F4u)!=640u ||
        *(uint32_t *)(memory+0x002EE8F8u)!=480u) {
        fprintf(stderr,"original setup_game text clip initialization failed eax=%08x eip=%08x bounds=%u,%u..%u,%u size=%u,%u\n",
                c.eax,c.eip,*(uint32_t *)(memory+0x002EE8E4u),
                *(uint32_t *)(memory+0x002EE8ECu),*(uint32_t *)(memory+0x002EE8E8u),
                *(uint32_t *)(memory+0x002EE8F0u),*(uint32_t *)(memory+0x002EE8F4u),
                *(uint32_t *)(memory+0x002EE8F8u)); free(memory); return 56;
    }
    printf("TRACE original FUN_0006EE60 text clip eip=0006ee60 regs=EAX:0 EBX:640 ECX:480 EDX:0 bounds=0,0..640,480\n");
    if (*(uint32_t *)(memory+0x002EECA0u)!=0u) {
        fprintf(stderr,"b_screen unexpectedly initialized before the original allocation block: %08x\n",
                *(uint32_t *)(memory+0x002EECA0u)); free(memory); return 31;
    }
    fprintf(stderr,"TRACE original BScreen allocation input site=00092B71 width=%u height=%u expected_bytes=%08x DS=%04x DS_BASE=%08x\n",
        *(uint32_t *)(memory+0x00376A78u),*(uint32_t *)(memory+0x00376A7Cu),
        *(uint32_t *)(memory+0x00376A78u)**(uint32_t *)(memory+0x00376A7Cu),
        g_seg_ds,g_ds_base);
    if (!invoke(gw_original_bscreen_alloc_store,&c,0x92B71u,memory,0,0)) {
        fprintf(stderr,"original b_screen allocation/store block faulted eax=%08x eip=%08x mem=%u/%08x\n",
                c.eax,c.eip,c.memory_fault.pending,c.memory_fault.linear); free(memory); return 32;
    }
    bscreen=*(uint32_t *)(memory+0x002EECA0u);
    trace_guest_heap_covering(bscreen,"immediately_after_original_92B71_allocation");
    if (!bscreen || bscreen<FLAT_HEAP_BEGIN || bscreen>GUEST_LIMIT ||
        0x4B000u>GUEST_LIMIT-bscreen || *(uint32_t *)(memory+0x00376A78u)!=640u ||
        *(uint32_t *)(memory+0x00376A7Cu)!=480u) {
        fprintf(stderr,"original b_screen allocation produced invalid state pointer=%08x dimensions=%u/%u\n",
                bscreen,*(uint32_t *)(memory+0x00376A78u),*(uint32_t *)(memory+0x00376A7Cu));
        free(memory); return 33;
    }
    if (bscreen!=*(uint32_t *)(memory+0x002EECA0u)) {
        fprintf(stderr,"b_screen changed unexpectedly before title PlugIn: %08x\n",
                *(uint32_t *)(memory+0x002EECA0u)); free(memory); return 28;
    }
    /* Resume setup_game at its real startup_files block. This initializes
       block_mem through the original loader and applies the original palette. */
    {
        const uint32_t startup_files=0x002DD554u;
        const uint32_t block_mem_guest=0x002EEC88u; /* 0x114C88 + verified object-3 rebase 0x1DA000 */
        unsigned opens_before=vfs.opens,reads_before=vfs.reads;
        uint32_t palette_writes_before=vga_dac_component_writes;
        if(strcmp((char *)(memory+startup_files+44u),"data/main.pal") ||
           strcmp((char *)(memory+startup_files+88u),"data/b32a.dat") ||
           *(uint32_t *)(memory+startup_files+88u+28u)!=block_mem_guest ||
           *(uint32_t *)(memory+block_mem_guest)!=0u) {
            fprintf(stderr,"canonical startup_files records/cells mismatch: main='%s' block='%s' cell=%08x value=%08x\n",
                (char *)(memory+startup_files+44u),(char *)(memory+startup_files+88u),
                *(uint32_t *)(memory+startup_files+88u+28u),*(uint32_t *)(memory+block_mem_guest));
            free(memory); return 113;
        }
        gw_recomp_context startup_resource_context;
        gw_recomp_trace_set_boundary_stop(1);
        int startup_resources_ok=invoke(gw_original_setup_game_startup_resources_entry,
            &startup_resource_context,0x94DF3u,memory,0u,0u);
        gw_recomp_trace_set_boundary_stop(0);
        uint32_t block_mem=*(uint32_t *)(memory+block_mem_guest);
        const uint32_t main_palette_record=startup_files+44u;
        const uint32_t main_palette_cell=*(uint32_t *)(memory+main_palette_record+28u);
        original_main_palette_guest=main_palette_cell && main_palette_cell+4u<GUEST_LIMIT?
            *(uint32_t *)(memory+main_palette_cell):0u;
        uint32_t packed=*(uint32_t *)(memory+startup_files+88u+32u);
        uint32_t unpacked=*(uint32_t *)(memory+startup_files+88u+36u);
        if(!startup_resources_ok || startup_resource_context.memory_fault.pending ||
           startup_resource_context.segment_fault_pending || startup_resource_context.interrupt_trap_pending ||
           startup_resource_context.port_io_trap.pending || !block_mem ||
           !in_guest(0x14u,block_mem,unpacked?unpacked:1u,NULL) ||
           strcmp((char *)(memory+main_palette_record),"data/main.pal") ||
           *(uint32_t *)(memory+main_palette_record+36u)!=768u ||
           !original_main_palette_guest || original_main_palette_guest+768u>GUEST_LIMIT ||
           vfs.opens<=opens_before || vfs.reads<=reads_before ||
           vga_dac_component_writes-palette_writes_before!=768u || vga_dac_component!=0u) {
            fprintf(stderr,"original setup_game startup resources failed ok=%d eip=%08x block_mem=%08x size=%u/%u io=%u/%u DAC=%u fault=%u/%08x seg=%u:%04x:%08x int=%u:%02x:%08x\n",
                startup_resources_ok,startup_resource_context.eip,block_mem,packed,unpacked,
                vfs.opens-opens_before,vfs.reads-reads_before,
                vga_dac_component_writes-palette_writes_before,
                startup_resource_context.memory_fault.pending,startup_resource_context.memory_fault.linear,
                startup_resource_context.segment_fault_pending,startup_resource_context.segment_fault_selector,
                startup_resource_context.segment_fault_instruction_va,
                startup_resource_context.interrupt_trap_pending,startup_resource_context.interrupt_vector,
                startup_resource_context.interrupt_instruction_va);
            free(memory); return 113;
        }
        printf("PASS original setup_game startup_files block=002dd554 data/b32a.dat->block_mem cell=002eec88 buffer=%08x bytes=%u/%u files_opened=%u reads=%u original_palette=data/main.pal DAC_component_writes=%u\n",
            block_mem,packed,unpacked,vfs.opens-opens_before,vfs.reads-reads_before,
            vga_dac_component_writes-palette_writes_before);
        unsigned main_palette_bad=0u,main_palette_diff=0u;
        for(uint32_t i=0;i<768u;i++) {
            if(vga_dac[i]>63u) main_palette_bad++;
            if(vga_dac[i]!=(memory[original_main_palette_guest+i]&0x3Fu)) main_palette_diff++;
        }
        if(main_palette_bad || main_palette_diff) {
            fprintf(stderr,"original setup_game main palette differs from its loaded resource source=%08x bad=%u diff=%u\n",
                original_main_palette_guest,main_palette_bad,main_palette_diff);
            free(memory); return 116;
        }
        printf("PASS original setup_game palette source=%08x bytes=768 DAC_matches_original_data_main_pal=1\n",
            original_main_palette_guest);
        trace_guest_heap_covering(block_mem,"after_original_setup_game_b32a_load");
    }
    /* Resume setup_game through its original 0x94E44..0x94EC0 font setup.
       EBP only addresses this block's local pointer at [EBP+0x56]; the guest
       code itself writes that local from the LE-fixed 0x11796C table base. */
    {
        gw_recomp_context font_context;
        memset(&font_context,0,sizeof font_context);
        font_context.eip=0x94E44u; font_context.cur_func=0x94E44u;
        font_context.esp=STACK_TOP; font_context.ebp=STACK_TOP-0x100u;
        font_context.cs=0x0Cu; font_context.ds=0x14u;
        font_context.es=0x14u; font_context.ss=0x14u;
        font_context.mem_base=(ptrdiff_t)(uintptr_t)memory;
        font_context.mem_guest_base=0; font_context.mem_size=GUEST_LIMIT;
        font_context.pit_initialized=1; font_context.fpu_cw=0x127Fu;
        *(uint32_t *)(memory+STACK_TOP)=RECOMP_RETADDR;
        gw_recomp_status font_status=gw_recomp_invoke(
            gw_original_setup_game_font_initializers_entry,&font_context);
        uint32_t font_object=0x00360BBCu; /* link 0x186BBC + measured object-3 delta */
        uint32_t glyph_table=*(uint32_t *)(memory+font_object);
        if(font_status!=GW_RECOMP_OK || font_context.memory_fault.pending ||
           font_context.segment_fault_pending || font_context.interrupt_trap_pending ||
           font_context.port_io_trap.pending || !in_guest(0x14u,font_object,0x1Cu,NULL) ||
           !glyph_table || !in_guest(0x14u,glyph_table,0x240u,NULL)) {
            fprintf(stderr,"original setup_game font initializer failed status=%u eip=%08x EBP=%08x font=%08x glyph_table=%08x mem=%u/%08x seg=%u:%04x:%08x int=%u:%02x:%08x port=%u:%04x:%08x\n",
                font_status,font_context.eip,font_context.ebp,font_object,glyph_table,
                font_context.memory_fault.pending,font_context.memory_fault.linear,
                font_context.segment_fault_pending,font_context.segment_fault_selector,
                font_context.segment_fault_instruction_va,font_context.interrupt_trap_pending,
                font_context.interrupt_vector,font_context.interrupt_instruction_va,
                font_context.port_io_trap.pending,font_context.port_io_trap.port,
                font_context.port_io_trap.guest_va);
            free(memory); return 128;
        }
        printf("PASS original setup_game font initialization block link=94E44..94EC0 initialized_font_objects=6 skipped_index=2 font_186BBC_guest=%08x glyph_table=%08x glyph_bytes_backed=576 MCB_chain_valid=%u\n",
            font_object,glyph_table,validate_dos_mcb_chain(memory,vfs.dos.dos_segment_end));
    }
    /* Run the hardware-independent world-array initialization calls that
       setup_game reaches after its omitted resource/configuration tail. These
       functions have no callees in the 1.1 MAP/REA bodies and their original
       setup_game order is retained. This is an explicit continuation of that
       initializer subset, not a claim that the full setup_game ran. */
    {
        static const struct { const char *name; void (*entry)(void); uint32_t link; } init[] = {
            {"Creature",recomp_gw_partial_W_InitArray_Creature_n_v,0x471C0u},
            {"Plant",recomp_gw_partial_W_InitArray_Plant_n_v,0x56FE0u},
            {"PlSpec",recomp_gw_partial_W_InitArray_PlSpec_n_v,0x43A20u},
            {"Building",recomp_gw_partial_W_InitArray_Building_n_v,0x39CB0u},
            {"Effect",recomp_gw_partial_W_InitArray_Effect_n_v,0x85030u},
            {"Event",recomp_gw_partial_W_InitArray_Event_n_v,0x89830u},
            {"Drone",recomp_gw_partial_W_InitArray_Drone_n_v,0x139B0u},
            {"UnknArr01",recomp_gw_partial_W_InitArray_UnknArr01_n_v,0x10010u},
        };
        for(unsigned i=0;i<sizeof(init)/sizeof(init[0]);i++) {
            gw_recomp_context init_context;
            if(!invoke(init[i].entry,&init_context,init[i].link,memory,0u,0u) ||
               init_context.memory_fault.pending || init_context.segment_fault_pending ||
               init_context.interrupt_trap_pending || init_context.port_io_trap.pending) {
                fprintf(stderr,"original setup_game InitArray %s link=%08x failed eip=%08x mem=%u/%08x seg=%u:%04x:%08x int=%u port=%u\n",
                    init[i].name,init[i].link,init_context.eip,
                    init_context.memory_fault.pending,init_context.memory_fault.linear,
                    init_context.segment_fault_pending,init_context.segment_fault_selector,
                    init_context.segment_fault_instruction_va,init_context.interrupt_trap_pending,
                    init_context.port_io_trap.pending);
                free(memory); return 122;
            }
        }
        if(!validate_dos_mcb_chain(memory,vfs.dos.dos_segment_end)) {
            fprintf(stderr,"original setup_game InitArray continuation damaged DOS MCB chain\n");
            free(memory); return 123;
        }
        printf("PASS original setup_game world-array initializers calls=8 order=95434..95457 MCB_chain_valid=1\n");
    }
    }
    const uint32_t record=TITLE_LIST;
    const uint32_t start_cell=*(uint32_t *)(memory+record+28u);
    const uint32_t end_cell=*(uint32_t *)(memory+record+32u);
    if(!start_cell || start_cell+4u>GUEST_LIMIT ||
       (end_cell && end_cell+4u>GUEST_LIMIT) || *(uint32_t *)(memory+start_cell)!=0 ||
       *(uint32_t *)(memory+0x2E4804u)!=0x001FFBB0u) {
        fprintf(stderr,"pre-load LE record/callback state mismatch startcell=%08x endcell=%08x cb=%08x\n",
                start_cell,end_cell,*(uint32_t *)(memory+0x2E4804u)); free(memory); return 12;
    }
    g_icall_trace_idx=g_icall_count=0;
    if(!invoke(gw_partial_W_PlugIn_IFCTitle_n_v,&c,0x70D10u,memory,0x0035EAB8u,0) ||
       c.esp!=STACK_TOP+4u ||
       *(uint8_t *)(memory+0x0035EAB8u+0x20u)!=2u || vfs.denied!=0u ||
       *(uint8_t *)(memory+0x002F165Cu)!=2u) {
        fprintf(stderr,"full original IFCTitle::PlugIn failed eax=%08x eip=%08x esp=%08x int=%u vector=%02x/%08x mem=%u/%08x meminst=%08x memsel=%04x offset=%08x width=%u segfault=%u/%08x/%04x stop=%u reason=%u guest=%08x target=%08x bscreen=%08x icalls=%u target0=%08x from0=%08x path='%s' denied=%u opens=%u reads=%u closes=%u title_reads=%u title_bytes=%u title_rnc=%u args=%08x/%08x/%08x state=%u\n",
                c.eax,c.eip,c.esp,c.interrupt_trap_pending,c.interrupt_vector,c.interrupt_instruction_va,
                c.memory_fault.pending,c.memory_fault.linear,c.memory_fault.instruction_va,
                c.memory_fault.selector,c.memory_fault.offset,c.memory_fault.width,
                c.segment_fault_pending,c.segment_fault_instruction_va,c.segment_fault_selector,c.port_io_trap.pending,
                c.port_io_trap.reason,c.port_io_trap.guest_va,c.port_io_trap.value,
                bscreen,g_icall_count,g_icall_trace[0],g_icall_from[0],vfs.last_path,
                vfs.denied,vfs.opens,vfs.reads,vfs.closes,vfs.title_screen_reads,vfs.title_screen_bytes,
                title_rnc_calls,title_rnc_eax,title_rnc_ecx,title_rnc_edx,*(uint8_t *)(memory+0x002F165Cu)); free(memory); return 13;
    }
    /* Link VA 0x001157E8 belongs to LE object 3, whose verified guest delta
       is +0x001DA000.  Keep this runtime observation at the translated guest
       address (0x002EF7E8); the former 0x002F17E8 probe was 0x2000 too high. */
    const uint32_t current_ifc=*(uint32_t *)(memory+0x002EF7E8u);
    const uint32_t pending_ifc=*(uint32_t *)(memory+0x002EF7ECu);
    const uint32_t pull_out=*(uint32_t *)(memory+0x002EF7F0u);
    printf("TRACE interface globals after PlugIn currentIFC=%08x pendingIFC=%08x pullOut=%08x guest_global=002ef7e8\n",
           current_ifc,pending_ifc,pull_out);
    uint32_t update_vtable=current_ifc && current_ifc+11u<GUEST_LIMIT?
        *(uint32_t *)(memory+current_ifc+7u):0;
    printf("TRACE active IFC subobject=%08x unaligned_vptr=%08x slots=%08x/%08x/%08x\n",
           current_ifc,update_vtable,
           update_vtable && update_vtable+12u<GUEST_LIMIT?*(uint32_t *)(memory+update_vtable+8u):0,
           update_vtable && update_vtable+16u<GUEST_LIMIT?*(uint32_t *)(memory+update_vtable+12u):0,
           update_vtable && update_vtable+8u<GUEST_LIMIT?*(uint32_t *)(memory+update_vtable+4u):0);
    if (current_ifc!=0x0035EAD8u || pending_ifc!=0u || pull_out!=0u) {
        fprintf(stderr,"original IFCTitle::PlugIn did not publish its active IFC subobject: current=%08x pending=%08x pullout=%08x expected_current=0035ead8\n",
                current_ifc,pending_ifc,pull_out); free(memory); return 36;
    }
    if (update_vtable!=0x002EC040u ||
        *(uint32_t *)(memory+update_vtable+8u)!=0x001FE700u) {
        fprintf(stderr,"IFCTitle original Update vtable slot mismatch: table=%08x slot+8=%08x\n",
                update_vtable, update_vtable?*(uint32_t *)(memory+update_vtable+8u):0);
        free(memory); return 37;
    }
    gw_recomp_context input_setup_context;
    uint32_t input_source_cell=0x002EEC9Cu;
    uint32_t input_source=*(uint32_t *)(memory+input_source_cell);
    if(!invoke(gw_original_setup_input_state_entry,&input_setup_context,
               0x94EC0u,memory,0,0) ||
       *(uint32_t *)(memory+0x002F1668u)!=0x002F1465u ||
       input_source>GUEST_LIMIT || 0x300u>GUEST_LIMIT-input_source ||
       memcmp(memory+0x002F166Cu,memory+input_source,0x300u)!=0) {
        fprintf(stderr,"original setup_game input-state block failed eax=%08x eip=%08x input=%08x copy=%u/%u\n",
                input_setup_context.eax,input_setup_context.eip,
                *(uint32_t *)(memory+0x002F1668u),
                input_source,
                input_setup_context.memory_fault.pending);
        free(memory); return 57;
    }
    printf("TRACE original setup_game input block eip=00094ec0..00094ef4 input_struct=002f1465 pointer_cell=002f1668 copied_state=002f166c..002f196b source_cell=%08x source=%08x bytes=768\n",
           input_source_cell,input_source);
    /* Resume the next exact setup_game block. Its own instructions copy the
       authentic main.pal pointer into 0x185E9C and call W?SetupColorLookups;
       the harness supplies no palette pointer or color-index values. */
    {
        gw_recomp_context color_context;
        uint32_t palette_cell=0x0035FE9Cu; /* link 0x185E9C + object-3 delta */
        uint32_t lookup_bytes=0x00360A4Cu; /* link 0x186A4C + object-3 delta */
        if(!in_guest(0x14u,original_main_palette_guest,768u,NULL) ||
           input_source!=original_main_palette_guest ||
           !invoke(gw_original_setup_game_color_lookups_entry,&color_context,
                   0x94EF5u,memory,0u,0u) ||
           color_context.memory_fault.pending || color_context.segment_fault_pending ||
           color_context.interrupt_trap_pending || color_context.port_io_trap.pending ||
           *(uint32_t *)(memory+palette_cell)!=original_main_palette_guest ||
           !in_guest(0x14u,lookup_bytes,8u,NULL)) {
            fprintf(stderr,"original setup_game color lookup block failed status=eip:%08x palette=%08x expected=%08x mem=%u/%08x seg=%u:%04x:%08x int=%u port=%u\n",
                color_context.eip,*(uint32_t *)(memory+palette_cell),original_main_palette_guest,
                color_context.memory_fault.pending,color_context.memory_fault.linear,
                color_context.segment_fault_pending,color_context.segment_fault_selector,
                color_context.segment_fault_instruction_va,color_context.interrupt_trap_pending,
                color_context.port_io_trap.pending);
            free(memory); return 131;
        }
        unsigned unique=0u;
        for(unsigned i=0;i<8u;i++) {
            int first=1;
            for(unsigned j=0;j<i;j++) if(memory[lookup_bytes+i]==memory[lookup_bytes+j]) first=0;
            unique+=(unsigned)first;
        }
        if(unique<2u) {
            fprintf(stderr,"original setup_game color lookup output is degenerate bytes=%02x,%02x,%02x,%02x,%02x,%02x,%02x,%02x\n",
                memory[lookup_bytes],memory[lookup_bytes+1],memory[lookup_bytes+2],memory[lookup_bytes+3],
                memory[lookup_bytes+4],memory[lookup_bytes+5],memory[lookup_bytes+6],memory[lookup_bytes+7]);
            free(memory); return 132;
        }
        printf("PASS original setup_game palette lookup block link=94EF5..94F08 target=W?SetupColorLookups@5B8C0 palette_ptr_cell=0035FE9C palette=%08x palette_bytes=768 output=00360A4C..00360A53 unique_indices=%u\n",
            original_main_palette_guest,unique);
    }
    /* Run setup_game's exact CPU-only 0x94F09..0x94F87 continuation. The
       slice includes the original call to setup_vecs_ and stops before the
       later table-building block that still needs separate analysis. */
    const uint32_t setup_vecs_base=0x002DA100u;
    const uint32_t vec_map_before=*(uint32_t *)(memory+setup_vecs_base+0x08u);
    const uint32_t vec_dither_before=*(uint32_t *)(memory+setup_vecs_base+0x1Cu);
    const uint32_t vec_dither_end_before=*(uint32_t *)(memory+setup_vecs_base+0x20u);
    gw_recomp_context vector_context={0};
    if(!invoke(gw_original_setup_game_vector_init_entry,&vector_context,
               0x94F09u,memory,0u,0u) ||
       vector_context.memory_fault.pending || vector_context.segment_fault_pending ||
       vector_context.interrupt_trap_pending || vector_context.port_io_trap.pending) {
        fprintf(stderr,"original setup_game setup_vecs block failed eip=%08x mem=%u/%08x seg=%u:%04x:%08x int=%u:%02x:%08x port=%u:%04x:%08x\n",
            vector_context.eip,vector_context.memory_fault.pending,vector_context.memory_fault.linear,
            vector_context.segment_fault_pending,vector_context.segment_fault_selector,
            vector_context.segment_fault_instruction_va,vector_context.interrupt_trap_pending,
            vector_context.interrupt_vector,vector_context.interrupt_instruction_va,
            vector_context.port_io_trap.pending,vector_context.port_io_trap.port,
            vector_context.port_io_trap.guest_va);
        free(memory); return 108;
    }
    const uint32_t vec_eax=*(uint32_t *)(memory+0x00376A5Cu);
    const uint32_t vec_ebx=*(uint32_t *)(memory+0x00376A78u);
    const uint32_t vec_edi=*(uint32_t *)(memory+0x00376A7Cu);
    if(*(uint32_t *)(memory+setup_vecs_base+0x10u)!=vec_ebx ||
       *(uint32_t *)(memory+setup_vecs_base+0x00u)!=vec_eax-vec_ebx ||
       *(uint32_t *)(memory+setup_vecs_base+0x04u)!=vec_eax ||
       *(uint32_t *)(memory+setup_vecs_base+0x08u)!=vec_map_before ||
       *(uint32_t *)(memory+setup_vecs_base+0x14u)!=vec_ebx ||
       *(uint32_t *)(memory+setup_vecs_base+0x1Cu)!=vec_dither_before ||
       *(uint32_t *)(memory+setup_vecs_base+0x20u)!=vec_dither_end_before ||
       *(uint32_t *)(memory+setup_vecs_base+0x18u)!=vec_edi ||
       !validate_dos_mcb_chain(memory,vfs.dos.dos_segment_end)) {
        fprintf(stderr,"original setup_game setup_vecs_ outputs differ from callsite registers EAX=%08x EBX=%08x EDI=%08x globals=%08x/%08x/%08x/%08x/%08x/%08x/%08x MCB=%d\n",
            vec_eax,vec_ebx,vec_edi,*(uint32_t *)(memory+setup_vecs_base),
            *(uint32_t *)(memory+setup_vecs_base+4u),*(uint32_t *)(memory+setup_vecs_base+8u),
            *(uint32_t *)(memory+setup_vecs_base+0x10u),*(uint32_t *)(memory+setup_vecs_base+0x18u),
            *(uint32_t *)(memory+setup_vecs_base+0x1Cu),*(uint32_t *)(memory+setup_vecs_base+0x20u),
            validate_dos_mcb_chain(memory,vfs.dos.dos_segment_end));
        free(memory); return 108;
    }
    printf("PASS original setup_game setup_vecs_ block link=94F09..94F87 inputs_EAX_EBX_EDX_ECX_stack=%08x/%08x/00000000/%08x/%08x outputs_poly_screen_vec_map_width_window_window_dither_end=%08x/%08x/%08x/%08x/%08x/%08x/%08x/%08x MCB_chain_valid=1\n",
        vec_eax,vec_ebx,vec_ebx,vec_edi,
        *(uint32_t *)(memory+setup_vecs_base),
        *(uint32_t *)(memory+setup_vecs_base+4u),
        *(uint32_t *)(memory+setup_vecs_base+8u),
        *(uint32_t *)(memory+setup_vecs_base+0x10u),
        *(uint32_t *)(memory+setup_vecs_base+0x14u),
        *(uint32_t *)(memory+setup_vecs_base+0x18u),
        *(uint32_t *)(memory+setup_vecs_base+0x1Cu),
        *(uint32_t *)(memory+setup_vecs_base+0x20u));
    /* Read-only view of the original UI manager inputs immediately before
       Update.  These addresses come from setup_game's stores and the 1.1
       MyGadgets global; this trace deliberately does not seed either one. */
    {
        const uint32_t input_cell=0x002F1668u; /* link 0x117668 + object-3 delta */
        const uint32_t gadgets_cell=0x00379490u; /* link 0x19F490 + object-3 delta */
        const uint32_t mode_index=0x002F1431u; /* link 0x117431 + object-3 delta */
        const uint32_t mode_table=0x002F1A3Cu; /* link 0x117A3C + object-3 delta */
        uint32_t input_ptr=*(uint32_t *)(memory+input_cell);
        uint32_t gadgets=*(uint32_t *)(memory+gadgets_cell);
        printf("TRACE original UI input cell=%08x ptr=%08x gadgets_cell=%08x gadgets=%08x\n",
               input_cell,input_ptr,gadgets_cell,gadgets);
        printf("TRACE original UI controller index=%u mode=%u lbMouse MXY=%d,%d XY=%d,%d buttons=left:%u mleft:%u right:%u mright:%u\n",
               *(uint8_t *)(memory+mode_index),
               *(uint8_t *)(memory+mode_table+*(uint8_t *)(memory+mode_index)*0x70Du),
               *(int32_t *)(memory+0x00376AA8u),*(int32_t *)(memory+0x00376AACu),
               *(int32_t *)(memory+0x00376AA0u),*(int32_t *)(memory+0x00376AA4u),
               *(uint8_t *)(memory+0x00376ABFu),*(uint8_t *)(memory+0x00376AC2u),
               *(uint8_t *)(memory+0x00376AC0u),*(uint8_t *)(memory+0x00376AC3u));
        if(input_ptr && input_ptr+12u<GUEST_LIMIT) {
            printf("TRACE original UI input bytes=");
            for(unsigned i=0;i<12u;i++) printf("%02x",memory[input_ptr+i]);
            printf(" x=%d y=%d state=%02x flags=%02x/%02x\n",
                   *(int16_t *)(memory+input_ptr),*(int16_t *)(memory+input_ptr+2u),
                   memory[input_ptr+4u],memory[input_ptr+8u],memory[input_ptr+9u]);
        }
        if(gadgets && gadgets+40u<GUEST_LIMIT) {
            for(unsigned i=0;i<24u;i++) {
                uint32_t p=gadgets+i*40u;
                if(p+40u>GUEST_LIMIT) break;
                uint32_t flags=*(uint32_t *)(memory+p);
                if(!flags) { printf("TRACE original UI gadget[%u] terminator=%08x\n",i,p); break; }
                printf("TRACE original UI gadget[%u] guest=%08x flags=%08x x=%d y=%d w=%d h=%d id=%d fn=%08x user=%08x help=%08x pressed=%u draw=%u\n",
                       i,p,flags,*(int16_t *)(memory+p+4u),*(int16_t *)(memory+p+6u),
                       *(int16_t *)(memory+p+8u),*(int16_t *)(memory+p+10u),
                       *(int16_t *)(memory+p+12u),*(uint32_t *)(memory+p+14u),
                       *(uint32_t *)(memory+p+30u),*(uint32_t *)(memory+p+34u),
                       memory[p+38u],memory[p+39u]);
            }
        }
    }
    gw_recomp_context controller_context;
    if(!invoke(gw_original_setup_controller_entry,&controller_context,
               0x5B170u,memory,0,0) ||
       *(uint32_t *)(memory+0x002F1668u)!=0x002F1465u) {
        fprintf(stderr,"original setup_controller failed eax=%08x eip=%08x input=%08x\n",
                controller_context.eax,controller_context.eip,
                *(uint32_t *)(memory+0x002F1668u)); free(memory); return 58;
    }
    printf("TRACE original setup_controller eip=0005b170 input=%08x x=%d y=%d mouse_flags=%02x/%02x mode=%u\n",
           *(uint32_t *)(memory+0x002F1668u),*(int16_t *)(memory+0x002F1465u),
           *(int16_t *)(memory+0x002F1467u),memory[0x002F146Du],memory[0x002F146Eu],
           *(uint8_t *)(memory+0x002F1A3Cu+*(uint8_t *)(memory+0x002F1431u)*0x70Du));
    uint8_t *update_before=(uint8_t *)malloc(GUEST_LIMIT);
    if(!update_before) { free(memory); return 38; }
    memcpy(update_before,memory,GUEST_LIMIT);
    uint32_t icalls_before=g_icall_count,trace_before=g_icall_trace_idx;
    gw_recomp_context update_context;
    int update_ok=invoke(gw_original_control_game_update_dispatch,&update_context,
                         0x5AF12u,memory,0,0);
    uint32_t update_changed=0,update_first=0,update_last=0,update_write_unexpected=0;
    FILE *update_diff=fopen("evidence/native_ifctitle_update_memory_diff.json","wb");
    if(update_diff) fputs("{\"changes\":[",update_diff);
    for(uint32_t i=0;i<GUEST_LIMIT;i++) if(update_before[i]!=memory[i]) {
        if(!update_changed) update_first=i;
        update_last=i; update_changed++;
        if(!((i>=0x002DA000u && i<0x00382C50u) ||
             (i>=STACK_TOP-0x3000u && i<GUEST_LIMIT))) update_write_unexpected++;
        if(update_diff) fprintf(update_diff,"%s{\"guest\":\"0x%08x\",\"before\":%u,\"after\":%u}",
                                update_changed==1?"":",",i,update_before[i],memory[i]);
    }
    if(update_diff) { fprintf(update_diff,"],\"changed_bytes\":%u}\n",update_changed); fclose(update_diff); }
    free(update_before);
    printf("TRACE original Update dispatch entry=0x5AF12 slot=+8 thunk=0x13700 method=0x70EB0 "
           "ok=%d eip=%08x eax=%08x flag_cf=%08x esp=%08x indirect_delta=%u targets=%08x/%08x guest_writes=%u unexpected_writes=%u range=%08x..%08x\n",
           update_ok,update_context.eip,update_context.eax,update_context.flag_cf,
           update_context.esp,g_icall_count-icalls_before,
           g_icall_trace[trace_before & (ICALL_TRACE_SIZE-1)],
           g_icall_trace[(trace_before+1u) & (ICALL_TRACE_SIZE-1)],update_changed,update_write_unexpected,
           update_changed?update_first:0,update_changed?update_last:0);
    if(!update_ok || update_context.esp!=STACK_TOP+4u || update_context.memory_fault.pending ||
       update_context.segment_fault_pending || update_context.interrupt_trap_pending ||
       update_context.port_io_trap.pending || g_icall_count-icalls_before!=2u ||
       update_write_unexpected!=0u ||
       g_icall_trace[trace_before & (ICALL_TRACE_SIZE-1)]!=0x001FE700u ||
       g_icall_trace[(trace_before+1u) & (ICALL_TRACE_SIZE-1)]!=0x00070EB0u) {
        fprintf(stderr,"authentic IFCTitle::Update did not return cleanly through original thunk: eip=%08x esp=%08x fault=%u/%08x icalls=%u trap=%u\n",
                update_context.eip,update_context.esp,update_context.memory_fault.pending,
                update_context.memory_fault.linear,g_icall_count-icalls_before,
                update_context.port_io_trap.pending);
        free(memory); return 39;
    }
    /* The standalone OPTIONS regression still exercises TITLE -> OPTIONS ->
       TITLE. The gameplay continuation has its own coverage, so begin from
       the already initialized original TITLE and avoid repeating that route. */
    if(!gameplay_continue) {
    if(SDL_Init(SDL_INIT_VIDEO)!=0) { fprintf(stderr,"SDL input Init: %s\n",SDL_GetError()); free(memory); return 59; }
    sdl_input_initialized=1;
    const int option_host_x=626,option_host_y=528; /* logical (313,264), center of original gadget id 3 */
    if(!push_sdl_motion(option_host_x,option_host_y)) { fprintf(stderr,"SDL_PushEvent motion failed: %s\n",SDL_GetError()); free(memory); return 60; }
    unsigned evcount=poll_sdl_into_lbdisplay(memory);
    if(evcount!=1u || !original_ui_cycle(memory,"hover-options",evcount)) { free(memory); return 61; }
    if(!push_sdl_button(SDL_MOUSEBUTTONDOWN,option_host_x,option_host_y)) { fprintf(stderr,"SDL_PushEvent down failed: %s\n",SDL_GetError()); free(memory); return 62; }
    evcount=poll_sdl_into_lbdisplay(memory);
    if(evcount!=1u || !original_ui_cycle(memory,"mouse-down-options",evcount)) { free(memory); return 63; }
    if(!push_sdl_button(SDL_MOUSEBUTTONUP,option_host_x,option_host_y)) { fprintf(stderr,"SDL_PushEvent up failed: %s\n",SDL_GetError()); free(memory); return 64; }
    evcount=poll_sdl_into_lbdisplay(memory);
    if(evcount!=1u || !original_ui_cycle(memory,"mouse-up-options",evcount)) { free(memory); return 65; }
    if(!original_ui_cycle(memory,"post-release-options",0u)) { free(memory); return 66; }
    if(*(uint32_t *)(memory+0x002EF7ECu)!=0x00360034u ||
       *(uint32_t *)(memory+0x002EF7F0u)!=0x0035EAD8u) {
        fprintf(stderr,"original OPCIONES action did not publish expected pending/pullout interfaces pending=%08x pullout=%08x current=%08x\n",
            *(uint32_t *)(memory+0x002EF7ECu),*(uint32_t *)(memory+0x002EF7F0u),
            *(uint32_t *)(memory+0x002EF7E8u)); free(memory); return 67;
    }
    uint32_t options_vptr=*(uint32_t *)(memory+0x00360034u+7u);
    uint32_t options_slot0=(options_vptr && options_vptr+4u<GUEST_LIMIT)?
        *(uint32_t *)(memory+options_vptr):0u;
    printf("TRACE original pending-interface object=00360034 vptr_at_plus7=%08x slot0=%08x currentIFC=%08x current_vptr=%08x\n",
        options_vptr,options_slot0,*(uint32_t *)(memory+0x002EF7E8u),
        *(uint32_t *)(memory+*(uint32_t *)(memory+0x002EF7F0u)+7u));
    printf("PASS original IFCTitle::Update recognized OPCIONES id=3 and published pendingIFC=00360034 pullOutIFC=0035ead8; current= %08x\n",
        *(uint32_t *)(memory+0x002EF7E8u));
    SDL_Quit(); sdl_input_initialized=0;
    if(*(uint32_t *)(memory+update_vtable+12u)!=0x001FE6F0u) {
        fprintf(stderr,"IFCTitle original Draw vtable slot mismatch: table=%08x slot+12=%08x\n",
                update_vtable,*(uint32_t *)(memory+update_vtable+12u));
        free(memory); return 40;
    }
    const uint32_t palette_record=TITLE_LIST+44u;
    const uint32_t palette_cell=*(uint32_t *)(memory+palette_record+28u);
    const uint32_t palette_guest=palette_cell && palette_cell+4u<GUEST_LIMIT?
        *(uint32_t *)(memory+palette_cell):0u;
    if(strcmp((char *)(memory+palette_record),"data/titlescr.pal") ||
       *(uint32_t *)(memory+palette_record+36u)!=768u || palette_guest<FLAT_HEAP_BEGIN ||
       palette_guest>GUEST_LIMIT || 768u>GUEST_LIMIT-palette_guest) {
        fprintf(stderr,"original PlugIn palette record is invalid: cell=%08x guest=%08x size=%u\n",
                palette_cell,palette_guest,*(uint32_t *)(memory+palette_record+36u));
        free(memory); return 47;
    }
    printf("TRACE title palette resource loaded by original PlugIn source=%08x bytes=768; DAC updates remain on original setup/game path\n",
           palette_guest);
    uint8_t *draw_before=(uint8_t *)malloc(GUEST_LIMIT);
    if(!draw_before) { free(memory); return 41; }
    memcpy(draw_before,memory,GUEST_LIMIT);
    uint32_t dac_index_before_draw=vga_dac_index_writes;
    uint32_t dac_components_before_draw=vga_dac_component_writes;
    icalls_before=g_icall_count; trace_before=g_icall_trace_idx;
    gw_recomp_context draw_context;
    int draw_ok=invoke(gw_original_draw_game_draw_dispatch,&draw_context,
                       0x83559u,memory,0,0);
    uint32_t wscreen=*(uint32_t *)(memory+0x00376A5Cu);
    if(!wscreen || wscreen>GUEST_LIMIT || 0x4B000u>GUEST_LIMIT-wscreen ||
       *(uint32_t *)(memory+0x00376A78u)!=640u || *(uint32_t *)(memory+0x00376A7Cu)!=480u) {
        fprintf(stderr,"experimental WScreen surface is not bounded 640x480x8: ptr=%08x wh=%u/%u\n",
                wscreen,*(uint32_t *)(memory+0x00376A78u),*(uint32_t *)(memory+0x00376A7Cu));
        free(draw_before); free(memory); return 44;
    }
    uint32_t draw_changed=0,draw_first=0,draw_last=0,draw_unexpected=0;
    uint32_t draw_bscreen_changed=0,draw_video_changed=0,draw_wscreen_changed=0;
    FILE *draw_diff=fopen("evidence/native_ifctitle_draw_memory_diff.json","wb");
    if(draw_diff) fputs("{\"changes\":[",draw_diff);
    for(uint32_t i=0;i<GUEST_LIMIT;i++) if(draw_before[i]!=memory[i]) {
        if(!draw_changed) draw_first=i;
        draw_last=i; draw_changed++;
        int in_object=(i>=0x002DA000u && i<0x00382C50u);
        int in_stack=(i>=STACK_TOP-0x3000u && i<GUEST_LIMIT);
        int in_bscreen=(i>=bscreen && i<bscreen+0x4B000u);
        int in_video=(i>=0x00090000u && i<0x000DB000u);
        int in_wscreen=(i>=wscreen && i<wscreen+0x4B000u);
        if(!in_object && !in_stack && !in_bscreen && !in_video && !in_wscreen) draw_unexpected++;
        if(in_bscreen) draw_bscreen_changed++;
        if(in_video) draw_video_changed++;
        if(in_wscreen) draw_wscreen_changed++;
        if(draw_diff) fprintf(draw_diff,"%s{\"guest\":\"0x%08x\",\"before\":%u,\"after\":%u}",
                              draw_changed==1?"":",",i,draw_before[i],memory[i]);
    }
    if(draw_diff) { fprintf(draw_diff,"],\"changed_bytes\":%u}\n",draw_changed); fclose(draw_diff); }
    free(draw_before);
    printf("TRACE original Draw dispatch entry=0x83559 slot=+12 thunk=0x136F0 method=0x710B0 "
           "ok=%d eip=%08x eax=%08x esp=%08x indirect_delta=%u guest_writes=%u bscreen_writes=%u wscreen_writes=%u video_writes=%u "
           "unexpected_writes=%u range=%08x..%08x deferred=%u/%u/%u palette_writes=%u/%u\n",
           draw_ok,draw_context.eip,draw_context.eax,draw_context.esp,
           g_icall_count-icalls_before,draw_changed,draw_bscreen_changed,draw_wscreen_changed,draw_video_changed,
           draw_unexpected,draw_changed?draw_first:0,draw_changed?draw_last:0,
           g_deferred_draw_sites[0],g_deferred_draw_sites[1],g_deferred_draw_sites[2],
           vga_dac_index_writes-dac_index_before_draw,
           vga_dac_component_writes-dac_components_before_draw);
    if(!draw_ok || draw_context.esp!=STACK_TOP+4u || draw_context.memory_fault.pending ||
       draw_context.segment_fault_pending || draw_context.interrupt_trap_pending ||
       draw_context.port_io_trap.pending || draw_unexpected ||
       g_deferred_draw_sites[0] || g_deferred_draw_sites[1] || g_deferred_draw_sites[2] ||
       g_icall_count-icalls_before<2u ||
       g_icall_trace[trace_before & (ICALL_TRACE_SIZE-1)]!=0x001FE6F0u ||
       g_icall_trace[(trace_before+1u) & (ICALL_TRACE_SIZE-1)]!=0x000710B0u) {
        fprintf(stderr,"authentic IFCTitle::Draw did not return cleanly through original thunk: eip=%08x esp=%08x fault=%u/%08x seg=%u int=%u port=%u icalls=%u unexpected=%u deferred=%u/%u/%u\n",
                draw_context.eip,draw_context.esp,draw_context.memory_fault.pending,
                draw_context.memory_fault.linear,draw_context.segment_fault_pending,
                draw_context.interrupt_trap_pending,draw_context.port_io_trap.pending,
                g_icall_count-icalls_before,draw_unexpected,g_deferred_draw_sites[0],
                g_deferred_draw_sites[1],g_deferred_draw_sites[2]);
        free(memory); return 42;
    }
    if(draw_wscreen_changed==0) {
        fprintf(stderr,"original Draw dispatch returned without changing experimental WScreen guest surface\n");
        free(memory); return 43;
    }
    FILE *wscreen_out=fopen("evidence/native_ifctitle_draw_wscreen.raw","wb");
    FILE *palette_out=fopen("evidence/native_ifctitle_draw_palette6.raw","wb");
    FILE *palette_source_out=fopen("evidence/native_ifctitle_draw_palette_source.raw","wb");
    if(!wscreen_out || fwrite(memory+wscreen,1,0x4B000u,wscreen_out)!=0x4B000u ||
       !palette_out || fwrite(vga_dac,1,sizeof vga_dac,palette_out)!=sizeof vga_dac ||
       !palette_source_out || !original_main_palette_guest ||
       fwrite(memory+original_main_palette_guest,1,768u,palette_source_out)!=768u) {
        if(wscreen_out) fclose(wscreen_out); if(palette_out) fclose(palette_out);
        if(palette_source_out) fclose(palette_source_out);
        fprintf(stderr,"failed to preserve original Draw surface/palette capture\n"); free(memory); return 45;
    }
    fclose(wscreen_out); fclose(palette_out); fclose(palette_source_out);
    if(!present_draw_sdl(memory+wscreen,vga_dac,
                         "GeneWars 1.1 — IFCTitle::Draw (aislado)",
                         "evidence/native_ifctitle_draw_sdl.bmp")) {
        fprintf(stderr,"original Draw WScreen bytes could not be presented/captured through SDL\n");
        free(memory); return 46;
    }
    uint32_t start=*(uint32_t *)(memory+start_cell);
    uint32_t length=*(uint32_t *)(memory+record+36u);
    /* The titleGfx_files record's +32 field is not a verified end-pointer
       cell. The authenticated loader checks above validate each published
       start pointer and byte count; only the TEXT.DAT record has a verified
       start/end pair in this fixture. */
    if(vfs.opens==0 || vfs.reads==0 || vfs.closes==0 ||
       !start || length!=0xE349u || start<FLAT_HEAP_BEGIN || start+length>GUEST_LIMIT) {
        fprintf(stderr,"loaded record mismatch path='%s' io=%u/%u/%u start=%08x length=%u\n",
                vfs.last_path,vfs.opens,vfs.reads,vfs.closes,start,length); free(memory); return 14;
    }
    static const char *resource_names[]={"data/iftitle.anb","data/titlescr.pal","data/font2.dat","data/font2.tab"};
    for (unsigned i=0;i<4u;i++) {
        uint32_t r=TITLE_LIST+i*44u, cell=*(uint32_t *)(memory+r+28u);
        uint32_t ptr=cell?*(uint32_t *)(memory+cell):0;
        uint32_t bytes=*(uint32_t *)(memory+r+36u);
        if (strcmp((char *)(memory+r),resource_names[i]) || !ptr || !bytes ||
            ptr<FLAT_HEAP_BEGIN || ptr>GUEST_LIMIT || bytes>GUEST_LIMIT-ptr) {
            fprintf(stderr,"PlugIn title resource[%u] was not committed by the original loader: name='%s' cell=%08x ptr=%08x bytes=%u\n",
                    i,(char *)(memory+r),cell,ptr,bytes); free(memory); return 27;
        }
        printf("TRACE title_resource[%u] path=%s guest=%08x bytes=%u\n",i,resource_names[i],ptr,bytes);
    }
    FILE *out=fopen("work\\lbdataload_iftitle.bin","wb");
    if(!out || fwrite(memory+start,1,length,out)!=length) { if(out) fclose(out); free(memory); return 15; }
    fclose(out);
    /* Keep the decoder's differential scratch separate from setup_game's live
     * heap. The original allocator can legitimately occupy the old fixed
     * RNC_SOURCE address once the BIOINTRO prefix has run. */
    if(RNC_SOURCE+30050u>GUEST_LIMIT || RNC_OUT+length>GUEST_LIMIT ||
       RNC_INPLACE+length>GUEST_LIMIT) { free(memory); return 16; }
    uint8_t *rnc_test=(uint8_t *)malloc(GUEST_LIMIT);
    if(!rnc_test) { free(memory); return 16; }
    memcpy(rnc_test,memory,GUEST_LIMIT);
    FILE *rnc_capture=fopen("work\\lbdataload_compressed_capture.bin","rb");
    if(!rnc_capture || fread(rnc_test+RNC_SOURCE,1u,30050u,rnc_capture)!=30050u ||
       fgetc(rnc_capture)!=EOF) {
        if(rnc_capture) fclose(rnc_capture); free(rnc_test); free(memory); return 16;
    }
    fclose(rnc_capture);
    memset(rnc_test+RNC_OUT-16u,0xA5,16u);
    memset(rnc_test+RNC_OUT+length,0x5A,16u);
    uint8_t *saved_guest_memory=guest_memory;
    ptrdiff_t saved_mem_base=g_mem_base;
    guest_memory=rnc_test; g_mem_base=(ptrdiff_t)(uintptr_t)rnc_test;
    if(!invoke(gw_partial_UnpackM1,&c,0xB9CFCu,rnc_test,RNC_SOURCE,RNC_OUT) || c.eax!=length) {
        fprintf(stderr,"out-of-place original RNC decode failed eax=%08x eip=%08x mem=%u/%08x\n",
                c.eax,c.eip,c.memory_fault.pending,c.memory_fault.linear);
        guest_memory=saved_guest_memory; g_mem_base=saved_mem_base; free(rnc_test); free(memory); return 17;
    }
    out=fopen("work\\lbdataload_rnc_out_of_place.bin","wb");
    if(!out || fwrite(rnc_test+RNC_OUT,1,length,out)!=length) {
        if(out) fclose(out); guest_memory=saved_guest_memory; g_mem_base=saved_mem_base;
        free(rnc_test); free(memory); return 18;
    }
    fclose(out);
    memcpy(rnc_test+RNC_INPLACE,rnc_test+RNC_SOURCE,30050u);
    if(!invoke(gw_partial_UnpackM1,&c,0xB9CFCu,rnc_test,RNC_INPLACE,RNC_INPLACE) || c.eax!=length) {
        fprintf(stderr,"in-place original RNC decode failed eax=%08x eip=%08x mem=%u/%08x\n",
                c.eax,c.eip,c.memory_fault.pending,c.memory_fault.linear);
        guest_memory=saved_guest_memory; g_mem_base=saved_mem_base; free(rnc_test); free(memory); return 19;
    }
    out=fopen("work\\lbdataload_rnc_in_place.bin","wb");
    if(!out || fwrite(rnc_test+RNC_INPLACE,1,length,out)!=length) {
        if(out) fclose(out); guest_memory=saved_guest_memory; g_mem_base=saved_mem_base;
        free(rnc_test); free(memory); return 20;
    }
    fclose(out);
    guest_memory=saved_guest_memory; g_mem_base=saved_mem_base; free(rnc_test);
    printf("TRACE RNC differential: source=%08x expanded=%08x bytes; manager=%08x out_of_place=%08x in_place=%08x\n",
           RNC_SOURCE,length,start,RNC_OUT,RNC_INPLACE);
    printf("TRACE original FUN_97E9C -> UnpackM1 args EAX=%08x ECX=%08x EDX=%08x; expected source=dest=%08x\n",
           rnc_call_eax,rnc_call_ecx,rnc_call_edx,start);
    printf("PASS original LbMemorySetup_ experimental budget=%08x blocks; original callback initializer installed %08x\n",
           GUEST_LIMIT,*(uint32_t *)(memory+0x2E4804u));
    printf("PASS original init -> IFCTitle::PlugIn 0x70D10 -> LbDataLoadAll_ 0x15090 -> LbDataLoad_ 0x14FF0 loaded %s through DOS/VFS: opens=%u reads=%u closes=%u start=%08x bytes=%u\n",
           vfs.last_path,vfs.opens,vfs.reads,vfs.closes,start,length);
    if (vfs.title_screen_reads!=4u || vfs.title_screen_bytes!=139413u ||
        title_rnc_calls!=1u || title_rnc_eax!=bscreen || title_rnc_ecx!=bscreen ||
        title_rnc_edx!=bscreen || !guest_path_has_suffix(vfs.last_path,"data/titlescr.dat") ||
        *(uint8_t *)(memory+0x002F165Cu)!=2u) {
        fprintf(stderr,"original PlugIn did not read TITLESCR.DAT through VFS: path=%s reads=%u bytes=%u denied=%u\n",
                vfs.last_path,vfs.title_screen_reads,vfs.title_screen_bytes,vfs.denied);
        free(memory); return 34;
    }
    for (unsigned i=0;i<vfs.title_screen_reads && i<4u;i++)
        printf("TRACE titlescr DOS AH=3F[%u] AX=%08x BX=%08x CX=%08x DX=%08x file+%08lx request=%u done=%u guest=%08x\n",
            i,vfs.title_dos_ax[i],vfs.title_dos_bx[i],vfs.title_dos_cx[i],vfs.title_dos_dx[i],
            vfs.title_read_pos[i],vfs.title_read_requested[i],vfs.title_read_done[i],vfs.title_read_guest[i]);
    FILE *screen_out=fopen("work\\ifctitle_plugin_bscreen.raw","wb");
    if (!screen_out || fwrite(memory+bscreen,1,0x4B000u,screen_out)!=0x4B000u) {
        if (screen_out) fclose(screen_out); free(memory); return 35;
    }
    fclose(screen_out);
    printf("PASS complete original IFCTitle::PlugIn 0x70D10..0x70E2C: LbDataLoadAll + LbFileLoadAt loaded and decoded TITLESCR.DAT; b_screen=%08x bytes=%u payload_bytes=%u DOS_reads=%u state=%u\n",
           bscreen,0x4B000u,vfs.title_screen_bytes-8u,vfs.title_screen_reads,
           *(uint8_t *)(memory+0x002F165Cu));
    printf("TRACE b_screen guest global: link=00114CA0 object3_delta=001DA000 guest=002EECA0 value=%08x\n",bscreen);
    trace_guest_heap_covering(bscreen,"after_IFCTitle_PlugIn_resource_loads");
    printf("TRACE allocations: DOS_AH4A=%u failures=%u AH_ED=%u indirect_calls=%u\n",
           dos_4a_calls,dos_4a_failures,dos_ed_calls,g_icall_count);
    for (unsigned i=0;i<vfs.reads && i<8u;i++)
        printf("TRACE read[%u] file+%08lx requested=%u done=%u guest=%08x\n",
               i,vfs.read_pos[i],vfs.read_requested[i],vfs.read_done[i],vfs.read_guest[i]);
    /* Run the exact game() pending-interface block after every TITLE capture
       has been saved. PullOut is original code; the pending slot remains
       deliberately unmapped so dispatch must stop at the fail-closed boundary. */
    {
        const uint32_t current=*(uint32_t *)(memory+0x002EF7F0u);
        const uint32_t pending=*(uint32_t *)(memory+0x002EF7ECu);
        if(current!=0x0035EAD8u || pending!=0x00360034u || current<4u || pending<4u) {
            fprintf(stderr,"transition fixture changed before original game() block current=%08x pending=%08x\n",current,pending);
            free(memory); return 68;
        }
        const uint32_t current_adjust=*(uint32_t *)(memory+current-4u);
        const uint32_t pending_adjust=*(uint32_t *)(memory+pending-4u);
        const uint32_t current_vptr=*(uint32_t *)(memory+current+7u);
        const uint32_t pending_vptr=*(uint32_t *)(memory+pending+7u);
        if(current_vptr+8u>=GUEST_LIMIT || pending_vptr+4u>=GUEST_LIMIT) {
            fprintf(stderr,"transition vtable pointer leaves guest backing current_vptr=%08x pending_vptr=%08x\n",
                    current_vptr,pending_vptr); free(memory); return 69;
        }
        const uint32_t pullout_target=*(uint32_t *)(memory+current_vptr+4u);
        const uint32_t plugin_target=*(uint32_t *)(memory+pending_vptr);
        if(pullout_target!=0x001FE710u || plugin_target!=0x001FE620u ||
           current-current_adjust!=0x0035EAB8u || pending_adjust!=0x130u ||
           pending-pending_adjust!=0x0035FF04u || pending_vptr!=0x002EBFE0u) {
            fprintf(stderr,"original IFC subobject/thunk map mismatch this=%08x delta=%08x top=%08x vptr=%08x pullout=%08x pending=%08x delta=%08x vptr=%08x plugin=%08x\n",
                    current,current_adjust,current-current_adjust,current_vptr,pullout_target,
                    pending,pending_adjust,pending_vptr,plugin_target); free(memory); return 70;
        }
        printf("TRACE original IFC ABI current_this=%08x adjustment=%08x complete_object=%08x vptr=%08x PullOut_thunk=%08x pending_this=%08x adjustment=%08x complete_object=%08x vptr=%08x PlugIn_thunk=%08x\n",
               current,current_adjust,current-current_adjust,current_vptr,pullout_target,
               pending,pending_adjust,pending-pending_adjust,pending_vptr,plugin_target);
        trace_resource_records(memory,0x002DFE58u,"before_OPTIONS_PlugIn");
        uint8_t *before=(uint8_t *)malloc(GUEST_LIMIT);
        if(!before) { free(memory); return 71; }
        memcpy(before,memory,GUEST_LIMIT);
        const uint32_t current_ifc_before=*(uint32_t *)(before+0x002EF7E8u);
        uint32_t calls_at=g_icall_count;
        uint32_t dac_read_index_at=vga_dac_read_index_writes;
        uint32_t dac_read_components_at=vga_dac_component_reads;
        uint32_t retrace_reads_at=vga_retrace_status_reads;
        gw_recomp_context transition_context;
        fprintf(stderr,"TRACE low-write transition-window=begin\n");
        int transition_ok=invoke(gw_original_game_interface_transition_entry,&transition_context,
                                 0x92819u,memory,0,0);
        gw_mcb_watch_disarm("LbMemorySetup_to_TITLE_OPTIONS");
        fprintf(stderr,"TRACE low-write transition-window=end\n");
        fprintf(stderr,"TRACE original stderr bytes=%u text=\"%.*s\" hex=",vfs.stderr_capture_size,
                (int)vfs.stderr_capture_size,(const char *)vfs.stderr_capture);
        for(uint32_t j=0;j<vfs.stderr_capture_size;j++) fprintf(stderr,"%02x",vfs.stderr_capture[j]);
        fputc('\n',stderr);
        fprintf(stderr,"TRACE original stdout bytes=%u text=\"%.*s\" hex=",vfs.stdout_capture_size,
                (int)vfs.stdout_capture_size,(const char *)vfs.stdout_capture);
        for(uint32_t j=0;j<vfs.stdout_capture_size;j++) fprintf(stderr,"%02x",vfs.stdout_capture[j]);
        fputc('\n',stderr);
        trace_resource_records(memory,0x002DFE58u,"after_OPTIONS_PlugIn");
        uint32_t unexpected=0,changed=0,first=0,last=0,first_unexpected=0,last_unexpected=0;
        for(uint32_t i=0;i<GUEST_LIMIT;i++) if(before[i]!=memory[i]) {
            if(!changed) first=i; last=i; changed++;
            int allowed=(i>=0x00090000u && i<0x000B0000u) ||
                        (i>=0x002DA000u && i<0x00382C50u) ||
                        (i>=0x00390000u && i<0x003FD000u) ||
                        (i>=STACK_TOP-0x3000u && i<GUEST_LIMIT) ||
                        (i>=0x01000000u && i<GUEST_LIMIT);
            /* DOS owns only the live MCB extents recorded by the provider.
               Include their corresponding 16-byte MCB headers; do not make
               all low memory writable to silence the integrity report. */
            for(uint32_t b=0;b<vfs.dos.dos_block_count && !allowed;b++) {
                uint32_t data_begin=(uint32_t)vfs.dos.dos_blocks[b].segment<<4;
                uint32_t data_end=(uint32_t)(vfs.dos.dos_blocks[b].segment+
                    vfs.dos.dos_blocks[b].paragraphs)<<4;
                uint32_t mcb_begin=data_begin>=16u?data_begin-16u:0u;
                if((i>=data_begin && i<data_end) || (i>=mcb_begin && i<mcb_begin+16u))
                    allowed=1;
            }
            if(!allowed) { if(!unexpected) first_unexpected=i; last_unexpected=i; unexpected++; }
        }
        const gw_port_io_trap transition_trap=transition_context.port_io_trap;
        const uint32_t pending_after=*(uint32_t *)(memory+0x002EF7ECu);
        const uint32_t current_ifc_after=*(uint32_t *)(memory+0x002EF7E8u);
        const uint32_t pullout_after=*(uint32_t *)(memory+0x002EF7F0u);
        printf("TRACE original game() transition block entry=00092819 result=%d trap=%u reason=%u unresolved=%08x trap_eip=%08x indirect_calls=%u vtable_targets=%08x/%08x changed=%u unexpected=%u range=%08x..%08x unexpected_range=%08x..%08x currentIFC_before=%08x currentIFC_after=%08x pullOut=%08x pending=%08x files=%u/%u/%u denied=%u missing_save_slots=%u save_slots=%u/%u/%u/%u/%u/%u/%u last='%s' memfault=%u:%08x segmentfault=%u:%04x:%08x portfault=%u:%u:%08x\n",
               transition_ok,transition_trap.pending,transition_trap.reason,
               transition_trap.value,transition_trap.guest_va,g_icall_count-calls_at,
               pullout_target,plugin_target,
               changed,unexpected,changed?first:0,changed?last:0,
               unexpected?first_unexpected:0,unexpected?last_unexpected:0,
               current_ifc_before,current_ifc_after,pullout_after,pending_after,
               vfs.opens,vfs.reads,vfs.closes,vfs.denied,vfs.missing_save_slots,
               vfs.save_slot_open_attempts[0],vfs.save_slot_open_attempts[1],
               vfs.save_slot_open_attempts[2],vfs.save_slot_open_attempts[3],
               vfs.save_slot_open_attempts[4],vfs.save_slot_open_attempts[5],
               vfs.save_slot_open_attempts[6],vfs.last_path,
               transition_context.memory_fault.pending,transition_context.memory_fault.linear,
               transition_context.segment_fault_pending,transition_context.segment_fault_selector,
               transition_context.segment_fault_instruction_va,transition_context.port_io_trap.pending,
               transition_context.port_io_trap.reason,transition_context.port_io_trap.value);
        if(unexpected && first_unexpected<GUEST_LIMIT) {
            uint32_t end=last_unexpected<GUEST_LIMIT?last_unexpected: GUEST_LIMIT-1u;
            if(end-first_unexpected>64u) end=first_unexpected+64u;
            fprintf(stderr,"TRACE original unexpected-memory bytes guest=%08x..%08x before/after=",
                    first_unexpected,end);
            for(uint32_t j=first_unexpected;j<=end;j++) fprintf(stderr,"%02x/%02x",before?before[j]:0u,memory[j]);
            fputc('\n',stderr);
        }
        free(before);
        printf("TRACE original PullOut VGA palette snapshot DAC_read_index_writes=%u DAC_component_reads=%u\n",
               vga_dac_read_index_writes-dac_read_index_at,
               vga_dac_component_reads-dac_read_components_at);
        printf("TRACE original PullOut VGA retrace wait status_reads=%u status_bit3=active_profile\n",
               vga_retrace_status_reads-retrace_reads_at);
        if(!transition_ok || transition_trap.pending ||
           g_icall_count-calls_at<2u ||
           vga_dac_read_index_writes-dac_read_index_at!=1u ||
           vga_dac_component_reads-dac_read_components_at!=768u ||
           vga_retrace_status_reads-retrace_reads_at==0u ||
           pending_after!=0u || current_ifc_after==current_ifc_before ||
           current_ifc_after==0u || vfs.denied || unexpected) {
            fprintf(stderr,"original OPTIONS PlugIn returned and currentIFC changed, but transition integrity checks failed; see guest-low-write trace\n");
            free(memory); return 72;
        }
        printf("PASS original game() transition executed IFCTitle::PullOut, original adjustment thunk 0x13620, and IFCOptions::PlugIn 0x6A3D0; pending request cleared\n");
        const uint32_t options_this=current_ifc_after;
        const uint32_t options_vptr=(options_this+7u<GUEST_LIMIT)?*(uint32_t *)(memory+options_this+7u):0u;
        {
            unsigned nonzero=0; uint32_t sum=0,distinct=0; uint8_t seen[256]={0};
            for(unsigned i=0;i<sizeof vga_dac;i++) { nonzero+=vga_dac[i]!=0; sum+=vga_dac[i]; }
            for(unsigned i=0;i<sizeof vga_dac;i++) if(!seen[vga_dac[i]]) { seen[vga_dac[i]]=1; distinct++; }
            printf("TRACE OPTIONS palette-after-PullOut-and-PlugIn nonzero=%u sum=%u distinct_components=%u\n",nonzero,sum,distinct);
        }
        {
            const uint32_t cell=0x00379490u, gadgets=*(uint32_t *)(memory+cell);
            printf("TRACE OPTIONS active-gadgets cell=%08x base=%08x stride=40\n",cell,gadgets);
            if(gadgets && gadgets+40u<GUEST_LIMIT) for(unsigned i=0;i<24u;i++) {
                uint32_t p=gadgets+i*40u; if(p+40u>GUEST_LIMIT) break;
                uint32_t flags=*(uint32_t *)(memory+p);
                if(!flags) { printf("TRACE OPTIONS gadget[%u] terminator=%08x\n",i,p); break; }
                printf("TRACE OPTIONS gadget[%u] guest=%08x flags=%08x x=%d y=%d w=%d h=%d id=%d fn=%08x user=%08x help=%08x pressed=%u draw=%u\n",
                    i,p,flags,*(int16_t *)(memory+p+4u),*(int16_t *)(memory+p+6u),
                    *(int16_t *)(memory+p+8u),*(int16_t *)(memory+p+10u),
                    *(int16_t *)(memory+p+12u),*(uint32_t *)(memory+p+14u),
                    *(uint32_t *)(memory+p+30u),*(uint32_t *)(memory+p+34u),
                    memory[p+38u],memory[p+39u]);
            }
        }
        if(!options_vptr || options_vptr+20u>=GUEST_LIMIT) {
            fprintf(stderr,"OPTIONS vtable is outside guest backing after original PlugIn: this=%08x vptr=%08x\n",
                    options_this,options_vptr); free(memory); return 80;
        }
        printf("TRACE original OPTIONS vtable after PlugIn this=%08x vptr=%08x slots=%08x/%08x/%08x/%08x/%08x\n",
               options_this,options_vptr,
               *(uint32_t *)(memory+options_vptr),*(uint32_t *)(memory+options_vptr+4u),
               *(uint32_t *)(memory+options_vptr+8u),*(uint32_t *)(memory+options_vptr+12u),
               *(uint32_t *)(memory+options_vptr+16u));
        if(options_this!=0x00360034u || options_vptr!=0x002EBFE0u ||
           *(uint32_t *)(memory+options_vptr)!=0x001FE620u ||
           *(uint32_t *)(memory+options_vptr+4u)!=0x001FE610u ||
           *(uint32_t *)(memory+options_vptr+8u)!=0x001FE600u ||
           *(uint32_t *)(memory+options_vptr+12u)!=0x001FE5F0u) {
            fprintf(stderr,"original OPTIONS vtable slots differ from the verified 1.1 thunk sequence\n");
            free(memory); return 81;
        }

        uint8_t *options_before=(uint8_t *)malloc(GUEST_LIMIT);
        if(!options_before) { free(memory); return 82; }
        memcpy(options_before,memory,GUEST_LIMIT);
        uint32_t options_icalls=g_icall_count,options_trace=g_icall_trace_idx;
        gw_recomp_context options_update_context;
        int options_update_ok=invoke(gw_original_control_game_update_dispatch,
            &options_update_context,0x5AF12u,memory,0,0);
        uint32_t update_changed=0,update_unexpected=0,update_first=0,update_last=0;
        for(uint32_t i=0;i<GUEST_LIMIT;i++) if(options_before[i]!=memory[i]) {
            if(!update_changed) update_first=i; update_last=i; update_changed++;
            int allowed=(i>=0x00090000u && i<0x000B0000u) ||
                        (i>=0x002DA000u && i<0x00382C50u) ||
                        (i>=0x00390000u && i<0x003FD000u) ||
                        (i>=STACK_TOP-0x3000u && i<GUEST_LIMIT) ||
                        (i>=0x01000000u && i<GUEST_LIMIT);
            for(uint32_t b=0;b<vfs.dos.dos_block_count && !allowed;b++) {
                uint32_t begin=(uint32_t)vfs.dos.dos_blocks[b].segment<<4;
                uint32_t end=(uint32_t)(vfs.dos.dos_blocks[b].segment+
                    vfs.dos.dos_blocks[b].paragraphs)<<4;
                uint32_t mcb=begin>=16u?begin-16u:0u;
                if((i>=begin && i<end) || (i>=mcb && i<mcb+16u)) allowed=1;
            }
            if(!allowed) update_unexpected++;
        }
        free(options_before);
        printf("TRACE original IFCOptions::Update dispatch=control_game@0x5AF12 thunk=0x13600 method=0x6AB30 ok=%d eip=%08x eax=%08x esp=%08x icalls=%u targets=%08x/%08x guest_writes=%u unexpected=%u range=%08x..%08x current=%08x pending=%08x\n",
            options_update_ok,options_update_context.eip,options_update_context.eax,
            options_update_context.esp,g_icall_count-options_icalls,
            g_icall_trace[options_trace&(ICALL_TRACE_SIZE-1)],
            g_icall_trace[(options_trace+1u)&(ICALL_TRACE_SIZE-1)],update_changed,
            update_unexpected,update_changed?update_first:0,update_changed?update_last:0,
            *(uint32_t *)(memory+0x002EF7E8u),*(uint32_t *)(memory+0x002EF7ECu));
        if(!options_update_ok || options_update_context.eip!=0x5AF12u ||
           options_update_context.esp!=STACK_TOP+4u ||
           options_update_context.memory_fault.pending ||
           options_update_context.segment_fault_pending ||
           options_update_context.interrupt_trap_pending ||
           options_update_context.port_io_trap.pending || update_unexpected ||
           g_icall_count-options_icalls<2u ||
           g_icall_trace[options_trace&(ICALL_TRACE_SIZE-1)]!=0x001FE600u ||
           g_icall_trace[(options_trace+1u)&(ICALL_TRACE_SIZE-1)]!=0x0006AB30u ||
           *(uint32_t *)(memory+0x002EF7E8u)!=options_this ||
           *(uint32_t *)(memory+0x002EF7ECu)!=0u) {
            fprintf(stderr,"original IFCOptions::Update failed clean virtual dispatch or memory bounds\n");
            free(memory); return 83;
        }
        printf("PASS original IFCOptions::Update executed through the game control dispatcher with no user event\n");

        options_before=(uint8_t *)malloc(GUEST_LIMIT);
        if(!options_before) { free(memory); return 84; }
        memcpy(options_before,memory,GUEST_LIMIT);
        options_icalls=g_icall_count; options_trace=g_icall_trace_idx;
        uint32_t dac_index_before_options=vga_dac_index_writes;
        uint32_t dac_components_before_options=vga_dac_component_writes;
        gw_recomp_context options_draw_context;
        int options_draw_ok=invoke(gw_original_draw_game_draw_dispatch,
            &options_draw_context,0x83559u,memory,0,0);
        const uint32_t options_wscreen=*(uint32_t *)(memory+0x00376A5Cu);
        if(!options_wscreen || options_wscreen>GUEST_LIMIT ||
           0x4B000u>GUEST_LIMIT-options_wscreen ||
           *(uint32_t *)(memory+0x00376A78u)!=640u ||
           *(uint32_t *)(memory+0x00376A7Cu)!=480u) {
            free(options_before); free(memory);
            fprintf(stderr,"OPTIONS Draw has no bounded WScreen surface\n"); return 85;
        }
        uint32_t draw_changed=0,draw_unexpected=0,draw_writes=0,draw_first=0,draw_last=0;
        for(uint32_t i=0;i<GUEST_LIMIT;i++) if(options_before[i]!=memory[i]) {
            if(!draw_changed) draw_first=i; draw_last=i; draw_changed++;
            int in_object=(i>=0x002DA000u && i<0x00382C50u);
            int in_stack=(i>=STACK_TOP-0x3000u && i<GUEST_LIMIT);
            int in_surface=(i>=options_wscreen && i<options_wscreen+0x4B000u);
            int in_video=(i>=0x00090000u && i<0x000DB000u);
            if(!in_object && !in_stack && !in_surface && !in_video &&
               !(i>=0x01000000u && i<GUEST_LIMIT) &&
               !guest_address_in_live_mcb(i)) draw_unexpected++;
            if(in_surface) draw_writes++;
        }
        free(options_before);
        printf("TRACE original IFCOptions::Draw dispatch=draw_game@0x83559 thunk=0x135F0 method=0x6A700 ok=%d eip=%08x eax=%08x esp=%08x icalls=%u targets=%08x/%08x surface=%08x guest_writes=%u WScreen_writes=%u unexpected=%u range=%08x..%08x palette=%u/%u\n",
            options_draw_ok,options_draw_context.eip,options_draw_context.eax,
            options_draw_context.esp,g_icall_count-options_icalls,
            g_icall_trace[options_trace&(ICALL_TRACE_SIZE-1)],
            g_icall_trace[(options_trace+1u)&(ICALL_TRACE_SIZE-1)],options_wscreen,draw_changed,
            draw_writes,draw_unexpected,draw_changed?draw_first:0,draw_changed?draw_last:0,
            vga_dac_index_writes-dac_index_before_options,
            vga_dac_component_writes-dac_components_before_options);
        if(!options_draw_ok || options_draw_context.eip!=0x83559u ||
           options_draw_context.esp!=STACK_TOP+4u ||
           options_draw_context.memory_fault.pending ||
           options_draw_context.segment_fault_pending ||
           options_draw_context.interrupt_trap_pending ||
           options_draw_context.port_io_trap.pending || draw_unexpected || !draw_writes ||
           g_icall_count-options_icalls<2u ||
           g_icall_trace[options_trace&(ICALL_TRACE_SIZE-1)]!=0x001FE5F0u ||
           g_icall_trace[(options_trace+1u)&(ICALL_TRACE_SIZE-1)]!=0x0006A700u) {
            fprintf(stderr,"original IFCOptions::Draw failed clean dispatch, surface writes, or bounds check\n");
            free(memory); return 86;
        }
        FILE *options_raw=fopen("evidence/native_ifcoptions_draw_wscreen.raw","wb");
        if(!options_raw || fwrite(memory+options_wscreen,1,0x4B000u,options_raw)!=0x4B000u) {
            if(options_raw) fclose(options_raw); free(memory);
            fprintf(stderr,"could not preserve IFCOptions WScreen capture\n"); return 87;
        }
        fclose(options_raw);
        FILE *options_palette=fopen("evidence/native_ifcoptions_draw_palette6.raw","wb");
        if(!options_palette || fwrite(vga_dac,1,sizeof vga_dac,options_palette)!=sizeof vga_dac) {
            if(options_palette) fclose(options_palette); free(memory);
            fprintf(stderr,"could not preserve post-OPTIONS VGA DAC palette\n"); return 89;
        }
        fclose(options_palette);
        if(!present_draw_sdl(memory+options_wscreen,vga_dac,
            "GeneWars 1.1 — IFCOptions::Draw (aislado)",
            "evidence/native_ifcoptions_draw_sdl.bmp")) {
            free(memory); fprintf(stderr,"SDL could not present original IFCOptions Draw surface\n"); return 88;
        }
        printf("PASS original IFCOptions::Draw wrote %u bytes in WScreen and its SDL capture is saved\n",draw_writes);

        /* Use the live 1.1 gadget published by OPTIONS::PlugIn. Gadget 9 is
           the return control; its bounds and ID were read from guest memory,
           and all input state changes below pass through SDL -> lbDisplay ->
           original setup_controller -> original virtual Update. */
        const uint32_t options_gads=*(uint32_t *)(memory+0x00379490u);
        const uint32_t return_gadget=options_gads+9u*40u;
        if(!options_gads || return_gadget+40u>GUEST_LIMIT ||
           *(int16_t *)(memory+return_gadget+12u)!=9 ||
           !(*(uint32_t *)(memory+return_gadget)&0x00010000u)) {
            fprintf(stderr,"live OPTIONS return gadget 9 is missing or disabled: base=%08x id=%d flags=%08x\n",
                options_gads,options_gads&&return_gadget+40u<=GUEST_LIMIT?*(int16_t *)(memory+return_gadget+12u):-1,
                options_gads&&return_gadget+40u<=GUEST_LIMIT?*(uint32_t *)(memory+return_gadget):0u);
            free(memory); return 90;
        }
        const int return_x=*(int16_t *)(memory+return_gadget+4u)+*(int16_t *)(memory+return_gadget+8u)/2;
        const int return_y=*(int16_t *)(memory+return_gadget+6u)+*(int16_t *)(memory+return_gadget+10u)/2;
        const int return_hx=return_x*2,return_hy=return_y*2;
        if(!sdl_input_initialized) {
            if(SDL_Init(SDL_INIT_VIDEO)!=0) {
                fprintf(stderr,"SDL reinitialization before original OPTIONS input failed: %s\n",SDL_GetError());
                free(memory); return 91;
            }
            sdl_input_initialized=1;
        }
        if(!push_sdl_motion(return_hx,return_hy) ||
           poll_sdl_into_lbdisplay(memory)!=1u ||
           !original_interface_ui_cycle(memory,"options-return-hover",1u,9u) ||
           !push_sdl_button(SDL_MOUSEBUTTONDOWN,return_hx,return_hy) ||
           poll_sdl_into_lbdisplay(memory)!=1u ||
           !original_interface_ui_cycle(memory,"options-return-down",1u,9u) ||
           !push_sdl_button(SDL_MOUSEBUTTONUP,return_hx,return_hy) ||
           poll_sdl_into_lbdisplay(memory)!=1u ||
           !original_interface_ui_cycle(memory,"options-return-up",1u,9u)) {
            fprintf(stderr,"original OPTIONS return click sequence failed\n"); free(memory); return 91;
        }
        if(*(uint32_t *)(memory+0x002EF7E8u)!=options_this ||
           *(uint32_t *)(memory+0x002EF7ECu)!=0x0035EAD8u ||
           *(uint32_t *)(memory+0x002EF7F0u)!=options_this) {
            fprintf(stderr,"original OPTIONS Update did not request TITLE: current=%08x pending=%08x pullOut=%08x\n",
                *(uint32_t *)(memory+0x002EF7E8u),*(uint32_t *)(memory+0x002EF7ECu),
                *(uint32_t *)(memory+0x002EF7F0u)); free(memory); return 92;
        }
        uint8_t *return_before=(uint8_t *)malloc(GUEST_LIMIT);
        if(!return_before) { free(memory); return 93; }
        memcpy(return_before,memory,GUEST_LIMIT);
        const uint32_t return_calls=g_icall_count,return_trace=g_icall_trace_idx;
        gw_recomp_context return_context;
        g_transition_dispatch_count=0u; g_transition_dispatch_enabled=1;
        int return_ok=invoke(gw_original_game_interface_transition_entry,&return_context,
            0x92819u,memory,0,0);
        g_transition_dispatch_enabled=0;
        uint32_t return_unexpected=0,return_changed=0;
        for(uint32_t i=0;i<GUEST_LIMIT;i++) if(return_before[i]!=memory[i]) {
            return_changed++;
            int allowed=(i>=0x00090000u&&i<0x000B0000u) ||
                        (i>=0x002DA000u&&i<0x00382C50u) ||
                        (i>=0x00390000u&&i<0x003FD000u) ||
                        (i>=STACK_TOP-0x3000u&&i<GUEST_LIMIT) ||
                        (i>=0x01000000u&&i<GUEST_LIMIT);
            for(uint32_t b=0;b<vfs.dos.dos_block_count&&!allowed;b++) {
                uint32_t begin=(uint32_t)vfs.dos.dos_blocks[b].segment<<4;
                uint32_t end=(uint32_t)(vfs.dos.dos_blocks[b].segment+
                    vfs.dos.dos_blocks[b].paragraphs)<<4;
                uint32_t mcb=begin>=16u?begin-16u:0u;
                if((i>=begin&&i<end)||(i>=mcb&&i<mcb+16u)) allowed=1;
            }
            if(!allowed) return_unexpected++;
        }
        free(return_before);
        const uint32_t title_after_return=*(uint32_t *)(memory+0x002EF7E8u);
        printf("TRACE OPTIONS->TITLE original game() block ok=%d eip=%08x esp=%08x calls=%u targets=%08x/%08x/%08x/%08x stages=%u/%u/%u/%u current=%08x pending=%08x pullOut=%08x changed=%u unexpected=%u\n",
            return_ok,return_context.eip,return_context.esp,g_icall_count-return_calls,
            g_transition_dispatch_count>0?g_transition_dispatch[0].target:0u,
            g_transition_dispatch_count>1?g_transition_dispatch[1].target:0u,
            g_transition_dispatch_count>2?g_transition_dispatch[2].target:0u,
            g_transition_dispatch_count>3?g_transition_dispatch[3].target:0u,
            g_transition_dispatch_count>0?g_transition_dispatch[0].stage:0u,
            g_transition_dispatch_count>1?g_transition_dispatch[1].stage:0u,
            g_transition_dispatch_count>2?g_transition_dispatch[2].stage:0u,
            g_transition_dispatch_count>3?g_transition_dispatch[3].stage:0u,title_after_return,
            *(uint32_t *)(memory+0x002EF7ECu),*(uint32_t *)(memory+0x002EF7F0u),return_changed,return_unexpected);
        if(!return_ok || return_context.eip!=0x92819u || return_context.esp!=STACK_TOP+4u ||
           return_context.memory_fault.pending || return_context.segment_fault_pending ||
           return_context.interrupt_trap_pending || return_context.port_io_trap.pending ||
           return_unexpected || g_icall_count-return_calls<4u || g_transition_dispatch_count!=4u ||
           g_transition_dispatch[0].stage!=1u || g_transition_dispatch[0].target!=0x001FE610u ||
           g_transition_dispatch[1].stage!=2u || g_transition_dispatch[1].target!=0x0006A600u ||
           g_transition_dispatch[2].stage!=3u || g_transition_dispatch[2].target!=0x001FE720u ||
           g_transition_dispatch[3].stage!=4u || g_transition_dispatch[3].target!=0x00070D10u ||
           title_after_return!=0x0035EAD8u || *(uint32_t *)(memory+0x002EF7ECu)!=0u ||
           *(uint32_t *)(memory+0x002EF7F0u)!=options_this) {
            fprintf(stderr,"original game() did not complete OPTIONS PullOut -> TITLE PlugIn cleanly\n");
            free(memory); return 94;
        }
        printf("PASS original game() completed OPTIONS PullOut 0x6A600 and dispatched TITLE PlugIn 0x70D10\n");

        /* titleGfx_files is the original LE-fixed list at link VA 0x105EE8,
           mapped to guest linear 0x2DFEE8. 0x2DFE58 is the separate
           FILESCR list populated by IFCOptions::PlugIn. */
        const uint32_t title_palette_record=0x002DFEE8u+44u;
        trace_resource_records(memory,0x002DFEE8u,"after_return_TITLE_PlugIn");
        const uint32_t title_palette_cell=*(uint32_t *)(memory+title_palette_record+28u);
        const uint32_t title_palette=title_palette_cell&&title_palette_cell+4u<GUEST_LIMIT?
            *(uint32_t *)(memory+title_palette_cell):0u;
        if(strcmp((char *)(memory+title_palette_record),"data/titlescr.pal") ||
           *(uint32_t *)(memory+title_palette_record+36u)!=768u || !title_palette ||
           title_palette>GUEST_LIMIT || 768u>GUEST_LIMIT-title_palette) {
            fprintf(stderr,"returned TITLE PlugIn palette record invalid: record=%08x name='%.*s' cell=%08x value=%08x packed=%u unpacked=%u\n",
                title_palette_record,28,(char *)(memory+title_palette_record),title_palette_cell,title_palette,
                *(uint32_t *)(memory+title_palette_record+32u),*(uint32_t *)(memory+title_palette_record+36u));
            free(memory); return 95;
        }
        printf("TRACE returned TITLE palette loaded by original PlugIn at %08x; harness leaves DAC under original game control\n",
               title_palette);
        gw_recomp_context returned_title_update,returned_title_draw;
        if(!invoke(gw_original_control_game_update_dispatch,&returned_title_update,0x5AF12u,memory,0,0) ||
           !invoke(gw_original_draw_game_draw_dispatch,&returned_title_draw,0x83559u,memory,0,0) ||
           returned_title_update.eip!=0x5AF12u || returned_title_draw.eip!=0x83559u) {
            fprintf(stderr,"returned original TITLE Update/Draw did not complete\n"); free(memory); return 97;
        }
        const uint32_t returned_wscreen=*(uint32_t *)(memory+0x00376A5Cu);
        FILE *returned_raw=fopen("evidence/native_ifcoptions_return_title_wscreen.raw","wb");
        FILE *returned_palette=fopen("evidence/native_ifcoptions_return_title_palette6.raw","wb");
        if(!returned_raw || fwrite(memory+returned_wscreen,1,0x4B000u,returned_raw)!=0x4B000u ||
           !returned_palette || fwrite(vga_dac,1,sizeof vga_dac,returned_palette)!=sizeof vga_dac) {
            if(returned_raw) fclose(returned_raw); if(returned_palette) fclose(returned_palette);
            free(memory); fprintf(stderr,"could not preserve returned TITLE frame\n"); return 98;
        }
        fclose(returned_raw); fclose(returned_palette);
        if(!present_draw_sdl(memory+returned_wscreen,vga_dac,
           "GeneWars 1.1 — original TITLE after OPTIONS return",
           "evidence/native_ifcoptions_return_title_sdl.bmp")) {
            free(memory); fprintf(stderr,"SDL could not present the returned original TITLE frame\n"); return 99;
        }
        printf("PASS returned TITLE original Update/Draw and palette output saved; WScreen=%08x\n",returned_wscreen);

    }
    }
    if(!(memory[intro_gate_guest]&1u)) {
        fprintf(stderr,"original setup_game BIOINTRO availability gate was lost before TITLE input: flags=%02x\n",
            memory[intro_gate_guest]);
        free(memory); return 103;
    }
    if(!gameplay_continue) {
        printf("TRACE returned TITLE state source=original OPTIONS->TITLE game() transition after authentic setup_game prefix; BIOINTRO gate link=00117662 guest=%08x value=%02x\n",
            intro_gate_guest,memory[intro_gate_guest]);
    } else {
        printf("TRACE gameplay fast path skips the separately covered OPTIONS roundtrip; setup_game left original TITLE active current=%08x BIOINTRO=%02x\n",
            *(uint32_t *)(memory+0x002EF7E8u),memory[intro_gate_guest]);
    }

        /* Continue from the original live TITLE gadget list. Click the
           observed id=0 control (“UN JUGADOR”) through the same device and
           virtual-method path; stop at its natural pending interface. */
        const uint32_t title_gads=*(uint32_t *)(memory+0x00379490u);
        const uint32_t new_game=title_gads;
        if(!title_gads || new_game+40u>GUEST_LIMIT || *(int16_t *)(memory+new_game+12u)!=0) {
            fprintf(stderr,"returned TITLE did not publish the original id=0 gadget\n"); free(memory); return 100;
        }
        const int new_x=*(int16_t *)(memory+new_game+4u)+*(int16_t *)(memory+new_game+8u)/2;
        const int new_y=*(int16_t *)(memory+new_game+6u)+*(int16_t *)(memory+new_game+10u)/2;
        const int new_hx=new_x*2,new_hy=new_y*2;
        /* present_draw_sdl closes SDL after writing the BMP. Reopen its input
           event queue before driving the original title controller. */
        if(!sdl_input_initialized && SDL_Init(SDL_INIT_VIDEO)!=0) {
            fprintf(stderr,"SDL reinitialization before original UN JUGADOR input failed: %s\n",SDL_GetError());
            free(memory); return 101;
        }
        sdl_input_initialized=1;
        printf("TRACE original UN JUGADOR gadget guest=%08x id=%d bounds=%d,%d..%d,%d center=%d,%d\n",
            new_game,*(int16_t *)(memory+new_game+12u),
            *(int16_t *)(memory+new_game+4u),*(int16_t *)(memory+new_game+6u),
            *(int16_t *)(memory+new_game+4u)+*(int16_t *)(memory+new_game+8u),
            *(int16_t *)(memory+new_game+6u)+*(int16_t *)(memory+new_game+10u),new_x,new_y);
        gw_recomp_trace_set_enabled(1);
        gw_recomp_trace_set_boundary_stop(1);
        gw_recomp_trace_watch_branch(0x00070EEDu);
        if(!push_sdl_motion(new_hx,new_hy) || poll_sdl_into_lbdisplay(memory)!=1u ||
           !original_interface_ui_cycle(memory,"title-new-game-hover",1u,0u) ||
           !push_sdl_button(SDL_MOUSEBUTTONDOWN,new_hx,new_hy) || poll_sdl_into_lbdisplay(memory)!=1u ||
           !original_interface_ui_cycle(memory,"title-new-game-down",1u,0u) ||
           !push_sdl_button(SDL_MOUSEBUTTONUP,new_hx,new_hy) || poll_sdl_into_lbdisplay(memory)!=1u ||
           !original_interface_ui_cycle(memory,"title-new-game-up",1u,0u)) {
            gw_recomp_trace_watch_branch(0u);
            if(gw_recomp_trace_boundary_hit()) {
                printf("PASS original New Game input reached the authentic exit_ callsite; harness stopped before executing exit_/__FiniRtns, link_callsite=00070f05 intro_gate=00117662 value=%02x main/filescr had been loaded through original VFS\n",
                    memory[intro_gate_guest]);
                gw_dos_descriptor_clear(&vfs.dos); gw_interrupt_set_callback(NULL,NULL);
                free(vfs.manifest); free(memory); return 0;
            }
            fprintf(stderr,"original UN JUGADOR input sequence failed\n"); free(memory); return 101;
        }
        gw_recomp_trace_watch_branch(0u);
        /* Preserve a targeted branch watch at 0x70EED through all three SDL
           input cycles; the call ring then confirms 0x70F05/exit_ was skipped. */
        gw_recomp_trace_checkpoint(0x00070F0Fu,0x00070EB0u);
        const uint32_t next_ifc=*(uint32_t *)(memory+0x002EF7ECu);
        const uint32_t next_vptr=next_ifc&&next_ifc+11u<GUEST_LIMIT?*(uint32_t *)(memory+next_ifc+7u):0u;
        printf("TRACE original UN JUGADOR request current=%08x pending=%08x pullOut=%08x next_vptr=%08x plugin=%08x pullout=%08x update=%08x draw=%08x\n",
            *(uint32_t *)(memory+0x002EF7E8u),next_ifc,*(uint32_t *)(memory+0x002EF7F0u),next_vptr,
            next_vptr&&next_vptr+16u<GUEST_LIMIT?*(uint32_t *)(memory+next_vptr):0u,
            next_vptr&&next_vptr+16u<GUEST_LIMIT?*(uint32_t *)(memory+next_vptr+4u):0u,
            next_vptr&&next_vptr+16u<GUEST_LIMIT?*(uint32_t *)(memory+next_vptr+8u):0u,
            next_vptr&&next_vptr+16u<GUEST_LIMIT?*(uint32_t *)(memory+next_vptr+12u):0u);
        if(next_ifc==0u) {
            fprintf(stderr,"original UN JUGADOR click did not request a new interface\n"); free(memory); return 102;
        }
        const uint32_t level_current=*(uint32_t *)(memory+0x002EF7E8u);
        const uint32_t level_vptr=next_ifc+7u<GUEST_LIMIT?*(uint32_t *)(memory+next_ifc+7u):0u;
        const uint32_t level_complete=0x003609F1u;
        if(next_ifc!=0x00360A11u || level_current!=0x0035EAD8u ||
           level_vptr!=0x002EBAD4u || next_ifc!=level_complete+0x20u ||
           level_vptr+32u>=GUEST_LIMIT) {
            fprintf(stderr,"New Game pending IFCLevel object/subobject mismatch current=%08x pending=%08x complete=%08x vptr=%08x\n",
                level_current,next_ifc,level_complete,level_vptr); free(memory); return 102;
        }
        const uint32_t level_slots[8]={0x00206650u,0x00206640u,0x00206630u,0x00206620u,
            0x00200710u,0x00200CF0u,0x002027C0u,0x002029F0u};
        for(unsigned i=0;i<8u;i++) if(*(uint32_t *)(memory+level_vptr+i*4u)!=level_slots[i]) {
            fprintf(stderr,"original IFCLevel vtable slot %u mismatch got=%08x expected=%08x\n",
                i,*(uint32_t *)(memory+level_vptr+i*4u),level_slots[i]); free(memory); return 102;
        }
        printf("TRACE original IFCLevel object link=001869F1 guest=%08x interface_subobject=+20 pending=%08x vptr=%08x fixup_slots=8 PlugIn/PullOut/Update/Draw=%08x/%08x/%08x/%08x\n",
            level_complete,next_ifc,level_vptr,level_slots[0],level_slots[1],level_slots[2],level_slots[3]);
        printf("PASS original TITLE::Update accepted UN JUGADOR through SDL and published constructor-initialized IFCLevel subobject %08x\n",next_ifc);

        /* Execute the exact original game() transition block against the
           fixup-backed IFCLevel vtable; no target is added to the dispatcher
           unless its original LE body was lifted above. */
        uint8_t *level_before=(uint8_t *)malloc(GUEST_LIMIT);
        low_write_last_eip=(uint32_t *)calloc(LOW_WRITE_CAPTURE_LIMIT,sizeof(*low_write_last_eip));
        low_write_live_mcb=(uint8_t *)calloc(LOW_WRITE_CAPTURE_LIMIT,sizeof(*low_write_live_mcb));
        low_write_kind=(uint8_t *)calloc(LOW_WRITE_CAPTURE_LIMIT,sizeof(*low_write_kind));
        low_write_source=(uint16_t *)calloc(LOW_WRITE_CAPTURE_LIMIT,sizeof(*low_write_source));
        if(!level_before || !low_write_last_eip || !low_write_live_mcb || !low_write_kind || !low_write_source) {
            free(level_before); free(low_write_last_eip); free(low_write_live_mcb); free(low_write_kind); free(low_write_source);
            low_write_last_eip=NULL; low_write_live_mcb=NULL; low_write_kind=NULL; low_write_source=NULL; free(memory); return 104;
        }
        memcpy(level_before,memory,GUEST_LIMIT);
        low_write_capture_events=0u; low_write_source_count=0u;
        memset(low_write_sources,0,sizeof low_write_sources); low_write_capture_enabled=1;
        set_guest_write_observer(capture_guest_low_write,NULL);
        trace_guest_heap_covering(*(uint32_t *)(memory+0x002EECA0u),"immediately_before_TITLE_to_IFCLevel_transition");
        trace_resource_records(memory,0x002DAE58u,"before_IFCLevel_PlugIn_level_data");
        const uint32_t bda_ticks_before=*(uint32_t *)(memory+0x46Cu);
        const uint8_t bda_midnight_before=memory[0x470u];
        g_transition_dispatch_count=0u; g_transition_dispatch_enabled=1;
        gw_recomp_context level_transition_context;
        uint32_t smack_draw_cb_before=*(uint32_t *)(memory+0x0037A29Cu);
        uint32_t smack_alloc_before=*(uint32_t *)(memory+0x002E54DCu);
        uint32_t smack_free_before=*(uint32_t *)(memory+0x002E54E0u);
        /* Bound this new native path independently from CRT startup. The
           generated instruction hook returns through original call frames
           once this ceiling is reached, preserving the last original EIP. */
        /* Keep the native replay bounded, but allow the original Smacker
         * frame loop to consume the 110M-instruction budget recorded by the
         * Python driver instead of truncating it at the stale 25M cap. */
        startup_budget_remaining=110000000u; startup_budget_executed=0u;
        startup_budget_last_va=0u; startup_budget_last_func=0u;
        startup_budget_exhausted=0;
        int level_transition_ok=invoke(gw_original_game_interface_transition_entry,
            &level_transition_context,0x92819u,memory,0,0);
        low_write_capture_enabled=0;
        set_guest_write_observer(NULL,NULL);
        startup_budget_remaining=0u;
        g_transition_dispatch_enabled=0;
        trace_guest_heap_covering(*(uint32_t *)(memory+0x002EECA0u),"immediately_after_IFCLevel_PlugIn_before_Draw");
        trace_resource_records(memory,0x002DAE58u,"after_IFCLevel_PlugIn_level_data");
        fprintf(stderr,"TRACE live Smacker callbacks before=%08x/%08x/%08x after=%08x/%08x/%08x slots=smack_draw_callback/RADMALLOC/RADFREE\n",
            smack_draw_cb_before,smack_alloc_before,smack_free_before,
            *(uint32_t *)(memory+0x0037A29Cu),*(uint32_t *)(memory+0x002E54DCu),
            *(uint32_t *)(memory+0x002E54E0u));
        fprintf(stderr,"TRACE SYSTEM1 VFS summary reads=%u eof_reads=%u last_offset=%08lx last_request=%u last_done=%u\n",
            vfs.system1_reads,vfs.system1_eof_reads,vfs.system1_last_offset,
            vfs.system1_last_requested,vfs.system1_last_done);
        if(startup_budget_exhausted) {
            fprintf(stderr,"TRACE bounded IFCLevel replay instruction_budget=%llu last_eip=%08x current_func=%08x esp=%08x icalls=%u\n",
                (unsigned long long)startup_budget_executed,startup_budget_last_va,
                startup_budget_last_func,level_transition_context.esp,g_icall_count);
        }
        uint32_t level_unexpected=0,level_first_unexpected=0,level_last_unexpected=0;
        uint32_t level_unexpected_samples=0;
        uint32_t transition_delta_count[7]={0},transition_delta_first[7],transition_delta_last[7];
        for(unsigned c=0;c<7u;c++) transition_delta_first[c]=transition_delta_last[c]=0xFFFFFFFFu;
        for(uint32_t i=0;i<GUEST_LIMIT;i++) if(level_before[i]!=memory[i]) {
            unsigned category=6u;
            if(i>=0x46Cu && i<0x471u) category=0u;
            else if(i>=0x002DA000u && i<0x00382C50u) category=3u;
            else if(i>=STACK_TOP-0x3000u && i<GUEST_LIMIT) category=5u;
            else {
                for(uint32_t b=0;b<vfs.dos.dos_block_count;b++) {
                    uint32_t begin=(uint32_t)vfs.dos.dos_blocks[b].segment<<4;
                    uint32_t end=(uint32_t)(vfs.dos.dos_blocks[b].segment+
                        vfs.dos.dos_blocks[b].paragraphs)<<4;
                    uint32_t mcb=begin>=16u?begin-16u:0u;
                    if((i>=begin && i<end) || (i>=mcb && i<mcb+16u)) { category=1u; break; }
                }
                if(category==6u) for(uint32_t a=0;a<GW_DOS_MAX_LINEAR_ALLOCATIONS;a++) {
                    const gw_dos_linear_allocation *allocation=&vfs.dos.linear_allocations[a];
                    if(allocation->active && i>=allocation->base &&
                       (uint64_t)i<(uint64_t)allocation->base+allocation->size) { category=2u; break; }
                }
                if(category==6u && i<0x000B0000u) {
                    if(i<LOW_WRITE_CAPTURE_LIMIT && low_write_last_eip[i] && low_write_live_mcb[i])
                        category=1u;
                    else category=4u;
                }
            }
            transition_delta_count[category]++;
            if(transition_delta_first[category]==0xFFFFFFFFu) transition_delta_first[category]=i;
            transition_delta_last[category]=i;
            int allowed=(i>=0x0000046Cu && i<0x00000471u) ||
                        (i>=0x00090000u && i<0x000B0000u) ||
                        (i>=0x002DA000u && i<0x00382C50u) ||
                        (i>=0x00390000u && i<0x003FD000u) ||
                        (i>=STACK_TOP-0x3000u && i<GUEST_LIMIT) ||
                        (i>=0x01000000u && i<GUEST_LIMIT);
            for(uint32_t b=0;b<vfs.dos.dos_block_count && !allowed;b++) {
                uint32_t begin=(uint32_t)vfs.dos.dos_blocks[b].segment<<4;
                uint32_t end=(uint32_t)(vfs.dos.dos_blocks[b].segment+
                    vfs.dos.dos_blocks[b].paragraphs)<<4;
                uint32_t mcb=begin>=16u?begin-16u:0u;
                if((i>=begin && i<end) || (i>=mcb && i<mcb+16u)) allowed=1;
            }
            if(!allowed && i<LOW_WRITE_CAPTURE_LIMIT && low_write_last_eip[i] &&
               low_write_live_mcb[i]) allowed=1;
            if(!allowed) {
                if(!level_unexpected) level_first_unexpected=i;
                level_last_unexpected=i; level_unexpected++;
                if(level_unexpected_samples<48u) {
                    fprintf(stderr,"TRACE unclassified guest delta addr=%08x before=%02x after=%02x\n",
                        i,level_before[i],memory[i]);
                    level_unexpected_samples++;
                }
            }
        }
        fprintf(stderr,"TRACE IFCLevel transition changed-byte regions BDA=%u DOS_MCB_or_blocks=%u DPMI_live=%u object3_DATA_BSS=%u low_unbacked=%u guest_stack=%u other=%u\n",
            transition_delta_count[0],transition_delta_count[1],transition_delta_count[2],
            transition_delta_count[3],transition_delta_count[4],transition_delta_count[5],transition_delta_count[6]);
        for(unsigned c=0;c<7u;c++) if(transition_delta_count[c])
            fprintf(stderr,"TRACE IFCLevel transition changed-byte-region[%u] range=%08x..%08x count=%u\n",
                c,transition_delta_first[c],transition_delta_last[c],transition_delta_count[c]);
        int final_mcb_valid=validate_dos_mcb_chain(memory,vfs.dos.dos_segment_end);
        FILE *low_audit=fopen("evidence/native_ifclevel_low_write_audit.json","wb");
        uint32_t low_audit_rows=0,low_audit_bytes=0,low_audit_no_writer=0,low_audit_not_live=0;
        uint32_t low_audit_expected_bda=0,low_audit_unexpected=0;
        if(low_audit) fprintf(low_audit,"{\"schema\":\"gw-ifclevel-low-write-audit/v4\",\"target_sha256\":\"2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f\",\"capture_events\":%u,\"initial_mcb_chain_valid\":%s,\"final_mcb_chain_valid\":%s,\"writer_kinds\":{\"none\":0,\"guest_store\":1,\"dos_file_read\":2},\"sources\":[",low_write_capture_events,initial_mcb_chain_valid?"true":"false",final_mcb_valid?"true":"false");
        if(low_audit) for(uint16_t source=1u;source<=low_write_source_count;source++) {
            char json_path[128]; size_t n=strlen(low_write_sources[source-1u]);
            if(n>=sizeof json_path)n=sizeof json_path-1u;
            for(size_t k=0;k<n;k++) json_path[k]=low_write_sources[source-1u][k]=='\\'?'/' : low_write_sources[source-1u][k];
            json_path[n]=0;
            fprintf(low_audit,"%s{\"id\":%u,\"path\":\"%s\"}",source==1u?"":",",source,json_path);
        }
        if(low_audit) fputs("],\"ranges\":[",low_audit);
        for(uint32_t i=0;i<0x00090000u;) {
            if(level_before[i]==memory[i]) { i++; continue; }
            uint32_t site=(i<LOW_WRITE_CAPTURE_LIMIT)?low_write_last_eip[i]:0u;
            uint8_t live=(i<LOW_WRITE_CAPTURE_LIMIT)?low_write_live_mcb[i]:0u;
            uint8_t kind=(i<LOW_WRITE_CAPTURE_LIMIT && low_write_kind)?low_write_kind[i]:LOW_WRITER_NONE;
            uint16_t source=(i<LOW_WRITE_CAPTURE_LIMIT && low_write_source)?low_write_source[i]:0u;
            uint32_t begin=i++,count=1u;
            while(i<0x00090000u && level_before[i]!=memory[i] &&
                  ((i<LOW_WRITE_CAPTURE_LIMIT)?low_write_last_eip[i]:0u)==site &&
                  ((i<LOW_WRITE_CAPTURE_LIMIT)?low_write_live_mcb[i]:0u)==live &&
                  ((i<LOW_WRITE_CAPTURE_LIMIT && low_write_kind)?low_write_kind[i]:LOW_WRITER_NONE)==kind &&
                  ((i<LOW_WRITE_CAPTURE_LIMIT && low_write_source)?low_write_source[i]:0u)==source) { i++; count++; }
            if(!site) low_audit_no_writer+=count;
            if(!live) low_audit_not_live+=count;
            if(begin>=0x46Cu && i<=0x471u) low_audit_expected_bda+=count;
            else if(!(live && (kind==LOW_WRITER_GUEST || kind==LOW_WRITER_DOS_READ)))
                low_audit_unexpected+=count;
            low_audit_bytes+=count; low_audit_rows++;
            if(low_audit) fprintf(low_audit,"%s{\"start\":\"0x%08x\",\"end_inclusive\":\"0x%08x\",\"changed_bytes\":%u,\"writer_eip\":\"0x%08x\",\"writer_kind\":%u,\"source_id\":%u,\"inside_active_DOS_block_at_write\":%s}",low_audit_rows==1u?"":",",begin,i-1u,count,site,(unsigned)kind,(unsigned)source,live?"true":"false");
        }
        if(low_audit) { fprintf(low_audit,"],\"changed_bytes_below_0x90000\":%u,\"bytes_without_guest_store_site\":%u,\"bytes_written_outside_live_MCB\":%u,\"expected_host_BDA_timer_bytes\":%u,\"unexpected_writes\":%u}\n",low_audit_bytes,low_audit_no_writer,low_audit_not_live,low_audit_expected_bda,low_audit_unexpected); fclose(low_audit); }
        fprintf(stderr,"TRACE IFCLevel low-write audit events=%u changed_bytes=%u ranges=%u no_guest_writer=%u outside_live_MCB=%u final_MCB_chain=%s evidence=evidence/native_ifclevel_low_write_audit.json\n",
            low_write_capture_events,low_audit_bytes,low_audit_rows,low_audit_no_writer,low_audit_not_live,final_mcb_valid?"valid":"INVALID");
        free(level_before);
        free(low_write_last_eip); free(low_write_live_mcb); free(low_write_kind); free(low_write_source);
        low_write_last_eip=NULL; low_write_live_mcb=NULL; low_write_kind=NULL; low_write_source=NULL;
        const int level_memory_integrity_ok=(level_unexpected==0u && final_mcb_valid);
        const uint32_t level_current_after=*(uint32_t *)(memory+0x002EF7E8u);
        const uint32_t level_pending_after=*(uint32_t *)(memory+0x002EF7ECu);
        fprintf(stderr,"TRACE guest BIOS BDA timer before=%08x after=%08x midnight=%u->%u PIT_reload0=%08x virtual_cycles=%llu\n",
            bda_ticks_before,*(uint32_t *)(memory+0x46Cu),bda_midnight_before,memory[0x470u],
            level_transition_context.pit.reload[0],
            (unsigned long long)level_transition_context.pit.virtual_cycles);
        printf("TRACE original INT33 registered=%u mask=%04x callback_linear=%08x callback_link=%08x callback=MouseHandler256 profile=experimental-two-button-no-event-dispatch\n",
            g_int33_user_callback_registrations,g_int33_user_callback_mask,
            g_int33_user_callback_linear,g_int33_user_callback_link);
        printf("TRACE original game() TITLE->IFCLevel transition entry=00092819 result=%d trap=%u reason=%u unresolved=%08x trap_eip=%08x dispatches=%u pullout=%08x plugin=%08x current=%08x pending=%08x unexpected_writes=%u range=%08x..%08x memfault=%u:%08x segmentfault=%u:%04x:%08x portfault=%u:%u:%08x\n",
            level_transition_ok,level_transition_context.port_io_trap.pending,
            level_transition_context.port_io_trap.reason,level_transition_context.port_io_trap.value,
            level_transition_context.port_io_trap.guest_va,g_transition_dispatch_count,
            g_transition_dispatch_count>0?g_transition_dispatch[0].target:0u,
            g_transition_dispatch_count>1?g_transition_dispatch[1].target:0u,
            level_current_after,level_pending_after,level_unexpected,
            level_unexpected?level_first_unexpected:0u,level_unexpected?level_last_unexpected:0u,
            level_transition_context.memory_fault.pending,level_transition_context.memory_fault.linear,
            level_transition_context.segment_fault_pending,level_transition_context.segment_fault_selector,
            level_transition_context.segment_fault_instruction_va,level_transition_context.port_io_trap.pending,
            level_transition_context.port_io_trap.reason,level_transition_context.port_io_trap.value);
        if(level_transition_context.port_io_trap.pending &&
           level_transition_context.port_io_trap.guest_va==0x000EDEADu) {
            fprintf(stderr,"TRACE SMACK indexed-jump frontier site=000EDEAD link_table=0010C950 guest_table=002E6950 index=%u registers EAX=%08x EBX=%08x ECX=%08x EDX=%08x ESI=%08x EDI=%08x EBP=%08x ESP=%08x table=%08x/%08x/%08x/%08x input=%08x/%08x/%08x/%08x\n",
                level_transition_context.ecx,
                level_transition_context.eax,level_transition_context.ebx,
                level_transition_context.ecx,level_transition_context.edx,
                level_transition_context.esi,level_transition_context.edi,
                level_transition_context.ebp,level_transition_context.esp,
                read_guest_u32(0x002E6950u),read_guest_u32(0x002E6954u),
                read_guest_u32(0x002E6958u),read_guest_u32(0x002E695Cu),
                read_guest_u32(level_transition_context.esi),
                read_guest_u32(level_transition_context.esi+4u),
                read_guest_u32(level_transition_context.esi+8u),
                read_guest_u32(level_transition_context.esi+12u));
        }
        if(startup_budget_exhausted || !level_transition_ok || level_transition_context.port_io_trap.pending ||
           level_transition_context.memory_fault.pending || level_transition_context.segment_fault_pending ||
           level_current_after!=next_ifc || level_pending_after!=0u ||
           g_transition_dispatch_count!=2u ||
           g_transition_dispatch[0].stage!=1u || g_transition_dispatch[0].target!=0x001FE710u ||
           g_transition_dispatch[1].stage!=3u || g_transition_dispatch[1].target!=0x00206650u) {
            free(memory); return 105;
        }

        /* IFCLevel::PlugIn has just returned from its original
           data/levscr01.pal load. The VFS supplied 706 compressed bytes and
           LbDataLoad returned 0x300, so this is its decoded 768-byte output.
           Update can reuse the temporary DPMI buffer at 0x010000F0. */
        const uint32_t palette_load_guest=0x010000F0u;
        const uint32_t palette_global_guest=0x002EEC9Cu; /* link 0x114C9C + object-3 rebase 0x1DA000 */
        const uint32_t palette_global_value=read_guest_u32(palette_global_guest);
        const uint8_t *palette_loaded=memory+palette_load_guest;
        unsigned palette_capture_nonzero=0,palette_capture_distinct=0;
        uint8_t palette_capture_seen[256]={0};
        for(uint32_t i=0;i<sizeof ifclevel_palette_capture;i++) {
            uint8_t value=palette_loaded[i];
            if(value) palette_capture_nonzero++;
            if(!palette_capture_seen[value]) { palette_capture_seen[value]=1u; palette_capture_distinct++; }
        }
        if(palette_global_value!=palette_load_guest || palette_capture_nonzero<32u || palette_capture_distinct<4u) {
            fprintf(stderr,"original IFCLevel LbDataLoad palette output/global is invalid: guest=%08x global_guest=%08x global_value=%08x decoded=768 nonzero=%u distinct=%u member_186A13=%08x\n",
                palette_load_guest,palette_global_guest,palette_global_value,palette_capture_nonzero,palette_capture_distinct,
                read_guest_u32(0x00360A13u));
            free(memory); return 112;
        }
        memcpy(ifclevel_palette_capture,palette_loaded,sizeof ifclevel_palette_capture);
        ifclevel_palette_capture_valid=1;
        FILE *level_palette_loaded_file=fopen("evidence/native_ifclevel_level_palette_after_plugin.raw","wb");
        if(!level_palette_loaded_file || fwrite(ifclevel_palette_capture,1,
             sizeof ifclevel_palette_capture,level_palette_loaded_file)!=
             sizeof ifclevel_palette_capture) {
            if(level_palette_loaded_file) fclose(level_palette_loaded_file);
            free(memory); return 112;
        }
        fclose(level_palette_loaded_file);
        printf("TRACE original IFCLevel palette captured immediately after PlugIn file=data/levscr01.pal vfs_read=706 LbDataLoad_result=768 decoded_guest=%08x nonzero=%u distinct=%u member_186A13=%08x\n",
            palette_load_guest,palette_capture_nonzero,palette_capture_distinct,
            read_guest_u32(0x00360A13u));
        ifclevel_interface_palette_guest=read_guest_u32(0x00360A13u);
        if(!in_guest(0x14u,ifclevel_interface_palette_guest,768u,NULL)) {
            fprintf(stderr,"original IFCLevel palette member is not backed after PlugIn: %08x\n",
                ifclevel_interface_palette_guest); free(memory); return 112;
        }
        memcpy(ifclevel_interface_palette_capture,memory+ifclevel_interface_palette_guest,
            sizeof ifclevel_interface_palette_capture);
        ifclevel_interface_palette_capture_valid=1;
        printf("TRACE original IFCLevel palette member captured after PlugIn guest=%08x decoded_resource=%08x same_bytes=%d\n",
            ifclevel_interface_palette_guest,palette_load_guest,
            memcmp(ifclevel_interface_palette_capture,ifclevel_palette_capture,768u)==0);

        /* First authentic IFCLevel Update and Draw through the original
           control_game/draw_game virtual callsites. */
        gw_recomp_context level_update_context,level_draw_context;
        uint8_t level_palette_before_update[768];
        if(!ifclevel_interface_palette_capture_valid) { free(memory); return 112; }
        memcpy(level_palette_before_update,ifclevel_interface_palette_capture,
            sizeof level_palette_before_update);
        ifclevel_palette_store_base=ifclevel_interface_palette_guest;
        memset(ifclevel_palette_store_seen,0,sizeof ifclevel_palette_store_seen);
        ifclevel_palette_store_events=0u; ifclevel_palette_store_first_eip=0u;
        set_guest_write_observer(capture_ifclevel_palette_guest_write,NULL);
        uint32_t level_update_trace=g_icall_trace_idx,level_update_calls=g_icall_count;
        /* Assert the actual Update dispatch itself. A second ring entry here
           would be stale: this IFCLevel::Update path does not invoke the
           formatter callback, which may have been used by earlier title UI. */
        int level_update_ok=invoke(gw_original_control_game_update_dispatch,
            &level_update_context,0x5AF12u,memory,0,0);
        if(!level_update_ok || level_update_context.port_io_trap.pending ||
           level_update_context.memory_fault.pending || level_update_context.segment_fault_pending ||
           level_update_context.eip!=0x5AF12u || level_update_context.esp!=STACK_TOP+4u ||
           g_icall_count-level_update_calls<1u ||
           g_icall_from[level_update_trace&(ICALL_TRACE_SIZE-1u)]!=0x0005AF12u ||
           g_icall_trace[level_update_trace&(ICALL_TRACE_SIZE-1u)]!=0x00206630u) {
            fprintf(stderr,"original IFCLevel Update dispatch failed result=%d eip=%08x trap=%u memory=%u instruction=%08x seg=%u selector=%04x offset=%08x width=%u linear=%08x regs=%08x/%08x/%08x/%08x/%08x/%08x/%08x esp=%08x segment_fault=%u:%04x:%08x call_delta=%u first_calls=%08x->%08x/%08x->%08x\n",
                level_update_ok,level_update_context.eip,
                level_update_context.port_io_trap.pending,level_update_context.memory_fault.pending,
                level_update_context.memory_fault.instruction_va,
                level_update_context.memory_fault.segment,level_update_context.memory_fault.selector,
                level_update_context.memory_fault.offset,level_update_context.memory_fault.width,
                level_update_context.memory_fault.linear,
                level_update_context.eax,level_update_context.ebx,level_update_context.ecx,
                level_update_context.edx,level_update_context.esi,level_update_context.edi,
                level_update_context.ebp,level_update_context.esp,
                level_update_context.segment_fault_pending,level_update_context.segment_fault_selector,
                level_update_context.segment_fault_instruction_va,
                g_icall_count-level_update_calls,
                g_icall_from[level_update_trace&(ICALL_TRACE_SIZE-1u)],
                g_icall_trace[level_update_trace&(ICALL_TRACE_SIZE-1u)],
                g_icall_from[(level_update_trace+1u)&(ICALL_TRACE_SIZE-1u)],
                g_icall_trace[(level_update_trace+1u)&(ICALL_TRACE_SIZE-1u)]); free(memory); return 106;
        }
        printf("TRACE original IFCLevel::Update dispatch=control_game@0x5AF12 -> thunk=0x1B630 -> method=0x179F0 ok=1 eip=%08x calls=%u\n",
            level_update_context.eip,g_icall_count-level_update_calls);

        /* Preserve the bytes produced by the original resource loader for
           inspection, but do not restore them or invoke LbPaletteSet_ from
           the harness.  The replay must expose the original game's palette
           transition through setup/update/draw. */
        const uint32_t level_palette_data=0x010000F0u;
        if(!ifclevel_palette_capture_valid) {
            fprintf(stderr,"original IFCLevel palette capture is missing after PlugIn\n");
            free(memory); return 112;
        }
        unsigned level_palette_nonzero=0,level_palette_distinct=0;
        uint8_t level_palette_seen[64]={0};
        for(unsigned i=0;i<768u;i++) {
            uint8_t value=ifclevel_palette_capture[i];
            if(value>63u) { fprintf(stderr,"decompressed level DAC component exceeds 6-bit range at %u: %u\n",i,value); free(memory); return 112; }
            if(value) level_palette_nonzero++;
            if(!level_palette_seen[value]) { level_palette_seen[value]=1u; level_palette_distinct++; }
        }
        if(!level_palette_nonzero || level_palette_distinct<2u) {
            fprintf(stderr,"decompressed level palette is empty/non-distinct nonzero=%u distinct=%u\n",
                level_palette_nonzero,level_palette_distinct); free(memory); return 112;
        }
        FILE *unpacked_palette_out=fopen("evidence/native_ifclevel_level_palette_rgb6.raw","wb");
        if(!unpacked_palette_out || fwrite(ifclevel_palette_capture,1,768u,unpacked_palette_out)!=768u) {
            if(unpacked_palette_out) fclose(unpacked_palette_out); free(memory); return 112;
        }
        fclose(unpacked_palette_out);
        unsigned dac_nonzero=0,dac_distinct=0; uint8_t dac_seen[64]={0};
        for(unsigned i=0;i<768u;i++) { if(vga_dac[i]) dac_nonzero++; if(!dac_seen[vga_dac[i]]) { dac_seen[vga_dac[i]]=1u; dac_distinct++; } }
        printf("TRACE original IFCLevel palette file=data/levscr01.pal decoded=768 source=%08x source_capture=authentic-resource DAC=%u distinct=%u resource=%u/%u W_palette_global_link=00114c9c guest=%08x current=%08x\n",
            level_palette_data,dac_nonzero,dac_distinct,
            level_palette_nonzero,level_palette_distinct,
            palette_global_guest,read_guest_u32(palette_global_guest));

        uint32_t level_wscreen=*(uint32_t *)(memory+0x00376A5Cu);
        if(!level_wscreen || level_wscreen>GUEST_LIMIT || 0x4B000u>GUEST_LIMIT-level_wscreen) {
            fprintf(stderr,"IFCLevel Draw has no bounded WScreen: %08x\n",level_wscreen); free(memory); return 107;
        }
        uint8_t *level_draw_before=(uint8_t *)malloc(GUEST_LIMIT);
        if(!level_draw_before) { free(memory); return 108; }
        memcpy(level_draw_before,memory,GUEST_LIMIT);
        uint32_t level_draw_trace=g_icall_trace_idx,level_draw_calls=g_icall_count;
        g_ifclevel_draw_dispatch_target=0u;
        g_ifclevel_draw_dispatch_caller=0u;
        g_ifclevel_draw_dispatch_count=0u;
        int level_draw_ok=invoke(gw_original_draw_game_draw_dispatch,
            &level_draw_context,0x83559u,memory,0,0);
        uint32_t level_draw_wscreen_changed=0,level_draw_unexpected=0;
        for(uint32_t i=0;i<GUEST_LIMIT;i++) if(level_draw_before[i]!=memory[i]) {
            int allowed=(i>=0x00090000u && i<0x000B0000u) ||
                        (i>=0x002DA000u && i<0x00382C50u) ||
                        (i>=0x00390000u && i<0x003FD000u) ||
                        (i>=STACK_TOP-0x3000u && i<GUEST_LIMIT) ||
                        (i>=0x01000000u && i<GUEST_LIMIT);
            for(uint32_t b=0;b<vfs.dos.dos_block_count && !allowed;b++) {
                uint32_t begin=(uint32_t)vfs.dos.dos_blocks[b].segment<<4;
                uint32_t end=(uint32_t)(vfs.dos.dos_blocks[b].segment+
                    vfs.dos.dos_blocks[b].paragraphs)<<4;
                uint32_t mcb=begin>=16u?begin-16u:0u;
                if((i>=begin && i<end) || (i>=mcb && i<mcb+16u)) allowed=1;
            }
            if(i>=level_wscreen && i<level_wscreen+0x4B000u) level_draw_wscreen_changed++;
            else if(!allowed) level_draw_unexpected++;
        }
        free(level_draw_before);
        fprintf(stderr,"TRACE IFCLevel Draw indirect-call delta=%u history=",
            g_icall_count-level_draw_calls);
        for(uint32_t i=0;i<g_icall_count-level_draw_calls && i<12u;i++) {
            uint32_t slot=(level_draw_trace+i)&(ICALL_TRACE_SIZE-1u);
            fprintf(stderr,"[%u:%08x->%08x]",i,g_icall_from[slot],g_icall_trace[slot]);
        }
        fputc('\n',stderr);
        fprintf(stderr,"TRACE IFCLevel Draw original virtual call site=00083561 caller=%08x target=%08x count=%u expected_thunk=00206620\n",
            g_ifclevel_draw_dispatch_caller,g_ifclevel_draw_dispatch_target,
            g_ifclevel_draw_dispatch_count);
        if(!level_draw_ok || level_draw_context.port_io_trap.pending ||
           level_draw_context.memory_fault.pending || level_draw_context.segment_fault_pending ||
           g_ifclevel_draw_dispatch_count!=1u ||
           g_ifclevel_draw_dispatch_caller!=0x00083559u ||
           g_ifclevel_draw_dispatch_target!=0x00206620u ||
           level_draw_unexpected || !level_draw_wscreen_changed) {
            fprintf(stderr,"original IFCLevel Draw dispatch failed result=%d eip=%08x trap=%u mem=%u:%08x instr=%08x selector=%04x offset=%08x width=%u segment=%u regs=%08x/%08x/%08x/%08x/%08x/%08x/%08x/%08x unexpected=%u changed_surface=%u targets=%08x/%08x\n",
                level_draw_ok,level_draw_context.eip,
                level_draw_context.port_io_trap.pending,level_draw_context.memory_fault.pending,
                level_draw_context.memory_fault.linear,level_draw_context.memory_fault.instruction_va,
                level_draw_context.memory_fault.selector,level_draw_context.memory_fault.offset,
                level_draw_context.memory_fault.width,level_draw_context.segment_fault_pending,
                level_draw_context.eax,level_draw_context.ebx,level_draw_context.ecx,level_draw_context.edx,
                level_draw_context.esi,level_draw_context.edi,level_draw_context.ebp,level_draw_context.esp,
                level_draw_unexpected,level_draw_wscreen_changed,
                g_icall_trace[level_draw_trace&(ICALL_TRACE_SIZE-1u)],
                g_icall_trace[(level_draw_trace+1u)&(ICALL_TRACE_SIZE-1u)]);
            fprintf(stderr,"TRACE IFCLevel Draw fault context SS=%04x SS_BASE=%08x ESP=%08x EBP=%08x stack=",
                g_seg_ss,g_ss_base,level_draw_context.esp,level_draw_context.ebp);
            for(uint32_t i=0;i<16u;i++) fprintf(stderr,"%08x/",stack_word_at((uint64_t)level_draw_context.esp+i*4u));
            fprintf(stderr,"\nTRACE remap fault bytes around source-field guest=%08x bytes=",level_draw_context.ebx>=12u?level_draw_context.ebx-12u:level_draw_context.ebx);
            { uint32_t b=level_draw_context.ebx>=12u?level_draw_context.ebx-12u:level_draw_context.ebx;
              for(uint32_t i=0;i<48u && b+i<GUEST_LIMIT;i++) fprintf(stderr,"%02x",memory[b+i]); }
            fprintf(stderr,"\nTRACE remap fault loaded-pixel-word guest=%08x value=%08x invalid-source=%08x call_count=%u completed=%u\n",
                level_draw_context.ebx,read_guest_u32(level_draw_context.ebx),
                level_draw_context.memory_fault.linear,remap_sprite_call_count,remap_sprite_return_count);
            trace_guest_heap_list("IFCLevel Draw fault after Plugin resource loads");
            for(uint32_t a=0;a<GW_DOS_MAX_LINEAR_ALLOCATIONS;a++) {
                const gw_dos_linear_allocation *allocation=&vfs.dos.linear_allocations[a];
                if(!allocation->active) continue;
                uint32_t end=allocation->base+allocation->size;
                if((level_draw_context.ebx>=allocation->base && level_draw_context.ebx<end) ||
                   (level_wscreen>=allocation->base && level_wscreen<end) ||
                   (level_draw_context.memory_fault.linear>=allocation->base && level_draw_context.memory_fault.linear<end))
                    fprintf(stderr,"TRACE IFCLevel relevant DPMI ledger base=%08x end=%08x size=%08x handle=%08x active=%u contains_field=%u contains_WScreen=%u contains_fault=%u\n",
                        allocation->base,end,allocation->size,allocation->handle,allocation->active,
                        level_draw_context.ebx>=allocation->base&&level_draw_context.ebx<end,
                        level_wscreen>=allocation->base&&level_wscreen<end,
                        level_draw_context.memory_fault.linear>=allocation->base&&level_draw_context.memory_fault.linear<end);
            }
            gw_recomp_trace_checkpoint(0x0009A3B9u,0x00099A20u);
            FILE *frontier_raw=fopen("evidence/native_ifclevel_draw_investigation_wscreen.raw","wb");
            if(frontier_raw) { fwrite(memory+level_wscreen,1,0x4B000u,frontier_raw); fclose(frontier_raw); }
            FILE *frontier_palette=fopen("evidence/native_ifclevel_draw_investigation_palette6.raw","wb");
            if(frontier_palette) { fwrite(vga_dac,1,sizeof vga_dac,frontier_palette); fclose(frontier_palette); }
            if(!frontier_raw || !frontier_palette || !present_draw_sdl(memory+level_wscreen,vga_dac,
                "GeneWars 1.1 — IFCLevel Draw diagnostic frontier","evidence/native_ifclevel_draw_investigation.bmp"))
                fprintf(stderr,"TRACE IFCLevel frontier image export incomplete\n");
            free(memory); return 109;
        }
        printf("TRACE original IFCLevel::Draw dispatch=draw_game@0x83559 -> thunk=0x1B620 -> method=0x177C0 ok=1 eip=%08x calls=%u changed_WScreen=%u unexpected_writes=%u palette_DAC_components=%u\n",
            level_draw_context.eip,g_icall_count-level_draw_calls,level_draw_wscreen_changed,
            level_draw_unexpected,vga_dac_component_writes);
        /* Continue through the original draw_game dirty-palette gate at
           0x8375A. It reads the live IFCLevel subobject's pointer and calls
           the original LbPaletteSet_; the harness does not supply palette
           bytes or invoke the palette writer directly. */
        const uint32_t level_palette_source=*(uint32_t *)(memory+0x00360A13u);
        uint32_t palette_updates_before=vga_dac_component_writes;
        printf("TRACE draw_game palette gate pre-state current=%08x fields=%02x/%02x palette_ptr=%08x palette_head=%02x%02x%02x%02x DAC_components=%u\n",
            *(uint32_t *)(memory+0x002EF7E8u),memory[0x00360A11u],memory[0x00360A12u],
            level_palette_source,
            level_palette_source<GUEST_LIMIT?memory[level_palette_source]:0u,
            level_palette_source+1u<GUEST_LIMIT?memory[level_palette_source+1u]:0u,
            level_palette_source+2u<GUEST_LIMIT?memory[level_palette_source+2u]:0u,
            level_palette_source+3u<GUEST_LIMIT?memory[level_palette_source+3u]:0u,
            vga_dac_component_writes);
        gw_recomp_context draw_game_palette_context;
        int draw_game_palette_ok=invoke(gw_original_draw_game_level_palette_fade_entry,
            &draw_game_palette_context,0x83A0Cu,memory,0u,0u);
        set_guest_write_observer(NULL,NULL);
        unsigned palette_update_guest_changed=0u,palette_update_unattributed=0u;
        for(uint32_t i=0;i<sizeof level_palette_before_update;i++) {
            if(memory[ifclevel_palette_store_base+i]!=level_palette_before_update[i]) {
                palette_update_guest_changed++;
                if(!ifclevel_palette_store_seen[i]) palette_update_unattributed++;
            }
        }
        unsigned palette_update_guest_covered=0u;
        for(uint32_t i=0;i<sizeof ifclevel_palette_store_seen;i++)
            palette_update_guest_covered+=ifclevel_palette_store_seen[i]!=0u;
        printf("TRACE original IFCLevel Update/Draw palette-source delta address=%08x changed=%u guest_store_events=%u covered=%u unattributed=%u first_guest_store_eip=%08x\n",
            ifclevel_palette_store_base,palette_update_guest_changed,
            ifclevel_palette_store_events,palette_update_guest_covered,
            palette_update_unattributed,ifclevel_palette_store_first_eip);
        unsigned palette_bytes_bad=0u,palette_diff=0u;
        for(uint32_t i=0;i<768u;i++) {
            if(vga_dac[i]>63u) palette_bytes_bad++;
            if(level_palette_source<GUEST_LIMIT && level_palette_source+768u<=GUEST_LIMIT &&
               vga_dac[i]!=memory[level_palette_source+i]) palette_diff++;
        }
        if(!draw_game_palette_ok || draw_game_palette_context.memory_fault.pending ||
           draw_game_palette_context.segment_fault_pending || draw_game_palette_context.interrupt_trap_pending ||
           draw_game_palette_context.port_io_trap.pending ||
           vga_dac_component_writes-palette_updates_before!=13056u ||
           !level_palette_source || !in_guest(0x14u,level_palette_source,768u,NULL) ||
           palette_bytes_bad || palette_diff || memory[0x00360A12u]!=1u ||
           level_palette_source!=ifclevel_interface_palette_guest ||
           palette_update_unattributed) {
            fprintf(stderr,"original draw_game type-2 palette fade failed ok=%d eip=%08x current=%08x type=%u dirty=%u source=%08x DAC_delta=%u bad=%u diff=%u source_capture_diff=%u faults=%u/%08x seg=%u:%04x:%08x int=%u:%02x:%08x port=%u:%08x\n",
                draw_game_palette_ok,draw_game_palette_context.eip,
                *(uint32_t *)(memory+0x002EF7E8u),memory[0x00360A11u],memory[0x00360A12u],level_palette_source,
                vga_dac_component_writes-palette_updates_before,palette_bytes_bad,palette_diff,
                memcmp(memory+level_palette_source,ifclevel_palette_capture,768u)!=0,
                draw_game_palette_context.memory_fault.pending,draw_game_palette_context.memory_fault.linear,
                draw_game_palette_context.segment_fault_pending,draw_game_palette_context.segment_fault_selector,
                draw_game_palette_context.segment_fault_instruction_va,
                draw_game_palette_context.interrupt_trap_pending,draw_game_palette_context.interrupt_vector,
                draw_game_palette_context.interrupt_instruction_va,
                draw_game_palette_context.port_io_trap.pending,draw_game_palette_context.port_io_trap.guest_va);
            free(memory); return 114;
        }
        printf("PASS original draw_game IFCLevel type-2 tail 0x83A0C -> LbPaletteFade_ 0xA26F0 currentIFC=00360a11 type=2 dirty=0->1 source=%08x DAC_components=13056 final_palette_matches_source=1 source_guest_writes=%u source_changed=%u\n",
            level_palette_source,ifclevel_palette_store_events,palette_update_guest_changed);
        FILE *level_raw=fopen("evidence/native_ifclevel_new_game_wscreen.raw","wb");
        FILE *level_palette=fopen("evidence/native_ifclevel_new_game_palette6.raw","wb");
        if(!level_raw || fwrite(memory+level_wscreen,1,0x4B000u,level_raw)!=0x4B000u ||
           !level_palette || fwrite(vga_dac,1,sizeof vga_dac,level_palette)!=sizeof vga_dac) {
            if(level_raw) fclose(level_raw); if(level_palette) fclose(level_palette);
            free(memory); return 110;
        }
        fclose(level_raw); fclose(level_palette);
        if(!present_draw_sdl(memory+level_wscreen,vga_dac,
            "GeneWars 1.1 — original IFCLevel::Draw",
            "evidence/native_ifclevel_new_game_sdl.bmp")) { free(memory); return 111; }
        if(!level_memory_integrity_ok) {
            fprintf(stderr,"TRACE IFCLevel PlugIn returned and Update/Draw ran, but low guest-memory delta remains unclassified: count=%u range=%08x..%08x; outputs retained for review\n",
                level_unexpected,level_first_unexpected,level_last_unexpected);
            free(memory); return 105;
        }
        printf("PASS original IFCLevel transition, first Update/Draw, WScreen bytes and DAC capture saved\n");
    /* Optional, bounded continuation of the authenticated IFCLevel screen.
       The default regression above remains unchanged.  SDL events enter only
       through poll_sdl_into_lbdisplay; setup_controller and the virtual
       IFCLevel Update/Draw dispatches consume them as original game input. */
    if (getenv("GWRECOMP_IFCLEVEL_CONTINUE") &&
        strcmp(getenv("GWRECOMP_IFCLEVEL_CONTINUE"), "1") == 0) {
        const uint32_t level_ifc=0x00360A11u;
        const uint32_t this_adjust=*(uint32_t *)(memory+0x00360A0Du);
        const uint32_t level_this=level_ifc-this_adjust;
        const uint32_t level_wscreen=*(uint32_t *)(memory+0x00376A5Cu);
        FILE *interaction=fopen("evidence/native_ifclevel_gameplay_continue.trace","wb");
        if(!interaction || SDL_Init(SDL_INIT_VIDEO)!=0 ||
           !in_guest(0x14u,level_wscreen,640u*480u,NULL) ||
           *(uint32_t *)(memory+0x002EF7E8u)!=level_ifc ||
           *(uint32_t *)(memory+level_ifc+7u)!=0x002EBAD4u ||
           this_adjust!=0x9D1u || level_this!=0x00360040u ||
           !in_guest(0x14u,level_this,0x9B8u,NULL)) {
             fprintf(stderr,"bounded IFCLevel continuation setup failed ifc=%08x expected_ifc=%08x vptr=%08x expected_vptr=%08x adjust=%08x expected_adjust=%08x this=%08x WScreen=%08x backed=%d\n",
                *(uint32_t *)(memory+0x002EF7E8u),level_ifc,
                *(uint32_t *)(memory+level_ifc+7u),0x002EBAD4u,this_adjust,0x9D1u,
                level_this,level_wscreen,(int)in_guest(0x14u,level_wscreen,640u*480u,NULL));
            if(interaction) fclose(interaction); free(memory); return 120;
        }
        fprintf(interaction,"schema=gw-ifclevel-interaction-trace/v1 target_sha256=2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f\n");
        fprintf(interaction,"profile=bounded-original-IFCLevel input=SDL-key/mouse->lbDisplay+lbInkey; full original control_game(0x5AE60)->process_packets(0x93010)->virtual Update; original Draw/palette tail and game() timer instruction 0x928AF; bounded frame pipeline, not game() loop max_ticks=140 logical_screen=640x480\n");
        fprintf(interaction,"before currentIFC=%08x pendingIFC=%08x method_this_guest=%08x interface_subobject=%08x adjustment_from_subobject_minus_4=%08x phase_9a9=%u proximity_flags_9aa=%02x motion_flags_958=%02x selected_field_28=%u selected_slot_959=%u mode_2e=%u timer_117472=%u flags_11746d=%02x runFlags_117661=%02x selected_planet_index_118123=%u mouse=%d,%d WScreen=%08x\n",
            *(uint32_t *)(memory+0x002EF7E8u),*(uint32_t *)(memory+0x002EF7ECu),
            level_this,level_ifc,this_adjust,
            memory[level_this+0x9A9u],memory[level_this+0x9AAu],memory[level_this+0x958u],*(uint16_t *)(memory+level_this+0x28u),
            *(uint32_t *)(memory+level_this+0x959u),memory[level_this+0x2Eu],
            *(uint16_t *)(memory+0x002F1472u),memory[0x002F146Du],memory[0x002F1661u],
            memory[0x002F3123u+memory[0x002F1431u]*0x70Du],
            *(int32_t *)(memory+0x00376AA8u),*(int32_t *)(memory+0x00376AACu),level_wscreen);
        const unsigned max_ticks=512u;
        int mouse_button_down=0, phase7_click_sent=0, phase9_click_sent=0;
        int timer_tick_count=0;
        int continuation_ok=1; unsigned completed=0; int transition_attempted=0,phase8_stalled=0;
        unsigned post_loader_ticks=0,post_loader_key_events=0,post_loader_input_misses=0;
        int post_loader_frontier=0,post_loader_capture_ok=0;
        static char tick_names[512][32];
        unsigned camera_stable_ticks=0;
        int32_t last_camera[3]={*(int32_t *)(memory+level_this+0x3E8u),
            *(int32_t *)(memory+level_this+0x3ECu),*(int32_t *)(memory+level_this+0x3F0u)};
        for(unsigned tick=0;tick<max_ticks;tick++) {
            const uint8_t phase_for_event=memory[level_this+0x9A9u];
            int event_code=0;
            if(mouse_button_down) {
                if(!push_sdl_button(SDL_MOUSEBUTTONUP,320,240)) continuation_ok=0;
                else { mouse_button_down=0; event_code=2; snprintf(tick_names[tick],sizeof tick_names[tick],"mouse-up-phase%u",phase_for_event); }
            } else if(phase_for_event==7u && !phase7_click_sent) {
                if(!push_sdl_button(SDL_MOUSEBUTTONDOWN,320,240)) continuation_ok=0;
                else { mouse_button_down=1; phase7_click_sent=1; event_code=1; snprintf(tick_names[tick],sizeof tick_names[tick],"mouse-down-phase7"); }
            } else if(phase_for_event>=9u && !phase9_click_sent) {
                if(!push_sdl_button(SDL_MOUSEBUTTONDOWN,320,240)) continuation_ok=0;
                else { mouse_button_down=1; phase9_click_sent=1; event_code=1; snprintf(tick_names[tick],sizeof tick_names[tick],"mouse-down-phase9"); }
            } else {
                snprintf(tick_names[tick],sizeof tick_names[tick],"frame-%03u",tick);
            }
            unsigned events=poll_sdl_into_lbdisplay(memory);
            if(!continuation_ok || events!=(unsigned)(event_code!=0)) { continuation_ok=0; break; }

            const uint8_t phase_before=memory[level_this+0x9A9u];
            const uint16_t selected_before=*(uint16_t *)(memory+level_this+0x28u);
            const uint32_t selected_slot_before=*(uint32_t *)(memory+level_this+0x959u);
            const uint8_t planet_index_before=memory[0x002F3123u+memory[0x002F1431u]*0x70Du];
            gw_recomp_context input_context,update_context,draw_context,palette_context,timer_context;
            if(!invoke(gw_original_setup_controller_entry,&input_context,0x5B170u,memory,0u,0u) ||
               input_context.memory_fault.pending || input_context.segment_fault_pending ||
               input_context.interrupt_trap_pending || input_context.port_io_trap.pending) {
                fprintf(interaction,"tick=%u label=%s stage=setup_controller failed eip=%08x\n",tick,tick_names[tick],input_context.eip);
                continuation_ok=0; break;
            }
            const uint8_t controller_flags=memory[0x002F146Du];
            if(event_code==1 && phase_for_event==7u && (controller_flags&1u)==0u) {
                fprintf(interaction,"tick=%u label=%s SDL left-button did not reach original GameControl action bit flags=%02x\n",
                    tick,tick_names[tick],controller_flags);
                continuation_ok=0; break;
            }
            const int32_t mx=*(int32_t *)(memory+0x00376AA8u),my=*(int32_t *)(memory+0x00376AACu);
            if(!invoke(gw_original_control_game_update_dispatch,&update_context,0x5AF12u,memory,0u,0u) ||
               update_context.memory_fault.pending || update_context.segment_fault_pending ||
               update_context.interrupt_trap_pending || update_context.port_io_trap.pending) {
                fprintf(interaction,"tick=%u label=%s stage=IFCLevel_Update failed eip=%08x faults=%u/%08x seg=%u int=%u port=%u/%08x\n",
                    tick,tick_names[tick],update_context.eip,update_context.memory_fault.pending,
                    update_context.memory_fault.linear,update_context.segment_fault_pending,
                    update_context.interrupt_trap_pending,update_context.port_io_trap.pending,
                    update_context.port_io_trap.guest_va);
                continuation_ok=0; break;
            }
            uint32_t phase_after_update=memory[level_this+0x9A9u];
            uint32_t selected_after_update=*(uint16_t *)(memory+level_this+0x28u);
            uint32_t selected_slot_after_update=*(uint32_t *)(memory+level_this+0x959u);
            uint32_t planet_index_after_update=memory[0x002F3123u+memory[0x002F1431u]*0x70Du];
            uint32_t mode_after_update=memory[level_this+0x2Eu];
            uint32_t pending_after_update=*(uint32_t *)(memory+0x002EF7ECu);
            uint8_t *frame_before=(uint8_t *)malloc(640u*480u);
            if(!frame_before) { continuation_ok=0; break; }
            memcpy(frame_before,memory+level_wscreen,640u*480u);
            g_ifclevel_draw_dispatch_target=0u; g_ifclevel_draw_dispatch_caller=0u; g_ifclevel_draw_dispatch_count=0u;
            int draw_invoke_ok=invoke(gw_original_draw_game_draw_dispatch,&draw_context,0x83559u,memory,0u,0u);
            if(!draw_invoke_ok ||
               draw_context.memory_fault.pending || draw_context.segment_fault_pending ||
               draw_context.interrupt_trap_pending || draw_context.port_io_trap.pending ||
               g_ifclevel_draw_dispatch_count!=1u || g_ifclevel_draw_dispatch_caller!=0x00083559u ||
               g_ifclevel_draw_dispatch_target!=0x00206620u) {
                fprintf(interaction,"tick=%u label=%s stage=IFCLevel_Draw failed invoke=%d eip=%08x esp=%08x eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x ebp=%08x dispatch=%u/%08x/%08x icalls=%u trace_boundary=%d mem=%u/%08x:%u:%u:%08x seg=%u:%04x:%08x int=%u:%02x:%08x port=%u:%04x:%08x\n",
                    tick,tick_names[tick],draw_invoke_ok,
                    draw_context.eip,draw_context.esp,draw_context.eax,draw_context.ebx,
                    draw_context.ecx,draw_context.edx,draw_context.esi,draw_context.edi,draw_context.ebp,
                    g_ifclevel_draw_dispatch_count,
                    g_ifclevel_draw_dispatch_caller,g_ifclevel_draw_dispatch_target,
                    g_icall_count,gw_recomp_trace_boundary_hit(),draw_context.memory_fault.pending,
                    draw_context.memory_fault.linear,draw_context.memory_fault.segment,
                    draw_context.memory_fault.width,draw_context.memory_fault.instruction_va,
                    draw_context.segment_fault_pending,draw_context.segment_fault_selector,
                    draw_context.segment_fault_instruction_va,draw_context.interrupt_trap_pending,
                    draw_context.interrupt_vector,draw_context.interrupt_instruction_va,
                    draw_context.port_io_trap.pending,draw_context.port_io_trap.port,
                    draw_context.port_io_trap.guest_va);
                fprintf(interaction,"tick=%u label=%s guest-stack@%08x",tick,tick_names[tick],draw_context.esp);
                for(unsigned si=0;si<12u && draw_context.esp+4u*si+4u<=GUEST_LIMIT;si++)
                    fprintf(interaction," %08x",*(uint32_t *)(memory+draw_context.esp+4u*si));
                fprintf(interaction,"\n");
                free(frame_before); continuation_ok=0; break;
            }
            unsigned screen_changed=0;
            for(uint32_t i=0;i<640u*480u;i++) if(frame_before[i]!=memory[level_wscreen+i]) screen_changed++;
            free(frame_before);
            if(!invoke(gw_original_draw_game_level_palette_fade_entry,&palette_context,0x83A0Cu,memory,0u,0u) ||
               palette_context.memory_fault.pending || palette_context.segment_fault_pending ||
               palette_context.interrupt_trap_pending || palette_context.port_io_trap.pending) {
                fprintf(interaction,"tick=%u label=%s stage=palette-fade failed eip=%08x\n",tick,tick_names[tick],palette_context.eip);
                continuation_ok=0; break;
            }
            const uint8_t phase_after_draw=memory[level_this+0x9A9u];
            if(!invoke(gw_original_game_frame_timer_tick_entry,&timer_context,0x928AFu,memory,0u,0u) ||
               timer_context.memory_fault.pending || timer_context.segment_fault_pending ||
               timer_context.interrupt_trap_pending || timer_context.port_io_trap.pending) {
                fprintf(interaction,"tick=%u label=%s stage=original-game-timer-increment failed eip=%08x\n",
                    tick,tick_names[tick],timer_context.eip);
                continuation_ok=0; break;
            }
            timer_tick_count++;
            int mcb_valid=validate_dos_mcb_chain(memory,vfs.dos.dos_segment_end);
            uint32_t current=*(uint32_t *)(memory+0x002EF7E8u),pending=*(uint32_t *)(memory+0x002EF7ECu);
            const uint32_t planet_table=*(uint32_t *)(memory+level_this+0x340u);
            const uint32_t selected_target=planet_table+selected_slot_after_update*12u;
            const int target_range_valid=(selected_target<=GUEST_LIMIT-12u);
            const int32_t camera_x=*(int32_t *)(memory+level_this+0x3E8u);
            const int32_t camera_y=*(int32_t *)(memory+level_this+0x3ECu);
            const int32_t camera_z=*(int32_t *)(memory+level_this+0x3F0u);
            if(camera_x==last_camera[0] && camera_y==last_camera[1] && camera_z==last_camera[2]) camera_stable_ticks++;
            else camera_stable_ticks=0;
            last_camera[0]=camera_x; last_camera[1]=camera_y; last_camera[2]=camera_z;
            fprintf(interaction,"tick=%u label=%s events=%u lbInkey@376bf0=%02x phase_9a9=%u->%u->%u proximity_flags_9aa=%02x motion_flags_958=%02x selected_field_28=%u->%u selected_slot_959=%u->%u selected_planet_index_118123=%u->%u runFlags_117661=%02x flags_11746d=%02x mouse=%d,%d raw_left=%u/%u timer_117472=%u current=%08x pending=%08x camera=%d,%d,%d target_ptr=%08x target_backed=%d target_xyz=%d,%d,%d range_95d=%d velocity=%d,%d,%d camera_stable_ticks=%u WScreen_changed=%u MCB_chain_valid=%u timer_instruction=928af\n",
                tick,tick_names[tick],events,memory[0x00376BF0u],
                phase_before,phase_after_update,phase_after_draw,memory[level_this+0x9AAu],memory[level_this+0x958u],
                selected_before,selected_after_update,
                selected_slot_before,selected_slot_after_update,
                planet_index_before,planet_index_after_update,
                memory[0x002F1661u],controller_flags,mx,my,memory[0x00376ABFu],memory[0x00376AC2u],
                *(uint16_t *)(memory+0x002F1472u),current,pending,camera_x,camera_y,camera_z,
                planet_table,target_range_valid,
                target_range_valid?*(int32_t *)(memory+selected_target):0,
                target_range_valid?*(int32_t *)(memory+selected_target+4u):0,
                target_range_valid?*(int32_t *)(memory+selected_target+8u):0,
                *(int32_t *)(memory+level_this+0x95Du),
                *(int32_t *)(memory+level_this+0x3DCu),*(int32_t *)(memory+level_this+0x3E0u),
                *(int32_t *)(memory+level_this+0x3E4u),camera_stable_ticks,screen_changed,mcb_valid);
            completed++;
            if(!mcb_valid || !in_guest(0x14u,level_wscreen,640u*480u,NULL)) { continuation_ok=0; break; }
            if(pending && pending!=current) {
                gw_recomp_context transition_context;
                int transition_ok=invoke(gw_original_game_interface_transition_entry,&transition_context,
                    0x92819u,memory,0u,0u);
                uint32_t pending_object=*(uint32_t *)(memory+0x002EF7ECu);
                uint32_t pending_vptr=(pending_object<=GUEST_LIMIT-11u)?*(uint32_t *)(memory+pending_object+7u):0u;
                uint32_t pending_plugin=(pending_vptr<=GUEST_LIMIT-4u)?*(uint32_t *)(memory+pending_vptr):0u;
                fprintf(interaction,"transition attempted=1 ok=%d eip=%08x esp=%08x eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x ebp=%08x eflags=%08x current=%08x pending=%08x pending_vptr=%08x pending_plugin=%08x memory_fault=%u/%08x:%u:%u:%08x segment_fault=%u:%04x:%08x interrupt=%u:%02x:%08x port=%u:%04x:%08x indirect=%u object_words=%08x/%08x/%08x/%08x\n",
                    transition_ok,transition_context.eip,transition_context.esp,
                    transition_context.eax,transition_context.ebx,transition_context.ecx,
                    transition_context.edx,transition_context.esi,transition_context.edi,
                    transition_context.ebp,recomp_eflags(transition_context.flag_k,
                        transition_context.flag_a,transition_context.flag_b,transition_context.flag_cf,1u),
                    *(uint32_t *)(memory+0x002EF7E8u),pending_object,pending_vptr,pending_plugin,
                    transition_context.memory_fault.pending,transition_context.memory_fault.linear,
                    transition_context.memory_fault.segment,transition_context.memory_fault.width,
                    transition_context.memory_fault.instruction_va,
                    transition_context.segment_fault_pending,transition_context.segment_fault_selector,
                    transition_context.segment_fault_instruction_va,transition_context.interrupt_trap_pending,
                    transition_context.interrupt_vector,transition_context.interrupt_instruction_va,
                    transition_context.port_io_trap.pending,transition_context.port_io_trap.port,
                    transition_context.port_io_trap.guest_va,g_icall_count,
                    pending_object<=GUEST_LIMIT-16u?*(uint32_t *)(memory+pending_object):0u,
                    pending_object<=GUEST_LIMIT-16u?*(uint32_t *)(memory+pending_object+4u):0u,
                    pending_object<=GUEST_LIMIT-16u?*(uint32_t *)(memory+pending_object+8u):0u,
                    pending_object<=GUEST_LIMIT-16u?*(uint32_t *)(memory+pending_object+12u):0u);
                uint32_t ring_begin=g_icall_trace_idx>16u?g_icall_trace_idx-16u:0u;
                for(uint32_t sequence=ring_begin;sequence<g_icall_trace_idx;sequence++) {
                    uint32_t slot=sequence&(ICALL_TRACE_SIZE-1u);
                    fprintf(interaction,"transition_icall seq=%u caller=%08x target=%08x\n",
                        sequence,g_icall_from[slot],g_icall_trace[slot]);
                }
                transition_attempted=1;
                if(!transition_ok || transition_context.memory_fault.pending || transition_context.segment_fault_pending ||
                   transition_context.interrupt_trap_pending || transition_context.port_io_trap.pending) continuation_ok=0;
                /* Advance one more original game-frame cycle on the interface
                   that the phase-9 PlugIn actually published. The constructor
                   table's LE fixups are checked in Python; this runtime guard
                   proves the constructor wrote that vtable into currentIFC. */
                if(continuation_ok) {
                    const uint32_t next_ifc=*(uint32_t *)(memory+0x002EF7E8u);
                    const uint32_t next_vptr=(next_ifc<=GUEST_LIMIT-11u)?*(uint32_t *)(memory+next_ifc+7u):0u;
                    const uint32_t next_update=(next_vptr<=GUEST_LIMIT-12u)?*(uint32_t *)(memory+next_vptr+8u):0u;
                    const uint32_t next_draw=(next_vptr<=GUEST_LIMIT-16u)?*(uint32_t *)(memory+next_vptr+12u):0u;
                    fprintf(interaction,"post_transition_interface current=%08x pending=%08x vptr=%08x slot0=%08x slot1=%08x slot2=%08x slot3=%08x\n",
                        next_ifc,*(uint32_t *)(memory+0x002EF7ECu),next_vptr,
                        next_vptr<=GUEST_LIMIT-4u?*(uint32_t *)(memory+next_vptr):0u,
                        next_vptr<=GUEST_LIMIT-8u?*(uint32_t *)(memory+next_vptr+4u):0u,
                        next_update,next_draw);
                    /* FUN_000862F0's record callback vptr is the relocated
                       object-3 table at LE 0x1121E4. The two slots exercised
                       by this continuation are proven in Python against the
                       canonical LE fixups, then checked as loaded guest data. */
                    const uint32_t record_vptr=0x002EC1E4u;
                    const uint32_t record_slot_3c=*(uint32_t *)(memory+record_vptr+0x3Cu);
                    const uint32_t record_slot_60=*(uint32_t *)(memory+record_vptr+0x60u);
                    fprintf(interaction,"post_transition_record_vtable guest=%08x slot3c=%08x slot60=%08x backing=%u provenance=object3-LE-fixups-112220-112244\n",
                        record_vptr,record_slot_3c,record_slot_60,
                        in_guest(0x14u,record_vptr,0x64u,NULL));
                    if(!in_guest(0x14u,record_vptr,0x64u,NULL) ||
                       record_slot_3c!=0x002701B0u || record_slot_60!=0x00270070u) {
                        fprintf(interaction,"post_transition_record_vtable rejected: loaded slots differ from exact LE fixups\n");
                        continuation_ok=0;
                    }
                    if(next_ifc!=0x0035FEB0u || next_vptr!=0x002EBF68u ||
                       next_update!=0x0026E3D0u || next_draw!=0x0026E3C0u) {
                        fprintf(interaction,"post_transition_interface rejected: live object/vtable differs from the canonical LE fixup table\n");
                        continuation_ok=0;
                    } else {
                        gw_recomp_context next_input={0},next_update_context={0},next_draw_context={0};
                        unsigned release_events=0u;
                        if(mouse_button_down) {
                            if(!push_sdl_button(SDL_MOUSEBUTTONUP,320,240)) continuation_ok=0;
                            else { mouse_button_down=0; release_events=poll_sdl_into_lbdisplay(memory); }
                        }
                        uint32_t calls_before=g_icall_count;
                        int next_input_ok=continuation_ok &&
                            invoke(gw_original_setup_controller_entry,&next_input,0x5B170u,memory,0u,0u);
                        int next_update_ok=next_input_ok && !next_input.memory_fault.pending &&
                            !next_input.segment_fault_pending && !next_input.interrupt_trap_pending &&
                            !next_input.port_io_trap.pending &&
                            invoke(gw_original_control_game_update_dispatch,&next_update_context,0x5AF12u,memory,0u,0u);
                        fprintf(interaction,"post_transition_update input_ok=%d release_events=%u update_ok=%d eip=%08x esp=%08x eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x ebp=%08x flags=%08x icall_delta=%u current=%08x pending=%08x faults=%u/%08x:%u:%u:%08x seg=%u:%04x:%08x int=%u:%02x:%08x port_trap=%u:reason=%u:eip=%08x:value=%08x\n",
                            next_input_ok,release_events,next_update_ok,next_update_context.eip,next_update_context.esp,
                            next_update_context.eax,next_update_context.ebx,next_update_context.ecx,next_update_context.edx,
                            next_update_context.esi,next_update_context.edi,next_update_context.ebp,
                            recomp_eflags(next_update_context.flag_k,next_update_context.flag_a,next_update_context.flag_b,
                                next_update_context.flag_cf,1u),g_icall_count-calls_before,
                            *(uint32_t *)(memory+0x002EF7E8u),*(uint32_t *)(memory+0x002EF7ECu),
                            next_update_context.memory_fault.pending,next_update_context.memory_fault.linear,
                            next_update_context.memory_fault.segment,next_update_context.memory_fault.width,
                            next_update_context.memory_fault.instruction_va,next_update_context.segment_fault_pending,
                            next_update_context.segment_fault_selector,next_update_context.segment_fault_instruction_va,
                            next_update_context.interrupt_trap_pending,next_update_context.interrupt_vector,
                            next_update_context.interrupt_instruction_va,next_update_context.port_io_trap.pending,
                            next_update_context.port_io_trap.reason,next_update_context.port_io_trap.guest_va,
                            next_update_context.port_io_trap.value);
                        if(!next_update_ok || next_update_context.memory_fault.pending ||
                           next_update_context.segment_fault_pending || next_update_context.interrupt_trap_pending ||
                           next_update_context.port_io_trap.pending) {
                            fprintf(interaction,"post_transition_update failed_closed=1\n");
                            uint32_t first= g_icall_count>12u?g_icall_count-12u:0u;
                            for(uint32_t ci=first;ci<g_icall_count;ci++) {
                                uint32_t cs=ci&(ICALL_TRACE_SIZE-1u);
                                fprintf(interaction,"post_transition_icall seq=%u caller=%08x target=%08x\n",
                                    ci,g_icall_from[cs],g_icall_trace[cs]);
                            }
                            continuation_ok=0;
                        } else {
                            const uint32_t draw_calls_before=g_icall_count;
                            g_ifclevel_draw_dispatch_target=0u; g_ifclevel_draw_dispatch_caller=0u;
                            g_ifclevel_draw_dispatch_count=0u;
                            int next_draw_ok=invoke(gw_original_draw_game_draw_dispatch,&next_draw_context,
                                0x83559u,memory,0u,0u);
                            unsigned changed=0u;
                            if(next_draw_ok && !next_draw_context.memory_fault.pending &&
                               !next_draw_context.segment_fault_pending && !next_draw_context.interrupt_trap_pending &&
                               !next_draw_context.port_io_trap.pending) {
                                /* Count writes are attributed to the original guest draw by the runtime. */
                                for(uint32_t wi=0;wi<640u*480u;wi++) if(memory[level_wscreen+wi]!=0u) changed++;
                            }
                            fprintf(interaction,"post_transition_draw draw_ok=%d eip=%08x esp=%08x icall_delta=%u dispatch=%u/%08x/%08x changed_nonzero=%u current=%08x pending=%08x faults=%u/%08x:%u:%u:%08x seg=%u:%04x:%08x int=%u:%02x:%08x port_trap=%u:reason=%u:eip=%08x:value=%08x\n",
                                next_draw_ok,next_draw_context.eip,next_draw_context.esp,g_icall_count-draw_calls_before,
                                g_ifclevel_draw_dispatch_count,g_ifclevel_draw_dispatch_caller,
                                g_ifclevel_draw_dispatch_target,changed,*(uint32_t *)(memory+0x002EF7E8u),
                                *(uint32_t *)(memory+0x002EF7ECu),next_draw_context.memory_fault.pending,
                                next_draw_context.memory_fault.linear,next_draw_context.memory_fault.segment,
                                next_draw_context.memory_fault.width,next_draw_context.memory_fault.instruction_va,
                                next_draw_context.segment_fault_pending,next_draw_context.segment_fault_selector,
                                next_draw_context.segment_fault_instruction_va,next_draw_context.interrupt_trap_pending,
                                next_draw_context.interrupt_vector,next_draw_context.interrupt_instruction_va,
                                next_draw_context.port_io_trap.pending,next_draw_context.port_io_trap.reason,
                                next_draw_context.port_io_trap.guest_va,next_draw_context.port_io_trap.value);
                            if(!next_draw_ok || next_draw_context.memory_fault.pending ||
                               next_draw_context.segment_fault_pending || next_draw_context.interrupt_trap_pending ||
                               next_draw_context.port_io_trap.pending || g_ifclevel_draw_dispatch_count!=1u ||
                               g_ifclevel_draw_dispatch_caller!=0x83559u ||
                               g_ifclevel_draw_dispatch_target!=0x0026E3C0u) {
                                continuation_ok=0;
                            } else {
                                /* draw_game's own post-dispatch path owns any fade; do not
                                   force IFCLevel's type-2 palette tail onto this class. */
                                fprintf(interaction,"post_transition_frame=1 original_setup_controller+control_game+draw_game slot2=833D0/716E0 slot3=833C0/71E70 palette_tail=left_to_original_draw_game_control_flow\n");
                                /* The original Update just published the loader
                                   singleton at link 0x185E9A. Record its live
                                   constructor-established vtable and then let
                                   the exact game() transition run once. Any
                                   unlisted PlugIn target remains a runtime
                                   fail-closed frontier. */
                                const uint32_t pending2=*(uint32_t *)(memory+0x002EF7ECu);
                                if(pending2==0x0035FE9Au) {
                                    uint32_t vptr2=*(uint32_t *)(memory+pending2+7u);
                                    uint32_t slot0=vptr2<=GUEST_LIMIT-4u?*(uint32_t *)(memory+vptr2):0u;
                                    uint32_t slot1=vptr2<=GUEST_LIMIT-8u?*(uint32_t *)(memory+vptr2+4u):0u;
                                    uint32_t slot2=vptr2<=GUEST_LIMIT-12u?*(uint32_t *)(memory+vptr2+8u):0u;
                                    uint32_t slot3=vptr2<=GUEST_LIMIT-16u?*(uint32_t *)(memory+vptr2+12u):0u;
                                    fprintf(interaction,"pending_loader_candidate guest=%08x vptr=%08x slots=%08x/%08x/%08x/%08x vtable_backed=%u object_prefix=%08x/%08x/%08x provenance=original-Update-store-185E9A\n",
                                        pending2,vptr2,slot0,slot1,slot2,slot3,
                                        in_guest(0x14u,vptr2,16u,NULL),
                                        *(uint32_t *)(memory+pending2),*(uint32_t *)(memory+pending2+2u),
                                        *(uint32_t *)(memory+pending2+7u));
                                    if(vptr2==0x002EBB04u && slot0==0x002101A0u &&
                                       slot1==0x00210190u && slot2==0x00210180u &&
                                       slot3==0x00210170u && in_guest(0x14u,vptr2,16u,NULL)) {
                                        gw_recomp_context transition2={0};
                                        uint32_t transition2_icalls=g_icall_count;
                                        g_transition_dispatch_count=0u; g_transition_dispatch_enabled=1;
                                        int transition2_ok=invoke(gw_original_game_interface_transition_entry,
                                            &transition2,0x92819u,memory,0u,0u);
                                        g_transition_dispatch_enabled=0;
                                        fprintf(interaction,"pending_loader_transition attempted=1 ok=%d eip=%08x esp=%08x current=%08x pending=%08x dispatches=%u targets=%08x/%08x memfault=%u:%08x segfault=%u:%04x:%08x int=%u:%02x:%08x port=%u:%04x:%08x icall_delta=%u\n",
                                            transition2_ok,transition2.eip,transition2.esp,
                                            *(uint32_t *)(memory+0x002EF7E8u),*(uint32_t *)(memory+0x002EF7ECu),
                                            g_transition_dispatch_count,
                                            g_transition_dispatch_count>0?g_transition_dispatch[0].target:0u,
                                            g_transition_dispatch_count>1?g_transition_dispatch[1].target:0u,
                                            transition2.memory_fault.pending,transition2.memory_fault.linear,
                                            transition2.segment_fault_pending,transition2.segment_fault_selector,
                                            transition2.segment_fault_instruction_va,
                                            transition2.interrupt_trap_pending,transition2.interrupt_vector,
                                            transition2.interrupt_instruction_va,transition2.port_io_trap.pending,
                                            transition2.port_io_trap.port,transition2.port_io_trap.guest_va,
                                            g_icall_count-transition2_icalls);
                                        if(!transition2_ok) {
                                            uint32_t first=g_icall_count>8u?g_icall_count-8u:0u;
                                            for(uint32_t ci=first;ci<g_icall_count;ci++) {
                                                uint32_t cs=ci&(ICALL_TRACE_SIZE-1u);
                                                fprintf(interaction,"pending_loader_icall seq=%u caller=%08x target=%08x\n",
                                                    ci,g_icall_from[cs],g_icall_trace[cs]);
                                            }
                                        } else if(transition2.memory_fault.pending ||
                                                  transition2.segment_fault_pending ||
                                                  transition2.interrupt_trap_pending ||
                                                  transition2.port_io_trap.pending) {
                                            fprintf(interaction,"pending_loader_transition returned-with-trap=1; no further guest dispatch attempted\n");
                                        } else {
                                            uint32_t current2=*(uint32_t *)(memory+0x002EF7E8u);
                                            uint32_t pending3=*(uint32_t *)(memory+0x002EF7ECu);
                                            uint32_t vptr3=current2<=GUEST_LIMIT-11u?
                                                *(uint32_t *)(memory+current2+7u):0u;
                                            fprintf(interaction,"pending_loader_plug_in_complete current=%08x pending=%08x vptr=%08x dispatches=%u targets=%08x/%08x\n",
                                                current2,pending3,vptr3,g_transition_dispatch_count,
                                                g_transition_dispatch_count>0?g_transition_dispatch[0].target:0u,
                                                g_transition_dispatch_count>1?g_transition_dispatch[1].target:0u);
                                            if(current2==pending2 && pending3==0u) {
                                                gw_recomp_context load_input={0},load_update={0},load_draw={0};
                                                int load_input_ok=invoke(gw_original_setup_controller_entry,
                                                    &load_input,0x5B170u,memory,0u,0u);
                                                int load_update_ok=load_input_ok && !load_input.memory_fault.pending &&
                                                    !load_input.segment_fault_pending && !load_input.interrupt_trap_pending &&
                                                    !load_input.port_io_trap.pending &&
                                                    invoke(gw_original_control_game_update_dispatch,&load_update,
                                                        0x5AF12u,memory,0u,0u);
                                                fprintf(interaction,"pending_loader_update input_ok=%d update_ok=%d eip=%08x current=%08x pending=%08x mem=%u/%08x seg=%u:%04x:%08x int=%u:%02x:%08x port=%u:%04x:%08x icall_delta=%u\n",
                                                    load_input_ok,load_update_ok,load_update.eip,
                                                    *(uint32_t *)(memory+0x002EF7E8u),*(uint32_t *)(memory+0x002EF7ECu),
                                                    load_update.memory_fault.pending,load_update.memory_fault.linear,
                                                    load_update.segment_fault_pending,load_update.segment_fault_selector,
                                                    load_update.segment_fault_instruction_va,load_update.interrupt_trap_pending,
                                                    load_update.interrupt_vector,load_update.interrupt_instruction_va,
                                                    load_update.port_io_trap.pending,load_update.port_io_trap.port,
                                                    load_update.port_io_trap.guest_va,g_icall_count-transition2_icalls);
                                                if(!load_update_ok && load_update.port_io_trap.pending &&
                                                   load_update.port_io_trap.guest_va==0x000215ACu) {
                                                    const uint32_t object=load_update.eax;
                                                    const uint32_t dispatch=load_update.ebx;
                                                    const uint32_t slot=dispatch+4u;
                                                    fprintf(interaction,"pending_loader_frontier site=000215ac instruction=FF5304 object=%08x object_plus6=%08x dispatch=%08x slot=%08x target=%08x esi=%08x edx=%08x esp=%08x ebp=%08x lazy_cf=%08x\n",
                                                        object,
                                                        in_guest(0x14u,object+6u,4u,NULL)?guest_u32_for_trace(object+6u):0u,
                                                        dispatch,slot,
                                                        in_guest(0x14u,slot,4u,NULL)?guest_u32_for_trace(slot):0u,
                                                        load_update.esi,load_update.edx,load_update.esp,
                                                        load_update.ebp,load_update.flag_cf);
                                                    for(uint32_t off=0u;off<0x20u;off+=4u) {
                                                        const uint32_t oa=object+off, da=dispatch+off;
                                                        fprintf(interaction,"pending_loader_frontier_word offset=%02x object=%08x dispatch=%08x\n",
                                                            off,in_guest(0x14u,oa,4u,NULL)?guest_u32_for_trace(oa):0u,
                                                            in_guest(0x14u,da,4u,NULL)?guest_u32_for_trace(da):0u);
                                                    }
                                                    fprintf(interaction,"pending_loader_frontier_stack esp=%08x",load_update.esp);
                                                    for(uint32_t si=0u;si<16u && load_update.esp+4u*si+4u<=GUEST_LIMIT;si++)
                                                        fprintf(interaction," %08x",guest_u32_for_trace(load_update.esp+4u*si));
                                                    fprintf(interaction,"\n");
                                                }
                                                if(load_update_ok && !load_update.memory_fault.pending &&
                                                   !load_update.segment_fault_pending && !load_update.interrupt_trap_pending &&
                                                   !load_update.port_io_trap.pending) {
                                                    g_ifclevel_draw_dispatch_target=0u;
                                                    g_ifclevel_draw_dispatch_caller=0u;
                                                    g_ifclevel_draw_dispatch_count=0u;
                                                    uint8_t *loader_draw_before=(uint8_t *)malloc(640u*480u);
                                                    if(loader_draw_before) memcpy(loader_draw_before,
                                                        memory+level_wscreen,640u*480u);
                                                    int load_draw_ok=invoke(gw_original_draw_game_draw_dispatch,
                                                        &load_draw,0x83559u,memory,0u,0u);
                                                    uint32_t loader_frontier_slot=load_draw.edx<=GUEST_LIMIT-0x6Cu?
                                                        load_draw.edx+0x68u:0xFFFFFFFFu;
                                                    uint32_t loader_frontier_target=loader_frontier_slot!=0xFFFFFFFFu?
                                                        *(uint32_t *)(memory+loader_frontier_slot):0xFFFFFFFFu;
                                                    fprintf(interaction,"pending_loader_draw draw_ok=%d eip=%08x dispatch=%u/%08x/%08x current=%08x pending=%08x eax=%08x edx=%08x frontier_slot=%08x frontier_target=%08x mem=%u/%08x seg=%u:%04x:%08x int=%u:%02x:%08x port=%u:%04x:%08x reason=%u operation=%08x value=%08x\n",
                                                        load_draw_ok,load_draw.eip,g_ifclevel_draw_dispatch_count,
                                                        g_ifclevel_draw_dispatch_caller,g_ifclevel_draw_dispatch_target,
                                                        *(uint32_t *)(memory+0x002EF7E8u),*(uint32_t *)(memory+0x002EF7ECu),
                                                        load_draw.eax,load_draw.edx,loader_frontier_slot,loader_frontier_target,
                                                        load_draw.memory_fault.pending,load_draw.memory_fault.linear,
                                                        load_draw.segment_fault_pending,load_draw.segment_fault_selector,
                                                        load_draw.segment_fault_instruction_va,load_draw.interrupt_trap_pending,
                                                        load_draw.interrupt_vector,load_draw.interrupt_instruction_va,
                                                        load_draw.port_io_trap.pending,load_draw.port_io_trap.port,
                                                        load_draw.port_io_trap.guest_va,load_draw.port_io_trap.reason,
                                                        load_draw.port_io_trap.operation,load_draw.port_io_trap.value);
                                                    if(load_draw_ok && !load_draw.memory_fault.pending &&
                                                       !load_draw.segment_fault_pending && !load_draw.interrupt_trap_pending &&
                                                       !load_draw.port_io_trap.pending && g_ifclevel_draw_dispatch_count==1u &&
                                                       g_ifclevel_draw_dispatch_caller==0x83559u) {
                                                        unsigned changed=0;
                                                        if(loader_draw_before) {
                                                            for(uint32_t pi=0;pi<640u*480u;pi++)
                                                                if(loader_draw_before[pi]!=memory[level_wscreen+pi]) changed++;
                                                        }
                                                        FILE *post_raw=fopen("evidence/native_ifclevel_post_confirmation_wscreen.raw","wb");
                                                        int post_raw_ok=post_raw && fwrite(memory+level_wscreen,1,
                                                            640u*480u,post_raw)==640u*480u;
                                                        if(post_raw) fclose(post_raw);
                                                        post_loader_capture_ok=loader_draw_before && post_raw_ok && present_draw_sdl(
                                                            memory+level_wscreen,vga_dac,
                                                            "GeneWars 1.1 — post planet confirmation",
                                                            "evidence/native_ifclevel_post_confirmation_sdl.bmp");
                                                        fprintf(interaction,"post_loader_frame original_draw=1 target=%08x WScreen=%08x changed_bytes=%u raw=%d capture=%d raw_path=evidence/native_ifclevel_post_confirmation_wscreen.raw bmp=evidence/native_ifclevel_post_confirmation_sdl.bmp\n",
                                                            g_ifclevel_draw_dispatch_target,level_wscreen,changed,post_raw_ok,
                                                            post_loader_capture_ok);
                                                        /* The preview helper closes SDL after the BMP is saved.
                                                           Reopen the event subsystem before accepting new SDL input. */
                                                        if(post_loader_capture_ok) {
                                                            if(SDL_Init(SDL_INIT_VIDEO)==0) sdl_input_initialized=1;
                                                            else {
                                                                fprintf(interaction,"post_loader_sdl_reinit failed error=%s\n",SDL_GetError());
                                                                post_loader_frontier=1;
                                                            }
                                                        }
                                                        const uint32_t post_tick_surface_bytes=0x4B000u;
                                                        uint8_t *post_tick_before=(level_wscreen<=GUEST_LIMIT &&
                                                            post_tick_surface_bytes<=GUEST_LIMIT-level_wscreen)?
                                                            (uint8_t *)malloc(post_tick_surface_bytes):NULL;
                                                        if(!post_tick_before) {
                                                            fprintf(interaction,"post_loader_tick_stats unavailable=1 WScreen=%08x bytes=%u\n",
                                                                level_wscreen,post_tick_surface_bytes);
                                                            post_loader_frontier=1;
                                                        }
                                                        /* Snapshot the live MyGadget chain built by the original
                                                           interface PlugIn before injecting any mouse event. */
                                                        if(!post_loader_frontier) {
                                                            uint32_t gadget=*(uint32_t *)(memory+0x00379490u);
                                                            fprintf(interaction,"post_loader_live_gadgets head=%08x\n",gadget);
                                                            for(unsigned gi=0;gi<64u && gadget;gi++) {
                                                                if(gadget>GUEST_LIMIT || 0x28u>GUEST_LIMIT-gadget) {
                                                                    fprintf(interaction,"post_loader_live_gadget_invalid index=%u addr=%08x\n",gi,gadget);
                                                                    break;
                                                                }
                                                                uint32_t flags=*(uint32_t *)(memory+gadget);
                                                                if(flags==0u) {
                                                                    fprintf(interaction,"post_loader_live_gadget_end index=%u addr=%08x\n",gi,gadget);
                                                                    break;
                                                                }
                                                                int16_t gx=*(int16_t *)(memory+gadget+4u);
                                                                int16_t gy=*(int16_t *)(memory+gadget+6u);
                                                                int16_t gw=*(int16_t *)(memory+gadget+8u);
                                                                int16_t gh=*(int16_t *)(memory+gadget+10u);
                                                                int16_t gid=*(int16_t *)(memory+gadget+12u);
                                                                uint32_t click_fn=*(uint32_t *)(memory+gadget+0x0eu);
                                                                uint32_t help_fn=*(uint32_t *)(memory+gadget+0x22u);
                                                                fprintf(interaction,"post_loader_live_gadget index=%u guest=%08x flags=%08x x=%d y=%d w=%d h=%d id=%d click_fn=%08x help_fn=%08x\n",
                                                                    gi,gadget,flags,gx,gy,gw,gh,gid,click_fn,help_fn);
                                                                uint32_t next=0u;
                                                                if((flags&2u)!=0u && (flags&1u)==0u)
                                                                    next=*(uint32_t *)(memory+gadget+0x1eu);
                                                                if(next) gadget=next;
                                                                else gadget+=0x28u;
                                                            }
                                                        }
                                                        /* Capture 40 bounded original interface frames. The harness
                                                           calls setup_controller and the original virtual Update
                                                           dispatch, but does not call all of control_game/game(). */
                                                        memset(&ifclevel_member_writes,0,sizeof ifclevel_member_writes);
                                                        ifclevel_member_writes.effect_slot_address=0x002EC1E8u;
                                                        recomp_null_ds_read_diag_enable(1);
                                                        set_guest_write_observer(capture_ifclevel_member_write,
                                                            &ifclevel_member_writes);
                                                        const char *ui_only_env=getenv("GWRECOMP_IFCLEVEL_UI_ONLY");
                                                        const int surface_ui_only=ui_only_env && ui_only_env[0]=='1';
                                                        if(surface_ui_only)
                                                            fprintf(interaction,"TRACE isolated_surface_UI_only process_packets=skipped reason=fail_closed_frontier_00088146; original_control_game_Update_Draw_and_timer=enabled\n");
                                                        for(unsigned post_tick=0;post_tick<40u && !post_loader_frontier;post_tick++) {
                                                            gw_test_mapdisplay_pick_begin(post_tick);
                                                            gw_recomp_context pu={0},pp={0},pd={0},pt={0};
                                                            const char *input_label="none";
                                                            int input_push_ok=-1;
                                                            unsigned events=0u;
                                                            if(post_tick==12u) {
                                                                /* Live LE record id=18: x=50..138,y=19..107.
                                                                   Center (94,63) maps to host (188,126). */
                                                                input_label="SDL_mouse_down_planet_gadget18_host_188_126";
                                                                input_push_ok=push_sdl_button(SDL_MOUSEBUTTONDOWN,188,126);
                                                                if(input_push_ok) events=poll_sdl_into_lbdisplay(memory);
                                                                if(events==1u) post_loader_key_events++;
                                                                else post_loader_input_misses++;
                                                            } else if(post_tick==13u) {
                                                                input_label="SDL_mouse_up_planet_gadget18_host_188_126";
                                                                input_push_ok=push_sdl_button(SDL_MOUSEBUTTONUP,188,126);
                                                                if(input_push_ok) events=poll_sdl_into_lbdisplay(memory);
                                                                if(events==1u) post_loader_key_events++;
                                                                else post_loader_input_misses++;
                                                            } else if(post_tick==14u) {
                                                                /* Live LE record id=0: x=19..54,y=177..212.
                                                                   Center (36,194) maps to host (73,389). */
                                                                input_label="SDL_mouse_down_slot_gadget0_host_73_389";
                                                                input_push_ok=push_sdl_button(SDL_MOUSEBUTTONDOWN,73,389);
                                                                if(input_push_ok) events=poll_sdl_into_lbdisplay(memory);
                                                                if(events==1u) post_loader_key_events++;
                                                                else post_loader_input_misses++;
                                                            } else if(post_tick==15u) {
                                                                input_label="SDL_mouse_up_slot_gadget0_host_73_389";
                                                                input_push_ok=push_sdl_button(SDL_MOUSEBUTTONUP,73,389);
                                                                if(input_push_ok) events=poll_sdl_into_lbdisplay(memory);
                                                                if(events==1u) post_loader_key_events++;
                                                                else post_loader_input_misses++;
                                                            } else if(post_tick==18u) {
                                                                /* Live viewport id=5 is x=128..639,y=0..479;
                                                                   this logical point is inside the map surface. */
                                                                input_label="SDL_mouse_down_viewport_id5_host_768_480";
                                                                input_push_ok=push_sdl_button(SDL_MOUSEBUTTONDOWN,768,480);
                                                                if(input_push_ok) events=poll_sdl_into_lbdisplay(memory);
                                                                if(events==1u) post_loader_key_events++;
                                                                else post_loader_input_misses++;
                                                            } else if(post_tick==19u) {
                                                                input_label="SDL_mouse_up_viewport_id5_host_768_480";
                                                                input_push_ok=push_sdl_button(SDL_MOUSEBUTTONUP,768,480);
                                                                if(input_push_ok) events=poll_sdl_into_lbdisplay(memory);
                                                                if(events==1u) post_loader_key_events++;
                                                                else post_loader_input_misses++;
                                                            } else if(post_tick==22u) {
                                                                /* Re-test the id=7 control after hitting the id=0
                                                                   specialist slot and the original viewport. The hit
                                                                   test alone does not prove world-entity selection. */
                                                                input_label="SDL_mouse_down_activation_gadget7_host_23_819";
                                                                input_push_ok=push_sdl_button(SDL_MOUSEBUTTONDOWN,23,819);
                                                                if(input_push_ok) events=poll_sdl_into_lbdisplay(memory);
                                                                if(events==1u) post_loader_key_events++;
                                                                else post_loader_input_misses++;
                                                            } else if(post_tick==23u) {
                                                                input_label="SDL_mouse_up_activation_gadget7_host_23_819";
                                                                input_push_ok=push_sdl_button(SDL_MOUSEBUTTONUP,23,819);
                                                                if(input_push_ok) events=poll_sdl_into_lbdisplay(memory);
                                                                if(events==1u) post_loader_key_events++;
                                                                else post_loader_input_misses++;
                                                            } else if(post_tick==24u) {
                                                                /* Exercise the game's original MapDisplay edge-scroll
                                                                   path. Host (768,0) maps to guest cursor (384,0), the
                                                                   top edge; subsequent ticks keep the pointer there. */
                                                                input_label="SDL_mouse_motion_map_top_edge_host_768_0";
                                                                input_push_ok=push_sdl_motion(768,0);
                                                                if(input_push_ok) events=poll_sdl_into_lbdisplay(memory);
                                                                if(events==1u) post_loader_key_events++;
                                                                else post_loader_input_misses++;
                                                            } else if(post_tick==32u) {
                                                                /* The live type-5 map candidate observed at tick 32 was
                                                                   projected to (178,163) after the top-edge scroll tick.
                                                                   First stop scrolling; the next motion targets the exact
                                                                   projection reported by the original picker observer. */
                                                                input_label="SDL_mouse_motion_projected_map_candidate_host_356_390";
                                                                input_push_ok=push_sdl_motion(356,390);
                                                                if(input_push_ok) events=poll_sdl_into_lbdisplay(memory);
                                                                if(events==1u) post_loader_key_events++;
                                                                else post_loader_input_misses++;
                                                            } else if(post_tick==33u) {
                                                                input_label="SDL_mouse_motion_exact_candidate_host_356_326";
                                                                input_push_ok=push_sdl_motion(356,326);
                                                                if(input_push_ok) events=poll_sdl_into_lbdisplay(memory);
                                                                if(events==1u) post_loader_key_events++;
                                                                else post_loader_input_misses++;
                                                            } else if(post_tick==34u) {
                                                                input_label="SDL_mouse_down_projected_map_candidate_host_356_326";
                                                                input_push_ok=push_sdl_button(SDL_MOUSEBUTTONDOWN,356,326);
                                                                if(input_push_ok) events=poll_sdl_into_lbdisplay(memory);
                                                                if(events==1u) post_loader_key_events++;
                                                                else post_loader_input_misses++;
                                                            } else if(post_tick==35u) {
                                                                input_label="SDL_mouse_up_projected_map_candidate_host_356_326";
                                                                input_push_ok=push_sdl_button(SDL_MOUSEBUTTONUP,356,326);
                                                                if(input_push_ok) events=poll_sdl_into_lbdisplay(memory);
                                                                if(events==1u) post_loader_key_events++;
                                                                else post_loader_input_misses++;
                                                            } else {
                                                                events=poll_sdl_into_lbdisplay(memory);
                                                                if(events!=0u) post_loader_input_misses++;
                                                            }
                                                            const uint32_t current_ifc_before=
                                                                *(uint32_t *)(memory+0x002EF7E8u);
                                                            uint32_t thunk_adjust_before=0u,method_this_before=0u;
                                                            if(current_ifc_before>=4u &&
                                                               in_guest(0x14u,current_ifc_before-4u,4u,NULL)) {
                                                                thunk_adjust_before=*(uint32_t *)(memory+current_ifc_before-4u);
                                                                method_this_before=current_ifc_before-thunk_adjust_before;
                                                            }
                                                            if(method_this_before<GUEST_LIMIT-0xC8u) {
                                                                ifclevel_member_writes.c7_address=method_this_before+0xC7u;
                                                                ifclevel_member_writes.c8_address=method_this_before+0xC8u;
                                                            }
                                                            const uint32_t c7_writes_before=ifclevel_member_writes.c7_writes;
                                                            const uint32_t c8_writes_before=ifclevel_member_writes.c8_writes;
                                                            const uint32_t null_reads_before=recomp_null_ds_read_diag_count();
                                                            const uint8_t c7_before=ifclevel_member_writes.c7_address<GUEST_LIMIT?
                                                                memory[ifclevel_member_writes.c7_address]:0xFFu;
                                                            const uint32_t c8_before=ifclevel_member_writes.c8_address<GUEST_LIMIT-4u?
                                                                *(uint32_t *)(memory+ifclevel_member_writes.c8_address):0xFFFFFFFFu;
                                                            /* Execute the complete original control_game body. It calls
                                                               setup_controller, W_Update_Computer, and the active IFC's
                                                               virtual Update in their original order. The previous test
                                                               called setup_controller plus only the 3-instruction virtual
                                                               dispatch slice, omitting the controller's surrounding work. */
                                                            int pu_ok=invoke(recomp_gw_partial_W_control_game_n_v,
                                                                &pu,0x5AE60u,memory,0u,0u);
                                                            /* game() runs process_packets immediately after
                                                               control_game and before draw_game. */
                                                            const uint32_t process_packets_trace_start=g_icall_trace_idx;
                                                            int pp_ok=pu_ok && !pu.memory_fault.pending &&
                                                                !pu.segment_fault_pending && !pu.interrupt_trap_pending &&
                                                                !pu.port_io_trap.pending;
                                                            if(pp_ok && !surface_ui_only)
                                                                pp_ok=invoke(recomp_gw_partial_W_process_packets_n_v,
                                                                    &pp,0x93010u,memory,0u,0u);
                                                            /* The original picker consumes MapDisplay link 0x16CD70
                                                               at its verified Obj3 guest location 0x346D70. Capture the
                                                               exact runtime EAX/EDX arguments and resulting +0x37/+0x18. */
                                                            uint32_t effect_virtual_calls_recent=0u;
                                                            uint32_t trace_begin=process_packets_trace_start;
                                                            if(g_icall_trace_idx-trace_begin>ICALL_TRACE_SIZE)
                                                                trace_begin=g_icall_trace_idx-ICALL_TRACE_SIZE;
                                                            for(uint32_t seq=trace_begin;seq<g_icall_trace_idx;seq++) {
                                                                uint32_t slot=seq&(ICALL_TRACE_SIZE-1u);
                                                                if((g_icall_from[slot]==0x00086810u ||
                                                                    g_icall_from[slot]==0x00078B30u) &&
                                                                   g_icall_trace[slot]==0x002552E0u)
                                                                    effect_virtual_calls_recent++;
                                                            }
                                                            if(!surface_ui_only)
                                                                fprintf(interaction,"TRACE process_packets effect_coordinate_calls_recent=%u callers=00086810,00078B30 expected_target=002552e0 trace_window=%u..%u result=%d eip=%08x\n",
                                                                    effect_virtual_calls_recent,trace_begin,g_icall_trace_idx,
                                                                    pp_ok,pp.eip);
                                                            uint32_t now=*(uint32_t *)(memory+0x002EF7E8u);
                                                            uint32_t pending_now=*(uint32_t *)(memory+0x002EF7ECu);
                                                            recomp_null_ds_read_diagnostic null_read=
                                                                recomp_null_ds_read_diag_last();
                                                            const uint8_t c7_after=ifclevel_member_writes.c7_address<GUEST_LIMIT?
                                                                memory[ifclevel_member_writes.c7_address]:0xFFu;
                                                            const uint32_t c8_after=ifclevel_member_writes.c8_address<GUEST_LIMIT-4u?
                                                                *(uint32_t *)(memory+ifclevel_member_writes.c8_address):0xFFFFFFFFu;
                                                            if(!pu_ok || pu.memory_fault.pending || pu.segment_fault_pending ||
                                                               pu.interrupt_trap_pending || pu.port_io_trap.pending ||
                                                               !pp_ok || pp.memory_fault.pending || pp.segment_fault_pending ||
                                                               pp.interrupt_trap_pending || pp.port_io_trap.pending) {
                                                                if(pp.port_io_trap.pending &&
                                                                   pp.port_io_trap.guest_va==0x00045228u &&
                                                                   pp.eax<GUEST_LIMIT) {
                                                                    /* These absolute data references already include the measured
                                                                       object-3 delta in this lifted closure; DS selector 14h is flat. */
                                                                    const uint32_t packets_guest=0x002F1A3Cu;
                                                                    const uint32_t team_table_guest=0x0033C2D6u;
                                                                    const uint8_t packet_count=memory[packets_guest+3u];
                                                                    const int8_t packet_record=(int8_t)memory[packets_guest+4u];
                                                                    const uint32_t row_guest=(uint32_t)((int64_t)team_table_guest+
                                                                        (int64_t)packet_record*0xC8);
                                                                    const uint32_t row_this=row_guest+0x23u<GUEST_LIMIT-4u?
                                                                        *(uint32_t *)(memory+row_guest+0x23u):0xFFFFFFFFu;
                                                                    const uint32_t callback_slot=pp.ebx+0x64u;
                                                                    const uint32_t callback_value=callback_slot<GUEST_LIMIT-4u?
                                                                        *(uint32_t *)(memory+callback_slot):0xFFFFFFFFu;
                                                                    const uint32_t callback_link=callback_value-0x001EB000u;
                                                                    fprintf(interaction,
                                                                        "process_packets_frontier link_eip=00045228 mnemonic=call_[ebx+64] "
                                                                        "team_table_link=001622D6 object3_delta=001DA000 DS=%04x DS_BASE=%08x team_table_guest=%08x team_index=%d "
                                                                        "row_guest=%08x row_this=%08x packet_globals_link=00117A3C packet_globals_guest=%08x "
                                                                        "packet_count=%u first_packet_index=%d callback_object=%08x "
                                                                        "record_link=%08x record_matches=%u callback_slot=%08x callback_value=%08x callback_as_obj1_link=%08x "
                                                                        "callback_target_bytes=",
                                                                        g_seg_ds,g_ds_base,team_table_guest,(int)packet_record,row_guest,row_this,
                                                                        packets_guest,packet_count,(int)packet_record,pp.ebx,
                                                                        pp.eax-0x001DA000u,(unsigned)(row_this==pp.ebx),
                                                                        callback_slot,callback_value,callback_link);
                                                                    for(unsigned di=0;di<16u && callback_value+di<GUEST_LIMIT;di++)
                                                                        fprintf(interaction,"%02x",memory[callback_value+di]);
                                                                    fprintf(interaction," team_row_bytes=");
                                                                    for(unsigned di=0;di<0x30u && row_guest+di<GUEST_LIMIT;di++)
                                                                        fprintf(interaction,"%02x",memory[row_guest+di]);
                                                                    fprintf(interaction," object_bytes=");
                                                                    for(unsigned di=0;di<0x70u && pp.ebx+di<GUEST_LIMIT;di++)
                                                                        fprintf(interaction,"%02x",memory[pp.ebx+di]);
                                                                    fputc('\n',interaction);
                                                                }
                                                                if(pp.port_io_trap.pending &&
                                                                   pp.port_io_trap.guest_va==0x00054C19u &&
                                                                   pp.esi<GUEST_LIMIT-0x70u && pp.edx<GUEST_LIMIT-0x7Cu) {
                                                                    const uint32_t slot=pp.esi+0x68u;
                                                                    const uint32_t target=*(uint32_t *)(memory+slot);
                                                                    fprintf(interaction,
                                                                        "process_packets_creature_frontier eip=00054C19 mnemonic=call_[esi+68] "
                                                                        "list_link=00152F86 list_guest=%08x creature_this=%08x creature_link=%08x "
                                                                        "callback_object=%08x callback_object_link=%08x slot=%08x slot_link=%08x "
                                                                        "target=%08x target_as_obj1_link=%08x creature_bytes=",
                                                                        0x0032CF86u,pp.edx,pp.edx-0x001DA000u,
                                                                        pp.esi,pp.esi-0x001DA000u,slot,slot-0x001DA000u,
                                                                        target,target-0x001EB000u);
                                                                    for(unsigned di=0;di<0x7Cu;di++)
                                                                        fprintf(interaction,"%02x",memory[pp.edx+di]);
                                                                    fprintf(interaction," callback_object_bytes=");
                                                                    for(unsigned di=0;di<0x70u;di++)
                                                                        fprintf(interaction,"%02x",memory[pp.esi+di]);
                                                                    fputc('\n',interaction);
                                                                }
                                                                if(pp.port_io_trap.pending &&
                                                                   pp.port_io_trap.guest_va==0x0004B2EFu &&
                                                                   pp.edx<GUEST_LIMIT-0x98u) {
                                                                    const uint32_t slot=pp.edx+0x94u;
                                                                    const uint32_t target=*(uint32_t *)(memory+slot);
                                                                    fprintf(interaction,
                                                                        "process_packets_entity_frontier eip=0004B2EF mnemonic=call_[edx+94] "
                                                                        "this=%08x this_link=%08x edx=%08x callback_slot=%08x "
                                                                        "callback_link=00111D98 callback_value=%08x target_as_obj1_link=%08x "
                                                                        "object_bytes=",
                                                                        pp.eax,pp.eax-0x001DA000u,pp.edx,slot,target,
                                                                        target-0x001EB000u);
                                                                    for(unsigned di=0;di<0x98u;di++)
                                                                        fprintf(interaction,"%02x",memory[pp.edx+di]);
                                                                    fputc('\n',interaction);
                                                                }
                                                                gw_recomp_context *frontier=!pu_ok || pu.memory_fault.pending ||
                                                                    pu.segment_fault_pending || pu.interrupt_trap_pending ||
                                                                    pu.port_io_trap.pending?&pu:&pp;
                                                                fprintf(interaction,"post_loader_tick=%u input=%s push_ok=%d events=%u lbInkey=%02x update_counter=%u update_limit=%u control_game_ok=%d process_packets_ok=%d eip=%08x current=%08x pending=%08x mem=%u/%08x seg=%u:%04x:%08x int=%u:%02x:%08x port=%u:%04x:%08x frontier=1\n",
                                                                    post_tick,input_label,input_push_ok,events,memory[0x00376BF0u],
                                                                    memory[now+0x5A1u],*(uint32_t *)(memory+0x002F1499u),
                                                                    pu_ok,pp_ok,frontier->eip,now,pending_now,
                                                                    frontier->memory_fault.pending,frontier->memory_fault.linear,
                                                                    frontier->segment_fault_pending,frontier->segment_fault_selector,
                                                                    frontier->segment_fault_instruction_va,frontier->interrupt_trap_pending,
                                                                    frontier->interrupt_vector,frontier->interrupt_instruction_va,
                                                                    frontier->port_io_trap.pending,frontier->port_io_trap.port,
                                                                    frontier->port_io_trap.guest_va);
                                                                post_loader_frontier=1; break;
                                                            }
                                                            if(pending_now && pending_now!=now) {
                                                                gw_recomp_context tr={0};
                                                                int tr_ok=invoke(gw_original_game_interface_transition_entry,
                                                                    &tr,0x92819u,memory,0u,0u);
                                                                fprintf(interaction,"post_loader_tick=%u transition_ok=%d eip=%08x current=%08x pending=%08x mem=%u/%08x seg=%u:%04x:%08x int=%u:%02x:%08x port=%u:%04x:%08x\n",
                                                                    post_tick,tr_ok,tr.eip,
                                                                    *(uint32_t *)(memory+0x002EF7E8u),
                                                                    *(uint32_t *)(memory+0x002EF7ECu),
                                                                    tr.memory_fault.pending,tr.memory_fault.linear,
                                                                    tr.segment_fault_pending,tr.segment_fault_selector,
                                                                    tr.segment_fault_instruction_va,tr.interrupt_trap_pending,
                                                                    tr.interrupt_vector,tr.interrupt_instruction_va,
                                                                    tr.port_io_trap.pending,tr.port_io_trap.port,
                                                                    tr.port_io_trap.guest_va);
                                                                if(!tr_ok || tr.memory_fault.pending || tr.segment_fault_pending ||
                                                                   tr.interrupt_trap_pending || tr.port_io_trap.pending) {
                                                                    post_loader_frontier=1; break;
                                                                }
                                                            }
                                                            g_ifclevel_draw_dispatch_target=0u;
                                                            g_ifclevel_draw_dispatch_caller=0u;
                                                            g_ifclevel_draw_dispatch_count=0u;
                                                            const uint32_t post_draw_icalls_before=g_icall_trace_idx;
                                                            memcpy(post_tick_before,memory+level_wscreen,
                                                                   post_tick_surface_bytes);
                                                            int pd_ok=invoke(gw_original_draw_game_draw_dispatch,&pd,
                                                                0x83559u,memory,0u,0u);
                                                            /* Continue through draw_game's authentic post-Draw
                                                               palette branch. The dispatch-only slice above is the
                                                               virtual IFCLevel::Draw call; omitting 0x83A0C leaves
                                                               the captured framebuffer indexed with a zero DAC. */
                                                            gw_recomp_context pf={0};
                                                            int palette_tail_ok=pd_ok && !pd.memory_fault.pending &&
                                                                !pd.segment_fault_pending && !pd.interrupt_trap_pending &&
                                                                !pd.port_io_trap.pending && invoke(
                                                                    gw_original_draw_game_level_palette_fade_entry,
                                                                    &pf,0x83A0Cu,memory,0u,0u);
                                                            fprintf(interaction,"post_loader_palette_tick tick=%u ok=%d eip=%08x DAC_component_writes=%u faults=%u/%08x seg=%u:%04x:%08x int=%u:%02x:%08x port=%u:%04x:%08x\n",
                                                                post_tick,palette_tail_ok,pf.eip,vga_dac_component_writes,
                                                                pf.memory_fault.pending,pf.memory_fault.linear,
                                                                pf.segment_fault_pending,pf.segment_fault_selector,
                                                                pf.segment_fault_instruction_va,pf.interrupt_trap_pending,
                                                                pf.interrupt_vector,pf.interrupt_instruction_va,
                                                                pf.port_io_trap.pending,pf.port_io_trap.port,
                                                                pf.port_io_trap.guest_va);
                                                            /* Keep the per-tick MapDisplay census live through the
                                                               authentic IFC Draw and its original bucket construction. */
                                                            gw_test_mapdisplay_pick_finish(0x00346D70u);
                                                            uint32_t wscreen_changed=0u,dac_nonzero=0u;
                                                            uint32_t mygadget_callbacks=0u,last_mygadget_callback=0u;
                                                            for(uint32_t bi=0;bi<post_tick_surface_bytes;bi++)
                                                                wscreen_changed+=post_tick_before[bi]!=memory[level_wscreen+bi];
                                                            for(uint32_t bi=0;bi<sizeof vga_dac;bi++)
                                                                dac_nonzero+=vga_dac[bi]!=0u;
                                                            for(uint32_t seq=post_draw_icalls_before;seq<g_icall_trace_idx;seq++) {
                                                                uint32_t target=g_icall_trace[seq&(ICALL_TRACE_SIZE-1u)];
                                                                if(target==0x0020F830u || target==0x0020F1A0u ||
                                                                   target==0x0020F550u || target==0x0020F2F0u ||
                                                                   target==0x00278B30u) {
                                                                    mygadget_callbacks++; last_mygadget_callback=target;
                                                                }
                                                            }
                                                            fprintf(interaction,"post_loader_tick_stats tick=%u draw_ok=%d WScreen_changed=%u DAC_nonzero_components=%u DAC_component_writes=%u MyGadget_callbacks=%u last_callback=%08x target=%08x\n",
                                                                post_tick,pd_ok,wscreen_changed,dac_nonzero,
                                                                vga_dac_component_writes,mygadget_callbacks,
                                                                last_mygadget_callback,g_ifclevel_draw_dispatch_target);
                                                            uint32_t control_state_ptr=
                                                                ifclevel_member_writes.c8_address<GUEST_LIMIT-4u?
                                                                *(uint32_t *)(memory+ifclevel_member_writes.c8_address):0u;
                                                            unsigned control_flags=
                                                                ifclevel_member_writes.c7_address<GUEST_LIMIT?
                                                                memory[ifclevel_member_writes.c7_address]:0xffu;
                                                            unsigned control_state_flags=(control_state_ptr!=0u &&
                                                                control_state_ptr<GUEST_LIMIT-6u)?
                                                                memory[control_state_ptr+5u]:0xffu;
                                                            unsigned ui_gate=memory[0x002F1660u];
                                                            fprintf(interaction,"post_loader_tick=%u input=%s push_ok=%d events=%u lbInkey=%02x selected_gadget_id=%d mouse=%d,%d control_c7=%02x control_state=%08x/%02x ui_gate_2f1660=%02x update_counter=%u update_limit=%u update_ok=1 process_packets_mode=%s draw_ok=%d draw_eip=%08x dispatch=%u/%08x/%08x current=%08x pending=%08x mem=%u/%08x seg=%u:%04x:%08x int=%u:%02x:%08x port=%u:%04x:%08x\n",
                                                                post_tick,input_label,input_push_ok,events,memory[0x00376BF0u],
                                                                *(int16_t *)(memory+0x002EF816u),
                                                                *(int32_t *)(memory+0x00376AA8u),
                                                                *(int32_t *)(memory+0x00376AACu),
                                                                control_flags,control_state_ptr,control_state_flags,ui_gate,
                                                                memory[now+0x5A1u],*(uint32_t *)(memory+0x002F1499u),
                                                                surface_ui_only?"isolated-skip":"original",
                                                                pd_ok,pd.eip,g_ifclevel_draw_dispatch_count,
                                                                g_ifclevel_draw_dispatch_caller,g_ifclevel_draw_dispatch_target,
                                                                *(uint32_t *)(memory+0x002EF7E8u),*(uint32_t *)(memory+0x002EF7ECu),
                                                                pd.memory_fault.pending,pd.memory_fault.linear,
                                                                pd.segment_fault_pending,pd.segment_fault_selector,
                                                                pd.segment_fault_instruction_va,pd.interrupt_trap_pending,
                                                                pd.interrupt_vector,pd.interrupt_instruction_va,
                                                                pd.port_io_trap.pending,pd.port_io_trap.port,
                                                                pd.port_io_trap.guest_va);
                                                            uint32_t this_plus4_value=method_this_before<GUEST_LIMIT-8u?
                                                                *(uint32_t *)(memory+method_this_before+4u):0xFFFFFFFFu;
                                                            /* Link field 0x16CD88 belongs to mapDisplay at 0x16CD70.
                                                               Object-3's verified +0x1DA000 placement makes its guest
                                                               address 0x00346D88. Observe the original pointer/value
                                                               without substituting a harness-selected state. */
                                                            const uint32_t action_state_ptr_guest=0x00346D88u;
                                                            uint32_t action_state_ptr=action_state_ptr_guest<GUEST_LIMIT-4u?
                                                                *(uint32_t *)(memory+action_state_ptr_guest):0u;
                                                            unsigned action_state=action_state_ptr<GUEST_LIMIT-0x2Eu?
                                                                memory[action_state_ptr+0x2Du]:0xFFu;
                                                            unsigned c8_byte5=(c8_after!=0u && c8_after<GUEST_LIMIT-6u)?
                                                                memory[c8_after+5u]:0xFFu;
                                                            fprintf(interaction,"post_loader_member_state tick=%u current_ifc=%08x this_adjust=[ifc-4]=%08x method_this=%08x link_this=%08x this_plus4=%08x action_state_ptr=%08x action_state_2d=%02x c7_guest=%08x c7_link=%08x c7=%02x->%02x writes=%u last_eip=%08x c8_guest=%08x c8_link=%08x c8=%08x->%08x c8_byte5=%02x writes=%u last_eip=%08x null_ds14_reads=%u last_eip=%08x address=%08x width=%u\n",
                                                                post_tick,now,thunk_adjust_before,method_this_before,
                                                                method_this_before-0x1DA000u,
                                                                this_plus4_value,
                                                                action_state_ptr,action_state,
                                                                ifclevel_member_writes.c7_address,
                                                                ifclevel_member_writes.c7_address-0x1DA000u,
                                                                c7_before,c7_after,
                                                                ifclevel_member_writes.c7_writes-c7_writes_before,
                                                                ifclevel_member_writes.c7_last_eip,
                                                                ifclevel_member_writes.c8_address,
                                                                ifclevel_member_writes.c8_address-0x1DA000u,
                                                                c8_before,c8_after,
                                                                c8_byte5,
                                                                ifclevel_member_writes.c8_writes-c8_writes_before,
                                                                ifclevel_member_writes.c8_last_eip,
                                                                recomp_null_ds_read_diag_count()-null_reads_before,
                                                                null_read.guest_eip,null_read.linear,null_read.width);
                                                            if(!pd_ok || pd.memory_fault.pending || pd.segment_fault_pending ||
                                                               pd.interrupt_trap_pending || pd.port_io_trap.pending) {
                                                                post_loader_frontier=1; break;
                                                            }
                                                            if(!palette_tail_ok || pf.memory_fault.pending ||
                                                               pf.segment_fault_pending || pf.interrupt_trap_pending ||
                                                               pf.port_io_trap.pending) {
                                                                post_loader_frontier=1; break;
                                                            }
                                                            if(!invoke(gw_original_game_frame_timer_tick_entry,&pt,
                                                                0x928AFu,memory,0u,0u) || pt.memory_fault.pending ||
                                                                pt.segment_fault_pending || pt.interrupt_trap_pending ||
                                                                pt.port_io_trap.pending) {
                                                                fprintf(interaction,"post_loader_tick=%u timer_ok=0 eip=%08x frontier=1\n",post_tick,pt.eip);
                                                                post_loader_frontier=1; break;
                                                            }
                                                            post_loader_ticks++;
                                                        }
                                                        gw_test_mapdisplay_census_dump();
                                                        set_guest_write_observer(NULL,NULL);
                                                        recomp_null_ds_read_diag_enable(0);
                                                        if(post_tick_before) free(post_tick_before);
                                                    }
                                                    if(loader_draw_before) free(loader_draw_before);
                                                }
                                            }
                                        }
                                    } else {
                                        fprintf(interaction,"pending_loader_transition skipped=1 reason=live-vtable-differs-from-four-LE-fixups\n");
                                    }
                                }
                            }
                        }
                    }
                }
                break;
            }
            if(memory[level_this+0x9A9u]==8u && camera_stable_ticks>=128u) {
                phase8_stalled=1;
                fprintf(interaction,"stop=phase8-camera-stalled ticks=%u camera=%d,%d,%d target=%08x range=%d flags=%02x\n",
                    completed,camera_x,camera_y,camera_z,selected_target,
                    *(int32_t *)(memory+level_this+0x95Du),memory[level_this+0x9AAu]);
                break;
            }
        }
        uint32_t final_current=*(uint32_t *)(memory+0x002EF7E8u),final_pending=*(uint32_t *)(memory+0x002EF7ECu);
        int final_mcb_valid=validate_dos_mcb_chain(memory,vfs.dos.dos_segment_end);
        FILE *frame=fopen("evidence/native_ifclevel_gameplay_continue_wscreen.raw","wb");
        FILE *pal=fopen("evidence/native_ifclevel_gameplay_continue_palette6.raw","wb");
        int output_ok=frame && fwrite(memory+level_wscreen,1,640u*480u,frame)==640u*480u;
        int palette_ok=pal && fwrite(vga_dac,1,sizeof vga_dac,pal)==sizeof vga_dac;
        if(frame) fclose(frame); if(pal) fclose(pal);
        int bmp_ok=output_ok && palette_ok && present_draw_sdl(memory+level_wscreen,vga_dac,
            "GeneWars 1.1 — IFCLevel gameplay continuation","evidence/native_ifclevel_gameplay_continue_sdl.bmp");
        fprintf(interaction,"result completed_ticks=%u continuation_ok=%d transition_attempted=%d phase8_stalled=%d phase7_click=%d phase9_click=%d original_timer_instructions=%d currentIFC=%08x pendingIFC=%08x method_this_guest=%08x phase_9a9=%u proximity_flags_9aa=%02x selected_28=%u timer_117472=%u MCB_chain_valid=%d WScreen_backed=%d post_loader_ticks=%u post_loader_frontier=%d post_loader_capture=%d post_loader_key_events=%u post_loader_input_misses=%u raw=%s palette=%s bmp=%s\n",
            completed,continuation_ok,transition_attempted,phase8_stalled,phase7_click_sent,phase9_click_sent,timer_tick_count,
            final_current,final_pending,level_this,memory[level_this+0x9A9u],memory[level_this+0x9AAu],*(uint16_t *)(memory+level_this+0x28u),
            *(uint16_t *)(memory+0x002F1472u),final_mcb_valid,
            in_guest(0x14u,level_wscreen,640u*480u,NULL),
            post_loader_ticks,post_loader_frontier,post_loader_capture_ok,post_loader_key_events,
            post_loader_input_misses,
            "evidence/native_ifclevel_gameplay_continue_wscreen.raw","evidence/native_ifclevel_gameplay_continue_palette6.raw",
            "evidence/native_ifclevel_gameplay_continue_sdl.bmp");
        fclose(interaction); SDL_Quit();
        if(!continuation_ok || (!transition_attempted && !phase8_stalled && completed!=max_ticks) ||
           (transition_attempted && completed==0u) || timer_tick_count!=completed ||
           (transition_attempted && !post_loader_capture_ok) ||
           !final_mcb_valid || !output_ok || !palette_ok || !bmp_ok) {
            fprintf(stderr,"bounded IFCLevel interaction continuation failed ticks=%u ok=%d mcb=%d outputs=%d/%d/%d\n",
                completed,continuation_ok,final_mcb_valid,output_ok,palette_ok,bmp_ok);
            free(memory); return 121;
        }
        printf("PASS bounded original IFCLevel game-frame continuation ticks=%u original_timer_incs=%d currentIFC=%08x pendingIFC=%08x method_this=%08x phase=%u selected=%u SDL/raw/palette evidence saved phase7_click=%d phase9_click=%d transition_attempted=%d\n",
            completed,timer_tick_count,final_current,final_pending,level_this,
            memory[level_this+0x9A9u],*(uint16_t *)(memory+level_this+0x28u),
            phase7_click_sent,phase9_click_sent,transition_attempted);
    }
    gw_dos_descriptor_clear(&vfs.dos); gw_interrupt_set_callback(NULL,NULL);
    free(vfs.manifest); free(memory); return 0;
}
