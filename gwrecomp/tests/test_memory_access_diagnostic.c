#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../runtime/gw_segments.h"

uint32_t g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,g_cur_func;
uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_fs,g_seg_gs,g_seg_ss,g_fpu_cw;
uint32_t g_fs_base,g_gs_base;
ptrdiff_t g_mem_base;
double g_st[8]; int g_fp_top;

static uint8_t backing[16];
static int backed(uintptr_t host,uint32_t linear,uint32_t width,uint8_t access,void *user) {
    uintptr_t expected=(uintptr_t)user+(uintptr_t)(linear-0x1000u);
    (void)access;
    return linear>=0x1000u && (uint64_t)linear+width<=0x1010u && host==expected;
}

int main(void) {
    memset(backing,0,sizeof backing);
    g_mem_base=(ptrdiff_t)(uintptr_t)backing-(ptrdiff_t)0x1000u;
    g_seg_ds=0x30u; g_ds_base=0x1000u;
    recomp_set_memory_bounds(0x1000u,0x3000u);
    recomp_memory_diag_set_backing_validator(backed,backing);

    /* With diagnosis disabled, the old in-range helper contract is unchanged. */
    recomp_memory_diag_enable(0);
    MEM32(0x1000u)=0xA1B2C3D4u;
    if (MEM32(0x1000u)!=0xA1B2C3D4u || backing[0]!=0xD4u) return 10;

    recomp_memory_diag_enable(1);
    g_eax=0x11111111u; g_ebx=0x22222222u; g_ecx=0x33333333u;
    g_edx=0x44444444u; g_esi=0x55555555u; g_edi=0x66666666u;
    g_ebp=0x77777777u; g_esp=0x88888888u;
    recomp_memory_diag_set_dpmi_state(0x100u,0x40u,0,0x1a89a8u,
                                      8u,0x36u,0,0x1a89a8u,1u);
    recomp_memory_diag_note_instruction(0x12345678u,0x8Bu,"mov",RECOMP_SEG_DS,
        RECOMP_MEM_ACCESS_READ,g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp);
    recomp_memory_diag_set_guest_eip(0x12345678u);
    uint32_t got=MEM32(0x1000u);
    recomp_memory_diagnostic diag=recomp_memory_diag_last_access();
    if (got!=0xA1B2C3D4u || diag.linear!=0x1000u || diag.width!=4u ||
        diag.instruction_va!=0x12345678u || diag.guest_eip!=0x12345678u || diag.selector!=0x30u ||
        diag.segment_base!=0x1000u || diag.access!=RECOMP_MEM_ACCESS_READ ||
        diag.backing!=RECOMP_MEM_BACKING_COMMITTED ||
        diag.host_address!=(uintptr_t)backing || g_eax!=0x11111111u ||
        g_ebx!=0x22222222u || g_ecx!=0x33333333u || g_edx!=0x44444444u ||
        g_esi!=0x55555555u || g_edi!=0x66666666u || g_ebp!=0x77777777u ||
        g_esp!=0x88888888u) return 11;

    /* A selected guest range keeps the ordinary fast path outside the
     * instrumented function while retaining full validation inside it. */
    recomp_memory_diag_set_guest_range(0x12345679u,0x12345680u);
    uint32_t before=backing[0];
    recomp_begin_memory_access_ex(RECOMP_SEG_DS,4u,0x12345670u,
                                  RECOMP_MEM_ACCESS_READ,0x8Bu,"mov");
    uint32_t out_of_range=MEM32(0x1000u);
    recomp_end_memory_access();
    if (out_of_range!=0xA1B2C3D4u || backing[0]!=before) return 18;
    diag=recomp_memory_diag_last_access();
    if (diag.instruction_va!=0x12345678u || diag.linear!=0x1000u) return 19;
    recomp_memory_diag_set_guest_range(0u,0u);

    recomp_clear_memory_fault();
    recomp_memory_diag_set_guest_eip(0x12345679u);
    recomp_begin_memory_access_ex(RECOMP_SEG_DS,4u,0x12345679u,
                                  RECOMP_MEM_ACCESS_READ,0x8Bu,"mov");
    if (MEM32(0x2000u)!=0u) return 12;
    recomp_end_memory_access();
    recomp_memory_fault fault=recomp_get_memory_fault();
    diag=recomp_memory_diag_last_access();
    if (!fault.pending || fault.instruction_va!=0x12345679u || fault.linear!=0x2000u ||
        fault.selector!=0x30u || fault.width!=4u || diag.backing!=RECOMP_MEM_BACKING_UNCOMMITTED ||
        diag.access!=RECOMP_MEM_ACCESS_READ || diag.instruction_id!=0x8Bu ||
        !diag.register_snapshot_valid || diag.eax!=g_eax || diag.ebx!=g_ebx ||
        diag.ecx!=g_ecx || diag.edx!=g_edx || diag.esi!=g_esi || diag.edi!=g_edi ||
        diag.ebp!=g_ebp || diag.esp!=g_esp ||
        strcmp(diag.mnemonic,"mov") || diag.dpmi_req_eax!=0x100u ||
        diag.dpmi_res_eax!=8u || diag.dpmi_carry!=1u) return 13;

    recomp_clear_memory_fault();
    recomp_memory_diag_set_guest_eip(0x1234567Au);
    recomp_begin_memory_access_ex(RECOMP_SEG_DS,4u,0x1234567Au,
                                  RECOMP_MEM_ACCESS_WRITE,0x89u,"mov");
    MEM32(0x2000u)=0xFEEDFACEu;
    recomp_end_memory_access();
    fault=recomp_get_memory_fault(); diag=recomp_memory_diag_last_access();
    if (!fault.pending || diag.instruction_va!=0x1234567Au ||
        diag.access!=RECOMP_MEM_ACCESS_WRITE || diag.backing!=RECOMP_MEM_BACKING_UNCOMMITTED ||
        backing[0]!=0xD4u) {
        fprintf(stderr,"write fault pending=%u va=%08x access=%u backing=%u byte=%02x\n",
                fault.pending,diag.instruction_va,diag.access,diag.backing,backing[0]);
        return 14;
    }

    /* A later valid dereference in the same guest frame cannot overwrite the
     * first-fault evidence or touch backing after the controlled stop. */
    recomp_memory_diagnostic first_fault_diag=diag;
    recomp_memory_fault first_fault=fault;
    if (MEM32(0x1000u)!=0u || backing[0]!=0xD4u) return 16;
    diag=recomp_memory_diag_last_access(); fault=recomp_get_memory_fault();
    if (memcmp(&first_fault_diag,&diag,sizeof diag)!=0 ||
        memcmp(&first_fault,&fault,sizeof fault)!=0) return 17;

    /* A host exception boundary can read the last access even when no guest
     * memory-fault record was created for the host-side exception itself. */
    recomp_memory_diagnostic retained=recomp_memory_diag_last_access();
    recomp_memory_fault retained_fault=recomp_get_memory_fault();
    (void)retained_fault;
    diag=recomp_memory_diag_last_access();
    if (memcmp(&retained,&diag,sizeof diag)!=0) return 15;

    puts("PASS valid access unchanged; unbacked read/write fault with original instruction, selector, registers and DPMI state");
    return 0;
}
