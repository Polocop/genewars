/* G-GP-002: synthetic coverage self-test for the guest write observer.
 *
 * Drives the real access macros (MEM8/MEM32/MEMF, MEMSEG32), the real
 * recomp_begin/end_memory_access and recomp_checked_segment_addr entry points,
 * and the real runtime/gw_segments.c. Guest memory is a private buffer; no
 * game state, snapshot, binary or oracle is touched.
 *
 * Each row prints one line:
 *   ROW <id> hits=<observer calls> stored=<0|1> fault=<0|1> linear=<hex> eip=<hex>
 * tests/test_guest_write_observer_coverage.py assigns the expectation and writes
 * the matrix. The "stored" flag separates "no observer call because the store
 * never happened" from "store happened but the observer was silent". */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../runtime/gw_segments.h"

uint32_t g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,g_cur_func;
uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_fs,g_seg_gs,g_seg_ss,g_fpu_cw;
uint32_t g_fs_base,g_gs_base;
ptrdiff_t g_mem_base;
double g_st[8]; int g_fp_top;

static uint8_t guest[0x4000];
static struct { unsigned hits; uint32_t eip, linear, width; } obs;
static int reject_all_ranges;

static void observe(uint32_t eip, recomp_segment_id seg, uint16_t sel, uint32_t base,
                    uint32_t linear, uint32_t width, void *user) {
    (void)seg; (void)sel; (void)base; (void)user;
    obs.hits++; obs.eip=eip; obs.linear=linear; obs.width=width;
}

static int range_validator(uint16_t sel, uint32_t off, uint32_t width, void *user) {
    (void)sel; (void)off; (void)width; (void)user;
    return !reject_all_ranges;
}

static void reset_row(void) {
    memset(&obs,0,sizeof obs);
    memset(guest,0,sizeof guest);
    recomp_write_census_clear();
    recomp_end_memory_access();
    recomp_clear_memory_fault();
    recomp_memory_diag_enable(0);
    reject_all_ranges=0;
    recomp_set_segment_range_validator(NULL,NULL);
    recomp_set_guest_write_observer(observe,NULL);
    g_seg_ds=0x14u; g_seg_es=0x1cu; g_seg_ss=0x14u; g_seg_cs=0x0cu;
    g_ds_base=0u; g_es_base=0u; g_ss_base=0u; g_cs_base=0u;
    g_eax=0x11111111u; g_ebx=0x22222222u; g_ecx=0x33333333u; g_edx=0x44444444u;
    g_esi=0x00000100u; g_edi=0x00000200u; g_ebp=0x3000u; g_esp=0x3800u;
}

static void row(const char *id,int stored) {
    recomp_memory_fault f=recomp_get_memory_fault();
    printf("ROW %s hits=%u stored=%d fault=%d linear=%08x eip=%08x\n",
           id,obs.hits,stored,f.pending?1:0,obs.linear,obs.eip);
    /* Opt-in census (GWRECOMP_WRITE_CENSUS=1): counts for this row only. */
    recomp_write_census_dump(id);
    recomp_clear_memory_fault();
    recomp_set_guest_write_observer(observe,NULL);
}

/* G1: generated plain store, as emitted for "mov byte ptr [ds+...], imm". */
static void g1(void) {
    reset_row();
    recomp_begin_memory_access_ex(RECOMP_SEG_DS,1u,0x00010023u,RECOMP_MEM_ACCESS_WRITE,460u,"mov");
    MEM8(DS_BASE+0x1000u)=(uint8_t)0x5Au;
    if (recomp_memory_fault_pending()) return;
    recomp_end_memory_access();
    row("G1_store_mov_byte_write",guest[0x1000]==0x5A);
}

/* G2: generated dword store through a computed address (mov [ebx+off], eax). */
static void g2(void) {
    reset_row();
    recomp_begin_memory_access_ex(RECOMP_SEG_DS,4u,0x00010027u,RECOMP_MEM_ACCESS_WRITE,460u,"mov");
    MEM32(DS_BASE+(g_ebx&0xFFu)+0x2000u)=g_eax;
    recomp_end_memory_access();
    row("G2_store_mov_dword_write",*(uint32_t *)(guest+0x2022u)==0x11111111u);
}

/* G3: generated push (SS:esp write). */
static void g3(void) {
    reset_row();
    g_esp=0x3800u;
    recomp_begin_memory_access_ex(RECOMP_SEG_SS,4u,0x00010030u,RECOMP_MEM_ACCESS_WRITE,609u,"push");
    MEM32(SS_BASE+(g_esp-4u))=0xCAFEBABEu;
    recomp_end_memory_access();
    row("G3_push_ss_write",*(uint32_t *)(guest+0x37FCu)==0xCAFEBABEu);
}

/* G4: generated read-modify-write (or byte ptr [m], imm): READWRITE window. */
static void g4(void) {
    reset_row();
    guest[0x1000]=0x01u;
    recomp_begin_memory_access_ex(RECOMP_SEG_DS,1u,0x0001038Fu,RECOMP_MEM_ACCESS_READWRITE,512u,"or");
    MEM8(DS_BASE+0x1000u)=(uint8_t)(MEM8(DS_BASE+0x1000u)|0x40u);
    recomp_end_memory_access();
    row("G4_rmw_or_byte_readwrite",guest[0x1000]==0x41u);
}

/* G5: x87 store (fstp dword ptr [m]) through MEMF. */
static void g5(void) {
    float v=1.5f;
    reset_row();
    recomp_begin_memory_access_ex(RECOMP_SEG_DS,4u,0x00010040u,RECOMP_MEM_ACCESS_WRITE,0u,"fstp");
    MEMF(DS_BASE+0x2100u)=v;
    recomp_end_memory_access();
    row("G5_fstp_dword_write",*(float *)(guest+0x2100u)==1.5f);
}

/* G6: generated read (no write intent). Included so a silent observer on
 * reads is distinguishable from a silent observer on writes. */
static void g6(void) {
    uint32_t v;
    reset_row();
    guest[0x1000]=0x7Fu;
    recomp_begin_memory_access_ex(RECOMP_SEG_DS,4u,0x00010050u,RECOMP_MEM_ACCESS_READ,460u,"mov");
    v=MEM32(DS_BASE+0x1000u);
    recomp_end_memory_access();
    row("G6_read_mov_dword_read",v==0x7Fu);
}

/* G7: generated plain store with opt-in memory diagnostics enabled. */
static void g7(void) {
    reset_row();
    recomp_memory_diag_enable(1);
    recomp_memory_diag_note_instruction(0x00010060u,460u,"mov",RECOMP_SEG_DS,
        RECOMP_MEM_ACCESS_WRITE,g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp);
    recomp_begin_memory_access_ex(RECOMP_SEG_DS,1u,0x00010060u,RECOMP_MEM_ACCESS_WRITE,460u,"mov");
    MEM8(DS_BASE+0x1100u)=(uint8_t)0x66u;
    recomp_end_memory_access();
    recomp_memory_diag_enable(0);
    row("G7_store_mov_byte_write_diag_on",guest[0x1100]==0x66u);
}

/* G8: store that never announced an access (access_active=0, diag off). */
static void g8(void) {
    reset_row();
    MEM8(DS_BASE+0x1200u)=(uint8_t)0x77u;
    row("G8_store_without_begin",guest[0x1200]==0x77u);
}

/* M1: a real store announced with READ intent (the lifter tags setcc/fistp/
 * fnstcw destinations this way). The observer only checks WRITE/READWRITE, so
 * the store is silent even though the byte changes. */
static void m1(void) {
    reset_row();
    recomp_begin_memory_access_ex(RECOMP_SEG_SS,1u,0x0002A508u,RECOMP_MEM_ACCESS_READ,0u,"setle");
    MEM8(SS_BASE+(g_esp+0x234u))=(uint8_t)1u;
    recomp_end_memory_access();
    row("M1_store_announced_as_read_setcc",guest[0x3800u+0x234u]==1u);
}

/* M2-M5: real store shapes from the lifted closure that are announced READ.
 * Each store happens; only the announced kind differs from a WRITE window.
 * Addresses are shrunk to fit the 16 KiB private buffer; the observer does not
 * use the address to decide, only the announced kind. */

/* M2: closure:70874 (0x00019717) "fistp dword ptr [esi+0x97d]", announced READ. */
static void m2(void) {
    reset_row();
    recomp_begin_memory_access_ex(RECOMP_SEG_DS,4u,0x00019717u,RECOMP_MEM_ACCESS_READ,253u,"fistp");
    MEM32(DS_BASE+(g_esi+0x97Du))=0x0BADC0DEu;
    recomp_end_memory_access();
    row("M2_store_announced_read_fistp_ds",*(uint32_t *)(guest+0x100u+0x97Du)==0x0BADC0DEu);
}

/* M3: closure:254849 (0x000374CA) "setb byte ptr [ebp-8]", announced READ. */
static void m3(void) {
    reset_row();
    recomp_begin_memory_access_ex(RECOMP_SEG_SS,1u,0x000374CAu,RECOMP_MEM_ACCESS_READ,660u,"setb");
    MEM8(SS_BASE+(g_ebp-0x8u))=(uint8_t)1u;
    recomp_end_memory_access();
    row("M3_store_announced_read_setb_ss",guest[0x3000u-0x8u]==1u);
}

/* M4: closure:849029 (0x000A38C0) "fnstcw word ptr [esp]", announced READ. */
static void m4(void) {
    reset_row();
    recomp_begin_memory_access_ex(RECOMP_SEG_SS,2u,0x000A38C0u,RECOMP_MEM_ACCESS_READ,195u,"fnstcw");
    MEM16(SS_BASE+(g_esp))=(uint16_t)0x037Fu;
    recomp_end_memory_access();
    row("M4_store_announced_read_fnstcw_ss",*(uint16_t *)(guest+0x3800u)==0x037Fu);
}

/* M5: closure:1114092 (0x000DD8B7) "rol dword ptr [0x2e703f], 4", announced READ.
 * Read-modify-write on memory whose store is announced READ, not READWRITE. */
static void m5(void) {
    reset_row();
    recomp_begin_memory_access_ex(RECOMP_SEG_DS,4u,0x000DD8B7u,RECOMP_MEM_ACCESS_READ,635u,"rol");
    MEM32(DS_BASE+(0xE00u))=(uint32_t)0x12345678u;
    recomp_end_memory_access();
    row("M5_store_announced_read_rol_mem_ds",*(uint32_t *)(guest+0xE00u)==0x12345678u);
}

/* C1: control. Same store as M2 (closure:70874) with the announced kind WRITE.
 * If C1 fires and M2 does not, the blindness comes from the announced kind. */
static void c1(void) {
    reset_row();
    recomp_begin_memory_access_ex(RECOMP_SEG_DS,4u,0x00019717u,RECOMP_MEM_ACCESS_WRITE,253u,"fistp");
    MEM32(DS_BASE+(g_esi+0x97Du))=0x0BADC0DEu;
    recomp_end_memory_access();
    row("C1_control_fistp_ds_announced_write",*(uint32_t *)(guest+0x100u+0x97Du)==0x0BADC0DEu);
}

/* S1: exact rep movsd block emitted by the lifter (closure 0x0006F78F, DF=0),
 * diagnostics off. Destination is ES:EDI via recomp_checked_segment_addr. */
static void s1_movsd(int diag) {
    reset_row();
    recomp_memory_diag_enable(diag);
    for (uint32_t i=0;i<4u;i++) *(uint32_t *)(guest+0x100u+4u*i)=0xA0A0A000u+i;
    g_esi=0x100u; g_edi=0x200u; g_ecx=4u;
    uint32_t _n=g_ecx; uint64_t _b64=(uint64_t)_n*4u;
    if (_n) {
        uint32_t _so=g_esi, _do=g_edi;
        if (recomp_memory_diag_enabled()) recomp_begin_memory_access_ex(RECOMP_SEG_DS,(uint32_t)_b64,0x000100AFu,RECOMP_MEM_ACCESS_READ,0u,"rep movs");
        uintptr_t _sp=recomp_checked_segment_addr(RECOMP_SEG_DS,_so,_b64,0x000100AFu);
        if (recomp_memory_diag_enabled()) recomp_end_memory_access();
        uintptr_t _dp=0;
        if (!recomp_memory_fault_pending()) {
            if (recomp_memory_diag_enabled()) recomp_begin_memory_access_ex(RECOMP_SEG_ES,(uint32_t)_b64,0x000100AFu,RECOMP_MEM_ACCESS_WRITE,0u,"rep movs");
            _dp=recomp_checked_segment_addr(RECOMP_SEG_ES,_do,_b64,0x000100AFu);
            if (recomp_memory_diag_enabled()) recomp_end_memory_access();
            if (!recomp_memory_fault_pending()) memcpy((void*)_dp,(void*)_sp,(size_t)_b64);
        }
    }
    recomp_memory_diag_enable(0);
}
static void s1a(void) { s1_movsd(0); row("S1a_rep_movsd_es_write_diag_off",*(uint32_t *)(guest+0x200u)==0xA0A0A000u); }
static void s1b(void) { s1_movsd(1); row("S1b_rep_movsd_es_write_diag_on",*(uint32_t *)(guest+0x200u)==0xA0A0A000u); }

/* S2: exact rep stosd block emitted by the lifter (closure 0x000AFBCB). */
static void s2(void) {
    uint32_t _n, edi=0x300u, eax=0xDEADBEEFu;
    uint64_t _b64;
    reset_row();
    _n=4u; _b64=(uint64_t)_n*4u;
    if (_n) {
        uint32_t _do=edi;
        uintptr_t _dp=recomp_checked_segment_addr(RECOMP_SEG_ES,_do,_b64,0x000AFBCBu);
        if (!recomp_memory_fault_pending()) {
            uint32_t _v=eax;
            for (uint64_t _i=0;_i<_b64;_i+=4) memcpy((void*)(_dp+(uintptr_t)_i),&_v,4);
        }
    }
    row("S2_rep_stosd_es_write",*(uint32_t *)(guest+0x300u)==0xDEADBEEFu);
}

/* S3: segmented string store as emitted for non-rep "movsd es:[edi], [esi]"
 * (closure 0x0001090E): MEMSEG32 on ES. */
static void s3(void) {
    reset_row();
    *(uint32_t *)(guest+0x400u)=0x0BADF00Du;
    g_esi=0x400u; g_edi=0x500u;
    { uint32_t _v=MEMSEG32(RECOMP_SEG_DS,g_esi,0x0001090Eu);
      if (!recomp_memory_fault_pending()) { MEMSEG32(RECOMP_SEG_ES,g_edi,0x0001090Eu)=_v; } }
    row("S3_movsd_nonrep_memseg32_es",*(uint32_t *)(guest+0x500u)==0x0BADF00Du);
}

/* S4: MEMSEG store after an explicit WRITE announcement. Shows whether the
 * announced kind survives recomp_checked_segment_addr (it does not: the call
 * resets access_kind to UNKNOWN before the observer check). */
static void s4(void) {
    reset_row();
    recomp_begin_memory_access_ex(RECOMP_SEG_ES,4u,0x00010070u,RECOMP_MEM_ACCESS_WRITE,460u,"mov");
    MEMSEG32(RECOMP_SEG_ES,0x600u,0x00010070u)=0x12345678u;
    recomp_end_memory_access();
    row("S4_memseg32_es_store_after_begin_write",*(uint32_t *)(guest+0x600u)==0x12345678u);
}

/* H1: host service writes guest memory through recomp_checked_segment_addr,
 * the same entry used by the DOS read path (gw_dos_services.c:582). */
static void h1(void) {
    reset_row();
    uint8_t src[8]={1,2,3,4,5,6,7,8};
    recomp_write_census_set_host_scope(1);
    uint8_t *buffer=(uint8_t *)recomp_checked_segment_addr(RECOMP_SEG_DS,0x700u,8u,0x00020000u);
    recomp_write_census_set_host_scope(0);
    if (!recomp_memory_fault_pending()) memcpy(buffer,src,8u);
    row("H1_host_dos_read_checked_segment_addr",guest[0x700]==1u && guest[0x707]==8u);
}

/* H2: host helper takes a translated pointer with ADDR() and writes through it. */
static void h2(void) {
    reset_row();
    uint8_t *p=(uint8_t *)ADDR(0x800u);
    p[0]=0x99u;
    row("H2_host_addr_translated_pointer",guest[0x800]==0x99u);
}

/* H3: bulk host copy straight into the mapped guest image (no runtime call on
 * the path), as a snapshot restore or loader would do. */
static void h3(void) {
    uint8_t src[16];
    reset_row();
    memset(src,0xC3,sizeof src);
    memcpy(guest+0x900u,src,sizeof src);
    row("H3_host_bulk_copy_into_guest_image",guest[0x900]==0xC3u);
}

/* E1: store rejected by the segment range validator (fail-closed). */
static void e1(void) {
    reset_row();
    recomp_set_segment_range_validator(range_validator,NULL);
    reject_all_ranges=1;
    recomp_begin_memory_access_ex(RECOMP_SEG_DS,4u,0x00010080u,RECOMP_MEM_ACCESS_WRITE,460u,"mov");
    MEM32(DS_BASE+0xA00u)=0xFFFFFFFFu;
    recomp_end_memory_access();
    row("E1_store_rejected_by_range_validator",guest[0xA00]==0xFFu);
}

/* E2: store after a first memory fault with diagnostics on (suppressed). */
static void e2(void) {
    reset_row();
    recomp_memory_diag_enable(1);
    recomp_begin_memory_access_ex(RECOMP_SEG_DS,4u,0x00010090u,RECOMP_MEM_ACCESS_READ,460u,"mov");
    g_seg_ds=0u;
    (void)MEM32(DS_BASE+0xB00u);
    recomp_end_memory_access();
    g_seg_ds=0x14u;
    recomp_begin_memory_access_ex(RECOMP_SEG_DS,4u,0x00010094u,RECOMP_MEM_ACCESS_WRITE,460u,"mov");
    MEM32(DS_BASE+0xB04u)=0x0BADCAFEu;
    recomp_end_memory_access();
    recomp_memory_diag_enable(0);
    row("E2_store_after_first_fault_diag_on",guest[0xB04]==0xFEu);
}

/* E3: translated pointer (width 0, ADDR-style) obtained inside an announced
 * WRITE window. The observer fires at address resolution, before the host
 * store, so a pointer taken inside a WRITE window is observed even if the
 * caller never dereferences it. */
static void e3(void) {
    reset_row();
    recomp_begin_memory_access_ex(RECOMP_SEG_DS,1u,0x000100A0u,RECOMP_MEM_ACCESS_WRITE,460u,"mov");
    uint8_t *p=(uint8_t *)recomp_checked_mem_addr(0xC00u,0u);
    p[0]=0x5Eu;
    recomp_end_memory_access();
    row("E3_translated_pointer_inside_write_window",guest[0xC00]==0x5Eu);
}

int main(void) {
    memset(guest,0,sizeof guest);
    g_mem_base=(ptrdiff_t)(uintptr_t)guest;
    g1(); g2(); g3(); g4(); g5(); g6(); g7(); g8(); m1();
    m2(); m3(); m4(); m5(); c1();
    s1a(); s1b(); s2(); s3(); s4();
    h1(); h2(); h3();
    e1(); e2(); e3();
    recomp_set_guest_write_observer(NULL,NULL);
    recomp_set_segment_range_validator(NULL,NULL);
    puts("DONE observer coverage self-test rows");
    return 0;
}
