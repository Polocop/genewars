#include "recomp_context.h"
#include "gw_segments.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void gw_partial_0x000830F0(void);
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
int gw_partial_install_code_map(void);

uint32_t g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp,g_cur_func;
uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_fs,g_seg_gs,g_seg_ss,g_fpu_cw;
uint32_t g_fs_base,g_gs_base;
ptrdiff_t g_mem_base;
double g_st[8]; int g_fp_top;
uint32_t g_icall_trace[ICALL_TRACE_SIZE],g_icall_from[ICALL_TRACE_SIZE];
uint32_t g_icall_trace_idx,g_icall_count;

enum { GUEST_SIZE=0x400000u, IMAGE_BASE=0xF0000u, STACK_BEGIN=0x3FD000u,
       STACK_TOP=0x3FF000u, OBJECT1_BEGIN=0x1FB000u, OBJECT1_END=0x2D9930u,
       OBJECT3_BEGIN=0x2DA000u, OBJECT3_END=0x382C50u, IFCTITLE_OBJECT=0x35EAB8u };
static const uint32_t callback_link_targets[]={
    0x2C3D0u,0x2C520u,0x2C560u,0x34F50u,0x834A0u,
    0x957B0u,0x69C80u,0x957C0u,0x957E0u,0x957D0u,
    0x95830u,0x95880u,0x95890u,0x958E0u
};

static uint8_t *memory;
static int guest_range(uint16_t selector,uint32_t offset,uint32_t width,void *user) {
    (void)user;
    if (selector!=0x14u || !width || offset>GUEST_SIZE || width>GUEST_SIZE-offset) return 0;
    return (offset>=OBJECT1_BEGIN && offset+width<=OBJECT1_END) ||
           (offset>=OBJECT3_BEGIN && offset+width<=OBJECT3_END) ||
           (offset>=STACK_BEGIN && offset+width<=GUEST_SIZE);
}

recomp_func_t recomp_lookup_manual(uint32_t va) { (void)va; return NULL; }
recomp_func_t recomp_lookup_import(uint32_t va) { (void)va; return NULL; }
recomp_func_t recomp_lookup(uint32_t va) {
    switch (va) {
    case 0x0002C3D0u: return gw_partial_0x0002C3D0;
    case 0x0002C520u: return gw_partial_0x0002C520;
    case 0x0002C560u: return gw_partial_0x0002C560;
    case 0x00034F50u: return gw_partial_0x00034F50;
    case 0x000834A0u: return gw_partial_0x000834A0;
    case 0x000957B0u: return gw_partial_0x000957B0;
    case 0x00069C80u: return gw_partial_0x00069C80;
    case 0x000957C0u: return gw_partial_0x000957C0;
    case 0x000957E0u: return gw_partial_0x000957E0;
    case 0x000957D0u: return gw_partial_0x000957D0;
    case 0x00095830u: return gw_partial_0x00095830;
    case 0x00095880u: return gw_partial_0x00095880;
    case 0x00095890u: return gw_partial_0x00095890;
    case 0x000958E0u: return gw_partial_0x000958E0;
    default: return NULL;
    }
}

int main(int argc,char **argv) {
    if (argc!=2) return 2;
    memory=(uint8_t *)calloc(GUEST_SIZE,1u);
    if (!memory) return 3;
    FILE *f=fopen(argv[1],"rb");
    if (!f) { free(memory); return 4; }
    if (fread(memory+IMAGE_BASE,1,0x293000u,f)!=0x293000u || fgetc(f)!=EOF) {
        fclose(f); free(memory); return 5;
    }
    fclose(f);
    if (!gw_partial_install_code_map()) { free(memory); return 6; }
    g_mem_base=(ptrdiff_t)(uintptr_t)memory;
    recomp_set_memory_bounds(0,GUEST_SIZE);
    recomp_set_segment_range_validator(guest_range,NULL);

    /* Explicit experimental call state: static CRT initializers are normally
       invoked with implementation-defined volatile register contents. The
       no-argument constructor gets a bounded zeroed stack and flat selectors;
       this does not claim to reproduce the original process entry state. */
    gw_recomp_context c; memset(&c,0,sizeof c);
    c.eax=0; c.ebx=0; c.ecx=0; c.edx=0; c.esi=0; c.edi=0; c.ebp=0;
    c.esp=STACK_TOP; c.eip=0x830F0u; c.cur_func=0x830F0u;
    c.cs=0x0Cu; c.ds=0x14u; c.es=0x14u; c.ss=0x14u;
    c.mem_base=(ptrdiff_t)(uintptr_t)memory; c.mem_guest_base=0; c.mem_size=GUEST_SIZE;
    c.fpu_cw=0x127Fu;
    *(uint32_t *)(memory+STACK_TOP)=RECOMP_RETADDR;
    uint32_t before=*(uint32_t *)(memory+IFCTITLE_OBJECT);
    uint8_t object_before[64];
    memcpy(object_before,memory+IFCTITLE_OBJECT,sizeof object_before);
    if (gw_recomp_invoke(gw_partial_0x000830F0,&c)!=GW_RECOMP_OK ||
        c.memory_fault.pending || c.segment_fault_pending || c.interrupt_trap_pending ||
        c.port_io_trap.pending || c.esp!=STACK_TOP+4u || c.cur_func!=0x830F0u) {
        fprintf(stderr,"ctor bounded invoke failed eip=%08x eax=%08x esp=%08x cur=%08x memfault=%u/%08x/%08x segfault=%u:%04x@%08x trap=%u:%u@%08x icalls=%u\n",
                c.eip,c.eax,c.esp,c.cur_func,c.memory_fault.pending,c.memory_fault.linear,
                c.memory_fault.instruction_va,c.segment_fault_pending,
                c.segment_fault_selector,c.segment_fault_instruction_va,
                c.port_io_trap.pending,c.port_io_trap.reason,
                c.port_io_trap.guest_va,g_icall_count);
        free(memory); return 7;
    }
    uint32_t after=*(uint32_t *)(memory+IFCTITLE_OBJECT);
    if (after!=0x002EBA98u || before==after || g_icall_count!=2156u ||
        *(uint32_t *)(memory+IFCTITLE_OBJECT+4u)!=0x002E0D88u ||
        *(uint32_t *)(memory+IFCTITLE_OBJECT+0x18u)!=0x002EC050u ||
        *(uint32_t *)(memory+IFCTITLE_OBJECT+0x1Cu)!=0x20u ||
        *(uint32_t *)(memory+IFCTITLE_OBJECT+0x2Cu)!=0x002EBA88u ||
        *(uint32_t *)(memory+IFCTITLE_OBJECT+0x30u)!=0x002E0E50u) {
        fprintf(stderr,"unexpected ctor object state before=%08x after=%08x icalls=%u\n",
                before,after,g_icall_count);
        free(memory); return 8;
    }
    FILE *state=fopen("work\\ifctitle_ctor_object_before.bin","wb");
    if (!state || fwrite(object_before,1,sizeof object_before,state)!=sizeof object_before) {
        if (state) fclose(state); free(memory); return 10;
    }
    fclose(state);
    state=fopen("work\\ifctitle_ctor_object_after.bin","wb");
    if (!state || fwrite(memory+IFCTITLE_OBJECT,1,sizeof object_before,state)!=sizeof object_before) {
        if (state) fclose(state); free(memory); return 11;
    }
    fclose(state);
    printf("IFCTITLE_STATE before=");
    for (size_t i=0;i<sizeof object_before;i++) printf("%02x",object_before[i]);
    printf(" after=");
    for (size_t i=0;i<sizeof object_before;i++) printf("%02x",memory[IFCTITLE_OBJECT+i]);
    printf("\n");
    uint32_t traced=g_icall_count<ICALL_TRACE_SIZE?g_icall_count:ICALL_TRACE_SIZE;
    for (uint32_t i=0;i<traced;i++) {
        uint32_t va=g_icall_trace[i];
        uint32_t link=0;
        if (!recomp_code_linear_to_link(va,&link)) {
            fprintf(stderr,"indirect target has no verified linear-to-link map %08x from %08x\n",va,g_icall_from[i]);
            free(memory); return 9;
        }
        int allowed=0;
        for (size_t j=0;j<sizeof callback_link_targets/sizeof callback_link_targets[0];j++)
            if (link==callback_link_targets[j]) allowed=1;
        if (!allowed) { fprintf(stderr,"unexpected indirect link target %08x from %08x\n",link,g_icall_from[i]); free(memory); return 9; }
    }
    printf("PASS original initializer 0x830F0 under bounded experimental state; IFCTitle static slot 0x35EAB8=%08x; indirect calls=%u; return esp=%08x\n",
           after,g_icall_count,c.esp);
    free(memory);
    return 0;
}
