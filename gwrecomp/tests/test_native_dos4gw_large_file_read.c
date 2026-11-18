#include "recomp_context.h"
#include "gw_dos_services.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

uint32_t g_eax,g_ebx,g_ecx,g_edx,g_esi,g_edi,g_ebp,g_esp;
uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_fs,g_seg_gs,g_seg_ss;
uint32_t g_fs_base,g_gs_base;
uint32_t g_flag_k,g_flag_a,g_flag_b,g_flag_cf;
double g_st[8]; int g_fp_top; uint16_t g_fpu_cw; uint32_t g_cur_func;
ptrdiff_t g_mem_base;

enum { GUEST_SIZE=0x00300000u, DEST=0x00010000u,
       REQUESTED=0x0004b000u, FILE_SIZE=139405u };
static uint8_t guest[GUEST_SIZE];
static uint8_t source[FILE_SIZE];
static uint32_t file_pos,read_calls,last_request;
static const char expected_path[]="data/titlescr.dat";

static uint16_t open_file(void *user,const char *path,uint8_t access,void **out) {
    (void)user;
    if (strcmp(path,expected_path) || access!=0 || !out) return 2;
    file_pos=0; *out=&file_pos; return 0;
}
static uint16_t read_file(void *user,void *file,uint8_t *buffer,
                          uint16_t requested,uint16_t *transferred) {
    (void)user;
    if (file!=&file_pos || !buffer || !transferred) return 6;
    read_calls++; last_request=requested;
    uint32_t available=FILE_SIZE-file_pos;
    uint16_t count=(uint16_t)(requested<available?requested:available);
    memcpy(buffer,source+file_pos,count); file_pos+=count; *transferred=count;
    return 0;
}
static uint16_t close_file(void *user,void *file) {
    (void)user; return file==&file_pos?0:6;
}
static int check(int value,const char *label) {
    if (!value) fprintf(stderr,"FAIL %s\n",label);
    return value;
}

int main(void) {
    gw_dos_services dos; memset(&dos,0,sizeof dos);
    for (uint32_t i=0;i<FILE_SIZE;i++) source[i]=(uint8_t)(i*37u+11u);
    g_seg_cs=g_seg_ds=g_seg_es=g_seg_ss=0x14u;
    g_ds_base=g_es_base=g_ss_base=0;
    g_mem_base=(ptrdiff_t)(uintptr_t)guest;
    recomp_set_memory_bounds(0,GUEST_SIZE); recomp_clear_memory_fault();
    gw_dos_services_init(&dos);
    if (!gw_dos_guest_memory_configure(&dos,GUEST_SIZE) ||
        !gw_dos_file_backend_configure(&dos,open_file,read_file,NULL,NULL,close_file,NULL)) return 1;

    memcpy(guest+0x100,expected_path,sizeof expected_path);
    g_eax=0x3d00u; g_ebx=0; g_ecx=0; g_edx=0x100; g_flag_cf=1;
    if (!check(gw_dos_services_callback(0x21,0x1234,&dos)==GW_INTERRUPT_HANDLED &&
               !g_flag_cf && (uint16_t)g_eax==5u,"DOS/4GW opens verified VFS path")) return 2;
    uint16_t handle=(uint16_t)g_eax;
    g_eax=0x3f00u; g_ebx=handle; g_ecx=REQUESTED; g_edx=DEST; g_flag_cf=1;
    if (!check(gw_dos_services_callback(0x21,0x1235,&dos)==GW_INTERRUPT_HANDLED &&
               !g_flag_cf && g_eax==FILE_SIZE,"32-bit DOS read returns full short-at-EOF count") ||
        !check(g_ecx==REQUESTED && g_edx==DEST,"read preserves request registers") ||
        !check(read_calls==3u && last_request==0xfff0u && file_pos==FILE_SIZE,
               "DOS/4GW splits transfer into sub-64-KiB reads") ||
        !check(memcmp(guest+DEST,source,FILE_SIZE)==0,
               "all bytes from fragmented VFS reads reach contiguous guest buffer") ||
        !check(!recomp_memory_fault_pending(),"large guest range remains valid")) return 3;
    printf("PASS DOS/4GW AH=3F 32-bit ECX=%u fragmented into %u reads; VFS EOF returned %u authentic bytes to guest 0x%08X\n",
           REQUESTED,read_calls,g_eax,DEST);
    return 0;
}
