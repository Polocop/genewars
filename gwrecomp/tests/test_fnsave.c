#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include "recomp_types.h"
#include "recomp_x87.h"
uint32_t g_eax,g_ecx,g_edx,g_ebx,g_esp,g_ebp,g_esi,g_edi,g_cur_func;
uint16_t g_seg_cs,g_seg_ds,g_seg_es,g_seg_fs,g_seg_gs,g_seg_ss;
uint32_t g_cs_base,g_ds_base,g_es_base,g_fs_base,g_gs_base,g_ss_base;
ptrdiff_t g_mem_base;
double g_st[8]; int g_fp_top; uint16_t g_fpu_cw;
extern void __save_8087_(void);
static uint8_t raw_mem[4096],lift_mem[4096]; static double seed=1.25;
static void fill(uint8_t *p,unsigned pat){for(unsigned i=0;i<sizeof(raw_mem);i++)p[i]=(uint8_t)(pat==0?0:pat==1?0xff:pat==2?i*17u:i*73u+pat*31u);}
int main(void){
 uint8_t *code=(uint8_t*)VirtualAlloc(NULL,4096,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE); if(!code)return 20;
 const uint8_t raw[]={0x9b,0xdd,0x30,0x9b,0xc3};memcpy(code,raw,sizeof(raw));
 for(unsigned pat=0;pat<4;pat++){
  fill(raw_mem,pat); uint16_t sw=0xffff;
  __asm__ volatile("fninit\n\tfldl %1\n\tmovl %2, %%eax\n\tcall *%3\n\tfnstsw %0\n\tfninit":"=m"(sw):"m"(seed),"r"(raw_mem),"r"(code):"eax","ecx","edx","memory","cc");
  if(sw!=0)return 21;
  fill(lift_mem,pat);g_mem_base=(ptrdiff_t)(uintptr_t)lift_mem-0x10000;
  memset(g_st,0,sizeof(g_st));g_st[0]=seed;g_fp_top=1;g_fpu_cw=0x037f;g_eax=0x10000;g_esp=0x5000;g_flag_k=FK_NONE;g_flag_a=g_flag_b=g_flag_cf=0;
  __save_8087_();
  if(g_fp_top!=0||g_fpu_cw!=0x037f||g_esp!=0x5004)return 22;
  /* IP, selector, opcode and data-pointer environment fields are not in the virtual CPU model. */
  memset(raw_mem+12,0,16);memset(lift_mem+12,0,16);
  if(memcmp(raw_mem,lift_mem,sizeof(raw_mem))!=0)return 23;
  uint16_t cw,fsw,tag;memcpy(&cw,lift_mem,2);memcpy(&fsw,lift_mem+4,2);memcpy(&tag,lift_mem+8,2);
  if(cw!=0x037f||fsw!=0x3800||tag!=0x3fff)return 24;
 }
 VirtualFree(code,0,MEM_RELEASE);puts("PASS __save_8087_ FNSAVE image, TOP reset, FWAIT x 4 patterns");return 0;
}


