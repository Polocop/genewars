#include "recomp_x87.h"
#include <math.h>
#include <stdatomic.h>
#include <string.h>
#include "../third_party/pcrecomp/runtime/recomp32/recomp_types.h"

void recomp_fnsave_image(uint8_t *dst,double *st,int *top,uint16_t *cw,int64_t exact_i64[8]) {
    if(!dst || !st || !top || !cw) return;
    memset(dst,0,108);
    uint16_t status=(uint16_t)(((8u-(unsigned)(*top<0?0:*top>8?8:*top))&7u)<<11);
    uint16_t tag=0xffffu;
    memcpy(dst+0,cw,2); memcpy(dst+2,"\xff\xff",2);
    memcpy(dst+4,&status,2); memcpy(dst+6,"\xff\xff",2);
    memcpy(dst+8,&tag,2); memcpy(dst+10,"\xff\xff",2);
    /* Instruction/data pointers and opcode are not modeled by this virtual x87. */
    memset(dst+12,0,12); memcpy(dst+26,"\xff\xff",2);
    int count=*top; if(count<0) count=0; if(count>8) count=8;
    unsigned phys_top=(8u-(unsigned)count)&7u;
    for(int i=0;i<count;i++) {
        unsigned physical=(phys_top+(unsigned)i)&7u;
        double value=st[i];
        unsigned kind=(isnan(value)||isinf(value)||fpclassify(value)==FP_SUBNORMAL)?2u:(value==0.0?1u:0u);
        tag=(uint16_t)((tag&~(3u<<(physical*2u)))|(kind<<(physical*2u)));
        long double ext=(exact_i64 && exact_i64[i])?(long double)exact_i64[i]:(long double)value;
        /* 32-bit FSAVE stores logical ST(0)..ST(7), 10 bytes each. */
        memcpy(dst+28+i*10,&ext,10);
    }
    memcpy(dst+8,&tag,2);
    for(int i=0;i<8;i++) { st[i]=0.0; if(exact_i64) exact_i64[i]=0; }
    *top=0; *cw=0x037fu;
}
void recomp_fwait(void) { atomic_signal_fence(memory_order_seq_cst); }
