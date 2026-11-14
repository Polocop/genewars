#ifndef GW_RECOMP_X87_H
#define GW_RECOMP_X87_H
#include <stdint.h>
/* Serialize the virtual pcrecomp x87 stack to the 32-bit protected-mode
 * 108-byte FSAVE image, then reset the virtual FPU as FNSAVE does. */
void recomp_fnsave_image(uint8_t *destination, double *stack, int *top, uint16_t *control_word, int64_t exact_i64[8]);
/* The virtual FPU has no asynchronous exception queue; ordering is still a compiler barrier. */
void recomp_fwait(void);
#endif
