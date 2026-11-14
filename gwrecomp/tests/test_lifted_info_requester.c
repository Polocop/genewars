#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include "../build/lifted_info_requester.c"

typedef void (__attribute__((cdecl)) * raw_fn)(void);

int main(void) {
    static const unsigned char raw[] = {
        0xC7,0x00,0xAC,0x58,0x10,0x00,
        0xC7,0x40,0x04,0x1C,0x59,0x10,0x00,
        0xC3
    };
    uint8_t native_out[16] = {0};
    uint8_t lifted_out[16] = {0};
    void *exec = VirtualAlloc(NULL, sizeof(raw), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!exec) return 10;
    memcpy(exec, raw, sizeof(raw));
    __asm__ volatile ("mov %0, %%eax\n\tcall *%1" :: "S"(native_out), "D"(exec) : "eax", "ecx", "edx", "memory", "cc");
    eax = 0x1010;
    lifted_info_requester_ctor();
    memcpy(lifted_out, guest_mem + 16, sizeof(lifted_out));
    printf("raw=%08X,%08X lifted=%08X,%08X\n",
        *(uint32_t*)(native_out), *(uint32_t*)(native_out+4),
        *(uint32_t*)(lifted_out), *(uint32_t*)(lifted_out+4));
    int same = memcmp(native_out, lifted_out, sizeof(native_out)) == 0;
    VirtualFree(exec, 0, MEM_RELEASE);
    return same ? 0 : 1;
}
