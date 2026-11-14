#include "gw_vbe_provider.h"
#include <stddef.h>
#include <string.h>

enum {
    VBE_CONTROLLER_INFO_SIZE = 512,
    VBE_MODE_INFO_SIZE = 256,
    VBE_MODE_LIST_OFFSET = 0x200,
    VBE_OEM_STRING_OFFSET = 0x220,
    VBE_INFO_AREA_SIZE = 0x240,
    VBE_SUCCESS = 0x004f,
    VBE_FAILURE = 0x014f,
    VBE_UNSUPPORTED = 0x024f
};

static void put16(uint8_t *p, uint16_t value) {
    p[0]=(uint8_t)value; p[1]=(uint8_t)(value>>8);
}
static void put32(uint8_t *p, uint32_t value) {
    put16(p,(uint16_t)value); put16(p+2,(uint16_t)(value>>16));
}
static uint16_t low16(uint32_t value) { return (uint16_t)value; }
static void response(gw_dos_real_mode_registers *r, uint16_t ax, int carry) {
    r->eax=(r->eax&0xffff0000u)|ax;
    r->flags=(uint16_t)((r->flags&~1u)|(carry?1u:0u));
}

static int guest_span(const gw_vbe_device *d,uint32_t base,uint32_t size) {
    return d && d->guest_memory && size && base<=d->guest_memory_size &&
           size<=d->guest_memory_size-base;
}

static int real_mode_pointer(const gw_vbe_device *d,
                             const gw_dos_real_mode_registers *r,
                             uint32_t size,uint32_t *linear) {
    uint32_t offset=(uint16_t)r->edi;
    uint32_t address=((uint32_t)(uint16_t)r->es<<4)+offset;
    if (address>=0x100000u || size>0x100000u-address ||
        !guest_span(d,address,size)) return 0;
    *linear=address;
    return 1;
}

int gw_vbe_device_configure(gw_vbe_device *d,uint8_t *memory,
                            uint32_t memory_size,uint32_t buffer,
                            uint16_t mode,uint16_t width,uint16_t height,
                            uint16_t pitch,uint8_t bpp,uint16_t gran_kb,
                            uint16_t win_kb,uint16_t win_segment,
                            uint32_t video_bytes) {
    if (!d || !memory || !memory_size || !buffer || buffer>=0x100000u ||
        !mode || !width || !height || !pitch || !bpp || !gran_kb || !win_kb ||
        !win_segment || !video_bytes ||
        (uint64_t)buffer+VBE_INFO_AREA_SIZE>0x100000ull ||
        (uint64_t)buffer+VBE_INFO_AREA_SIZE>memory_size ||
        (uint64_t)pitch*height>video_bytes ||
        (uint64_t)gran_kb*1024u>video_bytes ||
        (uint64_t)win_kb*1024u>(uint64_t)gran_kb*1024u) return 0;
    memset(d,0,sizeof(*d));
    d->guest_memory=memory; d->guest_memory_size=memory_size;
    d->info_buffer_linear=buffer; d->mode=mode; d->width=width;
    d->height=height; d->pitch=pitch; d->bits_per_pixel=bpp;
    d->memory_model=(bpp==8u)?4u:6u;
    d->granularity_kb=gran_kb; d->window_size_kb=win_kb;
    d->window_a_segment=win_segment; d->video_memory_bytes=video_bytes;
    return 1;
}

static int controller_info(gw_vbe_device *d,gw_dos_real_mode_registers *r) {
    uint32_t out;
    if (!real_mode_pointer(d,r,VBE_CONTROLLER_INFO_SIZE,&out)) {
        response(r,VBE_FAILURE,1); return 1;
    }
    uint32_t list=d->info_buffer_linear+VBE_MODE_LIST_OFFSET;
    uint32_t oem=d->info_buffer_linear+VBE_OEM_STRING_OFFSET;
    if (!guest_span(d,list,4) || !guest_span(d,oem,28) || list>=0x100000u || oem>=0x100000u) {
        response(r,VBE_FAILURE,1); return 1;
    }
    uint8_t *b=d->guest_memory+out;
    memset(b,0,VBE_CONTROLLER_INFO_SIZE);
    memcpy(b,"VESA",4); put16(b+4,0x0200);
    put32(b+6,((oem>>4)<<16)|(oem&0x0fu));
    put32(b+10,0);
    put32(b+14,((list>>4)<<16)|(list&0x0fu));
    put16(b+18,(uint16_t)((d->video_memory_bytes+65535u)/65536u));
    memcpy(d->guest_memory+oem,"GeneWars host VBE fixture",26);
    d->guest_memory[oem+26]=0;
    put16(d->guest_memory+list,d->mode);
    put16(d->guest_memory+list+2,0xffffu);
    d->controller_info_calls++;
    response(r,VBE_SUCCESS,0);
    return 1;
}

static int mode_info(gw_vbe_device *d,gw_dos_real_mode_registers *r) {
    if (low16(r->ecx)!=d->mode) { response(r,VBE_FAILURE,1); return 1; }
    uint32_t out;
    if (!real_mode_pointer(d,r,VBE_MODE_INFO_SIZE,&out)) {
        response(r,VBE_FAILURE,1); return 1;
    }
    uint8_t *b=d->guest_memory+out;
    memset(b,0,VBE_MODE_INFO_SIZE);
    put16(b+0,0x001bu);       /* supported, color, graphics */
    b[2]=0x07u;               /* window A exists and is readable/writable */
    put16(b+4,d->granularity_kb);
    put16(b+6,d->window_size_kb);
    put16(b+8,d->window_a_segment);
    put16(b+16,d->pitch);
    put16(b+18,d->width);
    put16(b+20,d->height);
    b[22]=8; b[23]=16; b[24]=1; b[25]=d->bits_per_pixel;
    b[26]=(uint8_t)((d->video_memory_bytes+(uint32_t)d->window_size_kb*1024u-1u)/
                    ((uint32_t)d->window_size_kb*1024u));
    b[27]=d->memory_model;
    b[28]=(uint8_t)(d->window_size_kb>255u?255u:d->window_size_kb);
    put16(b+40,0);            /* banked VGA aperture, no linear framebuffer */
    d->mode_info_calls++;
    response(r,VBE_SUCCESS,0);
    return 1;
}

static int set_mode(gw_vbe_device *d,gw_dos_real_mode_registers *r) {
    uint16_t mode=(uint16_t)(r->ebx&0x3fffu);
    if (mode!=d->mode) { response(r,VBE_FAILURE,1); return 1; }
    d->mode_active=1; d->bank[0]=d->bank[1]=0;
    d->set_mode_calls++;
    response(r,VBE_SUCCESS,0);
    return 1;
}

static int set_page(gw_vbe_device *d,gw_dos_real_mode_registers *r) {
    uint8_t function=(uint8_t)(r->ebx>>8), window=(uint8_t)r->ebx;
    uint16_t bank=low16(r->edx);
    uint64_t offset=(uint64_t)bank*d->granularity_kb*1024u;
    if (!d->mode_active || window>1u || function>1u) {
        response(r,VBE_FAILURE,1); return 1;
    }
    if (function==0u) {
        if (offset>=d->video_memory_bytes || d->set_page_calls>=32u) {
            response(r,VBE_FAILURE,1); return 1;
        }
        d->bank[window]=bank;
        d->page_log[d->set_page_calls]=bank;
        d->window_log[d->set_page_calls]=(uint8_t)window;
        d->set_page_calls++;
    } else {
        r->edx=(r->edx&0xffff0000u)|(d->bank[window]&0xffffu);
    }
    response(r,VBE_SUCCESS,0);
    return 1;
}

int gw_vbe_real_mode_interrupt(void *user,uint8_t vector,
                               gw_dos_real_mode_registers *r) {
    gw_vbe_device *d=(gw_vbe_device *)user;
    if (!d || !r || vector!=0x10u) return 0;
    /* The original setup queries the current VGA text mode with AH=0Fh
     * before switching to the selected VBE mode. Model that BIOS query as
     * part of the explicitly configured host video device. */
    if ((low16(r->eax)&0xff00u)==0x0f00u) {
        r->eax=(r->eax&0xffff0000u)|0x5003u; /* 80 columns, mode 03h */
        r->ebx&=0xffff00ffu;                 /* active page zero */
        r->flags=(uint16_t)(r->flags&~1u);
        d->legacy_mode_query_calls++;
        return 1;
    }
    switch (low16(r->eax)) {
    case 0x4f00u: return controller_info(d,r);
    case 0x4f01u: return mode_info(d,r);
    case 0x4f02u: return set_mode(d,r);
    case 0x4f05u: return set_page(d,r);
    default:
        response(r,VBE_UNSUPPORTED,1);
        return 1;
    }
}

gw_interrupt_result gw_vbe_interrupt(uint8_t vector,uint32_t instruction_va,
                                     void *user) {
    (void)instruction_va;
    if (vector!=0x10u) return GW_INTERRUPT_TRAPPED;
    gw_dos_real_mode_registers r;
    memset(&r,0,sizeof(r));
    r.eax=g_eax; r.ebx=g_ebx; r.ecx=g_ecx; r.edx=g_edx;
    r.esi=g_esi; r.edi=g_edi; r.ebp=g_ebp; r.flags=(uint16_t)(g_flag_cf&1u);
    r.es=g_seg_es; r.ds=g_seg_ds; r.fs=g_seg_fs; r.gs=g_seg_gs;
    if (!gw_vbe_real_mode_interrupt(user,vector,&r)) return GW_INTERRUPT_TRAPPED;
    g_eax=r.eax; g_ebx=r.ebx; g_ecx=r.ecx; g_edx=r.edx;
    g_esi=r.esi; g_edi=r.edi; g_ebp=r.ebp; g_flag_cf=(uint8_t)(r.flags&1u);
    return GW_INTERRUPT_HANDLED;
}
