#include "gw_dos_services.h"
#include "gw_interrupts.h"
#include "gw_segments.h"
#include <stdlib.h>
#include <string.h>

/* A standard DOS stream may only observe a caller-approved static range or
 * memory which this provider actually granted through DPMI AX=0501.  The
 * ledger is populated after backing succeeds, so merely lying inside the
 * guest's reserved address space never authorizes an AH=40/3F buffer. */
static int dos_stream_range_is_authorized(const gw_dos_services *services,
                                          uint64_t begin, uint64_t size) {
    if (!services || size == 0 || begin > UINT32_MAX ||
        size > 0x100000000ull - begin) return 0;
    uint64_t end=begin+size;
    if (services->stream_memory_configured) {
        uint64_t allowed_begin=services->stream_memory_begin;
        uint64_t allowed_end=allowed_begin+services->stream_memory_size;
        if (begin>=allowed_begin && end<=allowed_end) return 1;
    }
    for (uint32_t i=0;i<GW_DOS_MAX_LINEAR_ALLOCATIONS;i++) {
        const gw_dos_linear_allocation *allocation=&services->linear_allocations[i];
        if (!allocation->active) continue;
        uint64_t allocation_begin=allocation->base;
        uint64_t allocation_end=allocation_begin+allocation->size;
        if (begin>=allocation_begin && end<=allocation_end) return 1;
    }
    return 0;
}
#include <time.h>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <sys/time.h>
#endif

_Static_assert(sizeof(gw_dos_real_mode_registers)==50u,
               "DPMI real-mode register frame must be packed to 50 bytes");

int gw_dos_real_mode_interrupt_configure(gw_dos_services *services,
                                         gw_dos_real_mode_interrupt_fn interrupt_fn,
                                         void *user) {
    if (!services || !interrupt_fn) return 0;
    services->real_mode_interrupt=interrupt_fn;
    services->real_mode_interrupt_user=user;
    return 1;
}

static int dos_dbcs_table_valid(const uint8_t *table, uint16_t size) {
    if (!table || size < 2u || size > 4096u || (size & 1u)) return 0;
    for (uint32_t i=0; i+1u<size; i+=2u) {
        uint8_t first=table[i], last=table[i+1u];
        if (first==0u && last==0u) {
            for (uint32_t tail=i+2u; tail<size; ++tail)
                if (table[tail]!=0u) return 0;
            return 1;
        }
        if (first==0u || last==0u || first>last) return 0;
    }
    return 0;
}

int gw_dos_dbcs_table_configure(gw_dos_services *services,
                                uint32_t guest_real_mode_linear,
                                const uint8_t *table, uint16_t table_size) {
    if (!services || !services->guest_memory_configured || !g_mem_base ||
        guest_real_mode_linear==0u || guest_real_mode_linear>=0x100000u ||
        !dos_dbcs_table_valid(table,table_size)) return 0;
    uint64_t end=(uint64_t)guest_real_mode_linear+(uint64_t)table_size;
    if (end>0x100000ull || end>services->guest_memory_size ||
        (uintptr_t)g_mem_base>UINTPTR_MAX-(uintptr_t)guest_real_mode_linear)
        return 0;

    uintptr_t address=(uintptr_t)g_mem_base+(uintptr_t)guest_real_mode_linear;
    memcpy((void *)address,table,table_size);
    services->dbcs_table_linear=guest_real_mode_linear;
    services->dbcs_table_size=table_size;
    services->dbcs_table_configured=1;
    return 1;
}

int gw_dos_services_real_mode_interrupt(void *user, uint8_t vector,
                                        gw_dos_real_mode_registers *registers) {
    gw_dos_services *services=(gw_dos_services *)user;
    if (!services || !registers || vector!=0x21u ||
        (uint16_t)registers->eax!=0x6300u || !services->dbcs_table_configured ||
        !services->guest_memory_configured || !g_mem_base ||
        services->dbcs_table_linear==0u ||
        services->dbcs_table_linear>=0x100000u ||
        !services->dbcs_table_size || services->dbcs_table_size>4096u)
        return 0;

    uint64_t end=(uint64_t)services->dbcs_table_linear+
                 (uint64_t)services->dbcs_table_size;
    if (end>0x100000ull || end>services->guest_memory_size ||
        (uintptr_t)g_mem_base>UINTPTR_MAX-(uintptr_t)services->dbcs_table_linear)
        return 0;

    registers->ds=(uint16_t)(services->dbcs_table_linear>>4);
    registers->esi=(registers->esi&0xffff0000u)|
                   (services->dbcs_table_linear&0x0fu);
    registers->flags=(uint16_t)(registers->flags&~1u);
    return 1;
}

static gw_interrupt_result dos_dpmi_simulate_real_mode_interrupt(
        gw_dos_services *services) {
    if (!services || !services->real_mode_interrupt ||
        !services->guest_memory_configured || !g_mem_base ||
        g_ebx>0xffu || g_ecx!=0u) return GW_INTERRUPT_TRAPPED;

    uint32_t es_base=0;
    if (!gw_dos_descriptor_base(g_seg_es,&es_base,services) ||
        !gw_dos_descriptor_range(g_seg_es,g_edi,
                                 (uint32_t)sizeof(gw_dos_real_mode_registers),services))
        return GW_INTERRUPT_TRAPPED;

    uint64_t linear=(uint64_t)es_base+(uint64_t)g_edi;
    uint64_t end=linear+(uint64_t)sizeof(gw_dos_real_mode_registers);
    if (linear>UINT32_MAX || end>0x100000000ull ||
        end>services->guest_memory_size) return GW_INTERRUPT_TRAPPED;

    uintptr_t address=(uintptr_t)((intptr_t)g_mem_base+(intptr_t)(uint32_t)linear);
    gw_dos_real_mode_registers registers;
    memcpy(&registers,(const void *)address,sizeof(registers));

    /* BH stack words and CX flags are not part of the measured W3-187 shape.
     * Leave those extensions trapped until a caller contract is recorded. */
    if (!services->real_mode_interrupt(services->real_mode_interrupt_user,
                                       (uint8_t)g_ebx,&registers))
        return GW_INTERRUPT_TRAPPED;

    memcpy((void *)address,&registers,sizeof(registers));
    return GW_INTERRUPT_HANDLED;
}

int gw_dos_descriptor_bind(gw_dos_services *services, uint16_t selector, uint32_t base, uint32_t limit) {
    if (!services || selector == 0 || limit == 0 || base > UINT32_MAX - limit) return 0;
    for (uint32_t i = 0; i < services->descriptor_count; ++i) {
        /* RPL is not part of the descriptor-table index. GeneWars startup
         * legitimately changes selector 0x14 to 0x17 (same LDT entry). */
        if ((services->descriptors[i].selector & 0xFFFCu) == (selector & 0xFFFCu)) {
            services->descriptors[i].selector = (uint16_t)(selector & 0xFFFCu);
            services->descriptors[i].base = base; services->descriptors[i].limit = limit; return 1;
        }
    }
    if (services->descriptor_count == services->descriptor_capacity) {
        uint32_t next = services->descriptor_capacity ? services->descriptor_capacity * 2u : 8u;
        if (next < services->descriptor_capacity || next > UINT16_MAX) return 0;
        gw_dos_descriptor *items = (gw_dos_descriptor *)realloc(services->descriptors, (size_t)next * sizeof(*items));
        if (!items) return 0; services->descriptors = items; services->descriptor_capacity = next;
    }
    gw_dos_descriptor *item = &services->descriptors[services->descriptor_count++];
    item->selector = selector; item->reserved = 0; item->base = base; item->limit = limit; return 1;
}

int gw_dos_linear_allocator_configure(gw_dos_services *services, uint32_t begin, uint32_t end) {
    if (!services || begin >= end) return 0;
    /* Configuring a new guest allocation arena starts a new handle namespace.
     * Never let an earlier run's successful ranges authorize DOS buffers. */
    memset(services->linear_allocations,0,sizeof services->linear_allocations);
    services->linear_allocation_count=0;
    services->allocation_cursor = begin;
    services->allocation_end = end;
    services->next_allocation_handle = 1;
    services->allocation_configured = 1;
    return 1;
}

static int guest_region_compare(const void *left, const void *right) {
    const gw_dos_guest_region *a=(const gw_dos_guest_region *)left;
    const gw_dos_guest_region *b=(const gw_dos_guest_region *)right;
    if (a->begin < b->begin) return -1;
    if (a->begin > b->begin) return 1;
    if (a->end < b->end) return -1;
    if (a->end > b->end) return 1;
    return 0;
}

int gw_dos_linear_allocator_configure_from_map(gw_dos_services *services,
                                                uint32_t guest_limit,
                                                uint32_t minimum_address,
                                                const gw_dos_guest_region *occupied,
                                                uint32_t occupied_count) {
    if (!services || !services->guest_memory_configured || guest_limit == 0 ||
        guest_limit > services->guest_memory_size || minimum_address >= guest_limit ||
        (occupied_count && !occupied)) return 0;
    if (occupied_count > SIZE_MAX / sizeof(*occupied)) return 0;
    gw_dos_guest_region *regions=0;
    if (occupied_count) {
        regions=(gw_dos_guest_region *)malloc((size_t)occupied_count*sizeof(*regions));
        if (!regions) return 0;
        memcpy(regions,occupied,(size_t)occupied_count*sizeof(*regions));
        for (uint32_t i=0;i<occupied_count;i++) {
            if (regions[i].begin >= regions[i].end || regions[i].end > guest_limit) {
                free(regions); return 0;
            }
        }
        qsort(regions,occupied_count,sizeof(*regions),guest_region_compare);
    }
    uint32_t cursor=minimum_address, best_begin=0, best_end=0;
    for (uint32_t i=0;i<occupied_count;i++) {
        uint32_t begin=regions[i].begin, end=regions[i].end;
        if (end <= cursor) continue;
        if (begin > cursor && begin-cursor > best_end-best_begin) {
            best_begin=cursor; best_end=begin;
        }
        if (end > cursor) cursor=end;
        if (cursor >= guest_limit) break;
    }
    if (cursor < guest_limit && guest_limit-cursor > best_end-best_begin) {
        best_begin=cursor; best_end=guest_limit;
    }
    free(regions);
    if (best_begin >= best_end || best_begin > UINT32_MAX-0xfffu) return 0;
    uint32_t aligned=(best_begin+0xfffu)&~0xfffu;
    if (aligned >= best_end) return 0;
    return gw_dos_linear_allocator_configure(services,aligned,best_end);
}

void gw_dos_descriptor_clear(gw_dos_services *services) {
    if (!services) return;
    free(services->descriptors); services->descriptors = 0; services->descriptor_count = services->descriptor_capacity = 0;
    free(services->dos_blocks); services->dos_blocks = 0; services->dos_block_count = services->dos_block_capacity = 0;
}

void gw_dos_real_mode_vector_configure(gw_dos_services *services, uint8_t vector,
                                       uint16_t segment, uint16_t offset) {
    if (!services) return;
    services->dpmi_real_vector_segment[vector] = segment;
    services->dpmi_real_vector_offset[vector] = offset;
}

int gw_dos_time_configure(gw_dos_services *services, uint8_t hour, uint8_t minute,
                          uint8_t second, uint8_t hundredths) {
    if (!services || hour >= 24u || minute >= 60u || second >= 60u || hundredths >= 100u) return 0;
    services->time_hour = hour;
    services->time_minute = minute;
    services->time_second = second;
    services->time_hundredths = hundredths;
    services->time_configured = 1;
    return 1;
}

int gw_dos_time_realtime_enable(gw_dos_services *services) {
    if (!services || !services->time_configured) return 0;
    services->time_realtime_enabled=1u;
    return 1;
}

int gw_dos_descriptor_base(uint16_t selector, uint32_t *base, void *user) {
    gw_dos_services *services = (gw_dos_services *)user; if (!services || !base) return 0;
    if (selector == 0) { *base = 0; return 1; }
    uint16_t descriptor=(uint16_t)(selector & 0xFFFCu);
    if (descriptor == (g_seg_cs & 0xFFFCu)) { *base = g_cs_base; return 1; }
    if (descriptor == (g_seg_ds & 0xFFFCu)) { *base = g_ds_base; return 1; }
    if (descriptor == (g_seg_es & 0xFFFCu)) { *base = g_es_base; return 1; }
    if (descriptor == (g_seg_ss & 0xFFFCu)) { *base = g_ss_base; return 1; }
    if (descriptor == (g_seg_fs & 0xFFFCu)) { *base = g_fs_base; return 1; }
    if (descriptor == (g_seg_gs & 0xFFFCu)) { *base = g_gs_base; return 1; }
    for (uint32_t i = 0; i < services->descriptor_count; ++i)
        if ((services->descriptors[i].selector & 0xFFFCu) == descriptor) { *base = services->descriptors[i].base; return 1; }
    if (services->measured_ah48_active && selector==services->measured_ah48_segment) {
        *base=(uint32_t)selector<<4;
        return 1;
    }
    /* DOS INT 21h/AH=48h returns a real-mode paragraph segment, which this
     * DOS/4GW client loads directly into ES before AH=49h. It is not a DPMI
     * selector from the explicit descriptor table. Resolve only live,
     * provider-owned conventional blocks; never treat arbitrary segment
     * values as flat aliases. */
    for (uint32_t i=0;i<services->dos_block_count;i++) {
        const gw_dos_memory_block *block=&services->dos_blocks[i];
        if (!block->selector && block->reserved==1u && block->segment==selector) {
            *base=(uint32_t)block->segment<<4;
            return 1;
        }
    }
    return 0;
}

int gw_dos_descriptor_unbind(gw_dos_services *services, uint16_t selector) {
    if (!services || !selector) return 0;
    uint16_t descriptor=(uint16_t)(selector & 0xFFFCu);
    for (uint32_t i=0;i<services->descriptor_count;i++) if ((services->descriptors[i].selector & 0xFFFCu)==descriptor) {
        if (i+1<services->descriptor_count)
            memmove(&services->descriptors[i],&services->descriptors[i+1],
                    (services->descriptor_count-i-1)*sizeof(*services->descriptors));
        services->descriptor_count--;
        return 1;
    }
    return 0;
}

int gw_dos_memory_allocator_configure(gw_dos_services *services, uint16_t begin_segment,
                                      uint16_t end_segment, uint16_t first_selector,
                                      uint16_t psp_segment) {
    if (!services || begin_segment < psp_segment || begin_segment >= end_segment || end_segment > 0xa000u ||
        first_selector == 0 || (first_selector & 7u) != 4u || !psp_segment) return 0;
    services->dos_segment_begin = begin_segment;
    services->dos_segment_cursor = begin_segment;
    services->dos_segment_end = end_segment;
    services->dos_psp_segment = psp_segment;
    services->dos_selector_begin = first_selector;
    services->dos_selector_cursor = first_selector;
    services->dos_allocator_configured = 1;
    return 1;
}

int gw_dos4gw_flat_heap_configure(gw_dos_services *services, uint16_t selector) {
    if (!services || !selector || !services->guest_memory_configured ||
        services->guest_memory_size == 0) return 0;
    services->dos4gw_flat_heap_selector = selector;
    services->dos4gw_flat_heap_enabled = 1;
    return 1;
}

int gw_dos_stream_configure(gw_dos_services *services, uint16_t handle,
                            gw_dos_stream_read_fn read_fn,
                            gw_dos_stream_write_fn write_fn,
                            void *user, int device) {
    if (!services || handle >= 3u || (!read_fn && !write_fn)) return 0;
    gw_dos_stream *stream = &services->streams[handle];
    stream->read = read_fn;
    stream->write = write_fn;
    stream->user = user;
    stream->configured = 1;
    stream->device = device != 0;
    services->standard_handles_closed &= (uint8_t)~(1u << handle);
    stream->ioctl_info_configured = 0;
    stream->reserved = 0;
    stream->ioctl_device_info = 0;
    return 1;
}

int gw_dos_stream_ioctl_info_configure(gw_dos_services *services,
                                       uint16_t handle,
                                       uint16_t device_info) {
    if (!services || handle >= 3u || !(device_info & 0x8000u)) return 0;
    gw_dos_stream *stream = &services->streams[handle];
    if (!stream->configured || !stream->device) return 0;
    stream->ioctl_device_info = device_info;
    stream->ioctl_info_configured = 1;
    return 1;
}

int gw_dos_stream_memory_configure(gw_dos_services *services,
                                   uint32_t guest_begin, uint32_t guest_size) {
    uint64_t end = (uint64_t)guest_begin + guest_size;
    if (!services || !guest_size || end > 0x100000000ull) return 0;
    services->stream_memory_begin = guest_begin;
    services->stream_memory_size = guest_size;
    services->stream_memory_configured = 1;
    return 1;
}

int gw_dos_guest_memory_configure(gw_dos_services *services, uint32_t guest_size) {
    if (!services || !guest_size) return 0;
    services->guest_memory_size=guest_size;
    services->guest_memory_configured=1;
    return 1;
}
int gw_dos_guest_memory_backing_configure(gw_dos_services *services,
                                          gw_dos_guest_memory_prepare_fn prepare_fn,
                                          void *user) {
    if (!services || !prepare_fn) return 0;
    services->guest_memory_prepare=prepare_fn;
    services->guest_memory_prepare_user=user;
    services->guest_memory_backing_configured=1;
    return 1;
}

int gw_dos_file_backend_configure(gw_dos_services *services,
                                  gw_dos_file_open_fn open_fn,
                                  gw_dos_file_read_fn read_fn,
                                  gw_dos_file_create_fn create_fn,
                                  gw_dos_file_write_fn write_fn,
                                  gw_dos_file_close_fn close_fn, void *user) {
    if (!services || !open_fn || !read_fn || !close_fn) return 0;
    services->file_open = open_fn;
    services->file_read = read_fn;
    services->file_create = create_fn;
    services->file_write = write_fn;
    services->file_close = close_fn;
    services->file_user = user;
    return 1;
}

int gw_dos_file_ioctl_info_configure(gw_dos_services *services,
                                    gw_dos_file_ioctl_info_fn info_fn) {
    if (!services || !info_fn) return 0;
    services->file_ioctl_info = info_fn;
    return 1;
}

int gw_dos_file_seek_configure(gw_dos_services *services,
                               gw_dos_file_seek_fn seek_fn) {
    if (!services || !seek_fn) return 0;
    services->file_seek=seek_fn;
    return 1;
}

static gw_dos_file_handle *dos_find_file_handle(gw_dos_services *services,
                                                uint16_t handle) {
    if (!services || handle>=5u+GW_DOS_MAX_OPEN_FILES) return NULL;
    for (uint32_t i=0;i<GW_DOS_MAX_OPEN_FILES;i++)
        if (services->files[i].active &&
            services->files[i].dos_handle==(uint8_t)handle)
            return &services->files[i];
    return NULL;
}

static int dos_standard_handle_is_closed(const gw_dos_services *services,
                                         uint16_t handle) {
    return services && handle<5u &&
        (services->standard_handles_closed & (uint8_t)(1u<<handle))!=0u;
}

static uint16_t dos_allocate_file_handle(gw_dos_services *services) {
    const uint16_t handle_limit=(uint16_t)(5u+GW_DOS_MAX_OPEN_FILES);
    for (uint16_t handle=0;handle<handle_limit;handle++) {
        if (handle<5u && !dos_standard_handle_is_closed(services,handle))
            continue;
        if (!dos_find_file_handle(services,handle)) return handle;
    }
    return 0xffffu;
}

static uint16_t dos_seek_open_file(gw_dos_services *services) {
    uint8_t origin=(uint8_t)g_eax;
    uint16_t handle=(uint16_t)g_ebx;
    uint32_t raw=((uint32_t)(uint16_t)g_ecx<<16)|(uint16_t)g_edx;
    int32_t displacement=(int32_t)raw;
    uint32_t position=0;
    gw_dos_file_handle *entry=dos_find_file_handle(services,handle);
    if (origin>2u) return 1u;
    if (!entry) return 6u;
    if (!services->file_seek) return 0xffffu;
    uint16_t error=services->file_seek(services->file_user,
        entry->file,displacement,origin,&position);
    if (error) return error;
    g_eax=(g_eax&0xffff0000u)|(position&0xffffu);
    g_edx=(g_edx&0xffff0000u)|(position>>16);
    g_flag_cf=0;
    return 0;
}

static uint16_t dos_ioctl_get_device_info(gw_dos_services *services) {
    uint16_t handle=(uint16_t)g_ebx, info=0;
    gw_dos_file_handle *entry=dos_find_file_handle(services,handle);
    if (entry) {
        if (!services->file_ioctl_info) return 0xffffu;
        uint16_t error=services->file_ioctl_info(services->file_user,
            entry->file,&info);
        if (error) return error;
        if (info & 0x0080u) return 0xffffu; /* File callbacks cannot relabel as device. */
    } else if (handle < 3u && !dos_standard_handle_is_closed(services,handle)) {
        gw_dos_stream *stream=&services->streams[handle];
        /* Prefer device information supplied by the configured stream
         * provider. The generic fallback is retained for existing synthetic
         * callers; native fixtures should supply the measured DOS word. */
        if (stream->device && stream->ioctl_info_configured)
            info=stream->ioctl_device_info;
        else if (!stream->configured || stream->device)
            info=(uint16_t)(0x0080u | (handle==0u ? 1u : 2u));
        else return 0xffffu; /* Redirected streams need provider metadata. */
    } else return 6u;
    /* DOS returns the information word in both AX and DX. */
    g_eax=(g_eax&0xffff0000u)|info;
    g_edx=(g_edx&0xffff0000u)|info;
    g_flag_cf=0;
    return 0;
}

static uint16_t dos_guest_path(gw_dos_services *services, char path[260]) {
    uint64_t linear = (uint64_t)g_ds_base + (uint64_t)g_edx;
    uint32_t length = 0;
    if (!services->guest_memory_configured || !g_mem_base ||
        linear >= services->guest_memory_size)
        return 3u;

    /* INT 21h/3Dh in this DOS/4GW path uses DS:EDX. Bound the pathname scan
     * to DOS's 259-byte path limit plus NUL and the configured guest memory. */
    while (length < 259u && linear + length < services->guest_memory_size) {
        if (!gw_dos_descriptor_range(g_seg_ds, g_edx + length, 1u, services))
            return 3u;
        uint8_t ch = *((const uint8_t *)(uintptr_t)g_mem_base + (size_t)(linear + length));
        if (!ch) break;
        path[length++] = (char)ch;
    }
    if (!length || length >= 259u ||
        linear + length >= services->guest_memory_size ||
        *((const uint8_t *)(uintptr_t)g_mem_base + (size_t)(linear + length)) != 0)
        return 3u;
    path[length] = '\0';
    return 0;
}

static uint32_t dos_free_handle_slot(gw_dos_services *services) {
    for (uint32_t i = 0; i < GW_DOS_MAX_OPEN_FILES; ++i)
        if (!services->files[i].active) return i;
    return GW_DOS_MAX_OPEN_FILES;
}

static uint16_t dos_open_file(gw_dos_services *services, uint32_t instruction_va) {
    char path[260];
    uint8_t dos_mode=(uint8_t)g_eax;
    uint32_t access_mode=dos_mode&0x07u;
    uint32_t index = dos_free_handle_slot(services);
    uint16_t handle=dos_allocate_file_handle(services);
    void *file = 0;
    uint16_t error;
    if (!services->file_open || !services->file_read || !services->file_close)
        return 0xffffu; /* No configured virtual filesystem: preserve trap. */
    /* INT 21h/3Dh AL contains more than the access mode: bits 4-6 select
     * DOS sharing (0..4), bit 7 controls inheritance, and bit 3 is reserved.
     * Watcom's original open path uses AL=0x40 for read-only compatibility
     * sharing. Pass only the access bits to the VFS callback. */
    if (access_mode > 2u || (dos_mode&0x08u)!=0u ||
        ((dos_mode>>4)&0x07u)>4u) return 12u;
    if (index == GW_DOS_MAX_OPEN_FILES || handle==0xffffu) return 4u;
    error = dos_guest_path(services, path);
    if (error) return error;

    error = services->file_open(services->file_user, path, (uint8_t)access_mode, &file);
    if (error) return error;
    if (!file) return 5u;
    services->files[index].file = file;
    services->files[index].access_mode = (uint8_t)access_mode;
    services->files[index].active = 1;
    services->files[index].created = 0;
    services->files[index].dos_handle=(uint8_t)handle;
    g_eax = (g_eax & 0xffff0000u) | handle;
    g_flag_cf = 0;
    (void)instruction_va;
    return 0;
}

static uint16_t dos_create_file(gw_dos_services *services) {
    char path[260];
    uint32_t index = dos_free_handle_slot(services);
    uint16_t handle=dos_allocate_file_handle(services);
    void *file = 0;
    uint16_t error;
    if (!services->file_create || !services->file_write || !services->file_read ||
        !services->file_close) return 0xffffu;
    if (index == GW_DOS_MAX_OPEN_FILES || handle==0xffffu) return 4u;
    error = dos_guest_path(services, path);
    if (error) return error;
    error = services->file_create(services->file_user, path, (uint16_t)g_ecx, &file);
    if (error) return error;
    if (!file) return 5u;
    services->files[index].file = file;
    services->files[index].access_mode = 1u;
    services->files[index].active = 1u;
    services->files[index].created = 1u;
    services->files[index].dos_handle=(uint8_t)handle;
    g_eax = (g_eax & 0xffff0000u) | handle;
    g_flag_cf = 0;
    return 0;
}

/* Host DOS buffer access in the DS segment. The scope tag only feeds the opt-in
 * write census (GWRECOMP_WRITE_CENSUS); the guest address check is unchanged. */
static uintptr_t dos_host_checked_ds(uint32_t offset,uint64_t width,uint32_t instruction_va) {
    uintptr_t buffer;
    recomp_write_census_set_host_scope(1);
    buffer=recomp_checked_segment_addr(RECOMP_SEG_DS,offset,width,instruction_va);
    recomp_write_census_set_host_scope(0);
    return buffer;
}

static uint16_t dos_read_open_file(gw_dos_services *services, uint16_t handle,
                                   uint32_t instruction_va) {
    gw_dos_file_handle *entry=dos_find_file_handle(services,handle);
    if (!entry) return 6u;
    if (entry->access_mode == 1u) return 5u;
    uint32_t requested = g_ecx;
    if (!requested) {
        g_eax = 0;
        g_flag_cf = 0;
        return 0;
    }
    uint64_t linear = (uint64_t)g_ds_base + (uint64_t)g_edx;
    uint64_t end = linear + requested;
    if (!services->guest_memory_configured || !g_mem_base ||
        end > services->guest_memory_size || end > 0x100000000ull)
        return 0xffffu;
    if (!gw_dos_descriptor_range(g_seg_ds, g_edx, requested, services))
        return 0xffffu;
    uint8_t *buffer = (uint8_t *)dos_host_checked_ds(g_edx, requested, instruction_va);
    if (recomp_memory_fault_pending()) return 0xffffu;
    uint32_t total=0;
    while (total<requested) {
        uint32_t remaining=requested-total;
        uint16_t chunk=(uint16_t)(remaining>0xfff0u?0xfff0u:remaining);
        uint16_t transferred=0;
        uint16_t error=services->file_read(services->file_user,entry->file,
                                            buffer+total,chunk,&transferred);
        if (transferred>chunk) return 0xffffu;
        if (error) return error;
        total+=transferred;
        if (transferred<chunk) break; /* Short DOS read, including EOF. */
    }
    g_eax = total;
    g_flag_cf = 0;
    return 0;
}

static uint16_t dos_write_open_file(gw_dos_services *services, uint16_t handle,
                                    uint32_t instruction_va) {
    gw_dos_file_handle *entry=dos_find_file_handle(services,handle);
    if (!entry) return 6u;
    if (entry->access_mode == 0u) return 5u;
    uint32_t requested = g_ecx;
    if (!requested) {
        if (!services->file_write) return 0xffffu;
        uint16_t transferred=0;
        uint16_t error=services->file_write(services->file_user,entry->file,NULL,0,&transferred);
        if (transferred) return 0xffffu;
        if (error) return error;
        g_eax = 0; g_flag_cf = 0; return 0;
    }
    uint64_t linear = (uint64_t)g_ds_base + (uint64_t)g_edx;
    uint64_t end = linear + requested;
    if (!services->file_write || !services->guest_memory_configured || !g_mem_base ||
        end > services->guest_memory_size || end > 0x100000000ull ||
        !gw_dos_descriptor_range(g_seg_ds, g_edx, requested, services)) return 0xffffu;
    const uint8_t *buffer = (const uint8_t *)dos_host_checked_ds(g_edx, requested, instruction_va);
    if (recomp_memory_fault_pending()) return 0xffffu;
    uint32_t total=0;
    while (total<requested) {
        uint32_t remaining=requested-total;
        uint16_t chunk=(uint16_t)(remaining>0xfff0u?0xfff0u:remaining);
        uint16_t transferred=0;
        uint16_t error=services->file_write(services->file_user,entry->file,
                                             buffer+total,chunk,&transferred);
        if (transferred>chunk) return 0xffffu;
        if (error) return error;
        total+=transferred;
        if (transferred<chunk) break;
    }
    g_eax = total;
    g_flag_cf = 0;
    return 0;
}

static uint16_t dos_close_open_file(gw_dos_services *services, uint16_t handle) {
    gw_dos_file_handle *entry=dos_find_file_handle(services,handle);
    if (!entry && handle<5u && !dos_standard_handle_is_closed(services,handle)) {
        services->standard_handles_closed |= (uint8_t)(1u<<handle);
        return 0;
    }
    if (!entry) return 6u;
    uint16_t error = services->file_close(services->file_user, entry->file);
    if (!error) memset(entry, 0, sizeof(*entry));
    return error;
}

static int dos_measured_gwerr_path(gw_dos_services *services) {
    static const uint8_t expected[]={'g','w','.','e','r','r',0};
    uint64_t begin=(uint64_t)g_ds_base+(uint64_t)g_edx;
    if (!services || !services->guest_memory_configured || !g_mem_base ||
        g_seg_ds!=0x0014u || g_ds_base!=0 ||
        begin+sizeof(expected)>services->guest_memory_size) return 0;
    const uint8_t *memory=(const uint8_t *)(uintptr_t)g_mem_base;
    return memcmp(memory+(size_t)begin,expected,sizeof(expected))==0;
}

/* AH=43/AL=00 is serviced only through the configured virtual provider.
 * The current C provider contract represents regular files but does not
 * expose DOS attribute metadata; regular-file providers therefore report
 * DOS's archive bit. The open/close pair verifies fixture existence without
 * retaining a DOS handle or consulting the host filesystem. */
static uint16_t dos_get_file_attributes(gw_dos_services *services) {
    char path[260];
    void *file=0;
    uint16_t error;
    if (!services || !services->file_open || !services->file_close)
        return 0xffffu; /* No configured provider: preserve the trap. */
    error=dos_guest_path(services,path);
    if (error) return error;
    error=services->file_open(services->file_user,path,0u,&file);
    if (error) return error;
    if (!file) return 5u;
    error=services->file_close(services->file_user,file);
    if (error) return error;
    /* The bounded C file-provider API models regular files. Its present
     * metadata contract supports the archive bit only. */
    g_eax=(g_eax&0xffff0000u)|0x0020u;
    g_ecx=(g_ecx&0xffff0000u)|0x0020u;
    g_flag_cf=0;
    return 0;
}

static int dos_block_index(gw_dos_services *services, uint16_t selector) {
    if (!selector) return -1;
    for (uint32_t i=0;i<services->dos_block_count;i++)
        if (services->dos_blocks[i].selector==selector) return (int)i;
    return -1;
}

static uint16_t dos_largest_gap(gw_dos_services *services) {
    if (!services->dos_allocator_configured) return 0;
    uint32_t cursor=services->dos_segment_begin, largest=0;
    for (uint32_t step=0;step<=services->dos_block_count;step++) {
        int nearest=-1;
        for (uint32_t i=0;i<services->dos_block_count;i++)
            if (services->dos_blocks[i].segment>=cursor &&
                (nearest<0 || services->dos_blocks[i].segment<services->dos_blocks[nearest].segment)) nearest=(int)i;
        if (nearest<0) {
            uint32_t gap=services->dos_segment_end-cursor;
            if (gap>largest) largest=gap;
            break;
        }
        uint32_t gap=services->dos_blocks[nearest].segment-cursor;
        if (gap>largest) largest=gap;
        cursor=(uint32_t)services->dos_blocks[nearest].segment+services->dos_blocks[nearest].paragraphs;
        if (cursor>=services->dos_segment_end) break;
    }
    return largest>0xffffu?0xffffu:(uint16_t)largest;
}

static int dos_first_fit(gw_dos_services *services, uint16_t paragraphs, uint16_t *segment) {
    uint32_t candidate=services->dos_segment_begin;
    for (uint32_t step=0;step<=services->dos_block_count;step++) {
        if (candidate+(uint32_t)paragraphs>services->dos_segment_end) return 0;
        int conflict=-1;
        for (uint32_t i=0;i<services->dos_block_count;i++) {
            uint32_t begin=services->dos_blocks[i].segment;
            uint32_t end=begin+services->dos_blocks[i].paragraphs;
            if (candidate<end && begin<candidate+(uint32_t)paragraphs &&
                (conflict<0 || begin<services->dos_blocks[conflict].segment)) conflict=(int)i;
        }
        if (conflict<0) { *segment=(uint16_t)candidate; return 1; }
        candidate=(uint32_t)services->dos_blocks[conflict].segment+services->dos_blocks[conflict].paragraphs;
    }
    return 0;
}

static uint16_t dos_selector_find(gw_dos_services *services) {
    for (uint32_t s=services->dos_selector_begin;s<=0xfffcu;s+=8u) {
        uint16_t selector=(uint16_t)s;
        int used=selector==g_seg_cs||selector==g_seg_ds||selector==g_seg_es||
                 selector==g_seg_ss||selector==g_seg_fs||selector==g_seg_gs;
        for (uint32_t i=0;i<services->descriptor_count&&!used;i++)
            if (services->descriptors[i].selector==selector) used=1;
        if (!used) return selector;
    }
    return 0;
}

static int dos_block_append(gw_dos_services *services, uint16_t selector,
                            uint16_t segment, uint16_t paragraphs);

static int dos_mcb_read(gw_dos_services *services,uint16_t mcb_segment,
                        uint8_t *tag,uint16_t *owner,uint16_t *paragraphs) {
    uint64_t address=(uint64_t)mcb_segment<<4;
    if (!services || !services->guest_memory_configured || !g_mem_base || !tag || !owner || !paragraphs ||
        address+5u>services->guest_memory_size) return 0;
    const uint8_t *mcb=(const uint8_t *)(uintptr_t)g_mem_base+(uintptr_t)address;
    *tag=mcb[0];
    *owner=(uint16_t)(mcb[1]|((uint16_t)mcb[2]<<8));
    *paragraphs=(uint16_t)(mcb[3]|((uint16_t)mcb[4]<<8));
    return (*tag=='M'||*tag=='Z') &&
        (uint32_t)mcb_segment+1u+(uint32_t)*paragraphs<=services->dos_segment_end;
}

static int dos_mcb_write(gw_dos_services *services,uint16_t mcb_segment,
                         uint8_t tag,uint16_t owner,uint16_t paragraphs) {
    uint64_t address=(uint64_t)mcb_segment<<4;
    if (!services || !services->guest_memory_configured || !g_mem_base ||
        (tag!='M'&&tag!='Z') || address+16u>services->guest_memory_size) return 0;
    uint8_t bytes[16]={0};
    bytes[0]=tag; bytes[1]=(uint8_t)owner; bytes[2]=(uint8_t)(owner>>8);
    bytes[3]=(uint8_t)paragraphs; bytes[4]=(uint8_t)(paragraphs>>8);
    memcpy((uint8_t *)(uintptr_t)g_mem_base+(uintptr_t)address,bytes,sizeof bytes);
    return 1;
}

static int dos_ah48_allocate(gw_dos_services *services,uint16_t paragraphs) {
    uint16_t mcb=(uint16_t)(services->dos_segment_begin-1u),largest=0;
    for (uint32_t step=0;step<services->dos_block_capacity+services->dos_segment_end-services->dos_segment_begin+2u;step++) {
        uint8_t tag; uint16_t owner,size;
        if (!dos_mcb_read(services,mcb,&tag,&owner,&size)) return 0;
        if (owner==0u && size>largest) largest=size;
        if (owner==0u && paragraphs && size>=paragraphs) {
            uint16_t segment=(uint16_t)(mcb+1u);
            uint16_t remainder=(uint16_t)(size-paragraphs);
            if (!dos_block_append(services,0u,segment,paragraphs)) break;
            services->dos_blocks[services->dos_block_count-1u].reserved=1u;
            if (!remainder) {
                if (!dos_mcb_write(services,mcb,tag,services->dos_psp_segment,paragraphs)) {
                    services->dos_block_count--; return 0;
                }
            } else {
                uint16_t next=(uint16_t)(mcb+paragraphs+1u);
                uint16_t free_paragraphs=(uint16_t)(remainder-1u);
                if (!dos_mcb_write(services,mcb,'M',services->dos_psp_segment,paragraphs) ||
                    !dos_mcb_write(services,next,tag,0u,free_paragraphs)) {
                    services->dos_block_count--; return 0;
                }
            }
            g_eax=(g_eax&0xffff0000u)|segment; g_flag_cf=0;
            return 1;
        }
        if (tag=='Z') break;
        uint32_t next=(uint32_t)mcb+(uint32_t)size+1u;
        if (next<=mcb || next>=services->dos_segment_end) return 0;
        mcb=(uint16_t)next;
    }
    g_eax=(g_eax&0xffff0000u)|0x0008u;
    g_ebx=(g_ebx&0xffff0000u)|largest;
    g_flag_cf=1;
    return 1;
}

static int dos_ah48_free(gw_dos_services *services,uint16_t segment) {
    int index=-1;
    for (uint32_t i=0;i<services->dos_block_count;i++)
        if (!services->dos_blocks[i].selector && services->dos_blocks[i].reserved==1u &&
            services->dos_blocks[i].segment==segment) { index=(int)i; break; }
    if (index<0) { g_eax=(g_eax&0xffff0000u)|9u; g_flag_cf=1; return 1; }
    uint16_t current=(uint16_t)(segment-1u);
    uint8_t tag; uint16_t owner,size;
    if (!dos_mcb_read(services,current,&tag,&owner,&size) || owner!=services->dos_psp_segment ||
        size!=services->dos_blocks[index].paragraphs || !dos_mcb_write(services,current,tag,0u,size)) return 0;
    uint16_t scan=(uint16_t)(services->dos_segment_begin-1u),previous=0;
    uint8_t previous_tag=0; uint16_t previous_owner=0,previous_size=0; int have_previous=0;
    while (scan<current) {
        uint8_t scan_tag; uint16_t scan_owner,scan_size;
        if (!dos_mcb_read(services,scan,&scan_tag,&scan_owner,&scan_size)) return 0;
        if ((uint32_t)scan+scan_size+1u==current) {
            previous=scan; previous_tag=scan_tag; previous_owner=scan_owner; previous_size=scan_size; have_previous=1;
        }
        if (scan_tag=='Z') break;
        scan=(uint16_t)(scan+scan_size+1u);
    }
    if (have_previous && previous_owner==0u) {
        size=(uint16_t)(previous_size+1u+size); current=previous; tag=tag;
        if (!dos_mcb_write(services,current,tag,0u,size)) return 0;
    }
    if (tag=='M') {
        uint16_t next=(uint16_t)(current+size+1u); uint8_t next_tag; uint16_t next_owner,next_size;
        if (!dos_mcb_read(services,next,&next_tag,&next_owner,&next_size)) return 0;
        if (next_owner==0u) {
            size=(uint16_t)(size+1u+next_size); tag=next_tag;
            if (!dos_mcb_write(services,current,tag,0u,size)) return 0;
        }
    }
    memmove(&services->dos_blocks[index],&services->dos_blocks[index+1u],
            (services->dos_block_count-(uint32_t)index-1u)*sizeof(*services->dos_blocks));
    services->dos_block_count--; g_flag_cf=0;
    (void)previous_tag;
    return 1;
}

/* DPMI AX=0102 resizes the DOS MCB backing a DPMI 0100 allocation. Keep the
 * MCB chain and descriptor extent in sync; changing only the private ledger
 * lets the next AH=48/0100 allocation overlap a stale MCB. */
static int dos_dpmi_resize_block(gw_dos_services *services, int index,
                                 uint16_t requested, uint16_t *maximum) {
    if (!services || index<0 || (uint32_t)index>=services->dos_block_count ||
        !requested || !maximum) return 0;
    gw_dos_memory_block *block=&services->dos_blocks[index];
    if (block->reserved!=2u || !block->selector || block->segment==0u) return 0;
    uint16_t current=(uint16_t)(block->segment-1u);
    uint8_t tag; uint16_t owner,old_size;
    if (!dos_mcb_read(services,current,&tag,&owner,&old_size) ||
        owner!=services->dos_psp_segment || old_size!=block->paragraphs) return 0;
    uint16_t next=(uint16_t)(current+old_size+1u);
    uint8_t next_tag=0; uint16_t next_owner=0,next_size=0;
    int has_next=tag=='M';
    if (has_next && !dos_mcb_read(services,next,&next_tag,&next_owner,&next_size)) return 0;
    uint32_t max_size=old_size;
    if (has_next && next_owner==0u) max_size+=(uint32_t)next_size+1u;
    *maximum=(uint16_t)(max_size>0xffffu?0xffffu:max_size);
    if (requested>old_size) {
        if (!has_next || next_owner!=0u || (uint32_t)requested>max_size) return 1;
        uint32_t remaining=max_size-requested;
        uint8_t new_tag;
        if (remaining==0u) {
            new_tag=next_tag;
        } else {
            uint16_t free_mcb=(uint16_t)(current+(uint32_t)requested+1u);
            uint16_t free_size=(uint16_t)(remaining-1u);
            new_tag='M';
            if (!dos_mcb_write(services,free_mcb,next_tag,0u,free_size)) return 0;
        }
        if (!dos_mcb_write(services,current,new_tag,services->dos_psp_segment,requested)) return 0;
    } else if (requested<old_size) {
        uint32_t released=(uint32_t)old_size-requested-1u;
        uint16_t free_mcb=(uint16_t)(current+(uint32_t)requested+1u);
        uint8_t free_tag=tag;
        if (has_next && next_owner==0u) {
            released+=1u+(uint32_t)next_size;
            free_tag=next_tag;
        } else if (has_next) {
            free_tag='M';
        }
        if (released>0xffffu ||
            !dos_mcb_write(services,current,'M',services->dos_psp_segment,requested) ||
            !dos_mcb_write(services,free_mcb,free_tag,0u,(uint16_t)released)) return 0;
    }
    uint32_t limit=(uint32_t)requested*16u-1u;
    if (!gw_dos_descriptor_bind(services,block->selector,
                                (uint32_t)block->segment<<4,limit)) return 0;
    block->paragraphs=requested;
    return 1;
}

static int dos_block_append(gw_dos_services *services, uint16_t selector,
                            uint16_t segment, uint16_t paragraphs) {
    if (services->dos_block_count==services->dos_block_capacity) {
        uint32_t next=services->dos_block_capacity?services->dos_block_capacity*2u:8u;
        if (next<services->dos_block_capacity||next>UINT16_MAX) return 0;
        gw_dos_memory_block *p=(gw_dos_memory_block *)realloc(services->dos_blocks,(size_t)next*sizeof(*p));
        if (!p) return 0;
        services->dos_blocks=p; services->dos_block_capacity=next;
    }
    gw_dos_memory_block *b=&services->dos_blocks[services->dos_block_count++];
    b->selector=selector; b->segment=segment; b->paragraphs=paragraphs; b->reserved=0;
    return 1;
}

static gw_interrupt_result dpmi_lock_linear_region(gw_dos_services *services,
                                                    uint16_t function) {
    uint32_t start=((g_ebx&0xffffu)<<16)|(g_ecx&0xffffu);
    uint32_t size=((g_esi&0xffffu)<<16)|(g_edi&0xffffu);
    uint64_t end=(uint64_t)start+(uint64_t)size;
    if (!size) {
        g_eax=(g_eax&0xffff0000u)|0x8021u;
        g_flag_cf=1;
        return GW_INTERRUPT_HANDLED;
    }
    if (!services->guest_memory_configured || end>0xffffffffull ||
        end>services->guest_memory_size) {
        g_eax=(g_eax&0xffff0000u)|0x8025u;
        g_flag_cf=1;
        return GW_INTERRUPT_HANDLED;
    }
    /* The target's authenticated DOS/4GW profile has no DPMI paging host.
     * AX=0600/0601 are therefore no-ops after guest-range validation. Do not
     * infer a paging-capable DPMI host from the Windows backing implementation. */
    (void)function;
    g_flag_cf=0;
    return GW_INTERRUPT_HANDLED;
}

int gw_dos_descriptor_range(uint16_t selector, uint32_t offset, uint32_t width, void *user) {
    gw_dos_services *services=(gw_dos_services *)user;
    if (!services || !selector || !width) return 0;
    for (uint32_t i=0;i<services->descriptor_count;i++) {
        gw_dos_descriptor *d=&services->descriptors[i];
        if ((d->selector & 0xFFFCu)==(selector & 0xFFFCu))
            return (uint64_t)offset+(uint64_t)width <= (uint64_t)d->limit+1u;
    }
    /* Existing flat process selectors have no explicit DPMI limit record. */
    uint16_t descriptor=(uint16_t)(selector & 0xFFFCu);
    if (descriptor==(g_seg_cs & 0xFFFCu) || descriptor==(g_seg_ds & 0xFFFCu) ||
        descriptor==(g_seg_es & 0xFFFCu) || descriptor==(g_seg_ss & 0xFFFCu) ||
        descriptor==(g_seg_fs & 0xFFFCu) || descriptor==(g_seg_gs & 0xFFFCu)) return 1;
    if (services->measured_ah48_active && selector==services->measured_ah48_segment)
        return (uint64_t)offset+(uint64_t)width<=16u;
    /* Match the exact AH=48 paragraph value and enforce the allocation's
     * actual byte extent. The mapping disappears when the matching AH=49
     * succeeds, so stale real-mode segments remain fail-closed. */
    for (uint32_t i=0;i<services->dos_block_count;i++) {
        const gw_dos_memory_block *block=&services->dos_blocks[i];
        if (!block->selector && block->reserved==1u && block->segment==selector)
            return (uint64_t)offset+(uint64_t)width <= (uint64_t)block->paragraphs*16u;
    }
    return 0;
}

gw_interrupt_result gw_dos_services_callback(uint8_t vector,
                                              uint32_t instruction_va,
                                              void *user) {
    if (user == 0) return GW_INTERRUPT_TRAPPED;
    gw_dos_services *services = (gw_dos_services *)user;
    if (vector==0x31u && (uint16_t)g_eax==0x0300u)
        return dos_dpmi_simulate_real_mode_interrupt(services);
    if (vector==0x31u && ((uint16_t)g_eax==0x0600u ||
                         (uint16_t)g_eax==0x0601u))
        return dpmi_lock_linear_region(services,(uint16_t)g_eax);
    if (vector == 0x31u && (uint16_t)g_eax == 0x0200u) {
        uint8_t interrupt_number = (uint8_t)g_ebx;
        g_ecx = (g_ecx & 0xffff0000u) | services->dpmi_real_vector_segment[interrupt_number];
        g_edx = (g_edx & 0xffff0000u) | services->dpmi_real_vector_offset[interrupt_number];
        g_flag_cf = 0;
        return GW_INTERRUPT_HANDLED;
    }
    if (vector == 0x31u && (uint16_t)g_eax == 0x0201u) {
        uint8_t interrupt_number = (uint8_t)g_ebx;
        services->dpmi_real_vector_segment[interrupt_number] = (uint16_t)g_ecx;
        services->dpmi_real_vector_offset[interrupt_number] = (uint16_t)g_edx;
        g_flag_cf = 0;
        return GW_INTERRUPT_HANDLED;
    }
    if (vector == 0x31u && (uint16_t)g_eax == 0x0100u) {
        uint16_t paragraphs = (uint16_t)g_ebx;
        if (!paragraphs || !services->dos_allocator_configured) {
            g_eax = (g_eax & 0xffff0000u) | 0x0008u;
            g_ebx = (g_ebx & 0xffff0000u) | dos_largest_gap(services);
            g_flag_cf = 1;
            return GW_INTERRUPT_HANDLED;
        }
        /* DPMI 0100 allocates a DOS conventional-memory block. Keep it in the
         * same MCB chain as INT 21h/AH=48; an independent segment ledger can
         * otherwise hand out a segment occupied by a PSP/environment MCB. */
        if (!dos_ah48_allocate(services,paragraphs)) {
            g_eax=(g_eax&0xffff0000u)|0x8011u;
            g_flag_cf=1;
            return GW_INTERRUPT_HANDLED;
        }
        if (g_flag_cf) return GW_INTERRUPT_HANDLED;
        uint16_t segment=(uint16_t)g_eax;
        int block_index=-1;
        for (uint32_t i=0;i<services->dos_block_count;i++)
            if (!services->dos_blocks[i].selector &&
                services->dos_blocks[i].reserved==1u &&
                services->dos_blocks[i].segment==segment) { block_index=(int)i; break; }
        if (block_index<0) {
            g_eax=(g_eax&0xffff0000u)|0x8011u;
            g_flag_cf=1;
            return GW_INTERRUPT_HANDLED;
        }
        uint16_t selector=dos_selector_find(services);
        if (!selector) {
            (void)dos_ah48_free(services,segment);
            g_eax = (g_eax & 0xffff0000u) | 0x8011u;
            g_flag_cf = 1;
            return GW_INTERRUPT_HANDLED;
        }
        uint32_t limit = (uint32_t)paragraphs * 16u - 1u;
        if (!gw_dos_descriptor_bind(services, selector, (uint32_t)segment << 4, limit)) {
            (void)dos_ah48_free(services,segment);
            gw_dos_descriptor_unbind(services,selector);
            g_eax = (g_eax & 0xffff0000u) | 0x8011u;
            g_flag_cf = 1;
            return GW_INTERRUPT_HANDLED;
        }
        services->dos_blocks[block_index].selector=selector;
        services->dos_blocks[block_index].reserved=2u; /* DPMI-owned MCB */
        services->dos_segment_cursor = (uint16_t)(segment + paragraphs);
        services->dos_selector_cursor = selector > 0xfff0u ? 0 : (uint16_t)(selector + 8u);
        g_eax = (g_eax & 0xffff0000u) | segment;
        g_edx = (g_edx & 0xffff0000u) | selector;
        g_flag_cf = 0;
        return GW_INTERRUPT_HANDLED;
    }
    if (vector == 0x31u && (uint16_t)g_eax == 0x0101u) {
        uint16_t selector=(uint16_t)g_edx;
        int index=dos_block_index(services,selector);
        if (index<0 || services->dos_blocks[index].reserved!=2u) {
            g_eax=(g_eax&0xffff0000u)|0x8022u; g_flag_cf=1; return GW_INTERRUPT_HANDLED;
        }
        uint16_t segment=services->dos_blocks[index].segment;
        if (!gw_dos_descriptor_unbind(services,selector)) {
            g_eax=(g_eax&0xffff0000u)|0x8022u; g_flag_cf=1; return GW_INTERRUPT_HANDLED;
        }
        services->dos_blocks[index].selector=0;
        services->dos_blocks[index].reserved=1u;
        if (!dos_ah48_free(services,segment)) {
            /* Keep the failed operation visible and restore the descriptor
             * when the MCB chain refused the release without mutating it. */
            if (index<(int)services->dos_block_count &&
                services->dos_blocks[index].segment==segment) {
                services->dos_blocks[index].selector=selector;
                services->dos_blocks[index].reserved=2u;
                (void)gw_dos_descriptor_bind(services,selector,
                    (uint32_t)segment<<4,
                    (uint32_t)services->dos_blocks[index].paragraphs*16u-1u);
            }
            if (!g_flag_cf) { g_eax=(g_eax&0xffff0000u)|0x8022u; g_flag_cf=1; }
            return GW_INTERRUPT_HANDLED;
        }
        g_flag_cf=0; return GW_INTERRUPT_HANDLED;
    }
    if (vector == 0x31u && (uint16_t)g_eax == 0x0102u) {
        uint16_t selector=(uint16_t)g_edx, requested=(uint16_t)g_ebx;
        int index=dos_block_index(services,selector);
        if (index<0 || services->dos_blocks[index].reserved!=2u) { g_eax=(g_eax&0xffff0000u)|0x8022u; g_flag_cf=1; return GW_INTERRUPT_HANDLED; }
        if (!requested) { g_eax=(g_eax&0xffff0000u)|9u; g_flag_cf=1; return GW_INTERRUPT_HANDLED; }
        uint16_t maximum=0;
        if (!dos_dpmi_resize_block(services,index,requested,&maximum)) {
            g_eax=(g_eax&0xffff0000u)|0x8011u; g_flag_cf=1; return GW_INTERRUPT_HANDLED;
        }
        if (requested>maximum) {
            g_eax=(g_eax&0xffff0000u)|8u;
            g_ebx=(g_ebx&0xffff0000u)|maximum;
            g_flag_cf=1; return GW_INTERRUPT_HANDLED;
        }
        g_flag_cf=0; return GW_INTERRUPT_HANDLED;
    }
    if (vector == 0x21u) {
        uint16_t ax = (uint16_t)g_eax;
        uint8_t function = (uint8_t)((g_eax >> 8) & 0xffu);
        if (services->dos4gw_flat_heap_enabled && function==0xEDu &&
            (uint16_t)g_ebx==services->dos4gw_flat_heap_selector &&
            g_seg_ds==services->dos4gw_flat_heap_selector) {
            uint32_t base=0;
            if (!gw_dos_descriptor_base(services->dos4gw_flat_heap_selector,
                                        &base,services) || base!=0u)
                return GW_INTERRUPT_TRAPPED;
            /* Watcom __brk consumes bit 0 to choose the flat DS growth path. */
            g_eax=0;
            g_flag_cf=0;
            return GW_INTERRUPT_HANDLED;
        }
        if (services->dos4gw_flat_heap_enabled && function==0x4Au &&
            g_seg_es==services->dos4gw_flat_heap_selector &&
            g_seg_ds==services->dos4gw_flat_heap_selector) {
            uint32_t base=0;
            uint64_t requested_bytes=(uint64_t)g_ebx*16u;
            if (!gw_dos_descriptor_base(services->dos4gw_flat_heap_selector,
                                        &base,services) || base!=0u)
                return GW_INTERRUPT_TRAPPED;
            if (requested_bytes>services->guest_memory_size) {
                /* DOS AH=4A reports insufficient memory with AX=8, CF set,
                 * and BX equal to the largest available paragraph count. */
                g_eax=(g_eax&0xffff0000u)|0x0008u;
                g_ebx=(g_ebx&0xffff0000u)|
                      (uint32_t)(services->guest_memory_size/16u>0xffffu
                          ? 0xffffu : services->guest_memory_size/16u);
                g_flag_cf=1;
                return GW_INTERRUPT_HANDLED;
            }
            /* The process flat segment is already backed by the configured
             * guest map; accept only growth that remains inside that map. */
            g_flag_cf=0;
            return GW_INTERRUPT_HANDLED;
        }
        if (ax==0x4400u) {
            uint16_t error=dos_ioctl_get_device_info(services);
            if (error==0xffffu) return GW_INTERRUPT_TRAPPED;
            if (error) { g_eax=(g_eax&0xffff0000u)|error; g_flag_cf=1; }
            return GW_INTERRUPT_HANDLED;
        }
        if (function==0x42u) {
            uint16_t error=dos_seek_open_file(services);
            if (error==0xffffu) return GW_INTERRUPT_TRAPPED;
            if (error) { g_eax=(g_eax&0xffff0000u)|error; g_flag_cf=1; }
            return GW_INTERRUPT_HANDLED;
        }
        if (function == 0x43u && (uint8_t)g_eax == 0x00u &&
            instruction_va == 0x000AF93Au && dos_measured_gwerr_path(services)) {
            /* Exact original-oracle missing gw.err probe; keep other attribute
             * behavior provider-backed and fail-closed. */
            g_eax=(g_eax&0xffff0000u)|0x0003u;
            g_flag_cf=1;
            return GW_INTERRUPT_HANDLED;
        }
        if (function == 0x43u && (uint8_t)g_eax == 0x00u) {
            uint16_t error=dos_get_file_attributes(services);
            if (error==0xffffu) return GW_INTERRUPT_TRAPPED;
            if (error) { g_eax=(g_eax&0xffff0000u)|error; g_flag_cf=1; }
            return GW_INTERRUPT_HANDLED;
        }
        if (function == 0x35u) {
            uint8_t vector = (uint8_t)g_eax;
            g_seg_es = services->dos_vector_segment[vector];
            g_ebx = (g_ebx & 0xffff0000u) | services->dos_vector_offset[vector];
            g_flag_cf = 0;
            return GW_INTERRUPT_HANDLED;
        }
        if (function == 0x25u) {
            uint8_t vector = (uint8_t)g_eax;
            services->dos_vector_segment[vector] = g_seg_ds;
            services->dos_vector_offset[vector] = (uint16_t)g_edx;
            g_flag_cf = 0;
            return GW_INTERRUPT_HANDLED;
        }
        if (function == 0x3fu || function == 0x40u) {
            uint16_t handle = (uint16_t)g_ebx;
            uint32_t requested = g_ecx;
            if (dos_find_file_handle(services,handle) || handle >= 3u ||
                dos_standard_handle_is_closed(services,handle)) {
                if (function == 0x3fu) {
                    uint16_t error = dos_read_open_file(services, handle, instruction_va);
                    if (error == 0xffffu) return GW_INTERRUPT_TRAPPED;
                    if (error) { g_eax = error; g_flag_cf = 1; }
                    return GW_INTERRUPT_HANDLED;
                }
                uint16_t error = dos_write_open_file(services, handle, instruction_va);
                if (error == 0xffffu) return GW_INTERRUPT_TRAPPED;
                if (error) { g_eax = error; g_flag_cf = 1; }
                return GW_INTERRUPT_HANDLED;
            }
            gw_dos_stream *stream = &services->streams[handle];
            if (!stream->configured || (function == 0x3fu && !stream->read) ||
                (function == 0x40u && !stream->write)) return GW_INTERRUPT_TRAPPED;
            if (requested == 0) {
                g_eax = 0;
                g_flag_cf = 0;
                return GW_INTERRUPT_HANDLED;
            }
            /* INT 21h under the 32-bit DOS/4GW protected-mode interface uses
             * DS:EDX.  Keep the full selector-relative offset (the open-file
             * AH=3Fh/40h paths already do) and validate it before exposing the
             * guest buffer to an injected stream provider.  Besides explicitly
             * configured static ranges, accept only ranges contained in an
             * active DPMI allocation recorded after successful backing. */
            uint32_t offset = g_edx;
            uint64_t linear = (uint64_t)g_ds_base + offset;
            uint64_t end = linear + requested;
            if (end > 0x100000000ull ||
                !dos_stream_range_is_authorized(services,linear,requested))
                return GW_INTERRUPT_TRAPPED;
            uint8_t *buffer = (uint8_t *)dos_host_checked_ds(offset, requested, instruction_va);
            if (recomp_memory_fault_pending()) return GW_INTERRUPT_TRAPPED;
            uint32_t total=0;
            while (total<requested) {
                uint32_t remaining=requested-total;
                uint16_t chunk=(uint16_t)(remaining>0xfff0u?0xfff0u:remaining);
                uint16_t transferred=0;
                uint16_t error=function==0x3fu
                    ? stream->read(stream->user,buffer+total,chunk,&transferred)
                    : stream->write(stream->user,buffer+total,chunk,&transferred);
                if (transferred>chunk) return GW_INTERRUPT_TRAPPED;
                if (error) {
                    g_eax=error;
                    g_flag_cf=1;
                    return GW_INTERRUPT_HANDLED;
                }
                total+=transferred;
                if (transferred<chunk) break;
            }
            g_eax=total;
            g_flag_cf=0;
            return GW_INTERRUPT_HANDLED;
        }
        if (function == 0x3du) {
            uint16_t error = dos_open_file(services, instruction_va);
            if (error == 0xffffu) return GW_INTERRUPT_TRAPPED;
            if (error) { g_eax = (g_eax & 0xffff0000u) | error; g_flag_cf = 1; }
            return GW_INTERRUPT_HANDLED;
        }
        if (function == 0x3cu) {
            uint16_t error = dos_create_file(services);
            if (error == 0xffffu) return GW_INTERRUPT_TRAPPED;
            if (error) { g_eax = (g_eax & 0xffff0000u) | error; g_flag_cf = 1; }
            return GW_INTERRUPT_HANDLED;
        }
        if (function == 0x3eu) {
            uint16_t error = dos_close_open_file(services, (uint16_t)g_ebx);
            if (error) { g_eax = (g_eax & 0xffff0000u) | error; g_flag_cf = 1; }
            else g_flag_cf = 0;
            return GW_INTERRUPT_HANDLED;
        }
        if (function == 0x30u) {
            /* DOS AH=30h: AL=major, AH=minor. Preserve upper EAX and other GPRs. */
            g_eax = (g_eax & 0xffff0000u)
                  | ((uint32_t)services->minor << 8)
                  | (uint32_t)services->major;
            g_flag_cf = 0;
            return GW_INTERRUPT_HANDLED;
        }
        if (function == 0x2cu) {
            /* DOS AH=2Ch: CH:CL is hour:minute, DH:DL is second:hundredths.
             * Deterministic callers retain the configured snapshot. Runtime
             * startup may opt into live host wall-clock samples so Watcom's
             * original delay calibration cannot spin on a frozen second. */
            if (!services->time_configured) return GW_INTERRUPT_TRAPPED;
            uint8_t hour=services->time_hour,minute=services->time_minute;
            uint8_t second=services->time_second,hundredths=services->time_hundredths;
            if (services->time_realtime_enabled) {
#ifdef _WIN32
                SYSTEMTIME wall; GetLocalTime(&wall);
                hour=(uint8_t)wall.wHour; minute=(uint8_t)wall.wMinute;
                second=(uint8_t)wall.wSecond; hundredths=(uint8_t)(wall.wMilliseconds/10u);
#else
                struct timeval stamp; struct tm *local;
                if (gettimeofday(&stamp,0)!=0) return GW_INTERRUPT_TRAPPED;
                local=localtime(&stamp.tv_sec);
                if (!local) return GW_INTERRUPT_TRAPPED;
                hour=(uint8_t)local->tm_hour; minute=(uint8_t)local->tm_min;
                second=(uint8_t)local->tm_sec; hundredths=(uint8_t)(stamp.tv_usec/10000L);
#endif
            }
            g_ecx = (g_ecx & 0xffff0000u) | ((uint32_t)hour << 8) | minute;
            g_edx = (g_edx & 0xffff0000u) | ((uint32_t)second << 8) | hundredths;
            g_flag_cf = 0;
            return GW_INTERRUPT_HANDLED;
        }
        if (function==0x48u && services->dos_allocator_configured &&
            (instruction_va==0x000C3D21u || instruction_va==0x000C3D35u)
#if !defined(GW_NATIVE_W1_092_HOST_BACKED_GUEST_MEMORY)
            && !(instruction_va==0x000C3D21u && (uint16_t)g_ebx==1u && g_ecx==0x00008000u && g_edx==0u) &&
            !(instruction_va==0x000C3D35u && g_eax==0x0000484cu && g_ebx==0x00000800u &&
              g_ecx==0x00008000u && g_edx==0x0000004cu)
#endif
            ) {
            if (!dos_ah48_allocate(services,(uint16_t)g_ebx)) return GW_INTERRUPT_TRAPPED;
            return GW_INTERRUPT_HANDLED;
        }
        if (function==0x49u && services->dos_allocator_configured &&
            instruction_va==0x000C3D46u && g_seg_es!=services->measured_ah48_segment) {
            if (!dos_ah48_free(services,g_seg_es)) return GW_INTERRUPT_TRAPPED;
            return GW_INTERRUPT_HANDLED;
        }
        if (function == 0x48u && instruction_va == 0x000C3D21u &&
            (uint16_t)g_ebx == 1u && g_ecx == 0x00008000u && g_edx == 0u) {
            /* Single original-CUE measured fallback call. Keep all other
             * AH=48 requests fail-closed until their allocator contract is known. */
            g_eax = (g_eax & 0xffff0000u) | 0x004cu;
            g_flag_cf = 0;
            services->measured_ah48_segment = 0x004cu;
            services->measured_ah48_active = 1;
            return GW_INTERRUPT_HANDLED;
        }
        if (function == 0x48u && instruction_va == 0x000C3D35u &&
            g_eax == 0x0000484cu && g_ebx == 0x00000800u &&
            g_ecx == 0x00008000u && g_edx == 0x0000004cu) {
            /* Measured retry after the one-paragraph fallback: the bounded
             * original fixture reports AX=8 and BX=0x34 free paragraphs. */
            g_eax = (g_eax & 0xffff0000u) | 0x0008u;
            g_ebx = (g_ebx & 0xffff0000u) | 0x0034u;
            g_flag_cf = 1;
            return GW_INTERRUPT_HANDLED;
        }
        if (function == 0x49u && instruction_va == 0x000C3D46u &&
            services->measured_ah48_active && g_seg_es == services->measured_ah48_segment) {
            /* The original CD-present fixture frees the measured 0x4c block.
             * A different ES is deliberately left unhandled. */
            services->measured_ah48_active = 0;
            g_flag_cf = 0;
            return GW_INTERRUPT_HANDLED;
        }
        if (ax == 0xff00u && (uint16_t)g_edx == 0x0078u) {
            /* DOS/4G install check used by the measured LE entry. */
            g_eax = (g_eax & 0xffff0000u) | 0xffffu;
            g_flag_cf = 0;
            return GW_INTERRUPT_HANDLED;
        }
        return GW_INTERRUPT_TRAPPED;
    }
    if (vector == 0x31u && (uint16_t)g_eax == 0x0501u) {
        uint32_t size = ((g_ebx & 0xffffu) << 16) | (g_ecx & 0xffffu);
        if (!size) {
            g_eax = (g_eax & 0xffff0000u) | 0x8021u;
            g_flag_cf = 1;
            return GW_INTERRUPT_HANDLED;
        }
        if (!services->allocation_configured) {
            g_eax = (g_eax & 0xffff0000u) | 0x8012u;
            g_flag_cf = 1;
            return GW_INTERRUPT_HANDLED;
        }
        uint32_t allocation_slot=GW_DOS_MAX_LINEAR_ALLOCATIONS;
        for (uint32_t i=0;i<GW_DOS_MAX_LINEAR_ALLOCATIONS;i++) {
            if (!services->linear_allocations[i].active) { allocation_slot=i; break; }
        }
        if (allocation_slot==GW_DOS_MAX_LINEAR_ALLOCATIONS) goto allocation_unavailable;
        uint32_t cursor = services->allocation_cursor;
        if (!services->guest_memory_configured ||
            services->allocation_end > services->guest_memory_size ||
            cursor > UINT32_MAX - 0xfffu) goto allocation_unavailable;
        uint32_t base = (cursor + 0xfffu) & ~0xfffu;
        if (base < cursor || size > services->allocation_end - (base <= services->allocation_end ? base : services->allocation_end) ||
            (uint64_t)base + size > services->guest_memory_size)
            goto allocation_unavailable;
        if (base > services->allocation_end || services->next_allocation_handle == 0)
            goto allocation_unavailable;
        uintptr_t guest_base=(uintptr_t)g_mem_base;
        if (!guest_base || guest_base>UINTPTR_MAX-(uintptr_t)base ||
            guest_base+(uintptr_t)base>UINTPTR_MAX-(uintptr_t)size)
            goto allocation_unavailable;
        /* Backing providers may reserve the address space sparsely and commit
         * only the pages for a successful DPMI allocation. Failure is reported
         * before publishing a base/handle or advancing the allocator cursor. */
        if (services->guest_memory_backing_configured &&
            (!services->guest_memory_prepare ||
             !services->guest_memory_prepare(services->guest_memory_prepare_user,base,size)))
            goto allocation_unavailable;
        /* A configured backing provider must return newly zeroed backing.
         * VirtualAlloc(MEM_COMMIT) has that guarantee for this reserved map.
         * Keep the local clear for the ordinary in-process guest buffer. */
        if (!services->guest_memory_backing_configured)
            memset((void *)(guest_base+(uintptr_t)base),0,(size_t)size);
        uint32_t handle = services->next_allocation_handle++;
        services->linear_allocations[allocation_slot].base=base;
        services->linear_allocations[allocation_slot].size=size;
        services->linear_allocations[allocation_slot].handle=handle;
        services->linear_allocations[allocation_slot].active=1;
        services->linear_allocations[allocation_slot].reserved[0]=0;
        services->linear_allocations[allocation_slot].reserved[1]=0;
        services->linear_allocations[allocation_slot].reserved[2]=0;
        services->linear_allocation_count++;
        services->allocation_cursor = base + size;
        g_ebx = (g_ebx & 0xffff0000u) | ((base >> 16) & 0xffffu);
        g_ecx = (g_ecx & 0xffff0000u) | (base & 0xffffu);
        g_esi = (g_esi & 0xffff0000u) | ((handle >> 16) & 0xffffu);
        g_edi = (g_edi & 0xffff0000u) | (handle & 0xffffu);
        g_flag_cf = 0;
        return GW_INTERRUPT_HANDLED;
allocation_unavailable:
        g_eax = (g_eax & 0xffff0000u) | 0x8012u;
        g_flag_cf = 1;
        return GW_INTERRUPT_HANDLED;
    }
    if (vector == 0x31u && (uint16_t)g_eax == 0x0006u) {
        uint16_t selector = (uint16_t)g_ebx;
        uint32_t base;
        if (selector == 0) goto invalid_selector;
        if (!gw_dos_descriptor_base(selector, &base, services)) goto invalid_selector;
        g_ecx = (g_ecx & 0xffff0000u) | ((base >> 16) & 0xffffu);
        g_edx = (g_edx & 0xffff0000u) | (base & 0xffffu);
        g_flag_cf = 0;
        return GW_INTERRUPT_HANDLED;
invalid_selector:
        g_eax = (g_eax & 0xffff0000u) | 0x8022u;
        g_flag_cf = 1;
        return GW_INTERRUPT_HANDLED;
    }
    return GW_INTERRUPT_TRAPPED;
}

void gw_dos_services_init(gw_dos_services *services) {
    if (services) {
        services->standard_handles_closed=0;
        recomp_set_segment_resolver(gw_dos_descriptor_base, services);
        recomp_set_segment_range_validator(gw_dos_descriptor_range, services);
    }
    gw_interrupt_set_callback(gw_dos_services_callback, services);
}
