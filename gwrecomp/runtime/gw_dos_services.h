#ifndef GW_DOS_SERVICES_H
#define GW_DOS_SERVICES_H
#include <stdint.h>
#include "../third_party/pcrecomp/runtime/recomp32/recomp_types.h"

typedef struct gw_dos_descriptor {
    uint16_t selector;
    uint16_t reserved;
    uint32_t base;
    uint32_t limit;
} gw_dos_descriptor;

typedef struct gw_dos_memory_block {
    uint16_t selector;
    uint16_t segment;
    uint16_t paragraphs;
    uint16_t reserved;
} gw_dos_memory_block;

typedef uint16_t (*gw_dos_stream_read_fn)(void *user, uint8_t *buffer,
                                          uint16_t requested, uint16_t *transferred);
typedef uint16_t (*gw_dos_stream_write_fn)(void *user, const uint8_t *buffer,
                                           uint16_t requested, uint16_t *transferred);
typedef struct gw_dos_stream {
    gw_dos_stream_read_fn read;
    gw_dos_stream_write_fn write;
    void *user;
    uint8_t configured;
    uint8_t device;
    uint8_t ioctl_info_configured;
    uint8_t reserved;
    uint16_t ioctl_device_info;
} gw_dos_stream;

/* File operations are supplied by a confined virtual-filesystem adapter.
 * The DOS service layer never opens host paths itself. The adapter owns DOS
 * path/current-directory resolution and returns DOS error numbers. */
typedef uint16_t (*gw_dos_file_open_fn)(void *user, const char *dos_path,
                                        uint8_t access_mode, void **file);
typedef uint16_t (*gw_dos_file_read_fn)(void *user, void *file, uint8_t *buffer,
                                        uint16_t requested, uint16_t *transferred);
typedef uint16_t (*gw_dos_file_create_fn)(void *user, const char *dos_path,
                                          uint16_t attributes, void **file);
typedef uint16_t (*gw_dos_file_write_fn)(void *user, void *file, const uint8_t *buffer,
                                         uint16_t requested, uint16_t *transferred);
typedef uint16_t (*gw_dos_file_close_fn)(void *user, void *file);
/* Return the DOS AX=4400 device-information word for this virtual file. */
typedef uint16_t (*gw_dos_file_ioctl_info_fn)(void *user, void *file,
                                               uint16_t *device_info);
typedef uint16_t (*gw_dos_file_seek_fn)(void *user, void *file,
                                        int32_t displacement, uint8_t origin,
                                        uint32_t *position);

/* DPMI 0300 real-mode register frame. The packed size is 50 bytes: eight
 * 32-bit general registers followed by FLAGS and eight 16-bit registers. */
#pragma pack(push, 1)
typedef struct gw_dos_real_mode_registers {
    uint32_t edi, esi, ebp, reserved, ebx, edx, ecx, eax;
    uint16_t flags, es, ds, fs, gs, ip, cs, sp, ss;
} gw_dos_real_mode_registers;
#pragma pack(pop)
typedef int (*gw_dos_real_mode_interrupt_fn)(void *user, uint8_t vector,
                                              gw_dos_real_mode_registers *registers);
/* Prepare a fresh, zero-filled guest range before AX=0501 publishes it. */
typedef int (*gw_dos_guest_memory_prepare_fn)(void *user, uint32_t linear, uint32_t size);
typedef struct gw_dos_guest_region {
    uint32_t begin;
    uint32_t end; /* exclusive */
} gw_dos_guest_region;

#define GW_DOS_MAX_OPEN_FILES 32u
#define GW_DOS_MAX_LINEAR_ALLOCATIONS 1024u
typedef struct gw_dos_linear_allocation {
    uint32_t base;
    uint32_t size;
    uint32_t handle;
    uint8_t active;
    uint8_t reserved[3];
} gw_dos_linear_allocation;
typedef struct gw_dos_file_handle {
    void *file;
    uint8_t access_mode;
    uint8_t active;
    uint8_t created;
    uint8_t dos_handle;
} gw_dos_file_handle;

typedef struct gw_dos_services {
    uint8_t major;
    uint8_t minor;
    uint8_t time_hour;
    uint8_t time_minute;
    uint8_t time_second;
    uint8_t time_hundredths;
    uint8_t time_configured;
    uint8_t time_realtime_enabled;
    uint16_t measured_ah48_segment;
    uint8_t measured_ah48_active;
    uint8_t reserved;
    gw_dos_descriptor *descriptors;
    uint32_t descriptor_count;
    uint32_t descriptor_capacity;
    uint32_t allocation_cursor;
    uint32_t allocation_end;
    uint32_t next_allocation_handle;
    uint8_t allocation_configured;
    uint8_t linear_allocation_count_reserved[3];
    uint32_t linear_allocation_count;
    gw_dos_linear_allocation linear_allocations[GW_DOS_MAX_LINEAR_ALLOCATIONS];
    uint16_t dos_segment_begin;
    uint16_t dos_segment_end;
    uint16_t dos_segment_cursor;
    uint16_t dos_psp_segment;
    uint16_t dos_selector_begin;
    uint16_t dos_selector_cursor;
    uint8_t dos_allocator_configured;
    uint8_t dos4gw_flat_heap_enabled;
    uint16_t dos4gw_flat_heap_selector;
    uint16_t allocation_reserved;
    gw_dos_memory_block *dos_blocks;
    uint32_t dos_block_count;
    uint32_t dos_block_capacity;
    gw_dos_stream streams[3];
    /* DOS starts with JFT entries 0-4 open. A bit marks a standard slot
     * explicitly closed; a later virtual file may then reuse that number. */
    uint8_t standard_handles_closed;
    uint32_t stream_memory_begin;
    uint32_t stream_memory_size;
    uint8_t stream_memory_configured;
    uint8_t stream_reserved[3];
    uint32_t guest_memory_size;
    uint8_t guest_memory_configured;
    uint8_t guest_memory_backing_configured;
    uint8_t guest_memory_reserved[2];
    gw_dos_guest_memory_prepare_fn guest_memory_prepare;
    void *guest_memory_prepare_user;
    gw_dos_file_open_fn file_open;
    gw_dos_file_read_fn file_read;
    gw_dos_file_create_fn file_create;
    gw_dos_file_write_fn file_write;
    gw_dos_file_close_fn file_close;
    gw_dos_file_ioctl_info_fn file_ioctl_info;
    gw_dos_file_seek_fn file_seek;
    void *file_user;
    gw_dos_real_mode_interrupt_fn real_mode_interrupt;
    void *real_mode_interrupt_user;
    uint32_t dbcs_table_linear;
    uint16_t dbcs_table_size;
    uint8_t dbcs_table_configured;
    uint8_t dbcs_table_reserved;
    gw_dos_file_handle files[GW_DOS_MAX_OPEN_FILES];
    uint16_t dos_vector_segment[256];
    uint16_t dos_vector_offset[256];
    uint16_t dpmi_real_vector_segment[256];
    uint16_t dpmi_real_vector_offset[256];
} gw_dos_services;

/* Register a fail-closed DOS callback. The service state must outlive its use. */
void gw_dos_services_init(gw_dos_services *services);
int gw_dos_time_configure(gw_dos_services *services, uint8_t hour, uint8_t minute,
                          uint8_t second, uint8_t hundredths);
/* Opt into live host wall-clock samples for DOS AH=2Ch. Static configured
 * time remains the default for deterministic service tests. */
int gw_dos_time_realtime_enable(gw_dos_services *services);
int gw_dos_descriptor_bind(gw_dos_services *services, uint16_t selector, uint32_t base, uint32_t limit);
int gw_dos_descriptor_unbind(gw_dos_services *services, uint16_t selector);
void gw_dos_descriptor_clear(gw_dos_services *services);
void gw_dos_real_mode_vector_configure(gw_dos_services *services, uint8_t vector,
                                       uint16_t segment, uint16_t offset);
int gw_dos_linear_allocator_configure(gw_dos_services *services, uint32_t begin, uint32_t end);
/* Select the largest page-aligned free guest range from an explicit, bounded
 * guest map. This never infers guest capacity from host virtual memory. */
int gw_dos_linear_allocator_configure_from_map(gw_dos_services *services,
                                               uint32_t guest_limit,
                                               uint32_t minimum_address,
                                               const gw_dos_guest_region *occupied,
                                               uint32_t occupied_count);
int gw_dos_memory_allocator_configure(gw_dos_services *services, uint16_t begin_segment,
                                      uint16_t end_segment, uint16_t first_selector,
                                      uint16_t psp_segment);
/* Opt-in DOS/4GW flat-segment brk contract. It applies only when the given
 * live selector resolves to base zero and the guest memory map is configured. */
int gw_dos4gw_flat_heap_configure(gw_dos_services *services, uint16_t selector);
int gw_dos_stream_configure(gw_dos_services *services, uint16_t handle,
                            gw_dos_stream_read_fn read_fn,
                            gw_dos_stream_write_fn write_fn,
                            void *user, int device);
/* Configure the provider's DOS AX=4400 information word for a standard
 * character-device stream. The word must identify a device (bit 15 set). */
int gw_dos_stream_ioctl_info_configure(gw_dos_services *services,
                                       uint16_t handle,
                                       uint16_t device_info);
int gw_dos_stream_memory_configure(gw_dos_services *services,
                                   uint32_t guest_begin, uint32_t guest_size);
int gw_dos_guest_memory_configure(gw_dos_services *services, uint32_t guest_size);
int gw_dos_guest_memory_backing_configure(gw_dos_services *services,
                                          gw_dos_guest_memory_prepare_fn prepare_fn,
                                          void *user);
int gw_dos_file_backend_configure(gw_dos_services *services,
                                  gw_dos_file_open_fn open_fn,
                                  gw_dos_file_read_fn read_fn,
                                  gw_dos_file_create_fn create_fn,
                                  gw_dos_file_write_fn write_fn,
                                  gw_dos_file_close_fn close_fn, void *user);
int gw_dos_file_ioctl_info_configure(gw_dos_services *services,
                                     gw_dos_file_ioctl_info_fn info_fn);
int gw_dos_file_seek_configure(gw_dos_services *services,
                               gw_dos_file_seek_fn seek_fn);
int gw_dos_real_mode_interrupt_configure(gw_dos_services *services,
                                         gw_dos_real_mode_interrupt_fn interrupt_fn,
                                         void *user);
/* Configure a caller-reserved low-memory copy of a DOS DBCS lead-byte table.
 * The address is supplied per guest run; this API does not allocate guest
 * memory or assume that the caller's region overlaps no other object. */
int gw_dos_dbcs_table_configure(gw_dos_services *services,
                                uint32_t guest_real_mode_linear,
                                const uint8_t *table, uint16_t table_size);
/* Provider for the measured INT 21h AX=6300 case, suitable for the existing
 * DPMI AX=0300 real-mode interrupt callback configuration. */
int gw_dos_services_real_mode_interrupt(void *user, uint8_t vector,
                                        gw_dos_real_mode_registers *registers);
int gw_dos_descriptor_base(uint16_t selector, uint32_t *base, void *user);
int gw_dos_descriptor_range(uint16_t selector, uint32_t offset, uint32_t width, void *user);
gw_interrupt_result gw_dos_services_callback(uint8_t vector,
                                              uint32_t instruction_va,
                                              void *user);
#endif
