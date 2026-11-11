import pathlib
import tempfile
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime"))
from dos_services import (  # noqa: E402
    CF, CpuRegs, DOS_INSUFFICIENT_MEMORY, DOS_INVALID_BLOCK,
    DPMI_INVALID_SELECTOR, DPMI_INVALID_VALUE, DPMI_LINEAR_UNAVAILABLE, DosHost,
)
from guest_boot import prepare_guest, prepare_native_lift_guest  # noqa: E402
from host_devices import DosClock  # noqa: E402
from dos_filesystem import DosFileSystem  # noqa: E402

IMAGE = ROOT / "evidence" / "genewars-1_1.exe"


class DosServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.boot = prepare_guest(IMAGE)

    def setUp(self):
        self.boot = prepare_guest(IMAGE)
        self.host = DosHost(self.boot)

    def test_post_dos4gw_mcb_layout_exposes_bounded_64k_dos_block(self):
        boot = prepare_guest(IMAGE)
        host = DosHost(boot, dos_memory_profile="post_dos4gw_le_entry")
        layout = host.dos_mcb_layout
        self.assertEqual(layout["psp_end_segment"], layout["environment_mcb_segment"])
        self.assertEqual(boot.memory.read_u16(boot.psp_address + 2), layout["psp_end_segment"])
        self.assertEqual(layout["environment_paragraphs"], 2)
        self.assertEqual(layout["free_data_segment"], layout["free_mcb_segment"] + 1)
        self.assertGreaterEqual(layout["free_paragraphs"], 0x1000)
        for segment, tag, owner, paragraphs in (
            (layout["psp_mcb_segment"], b"M", boot.psp_segment, layout["psp_paragraphs"]),
            (layout["environment_mcb_segment"], b"M", boot.psp_segment, layout["environment_paragraphs"]),
            (layout["free_mcb_segment"], b"Z", 0, layout["free_paragraphs"]),
        ):
            address = segment << 4
            self.assertEqual(boot.memory.read(address, 1), tag)
            self.assertEqual(boot.memory.read_u16(address + 1), owner)
            self.assertEqual(boot.memory.read_u16(address + 3), paragraphs)
        alloc = CpuRegs(eax=0x0100, ebx=0x1000)
        result = host.dispatch(0x31, alloc, eip=0x001D23A7)
        self.assertEqual(result.service, "dpmi31.allocate_dos_memory")
        self.assertFalse(alloc.carry)
        self.assertEqual((alloc.ax, alloc.dx), (layout["free_data_segment"], 0x24))
        alloc_start = alloc.ax << 4
        alloc_end = alloc_start + 0x1000 * 16
        self.assertGreaterEqual(alloc_start, (boot.env_segment << 4) + len(boot.environment))
        self.assertLess(alloc_end, layout["vga_rom_start"])
        self.assertLess(alloc_end, layout["le_image_start"])
        self.assertEqual(host.dos_allocations[alloc.dx], (alloc.ax, 0x1000))

    def test_explicit_post_extender_top_preserves_measured_ah48_failure(self):
        # Isolated experimental profile matching the preserved PSP/environment
        # layout used by the native startup capture; it is not a DOSBox-wide
        # memory-equivalence claim.
        boot = prepare_native_lift_guest(IMAGE, command_tail=b"-k 38928",
            environment_block=b"A=" + b"x" * 70 + b"\0\0\x01\0C:\\GW.EXE\0")
        boot.image.mem_base = 0x000F0000  # actual image placement in this C harness
        host = DosHost(boot, dos_memory_profile="post_dos4gw_le_entry",
                       dos_memory_top_segment=0x1000)
        layout = host.dos_mcb_layout
        self.assertEqual(layout["free_data_segment"], 0x0907)
        self.assertEqual(layout["top_segment"], 0x1000)
        self.assertEqual(layout["free_paragraphs"], 0x06F9)

        first = CpuRegs(eax=0x4800, ebx=1)
        result = host.dispatch(0x21, first, eip=0x000C3D21)
        self.assertEqual(result.service, "dos21.allocate_memory")
        self.assertFalse(first.carry)
        self.assertEqual(first.ax, 0x0907)

        retry = CpuRegs(eax=0x4807, ebx=0x1000)
        result = host.dispatch(0x21, retry, eip=0x000C3D35)
        self.assertEqual(result.service, "dos21.allocate_memory.insufficient_memory")
        self.assertTrue(retry.carry)
        self.assertEqual((retry.ax, retry.bx), (DOS_INSUFFICIENT_MEMORY, 0x06F7))

    def test_dos_ah48_allocates_one_paragraph_from_post_dos4gw_mcb(self):
        boot = prepare_guest(IMAGE)
        host = DosHost(boot, dos_memory_profile="post_dos4gw_le_entry")
        initial_free = dict(host.dos_free_blocks)
        regs = CpuRegs(eax=0xABCD4800, ebx=0xFACE0001, eflags=0x203)
        result = host.dispatch(0x21, regs, eip=0x001C3D21)
        segment = min(initial_free) + 1
        self.assertEqual(result.service, "dos21.allocate_memory")
        self.assertEqual((regs.ax, regs.bx), (segment, 1))
        self.assertFalse(regs.carry)
        mcb = (segment - 1) << 4
        self.assertEqual(boot.memory.read(mcb, 1), b"M")
        self.assertEqual(boot.memory.read_u16(mcb + 1), boot.psp_segment)
        self.assertEqual(boot.memory.read_u16(mcb + 3), 1)
        self.assertEqual(host.dos_ah48_allocations[segment], (segment - 1, 1))
        self.assertEqual(sum(host.dos_free_blocks.values()), sum(initial_free.values()) - 2)

    def test_dos_ah49_frees_only_ah48_blocks_and_coalesces_mcb_chain(self):
        boot = prepare_guest(IMAGE)
        host = DosHost(boot, dos_memory_profile="post_dos4gw_le_entry")
        initial_free = dict(host.dos_free_blocks)
        allocated = CpuRegs(eax=0x4800, ebx=1)
        host.dispatch(0x21, allocated)
        segment = allocated.ax
        invalid = CpuRegs(eax=0x4900, es=segment + 1, eflags=0x202)
        bad = host.dispatch(0x21, invalid)
        self.assertEqual(bad.service, "dos21.free_memory.invalid_block")
        self.assertTrue(invalid.carry); self.assertEqual(invalid.ax, 9)
        freed = CpuRegs(eax=0xABCD4900, es=segment, eflags=0x203)
        result = host.dispatch(0x21, freed)
        self.assertEqual(result.service, "dos21.free_memory")
        self.assertFalse(freed.carry)
        self.assertEqual(host.dos_free_blocks, initial_free)
        self.assertEqual(host.dos_ah48_allocations, {})
        free_mcb = min(initial_free)
        self.assertEqual(boot.memory.read(free_mcb << 4, 1), b"Z")
        self.assertEqual(boot.memory.read_u16((free_mcb << 4) + 3), initial_free[free_mcb])

    def test_dos_ah48_failure_returns_largest_block_without_mutating_mcbs(self):
        boot = prepare_guest(IMAGE)
        host = DosHost(boot, dos_memory_profile="post_dos4gw_le_entry")
        before = dict(host.dos_free_blocks)
        request = CpuRegs(eax=0x12344800, ebx=0xFACEFFFF, eflags=0x202)
        result = host.dispatch(0x21, request)
        self.assertEqual(result.service, "dos21.allocate_memory.insufficient_memory")
        self.assertTrue(request.carry)
        self.assertEqual((request.ax, request.bx), (DOS_INSUFFICIENT_MEMORY, max(before.values())))
        self.assertEqual(host.dos_free_blocks, before)
        self.assertEqual(host.dos_ah48_allocations, {})

    def test_dos_ah48_zero_paragraph_request_fails_without_mutating_mcb_state(self):
        boot = prepare_guest(IMAGE)
        host = DosHost(boot, dos_memory_profile="post_dos4gw_le_entry")
        free_blocks_before = dict(host.dos_free_blocks)
        allocations_before = dict(host.dos_ah48_allocations)
        mcb_bytes_before = {
            segment: boot.memory.read(segment << 4, 16)
            for segment in free_blocks_before
        }
        request = CpuRegs(eax=0xABCD4800, ebx=0xFACE0000, eflags=0x202)

        result = host.dispatch(0x21, request)

        self.assertEqual(result.service, "dos21.allocate_memory.insufficient_memory")
        self.assertTrue(request.carry)
        self.assertEqual((request.ax, request.bx),
                         (DOS_INSUFFICIENT_MEMORY, max(free_blocks_before.values())))
        self.assertEqual(host.dos_free_blocks, free_blocks_before)
        self.assertEqual(host.dos_ah48_allocations, allocations_before)
        for segment, expected in mcb_bytes_before.items():
            self.assertEqual(boot.memory.read(segment << 4, 16), expected)

    def test_dos_ah48_split_and_out_of_order_frees_restore_single_owned_mcb(self):
        boot = prepare_guest(IMAGE)
        host = DosHost(boot, dos_memory_profile="post_dos4gw_le_entry")
        initial_free = dict(host.dos_free_blocks)
        first = CpuRegs(eax=0x4800, ebx=2)
        second = CpuRegs(eax=0x4800, ebx=4)

        self.assertEqual(host.dispatch(0x21, first).service, "dos21.allocate_memory")
        self.assertEqual(host.dispatch(0x21, second).service, "dos21.allocate_memory")
        first_mcb = first.ax - 1
        second_mcb = second.ax - 1
        tail_mcb = second_mcb + second.bx + 1

        self.assertEqual((first_mcb, second_mcb),
                         (min(initial_free), min(initial_free) + 3))
        self.assertEqual((boot.memory.read(first_mcb << 4, 1),
                          boot.memory.read_u16((first_mcb << 4) + 1),
                          boot.memory.read_u16((first_mcb << 4) + 3)),
                         (b"M", boot.psp_segment, 2))
        self.assertEqual((boot.memory.read(second_mcb << 4, 1),
                          boot.memory.read_u16((second_mcb << 4) + 1),
                          boot.memory.read_u16((second_mcb << 4) + 3)),
                         (b"M", boot.psp_segment, 4))
        self.assertEqual((boot.memory.read(tail_mcb << 4, 1),
                          boot.memory.read_u16((tail_mcb << 4) + 1)), (b"Z", 0))

        self.assertEqual(host.dispatch(0x21, CpuRegs(eax=0x4900, es=first.ax)).service,
                         "dos21.free_memory")
        self.assertEqual(host.dispatch(0x21, CpuRegs(eax=0x4900, es=second.ax)).service,
                         "dos21.free_memory")

        self.assertEqual(host.dos_free_blocks, initial_free)
        self.assertEqual(host.dos_ah48_allocations, {})
        final_mcb = min(initial_free)
        self.assertEqual((boot.memory.read(final_mcb << 4, 1),
                          boot.memory.read_u16((final_mcb << 4) + 1),
                          boot.memory.read_u16((final_mcb << 4) + 3)),
                         (b"Z", 0, initial_free[final_mcb]))

    def test_dos_ah49_double_free_is_rejected_without_mutating_free_chain(self):
        boot = prepare_guest(IMAGE)
        host = DosHost(boot, dos_memory_profile="post_dos4gw_le_entry")
        allocated = CpuRegs(eax=0x4800, ebx=3)
        host.dispatch(0x21, allocated)
        segment = allocated.ax
        host.dispatch(0x21, CpuRegs(eax=0x4900, es=segment))
        free_blocks_before = dict(host.dos_free_blocks)
        allocations_before = dict(host.dos_ah48_allocations)
        mcb_segment = min(free_blocks_before)
        mcb_bytes_before = boot.memory.read(mcb_segment << 4, 16)
        repeated = CpuRegs(eax=0x12344900, es=segment, eflags=0x202)

        result = host.dispatch(0x21, repeated)

        self.assertEqual(result.service, "dos21.free_memory.invalid_block")
        self.assertTrue(repeated.carry)
        self.assertEqual(repeated.ax, DOS_INVALID_BLOCK)
        self.assertEqual(host.dos_free_blocks, free_blocks_before)
        self.assertEqual(host.dos_ah48_allocations, allocations_before)
        self.assertEqual(boot.memory.read(mcb_segment << 4, 16), mcb_bytes_before)

    def test_dos_get_version_writes_ax_and_clears_carry(self):
        regs = CpuRegs(eax=0xABCD3000, eflags=0x203, eip=0x12345678)
        result = self.host.dispatch(0x21, regs)
        self.assertTrue(result.handled)
        self.assertEqual(result.service, "dos21.get_version")
        self.assertEqual(regs.ax, 0x1606)  # AH=minor 22, AL=major 6
        self.assertEqual(regs.eax >> 16, 0xABCD)
        self.assertFalse(regs.carry)

    def test_dos4g_install_check_requires_exact_ax_and_dx_signature(self):
        regs = CpuRegs(eax=0xAA00FF00, edx=0x12340078, eflags=0x203)
        result = self.host.dispatch(0x21, regs, eip=0x001AFAA8)
        self.assertTrue(result.handled)
        self.assertEqual(result.service, "dos21.dos4g_install_check")
        self.assertEqual(regs.ax, 0xFFFF)
        self.assertEqual(regs.eax >> 16, 0xAA00)
        self.assertFalse(regs.carry)
        wrong_dx = CpuRegs(eax=0xFF00, edx=0x79)
        self.assertFalse(self.host.dispatch(0x21, wrong_dx).handled)
        other_fn = CpuRegs(eax=0xFF01, edx=0x78)
        self.assertFalse(self.host.dispatch(0x21, other_fn).handled)

    def test_dos_open_existing_file_maps_handle_and_errors(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as temp:
            root = pathlib.Path(temp)
            (root / "GENEWARS").mkdir()
            (root / "GENEWARS" / "SAVE.DAT").write_bytes(b"save")
            self.host.filesystem = DosFileSystem(root)
            regs = CpuRegs(eax=0xABCD3D00, eflags=0x203, edx=0x12345678)
            result = self.host.dispatch(0x21, regs, filename=r"C:\GENEWARS\save.dat")
            self.assertTrue(result.handled)
            self.assertEqual(result.service, "dos21.open_file")
            self.assertEqual(regs.ax, 5)
            self.assertEqual(regs.eax >> 16, 0xABCD)
            self.assertFalse(regs.carry)
            self.assertEqual(self.host.filesystem.read(regs.ax, 4), b"save")
            self.host.filesystem.close(regs.ax)
            # Watcom's authentic DOS/4GW open call sets share mode 0x40 while
            # requesting read-only access; the DOS VFS receives access=read.
            shared_read = CpuRegs(eax=0x3D40, eflags=0x202)
            shared = self.host.dispatch(0x21, shared_read, filename=r"C:\GENEWARS\save.dat")
            self.assertEqual(shared.service, "dos21.open_file")
            self.assertFalse(shared_read.carry)
            self.assertEqual(self.host.filesystem.read(shared_read.ax, 4), b"save")
            self.host.filesystem.close(shared_read.ax)
            missing = CpuRegs(eax=0x3D01, eflags=0x202)
            failed = self.host.dispatch(0x21, missing, filename=r"C:\GENEWARS\missing.dat")
            self.assertTrue(failed.handled)
            self.assertEqual(failed.service, "dos21.open_file.error")
            self.assertEqual(missing.ax, 2)
            self.assertTrue(missing.carry)
            invalid = CpuRegs(eax=0x3D03)
            bad_mode = self.host.dispatch(0x21, invalid, filename="SAVE.DAT")
            self.assertEqual(bad_mode.service, "dos21.open_file.invalid_access")
            self.assertEqual(invalid.ax, 12)
            self.assertTrue(invalid.carry)
            invalid_share = CpuRegs(eax=0x3D50, eflags=0x202)
            bad_share = self.host.dispatch(0x21, invalid_share, filename="SAVE.DAT")
            self.assertEqual(bad_share.service, "dos21.open_file.invalid_access")
            self.assertEqual(invalid_share.ax, 12)
            self.assertTrue(invalid_share.carry)

    def test_dos_terminate_process_is_a_handled_terminal_service(self):
        regs = CpuRegs(eax=0xABCD4C2A, eip=0x12345678, eflags=0x203)
        result = self.host.dispatch(0x21, regs)
        self.assertTrue(result.handled)
        self.assertEqual(result.service, "dos21.terminate_process")
        self.assertEqual(regs.eax, 0xABCD4C2A)

    def test_dos_get_file_attributes_returns_dos_flags_and_errors(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as temp:
            root = pathlib.Path(temp)
            (root / "normal.dat").write_bytes(b"x")
            (root / ".hidden.dat").write_bytes(b"x")
            self.host.filesystem = DosFileSystem(root)
            regs = CpuRegs(eax=0xABCD4300, ecx=0x12340000, eflags=0x203)
            result = self.host.dispatch(0x21, regs, filename=r"C:\normal.dat")
            self.assertEqual(result.service, "dos21.get_file_attributes")
            self.assertEqual(regs.cx, 0x20)
            self.assertEqual(regs.ecx >> 16, 0x1234)
            self.assertFalse(regs.carry)
            hidden = CpuRegs(eax=0x4300)
            self.host.dispatch(0x21, hidden, filename=r"C:\.hidden.dat")
            self.assertEqual(hidden.cx, 0x22)
            directory = CpuRegs(eax=0x4300)
            self.host.dispatch(0x21, directory, filename=r"C:\.")
            self.assertEqual(directory.cx, 0x10)
            missing = CpuRegs(eax=0x4300)
            error = self.host.dispatch(0x21, missing, filename=r"C:\missing.dat")
            self.assertEqual(error.service, "dos21.get_file_attributes.error")
            self.assertEqual(missing.ax, 2)
            self.assertTrue(missing.carry)
            unsupported = CpuRegs(eax=0x4301)
            trap = self.host.dispatch(0x21, unsupported, filename=r"C:\normal.dat")
            self.assertFalse(trap.handled)

    def test_dos_close_file_flushes_and_releases_handle(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as temp:
            root = pathlib.Path(temp)
            target = root / "created.dat"
            self.host.filesystem = DosFileSystem(root)
            handle = self.host.filesystem.open(r"C:\created.dat", access="w", create=True)
            self.host.filesystem.write(handle, b"flush me")
            regs = CpuRegs(eax=0xABCD3E77, ebx=handle, eflags=0x203)
            result = self.host.dispatch(0x21, regs)
            self.assertTrue(result.handled)
            self.assertEqual(result.service, "dos21.close_file")
            self.assertEqual(regs.eax, 0xABCD3E77)
            self.assertFalse(regs.carry)
            self.assertEqual(target.read_bytes(), b"flush me")
            self.assertNotIn(handle, self.host.filesystem.handles)
            bad = CpuRegs(eax=0x3E00, ebx=handle)
            failed = self.host.dispatch(0x21, bad)
            self.assertEqual(failed.service, "dos21.close_file.error")
            self.assertEqual(bad.ax, 6)
            self.assertTrue(bad.carry)

    def test_dos_seek_file_supports_all_origins_and_errors(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as temp:
            root = pathlib.Path(temp)
            (root / "file.dat").write_bytes(b"0123456789")
            self.host.filesystem = DosFileSystem(root)
            handle = self.host.filesystem.open(r"C:\file.dat")
            absolute = CpuRegs(eax=0x4200, ebx=handle, ecx=0, edx=3, eflags=0x203)
            result = self.host.dispatch(0x21, absolute)
            self.assertEqual(result.service, "dos21.seek_file")
            self.assertEqual((absolute.dx, absolute.ax), (0, 3))
            self.assertFalse(absolute.carry)
            relative = CpuRegs(eax=0x4201, ebx=handle, ecx=0xffff, edx=0xffff)
            self.host.dispatch(0x21, relative)
            self.assertEqual(relative.ax, 2)
            end = CpuRegs(eax=0x4202, ebx=handle, ecx=0, edx=2)
            self.host.dispatch(0x21, end)
            self.assertEqual(end.ax, 12)
            invalid = CpuRegs(eax=0x4200, ebx=99)
            bad_handle = self.host.dispatch(0x21, invalid)
            self.assertEqual(bad_handle.service, "dos21.seek_file.error")
            self.assertEqual(invalid.ax, 6)
            self.assertTrue(invalid.carry)
            bad_origin = CpuRegs(eax=0x4203, ebx=handle)
            bad_mode = self.host.dispatch(0x21, bad_origin)
            self.assertEqual(bad_mode.service, "dos21.seek_file.invalid_origin")
            self.assertEqual(bad_origin.ax, 1)
            self.assertTrue(bad_origin.carry)
            self.host.filesystem.close(handle)

    def test_dos_write_file_writes_bytes_and_maps_errors(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as temp:
            root = pathlib.Path(temp)
            target = root / "out.dat"
            target.write_bytes(b"........")
            self.host.filesystem = DosFileSystem(root)
            handle = self.host.filesystem.open(r"C:\out.dat", access="w")
            regs = CpuRegs(eax=0xABCD4000, ebx=handle, ecx=4, edx=0x87654321, eflags=0x203)
            result = self.host.dispatch(0x21, regs, write_data=b"DATA")
            self.assertTrue(result.handled)
            self.assertEqual(result.service, "dos21.write_file")
            self.assertEqual(regs.ax, 4)
            self.assertEqual(regs.edx, 0x87654321)
            self.assertFalse(regs.carry)
            self.assertEqual(self.host.filesystem.seek(handle, 0, 1), 4)
            self.host.filesystem.close(handle)
            self.assertEqual(target.read_bytes(), b"DATA....")
            bad_handle = CpuRegs(eax=0x4000, ebx=99, ecx=1)
            error = self.host.dispatch(0x21, bad_handle, write_data=b"x")
            self.assertEqual(error.service, "dos21.write_file.error")
            self.assertEqual(bad_handle.ax, 6)
            self.assertTrue(bad_handle.carry)
            no_buffer = CpuRegs(eax=0x4000, ebx=handle, ecx=2)
            trap = self.host.dispatch(0x21, no_buffer)
            self.assertFalse(trap.handled)
            self.assertEqual(no_buffer.ax, 0x4000)

    def test_dos_ioctl_get_device_info_reports_file_drive_and_invalid_handle(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as temp:
            root = pathlib.Path(temp)
            (root / "file.dat").write_bytes(b"file")
            self.host.filesystem = DosFileSystem(root)
            handle = self.host.filesystem.open(r"C:\file.dat")
            regs = CpuRegs(eax=0xABCD4400, ebx=handle, edx=0x12345678, eflags=0x203)
            result = self.host.dispatch(0x21, regs)
            self.assertTrue(result.handled)
            self.assertEqual(result.service, "dos21.ioctl.get_device_info")
            self.assertEqual(regs.dx, 2)  # C: drive, bit 7 clear means regular file
            self.assertEqual(regs.edx >> 16, 0x1234)
            self.assertEqual(regs.ax, 2)  # DOSBox original destroys AX with the info word.
            self.assertFalse(regs.carry)
            invalid = CpuRegs(eax=0x4400, ebx=99)
            bad = self.host.dispatch(0x21, invalid)
            self.assertEqual(bad.service, "dos21.ioctl.get_device_info.invalid_handle")
            self.assertEqual(invalid.ax, 6)
            self.assertTrue(invalid.carry)
            unsupported = CpuRegs(eax=0x4402, ebx=handle)
            unknown = self.host.dispatch(0x21, unsupported)
            self.assertFalse(unknown.handled)
            self.assertEqual(unsupported.ax, 0x4402)
            self.host.filesystem.close(handle)

    def test_dos_create_truncates_confined_file_and_returns_dos_handle(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as temp:
            root = pathlib.Path(temp)
            (root / "GENEWARS").mkdir()
            existing = root / "address.txt"
            existing.write_bytes(b"old content")
            self.host.filesystem = DosFileSystem(root)
            regs = CpuRegs(eax=0xABCD3C00, ecx=0, eflags=0x203)
            result = self.host.dispatch(0x21, regs, filename=r"C:\address.txt")
            self.assertTrue(result.handled)
            self.assertEqual(result.service, "dos21.create_file")
            self.assertEqual(regs.ax, 5)
            self.assertEqual(regs.eax >> 16, 0xABCD)
            self.assertFalse(regs.carry)
            self.assertEqual(existing.read_bytes(), b"")
            self.host.filesystem.write(regs.ax, b"new")
            self.host.filesystem.close(regs.ax)
            self.assertEqual(existing.read_bytes(), b"new")

    def test_dos_create_errors_stay_inside_virtual_root(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as temp:
            root = pathlib.Path(temp)
            self.host.filesystem = DosFileSystem(root)
            regs = CpuRegs(eax=0x3C00)
            result = self.host.dispatch(0x21, regs, filename=r"C:\..\escape.txt")
            self.assertTrue(result.handled)
            self.assertEqual(result.service, "dos21.create_file.error")
            self.assertEqual(regs.ax, 5)
            self.assertTrue(regs.carry)
            self.assertFalse((root.parent / "escape.txt").exists())

    def test_dos_open_without_captured_filename_remains_unhandled(self):
        regs = CpuRegs(eax=0x3D00)
        result = self.host.dispatch(0x21, regs)
        self.assertFalse(result.handled)
        self.assertEqual(result.trap.function, 0x3D)
        self.assertEqual(regs.ax, 0x3D00)

    def test_dos_get_time_sets_packed_decimal_fields_and_preserves_other_bits(self):
        now=[0]
        self.host.dos_clock=DosClock(clock_ns=lambda:now[0],start_time=(23,59,59,99))
        regs=CpuRegs(eax=0xABCD2C77,ecx=0x12345678,edx=0x87654321,ebx=0x13579bdf,eflags=0x203)
        result=self.host.dispatch(0x21,regs)
        self.assertTrue(result.handled); self.assertEqual(result.service,"dos21.get_time")
        self.assertEqual((regs.ch,regs.cl,regs.dh,regs.dl),(23,59,59,99))
        self.assertEqual(regs.eax,0xABCD2C77); self.assertEqual(regs.ecx & 0xffff0000,0x12340000)
        self.assertEqual(regs.edx & 0xffff0000,0x87650000); self.assertEqual(regs.ebx,0x13579bdf)
        now[0]+=10_000_000
        self.assertEqual(self.host.dos_clock.time(),(0,0,0,0))

    def test_dos_dbcs_table_returns_terminated_environment_backing(self):
        regs = CpuRegs(eax=0x6300, esi=0xA5A50011, eflags=0x203)
        result = self.host.dispatch(0x21, regs)
        self.assertTrue(result.handled)
        self.assertEqual(result.service, "dos21.get_dbcs_lead_byte_table")
        self.assertEqual(regs.ds, self.boot.env_segment)
        self.assertEqual(regs.si, 0)
        self.assertEqual(self.boot.memory.read(self.boot.env_address, 2), b"\0\0")
        self.assertFalse(regs.carry)
        bad = CpuRegs(eax=0x6301)
        self.assertFalse(self.host.dispatch(0x21, bad).handled)

    def test_resize_dos_block_shrinks_and_updates_psp_and_mcbs(self):
        original = self.host.block_paragraphs
        regs = CpuRegs(eax=0x4A00, ebx=0x8000, es=self.boot.psp_segment)
        result = self.host.dispatch(0x21, regs)
        self.assertEqual(result.service, "dos21.resize.success")
        self.assertFalse(regs.carry)
        self.assertEqual(self.host.block_paragraphs, 0x8000)
        self.assertEqual(self.boot.memory.read_u16(self.boot.psp_address + 2), self.boot.psp_segment + 0x8000)
        mcb = (self.boot.psp_segment - 1) << 4
        self.assertEqual(self.boot.memory.read(mcb, 1), b"M")
        free_mcb = (self.boot.psp_segment + 0x8000) << 4
        self.assertEqual(self.boot.memory.read(free_mcb, 1), b"Z")
        self.assertEqual(original, 0x9000)

    def test_resize_can_rejoin_adjacent_free_block(self):
        first = CpuRegs(eax=0x4A00, ebx=0x8000, es=self.boot.psp_segment)
        self.host.dispatch(0x21, first)
        grow = CpuRegs(eax=0x4A00, ebx=0x9000, es=self.boot.psp_segment)
        result = self.host.dispatch(0x21, grow)
        self.assertEqual(result.service, "dos21.resize.success")
        self.assertFalse(grow.carry)
        self.assertEqual(self.host.block_paragraphs, 0x9000)
        self.assertIsNone(self.host.free_segment)
        self.assertEqual(self.boot.memory.read(((self.boot.psp_segment - 1) << 4), 1), b"Z")

    def test_resize_invalid_owner_and_insufficient_memory_return_dos_errors(self):
        invalid = CpuRegs(eax=0x4A00, ebx=0x100, es=0x2222)
        r1 = self.host.dispatch(0x21, invalid, eip=0xCAFEBABE)
        self.assertEqual(r1.service, "dos21.resize.invalid_block")
        self.assertTrue(invalid.carry)
        self.assertEqual(invalid.ax, DOS_INVALID_BLOCK)
        huge = CpuRegs(eax=0x4A00, ebx=0xFFFF, es=self.boot.psp_segment)
        r2 = self.host.dispatch(0x21, huge)
        self.assertEqual(r2.service, "dos21.resize.insufficient_memory")
        self.assertTrue(huge.carry)
        self.assertEqual(huge.ax, DOS_INSUFFICIENT_MEMORY)
        self.assertEqual(huge.bx, 0x9000)

    def test_dpmi_get_base_returns_cx_dx_and_invalid_selector_error(self):
        regs = CpuRegs(eax=0x00000006, ebx=0x14, ecx=0x12340000, edx=0x56780000, eflags=0x203)
        result = self.host.dispatch(0x31, regs)
        self.assertEqual(result.service, "dpmi31.get_segment_base")
        self.assertFalse(regs.carry)
        self.assertEqual((regs.cx, regs.dx), (0, 0))
        bad = CpuRegs(eax=6, ebx=0x88)
        result = self.host.dispatch(0x31, bad)
        self.assertEqual(result.service, "dpmi31.get_segment_base.invalid_selector")
        self.assertEqual(bad.ax, DPMI_INVALID_SELECTOR)
        self.assertTrue(bad.carry)

    def test_dpmi_allocate_memory_block_returns_backed_linear_range_and_handle(self):
        regs = CpuRegs(eax=0x0501, ebx=0, ecx=0x1000, eflags=0x203)
        result = self.host.dispatch(0x31, regs)
        self.assertTrue(result.handled); self.assertEqual(result.service, "dpmi31.allocate_memory")
        base = (regs.bx << 16) | regs.cx
        handle = (regs.si << 16) | regs.di
        self.assertEqual(base & 0xfff, 0); self.assertEqual(handle, 1)
        self.assertEqual(self.host.allocations[handle], (base, 0x1000))
        self.assertEqual(self.boot.memory.read(base, 0x1000), bytes(0x1000))
        self.assertFalse(regs.carry)
        self.boot.memory.write(base + 17, b"W2")
        self.assertEqual(self.boot.memory.read(base + 17, 2), b"W2")

        next_regs = CpuRegs(eax=0x0501, ebx=0, ecx=0x1000, eflags=0x202)
        next_result = self.host.dispatch(0x31, next_regs)
        next_base = (next_regs.bx << 16) | next_regs.cx
        next_handle = (next_regs.si << 16) | next_regs.di
        self.assertEqual(next_result.service, "dpmi31.allocate_memory")
        self.assertNotEqual(next_handle, handle)
        self.assertEqual(self.host.allocations[next_handle], (next_base, 0x1000))
        self.assertGreaterEqual(next_base, base + 0x1000)
        self.assertEqual(self.boot.memory.read(next_base, 0x1000), bytes(0x1000))

    def test_dpmi_large_linear_block_extends_logical_space_without_dense_commit(self):
        dense_size = len(self.boot.memory.data)
        regs = CpuRegs(eax=0x0501, ebx=0x0100, ecx=0)
        result = self.host.dispatch(0x31, regs)
        self.assertEqual(result.service, "dpmi31.allocate_memory")
        base = (regs.bx << 16) | regs.cx
        self.assertEqual(self.host.allocations[1], (base, 0x01000000))
        self.assertGreaterEqual(self.boot.memory.size, base + 0x01000000)
        self.assertEqual(len(self.boot.memory.data), dense_size)
        self.assertEqual(self.boot.memory.read(base, 64), bytes(64))
        self.boot.memory.write(base + 0x00ffffff, b"Z")
        self.assertEqual(self.boot.memory.read(base + 0x00ffffff, 1), b"Z")
        self.assertEqual(len(self.boot.memory.data), dense_size)

    def test_dpmi_allocate_rejects_zero_and_limit_without_false_success(self):
        zero = CpuRegs(eax=0xA5A50501, ebx=0x12340000, ecx=0x56780000,
                       esi=0x9abc0001, edi=0xdef00002, eflags=0x202)
        zero_before = zero.snapshot()
        r0 = self.host.dispatch(0x31, zero)
        self.assertEqual(r0.service, "dpmi31.allocate_memory.invalid_size")
        self.assertTrue(zero.carry); self.assertEqual(zero.ax, DPMI_INVALID_VALUE)
        for name in ("ebx", "ecx", "esi", "edi"):
            self.assertEqual(getattr(zero, name), zero_before[name], name)
        self.assertEqual(zero.eflags & ~CF, zero_before["eflags"] & ~CF)
        self.host.allocation_limit = self.host.next_allocation + 0xfff
        huge = CpuRegs(eax=0xBEEF0501, ebx=0x11110000, ecx=0x22202000,
                       esi=0x33330004, edi=0x44440005, eflags=0x246)
        huge_before = huge.snapshot()
        rh = self.host.dispatch(0x31, huge)
        self.assertEqual(rh.service, "dpmi31.allocate_memory.unavailable")
        self.assertTrue(huge.carry); self.assertEqual(huge.ax, DPMI_LINEAR_UNAVAILABLE)
        for name in ("ebx", "ecx", "esi", "edi"):
            self.assertEqual(getattr(huge, name), huge_before[name], name)
        self.assertEqual(huge.eflags & ~CF, huge_before["eflags"] & ~CF)
        self.assertEqual(self.host.allocations, {})

    def test_dpmi_free_linear_memory_neighbor_remains_fail_closed(self):
        regs = CpuRegs(eax=0x0502, esi=0x12340001, edi=0x56780002,
                       ebx=0x9abc0003, ecx=0xdef00004, eflags=0x202)
        before = regs.snapshot()
        result = self.host.dispatch(0x31, regs)
        self.assertFalse(result.handled)
        self.assertEqual(regs.snapshot(), before)

    def test_dpmi_lock_is_validated_noop_on_nonpaging_host(self):
        start = 0x001AFF40
        size = 0x6221
        regs = CpuRegs(eax=0x0600, ebx=start >> 16, ecx=start & 0xffff,
                       esi=size >> 16, edi=size & 0xffff, eflags=0x203)
        result = self.host.dispatch(0x31, regs)
        self.assertEqual(result.service, "dpmi31.lock.no_paging_host")
        self.assertFalse(regs.carry)
        self.assertEqual((regs.bx, regs.cx, regs.si, regs.di),
                         (start >> 16, start & 0xffff, size >> 16, size & 0xffff))
        bad = CpuRegs(eax=0x0600, ebx=0x7fff, ecx=0xffff, esi=0, edi=2)
        result = self.host.dispatch(0x31, bad)
        self.assertEqual(result.service, "dpmi31.lock.invalid_linear_range")
        self.assertTrue(bad.carry); self.assertEqual(bad.ax, 0x8025)

    def test_dpmi_virtual_lock_unlock_reference_counts(self):
        host = self.host
        host.dpmi_virtual_memory = True
        start, size = 0x2000, 0x2000
        def invoke(function):
            regs = CpuRegs(eax=function, ebx=start >> 16, ecx=start & 0xffff,
                           esi=size >> 16, edi=size & 0xffff)
            return host.dispatch(0x31, regs), regs
        result, regs = invoke(0x0601)
        self.assertEqual(result.service, "dpmi31.unlock.not_locked")
        self.assertTrue(regs.carry); self.assertEqual(regs.ax, 0x8002)
        for _ in range(2):
            result, regs = invoke(0x0600)
            self.assertEqual(result.service, "dpmi31.lock.success")
            self.assertFalse(regs.carry)
        self.assertEqual(host.locked_pages, {2: 2, 3: 2})
        invoke(0x0601)
        self.assertEqual(host.locked_pages, {2: 1, 3: 1})
        invoke(0x0601)
        self.assertEqual(host.locked_pages, {})

    def test_dpmi_get_real_mode_interrupt_vector_returns_configured_cx_dx(self):
        self.host.real_mode_interrupt_vectors[8] = (0x1234, 0x5678)
        regs = CpuRegs(eax=0x0200, ebx=0xaabbcc08, ecx=0x12340000,
                       edx=0xdeadbeef, eflags=0x203)
        result = self.host.dispatch(0x31, regs)
        self.assertEqual(result.service, "dpmi31.get_real_mode_interrupt_vector")
        self.assertEqual(regs.ecx, 0x12341234); self.assertEqual(regs.edx, 0xdead5678)
        self.assertEqual(regs.ebx, 0xaabbcc08); self.assertFalse(regs.carry)
        del self.host.real_mode_interrupt_vectors[8]
        empty = CpuRegs(eax=0x0200, ebx=8, ecx=0x12340000, edx=0xdeadbeef)
        self.host.dispatch(0x31, empty)
        self.assertEqual((empty.cx, empty.dx), (0, 0))
        self.assertEqual((empty.ecx, empty.edx), (0x12340000, 0xdead0000))
        self.assertFalse(empty.carry)

    def test_dpmi_set_real_mode_interrupt_vector_round_trip_without_selector_validation(self):
        regs = CpuRegs(eax=0x0201, ebx=0xaabbcc08, ecx=0x99991234,
                       edx=0xdead5678, eflags=0x203)
        result = self.host.dispatch(0x31, regs)
        self.assertEqual(result.service, "dpmi31.set_real_mode_interrupt_vector")
        self.assertFalse(regs.carry)
        self.assertEqual(regs.eax, 0x0201); self.assertEqual(regs.ebx, 0xaabbcc08)
        query = CpuRegs(eax=0x0200, ebx=8, ecx=0xabcd0000, edx=0x98760000)
        self.host.dispatch(0x31, query)
        self.assertEqual((query.ecx, query.edx), (0xabcd1234, 0x98765678))
        invalid_as_selector = CpuRegs(eax=0x0201, ebx=9, ecx=0x00880021,
                                      edx=0x99991000, eflags=0x203)
        result = self.host.dispatch(0x31, invalid_as_selector)
        self.assertEqual(result.service, "dpmi31.set_real_mode_interrupt_vector")
        self.assertFalse(invalid_as_selector.carry)
        self.assertEqual(self.host.real_mode_interrupt_vectors[9], (0x21, 0x1000))

    def test_dpmi_allocate_dos_memory_reports_real_exhaustion(self):
        regs = CpuRegs(eax=0x0100, ebx=0x1000, eflags=0x203)
        result = self.host.dispatch(0x31, regs)
        self.assertEqual(result.service, "dpmi31.allocate_dos_memory.insufficient_memory")
        self.assertTrue(regs.carry); self.assertEqual(regs.ax, 8); self.assertEqual(regs.bx, 0)
        self.assertEqual(self.host.dos_allocations, {})

    def test_dpmi_allocate_dos_memory_returns_backed_paragraph_block_and_selector(self):
        shrink = CpuRegs(eax=0x4a00, ebx=0x7fff, es=self.boot.psp_segment)
        self.host.dispatch(0x21, shrink)
        regs = CpuRegs(eax=0x0100, ebx=0x1000, eflags=0x203)
        result = self.host.dispatch(0x31, regs)
        self.assertEqual(result.service, "dpmi31.allocate_dos_memory")
        self.assertFalse(regs.carry)
        self.assertEqual((regs.ax, regs.dx), (0x9000, 0x24))
        self.assertEqual(self.host.dos_allocations[0x24], (0x9000, 0x1000))
        self.assertEqual(self.host.selectors[0x24], 0x90000)
        self.assertEqual(self.host.selector_limits[0x24], 0xffff)
        self.assertEqual(self.boot.memory.read(0x90000, 0x10000), bytes(0x10000))
        self.assertIsNone(self.host.free_segment)

    def test_dpmi_free_dos_blocks_validates_and_coalesces_adjacent_mcbs(self):
        self.host.dispatch(0x21, CpuRegs(eax=0x4a00, ebx=0x7ffe, es=self.boot.psp_segment))
        selectors=[]
        for _ in range(2):
            regs=CpuRegs(eax=0x0100,ebx=0x800)
            result=self.host.dispatch(0x31,regs)
            self.assertEqual(result.service,"dpmi31.allocate_dos_memory")
            selectors.append(regs.dx)
        for selector in selectors:
            result=self.host.dispatch(0x31,CpuRegs(eax=0x0101,edx=selector))
            self.assertEqual(result.service,"dpmi31.free_dos_memory")
        self.assertEqual(self.host.dos_free_blocks,{0x8ffe:0x1001})
        self.assertEqual(self.host.free_segment,0x8ffe)
        self.assertEqual(self.host.free_paragraphs,0x1001)
        self.assertNotIn(selectors[0],self.host.selectors)
        repeated=CpuRegs(eax=0x0101,edx=selectors[0])
        result=self.host.dispatch(0x31,repeated)
        self.assertEqual(result.service,"dpmi31.free_dos_memory.invalid_selector")
        self.assertTrue(repeated.carry); self.assertEqual(repeated.ax,DPMI_INVALID_SELECTOR)
        reuse=CpuRegs(eax=0x0100,ebx=0x1001)
        result=self.host.dispatch(0x31,reuse)
        self.assertEqual(result.service,"dpmi31.allocate_dos_memory")
        self.assertEqual((reuse.ax,reuse.dx),(0x8fff,0x34))

    def test_dpmi_resize_dos_block_shrinks_grows_and_preserves_neighbor(self):
        self.host.dispatch(0x21,CpuRegs(eax=0x4a00,ebx=0x7ffe,es=self.boot.psp_segment))
        first=CpuRegs(eax=0x0100,ebx=0x800); self.host.dispatch(0x31,first)
        second=CpuRegs(eax=0x0100,ebx=0x800); self.host.dispatch(0x31,second)
        resize=CpuRegs(eax=0x0102,ebx=0x400,edx=first.dx)
        result=self.host.dispatch(0x31,resize)
        self.assertEqual(result.service,"dpmi31.resize_dos_memory.shrink")
        self.assertEqual(self.host.dos_allocations[first.dx],(first.ax,0x400))
        self.assertEqual(self.host.selector_limits[first.dx],0x3fff)
        grow=CpuRegs(eax=0x0102,ebx=0x800,edx=first.dx)
        result=self.host.dispatch(0x31,grow)
        self.assertEqual(result.service,"dpmi31.resize_dos_memory.grow")
        self.assertEqual(self.host.dos_allocations[first.dx],(first.ax,0x800))
        self.assertEqual(self.host.selector_limits[first.dx],0x7fff)
        self.assertEqual(self.host.dos_allocations[second.dx],(second.ax,0x800))
        too_large=CpuRegs(eax=0x0102,ebx=0x801,edx=first.dx)
        result=self.host.dispatch(0x31,too_large)
        self.assertEqual(result.service,"dpmi31.resize_dos_memory.insufficient_memory")
        self.assertTrue(too_large.carry); self.assertEqual(too_large.ax,8)
        invalid=CpuRegs(eax=0x0102,ebx=0x200,edx=0x7777)
        result=self.host.dispatch(0x31,invalid)
        self.assertEqual(result.service,"dpmi31.resize_dos_memory.invalid_selector")
        self.assertTrue(invalid.carry); self.assertEqual(invalid.ax,DPMI_INVALID_SELECTOR)

    def test_dos_get_and_set_interrupt_vector_round_trip(self):
        self.host.dos_interrupt_vectors[8] = (0x1234, 0x5678)
        get = CpuRegs(eax=0xaabb3508, ebx=0xcccc0001, es=0x9999, eflags=0x203)
        result = self.host.dispatch(0x21, get)
        self.assertEqual(result.service, "dos21.get_interrupt_vector")
        self.assertEqual((get.es, get.bx), (0x1234, 0x5678))
        self.assertEqual(get.eax, 0xaabb3508); self.assertFalse(get.carry)
        empty = CpuRegs(eax=0x3509, es=0xaaaa, ebx=0xbbbb1234)
        self.host.dispatch(0x21, empty)
        self.assertEqual((empty.es, empty.bx), (0, 0))
        setv = CpuRegs(eax=0x2509, ds=0x2222, edx=0x12345678)
        result = self.host.dispatch(0x21, setv)
        self.assertEqual(result.service, "dos21.set_interrupt_vector")
        self.assertEqual(self.host.dos_interrupt_vectors[9], (0x2222, 0x5678))
        check = CpuRegs(eax=0x3509)
        self.host.dispatch(0x21, check)
        self.assertEqual((check.es, check.bx), (0x2222, 0x5678))

    def test_unsupported_interrupts_and_functions_return_traceable_traps(self):
        regs = CpuRegs(eax=0x12345678, eip=0xABCDEF01, ebx=0x90)
        before = regs.snapshot()
        result = self.host.dispatch(0x21, regs)
        self.assertFalse(result.handled)
        self.assertEqual(result.trap.vector, 0x21)
        self.assertEqual(result.trap.eip, 0xABCDEF01)
        self.assertEqual(result.trap.function, 0x56)
        self.assertEqual(result.trap.registers, before)
        self.assertEqual(regs.snapshot(), before)
        other = self.host.dispatch(0x10, regs)
        self.assertFalse(other.handled)
        self.assertEqual(other.trap.vector, 0x10)


if __name__ == "__main__":
    unittest.main()
    def test_mscdex_drive_count_and_starting_letter(self):
        boot = prepare_guest(IMAGE)
        host = DosHost(boot, cdrom_drives=("D",))
        regs = CpuRegs(eax=0x1500, ebx=0)
        result = host.dispatch(0x2f, regs)
        self.assertEqual(result.service, "int2f.mscdex_install_check")
        self.assertEqual((regs.bx, regs.cx), (1, 3))

    def test_mscdex_version_query_returns_major_minor_in_bx(self):
        boot = prepare_guest(IMAGE)
        host = DosHost(boot, cdrom_drives=("D",), mscdex_version=(2, 23))
        regs = CpuRegs(eax=0x150c, ebx=0, ecx=3)
        result = host.dispatch(0x2f, regs)
        self.assertEqual(result.service, "int2f.mscdex_get_version")
        self.assertEqual(regs.bx, 0x0217)
        self.assertEqual(regs.cx, 3)
