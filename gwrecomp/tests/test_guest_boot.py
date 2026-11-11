import hashlib
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime"))
from guest_boot import (  # noqa: E402
    DEFAULT_PROGRAM_PATH,
    DOS_CONVENTIONAL_BYTES,
    GuestAddressError,
    GuestAddressSpace,
    build_guest_memory_map,
    prepare_guest,
    prepare_native_lift_guest,
    GENEWARS_11_MEASURED_OBJECT_DELTAS,
    validate_environment_block,
)
from le_loader import load_le
from dos_services import CpuRegs, DosHost

IMAGE = ROOT / "evidence" / "genewars-1_1.exe"


class GuestBootTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.boot = prepare_guest(IMAGE, command_tail=b"-windowed")

    def test_rebased_le_image_and_stack(self):
        b = self.boot
        self.assertEqual(b.executable_sha256, "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f")
        self.assertEqual(b.seed.eip, 0x1AF96C)
        self.assertEqual(b.image.fixup_count, 25204)
        self.assertTrue(b.image.objects[b.image.entry_object - 1].executable)
        stack = b.image.objects[b.image.stack_object - 1]
        self.assertTrue(stack.writable)
        self.assertEqual(b.seed.esp, stack.end)
        self.assertGreater(b.seed.esp - stack.base, 0)
        self.assertEqual(b.memory.read(b.seed.eip, 2), bytes.fromhex("eb76"))

    def test_psp_environment_and_command_tail(self):
        b = self.boot
        self.assertLess(b.psp_address, DOS_CONVENTIONAL_BYTES)
        self.assertLess(b.env_address, DOS_CONVENTIONAL_BYTES)
        self.assertLess(b.memory.size, 0x400000)
        self.assertEqual(b.memory.read(b.psp_address, 2), b"\xcd\x20")
        self.assertEqual(b.memory.read_u16(b.psp_address + 0x2C), b.env_segment)
        self.assertEqual(b.memory.read(b.psp_address + 0x80, 1)[0], len(b"-windowed"))
        self.assertEqual(b.memory.read(b.psp_address + 0x81, len(b"-windowed")), b"-windowed")
        self.assertEqual(b.memory.read(b.env_address, len(b.environment)), b.environment)
        self.assertIn(DEFAULT_PROGRAM_PATH.encode("ascii"), b.environment)
        self.assertEqual(b.environment, b"\0\0\x01\x00" + DEFAULT_PROGRAM_PATH.encode("ascii") + b"\0")

    def test_authenticated_original_environment_fixture_is_injected_byte_exactly(self):
        evidence_path = ROOT / "evidence" / "w3_140_original_setenvp_environment.json"
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        payload = bytes.fromhex(evidence["capture"]["environment"]["sample_hex"])
        self.assertEqual(len(payload), 86)
        self.assertEqual(
            hashlib.sha256(payload).hexdigest(),
            "65c4d22c258efbf93a93cfcaa8d9d8c489e510cb2be76530646c36e0250ee895",
        )

        for boot in (
            prepare_guest(IMAGE, command_tail=b"-k 38928", environment_block=payload),
            prepare_native_lift_guest(IMAGE, command_tail=b"-k 38928", environment_block=payload),
        ):
            self.assertEqual(boot.environment, payload)
            self.assertEqual(boot.memory.read(boot.env_address, len(payload)), payload)
            self.assertEqual(boot.memory.read(boot.env_address, 86), payload)

    def test_environment_fixture_rejects_malformed_and_oversized_blocks(self):
        valid_tail = b"\0\0\x01\x00C:\\GAME.EXE\0"
        invalid = (
            b"NO-TERMINATOR",
            b"\0\0",
            b"\0\0\x01\x00\0",
            b"A\0\0\x01\x00C:\\GAME.EXE\0trailing",
        )
        for payload in invalid:
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError):
                    validate_environment_block(payload)
        with self.assertRaises(ValueError):
            validate_environment_block(b"\0\0\x01\x00" + b"A" * 4093 + b"\0")
        self.assertEqual(validate_environment_block(valid_tail), valid_tail)

    def test_environment_fixture_placement_remains_bounded(self):
        payload = b"A\0\0\x01\x00C:\\GAME.EXE\0"
        with self.assertRaises(ValueError):
            prepare_guest(IMAGE, env_segment=0xFFFF, environment_block=payload)
        with self.assertRaises(ValueError):
            prepare_native_lift_guest(IMAGE, env_segment=0x1000, environment_block=payload)

    def test_register_uncertainty_is_explicit(self):
        self.assertIn("eax", self.boot.seed.unknown_registers)
        self.assertEqual((self.boot.seed.cs, self.boot.seed.ds, self.boot.seed.ss), (0x0C, 0x14, 0x14))

    def test_guest_memory_bounds_fail_loudly(self):
        mem = GuestAddressSpace(8)
        with self.assertRaises(GuestAddressError):
            mem.read(7, 2)
        with self.assertRaises(GuestAddressError):
            mem.write(-1, b"x")
        with self.assertRaises(GuestAddressError):
            mem.read(0, -1)

    def test_guest_memory_growth_uses_zeroed_sparse_pages(self):
        mem = GuestAddressSpace(0x1800)
        mem.write(0x17fe, b"ab")
        mem.ensure_size(0x80000000)
        self.assertEqual(mem.size, 0x80000000)
        self.assertEqual(len(mem.data), 0x1800)
        self.assertEqual(mem.read(0x17fe, 4), b"ab\0\0")
        self.assertEqual(mem.read(0x7ffffffe, 2), b"\0\0")
        mem.write(0x7ffffffc, b"WXYZ")
        self.assertEqual(mem.read(0x7ffffffc, 4), b"WXYZ")
        self.assertLessEqual(len(mem._sparse_pages), 2)

    def test_guest_memory_sparse_range_still_checks_logical_bounds(self):
        mem = GuestAddressSpace(16)
        mem.ensure_size(0x10000)
        with self.assertRaises(GuestAddressError):
            mem.write(0xffff, b"xy")

    def test_psp_and_environment_do_not_overlap_rebased_image(self):
        self.assertLess(self.boot.psp_address + 256, self.boot.image.mem_base)
        self.assertLess(self.boot.env_address + len(self.boot.environment), self.boot.image.mem_base)

    def test_measured_gene_wars_object_layout_separates_link_and_linear_addresses(self):
        boot = prepare_native_lift_guest(IMAGE, object_rebases=GENEWARS_11_MEASURED_OBJECT_DELTAS)
        image = boot.image
        self.assertEqual(boot.executable_sha256, "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f")
        self.assertEqual([o.base for o in image.objects], [0x10000, 0xF0000, 0x100000, 0x1B0000])
        self.assertEqual([o.linear_base for o in image.objects], [0x1FB000, 0xF0000, 0x2DA000, 0x1B0000])
        ordered = sorted(image.objects, key=lambda o: o.linear_base)
        self.assertTrue(all(a.linear_end <= b.linear_base for a, b in zip(ordered, ordered[1:])))
        self.assertEqual((image.entry_link, image.entry_linear, boot.seed.eip),
                         (0xAF96C, 0x29A96C, 0xAF96C))
        self.assertEqual(image.object_containing(0xAF96C).index, 1)
        self.assertEqual(image.object_containing_linear(0x29A96C).index, 1)
        self.assertIsNone(image.object_containing_linear(0xAF96C))
        self.assertEqual(image.link_to_linear(0xAF96C), 0x29A96C)
        self.assertEqual(image.linear_to_link(0x29A96C), 0xAF96C)
        self.assertEqual(image.link_to_linear(0x110000), 0x2EA000)
        self.assertEqual(image.linear_to_link(0x2EA000), 0x110000)
        self.assertEqual(boot.memory.read(0x29A96C, 2), bytes.fromhex("eb76"))
        self.assertEqual(boot.memory.read(boot.psp_address, 2), b"\xcd\x20")
        self.assertLess(boot.psp_address + 256, 0xA0000)
        self.assertLess(boot.env_address + len(boot.environment), 0xA0000)
        self.assertEqual(image.object_containing_linear(0x2DA000).index, 3)
        self.assertFalse(image.objects[1].linear_base_verified)
        self.assertFalse(image.objects[3].linear_base_verified)
        self.assertEqual(image.objects[3].linear_base, image.objects[3].base,
                         "unmeasured object 4 retains a link-coordinate placeholder, not a runtime claim")

    def test_memory_map_keeps_unmeasured_object_bases_out_of_free_space(self):
        boot = prepare_native_lift_guest(IMAGE, object_rebases=GENEWARS_11_MEASURED_OBJECT_DELTAS)
        memory_map = build_guest_memory_map(boot.image, 0x10000000, require_complete=False)
        self.assertEqual(memory_map.unknown_objects, (2, 4))
        self.assertFalse(memory_map.complete)
        self.assertEqual(memory_map.free, (), "partial object maps cannot authorize DPMI allocations")
        self.assertIn((0, 0xA0000, "DOS conventional memory"), memory_map.occupied)
        with self.assertRaisesRegex(ValueError, "lacks verified linear bases"):
            build_guest_memory_map(boot.image, 0x10000000)

    def test_memory_map_uses_explicit_guest_limit_and_excludes_all_loaded_regions(self):
        # Synthetic map geometry validates the interval algorithm only; it is
        # not a claim about GeneWars 1.1 object 2/4 runtime placement.
        image = load_le(IMAGE, object_rebases={
            1: 0x1EB000, 2: 0x080000, 3: 0x1DA000, 4: 0x2F0000,
        })
        memory_map = build_guest_memory_map(image, 0x500000)
        self.assertTrue(memory_map.complete)
        self.assertEqual(memory_map.free[-1], (0x4A1350, 0x500000))
        self.assertEqual(memory_map.guest_limit, 0x500000)
        for start, end in memory_map.free:
            for occupied_start, occupied_end, _ in memory_map.occupied:
                self.assertTrue(end <= occupied_start or start >= occupied_end)

    def test_object_relative_fixups_target_the_loaded_data_object(self):
        baseline = load_le(IMAGE)
        mapped = load_le(IMAGE, object_rebases=GENEWARS_11_MEASURED_OBJECT_DELTAS)
        code_before = baseline.object_data(1)
        code_after = mapped.object_data(1)
        data = mapped.objects[2]
        found = False
        for offset in range(len(code_before) - 3):
            old = int.from_bytes(code_before[offset:offset + 4], "little")
            if data.base <= old < data.end:
                new = int.from_bytes(code_after[offset:offset + 4], "little")
                if new == old + 0x1DA000:
                    found = True
                    break
        self.assertTrue(found, "no code fixup was relocated to the observed data-object placement")
        self.assertEqual(mapped.fixup_count, baseline.fixup_count)

    def test_object_layout_rejects_overlaps_and_unpinned_images(self):
        with self.assertRaisesRegex(ValueError, "overlap"):
            load_le(IMAGE, object_rebases={1: 0x1FA000, 3: 0x1DA000, 4: 0x1DA000})
        with self.assertRaisesRegex(ValueError, "pinned executable hash"):
            prepare_native_lift_guest(pathlib.Path(__file__), object_rebases=GENEWARS_11_MEASURED_OBJECT_DELTAS)

    def test_dos_mcb_allocate_free_uses_low_memory_without_touching_relocated_objects(self):
        boot = prepare_native_lift_guest(IMAGE, object_rebases=GENEWARS_11_MEASURED_OBJECT_DELTAS)
        host = DosHost(boot, dos_memory_profile="post_dos4gw_le_entry")
        self.assertEqual(host.dos_mcb_layout["top_segment"], 0xA000)
        request = CpuRegs(eax=0x4800, ebx=0x0100)
        allocated = host.dispatch(0x21, request)
        self.assertEqual(allocated.service, "dos21.allocate_memory")
        self.assertFalse(request.carry)
        start, end = request.ax << 4, (request.ax << 4) + 0x100 * 16
        self.assertLess(end, 0xA0000)
        verified_objects = [o for o in boot.image.objects if o.linear_base_verified]
        self.assertTrue(all(end <= o.linear_base or start >= o.linear_end for o in verified_objects))
        self.assertEqual(tuple(o.index for o in boot.image.objects if not o.linear_base_verified), (2, 4))
        released = host.dispatch(0x21, CpuRegs(eax=0x4900, es=request.ax))
        self.assertEqual(released.service, "dos21.free_memory")
        self.assertEqual(host.dos_free_blocks, {host.dos_mcb_layout["free_mcb_segment"]:
                                                host.dos_mcb_layout["free_paragraphs"]})


if __name__ == "__main__":
    unittest.main()
