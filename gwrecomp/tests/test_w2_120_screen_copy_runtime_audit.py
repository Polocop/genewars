import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class ScreenCopyRuntimeAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = json.loads(
            (ROOT / "evidence/w3_234_screen_copy_audit.json").read_text(encoding="utf-8")
        )
        cls.generated = (ROOT / "build/entry_path_closure.c").read_text(encoding="utf-8")
        cls.segments = (ROOT / "runtime/gw_segments.c").read_text(encoding="utf-8")
        cls.context = (ROOT / "runtime/recomp_context.c").read_text(encoding="utf-8")
        cls.lifter = (ROOT / "third_party/pcrecomp/tools/lift/lift32.py").read_text(encoding="utf-8")
        cls.runtime_sources = {
            path: path.read_text(encoding="utf-8")
            for path in (ROOT / "runtime").rglob("*")
            if path.is_file() and path.suffix in {".c", ".h", ".py"}
        }

    def test_original_copy_measurement_is_bounded_and_arithmetic_consistent(self):
        evidence = self.evidence
        self.assertEqual(evidence["evidence_level"], "ORIGINAL_OBSERVED")
        self.assertEqual(evidence["copy"]["pre"]["link_va"], "0xA0013")
        pre = evidence["copy"]["pre"]
        post = evidence["copy"]["post"]
        byte_count = pre["ecx_dwords"] * 4
        self.assertEqual(pre["copy_bytes_from_count"], byte_count)
        self.assertEqual(int(post["esi_after"], 16), int(pre["esi_source"], 16) + byte_count)
        self.assertEqual(int(post["edi_after"], 16), int(pre["edi_destination"], 16) + byte_count)
        self.assertEqual(post["ecx_after"], 0)
        self.assertTrue(post["ds_descriptor_valid"])
        self.assertTrue(post["es_descriptor_valid"])
        self.assertEqual(post["ds_base"], "0x00000000")
        self.assertEqual(post["es_base"], "0x00000000")
        self.assertTrue(post["source_bounds_valid"])
        self.assertTrue(post["destination_bounds_valid"])
        self.assertEqual(post["sample_bytes"], 16)
        self.assertTrue(post["sample_all_zero"])
        self.assertFalse(evidence["first_framebuffer_verified"])
        self.assertFalse(evidence["menu_verified"])

    def test_exact_generated_rep_movsd_uses_checked_guest_memory(self):
        lines = self.generated.splitlines()
        site = next(line for line in lines if "0x000A0013: rep movsd" in line)
        self.assertIn("recomp_checked_segment_addr(RECOMP_SEG_DS", site)
        self.assertIn("recomp_checked_segment_addr(RECOMP_SEG_ES", site)
        self.assertIn("esi += (uint32_t)_b64", site)
        self.assertIn("edi += (uint32_t)_b64", site)
        self.assertIn("ecx = 0", site)
        self.assertIn("if (recomp_memory_fault_pending())", lines[lines.index(site) + 1])
        self.assertIn("_dp + (uintptr_t)_b64 <= _sp", self.lifter)
        self.assertIn("else if (_df > 0)", self.lifter)
        self.assertIn("_i+={esz}u", self.lifter)
        self.assertIn("recomp_begin_memory_access_ex(RECOMP_SEG_{src_segment}", self.lifter)
        self.assertIn("RECOMP_MEM_ACCESS_READ", self.lifter)
        self.assertIn("RECOMP_MEM_ACCESS_WRITE", self.lifter)

    def test_segment_checks_and_context_resolve_into_guest_backing(self):
        helper = self.segments.split("uintptr_t recomp_checked_segment_addr", 1)[1]
        helper = helper.split("void recomp_set_segment_resolver", 1)[0]
        checked = self.segments.split("uintptr_t recomp_checked_mem_addr", 1)[1]
        checked = checked.split("uintptr_t recomp_checked_segment_addr", 1)[0]
        for marker in (
            "width<=UINT32_MAX",
            "memory_fault.pending",
            "recomp_checked_mem_addr",
        ):
            self.assertIn(marker, helper)
        # Null selectors are rejected only while a checked segmented access is active.
        self.assertIn("access_active && selector==0", checked)
        self.assertIn("active_range_validator", checked)
        self.assertIn("region_end", checked)
        self.assertIn("g_mem_base", checked)
        self.assertIn("g_mem_base=c->mem_base", self.context)
        self.assertIn("recomp_set_memory_bounds(c->mem_guest_base,c->mem_size)", self.context)

    def test_indexed_video_is_a_separate_host_buffer_without_guest_mapping(self):
        video_file = ROOT / "runtime/host_devices.py"
        video = self.runtime_sources[video_file]
        self.assertIn("class IndexedVideo", video)
        self.assertIn("self.pixels = bytearray(width * height)", video)
        self.assertIn("def write_pixels", video)

        references = [
            path.relative_to(ROOT).as_posix()
            for path, source in self.runtime_sources.items()
            if "IndexedVideo" in source
        ]
        self.assertEqual(references, ["runtime/host_devices.py"])
        self.assertNotIn("IndexedVideo", self.generated)


if __name__ == "__main__":
    unittest.main()
