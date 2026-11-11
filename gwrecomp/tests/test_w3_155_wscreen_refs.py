import unittest

from tools.w3_155_wscreen_refs import classify_reference, extract


class WScreenReferencesTests(unittest.TestCase):
    def test_direct_reads_and_writes(self):
        self.assertEqual(classify_reference("mov lbDisplay__WScreen,%eax"), "direct_read")
        self.assertEqual(classify_reference("mov %ebp,lbDisplay__WScreen"), "direct_write")

    def test_unknown_reference_is_not_promoted_to_write(self):
        self.assertEqual(classify_reference("lea lbDisplay__WScreen,%eax"),
                         "reference_unclassified")

    def test_extraction_is_stable_and_line_bound(self):
        rows = extract(["mov lbDisplay__WScreen,%eax", "mov %eax,lbDisplay__WScreen"])
        self.assertEqual([(x["line"], x["kind"]) for x in rows],
                         [(1, "direct_read"), (2, "direct_write")])

    def test_wscreen_asset_name_is_not_itself_a_runtime_writer(self):
        self.assertEqual(classify_reference("mov $aWScreen,%edx", "aWScreen"),
                         "reference_unclassified")


if __name__ == "__main__":
    unittest.main()
