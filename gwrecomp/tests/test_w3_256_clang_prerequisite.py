from __future__ import annotations

import json
import unittest
from pathlib import Path

from tools.w3_256_clang_prerequisite import (
    OUT,
    PINNED_REVISION,
    classify_toolchain,
    parse_cache,
)


class ClangPrerequisiteTests(unittest.TestCase):
    def test_parse_cache_extracts_toolset_and_generator(self) -> None:
        cache = parse_cache(
            "# comment\nCMAKE_GENERATOR:INTERNAL=Visual Studio 17 2022\n"
            "CMAKE_GENERATOR_TOOLSET:UNINITIALIZED=ClangCL\n"
        )
        self.assertEqual(cache["CMAKE_GENERATOR"], "Visual Studio 17 2022")
        self.assertEqual(cache["CMAKE_GENERATOR_TOOLSET"], "ClangCL")

    def test_classification_does_not_claim_build_when_clang_missing(self) -> None:
        self.assertEqual(
            classify_toolchain(
                clang_exists=False,
                configured_toolset="ClangCL",
                compiler_path_seen=True,
                binary_exists=True,
                configured_source_matches=False,
            ),
            "CLANG_CL_MISSING",
        )

    def test_classification_does_not_misattribute_other_source_binary(self) -> None:
        self.assertEqual(
            classify_toolchain(
                clang_exists=True,
                configured_toolset="ClangCL",
                compiler_path_seen=True,
                binary_exists=True,
                configured_source_matches=False,
            ),
            "CLANGCL_READY_CACHE_POINTS_TO_DIFFERENT_SOURCE",
        )

    def test_current_source_binary_still_requires_freshness_proof(self) -> None:
        self.assertEqual(
            classify_toolchain(
                clang_exists=True,
                configured_toolset="ClangCL",
                compiler_path_seen=True,
                binary_exists=True,
                configured_source_matches=True,
            ),
            "CLANGCL_CONFIGURED_CURRENT_SOURCE_BINARY_PRESENT_FRESHNESS_UNPROVEN",
        )

    def test_written_evidence_is_pinned_and_hash_bound(self) -> None:
        self.assertTrue(OUT.is_file(), "run tools.w3_256_clang_prerequisite before this test")
        data = json.loads(OUT.read_text(encoding="utf-8"))
        self.assertEqual(data["pinned_revision"], PINNED_REVISION)
        self.assertEqual(data["schema"], "gwrecomp.w3-256-clang-prerequisite/v1")
        self.assertEqual(data["source_checkout"]["head"], PINNED_REVISION)
        self.assertTrue(data["cmake_configuration"]["cache_sha256"])
        self.assertFalse(data["cmake_configuration"]["source_matches_instrumented_checkout"])
        self.assertTrue(data["existing_binary"]["sha256"])
        self.assertIn("UNPROVEN", data["existing_binary"]["freshness_vs_modified_sources"])


if __name__ == "__main__":
    unittest.main()
