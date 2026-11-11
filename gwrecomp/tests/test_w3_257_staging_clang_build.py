from __future__ import annotations
import os as _gw_os
from pathlib import Path as _GwPath
_GW_ROOT=str(_GwPath(__file__).resolve().parents[1])

import json
import unittest

from tools.w3_257_staging_clang_build import OUT, REVISION, validate


class StagingClangBuildEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not OUT.is_file():
            raise AssertionError("run tools.w3_257_staging_clang_build before this test")
        cls.data = json.loads(OUT.read_text(encoding="utf-8"))

    def test_exact_revision_build_and_test_evidence(self) -> None:
        self.assertEqual(self.data["revision"], REVISION)
        self.assertEqual(self.data["configure"]["toolset"], "ClangCL")
        self.assertEqual(self.data["build"]["clean_build_exit_code"], 0)
        self.assertEqual(self.data["native_instrumentation_test"]["run_exit_code"], 0)
        self.assertEqual(validate(self.data), [])

    def test_rejects_wrong_source_mapping(self) -> None:
        data = json.loads(json.dumps(self.data))
        data["configure"]["source_directory"] = (_GW_ROOT + '\\third_party\\dosbox-staging')
        self.assertIn("CMake cache points to wrong source directory", validate(data))

    def test_rejects_game_or_oracle_execution(self) -> None:
        data = json.loads(json.dumps(self.data))
        data["safety"]["oracle_run"] = True
        self.assertIn("unexpected game/oracle execution or overwrite", validate(data))

    def test_rejects_hash_mismatch(self) -> None:
        data = json.loads(json.dumps(self.data))
        data["source"]["source_hashes_stable_across_recorded_incremental_build"] = False
        self.assertIn("source files changed during hash confirmation", validate(data))


if __name__ == "__main__":
    unittest.main()
