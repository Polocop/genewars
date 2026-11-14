import unittest
from pathlib import Path

from tools.w3_078_file_trace_filter import should_append_event, summarize_events


class FileTraceFilterTests(unittest.TestCase):
    def test_disabled_filter_skips_only_exact_high_volume_file_events(self):
        names = {
            "dos_file_read", "dos_file_seek", "dos_file_read_batch",
            "original_int21_ah43", "original_int21_ah44",
            "target_runtime_checkpoint", "setup_dos_api", "dos_execute",
        }
        kept = {name for name in names if should_append_event(name, False)}
        self.assertEqual(kept, {
            "original_int21_ah43", "original_int21_ah44",
            "target_runtime_checkpoint", "setup_dos_api", "dos_execute",
        })

    def test_default_enabled_preserves_all_prior_event_classes(self):
        for name in ("dos_file_read", "dos_file_seek", "dos_file_read_batch",
                     "original_int21_ah43", "target_runtime_checkpoint"):
            self.assertTrue(should_append_event(name, True))

    def test_checkpoint_summary_keeps_order_and_last_natural_frontier(self):
        events = [
            {"sequence": 1, "event": "target_runtime_checkpoint", "checkpoint": "SETUP_GAME_ENTRY"},
            {"sequence": 2, "event": "dos_file_read"},
            {"sequence": 3, "event": "target_runtime_checkpoint", "checkpoint": "VIDEO_FRAMEBUFFER_ASSIGN_AFTER"},
            {"sequence": 4, "event": "target_runtime_checkpoint", "checkpoint": "UNRELATED"},
        ]
        summary = summarize_events(events)
        self.assertEqual([e["sequence"] for e in summary["target_checkpoints"]], [1, 3])
        self.assertEqual(summary["last_target_checkpoint"]["sequence"], 3)
        self.assertEqual(summary["dos_file_io_events"], 1)

    def test_cxx_filter_is_opt_in_and_wired_before_jsonl_write(self):
        header = (Path("third_party/dosbox-staging-w3-059-instrumented/src/dos/exec_trace.h")
                  .read_text(encoding="utf-8"))
        self.assertIn('std::getenv("GWRECOMP_EXEC_TRACE_FILE_IO")', header)
        self.assertIn("filter[0] != '0'", header)
        for event in ("dos_file_read", "dos_file_seek", "dos_file_read_batch"):
            self.assertIn(f'\"event\\\":\\\"{event}\\\",', header)
        append_start = header.index("inline bool append_event(const std::string& json)\n{")
        self.assertLess(header.index("suppress_high_volume_file_io_event(json)", append_start),
                        header.index("trace_path_from_env()", append_start))


if __name__ == "__main__":
    unittest.main()
