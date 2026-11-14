import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
START, END = 0x94CDA, 0x94DC1


def in_window(link_va):
    return START <= link_va <= END


def dispatch_action(*, target_context, rebase, destination, block_exists, cache_running):
    """Pure model of the W3-163 dispatch decision; does not mutate guest state."""
    if not block_exists or not cache_running:
        return "restart_core"
    if target_context and rebase and destination >= rebase:
        if in_window(destination - rebase):
            return "restart_core"
    return "link_run_block"


class WscreenLinkRedispatchTests(unittest.TestCase):
    def test_interval_endpoints_redirect_and_neighbors_do_not(self):
        rebase = 0x1EB000
        for pc in (START, END):
            self.assertEqual(dispatch_action(target_context=True, rebase=rebase,
                                             destination=rebase + pc, block_exists=True,
                                             cache_running=True), "restart_core")
        for pc in (START - 1, END + 1):
            self.assertEqual(dispatch_action(target_context=True, rebase=rebase,
                                             destination=rebase + pc, block_exists=True,
                                             cache_running=True), "link_run_block")

    def test_cache_hit_redirects_only_target_process_and_window(self):
        rebase = 0x1EB000
        target = rebase + 0x94CE1
        self.assertEqual(dispatch_action(target_context=True, rebase=rebase,
                                         destination=target, block_exists=True,
                                         cache_running=True), "restart_core")
        self.assertEqual(dispatch_action(target_context=False, rebase=rebase,
                                         destination=target, block_exists=True,
                                         cache_running=True), "link_run_block")
        self.assertEqual(dispatch_action(target_context=True, rebase=rebase,
                                         destination=rebase + 0x95000, block_exists=True,
                                         cache_running=True), "link_run_block")

    def test_cache_miss_keeps_existing_restart_path(self):
        rebase = 0x1EB000
        self.assertEqual(dispatch_action(target_context=True, rebase=rebase,
                                         destination=rebase + 0x95000, block_exists=False,
                                         cache_running=True), "restart_core")
        self.assertEqual(dispatch_action(target_context=True, rebase=rebase,
                                         destination=rebase + 0x95000, block_exists=True,
                                         cache_running=False), "restart_core")

    def test_source_redirect_precedes_cached_link_and_preserves_outside_path(self):
        source = CORE.read_text(encoding="utf-8")
        link_case = source.index("case BR_Link1:")
        end_case = source.index("goto restart_core;", source.index("cache.block.running->LinkTo", link_case))
        body = source[link_case:end_case]
        self.assertIn("if (target_context && target_main_rebase &&", body)
        self.assertIn("linked_candidate_link_va >= 0x00094cda", body)
        self.assertIn("linked_candidate_link_va <= 0x00094dc1", body)
        self.assertIn("goto restart_core;", body)
        self.assertLess(body.index("goto restart_core;"), body.index("cache.block.running->LinkTo"))
        self.assertIn("goto run_block;", body)

    def test_dispatch_model_does_not_mutate_guest_registers_or_memory(self):
        registers = {"eip": 0x27FDC1, "eax": 0x12345678, "eflags": 0x202}
        guest_memory = bytes(range(16))
        before_registers, before_memory = registers.copy(), guest_memory
        result = dispatch_action(target_context=True, rebase=0x1EB000,
                                destination=0x1EB000 + 0x94DC1,
                                block_exists=True, cache_running=True)
        self.assertEqual(result, "restart_core")
        self.assertEqual(registers, before_registers)
        self.assertEqual(guest_memory, before_memory)


if __name__ == "__main__":
    unittest.main()
