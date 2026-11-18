"""Synthetic validator for the bounded W3-221 AX=4400 capture format."""
from __future__ import annotations

import json
from pathlib import Path
import unittest

MAX_TRACE_BYTES = 1_048_576
MAX_EVENTS = 128
TARGET_LINK = 0xC8973
CPU_EVENT = "original_cpu_int21_ah44_bx1_entry"


class TraceLimitError(ValueError):
    pass


def _number(value):
    if isinstance(value, str):
        return int(value, 0)
    return value


def parse_trace(raw: bytes) -> dict:
    if len(raw) > MAX_TRACE_BYTES:
        raise TraceLimitError("trace exceeds 1 MiB")
    selected = []
    seen = set()
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        event = row.get("event")
        is_ah44 = (event == "original_int21_ah44" and
                   _number(row.get("in_ax", 0)) == 0x4400)
        is_setup_ah44 = (event == "setup_dos_api" and
                         row.get("operation") == "INT21_AH44" and
                         _number(row.get("in_ax", 0)) == 0x4400)
        is_target_checkpoint = (event == "target_runtime_checkpoint" and
                                (_number(row.get("link_va", -1)) == TARGET_LINK or
                                 str(row.get("checkpoint", "")).startswith("AH44_")))
        keep = (is_ah44 or is_setup_ah44 or event == CPU_EVENT or
                event == "dos_execute" or event == "dos_handle_table_snapshot" or
                event in {"target_code_anchor", "target_gw_file_complete",
                          "target_protected_mode_transition"} or is_target_checkpoint)
        if not keep:
            continue
        key = (row.get("sequence"), event)
        if key in seen:
            continue
        seen.add(key)
        selected.append(row)
        if len(selected) > MAX_EVENTS:
            raise TraceLimitError("filtered event count exceeds 128")

    ordered = sorted(selected, key=lambda row: _number(row.get("sequence", -1)))
    cpu = [row for row in ordered if row.get("event") == CPU_EVENT]
    cpu = [row for row in cpu if row.get("mapping_valid") is True and
           row.get("int21_bytes_verified") is True and
           _number(row.get("int_instruction_link_va", -1)) == TARGET_LINK]
    dos_callbacks = [row for row in ordered if row.get("event") == "original_int21_ah44"]
    setup_callbacks = [row for row in ordered if row.get("event") == "setup_dos_api" and
                       row.get("operation") == "INT21_AH44"]
    pairs = []
    for entry in cpu:
        setup_ordinal = entry.get("setup_dos_api_callback_ordinal")
        ah44_ordinal = entry.get("ah44_callback_ordinal_if_available")
        callback = next((row for row in setup_callbacks
                         if row.get("ordinal") == setup_ordinal), None)
        if callback is None:
            callback = next((row for row in dos_callbacks
                             if row.get("ordinal") == ah44_ordinal), None)
        pairs.append({"cpu_entry": entry, "callback": callback,
                      "matched_setup_ordinal": callback is not None and
                      callback.get("ordinal") == setup_ordinal})
    launch = [row for row in ordered if row.get("event") == "dos_execute"]
    tail_observed = any(row.get("executable", "").upper().endswith("GW.EXE") and
                        "-k 38928" in row.get("command_tail", "") for row in launch)
    return {
        "selected_events": ordered,
        "ax4400_callbacks": dos_callbacks,
        "setup_ax4400_callbacks": setup_callbacks,
        "caller_entries_at_target": cpu,
        "pairs": pairs,
        "dos_exec_chain": launch,
        "tail_minus_k_38928_observed": tail_observed,
        "classification": ("ORIGINAL_BX1_CALLER_CAPTURED" if cpu else
                           "NO_MAPPED_BX1_CALLER_IN_BOUNDED_WINDOW"),
    }


def _row(seq, event, **fields):
    return {"sequence": seq, "event": event, **fields}


class W3221ParserTests(unittest.TestCase):
    def test_correlates_mapped_bx1_caller_and_exact_launch_tail(self):
        rows = [
            _row(1, "dos_execute", executable="gw.EXE", command_tail=" -k 38928"),
            _row(2, "original_cpu_int21_ah44_bx1_entry", mapping_valid=True,
                 int21_bytes_verified=True, int_instruction_link_va=TARGET_LINK,
                 setup_dos_api_callback_ordinal=24, ah44_callback_ordinal_if_available=9,
                 eax=0x4400, ebx=1, eflags=0x246),
            _row(3, "setup_dos_api", operation="INT21_AH44", ordinal=24,
                 in_ax=0x4400, in_bx=1, out_ax=0x80D3, out_dx=0x80D3, cf=False),
            _row(4, "original_int21_ah44", ordinal=9, in_ax=0x4400, in_bx=1,
                 out_ax=0x80D3, out_dx=0x80D3, cf=False),
        ]
        result = parse_trace(b"\n".join(json.dumps(row).encode() for row in rows))
        self.assertEqual(result["classification"], "ORIGINAL_BX1_CALLER_CAPTURED")
        self.assertTrue(result["tail_minus_k_38928_observed"])
        self.assertEqual(len(result["pairs"]), 1)
        self.assertTrue(result["pairs"][0]["matched_setup_ordinal"])
        self.assertEqual(result["pairs"][0]["callback"]["out_ax"], 0x80D3)

    def test_keeps_bx2_and_bx5_distinct_and_does_not_infer_caller(self):
        rows = [_row(i, "original_int21_ah44", ordinal=i, in_ax=0x4400,
                     in_bx=bx, out_ax=2, out_dx=2, cf=False)
                for i, bx in enumerate((5, 2), 1)]
        result = parse_trace(b"\n".join(json.dumps(row).encode() for row in rows))
        self.assertEqual(result["classification"], "NO_MAPPED_BX1_CALLER_IN_BOUNDED_WINDOW")
        self.assertEqual([row["in_bx"] for row in result["ax4400_callbacks"]], [5, 2])
        self.assertEqual(result["caller_entries_at_target"], [])

    def test_deduplicates_duplicate_sequence_and_event(self):
        row = _row(7, "original_int21_ah44", ordinal=1, in_ax=0x4400, in_bx=5)
        raw = (json.dumps(row) + "\n" + json.dumps(row)).encode()
        self.assertEqual(len(parse_trace(raw)["ax4400_callbacks"]), 1)

    def test_rejects_trace_over_hard_capture_limit(self):
        with self.assertRaises(TraceLimitError):
            parse_trace(b"x" * (MAX_TRACE_BYTES + 1))

    def test_saved_original_capture_is_bounded_and_maps_bx1(self):
        root = Path(__file__).resolve().parents[1]
        path = root / "evidence/original_ax4400_bx1_alignment_w3_221.json"
        if not path.is_file():
            self.skipTest("guarded capture evidence not present yet")
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(data["task"], "W3-221")
        self.assertEqual(data["preflight"]["runtime"]["staging_revision"],
                         "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f")
        self.assertEqual(data["preflight"]["sandbox"]["label"], "GWORACLE")
        self.assertTrue(data["guard"]["sandbox_verified"])
        self.assertLessEqual(data["trace"]["bytes"], MAX_TRACE_BYTES)
        self.assertTrue(data["tail_minus_k_38928_observed"])
        self.assertEqual(data["classification"], "ORIGINAL_BX1_CALLER_CAPTURED")
        self.assertEqual(len(data["caller_entries_at_C8973"]), 1)
        caller = data["caller_entries_at_C8973"][0]
        self.assertTrue(caller["mapping_valid"])
        self.assertTrue(caller["int21_bytes_verified"])
        self.assertEqual(caller["int_instruction_link_va"], TARGET_LINK)
        self.assertEqual(caller["eax"] & 0xFFFF, 0x4400)
        self.assertEqual(caller["ebx"] & 0xFFFF, 1)
        self.assertGreaterEqual(len(data["setup_ax4400_callbacks"]), 1)
        self.assertTrue(all(_number(row.get("in_ax", 0)) == 0x4400
                            for row in data["setup_ax4400_callbacks"]))
        paired = [row for row in data["paired_events"] if row["callback"]]
        self.assertTrue(paired)
        self.assertTrue(any(row["callback"].get("in_bx") == 1 for row in paired))


if __name__ == "__main__":
    unittest.main()
