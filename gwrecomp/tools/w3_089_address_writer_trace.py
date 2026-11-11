"""Parser for the capped W3-089 original ADDRESS.TXT writer trace."""
from __future__ import annotations

import json

MAX_TRACE_BYTES = 1_048_576
MAX_EVENTS = 512
MAX_WRITE_SAMPLE_BYTES = 64
MAIN_WRITER_CALLSITE = 0x93F4C
MAIN_AFTER_WRITER = {0x93F56, 0x93F5A}


class TraceLimitError(ValueError):
    pass


def _address_path(value: object) -> bool:
    if not isinstance(value, str):
        return False
    return value.replace("/", "\\").rsplit("\\", 1)[-1].upper() == "ADDRESS.TXT"


def parse_trace_bytes(raw: bytes) -> list[dict]:
    if len(raw) > MAX_TRACE_BYTES:
        raise TraceLimitError("trace exceeds 1 MiB")
    events: list[dict] = []
    seen: set[tuple[object, ...]] = set()
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        kind = event.get("event")
        if kind == "target_runtime_checkpoint":
            if event.get("checkpoint") not in {
                "MAIN_ENTRY_CHECKPOINT",
                "MAIN_LOCAL_WRITER_CHECKPOINT",
                "MAIN_GATE_CHECKPOINT",
                "ADDRESS_WRITER_ENTRY",
            }:
                continue
        elif kind in {"dos_handle_open", "dos_handle_create", "dos_handle_close"}:
            if not _address_path(event.get("requested_path", event.get("path"))):
                continue
        elif kind == "dos_address_txt_write":
            if not _address_path(event.get("path")):
                continue
            sample = event.get("sample_hex", "")
            if not isinstance(sample, str) or len(sample) > MAX_WRITE_SAMPLE_BYTES * 2:
                raise TraceLimitError("ADDRESS.TXT write sample exceeds 64 bytes")
        else:
            continue
        key = (event.get("sequence"), kind)
        if key in seen:
            continue
        seen.add(key)
        events.append(event)
        if len(events) > MAX_EVENTS:
            raise TraceLimitError("filtered event count exceeds 512")
    return events


def summarize(events: list[dict]) -> dict:
    ordered = sorted(events, key=lambda event: event.get("sequence", -1))
    checkpoints = [e for e in ordered if e.get("event") == "target_runtime_checkpoint"]
    main_entry = next((e for e in checkpoints if e.get("link_va") == 0x93F30), None)
    callsite = next((e for e in checkpoints if e.get("link_va") == MAIN_WRITER_CALLSITE), None)
    writer_entry = next((e for e in checkpoints if e.get("checkpoint") == "ADDRESS_WRITER_ENTRY"), None)
    main_return = next((e for e in checkpoints if e.get("link_va") in MAIN_AFTER_WRITER), None)
    address_files = [e for e in ordered if e.get("event") in {
        "dos_handle_open", "dos_handle_create", "dos_address_txt_write", "dos_handle_close"
    }]
    opened = next((e for e in address_files if e.get("event") in {"dos_handle_open", "dos_handle_create"}), None)
    writes = [e for e in address_files if e.get("event") == "dos_address_txt_write"]
    close = next((e for e in address_files if e.get("event") == "dos_handle_close"), None)
    main_gate = next((e for e in checkpoints if e.get("checkpoint") == "MAIN_GATE_CHECKPOINT"), None)
    output = next((e for e in writes if e.get("written", 0) > 0), None)
    output_bytes = bytes.fromhex(output.get("sample_hex", "")) if output else b""
    output_signature = output_bytes.startswith(b"offsetFunction ") and output_bytes.endswith(b".\r\n")

    dynamic_function = bool(writer_entry and main_entry and main_entry.get("sequence", 0) < writer_entry.get("sequence", 0))
    function_return = bool(writer_entry and main_return and writer_entry.get("sequence", 0) < main_return.get("sequence", 0))
    returned_to_main_later = bool(close and main_gate and close.get("sequence", 0) < main_gate.get("sequence", 0))
    path_opened = bool(opened and writer_entry and main_entry and
                       main_entry.get("sequence", 0) < opened.get("sequence", 0) < writer_entry.get("sequence", 0) + 20)
    chain = bool(main_entry and callsite and writer_entry and main_return and opened and writes and close and
                 main_entry.get("sequence", 0) < callsite.get("sequence", 0) < writer_entry.get("sequence", 0) <
                 opened.get("sequence", 0) <= writes[0].get("sequence", 0) <= close.get("sequence", 0) <
                 main_return.get("sequence", 0))
    effect_chain = bool(main_entry and opened and output and close and main_gate and output_signature and
                        main_entry.get("sequence", 0) < opened.get("sequence", 0) <= output.get("sequence", 0) <
                        close.get("sequence", 0) < main_gate.get("sequence", 0))

    return {
        "classification": ("ORIGINAL_WRITER_CHAIN_OBSERVED" if chain else
                           "ORIGINAL_WRITER_EFFECT_AND_MAIN_CONTINUATION_OBSERVED" if effect_chain else
                           "INCONCLUSIVE"),
        "main_entry": main_entry,
        "main_writer_callsite": callsite,
        "writer_function_entry": writer_entry,
        "address_open": opened,
        "address_writes": writes,
        "address_close": close,
        "main_after_writer": main_return,
        "main_gate_continuation": main_gate,
        "unique_output_signature_observed": output_signature,
        "dynamic_function_entry_observed": dynamic_function,
        "function_return_to_main_observed": function_return,
        "main_continuation_after_close_observed": returned_to_main_later,
        "address_path_opened_near_writer": path_opened,
        "ordered_full_writer_chain_observed": chain,
        "direct_entry_pc_missing": not dynamic_function,
        "limitations": [] if chain else ["The ADDRESS_WRITER_ENTRY checkpoint did not fire, so direct EIP at func_27D70 is absent; the unique formatted write and later main gate provide effect/continuation evidence, not an entry-PC sample."],
    }
