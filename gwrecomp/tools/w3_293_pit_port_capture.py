"""Static feasibility check for the W3-293 PIT observer ownership boundary.

This deliberately does not instrument or execute GeneWars. It verifies which
source file contains the actual byte-I/O callbacks and whether W3-293 owns it.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "coordination/task_W3-293.json"
CORE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
DECODER = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86/decoder.h"


def inspect_scope() -> dict[str, object]:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    owned = set(manifest.get("files_owned", []))
    core = CORE.read_text(encoding="utf-8")
    decoder = DECODER.read_text(encoding="utf-8")

    checks = {
        "core_includes_decoder": '#include "core_dyn_x86/decoder.h"' in core,
        "decoder_defines_byte_write_callback": "static bool dyn_io_writeB" in decoder,
        "decoder_defines_byte_read_callback": "static bool dyn_io_readB" in decoder,
        "write_callback_calls_real_port_handler": "if (!ex) IO_WriteB(port,val);" in decoder,
        "read_callback_captures_real_port_result": "core_dyn.readdata = IO_ReadB(port);" in decoder,
        "immediate_in_decode_calls_callback": 'gen_call_function((void*)&dyn_io_readB,"%Id",decode_fetchb());' in decoder,
        "immediate_out_decode_calls_callback": 'gen_call_function((void*)&dyn_io_writeB,"%Id%Dl",decode_fetchb(),DREG(EAX));' in decoder,
    }
    if not all(checks.values()):
        raise ValueError("unexpected source/ownership layout: " + ", ".join(k for k, v in checks.items() if not v))
    decoder_owned = "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86/decoder.h" in owned
    return {
        "task": "W3-293",
        "mode": "offline static source/ownership audit; no build, DOSBox, Oracle, or guest run",
        "required_callback_source": "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86/decoder.h",
        "owned_callback_source": "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp",
        "decoder_owned_by_task": decoder_owned,
        "source_checks": checks,
        "resolution": "BLOCKED_SCOPE: byte-I/O results are produced inside dyn_io_readB/dyn_io_writeB in decoder.h, which W3-293 does not declare as an owned path. Do not modify that file until a task explicitly owns it.",
        "source_hashes": {
            "core_dyn_x86.cpp": __import__("hashlib").sha256(CORE.read_bytes()).hexdigest(),
            "decoder.h": __import__("hashlib").sha256(DECODER.read_bytes()).hexdigest(),
        },
    }


if __name__ == "__main__":
    print(json.dumps(inspect_scope(), indent=2, ensure_ascii=False))
