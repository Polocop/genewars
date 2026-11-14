#!/usr/bin/env python3
"""Validate the bounded W1-055 sample embedded in a fresh native replay."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL_PATH = ROOT / "evidence" / "w3_093_ds_edx_sample.json"
W2_RUNTIME_PATH = ROOT / "evidence" / "native_dos_ah43_sound_ini_work2.json"


def validate(data: dict, original: dict, w2_runtime: dict | None = None) -> list[str]:
    errors: list[str] = []
    continuation = data.get("sound_ini_continuation", {})
    ax4400 = continuation.get("ax4400_origin", {})
    native_event = next((event for event in ax4400.get("requests_bx1", [])
                         if event.get("sample_valid") == "1"), None)
    original_event = original.get("capture", {}).get("target_sample_event", {})

    if data.get("schema") != "gwrecomp.native-setup-replay/v1":
        errors.append("unexpected native replay evidence schema")
    if data.get("native_returncode") != 0 or not data.get("capture_id") or not data.get("captured_at"):
        errors.append("evidence is not a completed fresh native replay")
    if native_event is None:
        errors.append("fresh replay has no bounded BX=1 memory sample")
        return errors

    if native_event.get("eip", "").lower() != "000c8973":
        errors.append("sample was not captured at link VA 0xC8973")
    if int(native_event.get("eax", "0"), 16) & 0xFFFF != 0x4400:
        errors.append("native request AX is not 0x4400")
    if int(native_event.get("ebx", "-1"), 16) != 1:
        errors.append("native request BX is not 1")
    if native_event.get("ds_base", "").lower() != "00000000":
        errors.append("unexpected native DS base")
    if native_event.get("edx") != native_event.get("sample_address", native_event.get("edx")):
        errors.append("sample address differs from effective request EDX")
    if native_event.get("sample_length") != "32" or native_event.get("sample_valid") != "1":
        errors.append("native sample is not one valid 32-byte window")
    try:
        native_bytes = bytes.fromhex(native_event.get("sample_hex", ""))
    except ValueError:
        native_bytes = b""
    try:
        original_bytes = bytes.fromhex(original_event.get("sample_bytes_hex", ""))
    except ValueError:
        original_bytes = b""
    if len(native_bytes) != 32:
        errors.append("native sample does not contain exactly 32 bytes")
    if len(original_bytes) != 32 or original_event.get("sample_status") != "sampled":
        errors.append("hash-bound W3-093 original sample is unavailable")

    original_capture = original.get("capture", {})
    if original_capture.get("classification") != "ORIGINAL_DS_EDX_SAMPLE_CORRELATED":
        errors.append("original window lacks W3-093 correlation")
    if original_event.get("value_at_plus_0x10") != 1:
        errors.append("W3-093 [EDX+0x10] measurement changed")
    if continuation.get("dynamic_invocation_equivalence") is not False or continuation.get("original_equivalence_claimed") is not False:
        errors.append("evidence must preserve the unproven invocation-alignment boundary")
    if continuation.get("same_dynamic_invocation_claimed") is True:
        errors.append("evidence must not claim native/original invocation equivalence")
    if not continuation.get("setup_game_entered") or not continuation.get("callee_14bf0_entered"):
        errors.append("fresh replay did not preserve the setup/callee path")
    if continuation.get("crt_callbacks") != 19 or str(continuation.get("argc")) != "3" or continuation.get("gate") != "1/1":
        errors.append("fresh replay lost the established CRT/argv/game gate")
    if data.get("frontier", {}).get("guest_eip", "").lower() != "0x000c8973":
        errors.append("fresh replay frontier is not the actual 0xC8973 request")

    if w2_runtime is None:
        w2_runtime = json.loads(W2_RUNTIME_PATH.read_text(encoding="utf-8"))
    expected_runtime = w2_runtime["implementation"]["c"]["sha256"].lower()
    runtime_capture = continuation.get("runtime_fingerprint", {})
    if runtime_capture.get("gw_dos_services_c_sha256", "").lower() != expected_runtime or runtime_capture.get("matches_w2_107") is not True:
        errors.append("fresh replay does not use the W2-107 Runtime fingerprint")

    return errors


def comparison(data: dict, original: dict) -> dict:
    continuation = data["sound_ini_continuation"]["ax4400_origin"]
    native = next(event for event in continuation["requests_bx1"] if event.get("sample_valid") == "1")
    original_event = original["capture"]["target_sample_event"]
    a = bytes.fromhex(native["sample_hex"])
    b = bytes.fromhex(original_event["sample_bytes_hex"])
    return {
        "native_sample_hex": a.hex(),
        "original_sample_hex": b.hex(),
        "equal_offsets": [i for i, (x, y) in enumerate(zip(a, b)) if x == y],
        "different_offsets": [i for i, (x, y) in enumerate(zip(a, b)) if x != y],
        "common_byte_count": sum(x == y for x, y in zip(a, b)),
        "different_byte_count": sum(x != y for x, y in zip(a, b)),
        "same_dynamic_invocation_claimed": False,
        "causal_divergence_claimed": False,
    }


def main(argv: list[str]) -> int:
    path = Path(argv[1]) if len(argv) > 1 else ROOT / "evidence" / "native_stream_object_sample_work1.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    original = json.loads(ORIGINAL_PATH.read_text(encoding="utf-8"))
    errors = validate(data, original)
    if errors:
        print("FAIL: " + "; ".join(errors))
        return 1
    print("PASS: fresh replay contains a bounded native sample paired with hash-bound W3-093 bytes")
    print(json.dumps(comparison(data, original), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
