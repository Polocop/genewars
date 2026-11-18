"""Audit caller visibility in the existing bounded AH=43 trace."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def audit_ah43_trace(path: Path) -> dict:
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        if event.get("event") == "original_int21_ah43":
            events.append(event)
    sound = [event for event in events
             if event.get("requested_path", "").casefold() == r"c:\genewars\sound.ini"]
    return {
        "schema": "w3-076-ah43-caller-audit/v1",
        "trace": str(path),
        "trace_bytes": path.stat().st_size,
        "trace_sha256": sha256(path),
        "ah43_count": len(events),
        "sound_ini_count": len(sound),
        "sound_ini_events": [{
            "sequence": event.get("sequence"),
            "ordinal": event.get("ordinal"),
            "process_psp": event.get("process_psp"),
            "in_ax": event.get("in_ax"),
            "in_ds": event.get("in_ds"),
            "in_dx": event.get("in_dx"),
            "requested_path": event.get("requested_path"),
            "out_ax": event.get("out_ax"),
            "out_cx": event.get("out_cx"),
            "cf": event.get("cf"),
            "callback_cs": event.get("callback_cs"),
            "callback_eip": event.get("callback_eip"),
            "caller_link_va": event.get("caller_link_va"),
            "caller_context": event.get("caller_context"),
        } for event in sound],
        "caller_recovered": bool(sound) and all(
            event.get("caller_link_va") is not None for event in sound),
        "static_inspection": {
            "dos_handler": "src/dos/dos.cpp:1252-1280 records callback CS:EIP and explicitly sets caller_link_va null",
            "callback_stub": "src/cpu/callback.cpp:471 emits native callback dispatch followed by IRET; this is DOSBox's callback path, not the guest caller address",
            "candidate_next_hook": "src/cpu/cpu.cpp:874 CPU_Interrupt receives interrupt number and oldeip before vector dispatch; a follow-up must verify that the original INT 21h crosses this function in the actual protected-mode path",
            "conclusion": "The saved caller cannot be reconstructed from the existing AH=43 trace. The three sound.ini callbacks contain no saved frame, original CS:EIP, or direct callsite.",
        },
    }


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("trace", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.write_text(json.dumps(audit_ah43_trace(args.trace), indent=2) + "\n",
                           encoding="utf-8")
