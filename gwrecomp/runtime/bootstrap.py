"""Prepare a guest CPU bootstrap state for the GeneWars 1.1 LE image.

This is deliberately a preflight shim, not an x86 executor: the target entry
runs DOS4GW startup and reaches DOS/DPMI interrupts before the C runtime.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from le_loader import FLAT_CODE_SEL, FLAT_DATA_SEL, load_le  # noqa: E402

DEFAULT_IMAGE = ROOT / "evidence" / "genewars-1_1.exe"


def prepare(image_path: pathlib.Path) -> dict:
    raw = image_path.read_bytes()
    image = load_le(image_path)
    entry_obj = image.objects[image.entry_object - 1]
    stack_obj = image.objects[image.stack_object - 1]
    if not entry_obj.executable:
        raise ValueError(f"entry object {entry_obj.index} is not executable")
    if not (stack_obj.linear_base <= image.stack_linear <= stack_obj.linear_end):
        raise ValueError("LE stack pointer is outside the declared stack object")
    entry_index = image.entry_linear - image.mem_base
    entry_bytes = image.mem[entry_index:entry_index + 16].hex()
    if len(entry_bytes) < 2:
        raise ValueError("entry point is not backed by loaded image bytes")
    return {
        "image": str(image_path),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "prepared": True,
        "executed": False,
        "entry": {
            "object": image.entry_object,
            "offset": f"0x{image.entry_offset:x}",
            "linear": f"0x{image.entry_linear:x}",
            "object_executable": entry_obj.executable,
            "bytes": entry_bytes,
        },
        "stack": {
            "object": image.stack_object,
            "offset": f"0x{image.stack_offset:x}",
            "linear": f"0x{image.stack_linear:x}",
            "object_writable": stack_obj.writable,
        },
        "memory": {
            "base": f"0x{image.mem_base:x}",
            "size": len(image.mem),
            "page_size": image.page_size,
            "object_count": len(image.objects),
            "fixup_count": image.fixup_count,
            "fixup_census": {f"0x{k:x}": v for k, v in image.fixup_census.items()},
        },
        "selectors": {"code": f"0x{FLAT_CODE_SEL:x}", "data_stack": f"0x{FLAT_DATA_SEL:x}"},
        "le_import_modules": 0,
        "runtime_status": "BLOCKED_BEFORE_EXECUTION",
        "blocker": {
            "kind": "missing_x86_32_instruction_executor_and_DOS4GW_DPMI_host",
            "evidence": "The target start path at 0xaf96c enters extender startup and uses INT 0x21 before CRT main_. The current project has an LE mapper and lift runtimes, but no instruction dispatcher for original x86 bytes or DOS/DPMI interrupt host.",
            "first_required_service": "DOS INT 0x21",
        },
        "register_state": "not initialized; DOS4GW startup input/register contract remains to be captured",
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("image", nargs="?", type=pathlib.Path, default=DEFAULT_IMAGE)
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = ap.parse_args()
    result = prepare(args.image)
    print(json.dumps(result, indent=2) if args.json else (
        f"Prepared {result['image']}\n"
        f"  entry: object {result['entry']['object']} + {result['entry']['offset']} "
        f"= {result['entry']['linear']}\n"
        f"  stack: object {result['stack']['object']} + {result['stack']['offset']} "
        f"= {result['stack']['linear']}\n"
        f"  fixups: {result['memory']['fixup_count']}\n"
        f"  execution: BLOCKED ({result['blocker']['first_required_service']}; no x86-32/DOS4GW host)"
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
