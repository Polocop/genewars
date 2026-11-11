"""Original-byte -k replay capturing DPMI AX=0100 PSP/MCB ownership and continuation."""
import hashlib
import importlib.util
import json
import pathlib
import struct

ROOT = pathlib.Path(__file__).resolve().parents[2]
SITE = ROOT / ".venv/Lib/site-packages"
import sys
sys.path.insert(0, str(SITE))
spec = importlib.util.spec_from_file_location("probe", ROOT / "tools/probes/unicorn_int21.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
sys.path.insert(0, str(ROOT / "runtime"))
from dos_filesystem import DosFileSystem

TARGET = ROOT / "evidence/genewars-1_1.exe"
STAGE = ROOT / "build/dos_c_reference_20261006"
OVERLAY = ROOT / "build/work3_dpmi_alloc_profile"
CONFIG = OVERLAY / "GENEWARS/config.ini"
CONFIG.parent.mkdir(parents=True, exist_ok=True)
if CONFIG.exists() and CONFIG.read_bytes() != b"":
    raise RuntimeError(f"refusing to replace nonempty fixture: {CONFIG}")
CONFIG.write_bytes(b"")

class OverlayFileSystem(DosFileSystem):
    def __init__(self, root, **kwargs):
        super().__init__(root, overlay_root=OVERLAY, **kwargs)

probe.DosFileSystem = OverlayFileSystem
original_prepare = probe.prepare_guest
probe.prepare_guest = lambda image: original_prepare(image, command_tail=b"-k")
original_install = probe.install_trace_hooks
allocations = []
post_success_code = []
post_success = {"active": False}

def read_chain(host):
    mem = host.boot.memory
    start = host.dos_mcb_layout["psp_mcb_segment"]
    chain = []
    seg = start
    for _ in range(32):
        raw = mem.read(seg << 4, 16)
        tag = chr(raw[0])
        owner, paragraphs = struct.unpack_from("<HH", raw, 1)
        chain.append({"mcb_segment": seg, "tag": tag, "owner_segment": owner,
                      "paragraphs": paragraphs, "data_segment": seg + 1})
        if tag == "Z":
            break
        seg += paragraphs + 1
    return chain

def install(uc, trace, limit, host=None):
    if host is not None:
        base_dispatch = host.dispatch
        def dispatch(vector, regs, *args, **kwargs):
            if vector == 0x31 and regs.ax == 0x0100:
                pre = {
                    "registers": regs.snapshot(),
                    "es": regs.es,
                    "psp_segment": host.boot.psp_segment,
                    "psp_linear": host.boot.psp_address,
                    "psp_top_segment": host.boot.memory.read_u16(host.boot.psp_address + 2),
                    "environment_segment": host.boot.env_segment,
                    "environment_bytes": len(host.boot.environment),
                    "profile": host.dos_memory_profile,
                    "mcb_layout": dict(host.dos_mcb_layout),
                    "mcb_chain": read_chain(host),
                    "dos_free_blocks": {f"0x{k:04x}": v for k, v in sorted(host.dos_free_blocks.items())},
                    "largest_free_paragraphs": max(host.dos_free_blocks.values(), default=0),
                    "dos_allocations": {f"0x{k:04x}": list(v) for k, v in host.dos_allocations.items()},
                    "allocation_mcb_owners": {f"0x{k:04x}": v for k, v in host.dos_allocation_mcb.items()},
                }
                result = base_dispatch(vector, regs, *args, **kwargs)
                post = {
                    "service": result.service,
                    "handled": result.handled,
                    "registers": regs.snapshot(),
                    "mcb_chain": read_chain(host),
                    "dos_free_blocks": {f"0x{k:04x}": v for k, v in sorted(host.dos_free_blocks.items())},
                    "dos_allocations": {f"0x{k:04x}": list(v) for k, v in host.dos_allocations.items()},
                    "allocation_mcb_owners": {f"0x{k:04x}": v for k, v in host.dos_allocation_mcb.items()},
                    "selector_linear_bases": {f"0x{k:04x}": v for k, v in host.selectors.items() if k >= 0x20},
                    "selector_limits": {f"0x{k:04x}": v for k, v in host.selector_limits.items() if k >= 0x20},
                }
                allocations.append({"before": pre, "after": post})
                if result.handled and result.service == "dpmi31.allocate_dos_memory":
                    post_success["active"] = True
                return result
            return base_dispatch(vector, regs, *args, **kwargs)
        host.dispatch = dispatch
    count = original_install(uc, trace, limit, host)
    def after_success(uc, address, size, _):
        if post_success["active"] and len(post_success_code) < 128:
            raw = bytes(uc.mem_read(address, size))
            post_success_code.append({"eip": f"0x{address:08x}", "bytes": raw.hex(),
                "registers": {k: f"0x{v:08x}" for k, v in probe.regs_snapshot(uc).items()}})
    uc.hook_add(probe.UC_HOOK_CODE, after_success)
    return count

probe.install_trace_hooks = install
trace = probe.target_probe(200_000, True, dos_root=STAGE)
base = {"target_sha256": hashlib.sha256(TARGET.read_bytes()).hexdigest(),
        "probe_sha256": hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
        "runtime_sha256": hashlib.sha256((ROOT / "runtime/dos_services.py").read_bytes()).hexdigest(),
        "command_tail": "-k", "fixture": {"path": str(CONFIG), "size_bytes": CONFIG.stat().st_size,
        "sha256": hashlib.sha256(CONFIG.read_bytes()).hexdigest()},
        "instruction_limit": 200_000, "executed_instruction_count": trace.get("executed_instruction_count"),
        "last_guest_eip": trace.get("last_guest_eip"), "stop_reason": trace.get("stop_reason"),
        "first_unsupported": trace.get("first_unsupported"), "process_exit": trace.get("process_exit"),
        "mcb_state_after_run": trace.get("dos_memory_state"),
        "ax0100_calls": allocations, "post_first_success_original_instructions": post_success_code,
        "interrupts_after_first_success": trace.get("interrupts", []),
        "menu_claimed": False, "menu_evidence": None}
out = ROOT / "evidence/dpmi_alloc_contract_work3.json"
out.write_text(json.dumps(base, indent=2) + "\n", encoding="utf-8")
print(json.dumps({k: base[k] for k in ("target_sha256", "probe_sha256", "runtime_sha256", "fixture",
    "executed_instruction_count", "last_guest_eip", "stop_reason", "first_unsupported",
    "process_exit", "mcb_state_after_run", "ax0100_calls")}, indent=2))
