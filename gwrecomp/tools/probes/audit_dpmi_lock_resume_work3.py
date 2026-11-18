"""Re-run original-byte -k startup and preserve DPMI AX=0600 resume evidence."""
import hashlib
import importlib.util
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("probe", ROOT / "tools/probes/unicorn_int21.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

fixture = ROOT / "build/work3_empty_config_fixture"
config = fixture / "GENEWARS/config.ini"
config.parent.mkdir(parents=True, exist_ok=True)
config.write_bytes(b"")
original_prepare = probe.prepare_guest
probe.prepare_guest = lambda image: original_prepare(image, command_tail=b"-k")

target = ROOT / "evidence/genewars-1_1.exe"
trace = probe.target_probe(200_000, True, dos_root=fixture)
locks = [i for i in trace.get("interrupts", [])
         if i.get("vector") == 0x31
         and int(i.get("registers", {}).get("eax", "0"), 16) & 0xffff == 0x0600]
lock = locks[0] if locks else None
later = [i for i in trace.get("interrupts", [])
         if i.get("vector") == 0x31 and i.get("eip_int_opcode_assumption") == "0x001c8cd2"]
evidence = {
    "target_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
    "command_tail": "-k",
    "fixture": {"path": str(config), "size_bytes": config.stat().st_size,
                "sha256": hashlib.sha256(config.read_bytes()).hexdigest()},
    "profile": "current deterministic DOS/4GW host profile; DPMI lock validation enabled",
    "instruction_limit": 200_000,
    "executed_instruction_count": trace.get("executed_instruction_count"),
    "stop_reason": trace.get("stop_reason"),
    "last_guest_eip": trace.get("last_guest_eip"),
    "dpmi_0600": lock,
    "post_lock_vector_query": later[0] if later else None,
    "subsequent_interrupts": trace.get("interrupts", [])[
        (trace.get("interrupts", []).index(lock) + 1 if lock else 0):],
    "process_exit": trace.get("process_exit"),
    "menu_claimed": False,
    "menu_root_evidence": None,
}
out = ROOT / "evidence/dpmi_lock_resume_oracle_work3.json"
out.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
print(json.dumps({k: v for k, v in evidence.items() if k != "subsequent_interrupts"}, indent=2))
print("subsequent interrupt count:", len(evidence["subsequent_interrupts"]))
