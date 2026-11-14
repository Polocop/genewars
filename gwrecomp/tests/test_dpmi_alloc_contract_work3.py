"""Validate original-byte AX=0100 inputs, MCB ownership and immediate continuation."""
import hashlib
import importlib.util
import json
from pathlib import Path

taskq_spec = importlib.util.spec_from_file_location("taskq", Path("coordination/taskq.py"))
taskq = importlib.util.module_from_spec(taskq_spec)
taskq_spec.loader.exec_module(taskq)
e = json.loads(Path("evidence/dpmi_alloc_contract_work3.json").read_text(encoding="utf-8"))
expected_target = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
assert e["target_sha256"] == expected_target
assert e["fixture"]["size_bytes"] == 0
assert e["fixture"]["sha256"] == hashlib.sha256(b"").hexdigest()
assert e["command_tail"] == "-k"
assert len(e["probe_sha256"]) == 64 and len(e["runtime_sha256"]) == 64

calls = e["ax0100_calls"]
assert calls, "no original-byte AX=0100 call captured"
first = calls[0]["before"]
regs = first["registers"]
assert (regs["eax"] & 0xffff) == 0x0100 and regs["ebx"] > 0
assert first["profile"] == "post_dos4gw_le_entry"
psp = first["psp_segment"]
layout = first["mcb_layout"]
assert first["es"] == regs["es"]
assert first["psp_top_segment"] == psp + layout["psp_paragraphs"]
assert layout["psp_mcb_segment"] == psp - 1
assert layout["environment_mcb_segment"] == layout["psp_end_segment"]
assert layout["environment_segment"] == layout["environment_mcb_segment"] + 1
assert layout["environment_paragraphs"] * 16 >= first["environment_bytes"]
assert layout["free_mcb_segment"] == layout["environment_segment"] + layout["environment_paragraphs"]

def check_chain(chain):
    assert chain and chain[-1]["tag"] == "Z", chain
    for current, nxt in zip(chain, chain[1:]):
        assert current["tag"] == "M"
        assert nxt["mcb_segment"] == current["mcb_segment"] + current["paragraphs"] + 1

chain = first["mcb_chain"]
check_chain(chain)
assert chain[0]["mcb_segment"] == layout["psp_mcb_segment"]
assert chain[0]["owner_segment"] == psp
assert chain[0]["paragraphs"] == layout["psp_paragraphs"]
assert chain[1]["mcb_segment"] == layout["environment_mcb_segment"]
assert chain[1]["owner_segment"] == psp
free = [x for x in chain if x["owner_segment"] == 0]
assert free == [chain[-1]]
assert free[0]["mcb_segment"] == layout["free_mcb_segment"]
free_map = {int(k, 16): v for k, v in first["dos_free_blocks"].items()}
assert free_map == {free[0]["mcb_segment"]: free[0]["paragraphs"]}
assert first["largest_free_paragraphs"] == max(free_map.values())

for call in calls:
    before, after = call["before"], call["after"]
    r0, r1 = before["registers"], after["registers"]
    requested = r0["ebx"]
    assert (r0["eax"] & 0xffff) == 0x0100 and requested > 0
    assert r0["es"] == before["es"] == first["es"]
    assert after["handled"] and after["service"] == "dpmi31.allocate_dos_memory"
    assert not (r1["eflags"] & 1), "successful allocation must return CF clear"
    segment, selector = r1["eax"] & 0xffff, r1["edx"] & 0xffff
    assert segment > 0 and selector >= 0x20
    assert after["dos_allocations"][f"0x{selector:04x}"] == [segment, requested]
    mcb_segment = after["allocation_mcb_owners"][f"0x{selector:04x}"]
    chain_after = after["mcb_chain"]
    check_chain(chain_after)
    allocated = next(x for x in chain_after if x["mcb_segment"] == mcb_segment)
    assert allocated["tag"] == "M" and allocated["owner_segment"] == psp
    assert allocated["paragraphs"] == requested and allocated["data_segment"] == segment
    assert after["selector_linear_bases"][f"0x{selector:04x}"] == segment << 4
    assert after["selector_limits"][f"0x{selector:04x}"] == requested * 16 - 1
    free_blocks = {int(k, 16): v for k, v in after["dos_free_blocks"].items()}
    if free_blocks:
        free_after = [x for x in chain_after if x["owner_segment"] == 0]
        assert len(free_after) == len(free_blocks)
        assert {x["mcb_segment"]: x["paragraphs"] for x in free_after} == free_blocks

post = e["interrupts_after_first_success"]
calls_after = [i for i in post if i.get("service") == "dpmi31.allocate_dos_memory"]
assert [int(i["registers"]["ebx"], 16) for i in calls_after] == [c["before"]["registers"]["ebx"] for c in calls]
first_alloc_index = next(n for n, i in enumerate(post)
    if i.get("service") == "dpmi31.allocate_dos_memory"
    and i["registers"]["eax"] == "0x00000100"
    and i["registers"]["ebx"] == f"0x{calls[0]['before']['registers']['ebx']:08x}")
next_int = next(i for i in post[first_alloc_index + 1:]
    if i.get("service") == "dpmi31.simulate_real_mode_interrupt"
    and i.get("real_mode_interrupt", {}).get("vector") == 0x2f)
rm = next_int["real_mode_interrupt"]
assert rm["bh"] == 0 and rm["stack_words"] == 0
assert next_int["registers"]["eax"] == "0x00000300"
assert next_int["handled"] is False
stop = e["first_unsupported"]
assert stop["vector"] == 0x31 and stop["function"] == 0x0300
assert stop["eip"] == "0x001d23a7" and e["process_exit"] is None
assert e["menu_claimed"] is False and e["menu_evidence"] is None
metric = taskq.dpmi_alloc_contract_metrics(e, expected_target)
assert metric["valid"], metric
assert metric["returned_real_segment"] == f"0x{calls[0]['after']['registers']['eax'] & 0xffff:04x}"
assert metric["returned_selector"] == f"0x{calls[0]['after']['registers']['edx'] & 0xffff:04x}"
assert metric["next_service"] == "DPMI AX=0300 -> real-mode INT 2F AX=1500"
assert not taskq.dpmi_alloc_contract_metrics(e, "stale-target")["valid"]
print("PASS: AX=0100 request/return and PSP-MCB ownership reconcile; original continues to real-mode INT 2F bridge")
