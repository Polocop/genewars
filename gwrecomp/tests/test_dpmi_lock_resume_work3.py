import json
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("taskq", Path("coordination/taskq.py"))
taskq = importlib.util.module_from_spec(spec)
spec.loader.exec_module(taskq)

evidence = json.loads(Path("evidence/dpmi_lock_resume_oracle_work3.json").read_text(encoding="utf-8"))
metric = taskq.dpmi_lock_resume_metrics(evidence, "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f")
assert metric["valid"], metric
assert metric["resume_eip"] == "0x001d23a9"
assert metric["next_blocker_service"] == "dpmi31.allocate_dos_memory.insufficient_memory"
assert metric["next_blocker_requested_paragraphs"] == "0x00001000"
assert metric["next_blocker_error_ax"] == "0x00000008" and metric["next_blocker_carry"] is True
assert not taskq.dpmi_lock_resume_metrics(evidence, "stale-target")["valid"]
print("PASS: exact AX=0600 request/resume and following DOS-memory allocation failure validated")
