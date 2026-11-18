import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
source_path = ROOT / "evidence/startup_runtime_current_work2.json"
projection_path = ROOT / "evidence/startup_ah48_current_work3.json"
source_bytes = source_path.read_bytes()
source = json.loads(source_bytes)
projection = json.loads(projection_path.read_text(encoding="utf-8"))
assert projection["source_capture"] == "evidence/startup_runtime_current_work2.json"
assert projection["source_capture_sha256"] == hashlib.sha256(source_bytes).hexdigest()
assert projection["target_sha256"] == source["target_sha256"]
assert projection["target_sha256"] == "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
assert projection["command_tail"] == "-k"
assert projection["fixture"]["sha256"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
assert projection["stop_reason"] == "process_terminated"
assert projection["executed_instruction_count"] == 7_975_503
assert projection["process_exit"]["code"] == 0
assert projection["process_exit"]["eip"] == "0x001afc33"
assert projection["last_guest_eip"] == "0x001afc33"
assert projection["menu_reached"] is False and projection["menu_claimed"] is False
assert projection["int2f_services"] == [{"eip":"0x001d23a7","ax":"0x00001500","service":"int2f.mscdex_install_check","handled":True}]
for item in projection["runtime_files"]:
    assert hashlib.sha256((ROOT / item["path"]).read_bytes()).hexdigest() == item["sha256"], item["path"]
combined = hashlib.sha256("".join(x["path"] + ":" + x["sha256"] + "\n" for x in projection["runtime_files"]).encode()).hexdigest()
assert combined == projection["runtime_sha256"]
state = (ROOT / "PROJECT_STATE.md").read_text(encoding="utf-8")
assert "'valid': True" in state and "complete runtime fingerprint" in state
assert "terminated via DOS AH=4Ch with code 0 at 0x001afc33" in state
assert "MENU not reached" in state
