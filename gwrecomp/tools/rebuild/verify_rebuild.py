"""Acceptance check for tools/rebuild/rebuild.ps1: compares a rebuild with the committed expectations (expected_v07.json).
usage: python -I verify_rebuild.py <Work dir of a rebuild>      exit code 0 = every check passed, 1 = at least one failed
Reads only the rebuild's own output and expected_v07.json (no historical trees)."""
import hashlib, json, struct, sys
from pathlib import Path
w = Path(sys.argv[1]); exp = json.loads((Path(__file__).with_name("expected_v07.json")).read_text(encoding="utf-8-sig"))
m = json.loads((w / "rebuild_manifest.json").read_text(encoding="utf-8-sig")); o = m["outputs"]
def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
checks = {}
checks["all rebuild phases exit 0"] = all(p["exit"] == 0 for p in m["phases"].values())
checks["lifter output base.c"] = o["base_c_sha256"] == exp["base_c_sha256"]
checks["closure.c"] = o["closure_c_sha256"] == exp["closure_c_sha256"]
checks["15 objects (names+hashes)"] = {x["name"]: x["sha256"] for x in o["objects"]} == exp["objects"]
for rel, h in exp["source_files_worktree_sha256"].items():
    checks[f"source {rel}"] = sha(w / "src" / rel) == h
det = w / "src" / "bin" / "gw_demo_sdl2.det.exe"; dflt = w / "src" / "bin" / "gw_demo_sdl2.exe"
checks["deterministic exe sha256 (byte-exact)"] = sha(det) == exp["deterministic_exe_sha256"] and det.stat().st_size == exp["deterministic_exe_size"]
a, b = det.read_bytes(), dflt.read_bytes(); pe = struct.unpack_from("<I", a, 0x3C)[0]
allowed = {x + j for x in (pe + 8, pe + 88) for j in range(4)}
diff = [i for i in range(min(len(a), len(b))) if a[i] != b[i]]
checks["default-link exe differs from deterministic only in PE TimeDateStamp/CheckSum"] = len(a) == len(b) and set(diff) <= allowed
for k, v in checks.items(): print(("PASS " if v else "FAIL ") + k)
print("ALL PASS" if all(checks.values()) else "NOT VALIDATED")
sys.exit(0 if all(checks.values()) else 1)
