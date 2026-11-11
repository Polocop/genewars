"""Verify W2-108 recovery copies and restore them only into a temporary directory."""
from __future__ import annotations
import os as _gw_os
from pathlib import Path as _GwPath
_GW_ROOT=str(_GwPath(__file__).resolve().parents[1])
import hashlib
import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "evidence" / "w2_108_runtime_recovery_manifest.json"
ALLOWED = {
    "runtime/gw_dos_services.c",
    "runtime/gw_dos_services.h",
    "runtime/dos_services.py",
    "runtime/dos_filesystem.py",
    "tests/test_dos_ah43_frontier_work2.c",
    "tests/test_dos_ah43_frontier_work2.py",
    "tests/test_dos_services.py",
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _contained(relative: str, base: Path) -> Path:
    rel = PurePosixPath(relative)
    if rel.is_absolute() or ".." in rel.parts:
        raise AssertionError(f"unsafe relative path: {relative}")
    result = base.joinpath(*rel.parts)
    if os.path.commonpath([str(base.resolve()), str(result.resolve())]) != str(base.resolve()):
        raise AssertionError(f"path escapes expected root: {relative}")
    return result


def verify_and_restore(manifest_path: Path = MANIFEST) -> dict:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema") != "w2-runtime-recovery/v1" or manifest.get("task") != "W2-108":
        raise AssertionError("unexpected recovery manifest identity")
    if len(manifest.get("files", [])) != len(ALLOWED):
        raise AssertionError("manifest file count does not match authorized scope")
    listed = {item["source"] for item in manifest["files"]}
    if listed != ALLOWED:
        raise AssertionError(f"manifest scope mismatch: {sorted(listed ^ ALLOWED)}")
    backup_root = _contained(manifest["backup_root"], ROOT)
    restore_root = ROOT / "cache"
    restore_root.mkdir(parents=True, exist_ok=True)
    restored = []
    with tempfile.TemporaryDirectory(prefix="w2-108-restore-", dir=restore_root) as temp:
        temp_root = Path(temp)
        for item in manifest["files"]:
            source = _contained(item["source"], ROOT)
            backup = _contained(item["recovery_copy"], ROOT)
            if os.path.commonpath([str(backup_root.resolve()), str(backup.resolve())]) != str(backup_root.resolve()):
                raise AssertionError("recovery copy is outside its authorized root")
            expected = item["original_sha256"]
            if source.stat().st_size != item["bytes"] or _sha256(source) != expected:
                raise AssertionError(f"live source changed since snapshot: {item['source']}")
            if backup.stat().st_size != item["bytes"] or _sha256(backup) != expected:
                raise AssertionError(f"recovery copy mismatch: {item['source']}")
            restored_path = _contained(item["source"], temp_root)
            restored_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(backup, restored_path)
            actual = _sha256(restored_path)
            if actual != expected:
                raise AssertionError(f"restored copy mismatch: {item['source']}")
            restored.append({"source": item["source"], "restored_sha256": actual, "matches": True})
    return {
        "schema": "w2-runtime-recovery-verification/v1",
        "task": "W2-108",
        "verified_at_utc": datetime.now(timezone.utc).isoformat(),
        "manifest": str(manifest_path.relative_to(ROOT)).replace("\\", "/"),
        "manifest_sha256": _sha256(manifest_path),
        "restoration_target": ('unique temporary directory under ' + _GW_ROOT.replace("\\","/") + '/cache'),
        "restored_files": restored,
        "all_match": len(restored) == len(ALLOWED) and all(item["matches"] for item in restored),
        "live_sources_modified": False,
    }


if __name__ == "__main__":
    result = verify_and_restore()
    print(json.dumps(result, indent=2))
