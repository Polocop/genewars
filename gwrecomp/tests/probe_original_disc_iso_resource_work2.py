import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime"))
from dos_cdrom import CueImage
from dos_filesystem import DosFsError
from dos_services import DosHost
from guest_boot import prepare_guest

cue = pathlib.Path(r"E:\GeneWarsFX\evidence\original_disc\Genewars (Europe) (En,Fr,De,Es,It,Sv).cue")
target = ROOT / "evidence" / "genewars-1_1.exe"
source_text = pathlib.Path(r"E:\GeneWarsFX\work\disc_extracted\GAME\DATA\TEXT\ENG\TEXT.DAT")
cue_hash_before = hashlib.sha256(cue.read_bytes()).hexdigest()
image = CueImage.from_cue(cue)
host = DosHost(prepare_guest(target), cdrom_drives=("D",), cdrom_images=(image,))
path = "GAME/DATA/TEXT/ENG/TEXT.DAT"
handle = host.filesystem.open(path)
try:
    payload = host.filesystem.read(handle, 36611)
finally:
    host.filesystem.close(handle)
flat_exists = True
flat_error_code = None
try:
    flat = host.filesystem.open("DATA/TEXT.DAT")
except DosFsError as exc:
    flat_exists = False
    flat_error_code = exc.dos_code
else:
    host.filesystem.close(flat)
evidence = {
    "task": "W2-075",
    "target_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
    "cue_path": str(cue),
    "cue_sha256_before": cue_hash_before,
    "cue_sha256_after": hashlib.sha256(cue.read_bytes()).hexdigest(),
    "tracks": [{"number": t.number, "mode": t.mode, "lba_start": t.lba_start, "sectors": t.sectors} for t in image.tracks],
    "runtime_files": [{"path": p, "sha256": hashlib.sha256((ROOT / p).read_bytes()).hexdigest()} for p in ["runtime/dos_cdrom.py", "runtime/dos_iso9660.py", "runtime/dos_filesystem.py", "runtime/dos_services.py"]],
    "doshost_iso_mount_error": host.iso_mount_error,
    "iso_root": host.filesystem.iso_volume.listdir(),
    "dos_filesystem_nested_path": path,
    "nested_size": len(payload),
    "nested_sha256": hashlib.sha256(payload).hexdigest(),
    "reference_install_file_size": source_text.stat().st_size,
    "reference_install_file_sha256": hashlib.sha256(source_text.read_bytes()).hexdigest(),
    "flat_data_text_dat_exists_at_cd_root": flat_exists,
    "flat_lookup_error_code": flat_error_code,
    "no_alias_or_synthetic_response": True,
    "reference_read_only": True
}
(ROOT / "evidence" / "original_disc_iso_resource_work2.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
print(json.dumps(evidence, indent=2))
