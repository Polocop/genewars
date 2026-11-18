"""Copy the read-only GeneWars GAME tree into an isolated virtual C drive."""
from __future__ import annotations
import os as _gw_os
from pathlib import Path as _GwPath
_GW_ROOT=str(_GwPath(__file__).resolve().parents[1])
_GW_FX=_gw_os.environ.get("GENEWARSFX_ROOT",_gw_os.path.join(_GW_ROOT,"third_party","GeneWarsFX"))
import hashlib
import json
import pathlib
import shutil

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = pathlib.Path((_GW_FX + '\\work\\disc_extracted\\GAME'))
DEST_ROOT = ROOT / "build" / "dos_c_reference_20261006"
DEST_GAME = DEST_ROOT / "GENEWARS"
MANIFEST = ROOT / "evidence" / "dos_game_install_manifest.json"


def sha(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def manifest(root: pathlib.Path) -> list[dict]:
    rows=[]
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rows.append({"relative_path":path.relative_to(root).as_posix(),
                     "size":path.stat().st_size,"sha256":sha(path)})
    return rows


def main() -> None:
    if not SOURCE.is_dir(): raise SystemExit(f"read-only source missing: {SOURCE}")
    source_rows=manifest(SOURCE)
    if not DEST_ROOT.exists():
        DEST_GAME.mkdir(parents=True)
        for row in source_rows:
            src=SOURCE / pathlib.PurePosixPath(row["relative_path"])
            dst=DEST_GAME / pathlib.PurePosixPath(row["relative_path"])
            dst.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(src,dst)
    elif not DEST_GAME.is_dir():
        raise SystemExit(f"destination exists without expected GAME root: {DEST_GAME}")
    dest_rows=manifest(DEST_GAME)
    source_after=manifest(SOURCE)
    if source_rows != source_after:
        raise SystemExit("read-only source changed while staging; refusing success")
    if source_rows != dest_rows:
        raise SystemExit("staged tree differs from source; refusing success")
    result={"source_root":str(SOURCE),"destination_root":str(DEST_ROOT),
            "virtual_drive_mapping":"C:\\GENEWARS -> build/dos_c_reference_20261006/GENEWARS",
            "files":len(source_rows),"total_bytes":sum(x["size"] for x in source_rows),
            "source_unchanged":True,"destination_matches_source":True,
            "file_manifest":source_rows}
    MANIFEST.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({k:v for k,v in result.items() if k!="file_manifest"},indent=2))

if __name__ == "__main__": main()
