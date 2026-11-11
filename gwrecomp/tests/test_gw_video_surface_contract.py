"""Compile and run the small contract test for indexed guest video surfaces."""
from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CLANG = Path(r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\Llvm\x64\bin\clang.exe")


def main() -> None:
    if not CLANG.is_file():
        raise SystemExit(f"surface contract compiler missing: {CLANG}")
    source = ROOT / "tests" / "test_gw_video_surface_contract.c"
    with tempfile.TemporaryDirectory(prefix="gw-video-surface-") as temp:
        exe = Path(temp) / "surface_contract.exe"
        built = subprocess.run([str(CLANG), "-std=c11", "-O0", "-I", str(ROOT / "tests"),
                                str(source), "-o", str(exe)], check=False, timeout=30)
        if built.returncode:
            raise SystemExit(f"surface contract compile failed: {built.returncode}")
        ran = subprocess.run([str(exe)], check=False, timeout=5)
        if ran.returncode:
            raise SystemExit(f"surface contract failed: {ran.returncode}")
    print("PASS pitch-aware surface bounds, row access, and 16:9 mouse mapping")


if __name__ == "__main__":
    main()
