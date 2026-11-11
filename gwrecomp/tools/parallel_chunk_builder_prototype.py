import os
import sys
import re
import hashlib
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed

ROOT = Path("E:/GWRecomp")
CLOSURE_C = ROOT / "work" / "ifctitle_creature_probe_closure.c"
OUT_DIR = ROOT / "work" / "parallel_chunks"

def split_closure(num_chunks=16):
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    if not CLOSURE_C.is_file():
        print(f"Error: {CLOSURE_C} no encontrado.")
        return False

    print(f"Leyendo {CLOSURE_C}...")
    data = CLOSURE_C.read_text(encoding="utf-8", errors="replace")

    func_pattern = re.compile(r'^[ \t]*(?:static\s+)?(?:void|unsigned|signed|int|uint\d+_t)\s+(recomp_gw_partial_\w+|gw_partial_\w+)\s*\(', re.M)
    matches = list(func_pattern.finditer(data))
    print(f"Funciones localizadas: {len(matches)}")

    chunks = [[] for _ in range(num_chunks)]
    for i, m in enumerate(matches):
        start = m.start()
        brace_pos = data.find('{', m.end())
        if brace_pos == -1:
            continue
        depth = 0
        j = brace_pos
        while j < len(data):
            if data[j] == '{':
                depth += 1
            elif data[j] == '}':
                depth -= 1
                if depth == 0:
                    break
            j += 1
        body = data[start:j+1]
        chunks[i % num_chunks].append(body)

    for i in range(num_chunks):
        chunk_path = OUT_DIR / f"chunk_{i:02d}.c"
        content = '#include "recomp_types.h"\n\n' + "\n\n".join(chunks[i])
        chunk_path.write_text(content, encoding="utf-8")
        h = hashlib.sha256(content.encode()).hexdigest()
        (OUT_DIR / f"chunk_{i:02d}.c.sha256").write_text(h)

    print(f"Exito: Generados {num_chunks} chunks en {OUT_DIR}")
    return True

if __name__ == "__main__":
    split_closure(16)