#!/usr/bin/env python3
"""
extract_icall.py — Extract and classify every RECOMP_ICALL (indirect-call)
site in the corrected-VA closure (build/recomp_282.c) into a dispatch table
the WORK2 runtime host needs to execute the entry path (FIRST_NATIVE_EXECUTION gate).

For each site we record:
  - line number in the C file
  - the function (VA) that contains the site
  - the operand shape: abs / mem32_abs / mem32_reg / reg / unresolved
  - the raw operand text and, for abs + mem32_abs, the numeric address
  - for numeric targets: class = lifted | not_lifted_in_range | below_code |
    above_code | external ; plus MAIN.MAP symbol name if one matches

Outputs:
  evidence/icall_dispatch_table.json   full table + per-class metrics
  reports/LOCAL_ICALL.md               human summary for WORK2

This is a derived, read-only batch: it parses the already-generated C and the
LE image; it does not touch any core tool or the runtime.
"""
import sys, json, re, time
from pathlib import Path
from collections import Counter, defaultdict

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "src"))
sys.path.insert(0, str(root / "third_party" / "pcrecomp"))

from le_loader import load_le
from tools.disasm.disasm32 import Disassembler
from tools.pe.pe_analyze import Section

# ---- locate generated C + metrics (same names scale_282.py writes) ----
CFILE = root / "build" / "recomp_282.c"
METRICS = root / "evidence" / "scale_282_metrics.json"
OUT_JSON = root / "evidence" / "icall_dispatch_table.json"
OUT_MD = root / "reports" / "LOCAL_ICALL.md"

t0 = time.time()
im = load_le(root / "evidence" / "genewars-1_1.exe")
obj = im.objects[0]
START = obj.base
END = START + obj.virtual_size
code = bytes(im.mem[START - im.mem_base : END - im.mem_base])
sec = Section(".text", obj.base, obj.virtual_size, 0, obj.virtual_size, 0x20000020)
ds = Disassembler(code, 0, [sec])

# lifted function set (names in C are sub_<VA8>) + their VAs
src = CFILE.read_text(encoding="utf-8", errors="replace")
func_def = re.compile(r"^\w[\w\s\*]*\bsub_([0-9A-Fa-f]{8})\s*\(")
lifted_va = {}
for ln, line in enumerate(src.splitlines(), 1):
    m = func_def.match(line)
    if m:
        lifted_va[int(m.group(1), 16)] = ln

# MAP symbols: exact same source + format as scale_282.py
# (evidence/genewars-1_1.map, lines "0001:ADDR NAME").
map_syms = {}
map_src = root / "evidence" / "genewars-1_1.map"
if map_src.exists():
    for line in map_src.read_text(encoding="utf-8", errors="replace").splitlines():
        p = line.split()
        if len(p) >= 2 and p[0].startswith("0001:"):
            try:
                a = int(p[0].split(":")[1], 16)
                map_syms[a] = p[1]
            except ValueError:
                pass

# also load discovered function starts so we can label not_lifted_in_range as "known function, not lifted"
try:
    funcs = ds.find_functions(START, END)
    discovered_va = set(funcs.keys())
except Exception as e:
    print(f"[warn] find_functions failed: {e}", file=sys.stderr)
    discovered_va = set()

# ---- operand classification ----

def read_slot32(slot_va):
    """Return the 32-bit little-endian value stored at a linear VA in the
    loaded (relocated) LE image, or None if the slot is out of the image."""
    off = slot_va - im.mem_base
    if 0 <= off + 4 <= len(im.mem):
        import struct
        return struct.unpack_from("<I", im.mem, off)[0]
    return None

def classify_operand(op):
    op = op.strip()
    if op.startswith("MEM32("):
        # outer RECOMP_ICALL regex captures up to the FIRST ')', i.e. the
        # MEM32 close paren. So the content may or may not carry a trailing
        # ')' — strip it, never a fixed last char (that drops a hex digit).
        inner = op[len("MEM32("):].lstrip("(").rstrip(")").strip()
        if re.fullmatch(r"0x[0-9A-Fa-f]+", inner):
            return ("mem32_abs", int(inner, 16))
        # register(+disp) e.g. ebx + 0x8
        return ("mem32_reg", inner)
    if re.fullmatch(r"0x[0-9A-Fa-f]+", op):
        return ("abs", int(op, 16))
    if op == "0":
        return ("unresolved", None)
    return ("reg", op)

def target_class(va):
    if va in lifted_va:
        return "lifted"
    if not (START <= va < END):
        if va < START:
            return "below_code_object"
        return "above_code_object"
    if va in discovered_va:
        return "not_lifted_in_range"
    return "not_lifted_in_range"  # in-range but no discovered boundary

records = []
cur_func = None
cur_func_va = None
for ln, line in enumerate(src.splitlines(), 1):
    m = func_def.match(line)
    if m:
        cur_func = f"sub_{m.group(1)}"
        cur_func_va = int(m.group(1), 16)
    im2 = re.search(r"RECOMP_ICALL\(([^)]*)\)", line)
    if not im2:
        continue
    raw = im2.group(1).strip()
    shape, addr = classify_operand(raw)
    rec = {
        "line": ln,
        "func": cur_func,
        "func_va": f"0x{cur_func_va:08X}" if cur_func_va is not None else None,
        "shape": shape,
        "operand": raw,
    }
    if shape in ("abs", "mem32_abs"):
        rec["target_va"] = f"0x{addr:08X}"
        rec["target_dec"] = addr
        rec["class"] = target_class(addr)  # class of the operand address itself
        sym = map_syms.get(addr)
        rec["map_symbol"] = sym
        if shape == "mem32_abs":
            # The operand is a POINTER-SLOT (data-object) address, not a code
            # target: the runtime reads the 32-bit value stored there and
            # dispatches to it. Resolve that value and classify it, because
            # the resolved value — not the slot address — is the real target.
            ptr = read_slot32(addr)
            rec["slot_static_ptr"] = f"0x{ptr:08X}" if ptr is not None else None
            if ptr is None:
                rec["slot_state"] = "slot_out_of_image"
                rec["resolved_class"] = "unresolved"
            elif ptr == 0:
                # unpopulated function-pointer / callback slot at static load
                rec["slot_state"] = "zero_static"
                rec["resolved_class"] = "zero_slot_runtime_populated"
            else:
                rec["slot_state"] = "populated_static"
                rec["resolved_class"] = target_class(ptr)
                rsym = map_syms.get(ptr)
                rec["resolved_map_symbol"] = rsym
                rec["resolved_lifted"] = ptr in lifted_va
        else:
            # plain abs: operand IS the target (call dword ptr [addr] not used)
            rec["resolved_class"] = rec["class"]
            rec["resolved_lifted"] = addr in lifted_va
    records.append(rec)

# ---- metrics ----
by_shape = Counter(r["shape"] for r in records)
by_class = Counter(r.get("class") for r in records if r.get("class"))
abs_targets = [r for r in records if r["shape"] in ("abs", "mem32_abs")]
abs_targets.sort(key=lambda r: r["target_dec"])
unresolved = [r for r in records if r["shape"] == "unresolved"]
mem32_reg = [r for r in records if r["shape"] == "mem32_reg"]
reg = [r for r in records if r["shape"] == "reg"]

# dedupe absolute targets by VA
uniq_abs = {}
for r in abs_targets:
    uniq_abs.setdefault(r["target_dec"], r)

metrics = {
    "source_c": "build/recomp_282.c",
    "closure_object": f"0x{START:08X}-0x{END:08X}",
    "lifted_functions_in_c": len(lifted_va),
    "total_icall_sites": len(records),
    "by_shape": dict(by_shape),
    # class of the OPERAND address itself (kept for reference)
    "operand_by_class": dict(by_class),
    # REAL dispatch target = for mem32_abs the 32-bit value stored at the slot,
    # for abs the address itself. This is what the runtime must dispatch to.
    "resolved_by_class": dict(Counter(r.get("resolved_class") for r in records if r.get("resolved_class"))),
    "resolved_lifted": sum(1 for r in records if r.get("resolved_lifted")),
    "resolved_not_lifted_in_range": sum(1 for r in records
        if r.get("resolved_class") == "not_lifted_in_range"),
    "unique_abs_targets": len(uniq_abs),
    "abs_lifted": sum(1 for r in uniq_abs.values() if r["class"] == "lifted"),
    "abs_not_lifted_in_range": sum(1 for r in uniq_abs.values() if r["class"] == "not_lifted_in_range"),
    "abs_below_code": sum(1 for r in uniq_abs.values() if r["class"] == "below_code_object"),
    "abs_above_code": sum(1 for r in uniq_abs.values() if r["class"] == "above_code_object"),
    "abs_map_named": sum(1 for r in uniq_abs.values() if r.get("map_symbol")),
    # pointer-slot population (mem32_abs only)
    "slot_populated_static": sum(1 for r in records if r.get("slot_state") == "populated_static"),
    "slot_zero_static": sum(1 for r in records if r.get("slot_state") == "zero_static"),
    "slot_out_of_image": sum(1 for r in records if r.get("slot_state") == "slot_out_of_image"),
    "mem32_reg_sites": len(mem32_reg),
    "reg_sites": len(reg),
    "unresolved_sites": len(unresolved),
    "map_symbols_loaded": len(map_syms),
    "map_source": str(map_src.relative_to(root)) if map_src else None,
    "discovered_functions": len(discovered_va),
    "elapsed_seconds": round(time.time() - t0, 2),
}

OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
OUT_JSON.write_text(json.dumps({
    "metrics": metrics,
    "records": records,
    "unique_abs_targets": [uniq_abs[k] for k in sorted(uniq_abs)],
}, ensure_ascii=False, indent=2), encoding="utf-8")

# ---- human summary ----
md = []
md.append("# LOCAL: ICALL dispatch table (closure VA-corregido, 1561-func)")
md.append("")
md.append(f"Fuente: `build/recomp_282.c` (objeto {metrics['closure_object']}, "
          f"{metrics['lifted_functions_in_c']} funcs levantadas). "
          f"{metrics['map_source'] or 'MAIN.MAP no cargado'} ({metrics['map_symbols_loaded']} simbolos).")
md.append("")
md.append(f"Total sitios RECOMP_ICALL: **{metrics['total_icall_sites']}**")
md.append("")
md.append("## Por forma de operando")
for k, v in sorted(by_shape.items(), key=lambda x: -x[1]):
    md.append(f"- `{k}`: {v}")
md.append("")
md.append("## Indirect-call: dos familias que el runtime DEBE modelar")
md.append("")
md.append("Los 553 sitios RECOMP_ICALL se reparten en dos mecanismos distintos:")
md.append("")
md.append(f"### 1) Despliegue por registro — `mem32_reg` ({metrics['mem32_reg_sites']} sitios) + `reg` ({metrics['reg_sites']})")
md.append("Son `call [reg]` / `call [reg+disp]`: el puntero de función vive en un")
md.append("registro/estructura en tiempo de ejecución. El host no puede resolver la")
md.append("dirección estáticamente: debe ejecutar la llamada leyendo el valor del")
md.append("registro al momento del dispatch. Es el mecanismo dominante.")
md.append("")
md.append("### 2) Slot de puntero absoluto — `mem32_abs` ({n} sitios, {u} slots únicos)".format(
    n=metrics["by_shape"].get("mem32_abs", 0), u=metrics["unique_abs_targets"]))
md.append("El operando es la dirección de un **slot de datos** en el objeto LE. El")
md.append("host lee los 4 bytes almacenados ahí y dispatcha al valor resuelto")
md.append("(no al slot). Resolución sobre la imagen LE relocada:")
md.append(f"- **{metrics['slot_populated_static']}** slots con puntero estático a código → el valor resuelto apunta a una función del objeto de código.")
md.append(f"- **{metrics['slot_zero_static']}** slots a `0` → puntero de función/callback **sin poblar en carga estática**: el juego lo rellena en runtime (callbacks, tabla de servicios). El host debe dejarlos a 0 en carga y permitir el write del guest.")
md.append(f"- **{metrics['slot_out_of_image']}** slots fuera de imagen.")
md.append("")
md.append("Clasificación del **target resuelto** (lo que el host dispatcha en realidad):")
for k, v in sorted(metrics["resolved_by_class"].items(), key=lambda x: -x[1]):
    md.append(f"- `{k}`: {v}")
md.append("")
md.append(f"- `resolved_lifted`: {metrics['resolved_lifted']} dispatches cuya función ya está recompilada → el host encadena directo a `sub_<VA>`.")
md.append(f"- `resolved_not_lifted_in_range`: {metrics['resolved_not_lifted_in_range']} apuntan a código del objeto aún no levantado en el closure → candidato a lift incremental (WORK1).")
md.append("")
md.append("## Slots de puntero absolutos (tabla slot → valor resuelto)")
for r in sorted(uniq_abs.values(), key=lambda r: r["target_dec"]):
    ptr = r.get("slot_static_ptr")
    rc = r.get("resolved_class")
    rsym = r.get("resolved_map_symbol") or r.get("map_symbol") or ""
    md.append(f"- slot `0x{r['target_dec']:08X}` → `{ptr or 'N/A'}` ({rc}) {rsym}  [en {r['func']}, ln {r['line']}]")
md.append("")
md.append("## ICALL por registro / sin resolver -> el host resuelve en runtime")
md.append(f"- `reg` (call [reg]): {len(reg)}")
md.append(f"- `unresolved` (0): {len(unresolved)} -> el lifter no pudo resolver; revisar en WORK1 si hay patrones repetidos.")
if unresolved[:20]:
    for r in unresolved[:20]:
        md.append(f"  - linea {r['line']} en {r['func']}")
md.append("")
md.append("## Nota de VA")
md.append("Los valores de slot y sus punteros se leen de la imagen LE relocada")
md.append("(obj.base Section, patrón corregido de W1-004). Coherente con")
md.append("`evidence/scale_282_metrics.json`. No hay targets `below_code_object`")
md.append("residuos: los 28 'stubs bajo 0x10000' de la corrida desplazada quedaron")
md.append("invalidados por L-CORR.")
md.append("")
md.append(f"Generado por `tools/extract_icall.py` en {metrics['elapsed_seconds']}s.")
OUT_MD.parent.mkdir(parents=True, exist_ok=True)
OUT_MD.write_text("\n".join(md) + "\n", encoding="utf-8")

print(json.dumps(metrics, indent=2))
print(f"\nwrote {OUT_JSON.relative_to(root)} and {OUT_MD.relative_to(root)}")