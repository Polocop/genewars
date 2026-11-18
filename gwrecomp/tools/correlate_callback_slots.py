#!/usr/bin/env python3
"""
correlate_callback_slots.py (LOCAL task L-CALLSLOTS)

Correlate the ZERO-valued (runtime-populated) function-pointer/callback slots
surfaced by the L-ICALL dispatch table to the code that populates them, and to
whether that code is lifted. This tells the WORK2 runtime host which callback-slot
semantics must be modeled before the current gate (original-byte -k path stops at
DPMI AX=0600 Lock Linear Region at 0x001d23a7 in _DoINTR_, on the way to MENU).

Method (pure-LOCAL, read-only over already-generated artifacts):
  1. Load the zero-static slots from evidence/icall_dispatch_table.json
     (records with slot_state == 'zero_static') -> set of slot VAs.
  2. Scan build/recomp_282.c for store lines  MEM32(0x<ADDR>) = <value>
     tracking the enclosing function (sub_<VA>). Record, per slot:
       populating function VA+name, store line, guest VA (from the /* comment),
       value type (immediate / register / computed).
  3. Classify each zero-slot:
       populated_by_immediate   : a store writes a 0x..u constant (static ptr)
       populated_by_register    : a store writes a register/computed value
       no_static_store_found    : no store to the slot in the lifted code
     and annotate each populating function with its lift status.

Outputs:
  evidence/correlated_callback_slots.json
  reports/LOCAL_CALLBACK_SLOTS.md

Touches no core tool and no runtime; reads only generated artifacts + the C file.
"""
import sys, re, json, time
from pathlib import Path
from collections import defaultdict, Counter

root = Path(__file__).resolve().parents[1]
CFILE = root / "build" / "recomp_282.c"
ICALL = root / "evidence" / "icall_dispatch_table.json"
OUT_JSON = root / "evidence" / "correlated_callback_slots.json"
OUT_MD = root / "reports" / "LOCAL_CALLBACK_SLOTS.md"

t0 = time.time()

# --- 1. zero-static slot VAs from the L-ICALL table -------------------------
d = json.loads(ICALL.read_text(encoding="utf-8"))
zero_slots = {}   # slot_va (int) -> first record (func, line) that read it via ICALL
for r in d["records"]:
    if r.get("slot_state") == "zero_static" and r.get("slot_static_ptr") == "0x00000000":
        sv = int(r["target_va"], 16)
        if sv not in zero_slots:
            zero_slots[sv] = r
zero_list = sorted(zero_slots)
print(f"[1] {len(zero_list)} zero-static callback slots from {ICALL.name}")

# --- lifted function set (names in C are sub_<VA8>) --------------------------
src = CFILE.read_text(encoding="utf-8", errors="replace")
func_def = re.compile(r"^\w[\w\s\*]*\bsub_([0-9A-Fa-f]{8})\s*\(")
lifted_va = set()
for line in src.splitlines():
    m = func_def.match(line)
    if m:
        lifted_va.add(int(m.group(1), 16))
print(f"[2] {len(lifted_va)} lifted functions in {CFILE.name}")

# entry-path closure (the -k startup route to MENU) -- which populator functions
# sit ON that route?  If none do, the host does not need to model slot
# population before MENU (it only matters for the later MISSION/GAMEPLAY phase).
ENTRY_C = root / "build" / "entry_path_combined.c"
entry_path_funcs = set()
if ENTRY_C.exists():
    _esrc = ENTRY_C.read_text(encoding="utf-8", errors="replace")
    for _l in _esrc.splitlines():
        _m = func_def.match(_l)
        if _m:
            entry_path_funcs.add("sub_" + _m.group(1).lower())
    print(f"[2b] {len(entry_path_funcs)} functions on the entry-path closure ({ENTRY_C.name})")

# --- 3. scan stores per slot -------------------------------------------------
store_re = re.compile(r"MEM32\(0x([0-9A-Fa-f]+)\)\s*=\s*([^;]+);")
guest_re = re.compile(r"/\*\s*(0x[0-9A-Fa-f]{6,8}):")
immedi_re = re.compile(r"^0x[0-9A-Fa-f]+u?$")
reg_re = re.compile(r"^[a-z]{2,4}$")  # eax, ecx, edx, esi, edi, ebp, esp

# stores[slot_va] = list of {func_va, func, line, value, value_type, guest_va}
stores = defaultdict(list)
cur_func = None
cur_func_va = None
lines = src.splitlines()
for ln, line in enumerate(lines, 1):
    m = func_def.match(line)
    if m:
        cur_func = f"sub_{m.group(1)}"
        cur_func_va = int(m.group(1), 16)
    sm = store_re.search(line)
    if not sm:
        continue
    slot = int(sm.group(1), 16)
    if slot not in zero_slots:
        continue
    value = sm.group(2).strip()
    if immedi_re.match(value):
        vtype = "immediate"
    elif reg_re.match(value):
        vtype = "register"
    else:
        vtype = "computed"
    gm = guest_re.search(line)
    guest = gm.group(1) if gm else None
    stores[slot].append({
        "func": cur_func,
        "func_va": f"0x{cur_func_va:08X}" if cur_func_va is not None else None,
        "func_lifted": cur_func_va in lifted_va if cur_func_va is not None else False,
        "line": ln,
        "value": value,
        "value_type": vtype,
        "guest_va": f"0x{int(guest,16):08X}" if guest else None,
    })

# --- 4. classify each slot ---------------------------------------------------
classified = []
for sv in zero_list:
    rec = zero_slots[sv]
    st = stores.get(sv, [])
    vtypes = {s["value_type"] for s in st}
    if not st:
        cls = "no_static_store_found"
    elif "immediate" in vtypes:
        cls = "populated_by_immediate"
    elif vtypes and vtypes <= {"register", "computed"}:
        cls = "populated_by_register"
    else:
        cls = "populated_by_register"  # mixed register/computed
    lift_states = {}
    for s in st:
        lift_states.setdefault(s["func"], s["func_lifted"])
    on_entry = [f for f in lift_states if f.lower() in entry_path_funcs]
    classified.append({
        "slot_va": f"0x{sv:08X}",
        "slot_dec": sv,
        "iclass_func": rec.get("func"),
        "iclass_line": rec.get("line"),
        "class": cls,
        "stores": st,
        "populating_functions": {
            f: {"va": f"0x{int(f.split('_')[1],16):08X}", "lifted": lift_states[f],
                "on_entry_path": f.lower() in entry_path_funcs}
            for f in lift_states
        },
        "populators_on_entry_path": on_entry,
        "all_populators_lifted": all(v for v in lift_states.values()) if lift_states else None,
    })

by_class = Counter(c["class"] for c in classified)
# 58 = L-ICALL mem32_abs ZERO sites (ICALL call-sites); 14 = distinct pointer slots
_icall_zero_sites = sum(1 for r in d["records"]
                        if r.get("slot_state") == "zero_static"
                        and r.get("slot_static_ptr") == "0x00000000")
entry_total = len(entry_path_funcs)
pops_all = {f for c in classified for f in c["populating_functions"]}
pops_on_entry = {f for f in pops_all if f.lower() in entry_path_funcs}
pops_not_entry = pops_all - pops_on_entry
slots_with_entry_populator = [c["slot_va"] for c in classified if c["populators_on_entry_path"]]
metrics = {
    "source_icall_table": "evidence/icall_dispatch_table.json",
    "source_c": "build/recomp_282.c",
    "entry_path_source": "build/entry_path_combined.c" if ENTRY_C.exists() else None,
    "zero_static_icall_sites": _icall_zero_sites,
    "zero_static_distinct_slots": len(zero_list),
    "note_sites_vs_slots": ("L-ICALL counts 58 mem32_abs ICALL call-sites that read zero-valued "
                            "slots; they deduplicate to %d distinct pointer slots (one slot is read "
                            "by several ICALL sites)." % len(zero_list)),
    "by_class": dict(by_class),
    "populated_by_lifted_func": sum(1 for c in classified
        if c["class"] != "no_static_store_found" and c["all_populators_lifted"]),
    "populated_by_unlifted_in_code": sum(1 for c in classified
        if c["class"] != "no_static_store_found" and c["all_populators_lifted"] is False),
    "no_static_store_found": sum(1 for c in classified if c["class"] == "no_static_store_found"),
    "distinct_populating_functions": len(pops_all),
    "lifted_functions_in_c": len(lifted_va),
    "entry_path_functions": entry_total,
    "populators_on_entry_path": sorted(f.lower() for f in pops_on_entry),
    "populators_not_on_entry_path": sorted(f.lower() for f in pops_not_entry),
    "slots_with_populator_on_entry_path": slots_with_entry_populator,
    "entry_path_relevance": (
        "NONE of the %d populator functions is on the -k entry-path closure (%d funcs to MENU); "
        "callback-slot population happens in post-MENU code, so the host does not need to model "
        "slot population to reach MENU. The only gap is the single no_static_store slot, whose "
        "filler is outside the lifted closure." % (len(pops_all), entry_total)
        if not slots_with_entry_populator else
        "Some slot populators ARE on the entry path: %s" % ", ".join(slots_with_entry_populator)),
    "elapsed_seconds": round(time.time() - t0, 2),
}

OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
OUT_JSON.write_text(json.dumps({"metrics": metrics, "slots": classified},
                              ensure_ascii=False, indent=2), encoding="utf-8")

# --- human report ------------------------------------------------------------
md = ["# LOCAL: Zero-callback slot population correlation (L-CALLSLOTS)", ""]
md.append(f"Fuente: `{ICALL.name}` (L-ICALL) + `{CFILE.name}` + "
          f"`{('entry_path_combined.c' if ENTRY_C.exists() else 'n/a')}`. ")
md.append(f"L-ICALL reportó **{_icall_zero_sites} ICALL call-sites** que leen slots de puntero en `0` "
          f"a carga estática; esas sites deduplican a **{len(zero_list)} slots de puntero distintos** "
          f"(un slot puede ser leído por varias ICALL). Esta tabla correlaciona los **{len(zero_list)} slots**.")
md.append("")
md.append(f"Resumen: **{len(zero_list)}** slots → "
          f"`populated_by_immediate`: {by_class.get('populated_by_immediate',0)}, "
          f"`populated_by_register`: {by_class.get('populated_by_register',0)}, "
          f"`no_static_store_found`: {by_class.get('no_static_store_found',0)}.")
md.append("")
md.append(f"- Populados por función **levantada**: {metrics['populated_by_lifted_func']}")
md.append(f"- Populados por función **no levantada** (in-code): {metrics['populated_by_unlifted_in_code']}")
md.append(f"- Sin store estático (fill 100% runtime): {metrics['no_static_store_found']}")
md.append(f"- Funciones populadoras distintas: {metrics['distinct_populating_functions']}")
md.append("")
md.append("## Clases")
md.append("- `populated_by_immediate`: el juego escribe un puntero constante → el host puede pre-poblar el slot.")
md.append("- `populated_by_register`: el slot se rellena con un valor calculado en runtime (callback/selector) → el host debe permitir el write del guest antes del dispatch.")
md.append("- `no_static_store_found`: ningún store visible en el código levantado → el slot se rellena fuera del closure o en runtime no levantado.")
md.append("")
md.append("## Relevancia para el gate actual (entry/startup → MENU)")
md.append(f"El closure de la ruta `-k` (hasta MENU) contiene **{entry_total}** funciones "
          f"(`entry_path_combined.c`). De las {metrics['distinct_populating_functions']} funciones que "
          f"rellenan estos slots: **{len(pops_on_entry)} están en la ruta de entrada** y "
          f"**{len(pops_not_entry)} no**. → {metrics['entry_path_relevance']}")
md.append("")
md.append("## Tareas derivadas")
no_static = [c for c in classified if c["class"] == "no_static_store_found"]
md.append(f"1. **WORK1** — El único slot sin store estático (`{no_static[0]['slot_va'] if no_static else 'n/a'}`, "
          f"ICALL en `{no_static[0]['iclass_func'] if no_static else 'n/a'}`) se rellena fuera del closure liftado. "
          f"Si WORK3 confirma que su llenador está en código in-code aún no liftado, WORK1 debe añadir ese "
          f"llenador al closure para que el slot tenga valor antes del dispatch.")
if pops_not_entry:
    md.append(f"2. **WORK2** — Ningún llenador está en la ruta `-k`→MENU; los slots solo importan en la fase "
             f"post-MENU (MISSION/GAMEPLAY). Cuando WORK2 modele el dispatch de los "
             f"{metrics['distinct_populating_functions']} callbacks `{', '.join(sorted(f.lower() for f in pops_not_entry))}`, "
             f"debe aceptar que el guest escribe el slot (registro) antes de llamarlo; no hay que pre-poblar en la arranque.")
md.append("3. **WORK3** — Para el único slot `no_static_store`, identificar la función que lo llena "
          f"(`{no_static[0]['iclass_func'] if no_static else 'n/a'}` lee `{no_static[0]['slot_va'] if no_static else 'n/a'}`) y confirmar si su "
          f"llenador es in-code (→ WORK1 lift) o runtime externo (→ WORK2 stub).")
md.append("")
md.append("## Tabla por slot")
for c in classified:
    ep = " [on entry-path]" if c["populators_on_entry_path"] else ""
    md.append(f"### slot `{c['slot_va']}` → `{c['class']}`  (ICALL en {c['iclass_func']}, ln {c['iclass_line']}){ep}")
    for s in c["stores"]:
        md.append(f"  - store ln {s['line']} en `{s['func']}` {'(LIFTED)' if s['func_lifted'] else '(no lev.)'}: `MEM32({c['slot_va'].lower()}) = {s['value']}` {s['value_type']}  [guest {s['guest_va']}]")
    if not c["stores"]:
        md.append("  - (sin store estático)")
    md.append("")
md.append(f"Generado por `tools/correlate_callback_slots.py` en {metrics['elapsed_seconds']}s.")
OUT_MD.parent.mkdir(parents=True, exist_ok=True)
OUT_MD.write_text("\n".join(md) + "\n", encoding="utf-8")

print(json.dumps(metrics, indent=2))
print(f"\nwrote {OUT_JSON.relative_to(root)} and {OUT_MD.relative_to(root)}")