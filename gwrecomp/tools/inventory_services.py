#!/usr/bin/env python3
"""
inventory_services.py  (LOCAL task L-SVCINV)

Read-only inventory of every DOS / DPMI / real-mode interrupt service request
that appears across the generated evidence traces (evidence/*.json), normalized
to a stable key and cross-referenced against the services WORK2 has already
implemented (parsed from the W2-* DONE task titles in the queue + the
'dos_service_contracts.json' implemented list).

Purpose: give WORK2 the exact, ordered, de-duplicated set of services the `-k`
original-byte path issues, so it can implement the PENDING ones in order toward
MENU without re-running the oracle per service. The current gate stops at the
real-mode DPMI AX=0300 -> INT 2Fh AX=1500 request at 0x001d23a7.

Pure-LOCAL: reads only generated artifacts + the queue; touches no core tool
and no runtime.

Outputs:
  evidence/real_mode_service_inventory.json
  reports/LOCAL_SERVICE_INVENTORY.md
"""
import sys, re, json, time, glob, subprocess
from pathlib import Path
from collections import defaultdict

ROOT = Path(__file__).resolve().parents[1]
OUT_JSON = ROOT / "evidence" / "real_mode_service_inventory.json"
OUT_MD = ROOT / "reports" / "LOCAL_SERVICE_INVENTORY.md"
t0 = time.time()

# ------------------------------------------------------------------ helpers ---
def to_int(v):
    if v is None: return None
    if isinstance(v, int): return v
    if isinstance(v, str):
        s = v.strip()
        try:
            if s.lower().startswith("0x"): return int(s, 16)
            if s.startswith("AH=") or s.startswith("AX="):
                return int(s.split("=")[1], 16)
            if s.startswith("AL=") or s.startswith("AL="):
                return int(s.split("=")[1], 16)
            return int(s, 0)
        except Exception:
            return None
    return None

# Canonical service labels seen in WORK2/WORK3 evidence. We reuse these labels
# verbatim (they are the other Works' own vocabulary) -- we do NOT translate
# them into AH/AX numbers here, which would risk inventing semantics. A record
# that carries a `service` label but no readable numeric AH/AX is keyed by the
# label, so the large opaque "(AH?)/(AX?)" capture-gap buckets collapse into the
# named services WORK2 already understands.
def service_label_key(vector, service_name):
    if vector is None or not service_name:
        return None
    return f"INT {vector:02X}h {service_name}"

def service_key(vector, ax=None, ah=None, al=None):
    if vector is None: return None
    if vector == 0x21:
        a = ah if ah is not None else ((ax >> 8) & 0xFF if ax is not None else None)
        return f"INT 21h AH={a:02X}" if a is not None else "INT 21h (AH?)"
    if vector == 0x2F:
        a = ah if ah is not None else ((ax >> 8) & 0xFF if ax is not None else None)
        base = f"INT 2Fh AH={a:02X}" if a is not None else "INT 2Fh (AH?)"
        if al is not None:
            base += f" AL={al:02X}"
        return base
    if vector == 0x31:
        x = ax if ax is not None else (ah << 8 if ah is not None else None)
        return f"INT 31h AX={x:04X}" if x is not None else "INT 31h (AX?)"
    x = ax if ax is not None else (ah << 8 if ah is not None else None)
    if x is not None:
        return f"INT {vector:02X}h AX={x:04X}"
    return f"INT {vector:02X}h"

# ------------------------------------------------------------------ walker ----
# Collect service descriptors: any dict carrying a recognizable vector plus an
# AH/AX/eax/function value, with an associated EIP.
def extract_from_dict(o, eip_hint, out):
    # Special-case DPMI AX=0300 real-mode frames: the vector is real_mode_vector,
    # the guest EIP is interrupt_eip, and the inner AX is frame.registers.eax.
    # These fields are split across nested dicts, so handle them explicitly.
    if "real_mode_vector" in o and "frame" in o:
        rmv = to_int(o["real_mode_vector"])
        eip = o.get("interrupt_eip") or eip_hint
        ax = None
        fr = o.get("frame") or {}
        regs = fr.get("registers") or {}
        if isinstance(regs.get("eax"), int):
            ax = regs["eax"] & 0xFFFF
        elif o.get("host_registers", {}).get("eax") is not None:
            ax = to_int(o["host_registers"]["eax"])
        key = service_key(rmv, ax=ax) if rmv is not None else None
        if key:
            out.append({"key": key, "vector": rmv,
                        "eip": to_int(eip) if eip is not None else None,
                        "ax": ax, "ah": (ax >> 8) & 0xFF if ax is not None else None,
                        "al": ax & 0xFF if ax is not None else None})
        return
    # Special-case the compact inner_real_mode_interrupt descriptor.
    if "inner_real_mode_interrupt" in o and isinstance(o["inner_real_mode_interrupt"], dict):
        irr = o["inner_real_mode_interrupt"]
        vec = to_int(irr.get("vector"))
        ax = to_int(irr.get("ax"))
        eip = o.get("eip") or eip_hint
        key = service_key(vec, ax=ax) if vec is not None else None
        if key:
            out.append({"key": key, "vector": vec,
                        "eip": to_int(eip) if eip is not None else None,
                        "ax": ax, "ah": (ax >> 8) & 0xFF if ax is not None else None,
                        "al": ax & 0xFF if ax is not None else None})
        return
    # vector present at this level?
    vec = None
    for k in ("vector",):
        if k in o and isinstance(o[k], (int, str)):
            vec = to_int(o[k])
            if vec is not None: break
    if vec is None:
        return
    ax = ah = al = None
    eip = o.get("eip") or o.get("guest_eip") or eip_hint
    eip_i = to_int(eip) if eip is not None else None
    # AX/AH/AL candidates
    if isinstance(o.get("ax"), (int, str)):
        ax = to_int(o["ax"])
    elif isinstance(o.get("eax"), int):
        ax = o["eax"] & 0xFFFF
    if "ah" in o:
        ah = to_int(o["ah"])
    if "al" in o:
        al = to_int(o["al"])
    # 'function' field: int (AH for 21h, AX for DPMI) or string "AH=0xNN"/"AX=0xNNNN"
    fn = o.get("function")
    if fn is not None and ax is None and ah is None:
        if isinstance(fn, str):
            m = re.match(r"AH=0x([0-9A-Fa-f]+)", fn)
            if m: ah = int(m.group(1), 16)
            m = re.match(r"AX=0x([0-9A-Fa-f]+)", fn)
            if m: ax = int(m.group(1), 16)
        elif isinstance(fn, int):
            if vec == 0x21: ah = fn & 0xFF
            else: ax = fn & 0xFFFF
    # Fallback: if numeric AH/AX could not be read but a canonical `service` label
    # is present, key by the label (WORK2/WORK3's own vocabulary) rather than
    # inventing AH/AX numbers.
    if ax is None and ah is None:
        svc_name = o.get("service")
        if isinstance(svc_name, str) and svc_name:
            key = service_label_key(vec, svc_name)
            if key:
                out.append({"key": key, "vector": vec, "eip": eip_i,
                            "ax": None, "ah": None, "al": None,
                            "label": svc_name})
                return
    key = service_key(vec, ax=ax, ah=ah, al=al)
    if key:
        out.append({"key": key, "vector": vec, "eip": eip_i,
                    "ax": ax, "ah": ah, "al": al})

def walk(o, eip_hint, src, out, depth=0):
    if depth > 40: return
    if isinstance(o, dict):
        extract_from_dict(o, eip_hint, out)
        # thread the EIP hint down but do NOT let a child's eip=0 overwrite a
        # non-zero parent hint (inner real-mode frames report eip=0).
        child_hint = eip_hint
        for k in ("eip", "guest_eip", "interrupt_eip"):
            v = o.get(k)
            if v is not None and to_int(v):
                child_hint = v
                break
        for v in o.values():
            walk(v, child_hint, src, out, depth + 1)
    elif isinstance(o, list):
        for v in o:
            walk(v, eip_hint, src, out, depth + 1)

files = sorted(glob.glob(str(ROOT / "evidence" / "*.json")))

# ------------------------------------------------------------------ aggregate -
svc = {}
label_svc = {}   # label-only observations (no numeric AH/AX): unclassified, shown separately
for f in files:
    src = Path(f).name
    try:
        d = json.loads(Path(f).read_text(encoding="utf-8"))
    except Exception:
        continue
    buf = []
    walk(d, None, src, buf)
    for r in buf:
        k = r["key"]
        target = label_svc if r.get("label") else svc
        e = target.setdefault(k, {"key": k, "request_count": 0, "first_eip": None,
                                  "eips": set(), "traces": set(),
                                  "ax": r.get("ax"), "ah": r.get("ah"), "al": r.get("al"),
                                  "label": r.get("label")})
        e["request_count"] += 1
        e["traces"].add(src)
        if r.get("eip") is not None:
            e["eips"].add(r["eip"])
            if e["first_eip"] is None or r["eip"] < e["first_eip"]:
                e["first_eip"] = r["eip"]
        if r.get("label") and not e.get("label"):
            e["label"] = r["label"]
        # keep highest-detail register snapshot
        for f2 in ("ax", "ah", "al"):
            if r.get(f2) is not None and e.get(f2) is None:
                e[f2] = r[f2]

# ------------------------------------------------- WORK2 implemented set ------
def w2_done_services():
    r = subprocess.run([sys.executable, str(ROOT / "coordination" / "taskq.py"), "status"],
                       cwd=str(ROOT), capture_output=True, text=True)
    impl = set()
    for line in r.stdout.splitlines():
        m = re.match(r"^\s*W2-[0-9A-Za-z]+ +P\d+ +DONE", line)
        if not m: continue
        title = line.split("|", 1)[1].strip() if "|" in line else ""
        # Reconstruct each INT nN AH/AX=val service using the SAME service_key
        # as the inventory so keys match exactly.
        for mm in re.finditer(r"INT\s*(21|2F|31)h(?:\s*/)?\s*(AH|AX)=(0x)?([0-9A-Fa-f]+)", title):
            vec = int(mm.group(1), 16)
            prefix = mm.group(2)
            val = int(mm.group(4), 16)
            ah = ax = al = None
            if prefix == "AX":
                ax = val
                ah = (val >> 8) & 0xFF
                al = val & 0xFF
            else:
                ah = val
            key = service_key(vec, ax=ax, ah=ah, al=al)
            if key: impl.add(key)
            # also add the AH-only form so a 2Fh AH=15 impl covers AH=15
            ahkey = service_key(vec, ah=ah, ax=ax, al=al)
            if ahkey: impl.add(ahkey)
        # NOTE: no bare "AX=NNNN" rule -- "DOS services AX=6300/1500" in W2-039
        # are real-mode INT 21h/2Fh AX values, not DPMI INT 31h services. Genuine
        # DPMI services carry the explicit "INT 31h/AX=NNNN" prefix above.
        # "DOS version service" / explicit AH=30 -> INT 21h AH=30
        if "DOS version service" in title:
            impl.add(service_key(0x21, ah=0x30))
    # dos_service_contracts implemented list
    try:
        c = json.loads((ROOT / "evidence" / "dos_service_contracts.json").read_text(encoding="utf-8"))
        for s in c.get("implemented", []):
            for mm in re.finditer(r"INT\s*(21|2F|31)h\s*/\s*(AH|AX)=(0x)?([0-9A-Fa-f]+)", s):
                vec = int(mm.group(1), 16); prefix = mm.group(2); val = int(mm.group(4), 16)
                ah = ax = al = None
                if prefix == "AX":
                    ax = val; ah = (val >> 8) & 0xFF; al = val & 0xFF
                else:
                    ah = val
                key = service_key(vec, ax=ax, ah=ah, al=al)
                if key: impl.add(key)
    except Exception:
        pass
    return impl

impl = w2_done_services()
# also mark the AX=0300 real-mode bridge itself as implemented (W2-017)
impl.add("INT 31h AX=0300")

def status_for(key, e):
    # a service is IMPLEMENTED if an exact key or its AH-prefix is in impl
    if key in impl: return "IMPLEMENTED"
    prefix = key.split(" AL=")[0]
    if prefix in impl: return "IMPLEMENTED"
    # DPMI AX=0300 bridge is the dispatcher, not a pending leaf
    if key == "INT 31h AX=0300": return "IMPLEMENTED"
    return "PENDING"

for e in svc.values():
    e["status"] = status_for(e["key"], e)
    e["eips"] = sorted(e["eips"])
    e["traces"] = sorted(e["traces"])

# known DPMI AX=0300 is the bridge; the real-mode leaf it dispatches (INT 2Fh AX=1500)
# is the actual blocker. Flag it explicitly.
for e in svc.values():
    if e["key"].startswith("INT 2Fh AH=15") and e.get("first_eip") == 0x001d23a7:
        e["is_current_blocker"] = True

# ------------------------------------------------------------------ ordering ---
# Runtime frontier: among PENDING services, the one(s) at the max observed EIP
# is what the oracle actually stopped on (title-based PENDING can over/under-state
# vs runtime: e.g. INT 21h AH=63 is served in-trace, INT 31h AX=0600 is the stop).
max_eip = max((e["first_eip"] or 0) for e in svc.values() if e["first_eip"])
for e in svc.values():
    e["runtime_served"] = bool(e["first_eip"] and e["first_eip"] < max_eip)
    e["at_frontier"] = e["status"] == "PENDING" and e["first_eip"] == max_eip
frontier_keys = sorted(e["key"] for e in svc.values() if e.get("at_frontier"))

def vec_of(key):
    m = re.match(r"INT ([0-9A-Fa-f]{2})h", key)
    return int(m.group(1), 16) if m else 0xFF
order = sorted(svc.values(), key=lambda e: (vec_of(e["key"]), e["key"]))

# label-only observations (numeric AH/AX not captured, but a canonical service
# label is present) - listed separately, unclassified, as a capture-gap roadmap.
label_order = sorted(label_svc.values(), key=lambda e: (vec_of(e["key"]), e["key"]))
metrics = {
    "source": "evidence/*.json (all generated oracle traces)",
    "traces_scanned": len(files),
    "distinct_services": len(svc),
    "total_requests": sum(e["request_count"] for e in svc.values()),
    "implemented": sorted(k for k, e in svc.items() if e["status"] == "IMPLEMENTED"),
    "pending": sorted(k for k, e in svc.items() if e["status"] == "PENDING"),
    "label_only_services": sorted(label_svc.keys()),
    "label_only_note": "services observed with a canonical `service` label but no numeric AH/AX captured; unclassified, see label_services",
    "w2_implemented_set": sorted(impl),
    "current_blocker": "INT 2Fh AH=15 (real-mode INT 2Fh AX=1500) via DPMI AX=0300 at 0x001d23a7" if any(e.get("is_current_blocker") for e in svc.values()) else "not directly present in traces",
    "runtime_frontier_eip": hex(max_eip) if max_eip else None,
    "runtime_frontier_services": frontier_keys,
    "gate": "original-byte -k passes DPMI AX=0100, stops at real-mode INT 2Fh AX=1500; MENU not reached",
    "elapsed_seconds": round(time.time() - t0, 2),
}

OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
def _ser(e):
    d = dict(e)
    d["eips"] = sorted(e["eips"])
    d["traces"] = sorted(e["traces"])
    return d

OUT_JSON.write_text(json.dumps({"metrics": metrics,
                                "services": [_ser(e) for e in order],
                                "label_services": [_ser(e) for e in label_order]},
                               ensure_ascii=False, indent=2), encoding="utf-8")

# ------------------------------------------------------------------ report ----
md = ["# LOCAL: Real-mode / DPMI service inventory for the -k path to MENU (L-SVCINV)", ""]
md.append(f"Fuente: {len(files)} trazas en `evidence/*.json`. "
          f"**{metrics['total_requests']}** peticiones de servicio en **{len(svc)}** servicios distintos. "
          f"Cruzado contra los servicios que WORK2 ya implementa (títulos W2-* DONE + `dos_service_contracts.json`).")
md.append("")
md.append(f"Gate actual: {metrics['gate']}")
md.append("")
md.append(f"- Implementados: **{len(metrics['implemented'])}**")
md.append(f"- Pendientes: **{len(metrics['pending'])}**")
md.append(f"- Bloqueador actual: {metrics['current_blocker']}")
md.append("")
md.append("## PENDING -> a implementar para llegar a MENU (orden de vector)")
pend = [e for e in order if e["status"] == "PENDING"]
if not pend:
    md.append("(ninguno)")
for e in pend:
    blk = "  <-- BLOQUEADOR ACTUAL" if e.get("is_current_blocker") else ""
    eips = ", ".join(f"0x{a:08X}" for a in e["eips"][:3]) or "?"
    md.append(f"- `{e['key']}` — {e['request_count']} peticion(es), primera EIP {eips}, "
              f"trazas: {', '.join(e['traces'][:4])}{blk}")
md.append("")
md.append("## Implementados (no re-pedir)")
for e in [x for x in order if x["status"] == "IMPLEMENTED"]:
    eips = ", ".join(f"0x{a:08X}" for a in e["eips"][:2]) or "?"
    md.append(f"- `{e['key']}` — {e['request_count']} peticion(es), EIP {eips}")
md.append("")
md.append("## Observados por etiqueta (sin AH/AX numérico: hueco de captura, no clasificados)")
if label_order:
    for e in label_order:
        md.append(f"- `{e['key']}` — {e['request_count']} peticion(es)")
    md.append("")
    md.append("Estos servicios aparecen en las trazas con su etiqueta canónica (`service`) pero sin los "
              "registros AH/AX capturados. No se clasifican como implementados/pendientes: WORK2 debe "
              "extender la captura del oráculo (AH/AX/EIP por servicio) antes de tratarlos como pendientes. "
              "Probablemente incluyen servicios ya implementados que solo faltan ser re-leídos.")
else:
    md.append("(ninguno)")
md.append("")
md.append("## Notas para WORK2")
md.append("- El bloqueador es el servicio real-mode `INT 2Fh AX=1500` (AH=15h) servido a través del puente "
          "`DPMI AX=0300` (ya implementado, W2-017). Implementar AH=15h en el bridge real-mode desbloquea el "
          "siguiente avance hacia MENU.")
md.append(f"- Frontera runtime: EIP máx. observado = `{hex(max_eip) if max_eip else '?'}`. Servicios en la frontera: "
          f"{', '.join(frontier_keys) if frontier_keys else 'ninguno'}.")
# INT 21h AH=63: title says PENDING but the -k run serves it in-trace (EIP below frontier)
e63 = svc.get("INT 21h AH=63")
if e63 and e63.get("first_eip"):
    md.append(f"- `INT 21h AH=63` (Get/Set Segment Base) aparece como PENDING por título, pero el oráculo lo sirve "
              f"en-trace (EIP {hex(e63['first_eip'])} < frontera {hex(max_eip)}): NO re-implementar; ya cubierto por el "
              f"bridge/0300. Reconciliar el título de W2-039 con su estado real.")
# AX=0600 lock -> real-mode 2Fh AH=15 dependency chain
e600 = svc.get("INT 31h AX=0600")
if e600 and e600.get("first_eip") == max_eip:
    md.append("- Cadena de la frontera: `DPMI INT 31h AX=0600` (Lock Linear Region, implementado W2-045) se detiene en "
              "0x1d23a7 porque su backend real-mode exige `INT 2Fh AH=15` (AX=1500), que aún no se sirve. "
              "Implementar `INT 2Fh AH=15` en el bridge real-mode es el paso que mueve la frontera.")
# (AH?)/(AX?) buckets are capture gaps, not real services
gaps = [k for k in metrics["pending"] if "(AH?)" in k or "(AX?)" in k]
if gaps:
    md.append(f"- Buckets sin funcion (`{', '.join(sorted(set(g for g in gaps)))}`) son huecos de captura (vector sin "
              "AH/AX resuelto o EIP perdido), NO servicios faltantes reales. Confirmar con WORK3 antes de tratarlos "
              "como trabajo de implementación.")
md.append(f"- Conjunto implementado reconocido: {len(impl)} servicios.")
md.append("")
md.append(f"Generado por `tools/inventory_services.py` en {metrics['elapsed_seconds']}s.")
OUT_MD.parent.mkdir(parents=True, exist_ok=True)
OUT_MD.write_text("\n".join(md) + "\n", encoding="utf-8")

print(json.dumps(metrics, indent=2, ensure_ascii=False))
print(f"\nwrote {OUT_JSON.relative_to(ROOT)} and {OUT_MD.relative_to(ROOT)}")