"""Evidence-only reconciliation of original A0000 writes and Runtime video."""
from __future__ import annotations
import os as _gw_os
from pathlib import Path as _GwPath
_GW_ROOT=str(_GwPath(__file__).resolve().parents[1])

import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path((_GW_ROOT))
INPUTS = {
    "w2_120": ROOT / "evidence/w2_120_screen_copy_runtime_audit.json",
    "w3_199": ROOT / "evidence/w3_199_ecd40_continuation.json",
    "w3_203": ROOT / "evidence/w3_203_bscreen_free_sample.json",
    "w3_234": ROOT / "evidence/w3_234_screen_copy_audit.json",
}
OUT = ROOT / "evidence/w3_260_a0000_video_mapping.json"
REPORT = ROOT / "reports/coordination/w3_260_a0000_video_mapping.md"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def trace_identity(evidence: dict[str, Any], path: Path) -> dict[str, Any]:
    if isinstance(evidence.get("trace"), dict):
        trace = evidence["trace"]
    elif isinstance(evidence.get("run", {}).get("trace"), dict):
        trace = evidence["run"]["trace"]
    else:
        trace = evidence["run"]
    expected_bytes = trace.get("bytes", trace.get("trace_bytes"))
    expected_hash = trace.get("sha256", trace.get("trace_sha256"))
    exists = path.is_file()
    actual_bytes = path.stat().st_size if exists else None
    actual_hash = sha256(path) if exists else None
    return {
        "path": str(path),
        "manifest_bytes": expected_bytes,
        "actual_bytes": actual_bytes,
        "manifest_sha256": expected_hash,
        "actual_sha256": actual_hash,
        "trace_matches_manifest": exists and actual_bytes == expected_bytes and actual_hash == expected_hash,
    }


def collect() -> dict[str, Any]:
    docs = {name: load_json(path) for name, path in INPUTS.items()}
    runtime_files = {
        "runtime/host_devices.py": docs["w2_120"]["source_sha256"]["runtime/host_devices.py"],
        "runtime/recomp_context.c": docs["w2_120"]["source_sha256"]["runtime/recomp_context.c"],
        "runtime/gw_segments.c": docs["w2_120"]["source_sha256"]["runtime/gw_segments.c"],
        "build/entry_path_closure.c": docs["w2_120"]["source_sha256"]["build/entry_path_closure.c"],
    }
    runtime_hash_checks = {
        name: {"expected_sha256": expected, "actual_sha256": sha256(ROOT / name),
               "matches": sha256(ROOT / name) == expected}
        for name, expected in runtime_files.items()
    }
    w199 = docs["w3_199"]
    w203 = docs["w3_203"]
    w234 = docs["w3_234"]
    w2 = docs["w2_120"]
    return {
        "schema": "gwrecomp-w3-260-a0000-video-mapping/v1",
        "task": "W3-260",
        "classification": "MAPPING_NOT_ESTABLISHED",
        "evidence_level": "ORIGINAL_OBSERVED_PLUS_STATIC_ONLY",
        "inputs": {
            name: {"path": str(path), "bytes": path.stat().st_size, "sha256": sha256(path)}
            for name, path in INPUTS.items()
        },
        "trace_integrity": {
            "w3_199": trace_identity(w199, ROOT / w199["trace"]["path"]),
            "w3_203": trace_identity(w203, ROOT / w203["trace"]["path"]),
            "w3_234": trace_identity(w234, ROOT / w234["run"]["trace"]),
        },
        "original_observed": {
            "fixture_sha256": w199["source"]["target_sha256"],
            "config_sha256": w199["source"]["config_sha256"],
            "cue_sha256": w199["source"]["cue_sha256"],
            "staging_revision": w199["source"]["staging_revision"],
            "w3_199": {
                "same_run_vesa_call_and_entry": w199["first_frame_limits"]["vesa_call_and_entry_observed"],
                "framebuffer_assignment_before_after": w199["first_frame_limits"]["framebuffer_assignment_before_after_observed"],
                "b_screen_allocation_pointer": w199["first_frame_limits"]["b_screen_allocation_pointer_observed"],
                "b_screen_allocation_bytes": w199["first_frame_limits"]["b_screen_allocation_bytes"],
                "pixel_payload_or_visible_frame_proven": w199["first_frame_limits"]["pixel_payload_or_visible_frame_proven"],
                "guard_cause": w199["guard"]["cause"],
                "guard_timeout_s": w199["guard"]["limits"]["timeout_s"],
            },
            "w3_203": {
                "allocation_bytes": int(w203["capture_conclusion"]["allocation_size_bytes"], 16),
                "pointer": w203["capture_conclusion"]["allocation_pointer"],
                "free_count": w203["b_screen_free_sample"]["free_count"],
                "sample_bytes": w203["b_screen_free_sample"]["sample_bytes"],
                "nonzero_bytes": w203["b_screen_free_sample"]["nonzero_bytes"],
                "guard_cause": w203["guard"]["cause"],
                "guard_timeout_s": w203["guard"]["limits"]["timeout_s"],
            },
            "w3_234": {
                "evidence_level": w234["evidence_level"],
                "same_run_id": w234["run"]["run_id"],
                "link_va": w234["copy"]["pre"]["link_va"],
                "destination": w234["copy"]["pre"]["edi_destination"],
                "bytes_copied": w234["copy"]["pre"]["copy_bytes_from_count"],
                "branch_vesa_state": w234["copy"]["branch"]["vesa_state"],
                "postcopy_sample_bytes": w234["copy"]["post"]["sample_bytes"],
                "postcopy_sample_all_zero": w234["copy"]["post"]["sample_all_zero"],
                "flat_descriptors_and_bounds_valid": (
                    w234["copy"]["checks"]["valid_descriptors"] and
                    w234["copy"]["checks"]["valid_bounds"]),
                "first_framebuffer_verified": w234["first_framebuffer_verified"],
            },
        },
        "runtime_static_only": {
            "evidence_level": w2["evidence_levels"]["code"],
            "memory_translation": w2["memory"]["host_pointer_translation"],
            "generated_copy": w2["generated"],
            "video_sink": w2["video_sink"],
            "guest_a0000_to_display_mapping_proven": w2["conclusion"]["guest_A0000_to_display_mapping_proven"],
            "runtime_modified_by_w2_120": w2["runtime_modified"],
            "source_hash_checks": runtime_hash_checks,
        },
        "conclusion": {
            "guest_memory_copy_to_A0000_original_observed": w234["copy"]["pre"]["edi_destination"] == "0x000A0000",
            "vesa_and_framebuffer_assignment_original_observed": (
                w199["first_frame_limits"]["vesa_call_and_entry_observed"] and
                w199["first_frame_limits"]["framebuffer_assignment_before_after_observed"]),
            "guest_A0000_to_host_surface_mapping_established": False,
            "validated_frame_presented": False,
            "first_framebuffer_verified": False,
            "menu_verified": False,
            "gameplay_verified": False,
            "missing_contract": [
                "guest physical/linear A0000 address routing into a host video surface",
                "mode and page selection that establishes the active guest framebuffer range",
                "palette interpretation and conversion into the host video sink",
                "the source-backed condition that calls the host present operation with a validated frame",
            ],
        },
        "provenance_limits": [
            "W3-199, W3-203, and W3-234 are original Staging observations from separate runs; their events are not one same-run causal sequence.",
            "W3-234 proves a 64,000-byte memory copy to guest linear destination 0xA0000 and only a 16-byte all-zero destination sample.",
            "W3-203 proves a 64-byte all-zero B_SCREEN pre-free sample, not pixels.",
            "W2-120 is STATIC_CODE_REVIEW plus a regression test; it did not alter Runtime or establish a displayed frame.",
        ],
        "test": {"result": "PENDING"},
    }


def validate(data: dict[str, Any]) -> list[str]:
    errors = []
    if data.get("classification") != "MAPPING_NOT_ESTABLISHED":
        errors.append("mapping classification is not conservative")
    if data["conclusion"]["guest_A0000_to_host_surface_mapping_established"]:
        errors.append("unsupported host display mapping claim")
    if data["conclusion"]["validated_frame_presented"] or data["conclusion"]["first_framebuffer_verified"]:
        errors.append("unsupported visible-frame claim")
    for name, info in data["trace_integrity"].items():
        if not info["trace_matches_manifest"]:
            errors.append(f"{name} trace does not match manifest")
    for name, info in data["runtime_static_only"]["source_hash_checks"].items():
        if not info["matches"]:
            errors.append(f"Runtime source drift: {name}")
    if data["original_observed"]["w3_234"]["bytes_copied"] != 64000:
        errors.append("W3-234 measured copy size mismatch")
    if data["original_observed"]["w3_234"]["destination"] != "0x000A0000":
        errors.append("W3-234 measured destination mismatch")
    if data["original_observed"]["w3_203"]["sample_bytes"] != 64:
        errors.append("W3-203 sample cap mismatch")
    if data["original_observed"]["w3_199"]["guard_timeout_s"] != 30:
        errors.append("W3-199 guard limit mismatch")
    return errors


def write() -> dict[str, Any]:
    data = collect()
    errors = validate(data)
    data["validation_errors"] = errors
    data["test"] = {"result": "PASS" if not errors else "FAIL"}
    OUT.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    REPORT.write_text(
        "# W3-260 — conciliación del destino A0000 con la superficie de Runtime\n\n"
        f"Resultado: **{data['classification']}**. No se ejecutó DOSBox ni se modificó Runtime.\n\n"
        "## Original observado\n\n"
        "W3-199 observó llamadas/entradas VESA, asignación del framebuffer y un bloque B_SCREEN de "
        "307,200 bytes en una ejecución original. W3-203 capturó 64 bytes antes del free de B_SCREEN; "
        "los 64 eran cero. W3-234 observó otra ejecución original que copió 64,000 bytes a la "
        "dirección guest 0xA0000; el muestreo post-copy de 16 bytes también era cero. Las trazas "
        "son de ejecuciones separadas y no acreditan un frame visible.\n\n"
        "## Revisión estática del Runtime\n\n"
        "W2-120 registra que el código generado conserva la aritmética del REP MOVSD con validación "
        "de DS/ES y memmove hacia la memoria guest. La traducción de punteros usa guest linear + "
        "g_mem_base. IndexedVideo mantiene una bytearray aparte y ofrece write_pixels/present; la "
        "revisión no encontró un puente desde A0000 o g_mem_base a esa superficie. Los hashes de "
        "los cuatro archivos revisados coinciden con W2-120.\n\n"
        "## Conclusión\n\n"
        "Está medido que GeneWars copia datos a A0000 y que existe una ruta original de setup VESA/"
        "framebuffer. **No está demostrado** cómo se dirige esa memoria a una superficie host, qué "
        "modo/página/paleta interpreta el Runtime, ni cuándo presenta un frame validado. El primer "
        "framebuffer visible, el menú y gameplay siguen pendientes.\n\n"
        f"Validación: {'PASS' if not errors else 'FAIL'}; errores: {errors}. "
        f"Evidencia: {OUT}.\n",
        encoding="utf-8")
    return data


if __name__ == "__main__":
    result = write()
    print(json.dumps({"evidence": str(OUT), "classification": result["classification"],
                      "validation_errors": result["validation_errors"]}, indent=2))
