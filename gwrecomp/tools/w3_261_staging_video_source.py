from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STAGING = ROOT / "third_party/dosbox-staging-w3-059-instrumented"
EXPECTED_COMMIT = "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f"
OUTPUT = ROOT / "evidence/w3_261_staging_video_source.json"
REPORT = ROOT / "reports/coordination/w3_261_staging_video_source.md"

FILES = {
    "mode_table": "src/ints/int10_modes.cpp",
    "int10_dispatch": "src/ints/int10.cpp",
    "vesa": "src/ints/int10_vesa.cpp",
    "vga_header": "src/hardware/video/vga.h",
    "vga_memory": "src/hardware/video/vga_memory.cpp",
    "vga_draw": "src/hardware/video/vga_draw.cpp",
    "vga_dac": "src/hardware/video/vga_dac.cpp",
    "render": "src/gui/render/render.cpp",
    "sdl_gui": "src/gui/sdl_gui.cpp",
    "sdl_renderer": "src/gui/render/sdl_renderer.cpp",
}

ANCHORS = {
    "mode_table": "{ 0x101,  M_LIN8,  640,  480",
    "int10_dispatch": "case 0x02:",
    "vesa": "uint8_t VESA_SetCPUWindow(uint8_t window, uint8_t address)",
    "vga_header": "#define VGA_LFB_MAPPED",
    "vga_memory": "class VGA_Map_Handler final : public PageHandler",
    "vga_draw": "PixelFormat VGA_ActivateHardwareCursor()",
    "vga_dac": "void VGA_DAC_SetEntry",
    "render": "void RENDER_EndUpdate",
    "sdl_gui": "void GFX_MaybePresentFrame()",
    "sdl_renderer": "void SdlRenderer::PresentFrame()",
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git(*args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(STAGING), *args], text=True, encoding="utf-8"
    ).strip()


def collect() -> dict:
    commit = git("rev-parse", "HEAD")
    sources = {}
    anchors = {}
    for key, relative in FILES.items():
        path = STAGING / relative
        raw = path.read_bytes()
        text = raw.decode("utf-8")
        blob = subprocess.check_output(
            ["git", "-C", str(STAGING), "show", f"HEAD:{relative}"]
        )
        source_sha = sha256_bytes(raw)
        normalized_sha = sha256_bytes(raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n"))
        head_sha = sha256_bytes(blob)
        lines = text.splitlines()
        anchor = ANCHORS[key]
        hits = [index + 1 for index, line in enumerate(lines) if anchor in line]
        sources[key] = {
            "path": relative.replace("/", "\\"),
            "working_tree_sha256_raw": source_sha,
            "working_tree_sha256_lf_normalized": normalized_sha,
            "head_blob_sha256": head_sha,
            "matches_pinned_head": normalized_sha == head_sha,
            "anchor": anchor,
            "anchor_lines": hits,
        }
        anchors[key] = bool(hits)

    return {
        "schema": "gwrecomp-w3-261-staging-video-source/v1",
        "task": "W3-261",
        "classification": "SOURCE_PATH_IDENTIFIED_DYNAMIC_MODE_STATE_NOT_FULLY_PROVEN",
        "evidence_levels": ["ORIGINAL_OBSERVED", "STATIC_ONLY", "INFERENCE"],
        "source": {
            "revision": commit,
            "expected_revision": EXPECTED_COMMIT,
            "revision_matches": commit == EXPECTED_COMMIT,
            "files": sources,
        },
        "source_findings": {
            "mode_101_table": {
                "evidence_level": "STATIC_ONLY",
                "semantics": "640x480 M_LIN8, mode table video base 0xA0000, 64KiB window",
                "source": "src/ints/int10_modes.cpp",
                "line": sources["mode_table"]["anchor_lines"][0] if anchors["mode_table"] else None,
            },
            "vesa_window": {
                "evidence_level": "STATIC_ONLY",
                "semantics": "VESA CPU window 0 accepts bank addresses within vmemsize and programs VGA CRTC index 0x6A; unsupported window numbers fail.",
                "source": "src/ints/int10_vesa.cpp",
                "line": sources["vesa"]["anchor_lines"][0] if anchors["vesa"] else None,
            },
            "a0000_memory_route": {
                "evidence_level": "STATIC_ONLY_WITH_RUNTIME_CONDITION",
                "semantics": "VGA_SetupHandlers selects the A000 page handler from current VGA mode and graphics-controller memory-map bits. The mapped handler's writes address vga.mem.linear with bank offset and video-memory wrapping. Thus A0000 is a guest aperture into VGA backing when that runtime mapping is active; the mapping state is not present in W3-260 captures.",
                "source": "src/hardware/video/vga_memory.cpp",
                "lines": [581, 597, 644, 963, 1020, 1068, 1081],
            },
            "vesa_lfb_distinction": {
                "evidence_level": "STATIC_ONLY",
                "semantics": "A separate linear-framebuffer mapping exists and is installed at the configured LFB page; its existence does not prove GeneWars requested or used it. A0000 banked aperture and VESA LFB must not be conflated.",
                "source": "src/hardware/video/vga_memory.cpp",
                "lines": [799, 804, 1111, 1119],
            },
            "mode_101_scanout": {
                "evidence_level": "STATIC_ONLY_WITH_RUNTIME_CONDITION",
                "semantics": "M_LIN8 scanout uses VGA video memory as the source base; indexed pixel values are looked up through the DAC palette and converted to host BGRX output. Dynamic display-start, page, memory-map and DAC values remain unmeasured.",
                "sources": ["src/hardware/video/vga_draw.cpp", "src/hardware/video/vga_dac.cpp"],
                "lines": [1497, 1687, 1708, 1719, 2373, 2426],
            },
            "frame_and_present": {
                "evidence_level": "STATIC_ONLY",
                "semantics": "After scheduled scanline drawing completes, VGA calls RENDER_EndUpdate. That ends the renderer update; SDL presentation occurs only through GFX_MaybePresentFrame when the renderer is active and the presentation timing/capture condition is met (with host-rate presentation handled later). This source path is not evidence that the game produced nonzero pixels or that a particular frame was presented.",
                "sources": ["src/hardware/video/vga_draw.cpp", "src/gui/render/render.cpp", "src/gui/sdl_gui.cpp", "src/gui/render/sdl_renderer.cpp"],
                "lines": [1251, 1254, 351, 368, 1170, 1188, 1220, 2468, 2487, 2489, 2491, 347, 363],
            },
        },
        "original_observations_from_w3_260": {
            "evidence_level": "ORIGINAL_OBSERVED",
            "mode_entry_101": True,
            "game_global_assigned_a0000": True,
            "copy_to_guest_linear_a0000_bytes": 64000,
            "postcopy_sample": {"bytes": 16, "all_zero": True},
            "page_set_or_current_display_start": "NOT_CAPTURED",
            "current_gfx_memory_map_bits": "NOT_CAPTURED",
            "dac_palette_contents": "NOT_CAPTURED",
            "presented_nonzero_frame": False,
            "source_evidence": "evidence/w3_260_a0000_video_mapping.json",
        },
        "conclusion": {
            "source_path_explains_candidate_mapping": True,
            "dynamic_a0000_handler_for_gene_wars_proven": False,
            "dynamic_page_and_palette_proven": False,
            "first_framebuffer_verified": False,
            "menu_verified": False,
            "gameplay_verified": False,
            "missing_dynamic_evidence": [
                "actual graphics-controller memory map and selected A0000 handler at the copy",
                "bank/window and display-start/page state for the copied region",
                "nonzero framebuffer payload and active DAC palette",
                "same-run completion of frame drawing and host PresentFrame",
            ],
        },
        "validation": {"revision_matches": commit == EXPECTED_COMMIT, "all_source_files_match_head": all(value["matches_pinned_head"] for value in sources.values()), "all_anchors_found": all(anchors.values())},
    }


def render_report(data: dict) -> str:
    hashes = data["source"]["files"]
    lines = [
        "# W3-261 — ruta de memoria VGA y presentación en DOSBox Staging",
        "",
        f"Revisión verificada: `{data['source']['revision']}`. Evidencia: fuente estática de esa revisión más observaciones originales ya registradas en W3-260. No se ejecutó DOSBox ni se compiló.",
        "",
        "## Lo que establece el código fuente",
        "",
        "- El modo VESA 101h está declarado como 640×480, `M_LIN8`, con base de ventana `0xA0000` y tamaño de ventana de 64 KiB.",
        "- El mapeo de `A0000` depende del modo VGA y de los bits del mapa de memoria del controlador gráfico. El handler de ventana bancaria indexa la memoria de vídeo interna (`vga.mem.linear`), aplicando offset de banco y wrap. Una ruta VESA LFB aparte existe; no es sinónimo de la ventana `A0000`.",
        "- Para `M_LIN8`, el dibujado obtiene píxeles de la memoria VGA y usa la LUT DAC para convertir índices de paleta a salida host BGRX. La paleta y el estado de página/display-start deben medirse en ejecución.",
        "- El callback de dibujado completa el frame tras sus scanlines y llama `RENDER_EndUpdate`. El present SDL depende además de que el renderer esté activo y se cumpla la condición temporal de presentación, o la ruta host-rate posterior.",
        "",
        "## Lo observado en GeneWars",
        "",
        "W3-260 observó una entrada al modo 101h, el global del juego apuntando a `0xA0000` y un `REP MOVSD` de 64.000 bytes hacia esa dirección guest. El muestreo post-copy fue de 16 bytes y todos eran cero. Esas capturas no contienen el estado del mapa VGA, banco, display-start, paleta, ni una llamada de presentación en la misma secuencia causal.",
        "",
        "## Estado",
        "",
        "La fuente explica una ruta plausible entre la ventana guest A0000, la memoria VGA y el convertidor/present del emulador, con condiciones de runtime explícitas. No demuestra que el handler/página/paleta correctos estuvieran activos durante la copia observada, ni que existiera contenido visible. Primer framebuffer, menú y gameplay siguen pendientes.",
        "",
        "## Procedencia",
        "",
        "Los archivos inspeccionados coinciden con sus blobs del HEAD tras normalizar finales de línea CRLF/LF. El checkout también contiene cambios de instrumentación en otras rutas; las rutas de vídeo enumeradas no aparecen como modificadas en el estado de Git.",
        "",
    ]
    for key, item in hashes.items():
        lines.append(f"- `{item['path']}` — raw SHA-256 `{item['working_tree_sha256_raw']}`; LF-normalized SHA-256 `{item['working_tree_sha256_lf_normalized']}`; pinned blob match: `{item['matches_pinned_head']}`.")
    return "\n".join(lines) + "\n"


def write_outputs(data: dict) -> None:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    REPORT.write_text(render_report(data), encoding="utf-8")


def main() -> int:
    data = collect()
    write_outputs(data)
    print(json.dumps({"validation": data["validation"], "evidence": str(OUTPUT), "report": str(REPORT)}, ensure_ascii=False))
    return 0 if all(data["validation"].values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
