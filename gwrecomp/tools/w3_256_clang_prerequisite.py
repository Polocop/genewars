from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(r"E:\GWRecomp")
PINNED_REVISION = "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f"
CLANG = Path(r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\Llvm\x64\bin\clang-cl.exe")
SOURCE = ROOT / "third_party/dosbox-staging-w3-059-instrumented"
BUILD = ROOT / "build/staging-w3-059-clang-base"
CACHE = BUILD / "CMakeCache.txt"
CONFIGURE_LOG = BUILD / "CMakeFiles/CMakeConfigureLog.yaml"
EXE = BUILD / "Debug/dosbox_with_debugger.exe"
OUT = ROOT / "evidence/w3_256_clang_prerequisite.json"
REPORT = ROOT / "reports/coordination/w3_256_clang_prerequisite.md"


def sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_cache(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        if line and not line.startswith("//") and not line.startswith("#") and "=" in line:
            left, value = line.split("=", 1)
            if ":" in left:
                key, _kind = left.split(":", 1)
                values[key] = value
    return values


def classify_toolchain(
    *, clang_exists: bool, configured_toolset: str | None, compiler_path_seen: bool,
    binary_exists: bool, configured_source_matches: bool
) -> str:
    if not clang_exists:
        return "CLANG_CL_MISSING"
    if configured_toolset == "ClangCL" and compiler_path_seen and binary_exists:
        if configured_source_matches:
            return "CLANGCL_CONFIGURED_CURRENT_SOURCE_BINARY_PRESENT_FRESHNESS_UNPROVEN"
        return "CLANGCL_READY_CACHE_POINTS_TO_DIFFERENT_SOURCE"
    return "CLANG_PRESENT_BUILD_CONFIGURATION_INCOMPLETE"


def audit() -> dict:
    cache_text = CACHE.read_text(encoding="utf-8", errors="replace") if CACHE.is_file() else ""
    cache = parse_cache(cache_text)
    log_text = CONFIGURE_LOG.read_text(encoding="utf-8", errors="replace") if CONFIGURE_LOG.is_file() else ""
    compiler_seen = str(CLANG).replace("\\", "\\\\").lower() in log_text.lower()
    version = None
    version_exit = None
    version_error = None
    if CLANG.is_file():
        try:
            proc = subprocess.run([str(CLANG), "--version"], capture_output=True, text=True, timeout=15, check=False)
            version = (proc.stdout + proc.stderr).strip()
            version_exit = proc.returncode
        except Exception as exc:  # recorded as evidence; do not turn an unavailable tool into success
            version_error = f"{type(exc).__name__}: {exc}"
    generator = cache.get("CMAKE_GENERATOR")
    toolset = cache.get("CMAKE_GENERATOR_TOOLSET")
    configured_source = cache.get("CMAKE_HOME_DIRECTORY")
    configured_source_matches = bool(configured_source) and Path(configured_source).resolve() == SOURCE.resolve()
    classification = classify_toolchain(
        clang_exists=CLANG.is_file(),
        configured_toolset=toolset,
        compiler_path_seen=compiler_seen,
        binary_exists=EXE.is_file(),
        configured_source_matches=configured_source_matches,
    )
    if classification == "CLANGCL_READY_CACHE_POINTS_TO_DIFFERENT_SOURCE":
        conclusion = (
            "The missing-clang-cl blocker is stale for the current host: the x64 clang-cl used by the dedicated CMake cache is present and reports a version. The cache points at a different source checkout than the pinned instrumented tree, so its existing executable cannot establish a build of the current instrumentation."
        )
    elif classification == "CLANGCL_CONFIGURED_CURRENT_SOURCE_BINARY_PRESENT_FRESHNESS_UNPROVEN":
        conclusion = (
            "ClangCL is present and configured for the pinned instrumented source, with an executable present. Its freshness against current modified sources is unproven, so do not claim that the current instrumentation builds."
        )
    else:
        conclusion = "The previous blocker is only partially reconciled; inspect the recorded paths/cache/log and do not claim a current-source build."
    dirty = subprocess.run(
        ["git", "-C", str(SOURCE), "status", "--short"], capture_output=True, text=True, timeout=15, check=False
    )
    head = subprocess.run(
        ["git", "-C", str(SOURCE), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=15, check=False
    )
    binary = None
    if EXE.is_file():
        stat = EXE.stat()
        binary = {
            "path": str(EXE),
            "size": stat.st_size,
            "mtime_local": __import__("datetime").datetime.fromtimestamp(stat.st_mtime).astimezone().isoformat(),
            "sha256": sha256(EXE),
            "freshness_vs_modified_sources": "UNPROVEN; binary predates some currently modified source files",
        }
    data = {
        "schema": "gwrecomp.w3-256-clang-prerequisite/v1",
        "task": "W3-256",
        "captured_at_utc": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        "pinned_revision": PINNED_REVISION,
        "source_checkout": {
            "path": str(SOURCE),
            "head": head.stdout.strip() if head.returncode == 0 else None,
            "head_matches_pinned": head.returncode == 0 and head.stdout.strip().lower() == PINNED_REVISION,
            "git_status_exit": dirty.returncode,
            "git_status_short": dirty.stdout.splitlines(),
        },
        "clang_cl": {
            "path": str(CLANG),
            "exists": CLANG.is_file(),
            "sha256": sha256(CLANG),
            "version_exit_code": version_exit,
            "version_output": version,
            "version_error": version_error,
        },
        "cmake_configuration": {
            "build_directory": str(BUILD),
            "cache_sha256": sha256(CACHE),
            "configure_log_sha256": sha256(CONFIGURE_LOG),
            "generator": generator,
            "generator_toolset": toolset,
            "source_directory": configured_source,
            "source_matches_instrumented_checkout": configured_source_matches,
            "clang_compiler_path_observed_in_configure_log": compiler_seen,
            "compiler_identity_from_log": str(CLANG) if compiler_seen else None,
        },
        "existing_binary": binary,
        "classification": classification,
        "old_w3_059_blocker": "Pinned Staging source instrumentation is blocked by missing clang-cl.",
        "conclusion": conclusion,
        "next_action": "Create a distinct clean ClangCL build directory configured from the pinned instrumented source checkout, reuse only validated installed dependencies, and do not overwrite or treat the existing binary as a current instrumentation build.",
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(
        "# W3-256 — revalidación del prerequisito Clang de W3-059\n\n"
        f"Clasificación: **{classification}**.\n\n"
        f"El `clang-cl` x64 que usa CMake existe en `{CLANG}`; `--version` terminó con código `{version_exit}`. "
        f"CMake usa `{generator}` y toolset `{toolset}`, pero el cache apunta a `{configured_source}` y coincide con el checkout instrumentado: `{configured_source_matches}`.\n\n"
        f"Hay un ejecutable de {binary['size'] if binary else 0} bytes con SHA-256 "
        f"`{binary['sha256'] if binary else 'missing'}`. Su actualidad frente a los fuentes modificados no está probada: el binario es anterior a algunos archivos modificados. "
        "Por tanto el prerequisito de instalación/configuración ya no falta, pero no se afirma que el estado actual de instrumentación haya compilado.\n\n"
        f"Evidencia estructurada: `{OUT}`. Revisión fijada: `{PINNED_REVISION}`.\n\n"
        "Siguiente acción concreta: tarea separada de build ClangCL acotado sobre el checkout fijado, tras revisar el build directory; no ejecutar DOSBox en esta comprobación.\n",
        encoding="utf-8",
    )
    return data


if __name__ == "__main__":
    print(json.dumps(audit(), indent=2, ensure_ascii=False))
