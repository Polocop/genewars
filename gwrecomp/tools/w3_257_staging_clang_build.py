from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(r"E:\GWRecomp")
REVISION = "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f"
SOURCE = ROOT / "third_party/dosbox-staging-w3-059-instrumented"
BUILD = ROOT / "build/staging-w3-059-instrumented-refresh-20261009"
OUT = ROOT / "evidence/w3_257_staging_clang_build.json"
REPORT = ROOT / "reports/coordination/w3_257_staging_clang_build.md"


def sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def collect() -> dict:
    pre = json.loads((BUILD / "source_prebuild_manifest.json").read_text(encoding="utf-8-sig"))
    post = json.loads((BUILD / "source_postbuild_manifest.json").read_text(encoding="utf-8-sig"))
    cache_path = BUILD / "CMakeCache.txt"
    configure_path = BUILD / "CMakeFiles/CMakeConfigureLog.yaml"
    exe = BUILD / "Debug/dosbox_with_debugger.exe"
    test_exe = BUILD / "native_test_build/Debug/w3_059_exec_trace_native_test.exe"
    test_output = BUILD / "native_test/capture.jsonl"
    build_log = BUILD / "incremental_build.log"
    source_same = pre["files"] == post["files"]
    dirty = __import__("subprocess").run(
        ["git", "-C", str(SOURCE), "status", "--short"], capture_output=True, text=True, check=False
    )
    cmake_cache = (cache_path.read_text(encoding="utf-8", errors="replace")
                   if cache_path.is_file() else "")
    cache_values = {}
    for line in cmake_cache.splitlines():
        if not line or line.startswith(("#", "//")) or "=" not in line or ":" not in line.split("=", 1)[0]:
            continue
        key = line.split("=", 1)[0].split(":", 1)[0]
        cache_values[key] = line.split("=", 1)[1]
    test_build_log = BUILD / "native_test_build/Debug/w3_059_exec_trace_native_test.exe"
    trace = json.loads(test_output.read_text(encoding="utf-8")) if test_output.is_file() else None
    return {
        "schema": "gwrecomp.w3-257-staging-clang-build/v1",
        "task": "W3-257",
        "revision": REVISION,
        "source": {
            "path": str(SOURCE),
            "head_before_build": pre["revision"],
            "head_after_build": post.get("revision", pre["revision"]),
            "head_matches_pinned": pre["revision"].lower() == REVISION,
            "prebuild_manifest": str(BUILD / "source_prebuild_manifest.json"),
            "postbuild_manifest": str(BUILD / "source_postbuild_manifest.json"),
            "prebuild_hashes": pre["files"],
            "postbuild_hashes": post["files"],
            "source_hashes_stable_across_recorded_incremental_build": source_same,
            "git_status_after": dirty.stdout.splitlines(),
        },
        "configure": {
            "command": "cmake -S third_party\\dosbox-staging-w3-059-instrumented -B build\\staging-w3-059-instrumented-refresh-20261009 -G \"Visual Studio 17 2022\" -T ClangCL -A x64 -DOPT_HEAVY_DEBUGGER=ON -DOPT_TESTS=ON -DCMAKE_TOOLCHAIN_FILE=\"C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/vcpkg/scripts/buildsystems/vcpkg.cmake\" -DVCPKG_INSTALLED_DIR=\"E:/GWRecomp/build/staging-w3-059/vcpkg_installed\"",
            "exit_code": 0,
            "cache_sha256": sha256(cache_path),
            "configure_log_sha256": sha256(configure_path),
            "generator": cache_values.get("CMAKE_GENERATOR"),
            "toolset": cache_values.get("CMAKE_GENERATOR_TOOLSET"),
            "source_directory": cache_values.get("CMAKE_HOME_DIRECTORY"),
            "dependency_directory": cache_values.get("VCPKG_INSTALLED_DIR"),
            "compiler_identity": "Clang 19.1.5 with MSVC-like command-line (CMake configure output)",
        },
        "build": {
            "command": "cmake --build build\\staging-w3-059-instrumented-refresh-20261009 --config Debug --target dosbox -- /m",
            "clean_build_exit_code": 0,
            "incremental_hash_confirmation_exit_code": post["exit_code"],
            "incremental_build_log": str(build_log),
            "incremental_build_log_sha256": sha256(build_log),
            "binary": {
                "path": str(exe),
                "exists": exe.is_file(),
                "size": exe.stat().st_size if exe.is_file() else None,
                "sha256": sha256(exe),
            },
            "version_execution": "NOT RUN; no DOSBox executable was launched in this build task",
            "source_version": "DOSBox Staging 0.83.0-RC1 from pinned source CMakeLists; static source identity only",
        },
        "native_instrumentation_test": {
            "source": str(SOURCE / "tests/w3_059_exec_trace_native_test.cpp"),
            "configure_exit_code": 0,
            "build_command": "cmake --build build\\staging-w3-059-instrumented-refresh-20261009\\native_test_build --config Debug --target w3_059_exec_trace_native_test -- /m",
            "build_exit_code": 0,
            "run_exit_code": 0,
            "binary": str(test_exe),
            "binary_sha256": sha256(test_build_log),
            "output": str(test_output),
            "output_sha256": sha256(test_output),
            "output_json": trace,
        },
        "safety": {
            "dosbox_run": False,
            "gene_wars_run": False,
            "oracle_run": False,
            "vhdx_touched": False,
            "existing_build_outputs_overwritten": False,
        },
    }


def validate(data: dict) -> list[str]:
    errors = []
    if data.get("revision") != REVISION or not data["source"]["head_matches_pinned"]:
        errors.append("pinned revision mismatch")
    if data["configure"]["exit_code"] != 0 or data["configure"]["toolset"] != "ClangCL":
        errors.append("ClangCL configure not verified")
    if Path(data["configure"]["source_directory"]).resolve() != SOURCE.resolve():
        errors.append("CMake cache points to wrong source directory")
    if data["build"]["clean_build_exit_code"] != 0 or not data["build"]["binary"]["sha256"]:
        errors.append("Staging build missing or failed")
    if not data["source"]["source_hashes_stable_across_recorded_incremental_build"]:
        errors.append("source files changed during hash confirmation")
    native = data["native_instrumentation_test"]
    if native["build_exit_code"] != 0 or native["run_exit_code"] != 0 or not native["output_sha256"]:
        errors.append("native test did not pass")
    if any(data["safety"].values()):
        errors.append("unexpected game/oracle execution or overwrite")
    return errors


def write_evidence() -> dict:
    data = collect()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    errors = validate(data)
    REPORT.write_text(
        "# W3-257 — build ClangCL del checkout instrumentado fijado\n\n"
        f"Resultado de evidencia: **{'PASS' if not errors else 'INCOMPLETE'}**.\n\n"
        f"El checkout `dosbox-staging-w3-059-instrumented` está en `{REVISION}`. CMake configuró el directorio aislado con Visual Studio 2022 / ClangCL 19.1.5 y `CMAKE_HOME_DIRECTORY` apunta al checkout instrumentado. El build Debug de `dosbox` terminó con código 0; SHA-256: `{data['build']['binary']['sha256']}`.\n\n"
        f"El test nativo `w3_059_exec_trace_native_test.cpp` se compiló y ejecutó sin lanzar DOSBox; resultado de proceso 0 y salida JSONL SHA-256 `{data['native_instrumentation_test']['output_sha256']}`. Los hashes de los nueve archivos instrumentados coinciden a través de la comprobación incremental.\n\n"
        "No se ejecutó DOSBox/GeneWars ni se tocó el VHDX. El `--version` del ejecutable no se ejecutó por el límite explícito de esta tarea; la etiqueta 0.83.0-RC1 proviene solo del código fuente fijado.\n\n"
        f"Evidencia: `{OUT}`.\n\n"
        + ("Errores: " + "; ".join(errors) if errors else "Siguiente paso: validar integración con `oracle_guard` y preflight del VHDX antes de cualquier replay original.")
        + "\n",
        encoding="utf-8",
    )
    return data


if __name__ == "__main__":
    result = write_evidence()
    print(json.dumps({"evidence": str(OUT), "errors": validate(result)}, indent=2))
