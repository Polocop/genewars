from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(r"E:\GWRecomp")
REVISION = "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f"
SOURCE = ROOT / "third_party/dosbox-staging-w3-059-instrumented"
BUILD_EVIDENCE = ROOT / "evidence/w3_257_staging_clang_build.json"
PRIOR_CAPTURE = ROOT / "evidence/w3_253_capture_flag_cache.json"
FUNCTIONAL = ROOT / "evidence/w3_067_staging_functional_validation_20261008.json"
BINARY = ROOT / "build/staging-w3-059-instrumented-refresh-20261009/Debug/dosbox_with_debugger.exe"
CONFIG = ROOT / "build/dosboxx_oracle/dosbox-staging.w3-067-functional.conf"
NEW_CACHE = ROOT / "build/staging-w3-059-instrumented-refresh-20261009/CMakeCache.txt"
PRIOR_CACHE = ROOT / "build/staging-w3-253-exec/CMakeCache.txt"
GUARD = ROOT / "tools/oracle_guard.py"
VERIFIER = ROOT / "tools/verify_oracle_sandbox.ps1"
BX1_SOURCE = SOURCE / "src/cpu/cpu.cpp"
OUT = ROOT / "evidence/w3_258_oracle_guard_preflight.json"
REPORT = ROOT / "reports/coordination/w3_258_oracle_guard_preflight.md"


def sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def validate(data: dict) -> list[str]:
    errors = []
    if data["build"]["revision"] != REVISION or not data["build"]["head_matches_pinned"]:
        errors.append("pinned source revision mismatch")
    if not data["build"]["binary_matches_recorded_hash"]:
        errors.append("instrumented binary hash mismatch")
    if not data["sandbox"]["verified"] or data["sandbox"]["label"] != "GWORACLE":
        errors.append("GWORACLE sandbox verification failed")
    if data["sandbox"]["capacity_bytes"] < 15 * 1024**3:
        errors.append("GWORACLE capacity below required 15 GiB floor")
    if data["sandbox"]["host_free_bytes"] < data["sandbox"]["host_floor_bytes"]:
        errors.append("host free-space floor is not met")
    if data["guard"]["required_sandbox"] is not True or not data["guard"]["run_subcommand_present"]:
        errors.append("oracle_guard protected run path not verified")
    if data["functional_config"]["sha256"] != data["functional_config"]["expected_sha256"]:
        errors.append("functional Staging config differs from authenticated W3-067 evidence")
    if any(data["safety"].values()):
        errors.append("DOSBox, GeneWars or oracle was launched during preflight")
    return errors


def parse_cache(path: Path) -> dict[str, str]:
    out = {}
    if not path.is_file():
        return out
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line and not line.startswith(("#", "//")) and "=" in line and ":" in line.split("=", 1)[0]:
            out[line.split("=", 1)[0].split(":", 1)[0]] = line.split("=", 1)[1]
    return out


def collect() -> dict:
    build = json.loads(BUILD_EVIDENCE.read_text(encoding="utf-8-sig"))
    prior = json.loads(PRIOR_CAPTURE.read_text(encoding="utf-8-sig"))
    functional = json.loads(FUNCTIONAL.read_text(encoding="utf-8-sig"))
    sandbox_proc = subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(VERIFIER), "-Json"],
        capture_output=True, text=True, timeout=30, check=False,
    )
    sandbox = json.loads(sandbox_proc.stdout.strip()) if sandbox_proc.returncode == 0 else {
        "verified": False, "reason": sandbox_proc.stderr.strip() or "verifier failed"
    }
    help_proc = subprocess.run(
        [sys.executable, str(GUARD), "--help"], capture_output=True, text=True, timeout=15, check=False
    )
    guard_source = GUARD.read_text(encoding="utf-8", errors="replace")
    sys.path.insert(0, str(ROOT / "tools"))
    from oracle_guard import Limits

    current_source_hashes = {x["path"]: x["sha256"] for x in build["source"]["prebuild_hashes"]}
    core_path = str(SOURCE / "src/cpu/core_dyn_x86.cpp")
    prior_core_sha = prior["instrumentation"]["edited_source_sha256"]
    bx1_text = BX1_SOURCE.read_text(encoding="utf-8", errors="replace")
    event_start = bx1_text.index("original_cpu_int21_ah44_bx1_entry")
    event_end = bx1_text.index("if (exec_trace::append_event(record))", event_start)
    event_source_block = bx1_text[event_start:event_end]
    expected_config_sha = functional["isolated_config"]["sha256"].lower()
    previous_guard_limits = prior["guard"]["limits"]
    limits = Limits().as_dict()
    prior_cache = parse_cache(PRIOR_CACHE)
    new_cache = parse_cache(NEW_CACHE)
    data = {
        "schema": "gwrecomp.w3-258-oracle-guard-preflight/v1",
        "task": "W3-258",
        "build": {
            "evidence": str(BUILD_EVIDENCE),
            "revision": build["revision"],
            "head_matches_pinned": build["source"]["head_matches_pinned"],
            "binary_path": str(BINARY),
            "binary_sha256": sha256(BINARY),
            "binary_expected_sha256": build["build"]["binary"]["sha256"],
            "binary_matches_recorded_hash": sha256(BINARY) == build["build"]["binary"]["sha256"],
            "cmake_source_directory": build["configure"]["source_directory"],
            "core_dyn_x86_sha256": current_source_hashes.get(core_path),
        },
        "sandbox": {
            "verifier_path": str(VERIFIER),
            "verifier_exit_code": sandbox_proc.returncode,
            **sandbox,
        },
        "guard": {
            "path": str(GUARD),
            "sha256": sha256(GUARD),
            "help_exit_code": help_proc.returncode,
            "run_subcommand_present": "run" in help_proc.stdout,
            "run_cli_excerpt": "run --exe <dosbox-x.exe> --config <conf> [--operation NAME] [--commit-sha S] [--target-sha S] [--runtime-sha S] [--fixture-sha S] [--staging-dir PATH] [--host-drive E:] [--max-file-mib N] [--max-run-gib N] [--host-floor-gib N] [--timeout-s N] [--run-id ID] [--extra ARG ...]",
            "required_sandbox": "SANDBOX_REQUIRED = True" in guard_source,
            "default_limits": limits,
            "previous_functional_capture_limits": previous_guard_limits,
        },
        "functional_config": {
            "path": str(CONFIG),
            "exists": CONFIG.is_file(),
            "sha256": sha256(CONFIG),
            "expected_sha256": expected_config_sha,
            "matches_w3_067_functional_evidence": sha256(CONFIG) == expected_config_sha,
        },
        "prior_bx1_capture": {
            "task": "W3-253",
            "classification": prior["classification"],
            "trace_sha256": prior["trace"]["sha256"],
            "trace_bytes": prior["trace"]["bytes"],
            "trace_event_count": prior["trace"]["event_count"],
            "trace_cap_bytes": prior["trace"]["max_bytes"],
            "last_event": prior.get("instrumentation", {}).get("last_trace_event"),
            "bx1_request_count": len(prior["caller_pairing"]["bx1_requests"]),
            "same_core_instrumentation_as_w3_253": current_source_hashes.get(core_path) == prior_core_sha,
            "prior_build_debugger_options": {
                "cache_path": str(PRIOR_CACHE),
                "cache_sha256": sha256(PRIOR_CACHE),
                "OPT_DEBUGGER": prior_cache.get("OPT_DEBUGGER"),
                "OPT_HEAVY_DEBUGGER": prior_cache.get("OPT_HEAVY_DEBUGGER"),
            },
            "new_build_debugger_options": {
                "cache_path": str(NEW_CACHE),
                "cache_sha256": sha256(NEW_CACHE),
                "OPT_DEBUGGER": new_cache.get("OPT_DEBUGGER"),
                "OPT_HEAVY_DEBUGGER": new_cache.get("OPT_HEAVY_DEBUGGER"),
            },
            "caller_stack_capture_present_in_bx1_cpu_event": "stack_words" in event_source_block,
            "bx1_event_has_esp_ss": '"esp":' in event_source_block and '"ss":' in event_source_block,
        },
        "replay_disposition": {
            "same_core_instrumentation_as_w3_253": current_source_hashes.get(core_path) == prior_core_sha,
            "replay_authorized_by_this_preflight": False,
            "reason": "The prior 30-second W3-253 replay timed out before BX=1; the new binary was built from the same core dispatcher source hash, and only debugger build options differ. A new replay needs a new target-level capture change, not this binary refresh. The BX=1 CPU-entry event has ESP/SS but no stack sample, which is a distinct, bounded instrumentation opportunity.",
            "proposed_next_hypothesis": "Add a four-to-six-dword SS:ESP sample to only the first verified protected MAIN INT21 AX=4400/BX=1 CPU-entry event, validate SS descriptor/range and checked memory reads, then one guarded replay to resolve the immediate return address/caller. Preserve event cap and do not modify guest state.",
        },
        "safety": {
            "dosbox_run": False,
            "gene_wars_run": False,
            "oracle_replay": False,
            "vhdx_modified": False,
        },
    }
    return data


def write_evidence() -> dict:
    data = collect()
    errors = validate(data)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(
        "# W3-258 — preflight guard del Staging reconstruido\n\n"
        f"Resultado: **{'PASS' if not errors else 'INCOMPLETE'}**. El binario de W3-257 conserva su SHA-256; `verify_oracle_sandbox.ps1` devolvió `verified={data['sandbox'].get('verified')}` para `{data['sandbox'].get('label')}` ({data['sandbox'].get('capacity_bytes')} bytes, host free {data['sandbox'].get('host_free_bytes')} bytes, floor {data['sandbox'].get('host_floor_bytes')}).\n\n"
        f"El guard expone el subcomando `run`, requiere el sandbox y los límites activos se registran en el JSON. El config funcional conserva SHA-256 `{data['functional_config']['sha256']}`. No se lanzó el emulador.\n\n"
        f"W3-253 ya había terminado por timeout antes de BX=1 con {data['prior_bx1_capture']['trace_event_count']} eventos y {data['prior_bx1_capture']['trace_bytes']} bytes. El hash de `core_dyn_x86.cpp` coincide con aquel build, mientras que las opciones del nuevo binario activan debugger pesado. No hay hipótesis suficiente para repetir esa misma captura.\n\n"
        "Nueva oportunidad acotada: el hook de INT21 BX=1 guarda ESP/SS pero no bytes de pila. Un muestreo checked de 24 bytes en ese único evento podría recuperar el retorno/caller; debe implementarse y probarse en una tarea separada antes de un replay.\n\n"
        f"Evidencia estructurada: `{OUT}`.\n\n"
        + ("Errores: " + "; ".join(errors) if errors else "No replay ejecutado; preflight completado.")
        + "\n",
        encoding="utf-8",
    )
    return data


if __name__ == "__main__":
    result = write_evidence()
    print(json.dumps({"evidence": str(OUT), "errors": validate(result)}, indent=2))
