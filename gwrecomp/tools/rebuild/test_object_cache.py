from __future__ import annotations
import os as _gw_os
from pathlib import Path as _GwPath
_GW_ROOT=str(_GwPath(__file__).resolve().parents[2])
_GW_MSYS2=_gw_os.environ.get("MSYS2_ROOT",r"C:\msys64")

import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
import json
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.rebuild import object_cache as object_cache_module
from tools.rebuild.object_cache import (
    CacheUnsafeInput,
    cached_object_matches,
    compile_content_addressed,
    discover_dependencies,
    object_cache_key,
    object_cache_key_diagnostics,
)


CLANG = Path(os.environ.get("GWRECOMP_CLANG_X64") or __import__("shutil").which("clang") or "clang.exe")
REBUILD_PS1 = ROOT / "tools" / "rebuild" / "rebuild.ps1"
POWERSHELL = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"


class ObjectCacheTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="gwrecomp-object-cache-test-", dir=Path(__file__).parent)
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.env = os.environ.copy()
        self.env["TEMP"] = str(self.base)
        self.env["TMP"] = str(self.base)
        self.env["TMPDIR"] = str(self.base)

    def _tree(self, name: str) -> tuple[Path, Path, Path]:
        root = self.base / name
        (root / "src").mkdir(parents=True)
        (root / "include").mkdir()
        inner = root / "include" / "inner.h"
        inner.write_text("#define VALUE 7\n", encoding="ascii")
        outer = root / "include" / "outer.h"
        outer.write_text('#include "inner.h"\n', encoding="ascii")
        source = root / "src" / "sample.c"
        source.write_text('#include "outer.h"\nint sample(void) { return VALUE; }\n', encoding="ascii")
        return root, source, inner

    def _flags(self, root: Path, extra: tuple[str, ...] = ()) -> list[object]:
        return [CLANG, "--target=i686-w64-windows-gnu", "-std=gnu11", "-O0", *extra, "-I", root / "include"]

    def _key(self, root: Path, source: Path, flags: list[object]) -> tuple[str, list[Path]]:
        dependencies, compiler_identity = discover_dependencies(source, flags, root, self.env)
        key = object_cache_key(source, flags, dependencies, root, compiler_identity, self.env)
        return key, dependencies

    def _compile(self, source: Path, root: Path, flags: list[object], cache: Path) -> tuple[Path, bool, str]:
        key, _ = self._key(root, source, flags)
        command = [*flags, "-c", source, "-o", self.base / "output.obj"]
        result, hit = compile_content_addressed(
            source,
            cache,
            key,
            command,
            lambda argv: subprocess.run(argv, cwd=root, env=self.env, check=True, capture_output=True),
        )
        return result, hit, key

    def test_a_identical_inputs_reuse_the_real_clang_object(self) -> None:
        self.assertTrue(CLANG.is_file(), "pinned Clang is unavailable")
        root_a, source_a, _ = self._tree("checkout-a")
        root_b, source_b, _ = self._tree("checkout-b")
        cache = self.base / "shared-cache"
        started = time.perf_counter()
        first, first_hit, key_a = self._compile(source_a, root_a, self._flags(root_a), cache)
        first_seconds = time.perf_counter() - started
        before_second = sum(p.stat().st_size for p in cache.rglob("*") if p.is_file())
        started = time.perf_counter()
        second, second_hit, key_b = self._compile(source_b, root_b, self._flags(root_b), cache)
        second_seconds = time.perf_counter() - started
        after_second = sum(p.stat().st_size for p in cache.rglob("*") if p.is_file())
        self.assertFalse(first_hit)
        self.assertTrue(second_hit)
        self.assertEqual(key_a, key_b)
        self.assertEqual(first, second)
        self.assertEqual(hashlib.sha256(first.read_bytes()).digest(), hashlib.sha256(second.read_bytes()).digest())
        print("CACHE_SAMPLE_METRIC " + json.dumps({
            "first_compile_seconds": round(first_seconds, 4),
            "second_hit_seconds": round(second_seconds, 4),
            "object_bytes": first.stat().st_size,
            "cache_bytes_after_first": before_second,
            "new_cache_bytes_on_hit": after_second - before_second,
            "second_run_hits": 1,
        }, sort_keys=True))

    def test_j_codex_tool_call_id_is_diagnostic_only(self) -> None:
        root, source, _ = self._tree("tool-call-id")
        flags = self._flags(root)
        self.env["CODEX_TOOL_CALL_ID"] = "exec-first"
        key_a, dependencies = self._key(root, source, flags)
        _, compiler_identity = discover_dependencies(source, flags, root, self.env)
        diagnostics = object_cache_key_diagnostics(
            source, flags, dependencies, root, compiler_identity, self.env
        )
        self.env["CODEX_TOOL_CALL_ID"] = "exec-second"
        key_b, _ = self._key(root, source, flags)
        self.assertEqual(key_a, key_b)
        self.assertEqual(diagnostics["cache_key"], key_a)
        self.assertNotIn("CODEX_TOOL_CALL_ID", diagnostics["environment_value_sha256"])

        # Reproduce the previous key policy in memory: this one injected
        # variable alone changes the key although every compiler input stays
        # fixed. Restore the production filter even if an assertion fails.
        object_cache_module._OUTPUT_ONLY_ENV.remove("CODEX_TOOL_CALL_ID")
        try:
            old_key_b, _ = self._key(root, source, flags)
            self.env["CODEX_TOOL_CALL_ID"] = "exec-first"
            old_key_a, _ = self._key(root, source, flags)
            self.assertNotEqual(old_key_a, old_key_b)
        finally:
            object_cache_module._OUTPUT_ONLY_ENV.add("CODEX_TOOL_CALL_ID")

    def test_k_real_gwrecomp_camera_object_reuse_invalidation_and_corruption(self) -> None:
        """Exercise the actual GWRecomp TU and header in isolated E: work roots."""
        real_root = ROOT
        source_path = real_root / "runtime" / "gw_camera_interpolation.c"
        header_path = real_root / "runtime" / "gw_camera_interpolation.h"
        self.assertTrue(source_path.is_file())
        self.assertTrue(header_path.is_file())
        original_header = header_path.read_bytes()
        roots = [self.base / "gw-camera-work-a", self.base / "gw-camera-work-b"]
        sources = []
        for work in roots:
            runtime = work / "runtime"
            runtime.mkdir(parents=True)
            (runtime / source_path.name).write_bytes(source_path.read_bytes())
            (runtime / header_path.name).write_bytes(original_header)
            sources.append(runtime / source_path.name)

        def flags_for(work: Path) -> list[object]:
            return [
                CLANG, "--target=i686-w64-windows-gnu", "-std=gnu11", "-m32", "-O1",
                "-DRECOMP_TRACE_LOW_WRITES=1", "-DMSCDEX_AUDIO_BEGIN=101726u",
                "-DMSCDEX_AUDIO_END=268260u", "-I", work / "runtime",
                "-I", real_root / "third_party" / "pcrecomp" / "runtime" / "recomp32",
                "-DGW_FUNC_COVERAGE_BUILD=1", "-I", Path((_GW_MSYS2 + '\\mingw32\\include\\SDL2')),
            ]

        cache = self.base / "gw-camera-real-object-cache"

        def compile_in(work: Path, source: Path, call_id: str, output: Path | None = None):
            env = dict(self.env)
            env["CODEX_TOOL_CALL_ID"] = call_id
            env["TEMP"] = str(work / "tmp")
            env["TMP"] = str(work / "tmp")
            env["TMPDIR"] = str(work / "tmp")
            env["PATH"] = (
                (_GW_MSYS2 + '\\mingw32\\bin;' + _GW_MSYS2 + '\\usr\\bin;') + env.get("PATH", "")
            )
            Path(env["TEMP"]).mkdir(parents=True, exist_ok=True)
            flags = flags_for(work)
            try:
                deps, compiler_identity = discover_dependencies(source, flags, work, env)
            except CacheUnsafeInput as exc:
                probe = subprocess.run(
                    [*(str(arg) for arg in flags), "-M", "-MT", "GWRECOMP_CACHE_TARGET", str(source)],
                    cwd=work, env=env, text=True, capture_output=True, check=False,
                )
                self.fail(f"real-object dependency discovery failed: {exc}: {probe.stderr}")
            self.assertIn(
                (work / "runtime" / header_path.name).resolve(), deps,
                "Clang dependency scan omitted the actual GWRecomp header",
            )
            key = object_cache_key(source, flags, deps, work, compiler_identity, env)
            if output is not None:
                argv = [*flags, "-c", source, "-o", output]
                subprocess.run(argv, cwd=work, env=env, check=True, capture_output=True)
                return output, False, key
            argv = [*flags, "-c", source, "-o", self.base / "unused.obj"]
            obj, hit = compile_content_addressed(
                source, cache, key, argv,
                lambda command: subprocess.run(
                    command, cwd=work, env=env, check=True, capture_output=True
                ),
            )
            return obj, hit, key

        first, first_hit, first_key = compile_in(roots[0], sources[0], "exec-real-first")
        second, second_hit, second_key = compile_in(roots[1], sources[1], "exec-real-second")
        self.assertFalse(first_hit)
        self.assertTrue(second_hit)
        self.assertEqual(first_key, second_key)
        self.assertEqual(first, second)
        self.assertTrue(cached_object_matches(
            first, first.with_suffix(first.suffix + ".sha256"), first_key
        ))

        reference, _, _ = compile_in(
            roots[1], sources[1], "exec-reference", self.base / "gw-camera-reference.obj"
        )
        expected_sha = hashlib.sha256(reference.read_bytes()).hexdigest()
        second_sha = hashlib.sha256(second.read_bytes()).hexdigest()
        second_size = second.stat().st_size
        self.assertEqual(second_sha, expected_sha)
        self.assertEqual(expected_sha, "5149120655f7866d6c042569236f5822551a7e5f4cadab657c5f1de25c3c5602")

        # Change an actual project header only in the isolated copy. A field
        # width change affects the generated access offsets and must miss.
        changed_header = roots[1] / "runtime" / header_path.name
        changed = original_header.replace(b"int current_valid;", b"short current_valid;", 1)
        self.assertNotEqual(changed, original_header)
        changed_header.write_bytes(changed)
        changed_obj, changed_hit, changed_key = compile_in(
            roots[1], sources[1], "exec-dependency-change"
        )
        self.assertFalse(changed_hit)
        self.assertNotEqual(changed_key, first_key)
        self.assertNotEqual(hashlib.sha256(changed_obj.read_bytes()).hexdigest(), expected_sha)

        # Corrupt the original immutable cache object; the same key must be
        # rejected and rebuilt from unchanged inputs in work A.
        first.write_bytes(b"corrupted-real-object")
        repaired, repair_hit, _ = compile_in(roots[0], sources[0], "exec-corruption-repair")
        self.assertFalse(repair_hit)
        self.assertEqual(hashlib.sha256(repaired.read_bytes()).hexdigest(), expected_sha)
        print("CACHE_GWRECOMP_REAL_METRIC " + json.dumps({
            "translation_unit": source_path.name,
            "header": header_path.name,
            "cold_cache_hit": first_hit,
            "second_work_cache_hit": second_hit,
            "work_roots_distinct": str(roots[0]) != str(roots[1]),
            "key_same_across_tool_call_ids": first_key == second_key,
            "object_bytes": second_size,
            "reference_sha256": expected_sha,
            "second_work_sha256": second_sha,
            "dependency_change_rejected": not changed_hit,
            "corruption_rejected_and_rebuilt": not repair_hit,
            "repaired_sha256": hashlib.sha256(repaired.read_bytes()).hexdigest(),
        }, sort_keys=True))

    def test_b_indirect_header_change_invalidates(self) -> None:
        root, source, inner = self._tree("indirect")
        deps, _ = discover_dependencies(source, self._flags(root), root, self.env)
        self.assertIn(inner.resolve(), deps)
        cache = self.base / "cache-indirect"
        first, first_hit, key1 = self._compile(source, root, self._flags(root), cache)
        inner.write_text("#define VALUE 8\n", encoding="ascii")
        second, second_hit, key2 = self._compile(source, root, self._flags(root), cache)
        self.assertFalse(first_hit)
        self.assertFalse(second_hit)
        self.assertNotEqual(key1, key2)
        self.assertNotEqual(first, second)
        self.assertTrue(first.is_file(), "old immutable cache version was replaced")

    def test_unmodeled_response_files_and_path_macros_fail_closed(self) -> None:
        root, source, _ = self._tree("fail-closed")
        with self.assertRaises(CacheUnsafeInput):
            discover_dependencies(source, [CLANG, "@options.rsp"], root, self.env)
        source.write_text('const char *source_path = __FILE__;\n', encoding="ascii")
        dependencies, compiler_identity = discover_dependencies(source, self._flags(root), root, self.env)
        with self.assertRaises(CacheUnsafeInput):
            object_cache_key(source, self._flags(root), dependencies, root, compiler_identity, self.env)

    def test_helper_loads_by_explicit_path_without_namespace_package(self) -> None:
        helper_path = ROOT / "tools" / "rebuild" / "object_cache.py"
        spec = importlib.util.spec_from_file_location("gwrecomp_object_cache_test_load", helper_path)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertTrue(callable(module.discover_dependencies))

    def test_c_compile_flags_invalidate(self) -> None:
        root, source, _ = self._tree("flags")
        flags_a = self._flags(root, ("-DVARIANT=1",))
        flags_b = self._flags(root, ("-DVARIANT=2",))
        cache = self.base / "cache-flags"
        first, first_hit, key_a = self._compile(source, root, flags_a, cache)
        second, second_hit, key_b = self._compile(source, root, flags_b, cache)
        self.assertFalse(first_hit)
        self.assertFalse(second_hit)
        self.assertNotEqual(key_a, key_b)
        self.assertNotEqual(first, second)

    def test_d_generated_source_change_invalidates(self) -> None:
        root, source, _ = self._tree("generated")
        flags = self._flags(root)
        cache = self.base / "cache-generated"
        first, first_hit, key_a = self._compile(source, root, flags, cache)
        source.write_text(source.read_text(encoding="ascii") + "/* generated change */\n", encoding="ascii")
        second, second_hit, key_b = self._compile(source, root, flags, cache)
        self.assertFalse(first_hit)
        self.assertFalse(second_hit)
        self.assertNotEqual(key_a, key_b)
        self.assertNotEqual(first, second)

    def test_e_corrupt_object_is_never_reused(self) -> None:
        root, source, _ = self._tree("corrupt")
        cache = self.base / "cache-corrupt"
        first, hit, key = self._compile(source, root, self._flags(root), cache)
        self.assertFalse(hit)
        expected_sha = hashlib.sha256(first.read_bytes()).hexdigest()
        first.write_bytes(b"corrupted object")
        self.assertFalse(cached_object_matches(first, first.with_suffix(first.suffix + ".sha256"), key))
        repaired, hit_again, _ = self._compile(source, root, self._flags(root), cache)
        self.assertFalse(hit_again)
        self.assertNotEqual(first, repaired)
        self.assertEqual(hashlib.sha256(repaired.read_bytes()).hexdigest(), expected_sha)
        self.assertTrue(cached_object_matches(repaired, repaired.with_suffix(repaired.suffix + ".sha256"), key))
        self.assertEqual(first.read_bytes(), b"corrupted object")

    def test_f_interrupted_write_cannot_leave_a_valid_cache_entry(self) -> None:
        root, source, _ = self._tree("interrupted")
        cache = self.base / "cache-interrupted"
        object_dir = cache / source.stem

        def interrupted(argv: list[object]) -> None:
            Path(argv[-1]).write_bytes(b"partial")
            raise RuntimeError("simulated interrupted compiler")

        with self.assertRaises(RuntimeError):
            compile_content_addressed(source, cache, "input-key", ["clang", "-c", source, "-o", self.base / "x.obj"], interrupted)
        self.assertFalse(list(object_dir.glob("*.obj")))
        self.assertFalse(list(object_dir.glob("*.sha256")))
        self.assertFalse(list(object_dir.glob("*.tmp.obj")))

        def tiny_compile(argv: list[object]) -> None:
            Path(argv[-1]).write_bytes(b"complete tiny object")

        with patch("tools.rebuild.object_cache.write_object_stamp", side_effect=RuntimeError("interrupted stamp")):
            with self.assertRaises(RuntimeError):
                compile_content_addressed(source, cache, "input-key", ["clang", "-c", source, "-o", self.base / "x.obj"], tiny_compile)
        self.assertTrue(list(object_dir.glob("*.obj")), "test did not interrupt after atomic object publication")
        self.assertFalse(list(object_dir.glob("*.obj.sha256")), "unstamped object appeared usable")

    def _start_lock_holder(self, lock_path: Path, ready: Path, release: Path) -> subprocess.Popen:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        script = (
            f"$l=[System.IO.File]::Open('{lock_path}',[System.IO.FileMode]::OpenOrCreate,"
            "[System.IO.FileAccess]::ReadWrite,[System.IO.FileShare]::None);"
            f"[System.IO.File]::WriteAllText('{ready}','ready');"
            f"while(-not(Test-Path -LiteralPath '{release}')){{Start-Sleep -Milliseconds 40}};"
            "$l.Dispose()"
        )
        return subprocess.Popen([str(POWERSHELL), "-NoProfile", "-Command", script],
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))

    def _wait_ready(self, proc: subprocess.Popen, ready: Path) -> None:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if ready.exists():
                return
            if proc.poll() is not None:
                self.fail(f"lock holder exited early: {proc.stderr.read().decode(errors='replace')}")
            time.sleep(0.04)
        self.fail("timed out waiting for lock holder")

    @staticmethod
    def _cleanup_holder(proc: subprocess.Popen) -> None:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
        if proc.stderr:
            proc.stderr.close()

    @unittest.skipUnless(POWERSHELL.is_file(), "Windows PowerShell is unavailable")
    def test_g_same_id_processes_cannot_hold_the_same_cache_lock(self) -> None:
        lock = self.base / "cache-same-id" / "workspace.lock"
        ready, release = self.base / "same.ready", self.base / "same.release"
        holder = self._start_lock_holder(lock, ready, release)
        self.addCleanup(self._cleanup_holder, holder)
        self._wait_ready(holder, ready)
        probe = (
            f"try{{$l=[System.IO.File]::Open('{lock}',[System.IO.FileMode]::OpenOrCreate,"
            "[System.IO.FileAccess]::ReadWrite,[System.IO.FileShare]::None);$l.Dispose();exit 0}"
            "catch{exit 17}"
        )
        blocked = subprocess.run([str(POWERSHELL), "-NoProfile", "-Command", probe], capture_output=True)
        self.assertEqual(blocked.returncode, 17)
        release.write_text("release", encoding="ascii")
        self.assertEqual(holder.wait(timeout=10), 0)
        holder.stderr.close()
        allowed = subprocess.run([str(POWERSHELL), "-NoProfile", "-Command", probe], capture_output=True)
        self.assertEqual(allowed.returncode, 0)

    @unittest.skipUnless(POWERSHELL.is_file(), "Windows PowerShell is unavailable")
    def test_h_distinct_agent_ids_use_independent_locks(self) -> None:
        ready_a, ready_b = self.base / "a.ready", self.base / "b.ready"
        release_a, release_b = self.base / "a.release", self.base / "b.release"
        holder_a = self._start_lock_holder(self.base / "cache-agent-a" / "workspace.lock", ready_a, release_a)
        holder_b = self._start_lock_holder(self.base / "cache-agent-b" / "workspace.lock", ready_b, release_b)
        self.addCleanup(self._cleanup_holder, holder_a)
        self.addCleanup(self._cleanup_holder, holder_b)
        self._wait_ready(holder_a, ready_a)
        self._wait_ready(holder_b, ready_b)
        self.assertIsNone(holder_a.poll())
        self.assertIsNone(holder_b.poll())
        release_a.write_text("release", encoding="ascii")
        release_b.write_text("release", encoding="ascii")
        self.assertEqual(holder_a.wait(timeout=10), 0)
        self.assertEqual(holder_b.wait(timeout=10), 0)
        holder_a.stderr.close()
        holder_b.stderr.close()

    @unittest.skipUnless(POWERSHELL.is_file(), "Windows PowerShell is unavailable")
    def test_i_default_rebuild_dry_run_keeps_historical_cache_disabled(self) -> None:
        work = Path((_GW_ROOT + '\\build\\candidates')) / f"cache-default-test-{time.time_ns()}"
        cache = Path((_GW_ROOT + '\\build\\reusable-object-cache')) / f"default-test-{time.time_ns()}"
        result = subprocess.run(
            [str(POWERSHELL), "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(REBUILD_PS1),
             "-Work", str(work), "-DryRun"],
            capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("disabled (historical per-build object directory)", result.stdout)
        self.assertFalse(work.exists())
        self.assertFalse(cache.exists())


if __name__ == "__main__":
    unittest.main()
