"""Content-keyed, cross-checkout cache support for compiled object files."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import subprocess
import uuid


class CacheUnsafeInput(RuntimeError):
    """Raised when an input cannot be represented safely in a cache key."""


_PATH_SENSITIVE_MACRO = re.compile(
    rb"\b__(?:FILE|FILE_NAME|BASE_FILE|TIMESTAMP|DATE|TIME)__\b"
)
_UNSUPPORTED_FLAGS = (
    "-xclang", "-include-pch", "-fmodule", "-fplugin", "-fprofile",
    "-fcoverage", "-ivfsoverlay", "-save-temps", "-ftime-trace",
    "-fdebug-compilation-dir", "-mj", "-mf", "-mt", "-mq", "-md",
    "-mmd",
)
_OUTPUT_ONLY_ENV = {
    "TEMP", "TMP", "TMPDIR", "GWRECOMP_OBJECT_CACHE_LOCKED",
    "GWRECOMP_OBJECT_CACHE_USAGE", "GWRECOMP_OBJECT_CACHE_DIAGNOSTICS",
    # Injected by the Codex tool runner for each shell invocation. Clang does
    # not consume this orchestration identifier; hashing it made every build
    # from a separate tool call use a different object key.
    "CODEX_TOOL_CALL_ID",
}


def _path_token(path: Path, root: Path) -> str:
    """Normalize checkout-local paths so identical clean checkouts share keys."""
    absolute = path.resolve()
    try:
        return "@ROOT/" + absolute.relative_to(root.resolve()).as_posix().casefold()
    except ValueError:
        return str(absolute).casefold()


def object_cache_key(
    source: Path,
    compile_flags: list[object],
    dependencies: list[Path],
    root: Path,
    compiler_identity: str,
    environment: dict[str, str],
) -> str:
    digest = hashlib.sha256()
    digest.update(b"gwrecomp-object-cache-v2\0")
    digest.update(compiler_identity.encode("ascii"))
    digest.update(b"\0")
    for arg in compile_flags:
        if isinstance(arg, Path):
            token = _path_token(arg, root)
        else:
            token = str(arg)
        digest.update(token.encode("utf-8"))
        digest.update(b"\0")
    digest.update(_path_token(source, root).encode("utf-8"))
    digest.update(b"\0")
    digest.update(source.read_bytes())
    for dep in sorted(set(dependencies), key=lambda item: _path_token(item, root)):
        raw = dep.resolve(strict=True).read_bytes()
        if _PATH_SENSITIVE_MACRO.search(raw):
            raise CacheUnsafeInput(f"path/time-sensitive macro in dependency: {dep}")
        digest.update(_path_token(dep, root).encode("utf-8"))
        digest.update(b"\0")
        digest.update(raw)
    for name, value in sorted(environment.items(), key=lambda item: item[0].casefold()):
        if name.upper() in _OUTPUT_ONLY_ENV:
            continue
        digest.update(name.casefold().encode("utf-8"))
        digest.update(b"\0")
        digest.update(value.encode("utf-8", errors="surrogatepass"))
        digest.update(b"\0")
    return digest.hexdigest()


def object_cache_key_diagnostics(
    source: Path,
    compile_flags: list[object],
    dependencies: list[Path],
    root: Path,
    compiler_identity: str,
    environment: dict[str, str],
) -> dict[str, object]:
    """Describe effective key inputs without changing the key calculation."""
    flag_tokens = [
        _path_token(arg, root) if isinstance(arg, Path) else str(arg)
        for arg in compile_flags
    ]
    dep_rows = []
    for dep in sorted(set(dependencies), key=lambda item: _path_token(item, root)):
        dep_rows.append({
            "path": _path_token(dep, root),
            "sha256": hashlib.sha256(dep.resolve(strict=True).read_bytes()).hexdigest(),
        })
    env_rows = {
        name: hashlib.sha256(value.encode("utf-8", errors="surrogatepass")).hexdigest()
        for name, value in sorted(environment.items(), key=lambda item: item[0].casefold())
        if name.upper() not in _OUTPUT_ONLY_ENV
    }
    return {
        "cache_key": object_cache_key(
            source, compile_flags, dependencies, root, compiler_identity, environment
        ),
        "compiler_identity_sha256": compiler_identity,
        "compile_flags": flag_tokens,
        "source_path": _path_token(source, root),
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "dependencies": dep_rows,
        "environment_value_sha256": env_rows,
        "environment_sha256": _environment_fingerprint(environment),
    }


def _argument(value: object) -> str:
    return str(value)


def _reject_unmodeled_flags(compile_flags: list[object]) -> None:
    for raw in compile_flags:
        arg = _argument(raw)
        folded = arg.casefold()
        if (arg.startswith("@") or folded in ("-o", "--config") or
                re.match(r"^-g(?:[0-9]|line|dwarf|codeview|split|full|z)", folded) or
                any(folded.startswith(flag) for flag in _UNSUPPORTED_FLAGS)):
            raise CacheUnsafeInput(f"unsupported compiler input/option for reusable cache: {arg}")


_COMPILER_IDENTITY_CACHE: dict[tuple[str, int, int, str], str] = {}


def _environment_fingerprint(environment: dict[str, str]) -> str:
    digest = hashlib.sha256()
    for name, value in sorted(environment.items(), key=lambda item: item[0].casefold()):
        if name.upper() in _OUTPUT_ONLY_ENV:
            continue
        digest.update(name.casefold().encode("utf-8"))
        digest.update(b"\0")
        digest.update(value.encode("utf-8", errors="surrogatepass"))
        digest.update(b"\0")
    return digest.hexdigest()


def _compiler_identity(compiler: Path, root: Path, environment: dict[str, str], timeout: int) -> str:
    stat = compiler.stat()
    env_sha = _environment_fingerprint(environment)
    cache_key = (str(compiler).casefold(), stat.st_size, stat.st_mtime_ns, env_sha)
    if cache_key in _COMPILER_IDENTITY_CACHE:
        return _COMPILER_IDENTITY_CACHE[cache_key]
    version = subprocess.run(
        [str(compiler), "--version"], cwd=root, env=environment,
        text=True, capture_output=True, timeout=timeout, check=False,
    )
    if version.returncode:
        raise CacheUnsafeInput("compiler version query failed")
    digest = hashlib.sha256(compiler.read_bytes())
    digest.update(version.stdout.encode("utf-8", errors="replace"))
    digest.update(version.stderr.encode("utf-8", errors="replace"))
    _COMPILER_IDENTITY_CACHE[cache_key] = digest.hexdigest()
    return digest.hexdigest()


def _normalized_dry_run(output: str, root: Path) -> str:
    canonical = str(root.resolve())
    forms = (canonical, canonical.replace("\\", "/"), canonical.replace("\\", "\\\\"))
    for form in forms:
        output = re.sub(re.escape(form), "__GWRECOMP_ROOT__", output, flags=re.IGNORECASE)
    return output


def _effective_compiler_command(
    compile_flags: list[object], source: Path, root: Path,
    environment: dict[str, str], timeout: int,
) -> str:
    compiler = Path(_argument(compile_flags[0])).resolve(strict=True)
    result = subprocess.run(
        [_argument(x) for x in compile_flags] + ["-###", "-c", str(source), "-o", "GWRECOMP_CACHE_OUTPUT.obj"],
        cwd=root, env=environment, text=True, capture_output=True,
        timeout=timeout, check=False,
    )
    if result.returncode:
        raise CacheUnsafeInput("compiler effective-command probe failed")
    effective = _normalized_dry_run(result.stdout + "\n" + result.stderr, root)
    tokens = [quoted or bare for quoted, bare in re.findall(r'"([^"]*)"|(\S+)', effective)]
    for token in tokens:
        folded = token.casefold()
        if (token.startswith("@") or folded in ("-load", "-plugin", "-include-pch") or
                any(folded.startswith(flag) for flag in (
                    "-fplugin", "-fpass-plugin", "-fmodule", "-fprofile",
                    "-ivfsoverlay",
                )) or folded.startswith("-g")):
            raise CacheUnsafeInput(f"effective compiler command has an unmodeled input: {token}")
    return effective


def parse_make_dependencies(output: str) -> list[str]:
    """Parse Clang's -M output; malformed or incomplete output is rejected."""
    flattened = re.sub(r"\\\r?\n[ \t]*", " ", output)
    marker, separator, body = flattened.partition("GWRECOMP_CACHE_TARGET:")
    if not separator or marker.strip():
        raise CacheUnsafeInput("compiler dependency output has an unexpected target format")
    tokens: list[str] = []
    current: list[str] = []
    i = 0
    while i < len(body):
        char = body[i]
        if char == "\\" and i + 1 < len(body):
            nxt = body[i + 1]
            if nxt.isspace() or nxt in "\\#:":
                current.append(nxt)
                i += 2
                continue
            current.append(char)
        elif char.isspace():
            if current:
                tokens.append("".join(current))
                current.clear()
            i += 1
            continue
        else:
            current.append(char)
        i += 1
    if current:
        tokens.append("".join(current))
    if not tokens:
        raise CacheUnsafeInput("compiler reported no dependencies")
    return tokens


def discover_dependencies(
    source: Path,
    compile_flags: list[object],
    root: Path,
    environment: dict[str, str],
    timeout: int = 60,
) -> tuple[list[Path], str]:
    _reject_unmodeled_flags(compile_flags)
    if not compile_flags:
        raise CacheUnsafeInput("compiler command is empty")
    compiler = Path(_argument(compile_flags[0])).resolve(strict=True)
    if not compiler.is_file():
        raise CacheUnsafeInput("compiler executable is not a regular file")
    for config in (compiler.with_suffix(".cfg"), compiler.parent / "clang.cfg",
                   root / "clang.cfg", root / "clang++.cfg"):
        if config.exists():
            raise CacheUnsafeInput(f"compiler config files are not cache-modeled: {config}")
    try:
        dep_result = subprocess.run(
            [_argument(x) for x in compile_flags] + ["-M", "-MT", "GWRECOMP_CACHE_TARGET", str(source)],
            cwd=root,
            env=environment,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        if dep_result.returncode:
            raise CacheUnsafeInput("compiler dependency scan failed")
        dep_names = parse_make_dependencies(dep_result.stdout)
        dependencies: list[Path] = []
        for name in dep_names:
            candidate = Path(name)
            if not candidate.is_absolute():
                candidate = root / candidate
            candidate = candidate.resolve(strict=True)
            if not candidate.is_file():
                raise CacheUnsafeInput(f"dependency is not a regular file: {candidate}")
            dependencies.append(candidate)
        identity = hashlib.sha256()
        identity.update(_compiler_identity(compiler, root, environment, timeout).encode("ascii"))
        identity.update(_effective_compiler_command(compile_flags, source, root, environment, timeout).encode("utf-8"))
        return sorted(set(dependencies)), identity.hexdigest()
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
        raise CacheUnsafeInput(f"cannot establish compiler inputs: {exc}") from exc


def cached_object_matches(obj: Path, stamp: Path, cache_key: str) -> bool:
    if not obj.is_file() or not stamp.is_file():
        return False
    try:
        key, expected_sha = stamp.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError, ValueError):
        return False
    if key != cache_key:
        return False
    actual = hashlib.sha256(obj.read_bytes()).hexdigest()
    return actual == expected_sha


def write_object_stamp(obj: Path, stamp: Path, cache_key: str) -> None:
    actual = hashlib.sha256(obj.read_bytes()).hexdigest()
    stamp.write_text(f"{cache_key}\n{actual}\n", encoding="ascii")


def compile_content_addressed(
    source: Path,
    cache_root: Path,
    cache_key: str,
    compile_command: list[object],
    run_compile,
) -> tuple[Path, bool]:
    """Reuse immutable objects; a changed input key creates a new cache entry."""
    object_dir = cache_root / source.stem
    object_dir.mkdir(parents=True, exist_ok=True)
    for candidate in sorted(object_dir.glob("*.obj")):
        stamp = candidate.with_suffix(candidate.suffix + ".sha256")
        if cached_object_matches(candidate, stamp, cache_key):
            return candidate, True

    temporary = object_dir / f".{cache_key}-{uuid.uuid4().hex}.tmp.obj"
    try:
        run_compile([*compile_command[:-2], "-o", temporary])
        object_sha = hashlib.sha256(temporary.read_bytes()).hexdigest()
        final_obj = object_dir / f"{cache_key}-{object_sha}.obj"
        try:
            os.rename(temporary, final_obj)
        except FileExistsError:
            if hashlib.sha256(final_obj.read_bytes()).hexdigest() == object_sha:
                temporary.unlink()
            else:
                # Preserve the corrupt entry and store the verified result under a fresh name.
                final_obj = object_dir / f"{cache_key[:24]}-{object_sha}-{uuid.uuid4().hex[:8]}.obj"
                os.rename(temporary, final_obj)
        write_object_stamp(final_obj, final_obj.with_suffix(final_obj.suffix + ".sha256"), cache_key)
        return final_obj, False
    finally:
        if temporary.exists():
            temporary.unlink()
