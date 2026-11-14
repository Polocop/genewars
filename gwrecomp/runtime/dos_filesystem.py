"""Confined DOS path, file-handle, and standard-stream layer."""
from __future__ import annotations

import io
import os
import pathlib
import re
import stat
from dataclasses import dataclass


class DosFsError(OSError):
    def __init__(self, dos_code: int, message: str, path: str | None = None):
        super().__init__(message)
        self.dos_code = dos_code
        self.dos_path = path


@dataclass
class Handle:
    stream: object
    owned: bool
    path: str


class DosFileSystem:
    ERR_INVALID_HANDLE = 6
    ERR_ACCESS_DENIED = 5
    ERR_FILE_NOT_FOUND = 2
    ERR_PATH_NOT_FOUND = 3
    ERR_INVALID_DRIVE = 15

    def __init__(self, root: pathlib.Path, *, cwd: str = "GENEWARS",
                 stdin=None, stdout=None, stderr=None, drive: str = "C",
                 overlay_root: pathlib.Path | None = None, iso_volume=None):
        self.root = pathlib.Path(root).resolve()
        self.overlay_root = pathlib.Path(overlay_root).resolve() if overlay_root is not None else None
        self.drive = drive.upper()
        self.iso_volume = iso_volume
        if len(self.drive) != 1 or not self.drive.isalpha():
            raise ValueError("drive must be one alphabetic letter")
        self.cwd = self._parts(cwd)
        self.handles: dict[int, Handle] = {
            0: Handle(stdin if stdin is not None else io.BytesIO(), False, "CONIN$"),
            1: Handle(stdout if stdout is not None else io.BytesIO(), False, "CONOUT$"),
            2: Handle(stderr if stderr is not None else io.BytesIO(), False, "CONERR$"),
        }
        self.attempts: list[dict] = []

    @staticmethod
    def _parts(value: str) -> list[str]:
        parts = []
        for item in value.replace("/", "\\").split("\\"):
            if not item or item == ".":
                continue
            if item == "..":
                if not parts:
                    raise DosFsError(DosFileSystem.ERR_ACCESS_DENIED, "path escapes virtual drive", value)
                parts.pop()
            else:
                if ":" in item or "\0" in item:
                    raise DosFsError(DosFileSystem.ERR_ACCESS_DENIED, "invalid DOS path component", value)
                parts.append(item)
        return parts

    def normalize(self, path: str) -> tuple[str, ...]:
        if not isinstance(path, str) or not path or "\0" in path:
            raise DosFsError(self.ERR_FILE_NOT_FOUND, "empty or invalid path", str(path))
        text = path.replace("/", "\\")
        match = re.match(r"^([A-Za-z]):", text)
        if match:
            if match.group(1).upper() != self.drive:
                raise DosFsError(self.ERR_INVALID_DRIVE, "unsupported DOS drive", path)
            text = text[2:]
        absolute = text.startswith("\\")
        tail = text.lstrip("\\") if absolute else text
        parts = [] if absolute else list(self.cwd)
        for item in tail.split("\\"):
            if not item or item == ".":
                continue
            if item == "..":
                if not parts:
                    raise DosFsError(self.ERR_ACCESS_DENIED, "path escapes virtual drive", path)
                parts.pop()
            else:
                if ":" in item:
                    raise DosFsError(self.ERR_ACCESS_DENIED, "invalid DOS path component", path)
                parts.append(item)
        return tuple(parts)

    def _case_path_at(self, root: pathlib.Path, parts: tuple[str, ...]) -> pathlib.Path:
        current = root
        for part in parts:
            if current.is_dir():
                try:
                    match = next((n for n in current.iterdir() if n.name.casefold() == part.casefold()), None)
                except OSError:
                    match = None
                if match is not None:
                    current = match
                    continue
            current = current / part
        resolved = current.resolve(strict=False)
        try:
            resolved.relative_to(root)
        except ValueError:
            raise DosFsError(self.ERR_ACCESS_DENIED, "resolved path escapes virtual root", "\\".join(parts))
        return resolved

    def _case_path(self, parts: tuple[str, ...]) -> pathlib.Path:
        return self._case_path_at(self.root, parts)

    def resolve(self, path: str) -> pathlib.Path:
        parts = self.normalize(path)
        if self.overlay_root is not None:
            overlay = self._case_path_at(self.overlay_root, parts)
            if overlay.exists():
                return overlay
        return self._case_path(parts)

    def _iso_path(self, path: str) -> str:
        parts = self.normalize(path)
        candidate = "\\".join(parts)
        if self.iso_volume is None:
            return candidate
        try:
            self.iso_volume.stat(candidate)
            return candidate
        except FileNotFoundError:
            if parts[:len(self.cwd)] == tuple(self.cwd):
                return "\\".join(parts[len(self.cwd):])
            return candidate

    def seed_empty_file(self, path: str) -> pathlib.Path:
        """Create a zero-byte first-run file in the writable overlay only if absent."""
        if self.overlay_root is None:
            raise ValueError("per-user file seeding requires an overlay root")
        parts = self.normalize(path)
        existing = self.resolve(path)
        if existing.exists():
            return existing
        target = self._case_path_at(self.overlay_root, parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.touch(exist_ok=False)
        self._record("seed_empty", path, result=True)
        return target

    def _record(self, operation: str, path: str, *, handle=None, result=None, error=None):
        self.attempts.append({"operation": operation, "path": path, "handle": handle,
                              "result": result, "error": error})

    def attributes(self, path: str) -> int:
        host = self.resolve(path)
        if not host.exists():
            if self.iso_volume is not None:
                try:
                    entry = self.iso_volume.stat(self._iso_path(path))
                    return (0x10 if entry["directory"] else 0x20) | 0x01
                except FileNotFoundError:
                    pass
            code = self.ERR_PATH_NOT_FOUND if not host.parent.exists() else self.ERR_FILE_NOT_FOUND
            raise DosFsError(code, "file not found", path)
        mode = host.stat().st_mode
        result = 0x10 if stat.S_ISDIR(mode) else 0x20  # archive bit on regular files
        if not (mode & stat.S_IWRITE):
            result |= 0x01
        if host.name.startswith("."):
            result |= 0x02
        return result

    def access(self, path: str) -> bool:
        try:
            host = self.resolve(path)
            ok = host.exists()
            if not ok and self.iso_volume is not None:
                try:
                    self.iso_volume.stat(self._iso_path(path))
                    ok = True
                except FileNotFoundError:
                    pass
            self._record("access", path, result=ok, error=None if ok else self.ERR_FILE_NOT_FOUND)
            return ok
        except DosFsError as exc:
            self._record("access", path, result=False, error=exc.dos_code)
            return False

    def open(self, path: str, *, access: str = "r", create: bool = False, truncate: bool = False) -> int:
        if access not in ("r", "w", "rw"):
            raise ValueError("access must be r, w, or rw")
        try:
            parts = self.normalize(path)
            if access == "r" and not create and not truncate and self.iso_volume is not None:
                source = self.resolve(path)
                if not source.exists():
                    try:
                        content = self.iso_volume.read_file(self._iso_path(path))
                    except FileNotFoundError:
                        pass
                    except IsADirectoryError as exc:
                        raise DosFsError(self.ERR_ACCESS_DENIED, "cannot open directory as file", path) from exc
                    else:
                        handle = next(h for h in range(5, 0x10000) if h not in self.handles)
                        self.handles[handle] = Handle(io.BytesIO(content), True, path)
                        self._record("open", path, handle=handle, result=True)
                        return handle
            if self.overlay_root is not None and (access != "r" or create or truncate):
                host = self._case_path_at(self.overlay_root, parts)
                source = self._case_path(parts)
                exists = host.exists() or source.exists()
                if not exists and not create:
                    raise DosFsError(self.ERR_FILE_NOT_FOUND, "file not found", path)
                if exists and (host.is_dir() if host.exists() else source.is_dir()):
                    raise DosFsError(self.ERR_ACCESS_DENIED, "cannot open directory as file", path)
                host.parent.mkdir(parents=True, exist_ok=True)
                if not host.exists() and source.is_file() and not (truncate or create):
                    import shutil
                    shutil.copyfile(source, host)
            else:
                host = self.resolve(path)
                exists = host.exists()
                if not exists and not create:
                    raise DosFsError(self.ERR_FILE_NOT_FOUND, "file not found", path)
                if exists and host.is_dir():
                    raise DosFsError(self.ERR_ACCESS_DENIED, "cannot open directory as file", path)
                if create:
                    host.parent.mkdir(parents=False, exist_ok=True)
            if access == "r":
                stream = open(host, "rb")
            elif access == "w":
                stream = open(host, "wb" if truncate or create else "r+b")
            else:
                stream = open(host, "w+b" if truncate or create else "r+b")
            handle = next(h for h in range(5, 0x10000) if h not in self.handles)
            self.handles[handle] = Handle(stream, True, path)
            self._record("open", path, handle=handle, result=True)
            return handle
        except DosFsError as exc:
            self._record("open", path, result=False, error=exc.dos_code)
            raise
        except FileNotFoundError as exc:
            dos_code = self.ERR_PATH_NOT_FOUND if not pathlib.Path(exc.filename or "").parent.exists() else self.ERR_FILE_NOT_FOUND
            err = DosFsError(dos_code, str(exc), path)
            self._record("open", path, result=False, error=dos_code)
            raise err from exc
        except PermissionError as exc:
            err = DosFsError(self.ERR_ACCESS_DENIED, str(exc), path)
            self._record("open", path, result=False, error=err.dos_code)
            raise err from exc

    def _handle(self, number: int) -> Handle:
        h = self.handles.get(number)
        if h is None or getattr(h.stream, "closed", False):
            raise DosFsError(self.ERR_INVALID_HANDLE, "invalid or closed DOS handle", str(number))
        return h

    def read(self, number: int, size: int) -> bytes:
        if size < 0:
            raise ValueError("read size cannot be negative")
        h = self._handle(number)
        data = h.stream.read(size)
        if isinstance(data, str):
            data = data.encode("utf-8")
        data = bytes(data)
        self._record("read", h.path, handle=number, result=len(data))
        return data

    def write(self, number: int, data: bytes) -> int:
        h = self._handle(number)
        try:
            result = h.stream.write(data)
        except TypeError:
            result = h.stream.write(data.decode("utf-8"))
        if result is None:
            result = len(data)
        self._record("write", h.path, handle=number, result=result)
        return int(result)

    def seek(self, number: int, offset: int, whence: int = 0) -> int:
        if whence not in (0, 1, 2):
            raise ValueError("whence must be 0, 1 or 2")
        h = self._handle(number)
        result = h.stream.seek(offset, whence)
        self._record("seek", h.path, handle=number, result=result)
        return int(result)

    def close(self, number: int) -> None:
        h = self._handle(number)
        h.stream.close()
        self._record("close", h.path, handle=number, result=True)
        if h.owned:
            del self.handles[number]

    def dos_error(self, exc: DosFsError) -> int:
        return exc.dos_code
