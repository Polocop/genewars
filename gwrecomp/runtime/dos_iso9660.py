"""Bounded, read-only ISO9660 reader over the MSCDEX CueImage interface."""
from __future__ import annotations

import math

from dos_cdrom import CueImageError


class Iso9660Error(ValueError):
    pass


def _both_endian(data: bytes, offset: int, size: int) -> int:
    half = size // 2
    little = int.from_bytes(data[offset:offset + half], "little")
    big = int.from_bytes(data[offset + half:offset + size], "big")
    if little != big:
        raise Iso9660Error("ISO9660 both-endian field mismatch")
    return little


class Iso9660Volume:
    """Open regular files by ISO path; writes are deliberately unsupported."""

    BLOCK_SIZE = 2048

    def __init__(self, image, *, max_file_bytes: int = 64 * 1024 * 1024,
                 max_directory_bytes: int = 4 * 1024 * 1024):
        if max_file_bytes <= 0 or max_directory_bytes <= 0:
            raise ValueError("ISO9660 read limits must be positive")
        self.image = image
        self.max_file_bytes = max_file_bytes
        self.max_directory_bytes = max_directory_bytes
        self._image_blocks = sum(track.sectors for track in image.tracks)
        self.volume_blocks, self.root = self._mount()

    def _read_blocks(self, lba: int, count: int) -> bytes:
        bound = getattr(self, "volume_blocks", self._image_blocks)
        if lba < 0 or count < 0 or lba + count > bound:
            raise Iso9660Error("ISO9660 extent lies outside declared volume")
        chunks = []
        while count:
            step = min(count, self.image.max_sectors)
            try:
                chunks.append(self.image.read_sectors(lba, step, raw=False))
            except (CueImageError, OSError) as exc:
                raise Iso9660Error(f"ISO9660 sector read failed: {exc}") from exc
            lba += step
            count -= step
        return b"".join(chunks)

    def _mount(self):
        pvd = None
        for lba in range(16, 32):
            descriptor = self._read_blocks(lba, 1)
            if descriptor[1:6] != b"CD001" or descriptor[6] != 1:
                raise Iso9660Error("invalid ISO9660 volume descriptor signature/version")
            kind = descriptor[0]
            if kind == 1:
                pvd = descriptor
                break
            if kind == 255:
                break
        if pvd is None:
            raise Iso9660Error("ISO9660 Primary Volume Descriptor not found")
        blocks = _both_endian(pvd, 80, 8)
        block_size = _both_endian(pvd, 128, 4)
        if blocks <= 0 or blocks > self._image_blocks or block_size != self.BLOCK_SIZE:
            raise Iso9660Error("unsupported ISO9660 volume size or logical block size")
        root = self._record(pvd[156:190])
        if not root["directory"]:
            raise Iso9660Error("ISO9660 root record is not a directory")
        self._check_extent(root["extent"], root["size"], blocks,
                           self.max_directory_bytes, "root directory")
        return blocks, root

    @staticmethod
    def _record(raw: bytes):
        if len(raw) < 34 or raw[0] < 34 or raw[0] > len(raw):
            raise Iso9660Error("malformed ISO9660 directory record length")
        length = raw[0]
        raw = raw[:length]
        name_length = raw[32]
        if 33 + name_length > length or name_length == 0:
            raise Iso9660Error("malformed ISO9660 directory identifier")
        flags = raw[25]
        if flags & 0x80:
            raise Iso9660Error("ISO9660 multi-extent files are unsupported")
        try:
            name = raw[33:33 + name_length].decode("ascii")
        except UnicodeDecodeError as exc:
            raise Iso9660Error("non-ASCII ISO9660 identifier is unsupported") from exc
        return {"name": name, "extent": _both_endian(raw, 2, 8),
                "size": _both_endian(raw, 10, 8), "directory": bool(flags & 0x02)}

    @staticmethod
    def _check_extent(extent: int, size: int, volume_blocks: int, limit: int, label: str):
        if size < 0 or size > limit:
            raise Iso9660Error(f"ISO9660 {label} exceeds configured byte limit")
        blocks = math.ceil(size / Iso9660Volume.BLOCK_SIZE)
        if extent < 0 or extent + blocks > volume_blocks:
            raise Iso9660Error(f"ISO9660 {label} extent lies outside declared volume")

    @staticmethod
    def _canonical_component(name: str) -> str:
        return name.split(";", 1)[0].rstrip(".").casefold()

    def _directory_entries(self, record):
        self._check_extent(record["extent"], record["size"], self.volume_blocks,
                           self.max_directory_bytes, "directory")
        blocks = math.ceil(record["size"] / self.BLOCK_SIZE)
        data = self._read_blocks(record["extent"], blocks)[:record["size"]]
        entries = []
        pos = 0
        while pos < len(data):
            length = data[pos]
            if length == 0:
                pos = ((pos // self.BLOCK_SIZE) + 1) * self.BLOCK_SIZE
                continue
            item = self._record(data[pos:pos + length])
            if item["name"] not in ("\x00", "\x01"):
                entries.append(item)
            pos += length
        return entries

    def _lookup(self, path: str):
        if not isinstance(path, str) or "\0" in path:
            raise Iso9660Error("invalid ISO9660 path")
        parts = [part for part in path.replace("\\", "/").split("/") if part not in ("", ".")]
        if any(part == ".." for part in parts):
            raise Iso9660Error("parent traversal is not allowed in ISO9660 paths")
        current = self.root
        for index, part in enumerate(parts):
            if not current["directory"]:
                raise Iso9660Error("ISO9660 path traverses through a regular file")
            key = self._canonical_component(part)
            current = next((item for item in self._directory_entries(current)
                            if self._canonical_component(item["name"]) == key), None)
            if current is None:
                raise FileNotFoundError(path)
            if index < len(parts) - 1 and not current["directory"]:
                raise FileNotFoundError(path)
        return current

    def listdir(self, path: str = "") -> list[str]:
        record = self._lookup(path)
        if not record["directory"]:
            raise NotADirectoryError(path)
        return sorted(item["name"] for item in self._directory_entries(record))

    def stat(self, path: str):
        record = self._lookup(path)
        return {"size": record["size"], "directory": record["directory"]}

    def read_file(self, path: str) -> bytes:
        record = self._lookup(path)
        if record["directory"]:
            raise IsADirectoryError(path)
        self._check_extent(record["extent"], record["size"], self.volume_blocks,
                           self.max_file_bytes, "file")
        blocks = math.ceil(record["size"] / self.BLOCK_SIZE)
        return self._read_blocks(record["extent"], blocks)[:record["size"]]
