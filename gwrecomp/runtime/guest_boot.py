"""Guest address space and deterministic DOS process seed for LE boot tests.

The seed describes memory/register fields that are known from the LE header.
It leaves extender-owned general registers explicitly unknown.
"""
from __future__ import annotations

import hashlib
import pathlib
import struct
import sys
from dataclasses import dataclass

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from le_loader import FLAT_CODE_SEL, FLAT_DATA_SEL, LEImage, load_le  # noqa: E402

DOS_CONVENTIONAL_BYTES = 0x100000
MAX_DOS_ENVIRONMENT_BYTES = 4096
DEFAULT_REBASE = 0x100000
DEFAULT_PSP_SEGMENT = 0x1000
DEFAULT_ENV_SEGMENT = 0x1100
DEFAULT_PROGRAM_PATH = r"C:\GENEWARS\GENEWARS.EXE"
GENEWARS_11_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
# Measured from the exact 1.1 original replay: object 1's code address and an
# object 3 data global each had independent link-to-runtime deltas. The
# 16-bit object 2 and data object 4 are not assigned either delta: the current
# captures do not establish their individual linear bases.
GENEWARS_11_MEASURED_OBJECT_DELTAS = {1: 0x001EB000, 3: 0x001DA000}


@dataclass(frozen=True)
class GuestMemoryMap:
    occupied: tuple[tuple[int, int, str], ...]
    free: tuple[tuple[int, int], ...]
    unknown_objects: tuple[int, ...]
    guest_limit: int

    @property
    def complete(self) -> bool:
        return not self.unknown_objects


def build_guest_memory_map(image: LEImage, guest_limit: int, *,
                           reservations: tuple[tuple[int, int, str], ...] = (),
                           require_complete: bool = True) -> GuestMemoryMap:
    """Build an explicit guest address map; host VA space is never a budget.

    `guest_limit` is a caller-supplied guest-visible limit (experimental unless
    independently measured). Unknown LE object bases block allocation planning.
    DOS conventional memory and the VGA/ROM hole are reserved separately.
    """
    if guest_limit <= 0 or guest_limit > 0xFFFFFFFF:
        raise ValueError("guest_limit must be an explicit 32-bit guest address bound")
    unknown = tuple(obj.index for obj in image.objects if not obj.linear_base_verified)
    if unknown and require_complete:
        raise ValueError(f"guest map lacks verified linear bases for LE objects {unknown}")
    conventional_end = min(0xA0000, guest_limit)
    hardware_end = min(0x110000, guest_limit)
    occupied = [(0, conventional_end, "DOS conventional memory")]
    if conventional_end < hardware_end:
        occupied.append((conventional_end, hardware_end, "VGA/ROM reserved range"))
    for start, end, name in reservations:
        if start < 0 or end <= start or end > guest_limit:
            raise ValueError(f"invalid reserved guest region {name!r}")
        occupied.append((start, end, name))
    for obj in image.objects:
        if obj.linear_base_verified:
            start, end = int(obj.linear_base), obj.linear_end
            if end > guest_limit:
                raise ValueError(f"LE object {obj.index} exceeds the guest-visible limit")
            occupied.append((start, end, f"LE object {obj.index}"))
    occupied.sort(key=lambda item: (item[0], item[1]))
    for left, right in zip(occupied, occupied[1:]):
        if left[1] > right[0]:
            raise ValueError(f"guest regions overlap: {left[2]} and {right[2]}")
    free = []
    cursor = 0
    for start, end, _name in occupied:
        if cursor < start:
            free.append((cursor, start))
        cursor = max(cursor, end)
    if cursor < guest_limit:
        free.append((cursor, guest_limit))
    # An incomplete map is useful as an inventory, never as an allocation plan.
    if unknown:
        free = []
    return GuestMemoryMap(tuple(occupied), tuple(free), unknown, guest_limit)


class GuestAddressError(ValueError):
    """A guest linear address is outside the mapped backing memory."""


class GuestAddressSpace:
    PAGE_SIZE = 0x1000

    def __init__(self, size: int):
        if size <= 0:
            raise ValueError("guest memory size must be positive")
        self.data = bytearray(size)
        self._size = size
        self._sparse_pages: dict[int, bytearray] = {}

    @property
    def size(self) -> int:
        return self._size

    def _span(self, address: int, size: int) -> slice:
        if address < 0 or size < 0 or address > self._size or size > self._size - address:
            raise GuestAddressError(
                f"guest range 0x{address:x}+0x{size:x} outside [0,0x{self._size:x})"
            )
        return slice(address, address + size)

    def ensure_size(self, size: int) -> None:
        if size < 0 or size > 0x100000000:
            raise GuestAddressError(f"invalid guest memory size 0x{size:x}")
        if size > self._size:
            self._size = size

    def read(self, address: int, size: int) -> bytes:
        span = self._span(address, size)
        if size == 0:
            return b""
        result = bytearray(size)
        cursor = address
        out = 0
        dense_end = min(span.stop, len(self.data))
        if cursor < dense_end:
            count = dense_end - cursor
            result[:count] = self.data[cursor:dense_end]
            cursor += count
            out += count
        while cursor < span.stop:
            page_index, page_offset = divmod(cursor, self.PAGE_SIZE)
            count = min(span.stop - cursor, self.PAGE_SIZE - page_offset)
            page = self._sparse_pages.get(page_index)
            if page is not None:
                result[out:out + count] = page[page_offset:page_offset + count]
            cursor += count
            out += count
        return bytes(result)

    def write(self, address: int, payload: bytes) -> None:
        span = self._span(address, len(payload))
        cursor = address
        source = 0
        dense_end = min(span.stop, len(self.data))
        if cursor < dense_end:
            count = dense_end - cursor
            self.data[cursor:dense_end] = payload[:count]
            cursor += count
            source += count
        while cursor < span.stop:
            page_index, page_offset = divmod(cursor, self.PAGE_SIZE)
            count = min(span.stop - cursor, self.PAGE_SIZE - page_offset)
            page = self._sparse_pages.get(page_index)
            if page is None:
                page = self._sparse_pages[page_index] = bytearray(self.PAGE_SIZE)
            page[page_offset:page_offset + count] = payload[source:source + count]
            cursor += count
            source += count

    def read_u16(self, address: int) -> int:
        return struct.unpack("<H", self.read(address, 2))[0]

    def read_u32(self, address: int) -> int:
        return struct.unpack("<I", self.read(address, 4))[0]


@dataclass(frozen=True)
class CpuSeed:
    eip: int
    esp: int
    cs: int = FLAT_CODE_SEL
    ds: int = FLAT_DATA_SEL
    es: int = FLAT_DATA_SEL
    ss: int = FLAT_DATA_SEL
    eflags: int = 0x202
    unknown_registers: tuple[str, ...] = (
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "fs", "gs"
    )


@dataclass
class GuestBoot:
    image: LEImage
    memory: GuestAddressSpace
    seed: CpuSeed
    psp_segment: int
    env_segment: int
    psp_address: int
    env_address: int
    environment: bytes
    command_tail: bytes
    executable_sha256: str


def make_environment(program_path: str = DEFAULT_PROGRAM_PATH) -> bytes:
    # DOS environment convention: entries, a second NUL, word count, then path.
    path = program_path.encode("ascii")
    return b"\0\0" + struct.pack("<H", 1) + path + b"\0"


def validate_environment_block(environment_block: bytes | bytearray | memoryview) -> bytes:
    """Validate and freeze a bounded, caller-supplied DOS environment block.

    The bytes are fixture data, not a host path or a request to inspect the
    host environment. Keep their DOS trailer intact for the guest CRT.
    """
    if not isinstance(environment_block, (bytes, bytearray, memoryview)):
        raise TypeError("DOS environment block must be bytes-like")
    raw = bytes(environment_block)
    if not raw or len(raw) > MAX_DOS_ENVIRONMENT_BYTES:
        raise ValueError("DOS environment block is empty or exceeds the 4 KiB limit")

    terminator = raw.find(b"\0\0")
    if terminator < 0:
        raise ValueError("DOS environment entries lack a double-NUL terminator")
    entries = raw[:terminator]
    if entries and any(not entry for entry in entries.split(b"\0")):
        raise ValueError("DOS environment contains an empty entry")

    trailer_start = terminator + 2
    if len(raw) < trailer_start + 4:
        raise ValueError("DOS environment trailer is incomplete")
    # The two-byte count is opaque here. The following executable path must
    # be one non-empty ASCIIZ byte string with no data after its terminator.
    path = raw[trailer_start + 2:]
    path_end = path.find(b"\0")
    if path_end <= 0 or path_end != len(path) - 1:
        raise ValueError("DOS environment executable path is malformed")
    return raw


def make_psp(env_segment: int, command_tail: bytes, top_segment: int = 0xA000) -> bytes:
    if len(command_tail) > 126:
        raise ValueError("DOS command tail exceeds 126 bytes")
    psp = bytearray(256)
    psp[0:2] = b"\xcd\x20"  # INT 20h termination stub
    struct.pack_into("<H", psp, 2, top_segment)
    struct.pack_into("<H", psp, 0x2C, env_segment)
    psp[0x80] = len(command_tail)
    psp[0x81:0x81 + len(command_tail)] = command_tail
    psp[0x81 + len(command_tail)] = 0x0D
    return bytes(psp)


def prepare_guest(image_path: pathlib.Path, *, rebase: int = DEFAULT_REBASE,
                 psp_segment: int = DEFAULT_PSP_SEGMENT,
                 env_segment: int = DEFAULT_ENV_SEGMENT,
                 command_tail: bytes = b"",
                 environment_block: bytes | bytearray | memoryview | None = None) -> GuestBoot:
    image_path = pathlib.Path(image_path)
    raw = image_path.read_bytes()
    image = load_le(image_path, rebase=rebase)
    if image.mem_base < DOS_CONVENTIONAL_BYTES:
        raise ValueError("rebased LE image overlaps the DOS conventional-memory range")
    image_end = image.mem_base + len(image.mem)
    memory = GuestAddressSpace(image_end)
    memory.write(image.mem_base, image.mem)

    psp_address = psp_segment << 4
    env_address = env_segment << 4
    environment = (make_environment() if environment_block is None
                   else validate_environment_block(environment_block))
    psp = make_psp(env_segment, command_tail)
    if psp_address + len(psp) > DOS_CONVENTIONAL_BYTES:
        raise ValueError("PSP must reside in conventional DOS memory")
    if env_address + len(environment) > DOS_CONVENTIONAL_BYTES:
        raise ValueError("environment block must reside in conventional DOS memory")
    if max(psp_address, env_address) < min(psp_address + len(psp), env_address + len(environment)):
        raise ValueError("PSP and environment block overlap")
    memory.write(psp_address, psp)
    memory.write(env_address, environment)

    entry_obj = image.objects[image.entry_object - 1]
    stack_obj = image.objects[image.stack_object - 1]
    if not entry_obj.executable:
        raise ValueError("LE entry object is not executable")
    if not stack_obj.writable or not (stack_obj.linear_base < image.stack_linear <= stack_obj.linear_end):
        raise ValueError("LE stack pointer is not inside its writable stack object")
    memory.read(image.entry_linear, 1)
    memory.read(image.stack_linear - 4, 4)
    seed = CpuSeed(eip=image.entry_linear, esp=image.stack_linear)
    return GuestBoot(
        image=image, memory=memory, seed=seed, psp_segment=psp_segment,
        env_segment=env_segment, psp_address=psp_address, env_address=env_address,
        environment=environment, command_tail=command_tail,
        executable_sha256=hashlib.sha256(raw).hexdigest(),
    )


def prepare_native_lift_guest(image_path: pathlib.Path, *, psp_segment: int = 0x0800,
                              env_segment: int = 0x0900, command_tail: bytes = b"",
                              environment_block: bytes | bytearray | memoryview | None = None,
                              object_rebases: dict[int, int] | None = None) -> GuestBoot:
    """Prepare memory for native entry lifts, retaining link PCs separately.

    The optional per-object map relocates LE bytes and applies fixups to the
    corresponding loaded object bases. The recompiled function dispatcher
    still starts at the LE link VA; the stack and memory bytes use guest-linear
    addresses. Do not use an object map until its source hash and non-overlap
    constraints have been verified.
    """
    image_path = pathlib.Path(image_path)
    raw = image_path.read_bytes()
    if object_rebases is not None and hashlib.sha256(raw).hexdigest() != GENEWARS_11_SHA256:
        raise ValueError("the measured GeneWars 1.1 object map is valid only for its pinned executable hash")
    image = load_le(image_path, rebase=0, object_rebases=object_rebases)
    psp_address = psp_segment << 4
    env_address = env_segment << 4
    environment = (make_environment() if environment_block is None
                   else validate_environment_block(environment_block))
    psp = make_psp(env_segment, command_tail)
    image_start = image.mem_base
    image_end = image.mem_base + len(image.mem)
    for name, address, size in (("PSP", psp_address, len(psp)),
                                ("environment", env_address, len(environment))):
        if address + size > DOS_CONVENTIONAL_BYTES:
            raise ValueError(f"{name} must reside in conventional DOS memory")
        if max(address, image_start) < min(address + size, image_end):
            raise ValueError(f"{name} overlaps the fixed-link-VAS LE image")
    if max(psp_address, env_address) < min(psp_address + len(psp), env_address + len(environment)):
        raise ValueError("PSP and environment block overlap")
    memory = GuestAddressSpace(max(DOS_CONVENTIONAL_BYTES, image_end))
    memory.write(image.mem_base, image.mem)
    memory.write(psp_address, psp)
    memory.write(env_address, environment)
    entry_obj = image.objects[image.entry_object - 1]
    stack_obj = image.objects[image.stack_object - 1]
    if not entry_obj.executable:
        raise ValueError("LE entry object is not executable")
    if not stack_obj.writable or not (stack_obj.linear_base < image.stack_linear <= stack_obj.linear_end):
        raise ValueError("LE stack pointer is not inside its writable stack object")
    memory.read(image.entry_linear, 1)
    memory.read(image.stack_linear - 4, 4)
    seed = CpuSeed(eip=image.entry_link, esp=image.stack_linear)
    return GuestBoot(
        image=image, memory=memory, seed=seed, psp_segment=psp_segment,
        env_segment=env_segment, psp_address=psp_address, env_address=env_address,
        environment=environment, command_tail=command_tail,
        executable_sha256=hashlib.sha256(raw).hexdigest(),
    )


def summary(boot: GuestBoot) -> dict:
    return {
        "target_sha256": boot.executable_sha256,
        "link_base": f"0x{boot.image.objects[0].base:x}",
        "linear_base": f"0x{boot.image.objects[0].linear_base:x}",
        "rebase": f"0x{boot.image.objects[0].base - 0x10000:x}",
        "entry_link": f"0x{boot.image.entry_link:x}",
        "entry_linear": f"0x{boot.image.entry_linear:x}",
        "object_map": [
            {"index": obj.index, "link": f"0x{obj.base:x}",
             "linear": f"0x{obj.linear_base:x}", "linear_verified": obj.linear_base_verified,
             "size": f"0x{obj.virtual_size:x}"}
            for obj in boot.image.objects
        ],
        "memory_size": boot.memory.size,
        "conventional_memory_size": DOS_CONVENTIONAL_BYTES,
        "entry": {
            "object": boot.image.entry_object,
            "linear": f"0x{boot.seed.eip:x}",
            "executable": boot.image.objects[boot.image.entry_object - 1].executable,
        },
        "stack": {
            "object": boot.image.stack_object,
            "linear": f"0x{boot.seed.esp:x}",
            "writable": boot.image.objects[boot.image.stack_object - 1].writable,
            "available_below_esp": boot.image.stack_linear - boot.image.objects[boot.image.stack_object - 1].linear_base,
        },
        "selectors": {"cs": boot.seed.cs, "ds": boot.seed.ds, "es": boot.seed.es, "ss": boot.seed.ss},
        "registers_unknown": list(boot.seed.unknown_registers),
        "fixups_applied": boot.image.fixup_count,
        "psp": {"segment": boot.psp_segment, "linear": f"0x{boot.psp_address:x}", "env_segment": boot.env_segment},
        "environment": {"linear": f"0x{boot.env_address:x}", "hex": boot.environment.hex()},
        "command_tail": {"length": len(boot.command_tail), "hex": boot.command_tail.hex()},
        "execution_started": False,
    }
