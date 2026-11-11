"""Small, explicit DOS/DPMI interrupt model for the GeneWars boot path.

Only services supported by current target evidence are implemented. Everything
else returns a structured unhandled trap and leaves guest registers unchanged.
"""
from __future__ import annotations

import pathlib
import struct
from dataclasses import dataclass, field
import io

from guest_boot import GuestBoot
from host_devices import DosClock, PIT8254, AudioEventSink
from dos_filesystem import DosFileSystem, DosFsError
from dos_cdrom import CueImageError, CdAudioState
from dos_iso9660 import Iso9660Error, Iso9660Volume

CF = 1 << 0
DOS_INVALID_BLOCK = 9
DOS_INSUFFICIENT_MEMORY = 8
DPMI_INVALID_SELECTOR = 0x8022
DPMI_LINEAR_UNAVAILABLE = 0x8012
DPMI_INVALID_VALUE = 0x8021
DOS_INVALID_ACCESS = 12
DOS_INVALID_FUNCTION = 1


@dataclass
class CpuRegs:
    eax: int = 0
    ebx: int = 0
    ecx: int = 0
    edx: int = 0
    esi: int = 0
    edi: int = 0
    ebp: int = 0
    esp: int = 0
    eip: int = 0
    eflags: int = 0x202
    es: int = 0
    ds: int = 0
    fs: int = 0
    gs: int = 0

    @property
    def ax(self): return self.eax & 0xFFFF
    @ax.setter
    def ax(self, value): self.eax = (self.eax & 0xFFFF0000) | (value & 0xFFFF)
    @property
    def al(self): return self.eax & 0xFF
    @al.setter
    def al(self, value): self.eax = (self.eax & 0xFFFFFF00) | (value & 0xFF)
    @property
    def ah(self): return (self.eax >> 8) & 0xFF
    @ah.setter
    def ah(self, value): self.eax = (self.eax & 0xFFFF00FF) | ((value & 0xFF) << 8)
    @property
    def bx(self): return self.ebx & 0xFFFF
    @bx.setter
    def bx(self, value): self.ebx = (self.ebx & 0xFFFF0000) | (value & 0xFFFF)
    @property
    def bl(self): return self.ebx & 0xFF
    @bl.setter
    def bl(self, value): self.ebx = (self.ebx & 0xFFFFFF00) | (value & 0xFF)
    @property
    def cx(self): return self.ecx & 0xFFFF
    @cx.setter
    def cx(self, value): self.ecx = (self.ecx & 0xFFFF0000) | (value & 0xFFFF)
    @property
    def dx(self): return self.edx & 0xFFFF
    @dx.setter
    def dx(self, value): self.edx = (self.edx & 0xFFFF0000) | (value & 0xFFFF)
    @property
    def ch(self): return (self.ecx >> 8) & 0xff
    @ch.setter
    def ch(self, value): self.ecx = (self.ecx & 0xffff00ff) | ((value & 0xff) << 8)
    @property
    def cl(self): return self.ecx & 0xff
    @cl.setter
    def cl(self, value): self.ecx = (self.ecx & 0xffffff00) | (value & 0xff)
    @property
    def dh(self): return (self.edx >> 8) & 0xff
    @dh.setter
    def dh(self, value): self.edx = (self.edx & 0xffff00ff) | ((value & 0xff) << 8)
    @property
    def dl(self): return self.edx & 0xff
    @dl.setter
    def dl(self, value): self.edx = (self.edx & 0xffffff00) | (value & 0xff)
    @property
    def si(self): return self.esi & 0xFFFF
    @si.setter
    def si(self, value): self.esi = (self.esi & 0xFFFF0000) | (value & 0xFFFF)
    @property
    def di(self): return self.edi & 0xFFFF
    @di.setter
    def di(self, value): self.edi = (self.edi & 0xFFFF0000) | (value & 0xFFFF)

    @property
    def carry(self): return bool(self.eflags & CF)
    @carry.setter
    def carry(self, value): self.eflags = (self.eflags | CF) if value else (self.eflags & ~CF)

    def snapshot(self):
        return {name: getattr(self, name) for name in
                ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip", "eflags", "es", "ds", "fs", "gs")}


@dataclass(frozen=True)
class ServiceTrap:
    vector: int
    eip: int
    function: int
    registers: dict
    reason: str


@dataclass(frozen=True)
class DispatchResult:
    handled: bool
    service: str | None = None
    trap: ServiceTrap | None = None
    guest_writes: tuple[tuple[int, bytes], ...] = ()


@dataclass
class DosHost:
    boot: GuestBoot
    # full_psp preserves the conservative pre-extender test fixture. The LE
    # entry runner must model DOS/4GW after its startup stub has returned unused
    # conventional memory and exposed the DOS allocation arena.
    dos_memory_profile: str = "full_psp"
    # Optional explicit post-extender ceiling for bounded native experiments.
    # None retains the normal 0xA000 conventional-memory ceiling.
    dos_memory_top_segment: int | None = None
    dos_major: int = 6
    dos_minor: int = 22
    cdrom_drives: tuple[str, ...] = ()
    mscdex_version: tuple[int, int] | None = (2, 23)
    # (first track, last track, lead-out frame, second, minute); explicit
    # media metadata is required before servicing CD-backed requests.
    cdrom_audio_disc_info: tuple[int, int, int, int, int] | None = None
    # Entries are (track number, frame, second, minute, attribute).
    cdrom_audio_track_info: tuple[tuple[int, int, int, int, int], ...] = ()
    # Explicit idle/current Q-subchannel state: attr, track, index, rel MSF, abs MSF.
    cdrom_audio_subchannel: tuple[int, int, int, int, int, int, int, int, int] | None = None
    # Four (output-channel, volume) byte pairs; DOSBox-X initializes them to zero.
    cdrom_audio_channel_control: tuple[int, int, int, int, int, int, int, int] = (0, 0, 0, 0, 0, 0, 0, 0)
    # Optional read-only CD images ordered by cdrom_drives.
    cdrom_images: tuple[object, ...] = ()
    cdrom_audio_states: dict[int, CdAudioState] = field(default_factory=dict, init=False)
    audio_sink: AudioEventSink = field(default_factory=AudioEventSink)
    dos_clock: DosClock = field(default_factory=DosClock)
    pit: PIT8254 = field(default_factory=PIT8254)
    filesystem: DosFileSystem | None = None
    iso_mount_error: str | None = field(default=None, init=False)
    selectors: dict[int, int] = field(default_factory=dict)
    block_paragraphs: int = field(init=False)
    free_segment: int | None = field(default=None, init=False)
    free_paragraphs: int = field(default=0, init=False)
    allocations: dict[int, tuple[int, int]] = field(default_factory=dict, init=False)
    next_allocation: int = field(default=0, init=False)
    allocation_limit: int = 0x7fff0000
    next_handle: int = field(default=1, init=False)
    dpmi_virtual_memory: bool = False
    locked_pages: dict[int, int] = field(default_factory=dict, init=False)
    real_mode_interrupt_vectors: dict[int, tuple[int, int]] = field(default_factory=dict, init=False)
    dos_interrupt_vectors: dict[int, tuple[int, int]] = field(default_factory=dict, init=False)
    dos_allocations: dict[int, tuple[int, int]] = field(default_factory=dict, init=False)
    dos_allocation_mcb: dict[int, int] = field(default_factory=dict, init=False)
    dos_ah48_allocations: dict[int, tuple[int, int]] = field(default_factory=dict, init=False)
    dos_ah48_selectors: dict[int, int] = field(default_factory=dict, init=False)
    dos4gw_free_selectors: list[int] = field(default_factory=list, init=False)
    dos_free_blocks: dict[int, int] = field(default_factory=dict, init=False)
    selector_limits: dict[int, int] = field(default_factory=dict, init=False)
    next_dos_selector: int = field(default=0x24, init=False)

    def __post_init__(self):
        self.cdrom_drives = tuple(str(drive).upper() for drive in self.cdrom_drives)
        if any(len(drive) != 1 or drive < "A" or drive > "Z" for drive in self.cdrom_drives):
            raise ValueError("CD-ROM drives must be single DOS drive letters")
        if self.filesystem is None:
            self.filesystem = DosFileSystem(pathlib.Path(__file__).resolve().parents[1] / "build" / "dos_c")
        self._mount_cdrom_iso()
        self.next_allocation = (self.boot.memory.size + 0xfff) & ~0xfff
        if self.dos_memory_profile == "full_psp":
            # Pre-extender EXEC baseline: the launched process retains the
            # available conventional block until a DOS resize operation.
            self.block_paragraphs = 0xA000 - self.boot.psp_segment
            self._write_mcb(self.boot.psp_segment - 1, b"Z", self.boot.psp_segment, self.block_paragraphs)
        elif self.dos_memory_profile == "post_dos4gw_le_entry":
            self._seed_post_dos4gw_mcb()
        else:
            raise ValueError(f"unknown DOS memory profile: {self.dos_memory_profile}")
        self.selectors = {
            0x000C: 0,  # flat CS
            0x0014: 0,  # flat DS/SS
            0x001c: self.boot.psp_address,  # synthetic protected-mode PSP selector
        }
        self.selector_limits = {0x000c: 0xffffffff, 0x0014: 0xffffffff, 0x001c: 0xffff}

    def _mount_cdrom_iso(self):
        if self.filesystem.iso_volume is not None or not self.cdrom_images:
            return
        configured = [image for image in self.cdrom_images if image is not None]
        if len(configured) != 1:
            self.iso_mount_error = "DOS filesystem ISO bridge requires exactly one configured CUE image"
            return
        image = configured[0]
        if not any(track.mode.startswith("MODE1/") for track in image.tracks):
            self.iso_mount_error = "configured CUE has no ISO-capable Mode1 data track"
            return
        try:
            self.filesystem.iso_volume = Iso9660Volume(image)
        except (Iso9660Error, CueImageError, OSError) as exc:
            self.iso_mount_error = f"configured CUE ISO mount failed: {exc}"

    def _seed_post_dos4gw_mcb(self):
        """Represent PSP, environment, and free conventional RAM as an MCB chain.

        This profile is for execution beginning at the LE entry, after the
        DOS/4GW startup stub. It derives reserved spans from the boot seed and
        only exposes memory between the environment block and conventional
        memory top; it never overlaps the LE image or A0000h+ video/ROM space.
        """
        top = 0xA000 if self.dos_memory_top_segment is None else self.dos_memory_top_segment
        psp = self.boot.psp_segment
        env = self.boot.env_segment
        env_paragraphs = max(1, (len(self.boot.environment) + 15) // 16)
        psp_mcb = psp - 1
        env_mcb = env - 1
        psp_paragraphs = env_mcb - psp
        free_mcb = env + env_paragraphs
        free_paragraphs = top - free_mcb - 1
        env_end = (env << 4) + len(self.boot.environment)
        image_start = self.boot.image.mem_base
        if (top <= free_mcb + 1 or top > 0xA000 or
                psp_mcb < 0 or psp_paragraphs < 0x10 or env_mcb != psp + psp_paragraphs
                or env_paragraphs <= 0 or free_paragraphs <= 0
                or (self.dos_memory_top_segment is None and free_paragraphs < 0x1000)
                or env_end > free_mcb << 4
                or image_start < top << 4):
            raise ValueError("PSP/environment/free MCB spans are inconsistent with the post-DOS/4GW layout")
        # DOS MCB paragraph counts exclude the 16-byte MCB headers themselves.
        self.block_paragraphs = psp_paragraphs
        struct.pack_into("<H", self.boot.memory.data, self.boot.psp_address + 2,
                         psp + psp_paragraphs)
        self._write_mcb(psp_mcb, b"M", psp, psp_paragraphs)
        self._write_mcb(env_mcb, b"M", psp, env_paragraphs)
        self._write_mcb(free_mcb, b"Z", 0, free_paragraphs)
        self.dos_free_blocks[free_mcb] = free_paragraphs
        self._refresh_free_summary()
        self.dos_mcb_layout = {
            "profile": self.dos_memory_profile,
            "psp_mcb_segment": psp_mcb,
            "psp_segment": psp,
            "psp_paragraphs": psp_paragraphs,
            "psp_end_segment": psp + psp_paragraphs,
            "environment_mcb_segment": env_mcb,
            "environment_segment": env,
            "environment_paragraphs": env_paragraphs,
            "free_mcb_segment": free_mcb,
            "free_data_segment": free_mcb + 1,
            "free_paragraphs": free_paragraphs,
            "top_segment": top,
            "le_image_start": image_start,
            "vga_rom_start": top << 4,
        }

    def _write_mcb(self, segment: int, tag: bytes, owner: int, paragraphs: int):
        address = segment << 4
        mcb = bytearray(16)
        mcb[0] = tag[0]
        struct.pack_into("<H", mcb, 1, owner & 0xFFFF)
        struct.pack_into("<H", mcb, 3, paragraphs & 0xFFFF)
        self.boot.memory.write(address, bytes(mcb))

    def _refresh_free_summary(self):
        if self.dos_free_blocks:
            self.free_segment = min(self.dos_free_blocks)
            self.free_paragraphs = self.dos_free_blocks[self.free_segment]
        else:
            self.free_segment = None
            self.free_paragraphs = 0

    def _coalesce_dos_free_blocks(self):
        changed = True
        while changed:
            changed = False
            ordered = sorted(self.dos_free_blocks)
            for left, right in zip(ordered, ordered[1:]):
                if left + self.dos_free_blocks[left] + 1 == right:
                    combined = self.dos_free_blocks.pop(left) + 1 + self.dos_free_blocks.pop(right)
                    self.dos_free_blocks[left] = combined
                    changed = True
                    break
        top_segment = getattr(self, "dos_mcb_layout", {}).get(
            "top_segment", self.boot.memory.read_u16(self.boot.psp_address + 2))
        for free_mcb, free_size in sorted(self.dos_free_blocks.items()):
            tag = b"Z" if free_mcb + free_size + 1 >= top_segment else b"M"
            self._write_mcb(free_mcb, tag, 0, free_size)
        self._refresh_free_summary()

    def _allocate_dos_ah48_block(self, paragraphs: int) -> int | None:
        candidates = [segment for segment, size in sorted(self.dos_free_blocks.items())
                      if size >= paragraphs]
        if not candidates:
            return None
        mcb_segment = candidates[0]
        old_size = self.dos_free_blocks.pop(mcb_segment)
        old_tag = self.boot.memory.read(mcb_segment << 4, 1)
        data_segment = mcb_segment + 1
        remainder = old_size - paragraphs
        if remainder:
            next_mcb = mcb_segment + paragraphs + 1
            free_size = remainder - 1
            self._write_mcb(mcb_segment, b"M", self.boot.psp_segment, paragraphs)
            self._write_mcb(next_mcb, old_tag, 0, free_size)
            self.dos_free_blocks[next_mcb] = free_size
        else:
            self._write_mcb(mcb_segment, old_tag, self.boot.psp_segment, paragraphs)
        self.dos_ah48_allocations[data_segment] = (mcb_segment, paragraphs)
        self._refresh_free_summary()
        return data_segment

    def dos4gw_alias_ah48_segment(self, segment: int) -> int | None:
        allocation = self.dos_ah48_allocations.get(segment)
        if allocation is None:
            return None
        selector = None
        while self.dos4gw_free_selectors and selector is None:
            candidate = self.dos4gw_free_selectors.pop()
            if candidate not in self.selectors:
                selector = candidate
        if selector is None:
            selector = self.next_dos_selector
            while selector <= 0xfff8 and selector in self.selectors:
                selector += 8
            if selector > 0xfff8:
                return None
            self.next_dos_selector = selector + 8
        _, paragraphs = allocation
        self.dos_ah48_selectors[selector] = segment
        self.selectors[selector] = segment << 4
        self.selector_limits[selector] = paragraphs * 16 - 1
        return selector

    def dos4gw_segment_for_ah48_selector(self, selector: int) -> int | None:
        return self.dos_ah48_selectors.get(selector)

    def dos4gw_release_ah48_selector(self, selector: int) -> None:
        self.dos_ah48_selectors.pop(selector, None)
        self.selectors.pop(selector, None)
        self.selector_limits.pop(selector, None)
        if selector not in self.dos4gw_free_selectors:
            self.dos4gw_free_selectors.append(selector)

    def _free_dos_ah48_block(self, segment: int) -> bool:
        allocation = self.dos_ah48_allocations.pop(segment, None)
        if allocation is None:
            return False
        mcb_segment, paragraphs = allocation
        self._write_mcb(mcb_segment, b"Z", 0, paragraphs)
        self.dos_free_blocks[mcb_segment] = paragraphs
        self._coalesce_dos_free_blocks()
        return True

    def _resize_dos_block(self, regs: CpuRegs) -> str:
        requested = regs.bx
        if regs.es != self.boot.psp_segment or requested == 0:
            regs.ax = DOS_INVALID_BLOCK
            regs.carry = True
            return "dos21.resize.invalid_block"
        current = self.block_paragraphs
        maximum = current
        if self.free_segment == self.boot.psp_segment + current:
            maximum += 1 + self.free_paragraphs
        if requested > maximum:
            regs.bx = maximum
            regs.ax = DOS_INSUFFICIENT_MEMORY
            regs.carry = True
            return "dos21.resize.insufficient_memory"
        if requested == current:
            regs.carry = False
            return "dos21.resize.no_change"
        if requested < current:
            free_seg = self.boot.psp_segment + requested
            free_size = current - requested - 1
            if free_size < 0:
                regs.ax = DOS_INSUFFICIENT_MEMORY
                regs.carry = True
                return "dos21.resize.no_room_for_mcb"
            self.block_paragraphs = requested
            self.free_segment = free_seg
            self.free_paragraphs = free_size
            self.dos_free_blocks[free_seg] = free_size
            self._write_mcb(self.boot.psp_segment - 1, b"M", self.boot.psp_segment, requested)
            self._write_mcb(free_seg, b"Z", 0, free_size)
        else:
            capacity = maximum
            remainder = capacity - requested
            self.block_paragraphs = requested
            if self.free_segment is not None:
                self.dos_free_blocks.pop(self.free_segment, None)
            if remainder:
                free_seg = self.boot.psp_segment + requested
                free_size = remainder - 1
                self.free_segment = free_seg
                self.free_paragraphs = free_size
                self.dos_free_blocks[free_seg] = free_size
                self._write_mcb(self.boot.psp_segment - 1, b"M", self.boot.psp_segment, requested)
                self._write_mcb(free_seg, b"Z", 0, free_size)
            else:
                self.free_segment = None
                self.free_paragraphs = 0
                self._write_mcb(self.boot.psp_segment - 1, b"Z", self.boot.psp_segment, requested)
        struct.pack_into("<H", self.boot.memory.data, self.boot.psp_address + 2,
                         self.boot.psp_segment + self.block_paragraphs)
        regs.carry = False
        self._refresh_free_summary()
        return "dos21.resize.success"

    def dispatch(self, vector: int, regs: CpuRegs, *, eip: int | None = None, filename: str | None = None, write_data: bytes | None = None, read_buffer_address: int | None = None, device_request_address: int | None = None, device_request: bytes | None = None, device_transfer_address: int | None = None, device_transfer: bytes | None = None) -> DispatchResult:
        at = regs.eip if eip is None else eip
        if vector == 0x2F:
            function = regs.ax
            before = regs.snapshot()
            if function == 0x1500 and regs.bx == 0:
                regs.bx = len(self.cdrom_drives)
                regs.cx = (ord(self.cdrom_drives[0]) - ord("A")) if self.cdrom_drives else 0
                return DispatchResult(True, "int2f.mscdex_install_check")
            if function == 0x150C and regs.bx == 0 and self.mscdex_version is not None:
                major, minor = self.mscdex_version
                regs.bx = ((major & 0xff) << 8) | (minor & 0xff)
                return DispatchResult(True, "int2f.mscdex_get_version")
            if function == 0x1510:
                def trap(reason):
                    return DispatchResult(False, trap=ServiceTrap(vector, at, function, before, reason))
                if not self.cdrom_drives or device_request_address is None or device_request is None:
                    return trap("MSCDEX device request requires a configured drive and validated DOS request packet")
                drive_letter = chr((regs.cx & 0xffff) + ord("A")) if 0 <= regs.cx < 26 else ""
                if drive_letter not in self.cdrom_drives:
                    return trap("MSCDEX device request drive does not match configured media")
                drive_unit = self.cdrom_drives.index(drive_letter)
                if len(device_request) < 26 or device_request[0] != 0x1a:
                    return trap("MSCDEX DOS device request header is incomplete or has an unsupported length")
                if device_request[2] == 0x0c:
                    if device_transfer_address is None or device_transfer is None:
                        return trap("MSCDEX IOCTL output requires a validated transfer buffer")
                    declared = struct.unpack_from("<H", device_request, 0x12)[0]
                    if declared != len(device_transfer) or len(device_transfer) != 9:
                        return trap("MSCDEX audio channel-control output requires a nine-byte buffer")
                    if device_transfer[0] != 0x03:
                        return trap(f"MSCDEX IOCTL output subfunction {device_transfer[0]:02x} is not implemented")
                    self.cdrom_audio_channel_control = tuple(device_transfer[1:9])
                    regs.carry = False
                    return DispatchResult(True, "int2f.mscdex_audio_channel_control_set",
                        guest_writes=((device_request_address + 1, bytes((drive_unit,))),
                                      (device_request_address + 3, struct.pack("<H", 0x0100))))
                if device_request[2] in (0x84, 0x85, 0x88):
                    if drive_unit >= len(self.cdrom_images) or self.cdrom_images[drive_unit] is None:
                        return trap("MSCDEX CD-audio request requires an explicitly configured CUE image")
                    image = self.cdrom_images[drive_unit]
                    state = self.cdrom_audio_states.setdefault(drive_unit, CdAudioState())
                    try:
                        if device_request[2] == 0x84:
                            mode = device_request[0x0d]
                            start = struct.unpack_from("<I", device_request, 0x0e)[0]
                            count = struct.unpack_from("<I", device_request, 0x12)[0]
                            if mode == 1:
                                minute, second, frame = (start >> 16) & 0xff, (start >> 8) & 0xff, start & 0xff
                                frames = minute * 60 * 75 + second * 75 + frame
                                if start >> 24 or second >= 60 or frame >= 75 or frames < 150:
                                    return trap("MSCDEX CD-audio Red Book start MSF is invalid")
                                start = frames - 150
                            elif mode != 0:
                                return trap("MSCDEX CD-audio address mode must be HSG or Red Book MSF")
                            state.play(image, start, count, self.audio_sink)
                            service = "int2f.mscdex_play_audio"
                        elif device_request[2] == 0x85:
                            state.stop(self.audio_sink)
                            service = "int2f.mscdex_stop_audio"
                        else:
                            state.resume(image, self.audio_sink)
                            service = "int2f.mscdex_resume_audio"
                    except CueImageError as exc:
                        return trap(f"MSCDEX CD-audio request failed: {exc}")
                    regs.carry = False
                    return DispatchResult(True, service,
                        guest_writes=((device_request_address + 1, bytes((drive_unit,))),
                                      (device_request_address + 3, struct.pack("<H", 0x0100))))
                if device_request[2] in (0x80, 0x82):
                    if device_transfer_address is None:
                        return trap("MSCDEX read-long request requires a validated transfer buffer address")
                    if device_request[0x0d] != 0:
                        return trap("MSCDEX read-long MSF addressing is not implemented")
                    count = struct.unpack_from("<H", device_request, 0x12)[0]
                    lba = struct.unpack_from("<I", device_request, 0x14)[0]
                    raw_flag = device_request[0x18]
                    if raw_flag not in (0, 1):
                        return trap("MSCDEX read-long raw flag is invalid")
                    if drive_unit >= len(self.cdrom_images) or self.cdrom_images[drive_unit] is None:
                        return trap("MSCDEX read-long requires an explicitly configured CUE image")
                    try:
                        payload = self.cdrom_images[drive_unit].read_sectors(lba, count, raw=bool(raw_flag))
                    except (CueImageError, OSError) as exc:
                        return trap(f"MSCDEX read-long sector request failed: {exc}")
                    status = struct.pack("<H", 0x0100)
                    regs.carry = False
                    return DispatchResult(True, "int2f.mscdex_read_long" if device_request[2] == 0x80 else "int2f.mscdex_read_long_prefetch",
                        guest_writes=((device_transfer_address, payload),
                                      (device_request_address + 1, bytes((drive_unit,))),
                                      (device_request_address + 3, status)))
                if device_request[2] != 0x03:
                    return trap(f"MSCDEX DOS device command {device_request[2]:02x} is not implemented")
                if device_transfer_address is None or device_transfer is None:
                    return trap("MSCDEX IOCTL input requires a validated transfer buffer")
                declared_transfer_length=struct.unpack_from("<H",device_request,0x12)[0]
                if declared_transfer_length != len(device_transfer):
                    return trap("MSCDEX IOCTL input transfer length does not match the request packet")
                expected_length = {0x04: 9, 0x06: 5, 0x07: 4, 0x08: 5,
                                   0x09: 2, 0x0c: 11, 0x0f: 11}.get(device_transfer[0], 7)
                if len(device_transfer) != expected_length:
                    return trap(f"MSCDEX IOCTL input subfunction {device_transfer[0]:02x} requires a {expected_length}-byte transfer buffer")
                output = bytearray(device_transfer)
                if device_transfer[0] in (0x06, 0x07, 0x08, 0x09):
                    image = self.cdrom_images[drive_unit] if drive_unit < len(self.cdrom_images) else None
                    if image is None:
                        return trap("MSCDEX media status/geometry query requires an explicitly configured CUE image")
                    if device_transfer[0] == 0x06:
                        # DOSBox-X MSCDEX device status capability bits: raw+cooked,
                        # Red Book reads, audio control, and HSG addressing.
                        audio = self.cdrom_audio_states.get(drive_unit)
                        status = (1 << 2) | (1 << 4) | (1 << 8) | (1 << 9)
                        if audio is not None and audio.status == "playing":
                            status |= 1 << 10
                        output[1:5] = struct.pack("<I", status)
                        service = "int2f.mscdex_ioctl_device_status"
                    elif device_transfer[0] == 0x07:
                        mode = device_transfer[1]
                        if mode not in (0, 1):
                            return trap("MSCDEX sector-size mode must be 0 (cooked) or 1 (raw)")
                        output[2:4] = struct.pack("<H", 2048 if mode == 0 else 2352)
                        service = "int2f.mscdex_ioctl_sector_size"
                    elif device_transfer[0] == 0x08:
                        volume_frames = sum(track.sectors for track in image.tracks) + 150
                        if not 0 <= volume_frames <= 0xffffffff:
                            return trap("MSCDEX CUE volume size exceeds the 32-bit frame field")
                        output[1:5] = struct.pack("<I", volume_frames)
                        service = "int2f.mscdex_ioctl_volume_size"
                    else:
                        # Static mounted media has not changed since this host mounted it.
                        output[1] = 0
                        service = "int2f.mscdex_ioctl_media_change"
                elif device_transfer[0] == 0x0a:
                    info = self.cdrom_audio_disc_info
                    if info is None:
                        image = self.cdrom_images[drive_unit] if drive_unit < len(self.cdrom_images) else None
                        if image is None:
                            return trap("MSCDEX audio-disc metadata is not configured and no CUE image is mounted")
                        try:
                            info = image.mscdex_disc_info()
                        except CueImageError as exc:
                            return trap(f"MSCDEX disc metadata from CUE is invalid: {exc}")
                    first_track, last_track, frame, second, minute = info
                    if not (1 <= first_track <= last_track <= 99 and 0 <= frame < 75 and 0 <= second < 60 and 0 <= minute <= 99):
                        return trap("MSCDEX audio-disc metadata is outside CD track/MSF bounds")
                    output[1:7] = bytes((first_track, last_track, frame, second, minute, 0))
                    service = "int2f.mscdex_ioctl_audio_disc_info"
                elif device_transfer[0] == 0x0b:
                    track = device_transfer[1]
                    info = next((x for x in self.cdrom_audio_track_info if x[0] == track), None)
                    if info is None:
                        image = self.cdrom_images[drive_unit] if drive_unit < len(self.cdrom_images) else None
                        if image is None:
                            return trap(f"MSCDEX audio-track metadata for track {track} is not configured and no CUE image is mounted")
                        try:
                            info = image.mscdex_track_info(track)
                        except CueImageError as exc:
                            return trap(f"MSCDEX track metadata from CUE is invalid: {exc}")
                    _, frame, second, minute, attribute = info
                    if not (1 <= track <= 99 and 0 <= frame < 75 and 0 <= second < 60 and 0 <= minute <= 99 and attribute in (0x00, 0x40)):
                        return trap("MSCDEX audio-track metadata is outside track/MSF/attribute bounds")
                    output[2:7] = bytes((frame, second, minute, 0, attribute))
                    service = "int2f.mscdex_ioctl_audio_track_info"
                elif device_transfer[0] == 0x0c:
                    info = self.cdrom_audio_subchannel
                    if info is None:
                        image = self.cdrom_images[drive_unit] if drive_unit < len(self.cdrom_images) else None
                        audio = self.cdrom_audio_states.get(drive_unit)
                        if image is None:
                            return trap("MSCDEX audio subchannel state is not configured and no CUE image is mounted")
                        if audio is not None and audio.status in ("playing", "paused"):
                            return trap("MSCDEX active audio subchannel requires an explicit time-position state")
                        try:
                            info = image.mscdex_idle_subchannel()
                        except CueImageError as exc:
                            return trap(f"MSCDEX idle subchannel cannot be derived from CUE: {exc}")
                    attribute, track, index, rel_minute, rel_second, rel_frame, abs_minute, abs_second, abs_frame = info
                    values = (rel_minute, rel_second, rel_frame, abs_minute, abs_second, abs_frame)
                    if attribute not in (0x00, 0x40) or not (1 <= track <= 99 and 0 <= index <= 99) or not (
                            0 <= rel_minute <= 99 and 0 <= rel_second < 60 and 0 <= rel_frame < 75 and
                            0 <= abs_minute <= 99 and 0 <= abs_second < 60 and 0 <= abs_frame < 75):
                        return trap("MSCDEX audio subchannel state is outside track/MSF bounds")
                    output[1:11] = bytes((attribute, track, index, rel_minute, rel_second, rel_frame, 0,
                                          abs_minute, abs_second, abs_frame))
                    service = "int2f.mscdex_ioctl_audio_subchannel"
                elif device_transfer[0] == 0x04:
                    control = self.cdrom_audio_channel_control
                    if len(control) != 8 or any(not 0 <= x <= 0xff for x in control):
                        return trap("MSCDEX audio channel-control metadata must contain eight bytes")
                    output[1:9] = bytes(control)
                    service = "int2f.mscdex_ioctl_audio_channel_control"
                elif device_transfer[0] == 0x0f:
                    if len(device_transfer) != 11:
                        return trap("MSCDEX audio-status query requires an eleven-byte transfer buffer")
                    state = self.cdrom_audio_states.get(drive_unit)
                    if state is not None and state.status in ("playing", "paused") and state.start_lba is not None:
                        start = state.start_lba + 150
                        end = state.sector_count + 150  # matches DOSBox-X MSCDEX's stored audioEnd field
                        def msf(frames):
                            minute, rem = divmod(frames, 4500)
                            second, frame = divmod(rem, 75)
                            if minute > 255:
                                raise ValueError("MSF minute exceeds MSCDEX byte range")
                            return minute, second, frame
                        try:
                            start_msf, end_msf = msf(start), msf(end)
                        except ValueError as exc:
                            return trap(str(exc))
                        output[1] = 1 if state.status == "paused" else 0
                        output[3:7] = bytes((start_msf[0], start_msf[1], start_msf[2], 0))
                        output[7:11] = bytes((end_msf[0], end_msf[1], end_msf[2], 0))
                    else:
                        output[1:11] = bytes(10)
                    service = "int2f.mscdex_audio_status"
                else:
                    return trap(f"MSCDEX IOCTL input subfunction {device_transfer[0]:02x} is not implemented")
                status = struct.pack("<H", 0x0100)  # DOS driver request complete
                regs.carry = False
                return DispatchResult(True, service,
                    guest_writes=((device_transfer_address, bytes(output)),
                                  (device_request_address + 1, bytes((drive_unit,))),
                                  (device_request_address + 3, status)))
            return DispatchResult(False, trap=ServiceTrap(
                vector, at, function, before,
                "INT 2Fh multiplex service is not implemented; no success value was fabricated"))
        if vector == 0x21:
            function = regs.ah
            before = regs.snapshot()
            if function == 0x4c:
                return DispatchResult(True, "dos21.terminate_process")
            if function == 0x35:  # Get interrupt vector
                segment, offset = self.dos_interrupt_vectors.get(regs.al, (0, 0))
                regs.es = segment & 0xffff
                regs.bx = offset & 0xffff
                regs.carry = False
                return DispatchResult(True, "dos21.get_interrupt_vector")
            if function == 0x25:  # Set interrupt vector
                self.dos_interrupt_vectors[regs.al] = (regs.ds & 0xffff, regs.dx)
                regs.carry = False
                return DispatchResult(True, "dos21.set_interrupt_vector")
            if function == 0x43 and regs.al == 0x00:
                if filename is None:
                    return DispatchResult(False, trap=ServiceTrap(
                        vector, at, function, before, "DOS attribute query requires a captured DS:EDX filename"))
                try:
                    attributes = self.filesystem.attributes(filename)
                except DosFsError as exc:
                    regs.ax = exc.dos_code
                    regs.carry = True
                    return DispatchResult(True, "dos21.get_file_attributes.error")
                regs.ax = attributes
                regs.cx = attributes
                regs.carry = False
                return DispatchResult(True, "dos21.get_file_attributes")
            if function == 0x3e:
                try:
                    self.filesystem.close(regs.bx)
                except DosFsError as exc:
                    regs.ax = exc.dos_code
                    regs.carry = True
                    return DispatchResult(True, "dos21.close_file.error")
                regs.carry = False
                return DispatchResult(True, "dos21.close_file")
            if function == 0x42:
                origin = regs.al
                if origin not in (0, 1, 2):
                    regs.ax = DOS_INVALID_FUNCTION
                    regs.carry = True
                    return DispatchResult(True, "dos21.seek_file.invalid_origin")
                displacement = ((regs.cx << 16) | regs.dx) & 0xffffffff
                if displacement & 0x80000000:
                    displacement -= 0x100000000
                try:
                    position = self.filesystem.seek(regs.bx, displacement, origin)
                except DosFsError as exc:
                    regs.ax = exc.dos_code
                    regs.carry = True
                    return DispatchResult(True, "dos21.seek_file.error")
                except (OSError, ValueError):
                    regs.ax = DOS_INVALID_FUNCTION
                    regs.carry = True
                    return DispatchResult(True, "dos21.seek_file.error")
                position &= 0xffffffff
                regs.ax = position & 0xffff
                regs.dx = (position >> 16) & 0xffff
                regs.carry = False
                return DispatchResult(True, "dos21.seek_file")
            if function == 0x3F:
                address = read_buffer_address
                if regs.cx and address is None:
                    return DispatchResult(False, trap=ServiceTrap(
                        vector, at, function, before, "DOS read requires a validated DS:EDX guest buffer"))
                if address is not None and (address < 0 or address > self.boot.memory.size or regs.cx > self.boot.memory.size - address):
                    return DispatchResult(False, trap=ServiceTrap(
                        vector, at, function, before, "DOS read buffer is outside mapped guest memory"))
                try:
                    payload = self.filesystem.read(regs.bx, regs.cx)
                except DosFsError as exc:
                    regs.ax = exc.dos_code
                    regs.carry = True
                    return DispatchResult(True, "dos21.read_file.error")
                except OSError:
                    regs.ax = DosFileSystem.ERR_INVALID_HANDLE
                    regs.carry = True
                    return DispatchResult(True, "dos21.read_file.error")
                if payload and address is not None:
                    self.boot.memory.write(address, payload)
                regs.ax = len(payload)
                regs.carry = False
                writes = ((address, payload),) if payload and address is not None else ()
                return DispatchResult(True, "dos21.read_file", guest_writes=writes)
            if function == 0x40:
                if write_data is None and regs.cx:
                    return DispatchResult(False, trap=ServiceTrap(
                        vector, at, function, before, "DOS write requires captured DS:EDX buffer bytes"))
                payload = b"" if write_data is None else write_data
                if len(payload) != regs.cx:
                    return DispatchResult(False, trap=ServiceTrap(
                        vector, at, function, before, "captured DOS write buffer length does not match CX"))
                try:
                    written = self.filesystem.write(regs.bx, payload)
                except DosFsError as exc:
                    regs.ax = exc.dos_code
                    regs.carry = True
                    return DispatchResult(True, "dos21.write_file.error")
                except (PermissionError, io.UnsupportedOperation, OSError):
                    regs.ax = DosFileSystem.ERR_ACCESS_DENIED
                    regs.carry = True
                    return DispatchResult(True, "dos21.write_file.error")
                regs.ax = written
                regs.carry = False
                return DispatchResult(True, "dos21.write_file")
            if function == 0x44 and regs.al == 0x00:
                handle = self.filesystem.handles.get(regs.bx)
                if handle is None or getattr(handle.stream, "closed", False):
                    regs.ax = DosFileSystem.ERR_INVALID_HANDLE
                    regs.carry = True
                    return DispatchResult(True, "dos21.ioctl.get_device_info.invalid_handle")
                if regs.bx == 0:
                    info = 0x81
                elif regs.bx in (1, 2):
                    info = 0x82
                else:
                    info = ord(self.filesystem.drive) - ord("A")
                regs.ax = info  # DOS returns the information word in both AX and DX.
                regs.dx = info
                regs.carry = False
                return DispatchResult(True, "dos21.ioctl.get_device_info")
            if function == 0x3C:
                if filename is None:
                    return DispatchResult(False, trap=ServiceTrap(
                        vector, at, function, before, "DOS create requires a captured DS:EDX filename"))
                try:
                    handle = self.filesystem.open(filename, access="w", create=True, truncate=True)
                except DosFsError as exc:
                    regs.ax = exc.dos_code
                    regs.carry = True
                    return DispatchResult(True, "dos21.create_file.error")
                regs.ax = handle
                regs.carry = False
                return DispatchResult(True, "dos21.create_file")
            if function == 0x3D:
                if filename is None:
                    return DispatchResult(False, trap=ServiceTrap(
                        vector, at, function, before, "DOS open requires a captured DS:EDX filename"))
                mode = regs.al
                access_mode = mode & 0x07
                sharing_mode = (mode >> 4) & 0x07
                access = {0: "r", 1: "w", 2: "rw"}.get(access_mode)
                if access is None or (mode & 0x08) or sharing_mode > 4:
                    regs.ax = DOS_INVALID_ACCESS
                    regs.carry = True
                    return DispatchResult(True, "dos21.open_file.invalid_access")
                try:
                    handle = self.filesystem.open(filename, access=access)
                except DosFsError as exc:
                    regs.ax = exc.dos_code
                    regs.carry = True
                    return DispatchResult(True, "dos21.open_file.error")
                regs.ax = handle
                regs.carry = False
                return DispatchResult(True, "dos21.open_file")
            if function == 0x2C:  # Get system time (CH:CL, DH:DL)
                hour,minute,second,hundredths=self.dos_clock.time()
                regs.ch=hour; regs.cl=minute; regs.dh=second; regs.dl=hundredths
                return DispatchResult(True, "dos21.get_time")
            if function == 0x63 and regs.al == 0x00:  # Get empty DBCS lead-byte table
                # The synthetic environment starts with the double-NUL terminator,
                # which is a valid empty lead-byte table for this observed client.
                regs.ds = self.boot.env_segment
                regs.si = 0
                regs.carry = False
                return DispatchResult(True, "dos21.get_dbcs_lead_byte_table")
            if function == 0x30:  # Get DOS version (observed in extender startup)
                regs.al = self.dos_major
                regs.ah = self.dos_minor
                regs.carry = False
                return DispatchResult(True, "dos21.get_version")
            if function == 0x4A:  # Resize memory block (observed in extender startup)
                return DispatchResult(True, self._resize_dos_block(regs))
            if function == 0x48:  # Allocate DOS conventional memory block
                paragraphs = regs.bx
                segment = self._allocate_dos_ah48_block(paragraphs) if paragraphs else None
                if segment is None:
                    regs.bx = max(self.dos_free_blocks.values(), default=0)
                    regs.ax = DOS_INSUFFICIENT_MEMORY
                    regs.carry = True
                    return DispatchResult(True, "dos21.allocate_memory.insufficient_memory")
                regs.ax = segment
                regs.carry = False
                return DispatchResult(True, "dos21.allocate_memory")
            if function == 0x49:  # Free a block returned by DOS AH=48h
                if not self._free_dos_ah48_block(regs.es):
                    regs.ax = DOS_INVALID_BLOCK
                    regs.carry = True
                    return DispatchResult(True, "dos21.free_memory.invalid_block")
                regs.carry = False
                return DispatchResult(True, "dos21.free_memory")
            if regs.ax == 0xFF00 and regs.dx == 0x0078:  # DOS/4G install check
                regs.al = 0xFF
                regs.carry = False
                return DispatchResult(True, "dos21.dos4g_install_check")
            return DispatchResult(False, trap=ServiceTrap(
                vector, at, function, before,
                "DOS INT 21h function is not implemented; no success value was fabricated"))
        if vector == 0x31:
            function = regs.ax
            before = regs.snapshot()
            if function == 0x0100:  # Allocate DOS memory block
                paragraphs = regs.bx
                if paragraphs == 0:
                    regs.ax = DPMI_INVALID_VALUE; regs.carry = True
                    return DispatchResult(True, "dpmi31.allocate_dos_memory.invalid_size")
                largest_free = max(self.dos_free_blocks.values(), default=0)
                if not self.dos_free_blocks or largest_free < paragraphs:
                    regs.bx = largest_free
                    regs.ax = 8  # DPMI 0.9 passes DOS insufficient-memory code through.
                    regs.carry = True
                    return DispatchResult(True, "dpmi31.allocate_dos_memory.insufficient_memory")
                if self.next_dos_selector > 0xfff8:
                    regs.ax = 0x8011; regs.carry = True
                    return DispatchResult(True, "dpmi31.allocate_dos_memory.no_selector")
                mcb_segment = min(self.dos_free_blocks,
                                  key=lambda seg: self.dos_free_blocks[seg])
                segment = mcb_segment + 1
                selector = self.next_dos_selector
                old_size = self.dos_free_blocks.pop(mcb_segment)
                remaining = old_size - paragraphs
                if remaining:
                    next_mcb = mcb_segment + paragraphs + 1
                    free_size = remaining - 1
                    self._write_mcb(mcb_segment, b"M", self.boot.psp_segment, paragraphs)
                    self._write_mcb(next_mcb, b"Z", 0, free_size)
                    self.dos_free_blocks[next_mcb] = free_size
                else:
                    top = self.boot.memory.read_u16(self.boot.psp_address + 2)
                    self._write_mcb(mcb_segment, b"Z" if segment + paragraphs >= top else b"M",
                                    self.boot.psp_segment, paragraphs)
                self._refresh_free_summary()
                self.dos_allocations[selector] = (segment, paragraphs)
                self.dos_allocation_mcb[selector] = mcb_segment
                self.selectors[selector] = segment << 4
                self.selector_limits[selector] = paragraphs * 16 - 1
                self.next_dos_selector += 8
                regs.ax = segment
                regs.dx = selector
                regs.carry = False
                return DispatchResult(True, "dpmi31.allocate_dos_memory")
            if function == 0x0101:  # Free DOS memory block
                selector = regs.dx
                allocation = self.dos_allocations.get(selector)
                if allocation is None:
                    regs.ax = DPMI_INVALID_SELECTOR; regs.carry = True
                    return DispatchResult(True, "dpmi31.free_dos_memory.invalid_selector")
                _, paragraphs = allocation
                mcb_segment = self.dos_allocation_mcb.pop(selector)
                self.dos_allocations.pop(selector)
                self.selectors.pop(selector, None)
                self.selector_limits.pop(selector, None)
                self.dos_free_blocks[mcb_segment] = paragraphs
                self._coalesce_dos_free_blocks()
                regs.carry = False
                return DispatchResult(True, "dpmi31.free_dos_memory")
            if function == 0x0102:  # Resize DOS memory block
                selector = regs.dx
                requested = regs.bx
                allocation = self.dos_allocations.get(selector)
                if allocation is None:
                    regs.ax = DPMI_INVALID_SELECTOR; regs.carry = True
                    return DispatchResult(True, "dpmi31.resize_dos_memory.invalid_selector")
                if requested == 0:
                    regs.ax = 9; regs.carry = True
                    return DispatchResult(True, "dpmi31.resize_dos_memory.invalid_size")
                segment, current = allocation
                mcb_segment = self.dos_allocation_mcb[selector]
                if requested < current:
                    tail_mcb = mcb_segment + requested + 1
                    tail_size = current - requested - 1
                    self.dos_allocations[selector] = (segment, requested)
                    self._write_mcb(mcb_segment, b"M", self.boot.psp_segment, requested)
                    self.dos_free_blocks[tail_mcb] = tail_size
                    self.selector_limits[selector] = requested * 16 - 1
                    self._coalesce_dos_free_blocks()
                    regs.carry = False
                    return DispatchResult(True, "dpmi31.resize_dos_memory.shrink")
                if requested == current:
                    regs.carry = False
                    return DispatchResult(True, "dpmi31.resize_dos_memory.no_change")
                following_mcb = mcb_segment + current + 1
                following_size = self.dos_free_blocks.get(following_mcb)
                maximum = current if following_size is None else current + 1 + following_size
                if requested > maximum:
                    regs.ax = 8
                    regs.bx = max(self.dos_free_blocks.values(), default=0)
                    regs.carry = True
                    return DispatchResult(True, "dpmi31.resize_dos_memory.insufficient_memory")
                self.dos_free_blocks.pop(following_mcb)
                remaining = maximum - requested
                self.dos_allocations[selector] = (segment, requested)
                if remaining:
                    free_mcb = mcb_segment + requested + 1
                    free_size = remaining - 1
                    self.dos_free_blocks[free_mcb] = free_size
                    self._write_mcb(mcb_segment, b"M", self.boot.psp_segment, requested)
                    self._write_mcb(free_mcb, b"Z", 0, free_size)
                else:
                    top = self.boot.memory.read_u16(self.boot.psp_address + 2)
                    self._write_mcb(mcb_segment, b"Z" if segment + requested >= top else b"M",
                                    self.boot.psp_segment, requested)
                self.selector_limits[selector] = requested * 16 - 1
                self._refresh_free_summary()
                regs.carry = False
                return DispatchResult(True, "dpmi31.resize_dos_memory.grow")
            if function == 0x0200:  # DPMI Get Real Mode Interrupt Vector
                vector = regs.bl
                segment, offset = self.real_mode_interrupt_vectors.get(vector, (0, 0))
                regs.cx = segment
                regs.dx = offset
                regs.carry = False
                return DispatchResult(True, "dpmi31.get_real_mode_interrupt_vector")
            if function == 0x0201:  # DPMI Set Real Mode Interrupt Vector
                vector = regs.bl
                segment = regs.cx
                offset = regs.dx
                self.real_mode_interrupt_vectors[vector] = (segment, offset)
                regs.carry = False
                return DispatchResult(True, "dpmi31.set_real_mode_interrupt_vector")
            if function in (0x0600, 0x0601):  # Lock / Unlock Linear Region
                start = ((regs.bx << 16) | regs.cx) & 0xffffffff
                size = ((regs.si << 16) | regs.di) & 0xffffffff
                end = start + size
                if size == 0:
                    regs.ax = DPMI_INVALID_VALUE; regs.carry = True
                    return DispatchResult(True, "dpmi31.lock.invalid_size")
                if end > 0xffffffff or end > self.boot.memory.size:
                    regs.ax = 0x8025; regs.carry = True
                    return DispatchResult(True, "dpmi31.lock.invalid_linear_range")
                if not self.dpmi_virtual_memory:
                    regs.carry = False
                    return DispatchResult(True, "dpmi31.lock.no_paging_host")
                pages = range(start >> 12, ((end - 1) >> 12) + 1)
                page_list = tuple(pages)
                if function == 0x0600:
                    if any(self.locked_pages.get(page, 0) >= 0xffff for page in page_list):
                        regs.ax = 0x8017; regs.carry = True
                        return DispatchResult(True, "dpmi31.lock.count_exceeded")
                    for page in page_list:
                        self.locked_pages[page] = self.locked_pages.get(page, 0) + 1
                    regs.carry = False
                    return DispatchResult(True, "dpmi31.lock.success")
                if any(self.locked_pages.get(page, 0) == 0 for page in page_list):
                    regs.ax = 0x8002; regs.carry = True
                    return DispatchResult(True, "dpmi31.unlock.not_locked")
                for page in page_list:
                    count = self.locked_pages[page] - 1
                    if count: self.locked_pages[page] = count
                    else: del self.locked_pages[page]
                regs.carry = False
                return DispatchResult(True, "dpmi31.unlock.success")
            if function == 0x0501:  # DPMI Allocate Memory Block (linear)
                size = ((regs.bx << 16) | regs.cx) & 0xffffffff
                if size == 0:
                    regs.ax = DPMI_INVALID_VALUE; regs.carry = True
                    return DispatchResult(True, "dpmi31.allocate_memory.invalid_size")
                base = (self.next_allocation + 0xfff) & ~0xfff
                end = base + size
                if end > self.allocation_limit or end > 0xffffffff:
                    regs.ax = DPMI_LINEAR_UNAVAILABLE; regs.carry = True
                    return DispatchResult(True, "dpmi31.allocate_memory.unavailable")
                try:
                    self.boot.memory.ensure_size(end)
                except Exception:
                    regs.ax = DPMI_LINEAR_UNAVAILABLE; regs.carry = True
                    return DispatchResult(True, "dpmi31.allocate_memory.unavailable")
                handle = self.next_handle; self.next_handle += 1
                self.allocations[handle] = (base, size)
                self.next_allocation = end
                regs.bx = (base >> 16) & 0xffff; regs.cx = base & 0xffff
                regs.si = (handle >> 16) & 0xffff; regs.di = handle & 0xffff
                regs.carry = False
                return DispatchResult(True, "dpmi31.allocate_memory")
            if function == 0x0006:  # DPMI Get Segment Base Address
                if regs.bx not in self.selectors:
                    regs.ax = DPMI_INVALID_SELECTOR
                    regs.carry = True
                    return DispatchResult(True, "dpmi31.get_segment_base.invalid_selector")
                base = self.selectors[regs.bx]
                regs.cx = (base >> 16) & 0xFFFF
                regs.dx = base & 0xFFFF
                regs.carry = False
                return DispatchResult(True, "dpmi31.get_segment_base")
            return DispatchResult(False, trap=ServiceTrap(
                vector, at, function, before,
                "DPMI INT 31h function is not implemented; no success value was fabricated"))
        before = regs.snapshot()
        return DispatchResult(False, trap=ServiceTrap(
            vector, at, 0, before,
            "Interrupt vector is not implemented; no success value was fabricated"))
