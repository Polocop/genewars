"""Deterministic host-facing timer, input, indexed video and audio interfaces."""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Callable


class MonotonicTimer:
    def __init__(self, *, clock_ns: Callable[[], int] = time.monotonic_ns, ticks_per_second: int = 1000):
        if ticks_per_second <= 0:
            raise ValueError("ticks_per_second must be positive")
        self.clock_ns = clock_ns
        self.ticks_per_second = ticks_per_second
        self._origin_ns = clock_ns()
        self._last_tick = 0

    def ticks(self) -> int:
        elapsed = max(0, self.clock_ns() - self._origin_ns)
        tick = (elapsed * self.ticks_per_second) // 1_000_000_000
        self._last_tick = max(self._last_tick, tick)
        return self._last_tick

    def elapsed(self, start_tick: int) -> int:
        return max(0, self.ticks() - start_tick)


class DosClock:
    """Monotonic DOS wall clock with deterministic initial time and 10 ms units."""
    def __init__(self, *, clock_ns: Callable[[], int] = time.monotonic_ns,
                 start_time: tuple[int, int, int, int] = (0, 0, 0, 0),
                 minimum_step_cs: int = 0):
        h,m,s,cs=start_time
        if not (0<=h<24 and 0<=m<60 and 0<=s<60 and 0<=cs<100):
            raise ValueError("DOS time fields outside 24-hour clock range")
        self.clock_ns=clock_ns
        self._origin_ns=clock_ns()
        if minimum_step_cs < 0: raise ValueError("minimum DOS clock step cannot be negative")
        self._start_cs=((h*60+m)*60+s)*100+cs
        self.minimum_step_cs=minimum_step_cs
        self._reads=0
        self._last_cs=0
    def time(self) -> tuple[int,int,int,int]:
        self._reads+=1
        elapsed=max(0,(self.clock_ns()-self._origin_ns)//10_000_000)
        virtual=self._reads*self.minimum_step_cs
        self._last_cs=max(self._last_cs,elapsed,virtual)
        total=(self._start_cs+self._last_cs)%(24*60*60*100)
        cs=total%100; sec=(total//100)%60; minute=(total//6000)%60; hour=total//360000
        return hour,minute,sec,cs


class PIT8254:
    """Deterministic port-level model for the three programmable timer channels."""
    def __init__(self):
        self.control_word = 0
        self.reload = [0, 0, 0]
        self.write_low = [None, None, None]
        self.write_high_next = [False, False, False]
        self.write_access = [3, 3, 3]
        self.read_access = [3, 3, 3]
        self.read_high_next = [False, False, False]
        self.read_latch = [None, None, None]
        self.latch_pending = [False, False, False]
        self.virtual_cycles = 0
        self.reload_cycle = [0, 0, 0]

    def advance(self, cycles: int = 1):
        if cycles < 0:
            raise ValueError("PIT virtual cycles cannot move backwards")
        self.virtual_cycles += int(cycles)

    def _current_count(self, channel: int) -> int:
        period = self.reload[channel]
        if period == 0:
            return 0
        elapsed = max(0, self.virtual_cycles - self.reload_cycle[channel])
        mode = (self.control_word >> 1) & 7
        if mode in (2, 3, 6, 7):
            count = period - (elapsed % period)
        else:
            count = max(0, period - elapsed)
        return count & 0xffff

    def write(self, port: int, value: int, size: int = 1) -> bool:
        if size != 1 or not 0 <= value <= 0xff:
            return False
        if port == 0x43:
            self.control_word = value
            channel = (value >> 6) & 3
            access = (value >> 4) & 3
            if channel == 3:  # 8254 read-back command is not required by measured startup yet.
                return False
            if access == 0:
                self.read_latch[channel] = self._current_count(channel)
                self.latch_pending[channel] = True
                self.read_high_next[channel] = False
            else:
                self.latch_pending[channel] = False
                self.read_latch[channel] = None
                self.write_access[channel] = access
                self.read_access[channel] = access
                self.write_high_next[channel] = False
                self.read_high_next[channel] = access == 2
            return True
        if port in (0x40, 0x41, 0x42):
            channel = port - 0x40
            if self.write_access[channel] == 3 and self.write_high_next[channel]:
                low = self.write_low[channel]
                self.reload[channel] = ((value << 8) | (low or 0)) or 0x10000
                self.reload_cycle[channel] = self.virtual_cycles
                self.write_low[channel] = None
                self.write_high_next[channel] = False
            elif self.write_access[channel] == 3:
                self.write_low[channel] = value
                self.write_high_next[channel] = True
            elif self.write_access[channel] == 2:
                self.reload[channel] = ((value << 8) | (self.reload[channel] & 0xff)) or 0x10000
                self.reload_cycle[channel] = self.virtual_cycles
            else:
                self.reload[channel] = value or 0x10000
                self.reload_cycle[channel] = self.virtual_cycles
            return True
        return False

    def read(self, port: int, size: int = 1) -> int | None:
        if size != 1 or port not in (0x40, 0x41, 0x42):
            return None
        channel = port - 0x40
        count = self.read_latch[channel]
        if count is None:
            count = self._current_count(channel)
        if self.read_access[channel] == 2:
            self.read_latch[channel] = None
            self.latch_pending[channel] = False
            return (count >> 8) & 0xff
        if self.read_high_next[channel]:
            self.read_high_next[channel] = False
            if self.latch_pending[channel]:
                self.read_latch[channel] = None
                self.latch_pending[channel] = False
            return (count >> 8) & 0xff
        value = count & 0xff
        if self.read_access[channel] == 3:
            self.read_high_next[channel] = True
        else:
            self.read_latch[channel] = None
            self.latch_pending[channel] = False
        return value

@dataclass
class InputSnapshot:
    keys_down: frozenset[int] = frozenset()
    mouse_x: int = 0
    mouse_y: int = 0
    mouse_buttons: int = 0
    sequence: int = 0


class HostInput:
    def __init__(self):
        self._keys: set[int] = set()
        self._mouse_x = 0
        self._mouse_y = 0
        self._buttons = 0
        self._sequence = 0

    def key(self, key_code: int, down: bool):
        if down:
            self._keys.add(int(key_code))
        else:
            self._keys.discard(int(key_code))
        self._sequence += 1

    def mouse(self, x: int, y: int, buttons: int):
        self._mouse_x, self._mouse_y, self._buttons = int(x), int(y), int(buttons) & 0xFF
        self._sequence += 1

    def snapshot(self) -> InputSnapshot:
        return InputSnapshot(frozenset(self._keys), self._mouse_x, self._mouse_y,
                             self._buttons, self._sequence)


@dataclass(frozen=True)
class PresentEvent:
    frame: int
    width: int
    height: int
    pixel_sha256: str


class IndexedVideo:
    def __init__(self, width: int, height: int,
                 present_callback: Callable[[bytes, tuple[tuple[int, int, int], ...], int, int], None] | None = None):
        if width <= 0 or height <= 0:
            raise ValueError("framebuffer dimensions must be positive")
        self.width, self.height = width, height
        self.pixels = bytearray(width * height)
        self.palette = [(0, 0, 0)] * 256
        self.events: list[PresentEvent] = []
        self.present_callback = present_callback

    def set_palette(self, first: int, colors):
        colors = tuple(tuple(int(c) for c in rgb) for rgb in colors)
        if first < 0 or first + len(colors) > 256:
            raise ValueError("palette range outside 0..255")
        if any(len(rgb) != 3 or any(c < 0 or c > 255 for c in rgb) for rgb in colors):
            raise ValueError("palette entries must be RGB triples in 0..255")
        self.palette[first:first + len(colors)] = colors

    def write_pixels(self, x: int, y: int, width: int, height: int, pixels: bytes):
        if width < 0 or height < 0 or x < 0 or y < 0 or x + width > self.width or y + height > self.height:
            raise ValueError("pixel rectangle outside framebuffer")
        if len(pixels) != width * height:
            raise ValueError("pixel payload length does not match rectangle")
        for row in range(height):
            dst = (y + row) * self.width + x
            src = row * width
            self.pixels[dst:dst + width] = pixels[src:src + width]

    def present(self) -> PresentEvent:
        payload = bytes(self.pixels)
        event = PresentEvent(len(self.events) + 1, self.width, self.height,
                             hashlib.sha256(payload).hexdigest())
        if self.present_callback is not None:
            self.present_callback(payload, tuple(self.palette), self.width, self.height)
        self.events.append(event)
        return event


@dataclass(frozen=True)
class AudioEvent:
    sequence: int
    operation: str
    sample_id: int | None = None
    volume: int | None = None
    pan: int | None = None
    start_lba: int | None = None
    sector_count: int | None = None


class AudioEventSink:
    """Trace-only sink: recording a request does not claim audible playback."""
    def __init__(self):
        self.events: list[AudioEvent] = []

    def _append(self, operation: str, sample_id=None, volume=None, pan=None, start_lba=None, sector_count=None):
        event = AudioEvent(len(self.events) + 1, operation, sample_id, volume, pan, start_lba, sector_count)
        self.events.append(event)
        return event

    def play(self, sample_id: int, *, volume: int = 255, pan: int = 0):
        if not 0 <= volume <= 255 or not -127 <= pan <= 127:
            raise ValueError("volume must be 0..255 and pan -127..127")
        return self._append("play", int(sample_id), int(volume), int(pan))

    def stop(self, sample_id: int | None = None):
        return self._append("stop", None if sample_id is None else int(sample_id))

    def set_master_volume(self, volume: int):
        if not 0 <= volume <= 255:
            raise ValueError("volume must be 0..255")
        return self._append("master_volume", volume=int(volume))

    def cd_play(self, start_lba: int, sector_count: int):
        return self._append("cd_play", start_lba=int(start_lba), sector_count=int(sector_count))

    def cd_pause(self, start_lba: int | None, sector_count: int):
        return self._append("cd_pause", start_lba=start_lba, sector_count=int(sector_count))

    def cd_resume(self):
        return self._append("cd_resume")

    def cd_stop(self):
        return self._append("cd_stop")


@dataclass
class HostDevices:
    timer: MonotonicTimer = field(default_factory=MonotonicTimer)
    dos_clock: DosClock = field(default_factory=DosClock)
    input: HostInput = field(default_factory=HostInput)
    audio: AudioEventSink = field(default_factory=AudioEventSink)
    video: IndexedVideo | None = None

    def configure_video(self, width: int, height: int, present_callback=None) -> IndexedVideo:
        self.video = IndexedVideo(width, height, present_callback)
        return self.video
