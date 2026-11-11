"""Bounded, read-only CUE/BIN sector reader for MSCDEX device requests."""
from __future__ import annotations

from dataclasses import dataclass
import pathlib
import re


@dataclass(frozen=True)
class CueTrack:
    path: pathlib.Path
    number: int
    mode: str
    sector_size: int
    lba_start: int
    sectors: int
    index01: int


class CueImageError(ValueError):
    pass


class CueImage:
    """Read sectors from an explicitly configured, single-track-per-FILE CUE."""

    def __init__(self, tracks: tuple[CueTrack, ...], max_sectors: int = 64):
        if not tracks or max_sectors <= 0:
            raise CueImageError("CUE image requires tracks and a positive request bound")
        self.tracks = tuple(tracks)
        self.max_sectors = max_sectors

    @staticmethod
    def _frames(msf: str) -> int:
        match = re.fullmatch(r"(\d+):(\d{2}):(\d{2})", msf)
        if not match:
            raise CueImageError(f"invalid CUE MSF: {msf}")
        minute, second, frame = map(int, match.groups())
        if second >= 60 or frame >= 75:
            raise CueImageError(f"CUE MSF out of range: {msf}")
        return minute * 60 * 75 + second * 75 + frame

    @classmethod
    def from_cue(cls, cue_path: pathlib.Path, max_sectors: int = 64) -> "CueImage":
        cue_path = pathlib.Path(cue_path).resolve(strict=True)
        current_file = None
        current_track = None
        tracks = []
        lba_start = 0
        file_tracks = 0
        def finalize_track():
            nonlocal lba_start, current_track
            if current_track is None:
                return
            if current_file is None or "index01" not in current_track:
                raise CueImageError("CUE track is missing FILE or INDEX 01")
            sector_size = 2048 if current_track["mode"] == "MODE1/2048" else 2352
            if current_track["mode"] not in ("MODE1/2048", "MODE1/2352", "AUDIO"):
                raise CueImageError(f"unsupported CUE track mode: {current_track['mode']}")
            byte_size = current_file.stat().st_size
            if byte_size % sector_size:
                raise CueImageError("track file size is not sector-aligned")
            sectors = byte_size // sector_size
            tracks.append(CueTrack(current_file, current_track["number"], current_track["mode"],
                                   sector_size, lba_start, sectors, current_track["index01"]))
            lba_start += sectors
            current_track = None
        for raw in cue_path.read_text(encoding="utf-8-sig").splitlines():
            line = raw.strip()
            fm = re.match(r'^FILE\s+"([^"]+)"\s+BINARY$', line, re.IGNORECASE)
            if fm:
                finalize_track()
                current_file = (cue_path.parent / fm.group(1)).resolve(strict=True)
                file_tracks = 0
                continue
            tm = re.match(r"^TRACK\s+(\d+)\s+(\S+)$", line, re.IGNORECASE)
            if tm:
                finalize_track()
                if current_file is None:
                    raise CueImageError("CUE TRACK must follow one BINARY FILE")
                if file_tracks:
                    raise CueImageError("only one TRACK per FILE is supported")
                file_tracks += 1
                current_track = {"number": int(tm.group(1)), "mode": tm.group(2).upper()}
                continue
            im = re.match(r"^INDEX\s+01\s+(\d+:\d{2}:\d{2})$", line, re.IGNORECASE)
            if im and current_track is not None:
                current_track["index01"] = cls._frames(im.group(1))
                continue
            if line and not line.startswith(("REM ", "TITLE ", "PERFORMER ", "FLAGS ", "PREGAP ", "INDEX ")):
                raise CueImageError(f"unsupported CUE directive: {line}")
        finalize_track()
        if not tracks:
            raise CueImageError("CUE contains no supported tracks")
        return cls(tuple(tracks), max_sectors)

    def read_sectors(self, lba: int, count: int, raw: bool = False) -> bytes:
        if not isinstance(lba, int) or not isinstance(count, int) or lba < 0 or not 1 <= count <= self.max_sectors:
            raise CueImageError("sector request has invalid LBA/count or exceeds configured bound")
        end = lba + count
        if end > 0xffffffff:
            raise CueImageError("sector request overflows LBA range")
        track = next((t for t in self.tracks if t.lba_start <= lba and end <= t.lba_start + t.sectors), None)
        if track is None:
            raise CueImageError("sector request is outside one configured track")
        if not raw and track.mode == "AUDIO":
            raise CueImageError("cooked sector reads are not supported for audio tracks")
        if raw and track.sector_size != 2352:
            raise CueImageError("raw reads require 2352-byte sectors")
        offset = (lba - track.lba_start) * track.sector_size
        with track.path.open("rb") as stream:
            stream.seek(offset)
            data = stream.read(count * track.sector_size)
        if len(data) != count * track.sector_size:
            raise CueImageError("track image ended during sector read")
        if raw or track.sector_size == 2048:
            return data
        return b"".join(data[i * 2352 + 16:i * 2352 + 2064] for i in range(count))

    def validate_audio_range(self, lba: int, count: int) -> CueTrack:
        if not isinstance(lba, int) or not isinstance(count, int) or lba < 0 or count <= 0:
            raise CueImageError("audio play request has invalid LBA or sector count")
        end = lba + count
        if end > 0xffffffff:
            raise CueImageError("audio play request overflows LBA range")
        track = next((t for t in self.tracks
                      if t.mode == "AUDIO" and t.lba_start + t.index01 <= lba
                      and end <= t.lba_start + t.sectors), None)
        if track is None:
            raise CueImageError("audio play range must fit inside one configured AUDIO track")
        return track

    @staticmethod
    def _red_book_msf(frame: int) -> tuple[int, int, int]:
        if not isinstance(frame, int) or frame < 0:
            raise CueImageError("CUE track position is invalid")
        minute, remainder = divmod(frame, 4500)
        second, frame = divmod(remainder, 75)
        if minute > 99:
            raise CueImageError("CUE position exceeds MSCDEX minute field")
        return frame, second, minute

    def mscdex_disc_info(self) -> tuple[int, int, int, int, int]:
        """Return (first, last, frame, second, minute) for IOCTL 0A."""
        tracks = [track.number for track in self.tracks]
        if any(not 1 <= number <= 99 for number in tracks):
            raise CueImageError("CUE track number is outside MSCDEX bounds")
        first, last = min(tracks), max(tracks)
        leadout = max(track.lba_start + track.sectors for track in self.tracks) + 150
        frame, second, minute = self._red_book_msf(leadout)
        return first, last, frame, second, minute

    def mscdex_track_info(self, number: int) -> tuple[int, int, int, int, int]:
        """Return (number, frame, second, minute, attribute) for IOCTL 0B."""
        track = next((track for track in self.tracks if track.number == number), None)
        if track is None:
            raise CueImageError(f"CUE has no track {number}")
        if not 1 <= track.number <= 99:
            raise CueImageError("CUE track number is outside MSCDEX bounds")
        absolute = track.lba_start + track.index01 + 150
        frame, second, minute = self._red_book_msf(absolute)
        attribute = 0x40 if track.mode.startswith("MODE1/") else 0x00
        return track.number, frame, second, minute, attribute

    def mscdex_idle_subchannel(self) -> tuple[int, int, int, int, int, int, int, int, int]:
        """Infer the initial idle head position at the first track's INDEX 01."""
        track = min(self.tracks, key=lambda item: item.number)
        number, frame, second, minute, attribute = self.mscdex_track_info(track.number)
        return attribute, number, 1, 0, 0, 0, minute, second, frame


@dataclass
class CdAudioState:
    """Logical CD-DA state; it records requests but does not render audio."""
    status: str = "stopped"
    start_lba: int | None = None
    sector_count: int = 0

    def play(self, image: CueImage, lba: int, count: int, sink=None) -> str:
        image.validate_audio_range(lba, count)
        resume = self.status == "paused" and self.start_lba == lba and self.sector_count == count
        self.start_lba, self.sector_count, self.status = lba, count, "playing"
        if sink is not None:
            (sink.cd_resume() if resume else sink.cd_play(lba, count))
        return "resume" if resume else "play"

    def stop(self, sink=None):
        if self.status == "playing":
            self.status = "paused"
            operation = "pause"
            if sink is not None:
                sink.cd_pause(self.start_lba, self.sector_count)
        else:
            self.status, self.start_lba, self.sector_count = "stopped", None, 0
            operation = "stop"
            if sink is not None:
                sink.cd_stop()
        return operation

    def resume(self, image: CueImage, sink=None):
        if self.status != "paused" or self.start_lba is None or self.sector_count <= 0:
            raise CueImageError("audio resume requires a paused range created by play")
        image.validate_audio_range(self.start_lba, self.sector_count)
        self.status = "playing"
        if sink is not None:
            sink.cd_resume()
