import os as _gw_os
from pathlib import Path as _GwPath
_GW_ROOT=str(_GwPath(__file__).resolve().parents[1])
_GW_FX=_gw_os.environ.get("GENEWARSFX_ROOT",_gw_os.path.join(_GW_ROOT,"third_party","GeneWarsFX"))
import hashlib as _hashlib


class _OrigDigest:
    """Stands in for a byte string taken from the original game.

    Only its SHA-256 and length are stored in the repository. Comparing it with
    bytes (or a hex string) from the user's own locally provided game files
    succeeds when they hash to the recorded value.
    """

    def __init__(self, sha256, length):
        self.sha256 = sha256
        self.length = length

    def __len__(self):
        return self.length

    def __eq__(self, other):
        if isinstance(other, str):
            try:
                other = bytes.fromhex(other.replace(" ", ""))
            except ValueError:
                return False
        if not isinstance(other, (bytes, bytearray, memoryview)):
            return NotImplemented
        other = bytes(other)
        return len(other) == self.length and _hashlib.sha256(other).hexdigest() == self.sha256

    def __ne__(self, other):
        r = self.__eq__(other)
        return r if r is NotImplemented else not r

    __hash__ = None

    def __repr__(self):
        return "<original bytes sha256=%s len=%d>" % (self.sha256, self.length)
import hashlib
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence" / "cd_present_gate_work3.json"
CUE = Path((_GW_FX + '\\\\evidence\\\\original_disc\\\\Genewars (Europe) (En,Fr,De,Es,It,Sv).cue'))
EXPECTED_TARGET = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
EXPECTED_CUE = "1d417e3aed625d4f054b51054a1211562a19cd4f712b08e7846613517228a5b5"

class CdPresentGateWork3(unittest.TestCase):
    def test_fresh_cue_replay_and_mscdex_frontier(self):
        data = json.loads(EVIDENCE.read_text(encoding="utf-8"))
        mode = data["fixture_mode"]
        self.assertEqual(data["target_sha256"], EXPECTED_TARGET)
        self.assertEqual(mode["command_tail"], "-k")
        self.assertEqual(mode["config_sha256"], hashlib.sha256(b"").hexdigest())
        self.assertEqual(mode["cdrom_drives"], ["D"])
        self.assertIsNone(mode["audio_disc_override"])
        self.assertEqual(mode["audio_track_override"], [])
        self.assertIsNone(mode["audio_subchannel_override"])
        self.assertTrue(mode["cue_read_only_mount"])
        self.assertEqual(mode["cue_sha256_before"], EXPECTED_CUE)
        self.assertEqual(mode["cue_sha256_after"], EXPECTED_CUE)
        self.assertEqual(hashlib.sha256(CUE.read_bytes()).hexdigest(), EXPECTED_CUE)
        self.assertTrue(data["read_only_reference_unchanged"])

        files = data["runtime_files"]
        for item in files:
            self.assertEqual(hashlib.sha256((ROOT / item["path"]).read_bytes()).hexdigest(), item["sha256"], item["path"])
        aggregate = hashlib.sha256("".join(x["path"] + ":" + x["sha256"] + "\n" for x in files).encode()).hexdigest()
        self.assertEqual(data["runtime_sha256"], aggregate)

        calls = data["cdrom_request_events"]
        self.assertEqual(len(calls), 8)
        observed = []
        writes = []
        for call in calls:
            rm = call["real_mode_interrupt"]
            self.assertEqual(rm["vector"], 0x2f)
            self.assertEqual(rm["registers_before"]["eax"], "0x00001510")
            req = rm["device_request"]
            self.assertEqual(req["command"], 3)
            self.assertEqual(int(rm["registers_after"]["eflags"], 16) & 1, 0)
            observed.append((req["transfer_before_hex"], rm["service"]))
            writes.append(call["guest_writes"][0]["data_hex"])
            self.assertEqual(call["guest_writes"][2]["data_hex"], "0001")
        self.assertEqual(observed, [
            ("0a000000000000", "int2f.mscdex_ioctl_audio_disc_info"),
            ("0b01053c263b00", "int2f.mscdex_ioctl_audio_track_info"),
            ("0b020002000040", "int2f.mscdex_ioctl_audio_track_info"),
            ("0b031a26160000", "int2f.mscdex_ioctl_audio_track_info"),
            ("0b04032d1f0000", "int2f.mscdex_ioctl_audio_track_info"),
            ("0b050226290000", "int2f.mscdex_ioctl_audio_track_info"),
            ("0c052a3436000000000000", "int2f.mscdex_ioctl_audio_subchannel"),
            ("040000010002000300", "int2f.mscdex_ioctl_audio_channel_control"),
        ])
        self.assertEqual(writes, [
            "0a01053c263b00", "0b010002000040", "0b021a26160000",
            "0b03032d1f0000", "0b040226290000", "0b052a34360000",
            "0c40010100000000000200", "040000000000000000",
        ])

        self.assertEqual(data["stop_reason"], "backend_error")
        fault = data["first_unsupported"]
        self.assertEqual((fault["kind"], fault["access"], fault["address"], fault["eip"]),
                         ("memory", 20, "0x00000000", "0x00194b5a"))
        self.assertEqual(fault["instruction_bytes"], _OrigDigest("d008baf9247274b8dfcb3bf3dbdd807a5fb545e2d1ea2fb76af6bc55f70b720f",15))
        self.assertEqual(data["executed_instruction_count"], 7771728)
        self.assertFalse(data.get("menu_reached", False))

if __name__ == "__main__":
    unittest.main()
