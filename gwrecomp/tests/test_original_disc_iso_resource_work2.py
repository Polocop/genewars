import os as _gw_os
from pathlib import Path as _GwPath
_GW_ROOT=str(_GwPath(__file__).resolve().parents[1])
_GW_FX=_gw_os.environ.get("GENEWARSFX_ROOT",_gw_os.path.join(_GW_ROOT,"third_party","GeneWarsFX"))
import hashlib
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime"))
from dos_cdrom import CueImage
from dos_filesystem import DosFsError
from dos_services import DosHost
from guest_boot import prepare_guest

CUE = pathlib.Path((_GW_FX + '\\evidence\\original_disc\\Genewars (Europe) (En,Fr,De,Es,It,Sv).cue'))
TARGET = ROOT / "evidence" / "genewars-1_1.exe"
EXPECTED_CUE_SHA256 = "1d417e3aed625d4f054b51054a1211562a19cd4f712b08e7846613517228a5b5"
EXPECTED_TEXT_SHA256 = "23e60305a9fa028a0f6541456ab453b7e7cc439f787a2b75e4b8d088e0b01786"
EXPECTED_TEXT_SIZE = 36610

class OriginalDiscIsoResourceTests(unittest.TestCase):
    def test_original_cd_nested_text_resource_and_flat_request_contract(self):
        self.assertEqual(hashlib.sha256(CUE.read_bytes()).hexdigest(), EXPECTED_CUE_SHA256)
        image = CueImage.from_cue(CUE)
        host = DosHost(prepare_guest(TARGET), cdrom_drives=("D",), cdrom_images=(image,))
        self.assertIsNone(host.iso_mount_error)
        self.assertIsNotNone(host.filesystem.iso_volume)
        self.assertIn("GAME", host.filesystem.iso_volume.listdir())

        handle = host.filesystem.open("GAME/DATA/TEXT/ENG/TEXT.DAT")
        try:
            payload = host.filesystem.read(handle, EXPECTED_TEXT_SIZE + 1)
        finally:
            host.filesystem.close(handle)
        self.assertEqual(len(payload), EXPECTED_TEXT_SIZE)
        self.assertEqual(hashlib.sha256(payload).hexdigest(), EXPECTED_TEXT_SHA256)

        with self.assertRaises(DosFsError) as missing:
            host.filesystem.open("DATA/TEXT.DAT")
        self.assertEqual(missing.exception.dos_code, host.filesystem.ERR_FILE_NOT_FOUND)
        self.assertEqual(hashlib.sha256(CUE.read_bytes()).hexdigest(), EXPECTED_CUE_SHA256)

if __name__ == "__main__":
    unittest.main()
