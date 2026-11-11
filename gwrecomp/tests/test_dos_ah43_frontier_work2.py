"""C Runtime check for the measured AH=4300 path and current unknown frontier."""
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tests" / "test_dos_ah43_frontier_work2.c"
EXE = ROOT / "build" / "test_dos_ah43_frontier_work2.exe"
W1 = ROOT / "evidence" / "native_setup_config_reconciled_work1_20261008.json"
CC = pathlib.Path(r"E:\msys64\mingw32\bin\gcc.exe")


def run_test_binary():
    cache=ROOT/"cache"; cache.mkdir(exist_ok=True)
    env={**os.environ,"TEMP":str(cache),"TMP":str(cache),"TMPDIR":str(cache),
         "PATH":r"E:\msys64\mingw32\bin;E:\msys64\usr\bin;"+os.environ.get("PATH","")}
    cmd=[str(CC),"-std=gnu11","-m32","-O0","-I",str(ROOT/"runtime"),
         "-I",str(ROOT/"third_party"/"pcrecomp"/"runtime"/"recomp32"),
         str(SOURCE),str(ROOT/"runtime"/"gw_dos_services.c"),
         str(ROOT/"runtime"/"gw_segments.c"),str(ROOT/"runtime"/"gw_interrupts.c"),
         "-o",str(EXE)]
    cp=subprocess.run(cmd,cwd=ROOT,env=env,text=True,capture_output=True)
    if cp.returncode: raise AssertionError(f"compile failed:\n{cp.stdout}\n{cp.stderr}")
    rp=subprocess.run([str(EXE)],cwd=ROOT,env=env,text=True,capture_output=True)
    if rp.returncode: raise AssertionError(f"C test failed ({rp.returncode}):\n{rp.stdout}\n{rp.stderr}")
    return rp.stdout


class DosAh43FrontierWork2(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.w1=json.loads(W1.read_text(encoding="utf-8"))
        cls.stdout=run_test_binary()

    def test_current_sound_ini_frontier_is_recorded_exactly(self):
        self.assertIn("DOS_AH43_FRONTIER_C_TEST pass=1",self.stdout)
        self.assertIn("sound_ax=0020 sound_cx=0020 sound_cf=0",self.stdout)
        self.assertIn("provider_open_close=1 missing_ax=0002 invalid_ax=0003",self.stdout)
        line=next(x for x in self.w1["stdout"].splitlines()
                  if x.startswith("NATIVE_DOS_AH43 ") and "path=C:\\GENEWARS\\sound.ini" in x)
        for field in ("request_eax=00004300","request_ebx=00000000",
                      "request_ecx=00117551","request_edx=00117551",
                      "response_eax=00004300","response_edx=00117551",
                      "cf_in=0 cf_out=0 handled=0"):
            self.assertIn(field,line)

    def test_original_contract_and_authentic_staged_fixture_are_verified(self):
        evidence=json.loads((ROOT/"evidence"/"w3_069_original_ah43_sound_ini.json").read_text(encoding="utf-8"))
        target=[event for event in evidence["ah43_events"]
                if event.get("requested_path", "").lower()==r"c:\genewars\sound.ini"]
        self.assertEqual(len(target),3)
        for event in target:
            self.assertEqual((event["out_ax"],event["out_cx"],event["attributes"]),(0x20,0x20,0x20))
            self.assertFalse(event["cf"])
            self.assertIsNone(event["caller_link_va"])
        sound=ROOT/"build"/"dosboxx_oracle"/"C"/"GENEWARS"/"SOUND.INI"
        data=sound.read_bytes()
        self.assertEqual(len(data),11)
        self.assertEqual(__import__("hashlib").sha256(data).hexdigest(),
                         "339a99f3fac46182dc52bec753c7122a7fcb1e3cf762e79d6693a9461c8cb9c3")

    def test_python_attribute_query_matches_measured_ax_cx_cf_and_provider_errors(self):
        sys.path.insert(0,str(ROOT/"runtime"))
        from dos_services import CpuRegs, DosHost
        from dos_filesystem import DosFileSystem
        from guest_boot import prepare_guest
        image=ROOT/"evidence"/"genewars-1_1.exe"
        fixture=ROOT/"build"/"dosboxx_oracle"/"C"/"GENEWARS"/"SOUND.INI"
        authentic=fixture.read_bytes()
        with tempfile.TemporaryDirectory(dir=ROOT/"cache") as temp:
            root=pathlib.Path(temp)
            (root/"GENEWARS").mkdir()
            (root/"GENEWARS"/"SOUND.INI").write_bytes(authentic)
            host=DosHost(prepare_guest(image))
            host.filesystem=DosFileSystem(root,cwd="GENEWARS")
            regs=CpuRegs(eax=0xABCD4300,ecx=0x12340000,edx=0x56780000,eflags=0x203)
            result=host.dispatch(0x21,regs,filename=r"C:\GENEWARS\sound.ini")
            self.assertEqual(result.service,"dos21.get_file_attributes")
            self.assertEqual((regs.ax,regs.cx),(0x20,0x20))
            self.assertEqual((regs.eax>>16,regs.ecx>>16,regs.edx),(0xABCD,0x1234,0x56780000))
            self.assertFalse(regs.carry)
            missing=CpuRegs(eax=0xABCD4300,ecx=0x12340000,eflags=0x202)
            failed=host.dispatch(0x21,missing,filename=r"C:\GENEWARS\missing.ini")
            self.assertEqual(failed.service,"dos21.get_file_attributes.error")
            self.assertEqual((missing.ax,missing.ecx>>16),(2,0x1234))
            self.assertTrue(missing.carry)

    def test_exact_measured_gwerr_exception_is_preserved(self):
        self.assertIn("gwerr_ax=0003 gwerr_cf=1",self.stdout)


if __name__=="__main__": unittest.main()
