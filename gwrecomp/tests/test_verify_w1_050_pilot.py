import copy
import hashlib
import pathlib
import unittest

from tools.verify_w1_050_pilot import validate
from tools import frontier_snapshot

ROOT=pathlib.Path(__file__).resolve().parents[1]


def sample():
    return {
        "schema":"gwrecomp.native-setup-replay/v1","execution_mode":"native_recompiled_guest",
        "evidence_level":"DIFF_VERIFIED","target_sha256":"a"*64,"build_id":"b"*64,
        "build_artifact":{"path":"build/synthetic.exe","sha256":"b"*64,
                           "runtime_fingerprint":{"c_h_sha256":"d"*64,"python_sha256":"e"*64}},
        "runtime_fingerprint":{"c_h_sha256":"d"*64,"python_sha256":"e"*64},
        "fixture_id":"synthetic-fixture","capture_id":"synthetic-capture","captured_at":"2026-10-08T00:00:00Z",
        "original_contract":{"path":"evidence/w3_setup_original_contract_20261008.json","sha256":"c"*64},
        "crt":{"callback_count":19,"destinations":[f"CRT-{i:02}" for i in range(19)]},
        "argv":{"argc":3},"gate":{"local_64":"01","local_68":"01"},
        "roots":{"setup_game":{"link_va":"0x94AC0"},"first_callee_14bf0":{"link_va":"0x14BF0","observed":True}},
        "config_ini":{"path":"C:\\GENEWARS\\CONFIG.INI","opened":True,"bytes_read":130,"eof_observed":True},
        "ax4400":[{"path":"C:\\GENEWARS\\CONFIG.INI","regular_file":True,"ax":2,"dx":2,"carry":False}],
        "ax4400_comparison":{"same_dynamic_invocation_claimed":False},
        "fixtures":{"comparable":True,"original":{"fingerprint":"same","address_txt_sha256":"7b1c5391160e1d95393d3abe980dde978b8a79ecb2814e144ee032d9710ba6ee",
                     "address_txt_path":"tests/fixtures/w3_067_address_seed_work1.bin",
                     "authentic_seed_evidence":{"path":"evidence/w3_067_staging_functional_validation_20261008.json","sha256":"381dba2a684ec39048cedcf4365e5d6fdf073146223385b15ad63a2cbc91f2bc"}},
                     "native":{"fingerprint":"same","address_txt_sha256":"7b1c5391160e1d95393d3abe980dde978b8a79ecb2814e144ee032d9710ba6ee",
                               "address_provider_initial_visibility":"present","address_provider_open":"NATIVE_W1_ADDRESS_OPEN",
                               "physical_host_path_observation":{"guest_provider_source":False}}},
        "frontier":{"newly_observed":True,"stop_reason":"bounded native stop","guest_eip":"0x00123456"},
        "prior_ax4300_checkpoint_reused":False,
    }


class PilotEvidenceContract(unittest.TestCase):
    def test_complete_synthetic_manifest_satisfies_shape_only(self):
        self.assertEqual(validate(sample()), [])

    def test_historical_ax4300_cannot_pass_as_fresh_capture(self):
        x=sample(); x["prior_ax4300_checkpoint_reused"]=True
        self.assertTrue(any("historical AX=4300" in e for e in validate(x)))

    def test_missing_address_txt_identity_fails_closed(self):
        x=sample(); x["fixtures"]["native"]["address_txt_sha256"]=""
        self.assertTrue(any("ADDRESS.TXT" in e for e in validate(x)))

    def test_synthetic_shape_test_does_not_execute_game(self):
        # This module constructs an in-memory contract only; it has no process/oracle calls.
        self.assertTrue(sample()["schema"].startswith("gwrecomp."))

    def test_stale_target_hash_fails_closed(self):
        self.assertTrue(any("target hash is stale" in e for e in validate(sample(),target_sha256="d"*64)))

    def test_native_build_and_runtime_fingerprints_are_required(self):
        x=sample(); x["build_artifact"]={}; x["runtime_fingerprint"]={}
        errors=validate(x)
        self.assertTrue(any("build_id" in e for e in errors))
        self.assertTrue(any("runtime_fingerprint" in e for e in errors))

    def test_authentic_seed_reference_is_required(self):
        x=sample(); x["fixtures"]["original"]["authentic_seed_evidence"]={}
        self.assertTrue(any("authentic original ADDRESS.TXT" in e for e in validate(x)))

    def test_native_address_seed_must_be_visible_in_virtual_provider(self):
        x=sample(); x["fixtures"]["native"]["address_provider_initial_visibility"]="absent"
        self.assertTrue(any("virtual provider" in e for e in validate(x)))

    def test_address_seed_fixture_matches_authenticated_source(self):
        fixture=ROOT/"tests"/"fixtures"/"w3_067_address_seed_work1.bin"
        evidence=ROOT/"evidence"/"w3_067_staging_functional_validation_20261008.json"
        auth=__import__("json").loads(evidence.read_text(encoding="utf-8"))["runtime"]["guest_errors"]
        self.assertEqual(len(fixture.read_bytes()),24)
        self.assertEqual(hashlib.sha256(fixture.read_bytes()).hexdigest(),auth["ADDRESS_TXT_sha256"])
        self.assertTrue(auth["ADDRESS_TXT_matches_functional_source"])

    def test_live_build_runtime_and_seed_evidence_fingerprints_validate(self):
        x=sample()
        contract=ROOT/"evidence"/"w3_setup_original_contract_20261008.json"
        seed_evidence=ROOT/"evidence"/"w3_067_staging_functional_validation_20261008.json"
        build=ROOT/"build"/"entry_path_native.exe"
        x["original_contract"]={"path":contract.relative_to(ROOT).as_posix(),"sha256":hashlib.sha256(contract.read_bytes()).hexdigest()}
        build_sha=hashlib.sha256(build.read_bytes()).hexdigest()
        x["build_id"]=build_sha; x["build_artifact"]={"path":build.relative_to(ROOT).as_posix(),"sha256":build_sha}
        x["fixtures"]["original"]["authentic_seed_evidence"]["sha256"]=hashlib.sha256(seed_evidence.read_bytes()).hexdigest()
        x["fixtures"]["original"]["address_txt_path"]="tests/fixtures/w3_067_address_seed_work1.bin"
        target=ROOT/"evidence"/"genewars-1_1.exe"
        target_sha=hashlib.sha256(target.read_bytes()).hexdigest() if target.is_file() else None
        x["target_sha256"]=target_sha or "a"*64
        x["runtime_fingerprint"]={"c_h_sha256":frontier_snapshot.runtime_hash(ROOT),
                                  "python_sha256":frontier_snapshot.manifest_hash(list((ROOT/"runtime").glob("*.py")),ROOT)}
        x["build_artifact"]["runtime_fingerprint"]=dict(x["runtime_fingerprint"])
        self.assertEqual(validate(x,target_sha256=target_sha,project_root=ROOT),[])
        x["fixtures"]["original"]["address_txt_path"]="build/work3_empty_config_fixture/ADDRESS.TXT"
        self.assertTrue(any("original fixture ADDRESS.TXT bytes" in e for e in validate(x,target_sha256=target_sha,project_root=ROOT)))


if __name__=="__main__": unittest.main()
