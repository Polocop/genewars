"""Synthetic safety predicates for a single B_SCREEN sample immediately before free."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
EXPECTED_SIZE = 0x4B000
SAMPLE_BYTES = 64


def matching_free_candidate(*, allocation_pointer: int, stored_pointer: int,
                            eax: int, allocation_size: int, psp: int,
                            allocation_psp: int, attempted: bool) -> bool:
    return bool(not attempted and allocation_pointer > 0 and
                allocation_size == EXPECTED_SIZE and
                allocation_pointer == stored_pointer == eax and
                psp == allocation_psp)


def validate_range(*, pointer: int, allocation_size: int, ds_base: int,
                   descriptor_limit: int, physical_memory_bytes: int,
                   sample_bytes: int = SAMPLE_BYTES) -> dict:
    if pointer <= 0 or allocation_size != EXPECTED_SIZE:
        return {"valid": False, "reason": "allocation_identity_invalid"}
    if sample_bytes != SAMPLE_BYTES or sample_bytes > allocation_size:
        return {"valid": False, "reason": "sample_size_invalid"}
    allocation_end = pointer + allocation_size
    sample_start = ds_base + pointer
    sample_end = sample_start + sample_bytes
    allocation_linear_end = ds_base + allocation_end
    if allocation_end > descriptor_limit + 1:
        return {"valid": False, "reason": "descriptor_limit"}
    if allocation_linear_end > physical_memory_bytes or allocation_end > 0x1_0000_0000:
        return {"valid": False, "reason": "physical_or_32bit_limit"}
    if sample_end > allocation_linear_end or sample_end > physical_memory_bytes or sample_end > 0x1_0000_0000:
        return {"valid": False, "reason": "sample_bounds"}
    return {"valid": True, "reason": "captured_raw_allocation_bytes",
            "sample_start": sample_start, "sample_end_exclusive": sample_end,
            "sample_bytes": sample_bytes}


def inspect_source(text: str) -> dict:
    compact = "".join(text.split())
    checks = {
        "allocation_psp_recorded": "w3_202_b_screen_alloc_psp=dos.psp();" in compact,
        "free_candidate_matches_pointer_size_psp": all(token in compact for token in (
            "w3_188_alloc_size==0x0004b000", "w3_188_alloc_pointer==w3_129_b_screen_value",
            "w3_188_alloc_pointer==reg_eax", "dos.psp()==w3_202_b_screen_alloc_psp")),
        "one_shot_free_sample": "!w3_202_b_screen_free_sample_attempted" in compact and
                                "w3_202_b_screen_free_sample_attempted=true;" in compact,
        "full_allocation_descriptor_and_physical_bounds": all(token in compact for token in (
            "allocation_end<=static_cast<uint64_t>(checkpoint_ds_descriptor.GetLimit())+1",
            "allocation_linear_end<=physical_memory_bytes",
            "allocation_linear_end<=static_cast<uint64_t>(UINT32_MAX)+1")),
        "sample_is_exactly_64_bytes": "for(uint32_ti=0;i<64;++i)" in compact and
                                     "w3_202_b_screen_sample_bytes=64;" in compact,
        "sample_is_specific_to_w3_129_free": "link_va==0x00092030" in compact and
                                             "W3_129_MEMORY_FREE_ENTRY" in compact and
                                             "W3_202_ECD40" not in compact,
        "raw_bytes_are_serialized_bounded": "w3_202_b_screen_sample_hex" in compact and
                                             "w3_202_b_screen_sample_nonzero" in compact,
    }
    if not all(checks.values()):
        raise ValueError("W3-202 source invariant failed: " +
                         ", ".join(k for k, value in checks.items() if not value))
    return {"checks": checks, "all_checks_pass": True}
