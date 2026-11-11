"""Fast/default instruction-probe rewriting shared by native GW test wrappers."""
from __future__ import annotations

import re
from pathlib import Path


def _boundary_sites(harness: Path) -> set[int]:
    source = harness.read_text(encoding="utf-8")
    start = source.find("void gw_test_instruction_budget_step(uint32_t guest_va) {")
    end = source.find("\n}\n", start)
    if start < 0 or end < 0:
        raise SystemExit(f"instruction probe callback unavailable in {harness}")
    body = source[start:end]
    sites = {int(value, 16) for value in
             re.findall(r"guest_va\s*==\s*0x([0-9A-Fa-f]+)u?", body)}
    # These sites are stored in local arrays rather than compared as literals.
    # Keep the draw-rectangle attribution sparse. These are the first
    # rectangle writer plus the previously validated stable draw checkpoints;
    # sampling every virtual call in this hot path made the bounded probe stop
    # at a later fail-closed boundary without adding useful causal evidence.
    sites.update((0x92865, 0x92896, 0x9289B, 0x928A0, 0x928AA, 0x928AF,
                  0x22F53, 0x22F58, 0x22F70, 0x22F75, 0x22F87, 0x22F8A,
                  0x22F9C, 0x22FA1, 0x23061, 0x23066,
                  0x23069, 0x2306E, 0x23091, 0x23096))
    # This is the synthetic cutoff after the original CRT init table. The
    # caller uses this one sparse observation to prove that __InitRtns made
    # its natural return; it is not an instruction-by-instruction budget hook.
    sites.add(0xAFBF4)
    for array in ("g_draw_game_gate_sites", "g_process_sounds_call_sites", "route_sites",
                  "g_cost_table_reader_sites", "g_picker_phase_sites"):
        # `route_sites` is intentionally declared with an inferred array size
        # (`route_sites[] = {...}`), unlike the other fixed-size hook arrays.
        # Accept empty brackets so all of its sparse sites remain instrumented.
        match = re.search(rf"{array}\s*\[[^]]*\]\s*=\s*\{{([^}}]+)\}}", source)
        if match:
            sites.update(int(value, 16) for value in
                         re.findall(r"0x([0-9A-Fa-f]+)u?", match.group(1)))
    return sites


def patch_lifted_instruction_probes(text: str, harness: Path) -> tuple[str, int, int]:
    """Compile out generic per-instruction test work in the default fast path.

    The runtime's architectural instruction/fault callback remains in place.
    Detailed test tracing and the instruction budget remain available in a
    GW_FULL_TRACE_BUILD; the default keeps only exact EIP boundary probes.
    """
    sites = _boundary_sites(harness)
    # Older probe-generation passes inserted these as separate statements;
    # stack and allocator traces may sit between them, so remove each generic
    # statement before rebuilding the instruction hook uniformly.
    text = re.sub(r"(?m)^[ \t]*gw_test_instruction_budget_step\(0x[0-9A-Fa-f]{8}u\);\n", "", text)
    text = re.sub(r"(?m)^[ \t]*if \(gw_test_instruction_budget_exhausted\(\)\) return;\n", "", text)
    text = re.sub(r"(?m)^[ \t]*gw_watch_mcb_instruction\(0x[0-9A-Fa-f]{8}u,eax,ebx,ecx,edx,esp\);\n", "", text)
    pattern = re.compile(
        r"    if \(!gw_recomp_guest_instruction\(0x([0-9A-Fa-f]{8})u\)\) return;"
    )

    def replace(match: re.Match[str]) -> str:
        va = int(match.group(1), 16)
        result = (f"    if (!gw_recomp_guest_instruction(0x{va:08X}u)) return;\n"
                  f"    GW_NATIVE_INSTRUCTION_TRACE(0x{va:08X}u,eax,ebx,ecx,edx,esp);")
        if va in sites:
            result += (f"\n#if !defined(GW_FULL_TRACE_BUILD) || !GW_FULL_TRACE_BUILD\n"
                       f"    gw_test_instruction_budget_step(0x{va:08X}u);\n#endif")
        return result

    text, count = pattern.subn(replace, text)
    if count < 1000:
        raise SystemExit(f"expected a large lifted closure, only patched {count} instruction probes")

    # These diagnostics were inserted inside frequent setup/decompression
    # loops. Keep them available in full trace mode without calling them in
    # the default build.
    text = re.sub(
        r"(?m)^    gw_test_init_my_anim_bank_step\(([^;\n]+)\);$",
        r"    GW_NATIVE_DETAIL_HOOK(gw_test_init_my_anim_bank_step(\1));", text)
    text = re.sub(
        r"(?m)^    gw_trace_strstr_stack\(([^;\n]+)\);$",
        r"    GW_NATIVE_DETAIL_HOOK(gw_trace_strstr_stack(\1));", text)

    preamble = r'''extern int g_full_instruction_trace;
void gw_test_instruction_budget_step(unsigned int);
int gw_test_instruction_budget_exhausted(void);
void gw_watch_mcb_instruction(unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int);
#if defined(GW_FULL_TRACE_BUILD) && GW_FULL_TRACE_BUILD
#define GW_NATIVE_INSTRUCTION_TRACE(va,eax,ebx,ecx,edx,esp) do { if (g_full_instruction_trace) { gw_test_instruction_budget_step(va); if (gw_test_instruction_budget_exhausted()) return; gw_watch_mcb_instruction(va,eax,ebx,ecx,edx,esp); } } while (0)
#define GW_NATIVE_DETAIL_HOOK(call) do { if (g_full_instruction_trace) { call; } } while (0)
#else
#define GW_NATIVE_INSTRUCTION_TRACE(va,eax,ebx,ecx,edx,esp) ((void)0)
#define GW_NATIVE_DETAIL_HOOK(call) ((void)0)
#endif
'''
    text = preamble + text
    return text, count, len(sites)
