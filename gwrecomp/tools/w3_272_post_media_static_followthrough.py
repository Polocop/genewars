from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import capstone

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT))
from tools.w3_270_post_present_static_frontier import map_le_link_va

EXE = ROOT / 'build/dosboxx_oracle/C/GENEWARS/GW.EXE'
TRACE = ROOT / 'build/dosboxx_oracle/C/W3_271_AFTER_MEDIA_20261009_01.jsonl'
SOURCE_EVIDENCE = ROOT / 'evidence/w3_271_after_media_frontier.json'
OUTPUT = ROOT / 'evidence/w3_272_post_media_static_followthrough.json'
REPORT = ROOT / 'reports/coordination/w3_272_post_media_static_followthrough.md'
TARGET_SHA256 = '2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f'
TARGETS = (0x92AE2, 0x92996, 0x929A9, 0x929C8, 0x94347, 0x92710)
MAX_TRACE_BYTES = 1024 * 1024
MAX_TRACE_ROWS = 2048


def correlate(rows: list[dict[str, Any]], code_rebase: int) -> list[dict[str, Any]]:
    observed = []
    for row in rows:
        if row.get('event') != 'w3_269_game_transition_checkpoint':
            continue
        runtime = int(row['runtime_linear'])
        link = runtime - int(row['code_rebase'])
        if link != int(row['link_va']) or int(row['code_rebase']) != code_rebase:
            raise ValueError('runtime-to-link mapping mismatch')
        observed.append({
            'sequence': int(row['sequence']),
            'link_va': f'0x{link:08X}',
            'runtime_linear': f'0x{runtime:08X}',
            'cs': f"0x{int(row['cs']):04X}",
            'eflags': f"0x{int(row['eflags']):08X}",
        })
    return observed


def build_evidence() -> dict[str, Any]:
    import hashlib
    image = EXE.read_bytes()
    if hashlib.sha256(image).hexdigest() != TARGET_SHA256:
        raise ValueError('exact original target hash mismatch')
    raw = TRACE.read_bytes()
    if len(raw) > MAX_TRACE_BYTES or len(raw.splitlines()) > MAX_TRACE_ROWS:
        raise ValueError('retained trace exceeds bounded limits')
    rows = [json.loads(line) for line in raw.splitlines()]
    if any(not isinstance(row, dict) for row in rows):
        raise ValueError('trace contains non-object JSON')
    source = json.loads(SOURCE_EVIDENCE.read_text(encoding='utf-8'))
    if source['trace']['sha256'] != hashlib.sha256(raw).hexdigest():
        raise ValueError('trace hash differs from W3-271 evidence')
    mapping = next(row for row in rows if row.get('event') == 'main_mapping')
    if mapping.get('mapping_matches') is not True:
        raise ValueError('fresh MAIN mapping was not verified')
    code_rebase = int(mapping['code_rebase'])
    observed = correlate(rows, code_rebase)
    static = []
    for target in TARGETS:
        mapped = map_le_link_va(image, target)
        code = image[mapped['file_offset']:mapped['file_offset'] + 32]
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        decoded = [{
            'link_va': f'0x{ins.address:08X}', 'bytes': ins.bytes.hex(),
            'mnemonic': ins.mnemonic, 'operands': ins.op_str,
        } for ins in decoder.disasm(code, target)]
        static.append({
            'link_va': f'0x{target:08X}',
            'file_offset': f"0x{mapped['file_offset']:X}",
            'raw_32_bytes': code.hex(),
            'bounded_decode_from_address': decoded,
            'decode_boundary_status': 'DYNAMIC_INSTRUCTION_BOUNDARY' if any(item['link_va'] == f'0x{target:08X}' for item in observed) else 'CANDIDATE_ADDRESS_ONLY',
            'dynamically_observed_in_w3_271': any(item['link_va'] == f'0x{target:08X}' for item in observed),
            'semantic_label': 'UNASSIGNED',
        })
    result = {
        'schema': 'w3-272-post-media-static-followthrough/v1',
        'task': 'W3-272',
        'evidence_level': 'ORIGINAL_OBSERVED_AND_STATIC_ONLY',
        'target_sha256': TARGET_SHA256,
        'source_task': 'W3-271',
        'trace_sha256': hashlib.sha256(raw).hexdigest(),
        'trace_rows': len(rows),
        'fresh_code_rebase': f'0x{code_rebase:08X}',
        'original_observed_order': observed,
        'static_targets': static,
        'limitations': [
            'A byte window is not a proven function boundary or caller relationship.',
            'The 0x92AE2 event proves the observed call-return checkpoint only; it does not prove final Smacker/media completion.',
            'No menu or gameplay state is inferred from the post-media return or viewport present.',
        ],
    }
    lines = [
        '# W3-272 — static follow-through from the original call-return checkpoint',
        '',
        'Evidence level: ORIGINAL_OBSERVED_AND_STATIC_ONLY. No DOSBox run was performed for this task.',
        '',
        f"- Exact target GW.EXE SHA-256: `{TARGET_SHA256}`.",
        f"- W3-271 trace SHA-256: `{result['trace_sha256']}`; {len(rows)} bounded rows.",
        f"- Fresh code rebase: `{result['fresh_code_rebase']}`.",
        '- Same-run observed sequence:',
    ]
    for item in observed:
        lines.append(f"  - seq {item['sequence']}: link `{item['link_va']}`, runtime `{item['runtime_linear']}`, CS `{item['cs']}`, EFLAGS `{item['eflags']}`.")
    lines += [
        '',
        '## Static target windows',
        '',
        'Each decode is bounded to 32 bytes from the requested address. Dynamic checkpoints are observed instruction boundaries; other locations remain candidate-address decodes.',
    ]
    for item in static:
        lines += ['', f"### {item['link_va']} (file offset {item['file_offset']})", '', f"Bytes: `{item['raw_32_bytes']}`", '']
        lines += [f"- `{ins['link_va']}`: `{ins['bytes']}` — `{ins['mnemonic']} {ins['operands']}`" for ins in item['bounded_decode_from_address']]
    lines += [
        '',
        '## Interpretation limits',
        '',
        '- W3-118 labels `0x92AE2` as the return checkpoint from the observed play-smacker call boundary. This checkpoint does not establish that all media playback completed.',
        '- The trace later observed `0x92996`; its broader function semantics are unassigned.',
        '- Static bytes at `0x94347` encode a direct call to `0x92710`; neither target fired in W3-271 before timeout.',
        '- Menu and gameplay remain unverified. The observed viewport present is not used as a menu claim.',
        '',
    ]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text('\n'.join(lines), encoding='utf-8')
    return result


def main() -> None:
    result = build_evidence()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'evidence': str(OUTPUT), 'report': str(REPORT), 'observed': result['original_observed_order'], 'static_targets': len(result['static_targets'])}, indent=2))


if __name__ == '__main__':
    main()
