"""Summarize bounded DOS handle ownership records for W3-085."""
from __future__ import annotations

HANDLE_EVENTS = {
    'dos_handle_table_snapshot', 'dos_handle_open', 'dos_handle_create',
    'dos_handle_close', 'dos_handle_dup', 'dos_handle_force_dup',
}


def summarize_handle_lineage(events: list[dict], target_psp: int, stream_entry: int = 5,
                             max_events: int = 96, as_of_sequence: int | None = None) -> dict:
    scoped = [e for e in events if e.get('event') in HANDLE_EVENTS and
              e.get('process_psp') == target_psp and
              (as_of_sequence is None or e.get('sequence', 0) <= as_of_sequence)]
    truncated = len(scoped) >= max_events
    scoped = scoped[:max_events]
    table: dict[int, dict] = {}
    provenance = []
    for event in scoped:
        kind = event.get('event')
        if kind == 'dos_handle_table_snapshot':
            for item in event.get('entries', []):
                entry = item.get('entry')
                if isinstance(entry, int) and 0 <= entry <= 8:
                    table[entry] = {'internal_handle': item.get('internal_handle'),
                                    'open': item.get('open'), 'path': item.get('name'),
                                    'source': 'initial_table_snapshot',
                                    'sequence': event.get('sequence')}
        elif kind in {'dos_handle_open', 'dos_handle_create'}:
            entry = event.get('entry')
            if isinstance(entry, int) and 0 <= entry <= 8:
                table[entry] = {'internal_handle': event.get('internal_handle'),
                                'open': True, 'path': event.get('path'),
                                'source': kind, 'sequence': event.get('sequence')}
        elif kind == 'dos_handle_close':
            entry = event.get('entry')
            if isinstance(entry, int) and 0 <= entry <= 8:
                table[entry] = {'internal_handle': event.get('internal_handle'),
                                'open': False, 'path': event.get('path'),
                                'source': kind, 'sequence': event.get('sequence')}
        elif kind == 'dos_handle_dup':
            source, target = event.get('source_entry'), event.get('new_entry')
            if isinstance(source, int) and isinstance(target, int) and 0 <= target <= 8:
                inherited = table.get(source, {})
                table[target] = {'internal_handle': event.get('internal_handle'),
                                 'open': True, 'path': event.get('path') or inherited.get('path'),
                                 'source': kind, 'source_entry': source,
                                 'sequence': event.get('sequence')}
        elif kind == 'dos_handle_force_dup':
            source, target = event.get('source_entry'), event.get('target_entry')
            if isinstance(target, int) and 0 <= target <= 8:
                inherited = table.get(source, {}) if isinstance(source, int) else {}
                table[target] = {'internal_handle': event.get('internal_handle'),
                                 'open': True, 'path': event.get('path') or inherited.get('path'),
                                 'source': kind, 'source_entry': source,
                                 'sequence': event.get('sequence')}
        provenance.append({'event': kind, 'sequence': event.get('sequence')})
    owner = table.get(stream_entry)
    complete = owner is not None and owner.get('open') is True and not truncated
    return {
        'status': 'MAPPED' if complete else 'UNKNOWN',
        'process_psp': target_psp,
        'stream_entry': stream_entry,
        'as_of_sequence': as_of_sequence,
        'owner': owner,
        'event_count': len(scoped),
        'event_cap': max_events,
        'truncated': truncated,
        'events': provenance,
        'limitation': None if complete else 'No complete target-PSP mapping for stream entry at the capture frontier; absence is not proof of no open/duplication.',
    }
