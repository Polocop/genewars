import argparse
import hashlib
import json
import struct
from pathlib import Path

HEADER_SIZE = 29032
GUEST_LEVEL_BUFFER = 0x002F1A28
WORLD_BEGIN = 0x355E
WORLD_BYTES = 128 * 128 * 14
CELL_STRIDE = 14

def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

ap = argparse.ArgumentParser()
ap.add_argument('--scenario', required=True)
ap.add_argument('--snapshot', required=True)
ap.add_argument('--output', required=True)
a = ap.parse_args()
scenario_path, snapshot_path, output_path = map(Path, (a.scenario, a.snapshot, a.output))
scenario = bytearray(scenario_path.read_bytes())
snap = snapshot_path.read_bytes()
if len(scenario) != 343958 or struct.unpack_from('<I', scenario)[0] != 0x55336:
    raise SystemExit('CONQ001 file contract mismatch')
if len(snap) < 36 or snap[:7] != b'GWSNAP2':
    raise SystemExit('snapshot magic/header mismatch')
version, guest_size, turn, descriptors, blocks, hits, active_files = struct.unpack_from('<7I', snap, 8)
guest_offset = HEADER_SIZE + hits * 16 + descriptors * 12 + blocks * 8
if version != 2 or len(snap) != guest_offset + guest_size:
    raise SystemExit('snapshot layout/size mismatch')
mem = snap[guest_offset:]
if struct.unpack_from('<I', mem, 0x002F1472)[0] != turn:
    raise SystemExit('snapshot turn field mismatch')
mapdisplay = 0x00346D70
camera = [struct.unpack_from('<H', mem, mapdisplay + 0x10)[0], struct.unpack_from('<H', mem, mapdisplay + 0x12)[0]]
source_start = GUEST_LEVEL_BUFFER + WORLD_BEGIN
runtime_world = mem[source_start:source_start + WORLD_BYTES]
if len(runtime_world) != WORLD_BYTES or source_start + WORLD_BYTES > len(mem):
    raise SystemExit('snapshot world bytes outside guest memory')
disk_world = scenario[WORLD_BEGIN:WORLD_BEGIN + WORLD_BYTES]
diff_counts = [0] * CELL_STRIDE
for i, (live, disk) in enumerate(zip(runtime_world, disk_world)):
    if live != disk:
        diff_counts[i % CELL_STRIDE] += 1
# Geometry inputs currently consumed by this renderer must match exactly.
for record in range(128 * 128):
    off = record * CELL_STRIDE
    if runtime_world[off + 2:off + 6] != disk_world[off + 2:off + 6]:
        raise SystemExit(f'snapshot terrain geometry differs from CONQ001 at record {record}')
scenario[WORLD_BEGIN:WORLD_BEGIN + WORLD_BYTES] = runtime_world
output_path.parent.mkdir(parents=True, exist_ok=True)
output_path.write_bytes(scenario)
print(json.dumps({
    'snapshot_turn': turn,
    'snapshot_version': version,
    'camera_q8': camera,
    'runtime_world_guest_range': [hex(source_start), hex(source_start + WORLD_BYTES)],
    'world_file_range': [hex(WORLD_BEGIN), hex(WORLD_BEGIN + WORLD_BYTES)],
    'world_bytes': WORLD_BYTES,
    'runtime_world_sha256': sha(runtime_world),
    'disk_world_sha256': sha(disk_world),
    'exact_raw_world_match': runtime_world == disk_world,
    'geometry_fields_match': True,
    'runtime_vs_disk_changed_bytes_by_record_offset': {str(i): n for i, n in enumerate(diff_counts) if n},
    'renderer_scenario_copy': str(output_path),
    'renderer_scenario_sha256': sha(scenario),
}, indent=2))
