import os as _gw_os
from pathlib import Path as _GwPath
_GW_ROOT=str(_GwPath(__file__).resolve().parents[2])
import os as _gw_os
from pathlib import Path as _GwPath
_GW_ROOT=str(_GwPath(__file__).resolve().parents[2])
import argparse, csv, hashlib, json, struct
from pathlib import Path

def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1<<20),b''): h.update(b)
    return h.hexdigest()
def raw(p,n):
    b=p.read_bytes()
    if len(b)!=n: raise ValueError(f'{p}: got {len(b)}, expected {n}')
    return b
def rows(p):
    with p.open(newline='') as f: return list(csv.DictReader(f))
ap=argparse.ArgumentParser()
for name in ['game-root','output-dir','snapshot','render-scenario']: ap.add_argument('--'+name,required=True)
for name in ['camera-x-q8','camera-y-q8','scale-x','scale-y','height-scale','planet-class']: ap.add_argument('--'+name,type=int,required=True)
a=ap.parse_args(); root=Path(a.game_root); out=Path(a.output_dir)
level=root/'LEVELS'/'CONQ001.DAT'; render_level=Path(a.render_scenario); pal=root/'DATA'/'MAIN.PAL'; bank=root/'DATA'/f'B32{"ABCD"[a.planet_class]}.DAT'
decoded=Path((_GW_ROOT + '\\work\\terrain_renderer\\input'))/f'B32{"ABCD"[a.planet_class]}.raw'
ld=level.read_bytes(); rd=render_level.read_bytes(); pd=pal.read_bytes(); bd=decoded.read_bytes()
if len(ld)!=343958 or struct.unpack_from('<I',ld)[0]!=0x55336 or len(rd)!=len(ld) or struct.unpack_from('<I',rd)[0]!=0x55336 or len(pd)!=768 or len(bd)!=163840: raise SystemExit('source dimensions/signature mismatch')
o=0x355E; st=14; pos=o+(38*128+95)*st
cl=[rd[o+(y*128+x)*st+5]&7 for x,y in [(95,38),(96,38),(96,39),(95,39)]]
key=(cl[0]<<9)|(cl[1]<<6)|(cl[2]<<3)|cl[3]; block=rd[pos+4]; height=struct.unpack_from('<h',rd,pos+2)[0]; atlas=(37//8)*0x2000+(37%8)*0x20
if (key,block,height,atlas)!=(56,37,557,0x80A0): raise SystemExit('CONQ001 known cell check failed')
spot={'world_xy':[95,38],'file_offset_hex':hex(pos),'classes_tl_tr_br_bl':cl,'selector_key':key,'block_id':block,'height_s16':height,'topology_byte':hex(ld[pos+5]),'B32A_offset':hex(atlas),
      'selected_texture_texels':{n:bd[atlas+v*256+u] for n,(u,v) in {'tl':(0,0),'tr':(31,0),'center':(16,16),'bl':(0,31),'br':(31,31)}.items()}}
# Snapshot layout is the native GWSNAP2 v2 header followed by variable metadata,
# then guest RAM. The loaded CONQ file buffer begins at 0x002F1A28, as recorded
# by the DOS VFS read trace. Compare the full 128x128x14 world record span.
snap_path=Path(a.snapshot); snap=snap_path.read_bytes()
if len(snap)<36 or snap[:7]!=b'GWSNAP2': raise SystemExit('snapshot magic/header mismatch')
version,guest_size,snap_turn,desc_count,block_count,hit_count,active_files=struct.unpack_from('<7I',snap,8)
header_size=29032
guest_off=header_size+hit_count*16+desc_count*12+block_count*8
if version!=2 or len(snap)!=guest_off+guest_size: raise SystemExit('snapshot layout/size mismatch')
mem=snap[guest_off:]
map_guest=0x00346D70
camera_xy=[struct.unpack_from('<H',mem,map_guest+0x10)[0],struct.unpack_from('<H',mem,map_guest+0x12)[0]]
if struct.unpack_from('<I',mem,0x002F1472)[0]!=snap_turn: raise SystemExit('snapshot Turn field mismatch')
if snap_turn!=435 or camera_xy!=[a.camera_x_q8,a.camera_y_q8]: raise SystemExit('renderer camera/snapshot state mismatch')
source_guest_base=0x002F1A28
world_guest_begin=source_guest_base+o
world_guest_end=world_guest_begin+128*128*st
if world_guest_end>len(mem): raise SystemExit('snapshot world span outside guest RAM')
snapshot_world=mem[world_guest_begin:world_guest_end]
source_world=ld[o:o+128*128*st]
render_world=rd[o:o+128*128*st]
if snapshot_world!=render_world: raise SystemExit('renderer scenario world does not match snapshot guest terrain')
diff_by_record_offset={}
for i,(live,disk) in enumerate(zip(snapshot_world,source_world)):
    if live!=disk: diff_by_record_offset[str(i%st)]=diff_by_record_offset.get(str(i%st),0)+1
for i in range(128*128):
    q=i*st
    if snapshot_world[q+2:q+6]!=source_world[q+2:q+6]: raise SystemExit(f'snapshot terrain geometry differs from CONQ001 at record {i}')
snapshot_verification={'path':str(snap_path),'version':version,'turn':snap_turn,'guest_bytes':guest_size,'guest_memory_file_offset':guest_off,
 'mapdisplay_guest':hex(map_guest),'mapdisplay_camera_q8':camera_xy,'level_buffer_guest_base':hex(source_guest_base),
 'snapshot_file_sha256':sha(snap_path),
 'world_guest_range':[hex(world_guest_begin),hex(world_guest_end)],'world_file_range':[hex(o),hex(o+len(source_world))],
 'world_bytes':len(source_world),'snapshot_world_sha256':hashlib.sha256(snapshot_world).hexdigest(),
 'conq001_world_sha256':hashlib.sha256(source_world).hexdigest(),'rendered_snapshot_world_sha256':hashlib.sha256(render_world).hexdigest(),
 'exact_raw_world_match_to_disk':snapshot_world==source_world,'exact_raw_world_match_to_renderer_input':snapshot_world==render_world,
 'runtime_vs_disk_changed_bytes_by_record_offset':diff_by_record_offset,
 'height_block_topology_equal_for_all_records':True,
 'meaning':'Renderer consumes a temporary CONQ copy whose complete world-record span was extracted from guest RAM in this snapshot; terrain height, block ID and topology fields match the source file across all 16384 cells.'}
views={}
for w,h in [(640,480),(854,480),(1280,720),(2560,1440)]:
    s=f'conq001_{w}x{h}'; ix=raw(out/(s+'.indexed.raw'),w*h); cv=raw(out/(s+'.coverage.raw'),w*h); rr=rows(out/(s+'.cells.csv')); bmp=out/(s+'.bmp')
    views[s]={'dimensions':[w,h],'bmp':str(bmp),'bmp_bytes':bmp.stat().st_size,'bmp_sha256':sha(bmp),'indexed_sha256':sha(out/(s+'.indexed.raw')),'coverage_sha256':sha(out/(s+'.coverage.raw')),'visible_world_cells':len(rr),'covered_pixels':sum(cv),'unique_covered_palette_indices':len({ix[i] for i,v in enumerate(cv) if v})}
base=raw(out/'conq001_640x480.indexed.raw',640*480); bc=raw(out/'conq001_640x480.coverage.raw',640*480)
wide=raw(out/'conq001_854x480.indexed.raw',854*480); wc=raw(out/'conq001_854x480.coverage.raw',854*480); shift=107
eq=sum(base[y*640+x]==wide[y*854+x+shift] and bc[y*640+x]==wc[y*854+x+shift] for y in range(480) for x in range(640))
bands={}
for name,x0,x1 in [('left',0,106),('right',747,853)]:
    ii=[y*854+x for y in range(480) for x in range(x0,x1+1) if wc[y*854+x]]
    bands[name]={'x_range':[x0,x1],'covered_pixels':len(ii),'unique_palette_indices':len({wide[i] for i in ii}),'nonzero_texels':sum(wide[i]!=0 for i in ii)}
extra=[]
for r in rows(out/'conq001_854x480.cells.csv'):
    if (int(r['world_x']),int(r['world_y'])) in [(94,38),(95,38)]:
        extra.append({'world_xy':[int(r['world_x']),int(r['world_y'])],'cell_offset':r['scenario_cell_offset'],'height':int(r['height_s16']),'block_id':int(r['block_id']),'orientation_byte':r['topology_orientation_byte'],'atlas_offset':r['atlas_offset'],'screen_center':[int(r['screen_center_x']),int(r['screen_center_y'])],'covered_pixels':int(r['covered_pixels'])})
report={'schema':'gwrecomp.standalone-terrain-renderer/v1','result':'snapshot_backed_terrain_rendered_with_additional_widescreen_cells','scope':'offline independent renderer; no LE execution or simulation changes',
 'implementation':{'renderer_source':(_GW_ROOT + '\\tools\\terrain_renderer\\gw_terrain_data_renderer.cpp'),'renderer_exe':(_GW_ROOT + '\\work\\terrain_renderer\\gw_terrain_data_renderer.exe'),
  'snapshot_extractor':(_GW_ROOT + '\\tools\\terrain_renderer\\prepare_snapshot_scenario.py'),'runner':(_GW_ROOT + '\\tools\\terrain_renderer\\run_terrain_renderer.ps1'),'validator':(_GW_ROOT + '\\tools\\terrain_renderer\\validate_terrain_renderer.py'),
  'renderer_source_sha256':sha(Path((_GW_ROOT + '\\tools\\terrain_renderer\\gw_terrain_data_renderer.cpp'))),'renderer_exe_sha256':sha(Path((_GW_ROOT + '\\work\\terrain_renderer\\gw_terrain_data_renderer.exe'))),
  'snapshot_extractor_sha256':sha(Path((_GW_ROOT + '\\tools\\terrain_renderer\\prepare_snapshot_scenario.py'))),'runner_sha256':sha(Path((_GW_ROOT + '\\tools\\terrain_renderer\\run_terrain_renderer.ps1'))),
  'validator_sha256':sha(Path((_GW_ROOT + '\\tools\\terrain_renderer\\validate_terrain_renderer.py')))},
 'inputs':{'scenario':{'path':str(level),'bytes':len(ld),'sha256':sha(level),'world_begin':'0x355E','world_records':16384,'record_stride':14,'world_end':'0x3B55E'},
 'render_scenario':{'path':str(render_level),'sha256':sha(render_level),'world_bytes_from_snapshot':True},
 'B32':{'path':str(bank),'compressed_sha256':sha(bank),'decoded_path':str(decoded),'decoded_bytes':len(bd),'decoded_sha256':sha(decoded),'atlas_layout':'8x20 blocks, 32x32 indexed; row pitch 256 bytes','sample_formula':'(block//8)*0x2000+(block%8)*32+v*256+u'},
 'palette':{'path':str(pal),'bytes':len(pd),'sha256':sha(pal),'components_are_6bit':all(x<=63 for x in pd),'gameplay_palette_validation':'existing setup_game probe compares all 768 bytes against VGA DAC; same conversion as SDL snapshot (v*255/63)'} ,'known_cell_95_38':spot},
 'snapshot_level_verification':snapshot_verification,
 'camera':{'snapshot':str(snap_path),'turn':snap_turn,'mapdisplay_center_q8':camera_xy,'camera_evidence':'evidence/true_widescreen_panorama_multipass_probe.json','projection_equation_shape':'screenX=cx+((dx-dy)*scaleX)/256; screenY=cy+((dx+dy)*scaleY)/256-(height>>6)*heightScale','scale':[a.scale_x,a.scale_y,a.height_scale],'numeric_scale_status':'experimental; live camera center is measured, but the renderer scales and height scale are not an authentic frame calibration'},
 'renderer':{'logical_cell_source':'stored scenario byte +4 block ID, signed word +2 height; byte +5 retained in CSV','tile_footprint':'32x16 diamond, top face only','texture':'original decoded B32 bank; 256-wide atlas rows','draw_order':'stable projected-y, projected-x, world-y, world-x','known_gaps':['byte+5 orientation geometry transform is recorded but not applied','exact original triangle UV/side-face topology is unresolved','output is authentic resource/map data in an experimental isometric projection, not pixel-equivalent to original']},
 'views':views,'comparison':{'4_3':'640x480','wide':'854x480','same_camera_and_pixel_scale':True,'center_alignment_shift':shift,'common_pixels_equal':eq,'common_pixels':640*480,'exact_overlap_parity':eq==640*480,'side_bands':bands,'additional_world_cells':extra},
 'preservation':{'canonical_LE_modified':False,'canonical_LE_sha256':sha(Path((_GW_ROOT + '\\evidence\\genewars-1_1.exe'))),
  'original_scenario_modified':False,'original_scenario_sha256':sha(level),'original_B32_modified':False,'original_B32_sha256':sha(bank),
  'original_palette_modified':False,'original_palette_sha256':sha(pal),'snapshot_modified':False,'snapshot_sha256':sha(snap_path),
  'GeneWarsFX_modified':False,'note':('Renderer and extraction pipeline only read the original LE/resources/snapshot; the temporary CONQ overlay and outputs are under ' + _GW_ROOT + '\\work and evidence.')}}
p=out/'standalone_terrain_renderer_report.json'; p.write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps({'report':str(p),'overlap_exact':eq==640*480,'side_bands':bands,'extra_cells':extra,'views':{k:{'dimensions':v['dimensions'],'visible_cells':v['visible_world_cells'],'covered_pixels':v['covered_pixels'],'bmp_sha256':v['bmp_sha256']} for k,v in views.items()}},indent=2))

