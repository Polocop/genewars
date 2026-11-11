"""Compose the existing native HUD edge over experimental mesh renders.

The curved edge mask is inferred from same-build full-frame vs isolated-map
captures. It is marked as a derived visual mask, not an original alpha plane.
"""
import os as _gw_os
from pathlib import Path as _GwPath
_GW_ROOT=str(_GwPath(__file__).resolve().parents[2])
import hashlib, json, struct
from pathlib import Path

ROOT=Path((_GW_ROOT))
OUT=ROOT/'evidence'
TERR=OUT/'terrain_renderer'
FULL=OUT/'native_wscreen_capture_turn435_436_final_sdl.bmp'
MAP=OUT/'terrain_geometry_projection_resolution'/'original_MapDisplay_turn435_640x480.bmp'

def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def load_bmp(path):
    data=path.read_bytes(); off=struct.unpack_from('<I',data,10)[0]
    w,h=struct.unpack_from('<ii',data,18); bits=struct.unpack_from('<H',data,28)[0]
    if bits not in (24,32): raise ValueError(f'expected 24/32-bit BMP: {path}')
    height=abs(h); stride=((w*bits+31)//32)*4
    pixels=[[(0,0,0)]*w for _ in range(height)]
    for y in range(height):
        file_y=height-1-y if h>0 else y; row=off+file_y*stride
        for x in range(w):
            p=row+x*(bits//8); b,g,r=data[p:p+3]; pixels[y][x]=(r,g,b)
    return w,height,pixels
def save_bmp(path,pixels):
    h=len(pixels); w=len(pixels[0]); stride=((w*3+3)//4)*4
    size=54+stride*h
    with path.open('wb') as f:
        f.write(b'BM'+struct.pack('<IHHI',size,0,0,54))
        f.write(struct.pack('<IiiHHIIiiII',40,w,h,1,24,0,stride*h,2835,2835,0,0))
        pad=b'\0'*(stride-w*3)
        for y in range(h-1,-1,-1):
            f.write(b''.join(bytes((b,g,r)) for r,g,b in pixels[y])+pad)
def resize_nearest(src,w,h):
    sh=len(src); sw=len(src[0])
    return [[src[min(sh-1,y*sh//h)][min(sw-1,x*sw//w)] for x in range(w)] for y in range(h)]

fw,fh,full=load_bmp(FULL); mw,mh,map_only=load_bmp(MAP)
if (fw,fh)!=(1280,960) or (mw,mh)!=(640,480): raise ValueError('unexpected source capture dimensions')
full640=[[full[y*2][x*2] for x in range(640)] for y in range(480)]
mask=[[x<128 or (x<176 and full640[y][x]!=map_only[y][x]) for x in range(640)] for y in range(480)]
mask_count=sum(sum(row) for row in mask)
results=[]
for width,height,prefix,factor in [
    (640,480,'watertight_640',1),
    (2560,1440,'watertight_2560x1440',3),
]:
    base_path=TERR/f'{prefix}.bmp'; bw,bh,base=load_bmp(base_path)
    if (bw,bh)!=(width,height): raise ValueError(f'bad mesh dimensions for {prefix}')
    out=[row[:] for row in base]
    hud=resize_nearest(full640,640*factor,480*factor)
    for y in range(height):
        sy=y//factor
        for x in range(176*factor):
            sx=x//factor
            if mask[sy][sx]: out[y][x]=hud[y][x]
    target=OUT/('live_modern_640x480_watertight.bmp' if factor==1 else 'live_modern_2560x1440_watertight.bmp')
    save_bmp(target,out)
    results.append({'path':str(target),'dimensions':[width,height],'sha256':sha(target),
                    'mesh_source':str(base_path),'hud_capture_source':str(FULL),
                    'hud_mask_pixels_640x480':mask_count,'hud_mask_rule':'opaque x<128; x128..175 where full native frame differs from isolated MapDisplay frame; nearest scaling'})
report={'schema':'gwrecomp.watertight-mesh-and-pan-capture/v1',
 'renderer_source':str(ROOT/'tools'/'terrain_renderer'/'gw_terrain_data_renderer.cpp'),
 'hud_mask_provenance':{'full_frame':str(FULL),'map_only':str(MAP),'dimensions':[640,480],
   'mask_pixels':mask_count,'edge_band_pixels':48*480,'edge_band_mask_pixels':sum(mask[y][x] for y in range(480) for x in range(128,176)),
   'limitation':'Mask is inferred by pixel difference between a native frame at turns 435/436 and an isolated MapDisplay capture from turn 435. This is a composition approximation, not an extracted original alpha channel.'},
 'outputs':results,
 'preservation':{'LE_canonical_modified':False,'original_scenario_or_resources_modified':False,'snapshot_modified':False}}
target=OUT/'watertight_mesh_and_pan_capture_report.json'; target.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print(json.dumps(report,indent=2))
