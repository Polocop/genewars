from pathlib import Path
import re
ROOT=Path(__file__).resolve().parents[1]
def get_body(path,name):
 s=path.read_text(encoding='utf-8'); m=re.search(r'void\s+'+re.escape(name)+r'\s*\(void\)\s*\{',s)
 if not m: raise SystemExit(f'missing {name} in {path}')
 brace=s.index('{',m.start()); depth=0
 for i,ch in enumerate(s[brace:],brace):
  if ch=='{': depth+=1
  elif ch=='}':
   depth-=1
   if depth==0: return s[m.start():i+1]
 raise SystemExit(f'unclosed {name}')
src=ROOT/'build'/'entry_path_combined.c'; dst=ROOT/'build'/'entry_path_closure.c'; name='sub_000C3CA9'
new=get_body(src,name); old=get_body(dst,name)
if 'recomp_write_segment(RECOMP_SEG_ES' not in new: raise SystemExit('combined body lacks measured ES write lift')
if '0x000C3D42' not in new: raise SystemExit('combined body missing guest MOV ES')
s=dst.read_text(encoding='utf-8'); s=s.replace(old,new,1); dst.write_text(s,encoding='utf-8')
print(f'copied exact generated {name} body: {len(old)} -> {len(new)} bytes; ES write helper present')
