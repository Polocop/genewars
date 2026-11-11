#!/usr/bin/env python3
"""extract_symbol_corpus.py  (LOCAL task L-BFLIB-MATCH)

Build the authoritative GeneWars symbol corpus that every L-BFLIB-MATCH
deliverable (cross-reference, relocation-aware matcher, Bullfrog library map,
Open Watcom runtime map, reference lookup index) consumes.

Inputs (READ-ONLY):
  evidence/genewars-1_1.exe   the exact target (sha256-pinned)
  evidence/genewars-1_1.map   loaded-VA symbol map (matches the works' VA scheme:
                              `0001:000A38F0 LbVesaGetGran_` -> loaded VA 0xA38F0)
  evidence/disc-MAIN.MAP      full link-time map (3818 lines) that additionally
                              records, before each symbol block, a
                              `Module: <lib>(<source>)` line giving the exact
                              origin library / source file of every symbol.

LE fixups are parsed directly from the EXE using the exact same semantics as
dos_re.le (SRC_OFFSET32=0x07 is the flat-model workhorse; a DWORD is written at
each relocated byte). Each fixup is recorded both as the loader's linear
coordinate (object-1 base 0x10000) and as the works' loaded-VA coordinate
(linear - 0x10000), so a fixup at loaded VA v can be addressed as im.mem[v+0x10000].

Output (authoritative, machine-readable):
  evidence/symbol_corpus.json
    {
      target: {path, sha256},
      maps:   {loaded_map: {path,sha256}, disc_map:{path,sha256}},
      code_range: [lo, hi],           # loaded-VA range of object-1 code
      object1_base: 0x10000,
      le: {entry_loaded_va, page_size, num_pages, fixup_count},
      symbols: [
        { name, va, class, disc_module, disc_source, disc_class, disc_flags,
          size, fixups: [ {src_va, target_va, target_linear, stype}, ... ] }
      ]
    }
  evidence/symbol_corpus_by_name.json   name -> [ {va,class,module,source,size,fixup_count} ]

A symbol's function body is [va, next_symbol_va) within the code object; the last
symbol in the code object runs to the object's end. This mirrors how the works
already delimit functions (see map_overlap_ownership_work1 / dependency_closure_va_corrected).
"""
import os as _gw_os
from pathlib import Path as _GwPath
_GW_ROOT=str(_GwPath(__file__).resolve().parents[1])
_GW_FX=_gw_os.environ.get("GENEWARSFX_ROOT",_gw_os.path.join(_GW_ROOT,"third_party","GeneWarsFX"))
import sys, struct, json, hashlib, pathlib

sys.path.insert(0, (_GW_FX.replace("\\","/") + '/experiments/dos-re-gw10'))
from dos_re.le import load_le  # read-only helper for the flat image + objects

ROOT   = pathlib.Path((_GW_ROOT.replace("\\","/")))
EXE    = ROOT/"evidence/genewars-1_1.exe"
LOAD   = ROOT/"evidence/genewars-1_1.map"
DISC   = ROOT/"evidence/disc-MAIN.MAP"
OUT    = ROOT/"evidence/symbol_corpus.json"
OUT_BN = ROOT/"evidence/symbol_corpus_by_name.json"

# ---------------------------------------------------------------- LE fixup table
# Reproduced verbatim from dos_re.le constants + _apply_fixups, but the records
# are RETURNED (with both linear and loaded-VA coordinates) instead of applied.
SRC_BYTE=0x00; SRC_SELECTOR16=0x02; SRC_PTR16_16=0x03; SRC_OFFSET16=0x05
SRC_PTR16_32=0x06; SRC_OFFSET32=0x07; SRC_SELF_REL32=0x08
SRC_TYPE_MASK=0x0F; SRC_FLAG_LIST=0x20
TGT_INTERNAL=0x00; TGT_TYPE_MASK=0x03; TGT_16BIT_OBJNUM=0x40; TGT_32BIT_OFFSET=0x10
TGT_ADDITIVE=0x04

def _u16(d,o): return struct.unpack_from("<H",d,o)[0]
def _u32(d,o): return struct.unpack_from("<I",d,o)[0]

def parse_fixups(data, objects, page_size, num_pages, obj_tab, obj_cnt,
                 fixup_page_tab, fixup_rec_tab):
    page_linear={}; p=1
    for o in objects:
        for local in range(o.page_count):
            # The LE fixup page index is global, but its source page offset is
            # local to the owning object. Using (p - 1) here shifts every
            # object after #1 by the cumulative preceding-object page count.
            page_linear[p]=o.base + local*page_size
            p+=1
    out=[]
    for page in range(1,num_pages+1):
        start=fixup_rec_tab+_u32(data,fixup_page_tab+(page-1)*4)
        end=fixup_rec_tab+_u32(data,fixup_page_tab+page*4)
        o=start; base=page_linear[page]
        while o<end:
            src_type=data[o]; tgt_flags=data[o+1]; o+=2
            stype=src_type & SRC_TYPE_MASK
            if src_type & SRC_FLAG_LIST:
                n=data[o]; o+=1
                offs=[struct.unpack_from("<h",data,o+2*i)[0] for i in range(n)]; o+=2*n
            else:
                offs=[struct.unpack_from("<h",data,o)[0]]; o+=2
            if (tgt_flags & TGT_TYPE_MASK) != TGT_INTERNAL:
                raise ValueError(f"page {page}: non-internal fixup 0x{tgt_flags:x}")
            obj_num=_u16(data,o) if (tgt_flags&TGT_16BIT_OBJNUM) else data[o]
            obj_num = obj_num if (tgt_flags&TGT_16BIT_OBJNUM) else obj_num
            o+= (2 if (tgt_flags&TGT_16BIT_OBJNUM) else 1)
            if stype==SRC_SELECTOR16:
                tgt_off=0
            elif stype==SRC_PTR16_32:
                tgt_off=_u32(data,o); o+=4
            elif stype in (SRC_PTR16_16, SRC_OFFSET16):
                tgt_off=_u16(data,o); o+=2
            elif tgt_flags & TGT_32BIT_OFFSET:
                tgt_off=_u32(data,o); o+=4
            else:
                tgt_off=_u16(data,o); o+=2
            tgt=objects[obj_num-1]
            tgt_linear=tgt.base+tgt_off
            for soff in offs:
                out.append((base+soff, tgt_linear, stype))
    return out

def le_fixup_header(data):
    le_off=_u32(data,0x3C)
    page_size=_u32(data,le_off+0x28); num_pages=_u32(data,le_off+0x14)
    entry_obj=_u32(data,le_off+0x18); entry_off=_u32(data,le_off+0x1C)
    obj_tab=le_off+_u32(data,le_off+0x40); obj_cnt=_u32(data,le_off+0x44)
    fixup_page_tab=le_off+_u32(data,le_off+0x68); fixup_rec_tab=le_off+_u32(data,le_off+0x6C)
    return dict(page_size=page_size,num_pages=num_pages,entry_obj=entry_obj,
                entry_off=entry_off,obj_tab=obj_tab,obj_cnt=obj_cnt,
                fixup_page_tab=fixup_page_tab,fixup_rec_tab=fixup_rec_tab)

# ---------------------------------------------------------------- map parsers
def parse_loaded_map(path):
    """genewars-1_1.map: lines ` 0001:000A38F0   Name` (loaded VA = obj offset)."""
    syms=[]  # (va, name, class) in file order
    for line in path.read_text(errors="replace").splitlines():
        line=line.strip()
        if not line or line.startswith(("Start","Address","Segment","Group","=====")) or line.startswith("0001:00000000 0"):
            pass
        if ":" not in line:
            continue
        seg, rest = line.split(":",1)
        if not seg.strip().startswith("0001"):
            continue
        parts = rest.split()
        if not parts:
            continue
        try:
            off=int(parts[0],16)
        except ValueError:
            continue
        # name is everything after the first run of spaces (may contain $ ? : ( ) [ ])
        name = rest[rest.index(parts[0])+len(parts[0]):].strip()
        if not name:
            continue
        syms.append((off, name))
    return syms

def parse_disc_map(path):
    """disc-MAIN.MAP: Module: lines + `0001:000a7800+ LbVesaGetGran_` symbol lines.
    Returns name -> {module, source, class, flags, offset} (last wins on dup)."""
    cur_module=None; out={}
    for line in path.read_text(errors="replace").splitlines():
        line=line.rstrip("\n")
        s=line.strip()
        if s.startswith("Module:"):
            cur_module=s[len("Module:"):].strip()
            continue
        if ":" not in s:
            continue
        head, rest = s.split(":",1)
        tok = rest.lstrip()
        # parse offset + flags then name
        i=0
        while i<len(tok) and (tok[i].isalnum() and (tok[i].isupper() or tok[i].isdigit())):
            i+=1
        off_hex=tok[:i]
        if not off_hex:
            continue
        seg_off = tok[:i]
        # flags: one of '' '+' '*' between offset and name
        j=i
        flags=""
        while j<len(tok) and tok[j] in "+*":
            flags+=tok[j]; j+=1
        j=j if j<i else i
        name = tok[j:].strip()
        if not name:
            continue
        try:
            off=int(off_hex,16)
            seg=int(head.strip() or "1", 16)
        except ValueError:
            # header / non-symbol lines (e.g. "Created on: 96/08/09 16:20:45")
            continue
        segclass = "code" if seg==1 else ("stack" if "STACK" in s else "data")
        out[name]={"offset":off,"class":segclass,"flags":flags,
                   "module":cur_module,"source":_src(cur_module)}
    return out

def _src(module):
    if not module: return None
    if "(" in module and module.endswith(")"):
        inner=module[module.find("(")+1:-1]
        return inner
    return module

def segclass_from_line(head, line):
    if head=="0001": return "code"
    if head=="0002": return "code16"
    return "data"

# ---------------------------------------------------------------- main
def main():
    data=EXE.read_bytes()
    sha=hashlib.sha256(data).hexdigest()
    im=load_le(EXE)
    obj1=im.objects[0]
    OBJ1_BASE=obj1.base            # 0x10000
    CODE_LO=0x0
    CODE_HI=obj1.virtual_size      # 0xde930  (max object-1 offset)
    hd=le_fixup_header(data)
    fixups=parse_fixups(data, im.objects, hd["page_size"], hd["num_pages"],
                        hd["obj_tab"], hd["obj_cnt"],
                        hd["fixup_page_tab"], hd["fixup_rec_tab"])
    # convert to loaded-VA coordinate (linear - OBJ1_BASE for object-1-resident)
    def to_va(lin): return lin - OBJ1_BASE
    fix_by_va={}
    for src_lin,tgt_lin,st in fixups:
        src_va=to_va(src_lin)
        fix_by_va.setdefault(src_va,[]).append({"target_va":to_va(tgt_lin),
                                                 "target_linear":tgt_lin,"stype":st})

    loaded=parse_loaded_map(LOAD)
    disc=parse_disc_map(DISC)

    # ordered code symbols (loaded VA) with next-symbol boundary
    code=[(va,name) for (va,name) in loaded if CODE_LO <= va < CODE_HI]
    code.sort()
    by_va={va:i for i,(va,name) in enumerate(code)}
    symbols=[]
    for idx,(va,name) in enumerate(code):
        nxt = code[idx+1][0] if idx+1<len(code) else CODE_HI
        size=nxt-va
        fix=[f for f in fix_by_va if va <= f < nxt]
        fva=sorted(fix)
        d=disc.get(name,{})
        symbols.append({
            "name":name,
            "va":va,
            "va_hex":f"0x{va:08X}",
            "class":"code",
            "size":size,
            "next_va":nxt,
            "module":d.get("module"),
            "source":d.get("source"),
            "disc_class":d.get("class"),
            "disc_flags":d.get("flags",""),
            "disc_offset":d.get("offset"),
            "fixup_count":len(fva),
            "fixups":[{"src_va":f,"target_va":fix_by_va[f][0]["target_va"],
                       "target_linear":fix_by_va[f][0]["target_linear"],
                       "stype":fix_by_va[f][0]["stype"]} for f in fva],
        })

    # data symbols (non-code) for reference
    data_syms=[]
    for (va,name) in loaded:
        if not (CODE_LO <= va < CODE_HI):
            d=disc.get(name,{})
            data_syms.append({"name":name,"va":va,"va_hex":f"0x{va:08X}",
                              "class":"data","module":d.get("module"),
                              "source":d.get("source")})

    out={
        "target":{"path":str(EXE),"sha256":sha},
        "maps":{"loaded_map":{"path":str(LOAD),"sha256":hashlib.sha256(LOAD.read_bytes()).hexdigest()},
                "disc_map":{"path":str(DISC),"sha256":hashlib.sha256(DISC.read_bytes()).hexdigest()}},
        "code_range":[f"0x{CODE_LO:08X}",f"0x{CODE_HI:08X}"],
        "object1_base":OBJ1_BASE,
        "le":{"entry_loaded_va":(im.entry_linear-OBJ1_BASE),
             "page_size":hd["page_size"],"num_pages":hd["num_pages"],
             "fixup_count":len(fixups)},
        "n_code_symbols":len(symbols),
        "n_data_symbols":len(data_syms),
        "symbols":symbols,
        "data_symbols":data_syms,
    }
    OUT.write_text(json.dumps(out,indent=1),encoding="utf-8")
    bn={}
    for s in symbols:
        bn.setdefault(s["name"],[]).append({"va":s["va"],"class":s["class"],
            "module":s["module"],"source":s["source"],"size":s["size"],
            "fixup_count":s["fixup_count"]})
    OUT_BN.write_text(json.dumps(bn,indent=1),encoding="utf-8")

    # sanity print
    print(f"target sha256 {sha[:16]}")
    print(f"code_range {hex(CODE_LO)}-{hex(CODE_HI)}  obj1_base {hex(OBJ1_BASE)}")
    print(f"code symbols {len(symbols)}  data symbols {len(data_syms)}  fixups {len(fixups)}")
    # spot-check the known anchors
    by_name={s["name"]:s for s in symbols}
    for n,expect in [("LbVesaGetGran_",0xA38F0),("LbVesaSetMode_",0xA3A00),
                     ("LbVesaSetPage_",0xA3A5C),("LbVesaGetInfo_",0xA3AD0),
                     ("LbVesaIsModeAvailable_",0xA3BA4),("RationalAlloc_",0xC3CA9)]:
        s=by_name.get(n)
        print(f"  {n:22} va={s['va_hex'] if s else 'MISSING'} module={s['module'] if s else '-'} fixups={s['fixup_count'] if s else '-'} (expect {hex(expect)})")
    print("wrote", OUT)
    print("wrote", OUT_BN)

if __name__=="__main__":
    main()
