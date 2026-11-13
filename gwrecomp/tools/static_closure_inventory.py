#!/usr/bin/env python3
"""Static closure inventory: which functions of the original executable are NOT lifted yet.

No game is played. The tool reads the user's own LE executable, finds every function entry it can prove statically
and compares the list with the functions the current build lifted (the closure report written by the build).

Function entries (union):
  * code symbols of the link map (names only; the map is the user's local file),
  * the program entry point,
  * every internal LE fixup that points into the code object and sits OUTSIDE a jump table (vtable slots, callback
    arrays, pushed function pointers),
  * every direct `call rel32` target found by recursive descent from all of the above and from the lifted functions
    (jump-table targets are followed as labels inside a function, not counted as functions).

Groups of the functions that are not lifted:
  A  referenced from a data-object pointer table (vtable / callback array) or called directly from lifted code, and
     belonging to the game logic (bio/ classes) - or, when the name is unknown, still referenced that way
  B  engine support (bflibrary, bfmydraw, smacklib, bfsoundlib names) not covered
  C  DOS / DPMI / IPX / hardware / CRT-start-up code replaced by the host layer, or code only reachable from such code
  U  unclassified: no name evidence and no reference from lifted code or data tables (listed so nothing is hidden)
Names come from the map (exact symbol, else the nearest preceding symbol, flagged in `name_basis`); the group of a name
comes from the public source tree (--src). This is a classification aid, not a proof: see the `basis` column.

Usage:
  python tools/static_closure_inventory.py --exe <genewars-1_1.exe> --map <genewars-1_1.map> \
      --closure <..._closure_closure.json> --src <build\\...\\src> --out docs/STATIC_CLOSURE_REMAINING.tsv
"""
from __future__ import annotations
import argparse, bisect, collections, hashlib, json, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from le_loader import load_le  # noqa: E402
import capstone  # noqa: E402

CRT_REGION_START = 0x000BC09F   # first Watcom runtime symbol (__save_8087_) in the link map; everything after is library code
EXPECTED_SHA = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"


def parse_map(path):
    syms = []
    for line in Path(path).read_text(errors="replace").splitlines():
        m = re.match(r"\s*0001:([0-9A-Fa-f]{8})\s+(\S+)\s*$", line)
        if m:
            name = m.group(2)
            if re.match(r"(jpt_|def_|jump_|___begtext)", name):
                continue
            syms.append((int(m.group(1), 16), name))
    syms.sort()
    return syms


def norm(name):
    """Map symbol -> (kind, key): C++ `W?Method$:Class$n(...)` -> ('cpp', 'class'); C `Name_` -> ('c', 'name')."""
    m = re.match(r"W\?([^$]*)\$:([^$]*)\$", name)
    if m:
        return "cpp", m.group(2).lower()
    m = re.match(r"W\?(\w+)\$n", name)
    if m:
        return "cppfunc", m.group(1).lower()
    if name.endswith("_"):
        return "c", name[:-1].lower()
    return "c", name.lower()


def source_names(src):
    """Identifier sets per group from the public source tree."""
    sets = {"A": set(), "B": set(), "NET": set(), "DOS": set()}
    src = Path(src)
    def scan(dirpath, key):
        for f in dirpath.rglob("*"):
            if f.suffix.lower() in (".c", ".cpp", ".h", ".hpp", ".asm", ".s"):
                sets[key].add(f.stem.lower())
                try:
                    t = f.read_text(errors="replace")
                except OSError:
                    continue
                for m in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", t):
                    sets[key].add(m.group(1).lower())
                for m in re.finditer(r"\b(?:class|struct)\s+(\w+)|\b(\w+)::\w+\s*\(", t):
                    sets[key].add((m.group(1) or m.group(2)).lower())
    if (src / "bio").is_dir(): scan(src / "bio", "A")
    for d in ("bflibrary", "bfmydraw", "smacklib", "bfsoundlib"):
        if (src / d).is_dir(): scan(src / d, "B")
    if (src / "bfnet2lib").is_dir(): scan(src / "bfnet2lib", "NET")
    dosdir = src / "bflibrary" / "src" / "x86-dos-watcom"
    if dosdir.is_dir(): scan(dosdir, "DOS")
    return sets


DOS_PAT = re.compile(r"(dpmi|int386|int86|_dos_|dos_|ipx|vesa|vbe|_cstart|___begtext|__wc|__wcpp|_wcpp|__chk|__stk|"
                     r"__exit|__init|__fini|_main|__alloc|_nmalloc|_nfree|__flt|__i8|__u8|__i4|__u4|__fp|__8087|"
                     r"__save_|__rest_|irq|isr|dma|sb16|adlib|__nh|__ff|__sbrk|__brk|__lseek|_fstrlen|_Init)", re.I)
CRT_PAT = re.compile(r"^(_?_?(printf|sprintf|puts|exit|memcpy|memset|strlen|strcpy|strcmp|malloc|free|fopen|fread|fclose|fwrite|abs|atoi|rand|srand)|"
                     r"__.*|_[a-z]+f?)$", re.I)


CRT_NAMES = set("""fcloseall __full_io_exit fclose fopen fread fwrite fseek ftell fflush fgets fputs fprintf fscanf printf sprintf
sscanf puts putchar getchar gets exit abort atexit atoi atol strtol strtoul strlen strcpy strncpy strcat strcmp strncmp strchr
strrchr strstr strupr strlwr stricmp strnicmp memcpy memmove memset memcmp memchr malloc calloc realloc free abs labs rand srand
qsort bsearch toupper tolower isalpha isdigit isspace time clock getenv system signal setjmp longjmp int386 int386x int86 delay
nullsub""".split())


# Engine entries that talk to DOS hardware or drivers the host replaces (gw_vsb16 virtual SB16 + timer, gw_smk_* hooks).
# They are kept out of the lift so no lifted path can reach them past the host layer.
HOST_REPLACED = {
    0x000AFFF0: "Miles _TIME_callback (timer interrupt; host timer)",
    0x000B0630: "Miles _AIL_set_USE16_ISR (ISR install)",
    0x000C8DC8: "Miles real-mode vector thunk", 0x000C8DCF: "Miles real-mode vector thunk",
    0x000C8DDE: "Miles real-mode vector thunk", 0x000C8DE4: "Miles real-mode vector thunk",
    0x000C8DFA: "Miles real-mode vector thunk", 0x000C8E04: "Miles real-mode vector thunk",
    0x000C8E0B: "Miles real-mode vector thunk",
    0x000C8E1D: "Miles _AIL_API_set_USE16_ISR (ISR install)",
    0x000C9078: "Miles _AIL_API_disable_interrupts (CLI)",
    0x000C94D0: "Miles _AIL_API_set_timer_frequency (PIT programming)",
    0x000C7A10: "Miles _DLL_size (DOS driver loader)", 0x000C7B50: "Miles _DLL_load (DOS driver loader)",
    0x000C4110: "SMACKSOUNDUSEMSS (MSS clock path; host forces GetSoundDriver_=0 at the Smacker call sites)",
    0x000C42E0: "SMACKSOUNDUSEMSS (MSS clock path; host forces GetSoundDriver_=0 at the Smacker call sites)",
}


# Entries the inventory finds through code pointers but that are not code (group X), and engine entries the lifter refuses
# (static access to an address that no fixup resolves); the latter stay in group B with the reason.
NOT_CODE = {0x000962A2: "lbSqrTable is a lookup table referenced by a code pointer"}
LIFTER_REFUSED = {
    0x000E1760: "lifter refuses: static access to 0x001B0000 (no fixup)",
    0x000E8DF0: "lifter refuses: static access to 0x001B034C (no fixup)",
    0x000EA668: "lifter refuses: static access to 0x001B034C (no fixup)",
}


def classify(name_syms, va, name, basis_exact, sets, lifted_ref, table_ref):
    if va in HOST_REPLACED:
        return "C", "host-replaced:" + HOST_REPLACED[va]
    if va in NOT_CODE:
        return "X", "not-code:" + NOT_CODE[va]
    if va in LIFTER_REFUSED:
        return "B", LIFTER_REFUSED[va]
    kind, key = norm(name)
    if not basis_exact:     # nearest-preceding symbol: no name evidence for THIS entry, use references only
        if lifted_ref or table_ref: return "A", "ref:table-or-lifted-caller(unnamed)"
        return "U", "unnamed,no-reference-from-lifted-or-tables"
    if re.match(r"^(j_)?_?smack", key): return "B", "name:smacklib"
    if re.match(r"^(radica_|.*datagram)", key) or key.startswith("w?send_old"): return "C", "name:network/IPX(radica)"
    if key == "start": return "C", "name:entry/CRT-startup"
    if re.match(r"^(main_|freopen_|log_|_get_osfhandle|_os_handle_|w\?(com_handler|kint|mousehandler|keyhandler|timer))", key) or key in ("write_string_", "close_file_"):
        return "C", "name:dos-hardware-handler/CRT"
    if key in CRT_NAMES or re.match(r"^(nullsub_|unknown_libname_|__)", key): return "C", "name:crt/stub"
    if key in sets["NET"] or "ipx" in key or key.startswith("lbnetwork") or "net2" in key:
        return "C", "name:network/IPX"
    if key in sets["A"] and kind == "cpp":
        return "A", "name:bio-class"
    if kind == "cppfunc" and key in sets["A"]:
        return "A", "name:bio-function"
    if kind == "cppfunc" and key in sets["B"]:
        return "B", "name:engine-function"
    if key in sets["A"] and key not in sets["B"]:
        return "A", "name:bio-symbol"
    if key in sets["DOS"] and key not in sets["A"]:
        return "C", "name:dos-platform"
    if key in sets["B"]:
        return "B", "name:engine-lib"
    if re.match(r"^(lb|bf|my|smk|smack|ail|sound|midi|digi|scr|spr|draw|pix|gad|font)", key):
        return "B", "name:engine-prefix"
    if DOS_PAT.search(name):
        return "C", "name:dos/crt-pattern"
    if kind == "cpp":
        return "A", "name:cpp-method-unmatched"
    if kind == "cppfunc" and va < CRT_REGION_START:
        return "A", "name:cpp-free-function-unmatched"
    if va >= CRT_REGION_START:
        return "C", "address>=CRT-runtime-region"
    if lifted_ref or table_ref:
        return "A", "ref:table-or-lifted-caller"
    return "U", "no-name-evidence"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--exe", required=True); ap.add_argument("--map", required=True)
    ap.add_argument("--closure", required=True); ap.add_argument("--src", required=True)
    ap.add_argument("--out", required=True); ap.add_argument("--summary")
    a = ap.parse_args()
    raw = Path(a.exe).read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    if sha != EXPECTED_SHA:
        sys.exit(f"unexpected executable SHA-256 {sha}")
    image = load_le(a.exe)
    obj1 = image.objects[0]
    base, size = obj1.base, obj1.virtual_size
    code = bytes(image.object_data(1))
    clos = json.load(open(a.closure))
    if clos.get("target_sha256") != sha:
        sys.exit("closure report is for a different executable")
    lifted = sorted((int(f["address"], 16), int(f["end"], 16)) for f in clos["lifted"])
    lstarts = [s for s, _ in lifted]
    def is_lifted(va):
        i = bisect.bisect_right(lstarts, va) - 1
        return i >= 0 and lifted[i][0] <= va < lifted[i][1]
    def in_code(va): return base <= va < base + size
    syms = parse_map(a.map)
    sym_addr = [s[0] for s in syms]
    sym_by_addr = {}
    for addr, name in syms: sym_by_addr.setdefault(addr, name)
    # fixups into the code object, split by where they live
    runs = collections.defaultdict(list)
    for fx in image.fixups:
        if fx.target_object == 1 and (fx.target_flags & 3) == 0 and fx.source_type == 0x07:
            runs[fx.source_link].append(base + fx.target_offset)
    table_regions = []
    for key in ("indexed_code_jump_tables", "indexed_code_call_tables"):
        for t in clos.get(key, []):
            tb = int(t["table_link"], 16); table_regions.append((tb, tb + 4 * int(t["count"])))
    srcs = sorted(runs)
    in_run = set()   # fixup sources that are part of a >=2-slot contiguous run
    i = 0
    while i < len(srcs):
        j = i
        while j + 1 < len(srcs) and srcs[j + 1] == srcs[j] + 4: j += 1
        if j > i:
            in_run.update(srcs[i:j + 1])
        i = j + 1
    table_ref = collections.defaultdict(list)    # function va -> data-table sources (object != 1)
    code_ptr_ref = collections.defaultdict(list)  # pushed/stored pointers inside code (single, not in a run)
    jump_labels = set()
    for s, tgts in runs.items():
        owner = image.object_containing(s)
        for t in tgts:
            if owner is not None and owner.index != 1:
                table_ref[t].append(s)
            elif s in in_run:
                jump_labels.add(t)
            else:
                code_ptr_ref[t].append(s)
    for s0 in in_run:
        table_regions.append((s0, s0 + 4))
    def in_table(va): return any(lo <= va < hi for lo, hi in table_regions)
    funcs = set(sym_addr_ for sym_addr_ in sym_addr if in_code(sym_addr_))
    funcs |= set(f for f in table_ref if in_code(f)) | set(code_ptr_ref)
    funcs = set(f for f in funcs if not in_table(f))    # pointers to jump-table data are not functions
    funcs.add(image.entry_link)
    funcs |= set(s for s, _ in lifted)
    callers = collections.defaultdict(set)       # target -> {caller instruction va}
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32); md.detail = True
    seen = set(); work = list(funcs) + list(jump_labels)
    while work:
        start = work.pop()
        if start in seen or not in_code(start): continue
        pc = start
        while in_code(pc):
            if pc in seen and pc != start: break
            seen.add(pc)
            ins = next(md.disasm(code[pc - base:pc - base + 16], pc), None)
            if ins is None: break
            grp = ins.groups
            if capstone.CS_GRP_CALL in grp and ins.operands and ins.operands[0].type == capstone.CS_OP_IMM:
                t = ins.operands[0].imm
                if in_code(t):
                    callers[t].add(ins.address)
                    if t not in funcs: funcs.add(t); work.append(t)
            elif capstone.CS_GRP_JUMP in grp and ins.operands and ins.operands[0].type == capstone.CS_OP_IMM:
                t = ins.operands[0].imm
                if in_code(t) and t not in seen: work.append(t)
            if capstone.CS_GRP_RET in grp or (ins.mnemonic == "jmp") or ins.mnemonic in ("int3", "ud2", "hlt"):
                break
            pc = ins.address + ins.size
    fl = sorted(funcs)
    sets = source_names(a.src)
    rows = []; counts = collections.Counter(); total_by = collections.Counter()
    for k, va in enumerate(fl):
        nxt = fl[k + 1] if k + 1 < len(fl) else base + size
        lifted_here = is_lifted(va)
        total_by["total"] += 1
        if lifted_here:
            total_by["lifted"] += 1; continue
        if va in sym_by_addr: name, nb = sym_by_addr[va], "exact"
        else:
            i = bisect.bisect_right(sym_addr, va) - 1
            name, nb = (syms[i][1], "nearest-preceding") if i >= 0 else ("?", "none")
        lifted_callers = sorted(c for c in callers.get(va, ()) if is_lifted(c))
        other_callers = sorted(c for c in callers.get(va, ()) if not is_lifted(c))
        tref = table_ref.get(va, []); cref = code_ptr_ref.get(va, [])
        group, basis = classify(syms, va, name, nb == "exact", sets, bool(lifted_callers), bool(tref or cref))
        if nb != "exact":
            # unnamed entry: it belongs to the module of the symbol that precedes it; inherit that symbol's group
            pg, pb = classify(syms, va, name, True, sets, False, False)
            if pg in ("A", "B", "C"):
                group, basis = pg, "inherit:" + pb
            elif va >= CRT_REGION_START:
                group, basis = "C", "address>=CRT-runtime-region"
        # an unnamed function reached only from data tables / lifted code keeps its reference-based group
        if group in ("U",) and (tref or cref or lifted_callers): group, basis = "A", "ref:table-or-lifted-caller"
        refs = []
        if tref: refs.append(f"table x{len(tref)}")
        if cref: refs.append(f"code-pointer x{len(cref)}")
        if lifted_callers: refs.append(f"called-from-lifted x{len(lifted_callers)}")
        if other_callers: refs.append(f"called-from-unlifted x{len(other_callers)}")
        rows.append((f"0x{va:08X}", nxt - va, group, name, nb, basis, "; ".join(refs) or "none"))
        counts[group] += 1
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    with open(a.out, "w", encoding="utf-8", newline="\n") as f:
        f.write("va\tsize_to_next_entry\tgroup\tname\tname_basis\tgroup_basis\treferences\n")
        for r in rows: f.write("\t".join(str(x) for x in r) + "\n")
    summ = {"exe_sha256": sha, "code_object_size": size, "function_entries_found": total_by["total"],
            "lifted_entries": total_by["lifted"], "not_lifted": len(rows), "by_group": dict(counts),
            "table_referenced_not_lifted": sum(1 for r in rows if "table" in r[6]),
            "called_from_lifted_not_lifted": sum(1 for r in rows if "called-from-lifted" in r[6])}
    print(json.dumps(summ, indent=2))
    if a.summary: Path(a.summary).write_text(json.dumps(summ, indent=2))


if __name__ == "__main__":
    main()
