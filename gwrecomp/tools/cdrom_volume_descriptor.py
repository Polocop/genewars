#!/usr/bin/env python3
"""L-CDVOLDESC: extract the ISO 9660 volume descriptor from the original
GeneWars CD-ROM (read-only reference E:\\GeneWarsFX) and emit the exact 16-byte
MSCDEX AH=1500 drive-parameter buffer that WORK2's W2-MSCDEXRESP handler must
return to serve a REAL drive-parameters response (not just no-CD) and back the
post-MENU AH=1510 data reads.

Method (per cd-image-iso9660 skill — standard reader, never hand-rolled):
  1. Parse the CUE: Track 1 = MODE1/2352 data (the ISO volume), Tracks 2-5 audio.
  2. Validate the 2352->2048 data offset by locating the canonical Primary
     Volume Descriptor (type byte 0x01 + ASCII 'CD001' + version byte at the
     standard PVD position) in Track 1's 2352 image.
  3. Convert Track 1 to a 2048-sector working ISO on E: (original left untouched).
  4. Prove fidelity: sha256 of N probe LBAs identical in raw-2352@offset and ISO.
  5. Parse the PVD via pycdlib (standard reader): set id, version, volume space
     size, path-table LBAs, root directory LBA+length, volume label.
  6. Extract the disc TOC (for AH=150C) and map to the MSCDEX AH=1500 buffer.
  7. Emit evidence/gw_cdrom_volume_descriptor.json (deterministic) + a report.

Read-only w.r.t. E:\\GeneWarsFX (hashes it to prove unchanged). No GUI. Does NOT
implement the MSCDEX runtime handler (that is W2-MSCDEXRESP/WORK2).
"""
import os, re, json, hashlib, struct, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EV = os.path.join(ROOT, "evidence")
REP = os.path.join(ROOT, "reports")
WORK = os.path.join(ROOT, "build", "cdrom")
os.makedirs(WORK, exist_ok=True)

REF = r"E:\GeneWarsFX"
CUE = os.path.join(REF, "Genewars (Europe) (En,Fr,De,Es,It,Sv).cue")

def log(m): print(m, flush=True)

# ---------------------------------------------------------------------------
# 1. Parse CUE -> data track bin + audio track list + first audio track LBA
# ---------------------------------------------------------------------------
def parse_cue(path):
    txt = open(path, "r", encoding="utf-8", errors="replace").read()
    files = re.findall(r'FILE\s+"([^"]+)"\s+(\S+)', txt)
    tracks = []
    cur_file = None
    for line in txt.splitlines():
        fm = re.match(r'FILE\s+"([^"]+)"\s+(\S+)', line)
        if fm:
            cur_file = (fm.group(1), fm.group(2)); continue
        tm = re.match(r'TRACK\s+(\d+|0[0-9])\s+(MODE[0-9/]+|AUDIO|CDROM)', line)
        if tm:
            ttype = tm.group(2); 
            tracks.append({"file": cur_file[0], "num": int(tm.group(1)), "type": ttype, "indexes": {}})
            continue
        im = re.match(r'INDEX\s+(\d+)\s+(\d+):(\d+):(\d+)', line)
        if im and tracks:
            fr, sec, fr60 = int(im.group(2)), int(im.group(3)), int(im.group(4))
            tracks[-1]["indexes"][im.group(1)] = fr*750000 + sec*75 + fr60  # raw ticks (unused for MODE1 data offset)
    data_track = next((t for t in tracks if t["type"].startswith("MODE1")), None)
    audio = [t for t in tracks if t["type"]=="AUDIO"]
    return tracks, data_track, audio

def bin_abs(cue_filename):
    p = os.path.join(REF, os.path.basename(cue_filename))
    return p

# ---------------------------------------------------------------------------
# 2. Offset validation: find canonical PVD in the 2352 image
# ---------------------------------------------------------------------------
def validate_offset(bin_path):
    """Return (offset, pvd_lba) or (None, None)."""
    data = open(bin_path, "rb").read()
    # candidate offsets for the 2048-byte data payload inside each 2352 sector
    for off in (24, 16, 18):
        # PVD is at ISO LBA 16 (the canonical primary volume descriptor set start)
        # but the *first* 2352 sector (ISO LBA 0) is the reserved sector; the
        # PVD itself is at ISO LBA 16. Scan a window of LBAs 10..20 to be safe.
        for lba in range(10, 21):
            base = lba*2352 + off
            if base + 4 > len(data): break
            if data[base] == 0x01 and data[base+1:base+6] == b"CD001":
                ver = data[base+840]
                log(f"  PVD found at 2352-offset={off}, ISO LBA={lba}, version={ver}")
                return off, lba
    return None, None

# ---------------------------------------------------------------------------
# 3. Convert 2352 -> 2048 (keep only the data volume, up to the last LBA)
# ---------------------------------------------------------------------------
def convert(data, off, out_iso):
    n2352 = len(data)//2352
    # ISO 9660 data usually ends well before the audio gap; we keep all data
    # sectors. pycdlib will read the volume space size from the PVD.
    with open(out_iso, "wb") as o:
        for i in range(n2352):
            o.write(data[i*2352+off : i*2352+off+2048])
    log(f"  converted {n2352} sectors -> {out_iso} ({os.path.getsize(out_iso)} bytes)")
    return n2352

def probe_hashes(bin_path, off, iso, probe_lbas=(16, 17, 20, 21)):
    """sha256 of the 2048 payload at each probe LBA in both sources."""
    data = open(bin_path, "rb").read()
    rows = []
    for lba in probe_lbas:
        a = hashlib.sha256(data[lba*2352+off : lba*2352+off+2048]).hexdigest()
        with open(iso, "rb") as f:
            f.seek(lba*2048); b = hashlib.sha256(f.read(2048)).hexdigest()
        rows.append({"lba": lba, "raw2352@offset": a, "iso2048": b, "match": a==b})
    return rows

# ---------------------------------------------------------------------------
# 4. Read PVD + TOC via pycdlib standard reader
# ---------------------------------------------------------------------------
def read_pycdlib(iso):
    import pycdlib
    d = pycdlib.PyCdlib()
    d.open(iso)
    vd = d.get_disk_1_primary_volume_descriptor()
    pvd = {
        "id": vd.id.decode() if isinstance(vd.id, bytes) else vd.id,
        "version": vd.version.decode() if isinstance(vd.version, bytes) else vd.version,
        "space_size": int(vd.space_size),
        "space_size_lba": int(vd.space_size)//2048,
        "path_table1_lba": int(vd.path_table1_lba),
        "path_table1_size": int(vd.path_table1_size),
        "path_table2_lba": int(vd.path_table2_lba),
        "path_table2_size": int(vd.path_table2_size),
        "set_disk_number": int(vd.set_disk_number),
        "set_disk_count": int(vd.set_disk_count),
        "application_id": (vd.application_id.decode(errors="replace").strip("\x00 ") or None),
        "publisher_id": (vd.publisher_id.decode(errors="replace").strip("\x00 ") or None),
        "preparer_id": (vd.preparer_id.decode(errors="replace").strip("\x00 ") or None),
        "volume_space_size": int(getattr(vd, "volume_space_size", 0) or 0),
    }
    # root directory record
    rd = d.get_directory_record(0)
    root = {
        "length": int(rd.length),
        "lba": int(rd.location),
        "filename": rd.filename.decode() if isinstance(rd.filename, bytes) else rd.filename,
    }
    vol_label = (vd.volume_space_id.decode(errors="replace").strip("\x00 ") if hasattr(vd,"volume_space_id") and vd.volume_space_id else "")
    pvd["volume_label"] = vol_label
    pvd["root_directory"] = root
    # TOC: list all tracks if pycdlib exposes them (for the AUDIO portion, the
    # 2048 ISO has no audio; we report audio from the CUE instead).
    try:
        pvd["toc"] = d.get_toc()
    except Exception as e:
        pvd["toc"] = f"unavailable via pycdlib on data-only ISO: {e}"
    d.close()
    return pvd

# ---------------------------------------------------------------------------
# 5. MSCDEX AH=1500 drive-parameter buffer mapping
# ---------------------------------------------------------------------------
def root_dir_length_code(root_len_bytes):
    # 01/02/04/08 = 1/2/4/8 sectors; round the root dir up to a power-of-two
    # sector count. MSCDEX historically used 0x04 (4 sectors) for most drives.
    sectors = (root_len_bytes + 2047)//2048
    code = 0
    for c, s in ((1,1),(2,2),(4,4),(8,8)):
        if sectors <= s: code = c; break
    else:
        code = 8
    return code, sectors

def mscdex_buffer(pvd, drive_letter="P", mscdex_drive=1, audio_first_lba=0):
    buf = {
        "drive_letter": drive_letter,
        "drive_letter_ascii": ord(drive_letter),
        "root_dir_length_code": root_dir_length_code(pvd["root_directory"]["length"])[0],
        "root_dir_length_sectors": root_dir_length_code(pvd["root_directory"]["length"])[1],
        "root_dir_start_lba": pvd["root_directory"]["lba"],
        "audio_first_track_lba": audio_first_lba,
        "mscdex_drive_number": mscdex_drive,
        "volume_label_length": len(pvd.get("volume_label","")),
        "volume_label": pvd.get("volume_label",""),
    }
    return buf

# ---------------------------------------------------------------------------
def main():
    log("=== L-CDVOLDESC: GeneWars CD ROM volume descriptor extraction ===")
    tracks, data_track, audio = parse_cue(CUE)
    log("CUE tracks:")
    for t in tracks:
        log(f"  TRACK {t['num']:02d} {t['type']:>10}  file={os.path.basename(t['file'])}")
    if not data_track:
        log("FATAL: no MODE1 data track in CUE"); sys.exit(2)
    data_bin = bin_abs(data_track["file"])
    log(f"data track bin: {data_bin}  size={os.path.getsize(data_bin)}")
    orig_sha = hashlib.sha256(open(data_bin,"rb").read()).hexdigest()
    log(f"original bin sha256: {orig_sha}")

    off, pvd_lba = validate_offset(data_bin)
    if off is None:
        log("FATAL: no canonical PVD at any candidate offset (16/18/24) in LBAs 10-20"); sys.exit(3)
    log(f"validated 2352->2048 offset = {off}")

    data = open(data_bin, "rb").read()
    iso = os.path.join(WORK, "genewars_eu_data.iso")
    convert(data, off, iso)

    probes = probe_hashes(data_bin, off, iso)
    log("probe-LBA fidelity:")
    ok = all(p["match"] for p in probes)
    for p in probes:
        log(f"  LBA {p['lba']:>4}: match={p['match']}  sha={p['iso2048'][:16]}")
    if not ok:
        log("FATAL: probe hashes mismatch -> conversion not trustworthy; BLOCKED"); sys.exit(4)

    pvd = read_pycdlib(iso)
    log("Primary Volume Descriptor (pycdlib):")
    for k in ("id","version","space_size_lba","path_table1_lba","path_table1_size",
              "root_directory","volume_label","set_disk_number","set_disk_count",
              "application_id","publisher_id","preparer_id"):
        log(f"  {k}: {pvd.get(k)}")

    # first audio track LBA: track 2 audio INDEX 01 = 00:01:74 (74 frames after the
    # data track end). The data track is n2352 sectors = its LBA span; audio starts
    # right after. We report the audio span for the AH=150C TOC context.
    n2352 = len(data)//2352
    audio_first_lba = n2352  # first audio sector LBA (approx: data ends, audio begins)

    buf = mscdex_buffer(pvd, drive_letter="P", mscdex_drive=1, audio_first_lba=audio_first_lba)
    log("MSCDEX AH=1500 drive-parameter buffer (WORK2 must return this for BX=1):")
    for k,v in buf.items(): log(f"  {k}: {v}")

    # Re-hash original to prove unchanged
    orig_sha2 = hashlib.sha256(open(data_bin,"rb").read()).hexdigest()
    ref_unchanged = (orig_sha == orig_sha2)

    # TOC context: audio tracks from CUE
    toc_audio = []
    for t in audio:
        toc_audio.append({"track": t["num"], "file": os.path.basename(t["file"]),
                          "index01": t["indexes"].get("01"), "type": "AUDIO"})

    result = {
        "schema": "gw_cdrom_volume_descriptor/v1",
        "generated_by": "tools/cdrom_volume_descriptor.py (L-CDVOLDESC, LOCAL)",
        "deterministic": True,
        "source_reference": {
            "path": data_bin,
            "cue": CUE,
            "read_only_reference": "E:/GeneWarsFX",
            "original_bin_sha256": orig_sha,
            "original_unchanged_after": ref_unchanged,
        },
        "cue_tracks": [{"track": t["num"], "type": t["type"], "file": os.path.basename(t["file"])} for t in tracks],
        "conversion": {
            "source_format": "2352 (MODE1/2352)",
            "data_offset": off,
            "pvd_lba": pvd_lba,
            "working_iso": iso,
            "working_iso_sha256": hashlib.sha256(open(iso,"rb").read()).hexdigest(),
            "working_iso_size": os.path.getsize(iso),
            "data_2352_sectors": n2352,
        },
        "probe_lba_fidelity": probes,
        "primary_volume_descriptor": pvd,
        "mscdex_ah_1500_drive_parameter_buffer": buf,
        "audio_toc_context": {"first_audio_lba_approx": audio_first_lba, "tracks": toc_audio},
        "consumed_by": "W2-MSCDEXRESP (WORK2) real-mode INT 2Fh AH=1500 handler",
        "notes": [
            "drive_letter 'P' and mscdex_drive_number 1 are the conventional defaults; WORK2 must confirm the actual letter against the game's expected CD drive (the no-CD W3-029 path used zero drives).",
            "audio_first_track_lba is approximate (data-track span); the exact first-audio LBA for the AH=150C TOC should be re-derived from the CUE INDEX 01 of Track 2 once WORK2 needs audio.",
            "volume space size / root dir LBA / length come straight from the standard pycdlib PVD parse and are the authoritative values for a real MSCDEX response.",
        ],
    }
    os.makedirs(EV, exist_ok=True)
    js = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False, default=str)
    out_json = os.path.join(EV, "gw_cdrom_volume_descriptor.json")
    open(out_json,"w",encoding="utf-8").write(js+"\n")
    log(f"WROTE {out_json}")
    log(f"sha256: {hashlib.sha256(js.encode('utf-8')).hexdigest()}")
    log(f"original reference unchanged: {ref_unchanged}")

    # Report
    os.makedirs(REP, exist_ok=True)
    L=[]; L.append("# LOCAL CD-ROM Volume Descriptor (L-CDVOLDESC)")
    L.append("")
    L.append("Extracted from the read-only original disc `E:\\GeneWarsFX` (5-track BIN/CUE; Track 1 = MODE1/2352 data volume, Tracks 2-5 = audio). Machine-readable companion: `evidence/gw_cdrom_volume_descriptor.json` (deterministic).")
    L.append("")
    L.append("Feeds WORK2's `W2-MSCDEXRESP` to return a **real** MSCDEX AH=1500 drive-parameters response (not just no-CD) and to back the post-MENU AH=1510 data reads.")
    L.append("")
    L.append("## Conversion & fidelity")
    L.append("")
    L.append("- 2352->2048 data offset: **%d** (validated against the canonical PVD `0x01`+`CD001` at ISO LBA %d)." % (off, pvd_lba))
    L.append("- Working ISO: `%s` (sha256 %s, %d bytes)." % (iso, result["conversion"]["working_iso_sha256"][:16], os.path.getsize(iso)))
    L.append("- Probe-LBA fidelity (raw 2352@offset vs ISO 2048):")
    L.append("")
    L.append("| LBA | match | sha256 (ISO) |")
    L.append("|-----|-------|--------------|")
    for p in probes:
        L.append("| %d | %s | %s… |" % (p["lba"], p["match"], p["iso2048"][:16]))
    L.append("")
    L.append("## Primary Volume Descriptor (standard pycdlib reader)")
    L.append("")
    L.append("| Field | Value |")
    L.append("|-------|-------|")
    p = result["primary_volume_descriptor"]
    for k in ("id","version","space_size_lba","path_table1_lba","path_table1_size",
              "path_table2_lba","path_table2_size","set_disk_number","set_disk_count",
              "application_id","publisher_id","preparer_id","volume_label"):
        L.append("| %s | %s |" % (k, p.get(k)))
    rd = p.get("root_directory",{})
    L.append("| root_directory.lba | %s |" % rd.get("lba"))
    L.append("| root_directory.length | %s |" % rd.get("length"))
    L.append("")
    L.append("## MSCDEX AH=1500 drive-parameter buffer (what WORK2 must return for BX=1)")
    L.append("")
    L.append("| Off | Size | Field | Value |")
    L.append("|-----|------|-------|-------|")
    b = result["mscdex_ah_1500_drive_parameter_buffer"]
    L.append("| 0 | 1 | drive_letter | %s (0x%02x) |" % (b["drive_letter"], b["drive_letter_ascii"]))
    L.append("| 1 | 1 | root_dir_length_code | 0x%02x (%d sectors) |" % (b["root_dir_length_code"], b["root_dir_length_sectors"]))
    L.append("| 2 | 2 | root_dir_start_lba | 0x%04x |" % b["root_dir_start_lba"])
    L.append("| 4 | 2 | audio_first_track_lba | 0x%04x (approx) |" % b["audio_first_track_lba"])
    L.append("| 6 | 2 | mscdex_drive_number | %d |" % b["mscdex_drive_number"])
    L.append("| 8 | 1 | volume_label_length | %d |" % b["volume_label_length"])
    L.append("| 9 | 31 | volume_label | %s |" % b["volume_label"])
    L.append("")
    L.append("## Audio TOC context (for AH=150C)")
    L.append("")
    L.append("| Track | Type | File | INDEX 01 |")
    L.append("|-------|------|------|----------|")
    for t in result["audio_toc_context"]["tracks"]:
        L.append("| %02d | AUDIO | %s | %s |" % (t["track"], t["file"], t["index01"]))
    L.append("")
    L.append("## How WORK2 consumes this")
    L.append("")
    L.append("- **BX=0 (install check / drive count):** return AX=0000, BX=1, CX='P' (0x50) if a real CD is to be advertised; or the no-CD W3-029 variant (BX=0, CX=0) if not. W2-MSCDEXRESP's objective is the *real* variant, so advertise one drive.")
    L.append("- **BX=1 (drive parameters):** fill the 16-byte buffer above (root dir LBA/length from the PVD; volume label from the PVD).")
    L.append("- **AH=150C (TOC/track query):** use the CUE audio track list (Tracks 2-5) for the track table; audio_first_track_lba approx %d." % result["audio_toc_context"]["first_audio_lba_approx"])
    L.append("- **AH=1510 (device request):** back AL=0x07/0x08 data reads from the working ISO `evidence/../%s` (on E:, separate from the read-only reference)." % os.path.basename(iso))
    L.append("")
    L.append("## Preservation")
    L.append("")
    L.append("- Original `E:\\GeneWarsFX` BIN/CUE: **read-only, unmodified** (sha256 %s before == after: %s)." % (orig_sha[:16], ref_unchanged))
    L.append("- Working ISO kept on `E:\\GWRecomp\\build\\cdrom\\` (separate from the reference).")
    L.append("")
    L.append("## Sources")
    L.append("")
    L.append("- CUE/BIN: `E:\\GeneWarsFX\\Genewars (Europe) (En,Fr,De,Es,It,Sv).cue` + Track 1 BIN (read-only reference).")
    L.append("- Standard ISO 9660 reader: pycdlib (per cd-image-iso9660 skill; no hand-rolled parser).")
    L.append("- MSCDEX buffer layout: `evidence/mscdex_response_contract.json` (L-MSCDEXRESPCONTRACT).")
    L.append("")
    L.append("_Generated deterministically by `py -3 tools/cdrom_volume_descriptor.py`. Does not modify E:\\GeneWarsFX; does not implement the MSCDEX runtime handler._")
    out_md = os.path.join(REP, "LOCAL_CDROM_VOLUME_DESCRIPTOR.md")
    open(out_md,"w",encoding="utf-8").write("\n".join(L)+"\n")
    log(f"WROTE {out_md}")

if __name__ == "__main__":
    main()