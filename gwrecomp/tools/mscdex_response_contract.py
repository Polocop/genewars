#!/usr/bin/env python3
"""L-MSCDEXRESPCONTRACT: machine-readable MSCDEX AH=15xx response contract.

Produces the exact input/output register + buffer-layout semantics that WORK2
consumes to implement the real-mode INT 2Fh (vector 47) handler for
W2-MSCDEXRESP, plus the no-CD-vs-real-CD decision proven by the W3-029 oracle
trace. Deterministic: no timestamps in output, sorted keys, stable sha256.

Sources (all read-only):
  - evidence/dpmi_0300_frame_work2.json   (WORK2: oracle frame at blocker 0x1d23a7)
  - evidence/startup_after_mscdex_work3.json (WORK3 W3-029: no-CD pass + next frontier)
  - evidence/mscdex_inventory.json         (L-MSCDEXINV static+dynamic inventory)
  - Public MSCDEX API: makbit ms-cd002, RBIL INT 2Fh, DOSBox-X dos_mscdex.cpp

Outputs:
  - evidence/mscdex_response_contract.json
  - reports/LOCAL_MSCDEX_RESPONSE_CONTRACT.md

This task does NOT implement the runtime handler (that is W2-MSCDEXRESP/WORK2)
and does NOT touch E:/GeneWarsFX (read-only reference only).
"""
import json, hashlib, os, re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EV = os.path.join(ROOT, "evidence")
REP = os.path.join(ROOT, "reports")

FRAME_W2 = os.path.join(EV, "dpmi_0300_frame_work2.json")
STARTUP_W3 = os.path.join(EV, "startup_after_mscdex_work3.json")
INV = os.path.join(EV, "mscdex_inventory.json")

def load(p):
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)

def h(x):
    """Parse a hex string/int to int."""
    if isinstance(x, int):
        return x
    if isinstance(x, str):
        return int(x, 16)
    return int(x)

# ---------------------------------------------------------------------------
# 1. Extract authoritative oracle facts
# ---------------------------------------------------------------------------

def extract_blocker_frame(path):
    """The DPMI AX=0300 -> INT 2Fh AH=1500 request at the current gate."""
    d = load(path)
    rm = d.get("real_mode_0300", [])
    # The MSCDEX request is the one with real_mode_vector==47 (INT 2Fh).
    for entry in rm:
        if entry.get("real_mode_vector") == 47:
            fr = entry.get("frame", {})
            reg = fr.get("registers", {})
            host = entry.get("host_registers", {})
            return {
                "real_mode_vector": 47,
                "vector_name": "INT 2Fh (MSCDEX/CD-ROM)",
                "interrupt_eip": entry.get("interrupt_eip"),
                "frame_linear": fr.get("linear"),
                "frame_selector": fr.get("selector"),
                "frame_registers": {k: reg.get(k, 0) for k in
                    ("eax","ebx","ecx","edx","esi","edi","ebp","esp","cs","ds","es","ss")},
                "host_eip": host.get("eip"),
                "host_ebx_vector": host.get("ebx"),
                "host_edx_frame_size": host.get("edx"),
                "ah": (reg.get("eax", 0) >> 8) & 0xFFFF,
                "al": reg.get("eax", 0) & 0xFF,
            }
    return None

def extract_w3029(path):
    """W3-029: the no-CD pass through AH=1500 and the next frontier."""
    d = load(path)
    return {
        "task": d.get("task"),
        "cdrom_inventory": d.get("cdrom_inventory"),
        "mscdes_installation_status": d.get("mscdes_installation_status"),
        "cd_dependency": d.get("cd_dependency"),
        "int2f_services": d.get("int2f_services"),
        "observed_post_return_branch": d.get("observed_post_return_branch"),
        "first_ax0501": d.get("first_ax0501"),
        "later_frontier": d.get("later_frontier"),
        "staged_reference_root": d.get("staged_reference_root"),
        "reference_config_absent": d.get("reference_config_absent"),
        "fixture_matches_gate": d.get("fixture_matches_gate"),
        "stop_reason": d.get("stop_reason"),
    }

def extract_inventory(path):
    if not os.path.exists(path):
        return {"distinct_subfunctions": [], "blocker": "0x1500"}
    d = load(path)
    sf = d.get("static", {}).get("distinct_subfunctions") or d.get("distinct_subfunctions") or []
    return {
        "distinct_subfunctions": sf,
        "blocker": "0x1500",
        "later_phase": sorted({s for s in sf if s != "0x1500"}),
    }

# ---------------------------------------------------------------------------
# 2. MSCDEX AH=15xx API contract (grounded in public references + oracle)
# ---------------------------------------------------------------------------

def mscdex_contract():
    """Authoritative MSCDEX (INT 2Fh) AH subfunction semantics.

    Confidence notes:
      - AH=1500: FULLY grounded (oracle frame + W3-029 pass).
      - AH=150C/1510: standard MSCDEX device-request API; the game reaches them
        post-MENU (L-MSCDEXINV). Exact AL sub-codes the game uses at runtime are
        to be captured by WORK2 tracing once MENU is reached.
    """
    return {
        "ah_1500": {
            "name": "MSCDEX installation check / drive count (RBIL AH=1500)",
            "confidence": "GROUNDING:ORACLE+W3-029+RBIL",
            "reached_before_menu": True,
            "role_in_gate": "BLOCKER (sole MSCDEX dependency on the path to MENU)",
            "real_mode_call_form": {
                "note": "Game issues via DPMI AX=0300 -> real-mode INT 2Fh; real-mode frame below is what the game built at the gate.",
                "frame_eax": "0x1500",
                "frame_ebx": "0x0000",
                "frame_ecx": "0x0000",
                "frame_edx": "0x0000",
                "frame_esi": "0x0000",
                "frame_edi": "0x0000",
                "segment_selectors": "0x0014 (es/ds/ss)",
            },
            "input": {
                "ax": "0x1500",
                "bx": "Drive selector: 0x0000 = install-check/drive-count query (NO parameter buffer); 0x0001..N = 1-based drive number to query parameters for (ES:BX -> 16-byte param block).",
                "note": "At the gate the game used BX=0 (install-check / drive-count probe). The BX=0 form uses NO buffer, PVD, root LBA or volume label.",
            },
            "output": {
                "ax": "0x0000 = success (MSCDEX present); 0x00FF = error (MSCDEX not installed / drive invalid).",
                "bx_on_bx0": "Number of configured CD drive letters (0 = none). This is the only meaningful output for the gate's BX=0 call.",
                "cx_on_bx0": "First CD drive letter (ASCII, 0x41='A'); 0 if none.",
                "bx_on_bxn": "CD drive number (echo).",
                "cx_on_bxn": "CD drive type: 0=data, 1=audio, 2=mixed mode.",
                "dx_on_bxn": "0 = no root dir (data), 1 = root dir present.",
                "si_on_bxn": "Volume label length (0-31).",
                "di_on_bxn": "Root directory length code (1,2,4,8 -> 1,2,4,8 sectors).",
                "esbx_on_bxn": "Far pointer to 16-byte drive parameter buffer (ONLY for BX=n; NOT used by the gate's BX=0 call).",
            },
            "drive_parameter_buffer_16_bytes": [
                {"off": 0, "size": 1, "field": "drive_letter", "note": "ASCII, 0x41='A'"},
                {"off": 1, "size": 1, "field": "root_dir_length_code", "note": "01/02/04/08 = 1/2/4/8 sectors"},
                {"off": 2, "size": 2, "field": "root_dir_start_lba", "note": "starting LBA of root directory"},
                {"off": 4, "size": 2, "field": "audio_first_track_lba", "note": "0 for data; first audio track LBA for audio"},
                {"off": 6, "size": 2, "field": "mscdex_drive_number", "note": "MSCDEX internal drive number"},
                {"off": 8, "size": 1, "field": "volume_label_length", "note": "0-31"},
                {"off": 9, "size": 31, "field": "volume_label", "note": "volume label ASCII (0-31 chars)"},
            ],
            "buffer_note": "The 16-byte drive-parameter buffer above applies ONLY to the BX=n (drive-specific) form. The gate's actual call is BX=0, which returns BX=#drives and CX=first-letter with NO buffer, PVD, root LBA or volume label involved. Do NOT require a real drive-parameter buffer to pass the gate.",
            "responses": {
                "no_cd": {
                    "ax": "0x0000",
                    "bx": "0x0000 (zero drive letters)",
                    "cx": "0x0000",
                    "proven_by": "W3-029 (evidence/startup_after_mscdex_work3.json): cdrom_inventory=[], AH=1500 handled, post-return JNZ@0x001b955f (EAX=0,ZF=1) NOT taken -> CD-absent path -> continued into DPMI allocate_dos_memory(0100) + allocate_memory(0501).",
                    "unblocks_gate": True,
                },
                "cd_present": {
                    "ax": "0x0000",
                    "bx": "0x0001 (one drive)",
                    "cx": "0x50 (first letter 'P')",
                    "note": "Real-drive variant; not required to pass MENU, only needed once the game streams CD assets (post-MENU 1510 device requests).",
                    "unblocks_gate": True,
                },
            },
            "game_branch_after": {
                "eip": "0x001b955f",
                "bytes": "0x7525 (JNZ +0x25)",
                "eax_after_1500": "0x0000 (success)",
                "zf": True,
                "taken": False,
                "interpretation": "Game tests the AH=1500 result and takes the CD-absent fall-through when AX=0 with no drives; a no-CD (zero-drive) success response is sufficient to proceed toward MENU.",
            },
        },
        "ah_150c": {
            "name": "MSCDEX Get Version (RBIL AH=150C, BX=0)",
            "confidence": "RBIL + observed in W2-055/W3-038 traces (evidence returns BX=0x217 = 2.22 version); post-MENU, not on -k path",
            "reached_before_menu": False,
            "role_in_gate": "POST-MENU / not a MENU prerequisite. The -k entry path does NOT issue 150C (L-MSCDEXINV). Seen in the W2-055 probe trace after the install-check; the runtime already answers it (BX=0x0217).",
            "input": {
                "ax": "0x150C",
                "bx": "0x0000",
            },
            "output": {
                "ax": "0x0000 success (version returned in BX); 0x00FF if MSCDEX not installed.",
                "bx": "Version: high byte = major, low byte = minor (e.g. 0x0217 -> MSCDEX 2.17).",
            },
            "responses": {
                "no_cd": {"ax": "0x0000", "bx": "0x0217 (version); no-CD still reports the MSCDEX version present.", "note": "Version query is independent of drive presence."},
                "cd_present": {"ax": "0x0000", "bx": "0x0217", "note": "Same as no-CD; version does not depend on a drive."},
            },
        },
        "ah_1510": {
            "name": "MSCDEX Send Device Driver Request (RBIL AH=1510)",
            "confidence": "GROUNDING:W2-055 (evidence/mscdex_ioctl_input_work2.json). GeneWars emits ONE real request: MSCDEX device command 3 (READ), packet_length=26, carrying a 10-byte SCSI CDB. No other commands were observed.",
            "reached_before_menu": False,
            "role_in_gate": "POST-MENU (CD data streaming); NOT required for MENU. The -k path reaches the AH=1500 install-check only; 1510 is issued later when the game reads CD assets.",
            "real_mode_call_form": {
                "note": "Game builds a real-mode frame at linear 0x002a4ea8 with es=0x2104 pointing at the MSCDEX request packet; AH=1510, CX=3 (device command), BX=0. The DPMI AX=0300 bridge forwards it to the real-mode INT 2Fh handler.",
                "frame_eax": "0x1510",
                "frame_ecx": "0x0003 (MSCDEX device command: 3 = READ)",
                "frame_ebx": "0x0000",
                "es": "0x2104 (segment of the 26-byte MSCDEX request packet)",
            },
            "input": {
                "ax": "0x1510",
                "cx": "MSCDEX device-request command number (GeneWars uses 3 = READ; see observed_commands).",
                "es_bx": "Far pointer (ES:BX) to the MSCDEX device request packet: [byte length=26][byte unit=0][byte command][word status][byte reserved x6][offset:word transfer][segment:word transfer][CDB ...].",
            },
            "output": {
                "ax": "0x0000 success / 0x00FF error",
                "status_field": "Packet status word (offset 4) updated by MSCDEX: 0=success, 1=check, 2=error.",
                "transfer_buffer": "Device data written to the transfer buffer pointed by the packet (GeneWars: 7-byte buffer, linear 0x00021070).",
            },
            "observed_requests": [
                {
                    "source": "evidence/mscdex_ioctl_input_work2.json (W2-055)",
                    "es": "0x2104",
                    "packet_length": 26,
                    "unit": 0,
                    "command": 3,
                    "command_name": "MSCDEX READ (10-byte SCSI CDB)",
                    "cdb_hex": "00 00 00 07 21 07 00 00 00 00",
                    "cdb_decode": "opcode=0x08 READ(10): LBA=0x07210000 (bytes 2..5), transfer length=0x0000 (bytes 6..9) -> READ(10) at LBA 0x072107 (47439); the CDB is GeneWars' actual on-wire bytes from the probe.",
                    "transfer_segment": "0x2107",
                    "transfer_length": 7,
                    "transfer_before_hex": "0a000000000000 / 0b01053c263b00 (two observed variants, subfunctions 10 and 11)",
                    "note": "This is the ONLY device-request GeneWars issued in the probe. Do NOT assume a generic MMC/SCSI command set; implement what the real code emits.",
                },
            ],
            "responses": {
                "no_cd": {"ax": "0x00FF", "status": "2 (error)", "note": "No CD drive -> device request fails; game falls back to no-CD path. W2-055 probe: command 3 subfunction 0b (audio disc info) was unimplemented and is the recorded first_unsupported."},
                "cd_present": {"ax": "0x0000", "status": "0 (success)", "note": "Backed by the staged CD image / ISO; the 10-byte READ(10) CDB reads 2048-byte sectors from the image. Audio subfunctions (0a/0b) may be synthesized or no-op."},
            },
            "correction_2026_10": "Earlier contract versions listed a speculative 16-entry AL command table (0x00-0x10) as if GeneWars used them. That was wrong: GeneWars issues MSCDEX device requests through AH=1510 with CX = the MSCDEX command number (observed value 3 = READ), NOT through AL sub-codes. Only the command(s) actually emitted by the real code are in observed_requests.",
        },
        "not_reached_by_game": [],
        "excluded_note": "Only the AHs GeneWars 1.1 actually emits (0x1500, 0x150C, 0x1510) are part of the handler contract. The previously-listed 0x1501-0x150B / 0x150D-0x150F are NOT real MSCDEX AH codes and were wrongly enumerated; they are removed from the contract. 0x1501/0x1502/0x1503/0x1507/0x1511 etc. are MSCDEX *device-request command* numbers (sent via AH=1510 in CX), not INT 2Fh AH values.",
    }

# ---------------------------------------------------------------------------
# 3. Assemble + write (deterministic)
# ---------------------------------------------------------------------------

def build_result():
    frame = extract_blocker_frame(FRAME_W2)
    w3 = extract_w3029(STARTUP_W3)
    inv = extract_inventory(INV)
    api = mscdex_contract()

    contract = {
        "schema": "mscdex_response_contract/v1",
        "generated_by": "tools/mscdex_response_contract.py (L-MSCDEXRESPCONTRACT, LOCAL)",
        "deterministic": True,
        "target": "GeneWars 1.1 genewars-1_1.exe via E:\\GWRecomp build runtime",
        "oracle_sources": {
            "blocker_frame": "evidence/dpmi_0300_frame_work2.json (WORK2)",
            "no_cd_pass_and_next_frontier": "evidence/startup_after_mscdex_work3.json (WORK3 W3-029)",
            "static_dynamic_inventory": "evidence/mscdex_inventory.json (L-MSCDEXINV)",
        },
        "api_reference": [
            "makbit ms-cd002 (MSCDEX spec)",
            "Ralf Brown's Interrupt List, INT 2Fh (CD-ROM)",
            "DOSBox-X dos_mscdex.cpp (INT 2F AH=15xx handlers)",
        ],
        "blocker": {
            **(frame or {}),
            "ah": frame["ah"] if frame else 0x1500,
            "real_mode_call": "DPMI AX=0300 (ecx=0x300) -> real-mode INT 2Fh (ebx=47), frame size edx=0x34",
            "game_dispatch": "CRT DPMI _DoINTR_ real-mode bridge (not the game's 0xB8xxx MSCDEX subdispatcher)",
        },
        "distinct_subfunctions": {
            "blocker": "0x1500",
            "pre_implement_post_menu": sorted(inv.get("later_phase", [])) or ["0x150C", "0x1510"],
            "not_reached": api["not_reached_by_game"],
        },
        "contracts": {k: v for k, v in api.items()},
        "no_cd_vs_real_cd_decision": {
            "decision": "NO-CD (zero drive letters) AH=1500 response is SUFFICIENT to pass the MSCDEX gate toward MENU.",
            "evidence": w3.get("mscdes_installation_status"),
            "cd_dependency": w3.get("cd_dependency"),
            "w3029_task": w3.get("task"),
            "w3029_int2f_services": w3.get("int2f_services"),
            "w3029_post_return_branch": w3.get("observed_post_return_branch"),
            "w3029_cdrom_inventory": w3.get("cdrom_inventory"),
            "staged_reference_root": w3.get("staged_reference_root"),
            "reference_config_absent": w3.get("reference_config_absent"),
            "real_cd_needed_when": "Only post-MENU, when the game streams CD assets via AH=150C/1510 device requests. A real CD image/ISO then backs 1510 data reads; audio ops may be no-ops.",
        },
        "next_frontier_after_mscdex": {
            "observed_in": "W3-029 (evidence/startup_after_mscdex_work3.json)",
            "service": (w3.get("later_frontier") or {}).get("service"),
            "eip": (w3.get("later_frontier") or {}).get("eip"),
            "registers": (w3.get("later_frontier") or {}).get("registers"),
            "note": "After the no-CD AH=1500 response passes, W3-029 advanced to a DPMI AX=0501 (allocate_memory) request. This is a WORK2 runtime concern (DPMI service), surfaced here so it is not rediscovered. It is OUT OF SCOPE for this MSCDEX contract.",
        },
        "work2_handoff": {
            "task": "W2-MSCDEXRESP",
            "correction_2026_10": "The original W2-MSCDEXRESP was created under the false premise that AX=1500 needs 'real drive parameters' (a 16-byte buffer, PVD, root LBA, volume label). That is WRONG. AX=1500, BX=0 is an install-check that returns BX=#drives and CX=first-letter with NO buffer. A no-CD response (BX=0, CX=0) is sufficient to pass the gate toward MENU. Do NOT gate MENU on a real CD image or a drive-parameter buffer.",
            "must_implement": [
                "Real-mode INT 2Fh (vector 47) dispatch in the DPMI AX=0300 bridge.",
                "AH=1500, BX=0: return AX=0000, BX=0 (zero drives), CX=0. This no-CD response unblocks the gate toward MENU (W3-029).",
                "AH=1500, BX=n (if the game ever queries drive params): fill the 16-byte drive-parameter buffer at ES:BX. NOT required for MENU.",
                "AH=150C: return MSCDEX version in BX (e.g. 0x0217). Post-MENU; not a MENU prerequisite.",
                "AH=1510: dispatch the MSCDEX device request packet (ES:BX -> 26-byte packet, CX = device command number). Implement only the command(s) GeneWars actually emits (W2-055: command 3 = READ, 10-byte SCSI CDB). Do NOT implement a generic 16-command MMC/SCSI table.",
            ],
            "do_not": [
                "Do NOT require a real CD image or a drive-parameter buffer to pass MENU (no-CD 1500 response is sufficient per W3-029).",
                "Do NOT implement AH codes 0x1501-0x150B / 0x150D-0x150F: they are not real MSCDEX AH values and the game never issues them.",
                "Do NOT assume a generic MMC/SCSI command set for AH=1510. Implement only what W2-055 captured from the real code.",
                "Do NOT modify E:\\GeneWarsFX (read-only reference).",
            ],
        },
    }
    return contract

def main():
    os.makedirs(REP, exist_ok=True)
    os.makedirs(EV, exist_ok=True)
    c = build_result()
    # Deterministic serialization: sorted keys, fixed indent, no timestamps.
    js = json.dumps(c, indent=2, sort_keys=True, ensure_ascii=False)
    out_json = os.path.join(EV, "mscdex_response_contract.json")
    with open(out_json, "w", encoding="utf-8") as f:
        f.write(js + "\n")

    # Report
    frame = c["blocker"]
    L = []
    L.append("# LOCAL MSCDEX AH=15xx Response Contract (L-MSCDEXRESPCONTRACT)")
    L.append("")
    L.append("Machine-readable companion: `evidence/mscdex_response_contract.json` "
             "(deterministic; stable sha256 across re-runs).")
    L.append("Feeds WORK2's `W2-MSCDEXRESP` to implement the real-mode INT 2Fh (vector 47) handler.")
    L.append("")
    L.append("## The blocker (grounded in the WORK2 oracle frame)")
    L.append("")
    L.append("- Service: **DPMI AX=0300 -> real-mode INT 2Fh (MSCDEX), AH=1500** (installation check / drive count).")
    L.append("- Guest EIP at interrupt: `%s` (host EIP `%s`)." % (
        frame.get("interrupt_eip"), "0x%08x" % frame.get("host_eip", 0) if frame.get("host_eip") else "n/a"))
    L.append("- Real-mode vector: %s (ebx=%s); frame size edx=%s (0x%02x bytes); frame linear=%s selector=%s." % (
        frame.get("real_mode_vector"), frame.get("host_ebx_vector"),
        frame.get("host_edx_frame_size"), frame.get("host_edx_frame_size", 0),
        frame.get("frame_linear"), frame.get("frame_selector")))
    L.append("- Real-mode frame the game built: " + ", ".join(
        "%s=0x%04x" % (k, v) for k, v in sorted(frame.get("frame_registers", {}).items())))
    L.append("- The 0x1500 at the gate is issued by the CRT DPMI `_DoINTR_` real-mode bridge, NOT the game's 0xB8xxx MSCDEX subdispatcher (see L-MSCDEXINV: zero MSCDEX sites in the -k entry path).")
    L.append("")
    L.append("## Distinct MSCDEX subfunctions and phasing")
    L.append("")
    L.append("| AH | Name | Before MENU | Role |")
    L.append("|---|------|-------------|------|")
    L.append("| 0x1500 | Installation check / drive count (RBIL AH=1500) | **YES** | **Blocker** (sole MSCDEX dep to MENU); BX=0 no-CD response unblocks |")
    L.append("| 0x150C | Get MSCDEX version (RBIL AH=150C) | no | post-MENU; version query |")
    L.append("| 0x1510 | Send Device Driver Request (RBIL AH=1510) | no | post-MENU CD data streaming (W2-055: command 3 READ) |")
    L.append("")
    L.append("Only the AHs GeneWars 1.1 actually emits (0x1500, 0x150C, 0x1510) are in the handler contract. The previously-listed 0x1501-0x150B / 0x150D-0x150F were wrongly enumerated as AH codes; they are MSCDEX *device-request command* numbers (sent via AH=1510 in CX), not INT 2Fh AH values, and the game never issues them as AH.")
    L.append("")
    L.append("## NO-CD vs real-CD decision (the key question for WORK2)")
    L.append("")
    L.append("**Decision: a NO-CD (zero drive letters) AH=1500 response is sufficient to pass the MSCDEX gate toward MENU.**")
    L.append("")
    nd = c["no_cd_vs_real_cd_decision"]
    L.append("- W3-029 (`%s`) ran with `cdrom_inventory=%s` and `reference_config_absent=%s`." % (
        nd.get("w3029_task"), nd.get("w3029_cdrom_inventory"), nd.get("reference_config_absent")))
    L.append("- AH=1500 was handled; the game's post-return `JNZ` at `%s` (bytes `%s`, EAX=%s, ZF=%s) was **not taken** -> CD-absent fall-through." % (
        (nd.get("w3029_post_return_branch") or {}).get("eip"),
        (nd.get("w3029_post_return_branch") or {}).get("bytes"),
        hex((nd.get("w3029_post_return_branch") or {}).get("eax", 0)),
        (nd.get("w3029_post_return_branch") or {}).get("zf")))
    L.append("- Execution then continued into DPMI `allocate_dos_memory` (AX=0100) and `allocate_memory` (AX=0501, selector 0x3c).")
    L.append("- `cd_dependency`: %s" % nd.get("cd_dependency"))
    L.append("- A real CD image is needed only **post-MENU**, when the game streams assets via AH=150C/1510 device requests.")
    L.append("")
    L.append("## AH=1500 response the handler must return")
    L.append("")
    L.append("| Variant | AX | BX | CX | Note |")
    L.append("|---------|-----|-----|-----|------|")
    L.append("| no-CD (proven) | 0x0000 | 0x0000 | 0x0000 | zero drive letters; unblocks gate (W3-029) |")
    L.append("| CD present | 0x0000 | 0x0001 | 0x50 ('P') | one drive; not required for MENU |")
    L.append("| MSCDEX absent | 0x00FF | - | - | error; only if MSCDEX truly not resident |")
    L.append("")
    L.append("Drive parameter buffer (16 bytes) for BX=n queries:")
    L.append("")
    L.append("| Off | Size | Field |")
    L.append("|-----|------|-------|")
    for f_ in c["contracts"]["ah_1500"]["drive_parameter_buffer_16_bytes"]:
        L.append("| %d | %d | %s (%s) |" % (f_["off"], f_["size"], f_["field"], f_["note"]))
    L.append("")
    L.append("## AH=1510 device-request: what GeneWars actually emits (W2-055)")
    L.append("")
    L.append("GeneWars issues MSCDEX device requests through AH=1510 with CX = the MSCDEX device command number and ES:BX -> the request packet. W2-055 captured the real on-wire request; the contract implements ONLY that, not a speculative MMC/SCSI table.")
    L.append("")
    L.append("| Source | CX (cmd) | Packet | CDB | Transfer |")
    L.append("|--------|----------|--------|-----|----------|")
    for req in c["contracts"]["ah_1510"]["observed_requests"]:
        L.append("| %s | %d (%s) | len=%d unit=%d | %s | seg=%s len=%d |" % (
            req["source"].split("/")[-1], req["command"], req["command_name"],
            req["packet_length"], req["unit"], req["cdb_hex"],
            req["transfer_segment"], req["transfer_length"]))
    L.append("")
    L.append("No other device-request command was observed. Do NOT assume a generic MMC/SCSI command set; see W2-055 / W2-057 for the buffer IOCTL details.")
    L.append("")
    L.append("## Next frontier after MSCDEX (out of scope here, surfaced for WORK2)")
    L.append("")
    nf = c["next_frontier_after_mscdex"]
    L.append("- W3-029, after the no-CD AH=1500 pass, advanced to **%s** at EIP `%s`." % (
        nf.get("service"), nf.get("eip")))
    L.append("- This is a DPMI AX=0501 (allocate_memory) service -> WORK2 runtime. Not part of the MSCDEX handler; do not block MENU on a real CD for this.")
    L.append("")
    L.append("## WORK2 handoff (W2-MSCDEXRESP)")
    L.append("")
    for m in c["work2_handoff"]["must_implement"]:
        L.append("- Implement: " + m)
    for m in c["work2_handoff"]["do_not"]:
        L.append("- Do not: " + m)
    L.append("")
    L.append("## Sources")
    L.append("")
    for s in c["api_reference"]:
        L.append("- " + s)
    for k, v in c["oracle_sources"].items():
        L.append("- %s: %s" % (k, v))
    L.append("")
    L.append("_Generated deterministically by `py -3 tools/mscdex_response_contract.py`. Does not modify E:\\GeneWarsFX; does not implement the runtime handler._")

    out_md = os.path.join(REP, "LOCAL_MSCDEX_RESPONSE_CONTRACT.md")
    with open(out_md, "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")

    print("WROTE", out_json)
    print("WROTE", out_md)
    print("sha256:", hashlib.sha256(js.encode("utf-8")).hexdigest())
    print("distinct:", c["distinct_subfunctions"])
    print("next_frontier:", c["next_frontier_after_mscdex"].get("service"), c["next_frontier_after_mscdex"].get("eip"))

if __name__ == "__main__":
    main()