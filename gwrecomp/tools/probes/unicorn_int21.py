"""Synthetic INT 21h hook proof and bounded GeneWars LE-entry execution probe."""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import pathlib
import struct
import sys
import time
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "runtime"))
from guest_boot import prepare_guest, summary as boot_summary  # noqa: E402
from dos_services import CpuRegs, DosHost  # noqa: E402
from host_devices import DosClock  # noqa: E402
from dos_filesystem import DosFileSystem  # noqa: E402

from unicorn import (  # noqa: E402
    Uc, UcError, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_INTR, UC_HOOK_MEM_WRITE,
    UC_HOOK_MEM_INVALID, UC_HOOK_INSN, UC_PROT_ALL,
)
from unicorn.x86_const import (  # noqa: E402
    UC_X86_INS_IN, UC_X86_INS_OUT, UC_X86_REG_EAX, UC_X86_REG_EBX,
    UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EFLAGS, UC_X86_REG_EIP,
    UC_X86_REG_ESP, UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES,
    UC_X86_REG_SS, UC_X86_REG_FS, UC_X86_REG_GS, UC_X86_REG_GDTR, UC_X86_REG_LDTR,
    UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP,
)

PAGE = 0x1000
GDT_ADDRESS = 0x4000
LDT_ADDRESS = 0x8000
TRAMP_ADDRESS = 0x9000
SYNTH_ADDRESS = 0x10000
SYNTH_CODE = bytes.fromhex("b821000000cd21f4")  # mov eax,21h; int 21h; hlt


def regs_snapshot(uc):
    return {name: uc.reg_read(reg) for name, reg in (
        ("eax", UC_X86_REG_EAX), ("ebx", UC_X86_REG_EBX),
        ("ecx", UC_X86_REG_ECX), ("edx", UC_X86_REG_EDX),
        ("esp", UC_X86_REG_ESP), ("esi", UC_X86_REG_ESI),
        ("edi", UC_X86_REG_EDI), ("ebp", UC_X86_REG_EBP),
        ("eip", UC_X86_REG_EIP), ("eflags", UC_X86_REG_EFLAGS),
    )}


def memory_fault_context(uc, dos_host, access, address, size, value):
    segments = {
        "cs": uc.reg_read(UC_X86_REG_CS), "ds": uc.reg_read(UC_X86_REG_DS),
        "es": uc.reg_read(UC_X86_REG_ES), "ss": uc.reg_read(UC_X86_REG_SS),
        "fs": uc.reg_read(UC_X86_REG_FS), "gs": uc.reg_read(UC_X86_REG_GS),
    }
    known_bases = {}
    selector_map = getattr(dos_host, "selectors", {}) if dos_host is not None else {}
    for name, selector in segments.items():
        if selector in selector_map:
            known_bases[name] = f"0x{selector_map[selector]:08x}"
    eip = uc.reg_read(UC_X86_REG_EIP)
    try:
        instruction = bytes(uc.mem_read(eip, 15)).hex()
    except UcError:
        instruction = ""
    return {
        "access": int(access), "address": f"0x{address:08x}", "size": size,
        "value": value, "eip": f"0x{eip:08x}",
        "registers": {k: f"0x{v:08x}" for k, v in regs_snapshot(uc).items()},
        "segments": {k: f"0x{v:04x}" for k, v in segments.items()},
        "known_selector_bases": known_bases,
        "instruction_bytes": instruction,
    }


def hook_ports(uc, trace, dos_host=None):
    def on_in(uc, port, size, user_data):
        if dos_host is not None:
            value = dos_host.pit.read(port, size)
            if value is not None:
                trace.setdefault("port_io", []).append({"operation":"in","port":port,"size":size,"value":value})
                return value
        trace["unsupported_port"] = {"operation": "in", "port": port, "size": size,
                                     "eip": uc.reg_read(UC_X86_REG_EIP)}
        uc.emu_stop()
        return 0

    def on_out(uc, port, size, value, user_data):
        if dos_host is not None and dos_host.pit.write(port, value, size):
            trace.setdefault("port_io", []).append({"operation":"out","port":port,"size":size,"value":value,
                "control_word":dos_host.pit.control_word,"reload":list(dos_host.pit.reload)})
            return
        trace["unsupported_port"] = {"operation": "out", "port": port, "size": size,
                                     "value": value, "eip": uc.reg_read(UC_X86_REG_EIP)}
        uc.emu_stop()

    try:
        uc.hook_add(UC_HOOK_INSN, on_in, None, 1, 0, UC_X86_INS_IN)   # UC_HOOK_INSN
        uc.hook_add(UC_HOOK_INSN, on_out, None, 1, 0, UC_X86_INS_OUT)
        trace["port_hooks_installed"] = True
    except Exception as exc:
        trace["port_hooks_installed"] = False
        trace["port_hook_error"] = f"{type(exc).__name__}: {exc}"


def decode_real_mode_frame(raw: bytes) -> dict:
    if len(raw) < 0x32: raise ValueError("DPMI real-mode register image is truncated")
    dwords = ("edi", "esi", "ebp", "reserved", "ebx", "edx", "ecx", "eax")
    out = {name: struct.unpack_from("<I", raw, index*4)[0] for index,name in enumerate(dwords)}
    out["eflags"] = struct.unpack_from("<H",raw,0x20)[0]
    for name,offset in (("es",0x22),("ds",0x24),("fs",0x26),("gs",0x28),
                        ("ip",0x2a),("cs",0x2c),("sp",0x2e),("ss",0x30)):
        out[name] = struct.unpack_from("<H",raw,offset)[0]
    return out


def install_trace_hooks(uc, trace, instruction_limit: int, dos_host=None):
    count = {"value": 0}
    mapped_allocation_pages = set()
    trace.setdefault("guest_allocation_page_count", 0)
    trace.setdefault("guest_allocation_first_page", {})

    def on_intr(uc, intno, user_data):
        after = uc.reg_read(UC_X86_REG_EIP)
        regs = regs_snapshot(uc)
        item = {"vector": intno, "eip_after_instruction": f"0x{after:08x}",
                "eip_int_opcode_assumption": f"0x{(after - 2) & 0xffffffff:08x}",
                "es":f"0x{uc.reg_read(UC_X86_REG_ES):04x}",
                "ds":f"0x{uc.reg_read(UC_X86_REG_DS):04x}",
                "registers": {k: f"0x{v:08x}" for k, v in regs.items()}}
        trace.setdefault("interrupts", []).append(item)
        if intno == 0x31 and (regs["eax"] & 0xffff) == 0x0300 and dos_host is not None:
            es_selector = uc.reg_read(UC_X86_REG_ES)
            es_base = dos_host.selectors.get(es_selector)
            frame_address = None if es_base is None else es_base + regs["edi"]
            if frame_address is not None:
                try:
                    raw_frame=bytes(uc.mem_read(frame_address,0x32))
                    item["real_mode_frame"]={"linear":f"0x{frame_address:08x}","bytes":raw_frame.hex(),"registers":decode_real_mode_frame(raw_frame)}
                except UcError: item["real_mode_frame"]={"linear":f"0x{frame_address:08x}","error":"unmapped"}
        if intno == 0x31 and (regs["eax"] & 0xffff) == 0x0300 and dos_host is not None:
            vector = regs["ebx"] & 0xff
            bh = (regs["ebx"] >> 8) & 0xff
            words = regs["ecx"] & 0xffff
            es_selector = uc.reg_read(UC_X86_REG_ES)
            es_base = dos_host.selectors.get(es_selector)
            frame_address = None if es_base is None else es_base + regs["edi"]
            item["service"] = "dpmi31.simulate_real_mode_interrupt"
            item["real_mode_interrupt"] = {"vector":vector,"bh":bh,"stack_words":words,
                                            "frame_linear":None if frame_address is None else f"0x{frame_address:08x}"}
            if vector not in (0x21, 0x2f) or bh != 0 or words != 0 or frame_address is None:
                trace["unsupported_service"] = {"vector":0x31,"function":0x0300,
                    "eip":f"0x{(after-2)&0xffffffff:08x}","reason":"real-mode interrupt parameters/vector are not implemented"}
                item["handled"] = False
                uc.emu_stop()
                return
            try:
                raw=bytearray(uc.mem_read(frame_address,0x32))
                rm=decode_real_mode_frame(bytes(raw))
            except (UcError,ValueError) as exc:
                trace["unsupported_service"]={"vector":0x31,"function":0x0300,
                    "eip":f"0x{(after-2)&0xffffffff:08x}","reason":f"invalid real-mode register frame: {exc}"}
                item["handled"] = False
                uc.emu_stop()
                return
            item["real_mode_interrupt"]["registers_before"]={k:f"0x{v:08x}" for k,v in rm.items()}
            if rm["ss"] != 0 or rm["sp"] != 0:
                trace["unsupported_service"]={"vector":0x31,"function":0x0300,
                    "eip":f"0x{(after-2)&0xffffffff:08x}","reason":"caller-specified real-mode stack is not modeled"}
                item["handled"] = False
                uc.emu_stop()
                return
            real_regs=CpuRegs(eax=rm["eax"],ebx=rm["ebx"],ecx=rm["ecx"],edx=rm["edx"],
                esi=rm["esi"],edi=rm["edi"],ebp=rm["ebp"],eflags=rm["eflags"],
                es=rm["es"],ds=rm["ds"],fs=rm["fs"],gs=rm["gs"],eip=(rm["cs"]<<16)|rm["ip"],esp=0)
            device_request_address=device_transfer_address=None
            device_transfer_length=0
            device_request=device_transfer=None
            if vector==0x2f and real_regs.ax==0x1510:
                packet_linear=((real_regs.es&0xffff)<<4)+(real_regs.bx&0xffff)
                try:
                    packet_length=uc.mem_read(packet_linear,1)[0]
                    if 13 <= packet_length <= 64:
                        device_request=bytes(uc.mem_read(packet_linear,packet_length))
                        device_request_address=packet_linear
                        if packet_length >= 20 and device_request[2] in (0x03, 0x0c, 0x80, 0x82):
                            transfer_offset=struct.unpack_from("<H",device_request,0x0e)[0]
                            transfer_segment=struct.unpack_from("<H",device_request,0x10)[0]
                            device_transfer_address=(transfer_segment<<4)+transfer_offset
                            declared=struct.unpack_from("<H",device_request,0x12)[0]
                            if device_request[2] == 0x03:
                                device_transfer_length=declared
                            elif device_request[2] in (0x80,0x82):
                                sector_size=2352 if device_request[0x18] == 1 else 2048
                                device_transfer_length=declared*sector_size
                            else:
                                device_transfer_length=declared
                            if device_transfer_length <= 4*1024*1024:
                                device_transfer=bytes(uc.mem_read(device_transfer_address,min(device_transfer_length,32)))
                        item["real_mode_interrupt"]["device_request"]={
                            "packet_linear":f"0x{packet_linear:08x}","packet_length":packet_length,
                            "command":device_request[2],"status_before":struct.unpack_from("<H",device_request,3)[0],
                            "transfer_linear":None if device_transfer_address is None else f"0x{device_transfer_address:08x}",
                            "transfer_length":device_transfer_length,
                            "transfer_before_hex":None if device_transfer is None else device_transfer.hex()}
                    else:
                        item["real_mode_interrupt"]["device_request"]={"packet_linear":f"0x{packet_linear:08x}",
                            "error":f"unsupported request header length {packet_length}"}
                except UcError as exc:
                    item["real_mode_interrupt"]["device_request"]={"packet_linear":f"0x{packet_linear:08x}",
                        "error":str(exc)}
            inner=dos_host.dispatch(vector,real_regs,eip=(after-2)&0xffffffff,
                device_request_address=device_request_address,device_request=device_request,
                device_transfer_address=device_transfer_address,device_transfer=device_transfer)
            item["real_mode_interrupt"]["service"]=inner.service
            if not inner.handled:
                trace["unsupported_service"]={"vector":vector,"function":real_regs.ah,
                    "eip":f"0x{(after-2)&0xffffffff:08x}","reason":inner.trap.reason if inner.trap else "unhandled"}
                item["handled"] = False
                uc.emu_stop()
                return
            if inner.guest_writes:
                try:
                    item["guest_writes"]=[]
                    for write_address,payload in inner.guest_writes:
                        uc.mem_write(write_address,payload)
                        item["guest_writes"].append({"address":f"0x{write_address:08x}",
                            "size":len(payload),"data_hex":payload.hex()})
                except UcError as exc:
                    trace["unsupported_memory"]={"access":"write","address":f"0x{write_address:08x}",
                        "size":len(payload),"eip":f"0x{(after-2)&0xffffffff:08x}","reason":str(exc)}
                    item["handled"]=False
                    uc.emu_stop()
                    return
            for name,offset in (("edi",0x00),("esi",0x04),("ebp",0x08),("ebx",0x10),
                                ("edx",0x14),("ecx",0x18),("eax",0x1c)):
                struct.pack_into("<I",raw,offset,getattr(real_regs,name))
            struct.pack_into("<H",raw,0x20,real_regs.eflags&0xffff)
            for name,offset in (("es",0x22),("ds",0x24),("fs",0x26),("gs",0x28)):
                struct.pack_into("<H",raw,offset,getattr(real_regs,name)&0xffff)
            uc.mem_write(frame_address,bytes(raw))
            uc.reg_write(UC_X86_REG_EFLAGS,uc.reg_read(UC_X86_REG_EFLAGS)&~1)
            item["real_mode_interrupt"]["registers_after"]={k:f"0x{v:08x}" for k,v in decode_real_mode_frame(bytes(raw)).items()}
            item["registers_after"]={k:f"0x{v:08x}" for k,v in regs_snapshot(uc).items()}
            item["handled"] = True
            return
        if intno < 0x20:
            fault_eip = uc.reg_read(UC_X86_REG_EIP)
            try: fault_bytes = bytes(uc.mem_read(fault_eip, 8)).hex()
            except UcError: fault_bytes = ""
            try: selector_value = struct.unpack("<H", bytes(uc.mem_read(0x0020B795, 2)))[0]
            except UcError: selector_value = None
            trace["guest_exception"] = {"vector":intno,"eip":f"0x{fault_eip:08x}",
                "exception_callback_eip":f"0x{after:08x}","fault_bytes":fault_bytes,
                "selector_source_va":"0x0020b795","selector_value":selector_value,
                "registers":item["registers"],"kind":"cpu_exception"}
            uc.emu_stop()
            return
        if dos_host is not None:
            names = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip", "eflags")
            mapped = {"eax":UC_X86_REG_EAX,"ebx":UC_X86_REG_EBX,"ecx":UC_X86_REG_ECX,"edx":UC_X86_REG_EDX,
                      "esi":UC_X86_REG_ESI,
                      "edi":UC_X86_REG_EDI,
                      "ebp":UC_X86_REG_EBP,
                      "esp":UC_X86_REG_ESP,"eip":UC_X86_REG_EIP,"eflags":UC_X86_REG_EFLAGS}
            ds_selector = uc.reg_read(UC_X86_REG_DS)
            service_regs = CpuRegs(**{n: uc.reg_read(mapped[n]) for n in names},
                es=uc.reg_read(UC_X86_REG_ES), ds=ds_selector,
                fs=uc.reg_read(UC_X86_REG_FS), gs=uc.reg_read(UC_X86_REG_GS))
            filename = None
            write_data = None
            if intno == 0x21 and service_regs.ah in (0x3c, 0x3d, 0x40, 0x43):
                base = dos_host.selectors.get(ds_selector)
                pointer = None if base is None else base + service_regs.edx
                capture = {"selector":f"0x{ds_selector:04x}", "offset":f"0x{service_regs.edx:08x}",
                           "linear":None if pointer is None else f"0x{pointer:08x}",
                           "function":service_regs.ah, "access_mode":service_regs.al, "attributes":service_regs.cx}
                if pointer is not None:
                    try:
                        raw_name = bytearray()
                        limit = service_regs.cx if service_regs.ah == 0x40 else 260
                        for offset in range(limit):
                            char = bytes(uc.mem_read(pointer + offset, 1))
                            if char == b"\0":
                                break
                            raw_name.extend(char)
                        else:
                            if service_regs.ah != 0x40:
                                raise ValueError("DOS path exceeds 259 bytes without NUL terminator")
                        capture["bytes"] = raw_name.hex()
                        if service_regs.ah == 0x40:
                            capture["requested_bytes"] = service_regs.cx
                            capture["data_hex"] = raw_name.hex()
                            write_data = bytes(raw_name)
                        else:
                            capture["path"] = raw_name.decode("cp437")
                            filename = capture["path"]
                    except (UcError, ValueError) as exc:
                        capture["error"] = str(exc)
                else:
                    capture["error"] = "DS selector has no modeled base"
                item["dos_filename"] = capture
            read_buffer_address = None
            if intno == 0x21 and service_regs.ah == 0x3f:
                base = dos_host.selectors.get(ds_selector)
                pointer = None if base is None or base > 0xffffffff - service_regs.edx else base + service_regs.edx
                capture = {"selector":f"0x{ds_selector:04x}", "offset":f"0x{service_regs.edx:08x}",
                           "linear":None if pointer is None else f"0x{pointer:08x}",
                           "requested_bytes":service_regs.cx}
                if pointer is None:
                    trace["unsupported_service"] = {"vector":0x21,"function":0x3f,
                        "eip":f"0x{(after-2)&0xffffffff:08x}","reason":"DS selector has no modeled non-overflowing base"}
                    item["dos_read_buffer"] = capture
                    uc.emu_stop()
                    return
                try:
                    if service_regs.cx:
                        bytes(uc.mem_read(pointer, service_regs.cx))
                    read_buffer_address = pointer
                except UcError as exc:
                    capture["error"] = str(exc)
                    item["dos_read_buffer"] = capture
                    trace["unsupported_memory"] = {"access":"write", "address":f"0x{pointer:08x}",
                        "size":service_regs.cx,"eip":f"0x{(after-2)&0xffffffff:08x}","reason":"DOS AH=3F destination is unmapped"}
                    uc.emu_stop()
                    return
                item["dos_read_buffer"] = capture
            allocations_before = set(dos_host.allocations)
            released_ah48_selector = None
            released_ah48_real_segment = None
            if intno == 0x21 and service_regs.ah == 0x49:
                released_ah48_selector = service_regs.es
                released_ah48_real_segment = dos_host.dos4gw_segment_for_ah48_selector(released_ah48_selector)
                if released_ah48_real_segment is not None:
                    service_regs.es = released_ah48_real_segment
            result = dos_host.dispatch(intno, service_regs, eip=(after-2)&0xffffffff, filename=filename,
                write_data=write_data, read_buffer_address=read_buffer_address)
            if result.handled and intno == 0x21 and result.service == "dos21.allocate_memory":
                real_segment = service_regs.ax
                selector = dos_host.dos4gw_alias_ah48_segment(real_segment)
                if selector is None:
                    dos_host._free_dos_ah48_block(real_segment)
                    service_regs.ax = 8
                    service_regs.bx = max(dos_host.dos_free_blocks.values(), default=0)
                    service_regs.carry = True
                    item["dos4gw_pointer_translation_error"] = "no free protected-mode selector for DOS AH=48 block"
                else:
                    install_dos_selector(uc, dos_host, selector)
                    service_regs.eax = selector
                    alias_event={"real_segment":real_segment,"selector":selector,
                        "base":dos_host.selectors[selector],"limit":dos_host.selector_limits[selector]}
                    trace.setdefault("dos4gw_segment_aliases", []).append(alias_event)
                    item["dos4gw_pointer_alias"]=alias_event
            if (result.handled and intno == 0x21 and result.service == "dos21.free_memory"
                    and released_ah48_real_segment is not None):
                dos_host.dos4gw_release_ah48_selector(released_ah48_selector)
                uc.mem_write(LDT_ADDRESS + (released_ah48_selector >> 3) * 8, bytes(8))
            for handle in set(dos_host.allocations) - allocations_before:
                base, size = dos_host.allocations[handle]
                trace.setdefault("guest_allocations", []).append({"handle":handle,"base":f"0x{base:08x}","size":size,
                    "mapping":"on_first_access"})
            if result.handled and result.service == "dpmi31.allocate_dos_memory":
                selector = service_regs.dx
                base, limit = install_dos_selector(uc, dos_host, selector)
                trace.setdefault("guest_dos_allocations", []).append({"selector":selector,"base":base,"limit":limit})
            elif result.handled and result.service.startswith("dpmi31.resize_dos_memory.") and "invalid_" not in result.service and "insufficient" not in result.service:
                install_dos_selector(uc, dos_host, service_regs.dx)
            elif result.handled and result.service == "dpmi31.free_dos_memory":
                uc.mem_write(LDT_ADDRESS + (service_regs.dx >> 3) * 8, bytes(8))
            item["service"] = result.service
            item["handled"] = result.handled
            if result.handled and result.service == "dos21.terminate_process":
                trace["process_exit"] = {"code":service_regs.al,
                    "eip":f"0x{(after-2)&0xffffffff:08x}",
                    "registers":service_regs.snapshot()}
                item["process_terminated"] = True
                uc.emu_stop()
                return
            if result.handled:
                if result.guest_writes:
                    try:
                        item["guest_writes"]=[]
                        for address, payload in result.guest_writes:
                            uc.mem_write(address, payload)
                            item["guest_writes"].append({"address":f"0x{address:08x}",
                                                          "size":len(payload),"data_hex":payload.hex()})
                    except UcError as exc:
                        trace["unsupported_memory"] = {"access":"write", "address":f"0x{address:08x}",
                            "size":len(payload),"eip":f"0x{(after-2)&0xffffffff:08x}","reason":str(exc)}
                        uc.emu_stop()
                        return
                for n in names: uc.reg_write(mapped[n], getattr(service_regs,n))
                item["registers_after"] = {k:f"0x{v:08x}" for k,v in regs_snapshot(uc).items()}
                return
            trace["unsupported_service"] = {"vector":intno,"function":service_regs.ah if intno==0x21 else service_regs.ax,
                "eip":f"0x{(after-2)&0xffffffff:08x}","registers":service_regs.snapshot(),
                "reason":result.trap.reason if result.trap else "unhandled"}
        uc.emu_stop()

    def on_code(uc, address, size, user_data):
        count["value"] += 1
        if dos_host is not None:
            dos_host.pit.advance()
        trace["last_guest_eip"] = f"0x{address:08x}"
        if len(trace.setdefault("instructions", [])) < 128:
            try:
                raw = bytes(uc.mem_read(address, size)).hex()
            except UcError:
                raw = ""
            trace["instructions"].append({"eip": f"0x{address:08x}", "cs": f"0x{uc.reg_read(UC_X86_REG_CS):04x}", "ds":f"0x{uc.reg_read(UC_X86_REG_DS):04x}", "es":f"0x{uc.reg_read(UC_X86_REG_ES):04x}", "ss":f"0x{uc.reg_read(UC_X86_REG_SS):04x}", "eax":f"0x{uc.reg_read(UC_X86_REG_EAX):08x}","ebx":f"0x{uc.reg_read(UC_X86_REG_EBX):08x}","ecx":f"0x{uc.reg_read(UC_X86_REG_ECX):08x}","edx":f"0x{uc.reg_read(UC_X86_REG_EDX):08x}","esi":f"0x{uc.reg_read(UC_X86_REG_ESI):08x}","edi":f"0x{uc.reg_read(UC_X86_REG_EDI):08x}","size": size, "bytes": raw})
        if count["value"] >= instruction_limit:
            trace["stop_reason"] = "instruction_limit"
            uc.emu_stop()

    def on_invalid(uc, access, address, size, value, user_data):
        if dos_host is not None and size > 0:
            access_end = address + size
            for handle, (alloc_base, alloc_size) in dos_host.allocations.items():
                alloc_end = alloc_base + alloc_size
                if alloc_base <= address and access_end <= alloc_end:
                    first_page = address & ~(PAGE - 1)
                    last_page = (access_end - 1) & ~(PAGE - 1)
                    try:
                        for page_address in range(first_page, last_page + PAGE, PAGE):
                            if page_address < alloc_base or page_address >= alloc_end or page_address in mapped_allocation_pages:
                                continue
                            payload_size = min(PAGE, alloc_end - page_address)
                            payload = dos_host.boot.memory.read(page_address, payload_size)
                            uc.mem_map(page_address, PAGE, UC_PROT_ALL)
                            uc.mem_write(page_address, payload + bytes(PAGE - payload_size))
                            mapped_allocation_pages.add(page_address)
                            trace["guest_allocation_page_count"] = len(mapped_allocation_pages)
                            trace["guest_allocation_first_page"].setdefault(str(handle), f"0x{page_address:08x}")
                        return True
                    except (UcError, ValueError):
                        break
        trace["unsupported_memory"] = memory_fault_context(uc, dos_host, access, address, size, value)
        uc.emu_stop()
        return False

    uc.hook_add(UC_HOOK_INTR, on_intr)
    uc.hook_add(UC_HOOK_CODE, on_code)
    if dos_host is not None:
        def on_write(uc, access, address, size, value, user_data):
            for handle, (base, length) in dos_host.allocations.items():
                if base <= address and address + size <= base + length:
                    payload = int(value).to_bytes(size, "little", signed=False)
                    dos_host.boot.memory.write(address, payload)
                    trace["guest_allocation_write_count"] = trace.get("guest_allocation_write_count", 0) + 1
                    writes = trace.setdefault("guest_allocation_writes", [])
                    if len(writes) < 64:
                        writes.append({"handle":handle,"address":f"0x{address:08x}","size":size,"bytes":payload.hex()})
                    break
        uc.hook_add(UC_HOOK_MEM_WRITE, on_write)

    uc.hook_add(UC_HOOK_MEM_INVALID, on_invalid)
    hook_ports(uc, trace, dos_host)
    return count


def synthetic_probe() -> dict:
    trace = {"kind": "synthetic", "stop_reason": None, "interrupts": []}
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(SYNTH_ADDRESS, PAGE, UC_PROT_ALL)
    uc.mem_write(SYNTH_ADDRESS, SYNTH_CODE)
    uc.reg_write(UC_X86_REG_ESP, SYNTH_ADDRESS + PAGE - 0x10)
    install_trace_hooks(uc, trace, 100)
    try:
        uc.emu_start(SYNTH_ADDRESS, SYNTH_ADDRESS + len(SYNTH_CODE), timeout=1_000_000, count=100)
        trace["stop_reason"] = trace.get("stop_reason") or "emulation_returned"
    except UcError as exc:
        trace["stop_reason"] = "backend_error"
        trace["backend_error"] = f"{type(exc).__name__}: {exc}"
    trace["final_registers"] = {k: f"0x{v:08x}" for k, v in regs_snapshot(uc).items()}
    trace["pass"] = bool(trace["interrupts"] and trace["interrupts"][0]["vector"] == 0x21
                         and trace["interrupts"][0]["registers"]["eax"] == "0x00000021")
    return trace


def encode_descriptor(base, limit, access, flags):
    return ((limit & 0xffff) | ((base & 0xffff) << 16)
            | (((base >> 16) & 0xff) << 32) | (access << 40)
            | (((limit >> 16) & 0xf) << 48) | (flags << 52)
            | (((base >> 24) & 0xff) << 56))


def install_dos_selector(uc, dos_host, selector):
    if selector not in dos_host.selectors:
        raise ValueError(f"unknown DOS selector 0x{selector:04x}")
    base = dos_host.selectors[selector]
    limit = dos_host.selector_limits[selector]
    flags = 0xC if limit > 0xfffff else 0x4
    descriptor = encode_descriptor(base, limit, 0x92, flags)
    uc.mem_write(LDT_ADDRESS + (selector >> 3) * 8, struct.pack("<Q", descriptor))
    return base, limit


def write_flat_gdt(uc, trace, psp_base=0, environment_base=None):
    # The project's selectors 0x0c/0x14 have TI=1: both refer to an LDT.
    # Provide a minimal GDT with one LDT system descriptor and a flat LDT.
    ldt_address = LDT_ADDRESS
    ldt = bytearray(0x1000)
    for index, desc in ((1, encode_descriptor(0, 0xffffffff, 0x9a, 0xc)),
                        (2, encode_descriptor(0, 0xffffffff, 0x92, 0xc)),
                        (3, encode_descriptor(psp_base, 0xffff, 0x92, 0x4))):
        struct.pack_into("<Q", ldt, index * 8, desc)
    if environment_base is None:
        gdt = bytearray(struct.pack("<QQ", 0, encode_descriptor(ldt_address, len(ldt) - 1, 0x82, 0)))
    else:
        gdt = bytearray(0x221 * 8)
        struct.pack_into("<Q", gdt, 8, encode_descriptor(ldt_address, len(ldt) - 1, 0x82, 0))
        struct.pack_into("<Q", gdt, 0x1100 // 8 * 8, encode_descriptor(environment_base, 0xffff, 0x92, 0x4))
    uc.mem_write(ldt_address, bytes(ldt))
    uc.mem_write(GDT_ADDRESS, bytes(gdt))
    try:
        uc.reg_write(UC_X86_REG_GDTR, (0, GDT_ADDRESS, len(gdt) - 1, 0))
        # Unicorn's MMR write requires the cached LDTR base/limit explicitly.
        uc.reg_write(UC_X86_REG_LDTR, (0x08, ldt_address, len(ldt) - 1, 0))
        for reg in (UC_X86_REG_DS, UC_X86_REG_SS):
            uc.reg_write(reg, 0x14)
        uc.reg_write(UC_X86_REG_ES, 0x1c)
        uc.reg_write(UC_X86_REG_FS, 0)
        uc.reg_write(UC_X86_REG_GS, 0)
        trace["gdt_setup"] = "ok"
        trace["ldt_setup"] = {"selector": "0x0008", "base": f"0x{ldt_address:08x}",
                              "limit": len(ldt) - 1}
        trace["cs_selector"] = f"0x{uc.reg_read(UC_X86_REG_CS):04x} (Unicorn default; CS write unsupported by this probe)"
        return True
    except Exception as exc:
        trace["gdt_setup"] = f"{type(exc).__name__}: {exc}"
        return False


def target_probe(instruction_limit: int = 5000, environment_alias_experiment: bool = True, dos_root: pathlib.Path | None = None,
                 timeout_us: int = 2_000_000, cdrom_drives: tuple[str, ...] = (),
                 cdrom_audio_disc_info: tuple[int, int, int, int, int] | None = None,
                 cdrom_audio_track_info: tuple[tuple[int, int, int, int, int], ...] = (),
                 cdrom_audio_subchannel: tuple[int, int, int, int, int, int, int, int, int] | None = None,
                 cdrom_audio_channel_control: tuple[int, int, int, int, int, int, int, int] = (0, 0, 0, 0, 0, 0, 0, 0),
                 cdrom_images: tuple[object, ...] = ()) -> dict:
    image = ROOT / "evidence" / "genewars-1_1.exe"
    boot = prepare_guest(image)
    trace = {
        "kind": "genewars_le_entry",
        "entry_eip": "0x001af96c",
        "target_sha256": boot.executable_sha256,
        "boot_layout": boot_summary(boot),
        "instruction_limit": instruction_limit,
        "stop_reason": None,
        "interrupts": [],
        "instructions": [],
        "first_unsupported": None,
    }
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    low_start, low_end = 0x1000, 0x100000
    uc.mem_map(low_start, low_end - low_start, UC_PROT_ALL)
    uc.mem_write(low_start, boot.memory.read(low_start, low_end - low_start))
    image_size = (len(boot.image.mem) + PAGE - 1) & ~(PAGE - 1)
    uc.mem_map(boot.image.mem_base, image_size, UC_PROT_ALL)
    uc.mem_write(boot.image.mem_base, bytes(boot.image.mem))
    gdt_ok = write_flat_gdt(uc, trace, boot.psp_address, boot.env_address if environment_alias_experiment else None)
    trace["environment_alias_experiment"] = environment_alias_experiment
    if not gdt_ok:
        trace["stop_reason"] = "segment_setup_failed"
        return trace

    # LE headers fix up the code/data selectors as 0x0c/0x14. GPR values are
    # synthetic zeroes until the extender's actual entry contract is measured.
    for reg in (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX):
        uc.reg_write(reg, 0)
    uc.reg_write(UC_X86_REG_EFLAGS, 0x202)
    uc.reg_write(UC_X86_REG_ESP, boot.seed.esp)
    # CS cannot be loaded directly through Unicorn's register API. A synthetic
    # far-jump trampoline loads the target's LDT code selector before its first
    # original instruction executes.
    trampoline = b"\xea" + struct.pack("<IH", boot.seed.eip, 0x0C)
    uc.mem_write(TRAMP_ADDRESS, trampoline)
    trace["host_trampoline"] = {"address": f"0x{TRAMP_ADDRESS:08x}",
                                "bytes": trampoline.hex(),
                                "target": f"0x{boot.seed.eip:08x}",
                                "selector": "0x000c",
                                "is_original_target_code": False}
    uc.reg_write(UC_X86_REG_EIP, TRAMP_ADDRESS)
    trace["initial_registers"] = {k: f"0x{v:08x}" for k, v in regs_snapshot(uc).items()}
    trace["initial_segments"] = {
        "cs": f"0x{uc.reg_read(UC_X86_REG_CS):04x}",
        "ds": f"0x{uc.reg_read(UC_X86_REG_DS):04x}",
        "es": f"0x{uc.reg_read(UC_X86_REG_ES):04x}",
        "ss": f"0x{uc.reg_read(UC_X86_REG_SS):04x}",
        "ldtr": f"0x{uc.reg_read(UC_X86_REG_LDTR)[0]:04x}",
    }
    trace["initial_gprs_are_synthetic"] = True
    owns_dos_root = dos_root is None
    if dos_root is None:
        probe_dos_root = pathlib.Path(tempfile.mkdtemp(prefix="dos_c_probe_", dir=ROOT / "build"))
    else:
        probe_dos_root = pathlib.Path(dos_root).resolve()
    host = DosHost(boot, dos_memory_profile="post_dos4gw_le_entry",
                   dos_clock=DosClock(minimum_step_cs=5),
                   filesystem=DosFileSystem(probe_dos_root, cwd="GENEWARS"),
                   cdrom_drives=cdrom_drives,cdrom_audio_disc_info=cdrom_audio_disc_info,
                   cdrom_audio_track_info=cdrom_audio_track_info,
                   cdrom_audio_subchannel=cdrom_audio_subchannel,
                   cdrom_audio_channel_control=cdrom_audio_channel_control,
                   cdrom_images=cdrom_images)
    host.selectors[0x001c] = boot.psp_address
    if environment_alias_experiment:
        host.selectors[boot.env_segment] = boot.env_address
    count = install_trace_hooks(uc, trace, instruction_limit, host)
    trace["dos_host_seed"] = {"dos_version": f"{host.dos_major}.{host.dos_minor}", "psp_segment": f"0x{boot.psp_segment:04x}"}
    started = time.perf_counter()
    try:
        uc.emu_start(TRAMP_ADDRESS, 0xFFFFFFFF, timeout=timeout_us, count=instruction_limit)
        trace["stop_reason"] = trace.get("stop_reason") or ("process_terminated" if "process_exit" in trace else "emulation_returned_or_stopped_by_hook")
    except UcError as exc:
        trace["stop_reason"] = "backend_error"
        trace["backend_error"] = f"{type(exc).__name__}: {exc}"
    finally:
        trace["elapsed_seconds"] = round(time.perf_counter() - started, 6)
    trace["executed_instruction_count"] = count["value"]
    if host.allocations:
        checks=[]
        for handle,(base,size) in host.allocations.items():
            page_text = trace.get("guest_allocation_first_page", {}).get(str(handle))
            if page_text is None:
                checks.append({"handle":handle,"base":f"0x{base:08x}","sample_size":0,
                               "materialized":False,"match":True})
                continue
            page = int(page_text, 16)
            sample_size=min(size - (page - base),64)
            guest_bytes=bytes(uc.mem_read(page,sample_size))
            host_bytes=host.boot.memory.read(page,sample_size)
            checks.append({"handle":handle,"base":f"0x{base:08x}","page":page_text,"sample_size":sample_size,
                           "materialized":True,"guest_sample":guest_bytes.hex(),"host_backing_sample":host_bytes.hex(),
                           "match":guest_bytes==host_bytes})
        trace["allocation_backing_checks"]=checks
    if "guest_exception" in trace:
        trace["first_unsupported"] = trace["guest_exception"]
    elif "unsupported_service" in trace:
        trace["first_unsupported"] = {"kind":"interrupt_service", **trace["unsupported_service"]}
    elif trace["interrupts"] and not trace["interrupts"][0].get("handled"):
        trace["first_unsupported"] = {"kind": "interrupt", **trace["interrupts"][0]}
    elif "unsupported_memory" in trace:
        trace["first_unsupported"] = {"kind": "memory", **trace["unsupported_memory"]}
    elif "unsupported_port" in trace:
        trace["first_unsupported"] = {"kind": "port", **trace["unsupported_port"]}
    elif trace.get("backend_error"):
        trace["first_unsupported"] = {"kind": "backend_or_guest_setup", "error": trace["backend_error"]}
    trace["dos_memory_state"] = {"profile":host.dos_memory_profile,
        "psp_segment":host.boot.psp_segment,"block_paragraphs":host.block_paragraphs,
        "free_segment":host.free_segment,"free_paragraphs":host.free_paragraphs,
        "mcb_layout":getattr(host,"dos_mcb_layout",None),
        "dpmi_dos_allocations":getattr(host,"dos_allocations",{}),
        "dos_ah48_allocations":getattr(host,"dos_ah48_allocations",{}),
        "dos_free_blocks":getattr(host,"dos_free_blocks",{})}
    for handle in list(host.filesystem.handles):
        if handle >= 5:
            host.filesystem.close(handle)
    if owns_dos_root:
        import shutil
        shutil.rmtree(probe_dos_root)
    return trace


def backend_metadata() -> dict:
    dist = importlib.metadata.distribution("unicorn")
    files = []
    for item in dist.files or []:
        path = pathlib.Path(dist.locate_file(item))
        if path.is_file() and (path.suffix.lower() in (".pyd", ".dll")):
            files.append({"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    license_files = [str(x) for x in (dist.files or []) if "license" in str(x).lower()]
    return {"distribution": dist.metadata.get("Name"), "version": dist.version,
            "wheel_metadata_license": dist.metadata.get("License"),
            "upstream_project_license": "GPLv2 per upstream README; wheel metadata declares BSD License, discrepancy preserved for review",
            "home_page": dist.metadata.get("Home-page"),
            "backend_binaries": files, "license_files": license_files}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--instruction-limit", type=int, default=5000)
    ap.add_argument("--without-environment-alias", dest="environment_alias_experiment", action="store_false", default=True, help="disable the evidence-backed selector 0x1100 environment descriptor")
    ap.add_argument("--output", type=pathlib.Path, default=ROOT / "evidence" / "runtime_backend_execution.json")
    args = ap.parse_args()
    result = {"backend": backend_metadata(), "synthetic": synthetic_probe(),
              "target": target_probe(args.instruction_limit, args.environment_alias_experiment)}
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"version": result["backend"]["version"],
                      "synthetic_pass": result["synthetic"]["pass"],
                      "synthetic_stop": result["synthetic"]["stop_reason"],
                      "target_stop": result["target"]["stop_reason"],
                      "target_instructions": result["target"].get("executed_instruction_count"),
                      "first_unsupported": result["target"].get("first_unsupported"),
                      "output": str(args.output)}, indent=2))
    return 0 if result["synthetic"]["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())






