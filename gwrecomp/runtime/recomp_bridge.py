"""Address-based adapter for Python guest callables. Native global-ABI lifts use runtime/recomp_context.h."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Callable, Mapping

@dataclass
class CpuState:
    eax:int=0; ebx:int=0; ecx:int=0; edx:int=0
    esi:int=0; edi:int=0; ebp:int=0; esp:int=0
    eip:int=0; eflags:int=0x202
    cs:int=0x0c; ds:int=0x14; es:int=0x14; fs:int=0; gs:int=0; ss:int=0x14
    def validate(self):
        for name, value in vars(self).items():
            if not isinstance(value,int) or not 0 <= value <= 0xffffffff:
                raise ValueError(f"{name} must be an unsigned 32-bit value")

@dataclass
class GuestTrap(RuntimeError):
    kind:str
    eip:int
    address:int|None=None
    detail:str=""
    def __str__(self):
        suffix=f" address=0x{self.address:08x}" if self.address is not None else ""
        return f"{self.kind} at EIP=0x{self.eip:08x}{suffix}: {self.detail}"

GuestFunction=Callable[[CpuState],None]

class RecompBridge:
    """Dispatch explicit-state host callables; does not adapt the legacy global ABI."""
    def __init__(self, functions:Mapping[int,GuestFunction]):
        self.functions={int(address):fn for address,fn in functions.items()}
        if any(not 0 <= address <= 0xffffffff for address in self.functions):
            raise ValueError("guest function address outside 32-bit range")
        self.trace=[]
    def call(self,address:int,state:CpuState)->CpuState:
        if not 0 <= address <= 0xffffffff: raise ValueError("guest VA outside 32-bit range")
        fn=self.functions.get(address)
        if fn is None: raise GuestTrap("unresolved_guest_call",state.eip,address,"no compiled function registered")
        state.validate()
        before=vars(state).copy()
        try:
            state.eip=address
            fn(state)
            state.validate()
        except GuestTrap:
            self.trace.append({"address":address,"before":before,"trap":True})
            raise
        except Exception as exc:
            trap=GuestTrap("host_function_trap",state.eip,address,f"{type(exc).__name__}: {exc}")
            self.trace.append({"address":address,"before":before,"trap":str(trap)})
            raise trap from exc
        self.trace.append({"address":address,"before":before,"after":vars(state).copy()})
        return state
