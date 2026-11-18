"""Host-only model of the target-specific W3-100 VESA checkpoint admission."""
from __future__ import annotations

CAP = 5
SUCCESSORS = {0xA3A00, 0x9FDD1, 0x9FDEF, 0x9FDF9}
CALLSITE = 0x9FDCC


def step(link_va: int, eax: int, edx: int, armed: bool, complete: bool, count: int):
    callsite = (link_va == CALLSITE and (eax & 0xFFFF) == 0x0101 and
                edx == 0x180 and not armed and not complete)
    successor = armed and link_va in SUCCESSORS
    admit = (callsite or successor) and count < CAP
    if not admit:
        return False, armed, complete, count
    count += 1
    if callsite:
        armed = True
    if link_va == 0x9FDF9 and armed:
        armed = False
        complete = True
    return True, armed, complete, count
