"""Host-only state machine for a bounded page-call filter."""

CAP = 5
MODE_CALLSITE = 0x9FDCC
PAGE_ENTRY = 0xA3A5C
INT10_ENTRY_RETURN = {0xA3A91, 0xA3A93, 0xA3AB7, 0xA3AB9}


def step(link_va: int, eax: int, edx: int, armed: bool,
         page_seen: bool, complete: bool, count: int):
    trigger = (link_va == MODE_CALLSITE and (eax & 0xFFFF) == 0x0101 and
               edx == 0x180 and not armed and not complete)
    if trigger:
        return False, True, page_seen, complete, count
    page_entry = armed and not page_seen and link_va == PAGE_ENTRY
    int10 = armed and page_seen and link_va in INT10_ENTRY_RETURN
    admit = (page_entry or int10) and count < CAP
    if not admit:
        return False, armed, page_seen, complete, count
    count += 1
    if page_entry:
        page_seen = True
    if link_va == 0xA3AB9:
        armed = False
        complete = True
    return True, armed, page_seen, complete, count
