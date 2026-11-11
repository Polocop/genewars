#include "recomp_bridge.h"
gw_dispatch_status gw_recomp_dispatch(const recomp_dispatch_entry_t *table, uint32_t count,
                                      uint32_t guest_va, gw_recomp_context *context) {
    if (!table || !context) return GW_DISPATCH_INVALID;
    for (uint32_t i=0; i<count; ++i) {
        if (table[i].address != guest_va) continue;
        if (!table[i].func) return GW_DISPATCH_INVALID;
        context->eip = guest_va;
        gw_recomp_status status = gw_recomp_invoke(table[i].func, context);
        if (status == GW_RECOMP_BUSY) return GW_DISPATCH_BUSY;
        if (status != GW_RECOMP_OK) return GW_DISPATCH_INVALID;
        return GW_DISPATCH_OK;
    }
    return GW_DISPATCH_NOT_FOUND;
}
