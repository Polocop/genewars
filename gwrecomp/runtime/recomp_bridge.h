#ifndef GW_RECOMP_BRIDGE_H
#define GW_RECOMP_BRIDGE_H
#include "recomp_context.h"
typedef enum gw_dispatch_status { GW_DISPATCH_OK=0, GW_DISPATCH_NOT_FOUND=1, GW_DISPATCH_BUSY=2, GW_DISPATCH_INVALID=3 } gw_dispatch_status;
/* Lookup is always by the target's full uint32 guest VA; never cast VA to a host pointer. */
gw_dispatch_status gw_recomp_dispatch(const recomp_dispatch_entry_t *table, uint32_t count,
                                      uint32_t guest_va, gw_recomp_context *context);
#endif
