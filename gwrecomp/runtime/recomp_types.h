/* Forwarder for the pcrecomp recomp_types.h, used only for the opt-in function-entry counter.
 *
 * Generated closures define RECOMP_GENERATED_CODE before they include recomp_types.h, so this
 * shim must not include the real header earlier (a -include prelude broke that ordering). With
 * #include_next the real header is still processed at the same point, with the same guards.
 *
 * Only the IFCLevel harness build defines GW_FUNC_COVERAGE_BUILD. In that build RECOMP_ENTER
 * also reaches gw_func_coverage_count() behind the GWRECOMP_FUNC_COVERAGE=1 flag. Without that
 * define this header is a plain forwarder and changes nothing. */
#ifndef GW_FUNC_COVERAGE_RECOMP_TYPES_SHIM_H
#define GW_FUNC_COVERAGE_RECOMP_TYPES_SHIM_H

#include_next "recomp_types.h"

#if defined(GW_FUNC_COVERAGE_BUILD) && !defined(RECOMP_TRACE)
#include "gw_func_coverage.h"
#undef RECOMP_ENTER
#define RECOMP_ENTER(va) (g_cur_func = (va), RECOMP_FLAGS_IN(), \
    (g_gw_func_coverage_enabled ? gw_func_coverage_count((uint32_t)(va)) : (void)0))
#endif

#endif
