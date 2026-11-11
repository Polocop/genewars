#ifndef GW_FUNC_COVERAGE_PRELUDE_H
#define GW_FUNC_COVERAGE_PRELUDE_H

/* Force-included ahead of the generated closure by the IFCLevel harness build only
 * (tests/test_ifctitle_creature_probe.py, -include). It replaces the function-entry
 * prologue so each lifted entry also reaches gw_func_coverage_count() when
 * GWRECOMP_FUNC_COVERAGE=1. The guest-visible part of the prologue is unchanged. */

#include "recomp_types.h"
#include "gw_func_coverage.h"

#ifndef RECOMP_TRACE
#undef RECOMP_ENTER
#define RECOMP_ENTER(va) (g_cur_func = (va), RECOMP_FLAGS_IN(), \
    (g_gw_func_coverage_enabled ? gw_func_coverage_count((uint32_t)(va)) : (void)0))
#endif

#endif
