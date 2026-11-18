#ifndef GW_FUNC_COVERAGE_H
#define GW_FUNC_COVERAGE_H

#include <stdint.h>

/* Opt-in guest function-entry counter (GWRECOMP_FUNC_COVERAGE=1, off by default).
 * Set once at process start. The lifted function prologue reads it on every entry. */
extern int g_gw_func_coverage_enabled;

/* Counts one entry of the lifted function whose guest VA is `va`. Only called when
 * g_gw_func_coverage_enabled is set. */
void gw_func_coverage_count(uint32_t va);

#endif
