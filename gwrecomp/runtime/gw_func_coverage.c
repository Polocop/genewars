/* Opt-in guest function-entry counter (GWRECOMP_FUNC_COVERAGE=1, off by default).
 *
 * Counts entries of lifted functions through RECOMP_ENTER (see gw_func_coverage_prelude.h).
 * Cost per entry when enabled: one hash probe into a fixed table of 64K slots, no per-
 * instruction trace, no guest memory access, no change to control flow. The table is
 * written once at process exit as JSON and summarised with one TRACE line on stderr.
 *
 * Limitation: host-implemented entries (manual/import hooks that never run RECOMP_ENTER)
 * are not counted, so "entered" is a lower bound on functions the guest executed. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "gw_func_coverage.h"

#define GW_FUNC_COVERAGE_SLOTS 65536u

typedef struct gw_func_coverage_slot {
    uint32_t va;
    uint64_t count; /* 0 marks an empty slot */
} gw_func_coverage_slot;

int g_gw_func_coverage_enabled = 0;

static gw_func_coverage_slot g_func_coverage_slots[GW_FUNC_COVERAGE_SLOTS];
static uint64_t g_func_coverage_total;
static uint64_t g_func_coverage_overflow;
static uint32_t g_func_coverage_distinct;
static char g_func_coverage_out[512] = "function_coverage.json";

void gw_func_coverage_count(uint32_t va) {
    g_func_coverage_total++;
    uint32_t index = (va * 0x9E3779B1u) >> 16;
    /* Linear probe. A full table makes new VAs fall through to overflow; seen VAs stay exact. */
    for (uint32_t probe = 0; probe < GW_FUNC_COVERAGE_SLOTS; probe++) {
        gw_func_coverage_slot *slot = &g_func_coverage_slots[(index + probe) & (GW_FUNC_COVERAGE_SLOTS - 1u)];
        if (slot->count == 0u) {
            slot->va = va;
            slot->count = 1u;
            g_func_coverage_distinct++;
            return;
        }
        if (slot->va == va) { slot->count++; return; }
    }
    g_func_coverage_overflow++;
}

static int gw_func_coverage_compare(const void *a, const void *b) {
    uint32_t va_a = ((const gw_func_coverage_slot *)a)->va;
    uint32_t va_b = ((const gw_func_coverage_slot *)b)->va;
    return (va_a > va_b) - (va_a < va_b);
}

/* Escapes a string for a JSON value; env paths on Windows contain backslashes. */
static void gw_func_coverage_json_string(FILE *out, const char *text) {
    fputc('"', out);
    for (const char *p = text ? text : ""; *p; p++) {
        if (*p == '"' || *p == '\\') fputc('\\', out);
        fputc(*p, out);
    }
    fputc('"', out);
}

static void gw_func_coverage_dump(void) {
    gw_func_coverage_slot *entries = NULL;
    uint32_t count = 0;
    if (g_func_coverage_distinct) {
        entries = (gw_func_coverage_slot *)malloc(sizeof(*entries) * g_func_coverage_distinct);
        if (!entries) return;
        for (uint32_t i = 0; i < GW_FUNC_COVERAGE_SLOTS; i++) {
            if (g_func_coverage_slots[i].count) entries[count++] = g_func_coverage_slots[i];
        }
        qsort(entries, count, sizeof(*entries), gw_func_coverage_compare);
    }

    FILE *out = fopen(g_func_coverage_out, "w");
    if (!out) {
        fprintf(stderr, "TRACE func_coverage_summary enabled=1 write_failed=1 out=%s\n", g_func_coverage_out);
        free(entries);
        return;
    }
    fprintf(out, "{\n");
    fprintf(out, "  \"schema\": \"gw-function-coverage/v1\",\n");
    fprintf(out, "  \"source\": \"RECOMP_ENTER prologue counter (runtime/gw_func_coverage.c)\",\n");
    fprintf(out, "  \"opt_in_env\": \"GWRECOMP_FUNC_COVERAGE=1\",\n");
    fprintf(out, "  \"window\": {\n");
    fprintf(out, "    \"snapshot_env\": "); gw_func_coverage_json_string(out, getenv("GWRECOMP_NATIVE_SNAPSHOT_LOAD")); fprintf(out, ",\n");
    fprintf(out, "    \"host_bound_turn_env\": "); gw_func_coverage_json_string(out, getenv("GWRECOMP_IFCLEVEL_HOST_BOUND_TURN")); fprintf(out, "\n");
    fprintf(out, "  },\n");
    fprintf(out, "  \"total_entries\": %llu,\n", (unsigned long long)g_func_coverage_total);
    fprintf(out, "  \"distinct_functions\": %u,\n", (unsigned)count);
    fprintf(out, "  \"overflow_entries\": %llu,\n", (unsigned long long)g_func_coverage_overflow);
    fprintf(out, "  \"entered\": [\n");
    for (uint32_t i = 0; i < count; i++) {
        fprintf(out, "    {\"va\": \"0x%08X\", \"count\": %llu}%s\n", entries[i].va,
                (unsigned long long)entries[i].count, (i + 1 < count) ? "," : "");
    }
    fprintf(out, "  ],\n");
    /* Counter-only instrumentation: it writes no guest memory, emits no per-instruction
     * trace and does not branch on guest state. Behaviour is checked against the
     * reference replay in run-evidence/function_coverage_turn725_730_compare.json. */
    fprintf(out, "  \"integrity\": {\"simulation_logic_modified\": false, \"memory_forced\": false, "
                 "\"per_instruction_trace\": false, \"counter_only\": true}\n");
    fprintf(out, "}\n");
    fclose(out);

    fprintf(stderr, "TRACE func_coverage_summary enabled=1 total_entries=%llu distinct=%u overflow_entries=%llu out=%s\n",
            (unsigned long long)g_func_coverage_total, (unsigned)count,
            (unsigned long long)g_func_coverage_overflow, g_func_coverage_out);
    free(entries);
}

__attribute__((constructor))
static void gw_func_coverage_init(void) {
    const char *flag = getenv("GWRECOMP_FUNC_COVERAGE");
    if (!flag || strcmp(flag, "1") != 0) return;
    const char *out = getenv("GWRECOMP_FUNC_COVERAGE_OUT");
    if (out && *out) {
        strncpy(g_func_coverage_out, out, sizeof(g_func_coverage_out) - 1u);
        g_func_coverage_out[sizeof(g_func_coverage_out) - 1u] = '\0';
    }
    g_gw_func_coverage_enabled = 1;
    atexit(gw_func_coverage_dump);
}
