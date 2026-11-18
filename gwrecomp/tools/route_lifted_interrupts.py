"""Upgrade stale generated INT no-op lines in the current entry lift artifacts."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
line_re = re.compile(
    r"^(\s*); /\* UNIMPLEMENTED: int (0x[0-9A-Fa-f]+) \*/ "
    r"/\* (0x[0-9A-Fa-f]+): int (?:0x[0-9A-Fa-f]+)? \*/\s*$",
    re.MULTILINE,
)
unscoped_dispatch = re.compile(
    r"^(\s*)RECOMP_REGS_OUT\(\); RECOMP_FLAGS_OUT\(\); /\* (0x[0-9A-Fa-f]+): int (0x[0-9A-Fa-f]+) \*/\n"
    r"\1gw_interrupt_result _gw_int_result = gw_interrupt_dispatch\(0x[0-9A-Fa-f]+u, 0x[0-9A-Fa-f]+u\);\n"
    r"\1RECOMP_REGS_IN\(\); RECOMP_FLAGS_IN\(\);\n"
    r"\1if \(_gw_int_result != GW_INTERRUPT_HANDLED\) return;\s*$",
    re.MULTILINE,
)
files = ["build/entry_path.c", "build/entry_path_combined.c", "build/entry_path_closure.c"]
counts = {}
for relative in files:
    path = ROOT / relative
    text = path.read_text(encoding="utf-8")

    def replace(match):
        indent, vector_text, va_text = match.groups()
        vector = int(vector_text, 16)
        va = int(va_text, 16)
        return (
            f"{indent}{{ RECOMP_REGS_OUT(); RECOMP_FLAGS_OUT(); /* {va_text}: int {vector_text} */\n"
            f"{indent}gw_interrupt_result _gw_int_result = gw_interrupt_dispatch(0x{vector:02X}u, 0x{va:08X}u);\n"
            f"{indent}RECOMP_REGS_IN(); RECOMP_FLAGS_IN();\n"
            f"{indent}if (_gw_int_result != GW_INTERRUPT_HANDLED) return; }}"
        )

    text, count = line_re.subn(replace, text)
    text, scopes = unscoped_dispatch.subn(
        lambda m: f"{m.group(1)}{{ {m.group(0)[len(m.group(1)):]} }}", text
    )
    path.write_text(text, encoding="utf-8")
    counts[relative] = {"legacy_noop_lines_routed": count, "previous_dispatch_blocks_scoped": scopes}

closure = (ROOT / "build/entry_path_closure.c").read_text(encoding="utf-8")
if "UNIMPLEMENTED: int" in closure:
    raise SystemExit("unrouted INT remains in entry closure")
report = {
    "routed_ints_by_artifact": counts,
    "routed_ints_total": len(re.findall(r"gw_interrupt_dispatch\(0x[0-9A-Fa-f]+u, 0x[0-9A-Fa-f]+u\)", closure)),
    "unrouted_ints_in_closure": 0,
    "passed": True,
}
(ROOT / "evidence/lifted_interrupt_routing.json").write_text(
    json.dumps(report, indent=2) + "\n", encoding="utf-8"
)
print(json.dumps(report, indent=2))
