"""Attach read-only host observers to the Gene Wars 1.1 entity draw path."""
import re


def instrument_entity_draws(source: str) -> str:
    owners = (0x79178, 0x7925B, 0x793BD, 0x793EC)
    blits = (
        (0x91A39, 0x904E0, "ebp", "0u"),
        (0x91AB7, 0x904E0, "ebp", "0u"),
        (0x91B60, 0x90F90, "ebp", "MEM32(SS_BASE + esp)"),
        (0x91BE4, 0x90F90, "ebp", "MEM32(SS_BASE + esp)"),
        (0x96670, 0x99A20, "MEM32(SS_BASE + esp)", "0u"),
        (0x966F2, 0x99A20, "MEM32(SS_BASE + esp)", "0u"),
    )
    hooks = {}
    for site in owners:
        hooks[site] = (
            "{ unsigned int gw_previous_owner=gw_entity_draw_enter(DS_BASE+eax);",
            "gw_entity_draw_leave(gw_previous_owner); }",
        )
    for site, target, frame, extra in blits:
        hooks[site] = (
            f"gw_entity_draw_sprite(0x{site:08X}u,0x{target:08X}u,DS_BASE,{frame},"
            f"eax,edx,ebx,ecx,{extra});",
            "",
        )

    watched = "|".join(f"{site:08X}" for site in hooks)
    pattern = re.compile(
        rf"^([ \t]*)(GW_RECOMP_(?:I)?CALL[^ \n]*[^\n]*?/\* 0x({watched}): call [^\n]*\*/[ \t]*)$",
        re.MULTILINE,
    )
    seen = set()

    def add_hook(match):
        indent, call, address = match.groups()
        site = int(address, 16)
        if site in seen:
            raise ValueError(f"duplicate entity draw call {address}")
        seen.add(site)
        before, after = hooks[site]
        lines = [indent + before, indent + call]
        if after:
            lines.append(indent + after)
        return "\n".join(lines)

    updated = pattern.sub(add_hook, source)
    missing = hooks.keys() - seen
    if missing:
        raise ValueError("missing entity draw calls: " + ", ".join(f"{site:#x}" for site in sorted(missing)))
    return (
        "unsigned int gw_entity_draw_enter(unsigned int);\n"
        "void gw_entity_draw_leave(unsigned int);\n"
        "void gw_entity_draw_sprite(unsigned int,unsigned int,unsigned int,unsigned int,"
        "unsigned int,unsigned int,unsigned int,unsigned int,unsigned int);\n"
        + updated
    )
