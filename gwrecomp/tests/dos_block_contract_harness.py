"""Injectable, contract-neutral DOS AH=48 -> ES -> AH=49 replay harness.

This module records supplied values and delegates all DOS/DPMI interpretation
to an adapter. It contains no selector conversion or default contract values.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class DosBlockContractInputs:
    requested_paragraphs: int
    raw_ah48_return: int
    real_mode_segment: int | None
    protected_mode_selector: int | None
    descriptor_base: int
    descriptor_limit: int
    descriptor_table: str
    access_rights: int
    allocation_lifetime: str
    mapping_lifetime: str
    allocation_owner: int
    psp_segment: int
    mov_es_operand: int
    ah49_es_input: int
    ah48_registers_before: dict[str, int]
    ah48_registers_after: dict[str, int]
    ah48_eflags_before: int
    ah48_eflags_after: int
    segments_before: dict[str, int]
    segments_after_ah48: dict[str, int]

    def validate(self) -> None:
        if not 0 <= self.requested_paragraphs <= 0xffff:
            raise ValueError("requested_paragraphs must be an explicit 16-bit value")
        for name in ("raw_ah48_return", "descriptor_base", "descriptor_limit",
                     "access_rights", "allocation_owner", "psp_segment",
                     "mov_es_operand", "ah49_es_input"):
            value = getattr(self, name)
            if not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be supplied explicitly as a non-negative integer")
        for name in ("real_mode_segment", "protected_mode_selector"):
            value = getattr(self, name)
            if value is not None and not 0 <= value <= 0xffff:
                raise ValueError(f"{name} must be a 16-bit value or explicit None")
        if not self.descriptor_table.strip():
            raise ValueError("descriptor_table must be explicit; use a named table or 'unavailable'")
        if not self.allocation_lifetime.strip() or not self.mapping_lifetime.strip():
            raise ValueError("allocation_lifetime and mapping_lifetime must be explicit")
        for name in ("ah48_registers_before", "ah48_registers_after", "segments_before",
                     "segments_after_ah48"):
            if not isinstance(getattr(self, name), dict):
                raise ValueError(f"{name} must be an explicit register/segment snapshot")


@dataclass(frozen=True)
class LifecycleEvent:
    phase: str
    outcome: str
    registers_before: dict[str, int]
    registers_after: dict[str, int]
    eflags_before: int
    eflags_after: int
    segments_before: dict[str, int]
    segments_after: dict[str, int]
    descriptor_state_before: str
    descriptor_state_after: str
    allocation_state_before: str
    allocation_state_after: str
    result_ax: int | None
    carry: bool | None
    detail: str


class DosBlockAdapter(Protocol):
    """Implementation under test; owns every semantic interpretation."""

    def ah48(self, inputs: DosBlockContractInputs) -> LifecycleEvent: ...

    def mov_es(self, inputs: DosBlockContractInputs) -> LifecycleEvent: ...

    def ah49(self, inputs: DosBlockContractInputs,
             es_event: LifecycleEvent) -> LifecycleEvent: ...


def run_lifecycle(inputs: DosBlockContractInputs, adapter: DosBlockAdapter) -> dict[str, Any]:
    """Run the supplied adapter's lifecycle and preserve its snapshots verbatim."""
    inputs.validate()
    events: list[LifecycleEvent] = [adapter.ah48(inputs)]
    if events[-1].outcome != "success":
        stop = "ah48_failed"
    else:
        events.append(adapter.mov_es(inputs))
        if events[-1].outcome != "success":
            stop = "mov_es_failed"
        else:
            events.append(adapter.ah49(inputs, events[-1]))
            stop = "complete" if events[-1].outcome == "success" else "ah49_failed"
    return {
        "classification": "SYNTHETIC_ADAPTER_RUN",
        "inputs": asdict(inputs),
        "events": [asdict(event) for event in events],
        "stop": stop,
    }
