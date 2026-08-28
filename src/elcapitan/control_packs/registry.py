"""Fail-closed registry for installed deterministic control packs."""
from __future__ import annotations

from .models import ControlDefinition, ControlPack


class ControlPackRegistry:
    def __init__(self, packs: tuple[ControlPack, ...]) -> None:
        self._packs = tuple(packs)
        if len({pack.pack_id for pack in self._packs}) != len(self._packs):
            raise ValueError("control pack ids must be unique")
        self._controls = tuple(
            control for pack in self._packs for control in pack.controls)
        self._by_key = {
            (item.provider, item.rule_id): item for item in self._controls
        }
        if len(self._by_key) != len(self._controls):
            raise ValueError("controls must be unique by provider and rule")

    def get(self, provider: str, rule_id: str,
            resource_type: str = "") -> ControlDefinition | None:
        control = self._by_key.get((provider.lower(), rule_id))
        if (control is not None and resource_type
                and resource_type.lower() not in {
                    item.lower() for item in control.resource_types}):
            return None
        return control

    def list(self, *, provider: str | None = None) -> tuple[ControlDefinition, ...]:
        selected = (
            item for item in self._controls
            if provider is None or item.provider == provider.lower())
        return tuple(sorted(
            selected, key=lambda item: (item.provider, item.rule_id)))

    def packs(self) -> tuple[ControlPack, ...]:
        return tuple(sorted(self._packs, key=lambda item: item.pack_id))
