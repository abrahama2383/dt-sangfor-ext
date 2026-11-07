"""Shared data types and helpers. No I/O and no Dynatrace SDK imports."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

PREFIX = "sangfor.hci."

ENTITY_CLUSTER = "sangfor_hci:cluster"
ENTITY_HOST = "sangfor_hci:host"
ENTITY_VM = "sangfor_hci:vm"
ENTITY_DATASTORE = "sangfor_hci:datastore"

_NUMBER = re.compile(r"\s*([-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?)(?![\d.])")


@dataclass(frozen=True)
class Metric:
    key: str  # without PREFIX, e.g. "host.cpu.usage"
    value: float
    dimensions: dict[str, str] = field(default_factory=dict)

    @property
    def full_key(self) -> str:
        return PREFIX + self.key


@dataclass(frozen=True)
class Event:
    event_type: str  # "ERROR_EVENT" or "CUSTOM_INFO"
    title: str
    entity_selector: str
    start_ms: int
    properties: dict[str, str] = field(default_factory=dict)


class MetricList(list):
    """A list of Metric that shares base dimensions and drops missing values."""

    def __init__(self, dims: dict[str, str]):
        super().__init__()
        self._dims = dict(dims)

    def add(self, key: str, value: float | None, extra: dict[str, str] | None = None) -> None:
        if value is None:
            return
        self.append(Metric(key, float(value), {**self._dims, **(extra or {})}))


def parse_number(raw: object) -> float | None:
    """Sangfor sends numbers as JSON numbers or as strings such as "0.45" or "52 C".

    The number must start the text (an optional unit may follow). Text such as IPs, versions
    or words is rejected, and so are NaN and infinity: a missing value is better than a wrong one.
    """
    if raw is None:
        return None
    if isinstance(raw, (int, float)):
        value = float(raw)
    else:
        match = _NUMBER.match(str(raw))
        if not match:
            return None
        value = float(match.group(1))
    return value if math.isfinite(value) else None


def ratio_to_percent(raw: object) -> float | None:
    value = parse_number(raw)
    return None if value is None else round(value * 100.0, 4)


def as_dict(raw: object) -> dict:
    return raw if isinstance(raw, dict) else {}


def cluster_dims(cluster: str) -> dict[str, str]:
    return {"sangfor.cluster": cluster}


def host_dims(cluster: str, ip: str, name: str) -> dict[str, str]:
    return {"sangfor.cluster": cluster, "sangfor.host.ip": ip, "sangfor.host.name": name or ip}


def vm_dims(cluster: str, vm_id: str, vm_name: str, host_ip: str) -> dict[str, str]:
    dims = {"sangfor.cluster": cluster, "sangfor.vm.id": vm_id, "sangfor.vm.name": vm_name or vm_id}
    if host_ip:
        dims["sangfor.host.ip"] = host_ip
    return dims


def datastore_dims(cluster: str, ds_id: str, ds_name: str) -> dict[str, str]:
    return {
        "sangfor.cluster": cluster,
        "sangfor.datastore.id": ds_id,
        "sangfor.datastore.name": ds_name or ds_id,
    }


# These must stay identical to instanceNamePattern in extension/extension.yaml.
def host_display_name(cluster: str, name: str) -> str:
    return f"{cluster} / {name}"


def vm_display_name(cluster: str, vm_name: str, vm_id: str) -> str:
    return f"{cluster} / {vm_name} ({vm_id})"


def datastore_display_name(cluster: str, name: str) -> str:
    return f"{cluster} / {name}"


def entity_selector(entity_type: str, display_name: str) -> str:
    escaped = display_name.replace("~", "~~").replace('"', '~"')
    return f'type("{entity_type}"),entityName.equals("{escaped}")'
