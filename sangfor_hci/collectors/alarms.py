"""GET /vapi/json/log/alert/all -> Dynatrace events (spec §5.4).

The response nests alarms in data.data[]. urgent_type is a string ("1" means urgent).
Alarms are filtered client-side by start time and log_id, because the format of the
API's starttime filter is not documented.
"""

from __future__ import annotations

from collections import OrderedDict

from ..model import (
    ENTITY_CLUSTER,
    ENTITY_HOST,
    ENTITY_VM,
    Event,
    as_dict,
    entity_selector,
    host_display_name,
    parse_number,
    vm_display_name,
)
from .host import HostInfo

EVENT_ERROR = "ERROR_EVENT"
EVENT_INFO = "CUSTOM_INFO"


class AlarmCursor:
    def __init__(self, start_after: int, capacity: int = 5000):
        self.start_after = start_after
        self._capacity = capacity
        self._seen: OrderedDict[str, None] = OrderedDict()

    def is_new(self, log_id: str, start: int) -> bool:
        return log_id not in self._seen and start >= self.start_after

    def remember(self, log_id: str) -> None:
        self._seen[log_id] = None
        while len(self._seen) > self._capacity:
            self._seen.popitem(last=False)


def collect(cluster: str, payload: object, hosts: dict[str, HostInfo], cursor: AlarmCursor) -> list[Event]:
    items = as_dict(payload).get("data")
    alarms = [item for item in items if isinstance(item, dict)] if isinstance(items, list) else []
    events = []
    for item in sorted(alarms, key=lambda a: parse_number(a.get("start")) or 0):
        log_id = str(item.get("log_id") or "")
        start = parse_number(item.get("start"))
        if not log_id or start is None or not cursor.is_new(log_id, int(start)):
            continue
        cursor.remember(log_id)
        events.append(_to_event(cluster, item, hosts, log_id, int(start)))
    return events


def _to_event(cluster: str, item: dict, hosts: dict[str, HostInfo], log_id: str, start: int) -> Event:
    kind = str(item.get("type") or item.get("type_cn") or "alarm")
    object_type = str(item.get("object_type") or "")
    host = hosts.get(str(item.get("hostid") or ""))
    vm_id = str(item.get("vm") or item.get("object_id") or "")
    if object_type == "host" and host:
        selector = entity_selector(ENTITY_HOST, host_display_name(cluster, host.name))
    elif object_type == "vm" and vm_id:
        selector = entity_selector(ENTITY_VM, vm_display_name(cluster, str(item.get("object_name") or vm_id), vm_id))
    else:
        selector = entity_selector(ENTITY_CLUSTER, cluster)
    properties = {
        "sangfor.log_id": log_id,
        "sangfor.alert.type": kind,
        "sangfor.object.type": object_type,
        "sangfor.object.name": str(item.get("object_name") or ""),
        "sangfor.description": str(item.get("description") or ""),
        "sangfor.host.name": host.name if host else "",
    }
    urgent = str(item.get("urgent_type", "0")).strip() == "1"
    return Event(
        event_type=EVENT_ERROR if urgent else EVENT_INFO,
        title=f"Sangfor HCI: {kind}",
        entity_selector=selector,
        start_ms=start * 1000,
        properties={key: value for key, value in properties.items() if value},
    )
