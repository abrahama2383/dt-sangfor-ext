"""GET /vapi/json/vtpstorage/storelist -> datastore metrics.

status is a set of flags (spec: 0x0001 online, 0x0010 some hosts cannot access, 0x0100 over 90%).
Whether these are hex masks or binary-digit notation is open question Q2; hex is assumed.
"""

from __future__ import annotations

from ..model import Metric, MetricList, as_dict, datastore_dims, parse_number

GROUPS = ("local", "iscsi", "fc", "nfs", "virtual_storage")
FLAG_ONLINE = 0x0001
FLAG_PARTIAL_ACCESS = 0x0010
FLAG_OVER_90 = 0x0100


def _status_flags(raw: object) -> int | None:
    """Accept the status as an int, a decimal string or a hex string such as "0x0011"."""
    if isinstance(raw, str) and raw.strip().lower().startswith("0x"):
        try:
            return int(raw.strip(), 16)
        except ValueError:
            return None
    value = parse_number(raw)
    return None if value is None else int(value)


def collect(cluster: str, storelist: object) -> list[Metric]:
    data = as_dict(storelist)
    result: list[Metric] = []
    for group in GROUPS:
        items = data.get(group)
        for item in items if isinstance(items, list) else []:
            if not isinstance(item, dict) or not item.get("id"):
                continue
            ds_id = str(item["id"])
            dims = datastore_dims(cluster, ds_id, str(item.get("name") or ds_id))
            dims["sangfor.datastore.type"] = str(item.get("type") or group)
            dims["sangfor.datastore.shared"] = "true" if parse_number(item.get("shared")) == 1 else "false"
            metrics = MetricList(dims)
            total, used = parse_number(item.get("total")), parse_number(item.get("used"))
            metrics.add("datastore.total", total)
            metrics.add("datastore.available", parse_number(item.get("avail")))
            if total and used is not None:
                metrics.add("datastore.usage", round(used / total * 100.0, 4))
            metrics.add("datastore.read.iops", parse_number(item.get("read_cnt")))
            metrics.add("datastore.write.iops", parse_number(item.get("write_cnt")))
            metrics.add("datastore.read.throughput", parse_number(item.get("read_ratio")))
            metrics.add("datastore.write.throughput", parse_number(item.get("write_ratio")))
            flags = _status_flags(item.get("status"))
            if flags is not None:
                metrics.add("datastore.online", 1.0 if flags & FLAG_ONLINE else 0.0)
                metrics.add("datastore.partial_access", 1.0 if flags & FLAG_PARTIAL_ACCESS else 0.0)
                metrics.add("datastore.capacity_alert", 1.0 if flags & FLAG_OVER_90 else 0.0)
            result.extend(metrics)
    return result
