"""GET /vapi/json/index/host_list and /vapi/json/nodes/{id}/info -> host metrics."""

from __future__ import annotations

from dataclasses import dataclass

from ..model import Metric, MetricList, as_dict, host_dims, parse_number, ratio_to_percent


@dataclass(frozen=True)
class HostInfo:
    host_id: str
    ip: str
    name: str
    online: bool


def _items(host_list: object) -> list[dict]:
    return [item for item in host_list if isinstance(item, dict)] if isinstance(host_list, list) else []


def index(host_list: object) -> dict[str, HostInfo]:
    hosts = {}
    for item in _items(host_list):
        host_id, ip = str(item.get("id") or ""), str(item.get("ip") or "")
        if host_id and ip:
            name = str(item.get("name") or ip)
            hosts[host_id] = HostInfo(host_id, ip, name, parse_number(item.get("status")) == 1)
    return hosts


def collect(cluster: str, host_list: object, node_infos: dict[str, dict]) -> list[Metric]:
    result: list[Metric] = []
    for item in _items(host_list):
        host_id, ip = str(item.get("id") or ""), str(item.get("ip") or "")
        if not host_id or not ip:
            continue
        node = as_dict(node_infos.get(host_id))
        dims = host_dims(cluster, ip, str(item.get("name") or ip))
        dims["sangfor.host.master"] = "true" if parse_number(item.get("master")) == 1 else "false"
        if node.get("os_version"):
            dims["sangfor.version"] = str(node["os_version"])
        metrics = MetricList(dims)
        metrics.add("host.cpu.usage", ratio_to_percent(item.get("cpu_ratio")))
        metrics.add("host.memory.usage", ratio_to_percent(item.get("mem_ratio")))
        metrics.add("host.io.usage", ratio_to_percent(item.get("io_ratio")))
        status = parse_number(item.get("status"))
        if status is not None:
            metrics.add("host.online", 1.0 if status == 1 else 0.0)
        raw_alert = item.get("alert")
        if raw_alert is not None:
            alert = str(raw_alert).strip()
            metrics.add("host.alarm", 0.0 if alert in ("", "0") else 1.0)
        metrics.add("host.uptime", parse_number(node.get("uptime")))
        metrics.add("host.vms.running", parse_number(node.get("running_vms")))
        result.extend(metrics)
    return result
