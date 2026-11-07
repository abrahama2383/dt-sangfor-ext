"""GET /vapi/json/index/overview -> cluster metrics."""

from __future__ import annotations

from ..model import Metric, MetricList, as_dict, cluster_dims, parse_number, ratio_to_percent


def collect(cluster: str, overview: object) -> list[Metric]:
    data = as_dict(overview)
    cpu, mem, stg = as_dict(data.get("cpu")), as_dict(data.get("mem")), as_dict(data.get("stg"))
    vms, hosts = as_dict(data.get("vm")), as_dict(data.get("host"))
    metrics = MetricList(cluster_dims(cluster))
    metrics.add("cluster.cpu.usage", ratio_to_percent(cpu.get("ratio")))
    metrics.add("cluster.memory.usage", ratio_to_percent(mem.get("ratio")))
    metrics.add("cluster.storage.usage", ratio_to_percent(stg.get("ratio")))
    metrics.add("cluster.storage.used", parse_number(stg.get("used")))
    metrics.add("cluster.storage.total", parse_number(stg.get("total")))
    metrics.add("cluster.vms", parse_number(vms.get("on")), {"state": "on"})
    metrics.add("cluster.vms", parse_number(vms.get("off")), {"state": "off"})
    metrics.add("cluster.hosts", parse_number(hosts.get("online")), {"state": "online"})
    metrics.add("cluster.hosts", parse_number(hosts.get("offline")), {"state": "offline"})
    return list(metrics)
