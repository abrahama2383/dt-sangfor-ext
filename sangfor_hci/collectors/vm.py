"""GET /vapi/json/cluster/vms -> VM metrics. Groups may nest; VMs are the items with a vmid.

Units of diskread/diskwrite/netin/netout are open question Q1; values are reported as sent.
"""

from __future__ import annotations

from typing import Iterator

from ..model import Metric, MetricList, parse_number, ratio_to_percent, vm_dims
from .host import HostInfo


def iter_vms(payload: object) -> Iterator[dict]:
    stack = list(payload) if isinstance(payload, list) else []
    while stack:
        item = stack.pop(0)
        if not isinstance(item, dict):
            continue
        if "vmid" in item:
            yield item
        elif isinstance(item.get("data"), list):
            stack[0:0] = item["data"]


def collect(cluster: str, payload: object, hosts: dict[str, HostInfo]) -> list[Metric]:
    result: list[Metric] = []
    for item in iter_vms(payload):
        vm_id = str(item["vmid"])
        host = hosts.get(str(item.get("host") or ""))
        dims = vm_dims(cluster, vm_id, str(item.get("name") or vm_id), host.ip if host else "")
        if item.get("groupname"):
            dims["sangfor.vm.group"] = str(item["groupname"])
        os_name = item.get("osname") or item.get("ostype")
        if os_name:
            dims["sangfor.vm.os"] = str(os_name)
        dims["sangfor.vm.ha"] = "true" if parse_number(item.get("ha")) == 1 else "false"
        metrics = MetricList(dims)
        metrics.add("vm.cpu.usage", ratio_to_percent(item.get("cpu_ratio")))
        metrics.add("vm.memory.usage", ratio_to_percent(item.get("mem_ratio")))
        metrics.add("vm.disk.used", parse_number(item.get("disk_used")))
        metrics.add("vm.disk.read", parse_number(item.get("diskread")))
        metrics.add("vm.disk.write", parse_number(item.get("diskwrite")))
        metrics.add("vm.net.in", parse_number(item.get("netin")))
        metrics.add("vm.net.out", parse_number(item.get("netout")))
        if item.get("status"):
            metrics.add("vm.running", 1.0 if str(item["status"]) == "running" else 0.0)
        result.extend(metrics)
    return result
