import pytest

from sangfor_hci.collectors import cluster, datastore, host
from simulator.mock_api import load_fixtures

FX = load_fixtures()


def by_key(metrics):
    result = {}
    for metric in metrics:
        result.setdefault(metric.key, []).append(metric)
    return result


def test_cluster_overview():
    metrics = cluster.collect("sim", FX["overview"]["data"])
    values = {(m.key, m.dimensions.get("state")): m.value for m in metrics}
    assert values == {
        ("cluster.cpu.usage", None): 6.0,
        ("cluster.memory.usage", None): 41.0,
        ("cluster.storage.usage", None): 9.0,
        ("cluster.storage.used", None): 575881084928.0,
        ("cluster.storage.total", None): 6109322543104.0,
        ("cluster.vms", "on"): 2.0,
        ("cluster.vms", "off"): 1.0,
        ("cluster.hosts", "online"): 2.0,
        ("cluster.hosts", "offline"): 0.0,
    }
    assert all(m.dimensions["sangfor.cluster"] == "sim" for m in metrics)


def test_cluster_tolerates_garbage():
    assert cluster.collect("sim", None) == []
    assert cluster.collect("sim", {"cpu": "oops", "vm": {"on": "n/a"}}) == []


def test_host_index():
    hosts = host.index(FX["host_list"]["data"])
    assert hosts["host-00e0ec000a11"] == host.HostInfo("host-00e0ec000a11", "10.0.0.11", "node-a", True)
    assert hosts["host-00e0ec000b12"].ip == "10.0.0.12"
    assert host.index(None) == {}
    assert host.index([{"id": "x"}, "junk"]) == {}


def test_host_metrics_with_node_info():
    metrics = host.collect("sim", FX["host_list"]["data"], FX["node_info"])
    assert len(metrics) == 14
    node_a = {m.key: m for m in metrics if m.dimensions["sangfor.host.ip"] == "10.0.0.11"}
    assert node_a["host.cpu.usage"].value == 12.0
    assert node_a["host.memory.usage"].value == 58.0
    assert node_a["host.io.usage"].value == 3.0
    assert node_a["host.online"].value == 1.0
    assert node_a["host.alarm"].value == 0.0
    assert node_a["host.uptime"].value == 10511969.0
    assert node_a["host.vms.running"].value == 2.0
    assert node_a["host.cpu.usage"].dimensions == {
        "sangfor.cluster": "sim",
        "sangfor.host.ip": "10.0.0.11",
        "sangfor.host.name": "node-a",
        "sangfor.host.master": "true",
        "sangfor.version": "SANGFOR aCloud 6.10.0_R2 Build20251020",
    }
    node_b = {m.key: m for m in metrics if m.dimensions["sangfor.host.ip"] == "10.0.0.12"}
    assert node_b["host.alarm"].value == 1.0
    assert node_b["host.cpu.usage"].dimensions["sangfor.host.master"] == "false"


def test_host_metrics_without_node_info():
    metrics = host.collect("sim", FX["host_list"]["data"], {})
    keys = {m.key for m in metrics}
    assert "host.uptime" not in keys and "host.vms.running" not in keys
    assert all("sangfor.version" not in m.dimensions for m in metrics)


def test_datastores():
    metrics = datastore.collect("sim", FX["storelist"]["data"])
    assert len(metrics) == 30
    local_a = {m.key: m for m in metrics if m.dimensions["sangfor.datastore.name"] == "local_a"}
    assert local_a["datastore.total"].value == 1997159792640.0
    assert local_a["datastore.available"].value == 1286765281280.0
    assert local_a["datastore.usage"].value == pytest.approx(35.5702, abs=1e-3)
    assert local_a["datastore.read.iops"].value == 0.33
    assert local_a["datastore.write.iops"].value == 44.67
    assert local_a["datastore.read.throughput"].value == 1361.92
    assert local_a["datastore.write.throughput"].value == 509777.92
    assert local_a["datastore.online"].value == 1.0
    assert local_a["datastore.partial_access"].value == 0.0
    assert local_a["datastore.capacity_alert"].value == 0.0
    assert local_a["datastore.usage"].dimensions == {
        "sangfor.cluster": "sim",
        "sangfor.datastore.id": "350014ee0aed9e86a_00e0ec000a11",
        "sangfor.datastore.name": "local_a",
        "sangfor.datastore.type": "local",
        "sangfor.datastore.shared": "false",
    }
    nfs = {m.key: m for m in metrics if m.dimensions["sangfor.datastore.name"] == "nfs-backup"}
    assert nfs["datastore.usage"].value == 25.0
    assert nfs["datastore.usage"].dimensions["sangfor.datastore.shared"] == "true"


def test_datastore_status_flags():
    store = {"local": [{"id": "d1", "name": "d1", "status": 0x0001 | 0x0010 | 0x0100, "total": 10, "used": 9}]}
    values = {m.key: m.value for m in datastore.collect("sim", store)}
    assert values["datastore.online"] == 1.0
    assert values["datastore.partial_access"] == 1.0
    assert values["datastore.capacity_alert"] == 1.0
    assert values["datastore.usage"] == 90.0
    assert "datastore.read.iops" not in values


def test_host_null_alert_is_skipped_not_an_alarm():
    metrics = host.collect("sim", [{"id": "h1", "ip": "10.0.0.9", "name": "n", "alert": None}], {})
    assert "host.alarm" not in {m.key for m in metrics}


def test_datastore_hex_string_status_is_read_as_hex():
    store = {"nfs": [{"id": "d2", "name": "d2", "status": "0x0011", "total": 10, "used": 1}]}
    values = {m.key: m.value for m in datastore.collect("sim", store)}
    assert values["datastore.online"] == 1.0
    assert values["datastore.partial_access"] == 1.0
