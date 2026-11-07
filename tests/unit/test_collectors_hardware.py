from sangfor_hci.collectors import hardware
from sangfor_hci.snmp import oids
from simulator.snmp_sim import load_snmprec


def snapshot(dataset):
    data = load_snmprec(dataset)
    tables = {t.entry: {oid: v for oid, v in data.items() if oid.startswith(t.entry + ".")} for t in oids.TABLES}
    return data, tables


def values(metrics, key, **dims):
    return [m.value for m in metrics if m.key == key and all(m.dimensions.get(k) == v for k, v in dims.items())]


def test_node_a_hardware():
    scalars, tables = snapshot("node-a")
    metrics = hardware.collect("sim", "10.0.0.11", "node-a", scalars, tables, hardware.StatusBaseline())
    assert len(metrics) == 19
    assert values(metrics, "hw.disk.usage") == [41.0]
    assert values(metrics, "hw.cpu.temperature", **{"sangfor.cpu": "CPU0"}) == [52.0]
    assert values(metrics, "hw.cpu.temperature", **{"sangfor.cpu": "CPU1"}) == [55.0]
    assert values(metrics, "hw.fs.size", **{"sangfor.fs": "/"}) == [50.0 * 1024**3]
    assert values(metrics, "hw.fs.usage", **{"sangfor.fs": "/sf/data"}) == [37.5]
    assert values(metrics, "hw.optical.tx.power", **{"sangfor.port": "eth4"}) == [-2.1]
    assert values(metrics, "hw.optical.rx.power", **{"sangfor.port": "eth4"}) == [-3.4]
    assert values(metrics, "hw.raid.ok", **{"sangfor.raid": "RAID1-sys"}) == [1.0]
    assert values(metrics, "hw.fan.ok") == [1.0, 1.0]
    assert values(metrics, "hw.fan.speed", **{"sangfor.fan": "FAN2"}) == [5520.0]
    assert values(metrics, "hw.ssd.life", **{"sangfor.ssd": "SSD-0"}) == [97.0]
    assert all(
        m.dimensions["sangfor.host.ip"] == "10.0.0.11" and m.dimensions["sangfor.host.name"] == "node-a"
        for m in metrics
    )


def test_node_b_failures():
    scalars, tables = snapshot("node-b")
    metrics = hardware.collect("sim", "10.0.0.12", "node-b", scalars, tables, hardware.StatusBaseline())
    assert len(metrics) == 12
    assert values(metrics, "hw.raid.ok") == [0.0]
    assert values(metrics, "hw.fan.ok", **{"sangfor.fan": "FAN2"}) == [0.0]
    assert values(metrics, "hw.ssd.life") == [12.0]
    assert values(metrics, "hw.optical.rx.power") == []


def test_bare_node_yields_nothing():
    scalars, tables = snapshot("bare")
    assert hardware.collect("sim", "10.0.0.12", "node-b", scalars, tables, hardware.StatusBaseline()) == []


def test_status_baseline_for_unknown_tokens():
    baseline = hardware.StatusBaseline()
    key = ("10.0.0.11", "fan:FAN1")
    assert baseline.is_ok(key, "spinning") is True
    assert baseline.is_ok(key, "spinning") is True
    assert baseline.is_ok(key, "stopped") is False
    assert baseline.is_ok(key, " OK ") is True
    assert baseline.is_ok(key, "Degraded") is False
    assert baseline.unknown_values == {"spinning", "stopped"}


def test_snmp_host_metrics():
    scalars, _ = snapshot("node-a")
    metrics = hardware.snmp_host_metrics("sim", "10.0.0.11", "node-a", scalars)
    assert {m.key: m.value for m in metrics} == {"host.cpu.usage": 12.0, "host.memory.usage": 58.0}
    assert hardware.snmp_host_metrics("sim", "10.0.0.11", "node-a", {}) == []


def test_status_baseline_unknown_values_are_capped():
    baseline = hardware.StatusBaseline()
    for i in range(500):
        baseline.is_ok(("10.0.0.11", f"fan:FAN{i}"), f"weird-{i}")
    assert len(baseline.unknown_values) == 100
