from sangfor_hci.collectors import alarms, host, vm
from simulator.mock_api import load_fixtures

FX = load_fixtures()
HOSTS = host.index(FX["host_list"]["data"])
ALERTS = FX["alerts"]["data"]  # fixture start times: 1762500000, 1762500060, 1762500120


def test_iter_vms_flattens_groups():
    names = [item["name"] for item in vm.iter_vms(FX["vms"]["data"])]
    assert names == ["app-01", "app-02", "db-01"]
    assert list(vm.iter_vms(None)) == []
    nested = [{"type": "group", "data": [{"type": "group", "data": [{"vmid": 1, "name": "deep"}]}]}]
    assert [item["name"] for item in vm.iter_vms(nested)] == ["deep"]


def test_vm_metrics():
    metrics = vm.collect("sim", FX["vms"]["data"], HOSTS)
    assert len(metrics) == 24
    app01 = {m.key: m for m in metrics if m.dimensions["sangfor.vm.name"] == "app-01"}
    assert {k: m.value for k, m in app01.items()} == {
        "vm.cpu.usage": 3.0,
        "vm.memory.usage": 14.0,
        "vm.disk.used": 7301444403.0,
        "vm.disk.read": 0.0,
        "vm.disk.write": 9830.0,
        "vm.net.in": 8148.0,
        "vm.net.out": 0.0,
        "vm.running": 1.0,
    }
    assert app01["vm.cpu.usage"].dimensions == {
        "sangfor.cluster": "sim",
        "sangfor.vm.id": "1774086864344",
        "sangfor.vm.name": "app-01",
        "sangfor.host.ip": "10.0.0.11",
        "sangfor.vm.group": "grp-app",
        "sangfor.vm.os": "linux-oracle",
        "sangfor.vm.ha": "true",
    }
    db01 = {m.key: m for m in metrics if m.dimensions["sangfor.vm.name"] == "db-01"}
    assert db01["vm.running"].value == 0.0
    assert db01["vm.running"].dimensions["sangfor.host.ip"] == "10.0.0.12"
    assert "sangfor.vm.group" not in db01["vm.running"].dimensions


def test_vm_on_unknown_host_has_no_host_dimension():
    metrics = vm.collect("sim", [{"vmid": 5, "name": "orphan", "host": "host-gone", "status": "running"}], HOSTS)
    assert metrics and all("sangfor.host.ip" not in m.dimensions for m in metrics)


def test_alarms_become_events_once():
    cursor = alarms.AlarmCursor(start_after=1762499000)
    events = alarms.collect("sim", ALERTS, HOSTS, cursor)
    assert [e.event_type for e in events] == ["ERROR_EVENT", "CUSTOM_INFO", "CUSTOM_INFO"]
    host_event, vm_event, storage_event = events
    assert host_event.title == "Sangfor HCI: Storage private network abnormal"
    assert host_event.entity_selector == 'type("sangfor_hci:host"),entityName.equals("sim / node-b")'
    assert host_event.start_ms == 1762500000000
    assert host_event.properties["sangfor.log_id"] == "host-00e0ec000b12:1001:1762500000:1"
    assert host_event.properties["sangfor.host.name"] == "node-b"
    assert vm_event.entity_selector == 'type("sangfor_hci:vm"),entityName.equals("sim / app-01 (1774086864344)")'
    assert storage_event.entity_selector == 'type("sangfor_hci:cluster"),entityName.equals("sim")'
    assert storage_event.properties["sangfor.object.name"] == "nfs-backup"
    assert "sangfor.host.name" not in storage_event.properties
    assert alarms.collect("sim", ALERTS, HOSTS, cursor) == []


def test_alarms_older_than_cursor_are_ignored():
    cursor = alarms.AlarmCursor(start_after=1762500100)
    events = alarms.collect("sim", ALERTS, HOSTS, cursor)
    assert [e.properties["sangfor.log_id"] for e in events] == ["cluster:1003:1762500120:3"]


def test_cursor_capacity_is_bounded():
    cursor = alarms.AlarmCursor(start_after=0, capacity=2)
    for log_id in ("a", "b", "c"):
        cursor.remember(log_id)
    assert cursor.is_new("a", 1) is True
    assert cursor.is_new("c", 1) is False


def test_alarms_tolerate_garbage():
    cursor = alarms.AlarmCursor(start_after=0)
    assert alarms.collect("sim", None, HOSTS, cursor) == []
    assert alarms.collect("sim", {"data": [{"log_id": "x"}, "junk"]}, HOSTS, cursor) == []
