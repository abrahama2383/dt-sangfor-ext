from sangfor_hci import model


def test_parse_number_accepts_numbers_and_numeric_strings():
    assert model.parse_number(3) == 3.0
    assert model.parse_number(0.45) == 0.45
    assert model.parse_number("0.45") == 0.45
    assert model.parse_number("14318.61456") == 14318.61456
    assert model.parse_number("-3.4") == -3.4
    assert model.parse_number("52 C") == 52.0
    assert model.parse_number(True) == 1.0


def test_parse_number_returns_none_for_missing_or_text():
    assert model.parse_number(None) is None
    assert model.parse_number("") is None
    assert model.parse_number("Optimal") is None


def test_ratio_to_percent():
    assert model.ratio_to_percent("0.12") == 12.0
    assert model.ratio_to_percent(0.585) == 58.5
    assert model.ratio_to_percent(None) is None


def test_metric_list_skips_none_and_merges_dimensions():
    metrics = model.MetricList({"sangfor.cluster": "sim"})
    metrics.add("cluster.cpu.usage", 6.0)
    metrics.add("cluster.memory.usage", None)
    metrics.add("cluster.vms", 2.0, {"state": "on"})
    assert len(metrics) == 2
    assert metrics[0] == model.Metric("cluster.cpu.usage", 6.0, {"sangfor.cluster": "sim"})
    assert metrics[1].dimensions == {"sangfor.cluster": "sim", "state": "on"}
    assert metrics[1].full_key == "sangfor.hci.cluster.vms"


def test_dimension_builders():
    assert model.cluster_dims("sim") == {"sangfor.cluster": "sim"}
    assert model.host_dims("sim", "10.0.0.11", "node-a") == {
        "sangfor.cluster": "sim",
        "sangfor.host.ip": "10.0.0.11",
        "sangfor.host.name": "node-a",
    }
    assert model.host_dims("sim", "10.0.0.11", "")["sangfor.host.name"] == "10.0.0.11"
    assert model.vm_dims("sim", "17", "app-01", "10.0.0.11") == {
        "sangfor.cluster": "sim",
        "sangfor.vm.id": "17",
        "sangfor.vm.name": "app-01",
        "sangfor.host.ip": "10.0.0.11",
    }
    assert "sangfor.host.ip" not in model.vm_dims("sim", "17", "app-01", "")
    assert model.datastore_dims("sim", "ds1", "local_a") == {
        "sangfor.cluster": "sim",
        "sangfor.datastore.id": "ds1",
        "sangfor.datastore.name": "local_a",
    }


def test_display_names_and_selectors():
    assert model.host_display_name("sim", "node-a") == "sim / node-a"
    assert model.vm_display_name("sim", "app-01", "17") == "sim / app-01 (17)"
    assert model.datastore_display_name("sim", "local_a") == "sim / local_a"
    assert (
        model.entity_selector(model.ENTITY_HOST, "sim / node-a")
        == 'type("sangfor_hci:host"),entityName.equals("sim / node-a")'
    )
    assert (
        model.entity_selector(model.ENTITY_VM, 'a "quoted" ~vm')
        == 'type("sangfor_hci:vm"),entityName.equals("a ~"quoted~" ~~vm")'
    )


def test_as_dict():
    assert model.as_dict({"a": 1}) == {"a": 1}
    assert model.as_dict(None) == {}
    assert model.as_dict([1]) == {}
