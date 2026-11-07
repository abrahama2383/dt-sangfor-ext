import threading

import pytest

from sangfor_hci.api.client import SangforApiClient, SangforApiError
from sangfor_hci.config import SnmpNode, parse_endpoint
from sangfor_hci.runner import FEATURE_SETS, ClusterRunner, CycleResult, _ApiAborted, default_snmp_factory

NODES = ["10.0.0.11=127.0.0.1:11161", "10.0.0.12=127.0.0.1:11162"]


def make_config(api_url, **overrides):
    raw = {
        "cluster_name": "sim",
        "mode": "both",
        "interval_seconds": 60,
        "vm_interval_seconds": 300,
        "timeout_seconds": 2,
        "api_url": api_url,
        "api_username": "dtmon",
        "api_password": "dtmon-pass",
        "api_verify_tls": False,
        "snmp_version": "v2c",
        "snmp_community": "sangfopub",
        "snmp_nodes": NODES,
    }
    raw.update(overrides)
    return parse_endpoint(raw)


def fast_api(config):
    api = config.api
    return SangforApiClient(api.url, api.username, api.password, verify_tls=False, timeout=2.0, sleep=lambda s: None)


def make_runner(config, enabled=FEATURE_SETS):
    return ClusterRunner(config, set(enabled), api_factory=fast_api)


def keys(result):
    return {m.key for m in result.metrics}


def value(result, key, **dims):
    found = [m.value for m in result.metrics if m.key == key and all(m.dimensions.get(k) == v for k, v in dims.items())]
    assert len(found) == 1, (key, dims, found)
    return found[0]


def test_healthy_both_mode_collects_every_feature_set(mock_api, snmp_agents):
    base, _ = mock_api
    runner = make_runner(make_config(base))
    result = runner.run_cycle()
    assert result.problems == []
    for expected in (
        "cluster.cpu.usage",
        "host.cpu.usage",
        "host.uptime",
        "datastore.usage",
        "vm.cpu.usage",
        "hw.fan.ok",
        "hw.cpu.temperature",
        "ext.poll.duration",
    ):
        assert expected in keys(result), expected
    assert "ext.poll.errors" not in keys(result)
    assert value(result, "host.cpu.usage", **{"sangfor.host.ip": "10.0.0.11"}) == 12.0
    assert value(result, "hw.fan.ok", **{"sangfor.host.ip": "10.0.0.12", "sangfor.fan": "FAN2"}) == 0.0
    assert value(result, "hw.ssd.life", **{"sangfor.host.ip": "10.0.0.11"}) == 97.0
    hardware_names = {m.dimensions["sangfor.host.name"] for m in result.metrics if m.key.startswith("hw.")}
    assert hardware_names == {"node-a", "node-b"}
    assert len(result.events) == 3
    second = runner.run_cycle()
    assert second.events == []
    assert "vm.cpu.usage" not in keys(second)
    runner.close()


def test_vm_metrics_every_nth_cycle(mock_api):
    base, _ = mock_api
    runner = make_runner(make_config(base, mode="api"), enabled={"vm"})
    with_vms = [("vm.cpu.usage" in keys(runner.run_cycle())) for _ in range(6)]
    assert with_vms == [True, False, False, False, False, True]


def test_disabled_feature_sets_are_not_collected(mock_api, snmp_agents):
    base, _ = mock_api
    result = make_runner(make_config(base), enabled={"cluster"}).run_cycle()
    data_keys = {k for k in keys(result) if not k.startswith("ext.")}
    assert data_keys and all(k.startswith("cluster.") for k in data_keys)
    assert not [m for m in result.metrics if m.dimensions.get("source") == "snmp"]


@pytest.mark.parametrize("mock_api", ["host_offline"], indirect=True)
def test_host_offline(mock_api):
    base, _ = mock_api
    result = make_runner(make_config(base, mode="api")).run_cycle()
    assert value(result, "host.online", **{"sangfor.host.ip": "10.0.0.12"}) == 0.0
    assert value(result, "cluster.hosts", state="offline") == 1.0


@pytest.mark.parametrize("mock_api", ["datastore_90"], indirect=True)
def test_datastore_over_90(mock_api):
    base, _ = mock_api
    result = make_runner(make_config(base, mode="api")).run_cycle()
    assert value(result, "datastore.capacity_alert", **{"sangfor.datastore.name": "local_a"}) == 1.0


@pytest.mark.parametrize("mock_api", ["ticket_expired"], indirect=True)
def test_ticket_expired_recovers_with_one_relogin(mock_api):
    base, state = mock_api
    result = make_runner(make_config(base, mode="api")).run_cycle()
    assert result.problems == []
    assert state.login_count == 2


def test_node_without_private_mib_is_reported_and_skipped(mock_api, snmp_agents):
    base, _ = mock_api
    config = make_config(base, snmp_nodes=["10.0.0.11=127.0.0.1:11161", "10.0.0.12=127.0.0.1:11163"])
    result = make_runner(config).run_cycle()
    hardware_ips = {m.dimensions["sangfor.host.ip"] for m in result.metrics if m.key.startswith("hw.")}
    assert hardware_ips == {"10.0.0.11"}
    assert any("10.0.0.12" in p and "private MIB" in p for p in result.problems)
    assert "cluster.cpu.usage" in keys(result)


def test_wrong_password_logs_in_once_and_falls_back_to_snmp(mock_api, snmp_agents):
    base, state = mock_api
    result = make_runner(make_config(base, api_password="wrong")).run_cycle()
    assert state.requests.count("POST /vapi/json/access/ticket") == 1
    assert any(m.key == "ext.poll.errors" and m.dimensions["reason"] == "auth" for m in result.metrics)
    assert "cluster.cpu.usage" not in keys(result)
    assert value(result, "host.cpu.usage", **{"sangfor.host.ip": "10.0.0.12"}) == 31.0
    assert "hw.raid.ok" in keys(result)


def test_unreachable_api_falls_back_to_snmp(snmp_agents):
    result = make_runner(make_config("http://127.0.0.1:9")).run_cycle()
    reasons = {m.dimensions["reason"] for m in result.metrics if m.key == "ext.poll.errors"}
    assert reasons == {"timeout"}
    assert value(result, "host.memory.usage", **{"sangfor.host.ip": "10.0.0.11"}) == 58.0


def test_snmp_mode_names_hosts_from_sysname(snmp_agents):
    config = make_config("https://unused.invalid", mode="snmp")
    result = ClusterRunner(config, set(FEATURE_SETS)).run_cycle()
    assert result.problems == []
    names = {m.dimensions["sangfor.host.name"] for m in result.metrics if m.key == "host.cpu.usage"}
    assert names == {"node-a", "node-b"}
    assert not [k for k in keys(result) if k.startswith("cluster.")]


def test_snmp_nodes_default_to_api_hosts(mock_api):
    base, _ = mock_api
    runner = make_runner(make_config(base, snmp_nodes=[]), enabled={"cluster", "host"})
    assert runner.run_cycle().problems == []
    assert runner.snmp_nodes() == [SnmpNode("10.0.0.11", "10.0.0.11", 161), SnmpNode("10.0.0.12", "10.0.0.12", 161)]


def test_overlapping_cycle_is_skipped(mock_api):
    base, _ = mock_api
    runner = make_runner(make_config(base, mode="api"))
    runner._lock.acquire()
    try:
        assert runner.run_cycle().skipped is True
    finally:
        runner._lock.release()


class _WrappedApi:
    def __init__(self, real, deny_prefix, record=None):
        self._real = real
        self._deny_prefix = deny_prefix
        self.paths = record if record is not None else []

    def get(self, path, params=None):
        self.paths.append(path)
        if path.startswith(self._deny_prefix):
            raise SangforApiError("auth", "denied")
        return self._real.get(path, params)

    def close(self):
        self._real.close()


def test_unexpected_snmp_error_on_one_node_keeps_the_cycle(mock_api, snmp_agents):
    base, _ = mock_api
    config = make_config(base)

    def snmp_factory(cfg, node):
        if node.host_ip == "10.0.0.12":
            raise ValueError("community=sangfopub")  # an exception we did not raise, carrying a secret
        return default_snmp_factory(cfg, node)

    result = ClusterRunner(config, set(FEATURE_SETS), api_factory=fast_api, snmp_factory=snmp_factory).run_cycle()
    assert any(m.key == "hw.fan.ok" and m.dimensions["sangfor.host.ip"] == "10.0.0.11" for m in result.metrics)
    assert "cluster.cpu.usage" in keys(result)
    assert any(
        m.key == "ext.poll.errors" and m.dimensions["target"] == "10.0.0.12" and m.dimensions["reason"] == "unexpected"
        for m in result.metrics
    )
    assert not any("sangfopub" in problem for problem in result.problems)


def test_abort_after_host_list_keeps_api_authoritative_for_hosts(mock_api, snmp_agents):
    base, _ = mock_api
    config = make_config(base)
    runner = ClusterRunner(
        config,
        set(FEATURE_SETS),
        api_factory=lambda c: _WrappedApi(fast_api(c), "/vapi/json/vtpstorage/storelist"),
    )
    result = runner.run_cycle()
    for ip in ("10.0.0.11", "10.0.0.12"):
        value(result, "host.cpu.usage", **{"sangfor.host.ip": ip})
    assert "hw.raid.ok" in keys(result)
    assert any(m.key == "ext.poll.errors" and m.dimensions["reason"] == "auth" for m in result.metrics)


def test_abort_inside_node_info_stops_the_api_path(mock_api):
    base, _ = mock_api
    paths = []
    config = make_config(base, mode="api")
    runner = ClusterRunner(
        config,
        set(FEATURE_SETS),
        api_factory=lambda c: _WrappedApi(fast_api(c), "/vapi/json/nodes/", paths),
    )
    runner.run_cycle()
    for later in ("/vapi/json/vtpstorage/storelist", "/vapi/json/cluster/vms", "/vapi/json/log/alert/all"):
        assert later not in paths


class _GatedNodeApi:
    """node_info for h1 fails with auth at once; every other host blocks briefly, keeping its worker busy."""

    def __init__(self):
        self.ids = []
        self._gate = threading.Event()

    def get(self, path, params=None):
        host_id = path.split("/")[4]
        self.ids.append(host_id)
        if host_id == "h1":
            raise SangforApiError("auth", "denied")
        self._gate.wait(0.5)
        return {}

    def close(self):
        pass


def test_abort_inside_node_info_does_not_send_queued_requests():
    api = _GatedNodeApi()
    config = make_config("https://127.0.0.1:1", mode="api")
    runner = ClusterRunner(config, set(FEATURE_SETS), api_factory=lambda c: api)
    runner._hosts = {f"h{i}": None for i in range(8)}
    with pytest.raises(_ApiAborted):
        runner._fetch_node_infos(CycleResult())
    # 4 workers: h0-h3 are in flight when h1 aborts; h4-h7 must never be sent (each would retry a failed login).
    assert set(api.ids) <= {"h0", "h1", "h2", "h3"}
