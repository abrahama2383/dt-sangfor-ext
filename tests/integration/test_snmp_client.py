import pytest

from sangfor_hci.snmp import oids
from sangfor_hci.snmp.client import SnmpClient, SnmpError, SnmpTarget
from simulator.snmp_sim import CONTEXT, V3_AUTH_KEY, V3_PRIV_KEY, V3_USER


def v2c(port, community="sangfopub"):
    return SnmpClient(SnmpTarget("127.0.0.1", port, "v2c", timeout=1.0, community=community), retries=0)


def test_v2c_get_returns_strings_and_skips_missing(snmp_agents):
    client = v2c(snmp_agents["node-a"])
    values = client.get([oids.HOST_CPU.oid, oids.SYS_NAME, oids.BMC_VERSION + ".99"])
    assert values == {oids.HOST_CPU.oid: "0.12", oids.SYS_NAME: "node-a"}


def test_v3_get_with_auth_and_privacy(snmp_agents):
    target = SnmpTarget(
        "127.0.0.1",
        snmp_agents["node-a"],
        "v3",
        timeout=2.0,
        v3_user=V3_USER,
        v3_auth_protocol="SHA",
        v3_auth_key=V3_AUTH_KEY,
        v3_priv_protocol="AES128",
        v3_priv_key=V3_PRIV_KEY,
        v3_context_name=CONTEXT,
    )
    assert SnmpClient(target, retries=0).get([oids.HOST_MEMORY.oid]) == {oids.HOST_MEMORY.oid: "0.58"}


def test_walk_returns_only_the_subtree(snmp_agents):
    fan_table = next(t for t in oids.TABLES if t.name == "fan")
    rows = v2c(snmp_agents["node-a"]).walk(fan_table.entry)
    assert len(rows) == 6
    assert rows[f"{fan_table.entry}.2.2"] == "FAN2"
    assert all(oid.startswith(fan_table.entry + ".") for oid in rows)


def test_has_subtree(snmp_agents):
    assert v2c(snmp_agents["node-a"]).has_subtree(oids.ROOT) is True
    assert v2c(snmp_agents["bare"]).has_subtree(oids.ROOT) is False


def test_wrong_community_times_out_with_snmp_error(snmp_agents):
    with pytest.raises(SnmpError, match="127.0.0.1"):
        v2c(snmp_agents["node-a"], community="wrong").get([oids.SYS_DESCR])


def test_repr_hides_secrets():
    target = SnmpTarget("127.0.0.1", 161, "v3", timeout=1.0, community="c-secret", v3_auth_key="a-secret", v3_priv_key="p-secret")
    text = repr(target)
    assert "c-secret" not in text and "a-secret" not in text and "p-secret" not in text
