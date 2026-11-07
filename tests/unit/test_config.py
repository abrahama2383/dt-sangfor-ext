import pytest

from sangfor_hci.config import ConfigError, SnmpNode, parse_endpoint, parse_node

BASE = {
    "cluster_name": "sim",
    "mode": "both",
    "api_url": "https://10.0.0.10/",
    "api_username": "dtmon",
    "api_password": "secret-pass",
    "snmp_version": "v3",
    "snmp_v3_user": "dtmon",
    "snmp_v3_auth_key": "auth-key-123",
    "snmp_v3_priv_key": "priv-key-123",
}


def test_defaults_for_both_mode():
    config = parse_endpoint(BASE)
    assert config.cluster_name == "sim"
    assert config.mode == "both"
    assert config.interval_seconds == 60
    assert config.vm_interval_seconds == 300
    assert config.timeout_seconds == 10
    assert config.vm_every_n_cycles == 5
    assert config.uses_api and config.uses_snmp
    assert config.api.url == "https://10.0.0.10"
    assert config.api.verify_tls is True
    assert config.snmp.port == 161
    assert config.snmp.community == "sangfopub"
    assert config.snmp.v3_auth_protocol == "SHA"
    assert config.snmp.v3_priv_protocol == "AES128"
    assert config.snmp.v3_context_name == ""
    assert config.snmp.nodes == ()


def test_api_mode_has_no_snmp_section():
    config = parse_endpoint({**BASE, "mode": "api"})
    assert config.snmp is None
    assert not config.uses_snmp


def test_snmp_mode_requires_nodes_and_skips_api():
    with pytest.raises(ConfigError, match="snmp_nodes"):
        parse_endpoint({**BASE, "mode": "snmp"})
    config = parse_endpoint({**BASE, "mode": "snmp", "snmp_nodes": ["10.0.0.11"], "api_password": ""})
    assert config.api is None
    assert config.snmp.nodes == (SnmpNode("10.0.0.11", "10.0.0.11", 161),)


def test_parse_node_forms():
    assert parse_node("10.0.0.11", 161) == SnmpNode("10.0.0.11", "10.0.0.11", 161)
    assert parse_node("10.0.0.11:1161", 161) == SnmpNode("10.0.0.11", "10.0.0.11", 1161)
    assert parse_node(" 10.0.0.11=127.0.0.1:11161 ", 161) == SnmpNode("10.0.0.11", "127.0.0.1", 11161)
    assert parse_node("10.0.0.11=nat.example.com", 162) == SnmpNode("10.0.0.11", "nat.example.com", 162)
    with pytest.raises(ConfigError):
        parse_node("node-a", 161)
    with pytest.raises(ConfigError):
        parse_node("10.0.0.11:abc", 161)


@pytest.mark.parametrize(
    "override, message",
    [
        ({"cluster_name": " "}, "cluster_name"),
        ({"mode": "all"}, "mode"),
        ({"api_url": "10.0.0.10"}, "api_url"),
        ({"api_password": ""}, "api_password"),
        ({"interval_seconds": 5}, "interval_seconds"),
        ({"vm_interval_seconds": 30}, "vm_interval_seconds"),
        ({"snmp_version": "v1"}, "snmp_version"),
        ({"snmp_v3_auth_key": "short"}, "snmp_v3_auth_key"),
        ({"snmp_v3_priv_protocol": "AES999"}, "snmp_v3_priv_protocol"),
        ({"api_ca_pem": "not a certificate"}, "api_ca_pem"),
    ],
)
def test_invalid_values(override, message):
    with pytest.raises(ConfigError, match=message):
        parse_endpoint({**BASE, **override})


def test_priv_none_does_not_need_priv_key():
    config = parse_endpoint({**BASE, "snmp_v3_priv_protocol": "NONE", "snmp_v3_priv_key": ""})
    assert config.snmp.v3_priv_protocol == "NONE"


def test_repr_hides_secrets():
    text = repr(parse_endpoint({**BASE, "snmp_community": "my-community"}))
    for secret in ("secret-pass", "auth-key-123", "priv-key-123", "my-community"):
        assert secret not in text
