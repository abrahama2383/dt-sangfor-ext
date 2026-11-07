import json
from pathlib import Path

import pytest
import yaml

from sangfor_hci import model
from sangfor_hci.config import parse_endpoint
from sangfor_hci.runner import FEATURE_SETS, ClusterRunner

ROOT = Path(__file__).resolve().parents[2]
EXT = yaml.safe_load((ROOT / "extension" / "extension.yaml").read_text(encoding="utf-8"))
SCHEMA = json.loads((ROOT / "extension" / "activationSchema.json").read_text(encoding="utf-8"))
DASHBOARD = json.loads((ROOT / "extension" / "dashboards" / "sangfor-hci-overview.json").read_text(encoding="utf-8"))
ACTIVATION = json.loads((ROOT / "activation.json").read_text(encoding="utf-8"))

METADATA_KEYS = {m["key"] for m in EXT["metrics"]}
FEATURE_OF = {m["key"]: fs["featureSet"] for fs in EXT["python"]["featureSets"] for m in fs["metrics"]}
PREFIX_TO_SET = {"cluster.": "cluster", "host.": "host", "vm.": "vm", "datastore.": "datastore", "hw.": "hardware"}
ACTIVATION_KEYS = [
    "cluster_name", "mode", "interval_seconds", "vm_interval_seconds", "timeout_seconds",
    "api_url", "api_username", "api_password", "api_verify_tls", "api_ca_pem",
    "snmp_version", "snmp_port", "snmp_community", "snmp_v3_user", "snmp_v3_auth_protocol",
    "snmp_v3_auth_key", "snmp_v3_priv_protocol", "snmp_v3_priv_key", "snmp_v3_context_name", "snmp_nodes",
]


def test_identity():
    assert EXT["name"] == "custom:sangfor-hci"
    assert EXT["python"]["runtime"]["module"] == "sangfor_hci"
    assert EXT["dashboards"] == [{"path": "dashboards/sangfor-hci-overview.json"}]


def test_feature_sets_cover_every_data_metric_exactly_once():
    assert {fs["featureSet"] for fs in EXT["python"]["featureSets"]} == set(FEATURE_SETS)
    assert set(FEATURE_OF) <= METADATA_KEYS
    for key in METADATA_KEYS:
        short = key[len(model.PREFIX):]
        if short.startswith("ext."):
            assert key not in FEATURE_OF, key
        else:
            expected = next(s for p, s in PREFIX_TO_SET.items() if short.startswith(p))
            assert FEATURE_OF.get(key) == expected, key
    assert len(METADATA_KEYS) == 46


def test_every_metric_the_runner_emits_is_declared(mock_api, snmp_agents):
    base, _ = mock_api
    config = parse_endpoint({
        "cluster_name": "sim", "mode": "both", "timeout_seconds": 2,
        "api_url": base, "api_username": "dtmon", "api_password": "dtmon-pass",
        "snmp_version": "v2c", "snmp_nodes": ["10.0.0.11=127.0.0.1:11161", "10.0.0.12=127.0.0.1:11162"],
    })
    result = ClusterRunner(config, set(FEATURE_SETS)).run_cycle()
    emitted = {m.full_key for m in result.metrics}
    assert emitted - METADATA_KEYS == set()
    assert len(emitted) >= 40


def _render(pattern, dims):
    for key, value in dims.items():
        pattern = pattern.replace("{" + key + "}", value)
    return pattern


def test_instance_name_patterns_match_model_display_names():
    patterns = {t["name"]: t["rules"][0]["instanceNamePattern"] for t in EXT["topology"]["types"]}
    host = model.host_dims("sim", "10.0.0.11", "node-a")
    vm = model.vm_dims("sim", "17", "app-01", "10.0.0.11")
    ds = model.datastore_dims("sim", "d1", "local_a")
    assert _render(patterns[model.ENTITY_CLUSTER], model.cluster_dims("sim")) == "sim"
    assert _render(patterns[model.ENTITY_HOST], host) == model.host_display_name("sim", "node-a")
    assert _render(patterns[model.ENTITY_VM], vm) == model.vm_display_name("sim", "app-01", "17")
    assert _render(patterns[model.ENTITY_DATASTORE], ds) == model.datastore_display_name("sim", "local_a")


def test_activation_schema_has_every_config_key_and_secrets_are_secret():
    props = SCHEMA["types"]["dynatrace.datasource.python:sangfor_hci-endpoint"]["properties"]
    assert set(props) == set(ACTIVATION_KEYS)
    for key in ("api_password", "snmp_community", "snmp_v3_auth_key", "snmp_v3_priv_key"):
        assert props[key]["type"] == "secret", key


@pytest.mark.parametrize("tile", [t for t in DASHBOARD["tiles"] if t["tileType"] == "DATA_EXPLORER"], ids=lambda t: t["name"])
def test_dashboard_metrics_exist(tile):
    for query in tile["queries"]:
        assert query["metric"] in METADATA_KEYS


def test_dev_activation_is_valid():
    assert set(ACTIVATION["featureSets"]) == set(FEATURE_SETS)
    for endpoint in ACTIVATION["pythonRemote"]["endpoints"]:
        assert set(endpoint) <= set(ACTIVATION_KEYS)
        parse_endpoint(endpoint)
