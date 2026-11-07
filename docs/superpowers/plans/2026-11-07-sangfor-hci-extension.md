# Sangfor HCI Extension Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `custom:sangfor-hci`, a Dynatrace Managed Extensions 2.0 Python extension that monitors Sangfor HCI clusters through the REST API and SNMP. It ships with a local simulator and a read-only field validation kit.

**Architecture:**
- Each Sangfor cluster is one monitoring configuration. A `ClusterRunner` runs one polling cycle per configuration: API and SNMP clients fetch raw data, pure collector functions turn it into `Metric` and `Event` records, and only `emit.py` talks to the Dynatrace SDK.
- The simulator (a mock HTTPS API plus snmpsim agents) stands in for a real HCI in tests and during development.

**Tech Stack:** Python 3.14 for development (the code must stay 3.10-compatible), dt-extensions-sdk 1.11.3, requests 2.34.2, pysnmp 7.1.31, cryptography 50.0.2, pytest 9.2.0, snmpsim 1.2.2, pysmi 2.0.0.

**Spec:** `docs/superpowers/specs/2026-11-07-sangfor-hci-extension-design.md`

## Global Constraints

- Repo root: `~/Github/rifqifitriady/dt-sangfor-ext`. Run every command from the repo root.
- Dev interpreter: `/opt/homebrew/bin/python3.14`, in a venv at `.venv`. Use `.venv/bin/python`, `.venv/bin/pytest` and `.venv/bin/dt-sdk`.
- Code must run on Python 3.10 and 3.14:
  - Put `from __future__ import annotations` at the top of every module.
  - Do not use `StrEnum`, `tomllib`, `except*`, `typing.Self` or any other 3.11+ feature.
- Extension name `custom:sangfor-hci`; Python module `sangfor_hci`; metric key prefix `sangfor.hci.`; entity types `sangfor_hci:cluster`, `sangfor_hci:host`, `sangfor_hci:vm`, `sangfor_hci:datastore`.
- Runtime dependencies are exactly `dt-extensions-sdk==1.11.3`, `requests==2.34.2`, `pysnmp==7.1.31`, `cryptography==50.0.2`. Do not add others.
- Read-only toward Sangfor. The only non-GET call is the login `POST /vapi/json/access/ticket`.
- Never log, print or put into exception messages a password, community string or SNMP key.
- Never emit a synthetic zero for a missing or unparseable value. Skip that data point.
- The built package must be under 25 MB. Build with `dt-sdk build --only-extra-platforms -e manylinux2014_x86_64 -e win_amd64 -p 3.10 -p 3.14`.
- Signing certificates live in `~/.dynatrace/certificates`, never in the repo.
- Commit after every task. End every commit message with a blank line, then `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## File map

| Path | Responsibility |
|---|---|
| `setup.py`, `requirements-dev.txt`, `pytest.ini` | Packaging, dev environment, test config |
| `sangfor_hci/model.py` | `Metric`, `Event`, `MetricList`, number parsing, dimensions, display names, entity selectors |
| `sangfor_hci/config.py` | Activation endpoint dict → frozen `ClusterConfig` |
| `sangfor_hci/api/client.py` | Sangfor REST login (RSA), ticket handling, GET allowlist, retries, TLS |
| `sangfor_hci/snmp/oids.py` | Every Sangfor OID |
| `sangfor_hci/snmp/client.py` | Synchronous v2c/v3 get, walk and subtree probe on pysnmp 7 |
| `sangfor_hci/collectors/{cluster,host,vm,datastore,hardware,alarms}.py` | Pure transforms from raw data to metrics and events |
| `sangfor_hci/runner.py` | One polling cycle for one cluster; no SDK import |
| `sangfor_hci/emit.py` | The only module that calls `report_metric` / `report_dt_event` |
| `sangfor_hci/__main__.py` | `Extension` subclass: parses configs, schedules runners, returns status |
| `extension/extension.yaml`, `extension/activationSchema.json`, `extension/dashboards/sangfor-hci-overview.json` | Extension definition |
| `activation.json` | Dev activation pointing at the simulator |
| `simulator/fixtures/*.json`, `simulator/mock_api.py` | Mock Sangfor REST API |
| `simulator/snmp/{node-a,node-b,bare}/sangfopub.snmprec`, `simulator/snmp_sim.py` | Mock SNMP agents |
| `scripts/smoke_run.py`, `scripts/check_package.py` | `dt-sdk run` smoke test; package verification |
| `validation-kit/sangfor_probe.py` | Read-only probe of a real HCI, producing a redacted zip |
| `tests/unit/*`, `tests/integration/*`, `tests/conftest.py` | Tests |
| `README.md` | Operator and developer guide |

---

### Task 1: Dev environment, packaging and the shared model

**Files:**
- Create: `setup.py`, `requirements-dev.txt`, `pytest.ini`, `sangfor_hci/__init__.py`, `sangfor_hci/model.py`, `tests/__init__.py`, `tests/unit/__init__.py`, `tests/unit/test_model.py`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: nothing.
- Produces (`sangfor_hci/model.py`):
  - `PREFIX = "sangfor.hci."`
  - `ENTITY_CLUSTER`, `ENTITY_HOST`, `ENTITY_VM`, `ENTITY_DATASTORE` (str)
  - `Metric(key: str, value: float, dimensions: dict[str, str])` with property `full_key -> str`
  - `Event(event_type: str, title: str, entity_selector: str, start_ms: int, properties: dict[str, str])`
  - `MetricList(dims: dict[str, str])`, a `list` subclass with `.add(key: str, value: float | None, extra: dict[str, str] | None = None) -> None`
  - `parse_number(raw: object) -> float | None`
  - `ratio_to_percent(raw: object) -> float | None`
  - `as_dict(raw: object) -> dict`
  - `cluster_dims(cluster)`, `host_dims(cluster, ip, name)`, `vm_dims(cluster, vm_id, vm_name, host_ip)`, `datastore_dims(cluster, ds_id, ds_name)`, each returning `dict[str, str]`
  - `host_display_name(cluster, name)`, `vm_display_name(cluster, vm_name, vm_id)`, `datastore_display_name(cluster, name)`, each returning `str`
  - `entity_selector(entity_type: str, display_name: str) -> str`

- [ ] **Step 1: Create the venv and packaging files**

`setup.py`:

```python
from __future__ import annotations

from pathlib import Path

from setuptools import find_packages, setup


def find_version() -> str:
    version = "0.0.1"
    extension_yaml_path = Path(__file__).parent / "extension" / "extension.yaml"
    try:
        with open(extension_yaml_path, encoding="utf-8") as f:
            for line in f:
                if line.startswith("version"):
                    version = line.split(" ")[-1].strip().strip('"')
                    break
    except OSError:
        pass
    return version


setup(
    name="sangfor_hci",
    version=find_version(),
    description="Sangfor HCI monitoring for Dynatrace Managed (Extensions 2.0, Python)",
    author="Rifqi Fitriady",
    packages=find_packages(include=["sangfor_hci", "sangfor_hci.*"]),
    python_requires=">=3.10",
    include_package_data=True,
    install_requires=[
        "dt-extensions-sdk==1.11.3",
        "requests==2.34.2",
        "pysnmp==7.1.31",
        "cryptography==50.0.2",
    ],
    extras_require={"dev": ["dt-extensions-sdk[cli]==1.11.3"]},
)
```

`requirements-dev.txt`:

```
-e .
dt-extensions-sdk[cli]==1.11.3
pytest==9.2.0
snmpsim==1.2.2
pysmi==2.0.0
```

`pytest.ini`:

```ini
[pytest]
testpaths = tests
pythonpath = .
addopts = -q
```

Append to `.gitignore`:

```
# Local development
.pytest_cache/
simulator/.certs/
secrets.json
validation-output/
*.log
```

`sangfor_hci/__init__.py`, `tests/__init__.py` and `tests/unit/__init__.py` are empty files.

Run:

```bash
uv venv -p /opt/homebrew/bin/python3.14 .venv
uv pip install -p .venv/bin/python -r requirements-dev.txt
.venv/bin/python -c "import dynatrace_extension, pysnmp, snmpsim, cryptography, requests; print('ok')"
```

Expected: `ok`

- [ ] **Step 2: Write the failing tests**

`tests/unit/test_model.py`:

```python
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
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `.venv/bin/pytest tests/unit/test_model.py`
Expected: FAIL with `ImportError: cannot import name 'model'` or `ModuleNotFoundError`.

- [ ] **Step 4: Implement `sangfor_hci/model.py`**

```python
"""Shared data types and helpers. No I/O and no Dynatrace SDK imports."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

PREFIX = "sangfor.hci."

ENTITY_CLUSTER = "sangfor_hci:cluster"
ENTITY_HOST = "sangfor_hci:host"
ENTITY_VM = "sangfor_hci:vm"
ENTITY_DATASTORE = "sangfor_hci:datastore"

_NUMBER = re.compile(r"-?[0-9]+(?:\.[0-9]+)?")


@dataclass(frozen=True)
class Metric:
    key: str  # without PREFIX, e.g. "host.cpu.usage"
    value: float
    dimensions: dict[str, str] = field(default_factory=dict)

    @property
    def full_key(self) -> str:
        return PREFIX + self.key


@dataclass(frozen=True)
class Event:
    event_type: str  # "ERROR_EVENT" or "CUSTOM_INFO"
    title: str
    entity_selector: str
    start_ms: int
    properties: dict[str, str] = field(default_factory=dict)


class MetricList(list):
    """A list of Metric that shares base dimensions and drops missing values."""

    def __init__(self, dims: dict[str, str]):
        super().__init__()
        self._dims = dict(dims)

    def add(self, key: str, value: float | None, extra: dict[str, str] | None = None) -> None:
        if value is None:
            return
        self.append(Metric(key, float(value), {**self._dims, **(extra or {})}))


def parse_number(raw: object) -> float | None:
    """Sangfor sends numbers as JSON numbers or as strings such as "0.45"."""
    if raw is None:
        return None
    if isinstance(raw, (int, float)):
        return float(raw)
    match = _NUMBER.search(str(raw))
    return float(match.group(0)) if match else None


def ratio_to_percent(raw: object) -> float | None:
    value = parse_number(raw)
    return None if value is None else round(value * 100.0, 4)


def as_dict(raw: object) -> dict:
    return raw if isinstance(raw, dict) else {}


def cluster_dims(cluster: str) -> dict[str, str]:
    return {"sangfor.cluster": cluster}


def host_dims(cluster: str, ip: str, name: str) -> dict[str, str]:
    return {"sangfor.cluster": cluster, "sangfor.host.ip": ip, "sangfor.host.name": name or ip}


def vm_dims(cluster: str, vm_id: str, vm_name: str, host_ip: str) -> dict[str, str]:
    dims = {"sangfor.cluster": cluster, "sangfor.vm.id": vm_id, "sangfor.vm.name": vm_name or vm_id}
    if host_ip:
        dims["sangfor.host.ip"] = host_ip
    return dims


def datastore_dims(cluster: str, ds_id: str, ds_name: str) -> dict[str, str]:
    return {
        "sangfor.cluster": cluster,
        "sangfor.datastore.id": ds_id,
        "sangfor.datastore.name": ds_name or ds_id,
    }


# These must stay identical to instanceNamePattern in extension/extension.yaml.
def host_display_name(cluster: str, name: str) -> str:
    return f"{cluster} / {name}"


def vm_display_name(cluster: str, vm_name: str, vm_id: str) -> str:
    return f"{cluster} / {vm_name} ({vm_id})"


def datastore_display_name(cluster: str, name: str) -> str:
    return f"{cluster} / {name}"


def entity_selector(entity_type: str, display_name: str) -> str:
    escaped = display_name.replace("~", "~~").replace('"', '~"')
    return f'type("{entity_type}"),entityName.equals("{escaped}")'
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `.venv/bin/pytest tests/unit/test_model.py`
Expected: `7 passed`

- [ ] **Step 6: Commit**

```bash
git add setup.py requirements-dev.txt pytest.ini .gitignore sangfor_hci tests
git commit -m "feat: add packaging, dev environment and shared model

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Monitoring configuration parsing

**Files:**
- Create: `sangfor_hci/config.py`, `tests/unit/test_config.py`

**Interfaces:**
- Consumes: nothing.
- Produces (`sangfor_hci/config.py`):
  - `ConfigError(ValueError)`
  - `ApiConfig(url, username, password, verify_tls: bool, ca_pem: str)`
  - `SnmpNode(host_ip: str, address: str, port: int)`
  - `SnmpConfig(version, port, community, v3_user, v3_auth_protocol, v3_auth_key, v3_priv_protocol, v3_priv_key, v3_context_name, nodes: tuple[SnmpNode, ...])`
  - `ClusterConfig(cluster_name, mode, interval_seconds, vm_interval_seconds, timeout_seconds, api: ApiConfig | None, snmp: SnmpConfig | None)` with properties `uses_api`, `uses_snmp` and `vm_every_n_cycles -> int`
  - `parse_node(entry: str, default_port: int) -> SnmpNode`
  - `parse_endpoint(raw: dict) -> ClusterConfig`
- Activation keys read (flat): `cluster_name`, `mode`, `interval_seconds`, `vm_interval_seconds`, `timeout_seconds`, `api_url`, `api_username`, `api_password`, `api_verify_tls`, `api_ca_pem`, `snmp_version`, `snmp_port`, `snmp_community`, `snmp_v3_user`, `snmp_v3_auth_protocol`, `snmp_v3_auth_key`, `snmp_v3_priv_protocol`, `snmp_v3_priv_key`, `snmp_v3_context_name`, `snmp_nodes`.

- [ ] **Step 1: Write the failing tests**

`tests/unit/test_config.py`:

```python
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/pytest tests/unit/test_config.py`
Expected: FAIL with `ModuleNotFoundError: No module named 'sangfor_hci.config'`.

- [ ] **Step 3: Implement `sangfor_hci/config.py`**

```python
"""Turns one activation-config endpoint into a validated, frozen ClusterConfig."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

MODES = ("api", "snmp", "both")
SNMP_VERSIONS = ("v2c", "v3")
AUTH_PROTOCOLS = ("MD5", "SHA", "SHA256")
PRIV_PROTOCOLS = ("NONE", "DES", "AES128", "AES256")


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class ApiConfig:
    url: str
    username: str
    password: str = field(repr=False)
    verify_tls: bool = True
    ca_pem: str = field(default="", repr=False)


@dataclass(frozen=True)
class SnmpNode:
    host_ip: str  # identity: the host's management IP
    address: str  # where to poll
    port: int


@dataclass(frozen=True)
class SnmpConfig:
    version: str
    port: int
    community: str = field(repr=False)
    v3_user: str
    v3_auth_protocol: str
    v3_auth_key: str = field(repr=False)
    v3_priv_protocol: str
    v3_priv_key: str = field(repr=False)
    v3_context_name: str
    nodes: tuple[SnmpNode, ...]


@dataclass(frozen=True)
class ClusterConfig:
    cluster_name: str
    mode: str
    interval_seconds: int
    vm_interval_seconds: int
    timeout_seconds: int
    api: ApiConfig | None
    snmp: SnmpConfig | None

    @property
    def uses_api(self) -> bool:
        return self.mode in ("api", "both")

    @property
    def uses_snmp(self) -> bool:
        return self.mode in ("snmp", "both")

    @property
    def vm_every_n_cycles(self) -> int:
        return max(1, round(self.vm_interval_seconds / self.interval_seconds))


def parse_endpoint(raw: dict) -> ClusterConfig:
    name = _text(raw, "cluster_name")
    if not name:
        raise ConfigError("cluster_name is required")
    mode = _text(raw, "mode", "both").lower()
    if mode not in MODES:
        raise ConfigError(f"mode must be one of {', '.join(MODES)}, got '{mode}'")
    interval = _int(raw, "interval_seconds", 60, minimum=10)
    vm_interval = _int(raw, "vm_interval_seconds", 300, minimum=interval)
    timeout = _int(raw, "timeout_seconds", 10, minimum=1)
    api = _parse_api(raw) if mode in ("api", "both") else None
    snmp = _parse_snmp(raw, mode) if mode in ("snmp", "both") else None
    return ClusterConfig(name, mode, interval, vm_interval, timeout, api, snmp)


def parse_node(entry: str, default_port: int) -> SnmpNode:
    text = str(entry).strip()
    if "=" in text:
        ip, target = (part.strip() for part in text.split("=", 1))
    else:
        ip, target = text, text
    address, port = target, default_port
    if ":" in target:
        address, port_text = target.rsplit(":", 1)
        if not port_text.isdigit():
            raise ConfigError(f"snmp_nodes entry '{entry}' has an invalid port")
        port = int(port_text)
    if "=" not in text:
        ip = address  # "IP" or "IP:PORT": identity and poll address are the same
    try:
        ipaddress.IPv4Address(ip)
    except ValueError as exc:
        raise ConfigError(f"snmp_nodes entry '{entry}' must start with the host's IPv4 address") from exc
    if not address:
        raise ConfigError(f"snmp_nodes entry '{entry}' has no address")
    return SnmpNode(host_ip=ip, address=address, port=port)


def _parse_api(raw: dict) -> ApiConfig:
    url = _text(raw, "api_url").rstrip("/")
    if not url.startswith(("https://", "http://")):
        raise ConfigError("api_url must start with https:// (or http:// for the simulator)")
    username = _text(raw, "api_username")
    if not username:
        raise ConfigError("api_username is required in api and both modes")
    password = str(raw.get("api_password") or "")
    if not password:
        raise ConfigError("api_password is required in api and both modes")
    ca_pem = _text(raw, "api_ca_pem")
    if ca_pem and "BEGIN CERTIFICATE" not in ca_pem:
        raise ConfigError("api_ca_pem must be a PEM certificate (-----BEGIN CERTIFICATE-----)")
    verify = raw.get("api_verify_tls", True)
    return ApiConfig(url, username, password, bool(True if verify is None else verify), ca_pem)


def _parse_snmp(raw: dict, mode: str) -> SnmpConfig:
    version = _text(raw, "snmp_version", "v3").lower()
    if version not in SNMP_VERSIONS:
        raise ConfigError(f"snmp_version must be one of {', '.join(SNMP_VERSIONS)}, got '{version}'")
    port = _int(raw, "snmp_port", 161, minimum=1)
    community = str(raw.get("snmp_community") or "sangfopub")
    user = _text(raw, "snmp_v3_user")
    auth_protocol = _text(raw, "snmp_v3_auth_protocol", "SHA").upper()
    auth_key = str(raw.get("snmp_v3_auth_key") or "")
    priv_protocol = _text(raw, "snmp_v3_priv_protocol", "AES128").upper()
    priv_key = str(raw.get("snmp_v3_priv_key") or "")
    if version == "v3":
        if not user:
            raise ConfigError("snmp_v3_user is required for SNMP v3")
        if auth_protocol not in AUTH_PROTOCOLS:
            raise ConfigError(f"snmp_v3_auth_protocol must be one of {', '.join(AUTH_PROTOCOLS)}")
        if len(auth_key) < 8:
            raise ConfigError("snmp_v3_auth_key must be at least 8 characters")
        if priv_protocol not in PRIV_PROTOCOLS:
            raise ConfigError(f"snmp_v3_priv_protocol must be one of {', '.join(PRIV_PROTOCOLS)}")
        if priv_protocol != "NONE" and len(priv_key) < 8:
            raise ConfigError("snmp_v3_priv_key must be at least 8 characters")
    nodes = tuple(parse_node(entry, port) for entry in (raw.get("snmp_nodes") or []) if str(entry).strip())
    if mode == "snmp" and not nodes:
        raise ConfigError("snmp_nodes is required in snmp mode")
    return SnmpConfig(
        version=version,
        port=port,
        community=community,
        v3_user=user,
        v3_auth_protocol=auth_protocol,
        v3_auth_key=auth_key,
        v3_priv_protocol=priv_protocol,
        v3_priv_key=priv_key,
        v3_context_name=_text(raw, "snmp_v3_context_name"),
        nodes=nodes,
    )


def _text(raw: dict, key: str, default: str = "") -> str:
    value = raw.get(key)
    return default if value is None or str(value).strip() == "" else str(value).strip()


def _int(raw: dict, key: str, default: int, minimum: int) -> int:
    value = raw.get(key)
    if value is None or value == "":
        value = default
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{key} must be a whole number, got '{value}'") from exc
    if number < minimum:
        raise ConfigError(f"{key} must be at least {minimum}, got {number}")
    return number
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/bin/pytest tests/unit/test_config.py`
Expected: `16 passed`

- [ ] **Step 5: Commit**

```bash
git add sangfor_hci/config.py tests/unit/test_config.py
git commit -m "feat: parse and validate monitoring configurations

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Mock Sangfor REST API (simulator)

The mock speaks the real protocol from the Sangfor spec:
- RSA public key at `/vapi/json/public_key`.
- PKCS#1 v1.5-encrypted password posted form-encoded to `/vapi/json/access/ticket`.
- The ticket returned as the `LoginAuthCookie` cookie, plus a `CSRFPreventionToken` header.
- Responses shaped `{"success": 1, "data": ...}`.

The fixture values below are referenced by exact number in later tasks. Do not change them.

**Files:**
- Create: `simulator/__init__.py` (empty), `simulator/fixtures/overview.json`, `simulator/fixtures/host_list.json`, `simulator/fixtures/node_info.json`, `simulator/fixtures/vms.json`, `simulator/fixtures/storelist.json`, `simulator/fixtures/alerts.json`, `simulator/mock_api.py`, `tests/conftest.py`, `tests/integration/__init__.py` (empty), `tests/integration/test_mock_api.py`

**Interfaces:**
- Consumes: nothing from `sangfor_hci`. The mock uses `cryptography` directly.
- Produces (`simulator/mock_api.py`):
  - `SCENARIOS = ("healthy", "host_offline", "datastore_90", "ticket_expired")`
  - `load_fixtures() -> dict[str, object]`, keyed by file stem: `overview`, `host_list`, `node_info`, `vms`, `storelist`, `alerts`
  - `apply_scenario(fixtures: dict, scenario: str) -> dict`
  - `MockState`, with fields `scenario`, `username`, `password`, `fixtures`, `login_count: int`, `requests: list[str]` (e.g. `"GET /vapi/json/index/overview"`) and method `modulus_hex() -> str`
  - `make_server(host="127.0.0.1", port=0, scenario="healthy", username="dtmon", password="dtmon-pass", certfile=None, keyfile=None) -> tuple[ThreadingHTTPServer, MockState]`
  - `write_self_signed_cert(directory: Path) -> tuple[Path, Path]`, returning `(cert_path, key_path)`
- Produces (`tests/conftest.py`):
  - fixture `mock_api`, yielding `(base_url: str, state: MockState)`; plain HTTP; scenario via `@pytest.mark.parametrize("mock_api", [...], indirect=True)`
  - fixture `mock_api_tls`, yielding `(base_url: str, state: MockState, cert_pem: str)`

- [ ] **Step 1: Create the fixtures**

`simulator/fixtures/overview.json`:

```json
{
  "success": 1,
  "data": {
    "vm": {"on": 2, "off": 1, "cnt": 3},
    "stg": {"ratio": "0.09", "itl": 2, "used": 575881084928, "total": 6109322543104, "ext": 1, "cnt": 3},
    "cpu": {"ratio": "0.06", "used": "14318.61456", "total": "230400"},
    "mem": {"ratio": "0.41", "used": 219902325555, "total": 536870912000},
    "host": {"cnt": 2, "online": 2, "offline": 0}
  }
}
```

`simulator/fixtures/host_list.json`:

```json
{
  "success": 1,
  "data": [
    {"alert": "0", "master": 1, "cpu_ratio": "0.12", "status": 1, "ip": "10.0.0.11", "name": "node-a",
     "urgent": 0, "io_ratio": "0.03", "mem_ratio": "0.58", "id": "host-00e0ec000a11", "type": "h"},
    {"alert": "1", "master": 0, "cpu_ratio": "0.31", "status": 1, "ip": "10.0.0.12", "name": "node-b",
     "urgent": 0, "io_ratio": "0.10", "mem_ratio": "0.64", "id": "host-00e0ec000b12", "type": "h"}
  ],
  "total": 2
}
```

`simulator/fixtures/node_info.json` holds node data keyed by host id. The mock wraps each entry in `{"success": 1, "data": ...}`.

```json
{
  "host-00e0ec000a11": {"control_role": 2, "status": "on", "ip": "10.0.0.11", "hardware_type": "Sangfor aServer",
                        "os_version": "SANGFOR aCloud 6.10.0_R2 Build20251020", "uptime": 10511969, "running_vms": 2},
  "host-00e0ec000b12": {"control_role": 1, "status": "on", "ip": "10.0.0.12", "hardware_type": "Sangfor aServer",
                        "os_version": "SANGFOR aCloud 6.10.0_R2 Build20251020", "uptime": 864000, "running_vms": 0}
}
```

`simulator/fixtures/vms.json` has one group holding two VMs and one ungrouped VM, the same nesting the spec shows for `?group_type=group`:

```json
{
  "success": 1,
  "data": [
    {"owner": "admin@vtp", "name": "grp-app", "type": "group", "id": "61394df39524", "vm_num": 2, "data": [
      {"vmid": 1774086864344, "name": "app-01", "vmtype": "vm", "status": "running", "host": "host-00e0ec000a11",
       "hostname": "10.0.0.11", "groupname": "grp-app", "osname": "linux-oracle", "cpus": 2, "cpu_ratio": "0.03",
       "mem_ratio": "0.14", "mem_used": 2422394880, "mem_total": 17179869184, "disk_used": "7301444403",
       "disk_total": 85899345920, "diskread": 0, "diskwrite": 9830, "netin": 8148, "netout": 0, "ha": 1, "alert": "0"},
      {"vmid": 1774086864345, "name": "app-02", "vmtype": "vm", "status": "running", "host": "host-00e0ec000a11",
       "hostname": "10.0.0.11", "groupname": "grp-app", "osname": "linux-ubuntu", "cpus": 4, "cpu_ratio": "0.20",
       "mem_ratio": "0.50", "mem_used": 4294967296, "mem_total": 8589934592, "disk_used": "1000000000",
       "disk_total": 53687091200, "diskread": 2048, "diskwrite": 4096, "netin": 100, "netout": 200, "ha": 0, "alert": "0"}
    ]},
    {"vmid": 2000000000001, "name": "db-01", "vmtype": "vm", "status": "stopped", "host": "host-00e0ec000b12",
     "hostname": "10.0.0.12", "groupname": "", "osname": "windows", "cpus": 8, "cpu_ratio": "0", "mem_ratio": "0",
     "mem_used": 0, "mem_total": 34359738368, "disk_used": "5000000000", "disk_total": 214748364800,
     "diskread": 0, "diskwrite": 0, "netin": 0, "netout": 0, "ha": 1, "alert": "0"}
  ]
}
```

`simulator/fixtures/storelist.json`:

```json
{
  "success": 1,
  "data": {
    "virtual_storage": [],
    "fc": [],
    "iscsi": [],
    "local": [
      {"hosts": "1", "host_cnt": "1/1", "used_ratio": "35.57", "status": 1, "read_cnt": "0.33", "shared": 0,
       "id": "350014ee0aed9e86a_00e0ec000a11", "alert": "0", "active": 1, "write_ratio": "509777.92",
       "name": "local_a", "urgent": 0, "total": 1997159792640, "read_ratio": "1361.92", "avail": 1286765281280,
       "write_cnt": "44.67", "used": 710394511360, "type": "local", "nodes": "host-00e0ec000a11"},
      {"hosts": "1", "host_cnt": "1/1", "used_ratio": "2.39", "status": 1, "read_cnt": 0, "shared": 0,
       "id": "350014ee0aee30c88_00e0ec000b12", "alert": "0", "active": 1, "write_ratio": 139264,
       "name": "local_b", "urgent": 0, "total": 1997159792640, "read_ratio": 0, "avail": 1949327949824,
       "write_cnt": "10.67", "used": 47831842816, "type": "local", "nodes": "host-00e0ec000b12"}
    ],
    "nfs": [
      {"hosts": "2", "host_cnt": "2/2", "used_ratio": "25.00", "status": 1, "read_cnt": "1.5", "shared": 1,
       "id": "nfs_backup", "alert": "0", "active": 1, "write_ratio": "2048", "name": "nfs-backup", "urgent": 0,
       "total": 4000000000000, "read_ratio": "1024", "avail": 3000000000000, "write_cnt": "2.5",
       "used": 1000000000000, "type": "nfs", "nodes": "host-00e0ec000a11,host-00e0ec000b12"}
    ]
  }
}
```

`simulator/fixtures/alerts.json` copies the spec's nesting (`data.data[]`, string `urgent_type`):

```json
{
  "success": 1,
  "data": {
    "data": [
      {"object_type": "host", "status": 2, "hostid": "host-00e0ec000b12", "hostname": "10.0.0.12",
       "log_id": "host-00e0ec000b12:1001:1762500000:1", "object_id": "host-00e0ec000b12", "id": 5301,
       "urgent_type": "1", "description": "Host node-b (10.0.0.12) storage private network is abnormal",
       "end": 1762500000, "host": "10.0.0.12", "vm": "", "type": "Storage private network abnormal",
       "otype": "Host", "object_name": "node-b", "start": 1762500000, "mark_read": "0"},
      {"object_type": "vm", "status": 2, "hostid": "host-00e0ec000a11", "hostname": "10.0.0.11",
       "log_id": "host-00e0ec000a11:1002:1762500060:2", "object_id": "1774086864344", "id": 5302,
       "urgent_type": "0", "description": "VM app-01 memory usage 99.5% exceeds threshold 90.0%",
       "end": 1762500060, "host": "10.0.0.11", "vm": "1774086864344", "type": "VM memory alarm",
       "otype": "VM", "object_name": "app-01", "start": 1762500060, "mark_read": "0"},
      {"object_type": "storage", "status": 2, "hostid": "", "hostname": "",
       "log_id": "cluster:1003:1762500120:3", "object_id": "nfs_backup", "id": 5303,
       "urgent_type": "0", "description": "Datastore nfs-backup latency is high",
       "end": 1762500120, "host": "", "vm": "", "type": "Datastore latency alarm",
       "otype": "Storage", "object_name": "nfs-backup", "start": 1762500120, "mark_read": "0"}
    ],
    "total": 3
  }
}
```

- [ ] **Step 2: Write the failing tests**

`tests/conftest.py`:

```python
from __future__ import annotations

import threading

import pytest

from simulator.mock_api import make_server, write_self_signed_cert


def _serve(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


@pytest.fixture
def mock_api(request):
    scenario = getattr(request, "param", "healthy")
    server, state = make_server(scenario=scenario)
    _serve(server)
    yield f"http://127.0.0.1:{server.server_address[1]}", state
    server.shutdown()
    server.server_close()


@pytest.fixture
def mock_api_tls(tmp_path):
    cert, key = write_self_signed_cert(tmp_path)
    server, state = make_server(certfile=str(cert), keyfile=str(key))
    _serve(server)
    yield f"https://127.0.0.1:{server.server_address[1]}", state, cert.read_text()
    server.shutdown()
    server.server_close()
```

`tests/integration/test_mock_api.py`:

```python
import pytest
import requests
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def _login(base, state, password="dtmon-pass"):
    modulus = requests.get(f"{base}/vapi/json/public_key", timeout=5).json()["data"]
    key = rsa.RSAPublicNumbers(0x10001, int(modulus, 16)).public_key()
    encrypted = key.encrypt(password.encode(), padding.PKCS1v15()).hex()
    return requests.post(
        f"{base}/vapi/json/access/ticket", data={"username": "dtmon", "password": encrypted}, timeout=5
    )


def _auth_headers(response):
    data = response.json()["data"]
    return {"Cookie": f"LoginAuthCookie={data['ticket']}", "CSRFPreventionToken": data["CSRFPreventionToken"]}


def test_public_key_is_hex_modulus(mock_api):
    base, state = mock_api
    body = requests.get(f"{base}/vapi/json/public_key", timeout=5).json()
    assert body["success"] == 1
    assert body["data"] == state.modulus_hex()
    int(body["data"], 16)


def test_login_and_read_overview(mock_api):
    base, state = mock_api
    login = _login(base, state)
    assert login.status_code == 200
    overview = requests.get(f"{base}/vapi/json/index/overview", headers=_auth_headers(login), timeout=5).json()
    assert overview["data"]["vm"] == {"on": 2, "off": 1, "cnt": 3}
    assert state.login_count == 1


def test_wrong_password_is_rejected(mock_api):
    base, state = mock_api
    response = _login(base, state, password="wrong")
    assert response.status_code == 401
    assert response.json()["success"] == 0


def test_data_requires_ticket(mock_api):
    base, _ = mock_api
    response = requests.get(f"{base}/vapi/json/index/host_list", timeout=5)
    assert response.status_code == 401


def test_node_info_and_unknown_host(mock_api):
    base, state = mock_api
    headers = _auth_headers(_login(base, state))
    info = requests.get(f"{base}/vapi/json/nodes/host-00e0ec000a11/info", headers=headers, timeout=5).json()
    assert info["data"]["running_vms"] == 2
    missing = requests.get(f"{base}/vapi/json/nodes/host-nope/info", headers=headers, timeout=5)
    assert missing.status_code == 404


def test_alarm_start_times_are_fresh(mock_api):
    import time

    base, state = mock_api
    headers = _auth_headers(_login(base, state))
    alarms = requests.get(f"{base}/vapi/json/log/alert/all", headers=headers, timeout=5).json()["data"]["data"]
    assert len(alarms) == 3
    assert all(abs(a["start"] - time.time()) < 120 for a in alarms)


@pytest.mark.parametrize("mock_api", ["host_offline"], indirect=True)
def test_host_offline_scenario(mock_api):
    base, state = mock_api
    headers = _auth_headers(_login(base, state))
    hosts = requests.get(f"{base}/vapi/json/index/host_list", headers=headers, timeout=5).json()["data"]
    assert hosts[1]["status"] == 0


@pytest.mark.parametrize("mock_api", ["ticket_expired"], indirect=True)
def test_ticket_expired_scenario_rejects_first_ticket_once(mock_api):
    base, state = mock_api
    headers = _auth_headers(_login(base, state))
    first = requests.get(f"{base}/vapi/json/index/overview", headers=headers, timeout=5)
    assert first.status_code == 401
    headers = _auth_headers(_login(base, state))
    second = requests.get(f"{base}/vapi/json/index/overview", headers=headers, timeout=5)
    assert second.status_code == 200


def test_tls_server_serves_https(mock_api_tls):
    base, _, cert_pem = mock_api_tls
    assert "BEGIN CERTIFICATE" in cert_pem
    response = requests.get(f"{base}/vapi/json/public_key", verify=False, timeout=5)
    assert response.json()["success"] == 1
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `.venv/bin/pytest tests/integration/test_mock_api.py`
Expected: FAIL with `ModuleNotFoundError: No module named 'simulator.mock_api'`.

- [ ] **Step 4: Implement `simulator/mock_api.py`**

```python
"""Local stand-in for the Sangfor HCI REST API. For development and tests only.

Run:  .venv/bin/python -m simulator.mock_api --port 8443 --scenario healthy
"""

from __future__ import annotations

import argparse
import copy
import datetime
import ipaddress
import json
import secrets
import ssl
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

FIXTURES = Path(__file__).parent / "fixtures"
SCENARIOS = ("healthy", "host_offline", "datastore_90", "ticket_expired")


def load_fixtures() -> dict[str, object]:
    return {path.stem: json.loads(path.read_text(encoding="utf-8")) for path in sorted(FIXTURES.glob("*.json"))}


def apply_scenario(fixtures: dict, scenario: str) -> dict:
    data = copy.deepcopy(fixtures)
    now = int(time.time())
    for alarm in data["alerts"]["data"]["data"]:
        alarm["start"] = now - 30
        alarm["end"] = now - 30
    if scenario == "host_offline":
        data["host_list"]["data"][1]["status"] = 0
        data["overview"]["data"]["host"].update({"online": 1, "offline": 1})
    elif scenario == "datastore_90":
        datastore = data["storelist"]["data"]["local"][0]
        datastore["status"] = 0x0001 | 0x0100
        datastore["used"] = int(datastore["total"] * 0.93)
        datastore["avail"] = datastore["total"] - datastore["used"]
    return data


@dataclass
class MockState:
    scenario: str
    username: str
    password: str
    fixtures: dict
    private_key: rsa.RSAPrivateKey
    tickets: set[str] = field(default_factory=set)
    login_count: int = 0
    expire_next_ticket: bool = False
    requests: list[str] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def modulus_hex(self) -> str:
        return format(self.private_key.public_key().public_numbers().n, "x")

    def decrypt(self, hex_text: str) -> str:
        return self.private_key.decrypt(bytes.fromhex(hex_text), padding.PKCS1v15()).decode("utf-8")


class Handler(BaseHTTPRequestHandler):
    state: MockState  # bound per server by make_server

    def log_message(self, format, *args):  # noqa: A002 - keep test output quiet
        return

    def _send(self, status: int, body: object) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _ticket_ok(self) -> bool:
        ticket = ""
        for part in self.headers.get("Cookie", "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == "LoginAuthCookie":
                ticket = value
        csrf = self.headers.get("CSRFPreventionToken", "")
        with self.state.lock:
            if ticket not in self.state.tickets or csrf != f"csrf-{ticket}":
                return False
            if self.state.expire_next_ticket:
                self.state.expire_next_ticket = False
                self.state.tickets.discard(ticket)
                return False
            return True

    def do_POST(self):  # noqa: N802 - http.server naming
        path = urlparse(self.path).path
        self.state.requests.append(f"POST {path}")
        if path != "/vapi/json/access/ticket":
            return self._send(405, {"success": 0, "status": 405, "message": "method not allowed"})
        length = int(self.headers.get("Content-Length", "0"))
        form = parse_qs(self.rfile.read(length).decode("utf-8"))
        username = form.get("username", [""])[0]
        try:
            password = self.state.decrypt(form.get("password", [""])[0])
        except ValueError:
            password = None
        if username != self.state.username or password != self.state.password:
            return self._send(401, {"success": 0, "status": 401, "message": "invalid username or password"})
        ticket = secrets.token_hex(16)
        with self.state.lock:
            self.state.tickets.add(ticket)
            self.state.login_count += 1
            if self.state.scenario == "ticket_expired" and self.state.login_count == 1:
                self.state.expire_next_ticket = True
        data = {"ticket": ticket, "CSRFPreventionToken": f"csrf-{ticket}", "username": username}
        return self._send(200, {"success": 1, "data": data})

    def do_GET(self):  # noqa: N802 - http.server naming
        path = urlparse(self.path).path
        self.state.requests.append(f"GET {path}")
        if path == "/vapi/json/public_key":
            return self._send(200, {"success": 1, "data": self.state.modulus_hex()})
        if not self._ticket_ok():
            return self._send(401, {"success": 0, "status": 401, "message": "authentication failure"})
        fixtures = self.state.fixtures
        routes = {
            "/vapi/json/index/overview": "overview",
            "/vapi/json/index/host_list": "host_list",
            "/vapi/json/cluster/vms": "vms",
            "/vapi/json/vtpstorage/storelist": "storelist",
            "/vapi/json/log/alert/all": "alerts",
        }
        if path in routes:
            return self._send(200, fixtures[routes[path]])
        if path.startswith("/vapi/json/nodes/") and path.endswith("/info"):
            host_id = path[len("/vapi/json/nodes/") : -len("/info")]
            info = fixtures["node_info"].get(host_id)
            if info is None:
                return self._send(404, {"success": 0, "status": 404, "message": "no such host"})
            return self._send(200, {"success": 1, "data": info})
        return self._send(404, {"success": 0, "status": 404, "message": "not found"})


def make_server(
    host: str = "127.0.0.1",
    port: int = 0,
    scenario: str = "healthy",
    username: str = "dtmon",
    password: str = "dtmon-pass",
    certfile: str | None = None,
    keyfile: str | None = None,
) -> tuple[ThreadingHTTPServer, MockState]:
    if scenario not in SCENARIOS:
        raise ValueError(f"unknown scenario '{scenario}', expected one of {SCENARIOS}")
    state = MockState(
        scenario=scenario,
        username=username,
        password=password,
        fixtures=apply_scenario(load_fixtures(), scenario),
        private_key=rsa.generate_private_key(public_exponent=65537, key_size=2048),
    )
    handler = type("BoundHandler", (Handler,), {"state": state})
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    if certfile:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile, keyfile)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    return server, state


def write_self_signed_cert(directory: Path) -> tuple[Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sangfor-sim.local")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    directory.mkdir(parents=True, exist_ok=True)
    cert_path = directory / "sim-cert.pem"
    key_path = directory / "sim-key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
        )
    )
    return cert_path, key_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Mock Sangfor HCI REST API")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--scenario", choices=SCENARIOS, default="healthy")
    parser.add_argument("--no-tls", action="store_true", help="serve plain HTTP")
    args = parser.parse_args()
    certfile = keyfile = None
    if not args.no_tls:
        cert, key = write_self_signed_cert(Path(__file__).parent / ".certs")
        certfile, keyfile = str(cert), str(key)
    server, _ = make_server(port=args.port, scenario=args.scenario, certfile=certfile, keyfile=keyfile)
    scheme = "http" if args.no_tls else "https"
    print(f"Mock Sangfor API on {scheme}://127.0.0.1:{args.port} scenario={args.scenario} user=dtmon password=dtmon-pass")
    server.serve_forever()


if __name__ == "__main__":
    main()
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `.venv/bin/pytest tests/integration/test_mock_api.py`
Expected: `9 passed`

- [ ] **Step 6: Commit**

```bash
git add simulator tests/conftest.py tests/integration
git commit -m "feat: add mock Sangfor REST API simulator with scenarios

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Sangfor REST API client

**Files:**
- Create: `sangfor_hci/api/__init__.py` (empty), `sangfor_hci/api/client.py`, `tests/integration/test_api_client.py`

**Interfaces:**
- Consumes: `tests/conftest.py` fixtures `mock_api` and `mock_api_tls` (Task 3).
- Produces (`sangfor_hci/api/client.py`):
  - `ALLOWED_GET_PREFIXES: tuple[str, ...]`
  - `SangforApiError(Exception)` with attribute `reason: str`, one of `"auth"`, `"tls"`, `"timeout"`, `"http"`, `"parse"` or `"forbidden"`
  - `encrypt_password(password: str, modulus_hex: str) -> str` (hex ciphertext)
  - `SangforApiClient(base_url, username, password, *, verify_tls=True, ca_pem="", timeout=10.0, relogin_seconds=600.0, sleep=time.sleep, clock=time.monotonic)` with:
    - `.login() -> None`
    - `.get(path: str, params: dict | None = None) -> object` (returns the response's `data`)
    - `.close() -> None`
    - `.login_count: int`

- [ ] **Step 1: Write the failing tests**

`tests/integration/test_api_client.py`:

```python
import pytest
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from sangfor_hci.api.client import SangforApiClient, SangforApiError, encrypt_password


def _client(base, **kwargs):
    kwargs.setdefault("sleep", lambda seconds: None)
    return SangforApiClient(base, "dtmon", "dtmon-pass", timeout=2.0, **kwargs)


def test_encrypt_password_round_trip():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    modulus_hex = format(key.public_key().public_numbers().n, "x")
    ciphertext = encrypt_password("pässword", modulus_hex)
    assert key.decrypt(bytes.fromhex(ciphertext), padding.PKCS1v15()).decode() == "pässword"


def test_get_logs_in_once_and_returns_data(mock_api):
    base, state = mock_api
    client = _client(base)
    overview = client.get("/vapi/json/index/overview")
    hosts = client.get("/vapi/json/index/host_list")
    assert overview["host"]["online"] == 2
    assert [h["name"] for h in hosts] == ["node-a", "node-b"]
    assert client.login_count == 1
    assert state.requests.count("POST /vapi/json/access/ticket") == 1


def test_wrong_password_raises_auth(mock_api):
    base, _ = mock_api
    client = SangforApiClient(base, "dtmon", "wrong", sleep=lambda s: None)
    with pytest.raises(SangforApiError) as info:
        client.get("/vapi/json/index/overview")
    assert info.value.reason == "auth"
    assert "wrong" not in str(info.value)


def test_paths_outside_allowlist_are_refused_without_a_request(mock_api):
    base, state = mock_api
    client = _client(base)
    with pytest.raises(SangforApiError) as info:
        client.get("/vapi/json/cluster/vm/123/status/stop")
    assert info.value.reason == "forbidden"
    assert state.requests == []


@pytest.mark.parametrize("mock_api", ["ticket_expired"], indirect=True)
def test_rejected_ticket_triggers_one_relogin(mock_api):
    base, _ = mock_api
    client = _client(base)
    assert client.get("/vapi/json/index/overview")["vm"]["cnt"] == 3
    assert client.login_count == 2


def test_proactive_relogin_after_interval(mock_api):
    base, _ = mock_api
    now = [1000.0]
    client = _client(base, clock=lambda: now[0], relogin_seconds=600)
    client.get("/vapi/json/index/overview")
    now[0] += 599
    client.get("/vapi/json/index/overview")
    assert client.login_count == 1
    now[0] += 2
    client.get("/vapi/json/index/overview")
    assert client.login_count == 2


def test_unreachable_server_retries_then_raises_timeout():
    sleeps = []
    client = SangforApiClient("http://127.0.0.1:9", "dtmon", "dtmon-pass", timeout=1.0, sleep=sleeps.append)
    with pytest.raises(SangforApiError) as info:
        client.get("/vapi/json/index/overview")
    assert info.value.reason == "timeout"
    assert sleeps == [1.0, 3.0]


def test_http_error_body_raises_http(mock_api):
    base, _ = mock_api
    client = _client(base)
    with pytest.raises(SangforApiError) as info:
        client.get("/vapi/json/nodes/host-nope/info")
    assert info.value.reason == "http"


def test_tls_verification(mock_api_tls):
    base, _, cert_pem = mock_api_tls
    with pytest.raises(SangforApiError) as info:
        _client(base).get("/vapi/json/index/overview")
    assert info.value.reason == "tls"

    trusted = _client(base, ca_pem=cert_pem)
    assert trusted.get("/vapi/json/index/overview")["vm"]["on"] == 2
    trusted.close()

    insecure = _client(base, verify_tls=False)
    assert insecure.get("/vapi/json/index/overview")["vm"]["off"] == 1
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/pytest tests/integration/test_api_client.py`
Expected: FAIL with `ModuleNotFoundError: No module named 'sangfor_hci.api'`.

- [ ] **Step 3: Implement `sangfor_hci/api/client.py`**

```python
"""Read-only client for the Sangfor HCI REST API (/vapi/json).

Login (Sangfor API spec 2022-01-06): GET /vapi/json/public_key returns the RSA modulus as hex
(exponent 0x10001). The password is encrypted with RSA PKCS#1 v1.5 and posted form-encoded to
/vapi/json/access/ticket. The returned ticket is sent as the LoginAuthCookie cookie and the
CSRFPreventionToken as a header.
"""

from __future__ import annotations

import logging
import tempfile
import threading
import time
from pathlib import Path
from typing import Callable

import requests
import urllib3
from cryptography.hazmat.primitives.asymmetric import padding, rsa

log = logging.getLogger(__name__)

PUBLIC_KEY_PATH = "/vapi/json/public_key"
TICKET_PATH = "/vapi/json/access/ticket"
ALLOWED_GET_PREFIXES = (
    "/vapi/json/index/overview",
    "/vapi/json/index/host_list",
    "/vapi/json/nodes/",
    "/vapi/json/cluster/vms",
    "/vapi/json/vtpstorage/storelist",
    "/vapi/json/log/alert/all",
)
RSA_EXPONENT = 0x10001
RETRY_BACKOFF_SECONDS = (1.0, 3.0)


class SangforApiError(Exception):
    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason


def encrypt_password(password: str, modulus_hex: str) -> str:
    public_key = rsa.RSAPublicNumbers(RSA_EXPONENT, int(modulus_hex, 16)).public_key()
    return public_key.encrypt(password.encode("utf-8"), padding.PKCS1v15()).hex()


class SangforApiClient:
    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        *,
        verify_tls: bool = True,
        ca_pem: str = "",
        timeout: float = 10.0,
        relogin_seconds: float = 600.0,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._base = base_url.rstrip("/")
        self._username = username
        self._password = password
        self._timeout = timeout
        self._relogin_seconds = relogin_seconds
        self._sleep = sleep
        self._clock = clock
        self._session = requests.Session()
        self._ca_file: Path | None = None
        if ca_pem:
            handle = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False, encoding="utf-8")
            handle.write(ca_pem)
            handle.close()
            self._ca_file = Path(handle.name)
            self._session.verify = str(self._ca_file)
        else:
            self._session.verify = verify_tls
            if not verify_tls:
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                log.warning("TLS verification is disabled for %s", self._base)
        self._login_lock = threading.Lock()
        self._ticket = ""
        self._csrf = ""
        self._logged_in_at: float | None = None
        self.login_count = 0

    def login(self) -> None:
        modulus = self._request("GET", PUBLIC_KEY_PATH, authenticated=False)
        if not isinstance(modulus, str) or not modulus:
            raise SangforApiError("parse", "public_key response has no RSA modulus")
        try:
            encrypted = encrypt_password(self._password, modulus)
        except ValueError as exc:
            raise SangforApiError("auth", f"cannot encrypt the password with the server key: {exc}") from exc
        data = self._request(
            "POST", TICKET_PATH, authenticated=False, form={"username": self._username, "password": encrypted}
        )
        if not isinstance(data, dict) or not data.get("ticket"):
            raise SangforApiError("auth", "login response has no ticket")
        self._ticket = str(data["ticket"])
        self._csrf = str(data.get("CSRFPreventionToken", ""))
        self._logged_in_at = self._clock()
        self.login_count += 1

    def get(self, path: str, params: dict | None = None) -> object:
        if not path.startswith(ALLOWED_GET_PREFIXES):
            raise SangforApiError("forbidden", f"path is not in the read-only allowlist: {path}")
        with self._login_lock:
            if self._needs_login():
                self.login()
            ticket = self._ticket
        try:
            return self._request("GET", path, params=params)
        except SangforApiError as exc:
            if exc.reason != "auth":
                raise
            with self._login_lock:
                if self._ticket == ticket:
                    log.info("Sangfor rejected the ticket, logging in again")
                    self.login()
            return self._request("GET", path, params=params)

    def close(self) -> None:
        self._session.close()
        if self._ca_file is not None:
            self._ca_file.unlink(missing_ok=True)
            self._ca_file = None

    def _needs_login(self) -> bool:
        return self._logged_in_at is None or (self._clock() - self._logged_in_at) >= self._relogin_seconds

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict | None = None,
        form: dict | None = None,
        authenticated: bool = True,
    ) -> object:
        headers = {}
        if authenticated:
            headers = {"Cookie": f"LoginAuthCookie={self._ticket}", "CSRFPreventionToken": self._csrf}
        attempts = len(RETRY_BACKOFF_SECONDS) + 1
        for attempt in range(attempts):
            try:
                response = self._session.request(
                    method, self._base + path, params=params, data=form, headers=headers, timeout=self._timeout
                )
            except requests.exceptions.SSLError as exc:
                raise SangforApiError("tls", f"TLS verification failed for {self._base}: {exc}") from exc
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as exc:
                if attempt + 1 < attempts:
                    self._sleep(RETRY_BACKOFF_SECONDS[attempt])
                    continue
                raise SangforApiError("timeout", f"{method} {path} failed: {exc.__class__.__name__}") from exc
            if response.status_code >= 500 and attempt + 1 < attempts:
                self._sleep(RETRY_BACKOFF_SECONDS[attempt])
                continue
            return self._parse(response, method, path)
        raise AssertionError("unreachable")

    @staticmethod
    def _parse(response: requests.Response, method: str, path: str) -> object:
        try:
            body = response.json()
        except ValueError as exc:
            raise SangforApiError("parse", f"{method} {path}: HTTP {response.status_code}, body is not JSON") from exc
        status = body.get("status") if isinstance(body, dict) else None
        message = str(body.get("message", "")) if isinstance(body, dict) else ""
        if response.status_code in (401, 403) or status in (401, 403):
            raise SangforApiError("auth", f"{method} {path}: authentication rejected {message}".strip())
        if response.status_code >= 400 or not isinstance(body, dict) or body.get("success") != 1:
            raise SangforApiError("http", f"{method} {path}: HTTP {response.status_code} {message}".strip())
        return body.get("data")
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/bin/pytest tests/integration/test_api_client.py`
Expected: `9 passed`. The unreachable-server test finishes in about a second, because the injected `sleep` does not wait.

If `test_tls_verification` fails on the `ca_pem` branch with `CERTIFICATE_VERIFY_FAILED`, the issue is the simulator certificate, not the client. Check that `write_self_signed_cert` sets `BasicConstraints(ca=True)` and `KeyUsage(key_cert_sign=True)` exactly as in Task 3.

- [ ] **Step 5: Commit**

```bash
git add sangfor_hci/api tests/integration/test_api_client.py
git commit -m "feat: add read-only Sangfor REST API client with RSA login

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: SNMP OIDs, SNMP client and simulated SNMP agents

Verified on 2026-11-07 (spec F13):
- pysnmp 7.1.31 on Python 3.14 reads `OctetString` values from snmpsim 1.2.2 over v2c (community `sangfopub`) and over v3 (SHA/AES, context `sangfopub`).
- snmpsim needs `pysmi` installed; it is in `requirements-dev.txt`.

**Files:**
- Create: `sangfor_hci/snmp/__init__.py` (empty), `sangfor_hci/snmp/oids.py`, `sangfor_hci/snmp/client.py`, `simulator/snmp/node-a/sangfopub.snmprec`, `simulator/snmp/node-b/sangfopub.snmprec`, `simulator/snmp/bare/sangfopub.snmprec`, `simulator/snmp_sim.py`, `tests/unit/test_oids.py`, `tests/integration/test_snmp_client.py`
- Modify: `tests/conftest.py` (append the `snmp_agents` fixture)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces (`sangfor_hci/snmp/oids.py`):
  - `ROOT`, `SYS_DESCR`, `SYS_NAME`, `VERSION`, `BMC_IPMI_IP`, `BMC_IPMI_VERSION`, `BMC_VERSION` (str, dotted without a leading dot)
  - `Scalar(metric, oid, ratio: bool)`; constants `HOST_CPU`, `HOST_MEMORY`, `HOST_DISK`
  - `Column(metric, suffix, kind)`, where kind is one of `"number"`, `"status"` or `"gb"`
  - `Table(name, entry, name_column, columns)` with `.column_oid(suffix) -> str`
  - `TABLES: tuple[Table, ...]`
- Produces (`sangfor_hci/snmp/client.py`):
  - `SnmpError(Exception)`
  - `SnmpTarget(address, port, version, timeout, community="", v3_user="", v3_auth_protocol="SHA", v3_auth_key="", v3_priv_protocol="AES128", v3_priv_key="", v3_context_name="")`
  - `SnmpClient(target, retries=1)` with:
    - `.get(oids: list[str]) -> dict[str, str]`
    - `.walk(base_oid: str) -> dict[str, str]`
    - `.has_subtree(base_oid: str) -> bool`
- Produces (`simulator/snmp_sim.py`):
  - `V3_USER = "dtmon"`, `V3_AUTH_KEY = "dtmon-auth-key"`, `V3_PRIV_KEY = "dtmon-priv-key"`, `CONTEXT = "sangfopub"`
  - `start_agent(dataset: str, port: int) -> subprocess.Popen`
  - `load_snmprec(dataset: str) -> dict[str, str]`
- Produces (`tests/conftest.py`): session fixture `snmp_agents`, yielding `{"node-a": 11161, "node-b": 11162, "bare": 11163}`

- [ ] **Step 1: Create the SNMP datasets**

The lines must stay in OID order. Type `4` is OctetString: the values are strings, as F10 expects.

`simulator/snmp/node-a/sangfopub.snmprec`:

```
1.3.6.1.2.1.1.1.0|4|Linux node-a 5.10.0 SANGFOR aCloud
1.3.6.1.2.1.1.5.0|4|node-a
1.3.6.1.4.1.35047.3.2.1.1.0|4|6.10.0_R2 Build20251020
1.3.6.1.4.1.35047.3.2.1.2.1.1.0|4|0.12
1.3.6.1.4.1.35047.3.2.1.2.1.2.1.7.1|4|52
1.3.6.1.4.1.35047.3.2.1.2.1.2.1.7.2|4|55
1.3.6.1.4.1.35047.3.2.1.2.1.2.1.8.1|4|CPU0
1.3.6.1.4.1.35047.3.2.1.2.1.2.1.8.2|4|CPU1
1.3.6.1.4.1.35047.3.2.1.2.2.1.0|4|0.58
1.3.6.1.4.1.35047.3.2.1.2.3.1.0|4|0.41
1.3.6.1.4.1.35047.3.2.1.2.5.1.2.1|4|/
1.3.6.1.4.1.35047.3.2.1.2.5.1.2.2|4|/sf/data
1.3.6.1.4.1.35047.3.2.1.2.5.1.3.1|4|50.0
1.3.6.1.4.1.35047.3.2.1.2.5.1.3.2|4|800.0
1.3.6.1.4.1.35047.3.2.1.2.5.1.4.1|4|21.5
1.3.6.1.4.1.35047.3.2.1.2.5.1.4.2|4|300.0
1.3.6.1.4.1.35047.3.2.1.2.5.1.5.1|4|28.5
1.3.6.1.4.1.35047.3.2.1.2.5.1.5.2|4|500.0
1.3.6.1.4.1.35047.3.2.1.2.5.1.6.1|4|43
1.3.6.1.4.1.35047.3.2.1.2.5.1.6.2|4|37.5
1.3.6.1.4.1.35047.3.2.1.2.7.1.0|4|10.0.1.11
1.3.6.1.4.1.35047.3.2.1.2.7.2.0|4|2.0
1.3.6.1.4.1.35047.3.2.1.2.7.3.0|4|3.45.1
1.3.6.1.4.1.35047.3.2.1.2.12.1.3.1|4|eth4
1.3.6.1.4.1.35047.3.2.1.2.12.1.4.1|4|-2.1
1.3.6.1.4.1.35047.3.2.1.2.12.1.5.1|4|-3.4
1.3.6.1.4.1.35047.3.2.1.2.14.1.3.1|4|RAID1-sys
1.3.6.1.4.1.35047.3.2.1.2.14.1.5.1|4|Optimal
1.3.6.1.4.1.35047.3.2.1.2.16.1.2.1|4|FAN1
1.3.6.1.4.1.35047.3.2.1.2.16.1.2.2|4|FAN2
1.3.6.1.4.1.35047.3.2.1.2.16.1.3.1|4|5400
1.3.6.1.4.1.35047.3.2.1.2.16.1.3.2|4|5520
1.3.6.1.4.1.35047.3.2.1.2.16.1.4.1|4|ok
1.3.6.1.4.1.35047.3.2.1.2.16.1.4.2|4|ok
1.3.6.1.4.1.35047.3.2.1.2.18.1.4.1|4|SSD-0
1.3.6.1.4.1.35047.3.2.1.2.18.1.9.1|4|97
```

`simulator/snmp/node-b/sangfopub.snmprec` has a degraded RAID, a failed fan and a worn SSD, and no optical or BMC data:

```
1.3.6.1.2.1.1.1.0|4|Linux node-b 5.10.0 SANGFOR aCloud
1.3.6.1.2.1.1.5.0|4|node-b
1.3.6.1.4.1.35047.3.2.1.1.0|4|6.10.0_R2 Build20251020
1.3.6.1.4.1.35047.3.2.1.2.1.1.0|4|0.31
1.3.6.1.4.1.35047.3.2.1.2.1.2.1.7.1|4|61
1.3.6.1.4.1.35047.3.2.1.2.1.2.1.8.1|4|CPU0
1.3.6.1.4.1.35047.3.2.1.2.2.1.0|4|0.64
1.3.6.1.4.1.35047.3.2.1.2.3.1.0|4|0.47
1.3.6.1.4.1.35047.3.2.1.2.5.1.2.1|4|/
1.3.6.1.4.1.35047.3.2.1.2.5.1.3.1|4|50.0
1.3.6.1.4.1.35047.3.2.1.2.5.1.4.1|4|45.0
1.3.6.1.4.1.35047.3.2.1.2.5.1.5.1|4|5.0
1.3.6.1.4.1.35047.3.2.1.2.5.1.6.1|4|90
1.3.6.1.4.1.35047.3.2.1.2.14.1.3.1|4|RAID1-sys
1.3.6.1.4.1.35047.3.2.1.2.14.1.5.1|4|Degraded
1.3.6.1.4.1.35047.3.2.1.2.16.1.2.1|4|FAN1
1.3.6.1.4.1.35047.3.2.1.2.16.1.2.2|4|FAN2
1.3.6.1.4.1.35047.3.2.1.2.16.1.3.1|4|5300
1.3.6.1.4.1.35047.3.2.1.2.16.1.3.2|4|0
1.3.6.1.4.1.35047.3.2.1.2.16.1.4.1|4|ok
1.3.6.1.4.1.35047.3.2.1.2.16.1.4.2|4|failed
1.3.6.1.4.1.35047.3.2.1.2.18.1.4.1|4|SSD-0
1.3.6.1.4.1.35047.3.2.1.2.18.1.9.1|4|12
```

`simulator/snmp/bare/sangfopub.snmprec` stands for a node without the Sangfor private branch (the HCI 6.9.1 report, F9):

```
1.3.6.1.2.1.1.1.0|4|Linux node-b 5.10.0 SANGFOR aCloud
1.3.6.1.2.1.1.5.0|4|node-b
```

- [ ] **Step 2: Create `simulator/snmp_sim.py`**

```python
"""Starts snmpsim agents that pretend to be Sangfor HCI nodes.

Run:  .venv/bin/python -m simulator.snmp_sim
Agents: node-a on UDP 11161, node-b on 11162, bare (no private MIB) on 11163, all on 127.0.0.1.
v2c community "sangfopub". v3 user dtmon, SHA "dtmon-auth-key", AES "dtmon-priv-key", context "sangfopub".
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

DATA = Path(__file__).parent / "snmp"
V3_USER = "dtmon"
V3_AUTH_KEY = "dtmon-auth-key"
V3_PRIV_KEY = "dtmon-priv-key"
CONTEXT = "sangfopub"
DATASETS = ("node-a", "node-b", "bare")


def responder_path() -> str:
    return str(Path(sys.executable).parent / "snmpsim-command-responder")


def start_agent(dataset: str, port: int) -> subprocess.Popen:
    command = [
        responder_path(),
        f"--data-dir={DATA / dataset}",
        f"--agent-udpv4-endpoint=127.0.0.1:{port}",
        f"--v3-user={V3_USER}",
        f"--v3-auth-key={V3_AUTH_KEY}",
        "--v3-auth-proto=SHA",
        f"--v3-priv-key={V3_PRIV_KEY}",
        "--v3-priv-proto=AES",
    ]
    return subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def load_snmprec(dataset: str) -> dict[str, str]:
    values = {}
    for line in (DATA / dataset / "sangfopub.snmprec").read_text(encoding="utf-8").splitlines():
        if line.strip():
            oid, _type, value = line.split("|", 2)
            values[oid] = value
    return values


def main() -> None:
    parser = argparse.ArgumentParser(description="Simulated Sangfor HCI SNMP agents")
    parser.add_argument("--base-port", type=int, default=11161)
    args = parser.parse_args()
    processes = [start_agent(name, args.base_port + offset) for offset, name in enumerate(DATASETS)]
    for offset, name in enumerate(DATASETS):
        print(f"{name}: udp://127.0.0.1:{args.base_port + offset}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        for process in processes:
            process.terminate()


if __name__ == "__main__":
    main()
```

- [ ] **Step 3: Append the `snmp_agents` fixture to `tests/conftest.py`**

```python
import time

from simulator.snmp_sim import start_agent

SNMP_PORTS = {"node-a": 11161, "node-b": 11162, "bare": 11163}


def _wait_for_agent(port: int, deadline_seconds: float = 30.0) -> None:
    from sangfor_hci.snmp.client import SnmpClient, SnmpError, SnmpTarget
    from sangfor_hci.snmp.oids import SYS_DESCR

    client = SnmpClient(SnmpTarget("127.0.0.1", port, "v2c", timeout=1.0, community="sangfopub"), retries=0)
    end = time.monotonic() + deadline_seconds
    while time.monotonic() < end:
        try:
            if client.get([SYS_DESCR]):
                return
        except SnmpError:
            continue
    raise RuntimeError(f"snmpsim on UDP {port} did not answer within {deadline_seconds} s")


@pytest.fixture(scope="session")
def snmp_agents():
    processes = [start_agent(name, port) for name, port in SNMP_PORTS.items()]
    try:
        for port in SNMP_PORTS.values():
            _wait_for_agent(port)
        yield dict(SNMP_PORTS)
    finally:
        for process in processes:
            process.terminate()
            process.wait(timeout=10)
```

- [ ] **Step 4: Write the failing tests**

`tests/unit/test_oids.py`:

```python
from sangfor_hci.snmp import oids
from simulator.snmp_sim import load_snmprec


def test_root_is_sangfor_acloud():
    assert oids.ROOT == "1.3.6.1.4.1.35047.3.2.1"
    assert oids.HOST_CPU.oid == "1.3.6.1.4.1.35047.3.2.1.2.1.1.0"
    assert oids.HOST_MEMORY.oid == "1.3.6.1.4.1.35047.3.2.1.2.2.1.0"
    assert oids.HOST_DISK.oid == "1.3.6.1.4.1.35047.3.2.1.2.3.1.0"
    assert all(s.ratio for s in (oids.HOST_CPU, oids.HOST_MEMORY, oids.HOST_DISK))


def test_every_oid_exists_in_the_full_simulator_dataset():
    data = load_snmprec("node-a")
    for oid in (oids.SYS_DESCR, oids.SYS_NAME, oids.VERSION, oids.BMC_IPMI_IP, oids.BMC_IPMI_VERSION, oids.BMC_VERSION):
        assert oid in data, oid
    for scalar in (oids.HOST_CPU, oids.HOST_MEMORY, oids.HOST_DISK):
        assert scalar.oid in data, scalar.oid
    for table in oids.TABLES:
        assert f"{table.column_oid(table.name_column)}.1" in data, table.name
        for column in table.columns:
            assert f"{table.column_oid(column.suffix)}.1" in data, column.metric


def test_table_metrics_are_hardware_metrics_with_known_kinds():
    for table in oids.TABLES:
        for column in table.columns:
            assert column.metric.startswith("hw.")
            assert column.kind in ("number", "status", "gb")
```

`tests/integration/test_snmp_client.py`:

```python
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
```

- [ ] **Step 5: Run the tests to verify they fail**

Run: `.venv/bin/pytest tests/unit/test_oids.py tests/integration/test_snmp_client.py`
Expected: FAIL with `ModuleNotFoundError: No module named 'sangfor_hci.snmp'`.

- [ ] **Step 6: Implement `sangfor_hci/snmp/oids.py`**

```python
"""Sangfor aCloud private MIB (enterprise 35047). The single source of truth for OIDs.

Source: Zabbix community template Virtualization/Sangfor/template_hci (2025), whose item keys
carry the MIB object names (aCloudHostCpuUseRate and so on).
"""

from __future__ import annotations

from dataclasses import dataclass

ROOT = "1.3.6.1.4.1.35047.3.2.1"
SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
VERSION = f"{ROOT}.1.0"
BMC_IPMI_IP = f"{ROOT}.2.7.1.0"
BMC_IPMI_VERSION = f"{ROOT}.2.7.2.0"
BMC_VERSION = f"{ROOT}.2.7.3.0"


@dataclass(frozen=True)
class Scalar:
    metric: str
    oid: str
    ratio: bool  # True: Sangfor sends 0-1, report percent


HOST_CPU = Scalar("host.cpu.usage", f"{ROOT}.2.1.1.0", True)
HOST_MEMORY = Scalar("host.memory.usage", f"{ROOT}.2.2.1.0", True)
HOST_DISK = Scalar("hw.disk.usage", f"{ROOT}.2.3.1.0", True)


@dataclass(frozen=True)
class Column:
    metric: str
    suffix: str  # column number under the table entry
    kind: str  # "number" | "status" | "gb"


@dataclass(frozen=True)
class Table:
    name: str  # dimension becomes sangfor.<name>
    entry: str  # table entry OID
    name_column: str
    columns: tuple[Column, ...]

    def column_oid(self, suffix: str) -> str:
        return f"{self.entry}.{suffix}"


TABLES = (
    Table("cpu", f"{ROOT}.2.1.2.1", "8", (Column("hw.cpu.temperature", "7", "number"),)),
    Table(
        "fs",
        f"{ROOT}.2.5.1",
        "2",
        (
            Column("hw.fs.size", "3", "gb"),
            Column("hw.fs.used", "4", "gb"),
            Column("hw.fs.available", "5", "gb"),
            Column("hw.fs.usage", "6", "number"),
        ),
    ),
    Table(
        "port",
        f"{ROOT}.2.12.1",
        "3",
        (Column("hw.optical.tx.power", "4", "number"), Column("hw.optical.rx.power", "5", "number")),
    ),
    Table("raid", f"{ROOT}.2.14.1", "3", (Column("hw.raid.ok", "5", "status"),)),
    Table("fan", f"{ROOT}.2.16.1", "2", (Column("hw.fan.speed", "3", "number"), Column("hw.fan.ok", "4", "status"))),
    Table("ssd", f"{ROOT}.2.18.1", "4", (Column("hw.ssd.life", "9", "number"),)),
)
```

- [ ] **Step 7: Implement `sangfor_hci/snmp/client.py`**

```python
"""Synchronous SNMP v2c/v3 reads on pysnmp 7's asyncio API. One SnmpEngine per call."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    bulk_walk_cmd,
    get_cmd,
    next_cmd,
    usmAesCfb128Protocol,
    usmAesCfb256Protocol,
    usmDESPrivProtocol,
    usmHMAC192SHA256AuthProtocol,
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
    usmNoPrivProtocol,
)

_AUTH = {"MD5": usmHMACMD5AuthProtocol, "SHA": usmHMACSHAAuthProtocol, "SHA256": usmHMAC192SHA256AuthProtocol}
_PRIV = {
    "NONE": usmNoPrivProtocol,
    "DES": usmDESPrivProtocol,
    "AES128": usmAesCfb128Protocol,
    "AES256": usmAesCfb256Protocol,
}
_EMPTY_TYPES = ("NoSuchObject", "NoSuchInstance", "EndOfMibView", "Null")


class SnmpError(Exception):
    pass


@dataclass(frozen=True)
class SnmpTarget:
    address: str
    port: int
    version: str  # "v2c" | "v3"
    timeout: float
    community: str = field(default="", repr=False)
    v3_user: str = ""
    v3_auth_protocol: str = "SHA"
    v3_auth_key: str = field(default="", repr=False)
    v3_priv_protocol: str = "AES128"
    v3_priv_key: str = field(default="", repr=False)
    v3_context_name: str = ""


def _is_empty(value: object) -> bool:
    return type(value).__name__ in _EMPTY_TYPES


class SnmpClient:
    def __init__(self, target: SnmpTarget, retries: int = 1):
        self._target = target
        self._retries = retries

    def get(self, oids: list[str]) -> dict[str, str]:
        return asyncio.run(self._get(oids))

    def walk(self, base_oid: str) -> dict[str, str]:
        return asyncio.run(self._walk(base_oid))

    def has_subtree(self, base_oid: str) -> bool:
        return asyncio.run(self._has_subtree(base_oid))

    @property
    def _label(self) -> str:
        return f"{self._target.address}:{self._target.port}"

    def _auth(self):
        target = self._target
        if target.version == "v2c":
            return CommunityData(target.community, mpModel=1)
        priv = _PRIV[target.v3_priv_protocol]
        return UsmUserData(
            target.v3_user,
            authKey=target.v3_auth_key,
            privKey=None if priv is usmNoPrivProtocol else target.v3_priv_key,
            authProtocol=_AUTH[target.v3_auth_protocol],
            privProtocol=priv,
        )

    def _context(self) -> ContextData:
        if self._target.version == "v3" and self._target.v3_context_name:
            return ContextData(contextName=self._target.v3_context_name.encode("utf-8"))
        return ContextData()

    async def _transport(self) -> UdpTransportTarget:
        return await UdpTransportTarget.create(
            (self._target.address, self._target.port), timeout=self._target.timeout, retries=self._retries
        )

    def _check(self, error_indication, error_status, error_index) -> None:
        if error_indication:
            raise SnmpError(f"{self._label} {error_indication}")
        if error_status:
            raise SnmpError(f"{self._label} {error_status.prettyPrint()} at index {int(error_index)}")

    async def _get(self, oids: list[str]) -> dict[str, str]:
        engine = SnmpEngine()
        try:
            error_indication, error_status, error_index, var_binds = await get_cmd(
                engine,
                self._auth(),
                await self._transport(),
                self._context(),
                *[ObjectType(ObjectIdentity(oid)) for oid in oids],
            )
            self._check(error_indication, error_status, error_index)
            return {str(oid): value.prettyPrint() for oid, value in var_binds if not _is_empty(value)}
        finally:
            engine.close_dispatcher()

    async def _walk(self, base_oid: str) -> dict[str, str]:
        engine = SnmpEngine()
        result: dict[str, str] = {}
        try:
            async for error_indication, error_status, error_index, var_binds in bulk_walk_cmd(
                engine,
                self._auth(),
                await self._transport(),
                self._context(),
                0,
                25,
                ObjectType(ObjectIdentity(base_oid)),
                lexicographicMode=False,
            ):
                self._check(error_indication, error_status, error_index)
                for oid, value in var_binds:
                    if not _is_empty(value):
                        result[str(oid)] = value.prettyPrint()
            return result
        finally:
            engine.close_dispatcher()

    async def _has_subtree(self, base_oid: str) -> bool:
        engine = SnmpEngine()
        try:
            error_indication, error_status, error_index, var_binds = await next_cmd(
                engine, self._auth(), await self._transport(), self._context(), ObjectType(ObjectIdentity(base_oid))
            )
            if error_indication:
                raise SnmpError(f"{self._label} {error_indication}")
            if error_status:
                return False
            return any(str(oid).startswith(base_oid + ".") and not _is_empty(value) for oid, value in var_binds)
        finally:
            engine.close_dispatcher()
```

- [ ] **Step 8: Run the tests to verify they pass**

Run: `.venv/bin/pytest tests/unit/test_oids.py tests/integration/test_snmp_client.py`
Expected: `9 passed`. The first run takes up to about 10 s while snmpsim starts.

If `next_cmd` returns an async generator instead of a tuple in this pysnmp build, `test_has_subtree` fails with `TypeError: cannot unpack`. In that case, take the first item of `walk_cmd(..., lexicographicMode=False)` instead: iterate with `async for` and `break` after the first result.

- [ ] **Step 9: Commit**

```bash
git add sangfor_hci/snmp simulator/snmp simulator/snmp_sim.py tests
git commit -m "feat: add Sangfor SNMP OIDs, v2c/v3 client and simulated agents

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: Cluster, host and datastore collectors

Collectors are pure functions: raw `data` payloads from the API go in, and `Metric` lists come out. They do no I/O, and they never raise on missing or odd fields.

**Files:**
- Create: `sangfor_hci/collectors/__init__.py` (empty), `sangfor_hci/collectors/cluster.py`, `sangfor_hci/collectors/host.py`, `sangfor_hci/collectors/datastore.py`, `tests/unit/test_collectors_api.py`

**Interfaces:**
- Consumes: `sangfor_hci.model` (Task 1), and `simulator.mock_api.load_fixtures` in tests (Task 3).
- Produces:
  - `cluster.collect(cluster: str, overview: object) -> list[Metric]`
  - `host.HostInfo(host_id: str, ip: str, name: str, online: bool)`
  - `host.index(host_list: object) -> dict[str, HostInfo]`, keyed by host id
  - `host.collect(cluster: str, host_list: object, node_infos: dict[str, dict]) -> list[Metric]`
  - `datastore.collect(cluster: str, storelist: object) -> list[Metric]`

- [ ] **Step 1: Write the failing tests**

`tests/unit/test_collectors_api.py`:

```python
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/pytest tests/unit/test_collectors_api.py`
Expected: FAIL with `ModuleNotFoundError: No module named 'sangfor_hci.collectors'`.

- [ ] **Step 3: Implement `sangfor_hci/collectors/cluster.py`**

```python
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
```

- [ ] **Step 4: Implement `sangfor_hci/collectors/host.py`**

```python
"""GET /vapi/json/index/host_list and /vapi/json/nodes/{id}/info -> host metrics."""

from __future__ import annotations

from dataclasses import dataclass

from ..model import Metric, MetricList, as_dict, host_dims, parse_number, ratio_to_percent


@dataclass(frozen=True)
class HostInfo:
    host_id: str
    ip: str
    name: str
    online: bool


def _items(host_list: object) -> list[dict]:
    return [item for item in host_list if isinstance(item, dict)] if isinstance(host_list, list) else []


def index(host_list: object) -> dict[str, HostInfo]:
    hosts = {}
    for item in _items(host_list):
        host_id, ip = str(item.get("id") or ""), str(item.get("ip") or "")
        if host_id and ip:
            name = str(item.get("name") or ip)
            hosts[host_id] = HostInfo(host_id, ip, name, parse_number(item.get("status")) == 1)
    return hosts


def collect(cluster: str, host_list: object, node_infos: dict[str, dict]) -> list[Metric]:
    result: list[Metric] = []
    for item in _items(host_list):
        host_id, ip = str(item.get("id") or ""), str(item.get("ip") or "")
        if not host_id or not ip:
            continue
        node = as_dict(node_infos.get(host_id))
        dims = host_dims(cluster, ip, str(item.get("name") or ip))
        dims["sangfor.host.master"] = "true" if parse_number(item.get("master")) == 1 else "false"
        if node.get("os_version"):
            dims["sangfor.version"] = str(node["os_version"])
        metrics = MetricList(dims)
        metrics.add("host.cpu.usage", ratio_to_percent(item.get("cpu_ratio")))
        metrics.add("host.memory.usage", ratio_to_percent(item.get("mem_ratio")))
        metrics.add("host.io.usage", ratio_to_percent(item.get("io_ratio")))
        status = parse_number(item.get("status"))
        if status is not None:
            metrics.add("host.online", 1.0 if status == 1 else 0.0)
        alert = str(item.get("alert", "0")).strip()
        metrics.add("host.alarm", 0.0 if alert in ("", "0") else 1.0)
        metrics.add("host.uptime", parse_number(node.get("uptime")))
        metrics.add("host.vms.running", parse_number(node.get("running_vms")))
        result.extend(metrics)
    return result
```

- [ ] **Step 5: Implement `sangfor_hci/collectors/datastore.py`**

```python
"""GET /vapi/json/vtpstorage/storelist -> datastore metrics.

status is a set of flags (spec: 0x0001 online, 0x0010 some hosts cannot access, 0x0100 over 90%).
Whether these are hex masks or binary-digit notation is open question Q2; hex is assumed.
"""

from __future__ import annotations

from ..model import Metric, MetricList, as_dict, datastore_dims, parse_number

GROUPS = ("local", "iscsi", "fc", "nfs", "virtual_storage")
FLAG_ONLINE = 0x0001
FLAG_PARTIAL_ACCESS = 0x0010
FLAG_OVER_90 = 0x0100


def collect(cluster: str, storelist: object) -> list[Metric]:
    data = as_dict(storelist)
    result: list[Metric] = []
    for group in GROUPS:
        items = data.get(group)
        for item in items if isinstance(items, list) else []:
            if not isinstance(item, dict) or not item.get("id"):
                continue
            ds_id = str(item["id"])
            dims = datastore_dims(cluster, ds_id, str(item.get("name") or ds_id))
            dims["sangfor.datastore.type"] = str(item.get("type") or group)
            dims["sangfor.datastore.shared"] = "true" if parse_number(item.get("shared")) == 1 else "false"
            metrics = MetricList(dims)
            total, used = parse_number(item.get("total")), parse_number(item.get("used"))
            metrics.add("datastore.total", total)
            metrics.add("datastore.available", parse_number(item.get("avail")))
            if total and used is not None:
                metrics.add("datastore.usage", round(used / total * 100.0, 4))
            metrics.add("datastore.read.iops", parse_number(item.get("read_cnt")))
            metrics.add("datastore.write.iops", parse_number(item.get("write_cnt")))
            metrics.add("datastore.read.throughput", parse_number(item.get("read_ratio")))
            metrics.add("datastore.write.throughput", parse_number(item.get("write_ratio")))
            status = parse_number(item.get("status"))
            if status is not None:
                flags = int(status)
                metrics.add("datastore.online", 1.0 if flags & FLAG_ONLINE else 0.0)
                metrics.add("datastore.partial_access", 1.0 if flags & FLAG_PARTIAL_ACCESS else 0.0)
                metrics.add("datastore.capacity_alert", 1.0 if flags & FLAG_OVER_90 else 0.0)
            result.extend(metrics)
    return result
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `.venv/bin/pytest tests/unit/test_collectors_api.py`
Expected: `7 passed`

- [ ] **Step 7: Commit**

```bash
git add sangfor_hci/collectors tests/unit/test_collectors_api.py
git commit -m "feat: add cluster, host and datastore collectors

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: VM and alarm collectors

**Files:**
- Create: `sangfor_hci/collectors/vm.py`, `sangfor_hci/collectors/alarms.py`, `tests/unit/test_collectors_vm_alarms.py`

**Interfaces:**
- Consumes: `sangfor_hci.model` (Task 1); `host.HostInfo` and `host.index` (Task 6).
- Produces:
  - `vm.iter_vms(payload: object) -> Iterator[dict]`, which flattens nested groups
  - `vm.collect(cluster: str, payload: object, hosts: dict[str, HostInfo]) -> list[Metric]`
  - `alarms.EVENT_ERROR = "ERROR_EVENT"`, `alarms.EVENT_INFO = "CUSTOM_INFO"`
  - `alarms.AlarmCursor(start_after: int, capacity: int = 5000)` with:
    - `.is_new(log_id: str, start: int) -> bool`
    - `.remember(log_id: str) -> None`
  - `alarms.collect(cluster: str, payload: object, hosts: dict[str, HostInfo], cursor: AlarmCursor) -> list[Event]`

- [ ] **Step 1: Write the failing tests**

`tests/unit/test_collectors_vm_alarms.py`:

```python
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/pytest tests/unit/test_collectors_vm_alarms.py`
Expected: FAIL with `ImportError: cannot import name 'alarms'`.

- [ ] **Step 3: Implement `sangfor_hci/collectors/vm.py`**

```python
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
```

- [ ] **Step 4: Implement `sangfor_hci/collectors/alarms.py`**

```python
"""GET /vapi/json/log/alert/all -> Dynatrace events (spec §5.4).

The response nests alarms in data.data[]. urgent_type is a string ("1" means urgent).
Alarms are filtered client-side by start time and log_id, because the format of the
API's starttime filter is not documented.
"""

from __future__ import annotations

from collections import OrderedDict

from ..model import (
    ENTITY_CLUSTER,
    ENTITY_HOST,
    ENTITY_VM,
    Event,
    as_dict,
    entity_selector,
    host_display_name,
    parse_number,
    vm_display_name,
)
from .host import HostInfo

EVENT_ERROR = "ERROR_EVENT"
EVENT_INFO = "CUSTOM_INFO"


class AlarmCursor:
    def __init__(self, start_after: int, capacity: int = 5000):
        self.start_after = start_after
        self._capacity = capacity
        self._seen: OrderedDict[str, None] = OrderedDict()

    def is_new(self, log_id: str, start: int) -> bool:
        return log_id not in self._seen and start >= self.start_after

    def remember(self, log_id: str) -> None:
        self._seen[log_id] = None
        while len(self._seen) > self._capacity:
            self._seen.popitem(last=False)


def collect(cluster: str, payload: object, hosts: dict[str, HostInfo], cursor: AlarmCursor) -> list[Event]:
    items = as_dict(payload).get("data")
    alarms = [item for item in items if isinstance(item, dict)] if isinstance(items, list) else []
    events = []
    for item in sorted(alarms, key=lambda a: parse_number(a.get("start")) or 0):
        log_id = str(item.get("log_id") or "")
        start = parse_number(item.get("start"))
        if not log_id or start is None or not cursor.is_new(log_id, int(start)):
            continue
        cursor.remember(log_id)
        events.append(_to_event(cluster, item, hosts, log_id, int(start)))
    return events


def _to_event(cluster: str, item: dict, hosts: dict[str, HostInfo], log_id: str, start: int) -> Event:
    kind = str(item.get("type") or item.get("type_cn") or "alarm")
    object_type = str(item.get("object_type") or "")
    host = hosts.get(str(item.get("hostid") or ""))
    vm_id = str(item.get("vm") or item.get("object_id") or "")
    if object_type == "host" and host:
        selector = entity_selector(ENTITY_HOST, host_display_name(cluster, host.name))
    elif object_type == "vm" and vm_id:
        selector = entity_selector(ENTITY_VM, vm_display_name(cluster, str(item.get("object_name") or vm_id), vm_id))
    else:
        selector = entity_selector(ENTITY_CLUSTER, cluster)
    properties = {
        "sangfor.log_id": log_id,
        "sangfor.alert.type": kind,
        "sangfor.object.type": object_type,
        "sangfor.object.name": str(item.get("object_name") or ""),
        "sangfor.description": str(item.get("description") or ""),
        "sangfor.host.name": host.name if host else "",
    }
    urgent = str(item.get("urgent_type", "0")).strip() == "1"
    return Event(
        event_type=EVENT_ERROR if urgent else EVENT_INFO,
        title=f"Sangfor HCI: {kind}",
        entity_selector=selector,
        start_ms=start * 1000,
        properties={key: value for key, value in properties.items() if value},
    )
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `.venv/bin/pytest tests/unit/test_collectors_vm_alarms.py`
Expected: `7 passed`

- [ ] **Step 6: Commit**

```bash
git add sangfor_hci/collectors/vm.py sangfor_hci/collectors/alarms.py tests/unit/test_collectors_vm_alarms.py
git commit -m "feat: add VM and alarm collectors

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8: Hardware collector (SNMP)

The OK/not-OK strings for status columns are unknown (spec Q4). Values are classified in this order:
1. A known-good token such as `ok`, `normal` or `optimal` means OK (1).
2. A known-bad token such as `failed`, `degraded` or `error` means not OK (0).
3. Anything else is compared with the first value seen for that component: the same value means OK, a different value means not OK. Unknown tokens are kept in `StatusBaseline.unknown_values`, so the validation kit can report them.

Filesystem sizes arrive in GB; GiB (1024³) is assumed and recorded as spec Q10.

**Files:**
- Create: `sangfor_hci/collectors/hardware.py`, `tests/unit/test_collectors_hardware.py`
- Modify: `docs/superpowers/specs/2026-11-07-sangfor-hci-extension-design.md` (Q4 wording and a new Q10 row in §11)

**Interfaces:**
- Consumes: `sangfor_hci.model` (Task 1); `sangfor_hci.snmp.oids` (Task 5); `simulator.snmp_sim.load_snmprec` in tests (Task 5).
- Produces:
  - `hardware.StatusBaseline()` with `.is_ok(key: tuple[str, str], text: str) -> bool` and `.unknown_values: set[str]`
  - `hardware.collect(cluster: str, host_ip: str, host_name: str, scalars: dict[str, str], tables: dict[str, dict[str, str]], baseline: StatusBaseline) -> list[Metric]`, where `tables` is keyed by `Table.entry`
  - `hardware.snmp_host_metrics(cluster: str, host_ip: str, host_name: str, scalars: dict[str, str]) -> list[Metric]`

- [ ] **Step 1: Write the failing tests**

`tests/unit/test_collectors_hardware.py`:

```python
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/pytest tests/unit/test_collectors_hardware.py`
Expected: FAIL with `ImportError: cannot import name 'hardware'`.

- [ ] **Step 3: Implement `sangfor_hci/collectors/hardware.py`**

```python
"""SNMP readings from one HCI node -> hardware metrics (feature set "hardware")."""

from __future__ import annotations

from ..model import Metric, MetricList, host_dims, parse_number, ratio_to_percent
from ..snmp import oids

OK_TOKENS = {"ok", "normal", "optimal", "good", "online", "healthy", "1"}
BAD_TOKENS = {"fail", "failed", "failure", "error", "fault", "faulty", "degraded", "offline", "critical", "abnormal", "bad", "0"}
GIB = 1024**3


class StatusBaseline:
    """Classifies status strings; unknown strings are compared with the first value seen."""

    def __init__(self) -> None:
        self._first: dict[tuple[str, str], str] = {}
        self.unknown_values: set[str] = set()

    def is_ok(self, key: tuple[str, str], text: str) -> bool:
        token = text.strip().lower()
        if token in OK_TOKENS:
            return True
        if token in BAD_TOKENS:
            return False
        self.unknown_values.add(token)
        return token == self._first.setdefault(key, token)


def _scalar(scalar: oids.Scalar, scalars: dict[str, str]) -> float | None:
    raw = scalars.get(scalar.oid)
    return ratio_to_percent(raw) if scalar.ratio else parse_number(raw)


def _column(values: dict[str, str], table: oids.Table, suffix: str) -> dict[str, str]:
    prefix = table.column_oid(suffix) + "."
    return {oid[len(prefix) :]: value for oid, value in values.items() if oid.startswith(prefix)}


def collect(
    cluster: str,
    host_ip: str,
    host_name: str,
    scalars: dict[str, str],
    tables: dict[str, dict[str, str]],
    baseline: StatusBaseline,
) -> list[Metric]:
    metrics = MetricList(host_dims(cluster, host_ip, host_name))
    metrics.add(oids.HOST_DISK.metric, _scalar(oids.HOST_DISK, scalars))
    for table in oids.TABLES:
        values = tables.get(table.entry, {})
        names = _column(values, table, table.name_column)
        for column in table.columns:
            for index, raw in _column(values, table, column.suffix).items():
                label = names.get(index, index)
                extra = {f"sangfor.{table.name}": label}
                if column.kind == "status":
                    ok = baseline.is_ok((host_ip, f"{table.name}:{label}"), raw)
                    metrics.add(column.metric, 1.0 if ok else 0.0, extra)
                elif column.kind == "gb":
                    number = parse_number(raw)
                    metrics.add(column.metric, None if number is None else number * GIB, extra)
                else:
                    metrics.add(column.metric, parse_number(raw), extra)
    return list(metrics)


def snmp_host_metrics(cluster: str, host_ip: str, host_name: str, scalars: dict[str, str]) -> list[Metric]:
    """Host CPU and memory from SNMP: used in snmp mode and as the fallback when the API fails."""
    metrics = MetricList(host_dims(cluster, host_ip, host_name))
    for scalar in (oids.HOST_CPU, oids.HOST_MEMORY):
        metrics.add(scalar.metric, _scalar(scalar, scalars))
    return list(metrics)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/bin/pytest tests/unit/test_collectors_hardware.py`
Expected: `5 passed`

- [ ] **Step 5: Update the spec's open questions**

In `docs/superpowers/specs/2026-11-07-sangfor-hci-extension-design.md` §11:

1. Replace the Q4 default `Change-from-baseline rule (§5.2).` with:
   `Known tokens first (ok/normal/optimal → OK; failed/degraded/error → not OK); unknown strings use the change-from-baseline rule and are reported by the validation kit.`
2. Add this row after Q9:

```
| Q10 | Are SNMP filesystem sizes GB (10⁹) or GiB (1024³)? | GiB. |
```

- [ ] **Step 6: Commit**

```bash
git add sangfor_hci/collectors/hardware.py tests/unit/test_collectors_hardware.py docs/superpowers/specs
git commit -m "feat: add SNMP hardware collector with status classification

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 9: Cluster runner (one polling cycle)

`ClusterRunner` does exactly one cycle per call (spec §7, §8):
- **API path:** overview → host_list → node infos (4 parallel) → storelist → VMs every Nth cycle → alarms.
- **SNMP path:** per node (8 parallel), a subtree probe (cached for 1 h), then GETs, then table walks.
- **Error handling:**
  - Auth, TLS or forbidden errors stop the API path for that cycle.
  - Timeout, HTTP or parse errors skip only that endpoint.
  - If the API path fails, host CPU and memory come from SNMP instead.
- **Overlap:** a cycle that overlaps a running one is skipped.

**Files:**
- Create: `sangfor_hci/runner.py`, `tests/integration/test_runner.py`

**Interfaces:**
- Consumes:
  - `config.ClusterConfig`, `config.SnmpNode`, `config.parse_endpoint` (Task 2)
  - `api.client.SangforApiClient`, `SangforApiError` (Task 4)
  - `snmp.client.SnmpClient`, `SnmpTarget`, `SnmpError`, and `snmp.oids` (Task 5)
  - the collectors (Tasks 6–8)
  - fixtures `mock_api` and `snmp_agents`
- Produces (`sangfor_hci/runner.py`):
  - `FEATURE_SETS = ("cluster", "host", "vm", "datastore", "hardware")`
  - `CycleResult(metrics: list[Metric], events: list[Event], problems: list[str], skipped: bool)`
  - `default_api_factory(config) -> SangforApiClient`
  - `default_snmp_factory(config, node) -> SnmpClient`
  - `ClusterRunner(config, enabled_sets, *, api_factory=default_api_factory, snmp_factory=default_snmp_factory, clock=time.time)` with:
    - `.run_cycle() -> CycleResult`
    - `.snmp_nodes() -> list[SnmpNode]`
    - `.close() -> None`
    - `.config`
    - `.enabled: set[str]`

- [ ] **Step 1: Write the failing tests**

`tests/integration/test_runner.py`:

```python
import pytest

from sangfor_hci.api.client import SangforApiClient
from sangfor_hci.config import SnmpNode, parse_endpoint
from sangfor_hci.runner import FEATURE_SETS, ClusterRunner

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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/pytest tests/integration/test_runner.py`
Expected: FAIL with `ModuleNotFoundError: No module named 'sangfor_hci.runner'`.

- [ ] **Step 3: Implement `sangfor_hci/runner.py`**

```python
"""One polling cycle for one Sangfor cluster. Calls clients and collectors; never imports the SDK."""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable

from .api.client import SangforApiClient, SangforApiError
from .collectors import alarms, cluster, datastore, hardware, host, vm
from .config import ClusterConfig, SnmpNode
from .model import Event, Metric, cluster_dims
from .snmp import oids
from .snmp.client import SnmpClient, SnmpError, SnmpTarget

log = logging.getLogger(__name__)

FEATURE_SETS = ("cluster", "host", "vm", "datastore", "hardware")
PROBE_INTERVAL_SECONDS = 3600
ALERT_PARAMS = {"distinct": 0, "limit": 100, "direct": "DESC"}
NODE_INFO_TARGET = "/vapi/json/nodes/{id}/info"
ABORT_REASONS = ("auth", "tls", "forbidden")


@dataclass
class CycleResult:
    metrics: list[Metric] = field(default_factory=list)
    events: list[Event] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    skipped: bool = False


class _ApiAborted(Exception):
    pass


def default_api_factory(config: ClusterConfig) -> SangforApiClient:
    api = config.api
    return SangforApiClient(
        api.url,
        api.username,
        api.password,
        verify_tls=api.verify_tls,
        ca_pem=api.ca_pem,
        timeout=float(config.timeout_seconds),
    )


def default_snmp_factory(config: ClusterConfig, node: SnmpNode) -> SnmpClient:
    snmp = config.snmp
    return SnmpClient(
        SnmpTarget(
            address=node.address,
            port=node.port,
            version=snmp.version,
            timeout=float(config.timeout_seconds),
            community=snmp.community,
            v3_user=snmp.v3_user,
            v3_auth_protocol=snmp.v3_auth_protocol,
            v3_auth_key=snmp.v3_auth_key,
            v3_priv_protocol=snmp.v3_priv_protocol,
            v3_priv_key=snmp.v3_priv_key,
            v3_context_name=snmp.v3_context_name,
        )
    )


class ClusterRunner:
    def __init__(
        self,
        config: ClusterConfig,
        enabled_sets: set[str],
        *,
        api_factory: Callable[[ClusterConfig], SangforApiClient] = default_api_factory,
        snmp_factory: Callable[[ClusterConfig, SnmpNode], SnmpClient] = default_snmp_factory,
        clock: Callable[[], float] = time.time,
    ):
        self.config = config
        self.enabled = set(enabled_sets) & set(FEATURE_SETS)
        self._clock = clock
        self._api = api_factory(config) if config.uses_api else None
        self._snmp_factory = snmp_factory
        self._cycle = 0
        self._lock = threading.Lock()
        self._cursor = alarms.AlarmCursor(start_after=int(clock()) - 2 * config.interval_seconds)
        self._baseline = hardware.StatusBaseline()
        self._probes: dict[str, tuple[bool, float]] = {}
        self._hosts: dict[str, host.HostInfo] = {}

    def run_cycle(self) -> CycleResult:
        if not self._lock.acquire(blocking=False):
            log.warning("Previous cycle for %s is still running; skipping this one", self.config.cluster_name)
            return CycleResult(skipped=True)
        try:
            self._cycle += 1
            result = CycleResult()
            api_ok = self._run_api(result) if self._api is not None else False
            if self.config.uses_snmp:
                self._run_snmp(result, api_ok)
            return result
        finally:
            self._lock.release()

    def snmp_nodes(self) -> list[SnmpNode]:
        snmp = self.config.snmp
        if snmp is None:
            return []
        if snmp.nodes:
            return list(snmp.nodes)
        return [SnmpNode(h.ip, h.ip, snmp.port) for h in self._hosts.values()]

    def close(self) -> None:
        if self._api is not None:
            self._api.close()

    # --- API path -------------------------------------------------------------

    def _run_api(self, result: CycleResult) -> bool:
        name = self.config.cluster_name
        try:
            overview = self._fetch(result, "/vapi/json/index/overview")
            host_list = self._fetch(result, "/vapi/json/index/host_list")
            if host_list is not None:
                self._hosts = host.index(host_list)
            if "cluster" in self.enabled and overview is not None:
                result.metrics += cluster.collect(name, overview)
            if "host" in self.enabled and host_list is not None:
                result.metrics += host.collect(name, host_list, self._fetch_node_infos(result))
            if "datastore" in self.enabled:
                stores = self._fetch(result, "/vapi/json/vtpstorage/storelist")
                if stores is not None:
                    result.metrics += datastore.collect(name, stores)
            if "vm" in self.enabled and (self._cycle - 1) % self.config.vm_every_n_cycles == 0:
                vms = self._fetch(result, "/vapi/json/cluster/vms")
                if vms is not None:
                    result.metrics += vm.collect(name, vms, self._hosts)
            alerts = self._fetch(result, "/vapi/json/log/alert/all", ALERT_PARAMS)
            if alerts is not None:
                result.events += alarms.collect(name, alerts, self._hosts, self._cursor)
            return host_list is not None
        except _ApiAborted:
            return False

    def _fetch(self, result: CycleResult, path: str, params: dict | None = None, target: str | None = None) -> object:
        target = target or path
        started = time.perf_counter()
        try:
            return self._api.get(path, params)
        except SangforApiError as exc:
            self._record_error(result, "api", target, exc.reason, str(exc))
            if exc.reason in ABORT_REASONS:
                raise _ApiAborted() from exc
            return None
        finally:
            self._record_duration(result, "api", target, started)

    def _fetch_node_infos(self, result: CycleResult) -> dict[str, dict]:
        ids = list(self._hosts)
        with ThreadPoolExecutor(max_workers=4) as pool:
            responses = list(
                pool.map(
                    lambda host_id: self._fetch(result, f"/vapi/json/nodes/{host_id}/info", target=NODE_INFO_TARGET),
                    ids,
                )
            )
        return {host_id: data for host_id, data in zip(ids, responses) if isinstance(data, dict)}

    # --- SNMP path ------------------------------------------------------------

    def _run_snmp(self, result: CycleResult, api_ok: bool) -> None:
        want_hardware = "hardware" in self.enabled
        want_host = "host" in self.enabled and not api_ok
        if not (want_hardware or want_host):
            return
        nodes = self.snmp_nodes()
        if not nodes:
            result.problems.append("snmp: no nodes to poll (snmp_nodes is empty and the API host list is unavailable)")
            return
        names = {h.ip: h.name for h in self._hosts.values()}
        with ThreadPoolExecutor(max_workers=8) as pool:
            batches = list(
                pool.map(
                    lambda node: self._poll_node(result, node, names.get(node.host_ip, ""), want_hardware, want_host),
                    nodes,
                )
            )
        for batch in batches:
            result.metrics += batch

    def _poll_node(
        self, result: CycleResult, node: SnmpNode, api_name: str, want_hardware: bool, want_host: bool
    ) -> list[Metric]:
        client = self._snmp_factory(self.config, node)
        started = time.perf_counter()
        name_of_cluster = self.config.cluster_name
        try:
            if not self._private_subtree_present(result, client, node):
                return []
            scalars = client.get([oids.SYS_NAME, oids.HOST_CPU.oid, oids.HOST_MEMORY.oid, oids.HOST_DISK.oid])
            name = api_name or scalars.get(oids.SYS_NAME) or node.host_ip
            metrics: list[Metric] = []
            if want_host:
                metrics += hardware.snmp_host_metrics(name_of_cluster, node.host_ip, name, scalars)
            if want_hardware:
                tables = {table.entry: client.walk(table.entry) for table in oids.TABLES}
                metrics += hardware.collect(name_of_cluster, node.host_ip, name, scalars, tables, self._baseline)
            return metrics
        except SnmpError as exc:
            self._record_error(result, "snmp", node.host_ip, "snmp", str(exc))
            return []
        finally:
            self._record_duration(result, "snmp", node.host_ip, started)

    def _private_subtree_present(self, result: CycleResult, client: SnmpClient, node: SnmpNode) -> bool:
        now = self._clock()
        cached = self._probes.get(node.host_ip)
        if cached is None or now - cached[1] >= PROBE_INTERVAL_SECONDS:
            present = client.has_subtree(oids.ROOT)
            if not present and (cached is None or cached[0]):
                log.warning(
                    "Node %s does not expose the Sangfor private MIB %s; its SNMP metrics stay off until the next hourly check",
                    node.host_ip,
                    oids.ROOT,
                )
            cached = (present, now)
            self._probes[node.host_ip] = cached
        if not cached[0]:
            result.problems.append(f"snmp {node.host_ip}: Sangfor private MIB {oids.ROOT} not available")
        return cached[0]

    # --- self-monitoring ------------------------------------------------------

    def _record_duration(self, result: CycleResult, source: str, target: str, started: float) -> None:
        elapsed_ms = round((time.perf_counter() - started) * 1000.0, 1)
        dims = {**cluster_dims(self.config.cluster_name), "source": source, "target": target}
        result.metrics.append(Metric("ext.poll.duration", elapsed_ms, dims))

    def _record_error(self, result: CycleResult, source: str, target: str, reason: str, message: str) -> None:
        dims = {**cluster_dims(self.config.cluster_name), "source": source, "target": target, "reason": reason}
        result.metrics.append(Metric("ext.poll.errors", 1.0, dims))
        result.problems.append(f"{source} {target}: {message}")
        log.warning("%s %s failed (%s): %s", source, target, reason, message)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/bin/pytest tests/integration/test_runner.py`
Expected: `12 passed`

- [ ] **Step 5: Run the whole suite**

Run: `.venv/bin/pytest`
Expected: all tests pass (`81 passed` at this point).

- [ ] **Step 6: Commit**

```bash
git add sangfor_hci/runner.py tests/integration/test_runner.py
git commit -m "feat: add cluster runner orchestrating API and SNMP cycles

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 10: Extension entry point, extension definition and `dt-sdk run` smoke test

**Files:**
- Create:
  - `sangfor_hci/emit.py`, `sangfor_hci/__main__.py`
  - `extension/extension.yaml`, `extension/activationSchema.json`, `extension/dashboards/sangfor-hci-overview.json`
  - `activation.json`, `scripts/smoke_run.py`
  - `tests/unit/test_emit.py`, `tests/integration/test_extension_definition.py`

**Interfaces:**
- Consumes: `runner.ClusterRunner`, `runner.FEATURE_SETS`, `runner.CycleResult` (Task 9); `config.parse_endpoint`, `config.ConfigError` (Task 2); `model.*` (Task 1).
- Produces:
  - `emit.EVENT_TIMEOUT_MINUTES = 15`
  - `emit.emit_metrics(extension, metrics: list[Metric]) -> None`
  - `emit.emit_events(extension, events: list[Event]) -> None`
  - `__main__.SangforHciExtension(Extension)` and `__main__.main()`

- [ ] **Step 1: Write the failing tests**

`tests/unit/test_emit.py`:

```python
from dynatrace_extension import DtEventType

from sangfor_hci.emit import EVENT_TIMEOUT_MINUTES, emit_events, emit_metrics
from sangfor_hci.model import Event, Metric


class FakeExtension:
    def __init__(self):
        self.metrics, self.events = [], []

    def report_metric(self, key, value, dimensions=None, **kwargs):
        self.metrics.append((key, value, dimensions))

    def report_dt_event(self, event_type, title, **kwargs):
        self.events.append((event_type, title, kwargs))


def test_emit_metrics_uses_full_keys_and_copies_dimensions():
    fake = FakeExtension()
    dims = {"sangfor.cluster": "sim"}
    emit_metrics(fake, [Metric("cluster.cpu.usage", 6.0, dims)])
    assert fake.metrics == [("sangfor.hci.cluster.cpu.usage", 6.0, {"sangfor.cluster": "sim"})]
    assert fake.metrics[0][2] is not dims


def test_emit_events_maps_types_and_timeout():
    fake = FakeExtension()
    event = Event("ERROR_EVENT", "Sangfor HCI: x", 'type("sangfor_hci:cluster"),entityName.equals("sim")', 1000, {"a": "b"})
    emit_events(fake, [event])
    event_type, title, kwargs = fake.events[0]
    assert event_type is DtEventType.ERROR_EVENT
    assert title == "Sangfor HCI: x"
    assert kwargs == {
        "start_time": 1000,
        "timeout": EVENT_TIMEOUT_MINUTES,
        "entity_selector": 'type("sangfor_hci:cluster"),entityName.equals("sim")',
        "properties": {"a": "b"},
    }
```

`tests/integration/test_extension_definition.py`:

```python
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/pytest tests/unit/test_emit.py tests/integration/test_extension_definition.py`
Expected: FAIL with `ModuleNotFoundError: No module named 'sangfor_hci.emit'`, and `FileNotFoundError` for `extension/extension.yaml`.

- [ ] **Step 3: Implement `sangfor_hci/emit.py` and `sangfor_hci/__main__.py`**

`sangfor_hci/emit.py`:

```python
"""The only module that hands data to the Dynatrace SDK."""

from __future__ import annotations

from dynatrace_extension import DtEventType

from .model import Event, Metric

EVENT_TIMEOUT_MINUTES = 15


def emit_metrics(extension, metrics: list[Metric]) -> None:
    for metric in metrics:
        extension.report_metric(metric.full_key, metric.value, dict(metric.dimensions))


def emit_events(extension, events: list[Event]) -> None:
    for event in events:
        extension.report_dt_event(
            DtEventType(event.event_type),
            event.title,
            start_time=event.start_ms,
            timeout=EVENT_TIMEOUT_MINUTES,
            entity_selector=event.entity_selector,
            properties=dict(event.properties),
        )
```

`sangfor_hci/__main__.py`:

```python
"""Dynatrace Extensions 2.0 entry point for custom:sangfor-hci."""

from __future__ import annotations

import logging

from dynatrace_extension import Extension, Status, StatusValue

from .config import ConfigError, parse_endpoint
from .emit import emit_events, emit_metrics
from .runner import FEATURE_SETS, ClusterRunner


class SangforHciExtension(Extension):
    def initialize(self):
        self._runners: list[ClusterRunner] = []
        package_logger = logging.getLogger("sangfor_hci")
        if not package_logger.handlers:
            for handler in self.logger.handlers:
                package_logger.addHandler(handler)
            package_logger.setLevel(self.logger.level or logging.INFO)

        enabled = set(self.activation_config.feature_sets) & set(FEATURE_SETS)
        if not enabled:
            self.logger.warning("No feature sets are enabled; only self-monitoring metrics will be reported")
        problems = []
        for raw in self.activation_config.get("endpoints", []):
            try:
                config = parse_endpoint(raw)
            except ConfigError as exc:
                problems.append(str(exc))
                continue
            runner = ClusterRunner(config, enabled)
            self._runners.append(runner)
            self.schedule(self._run_cycle, config.interval_seconds, args=(runner,))
            self.logger.info(
                "Monitoring Sangfor cluster '%s' in %s mode every %s s", config.cluster_name, config.mode, config.interval_seconds
            )
        if not self._runners:
            return Status(StatusValue.INVALID_CONFIG_ERROR, "; ".join(problems) or "no endpoints configured")
        if problems:
            self.logger.warning("Ignored invalid endpoints: %s", "; ".join(problems))
        return None

    def _run_cycle(self, runner: ClusterRunner) -> Status:
        result = runner.run_cycle()
        name = runner.config.cluster_name
        if result.skipped:
            return Status(StatusValue.WARNING, f"{name}: previous cycle still running")
        emit_metrics(self, result.metrics)
        emit_events(self, result.events)
        if result.problems:
            return Status(StatusValue.WARNING, f"{name}: " + "; ".join(result.problems[:5]))
        return Status(StatusValue.OK)

    def on_shutdown(self):
        for runner in getattr(self, "_runners", []):
            runner.close()


def main():
    SangforHciExtension(name="sangfor_hci").run()


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Write `extension/extension.yaml`**

```yaml
name: custom:sangfor-hci
version: 0.1.0
minDynatraceVersion: "1.285"
author:
  name: Rifqi Fitriady

python:
  runtime:
    module: sangfor_hci
    version:
      min: "3.10"
  activation:
    remote:
      path: activationSchema.json
  featureSets:
    - featureSet: cluster
      metrics:
        - key: sangfor.hci.cluster.cpu.usage
        - key: sangfor.hci.cluster.memory.usage
        - key: sangfor.hci.cluster.storage.usage
        - key: sangfor.hci.cluster.storage.used
        - key: sangfor.hci.cluster.storage.total
        - key: sangfor.hci.cluster.vms
        - key: sangfor.hci.cluster.hosts
    - featureSet: host
      metrics:
        - key: sangfor.hci.host.cpu.usage
        - key: sangfor.hci.host.memory.usage
        - key: sangfor.hci.host.io.usage
        - key: sangfor.hci.host.online
        - key: sangfor.hci.host.alarm
        - key: sangfor.hci.host.uptime
        - key: sangfor.hci.host.vms.running
    - featureSet: vm
      metrics:
        - key: sangfor.hci.vm.cpu.usage
        - key: sangfor.hci.vm.memory.usage
        - key: sangfor.hci.vm.disk.used
        - key: sangfor.hci.vm.disk.read
        - key: sangfor.hci.vm.disk.write
        - key: sangfor.hci.vm.net.in
        - key: sangfor.hci.vm.net.out
        - key: sangfor.hci.vm.running
    - featureSet: datastore
      metrics:
        - key: sangfor.hci.datastore.total
        - key: sangfor.hci.datastore.available
        - key: sangfor.hci.datastore.usage
        - key: sangfor.hci.datastore.read.iops
        - key: sangfor.hci.datastore.write.iops
        - key: sangfor.hci.datastore.read.throughput
        - key: sangfor.hci.datastore.write.throughput
        - key: sangfor.hci.datastore.online
        - key: sangfor.hci.datastore.partial_access
        - key: sangfor.hci.datastore.capacity_alert
    - featureSet: hardware
      metrics:
        - key: sangfor.hci.hw.disk.usage
        - key: sangfor.hci.hw.cpu.temperature
        - key: sangfor.hci.hw.fan.speed
        - key: sangfor.hci.hw.fan.ok
        - key: sangfor.hci.hw.raid.ok
        - key: sangfor.hci.hw.ssd.life
        - key: sangfor.hci.hw.fs.size
        - key: sangfor.hci.hw.fs.used
        - key: sangfor.hci.hw.fs.available
        - key: sangfor.hci.hw.fs.usage
        - key: sangfor.hci.hw.optical.rx.power
        - key: sangfor.hci.hw.optical.tx.power

metrics:
  - key: sangfor.hci.cluster.cpu.usage
    metadata: {displayName: Cluster CPU usage, unit: Percent}
  - key: sangfor.hci.cluster.memory.usage
    metadata: {displayName: Cluster memory usage, unit: Percent}
  - key: sangfor.hci.cluster.storage.usage
    metadata: {displayName: Cluster storage usage, unit: Percent}
  - key: sangfor.hci.cluster.storage.used
    metadata: {displayName: Cluster storage used, unit: Byte}
  - key: sangfor.hci.cluster.storage.total
    metadata: {displayName: Cluster storage total, unit: Byte}
  - key: sangfor.hci.cluster.vms
    metadata: {displayName: Cluster VMs by state, unit: Count}
  - key: sangfor.hci.cluster.hosts
    metadata: {displayName: Cluster hosts by state, unit: Count}
  - key: sangfor.hci.host.cpu.usage
    metadata: {displayName: Host CPU usage, unit: Percent}
  - key: sangfor.hci.host.memory.usage
    metadata: {displayName: Host memory usage, unit: Percent}
  - key: sangfor.hci.host.io.usage
    metadata: {displayName: Host IO usage, unit: Percent}
  - key: sangfor.hci.host.online
    metadata: {displayName: Host online (1 = online), unit: Unspecified}
  - key: sangfor.hci.host.alarm
    metadata: {displayName: Host has active alarm (1 = yes), unit: Unspecified}
  - key: sangfor.hci.host.uptime
    metadata: {displayName: Host uptime, unit: Second}
  - key: sangfor.hci.host.vms.running
    metadata: {displayName: Host running VMs, unit: Count}
  - key: sangfor.hci.vm.cpu.usage
    metadata: {displayName: VM CPU usage, unit: Percent}
  - key: sangfor.hci.vm.memory.usage
    metadata: {displayName: VM memory usage, unit: Percent}
  - key: sangfor.hci.vm.disk.used
    metadata: {displayName: VM disk used, unit: Byte}
  - key: sangfor.hci.vm.disk.read
    metadata: {displayName: VM disk read (as reported by Sangfor), unit: Unspecified}
  - key: sangfor.hci.vm.disk.write
    metadata: {displayName: VM disk write (as reported by Sangfor), unit: Unspecified}
  - key: sangfor.hci.vm.net.in
    metadata: {displayName: VM network in (as reported by Sangfor), unit: Unspecified}
  - key: sangfor.hci.vm.net.out
    metadata: {displayName: VM network out (as reported by Sangfor), unit: Unspecified}
  - key: sangfor.hci.vm.running
    metadata: {displayName: VM running (1 = running), unit: Unspecified}
  - key: sangfor.hci.datastore.total
    metadata: {displayName: Datastore capacity, unit: Byte}
  - key: sangfor.hci.datastore.available
    metadata: {displayName: Datastore available, unit: Byte}
  - key: sangfor.hci.datastore.usage
    metadata: {displayName: Datastore usage, unit: Percent}
  - key: sangfor.hci.datastore.read.iops
    metadata: {displayName: Datastore read IOPS, unit: PerSecond}
  - key: sangfor.hci.datastore.write.iops
    metadata: {displayName: Datastore write IOPS, unit: PerSecond}
  - key: sangfor.hci.datastore.read.throughput
    metadata: {displayName: Datastore read throughput, unit: BytePerSecond}
  - key: sangfor.hci.datastore.write.throughput
    metadata: {displayName: Datastore write throughput, unit: BytePerSecond}
  - key: sangfor.hci.datastore.online
    metadata: {displayName: Datastore online (1 = online), unit: Unspecified}
  - key: sangfor.hci.datastore.partial_access
    metadata: {displayName: Datastore not reachable from some hosts (1 = yes), unit: Unspecified}
  - key: sangfor.hci.datastore.capacity_alert
    metadata: {displayName: Datastore over 90% (1 = yes), unit: Unspecified}
  - key: sangfor.hci.hw.disk.usage
    metadata: {displayName: Node disk usage, unit: Percent}
  - key: sangfor.hci.hw.cpu.temperature
    metadata: {displayName: CPU temperature (°C), unit: Unspecified}
  - key: sangfor.hci.hw.fan.speed
    metadata: {displayName: Fan speed (rpm), unit: Unspecified}
  - key: sangfor.hci.hw.fan.ok
    metadata: {displayName: Fan healthy (1 = OK), unit: Unspecified}
  - key: sangfor.hci.hw.raid.ok
    metadata: {displayName: RAID healthy (1 = OK), unit: Unspecified}
  - key: sangfor.hci.hw.ssd.life
    metadata: {displayName: SSD remaining life, unit: Percent}
  - key: sangfor.hci.hw.fs.size
    metadata: {displayName: Filesystem size, unit: Byte}
  - key: sangfor.hci.hw.fs.used
    metadata: {displayName: Filesystem used, unit: Byte}
  - key: sangfor.hci.hw.fs.available
    metadata: {displayName: Filesystem available, unit: Byte}
  - key: sangfor.hci.hw.fs.usage
    metadata: {displayName: Filesystem usage, unit: Percent}
  - key: sangfor.hci.hw.optical.rx.power
    metadata: {displayName: Optical Rx power (dBm), unit: Unspecified}
  - key: sangfor.hci.hw.optical.tx.power
    metadata: {displayName: Optical Tx power (dBm), unit: Unspecified}
  - key: sangfor.hci.ext.poll.duration
    metadata: {displayName: Sangfor extension poll duration, unit: MilliSecond}
  - key: sangfor.hci.ext.poll.errors
    metadata: {displayName: Sangfor extension poll errors, unit: Count}

topology:
  types:
    - name: sangfor_hci:cluster
      displayName: Sangfor HCI cluster
      enabled: true
      rules:
        - idPattern: sangfor_hci_cluster_{sangfor.cluster}
          instanceNamePattern: "{sangfor.cluster}"
          iconPattern: cluster
          sources:
            - sourceType: Metrics
              condition: $prefix(sangfor.hci.cluster.)
            - sourceType: Metrics
              condition: $prefix(sangfor.hci.host.)
            - sourceType: Metrics
              condition: $prefix(sangfor.hci.hw.)
            - sourceType: Metrics
              condition: $prefix(sangfor.hci.datastore.)
            - sourceType: Metrics
              condition: $prefix(sangfor.hci.ext.)
          requiredDimensions:
            - key: sangfor.cluster
          attributes: []
    - name: sangfor_hci:host
      displayName: Sangfor HCI host
      enabled: true
      rules:
        - idPattern: sangfor_hci_host_{sangfor.cluster}_{sangfor.host.ip}
          instanceNamePattern: "{sangfor.cluster} / {sangfor.host.name}"
          iconPattern: host
          sources:
            - sourceType: Metrics
              condition: $prefix(sangfor.hci.host.)
            - sourceType: Metrics
              condition: $prefix(sangfor.hci.hw.)
          requiredDimensions:
            - key: sangfor.cluster
            - key: sangfor.host.ip
          attributes:
            - key: ip_address
              displayName: IP address
              pattern: "{sangfor.host.ip}"
            - key: sangfor_version
              displayName: Sangfor version
              pattern: "{sangfor.version}"
    - name: sangfor_hci:vm
      displayName: Sangfor HCI VM
      enabled: true
      rules:
        - idPattern: sangfor_hci_vm_{sangfor.cluster}_{sangfor.vm.id}
          instanceNamePattern: "{sangfor.cluster} / {sangfor.vm.name} ({sangfor.vm.id})"
          iconPattern: virtualmachine
          sources:
            - sourceType: Metrics
              condition: $prefix(sangfor.hci.vm.)
          requiredDimensions:
            - key: sangfor.cluster
            - key: sangfor.vm.id
          attributes:
            - key: vm_os
              displayName: Operating system
              pattern: "{sangfor.vm.os}"
            - key: vm_group
              displayName: Group
              pattern: "{sangfor.vm.group}"
            - key: vm_ha
              displayName: HA enabled
              pattern: "{sangfor.vm.ha}"
    - name: sangfor_hci:datastore
      displayName: Sangfor HCI datastore
      enabled: true
      rules:
        - idPattern: sangfor_hci_datastore_{sangfor.cluster}_{sangfor.datastore.id}
          instanceNamePattern: "{sangfor.cluster} / {sangfor.datastore.name}"
          iconPattern: database
          sources:
            - sourceType: Metrics
              condition: $prefix(sangfor.hci.datastore.)
          requiredDimensions:
            - key: sangfor.cluster
            - key: sangfor.datastore.id
          attributes:
            - key: datastore_type
              displayName: Type
              pattern: "{sangfor.datastore.type}"
            - key: datastore_shared
              displayName: Shared
              pattern: "{sangfor.datastore.shared}"
  relationships:
    - fromType: sangfor_hci:host
      toType: sangfor_hci:cluster
      typeOfRelation: CHILD_OF
      enabled: true
      sources:
        - sourceType: Metrics
          condition: $prefix(sangfor.hci.host.)
    - fromType: sangfor_hci:vm
      toType: sangfor_hci:host
      typeOfRelation: RUNS_ON
      enabled: true
      sources:
        - sourceType: Metrics
          condition: $prefix(sangfor.hci.vm.)
    - fromType: sangfor_hci:datastore
      toType: sangfor_hci:cluster
      typeOfRelation: CHILD_OF
      enabled: true
      sources:
        - sourceType: Metrics
          condition: $prefix(sangfor.hci.datastore.)

screens:
  - entityType: sangfor_hci:cluster
    detailsSettings:
      staticContent: {showProblems: true, showProperties: true, showTags: true, showGlobalFilter: true, showAddTag: true}
      layout:
        autoGenerate: false
        cards:
          - {key: cluster_usage, type: CHART_GROUP}
          - {key: cluster_hosts, type: ENTITIES_LIST}
          - {key: cluster_datastores, type: ENTITIES_LIST}
    listSettings:
      staticContent: {showGlobalFilter: true}
      layout:
        autoGenerate: false
        cards:
          - {key: cluster_list, type: ENTITIES_LIST}
    chartsCards:
      - key: cluster_usage
        displayName: Cluster usage
        numberOfVisibleCharts: 4
        charts:
          - displayName: CPU usage (%)
            visualizationType: GRAPH_CHART
            graphChartConfig:
              metrics:
                - metricSelector: sangfor.hci.cluster.cpu.usage:splitBy("dt.entity.sangfor_hci:cluster")
          - displayName: Memory usage (%)
            visualizationType: GRAPH_CHART
            graphChartConfig:
              metrics:
                - metricSelector: sangfor.hci.cluster.memory.usage:splitBy("dt.entity.sangfor_hci:cluster")
          - displayName: Storage usage (%)
            visualizationType: GRAPH_CHART
            graphChartConfig:
              metrics:
                - metricSelector: sangfor.hci.cluster.storage.usage:splitBy("dt.entity.sangfor_hci:cluster")
          - displayName: VMs by state
            visualizationType: GRAPH_CHART
            graphChartConfig:
              metrics:
                - metricSelector: sangfor.hci.cluster.vms:splitBy("state")
    entitiesListCards:
      - key: cluster_list
        displayName: Sangfor HCI clusters
        entitySelectorTemplate: type("sangfor_hci:cluster")
        pageSize: 10
        displayCharts: false
        enableDetailsExpandability: true
        numberOfVisibleCharts: 0
        charts: []
      - key: cluster_hosts
        displayName: Hosts
        entitySelectorTemplate: type("sangfor_hci:host"),fromRelationships.isChildOf($(entityConditions))
        pageSize: 10
        displayCharts: true
        enableDetailsExpandability: true
        numberOfVisibleCharts: 2
        charts:
          - displayName: CPU usage (%)
            visualizationType: GRAPH_CHART
            graphChartConfig:
              metrics:
                - metricSelector: sangfor.hci.host.cpu.usage:splitBy("dt.entity.sangfor_hci:host")
          - displayName: Memory usage (%)
            visualizationType: GRAPH_CHART
            graphChartConfig:
              metrics:
                - metricSelector: sangfor.hci.host.memory.usage:splitBy("dt.entity.sangfor_hci:host")
      - key: cluster_datastores
        displayName: Datastores
        entitySelectorTemplate: type("sangfor_hci:datastore"),fromRelationships.isChildOf($(entityConditions))
        pageSize: 10
        displayCharts: true
        enableDetailsExpandability: true
        numberOfVisibleCharts: 1
        charts:
          - displayName: Usage (%)
            visualizationType: GRAPH_CHART
            graphChartConfig:
              metrics:
                - metricSelector: sangfor.hci.datastore.usage:splitBy("dt.entity.sangfor_hci:datastore")
  - entityType: sangfor_hci:host
    detailsSettings:
      staticContent: {showProblems: true, showProperties: true, showTags: true, showGlobalFilter: true, showAddTag: true}
      layout:
        autoGenerate: false
        cards:
          - {key: host_usage, type: CHART_GROUP}
          - {key: host_hardware, type: CHART_GROUP}
          - {key: host_vms, type: ENTITIES_LIST}
    listSettings:
      staticContent: {showGlobalFilter: true}
      layout:
        autoGenerate: false
        cards:
          - {key: host_list, type: ENTITIES_LIST}
    chartsCards:
      - key: host_usage
        displayName: Utilization
        numberOfVisibleCharts: 3
        charts:
          - displayName: CPU usage (%)
            visualizationType: GRAPH_CHART
            graphChartConfig:
              metrics:
                - metricSelector: sangfor.hci.host.cpu.usage:splitBy("dt.entity.sangfor_hci:host")
          - displayName: Memory usage (%)
            visualizationType: GRAPH_CHART
            graphChartConfig:
              metrics:
                - metricSelector: sangfor.hci.host.memory.usage:splitBy("dt.entity.sangfor_hci:host")
          - displayName: IO usage (%)
            visualizationType: GRAPH_CHART
            graphChartConfig:
              metrics:
                - metricSelector: sangfor.hci.host.io.usage:splitBy("dt.entity.sangfor_hci:host")
      - key: host_hardware
        displayName: Hardware health (SNMP)
        numberOfVisibleCharts: 4
        charts:
          - displayName: CPU temperature (°C)
            visualizationType: GRAPH_CHART
            graphChartConfig:
              metrics:
                - metricSelector: sangfor.hci.hw.cpu.temperature:splitBy("sangfor.cpu")
          - displayName: Fan healthy (1 = OK)
            visualizationType: GRAPH_CHART
            graphChartConfig:
              metrics:
                - metricSelector: sangfor.hci.hw.fan.ok:splitBy("sangfor.fan")
          - displayName: RAID healthy (1 = OK)
            visualizationType: GRAPH_CHART
            graphChartConfig:
              metrics:
                - metricSelector: sangfor.hci.hw.raid.ok:splitBy("sangfor.raid")
          - displayName: SSD remaining life (%)
            visualizationType: GRAPH_CHART
            graphChartConfig:
              metrics:
                - metricSelector: sangfor.hci.hw.ssd.life:splitBy("sangfor.ssd")
    entitiesListCards:
      - key: host_list
        displayName: Sangfor HCI hosts
        entitySelectorTemplate: type("sangfor_hci:host")
        pageSize: 15
        displayCharts: true
        enableDetailsExpandability: true
        numberOfVisibleCharts: 2
        charts:
          - displayName: CPU usage (%)
            visualizationType: GRAPH_CHART
            graphChartConfig:
              metrics:
                - metricSelector: sangfor.hci.host.cpu.usage:splitBy("dt.entity.sangfor_hci:host")
          - displayName: Memory usage (%)
            visualizationType: GRAPH_CHART
            graphChartConfig:
              metrics:
                - metricSelector: sangfor.hci.host.memory.usage:splitBy("dt.entity.sangfor_hci:host")
      - key: host_vms
        displayName: VMs on this host
        entitySelectorTemplate: type("sangfor_hci:vm"),fromRelationships.runsOn($(entityConditions))
        pageSize: 10
        displayCharts: true
        enableDetailsExpandability: true
        numberOfVisibleCharts: 1
        charts:
          - displayName: CPU usage (%)
            visualizationType: GRAPH_CHART
            graphChartConfig:
              metrics:
                - metricSelector: sangfor.hci.vm.cpu.usage:splitBy("dt.entity.sangfor_hci:vm")
  - entityType: sangfor_hci:vm
    detailsSettings:
      staticContent: {showProblems: true, showProperties: true, showTags: true, showGlobalFilter: true, showAddTag: true}
      layout:
        autoGenerate: false
        cards:
          - {key: vm_usage, type: CHART_GROUP}
    listSettings:
      staticContent: {showGlobalFilter: true}
      layout:
        autoGenerate: false
        cards:
          - {key: vm_list, type: ENTITIES_LIST}
    chartsCards:
      - key: vm_usage
        displayName: Utilization
        numberOfVisibleCharts: 4
        charts:
          - displayName: CPU usage (%)
            visualizationType: GRAPH_CHART
            graphChartConfig:
              metrics:
                - metricSelector: sangfor.hci.vm.cpu.usage:splitBy("dt.entity.sangfor_hci:vm")
          - displayName: Memory usage (%)
            visualizationType: GRAPH_CHART
            graphChartConfig:
              metrics:
                - metricSelector: sangfor.hci.vm.memory.usage:splitBy("dt.entity.sangfor_hci:vm")
          - displayName: Disk read / write
            visualizationType: GRAPH_CHART
            graphChartConfig:
              metrics:
                - metricSelector: sangfor.hci.vm.disk.read:splitBy("dt.entity.sangfor_hci:vm")
                - metricSelector: sangfor.hci.vm.disk.write:splitBy("dt.entity.sangfor_hci:vm")
          - displayName: Network in / out
            visualizationType: GRAPH_CHART
            graphChartConfig:
              metrics:
                - metricSelector: sangfor.hci.vm.net.in:splitBy("dt.entity.sangfor_hci:vm")
                - metricSelector: sangfor.hci.vm.net.out:splitBy("dt.entity.sangfor_hci:vm")
    entitiesListCards:
      - key: vm_list
        displayName: Sangfor HCI VMs
        entitySelectorTemplate: type("sangfor_hci:vm")
        pageSize: 20
        displayCharts: true
        enableDetailsExpandability: true
        numberOfVisibleCharts: 2
        charts:
          - displayName: CPU usage (%)
            visualizationType: GRAPH_CHART
            graphChartConfig:
              metrics:
                - metricSelector: sangfor.hci.vm.cpu.usage:splitBy("dt.entity.sangfor_hci:vm")
          - displayName: Memory usage (%)
            visualizationType: GRAPH_CHART
            graphChartConfig:
              metrics:
                - metricSelector: sangfor.hci.vm.memory.usage:splitBy("dt.entity.sangfor_hci:vm")
  - entityType: sangfor_hci:datastore
    detailsSettings:
      staticContent: {showProblems: true, showProperties: true, showTags: true, showGlobalFilter: true, showAddTag: true}
      layout:
        autoGenerate: false
        cards:
          - {key: datastore_usage, type: CHART_GROUP}
    listSettings:
      staticContent: {showGlobalFilter: true}
      layout:
        autoGenerate: false
        cards:
          - {key: datastore_list, type: ENTITIES_LIST}
    chartsCards:
      - key: datastore_usage
        displayName: Capacity and performance
        numberOfVisibleCharts: 3
        charts:
          - displayName: Usage (%)
            visualizationType: GRAPH_CHART
            graphChartConfig:
              metrics:
                - metricSelector: sangfor.hci.datastore.usage:splitBy("dt.entity.sangfor_hci:datastore")
          - displayName: IOPS (read / write)
            visualizationType: GRAPH_CHART
            graphChartConfig:
              metrics:
                - metricSelector: sangfor.hci.datastore.read.iops:splitBy("dt.entity.sangfor_hci:datastore")
                - metricSelector: sangfor.hci.datastore.write.iops:splitBy("dt.entity.sangfor_hci:datastore")
          - displayName: Throughput (read / write)
            visualizationType: GRAPH_CHART
            graphChartConfig:
              metrics:
                - metricSelector: sangfor.hci.datastore.read.throughput:splitBy("dt.entity.sangfor_hci:datastore")
                - metricSelector: sangfor.hci.datastore.write.throughput:splitBy("dt.entity.sangfor_hci:datastore")
    entitiesListCards:
      - key: datastore_list
        displayName: Sangfor HCI datastores
        entitySelectorTemplate: type("sangfor_hci:datastore")
        pageSize: 15
        displayCharts: true
        enableDetailsExpandability: true
        numberOfVisibleCharts: 1
        charts:
          - displayName: Usage (%)
            visualizationType: GRAPH_CHART
            graphChartConfig:
              metrics:
                - metricSelector: sangfor.hci.datastore.usage:splitBy("dt.entity.sangfor_hci:datastore")

dashboards:
  - path: dashboards/sangfor-hci-overview.json
```

The screens schema cannot be validated locally. Task 13 validates it against the Managed environment's extension schema before the first real upload.

- [ ] **Step 5: Write `extension/activationSchema.json`**

```json
{
  "types": {
    "dynatrace.datasource.python:sangfor_hci-endpoint": {
      "type": "object",
      "displayName": "Sangfor HCI cluster",
      "summaryPattern": "{cluster_name} ({mode})",
      "properties": {
        "cluster_name": {"displayName": "Cluster name", "description": "Unique name for this Sangfor cluster in Dynatrace. Used as the entity identity; do not change it later.", "type": "text", "nullable": false, "default": "", "constraints": [{"type": "LENGTH", "minLength": 1, "maxLength": 100}]},
        "mode": {"displayName": "Collection mode", "type": {"$ref": "#/enums/mode"}, "nullable": false, "default": "both"},
        "interval_seconds": {"displayName": "Polling interval (seconds)", "type": "integer", "nullable": false, "default": 60, "constraints": [{"type": "RANGE", "minimum": 10, "maximum": 3600}]},
        "vm_interval_seconds": {"displayName": "VM polling interval (seconds)", "description": "VM metrics dominate ingest volume (DDU). Must be at least the polling interval.", "type": "integer", "nullable": false, "default": 300, "constraints": [{"type": "RANGE", "minimum": 10, "maximum": 86400}]},
        "timeout_seconds": {"displayName": "Request timeout (seconds)", "type": "integer", "nullable": false, "default": 10, "constraints": [{"type": "RANGE", "minimum": 1, "maximum": 120}]},
        "api_url": {"displayName": "Sangfor API URL", "description": "For example https://10.0.0.10 (cluster VIP). Required for the API and both modes.", "type": "text", "nullable": false, "default": ""},
        "api_username": {"displayName": "API user name", "description": "A read-only Sangfor account is recommended.", "type": "text", "nullable": false, "default": ""},
        "api_password": {"displayName": "API password", "type": "secret", "nullable": false, "default": ""},
        "api_verify_tls": {"displayName": "Verify TLS certificate", "type": "boolean", "nullable": false, "default": true},
        "api_ca_pem": {"displayName": "Custom CA certificate (PEM)", "description": "Trust this CA for a self-signed HCI certificate instead of turning verification off.", "type": "text", "subType": "multiline", "nullable": false, "default": ""},
        "snmp_version": {"displayName": "SNMP version", "type": {"$ref": "#/enums/snmpVersion"}, "nullable": false, "default": "v3"},
        "snmp_port": {"displayName": "SNMP port", "type": "integer", "nullable": false, "default": 161, "constraints": [{"type": "RANGE", "minimum": 1, "maximum": 65535}]},
        "snmp_community": {"displayName": "SNMP v2c community", "description": "Empty means sangfopub, the community HCI is reported to use.", "type": "secret", "nullable": false, "default": ""},
        "snmp_v3_user": {"displayName": "SNMP v3 user", "type": "text", "nullable": false, "default": ""},
        "snmp_v3_auth_protocol": {"displayName": "SNMP v3 authentication protocol", "type": {"$ref": "#/enums/authProtocol"}, "nullable": false, "default": "SHA"},
        "snmp_v3_auth_key": {"displayName": "SNMP v3 authentication key", "type": "secret", "nullable": false, "default": ""},
        "snmp_v3_priv_protocol": {"displayName": "SNMP v3 privacy protocol", "type": {"$ref": "#/enums/privProtocol"}, "nullable": false, "default": "AES128"},
        "snmp_v3_priv_key": {"displayName": "SNMP v3 privacy key", "type": "secret", "nullable": false, "default": ""},
        "snmp_v3_context_name": {"displayName": "SNMP v3 context name", "description": "Usually empty on a real HCI.", "type": "text", "nullable": false, "default": ""},
        "snmp_nodes": {"displayName": "SNMP nodes", "description": "One entry per HCI node: IP, or IP=ADDRESS:PORT when it must be polled elsewhere. Empty in both mode means: use the host IPs from the API.", "type": "list", "items": {"type": "text"}, "nullable": false, "minItems": 0, "maxItems": 64}
      }
    },
    "pythonRemote": {
      "type": "object",
      "properties": {
        "endpoints": {
          "displayName": "Sangfor HCI clusters",
          "type": "list",
          "items": {"type": {"$ref": "#/types/dynatrace.datasource.python:sangfor_hci-endpoint"}},
          "nullable": false,
          "minItems": 1,
          "maxItems": 100,
          "metaData": {"addItemButton": "Add cluster"}
        }
      }
    }
  },
  "enums": {
    "mode": {"type": "enum", "displayName": "Mode", "items": [
      {"value": "both", "displayName": "REST API and SNMP"},
      {"value": "api", "displayName": "REST API only"},
      {"value": "snmp", "displayName": "SNMP only"}]},
    "snmpVersion": {"type": "enum", "displayName": "SNMP version", "items": [
      {"value": "v3", "displayName": "SNMP v3"},
      {"value": "v2c", "displayName": "SNMP v2c"}]},
    "authProtocol": {"type": "enum", "displayName": "Authentication protocol", "items": [
      {"value": "SHA", "displayName": "SHA"},
      {"value": "SHA256", "displayName": "SHA-256"},
      {"value": "MD5", "displayName": "MD5"}]},
    "privProtocol": {"type": "enum", "displayName": "Privacy protocol", "items": [
      {"value": "AES128", "displayName": "AES-128"},
      {"value": "AES256", "displayName": "AES-256"},
      {"value": "DES", "displayName": "DES"},
      {"value": "NONE", "displayName": "None (authNoPriv)"}]}
  },
  "dynatrace": "1",
  "description": "Sangfor HCI monitoring configuration",
  "schemaId": "python-extension.activation",
  "displayName": "Sangfor HCI monitoring configuration",
  "ownerProductManagement": "dynatrace",
  "ownerDevelopment": "dynatrace",
  "maturity": "GENERAL_AVAILABILITY",
  "allowedScopes": ["tenant"],
  "multiObject": false,
  "properties": {
    "pythonRemote": {"displayName": "Python Remote Extension", "type": {"$ref": "#/types/pythonRemote"}}
  }
}
```

- [ ] **Step 6: Write `extension/dashboards/sangfor-hci-overview.json`**

```json
{
  "metadata": {"configurationVersions": [7], "clusterVersion": "1.285.0"},
  "dashboardMetadata": {
    "name": "Sangfor HCI overview",
    "shared": true,
    "owner": "",
    "tags": ["sangfor", "hci"],
    "preset": true
  },
  "tiles": [
    {"name": "Markdown", "tileType": "MARKDOWN", "configured": true,
     "bounds": {"top": 0, "left": 0, "width": 1254, "height": 76}, "tileFilter": {},
     "markdown": "## Sangfor HCI\nClusters, hosts, VMs and datastores collected by the custom:sangfor-hci extension. Open an entity from the charts for details."},
    {"name": "Cluster CPU usage", "tileType": "DATA_EXPLORER", "configured": true,
     "bounds": {"top": 76, "left": 0, "width": 418, "height": 304}, "tileFilter": {}, "customName": "Cluster CPU usage (%)",
     "queries": [{"id": "A", "metric": "sangfor.hci.cluster.cpu.usage", "spaceAggregation": "AVG", "timeAggregation": "DEFAULT", "splitBy": ["dt.entity.sangfor_hci:cluster"], "sortBy": "DESC", "filterBy": {"nestedFilters": [], "criteria": []}, "limit": 20, "rate": "NONE", "enabled": true}],
     "visualConfig": {"type": "GRAPH_CHART", "global": {}, "rules": [], "axes": {"xAxis": {"visible": true}, "yAxes": []}, "heatmapSettings": {}, "thresholds": [], "tableSettings": {}, "graphChartSettings": {}, "honeycombSettings": {}},
     "queriesSettings": {"resolution": ""},
     "metricExpressions": ["resolution=null&(sangfor.hci.cluster.cpu.usage:splitBy(\"dt.entity.sangfor_hci:cluster\"):avg:sort(value(avg,descending)):limit(20)):limit(100):names"]},
    {"name": "Cluster memory usage", "tileType": "DATA_EXPLORER", "configured": true,
     "bounds": {"top": 76, "left": 418, "width": 418, "height": 304}, "tileFilter": {}, "customName": "Cluster memory usage (%)",
     "queries": [{"id": "A", "metric": "sangfor.hci.cluster.memory.usage", "spaceAggregation": "AVG", "timeAggregation": "DEFAULT", "splitBy": ["dt.entity.sangfor_hci:cluster"], "sortBy": "DESC", "filterBy": {"nestedFilters": [], "criteria": []}, "limit": 20, "rate": "NONE", "enabled": true}],
     "visualConfig": {"type": "GRAPH_CHART", "global": {}, "rules": [], "axes": {"xAxis": {"visible": true}, "yAxes": []}, "heatmapSettings": {}, "thresholds": [], "tableSettings": {}, "graphChartSettings": {}, "honeycombSettings": {}},
     "queriesSettings": {"resolution": ""},
     "metricExpressions": ["resolution=null&(sangfor.hci.cluster.memory.usage:splitBy(\"dt.entity.sangfor_hci:cluster\"):avg:sort(value(avg,descending)):limit(20)):limit(100):names"]},
    {"name": "Cluster storage usage", "tileType": "DATA_EXPLORER", "configured": true,
     "bounds": {"top": 76, "left": 836, "width": 418, "height": 304}, "tileFilter": {}, "customName": "Cluster storage usage (%)",
     "queries": [{"id": "A", "metric": "sangfor.hci.cluster.storage.usage", "spaceAggregation": "AVG", "timeAggregation": "DEFAULT", "splitBy": ["dt.entity.sangfor_hci:cluster"], "sortBy": "DESC", "filterBy": {"nestedFilters": [], "criteria": []}, "limit": 20, "rate": "NONE", "enabled": true}],
     "visualConfig": {"type": "GRAPH_CHART", "global": {}, "rules": [], "axes": {"xAxis": {"visible": true}, "yAxes": []}, "heatmapSettings": {}, "thresholds": [], "tableSettings": {}, "graphChartSettings": {}, "honeycombSettings": {}},
     "queriesSettings": {"resolution": ""},
     "metricExpressions": ["resolution=null&(sangfor.hci.cluster.storage.usage:splitBy(\"dt.entity.sangfor_hci:cluster\"):avg:sort(value(avg,descending)):limit(20)):limit(100):names"]},
    {"name": "Top hosts by CPU", "tileType": "DATA_EXPLORER", "configured": true,
     "bounds": {"top": 380, "left": 0, "width": 627, "height": 304}, "tileFilter": {}, "customName": "Top hosts by CPU (%)",
     "queries": [{"id": "A", "metric": "sangfor.hci.host.cpu.usage", "spaceAggregation": "AVG", "timeAggregation": "DEFAULT", "splitBy": ["dt.entity.sangfor_hci:host"], "sortBy": "DESC", "filterBy": {"nestedFilters": [], "criteria": []}, "limit": 10, "rate": "NONE", "enabled": true}],
     "visualConfig": {"type": "TOP_LIST", "global": {}, "rules": [], "axes": {"xAxis": {"visible": true}, "yAxes": []}, "heatmapSettings": {}, "thresholds": [], "tableSettings": {}, "graphChartSettings": {}, "honeycombSettings": {}},
     "queriesSettings": {"resolution": ""},
     "metricExpressions": ["resolution=Inf&(sangfor.hci.host.cpu.usage:splitBy(\"dt.entity.sangfor_hci:host\"):avg:sort(value(avg,descending)):limit(10)):limit(100):names"]},
    {"name": "Top VMs by CPU", "tileType": "DATA_EXPLORER", "configured": true,
     "bounds": {"top": 380, "left": 627, "width": 627, "height": 304}, "tileFilter": {}, "customName": "Top VMs by CPU (%)",
     "queries": [{"id": "A", "metric": "sangfor.hci.vm.cpu.usage", "spaceAggregation": "AVG", "timeAggregation": "DEFAULT", "splitBy": ["dt.entity.sangfor_hci:vm"], "sortBy": "DESC", "filterBy": {"nestedFilters": [], "criteria": []}, "limit": 10, "rate": "NONE", "enabled": true}],
     "visualConfig": {"type": "TOP_LIST", "global": {}, "rules": [], "axes": {"xAxis": {"visible": true}, "yAxes": []}, "heatmapSettings": {}, "thresholds": [], "tableSettings": {}, "graphChartSettings": {}, "honeycombSettings": {}},
     "queriesSettings": {"resolution": ""},
     "metricExpressions": ["resolution=Inf&(sangfor.hci.vm.cpu.usage:splitBy(\"dt.entity.sangfor_hci:vm\"):avg:sort(value(avg,descending)):limit(10)):limit(100):names"]},
    {"name": "Datastore usage", "tileType": "DATA_EXPLORER", "configured": true,
     "bounds": {"top": 684, "left": 0, "width": 627, "height": 304}, "tileFilter": {}, "customName": "Datastore usage (%)",
     "queries": [{"id": "A", "metric": "sangfor.hci.datastore.usage", "spaceAggregation": "AVG", "timeAggregation": "DEFAULT", "splitBy": ["dt.entity.sangfor_hci:datastore"], "sortBy": "DESC", "filterBy": {"nestedFilters": [], "criteria": []}, "limit": 20, "rate": "NONE", "enabled": true}],
     "visualConfig": {"type": "TOP_LIST", "global": {}, "rules": [], "axes": {"xAxis": {"visible": true}, "yAxes": []}, "heatmapSettings": {}, "thresholds": [], "tableSettings": {}, "graphChartSettings": {}, "honeycombSettings": {}},
     "queriesSettings": {"resolution": ""},
     "metricExpressions": ["resolution=Inf&(sangfor.hci.datastore.usage:splitBy(\"dt.entity.sangfor_hci:datastore\"):avg:sort(value(avg,descending)):limit(20)):limit(100):names"]},
    {"name": "Unhealthy hardware", "tileType": "DATA_EXPLORER", "configured": true,
     "bounds": {"top": 684, "left": 627, "width": 627, "height": 304}, "tileFilter": {}, "customName": "Fans and RAID not OK (0 = failed)",
     "queries": [{"id": "A", "metric": "sangfor.hci.hw.fan.ok", "spaceAggregation": "MIN", "timeAggregation": "DEFAULT", "splitBy": ["dt.entity.sangfor_hci:host", "sangfor.fan"], "sortBy": "ASC", "filterBy": {"nestedFilters": [], "criteria": []}, "limit": 20, "rate": "NONE", "enabled": true},
                 {"id": "B", "metric": "sangfor.hci.hw.raid.ok", "spaceAggregation": "MIN", "timeAggregation": "DEFAULT", "splitBy": ["dt.entity.sangfor_hci:host", "sangfor.raid"], "sortBy": "ASC", "filterBy": {"nestedFilters": [], "criteria": []}, "limit": 20, "rate": "NONE", "enabled": true}],
     "visualConfig": {"type": "TABLE", "global": {}, "rules": [], "axes": {"xAxis": {"visible": true}, "yAxes": []}, "heatmapSettings": {}, "thresholds": [], "tableSettings": {}, "graphChartSettings": {}, "honeycombSettings": {}},
     "queriesSettings": {"resolution": ""},
     "metricExpressions": [
       "resolution=Inf&(sangfor.hci.hw.fan.ok:splitBy(\"dt.entity.sangfor_hci:host\",\"sangfor.fan\"):min:sort(value(min,ascending)):limit(20)):limit(100):names",
       "resolution=Inf&(sangfor.hci.hw.raid.ok:splitBy(\"dt.entity.sangfor_hci:host\",\"sangfor.raid\"):min:sort(value(min,ascending)):limit(20)):limit(100):names"]}
  ]
}
```

- [ ] **Step 7: Write `activation.json` (dev activation pointing at the simulator)**

These are the simulator's own throwaway credentials, so the file is safe to commit.

```json
{
  "enabled": true,
  "description": "Sangfor HCI simulator",
  "version": "0.1.0",
  "activationContext": "REMOTE",
  "featureSets": ["cluster", "host", "vm", "datastore", "hardware"],
  "pythonRemote": {
    "endpoints": [
      {
        "cluster_name": "sim-cluster",
        "mode": "both",
        "interval_seconds": 60,
        "vm_interval_seconds": 300,
        "timeout_seconds": 5,
        "api_url": "https://127.0.0.1:8443",
        "api_username": "dtmon",
        "api_password": "dtmon-pass",
        "api_verify_tls": false,
        "api_ca_pem": "",
        "snmp_version": "v3",
        "snmp_port": 161,
        "snmp_community": "",
        "snmp_v3_user": "dtmon",
        "snmp_v3_auth_protocol": "SHA",
        "snmp_v3_auth_key": "dtmon-auth-key",
        "snmp_v3_priv_protocol": "AES128",
        "snmp_v3_priv_key": "dtmon-priv-key",
        "snmp_v3_context_name": "sangfopub",
        "snmp_nodes": ["10.0.0.11=127.0.0.1:11161", "10.0.0.12=127.0.0.1:11162"]
      }
    ]
  }
}
```

- [ ] **Step 8: Run the tests to verify they pass**

Run: `.venv/bin/pytest tests/unit/test_emit.py tests/integration/test_extension_definition.py`
Expected: `15 passed`: 2 emit tests, plus 13 definition tests (6 base tests, and the dashboard test parametrized over 7 DATA_EXPLORER tiles).

- [ ] **Step 9: Write `scripts/smoke_run.py` and run it**

```python
"""Runs the real extension with `dt-sdk run` against the simulator and checks what it sends.

Usage: .venv/bin/python scripts/smoke_run.py   (exit code 0 = pass)
"""

from __future__ import annotations

import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from simulator.mock_api import make_server, write_self_signed_cert  # noqa: E402
from simulator.snmp_sim import start_agent  # noqa: E402

REQUIRED = (
    "send_metric: sangfor.hci.cluster.cpu.usage",
    "send_metric: sangfor.hci.host.cpu.usage",
    "send_metric: sangfor.hci.vm.cpu.usage",
    "send_metric: sangfor.hci.datastore.usage",
    "send_metric: sangfor.hci.hw.fan.ok",
    "Sending DT Event",
)
DEADLINE_SECONDS = 180


def main() -> int:
    cert, key = write_self_signed_cert(ROOT / "simulator" / ".certs")
    server, _ = make_server(port=8443, certfile=str(cert), keyfile=str(key))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    agents = [start_agent("node-a", 11161), start_agent("node-b", 11162)]
    dt_sdk = str(Path(sys.executable).parent / "dt-sdk")
    process = subprocess.Popen(
        [dt_sdk, "run"], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
    )
    seen: set[str] = set()
    started = time.monotonic()
    try:
        for line in process.stdout:
            sys.stdout.write(line)
            seen.update(marker for marker in REQUIRED if marker in line)
            if seen == set(REQUIRED) or time.monotonic() - started > DEADLINE_SECONDS:
                break
    finally:
        process.terminate()
        process.wait(timeout=20)
        for agent in agents:
            agent.terminate()
        server.shutdown()
    missing = sorted(set(REQUIRED) - seen)
    if missing:
        print(f"\nSMOKE FAILED, missing: {missing}")
        return 1
    print("\nSMOKE PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

Run: `.venv/bin/python scripts/smoke_run.py`
Expected: the last line is `SMOKE PASSED`, within 3 minutes. The SDK flushes metrics about once a minute.

If it prints `SMOKE FAILED`, read the log lines above the result. Typical causes:
- A traceback in `initialize`: compare `activation.json` with `parse_endpoint`.
- No `hw.` metrics: snmpsim did not start, or the v3 context name is wrong.
- No event: check the alarm cursor; alarms from the mock start 30 s before server start.

- [ ] **Step 10: Run the whole suite and commit**

Run: `.venv/bin/pytest`
Expected: `96 passed`

```bash
git add sangfor_hci/emit.py sangfor_hci/__main__.py extension activation.json scripts/smoke_run.py tests
git commit -m "feat: add extension entry point, definition, screens and dashboard

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 11: Field validation kit (read-only probe with redaction)

The probe runs on a real HCI (Rifqi or the customer runs it) and answers spec §11 Q1–Q10. It reuses the extension's own clients, so it inherits the GET-only allowlist. Its output zip is redacted:
- IPv4 addresses, MAC addresses and 12-hex host IDs become stable placeholders.
- Every name it has learned (hosts, VMs, groups, users, sysName) is replaced everywhere it appears.
- Serial-number fields are replaced.
- OIDs are kept, because they are dict keys and are never redacted.

**Files:**
- Create: `validation-kit/sangfor_probe.py`, `validation-kit/README.md`, `tests/integration/test_probe.py`

**Interfaces:**
- Consumes:
  - `SangforApiClient`, `SangforApiError` (Task 4)
  - `SnmpClient`, `SnmpTarget`, `SnmpError`, `oids` (Task 5)
  - `config.parse_node`, `config.ConfigError` (Task 2)
  - fixtures `mock_api` and `snmp_agents`
- Produces (`validation-kit/sangfor_probe.py`, loaded via importlib because the folder name has a hyphen):
  - `Redactor()` with:
    - `.learn(obj) -> None`
    - `.learn_name(text: str) -> None`
    - `.redact(obj) -> object`
    - `.text(value: str) -> str`
  - `main(argv: list[str] | None = None) -> int`
- Secrets come from environment variables (`SANGFOR_PASSWORD`, `SANGFOR_SNMP_COMMUNITY`, `SANGFOR_SNMP_AUTH_KEY`, `SANGFOR_SNMP_PRIV_KEY`), with an interactive prompt when one is unset. They are never accepted as CLI arguments, so they do not land in shell history.

- [ ] **Step 1: Write the failing tests**

`tests/integration/test_probe.py`:

```python
import importlib.util
import json
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("sangfor_probe", ROOT / "validation-kit" / "sangfor_probe.py")
probe = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(probe)


def test_redactor_is_consistent_and_keeps_oids():
    redactor = probe.Redactor()
    data = {
        "host_list": [{"id": "host-00e0ec000a11", "ip": "10.0.0.11", "name": "node-a", "sn": "SN123456"}],
        "description": "Host node-a (10.0.0.11) with MAC 00:e0:ec:00:0a:11 is fine",
        "walk": {"1.3.6.1.4.1.35047.3.2.1.2.1.1.0": "0.12", "1.3.6.1.2.1.1.5.0": "node-a"},
        "version": "SANGFOR aCloud 6.10.0_R2",
        "store": "350014ee0aed9e86a_00e0ec000a11",
    }
    redactor.learn(data)
    out = redactor.redact(data)
    text = json.dumps(out)
    for secret in ("10.0.0.11", "node-a", "00e0ec000a11", "00:e0:ec:00:0a:11", "SN123456"):
        assert secret not in text, secret
    assert out["host_list"][0]["ip"] in out["description"]
    assert out["host_list"][0]["name"] in out["description"]
    assert "1.3.6.1.4.1.35047.3.2.1.2.1.1.0" in out["walk"]
    assert out["walk"]["1.3.6.1.4.1.35047.3.2.1.2.1.1.0"] == "0.12"
    assert out["version"] == "SANGFOR aCloud 6.10.0_R2"


def test_probe_end_to_end_against_simulator(mock_api, snmp_agents, tmp_path, monkeypatch):
    base, state = mock_api
    monkeypatch.setenv("SANGFOR_PASSWORD", "dtmon-pass")
    monkeypatch.setenv("SANGFOR_SNMP_COMMUNITY", "sangfopub")
    out = tmp_path / "probe.zip"
    code = probe.main([
        "--url", base, "--user", "dtmon",
        "--snmp-version", "v2c", "--timeout", "2",
        "--snmp-node", "10.0.0.11=127.0.0.1:11161",
        "--snmp-node", "10.0.0.12=127.0.0.1:11163",
        "--out", str(out),
    ])
    assert code == 0
    assert all(request.startswith(("GET ", "POST /vapi/json/access/ticket")) for request in state.requests)
    with zipfile.ZipFile(out) as bundle:
        names = set(bundle.namelist())
        assert {"meta.json", "api/overview.json", "api/host_list.json", "api/node_info.json", "api/alerts.json"} <= names
        everything = "\n".join(bundle.read(n).decode("utf-8") for n in names)
        meta = json.loads(bundle.read("meta.json"))
    for secret in ("10.0.0.11", "10.0.0.12", "127.0.0.1", "node-a", "node-b", "app-01", "00e0ec000a11", "dtmon-pass"):
        assert secret not in everything, secret
    assert all(check["ok"] for check in meta["api_checks"])
    subtrees = sorted(node["has_private_subtree"] for node in meta["snmp_nodes"])
    assert subtrees == [False, True]
    assert {"optimal", "ok"} <= set(meta["status_values_seen"])
    assert meta["sangfor_versions"]


def test_probe_reports_failure_when_nothing_answers(tmp_path, monkeypatch):
    monkeypatch.setenv("SANGFOR_PASSWORD", "x")
    code = probe.main(["--url", "http://127.0.0.1:9", "--user", "dtmon", "--timeout", "1", "--out", str(tmp_path / "p.zip")])
    assert code == 2
    assert (tmp_path / "p.zip").exists()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/pytest tests/integration/test_probe.py`
Expected: FAIL with `FileNotFoundError` for `validation-kit/sangfor_probe.py`.

- [ ] **Step 3: Implement `validation-kit/sangfor_probe.py`**

```python
#!/usr/bin/env python3
"""Read-only probe of a real Sangfor HCI, for the dt-sangfor-ext developers.

It logs in, sends GET requests only to the endpoints the extension uses, and walks the Sangfor
private SNMP subtree (1.3.6.1.4.1.35047.3.2.1) on each node you name. It never changes anything:
the API client refuses every path outside a read-only allowlist.

Output: one zip in which IP and MAC addresses, host IDs, serial numbers and every learned name are
replaced with stable placeholders. Open it and check it before you send it on.

Secrets are read from environment variables, or prompted for:
  SANGFOR_PASSWORD, SANGFOR_SNMP_COMMUNITY (v2c), SANGFOR_SNMP_AUTH_KEY, SANGFOR_SNMP_PRIV_KEY (v3)

Example:
  .venv/bin/python validation-kit/sangfor_probe.py --url https://10.1.2.3 --user dtmon \
      --snmp-version v3 --v3-user dtmon --snmp-node 10.1.2.11 --snmp-node 10.1.2.12
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import sys
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from sangfor_hci.api.client import SangforApiClient, SangforApiError  # noqa: E402
from sangfor_hci.config import ConfigError, parse_node  # noqa: E402
from sangfor_hci.snmp import oids  # noqa: E402
from sangfor_hci.snmp.client import SnmpClient, SnmpError, SnmpTarget  # noqa: E402

PROBE_VERSION = "1"
API_ENDPOINTS = (
    ("overview", "/vapi/json/index/overview", None),
    ("host_list", "/vapi/json/index/host_list", None),
    ("storelist", "/vapi/json/vtpstorage/storelist", None),
    ("vms", "/vapi/json/cluster/vms", None),
    ("alerts", "/vapi/json/log/alert/all", {"distinct": 0, "limit": 50, "direct": "DESC"}),
)
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
BARE_HEX12 = re.compile(r"(?<![0-9A-Za-z])(?=[0-9]*[a-fA-F])[0-9a-fA-F]{12}(?![0-9A-Za-z])")
NAME_KEYS = {"name", "hostname", "object_name", "target", "groupname", "owner", "user", "label", "displayname", "bridgename"}
SECRET_KEYS = {"sn", "serial", "serial_number", "license", "uuid", "mac"}
STATUS_TABLES = ("fan", "raid")


class Redactor:
    def __init__(self) -> None:
        self._tokens: dict[tuple[str, str], str] = {}
        self._counts: dict[str, int] = {}
        self._names: dict[str, str] = {}

    def _token(self, kind: str, value: str) -> str:
        key = (kind, value)
        if key not in self._tokens:
            number = self._counts[kind] = self._counts.get(kind, 0) + 1
            self._tokens[key] = f"10.255.{number // 256}.{number % 256}" if kind == "ip" else f"{kind}-{number:03d}"
        return self._tokens[key]

    def learn_name(self, text: str) -> None:
        text = text.strip()
        if len(text) >= 3 and not IPV4.fullmatch(text) and text not in self._names:
            self._names[text] = self._token("name", text)

    def learn(self, obj: object, key: str = "") -> None:
        if isinstance(obj, dict):
            for child_key, value in obj.items():
                self.learn(value, str(child_key).lower())
        elif isinstance(obj, list):
            for value in obj:
                self.learn(value, key)
        elif isinstance(obj, str) and key in NAME_KEYS:
            self.learn_name(obj)

    def text(self, value: str) -> str:
        for name in sorted(self._names, key=len, reverse=True):
            value = value.replace(name, self._names[name])
        value = MAC.sub(lambda m: self._token("mac", m.group(0)), value)
        value = BARE_HEX12.sub(lambda m: self._token("hex", m.group(0)), value)
        return IPV4.sub(lambda m: self._token("ip", m.group(0)), value)

    def redact(self, obj: object, key: str = "") -> object:
        if isinstance(obj, dict):
            return {child_key: self.redact(value, str(child_key).lower()) for child_key, value in obj.items()}
        if isinstance(obj, list):
            return [self.redact(value, key) for value in obj]
        if isinstance(obj, str):
            return self._token(key, obj) if key in SECRET_KEYS else self.text(obj)
        return obj


def _secret(env_name: str, prompt: str) -> str:
    value = os.environ.get(env_name)
    if value is not None:
        return value
    return getpass.getpass(prompt)


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Read-only Sangfor HCI probe for dt-sangfor-ext")
    parser.add_argument("--url", help="Sangfor API URL, e.g. https://10.1.2.3 (omit to probe SNMP only)")
    parser.add_argument("--user", default="", help="Sangfor API user (read-only account recommended)")
    parser.add_argument("--insecure", action="store_true", help="do not verify the HCI TLS certificate")
    parser.add_argument("--ca-file", help="PEM file of the CA that signed the HCI certificate")
    parser.add_argument("--snmp-node", action="append", default=[], help="IP or IP=ADDRESS:PORT; repeat per node")
    parser.add_argument("--snmp-port", type=int, default=161)
    parser.add_argument("--snmp-version", choices=("v2c", "v3"), default="v3")
    parser.add_argument("--v3-user", default="")
    parser.add_argument("--v3-auth-protocol", choices=("MD5", "SHA", "SHA256"), default="SHA")
    parser.add_argument("--v3-priv-protocol", choices=("NONE", "DES", "AES128", "AES256"), default="AES128")
    parser.add_argument("--v3-context", default="")
    parser.add_argument("--timeout", type=float, default=10.0)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    parser.add_argument("--out", default=f"validation-output/sangfor-probe-{stamp}.zip")
    return parser.parse_args(argv)


def probe_api(args: argparse.Namespace) -> tuple[dict[str, object], list[dict]]:
    raw: dict[str, object] = {}
    checks: list[dict] = []
    if not args.url:
        return raw, checks
    password = _secret("SANGFOR_PASSWORD", "Sangfor API password: ")
    ca_pem = Path(args.ca_file).read_text(encoding="utf-8") if args.ca_file else ""
    client = SangforApiClient(
        args.url, args.user, password, verify_tls=not args.insecure, ca_pem=ca_pem, timeout=args.timeout
    )

    def call(name: str, path: str, params: dict | None) -> object:
        started = time.perf_counter()
        try:
            data = client.get(path, params)
            checks.append({"endpoint": name, "ok": True, "ms": round((time.perf_counter() - started) * 1000)})
            return data
        except SangforApiError as exc:
            checks.append(
                {"endpoint": name, "ok": False, "reason": exc.reason, "error": str(exc),
                 "ms": round((time.perf_counter() - started) * 1000)}
            )
            raise

    try:
        for name, path, params in API_ENDPOINTS:
            try:
                raw[name] = call(name, path, params)
            except SangforApiError as exc:
                if exc.reason in ("auth", "tls", "timeout"):
                    return raw, checks  # nothing more to learn if we cannot log in or connect
        infos = []
        for item in raw.get("host_list") if isinstance(raw.get("host_list"), list) else []:
            host_id = str(item.get("id", "")) if isinstance(item, dict) else ""
            if host_id:
                try:
                    infos.append({"host_id": host_id, "info": call("node_info", f"/vapi/json/nodes/{host_id}/info", None)})
                except SangforApiError:
                    continue
        raw["node_info"] = infos
    finally:
        client.close()
    return raw, checks


def probe_snmp(args: argparse.Namespace) -> list[dict]:
    if not args.snmp_node:
        return []
    community = auth_key = priv_key = ""
    if args.snmp_version == "v2c":
        community = _secret("SANGFOR_SNMP_COMMUNITY", "SNMP v2c community (empty = sangfopub): ") or "sangfopub"
    else:
        auth_key = _secret("SANGFOR_SNMP_AUTH_KEY", "SNMP v3 auth key: ")
        if args.v3_priv_protocol != "NONE":
            priv_key = _secret("SANGFOR_SNMP_PRIV_KEY", "SNMP v3 privacy key: ")
    records = []
    for entry in args.snmp_node:
        try:
            node = parse_node(entry, args.snmp_port)
        except ConfigError as exc:
            records.append({"node": entry, "error": str(exc)})
            continue
        client = SnmpClient(
            SnmpTarget(
                node.address, node.port, args.snmp_version, timeout=args.timeout, community=community,
                v3_user=args.v3_user, v3_auth_protocol=args.v3_auth_protocol, v3_auth_key=auth_key,
                v3_priv_protocol=args.v3_priv_protocol, v3_priv_key=priv_key, v3_context_name=args.v3_context,
            )
        )
        record: dict = {"host_ip": node.host_ip, "snmp_version": args.snmp_version}
        started = time.perf_counter()
        try:
            record["scalars"] = client.get([oids.SYS_DESCR, oids.SYS_NAME, oids.VERSION])
            record["has_private_subtree"] = client.has_subtree(oids.ROOT)
            record["walk"] = client.walk(oids.ROOT) if record["has_private_subtree"] else {}
        except SnmpError as exc:
            record["error"] = str(exc)
        record["ms"] = round((time.perf_counter() - started) * 1000)
        records.append(record)
    return records


def status_values(records: list[dict]) -> list[str]:
    found = set()
    for table in oids.TABLES:
        if table.name not in STATUS_TABLES:
            continue
        for column in table.columns:
            if column.kind != "status":
                continue
            prefix = table.column_oid(column.suffix) + "."
            for record in records:
                found.update(v.strip().lower() for oid, v in record.get("walk", {}).items() if oid.startswith(prefix))
    return sorted(found)


def versions(raw: dict, records: list[dict]) -> list[str]:
    found = {str(entry["info"].get("os_version")) for entry in raw.get("node_info", []) if isinstance(entry.get("info"), dict) and entry["info"].get("os_version")}
    found.update(r["scalars"][oids.VERSION] for r in records if oids.VERSION in r.get("scalars", {}))
    return sorted(found)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    raw, checks = probe_api(args)
    records = probe_snmp(args)

    redactor = Redactor()
    redactor.learn(raw)
    for record in records:
        name = record.get("scalars", {}).get(oids.SYS_NAME)
        if name:
            redactor.learn_name(name)
    meta = {
        "probe_version": PROBE_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "api_url": args.url or "",
        "sangfor_versions": versions(raw, records),
        "status_values_seen": status_values(records),
        "api_checks": checks,
        "snmp_nodes": [
            {key: value for key, value in record.items() if key not in ("walk", "scalars")} for record in records
        ],
    }

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("meta.json", json.dumps(redactor.redact(meta), indent=2, ensure_ascii=False))
        for name, data in raw.items():
            bundle.writestr(f"api/{name}.json", json.dumps(redactor.redact(data), indent=2, ensure_ascii=False))
        for record in records:
            label = redactor.text(record.get("host_ip", record.get("node", "unknown")))
            bundle.writestr(f"snmp/{label}.json", json.dumps(redactor.redact(record), indent=2, ensure_ascii=False))

    api_ok = any(check["ok"] for check in checks)
    snmp_ok = any("error" not in record for record in records)
    print(f"Wrote {out}  (API {'OK' if api_ok else 'FAILED'}, SNMP {'OK' if snmp_ok else 'FAILED or skipped'})")
    print("Open the zip and check that nothing sensitive is left before you share it.")
    return 0 if (api_ok or snmp_ok) else 2


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Write `validation-kit/README.md`**

````markdown
# Sangfor HCI validation kit

`sangfor_probe.py` checks what a real Sangfor HCI returns, so the extension can be confirmed against it.
It is read-only: it logs in, sends GET requests to six endpoints, and walks one SNMP subtree.

## Before you run it

- Use a read-only Sangfor account.
- Enable SNMP on HCI (System Management > Port Management > SNMP) if you want hardware data.
- Run it from a machine that can reach the HCI on TCP 443 and each node on UDP 161, ideally the ActiveGate host.

## Run

```bash
git clone https://github.com/rifqifitriady/dt-sangfor-ext && cd dt-sangfor-ext
python3 -m venv .venv && .venv/bin/pip install -e .
export SANGFOR_PASSWORD='...'          # or leave unset to be prompted
export SANGFOR_SNMP_AUTH_KEY='...'     # SNMP v3
export SANGFOR_SNMP_PRIV_KEY='...'     # SNMP v3
.venv/bin/python validation-kit/sangfor_probe.py \
  --url https://<cluster-vip> --user <read-only-user> \
  --snmp-version v3 --v3-user <snmp-user> \
  --snmp-node <node-1-ip> --snmp-node <node-2-ip>
```

For SNMP v2c, use `--snmp-version v2c` and `SANGFOR_SNMP_COMMUNITY`. Empty means `sangfopub`.
If the HCI uses a self-signed certificate, pass `--ca-file hci-ca.pem`, or `--insecure`.

## Output

The output is `validation-output/sangfor-probe-<time>.zip`. In it, IP and MAC addresses, host IDs, serial numbers
and host, VM and user names are replaced with placeholders such as `10.255.0.3` and `name-007`.
**Open it and check it before sharing.** `meta.json` summarises the result: versions, endpoint status, which
nodes expose the Sangfor private MIB, and the raw fan and RAID status words.
````

- [ ] **Step 5: Run the tests to verify they pass**

Run: `.venv/bin/pytest tests/integration/test_probe.py`
Expected: `3 passed`

- [ ] **Step 6: Commit**

```bash
git add validation-kit tests/integration/test_probe.py
git commit -m "feat: add read-only field validation kit with redaction

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 12: Signed build, package verification and README

**Files:**
- Create: `scripts/check_package.py`, `tests/unit/test_check_package.py`
- Modify: `README.md` (full rewrite)

**Interfaces:**
- Consumes: the whole extension (Tasks 1–10).
- Produces (`scripts/check_package.py`):
  - `MAX_BYTES = 25 * 1024 * 1024`
  - `REQUIRED_WHEELS: tuple[str, ...]` (regex patterns)
  - `check(package: Path) -> list[str]` (problems; empty means OK)
  - CLI: `python scripts/check_package.py <zip>`, which exits 0 and prints `PACKAGE OK (<n> MB)` on success

- [ ] **Step 1: Write the failing tests**

`tests/unit/test_check_package.py`:

```python
import importlib.util
import io
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("check_package", ROOT / "scripts" / "check_package.py")
check_package = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_package)

GOOD_WHEELS = [
    "cryptography-50.0.2-cp39-abi3-manylinux2014_x86_64.manylinux_2_17_x86_64.whl",
    "cryptography-50.0.2-cp311-abi3-manylinux2014_x86_64.manylinux_2_17_x86_64.whl",
    "cryptography-50.0.2-cp39-abi3-win_amd64.whl",
    "cryptography-50.0.2-cp311-abi3-win_amd64.whl",
    "cffi-2.1.1-cp310-cp310-manylinux2014_x86_64.manylinux_2_17_x86_64.whl",
    "cffi-2.1.1-cp314-cp314-manylinux2014_x86_64.manylinux_2_17_x86_64.whl",
    "cffi-2.1.1-cp310-cp310-win_amd64.whl",
    "cffi-2.1.1-cp314-cp314-win_amd64.whl",
    "pysnmp-7.1.31-py3-none-any.whl",
    "requests-2.34.2-py3-none-any.whl",
    "dt_extensions_sdk-1.11.3-py3-none-any.whl",
    "sangfor_hci-0.1.0-py3-none-any.whl",
]


def make_package(tmp_path, wheels, with_sig=True):
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as z:
        z.writestr("extension.yaml", "name: custom:sangfor-hci\n")
        for wheel in wheels:
            z.writestr(f"lib/{wheel}", b"x")
    path = tmp_path / "custom_sangfor-hci-0.1.0.zip"
    with zipfile.ZipFile(path, "w") as outer:
        outer.writestr("extension.zip", inner.getvalue())
        if with_sig:
            outer.writestr("extension.zip.sig", b"sig")
    return path


def test_good_package_passes(tmp_path):
    assert check_package.check(make_package(tmp_path, GOOD_WHEELS)) == []


def test_missing_windows_wheel_and_signature_are_reported(tmp_path):
    wheels = [w for w in GOOD_WHEELS if w != "cryptography-50.0.2-cp311-abi3-win_amd64.whl"]
    problems = check_package.check(make_package(tmp_path, wheels, with_sig=False))
    assert any("extension.zip.sig" in p for p in problems)
    assert any("cp311-abi3-win_amd64" in p for p in problems)


def test_macos_wheels_are_rejected(tmp_path):
    wheels = GOOD_WHEELS + ["cryptography-50.0.2-cp311-abi3-macosx_11_0_arm64.whl"]
    assert any("macosx" in p for p in check_package.check(make_package(tmp_path, wheels)))


def test_size_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(check_package, "MAX_BYTES", 10)
    assert any("25 MB" in p or "limit" in p for p in check_package.check(make_package(tmp_path, GOOD_WHEELS)))
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/pytest tests/unit/test_check_package.py`
Expected: FAIL with `FileNotFoundError` for `scripts/check_package.py`.

- [ ] **Step 3: Implement `scripts/check_package.py`**

```python
"""Checks a built extension package: size, signature, and wheels for every target platform.

Usage: .venv/bin/python scripts/check_package.py dist/<package>.zip
"""

from __future__ import annotations

import io
import re
import sys
import zipfile
from pathlib import Path

MAX_BYTES = 25 * 1024 * 1024
REQUIRED_WHEELS = (
    r"cryptography-50\.0\.2-cp39-abi3-.*manylinux2014_x86_64.*\.whl",
    r"cryptography-50\.0\.2-cp311-abi3-.*manylinux2014_x86_64.*\.whl",
    r"cryptography-50\.0\.2-cp39-abi3-win_amd64\.whl",
    r"cryptography-50\.0\.2-cp311-abi3-win_amd64\.whl",
    r"cffi-.*-cp310-cp310-.*manylinux.*x86_64.*\.whl",
    r"cffi-.*-cp314-cp314-.*manylinux.*x86_64.*\.whl",
    r"cffi-.*-cp310-cp310-win_amd64\.whl",
    r"cffi-.*-cp314-cp314-win_amd64\.whl",
    r"pysnmp-7\.1\.31-py3-none-any\.whl",
    r"requests-2\.34\.2-py3-none-any\.whl",
    r"dt_extensions_sdk-1\.11\.3-py3-none-any\.whl",
    r"sangfor_hci-.*-py3-none-any\.whl",
)
FORBIDDEN_WHEELS = (r"macosx",)


def check(package: Path) -> list[str]:
    problems = []
    size = package.stat().st_size
    if size >= MAX_BYTES:
        problems.append(f"package is {size / 1048576:.1f} MB, over the 25 MB limit")
    with zipfile.ZipFile(package) as outer:
        names = set(outer.namelist())
        for required in ("extension.zip", "extension.zip.sig"):
            if required not in names:
                problems.append(f"missing {required} (was the package signed?)")
        if "extension.zip" not in names:
            return problems
        inner_names = zipfile.ZipFile(io.BytesIO(outer.read("extension.zip"))).namelist()
    if "extension.yaml" not in inner_names:
        problems.append("extension.zip has no extension.yaml")
    wheels = [Path(name).name for name in inner_names if name.endswith(".whl")]
    for pattern in REQUIRED_WHEELS:
        if not any(re.fullmatch(pattern, wheel) for wheel in wheels):
            problems.append(f"no wheel matching {pattern}")
    for pattern in FORBIDDEN_WHEELS:
        bad = [wheel for wheel in wheels if re.search(pattern, wheel)]
        if bad:
            problems.append(f"unexpected {pattern} wheels (build with --only-extra-platforms): {bad}")
    return problems


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: check_package.py <package.zip>")
        return 2
    package = Path(argv[0])
    problems = check(package)
    if problems:
        print("PACKAGE NOT OK")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print(f"PACKAGE OK ({package.stat().st_size / 1048576:.1f} MB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/bin/pytest tests/unit/test_check_package.py`
Expected: `4 passed`

- [ ] **Step 5: Generate signing certificates (outside the repo)**

Run: `ls ~/.dynatrace/certificates/ 2>/dev/null || .venv/bin/dt-sdk gencerts`
Expected: `~/.dynatrace/certificates/` contains `ca.pem`, `ca.key` and `developer.pem`. If the directory already existed with these files, keep them: they are the same CA the environments already trust.

Run: `git status --porcelain | grep -E '\.(pem|key)$' || echo "no certificates in repo"`
Expected: `no certificates in repo`

- [ ] **Step 6: Build and verify the package**

Run:

```bash
rm -rf dist
.venv/bin/dt-sdk build --only-extra-platforms -e manylinux2014_x86_64 -e win_amd64 -p 3.10 -p 3.14
ls dist/
.venv/bin/python scripts/check_package.py dist/*.zip
```

Expected: one zip in `dist/`, and `PACKAGE OK (<about 18–21> MB)`.

If a cffi pattern fails because pip resolved a different platform tag (for example `manylinux_2_17` only), read the actual wheel names with `unzip -l dist/*.zip` and `unzip -p dist/*.zip extension.zip | python -c "import sys,zipfile,io; print(*zipfile.ZipFile(io.BytesIO(sys.stdin.buffer.read())).namelist(), sep='\n')"`. Then widen only that pattern in `REQUIRED_WHEELS` and its test.

- [ ] **Step 7: Rewrite `README.md`**

````markdown
# dt-sangfor-ext

`custom:sangfor-hci` is a Dynatrace Managed extension (Extensions 2.0, Python) that monitors Sangfor HCI clusters.
It collects data over two paths, chosen per cluster:

| Mode | Collects |
|---|---|
| `api` | Cluster, host, VM and datastore metrics, and Sangfor alarms as Dynatrace events (REST API) |
| `snmp` | Host CPU and memory plus hardware health per node: CPU temperature, fans, RAID, SSD life, filesystems, optical power (Sangfor private MIB 1.3.6.1.4.1.35047.3.2.1) |
| `both` (default) | Everything above. The API is authoritative for overlapping metrics, and SNMP takes over host CPU and memory if the API fails |

Entities: `sangfor_hci:cluster` → `sangfor_hci:host` → `sangfor_hci:vm`, and `sangfor_hci:datastore` → cluster.
The extension also ships screens for each entity and a classic dashboard, "Sangfor HCI overview".
The design and its open questions are in [docs/superpowers/specs/](docs/superpowers/specs/).

## Requirements

- Dynatrace Managed with an **Environment ActiveGate** (not a Cluster ActiveGate) in an ActiveGate group.
  - ActiveGate 1.333 or newer runs the Python 3.14 runtime. Older ActiveGates use the bundled 3.10 build.
  - Python 3.10 support ended on 2026-10-26.
- Network from the ActiveGate: TCP 443 to the HCI cluster VIP, and UDP 161 to every HCI node.
- Sangfor side:
  - A read-only API account.
  - SNMP enabled under System Management > Port Management > SNMP. v3 is recommended; for v2c the community is reported to be `sangfopub`.

## Install on Dynatrace Managed

1. **Trust the signing CA**
   - Add `~/.dynatrace/certificates/ca.pem` to the Credential Vault of each environment: type *Public certificate*, scope *Extension validation*.
   - Copy the same file to every ActiveGate in the group, and make it readable by `dtuserag`:
     - Linux: `/var/lib/dynatrace/remotepluginmodule/agent/conf/certificates/`
     - Windows: `%PROGRAMDATA%\dynatrace\remotepluginmodule\agent\conf\certificates`
2. **Upload the package.** The API token needs `extensions.read` and `extensions.write`:

   ```bash
   export DT_API_URL=https://<managed-domain>/e/<environment-id>
   export DT_API_TOKEN=<token>
   export REQUESTS_CA_BUNDLE=<managed-ca.pem>   # only if the Managed endpoint uses a private CA
   .venv/bin/dt-sdk upload dist/<package>.zip
   ```

3. **Add a monitoring configuration** for each Sangfor cluster (Extensions → custom:sangfor-hci): choose the ActiveGate group and the feature sets, then fill in the fields below.

| Field | Notes |
|---|---|
| Cluster name | Unique, and used as the entity identity. Do not rename it later. |
| Collection mode | `both`, `api` or `snmp` |
| Polling interval / VM polling interval | 60 s and 300 s by default. VM metrics dominate the cost; see below. |
| API URL, user, password | For example `https://10.0.0.10`. A read-only account is recommended. |
| Verify TLS / Custom CA | HCI usually has a self-signed certificate: paste its CA rather than switching verification off. |
| SNMP version, community or v3 user and keys, context | v3 with SHA and AES128 by default. The context is usually empty. |
| SNMP nodes | `IP` or `IP=ADDRESS:PORT` per node. Empty in `both` mode means: use the host IPs from the API. |

## Ingest volume (DDU)

Each data point costs 0.001 DDU. Per day:

```
DDU/day ≈ 1.44 × (9 + 55 × hosts + 10 × datastores)          # cluster, host, hardware, datastore at 60 s
        + 0.00288 × 8 × VMs × (300 / vm_interval_seconds)      # 8 VM metrics
```

Examples: 4 hosts, 100 VMs and 5 datastores come to about 0.6k DDU/day. 8 hosts, 500 VMs and 10 datastores come to about 1.9k DDU/day.
The 55 series per host is an estimate that depends on the hardware. To lower the cost, turn off the `vm` feature set or raise the VM interval.

## Develop

```bash
uv venv -p /opt/homebrew/bin/python3.14 .venv
uv pip install -p .venv/bin/python -r requirements-dev.txt
.venv/bin/pytest                                   # unit + integration against the simulator
.venv/bin/python scripts/smoke_run.py              # real `dt-sdk run` against the simulator
```

Simulator, for manual runs:

| Command | Starts |
|---|---|
| `.venv/bin/python -m simulator.mock_api` | Mock REST API at https://127.0.0.1:8443. User `dtmon`, password `dtmon-pass`. Scenarios: `healthy`, `host_offline`, `datastore_90`, `ticket_expired` |
| `.venv/bin/python -m simulator.snmp_sim` | SNMP agents node-a (UDP 11161), node-b (11162) and bare (11163, no private MIB) |
| `.venv/bin/dt-sdk run` | The extension, using `activation.json` |

## Build

```bash
.venv/bin/dt-sdk gencerts      # once; certificates stay in ~/.dynatrace/certificates, never in this repo
.venv/bin/dt-sdk build --only-extra-platforms -e manylinux2014_x86_64 -e win_amd64 -p 3.10 -p 3.14
.venv/bin/python scripts/check_package.py dist/*.zip
```

Raise `version` in `extension/extension.yaml` before every upload; Dynatrace rejects a version it already has.

## Validate against a real HCI

See [validation-kit/README.md](validation-kit/README.md). The probe is read-only and produces a redacted zip.
It answers the open questions in the spec: units of VM disk and network values, datastore status flags,
SNMP value formats and status words, and the SNMP versions each node answers.
````

- [ ] **Step 8: Run the whole suite and commit**

Run: `.venv/bin/pytest`
Expected: `103 passed`

```bash
git add scripts/check_package.py tests/unit/test_check_package.py README.md
git commit -m "feat: add package verification and operator README

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 13: End-to-end on Dynatrace Managed (with Rifqi; needs environment access)

This task needs things the developer machine does not have:
- A reachable Managed environment. The `dynatrace-managed-mcp` connection to `ewe502.dynatrace-managed.com` failed on 2026-11-07, so check VPN and token first.
- An Environment ActiveGate.
- Ideally a real Sangfor HCI.

Do not run any upload or configuration change without Rifqi confirming the target environment.

**Files:**
- Create: `docs/validation/2026-MM-DD-managed-e2e.md`. Use the real run date; the template is in Step 6.
- Modify, only if validation fails: `extension/extension.yaml`, `extension/activationSchema.json`, `extension/dashboards/sangfor-hci-overview.json`

**Interfaces:**
- Consumes: the signed package from Task 12 and the validation kit from Task 11.
- Produces: a validated extension version, and recorded answers to spec §11.

- [ ] **Step 1: Confirm the target with Rifqi**

Ask for:
- the environment URL (`https://<domain>/e/<env-id>`);
- an API token with `extensions.read`, `extensions.write` and `ReadConfig`;
- the ActiveGate group name and the ActiveGate version;
- whether a non-production environment is available.

Record the answers in the validation note. Continue only after explicit confirmation.

- [ ] **Step 2: Validate the package against the environment's schemas (no install)**

```bash
export DT_API_URL=https://<domain>/e/<env-id> DT_API_TOKEN=<token>
.venv/bin/dt-sdk upload dist/*.zip --validate
```

Expected: validation succeeds. If it reports schema errors in `screens`, `topology`, the dashboard or the activation schema, fix exactly the reported paths, then rerun `.venv/bin/pytest` and the Task 12 build. Repeat until validation passes. Common fixes:
- Remove an unsupported key that the error names.
- Change `iconPattern` to a value the environment accepts.
- Drop `metricExpressions` from a dashboard tile.

Commit each fix with a message naming the error.

- [ ] **Step 3: Install**

1. With Rifqi, add `~/.dynatrace/certificates/ca.pem` to the environment's Credential Vault (*Public certificate*, scope *Extension validation*).
2. Copy the same file to each ActiveGate in the group at `/var/lib/dynatrace/remotepluginmodule/agent/conf/certificates/ca.pem`, owned or readable by `dtuserag`.
3. Run `.venv/bin/dt-sdk upload dist/*.zip`.

Expected: the upload succeeds and `custom:sangfor-hci 0.1.0` appears under Extensions.

- [ ] **Step 4: Field probe and monitoring configuration**

1. Rifqi or the customer runs `validation-kit/sangfor_probe.py` against the HCI from the ActiveGate host, then reviews and shares the zip.
2. Store the shared zip outside the repo. Copy only the reviewed JSON into `simulator/fixtures/field/<hci-version>/` and commit it.
3. Create one monitoring configuration in `both` mode with all feature sets enabled.

- [ ] **Step 5: Check the v1 success criteria (spec §10)**

| # | Criterion | How to check |
|---|---|---|
| 1 | All four entity types with relationships | Entity list for each `sangfor_hci:*` type; host page lists VMs; cluster page lists hosts and datastores |
| 2 | Every supported metric non-empty | Data explorer for each `sangfor.hci.*` key in `extension.yaml` |
| 3 | An alarm becomes an event on the right entity within 2 cycles | Trigger or wait for a Sangfor alarm; check the entity's events |
| 4 | Extension status OK for 24 h | Extensions → custom:sangfor-hci → monitoring configuration status |
| 5 | ActiveGate within default limits (5% CPU, 500 MB) | ActiveGate host metrics for the extension process |

- [ ] **Step 6: Write the validation note and close the open questions**

Create `docs/validation/<date>-managed-e2e.md`:

```markdown
# Managed end-to-end validation, <date>

- Environment: <domain>/e/<env-id> (non-production: yes/no)
- Managed cluster version: <x>  ActiveGate version: <y>  Python runtime used: <3.10/3.14>
- Sangfor HCI version(s): <from probe meta.json>
- Package: custom:sangfor-hci <version>, <size> MB

## Success criteria
| # | Result | Evidence |
|---|---|---|
| 1 | pass/fail | ... |
| 2 | pass/fail | ... |
| 3 | pass/fail | ... |
| 4 | pass/fail | ... |
| 5 | pass/fail | ... |

## Open questions (spec §11)
| # | Answer | Source (probe file / UI) | Code change needed |
|---|---|---|---|
| Q1 ... Q10 | ... | ... | ... |
```

For every answer that differs from the current default, open a follow-up task (unit and fixture update first, then code), and set `minDynatraceVersion` to the verified cluster version (Q7).

- [ ] **Step 7: Commit**

```bash
git add docs/validation simulator/fixtures/field
git commit -m "docs: record Managed end-to-end validation results

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

