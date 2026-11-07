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
