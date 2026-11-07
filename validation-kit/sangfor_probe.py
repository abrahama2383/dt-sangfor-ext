#!/usr/bin/env python3
"""Read-only probe of a real Sangfor HCI, for the dt-sangfor-ext developers.

It logs in once, sends GET requests only to the endpoints the extension uses, and walks the Sangfor
private SNMP subtree (1.3.6.1.4.1.35047.3.2.1) on each node you name. It never changes anything:
the API client refuses every path outside a read-only allowlist.

Output: one zip in which IP, IPv6 and MAC addresses, e-mail addresses, host names, WWNs, host IDs,
serial numbers and every learned name are replaced with stable placeholders. The raw fan/RAID status
words and the Sangfor version strings are kept. Open the zip and check it before you send it on.
The zip is written even when something fails; the exit code is 0 when everything answered, 1 when
some checks failed and 2 when nothing answered.

Secrets are prompted for (input hidden). To run unattended, put them in the environment without
typing them on the command line, e.g. `read -rs SANGFOR_PASSWORD && export SANGFOR_PASSWORD`:
  SANGFOR_PASSWORD, SANGFOR_SNMP_COMMUNITY (v2c), SANGFOR_SNMP_AUTH_KEY, SANGFOR_SNMP_PRIV_KEY (v3)

Example:
  .venv/bin/python validation-kit/sangfor_probe.py --url https://10.1.2.3 --user dtmon \
      --snmp-version v3 --v3-user dtmon --snmp-node 10.1.2.11 --snmp-node 10.1.2.12
"""

from __future__ import annotations

import argparse
import getpass
import ipaddress
import json
import os
import re
import sys
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from sangfor_hci.api.client import SangforApiClient, SangforApiError  # noqa: E402
from sangfor_hci.config import ConfigError, parse_node  # noqa: E402
from sangfor_hci.snmp import oids  # noqa: E402
from sangfor_hci.snmp.client import SnmpClient, SnmpError, SnmpTarget  # noqa: E402

PROBE_VERSION = "2"
API_ENDPOINTS = (
    ("overview", "/vapi/json/index/overview", None),
    ("host_list", "/vapi/json/index/host_list", None),
    ("storelist", "/vapi/json/vtpstorage/storelist", None),
    ("vms", "/vapi/json/cluster/vms", None),
    ("alerts", "/vapi/json/log/alert/all", {"distinct": 0, "limit": 50, "direct": "DESC"}),
)
STOP_REASONS = ("tls", "timeout", "unreachable", "network")  # the API cannot be reached: nothing more to learn
MAX_AUTH_STREAK = 2  # two endpoints in a row rejecting the ticket: stop (at most 1 + 2 ticket POSTs)

_HEX = "0-9A-Fa-f"
EMAIL = re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,63}(?![A-Za-z0-9-])")
CISCO_MAC = re.compile(rf"(?<![0-9A-Za-z.])[{_HEX}]{{4}}\.[{_HEX}]{{4}}\.[{_HEX}]{{4}}(?![0-9A-Za-z]|\.[0-9A-Za-z])")
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
FQDN = re.compile(rf"(?<![A-Za-z0-9._@-])(?:{_LABEL}\.)+[A-Za-z]{{2,63}}(?![A-Za-z0-9_-]|\.[A-Za-z0-9])")
SERIAL_PHRASE = re.compile(
    r"\b(?:S/?N|serial(?:\s*(?:no|number))?)[:#\s]+(?=[A-Za-z-]*\d)([A-Za-z0-9-]{4,})", re.IGNORECASE
)
FILE_EXTENSIONS = {"img", "qcow2", "vmdk", "iso", "log", "txt", "json", "xml", "conf", "cfg", "tar", "gz", "zip", "bin"}
UUID = re.compile(rf"(?<![0-9A-Za-z])[{_HEX}]{{8}}-[{_HEX}]{{4}}-[{_HEX}]{{4}}-[{_HEX}]{{4}}-[{_HEX}]{{12}}(?![0-9A-Za-z])")
WWN_COLON = re.compile(rf"(?<![0-9A-Za-z:])(?:[{_HEX}]{{2}}:){{7}}[{_HEX}]{{2}}(?![0-9A-Za-z:])")
MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
IPV6_CANDIDATE = re.compile(
    rf"(?<![0-9A-Za-z:.])(?:[{_HEX}]{{0,4}}:){{2,7}}(?:(?:\d{{1,3}}\.){{3}}\d{{1,3}}|[{_HEX}]{{0,4}})"
    r"(?:%[0-9A-Za-z_.-]+)?(?![0-9A-Za-z:])"
)
WWN_HEX = re.compile(rf"(?<![0-9A-Za-z])(?=[0-9]*[a-fA-F])[{_HEX}]{{16,17}}(?![0-9A-Za-z])")
LONG_HEX = re.compile(rf"(?<![0-9A-Za-z])(?=[0-9]*[a-fA-F])[{_HEX}]{{18,64}}(?![0-9A-Za-z])")
BARE_HEX12 = re.compile(rf"(?<![0-9A-Za-z])(?=[0-9]*[a-fA-F])[{_HEX}]{{12}}(?![0-9A-Za-z])")
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
OID_KEY = re.compile(r"\d+(?:\.\d+){5,}")
NUMERIC_NAME = re.compile(r"-?[\d.]+")
IDENTIFIER = re.compile(r"(?=\S*[A-Za-z])(?=\S*\d)\S{6,}")
NAME_BOUNDARY = "A-Za-z0-9_-"
# A name may also follow a numeric segment and '-'/'_', as in the kernel string 5.10.0-acme-node1.
NAME_LEFT = rf"(?:(?<![{NAME_BOUNDARY}])|(?<=\d[-_]))"
PROTECTABLE_KEY = re.compile(r"[A-Za-z_]+")  # schema-style payload keys; ids and host names carry digits or '-'
LONG_DIGITS = re.compile(r"\d{8,}")

NAME_KEYS = {"name", "hostname", "object_name", "target", "groupname", "owner", "user", "label", "displayname", "bridgename"}
SERIAL_TOKENS = {
    "sn", "serial", "serialno", "license", "licence", "uuid", "mac", "wwn", "bios", "asset", "tag", "chassis",
    "servicetag",
}
VERSION_TOKENS = {"version", "firmware", "fw"}
OS_KEYS = {"os", "osname", "ostype", "osversion", "osfullname", "guestos", "guestosname", "guestostype"}
ENUM_KEYS = {"type", "object_type", "otype", "vmtype", "status", "state", "urgent_type"}
# Generic infrastructure words and the placeholder kinds: never treated as names.
STOP_WORDS = {
    "data", "local", "storage", "host", "hosts", "node", "nodes", "vm", "vms", "cluster", "network", "disk", "ha",
    "fc", "nfs", "iscsi", "ssd", "hdd", "raid", "fan", "cpu", "mem", "memory", "default", "admin", "system", "backup",
    "test", "name", "ip", "ipv6", "email", "fqdn", "mac", "wwn", "hex", "uuid", "id", "serial", "sn", "license",
    "licence", "bios", "asset", "tag", "chassis", "servicetag",
}
# Status words and version strings are what the probe exists to discover; they are not customer data.
# Probe-made strings only; api_url is already reduced to scheme, redacted host and port by Redactor.url().
RAW_KEYS = {"status_values_seen", "sangfor_versions", "api_checks", "probe_errors", "api_url"}
SNMP_VALUE_KEYS = {"walk", "scalars"}
META_KEYS = {
    "probe_version", "generated_at", "api_url", "sangfor_versions", "status_values_seen", "api_checks", "snmp_nodes",
    "probe_errors", "phase", "endpoint", "ok", "reason", "error", "detail", "http_status", "ms", "host_ip",
    "snmp_version", "has_private_subtree", "node", "scalars", "walk", "host_id", "info",
}
STATUS_TABLES = ("fan", "raid")
STATUS_OID_PREFIXES = tuple(
    table.column_oid(column.suffix) + "." for table in oids.TABLES for column in table.columns if column.kind == "status"
)
RAW_SNMP_OIDS = {oids.VERSION, oids.BMC_VERSION, oids.BMC_IPMI_VERSION}
NUMERIC_OID_PREFIXES = tuple(
    table.column_oid(column.suffix) + "." for table in oids.TABLES for column in table.columns if column.kind != "status"
)
NUMERIC_SCALAR_OIDS = {oids.HOST_CPU.oid, oids.HOST_MEMORY.oid, oids.HOST_DISK.oid}


def _key_tokens(key: str) -> list[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", key)
    spaced = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", spaced)
    return [token for token in re.split(r"[\s_.\-]+", spaced.lower()) if token]


def _serial_kind(key: str) -> str:
    return next((token for token in _key_tokens(key) if token in SERIAL_TOKENS), "")


def _is_os_key(key: str) -> bool:
    tokens = _key_tokens(key)
    return "os" in tokens or "".join(tokens) in OS_KEYS


def _is_name_key(key: str) -> bool:
    lowered = key.lower()
    return (lowered.endswith("name") or lowered in NAME_KEYS) and not _is_os_key(key)


def _is_enum_key(key: str) -> bool:
    lowered = key.lower()
    return lowered in ENUM_KEYS or lowered.endswith("_type")


def _is_version_key(key: str) -> bool:
    return any(token in VERSION_TOKENS for token in _key_tokens(key))


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        return False
    return True


def _name_key(text: str) -> str:
    """Names match case-insensitively, with '-' and '_' treated alike (nfs-backup is also the id nfs_backup)."""
    return text.lower().replace("_", "-")


def _is_number(text: str) -> bool:
    try:
        float(text)
    except ValueError:
        return False
    return True


class Redactor:
    def __init__(self) -> None:
        self._tokens: dict[tuple[str, str], str] = {}
        self._counts: dict[str, int] = {}
        self._names: dict[str, str] = {}  # _name_key(name) -> placeholder
        self._protected: set[str] = set(STOP_WORDS)  # payload keys and enum values: never used as names
        self._name_re: re.Pattern[str] | None = None

    def _token(self, kind: str, value: str) -> str:
        key = (kind, value)
        if key not in self._tokens:
            number = self._counts[kind] = self._counts.get(kind, 0) + 1
            self._tokens[key] = f"10.255.{number // 256}.{number % 256}" if kind == "ip" else f"{kind}-{number:03d}"
        return self._tokens[key]

    def learn_name(self, text: str, allow_short: bool = False) -> None:
        text = text.strip()
        if len(text) < (2 if allow_short else 3) or NUMERIC_NAME.fullmatch(text) or _is_ip(text):
            return
        key = _name_key(text)
        if key not in self._names:
            self._names[key] = self._token("name", key)
            self._name_re = None

    def _protect(self, word: str) -> None:
        key = _name_key(word.strip())
        if key and key not in self._protected:
            self._protected.add(key)
            self._name_re = None

    def learn(self, obj: object, key: str = "") -> None:
        """Learn names from name-like keys; remember payload keys and enum values so they are never names."""
        if isinstance(obj, dict):
            for child_key, value in obj.items():
                child_key = str(child_key)
                if PROTECTABLE_KEY.fullmatch(child_key):
                    self._protect(child_key)
                self.learn(value, child_key)
        elif isinstance(obj, list):
            for value in obj:
                self.learn(value, key)
        elif isinstance(obj, str) and _is_enum_key(key):
            self._protect(obj)
        elif isinstance(obj, str) and _is_name_key(key):
            self.learn_name(obj, allow_short=key.lower() in NAME_KEYS)

    def _names_pattern(self) -> re.Pattern[str] | None:
        if self._name_re is None:
            names = sorted((name for name in self._names if name not in self._protected), key=len, reverse=True)
            if not names:
                return None
            alternatives = "|".join(re.escape(name).replace(r"\-", "[-_]") for name in names)
            self._name_re = re.compile(rf"{NAME_LEFT}(?:{alternatives})(?![{NAME_BOUNDARY}])", re.IGNORECASE)
        return self._name_re

    def _ipv6(self, match: re.Match[str]) -> str:
        found = match.group(0)
        if not re.search(f"[{_HEX}]", found) or not _is_ip(found):  # times like 12:30:45 are not addresses
            return found
        return self._token("ipv6", found.lower())

    def _ipv4(self, match: re.Match[str]) -> str:
        found = match.group(0)
        try:
            ipaddress.IPv4Address(found)  # rejects 4.40.30.00 (leading zero) and 300.1.1.1
        except ValueError:
            return found
        return self._token("ip", found)

    def _fqdn(self, match: re.Match[str]) -> str:
        labels = match.group(0).split(".")
        extensions: list[str] = []
        while labels and labels[-1].lower() in FILE_EXTENSIONS:
            extensions.insert(0, labels.pop())
        if len(labels) < 2 or not re.fullmatch(r"[A-Za-z]{2,63}", labels[-1]):
            return match.group(0)  # a file name such as disk.qcow2 or backup.tar.gz
        return ".".join([self._token("fqdn", ".".join(labels).lower()), *extensions])

    def _serial_phrase(self, match: re.Match[str]) -> str:
        return match.group(0)[: match.start(1) - match.start(0)] + self._token("serial", match.group(1))

    def _cisco_mac(self, match: re.Match[str]) -> str:
        found = match.group(0)
        return self._token("mac", found.lower()) if re.search("[a-fA-F]", found) else found

    def text(self, value: str, fqdn: bool = True) -> str:
        """Redact free text. fqdn=False (version, firmware and OS values) skips only the host-name rule."""
        value = EMAIL.sub(lambda m: self._token("email", m.group(0).lower()), value)
        value = SERIAL_PHRASE.sub(self._serial_phrase, value)
        value = CISCO_MAC.sub(self._cisco_mac, value)
        if fqdn:
            value = FQDN.sub(self._fqdn, value)
        value = UUID.sub(lambda m: self._token("uuid", m.group(0).lower()), value)
        value = WWN_COLON.sub(lambda m: self._token("wwn", m.group(0).lower()), value)
        value = MAC.sub(lambda m: self._token("mac", m.group(0).lower()), value)
        value = IPV6_CANDIDATE.sub(self._ipv6, value)
        value = WWN_HEX.sub(lambda m: self._token("wwn", m.group(0).lower()), value)
        value = LONG_HEX.sub(lambda m: self._token("hex", m.group(0).lower()), value)
        value = BARE_HEX12.sub(lambda m: self._token("hex", m.group(0).lower()), value)
        value = IPV4.sub(self._ipv4, value)
        pattern = self._names_pattern()
        if pattern is not None:  # last: every placeholder above is joined by '-', which blocks a name match
            value = pattern.sub(lambda m: self._names[_name_key(m.group(0))], value)
        return value

    def _key(self, key: object) -> str:
        key = str(key)
        if key in META_KEYS or OID_KEY.fullmatch(key):
            return key
        return self.text(key)

    def _snmp_value(self, oid: str, value: object) -> object:
        if not isinstance(value, str):
            return self.redact(value)
        if oid in RAW_SNMP_OIDS or oid.startswith(STATUS_OID_PREFIXES):
            return value
        if _is_number(value):
            known = oid in NUMERIC_SCALAR_OIDS or oid.startswith(NUMERIC_OID_PREFIXES)
            return self._token("serial", value.strip()) if LONG_DIGITS.fullmatch(value.strip()) and not known else value
        redacted = self.text(value)
        if redacted == value and IDENTIFIER.fullmatch(value):
            return self._token("id", value)
        return redacted

    def redact(self, obj: object, key: str = "") -> object:
        key = str(key)
        if key in RAW_KEYS:
            return obj
        if isinstance(obj, dict):
            result: dict[str, object] = {}
            for child_key, value in obj.items():
                child_key = str(child_key)
                redacted_key = self._key(child_key)
                if redacted_key in result:  # two keys redacted to one placeholder: keep both
                    number = 2
                    while f"{redacted_key}#{number}" in result:
                        number += 1
                    redacted_key = f"{redacted_key}#{number}"
                if key in SNMP_VALUE_KEYS:
                    result[redacted_key] = self._snmp_value(child_key, value)
                else:
                    result[redacted_key] = self.redact(value, child_key)
            return result
        if isinstance(obj, list):
            return [self.redact(value, key) for value in obj]
        serial = _serial_kind(key)
        if serial and isinstance(obj, (str, int, float)) and not isinstance(obj, bool) and obj != "":
            return self._token(serial, str(obj))
        if isinstance(obj, str):
            return self.text(obj, fqdn=not (_is_version_key(key) or _is_os_key(key)))
        return obj

    def url(self, url: str) -> str:
        """Scheme, redacted host and port only: user info, path and query are dropped."""
        parsed = urlparse(url if "://" in url else f"//{url}")
        try:
            host, port = parsed.hostname or "", parsed.port
        except ValueError:
            host, port = parsed.hostname or "", None
        if not host:
            return ""
        redacted = self.text(host)
        if redacted == host:
            redacted = self._token("host", host.lower())
        scheme = f"{parsed.scheme}://" if parsed.scheme else ""
        return f"{scheme}{redacted}{f':{port}' if port else ''}"


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


def _ms(started: float) -> int:
    return round((time.perf_counter() - started) * 1000)


def _failed_check(endpoint: str, exc: BaseException, started: float) -> dict:
    """A failed check carries the reason or the exception class only, never the exception text."""
    check: dict = {"endpoint": endpoint, "ok": False}
    if isinstance(exc, SangforApiError):
        check["reason"] = exc.reason
        if exc.error_class:  # e.g. MissingSchema or ConnectTimeout: a class name, never the exception text
            check["error"] = exc.error_class
        status = re.search(r"\bHTTP (\d{3})\b", str(exc))
        if status:
            check["http_status"] = int(status.group(1))
    else:
        check["reason"] = "error"
        check["error"] = type(exc).__name__
    check["ms"] = _ms(started)
    return check


class _StopApi(Exception):
    pass


def probe_api(args: argparse.Namespace, raw: dict[str, object], checks: list[dict]) -> None:
    if not args.url:
        return
    started = time.perf_counter()
    try:
        password = _secret("SANGFOR_PASSWORD", "Sangfor API password: ")
        ca_pem = Path(args.ca_file).read_text(encoding="utf-8") if args.ca_file else ""
        client = SangforApiClient(
            args.url, args.user, password, verify_tls=not args.insecure, ca_pem=ca_pem, timeout=args.timeout
        )
    except Exception as exc:
        checks.append(_failed_check("setup", exc, started))
        return
    try:
        try:
            client.login()  # exactly one attempt: a failed login is not retried per endpoint
        except Exception as exc:
            checks.append(_failed_check("login", exc, started))
            return
        checks.append({"endpoint": "login", "ok": True, "ms": _ms(started)})
        auth_streak = 0

        def fetch(name: str, path: str, params: dict | None) -> tuple[bool, object]:
            """One endpoint. A 401/403 is recorded and skipped; the API phase stops on tls, timeout, an
            unexpected error, or MAX_AUTH_STREAK endpoints in a row rejecting the ticket."""
            nonlocal auth_streak
            begun = time.perf_counter()
            try:
                data = client.get(path, params)
            except Exception as exc:
                checks.append(_failed_check(name, exc, begun))
                auth = isinstance(exc, SangforApiError) and exc.reason == "auth"
                auth_streak = auth_streak + 1 if auth else 0
                if not isinstance(exc, SangforApiError) or exc.reason in STOP_REASONS or auth_streak >= MAX_AUTH_STREAK:
                    raise _StopApi from None
                return False, None
            auth_streak = 0
            checks.append({"endpoint": name, "ok": True, "ms": _ms(begun)})
            return True, data

        try:
            for name, path, params in API_ENDPOINTS:
                ok, data = fetch(name, path, params)
                if ok:
                    raw[name] = data
            infos: list[dict] = []
            raw["node_info"] = infos
            host_list = raw.get("host_list")
            for item in host_list if isinstance(host_list, list) else []:
                host_id = str(item.get("id", "")) if isinstance(item, dict) else ""
                if host_id:
                    ok, data = fetch("node_info", f"/vapi/json/nodes/{host_id}/info", None)
                    if ok:
                        infos.append({"host_id": host_id, "info": data})
        except _StopApi:
            return
    finally:
        client.close()


def _snmp_entries(args: argparse.Namespace) -> list[str]:
    return list(dict.fromkeys(entry.strip() for entry in args.snmp_node if entry.strip()))


def probe_snmp(args: argparse.Namespace, records: list[dict]) -> None:
    entries = _snmp_entries(args)
    if not entries:
        return
    community = auth_key = priv_key = ""
    if args.snmp_version == "v2c":
        community = _secret("SANGFOR_SNMP_COMMUNITY", "SNMP v2c community (empty = sangfopub): ") or "sangfopub"
    else:
        auth_key = _secret("SANGFOR_SNMP_AUTH_KEY", "SNMP v3 auth key: ")
        if args.v3_priv_protocol != "NONE":
            priv_key = _secret("SANGFOR_SNMP_PRIV_KEY", "SNMP v3 privacy key: ")
    for index, entry in enumerate(entries, 1):
        try:
            node = parse_node(entry, args.snmp_port)
        except ConfigError as exc:
            # The message quotes the entry (which may itself contain quotes); keep only its shape.
            detail = str(exc).replace(f"'{entry}'", "'<entry>'")
            if entry in detail:
                detail = "invalid snmp_nodes entry"
            records.append({"node": f"invalid-{index}", "error": "ConfigError", "detail": detail})
            continue
        record: dict = {"host_ip": node.host_ip, "snmp_version": args.snmp_version}
        records.append(record)
        started = time.perf_counter()
        try:
            client = SnmpClient(
                SnmpTarget(
                    node.address, node.port, args.snmp_version, timeout=args.timeout, community=community,
                    v3_user=args.v3_user, v3_auth_protocol=args.v3_auth_protocol, v3_auth_key=auth_key,
                    v3_priv_protocol=args.v3_priv_protocol, v3_priv_key=priv_key, v3_context_name=args.v3_context,
                )
            )
            record["scalars"] = client.get([oids.SYS_DESCR, oids.SYS_NAME, oids.VERSION])
            record["has_private_subtree"] = client.has_subtree(oids.ROOT)
            record["walk"] = client.walk(oids.ROOT) if record["has_private_subtree"] else {}
        except SnmpError as exc:
            record["error"] = str(exc)  # address:port and the pysnmp indication; redacted by text() on write
        except Exception as exc:  # pysnmp key, transport or resolver errors may quote keys or host names
            record["error"] = type(exc).__name__
        finally:
            record["ms"] = _ms(started)


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
    found = {
        str(entry["info"].get("os_version"))
        for entry in raw.get("node_info", [])
        if isinstance(entry, dict) and isinstance(entry.get("info"), dict) and entry["info"].get("os_version")
    }
    found.update(r["scalars"][oids.VERSION] for r in records if oids.VERSION in r.get("scalars", {}))
    return sorted(found)


def learn_inputs(redactor: Redactor, args: argparse.Namespace) -> None:
    """Learn the host names the operator typed, so they never reach the zip."""
    if args.url:
        url = args.url if "://" in args.url else f"//{args.url}"
        try:
            hostname = urlparse(url).hostname
        except ValueError:
            hostname = None
        if hostname:
            redactor.learn_name(hostname)
    for user in (args.user, args.v3_user):
        if user:
            redactor.learn_name(user)
    for entry in _snmp_entries(args):
        try:
            # IP addresses are skipped; a short host name is still an operator-supplied identifier.
            redactor.learn_name(parse_node(entry, args.snmp_port).address, allow_short=True)
        except ConfigError:
            continue  # an invalid entry is written only as invalid-<n> with '<entry>' in its detail


def _unique(name: str, used: set[str]) -> str:
    candidate, number = name, 1
    while candidate in used:
        number += 1
        candidate = f"{name}-{number}"
    used.add(candidate)
    return candidate


def write_bundle(
    out: Path, args: argparse.Namespace, redactor: Redactor, raw: dict, checks: list[dict], records: list[dict],
    errors: list[dict],
) -> None:
    redactor.learn(raw)
    for record in records:
        name = record.get("scalars", {}).get(oids.SYS_NAME)
        if name:
            redactor.learn_name(name)
    meta = {
        "probe_version": PROBE_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "api_url": redactor.url(args.url) if args.url else "",
        "sangfor_versions": versions(raw, records),
        "status_values_seen": status_values(records),
        "api_checks": checks,
        "snmp_nodes": [
            {key: value for key, value in record.items() if key not in ("walk", "scalars")} for record in records
        ],
        "probe_errors": errors,
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    used: set[str] = set()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr(_unique("meta.json", used), json.dumps(redactor.redact(meta), indent=2, ensure_ascii=False))
        for name, data in raw.items():
            member = _unique(f"api/{name}", used)
            bundle.writestr(f"{member}.json", json.dumps(redactor.redact(data), indent=2, ensure_ascii=False))
        for record in records:
            label = redactor.text(record["host_ip"]) if "host_ip" in record else str(record.get("node", "node"))
            member = _unique(f"snmp/{label}", used)
            bundle.writestr(f"{member}.json", json.dumps(redactor.redact(record), indent=2, ensure_ascii=False))


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    out = Path(args.out)
    redactor = Redactor()
    learn_inputs(redactor, args)
    raw: dict[str, object] = {}
    checks: list[dict] = []
    records: list[dict] = []
    errors: list[dict] = []
    try:
        for phase, run in (("api", lambda: probe_api(args, raw, checks)), ("snmp", lambda: probe_snmp(args, records))):
            try:
                run()
            except Exception as exc:
                errors.append({"phase": phase, "error": type(exc).__name__})
    finally:
        write_bundle(out, args, redactor, raw, checks, records, errors)

    api_ok = any(check["ok"] for check in checks if check["endpoint"] != "login")
    snmp_ok = any("error" not in record for record in records)
    failed = any(not check["ok"] for check in checks) or any("error" in record for record in records) or errors
    print(f"Wrote {out}  (API {'OK' if api_ok else 'FAILED or skipped'}, SNMP {'OK' if snmp_ok else 'FAILED or skipped'})")
    print("Open the zip and check that nothing sensitive is left before you share it.")
    if not (api_ok or snmp_ok):
        return 2
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
