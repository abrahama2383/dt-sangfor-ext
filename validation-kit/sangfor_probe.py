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
STOP_REASONS = ("auth", "tls", "timeout")  # nothing more to learn from the API after one of these

_HEX = "0-9A-Fa-f"
EMAIL = re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,63}(?![A-Za-z0-9-])")
CISCO_MAC = re.compile(rf"(?<![0-9A-Za-z.])[{_HEX}]{{4}}\.[{_HEX}]{{4}}\.[{_HEX}]{{4}}(?![0-9A-Za-z]|\.[0-9A-Za-z])")
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
FQDN = re.compile(rf"(?<![A-Za-z0-9._@-])(?:{_LABEL}\.)+[A-Za-z]{{2,63}}(?![A-Za-z0-9_-]|\.[A-Za-z0-9])")
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

NAME_KEYS = {"name", "hostname", "object_name", "target", "groupname", "owner", "user", "label", "displayname", "bridgename"}
SERIAL_TOKENS = {"sn", "serial", "serialno", "license", "licence", "uuid", "mac", "wwn", "bios", "asset"}
# Status words and version strings are what the probe exists to discover; they are not customer data.
RAW_KEYS = {"status_values_seen", "sangfor_versions"}
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


def _key_tokens(key: str) -> list[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", key)
    spaced = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", spaced)
    return [token for token in re.split(r"[\s_.\-]+", spaced.lower()) if token]


def _serial_kind(key: str) -> str:
    return next((token for token in _key_tokens(key) if token in SERIAL_TOKENS), "")


def _is_name_key(key: str) -> bool:
    lowered = key.lower()
    return lowered.endswith("name") or lowered in NAME_KEYS


def _is_version_key(key: str) -> bool:
    return "version" in _key_tokens(key)


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

    def learn(self, obj: object, key: str = "") -> None:
        if isinstance(obj, dict):
            for child_key, value in obj.items():
                self.learn(value, str(child_key))
        elif isinstance(obj, list):
            for value in obj:
                self.learn(value, key)
        elif isinstance(obj, str) and _is_name_key(key):
            self.learn_name(obj, allow_short=key.lower() in NAME_KEYS)

    def _names_pattern(self) -> re.Pattern[str] | None:
        if self._name_re is None and self._names:
            alternatives = "|".join(
                re.escape(name).replace(r"\-", "[-_]") for name in sorted(self._names, key=len, reverse=True)
            )
            self._name_re = re.compile(
                rf"(?<![{NAME_BOUNDARY}])(?:{alternatives})(?![{NAME_BOUNDARY}])", re.IGNORECASE
            )
        return self._name_re

    def _ipv6(self, match: re.Match[str]) -> str:
        found = match.group(0)
        if not re.search(f"[{_HEX}]", found) or not _is_ip(found):  # times like 12:30:45 are not addresses
            return found
        return self._token("ipv6", found.lower())

    def _cisco_mac(self, match: re.Match[str]) -> str:
        found = match.group(0)
        return self._token("mac", found.lower()) if re.search("[a-fA-F]", found) else found

    def text(self, value: str) -> str:
        value = EMAIL.sub(lambda m: self._token("email", m.group(0).lower()), value)
        value = CISCO_MAC.sub(self._cisco_mac, value)
        value = FQDN.sub(lambda m: self._token("fqdn", m.group(0).lower()), value)
        value = UUID.sub(lambda m: self._token("uuid", m.group(0).lower()), value)
        value = WWN_COLON.sub(lambda m: self._token("wwn", m.group(0).lower()), value)
        value = MAC.sub(lambda m: self._token("mac", m.group(0).lower()), value)
        value = IPV6_CANDIDATE.sub(self._ipv6, value)
        value = WWN_HEX.sub(lambda m: self._token("wwn", m.group(0).lower()), value)
        value = LONG_HEX.sub(lambda m: self._token("hex", m.group(0).lower()), value)
        value = BARE_HEX12.sub(lambda m: self._token("hex", m.group(0).lower()), value)
        value = IPV4.sub(lambda m: self._token("ip", m.group(0)), value)
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
        if _is_number(value) or oid in RAW_SNMP_OIDS or oid.startswith(STATUS_OID_PREFIXES):
            return value
        redacted = self.text(value)
        if redacted == value and IDENTIFIER.fullmatch(value):
            return self._token("id", value)
        return redacted

    def redact(self, obj: object, key: str = "") -> object:
        key = str(key)
        if key in RAW_KEYS:
            return obj
        if isinstance(obj, dict):
            if key in SNMP_VALUE_KEYS:
                return {self._key(oid): self._snmp_value(str(oid), value) for oid, value in obj.items()}
            return {self._key(child_key): self.redact(value, str(child_key)) for child_key, value in obj.items()}
        if isinstance(obj, list):
            return [self.redact(value, key) for value in obj]
        serial = _serial_kind(key)
        if serial and isinstance(obj, (str, int, float)) and not isinstance(obj, bool) and obj != "":
            return self._token(serial, str(obj))
        if isinstance(obj, str):
            return obj if _is_version_key(key) else self.text(obj)
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


def _ms(started: float) -> int:
    return round((time.perf_counter() - started) * 1000)


def _failed_check(endpoint: str, exc: BaseException, started: float) -> dict:
    """A failed check carries the reason or the exception class only, never the exception text."""
    check: dict = {"endpoint": endpoint, "ok": False}
    if isinstance(exc, SangforApiError):
        check["reason"] = exc.reason
        status = re.search(r"\bHTTP (\d{3})\b", str(exc))
        if status:
            check["http_status"] = int(status.group(1))
    else:
        check["reason"] = "error"
        check["error"] = type(exc).__name__
    check["ms"] = _ms(started)
    return check


def _must_stop(exc: BaseException) -> bool:
    return not isinstance(exc, SangforApiError) or exc.reason in STOP_REASONS


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

        def call(name: str, path: str, params: dict | None) -> object:
            begun = time.perf_counter()
            data = client.get(path, params)
            checks.append({"endpoint": name, "ok": True, "ms": _ms(begun)})
            return data

        for name, path, params in API_ENDPOINTS:
            begun = time.perf_counter()
            try:
                raw[name] = call(name, path, params)
            except Exception as exc:
                checks.append(_failed_check(name, exc, begun))
                if _must_stop(exc):
                    return
        infos: list[dict] = []
        raw["node_info"] = infos
        host_list = raw.get("host_list")
        for item in host_list if isinstance(host_list, list) else []:
            host_id = str(item.get("id", "")) if isinstance(item, dict) else ""
            if not host_id:
                continue
            begun = time.perf_counter()
            try:
                infos.append({"host_id": host_id, "info": call("node_info", f"/vapi/json/nodes/{host_id}/info", None)})
            except Exception as exc:
                checks.append(_failed_check("node_info", exc, begun))
                if _must_stop(exc):
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
            # The message quotes the entry; keep only its shape so no address reaches the zip.
            detail = re.sub(r"'[^']*'", "'<entry>'", str(exc))
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
            redactor.learn_name(parse_node(entry, args.snmp_port).address)  # IP addresses are skipped
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
        "api_url": args.url or "",
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
