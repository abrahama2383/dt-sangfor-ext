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
