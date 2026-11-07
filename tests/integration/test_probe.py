import importlib.util
import json
import re
import zipfile
from pathlib import Path

import pytest

from sangfor_hci.snmp import oids

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("sangfor_probe", ROOT / "validation-kit" / "sangfor_probe.py")
probe = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(probe)

FAN = next(table for table in oids.TABLES if table.name == "fan")
RAID = next(table for table in oids.TABLES if table.name == "raid")


@pytest.fixture
def fast_retries(monkeypatch):
    monkeypatch.setattr("sangfor_hci.api.client.RETRY_BACKOFF_SECONDS", (0.0, 0.0))


def _read_zip(path):
    with zipfile.ZipFile(path) as bundle:
        names = bundle.namelist()
        members = {name: bundle.read(name).decode("utf-8") for name in names}
    return names, members


def _everything(names, members):
    return "\n".join([*names, *members.values()])


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
    for secret in ("10.0.0.11", "node-a", "00e0ec000a11", "00:e0:ec:00:0a:11", "SN123456", "350014ee0aed9e86a"):
        assert secret not in text, secret
    assert out["host_list"][0]["ip"] in out["description"]
    assert out["host_list"][0]["name"] in out["description"]
    assert "1.3.6.1.4.1.35047.3.2.1.2.1.1.0" in out["walk"]
    assert out["walk"]["1.3.6.1.4.1.35047.3.2.1.2.1.1.0"] == "0.12"
    assert out["version"] == "SANGFOR aCloud 6.10.0_R2"


# Item 2: free-text patterns
def test_redactor_text_redacts_emails_ipv6_fqdns_cisco_macs_and_wwns():
    redactor = probe.Redactor()
    source = (
        "mail ops.team@acme.co.id; v6 2001:db8::8a2e:370:7334, fe80::1ff:fe23:4567:890a%eth0 and "
        "2001:0db8:0000:0000:0000:ff00:0042:8329; host acme-prod-node1.acme.co.id; "
        "mac 00e0.ec00.0a11; naa 5000c500a1b2c3d4 and 6000c29a1b2c3d4e5"
    )
    out = redactor.text(source)
    for leaked in (
        "ops.team", "acme.co.id", "2001:db8", "fe80::", "0db8", "8a2e", "acme-prod-node1", "00e0.ec00.0a11",
        "5000c500a1b2c3d4", "6000c29a1b2c3d4e5",
    ):
        assert leaked not in out, leaked
    assert re.findall(r"\bemail-\d{3}\b", out) == ["email-001"]
    assert re.findall(r"\bfqdn-\d{3}\b", out) == ["fqdn-001"]
    assert re.findall(r"\bipv6-\d{3}\b", out) == ["ipv6-001", "ipv6-002", "ipv6-003"]
    assert re.findall(r"\bmac-\d{3}\b", out) == ["mac-001"]
    assert re.findall(r"\bwwn-\d{3}\b", out) == ["wwn-001", "wwn-002"]
    assert redactor.text("acme-prod-node1.acme.co.id") == "fqdn-001"
    assert redactor.text("ACME-PROD-NODE1.ACME.CO.ID") == "fqdn-001"
    for keep in (
        "1.3.6.1.4.1.35047.3.2.1.2.16.1.4.1", "6.8.0", "SANGFOR aCloud 6.10.0_R2 Build20251020", "12:30:45",
        "std::vector", "1234567890123456", "e.g. fine", "cpu_ratio", "50.0", "-3.4",
    ):
        assert redactor.text(keep) == keep, keep


# Item 3: key matching, non-string values, dict keys, SNMP walk values
def test_redactor_matches_serial_keys_by_token_whatever_the_value_type():
    redactor = probe.Redactor()
    data = {
        "hostSN": 20481234, "serialNumber": "X9Z", "bios_uuid": "4c4c4544-0042", "BIOSVersion": "1.2.3",
        "license-key": 12.5, "asset_tag": "T-1", "macAddr": "ab", "node_wwn": 77, "enabled": True, "sn": None,
        "snapshot": "keep-me", "dns_server": "keep-too",
    }
    out = redactor.redact(data)
    for key in ("hostSN", "serialNumber", "bios_uuid", "BIOSVersion", "license-key", "asset_tag", "macAddr", "node_wwn"):
        assert isinstance(out[key], str) and re.fullmatch(r"[a-z]+-\d{3}", out[key]), (key, out[key])
    text = json.dumps(out)
    for leaked in ("20481234", "X9Z", "4c4c4544", "1.2.3", "12.5", "T-1", "\"ab\"", "77"):
        assert leaked not in text, leaked
    assert out["enabled"] is True and out["sn"] is None
    assert out["snapshot"] == "keep-me" and out["dns_server"] == "keep-too"
    assert redactor.redact({"hw.asset": "T-2"}) == {"fqdn-001": "asset-002"}  # dotted key: FQDN-like, split on '.'


def test_redactor_learns_names_from_any_key_ending_in_name():
    redactor = probe.Redactor()
    redactor.learn({"cluster_name": "acme-hci", "detail": {"hostName": "hv01x"}, "osname": "linux-acme"})
    out = redactor.text("cluster acme-hci on hv01x runs linux-acme")
    for leaked in ("acme-hci", "hv01x", "linux-acme"):
        assert leaked not in out, leaked
    assert re.fullmatch(r"cluster name-\d{3} on name-\d{3} runs name-\d{3}", out)


def test_redactor_redacts_dict_keys_but_keeps_oids_and_meta_keys():
    redactor = probe.Redactor()
    redactor.learn({"name": "node-a"})
    out = redactor.redact({
        "10.0.0.5": 1, "node-a": {"x": 1}, "host-00e0ec000a11": 2, "ops@acme.co.id": 3,
        "1.3.6.1.4.1.35047.3.2.1.1.0": "v", "api_checks": [], "status_values_seen": [], "cpu_ratio": "0.1",
    })
    keys = json.dumps(list(out))
    for leaked in ("10.0.0.5", "node-a", "00e0ec000a11", "acme"):
        assert leaked not in keys, leaked
    for kept in ("1.3.6.1.4.1.35047.3.2.1.1.0", "api_checks", "status_values_seen", "cpu_ratio"):
        assert kept in out, kept


def test_redactor_snmp_walk_keeps_numbers_and_status_words_and_tokenizes_identifiers():
    redactor = probe.Redactor()
    redactor.learn_name("node-a")
    fan_status = FAN.column_oid("4") + ".1"
    raid_status = RAID.column_oid("5") + ".1"
    raid_name = RAID.column_oid("3") + ".1"
    record = {
        "host_ip": "10.0.0.11",
        "scalars": {oids.SYS_NAME: "node-a", oids.SYS_DESCR: "Linux node-a 5.10.0 SANGFOR aCloud",
                    oids.VERSION: "6.10.0_R2"},
        "walk": {
            fan_status: "ok", raid_status: "Rebuild50pct", raid_name: "RAID1-sys",
            f"{oids.ROOT}.2.1.2.1.7.1": "52", f"{oids.ROOT}.2.12.1.4.1": "-2.1",
            f"{oids.ROOT}.2.5.1.2.2": "/sf/data", oids.BMC_IPMI_IP: "10.0.1.11", oids.BMC_VERSION: "3.45.1",
            f"{oids.ROOT}.2.12.1.3.1": "eth4", f"{oids.ROOT}.2.18.1.4.1": "ab12cd34ef",
            oids.VERSION: "6.10.0_R2",
        },
    }
    out = redactor.redact(record)
    walk = out["walk"]
    assert walk[fan_status] == "ok" and walk[raid_status] == "Rebuild50pct"
    assert walk[f"{oids.ROOT}.2.1.2.1.7.1"] == "52" and walk[f"{oids.ROOT}.2.12.1.4.1"] == "-2.1"
    assert walk[f"{oids.ROOT}.2.5.1.2.2"] == "/sf/data" and walk[f"{oids.ROOT}.2.12.1.3.1"] == "eth4"
    assert walk[oids.BMC_VERSION] == "3.45.1" and walk[oids.VERSION] == "6.10.0_R2"
    assert re.fullmatch(r"id-\d{3}", walk[raid_name]) and re.fullmatch(r"id-\d{3}", walk[f"{oids.ROOT}.2.18.1.4.1"])
    assert walk[oids.BMC_IPMI_IP].startswith("10.255.")
    assert re.fullmatch(r"name-\d{3}", out["scalars"][oids.SYS_NAME])
    assert out["scalars"][oids.VERSION] == "6.10.0_R2"
    text = json.dumps(out)
    for leaked in ("node-a", "RAID1-sys", "ab12cd34ef", "10.0.1.11", "10.0.0.11"):
        assert leaked not in text, leaked


# Item 8: name matching
def test_redactor_names_are_case_insensitive_and_word_bounded():
    redactor = probe.Redactor()
    redactor.learn_name("node")
    redactor.learn_name("ACME-Node1")
    assert re.fullmatch(r"nodes and name-\d{3}", redactor.text("nodes and node"))
    assert re.fullmatch(r"name-\d{3}", redactor.text("acme-node1"))
    assert redactor.text("acme-node1") == redactor.text("ACME-NODE1") == redactor.text("ACME-Node1")
    assert redactor.text("acme-node12") == "acme-node12"
    redactor.learn_name("nfs-backup")
    assert redactor.text("nfs_backup") == redactor.text("NFS-backup") != "nfs_backup"


def test_redactor_learns_two_char_names_only_from_name_keys():
    redactor = probe.Redactor()
    redactor.learn({"name": "db", "description": "zz", "cluster_name": "qq"})
    out = redactor.text("db is up, dba and zz and qq")
    assert re.fullmatch(r"name-\d{3} is up, dba and zz and qq", out), out


def test_redactor_never_name_replaces_status_words_or_versions():
    redactor = probe.Redactor()
    redactor.learn({"name": "ok", "hostname": "optimal", "target": "6.10.0_R2"})
    meta = {"status_values_seen": ["ok", "optimal"], "sangfor_versions": ["SANGFOR aCloud 6.10.0_R2"]}
    assert redactor.redact(meta) == meta


# End-to-end (Item 10: the simulator secrets and every learned name, IP and hostname are absent)
def test_probe_end_to_end_against_simulator(mock_api, snmp_agents, tmp_path, monkeypatch):
    base, state = mock_api
    monkeypatch.setenv("SANGFOR_PASSWORD", "dtmon-pass")
    monkeypatch.setenv("SANGFOR_SNMP_COMMUNITY", "sangfopub")
    out = tmp_path / "probe.zip"
    code = probe.main([
        "--url", base, "--user", "dtmon",
        "--snmp-version", "v2c", "--timeout", "2",
        "--snmp-node", "10.0.0.11=127.0.0.1:11161",
        "--snmp-node", "10.0.0.12=localhost:11163",
        "--out", str(out),
    ])
    assert code == 0
    assert all(request.startswith(("GET ", "POST /vapi/json/access/ticket")) for request in state.requests)
    assert state.requests.count("POST /vapi/json/access/ticket") == 1
    names, members = _read_zip(out)
    assert {"meta.json", "api/overview.json", "api/host_list.json", "api/node_info.json", "api/alerts.json"} <= set(names)
    assert len(names) == len(set(names))
    everything = _everything(names, members)
    meta = json.loads(members["meta.json"])
    simulator_secrets = ("sangfopub", "dtmon-pass")
    ips_and_hosts = ("10.0.0.11", "10.0.0.12", "10.0.1.11", "127.0.0.1", "localhost", "00e0ec000a11", "00e0ec000b12")
    learned_names = (
        "node-a", "node-b", "app-01", "app-02", "db-01", "grp-app", "local_a", "local_b", "nfs-backup", "admin@vtp",
        "linux-oracle", "linux-ubuntu", "dtmon", "nfs_backup",
    )
    for secret in (*simulator_secrets, *ips_and_hosts, *learned_names):
        assert secret not in everything, secret
    assert all(check["ok"] for check in meta["api_checks"])
    subtrees = sorted(node["has_private_subtree"] for node in meta["snmp_nodes"])
    assert subtrees == [False, True]
    assert {"optimal", "ok"} <= set(meta["status_values_seen"])
    assert meta["sangfor_versions"]
    assert "SANGFOR aCloud 6.10.0_R2 Build20251020" in meta["sangfor_versions"]


def test_probe_reports_failure_when_nothing_answers(tmp_path, monkeypatch):
    monkeypatch.setenv("SANGFOR_PASSWORD", "x")
    code = probe.main(["--url", "http://127.0.0.1:9", "--user", "dtmon", "--timeout", "1", "--out", str(tmp_path / "p.zip")])
    assert code == 2
    assert (tmp_path / "p.zip").exists()


# Item 1: hostnames from inputs, TLS error text, bad --snmp-node entries
def test_probe_redacts_input_hostnames_and_error_text(mock_api_tls, snmp_agents, tmp_path, monkeypatch):
    base, _state, _pem = mock_api_tls
    monkeypatch.setenv("SANGFOR_PASSWORD", "dtmon-pass")
    monkeypatch.setenv("SANGFOR_SNMP_COMMUNITY", "sangfopub")
    out = tmp_path / "p.zip"
    code = probe.main([
        "--url", base.replace("127.0.0.1", "localhost"), "--user", "dtmon",
        "--snmp-version", "v2c", "--timeout", "2",
        "--snmp-node", "10.0.0.11=localhost:11161",
        "--snmp-node", "acme-hci-node9:entry",
        "--out", str(out),
    ])
    assert code == 1
    names, members = _read_zip(out)
    everything = _everything(names, members).lower()
    for leaked in ("localhost", "acme-hci-node9", "certificate", "self-signed", "self signed", "verify"):
        assert leaked not in everything, leaked
    meta = json.loads(members["meta.json"])
    login = meta["api_checks"][0]
    assert login["endpoint"] == "login" and login["ok"] is False and login["reason"] == "tls"
    for check in meta["api_checks"]:
        assert set(check) <= {"endpoint", "ok", "reason", "error", "http_status", "ms"}
        assert re.fullmatch(r"[A-Za-z_]*", check.get("error", "")), check
    assert len([name for name in names if name.startswith("snmp/")]) == 2
    invalid = [node for node in meta["snmp_nodes"] if node.get("error") == "ConfigError"]
    assert invalid == [{"node": "invalid-2", "error": "ConfigError",
                        "detail": "snmp_nodes entry '<entry>' has an invalid port"}]


# Item 4: no crash, always write the zip
@pytest.mark.parametrize(
    "argv, env, secrets",
    [
        (["--snmp-version", "v3", "--v3-user", "dtmon", "--snmp-node", "10.0.0.11=127.0.0.1:9"],
         {"SANGFOR_SNMP_AUTH_KEY": "", "SANGFOR_SNMP_PRIV_KEY": ""}, ()),
        (["--snmp-version", "v3", "--v3-user", "dtmon", "--snmp-node", "10.0.0.11=127.0.0.1:9"],
         {"SANGFOR_SNMP_AUTH_KEY": "short1", "SANGFOR_SNMP_PRIV_KEY": "short2"}, ("short1", "short2")),
        (["--snmp-version", "v2c", "--snmp-node", "10.0.0.11=no-such-host.invalid:161"],
         {"SANGFOR_SNMP_COMMUNITY": "comm-secret"}, ("comm-secret", "no-such-host", "invalid")),
        (["--url", "127.0.0.1:9", "--user", "dtmon"], {"SANGFOR_PASSWORD": "pw-secret"}, ("pw-secret", "127.0.0.1")),
        (["--url", "http://127.0.0.1:9", "--user", "dtmon", "--ca-file", "/nonexistent/acme-ca.pem"],
         {"SANGFOR_PASSWORD": "pw-secret"}, ("pw-secret", "acme-ca", "nonexistent")),
    ],
    ids=["v3-empty-key", "v3-short-key", "unresolvable-address", "url-without-scheme", "missing-ca-file"],
)
def test_probe_always_writes_the_zip(argv, env, secrets, tmp_path, monkeypatch, fast_retries):
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    out = tmp_path / "p.zip"
    code = probe.main([*argv, "--timeout", "0.5", "--out", str(out)])
    assert code != 0
    names, members = _read_zip(out)
    assert "meta.json" in names
    meta = json.loads(members["meta.json"])
    errors = [node.get("error") for node in meta["snmp_nodes"]] + [c.get("error") for c in meta["api_checks"]]
    assert any(errors), meta
    everything = _everything(names, members)
    for secret in secrets:
        assert secret not in everything, secret


# Item 5: a single login attempt
def test_probe_logs_in_once_and_skips_endpoints_when_login_fails(mock_api, tmp_path, monkeypatch):
    base, state = mock_api
    monkeypatch.setenv("SANGFOR_PASSWORD", "wrong-pass")
    out = tmp_path / "p.zip"
    code = probe.main(["--url", base, "--user", "dtmon", "--timeout", "2", "--out", str(out)])
    assert code == 2
    assert state.requests.count("POST /vapi/json/access/ticket") == 1
    assert set(state.requests) <= {"GET /vapi/json/public_key", "POST /vapi/json/access/ticket"}
    names, members = _read_zip(out)
    meta = json.loads(members["meta.json"])
    assert [(c["endpoint"], c["ok"], c["reason"]) for c in meta["api_checks"]] == [("login", False, "auth")]
    assert "wrong-pass" not in _everything(names, members)


def test_probe_does_not_retry_a_failed_login_per_endpoint(tmp_path, monkeypatch):
    calls = []

    def failing_login(self):
        calls.append(1)
        raise probe.SangforApiError("parse", "public_key response has no RSA modulus")

    monkeypatch.setattr(probe.SangforApiClient, "login", failing_login)
    monkeypatch.setenv("SANGFOR_PASSWORD", "x")
    code = probe.main(["--url", "http://127.0.0.1:9", "--user", "dtmon", "--out", str(tmp_path / "p.zip")])
    assert code == 2
    assert len(calls) == 1


# Item 6: README never shows secrets on the command line
def test_readme_documents_prompt_and_no_literal_secrets():
    readme = (ROOT / "validation-kit" / "README.md").read_text(encoding="utf-8")
    assert not re.search(r"export\s+SANGFOR_\w+\s*=", readme)
    assert "read -rs SANGFOR_PASSWORD && export SANGFOR_PASSWORD" in readme
    assert "prompt" in readme.lower()
    assert "six endpoints" not in readme


# Item 9: no duplicate zip entries
def test_probe_dedupes_repeated_snmp_nodes(tmp_path, monkeypatch):
    monkeypatch.setenv("SANGFOR_SNMP_COMMUNITY", "sangfopub")
    out = tmp_path / "p.zip"
    node = "10.0.0.50=127.0.0.1:9"
    code = probe.main(["--snmp-version", "v2c", "--timeout", "0.3", "--snmp-node", node, "--snmp-node", node,
                       "--snmp-node", "10.0.0.50=127.0.0.1:10", "--out", str(out)])
    assert code == 2
    names, _members = _read_zip(out)
    assert len(names) == len(set(names))
    assert len([name for name in names if name.startswith("snmp/")]) == 2
