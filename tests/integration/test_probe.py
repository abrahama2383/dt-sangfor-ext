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
