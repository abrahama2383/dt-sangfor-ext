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
