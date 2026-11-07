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
