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
