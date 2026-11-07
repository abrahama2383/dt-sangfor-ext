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


@pytest.mark.parametrize("mock_api", ["datastore_90"], indirect=True)
def test_datastore_90_scenario_is_consistent(mock_api):
    base, state = mock_api
    headers = _auth_headers(_login(base, state))
    store = requests.get(f"{base}/vapi/json/vtpstorage/storelist", headers=headers, timeout=5).json()["data"]["local"][0]
    assert store["status"] == 0x0101
    assert store["used"] + store["avail"] == store["total"]
    assert store["used_ratio"] == "93.00"


@pytest.mark.parametrize("mock_api", ["ticket_expired"], indirect=True)
def test_ticket_expired_scenario_rejects_first_ticket_once(mock_api):
    base, state = mock_api
    headers = _auth_headers(_login(base, state))
    first = requests.get(f"{base}/vapi/json/index/overview", headers=headers, timeout=5)
    assert first.status_code == 401
    headers = _auth_headers(_login(base, state))
    second = requests.get(f"{base}/vapi/json/index/overview", headers=headers, timeout=5)
    assert second.status_code == 200


@pytest.mark.filterwarnings("ignore::urllib3.exceptions.InsecureRequestWarning")  # verify=False is the point of this test
def test_tls_server_serves_https(mock_api_tls):
    base, _, cert_pem = mock_api_tls
    assert "BEGIN CERTIFICATE" in cert_pem
    response = requests.get(f"{base}/vapi/json/public_key", verify=False, timeout=5)
    assert response.json()["success"] == 1
