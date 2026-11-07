import json
import threading
import time

import requests
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


def test_unencodable_password_is_not_echoed_in_the_error(mock_api):
    base, state = mock_api
    client = SangforApiClient(base, "dtmon", "pa\udcffss-secret", sleep=lambda s: None)
    with pytest.raises(SangforApiError) as info:
        client.login()
    message = str(info.value)
    assert info.value.reason == "auth"
    assert "UnicodeEncodeError" in message
    for leaked in ("\udcff", "udcff", "pa\udcffss-secret", "position", "surrogate"):
        assert leaked not in message.lower(), leaked
    assert info.value.__cause__ is None
    assert "POST /vapi/json/access/ticket" not in state.requests


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


def _response(status, content=b"", content_type="text/html"):
    resp = requests.Response()
    resp.status_code = status
    resp._content = content
    resp.headers["Content-Type"] = content_type
    return resp


def test_forbidden_dot_segments(mock_api):
    base, state = mock_api
    client = _client(base)
    with pytest.raises(SangforApiError) as info:
        client.get("/vapi/json/nodes/../cluster/vm/123/status/stop")
    assert info.value.reason == "forbidden"
    assert state.requests == []


def test_parse_judges_status_before_body():
    parse = SangforApiClient._parse
    html = b"<html>proxy</html>"
    with pytest.raises(SangforApiError) as info:
        parse(_response(401, html), "GET", "/x")
    assert info.value.reason == "auth"
    with pytest.raises(SangforApiError) as info:
        parse(_response(403, b""), "GET", "/x")
    assert info.value.reason == "auth"
    with pytest.raises(SangforApiError) as info:
        parse(_response(503, html), "GET", "/x")
    assert info.value.reason == "http"
    with pytest.raises(SangforApiError) as info:
        parse(_response(200, html), "GET", "/x")
    assert info.value.reason == "parse"
    with pytest.raises(SangforApiError) as info:
        parse(_response(200, b'{"success": 0, "message": "nope"}', "application/json"), "GET", "/x")
    assert info.value.reason == "http"
    assert parse(_response(200, b'{"success": 1, "data": 5}', "application/json"), "GET", "/x") == 5


def test_persistent_5xx_retries_then_http():
    class FakeSession:
        def request(self, *args, **kwargs):
            return _response(503, b"<html>bad gateway</html>")

        def close(self):
            pass

    sleeps = []
    client = SangforApiClient("https://sangfor.invalid", "u", "p", sleep=sleeps.append)
    client._session = FakeSession()
    with pytest.raises(SangforApiError) as info:
        client._request("GET", "/vapi/json/index/overview", authenticated=False)
    assert info.value.reason == "http"
    assert sleeps == [1.0, 3.0]


# --- Final fix item 1: no login storm and no lockout on a wrong password ---------------------------------

_LOGIN_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_MODULUS = format(_LOGIN_KEY.public_key().public_numbers().n, "x")
GOOD_TICKET = b'{"success": 1, "data": {"ticket": "t-1", "CSRFPreventionToken": "c-1"}}'
BAD_LOGIN_200 = b'{"success": 0, "message": "invalid username or password"}'


class LoginSession:
    """Fake requests session: serves the public key, answers the ticket POST from `ticket`, data GETs with 200."""

    def __init__(self, ticket=(200, BAD_LOGIN_200), post_delay=0.0):
        self.ticket = ticket
        self.post_delay = post_delay
        self.posts = 0
        self.gets = []
        self._lock = threading.Lock()

    def request(self, method, url, **kwargs):
        if url.endswith("/vapi/json/public_key"):
            return _response(200, json.dumps({"success": 1, "data": _MODULUS}).encode(), "application/json")
        if method == "POST":
            with self._lock:
                self.posts += 1
            if self.post_delay:
                time.sleep(self.post_delay)
            ticket = self.ticket
            if isinstance(ticket, BaseException):
                raise ticket
            status, body = ticket
            return _response(status, body, "application/json")
        with self._lock:
            self.gets.append(url)
        return _response(200, b'{"success": 1, "data": {"ok": true}}', "application/json")

    def close(self):
        pass


def _login_client(session, now, **kwargs):
    client = SangforApiClient("https://hci.invalid", "dtmon", "pw-typo", sleep=lambda s: None, clock=lambda: now[0], **kwargs)
    client._session = session
    return client


def _raises(call):
    with pytest.raises(SangforApiError) as info:
        call()
    return info.value


@pytest.mark.parametrize(
    "ticket",
    [
        (200, BAD_LOGIN_200),
        (200, b'{"success": 1, "data": {}}'),
        (200, b"<html>login page</html>"),
        (400, b'{"success": 0, "message": "bad request"}'),
        (404, b"not found"),
        (401, b'{"success": 0, "status": 401}'),
    ],
    ids=["200-success0", "no-ticket", "200-html", "400", "404", "401"],
)
def test_every_rejected_login_is_auth_and_sent_once(ticket):
    session = LoginSession(ticket)
    client = _login_client(session, [1000.0])
    error = _raises(lambda: client.get("/vapi/json/index/overview"))
    assert error.reason == "auth"
    assert "pw-typo" not in str(error)
    assert session.posts == 1
    assert session.gets == []


@pytest.mark.parametrize(
    "ticket, reason",
    [
        ((503, b"<html>bad gateway</html>"), "http"),
        (requests.exceptions.ReadTimeout("read timed out"), "timeout"),
        (requests.exceptions.ConnectTimeout("connect timed out"), "unreachable"),
        (requests.exceptions.ConnectionError("refused"), "unreachable"),
        (requests.exceptions.SSLError("bad cert"), "tls"),
    ],
    ids=["5xx", "read-timeout", "connect-timeout", "refused", "tls"],
)
def test_server_side_login_failures_keep_their_reason_and_are_not_resent(ticket, reason):
    session = LoginSession(ticket)
    sleeps = []
    client = _login_client(session, [1000.0])
    client._sleep = sleeps.append
    error = _raises(client.login)
    assert error.reason == reason
    assert session.posts == 1  # the ticket POST is never retried: a resent bad password is a second failed login
    assert sleeps == []


def test_failed_login_suppresses_logins_until_the_back_off_expires():
    session = LoginSession()
    now = [1000.0]
    client = _login_client(session, now)
    assert _raises(client.login).reason == "auth"
    now[0] += 299
    error = _raises(lambda: client.get("/vapi/json/index/overview"))
    assert error.reason == "auth"
    assert "login suppressed after a failed login; next attempt in 1 s" in str(error)
    assert _raises(client.login).reason == "auth"
    assert session.posts == 1 and session.gets == []
    now[0] += 1
    assert _raises(client.login).reason == "auth"
    assert session.posts == 2


def test_login_back_off_grows_and_caps_at_60_minutes():
    session = LoginSession()
    now = [1000.0]
    client = _login_client(session, now)
    waits = []
    for _ in range(7):
        posts = session.posts
        _raises(client.login)
        assert session.posts == posts + 1
        message = str(_raises(client.login))
        assert session.posts == posts + 1
        waits.append(int(message.split("next attempt in ")[1].split(" s")[0]))
        now[0] += waits[-1]
    assert waits == [300, 600, 1200, 2400, 3600, 3600, 3600]


def test_successful_login_resets_the_back_off():
    session = LoginSession()
    now = [1000.0]
    client = _login_client(session, now)
    _raises(client.login)
    now[0] += 300
    _raises(client.login)  # second failure: next wait 600 s
    now[0] += 600
    session.ticket = (200, GOOD_TICKET)
    assert client.get("/vapi/json/index/overview") == {"ok": True}
    session.ticket = (200, BAD_LOGIN_200)
    _raises(client.login)
    assert "next attempt in 300 s" in str(_raises(client.login))


def test_concurrent_gets_during_a_failing_login_send_one_post():
    session = LoginSession(post_delay=0.2)
    client = _login_client(session, [1000.0])
    barrier = threading.Barrier(4)
    reasons = []

    def worker():
        barrier.wait()
        try:
            client.get("/vapi/json/index/overview")
        except SangforApiError as exc:
            reasons.append(exc.reason)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
    assert reasons == ["auth"] * 4
    assert session.posts == 1
    assert session.gets == []


def test_rejected_ticket_with_a_failing_relogin_backs_off():
    class RejectingSession(LoginSession):
        def request(self, method, url, **kwargs):
            if method == "GET" and not url.endswith("/public_key"):
                with self._lock:
                    self.gets.append(url)
                return _response(401, b'{"success": 0, "status": 401}', "application/json")
            return super().request(method, url, **kwargs)

    session = RejectingSession(ticket=(200, GOOD_TICKET))
    now = [1000.0]
    client = _login_client(session, now)
    client.login()
    session.ticket = (200, BAD_LOGIN_200)  # the password was changed on the HCI
    assert _raises(lambda: client.get("/vapi/json/index/overview")).reason == "auth"
    assert session.posts == 2
    for _ in range(3):
        assert _raises(lambda: client.get("/vapi/json/index/overview")).reason == "auth"
    assert session.posts == 2
    assert len(session.gets) == 1  # no GET is sent with a ticket known to be dead


# --- Final fix items 2 and 3: unreachable and other network errors ----------------------------------------

def test_unreachable_server_is_not_retried():
    sleeps = []
    client = SangforApiClient("http://127.0.0.1:9", "dtmon", "dtmon-pass", timeout=1.0, sleep=sleeps.append)
    error = _raises(lambda: client.get("/vapi/json/index/overview"))
    assert error.reason == "unreachable"
    assert sleeps == []


def test_read_timeouts_on_gets_are_still_retried():
    class SlowSession:
        def request(self, *args, **kwargs):
            raise requests.exceptions.ReadTimeout("read timed out")

        def close(self):
            pass

    sleeps = []
    client = SangforApiClient("https://hci.invalid", "u", "p", sleep=sleeps.append)
    client._session = SlowSession()
    error = _raises(lambda: client._request("GET", "/vapi/json/index/overview", authenticated=False))
    assert error.reason == "timeout"
    assert sleeps == [1.0, 3.0]


@pytest.mark.parametrize(
    "exc",
    [
        requests.exceptions.InvalidURL("bad url https://u:secret-xyz@h"),
        requests.exceptions.ChunkedEncodingError("secret-xyz"),
        requests.exceptions.ContentDecodingError("secret-xyz"),
        requests.exceptions.TooManyRedirects("secret-xyz"),
    ],
    ids=lambda e: type(e).__name__,
)
def test_other_request_errors_become_network_with_the_class_name_only(exc):
    class BrokenSession:
        def request(self, *args, **kwargs):
            raise exc

        def close(self):
            pass

    sleeps = []
    client = SangforApiClient("https://hci.invalid", "u", "p", sleep=sleeps.append)
    client._session = BrokenSession()
    error = _raises(lambda: client._request("GET", "/vapi/json/index/overview", authenticated=False))
    assert error.reason == "network"
    assert type(exc).__name__ in str(error)
    assert "secret-xyz" not in str(error)
    assert sleeps == []
