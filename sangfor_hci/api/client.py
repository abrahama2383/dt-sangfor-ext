"""Read-only client for the Sangfor HCI REST API (/vapi/json).

Login (Sangfor API spec 2022-01-06): GET /vapi/json/public_key returns the RSA modulus as hex
(exponent 0x10001). The password is encrypted with RSA PKCS#1 v1.5 and posted form-encoded to
/vapi/json/access/ticket. The returned ticket is sent as the LoginAuthCookie cookie and the
CSRFPreventionToken as a header.

Lockout safety: the ticket POST is sent at most once per login and never retried. A login the server rejects
(reason "auth") starts a back-off of 5, 10, 20, 40, then 60 minutes; until it expires no ticket POST is sent and
every call that needs a login fails at once with reason "auth". Login runs under one lock, so concurrent callers
during a failing login cause one POST, not one each.
"""

from __future__ import annotations

import logging
import math
import tempfile
import threading
import time
from pathlib import Path
from typing import Callable

import requests
import urllib3
from cryptography.hazmat.primitives.asymmetric import padding, rsa

log = logging.getLogger(__name__)

PUBLIC_KEY_PATH = "/vapi/json/public_key"
TICKET_PATH = "/vapi/json/access/ticket"
ALLOWED_GET_PREFIXES = (
    "/vapi/json/index/overview",
    "/vapi/json/index/host_list",
    "/vapi/json/nodes/",
    "/vapi/json/cluster/vms",
    "/vapi/json/vtpstorage/storelist",
    "/vapi/json/log/alert/all",
)
UNSAFE_PATH_PARTS = ("..", "//", "?", "#", "%", "\\")
RSA_EXPONENT = 0x10001
RETRY_BACKOFF_SECONDS = (1.0, 3.0)
LOGIN_BACKOFF_SECONDS = (300.0, 600.0, 1200.0, 2400.0, 3600.0)
# Ticket POST failures in which the server cannot have judged the password: they keep their own reason.
SERVER_SIDE_LOGIN_REASONS = ("timeout", "tls", "unreachable")


class SangforApiError(Exception):
    def __init__(
        self,
        reason: str,
        message: str,
        *,
        status: int | None = None,
        during_login: bool = False,
        error_class: str = "",
    ):
        super().__init__(message)
        self.reason = reason
        self.status = status  # the HTTP status, when the server answered
        self.during_login = during_login  # raised while logging in: no further request can succeed this cycle
        self.error_class = error_class  # the requests exception class behind a transport failure, e.g. "ConnectTimeout"


def encrypt_password(password: str, modulus_hex: str) -> str:
    public_key = rsa.RSAPublicNumbers(RSA_EXPONENT, int(modulus_hex, 16)).public_key()
    return public_key.encrypt(password.encode("utf-8"), padding.PKCS1v15()).hex()


class SangforApiClient:
    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        *,
        verify_tls: bool = True,
        ca_pem: str = "",
        timeout: float = 10.0,
        relogin_seconds: float = 600.0,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._base = base_url.rstrip("/")
        self._username = username
        self._password = password
        self._timeout = timeout
        self._relogin_seconds = relogin_seconds
        self._sleep = sleep
        self._clock = clock
        self._session = requests.Session()
        self._ca_file: Path | None = None
        if ca_pem:
            handle = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False, encoding="utf-8")
            handle.write(ca_pem)
            handle.close()
            self._ca_file = Path(handle.name)
            self._session.verify = str(self._ca_file)
        else:
            self._session.verify = verify_tls
            if not verify_tls:
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                log.warning("TLS verification is disabled for %s", self._base)
        self._login_lock = threading.Lock()
        self._ticket = ""
        self._csrf = ""
        self._logged_in_at: float | None = None
        self.login_count = 0
        self._login_failures = 0
        self._next_login_at: float | None = None
        self._last_login_error = ""

    def login(self) -> None:
        with self._login_lock:
            self._login_locked()

    def get(self, path: str, params: dict | None = None) -> object:
        if any(part in path for part in UNSAFE_PATH_PARTS) or not path.startswith(ALLOWED_GET_PREFIXES):
            raise SangforApiError("forbidden", f"path is not in the read-only allowlist: {path}")
        with self._login_lock:
            if self._needs_login():
                self._login_locked()
            ticket = self._ticket
        try:
            return self._request("GET", path, params=params)
        except SangforApiError as exc:
            if exc.reason != "auth":
                raise
            with self._login_lock:
                if self._ticket == ticket:
                    log.info("Sangfor rejected the ticket, logging in again")
                    self._login_locked()
            return self._request("GET", path, params=params)

    def close(self) -> None:
        self._session.close()
        if self._ca_file is not None:
            self._ca_file.unlink(missing_ok=True)
            self._ca_file = None

    def _needs_login(self) -> bool:
        return self._logged_in_at is None or (self._clock() - self._logged_in_at) >= self._relogin_seconds

    def _login_locked(self) -> None:
        """Caller holds _login_lock. Every login failure leaves the client logged out."""
        if self._next_login_at is not None:
            wait = self._next_login_at - self._clock()
            if wait > 0:
                raise SangforApiError(
                    "auth",
                    f"login suppressed after a failed login; next attempt in {math.ceil(wait)} s "
                    f"(last failure: {self._last_login_error})",
                    during_login=True,
                )
        self._ticket = self._csrf = ""
        self._logged_in_at = None
        try:
            modulus = self._request("GET", PUBLIC_KEY_PATH, authenticated=False)
            if not isinstance(modulus, str) or not modulus:
                raise SangforApiError("parse", "public_key response has no RSA modulus")
        except SangforApiError as exc:
            exc.during_login = True  # no password was sent: no back-off
            raise
        try:
            data = self._post_ticket(modulus)
        except SangforApiError as exc:
            exc.during_login = True
            if exc.reason == "auth":
                self._start_login_back_off(str(exc))
            raise
        self._ticket = str(data["ticket"])
        self._csrf = str(data.get("CSRFPreventionToken", ""))
        self._logged_in_at = self._clock()
        self._login_failures = 0
        self._next_login_at = None
        self._last_login_error = ""
        self.login_count += 1

    def _post_ticket(self, modulus: str) -> dict:
        try:
            encrypted = encrypt_password(self._password, modulus)
        except ValueError as exc:  # UnicodeEncodeError text would quote the offending password character
            raise SangforApiError(
                "auth", f"cannot encrypt the password with the server key: {exc.__class__.__name__}"
            ) from None
        try:
            data = self._request(
                "POST",
                TICKET_PATH,
                authenticated=False,
                form={"username": self._username, "password": encrypted},
                retry=False,  # a resent wrong password is a second failed login toward the account lockout
            )
        except SangforApiError as exc:
            server_error = exc.reason == "http" and exc.status is not None and exc.status >= 500
            if exc.reason in SERVER_SIDE_LOGIN_REASONS or exc.reason == "auth" or server_error:
                raise
            # HTTP 200 with success != 1, any 4xx, a non-JSON body: the server most likely refused the password.
            raise SangforApiError("auth", f"login rejected: {exc}", status=exc.status) from exc
        if not isinstance(data, dict) or not data.get("ticket"):
            raise SangforApiError("auth", "login response has no ticket")
        return data

    def _start_login_back_off(self, message: str) -> None:
        delay = LOGIN_BACKOFF_SECONDS[min(self._login_failures, len(LOGIN_BACKOFF_SECONDS) - 1)]
        self._login_failures += 1
        self._next_login_at = self._clock() + delay
        self._last_login_error = message
        log.warning("Sangfor login failed; no login is attempted for the next %d s: %s", delay, message)

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict | None = None,
        form: dict | None = None,
        authenticated: bool = True,
        retry: bool = True,
    ) -> object:
        """Read timeouts and 5xx are retried (1 s, 3 s): worst case 3 x timeout + 4 s per request.

        A refused or timed-out connection is not retried (reason "unreachable"): the caller aborts the API path.
        """
        headers = {}
        if authenticated:
            headers = {"Cookie": f"LoginAuthCookie={self._ticket}", "CSRFPreventionToken": self._csrf}
        attempts = len(RETRY_BACKOFF_SECONDS) + 1 if retry else 1
        for attempt in range(attempts):
            try:
                response = self._session.request(
                    method, self._base + path, params=params, data=form, headers=headers, timeout=self._timeout
                )
            except requests.exceptions.SSLError as exc:
                raise SangforApiError("tls", f"TLS verification failed for {self._base}: {exc}") from exc
            except (requests.exceptions.ConnectTimeout, requests.exceptions.ConnectionError) as exc:
                raise SangforApiError(
                    "unreachable", f"{method} {path} failed: {exc.__class__.__name__}", error_class=exc.__class__.__name__
                ) from exc
            except requests.exceptions.Timeout as exc:
                if attempt + 1 < attempts:
                    self._sleep(RETRY_BACKOFF_SECONDS[attempt])
                    continue
                raise SangforApiError(
                    "timeout", f"{method} {path} failed: {exc.__class__.__name__}", error_class=exc.__class__.__name__
                ) from exc
            except requests.exceptions.RequestException as exc:
                # Only the class name: the text of e.g. InvalidURL quotes the URL, which may carry credentials.
                raise SangforApiError(
                    "network", f"{method} {path} failed: {exc.__class__.__name__}", error_class=exc.__class__.__name__
                ) from None
            if response.status_code >= 500 and attempt + 1 < attempts:
                self._sleep(RETRY_BACKOFF_SECONDS[attempt])
                continue
            return self._parse(response, method, path)
        raise AssertionError("unreachable")

    @staticmethod
    def _parse(response: requests.Response, method: str, path: str) -> object:
        code = response.status_code
        try:
            body = response.json()
        except ValueError:
            body = None
        if not isinstance(body, dict):
            body = None
        status = body.get("status") if body is not None else None
        message = str(body.get("message", "")) if body is not None else ""
        if code in (401, 403) or status in (401, 403):
            raise SangforApiError("auth", f"{method} {path}: authentication rejected {message}".strip(), status=code)
        if code >= 400:
            raise SangforApiError("http", f"{method} {path}: HTTP {code} {message}".strip(), status=code)
        if body is None:
            raise SangforApiError("parse", f"{method} {path}: HTTP {code}, body is not JSON", status=code)
        if body.get("success") != 1:
            raise SangforApiError("http", f"{method} {path}: HTTP {code} {message}".strip(), status=code)
        return body.get("data")
