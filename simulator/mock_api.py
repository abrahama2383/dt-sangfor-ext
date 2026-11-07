"""Local stand-in for the Sangfor HCI REST API. For development and tests only.

Run:  .venv/bin/python -m simulator.mock_api --port 8443 --scenario healthy
"""

from __future__ import annotations

import argparse
import copy
import datetime
import ipaddress
import json
import secrets
import ssl
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

FIXTURES = Path(__file__).parent / "fixtures"
SCENARIOS = ("healthy", "host_offline", "datastore_90", "ticket_expired")


def load_fixtures() -> dict[str, object]:
    return {path.stem: json.loads(path.read_text(encoding="utf-8")) for path in sorted(FIXTURES.glob("*.json"))}


def apply_scenario(fixtures: dict, scenario: str) -> dict:
    data = copy.deepcopy(fixtures)
    now = int(time.time())
    for alarm in data["alerts"]["data"]["data"]:
        alarm["start"] = now - 30
        alarm["end"] = now - 30
    if scenario == "host_offline":
        data["host_list"]["data"][1]["status"] = 0
        data["overview"]["data"]["host"].update({"online": 1, "offline": 1})
    elif scenario == "datastore_90":
        datastore = data["storelist"]["data"]["local"][0]
        datastore["status"] = 0x0001 | 0x0100
        datastore["used"] = int(datastore["total"] * 0.93)
        datastore["avail"] = datastore["total"] - datastore["used"]
    return data


@dataclass
class MockState:
    scenario: str
    username: str
    password: str
    fixtures: dict
    private_key: rsa.RSAPrivateKey
    tickets: set[str] = field(default_factory=set)
    login_count: int = 0
    expire_next_ticket: bool = False
    requests: list[str] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def modulus_hex(self) -> str:
        return format(self.private_key.public_key().public_numbers().n, "x")

    def decrypt(self, hex_text: str) -> str:
        return self.private_key.decrypt(bytes.fromhex(hex_text), padding.PKCS1v15()).decode("utf-8")


class Handler(BaseHTTPRequestHandler):
    state: MockState  # bound per server by make_server

    def log_message(self, format, *args):  # noqa: A002 - keep test output quiet
        return

    def _send(self, status: int, body: object) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _ticket_ok(self) -> bool:
        ticket = ""
        for part in self.headers.get("Cookie", "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == "LoginAuthCookie":
                ticket = value
        csrf = self.headers.get("CSRFPreventionToken", "")
        with self.state.lock:
            if ticket not in self.state.tickets or csrf != f"csrf-{ticket}":
                return False
            if self.state.expire_next_ticket:
                self.state.expire_next_ticket = False
                self.state.tickets.discard(ticket)
                return False
            return True

    def do_POST(self):  # noqa: N802 - http.server naming
        path = urlparse(self.path).path
        self.state.requests.append(f"POST {path}")
        if path != "/vapi/json/access/ticket":
            return self._send(405, {"success": 0, "status": 405, "message": "method not allowed"})
        length = int(self.headers.get("Content-Length", "0"))
        form = parse_qs(self.rfile.read(length).decode("utf-8"))
        username = form.get("username", [""])[0]
        try:
            password = self.state.decrypt(form.get("password", [""])[0])
        except ValueError:
            password = None
        if username != self.state.username or password != self.state.password:
            return self._send(401, {"success": 0, "status": 401, "message": "invalid username or password"})
        ticket = secrets.token_hex(16)
        with self.state.lock:
            self.state.tickets.add(ticket)
            self.state.login_count += 1
            if self.state.scenario == "ticket_expired" and self.state.login_count == 1:
                self.state.expire_next_ticket = True
        data = {"ticket": ticket, "CSRFPreventionToken": f"csrf-{ticket}", "username": username}
        return self._send(200, {"success": 1, "data": data})

    def do_GET(self):  # noqa: N802 - http.server naming
        path = urlparse(self.path).path
        self.state.requests.append(f"GET {path}")
        if path == "/vapi/json/public_key":
            return self._send(200, {"success": 1, "data": self.state.modulus_hex()})
        if not self._ticket_ok():
            return self._send(401, {"success": 0, "status": 401, "message": "authentication failure"})
        fixtures = self.state.fixtures
        routes = {
            "/vapi/json/index/overview": "overview",
            "/vapi/json/index/host_list": "host_list",
            "/vapi/json/cluster/vms": "vms",
            "/vapi/json/vtpstorage/storelist": "storelist",
            "/vapi/json/log/alert/all": "alerts",
        }
        if path in routes:
            return self._send(200, fixtures[routes[path]])
        if path.startswith("/vapi/json/nodes/") and path.endswith("/info"):
            host_id = path[len("/vapi/json/nodes/") : -len("/info")]
            info = fixtures["node_info"].get(host_id)
            if info is None:
                return self._send(404, {"success": 0, "status": 404, "message": "no such host"})
            return self._send(200, {"success": 1, "data": info})
        return self._send(404, {"success": 0, "status": 404, "message": "not found"})


def make_server(
    host: str = "127.0.0.1",
    port: int = 0,
    scenario: str = "healthy",
    username: str = "dtmon",
    password: str = "dtmon-pass",
    certfile: str | None = None,
    keyfile: str | None = None,
) -> tuple[ThreadingHTTPServer, MockState]:
    if scenario not in SCENARIOS:
        raise ValueError(f"unknown scenario '{scenario}', expected one of {SCENARIOS}")
    state = MockState(
        scenario=scenario,
        username=username,
        password=password,
        fixtures=apply_scenario(load_fixtures(), scenario),
        private_key=rsa.generate_private_key(public_exponent=65537, key_size=2048),
    )
    handler = type("BoundHandler", (Handler,), {"state": state})
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    if certfile:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile, keyfile)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    return server, state


def write_self_signed_cert(directory: Path) -> tuple[Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sangfor-sim.local")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    directory.mkdir(parents=True, exist_ok=True)
    cert_path = directory / "sim-cert.pem"
    key_path = directory / "sim-key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
        )
    )
    return cert_path, key_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Mock Sangfor HCI REST API")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--scenario", choices=SCENARIOS, default="healthy")
    parser.add_argument("--no-tls", action="store_true", help="serve plain HTTP")
    args = parser.parse_args()
    certfile = keyfile = None
    if not args.no_tls:
        cert, key = write_self_signed_cert(Path(__file__).parent / ".certs")
        certfile, keyfile = str(cert), str(key)
    server, _ = make_server(port=args.port, scenario=args.scenario, certfile=certfile, keyfile=keyfile)
    scheme = "http" if args.no_tls else "https"
    print(f"Mock Sangfor API on {scheme}://127.0.0.1:{args.port} scenario={args.scenario} user=dtmon password=dtmon-pass")
    server.serve_forever()


if __name__ == "__main__":
    main()
