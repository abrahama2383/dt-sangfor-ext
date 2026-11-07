"""Starts snmpsim agents that pretend to be Sangfor HCI nodes.

Run:  .venv/bin/python -m simulator.snmp_sim
Agents: node-a on UDP 11161, node-b on 11162, bare (no private MIB) on 11163, all on 127.0.0.1.
v2c community "sangfopub". v3 user dtmon, SHA "dtmon-auth-key", AES "dtmon-priv-key", context "sangfopub".
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

DATA = Path(__file__).parent / "snmp"
V3_USER = "dtmon"
V3_AUTH_KEY = "dtmon-auth-key"
V3_PRIV_KEY = "dtmon-priv-key"
CONTEXT = "sangfopub"
DATASETS = ("node-a", "node-b", "bare")


def responder_path() -> str:
    return str(Path(sys.executable).parent / "snmpsim-command-responder")


def start_agent(dataset: str, port: int, log_path: Path | None = None) -> subprocess.Popen:
    """Starts one agent. With log_path, its output goes there, so a failed start can be diagnosed."""
    command = [
        responder_path(),
        f"--data-dir={DATA / dataset}",
        f"--agent-udpv4-endpoint=127.0.0.1:{port}",
        f"--v3-user={V3_USER}",
        f"--v3-auth-key={V3_AUTH_KEY}",
        "--v3-auth-proto=SHA",
        f"--v3-priv-key={V3_PRIV_KEY}",
        "--v3-priv-proto=AES",
    ]
    if log_path is None:
        return subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    with open(log_path, "wb") as log:  # the child keeps its own copy of the descriptor
        return subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)


def load_snmprec(dataset: str) -> dict[str, str]:
    values = {}
    for line in (DATA / dataset / "sangfopub.snmprec").read_text(encoding="utf-8").splitlines():
        if line.strip():
            oid, _type, value = line.split("|", 2)
            values[oid] = value
    return values


def main() -> None:
    parser = argparse.ArgumentParser(description="Simulated Sangfor HCI SNMP agents")
    parser.add_argument("--base-port", type=int, default=11161)
    args = parser.parse_args()
    processes = [start_agent(name, args.base_port + offset) for offset, name in enumerate(DATASETS)]
    for offset, name in enumerate(DATASETS):
        print(f"{name}: udp://127.0.0.1:{args.base_port + offset}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        for process in processes:
            process.terminate()


if __name__ == "__main__":
    main()
