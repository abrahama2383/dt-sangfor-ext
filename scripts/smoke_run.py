"""Runs the real extension with `dt-sdk run` against the simulator and checks what it sends.

Usage: .venv/bin/python scripts/smoke_run.py   (exit code 0 = pass)
"""

from __future__ import annotations

import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from simulator.mock_api import make_server, write_self_signed_cert  # noqa: E402
from simulator.snmp_sim import start_agent  # noqa: E402

REQUIRED = (
    "send_metric: sangfor.hci.cluster.cpu.usage",
    "send_metric: sangfor.hci.host.cpu.usage",
    "send_metric: sangfor.hci.vm.cpu.usage",
    "send_metric: sangfor.hci.datastore.usage",
    "send_metric: sangfor.hci.hw.fan.ok",
    "Sending DT Event",
)
DEADLINE_SECONDS = 180


def main() -> int:
    cert, key = write_self_signed_cert(ROOT / "simulator" / ".certs")
    server, _ = make_server(port=8443, certfile=str(cert), keyfile=str(key))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    agents = [start_agent("node-a", 11161), start_agent("node-b", 11162)]
    dt_sdk = str(Path(sys.executable).parent / "dt-sdk")
    process = subprocess.Popen(
        [dt_sdk, "run"], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
    )
    seen: set[str] = set()
    started = time.monotonic()
    try:
        for line in process.stdout:
            sys.stdout.write(line)
            seen.update(marker for marker in REQUIRED if marker in line)
            if seen == set(REQUIRED) or time.monotonic() - started > DEADLINE_SECONDS:
                break
    finally:
        process.terminate()
        process.wait(timeout=20)
        for agent in agents:
            agent.terminate()
        server.shutdown()
    missing = sorted(set(REQUIRED) - seen)
    if missing:
        print(f"\nSMOKE FAILED, missing: {missing}")
        return 1
    print("\nSMOKE PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
