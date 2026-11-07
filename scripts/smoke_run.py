"""Runs the real extension with `dt-sdk run` against the simulator and checks what it sends.

Usage: .venv/bin/python scripts/smoke_run.py   (exit code 0 = pass)
"""

from __future__ import annotations

import os
import queue
import signal
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
STOP_GRACE_SECONDS = 20


def _pump(stream, lines: queue.Queue) -> None:
    for line in stream:
        lines.put(line)
    lines.put(None)


def _stop_group(process: subprocess.Popen) -> None:
    """SIGTERM the whole process group, then SIGKILL it if it has not exited in time."""
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=STOP_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)  # also reaches a child that outlived dt-sdk
    except ProcessLookupError:
        pass
    process.wait(timeout=STOP_GRACE_SECONDS)


def main() -> int:
    cert, key = write_self_signed_cert(ROOT / "simulator" / ".certs")
    server, _ = make_server(port=8443, certfile=str(cert), keyfile=str(key))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    agents = [start_agent("node-a", 11161), start_agent("node-b", 11162)]
    dt_sdk = str(Path(sys.executable).parent / "dt-sdk")
    seen: set[str] = set()
    process = None
    try:
        # Own process group: `dt-sdk run` starts `python -m sangfor_hci` as a child that a plain
        # terminate() of dt-sdk would leave running (orphaned, still polling the simulator).
        process = subprocess.Popen(
            [dt_sdk, "run"],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            start_new_session=True,
        )
        lines: queue.Queue[str | None] = queue.Queue()
        threading.Thread(target=_pump, args=(process.stdout, lines), daemon=True).start()
        deadline = time.monotonic() + DEADLINE_SECONDS
        while seen != set(REQUIRED):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                line = lines.get(timeout=remaining)
            except queue.Empty:
                break
            if line is None:  # dt-sdk exited
                break
            sys.stdout.write(line)
            seen.update(marker for marker in REQUIRED if marker in line)
    finally:
        try:
            if process is not None:
                _stop_group(process)
        finally:
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
