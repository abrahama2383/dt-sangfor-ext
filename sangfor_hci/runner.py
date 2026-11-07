"""One polling cycle for one Sangfor cluster. Calls clients and collectors; never imports the SDK."""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable

from .api.client import SangforApiClient, SangforApiError
from .collectors import alarms, cluster, datastore, hardware, host, vm
from .config import ClusterConfig, SnmpNode
from .model import Event, Metric, cluster_dims
from .snmp import oids
from .snmp.client import SnmpClient, SnmpError, SnmpTarget

log = logging.getLogger(__name__)

FEATURE_SETS = ("cluster", "host", "vm", "datastore", "hardware")
PROBE_INTERVAL_SECONDS = 3600
ALERT_PARAMS = {"distinct": 0, "limit": 100, "direct": "DESC"}
NODE_INFO_TARGET = "/vapi/json/nodes/{id}/info"
ABORT_REASONS = ("auth", "tls", "forbidden")


@dataclass
class CycleResult:
    metrics: list[Metric] = field(default_factory=list)
    events: list[Event] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    skipped: bool = False


class _ApiAborted(Exception):
    pass


def default_api_factory(config: ClusterConfig) -> SangforApiClient:
    api = config.api
    return SangforApiClient(
        api.url,
        api.username,
        api.password,
        verify_tls=api.verify_tls,
        ca_pem=api.ca_pem,
        timeout=float(config.timeout_seconds),
    )


def default_snmp_factory(config: ClusterConfig, node: SnmpNode) -> SnmpClient:
    snmp = config.snmp
    return SnmpClient(
        SnmpTarget(
            address=node.address,
            port=node.port,
            version=snmp.version,
            timeout=float(config.timeout_seconds),
            community=snmp.community,
            v3_user=snmp.v3_user,
            v3_auth_protocol=snmp.v3_auth_protocol,
            v3_auth_key=snmp.v3_auth_key,
            v3_priv_protocol=snmp.v3_priv_protocol,
            v3_priv_key=snmp.v3_priv_key,
            v3_context_name=snmp.v3_context_name,
        )
    )


class ClusterRunner:
    def __init__(
        self,
        config: ClusterConfig,
        enabled_sets: set[str],
        *,
        api_factory: Callable[[ClusterConfig], SangforApiClient] = default_api_factory,
        snmp_factory: Callable[[ClusterConfig, SnmpNode], SnmpClient] = default_snmp_factory,
        clock: Callable[[], float] = time.time,
    ):
        self.config = config
        self.enabled = set(enabled_sets) & set(FEATURE_SETS)
        self._clock = clock
        self._api = api_factory(config) if config.uses_api else None
        self._snmp_factory = snmp_factory
        self._cycle = 0
        self._lock = threading.Lock()
        self._cursor = alarms.AlarmCursor(start_after=int(clock()) - 2 * config.interval_seconds)
        self._baseline = hardware.StatusBaseline()
        self._probes: dict[str, tuple[bool, float]] = {}
        self._hosts: dict[str, host.HostInfo] = {}

    def run_cycle(self) -> CycleResult:
        if not self._lock.acquire(blocking=False):
            log.warning("Previous cycle for %s is still running; skipping this one", self.config.cluster_name)
            return CycleResult(skipped=True)
        try:
            self._cycle += 1
            result = CycleResult()
            api_ok = self._run_api(result) if self._api is not None else False
            if self.config.uses_snmp:
                self._run_snmp(result, api_ok)
            return result
        finally:
            self._lock.release()

    def snmp_nodes(self) -> list[SnmpNode]:
        snmp = self.config.snmp
        if snmp is None:
            return []
        if snmp.nodes:
            return list(snmp.nodes)
        return [SnmpNode(h.ip, h.ip, snmp.port) for h in self._hosts.values()]

    def close(self) -> None:
        if self._api is not None:
            self._api.close()

    # --- API path -------------------------------------------------------------

    def _run_api(self, result: CycleResult) -> bool:
        """Returns True when the API delivered the host metrics, so SNMP must not emit them again.

        An abort later in the cycle (for example an auth error on the datastore list) does not undo that.
        """
        name = self.config.cluster_name
        hosts_from_api = False
        try:
            overview = self._fetch(result, "/vapi/json/index/overview")
            host_list = self._fetch(result, "/vapi/json/index/host_list")
            if host_list is not None:
                self._hosts = host.index(host_list)
            if "cluster" in self.enabled and overview is not None:
                result.metrics += cluster.collect(name, overview)
            if "host" in self.enabled and host_list is not None:
                result.metrics += host.collect(name, host_list, self._fetch_node_infos(result))
                hosts_from_api = True
            if "datastore" in self.enabled:
                stores = self._fetch(result, "/vapi/json/vtpstorage/storelist")
                if stores is not None:
                    result.metrics += datastore.collect(name, stores)
            if "vm" in self.enabled and (self._cycle - 1) % self.config.vm_every_n_cycles == 0:
                vms = self._fetch(result, "/vapi/json/cluster/vms")
                if vms is not None:
                    result.metrics += vm.collect(name, vms, self._hosts)
            alerts = self._fetch(result, "/vapi/json/log/alert/all", ALERT_PARAMS)
            if alerts is not None:
                result.events += alarms.collect(name, alerts, self._hosts, self._cursor)
        except _ApiAborted:
            pass
        return hosts_from_api

    def _fetch(self, result: CycleResult, path: str, params: dict | None = None, target: str | None = None) -> object:
        target = target or path
        started = time.perf_counter()
        try:
            return self._api.get(path, params)
        except SangforApiError as exc:
            self._record_error(result, "api", target, exc.reason, str(exc))
            if exc.reason in ABORT_REASONS:
                raise _ApiAborted() from exc
            return None
        finally:
            self._record_duration(result, "api", target, started)

    def _fetch_node_infos(self, result: CycleResult) -> dict[str, dict]:
        ids = list(self._hosts)
        aborted = threading.Event()

        def fetch_one(host_id: str) -> object:
            # Once one request has aborted the API path (auth/TLS/forbidden), queued requests are not sent.
            if aborted.is_set():
                return None
            try:
                return self._fetch(result, f"/vapi/json/nodes/{host_id}/info", target=NODE_INFO_TARGET)
            except _ApiAborted:
                aborted.set()
                raise

        with ThreadPoolExecutor(max_workers=4) as pool:
            responses = list(pool.map(fetch_one, ids))
        return {host_id: data for host_id, data in zip(ids, responses) if isinstance(data, dict)}

    # --- SNMP path ------------------------------------------------------------

    def _run_snmp(self, result: CycleResult, api_ok: bool) -> None:
        want_hardware = "hardware" in self.enabled
        want_host = "host" in self.enabled and not api_ok
        if not (want_hardware or want_host):
            return
        nodes = self.snmp_nodes()
        if not nodes:
            result.problems.append("snmp: no nodes to poll (snmp_nodes is empty and the API host list is unavailable)")
            return
        names = {h.ip: h.name for h in self._hosts.values()}
        with ThreadPoolExecutor(max_workers=8) as pool:
            batches = list(
                pool.map(
                    lambda node: self._poll_node(result, node, names.get(node.host_ip, ""), want_hardware, want_host),
                    nodes,
                )
            )
        for batch in batches:
            result.metrics += batch

    def _poll_node(
        self, result: CycleResult, node: SnmpNode, api_name: str, want_hardware: bool, want_host: bool
    ) -> list[Metric]:
        started = time.perf_counter()
        name_of_cluster = self.config.cluster_name
        try:
            client = self._snmp_factory(self.config, node)
            if not self._private_subtree_present(result, client, node):
                return []
            scalars = client.get([oids.SYS_NAME, oids.HOST_CPU.oid, oids.HOST_MEMORY.oid, oids.HOST_DISK.oid])
            name = api_name or scalars.get(oids.SYS_NAME) or node.host_ip
            metrics: list[Metric] = []
            if want_host:
                metrics += hardware.snmp_host_metrics(name_of_cluster, node.host_ip, name, scalars)
            if want_hardware:
                tables = {table.entry: client.walk(table.entry) for table in oids.TABLES}
                metrics += hardware.collect(name_of_cluster, node.host_ip, name, scalars, tables, self._baseline)
            return metrics
        except SnmpError as exc:
            self._record_error(result, "snmp", node.host_ip, "snmp", str(exc))
            return []
        except Exception as exc:  # noqa: BLE001 - one bad node (e.g. unresolvable address) must not end the cycle
            # Only the type name: the message of an exception we did not raise could carry a community or key.
            self._record_error(result, "snmp", node.host_ip, "unexpected", f"unexpected {type(exc).__name__}")
            return []
        finally:
            self._record_duration(result, "snmp", node.host_ip, started)

    def _private_subtree_present(self, result: CycleResult, client: SnmpClient, node: SnmpNode) -> bool:
        now = self._clock()
        cached = self._probes.get(node.host_ip)
        if cached is None or now - cached[1] >= PROBE_INTERVAL_SECONDS:
            present = client.has_subtree(oids.ROOT)
            if not present and (cached is None or cached[0]):
                log.warning(
                    "Node %s does not expose the Sangfor private MIB %s; its SNMP metrics stay off until the next hourly check",
                    node.host_ip,
                    oids.ROOT,
                )
            cached = (present, now)
            self._probes[node.host_ip] = cached
        if not cached[0]:
            result.problems.append(f"snmp {node.host_ip}: Sangfor private MIB {oids.ROOT} not available")
        return cached[0]

    # --- self-monitoring ------------------------------------------------------

    def _record_duration(self, result: CycleResult, source: str, target: str, started: float) -> None:
        elapsed_ms = round((time.perf_counter() - started) * 1000.0, 1)
        dims = {**cluster_dims(self.config.cluster_name), "source": source, "target": target}
        result.metrics.append(Metric("ext.poll.duration", elapsed_ms, dims))

    def _record_error(self, result: CycleResult, source: str, target: str, reason: str, message: str) -> None:
        dims = {**cluster_dims(self.config.cluster_name), "source": source, "target": target, "reason": reason}
        result.metrics.append(Metric("ext.poll.errors", 1.0, dims))
        result.problems.append(f"{source} {target}: {message}")
        log.warning("%s %s failed (%s): %s", source, target, reason, message)
