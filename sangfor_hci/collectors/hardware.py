"""SNMP readings from one HCI node -> hardware metrics (feature set "hardware")."""

from __future__ import annotations

from ..model import Metric, MetricList, host_dims, parse_number, ratio_to_percent
from ..snmp import oids

OK_TOKENS = {"ok", "normal", "optimal", "good", "online", "healthy", "1"}
BAD_TOKENS = {"fail", "failed", "failure", "error", "fault", "faulty", "degraded", "offline", "critical", "abnormal", "bad", "0"}
GIB = 1024**3
MAX_UNKNOWN_VALUES = 100  # kept for diagnostics only; bounded against a node that reports free text


class StatusBaseline:
    """Classifies status strings; unknown strings are compared with the first value seen."""

    def __init__(self) -> None:
        self._first: dict[tuple[str, str], str] = {}
        self.unknown_values: set[str] = set()

    def is_ok(self, key: tuple[str, str], text: str) -> bool:
        token = text.strip().lower()
        first = self._first.setdefault(key, token)
        if token in OK_TOKENS:
            return True
        if token in BAD_TOKENS:
            return False
        if len(self.unknown_values) < MAX_UNKNOWN_VALUES:
            self.unknown_values.add(token)
        return token == first


def _scalar(scalar: oids.Scalar, scalars: dict[str, str]) -> float | None:
    raw = scalars.get(scalar.oid)
    return ratio_to_percent(raw) if scalar.ratio else parse_number(raw)


def _column(values: dict[str, str], table: oids.Table, suffix: str) -> dict[str, str]:
    prefix = table.column_oid(suffix) + "."
    return {oid[len(prefix) :]: value for oid, value in values.items() if oid.startswith(prefix)}


def collect(
    cluster: str,
    host_ip: str,
    host_name: str,
    scalars: dict[str, str],
    tables: dict[str, dict[str, str]],
    baseline: StatusBaseline,
) -> list[Metric]:
    metrics = MetricList(host_dims(cluster, host_ip, host_name))
    metrics.add(oids.HOST_DISK.metric, _scalar(oids.HOST_DISK, scalars))
    for table in oids.TABLES:
        values = tables.get(table.entry, {})
        names = _column(values, table, table.name_column)
        for column in table.columns:
            for index, raw in _column(values, table, column.suffix).items():
                label = names.get(index, index)
                extra = {f"sangfor.{table.name}": label}
                if column.kind == "status":
                    if not raw.strip():
                        continue
                    ok = baseline.is_ok((host_ip, f"{table.name}:{label}"), raw)
                    metrics.add(column.metric, 1.0 if ok else 0.0, extra)
                elif column.kind == "gb":
                    number = parse_number(raw)
                    metrics.add(column.metric, None if number is None else number * GIB, extra)
                else:
                    metrics.add(column.metric, parse_number(raw), extra)
    return list(metrics)


def snmp_host_metrics(cluster: str, host_ip: str, host_name: str, scalars: dict[str, str]) -> list[Metric]:
    """Host CPU and memory from SNMP: used in snmp mode and as the fallback when the API fails."""
    metrics = MetricList(host_dims(cluster, host_ip, host_name))
    for scalar in (oids.HOST_CPU, oids.HOST_MEMORY):
        metrics.add(scalar.metric, _scalar(scalar, scalars))
    return list(metrics)
