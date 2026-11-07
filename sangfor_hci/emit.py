"""The only module that hands data to the Dynatrace SDK."""

from __future__ import annotations

from dynatrace_extension import DtEventType

from .model import Event, Metric

EVENT_TIMEOUT_MINUTES = 15
MAX_DIMENSION_VALUE_LENGTH = 250
# A quote, a backslash or a control character in a value would break the MINT line or the entity selectors.
_UNSAFE = {ord('"'): "'", ord("\\"): "/", **{c: " " for c in (*range(0x20), *range(0x7F, 0xA0))}}


def sanitize_dimension_value(value: str) -> str:
    return str(value).translate(_UNSAFE)[:MAX_DIMENSION_VALUE_LENGTH]


def emit_metrics(extension, metrics: list[Metric]) -> None:
    for metric in metrics:
        dims = {key: sanitize_dimension_value(value) for key, value in metric.dimensions.items()}
        extension.report_metric(metric.full_key, metric.value, dims)


def emit_events(extension, events: list[Event]) -> None:
    for event in events:
        extension.report_dt_event(
            DtEventType(event.event_type),
            event.title,
            start_time=event.start_ms,
            timeout=EVENT_TIMEOUT_MINUTES,
            entity_selector=event.entity_selector,
            properties=dict(event.properties),
        )
