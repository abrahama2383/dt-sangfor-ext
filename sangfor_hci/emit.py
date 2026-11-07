"""The only module that hands data to the Dynatrace SDK."""

from __future__ import annotations

from dynatrace_extension import DtEventType

from .model import Event, Metric

EVENT_TIMEOUT_MINUTES = 15


def emit_metrics(extension, metrics: list[Metric]) -> None:
    for metric in metrics:
        extension.report_metric(metric.full_key, metric.value, dict(metric.dimensions))


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
