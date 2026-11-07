"""The only module that hands data to the Dynatrace SDK."""

from __future__ import annotations

from dynatrace_extension import DtEventType

from .model import MAX_DIMENSION_VALUE_LENGTH, Event, Metric, sanitize_dimension_value  # noqa: F401 (re-export)

EVENT_TIMEOUT_MINUTES = 15


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
