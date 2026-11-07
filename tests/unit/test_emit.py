from dynatrace_extension import DtEventType

from sangfor_hci.emit import EVENT_TIMEOUT_MINUTES, emit_events, emit_metrics
from sangfor_hci.model import Event, Metric


class FakeExtension:
    def __init__(self):
        self.metrics, self.events = [], []

    def report_metric(self, key, value, dimensions=None, **kwargs):
        self.metrics.append((key, value, dimensions))

    def report_dt_event(self, event_type, title, **kwargs):
        self.events.append((event_type, title, kwargs))


def test_emit_metrics_uses_full_keys_and_copies_dimensions():
    fake = FakeExtension()
    dims = {"sangfor.cluster": "sim"}
    emit_metrics(fake, [Metric("cluster.cpu.usage", 6.0, dims)])
    assert fake.metrics == [("sangfor.hci.cluster.cpu.usage", 6.0, {"sangfor.cluster": "sim"})]
    assert fake.metrics[0][2] is not dims


def test_emit_events_maps_types_and_timeout():
    fake = FakeExtension()
    event = Event("ERROR_EVENT", "Sangfor HCI: x", 'type("sangfor_hci:cluster"),entityName.equals("sim")', 1000, {"a": "b"})
    emit_events(fake, [event])
    event_type, title, kwargs = fake.events[0]
    assert event_type is DtEventType.ERROR_EVENT
    assert title == "Sangfor HCI: x"
    assert kwargs == {
        "start_time": 1000,
        "timeout": EVENT_TIMEOUT_MINUTES,
        "entity_selector": 'type("sangfor_hci:cluster"),entityName.equals("sim")',
        "properties": {"a": "b"},
    }
