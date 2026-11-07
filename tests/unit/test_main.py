import logging

from dynatrace_extension import StatusValue
from dynatrace_extension.sdk.activation import ActivationConfig

from sangfor_hci.__main__ import SangforHciExtension
from sangfor_hci.runner import CycleResult

VALID = {
    "cluster_name": "good", "mode": "api", "api_url": "https://10.0.0.10",
    "api_username": "dtmon", "api_password": "pw-secret-1",
}
INVALID = {
    "cluster_name": "broken", "mode": "api", "api_url": "ftp://10.0.0.20",
    "api_username": "dtmon", "api_password": "pw-secret-2",
}


class _Executor:
    def shutdown(self, *args, **kwargs):
        pass


def _extension(endpoints):
    ext = object.__new__(SangforHciExtension)  # bypass the SDK singleton and its EEC connection
    ext._callbacks_executor = ext._internal_executor = _Executor()  # Extension.__del__ shuts these down
    ext.logger = logging.getLogger("test-sangfor-main")
    ext.activation_config = ActivationConfig({"featureSets": ["cluster"], "pythonRemote": {"endpoints": endpoints}})
    ext.scheduled = []
    ext.schedule = lambda callback, interval, args=None: ext.scheduled.append(args)
    ext.report_metric = lambda *a, **k: None
    ext.report_dt_event = lambda *a, **k: None
    return ext


class _Runner:
    def __init__(self, result):
        self._result = result
        self.config = type("C", (), {"cluster_name": "good"})()

    def run_cycle(self):
        return self._result


def test_partial_config_reports_warning_naming_the_invalid_endpoint():
    ext = _extension([VALID, INVALID])
    status = ext.initialize()
    assert status.status is StatusValue.WARNING
    assert "broken" in status.message and "api_url" in status.message
    assert "good" not in status.message
    assert "pw-secret" not in status.message
    assert len(ext.scheduled) == 1
    cycle = ext._run_cycle(_Runner(CycleResult()))
    assert cycle.status is StatusValue.WARNING
    assert "broken" in cycle.message and "pw-secret" not in cycle.message
    for runner in ext._runners:
        runner.close()


def test_fully_valid_config_is_ok():
    ext = _extension([VALID])
    assert ext.initialize() is None
    assert ext._run_cycle(_Runner(CycleResult())).status is StatusValue.OK
    for runner in ext._runners:
        runner.close()
