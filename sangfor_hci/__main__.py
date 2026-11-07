"""Dynatrace Extensions 2.0 entry point for custom:sangfor-hci."""

from __future__ import annotations

import logging

from dynatrace_extension import Extension, Status, StatusValue

from .config import ConfigError, parse_endpoint
from .emit import emit_events, emit_metrics
from .runner import FEATURE_SETS, ClusterRunner


class SangforHciExtension(Extension):
    def initialize(self):
        self._runners: list[ClusterRunner] = []
        package_logger = logging.getLogger("sangfor_hci")
        if not package_logger.handlers:
            for handler in self.logger.handlers:
                package_logger.addHandler(handler)
            package_logger.setLevel(self.logger.level or logging.INFO)

        enabled = set(self.activation_config.feature_sets) & set(FEATURE_SETS)
        if not enabled:
            self.logger.warning("No feature sets are enabled; only self-monitoring metrics will be reported")
        problems = []
        self._config_warning = ""
        for number, raw in enumerate(self.activation_config.get("endpoints", []), 1):
            try:
                config = parse_endpoint(raw)
            except ConfigError as exc:  # ConfigError messages never quote a secret
                label = str(raw.get("cluster_name") or f"#{number}") if isinstance(raw, dict) else f"#{number}"
                problems.append(f"endpoint '{label}': {exc}")
                continue
            runner = ClusterRunner(config, enabled)
            self._runners.append(runner)
            self.schedule(self._run_cycle, config.interval_seconds, args=(runner,))
            self.logger.info(
                "Monitoring Sangfor cluster '%s' in %s mode every %s s", config.cluster_name, config.mode, config.interval_seconds
            )
        if not self._runners:
            return Status(StatusValue.INVALID_CONFIG_ERROR, "; ".join(problems) or "no endpoints configured")
        if problems:
            self._config_warning = "ignored invalid endpoints: " + "; ".join(problems)
            self.logger.warning(self._config_warning)
            # The SDK only acts on an error status from initialize(), so every cycle status repeats this warning.
            return Status(StatusValue.WARNING, self._config_warning)
        return None

    def _run_cycle(self, runner: ClusterRunner) -> Status:
        result = runner.run_cycle()
        name = runner.config.cluster_name
        if result.skipped:
            return Status(StatusValue.WARNING, f"{name}: previous cycle still running")
        emit_metrics(self, result.metrics)
        emit_events(self, result.events)
        messages = []
        if result.problems:
            messages.append(f"{name}: " + "; ".join(result.problems[:5]))
        if getattr(self, "_config_warning", ""):
            messages.append(self._config_warning)
        if messages:
            return Status(StatusValue.WARNING, " | ".join(messages))
        return Status(StatusValue.OK)

    def on_shutdown(self):
        for runner in getattr(self, "_runners", []):
            runner.close()


def main():
    SangforHciExtension(name="sangfor_hci").run()


if __name__ == "__main__":
    main()
