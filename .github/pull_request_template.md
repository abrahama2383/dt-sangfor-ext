## What this changes

<!-- One or two sentences. Link the issue if there is one: "Closes #123". -->

## Why

<!-- The problem it solves. For a metric change, what was wrong about the old values. -->

## How I verified it

<!--
What you ran and what you saw: the test suite on Python 3.10 and 3.14, the smoke run, and, if you had one,
a run against a real HCI (versions only; never paste credentials, addresses or unredacted output).
-->

## Checklist

- [ ] `pytest -W error` passes on Python 3.10 and 3.14
- [ ] `scripts/smoke_run.py` prints SMOKE PASSED
- [ ] New behaviour has a test, written before the fix, and tests do not touch a real HCI, Dynatrace or the network
- [ ] Still read-only toward Sangfor: new API paths are GET and in the allowlist
- [ ] No change can send more than one failed login per back-off window (login changes count ticket POSTs in a test)
- [ ] No secret in logs, exception messages, reprs, the extension status, events or dimensions
- [ ] No synthetic zeros: missing or unparseable values are skipped
- [ ] No new runtime dependencies; code runs on Python 3.10
- [ ] New metrics are declared in `extension/extension.yaml`; README and spec updated if behaviour or options changed
