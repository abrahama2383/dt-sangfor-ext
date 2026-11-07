# Contributing to dt-sangfor-ext

Thanks for helping. This extension runs against customers' production Sangfor HCI clusters, so a few rules matter
more than usual; they are listed below. Everything else is ordinary Python.

## Before you start

- For a bug, open an issue with the bug template. Do not paste credentials, IP addresses, hostnames or unredacted
  validation-kit output.
- For a security problem, do not open an issue: see [SECURITY.md](SECURITY.md).
- For a larger change (a new feature set, a new Sangfor version, a different collection path), open a feature request
  first, so we can agree on the approach before you write code.

## Getting set up

```bash
uv venv -p python3.14 .venv
uv pip install -p .venv/bin/python -r requirements-dev.txt
.venv/bin/pytest                                   # unit + integration tests against the simulator
.venv/bin/python scripts/smoke_run.py              # real `dt-sdk run` against the simulator; prints SMOKE PASSED
```

The tests start a mock Sangfor REST API on 127.0.0.1 and snmpsim agents on UDP 11161–11163. They need no network
access and no real HCI. To check the oldest supported runtime, create a second venv with `uv venv -p 3.10` and run the
suite there too; CI does both.

## How the project is laid out

| Path | What it is |
|---|---|
| `sangfor_hci/model.py` | Shared types and helpers. No I/O and no SDK imports. |
| `sangfor_hci/api/client.py` | The read-only REST client: GET allowlist, RSA login, retries, login back-off. |
| `sangfor_hci/snmp/` | OIDs and the SNMP client (GET and WALK only). |
| `sangfor_hci/collectors/` | One module per feature set. Pure functions from response data to metrics or events. |
| `sangfor_hci/runner.py` | One polling cycle per cluster. Calls clients and collectors; never imports the SDK. |
| `sangfor_hci/emit.py` | The only module that hands data to the Dynatrace SDK. |
| `sangfor_hci/__main__.py` | The extension entry point. |
| `extension/` | `extension.yaml`, the activation schema and the dashboard. |
| `simulator/` | Mock REST API with scenarios, and recorded SNMP data. |
| `validation-kit/` | The read-only, redacting probe for real clusters. |
| `docs/superpowers/` | Design spec and implementation plan. |

## The rules that matter most

1. **Read-only toward Sangfor.** The only non-GET request is the login POST. New paths go into the allowlist in
   `api/client.py` and must be GET.
2. **Never risk a lockout.** The ticket POST is never resent, and any failed login that may have reached the HCI
   starts the back-off. A change near login needs a test that counts ticket POSTs.
3. **No secret anywhere.** A password, community or SNMP key never appears in a log, an exception message, a repr,
   the extension status, an event or a dimension. Record third-party errors by class name only.
4. **No synthetic zeros.** A missing or unparseable value is skipped, never reported as 0.
5. **One bad target never ends the cycle.** Contain failures per endpoint and per node, and record them as
   `ext.poll.errors` with a reason.
6. **Python 3.10 and 3.14.** Use `from __future__ import annotations` and nothing newer than 3.10 (no `StrEnum`,
   `tomllib`, `except*` or `typing.Self`).
7. **No new runtime dependencies** beyond `dt-extensions-sdk`, `requests`, `pysnmp` and `cryptography`. Every one ends
   up in the signed package on every ActiveGate.

## Code style

- Small, pure functions in collectors; I/O stays in the clients and the runner.
- Names and comments explain why, not what. Keep docstrings short.
- New metrics are declared in `extension/extension.yaml` with a unit and a display name;
  `tests/integration/test_extension_definition.py` fails otherwise.

## Tests

- Write the test first and watch it fail for the right reason, then make it pass.
- Unit tests go in `tests/unit/`, tests that use the simulator in `tests/integration/`.
- The suite runs with `-W error` in CI, so new warnings fail the build.
- Tests never touch a real HCI, a real Dynatrace environment, `~/.dynatrace/certificates` or the network.

## Pull requests

- One topic per pull request, with a description of what changed, why, and how you verified it. The template asks
  for exactly that.
- CI must pass on Python 3.10 and 3.14, and the smoke run must print SMOKE PASSED.
- If behaviour or configuration changes, update the README and the spec in `docs/superpowers/specs/`.

## Releases

1. Raise `version` in `extension/extension.yaml`. Dynatrace rejects a version it already has.
2. Build and sign: `dt-sdk build --only-extra-platforms -e manylinux2014_x86_64 -e win_amd64 -p 3.10 -p 3.14`.
3. Check: `python scripts/check_package.py dist/*.zip` must print PACKAGE OK.
4. Upload with `dt-sdk upload --active` and note the version in the release notes.
