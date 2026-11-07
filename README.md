<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/banner-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/assets/banner-light.svg">
  <img alt="Sangfor HCI monitoring for Dynatrace Managed: cluster, host, VM, datastore and hardware health over the read-only REST API and SNMP" src="docs/assets/banner-dark.svg" width="100%">
</picture>

<br>

<img alt="Dynatrace Managed" src="https://img.shields.io/badge/Dynatrace-Managed-0f1b2a?style=flat-square&logo=dynatrace&logoColor=white">
<img alt="Extensions 2.0" src="https://img.shields.io/badge/Extensions-2.0%20%C2%B7%20Python-1f7f95?style=flat-square">
<img alt="Python 3.10 and 3.14" src="https://img.shields.io/badge/Python-3.10%20%C2%B7%203.14-2a78d6?style=flat-square&logo=python&logoColor=white">
<img alt="Read-only toward Sangfor" src="https://img.shields.io/badge/Sangfor-read--only-1baf7a?style=flat-square">
<img alt="SNMP v2c and v3" src="https://img.shields.io/badge/SNMP-v2c%20%C2%B7%20v3-eb6834?style=flat-square">
<img alt="46 metrics, 4 entity types" src="https://img.shields.io/badge/metrics-46%20%C2%B7%204%20entity%20types-6250d6?style=flat-square">
<img alt="Lockout-safe login" src="https://img.shields.io/badge/login-lockout--safe-e87ba4?style=flat-square">
<a href=".github/workflows/ci.yml"><img alt="CI" src="https://github.com/rifqifitriady/dt-sangfor-ext/actions/workflows/ci.yml/badge.svg"></a>
<a href="LICENSE"><img alt="MIT License" src="https://img.shields.io/badge/license-MIT-1f7f95?style=flat-square"></a>

**Sangfor HCI in Dynatrace Managed, the way you watch everything else:**<br>
cluster, host, VM, datastore and hardware health as metrics, Sangfor alarms as events on the right entity,<br>
and a topology from VM to host to cluster, collected read-only over the REST API and SNMP.

[Why](#why-this-extension) · [Features](#features) · [Quick start](#quick-start) · [Install](#install-on-dynatrace-managed) · [Configure](#configuration) · [Metrics](#what-it-collects) · [Cost](#ingest-volume-ddu) · [How it works](#how-it-works) · [Develop](#develop) · [Validate](#validate-against-a-real-hci) · [Contributing](#contributing)

</div>

<br>

## Why this extension

Sangfor HCI has its own console, but the rest of the estate lives in Dynatrace. This extension brings the HCI into the
same place, so one problem view, one dashboard and one alerting setup cover the hypervisor layer too.

| | Question | What you get |
|---|---|---|
| **◉** | *Is the cluster healthy?* | Cluster CPU, memory and storage usage, used and total capacity, and VMs and hosts by state, every minute. |
| **▣** | *Which host is in trouble?* | Per-host CPU, memory, IO, uptime, running VMs, online state and active alarms; hardware health from SNMP: CPU temperature, fans, RAID, SSD life, filesystems and optical power. |
| **◇** | *Which VM is hungry?* | Per-VM CPU, memory, disk and network, linked to the host it runs on, so a VM problem and a host problem show up as one story. |
| **▤** | *Is storage about to run out?* | Per-datastore capacity, usage, IOPS and throughput, plus flags for offline, partly unreachable and over 90 %. |
| **!** | *Did Sangfor raise an alarm?* | New Sangfor alarms become Dynatrace events on the cluster, host or VM they are about: urgent ones as error events, the rest as info. |
| **⇄** | *What if the API is down?* | In `both` mode SNMP keeps host CPU and memory flowing in the same cycle, and an unreachable API is skipped fast instead of stalling the cycle. |
| **⚿** | *Can it lock out the service account?* | No. The login is sent once and never resent, and any failed login pauses logins for 5 to 60 minutes, so a typo costs at most one failed login per window. |
| **$** | *What does it cost?* | A [formula](#ingest-volume-ddu) for DDU per day from hosts, VMs and datastores, and two knobs to lower it: the VM interval and the `vm` feature set. |

## Features

<table>
<tr>
<td width="33%" valign="top">

**Cluster**<br>
<sub>CPU, memory and storage usage, storage used and total, VMs by state (on, off) and hosts by state (online, offline) from the cluster overview.</sub>

</td>
<td width="33%" valign="top">

**Hosts**<br>
<sub>CPU, memory and IO usage, uptime, running VMs, online state and an active-alarm flag, from the host list and each node's info. SNMP fills in CPU and memory when the API is unavailable.</sub>

</td>
<td width="33%" valign="top">

**Virtual machines**<br>
<sub>CPU and memory usage, disk used, disk read and write, network in and out, and a running flag, with group, OS and HA as dimensions. Polled every 300 s by default, because VMs dominate the cost.</sub>

</td>
</tr>
<tr>
<td valign="top">

**Datastores**<br>
<sub>Capacity, available, usage, read and write IOPS and throughput, and three status flags decoded from Sangfor's bit mask: online, not reachable from some hosts, and over 90 %.</sub>

</td>
<td valign="top">

**Hardware (SNMP)**<br>
<sub>From the Sangfor private MIB on every node: CPU temperature, fan speed and health, RAID health, SSD remaining life, filesystem size and usage, node disk usage, and optical Rx/Tx power. Known words (ok, normal, failed, degraded, …) are mapped directly; an unknown word counts as not OK when it differs from the first value seen.</sub>

</td>
<td valign="top">

**Alarms as events**<br>
<sub>Sangfor alarms read from the alert log become Dynatrace events on the right cluster, host or VM. Each alarm is sent once: a cursor remembers what was already reported.</sub>

</td>
</tr>
<tr>
<td valign="top">

**Topology, screens & dashboard**<br>
<sub>Four entity types with relationships (VM runs on host, host and datastore belong to cluster), a screen for each entity type, and a classic "Sangfor HCI overview" dashboard.</sub>

</td>
<td valign="top">

**Safe toward Sangfor**<br>
<sub>An allowlist of read-only GET paths, plus the one login POST with an RSA-encrypted password. SNMP uses GET and WALK only. Secrets stay in the Dynatrace credential store and never reach logs, events or dimensions.</sub>

</td>
<td valign="top">

**Self-monitoring**<br>
<sub><code>ext.poll.duration</code> per endpoint and node, and <code>ext.poll.errors</code> with a reason (<code>auth</code>, <code>unreachable</code>, <code>timeout</code>, <code>snmp</code>, …), so you can see in Dynatrace why data is missing.</sub>

</td>
</tr>
</table>

## Quick start

```bash
# 1. Build and sign the package (once per version)
uv venv -p python3.14 .venv && uv pip install -p .venv/bin/python -r requirements-dev.txt
.venv/bin/dt-sdk gencerts                       # first time only; keep ~/.dynatrace/certificates safe
.venv/bin/dt-sdk build --only-extra-platforms -e manylinux2014_x86_64 -e win_amd64 -p 3.10 -p 3.14
.venv/bin/python scripts/check_package.py dist/*.zip

# 2. Trust the CA and upload (see Install below for the CA steps)
export DT_API_URL=https://<managed-domain>/e/<environment-id>
read -rs DT_API_TOKEN && export DT_API_TOKEN
.venv/bin/dt-sdk upload --active dist/custom_sangfor-hci-*.zip && unset DT_API_TOKEN
```

Then add a monitoring configuration per Sangfor cluster in **Extensions → custom:sangfor-hci**.

## Requirements

- Dynatrace Managed with an **Environment ActiveGate** (not a Cluster ActiveGate) in an ActiveGate group.
  - ActiveGate 1.333 or newer runs the Python 3.14 runtime. Older ActiveGates use the bundled 3.10 build.
  - Python 3.10 support ended on 2026-10-26.
- Network from the ActiveGate: TCP 443 to the HCI cluster VIP, and UDP 161 to every HCI node.
- Sangfor side:
  - A read-only API account that can read: the cluster overview, the host list and node info, the storage list, VMs, and alerts/logs. The extension only sends GET requests, plus the one login POST.
  - SNMP enabled under System Management > Port Management > SNMP. v3 is recommended; for v2c the community is reported to be `sangfopub`.

## Install on Dynatrace Managed

1. **Trust the signing CA.** This is the `ca.pem` of the CA that signed the package (see [Signing](#signing)).
   - Add `ca.pem` to the Credential Vault of every environment that will run the extension: type *Public certificate*, scope *Extension validation*.
   - Copy the same file to every ActiveGate in the group, and make it readable by `dtuserag`:
     - Linux: `/var/lib/dynatrace/remotepluginmodule/agent/conf/certificates/`
     - Windows: `%PROGRAMDATA%\dynatrace\remotepluginmodule\agent\conf\certificates`
2. **Upload the package.** The API token needs `extensions.read` and `extensions.write`:

   ```bash
   export DT_API_URL=https://<managed-domain>/e/<environment-id>
   read -rs DT_API_TOKEN && export DT_API_TOKEN   # paste the token; it is not echoed or kept in shell history
   export REQUESTS_CA_BUNDLE=<managed-ca.pem>     # only if the Managed endpoint uses a private CA
   .venv/bin/dt-sdk upload --active dist/<package>.zip
   unset DT_API_TOKEN
   ```

   `--active` makes the uploaded version the active one. Without it, a later upload stays inactive until you activate it in the UI.

3. **Add a monitoring configuration** for each Sangfor cluster (Extensions → custom:sangfor-hci): choose the ActiveGate group and the feature sets, then fill in the fields below.

## Configuration

| Field | Notes |
|---|---|
| Cluster name | Unique, and used as the entity identity. Do not rename it later. |
| Collection mode | `both` (default), `api` or `snmp`; see [How it works](#how-it-works). |
| Polling interval / VM polling interval | 60 s and 300 s by default. VM metrics dominate the cost; see [Ingest volume](#ingest-volume-ddu). |
| Request timeout | 10 s by default (1–120), per API request and per SNMP request. See [API failures](#api-failures-and-login-back-off) for the worst case per cycle. |
| API URL, user, password | For example `https://10.0.0.10`. A read-only account is recommended. |
| Verify TLS / Custom CA | HCI usually has a self-signed certificate: paste its CA rather than switching verification off. |
| SNMP version, community or v3 user and keys, context | v3 with SHA and AES128 by default. The context is usually empty. |
| SNMP port | 161 by default; used for every node that does not give its own `:PORT`. |
| SNMP nodes | `IP` or `IP=ADDRESS:PORT` per node. Empty in `both` mode means: use the host IPs from the API. |

A configuration with some invalid endpoints still runs the valid ones and reports a WARNING status that names the invalid ones.

### TLS on ActiveGate 1.333+ (Python 3.14)

On Python 3.14, urllib3 turns on strict X.509 verification. A pasted HCI CA can still be rejected when:

- the leaf certificate has no Subject Alternative Name for the VIP address or IP you put in the API URL;
- the chain lacks an Authority Key Identifier;
- a self-signed leaf certificate is used as its own CA.

Before you configure the extension, run the validation probe with `--ca-file <the CA you will paste>` under the
same Python version as the ActiveGate (see [validation-kit/README.md](validation-kit/README.md)). If it fails with
reason `tls`, fix or reissue the HCI certificate. Turn verification off only as a last resort.

### API failures and login back-off

- **Wrong password.** The login is sent once and never resent. A rejected login (HTTP 200 with `success` ≠ 1, any
  4xx, or no ticket) stops all logins for 5 minutes, then 10, 20, 40 and 60 minutes, and stays at 60 minutes until a
  login succeeds. Until then each cycle reports `reason=auth` with the text "login suppressed after a failed login;
  next attempt in N s" in the extension status, and no request is sent. So a typo in the password costs at most one
  failed login per back-off window; fix the password and the next attempt after the window recovers.
- **Unreachable API** (connection refused or connect timeout). Not retried: the API path is aborted for that cycle
  (`reason=unreachable`) and, in `both` mode, SNMP still delivers host CPU and memory within the same cycle.
- **Read timeouts and HTTP 5xx** on a data request are retried twice (1 s, then 3 s). The worst case per request is
  3 × the request timeout + 4 s; after that only that endpoint is skipped. A login that fails this way is not
  resent and starts the same back-off as a wrong password: the password reached the HCI, which may have counted
  it as a failed login. The same holds for a connection that drops, or a TLS error, after the login was sent. Only
  a connect timeout (no password sent) is tried again in the next cycle. The trade-off: if the HCI keeps failing
  logins with 5xx during maintenance, the API path can stay paused for up to 60 minutes after it recovers (SNMP
  keeps delivering host CPU and memory meanwhile); restarting the monitoring configuration clears the back-off.
- **Other network errors** (`reason=network`) and unexpected errors (`reason=unexpected`) are reported by class
  name only; SNMP still runs.

## What it collects

All keys start with `sangfor.hci.`. Each feature set can be switched on or off per monitoring configuration.

<details>
<summary><b>cluster</b> · 7 metrics · source: REST API</summary>

| Key | Meaning | Unit |
|---|---|---|
| `cluster.cpu.usage` | Cluster CPU usage | % |
| `cluster.memory.usage` | Cluster memory usage | % |
| `cluster.storage.usage` | Cluster storage usage | % |
| `cluster.storage.used` / `cluster.storage.total` | Storage used and total | bytes |
| `cluster.vms` | VMs by `state` (on, off) | count |
| `cluster.hosts` | Hosts by `state` (online, offline) | count |

</details>

<details>
<summary><b>host</b> · 7 metrics · source: REST API (CPU and memory from SNMP when the API fails)</summary>

| Key | Meaning | Unit |
|---|---|---|
| `host.cpu.usage` / `host.memory.usage` / `host.io.usage` | CPU, memory and IO usage | % |
| `host.online` | 1 = online | flag |
| `host.alarm` | 1 = the host has an active alarm | flag |
| `host.uptime` | Uptime | s |
| `host.vms.running` | Running VMs on the host | count |

</details>

<details>
<summary><b>vm</b> · 8 metrics · source: REST API, every 300 s by default</summary>

| Key | Meaning | Unit |
|---|---|---|
| `vm.cpu.usage` / `vm.memory.usage` | CPU and memory usage | % |
| `vm.disk.used` | Disk used | bytes |
| `vm.disk.read` / `vm.disk.write` | Disk read and write, as Sangfor reports them | see spec Q1 |
| `vm.net.in` / `vm.net.out` | Network in and out, as Sangfor reports them | see spec Q1 |
| `vm.running` | 1 = running | flag |

</details>

<details>
<summary><b>datastore</b> · 10 metrics · source: REST API</summary>

| Key | Meaning | Unit |
|---|---|---|
| `datastore.total` / `datastore.available` | Capacity and available space | bytes |
| `datastore.usage` | Usage | % |
| `datastore.read.iops` / `datastore.write.iops` | Read and write IOPS | /s |
| `datastore.read.throughput` / `datastore.write.throughput` | Read and write throughput | bytes/s |
| `datastore.online` | 1 = online | flag |
| `datastore.partial_access` | 1 = not reachable from some hosts | flag |
| `datastore.capacity_alert` | 1 = over 90 % | flag |

</details>

<details>
<summary><b>hardware</b> · 12 metrics · source: SNMP, Sangfor private MIB 1.3.6.1.4.1.35047.3.2.1</summary>

| Key | Meaning | Unit |
|---|---|---|
| `hw.disk.usage` | Node disk usage | % |
| `hw.cpu.temperature` | CPU temperature | °C |
| `hw.fan.speed` / `hw.fan.ok` | Fan speed and health (1 = OK) | rpm / flag |
| `hw.raid.ok` | RAID health (1 = OK) | flag |
| `hw.ssd.life` | SSD remaining life | % |
| `hw.fs.size` / `hw.fs.used` / `hw.fs.available` / `hw.fs.usage` | Filesystem size, used, available and usage | bytes / % |
| `hw.optical.rx.power` / `hw.optical.tx.power` | Optical Rx and Tx power | dBm |

</details>

<details>
<summary><b>self-monitoring</b> · 2 metrics · always on</summary>

| Key | Meaning | Unit |
|---|---|---|
| `ext.poll.duration` | Time per API endpoint and per SNMP node, with `source` and `target` | ms |
| `ext.poll.errors` | Errors in this cycle, with `source`, `target` and `reason` (`auth`, `tls`, `forbidden`, `unreachable`, `timeout`, `http`, `parse`, `network`, `snmp`, `unexpected`) | count |

</details>

Entities: `sangfor_hci:cluster`, `sangfor_hci:host`, `sangfor_hci:vm` and `sangfor_hci:datastore`, with
VM RUNS_ON host, and host and datastore CHILD_OF cluster. Alarms become events with a 15-minute timeout.

## Ingest volume (DDU)

Each data point costs 0.001 DDU. Per day, with the default 60 s polling interval:

```
DDU/day ≈ 1.44 × (14 + 57 × hosts + 10 × datastores) × (60 / interval_seconds)   # cluster, host, hardware, datastore, self-monitoring
        + 0.288 × 8 × VMs × (300 / vm_interval_seconds)                           # 8 VM metrics
```

1.44 is one metric every 60 s for a day (1,440 points), and 0.288 is one metric every 300 s (288 points). The 14 and
the 2 extra per host are the extension's own `ext.poll.*` self-monitoring points.

| Cluster | DDU per day |
|---|---|
| 4 hosts, 100 VMs, 5 datastores | about 0.65k |
| 8 hosts, 500 VMs, 10 datastores | about 2.0k |

The 57 points per host (55 metric series plus 2 self-monitoring) are an estimate that depends on the hardware. To lower
the cost, turn off the `vm` feature set or raise the VM interval.

## How it works

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/architecture-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/assets/architecture-light.svg">
  <img alt="The Sangfor REST API and SNMP agents are polled from an Environment ActiveGate, mapped to metrics, entities and events, and sent to Dynatrace Managed" src="docs/assets/architecture-dark.svg" width="100%">
</picture>

| Mode | Collects |
|---|---|
| `api` | Cluster, host, VM and datastore metrics, and Sangfor alarms as Dynatrace events (REST API) |
| `snmp` | Host CPU and memory plus hardware health per node: CPU temperature, fans, RAID, SSD life, filesystems, optical power (Sangfor private MIB 1.3.6.1.4.1.35047.3.2.1) |
| `both` (default) | Everything above. The API is authoritative for overlapping metrics, and SNMP takes over host CPU and memory if the API fails |

One cycle runs per cluster: the API path first (overview, host list, node info in parallel, storage, VMs every
fifth cycle, alerts), then SNMP on every node in parallel. A cycle never overlaps the previous one, one bad SNMP
node never stops the others, and every failure is recorded as `ext.poll.errors` instead of ending the cycle.

The design, its decisions and its open questions are in [docs/superpowers/specs/](docs/superpowers/specs/).

## Develop

```bash
uv venv -p /opt/homebrew/bin/python3.14 .venv
uv pip install -p .venv/bin/python -r requirements-dev.txt
.venv/bin/pytest                                   # unit + integration against the simulator
.venv/bin/python scripts/smoke_run.py              # real `dt-sdk run` against the simulator
```

Simulator, for manual runs:

| Command | Starts |
|---|---|
| `.venv/bin/python -m simulator.mock_api` | Mock REST API at https://127.0.0.1:8443. User `dtmon`, password `dtmon-pass`. Scenarios: `healthy`, `host_offline`, `datastore_90`, `ticket_expired` |
| `.venv/bin/python -m simulator.snmp_sim` | SNMP agents node-a (UDP 11161), node-b (11162) and bare (11163, no private MIB) |
| `.venv/bin/dt-sdk run` | The extension, using `activation.json` |

<details>
<summary><b>Project layout</b></summary>

| Path | What it is |
|---|---|
| `sangfor_hci/` | The extension: `api/` (read-only REST client with RSA login and back-off), `snmp/` (OIDs and client), `collectors/` (one module per feature set), `runner.py` (one polling cycle), `emit.py` (the only module that calls the SDK), `__main__.py` (entry point) |
| `extension/` | `extension.yaml` (metrics, topology, screens), `activationSchema.json` (the configuration form) and the dashboard |
| `simulator/` | Mock Sangfor REST API with scenarios, and snmpsim agents with recorded node data |
| `scripts/` | `smoke_run.py` (real `dt-sdk run` against the simulator) and `check_package.py` (package verification) |
| `validation-kit/` | Read-only probe for a real HCI with a redacted output zip |
| `tests/` | Unit and integration tests; CI runs them on Python 3.10 and 3.14 |
| `docs/` | Design spec, implementation plan and the README images |

</details>

## Signing

Dynatrace only runs a package signed by a developer certificate whose CA every environment trusts. Choose one path:

- **Create a CA with `dt-sdk gencerts`.**

  ```bash
  .venv/bin/dt-sdk gencerts      # writes ca.pem, ca.key and developer.pem to ~/.dynatrace/certificates
  ```

  Upload the resulting `ca.pem` to every Dynatrace Managed environment that will run the extension, and copy it to the ActiveGates, as in [Install](#install-on-dynatrace-managed) step 1.
  Keep `ca.key` outside this repository (the default location is outside it) and back it up: whoever holds it can sign extensions your environments will trust, and losing it means re-trusting a new CA everywhere.

- **Use an existing company CA.** Have it issue a developer certificate for extension signing, combine the certificate and its private key into one fused PEM file, and pass it to the build with `--private-key <path>` (add `--passphrase` if the key is encrypted). Upload the company CA's certificate to every environment as in step 1.

Certificates and keys never go into this repository; `.gitignore` excludes `*.pem` and `*.key`.

## Build

```bash
.venv/bin/dt-sdk build --only-extra-platforms -e manylinux2014_x86_64 -e win_amd64 -p 3.10 -p 3.14 \
    --private-key ~/.dynatrace/certificates/developer.pem   # the default; pass another path for a company CA
.venv/bin/python scripts/check_package.py dist/*.zip
```

`check_package.py` confirms the package is signed, under 25 MB, carries the pinned dependency versions, and has the native cryptography and cffi wheels for Linux (manylinux2014) and Windows on Python 3.10 and 3.14.
It does not verify the signature against your CA; Dynatrace does that on upload.

Raise `version` in `extension/extension.yaml` before every upload; Dynatrace rejects a version it already has.

## Validate against a real HCI

See [validation-kit/README.md](validation-kit/README.md). The probe is read-only and produces a redacted zip.
It answers the open questions in the spec: units of VM disk and network values, datastore status flags,
SNMP value formats and status words, and the SNMP versions each node answers.

## Contributing

Contributions are welcome: bug reports, fixes, new metrics, support for more Sangfor versions, and docs.

| | |
|---|---|
| [Contributing guide](CONTRIBUTING.md) | Setup, project layout, the rules that matter (read-only toward Sangfor, lockout safety, no secrets anywhere, no synthetic zeros), tests and pull requests |
| [Code of Conduct](CODE_OF_CONDUCT.md) | How we work together (Contributor Covenant 2.1) |
| [Security Policy](SECURITY.md) | How to report a vulnerability privately, what is in scope, and how to run the extension safely |
| [MIT License](LICENSE) | Use, change and share the extension freely; keep the copyright notice |

Found a security problem? Do not open an issue. [Report it privately](https://github.com/rifqifitriady/dt-sangfor-ext/security/advisories/new).

## License

Released under the [MIT License](LICENSE). Copyright © 2026 Rifqi Fitriady.

Sangfor and Sangfor HCI are trademarks of Sangfor Technologies. Dynatrace is a trademark of Dynatrace LLC. This is an
independent extension, not affiliated with or endorsed by either company.

<br>

<div align="center">
<sub>Built with the Dynatrace Extensions SDK, requests, pysnmp and cryptography. Read-only toward Sangfor, by design.</sub>
</div>
