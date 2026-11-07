# dt-sangfor-ext

`custom:sangfor-hci` is a Dynatrace Managed extension (Extensions 2.0, Python) that monitors Sangfor HCI clusters.
It collects data over two paths, chosen per cluster:

| Mode | Collects |
|---|---|
| `api` | Cluster, host, VM and datastore metrics, and Sangfor alarms as Dynatrace events (REST API) |
| `snmp` | Host CPU and memory plus hardware health per node: CPU temperature, fans, RAID, SSD life, filesystems, optical power (Sangfor private MIB 1.3.6.1.4.1.35047.3.2.1) |
| `both` (default) | Everything above. The API is authoritative for overlapping metrics, and SNMP takes over host CPU and memory if the API fails |

Entities: `sangfor_hci:cluster` → `sangfor_hci:host` → `sangfor_hci:vm`, and `sangfor_hci:datastore` → cluster.
The extension also ships screens for each entity and a classic dashboard, "Sangfor HCI overview".
The design and its open questions are in [docs/superpowers/specs/](docs/superpowers/specs/).

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

| Field | Notes |
|---|---|
| Cluster name | Unique, and used as the entity identity. Do not rename it later. |
| Collection mode | `both`, `api` or `snmp` |
| Polling interval / VM polling interval | 60 s and 300 s by default. VM metrics dominate the cost; see below. |
| Request timeout | 10 s by default (1–120), per API request and per SNMP request. See [API failures](#api-failures-and-login-back-off) for the worst case per cycle. |
| API URL, user, password | For example `https://10.0.0.10`. A read-only account is recommended. |
| Verify TLS / Custom CA | HCI usually has a self-signed certificate: paste its CA rather than switching verification off. |
| SNMP version, community or v3 user and keys, context | v3 with SHA and AES128 by default. The context is usually empty. |
| SNMP port | 161 by default; used for every node that does not give its own `:PORT`. |
| SNMP nodes | `IP` or `IP=ADDRESS:PORT` per node. Empty in `both` mode means: use the host IPs from the API. |

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

## Ingest volume (DDU)

Each data point costs 0.001 DDU. Per day, with the default 60 s polling interval:

```
DDU/day ≈ 1.44 × (14 + 57 × hosts + 10 × datastores) × (60 / interval_seconds)   # cluster, host, hardware, datastore, self-monitoring
        + 0.288 × 8 × VMs × (300 / vm_interval_seconds)                           # 8 VM metrics
```

1.44 is one metric every 60 s for a day (1,440 points), and 0.288 is one metric every 300 s (288 points). The 14 and the 2 extra per host are the extension's own `ext.poll.*` self-monitoring points.

Examples: 4 hosts, 100 VMs and 5 datastores come to about 0.65k DDU/day. 8 hosts, 500 VMs and 10 datastores come to about 2.0k DDU/day.
The 55 series per host is an estimate that depends on the hardware. To lower the cost, turn off the `vm` feature set or raise the VM interval.

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
