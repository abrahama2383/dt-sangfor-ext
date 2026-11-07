# Sangfor HCI extension for Dynatrace Managed: design

- Date: 2026-11-07
- Status: approved design, awaiting spec review
- Repo: `rifqifitriady/dt-sangfor-ext`

## 1. Goal

Monitor Sangfor HCI (aCloud) clusters from Dynatrace Managed with one custom Extensions 2.0 extension. The extension collects data over two paths:

- **REST API**: cluster, host, VM and datastore metrics, plus Sangfor alarms.
- **SNMP**: per-node hardware health that the API does not expose.

Each monitoring configuration selects which paths it uses (`api`, `snmp` or `both`).

### In scope for v1

1. Cluster, host, VM and datastore metrics through the REST API.
2. Hardware health through SNMP: CPU temperature, fans, RAID, SSD life, filesystems, optical power and BMC info.
3. Sangfor alarms sent to Dynatrace as events, attached to the affected entity.
4. Generic topology (cluster → host → VM, cluster → datastore), Unified Analysis screens and one classic dashboard.
5. A local simulator (mock REST API plus SNMP agent) and a read-only field validation kit.

### Out of scope for v1

- Receiving SNMP traps. Alarms come from the API in v1. Dynatrace's built-in SNMP Traps extension can be added later.
- Any write or control action on Sangfor (start, stop, snapshot). The extension is read-only.
- Sangfor SCP (multi-cluster cloud platform), aSAN-specific internals, and network objects (vRouters, distributed firewall).
- VM-to-datastore relationships.
- Dynatrace SaaS-only features: Grail, DQL, Notebooks, Gen3 dashboards and AppEngine apps.

## 2. Constraints and facts this design rests on

| # | Fact | Source |
|---|---|---|
| F1 | An Extensions 2.0 extension can use only one data source type. Python is the only type that can call both REST and SNMP. | Dynatrace Python SDK, extension structure guide: different datasources "can't be used within the same extension" |
| F2 | Python extensions run remotely on an **Environment ActiveGate** that belongs to an ActiveGate group. Cluster and multi-environment ActiveGates are not supported. | Dynatrace docs: Extensions concepts (Managed) |
| F3 | Python 3.10 support ended 2026-10-26. ActiveGate 1.333+ ships Python 3.14, and ActiveGate 1.349+ no longer ships 3.10. Build with `dt-extensions-sdk` ≥ 1.8.0 and `--python-version 3.14`. | Dynatrace docs: Python 3.10 end of support |
| F4 | Custom extensions must be signed. The root CA goes into the Credential Vault of **each** environment (type "Public certificate", scope "Extension validation"). It must also be copied to every ActiveGate in the group at `/var/lib/dynatrace/remotepluginmodule/agent/conf/certificates/` (Linux, readable by `dtuserag`) or `%PROGRAMDATA%\dynatrace\remotepluginmodule\agent\conf\certificates` (Windows). | Dynatrace docs: Sign extensions |
| F5 | Package size is limited to 25 MB. The version must increase on every upload. Default per-extension limits on ActiveGate are 5% CPU and 500 MB RAM. | Dynatrace docs: Extensions concepts |
| F6 | Sangfor REST API login: get the RSA modulus from `GET /vapi/json/public_key` (exponent 0x10001), encrypt the password with RSA PKCS#1 v1.5, then `POST /vapi/json/access/ticket` (form-encoded). The response gives `ticket` (sent as the `LoginAuthCookie` cookie) and `CSRFPreventionToken` (sent as a header). | Sangfor 超融合平台API接口说明 (2022-01-06), bundled in github.com/liudonghua123/hci_api |
| F7 | Sangfor private SNMP root is `1.3.6.1.4.1.35047.3.2.1` (aCloud). The OIDs used here come from the Zabbix community template `Virtualization/Sangfor/template_hci` (2025). | zabbix/community-templates |
| F8 | SNMP on HCI is enabled under System Management > Port Management > SNMP, where the MIB is also downloadable. The v2c community is reportedly fixed to `sangfopub`. v3 supports MD5/SHA auth and AES/DES privacy. | Sangfor support docs (HCI 6.10), Sangfor CN forum |
| F9 | SNMP support varies by release: one user reports the HCI 6.9.1 MIB has no private branch, and another reports v2c timing out with only v3 answering. | Sangfor community forums |
| F10 | SNMP values appear to be strings such as `"0.45"`. The Zabbix template applies regex `([0-9.]+)` and a ×100 multiplier. This is inferred from the template and not yet observed on a device. | zabbix/community-templates |
| F11 | pysnmp 7 needs `cryptography` (a native package) for SNMPv3 privacy (AES/DES). `cryptography` 50.0.2 ships `abi3` wheels for `manylinux2014_x86_64` and `win_amd64`: about 4.7 MB per Linux wheel and 3.9 MB per Windows wheel, for each of Python 3.10 and 3.14. | pysnmp 7.1.31 source, PyPI |
| F12 | `dt-sdk build` supports `--only-extra-platforms`, which skips wheels for the build machine (macOS arm64) and keeps the package under the 25 MB limit. | dt-extensions-sdk 1.11.3 CLI source |
| F13 | Verified on the Mac: pysnmp 7.1.31 on Python 3.14 reads string (`OctetString`) values from snmpsim 1.2.2 over v2c and over v3 (SHA/AES). snmpsim selects its data file by v3 context name, so the simulator needs `context_name = "sangfopub"`. | local spike, 2026-11-07 |

Versions of the target Sangfor HCI, the Managed cluster and the ActiveGates are **unknown**. The design targets HCI 6.x with runtime version detection, and ActiveGate builds for both Python 3.10 and 3.14.

## 3. Architecture

```
Dynatrace Managed cluster  https://<domain>/e/<env-id>
 ├─ Credential Vault: our root CA
 ├─ Extension custom:sangfor-hci  (metrics metadata, topology, feature sets, screens, dashboard)
 │    └─ monitoring configurations: one per Sangfor cluster, bound to an ActiveGate group
 └─ Metrics API v2 / Events API v2 ingest
          ▲
Environment ActiveGate (group: e.g. "sangfor")
 └─ EEC → python process: sangfor_hci
      ├─ HTTPS 443 → Sangfor cluster VIP     (REST API, once per cluster)
      └─ UDP 161   → each HCI node IP       (SNMP, per node)
```

- Extension name: `custom:sangfor-hci`. Python module: `sangfor_hci`.
- `minDynatraceVersion: "1.285"` for now, taken from the SDK example. It must be confirmed against a real Managed cluster (see §11).
- Build from the Mac (arm64) for Linux and Windows ActiveGates:
  `dt-sdk build --only-extra-platforms -e manylinux2014_x86_64 -e win_amd64 -p 3.10 -p 3.14`
- Runtime dependencies, pinned: `dt-extensions-sdk==1.11.3`, `requests==2.34.2`, `pysnmp==7.1.31`, `cryptography==50.0.2`. `cryptography` is used for both the Sangfor RSA login and SNMPv3 privacy. The build is checked for the presence of the Linux and Windows wheels and for the package size staying under 25 MB.
- Signing certificates are generated with `dt-sdk gencerts` and stored **outside the repo**. `.gitignore` already blocks `*.pem`, `*.key`, `*.crt` and `*.p12`.
- Upload: `dt-sdk upload` with `DT_API_URL=https://<domain>/e/<env-id>` and a token with `extensions.read` and `extensions.write`. Managed endpoints often use a custom or self-signed TLS certificate, so the upload step must accept a custom CA bundle.

## 4. Monitoring configuration (activation schema)

One configuration describes one Sangfor cluster.

| Field | Type | Default | Notes |
|---|---|---|---|
| `cluster_name` | string, required | — | Entity identity anchor. Must be unique per environment. |
| `mode` | enum `api` / `snmp` / `both` | `both` | |
| `interval_seconds` | int | 60 | Main polling cycle. |
| `vm_interval_seconds` | int | 300 | VM metrics are collected every Nth cycle to control ingest volume (§9). |
| `api.url` | string | — | e.g. `https://10.0.0.10`. Required for `api` and `both`. |
| `api.username` / `api.password` | string / secret | — | A read-only Sangfor account is recommended. |
| `api.verify_tls` | bool | true | Turning it off logs a warning on every start. |
| `api.ca_pem` | string (multiline) | empty | Custom CA for self-signed HCI certificates. |
| `snmp.nodes` | list of `IP` or `IP=ADDRESS:PORT` | empty | `IP` is the host's management IP and is used for identity. `ADDRESS:PORT` is where to poll when it differs (NAT, or the simulator). In `both` mode, empty means "use host IPs from the API `host_list`". |
| `snmp.port` | int | 161 | |
| `snmp.version` | enum `v2c` / `v3` | `v3` | |
| `snmp.community` | secret | `sangfopub` | v2c only. |
| `snmp.v3.*` | user, auth protocol (MD5/SHA/SHA256), auth key, priv protocol (NONE/DES/AES128/AES256), priv key, context name | context name empty | Keys are secret fields. The simulator uses context name `sangfopub` (F13). |
| `timeout_seconds` | int | 10 | Applies to both HTTP and SNMP. |

Secrets are stored as secret fields in the activation schema, so Dynatrace encrypts them. They are never logged.

## 5. Data model

### 5.1 Entities (generic topology defined in `extension.yaml`)

Entities are built from metric dimensions. Every metric carries `sangfor.cluster` plus the dimensions of its own entity.

| Type | ID pattern (from dimensions) | Display name | Relationship |
|---|---|---|---|
| `sangfor_hci:cluster` | `{sangfor.cluster}` | `{sangfor.cluster}` | — |
| `sangfor_hci:host` | `{sangfor.cluster}-{sangfor.host.ip}` | `{sangfor.cluster} / {sangfor.host.name}` | CHILD_OF cluster |
| `sangfor_hci:vm` | `{sangfor.cluster}-{sangfor.vm.id}` | `{sangfor.cluster} / {sangfor.vm.name} ({sangfor.vm.id})` | RUNS_ON host |
| `sangfor_hci:datastore` | `{sangfor.cluster}-{sangfor.datastore.id}` | `{sangfor.cluster} / {sangfor.datastore.name}` | CHILD_OF cluster |

Hosts are keyed by IP because it is the only identifier that both the API (`host_list[].ip`) and SNMP (the polled address) know. That makes `api`, `snmp` and `both` produce the same host entity. Display names include the cluster so that names are unique, which event attachment needs (§5.4).

### 5.2 Metrics

All keys are prefixed `sangfor.hci.`. Ratio values from Sangfor (0–1) are converted to percent. `count`-type metrics use the `.count` suffix.

**Feature set `cluster`** (API `GET /vapi/json/index/overview`)

| Key | Unit | Field |
|---|---|---|
| `cluster.cpu.usage` | % | `cpu.ratio` |
| `cluster.memory.usage` | % | `mem.ratio` |
| `cluster.storage.usage` | % | `stg.ratio` |
| `cluster.storage.used` / `cluster.storage.total` | bytes | `stg.used` / `stg.total` |
| `cluster.vms` (dim `state` = on/off) | count | `vm.on` / `vm.off` |
| `cluster.hosts` (dim `state` = online/offline) | count | `host.online` / `host.offline` |

**Feature set `host`** (API `GET /vapi/json/index/host_list` and `GET /vapi/json/nodes/{id}/info`; SNMP fallback in brackets)

| Key | Unit | Field |
|---|---|---|
| `host.cpu.usage` | % | `cpu_ratio` [SNMP `.2.1.1.0`] |
| `host.memory.usage` | % | `mem_ratio` [SNMP `.2.2.1.0`] |
| `host.io.usage` | % | `io_ratio` |
| `host.online` | 0/1 | `status` |
| `host.alarm` | 0/1 | `alert` ≠ "0" |
| `host.uptime` | s | `nodes/{id}/info.uptime` |
| `host.vms.running` | count | `nodes/{id}/info.running_vms` |

Dimensions: `sangfor.host.ip`, `sangfor.host.name`, `sangfor.host.master`, `sangfor.version` (`os_version`).

**Feature set `vm`** (API `GET /vapi/json/cluster/vms`, collected every `vm_interval_seconds`)

| Key | Unit | Field |
|---|---|---|
| `vm.cpu.usage` | % | `cpu_ratio` |
| `vm.memory.usage` | % | `mem_ratio` |
| `vm.disk.used` | bytes | `disk_used` |
| `vm.disk.read` / `vm.disk.write` | see §11 | `diskread` / `diskwrite` |
| `vm.net.in` / `vm.net.out` | see §11 | `netin` / `netout` |
| `vm.running` | 0/1 | `status == "running"` |

Dimensions: `sangfor.vm.id`, `sangfor.vm.name`, `sangfor.host.ip` (resolved from `host` id → ip via `host_list`), `sangfor.vm.group`, `sangfor.vm.os`, `sangfor.vm.ha`.

The VM set is kept small on purpose (§9). Packet counters, IO ops and `io_ratio` are left for later feature sets.

**Feature set `datastore`** (API `GET /vapi/json/vtpstorage/storelist`)

| Key | Unit | Field |
|---|---|---|
| `datastore.total` / `datastore.available` | bytes | `total` / `avail` |
| `datastore.usage` | % | `used / total` |
| `datastore.read.iops` / `datastore.write.iops` | IOPS | `read_cnt` / `write_cnt` |
| `datastore.read.throughput` / `datastore.write.throughput` | B/s | `read_ratio` / `write_ratio` |
| `datastore.online` | 0/1 | `status & 0x0001` |
| `datastore.partial_access` | 0/1 | `status & 0x0010` |
| `datastore.capacity_alert` | 0/1 | `status & 0x0100` (over 90%) |

Dimensions: `sangfor.datastore.id`, `sangfor.datastore.name`, `sangfor.datastore.type` (fc / iscsi / local / nfs), `sangfor.datastore.shared`.

The spec lists the `status` flag values in hex notation (0x0001, 0x0010, 0x0100, 0x1000). Whether these are hex bit masks or binary-digit notation (1, 2, 4, 8) is ambiguous, and the validation kit must settle it (§11). Numeric fields arrive as either JSON numbers or strings (for example `"read_cnt": "0.33"` next to `"read_cnt": 0`), so every field goes through one number parser.

Virtual storage (aSAN) is not returned by `storelist`. It is covered in v2.

**Feature set `hardware`** (SNMP, per node, root `R = 1.3.6.1.4.1.35047.3.2.1`)

| Key | Unit | OID | Index dimension |
|---|---|---|---|
| `hw.disk.usage` | % | `R.2.3.1.0` | — |
| `hw.cpu.temperature` | °C | `R.2.1.2.1.7.{i}` | `cpu` = `R.2.1.2.1.8.{i}` |
| `hw.fan.speed` | rpm | `R.2.16.1.3.{i}` | `fan` = `R.2.16.1.2.{i}` |
| `hw.fan.ok` | 0/1 | `R.2.16.1.4.{i}` | `fan` |
| `hw.raid.ok` | 0/1 | `R.2.14.1.5.{i}` | `raid` = `R.2.14.1.3.{i}` |
| `hw.ssd.life` | % | `R.2.18.1.9.{i}` | `ssd` = `R.2.18.1.4.{i}` |
| `hw.fs.size` / `hw.fs.used` / `hw.fs.available` | bytes (source GB) | `R.2.5.1.3/4/5.{i}` | `fs` = `R.2.5.1.2.{i}` |
| `hw.fs.usage` | % | `R.2.5.1.6.{i}` | `fs` |
| `hw.optical.rx.power` / `hw.optical.tx.power` | dBm | `R.2.12.1.5/4.{i}` | `port` = `R.2.12.1.3.{i}` |

The extension reads `sysName` (`1.3.6.1.2.1.1.5.0`) to name hosts in `snmp` mode. `sysDescr`, `aCloudVersion` (`R.1.0`) and BMC info (`R.2.7.1/2/3.0`) are read by the validation kit only. Showing them as entity properties is deferred to v2.

The OK/not-OK string values for fan and RAID status are unknown. Until the validation kit shows them, any value other than the first value seen at startup is treated as "not OK" (the same logic the Zabbix template uses) and logged for later mapping.

**Self-monitoring** (always on)

| Key | Unit | Dimensions |
|---|---|---|
| `ext.poll.duration` | ms | `source` (api/snmp), `target` (endpoint or node) |
| `ext.poll.errors` | errors in this cycle (gauge) | `source`, `target`, `reason` (auth / timeout / http / parse / snmp) |

### 5.3 Overlap rule in `both` mode

The API is authoritative for metrics both paths provide (host CPU and memory). SNMP only adds `hardware`. If the API path fails in a cycle, host CPU and memory for that cycle come from SNMP, so the host is not left blank.

### 5.4 Alarms as events

- Source: `GET /vapi/json/log/alert/all?distinct=0&limit=100&direct=DESC`. The response is nested: `data.data[]` holds the alarms and `data.total` the count. The format of the `starttime` filter is undocumented, so it is not used. Filtering happens client-side on `start` (epoch seconds) and `log_id`.
- Mapping: `urgent_type == "1"` (a string in the spec example) becomes `ERROR_EVENT` (opens a Davis problem); anything else becomes `CUSTOM_INFO`.
- Target entity: `object_type == host` attaches to `sangfor_hci:host`, `vm` attaches to `sangfor_hci:vm`, and everything else attaches to `sangfor_hci:cluster`. The host name is resolved through `hostid` → `host_list[].name`, because the alarm's own `hostname` field holds an IP. The selector matches the exact display name, for example `type("sangfor_hci:host"),entityName.equals("<cluster> / <host name>")`.
- Properties: `sangfor.log_id`, `sangfor.alert.type`, `sangfor.object.name`, `sangfor.host.name`, and the original message.
- Deduplication: an in-memory set of the last 5,000 `log_id`s plus a time cursor. After an extension restart, the cursor starts at "now minus 2 cycles", which can produce a small number of duplicates. This is accepted and documented.
- Event timeout: 15 minutes, one-shot. Re-sending active alarms to keep the event open is deferred until the validation kit shows what the alarm `status` field means.

## 6. Components

```
dt-sangfor-ext/
├─ extension/
│  ├─ extension.yaml          metrics metadata, topology, feature sets, screens, dashboard
│  └─ activationSchema.json   §4
├─ sangfor_hci/
│  ├─ __main__.py             Extension subclass: schedules one cycle per configuration, emits, sets status
│  ├─ runner.py               one cycle for one cluster: calls clients and collectors, returns metrics, events and problems (no SDK import)
│  ├─ config.py               activation config → frozen dataclasses, validation errors with clear messages
│  ├─ model.py                Metric and Event dataclasses, entity dimension builders
│  ├─ emit.py                 the only module that calls the SDK's report_metric / report_dt_event
│  ├─ api/auth.py             public key, RSA PKCS#1 v1.5 password encryption, ticket + CSRF, re-login
│  ├─ api/client.py           requests session, timeouts, retries, TLS/CA, GET-only allowlist (+ login POST)
│  ├─ snmp/client.py          get / bulk-walk for v2c and v3, subtree probe
│  ├─ snmp/oids.py            all OIDs, the single source of truth
│  └─ collectors/
│     ├─ cluster.py  host.py  vm.py  datastore.py  hardware.py  alarms.py
│     └─ each one is a pure function: raw response(s) → list[Metric] / list[Event]
├─ simulator/
│  ├─ mock_api.py             HTTPS server on localhost:8443 (self-signed), serves fixtures, implements login/ticket expiry
│  ├─ snmp/                   snmpsim .snmprec data for subtree R, served on localhost:1161
│  ├─ fixtures/               JSON from the official spec examples, later replaced by redacted field data
│  └─ scenarios/              healthy, host_offline, datastore_90, ticket_expired, no_private_subtree
├─ validation-kit/
│  └─ sangfor_probe.py        read-only probe → one redacted bundle
└─ tests/
   ├─ unit/                   collectors, auth, config, oids
   └─ integration/            full cycle against the simulator
```

Boundaries:

- Collectors never do I/O.
- Clients never build metrics.
- Only `emit.py` knows the Dynatrace SDK.

Because of these rules, every collector is testable from fixtures, and the SDK can change without affecting collection logic.

## 7. Data flow

Per configuration, every `interval_seconds`:

1. **API path** (`api` / `both`):
   1. Ensure a valid ticket: log in if missing, and log in once more on 401.
   2. Fetch `overview`, `host_list`, `storelist` and `alert/all`.
   3. Fetch `nodes/{id}/info` per host, at most 4 concurrent requests.
   4. On every Nth cycle, fetch `cluster/vms`.
2. **SNMP path** (`snmp` / `both`): for each node, run GETs for the scalars and bulk-walks for the tables in §5.2, at most 8 nodes concurrently.
3. Collectors turn the responses into metrics and events. `emit.py` sends them.
4. Self-monitoring metrics are emitted, and the extension status is set (OK, or a warning naming the failing part).

The SNMP subtree probe (`GETNEXT` on `R`) runs at startup and every hour per node. If the subtree is missing, the `hardware` set for that node is disabled with a single warning until the next probe.

## 8. Error handling

| Failure | Behaviour |
|---|---|
| Login fails (wrong credentials, RSA error) | API path skipped this cycle, `errors{reason=auth}`, extension status shows a warning with the HTTP status. Never retried in a tight loop. |
| 401 mid-cycle | One re-login, then retry the request once. |
| Timeout / 5xx | Up to 2 retries with backoff (1 s, 3 s), then skip that endpoint only. |
| One endpoint or one node fails | Others continue. Metrics for the failed part are simply absent for that cycle. |
| Unparseable value | That data point is skipped and logged at debug level. **No synthetic zeros, ever.** |
| SNMP subtree missing | `hardware` disabled for that node (§7). In `snmp` mode, host CPU and memory also come from the private subtree, so such a node only reports self-monitoring (poll duration and errors) and the extension status names the node. |
| Unknown Sangfor version | The version (`os_version`) is carried as the `sangfor.version` dimension and host attribute, so it is visible per host. Collection continues, and missing fields are handled by the unparseable-value rule. |
| Cycle overruns its interval | The next cycle is skipped rather than stacked, and logged. |

Security rules:

- Secrets are never logged.
- TLS verification is on by default.
- The API client refuses any non-GET call except the login POST.

## 9. Ingest volume and cost

Each data point sent to Dynatrace Managed is billed: 0.001 DDU per metric data point on DDU licensing, or the per-data-point custom metric rate on DPS. VMs dominate the volume.

Per VM, the v1 set is 8 metrics. At `vm_interval_seconds = 300` that is 8 × 288 = 2,304 data points/day, about **2.3 DDU/day per VM**. At a 60 s interval it would be about 11.5 DDU/day per VM.

Per host, about 55 series per minute is assumed: 7 `host` metrics plus about 48 `hardware` series (2 CPUs, 6 fans × 2, 1 RAID, 4 SSDs, 5 filesystems × 4, 4 optical ports × 2, disk usage). The cluster set has 9 series and each datastore has 10.

| Cluster size | Cluster + hosts + datastores (60 s) | VMs at 300 s | Total / day |
|---|---|---|---|
| 4 hosts, 100 VMs, 5 datastores | 9 + 4 × 55 + 5 × 10 = 279 dp/min ≈ 402 DDU | ≈ 230 DDU | ≈ 0.6k DDU |
| 8 hosts, 500 VMs, 10 datastores | 9 + 8 × 55 + 10 × 10 = 549 dp/min ≈ 791 DDU | ≈ 1,152 DDU | ≈ 1.9k DDU |

These are design-time estimates. Hardware series counts depend on how many CPUs, fans and filesystems each node actually reports. The `vm` feature set can be turned off per configuration, and `vm_interval_seconds` can be raised. The README will ship a calculator formula so that a customer sees the cost before enabling the extension.

## 10. Testing

1. **Unit (pytest)**:
   - Every collector is tested against fixtures from the official spec examples.
   - Auth is tested by encrypting with a test RSA key and decrypting in the test.
   - Config validation covers each required-field and mode combination.
   - The OID table is checked to stay consistent with the simulator data.
2. **Integration**: `dt-sdk run` (or a test harness around the Extension class) against the simulator, once per scenario:
   - `healthy`: all feature sets produce metrics, entity dimensions are complete, and there are no errors.
   - `host_offline`: `host.online = 0`; the API path still succeeds.
   - `datastore_90`: `datastore.capacity_alert = 1`.
   - `ticket_expired`: exactly one re-login, and the cycle succeeds.
   - `no_private_subtree`: `hardware` is disabled with one warning, and the API data is unaffected.
   - An urgent alarm fixture produces one `ERROR_EVENT` with the correct selector and no duplicate on the next cycle.
3. **Field validation kit** (`validation-kit/sangfor_probe.py`):
   - It is run by Rifqi or the customer on a real HCI. It only performs the login, GETs the endpoints in §5.2, and runs an SNMP walk of `R` plus `sysDescr`.
   - It replaces IPs, names, serials and MACs with stable placeholders and writes one zip bundle.
   - The bundle becomes new fixtures and settles the open questions in §11.
4. **End-to-end on Managed**:
   - Signed package uploaded to a non-production environment with an Environment ActiveGate.
   - Root CA in the Credential Vault and on the ActiveGate.
   - One monitoring configuration in `both` mode.

### Success criteria for v1 (on a real HCI, `both` mode)

1. All four entity types appear with the correct relationships.
2. Every metric in §5.2 that the device supports is non-empty.
3. A Sangfor alarm shows as an event on the correct entity within 2 cycles.
4. Extension status stays OK for 24 hours.
5. ActiveGate resource use stays within the default limits (5% CPU, 500 MB RAM).

## 11. Open questions, settled by the validation kit or the first E2E

| # | Question | Default until settled |
|---|---|---|
| Q1 | Are `diskread`, `diskwrite`, `netin` and `netout` per-second rates or cumulative counters, and in which unit? | Reported as gauges named without units. The unit is set in metadata after validation. |
| Q2 | Datastore `status`: hex bit masks or binary-digit notation? | Hex masks as written in the spec. |
| Q3 | SNMP value encoding: strings or integers, and the ratio scale. | Parse with regex `([0-9.]+)`. The OIDs the Zabbix template multiplies by 100 (host CPU, memory and disk use rate, datastore use rate) are marked as ratios in `oids.py` and converted to percent. All other OIDs are taken as-is. |
| Q4 | Fan and RAID status string values. | Known tokens first (ok/normal/optimal → OK; failed/degraded/error → not OK); unknown strings use the change-from-baseline rule and are reported by the validation kit. |
| Q5 | Which SNMP versions answer on the target HCI release, and whether the v2c community is fixed. | Default v3, with v2c `sangfopub` allowed. |
| Q6 | Ticket lifetime. | Re-login on 401, and proactively every 10 minutes. |
| Q7 | Minimum Managed cluster version for Python extensions, generic topology and screens. | `minDynatraceVersion: "1.285"`. |
| Q8 | Is the alarm `status` field "active vs resolved"? | One-shot events with a 15-minute timeout. |
| Q9 | Does the 2022 API spec still match current HCI releases (6.8 to 6.11)? | Code against the spec. Missing fields are tolerated (§8). |
| Q10 | Are SNMP filesystem sizes GB (10⁹) or GiB (1024³)? | GiB. |

## 12. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Sangfor changes the API or OIDs between releases | Silent data gaps | Version dimension on every host, parse-failure counters, field kit per release |
| No private SNMP subtree on some releases (F9) | No hardware data | Probe and degrade cleanly. API data unaffected. |
| VM-heavy clusters cost more than expected | Customer pushback on DDU | §9 estimates, the VM interval knob, and a README calculator |
| Customer cannot run unsigned or unknown extensions | Blocked rollout | Signing procedure documented step by step for Managed (F4) |
| ActiveGate cannot reach node IPs on UDP 161 | No hardware data | Pre-flight connectivity check in the validation kit |

## 13. References

- Sangfor 超融合平台API接口说明 (2022-01-06): https://github.com/liudonghua123/hci_api
- Zabbix community template, Sangfor HCI: https://github.com/zabbix/community-templates/tree/main/Virtualization/Sangfor/template_hci/7.0
- Sangfor CN forum, Zabbix and HCI over SNMP: https://bbs.sangfor.com.cn/forum.php?mod=viewthread&tid=249445
- Sangfor support, SNMP settings (HCI 6.10): https://support.sangfor.com.cn/productDocument/read?product_id=33&version_id=993&category_id=283492
- Dynatrace Python SDK: https://github.com/dynatrace-extensions/dt-extensions-python-sdk
- Dynatrace, Python 3.10 end of support: https://docs.dynatrace.com/docs/ingest-from/extensions/end-of-support/python-extension-runtime-update
- Dynatrace, Sign extensions: https://docs.dynatrace.com/docs/ingest-from/extensions/develop-your-extensions/sign-extensions
- Dynatrace, Extensions concepts (Managed): https://docs.dynatrace.com/managed/ingest-from/extensions/concepts
