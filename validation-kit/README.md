# Sangfor HCI validation kit

`sangfor_probe.py` checks what a real Sangfor HCI returns, so the extension can be confirmed against it.
It is read-only. It logs in once (`GET /vapi/json/public_key`, then `POST /vapi/json/access/ticket`), sends GET
requests to six data endpoints (overview, host list, storage list, VMs, alerts, and the info of each host), and
walks one SNMP subtree on each node you name.

Login attempts and account lockout:

- A failed login (for example a wrong password) is sent once and never retried; the probe then skips the API.
- The ticket POST is never resent, not even after an HTTP 5xx or a timeout, so the one login is exactly 1 ticket POST
  and cannot add a second failed attempt toward a lockout.
- If a data endpoint rejects the ticket (HTTP 401/403), the probe logs in again once for that endpoint, records it as
  failed and moves on to the next one. After two endpoints in a row are rejected it stops calling the API. A failed
  re-login pauses all logins (the extension's back-off), so a password changed mid-run causes at most 1 more failed
  ticket POST.

## Before you run it

- Use a read-only Sangfor account.
- Enable SNMP on HCI (System Management > Port Management > SNMP) if you want hardware data.
- Run it from a machine that can reach the HCI on TCP 443 and each node on UDP 161, ideally the ActiveGate host.

## Run

```bash
git clone https://github.com/rifqifitriady/dt-sangfor-ext && cd dt-sangfor-ext
python3 -m venv .venv && .venv/bin/pip install -e .
.venv/bin/python validation-kit/sangfor_probe.py \
  --url https://<cluster-vip> --user <read-only-user> \
  --snmp-version v3 --v3-user <snmp-user> \
  --snmp-node <node-1-ip> --snmp-node <node-2-ip>
```

The probe prompts for the API password and the SNMP secrets; what you type is not shown. This is the default and
the recommended way: the secrets never appear on the command line or in the shell history.

To run without prompts (for example over a script), read each secret into the environment with a hidden prompt
first. Never write `VAR=secret` on the command line.

```bash
read -rs SANGFOR_PASSWORD && export SANGFOR_PASSWORD             # Sangfor API password
read -rs SANGFOR_SNMP_AUTH_KEY && export SANGFOR_SNMP_AUTH_KEY   # SNMP v3 auth key
read -rs SANGFOR_SNMP_PRIV_KEY && export SANGFOR_SNMP_PRIV_KEY   # SNMP v3 privacy key
read -rs SANGFOR_SNMP_COMMUNITY && export SANGFOR_SNMP_COMMUNITY # SNMP v2c community instead of the v3 keys
```

Run `unset SANGFOR_PASSWORD SANGFOR_SNMP_AUTH_KEY SANGFOR_SNMP_PRIV_KEY SANGFOR_SNMP_COMMUNITY` when done.

For SNMP v2c, use `--snmp-version v2c`; an empty community means `sangfopub`.
If the HCI uses a self-signed certificate, pass `--ca-file hci-ca.pem`, or `--insecure`.

## Output

The output is `validation-output/sangfor-probe-<time>.zip`. It is written even when a check fails. In it, IP, IPv6
and MAC addresses, e-mail addresses, host names, WWNs, host IDs, serial numbers, and host, VM and user names are
replaced with placeholders such as `10.255.0.3`, `name-007` and `fqdn-002`. Error details are reduced to a reason or
an error type. **Open it and check it before sharing.** `meta.json` summarises the result: Sangfor versions,
endpoint status, which nodes expose the Sangfor private MIB, and the raw fan and RAID status words.

The exit code is 0 when everything answered, 1 when some checks failed, and 2 when nothing answered.
