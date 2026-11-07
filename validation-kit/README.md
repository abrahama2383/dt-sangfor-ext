# Sangfor HCI validation kit

`sangfor_probe.py` checks what a real Sangfor HCI returns, so the extension can be confirmed against it.
It is read-only: it logs in, sends GET requests to six endpoints, and walks one SNMP subtree.

## Before you run it

- Use a read-only Sangfor account.
- Enable SNMP on HCI (System Management > Port Management > SNMP) if you want hardware data.
- Run it from a machine that can reach the HCI on TCP 443 and each node on UDP 161, ideally the ActiveGate host.

## Run

```bash
git clone https://github.com/rifqifitriady/dt-sangfor-ext && cd dt-sangfor-ext
python3 -m venv .venv && .venv/bin/pip install -e .
export SANGFOR_PASSWORD='...'          # or leave unset to be prompted
export SANGFOR_SNMP_AUTH_KEY='...'     # SNMP v3
export SANGFOR_SNMP_PRIV_KEY='...'     # SNMP v3
.venv/bin/python validation-kit/sangfor_probe.py \
  --url https://<cluster-vip> --user <read-only-user> \
  --snmp-version v3 --v3-user <snmp-user> \
  --snmp-node <node-1-ip> --snmp-node <node-2-ip>
```

For SNMP v2c, use `--snmp-version v2c` and `SANGFOR_SNMP_COMMUNITY`. Empty means `sangfopub`.
If the HCI uses a self-signed certificate, pass `--ca-file hci-ca.pem`, or `--insecure`.

## Output

The output is `validation-output/sangfor-probe-<time>.zip`. In it, IP and MAC addresses, host IDs, serial numbers
and host, VM and user names are replaced with placeholders such as `10.255.0.3` and `name-007`.
**Open it and check it before sharing.** `meta.json` summarises the result: versions, endpoint status, which
nodes expose the Sangfor private MIB, and the raw fan and RAID status words.
