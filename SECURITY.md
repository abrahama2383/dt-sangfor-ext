# Security Policy

This extension runs on a Dynatrace ActiveGate inside a customer network and talks to a production Sangfor HCI. It handles sensitive things:

- the Sangfor API account and its password;
- SNMP communities and SNMPv3 keys;
- the TLS trust toward the HCI;
- the extension signing CA that every Dynatrace environment trusts.

A vulnerability here can lock out an account, leak a credential or open a path into a hypervisor, so please report it privately.

## Reporting a vulnerability

Use GitHub's [private vulnerability reporting](https://github.com/rifqifitriady/dt-sangfor-ext/security/advisories/new) (Security → Report a vulnerability), or contact the maintainer, [@rifqifitriady](https://github.com/rifqifitriady), directly. Please do not open a public issue, discussion or pull request for a security problem.

Please include:

- the extension version (`version` in `extension/extension.yaml`) and the ActiveGate version;
- the collection mode (`api`, `snmp` or `both`) and the SNMP version;
- the steps to reproduce, and what an attacker gains.

Never include real credentials, IP addresses, hostnames or unredacted validation-kit output.

What to expect:

- A first response within 7 days.
- An assessment and a plan within 14 days.
- A fix as fast as its severity calls for. We coordinate the disclosure date with you and credit you in the release notes, unless you prefer otherwise.

## Supported versions

| Version | Supported |
|---|---|
| 0.x (latest release and `main`) | ✓ |
| older | ✗ |

## What is in scope

- Any request toward Sangfor other than an allowlisted GET or the single login POST, or a way to make the extension change state on the HCI.
- More than one failed login per back-off window, or any other path that can lock out the Sangfor account.
- A password, community string or SNMP key reaching a log, an exception message, a repr, the extension status, an event property or a metric dimension.
- TLS verification turned off or weakened without the operator choosing it.
- The validation kit's redacted zip leaking a secret or customer-identifying data (IP and MAC addresses, hostnames, domains, emails, serial numbers, names).
- Path traversal or injection through values the HCI returns (host IDs, names, alarm text).
- A signed package that contains files it should not, or a build that can be tampered with.

## Out of scope

- Anything that needs an attacker to already control the ActiveGate, the Dynatrace environment or the HCI.
- Weaknesses in Sangfor HCI or Dynatrace themselves; report those to the vendor.
- Running with TLS verification off, or with SNMP v2c on an untrusted network, against the guidance in the README.
- Metric values that are wrong without crossing a security boundary (that is a quality issue; please open a normal issue).

## Built-in protections

The extension was reviewed task by task and then as a whole branch, with an adversarial re-test of the lockout fixes, before its first release:

- a read-only GET allowlist that also rejects traversal and encoded paths;
- an RSA-encrypted password, a ticket POST that is never resent, and a login back-off of 5 → 10 → 20 → 40 → 60 minutes after any failure that could have reached the HCI, with concurrent requests serialized into one POST;
- secrets marked `repr=False`, and errors recorded by class name only, so third-party exception text never carries a secret;
- dimension values sanitized before they are sent;
- TLS verification on by default, with a custom CA field instead of an off switch;
- a redacting validation probe that reads its secrets from environment variables or a prompt, never from the command line.

## Running the extension safely

- **Use a dedicated read-only Sangfor account** for the extension, never an administrator.
- **Prefer SNMPv3** with SHA or SHA256 and AES; restrict SNMP on the nodes to the ActiveGate's address.
- **Paste the HCI's CA** instead of turning TLS verification off.
- **Keep the signing CA's private key (`ca.key`) off shared machines and out of this repository**, and back it up. Whoever holds it can sign extensions your environments trust.
- **Read API tokens with `read -rs`**, as the README shows, so they stay out of shell history.
- **Open and check the validation kit's zip** before you share it, even though it is redacted.
