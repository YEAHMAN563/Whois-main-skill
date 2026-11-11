# Security and responsible use

Reverse Master is intended for authorized reverse engineering, interoperability work, software assurance, incident response, and defensive security research.

## Safe handling

- Analyze only software you own or have explicit permission to examine.
- Treat binaries, archives, scripts, memory dumps, and extracted files as untrusted input.
- Prefer static analysis. Do not execute unknown samples on a daily-use workstation or production system.
- When execution is necessary, use a disposable, isolated, snapshotted, network-restricted lab with no sensitive accounts or data.
- Do not expose analysis infrastructure to untrusted samples.
- Keep original samples immutable and store derived artifacts separately.

## Out of scope

This project does not provide authorization to bypass access controls on systems you do not own, steal credentials or data, deploy malware, or evade security monitoring in real-world environments.

## Reporting issues

For a vulnerability in this repository or its instructions, open a private security advisory through GitHub if that feature is available. Do not publish sensitive details or exploit material in a public issue.
