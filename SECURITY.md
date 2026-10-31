# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: open the repository's **Security** tab
and choose **Report a vulnerability**. Do not open a public issue for security problems.

Helpful details: the affected version or commit, your configuration (reverse proxy,
`ADMIN_PUBLIC` or `ADMIN_CIDRS`), steps to reproduce, and what an attacker gains.

## Supported versions

Fixes are made on the `main` branch only. Update to the latest `main` before reporting, and
after a fix is released.

## Scope

The threat model and what pushgate does and does not protect against are described in the
README ([How it is secured](README.md#how-it-is-secured), [Security model](README.md#security-model))
and in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#threat-model-summary). Problems that require
control of the server itself, or of an unlocked phone holding the passkey, are outside that model.
