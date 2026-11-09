# Security policy

Ops Portal runs commands on servers, talks to storage and network APIs and keeps service-account passwords, so
security reports are welcome and taken seriously.

## Reporting a vulnerability

Please do not open a public issue. Report it privately on GitHub: **Security → Report a vulnerability**
(<https://github.com/fauzan1901/ops-portal/security/advisories/new>).

Include what you found, how to reproduce it (the demo mode, `portal/test_mode.sh`, is the easiest place), and the
version (tag or commit). I aim to answer within a week and to publish a fix with a note in
[CHANGELOG.md](CHANGELOG.md).

## Supported versions

The latest release and `main`.

## Scope

In scope: the portal (`portal/`), its deployment files (`portal/deploy/`) and the scripts in `tools/`.

Not a vulnerability: the demo accounts and keys that `portal/test_mode.sh` prints or creates on purpose, and the mock
servers in `portal/tests/` (they exist only for tests and the demo).

## Running it safely

- Never run the demo mode on a shared or reachable host.
- Put the portal behind nginx with TLS (see `portal/deploy/`), and let only the operations networks reach it.
- Keep `credentials.key` and `auth.yml` readable by the service user only, and use read-only service accounts where
  the work allows it.
