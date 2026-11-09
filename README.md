# Ops Portal

[![tests](https://github.com/fauzan1901/ops-portal/actions/workflows/tests.yml/badge.svg)](https://github.com/fauzan1901/ops-portal/actions/workflows/tests.yml)
[![release](https://img.shields.io/github/v/release/fauzan1901/ops-portal)](CHANGELOG.md)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

I look after cloud infrastructure with a small operations team: OpenStack, NetApp storage, VMware and Cisco ACI in
three data centers. Almost none of it has a public address. You reach it from a jump host on the management network,
and most fixes used to start with logging in somewhere and following a work instruction by hand.

Ops Portal is what we built so we could stop doing that. It runs on a server inside the management network and the
team just opens it in a browser. From there you can:

- run the checks from our work instructions and see, step by step, what is wrong
- get the fix with the real values filled in, and run it from the portal if you are allowed to
- let Grafana alerts start the right checks on their own
- restore an OpenStack volume from a NetApp snapshot
- manage static ports and templates on Cisco ACI
- open SSH terminals to any host the portal knows, with no keys or passwords on your laptop

It is a Flask app, and the work runs as Ansible jobs. We use it every day.

> This repository is a cleaned-up copy of our internal project. Company, product, customer and site names, host
> names and every IP address were replaced with made-up ones (sites `DCA`, `DCB`, `DCC`, domains
> `*.example.internal`). There are no credentials or real data in it. [How the copy is made](docs/GITHUB.md).

## Why it runs inside the network

Your laptop only needs to reach the portal over HTTPS, not every management network. Service-account passwords stay
encrypted on the portal server and never reach the browser. Every check, fix and terminal session lands in one
activity log, and access is given per person and per host.

## Screenshots

From the demo mode, with made-up data.

| | |
|---|---|
| **Home**: one sign-in, every module | **Operation Automation**: a check rates every step |
| ![Home](docs/screenshots/01-home.png) | ![Check result](docs/screenshots/02-check-result.png) |
| **How to fix it**: the commands with the real values | **Shell**: SSH terminals in the browser, split panes |
| ![How to fix it](docs/screenshots/02b-how-to-fix.png) | ![Shell](docs/screenshots/03-shell.png) |
| **Alerts**: Grafana alerts start the matching checks | **ONTAP Restore**: a volume back from a snapshot |
| ![Alerts](docs/screenshots/04-alerts.png) | ![ONTAP Restore](docs/screenshots/05-ontap-restore.png) |
| **ACI**: static port bindings per site | |
| ![ACI](docs/screenshots/06-aci.png) | |

## Try it

You need Python 3.11 or newer (I use 3.14).

```bash
cd portal
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
./test_mode.sh
```

Then open <http://localhost:8083>. Everything in the demo is fake: the APICs, ONTAP clusters, vCenter, the OpenStack
director, the SSH hosts and the directory. The script prints the demo accounts and a few things to try.

## Tests

Each suite runs in its own process:

```bash
cd portal
for s in tests/test_*.py; do s=${s%.py}; .venv/bin/python -m unittest "${s//\//.}" || break; done
```

`test_wi` and `test_ontap` take a while (about 15 and 10 minutes) because Ansible really runs. GitHub Actions runs
every suite on each push.

## More

- [docs/FEATURES.md](docs/FEATURES.md): each module in detail, how it works, configuration, deployment and security
- [portal/docs/GRAFANA-ALERTS.md](portal/docs/GRAFANA-ALERTS.md): connecting Grafana
- [portal/docs/WI-COVERAGE.md](portal/docs/WI-COVERAGE.md): what each check does
- [portal/MODULES.md](portal/MODULES.md): how to write a module
- [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) and [CHANGELOG.md](CHANGELOG.md)

## License

MIT, see [LICENSE](LICENSE).
