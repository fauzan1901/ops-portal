# Contributing

Thanks for taking a look. Questions, bug reports and ideas are welcome as issues; pull requests too.

## Set up

Python 3.11 or later (developed with 3.14):

```bash
cd portal
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
./test_mode.sh          # demo on http://localhost:8483 with fake sites, hosts and APIs
```

## Tests

The tests use the standard library `unittest` and the fakes in `portal/tests/`; nothing real is touched. Run each
suite in its own process:

```bash
cd portal
.venv/bin/python -m unittest tests.test_wi_alerts
for s in tests/test_*.py; do s=${s%.py}; .venv/bin/python -m unittest "${s//\//.}" || break; done
```

GitHub Actions runs every suite on each push and pull request. A change comes with a test for what it changes.

## How the code is written

- Checks are read-only: fixed commands, GET-only REST calls, validated parameters. No free text from the browser
  reaches a shell.
- A fix shows its exact commands before it runs; risky ones ask for a typed confirmation.
- Comments, messages and documentation are in English. The UI reuses the existing PatternFly-style CSS and patterns
  instead of new styles.
- A module is a Flask blueprint, see [portal/MODULES.md](portal/MODULES.md).

## Never commit

Passwords, keys, tokens, real host names or addresses. Use the example ranges and names already in the code.

## Pull requests

Keep them small and say what and why. This repository is the published copy of an internal project: an accepted
change is carried into that project and comes back here with the next update, so it may arrive as a new commit
rather than a merge. Contributions are under the [MIT license](LICENSE).
