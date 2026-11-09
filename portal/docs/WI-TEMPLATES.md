# Operation Automation: templates

A template is a check an administrator makes on the portal, without writing Ansible: the commands to run on a host and
what in their output is a problem. It is listed, launched, run and shown like every built-in check (the same playbook
`run_check.yml`, host connection, result page, run history, "Where to look" and fixes).

## Who does what

| Who | What |
|---|---|
| Administrator | **Create template** (button on All checks and on every list page), **Edit template** (pencil on the row, button on the check page), **Delete template**. Every change is a portal event `wi.template`. |
| Every user of the module | Runs a template like any check: choose a host of its group, **Run check**. |
| Users with the fix permission (`wi-fix`) | Run the change steps of a template from its result, after typing the host name. |

## A template

| Field | Notes |
|---|---|
| Name | 3 to 80 characters, unique. The id (`tpl-<name>`) is made once and stays when the name changes (the runs keep it). |
| Runs on | A host group of Hosts & SSH and `sites.yml`: linux, cdn, repo, dns, siem, esxi, gb200, vyos, huawei. The operator picks one host of it at launch. Huawei routers stay read-only: their templates only have `display` commands. |
| Activity, Product | Where the template is listed (left menu, filters, tables). |
| Description | Optional; shown in the table and on the check page. |
| Steps | 1 to 20. Each: a title and **one command line**, as typed on the host (with `sudo` when it needs root). |
| Rules of a read step | *Problem if the output contains*, *Warning if the output contains*, *Problem if the output does not contain* (a text or a regular expression, not case-sensitive) and *Problem when the command fails* (exit code not 0, on by default). |
| Wait before the next step | 0 (go on at once) to 30 minutes, in seconds or minutes; all the waits of a template add up to at most 60 minutes. Not on Huawei routers (each `display` command is its own connection). See [Waits](#waits). |

## Read steps and change steps

What a step does comes from its command, never from what the author says (`wi_analysis/template.py`, `classify`):

- **Reads**: every command of the step (`|`, `;`, `&&`, `||`) is a known read command used to read, for example
  `df`, `du`, `free`, `cat`, `grep`, `tail`, `journalctl`, `systemctl status / is-active`, `ip addr / route`, `ss`,
  `ping`, `curl` (GET), `docker ps / logs`, `ovs-vsctl show`, `esxcli ... list / get`, `nvidia-smi -q`, `show ...` on
  VyOS, `display ...` on Huawei. No `> file`, `tee`, `sed -i`, `curl -o`, `find -delete / -exec`, `$(...)` or a background
  job. Read steps run with the check, in one SSH connection, with the SSH credential of the host.
- **Changes**: anything else (`rm`, `systemctl restart`, `kill`, VyOS `configure / set / commit`...). A change step never
  runs with the check. The result offers the change steps as one fix: they run in order as one script and stop at the
  first command that fails. That fix:
  - is **risk high**: the operator types the host name;
  - needs the fix permission and a host of Hosts & SSH whose SSH credential allows fixes (hosts of `sites.yml` stay
    read-only);
  - runs from a result of at most `WI_FIX_MAX_AGE_MINUTES` minutes, even when every read step was OK;
  - is followed by the template running again, so the result shows the state after the change.

The form shows, for every command, what the portal will do with it (*Reads* or *Changes the host · after confirmation*,
with the reason). The portal rates every command again when a run is planned: a command stored as a read step that is
no longer one is not run with the check.

## Waits

A step may wait before the next one (`Wait before the next step`), for example to give a restarted service time to come
back. Where the wait happens follows from where the step runs:

| Step | Its wait |
|---|---|
| Read step followed by another read step | Inside the check, in the same SSH script: `sleep N` between the two commands. The result shows it as a step *Wait N seconds* (info). The time limit of the run grows by the waits. |
| Last read step | Nothing follows inside the check: no wait. |
| Change step | Inside the fix, as a visible command of the script (`sleep N   # wait N seconds, before the next step`). After the last change step it holds the check that runs again after the fix (`… then the check runs again`). The time limit of the fix grows by the waits. |

Example: step 1 reads `systemctl is-active nginx` (Problem if the output does not contain `^active`), step 2 changes
`sudo systemctl restart nginx` and waits 30 seconds. The check finds nginx inactive; the fix restarts it, waits 30 seconds,
then the check runs again and step 1 is OK.

## Result of a run

- **Connection**: the host answered (`uname -n`), for every group except Huawei.
- One step per read step: OK, Warning or Problem with the line of the output that matched, and the output as evidence;
  a wait between two read steps is a step *Wait N seconds*.
- The fix "Run the N change steps of this template" when the template has change steps.

## Storage and API

- SQLite table `wi_templates` in the portal database (`modules/wi/templates.py`): id, name, summary, activity, category,
  group, steps (JSON), created / updated and by whom.
- `GET /wi/api/templates/meta`, `POST /wi/api/templates/classify`, `GET|PUT|DELETE /wi/api/templates/<id>`,
  `POST /wi/api/templates`: administrators only. `GET /wi/api/catalog` lists the templates with the checks
  (`basis: "template"`).
- Tests: `tests/test_wi.py` (`TemplateClassifyTest`, `TemplateWaitTest`, `FlowTest.test_templates`).
