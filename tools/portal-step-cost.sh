#!/usr/bin/env bash
# Read-only: what each check of a live migration costs on this site. Runs the portal's own reads (wi_ops.py as installed on
# this bastion) for ONE running instance of the source compute, in the order a live migration of the portal runs them,
# without migrating anything and without changing anything; every OpenStack / Cinder command and every SSH is timed.
# Also: one SSH to the compute new each time vs over a reused connection, one OpenStack command with the password vs with
# a token, and the round trip of the portal to the director (each step of an item). Nothing of the instance is printed
# but its ID: no console log, no screenshot, no connection info.
# Same path as the portal: portal service account -> management host -> director -> controller / computes.
# Run on the bastion:  sudo bash ~/portal-step-cost.sh <SITE> <source compute> <destination compute> [wi_ops.py to try]
# (short names; the last argument: a newer wi_ops.py, e.g. ~/wi_ops-new.py, measured instead of the installed one)
set -u
SITE="${1:-}"
SRC="${2:-}"
DST="${3:-}"
CAND="${4:-}"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$SRC" =~ ^[a-z0-9-]{1,63}$ ]] && [[ "$DST" =~ ^[a-z0-9-]{1,63}$ ]] || { echo "Source and destination: short names"; exit 1; }
OUT="/home/deploy/portal-step-cost-$SITE-$(date +%Y%m%d-%H%M%S).txt"
SVC=opsportal
PY=/opt/ops-portal/.venv/bin/python
OPS=/opt/ops-portal/modules/wi/wi_analysis/wi_ops.py
[ -n "$CAND" ] && OPS="$CAND"
[ -r "$OPS" ] || { echo "$OPS not readable (run with sudo)"; exit 1; }

read -r MGMT_HOST MGMT_PORT MGMT_USER MGMT_KEY DIR_HOST DIR_USER DIR_PORT RC < <("$PY" - "$SITE" <<'EOF'
import sys, yaml
c = yaml.safe_load(open("/etc/ops-portal/sites.yml"))["sites"][sys.argv[1]]
m, d = c.get("mgmt") or {}, c.get("director") or {}
print(m.get("host", "-"), m.get("port", 22), m.get("user") or "-", m.get("private_key") or "-",
      d.get("host", "-"), d.get("user") or "stack", d.get("port", 22), d.get("overcloudrc") or "~/overcloudrc")
EOF
)
OPTS=(-o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new -p "$MGMT_PORT")
[ "$MGMT_KEY" != "-" ] && OPTS+=(-i "$MGMT_KEY")
TARGET="$MGMT_HOST"
[ "$MGMT_USER" != "-" ] && TARGET="$MGMT_USER@$MGMT_HOST"
HOP="ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST"

HARNESS=$(cat <<'PY'
import os, re, shlex, subprocess, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wi_ops

src, dst = sys.argv[1], sys.argv[2]
calls, steps, current = [], [], ["-"]


def kind(argv):
    if argv[0] == "ssh":
        cmd = argv[-1]
        return "ssh controller" if "galera" in cmd else "ssh compute"
    return argv[0] if argv[0] in ("openstack", "cinder", "nova") else "local"


def runner(argv, timeout):
    t = time.time()
    rc, out = wi_ops.Director._subprocess(argv, timeout)
    calls.append((current[0], kind(argv), time.time() - t, rc))
    return rc, out


d = wi_ops.Director(runner=runner, write=lambda line: None)   # the log lines are not printed (names, console)


def step(name, fn):
    current[0] = name
    n, t = len(calls), time.time()
    note = ""
    try:
        r = fn()
    except Exception as e:   # noqa: BLE001
        r, note = None, f"error {type(e).__name__}: {str(e)[:80]}"
    steps.append((name, time.time() - t, len(calls) - n, note))
    return r


services = step("compute service list", d.computes)
nova_src = d.names.get(src)
if not nova_src:
    print(f"{src} is not a nova-compute of this site")
    raise SystemExit(1)
ids = step("pick an instance (not a step of the portal)", lambda: d.read(
    ["openstack", "server", "list", "--all-projects", "--host", nova_src, "--status", "ACTIVE", "--limit", "20", "-c", "ID"])[0]) or []
sid, s = "", None
for row in ids:
    x = d.server(str(row.get("ID") or ""))
    if x and not x.get("unknown") and x["volumes"] and wi_ops.INSTANCE_RE.match(x["instance"]):
        sid, s = str(row.get("ID")), x
        break
if not s:
    print(f"no ACTIVE instance with a volume on {src}")
    raise SystemExit(1)
print(f"Instance {sid} on {src} ({len(s['volumes'])} volume(s)); destination {dst}; nothing is changed")
sip, user = d.node(src)
dip, _ = d.node(dst)
calls.clear()
steps.clear()
inst = s["instance"]
since = int(time.time()) - 300

# ---- before the migration, in the order of wi_ops.live_migrate
step("openstack --version (client generation)", d.modern)
step("server show", lambda: d.server(sid, show=True))
step("attachment-list of each volume", lambda: [d.attachments(v) for v in s["volumes"]])
step("libvirt job check (source)", lambda: d.job_blocked(sip, user, inst))
rows = step("Nova BDM read (controller)", lambda: d.bdm_rows(sid)) or []
step("disks of the instance (source)", lambda: d.disk_facts(sip, user, inst, [(r[2], r[3]) for r in rows]))
step("host LVs (source)", lambda: d.host_lvs(sip, user))
step("compute service list", d.computes)
step("console log (before)", lambda: d.console_log(sid))
step("port states (before)", lambda: d.port_states(sid))
step("server show (before)", lambda: d.server(sid))
step("screenshot (before)", lambda: d.screenshot(sip, user, inst))
step("CPU vendor (source, destination)", lambda: [d.runner(wi_ops.SSH + [f"{user}@{ip}", wi_ops.VENDOR_COMMAND], 60) for ip in (sip, dip)])
step("instance directory (destination)", lambda: d.instance_dir(dip, user, sid))
step("live migrations of the site", lambda: d.live_migrations_running(sid, show=True))
step("dead disks baseline (source)", lambda: d.dead_disks(sip, user))
step("dead disks baseline (destination)", lambda: d.dead_disks(dip, user))
# ---- while it runs: one poll (the portal polls every 10 s)
step("one poll: server show", lambda: d.server(sid))
step("migration list", lambda: d.migrations(sid))
# ---- after it
step("disk paths since the start (source)", lambda: d.disk_paths(sip, user, since, show=False))
step("host LVs (destination)", lambda: d.host_lvs(dip, user))
step("server show (after)", lambda: d.server(sid))
step("ports (after)", lambda: d.ports_of(sid))
step("domain check", lambda: d.domain_check(sip, user, inst, []))
step("screenshot (after)", lambda: d.screenshot(sip, user, inst))
step("console log (after)", lambda: d.console_log(sid))

total = sum(x[1] for x in steps)
print()
print("%-44s %8s %6s" % ("Step (as a live migration of the portal runs them)", "seconds", "calls"))
for name, sec, n, note in steps:
    print("%-44s %8.1f %6d  %s" % (name, sec, n, note))
print("%-44s %8.1f %6d" % ("TOTAL of the checks of one instance", total, len(calls)))
print()
print("By kind of call:")
for k in ("openstack", "cinder", "ssh compute", "ssh controller", "local"):
    xs = [c[2] for c in calls if c[1] == k]
    if xs:
        print("   %-16s %3d call(s), %6.1f s in all, %5.1f s each on average, slowest %5.1f s" % (k, len(xs), sum(xs), sum(xs) / len(xs), max(xs)))

# ---- what a reused SSH connection and a token would save
print()


def timed(argv, env=None, n=3):
    out = []
    for _ in range(n):
        t = time.time()
        try:
            rc = subprocess.run(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env, timeout=120).returncode
        except (OSError, subprocess.SubprocessError):
            rc = -1
        out.append("%.2f s%s" % (time.time() - t, "" if rc == 0 else " (failed)"))
    return out


fresh = timed(wi_ops.SSH + [f"{user}@{sip}", "true"])
cm_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cm")
os.makedirs(cm_dir, mode=0o700, exist_ok=True)
cm = ["-o", "ControlMaster=auto", "-o", f"ControlPath={cm_dir}/%C", "-o", "ControlPersist=60"]
reused = timed(wi_ops.SSH + cm + [f"{user}@{sip}", "true"], n=4)
subprocess.run(["ssh", "-o", f"ControlPath={cm_dir}/%C", "-O", "exit", f"{user}@{sip}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print("SSH to the compute, new each time:        " + ", ".join(fresh))
print("SSH to the compute, reused connection:    " + ", ".join(reused) + "   (the first one opens it)")
pw = timed(["openstack", "server", "show", sid, "-f", "json"])
try:
    tok = subprocess.run(["openstack", "token", "issue", "-f", "value", "-c", "id"], capture_output=True, text=True, timeout=120).stdout.strip()
except (OSError, subprocess.SubprocessError):
    tok = ""
env = {k: v for k, v in os.environ.items() if k not in ("OS_PASSWORD", "OS_USERNAME", "OS_USER_DOMAIN_NAME", "OS_USER_DOMAIN_ID")}
env.update(OS_AUTH_TYPE="v3token", OS_TOKEN=tok)
tk = timed(["openstack", "server", "show", sid, "-f", "json"], env=env) if tok else []
ver = timed(["openstack", "--version"], n=2)
py = timed(["python3", "-c", "pass"], n=2)
print("openstack server show, with the password: " + ", ".join(pw))
print("openstack server show, with a token:      " + (", ".join(tk) if tk else "token not issued"))
print("openstack --version (client start only):  " + ", ".join(ver))
print("python3 start:                            " + ", ".join(py))
PY
)

REMOTE=$(cat <<'EOF'
set -u
source $RC >/dev/null 2>&1 || { echo "source $RC failed"; exit 1; }
W=$(mktemp -d /tmp/wi-cost.XXXXXXXX) || exit 1
trap 'rm -rf "$W"' EXIT
printf %s "$OPSB" | base64 -d | gunzip > "$W/wi_ops.py"
printf %s "$HB" | base64 -d > "$W/harness.py"
python3 "$W/harness.py" "$SRC" "$DST"
EOF
)

{
  echo "Read-only, $(date -Is), site $SITE, source $SRC, destination $DST, wi_ops.py $OPS ($(md5sum < "$OPS" | cut -c1-8)); management host $MGMT_HOST, director $DIR_USER@$DIR_HOST (keys are not printed)"
  echo "== The round trip of the portal to the director (each step of an item: start, every read of its output, its result):"
  for i in 1 2 3; do
    s=$(date +%s.%N); sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" "$HOP true" >/dev/null 2>&1; e=$(date +%s.%N)
    awk -v s="$s" -v e="$e" 'BEGIN {printf "   %.2f s\n", e - s}'
  done
  OPSB=$(gzip -c "$OPS" | base64 -w0)
  HB=$(printf '%s\n' "$HARNESS" | base64 -w0)
  printf 'RC=%s\nSRC=%q\nDST=%q\nOPSB=%q\nHB=%q\n%s\n' "$RC" "$SRC" "$DST" "$OPSB" "$HB" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "$HOP bash -s" 2>&1 | grep -v '^\*\* '
  echo "== exit ${PIPESTATUS[1]}"
} | tee "$OUT"
chown deploy: "$OUT"
echo "Saved: $OUT"
