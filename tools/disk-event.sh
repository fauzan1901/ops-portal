#!/usr/bin/env bash
# Read-only: a disk event on a compute (I/O errors on a dm of a running VM, SCSI devices removed) and what ran around it.
# On the compute: the kernel disk lines from <from> per minute (first and last raw ones too), I/O errors of the last
# 10 minutes, which running domain uses the dm now, the multipath map of the dm and of every disk of the instance, the
# instance's domain (UUID, state, disks, disk errors, job), the nova-compute lines of volume connects / disconnects and
# migrations from <from>. On the director: where Nova has the instance, its actions, migrations and volumes (status and
# attachments only, never connection_info). On the bastion: the portal's checks and fixes from <from> (database read-only).
# Same path as the portal: portal service account -> management host -> director -> compute. Only show / list / grep.
# Run on the bastion:  sudo bash ~/disk-event.sh <SITE> <compute> <instance-XXXXXXXX> <dm-N> "<from YYYY-MM-DD HH:MM>"
#   e.g. sudo bash ~/disk-event.sh DCA overcloud-novacomputeiha-0 instance-00c0ffee dm-23 "2026-10-31 15:00"
set -u
SITE="${1:-}"
NODE="${2:-}"
INST="${3:-}"
DM="${4:-}"
FROM="${5:-}"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$NODE" =~ ^[A-Za-z0-9.-]+$ ]] || { echo "Compute: a name such as overcloud-novacomputeiha-0"; exit 1; }
[[ "$INST" =~ ^instance-[0-9a-f]{8}$ ]] || { echo "Instance: the libvirt name, e.g. instance-00c0ffee"; exit 1; }
[[ "$DM" =~ ^dm-[0-9]+$ ]] || { echo "Device: dm-N, e.g. dm-23"; exit 1; }
[[ "$FROM" =~ ^20[0-9]{2}-[0-9]{2}-[0-9]{2}\ [0-9]{2}:[0-9]{2}$ ]] || { echo "From: \"YYYY-MM-DD HH:MM\" (WIB)"; exit 1; }
OUT="/home/deploy/disk-event-$SITE-$INST-$(date +%Y%m%d-%H%M%S).txt"
SVC=opsportal
PY=/opt/ops-portal/.venv/bin/python
DB=/var/lib/ops-portal/portal.db

read -r MGMT_HOST MGMT_PORT MGMT_USER MGMT_KEY DIR_HOST DIR_USER DIR_PORT RC < <("$PY" - "$SITE" <<'EOF'
import sys, yaml
c = yaml.safe_load(open("/etc/ops-portal/sites.yml"))["sites"][sys.argv[1]]
m, d = c.get("mgmt") or {}, c.get("director") or {}
print(m.get("host", "-"), m.get("port", 22), m.get("user") or "-", m.get("private_key") or "-",
      d.get("host", "-"), d.get("user") or "stack", d.get("port", 22), d.get("overcloudrc") or "~/overcloudrc")
EOF
)
[ "${MGMT_HOST:-"-"}" != "-" ] || { echo "No management host for $SITE in /etc/ops-portal/sites.yml (run with sudo)"; exit 1; }
OPTS=(-o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new -p "$MGMT_PORT")
[ "$MGMT_KEY" != "-" ] && OPTS+=(-i "$MGMT_KEY")
TARGET="$MGMT_HOST"
[ "$MGMT_USER" != "-" ] && TARGET="$MGMT_USER@$MGMT_HOST"

# runs on the compute (as its overcloud user, sudo -n for root reads)
COMPUTE=$(cat <<'EOF'
set -u
c=$(sudo -n podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$')
m=$(sudo -n podman ps --format '{{.Names}}' | grep -m1 -x multipathd)
V() { sudo -n podman exec "$c" virsh -c qemu:///system "$@" 2>&1; }
MP() { if [ -n "$m" ]; then sudo -n podman exec "$m" multipath -ll 2>&1; else sudo -n multipath -ll 2>&1; fi; }
block() { awk -v d="$1" '/^[^ |`]/ && !/^size=/ {p = ($0 ~ (" " d " ") || $0 ~ (" " d "$"))} p'; }
echo "== Compute $(hostname -s), now $(date '+%F %T %Z'); libvirt container ${c:-none}, multipathd container ${m:-none (host)}"
K=$(sudo -n journalctl -k --since "$SINCE" --no-pager -o short-iso 2>/dev/null | grep -E "I/O error|alua: Detached|Synchronizing SCSI|remaining active paths|reinstated|failing path|rejecting I/O|device offline|Attached SCSI disk|Buffer I/O error|EXT4-fs error|XFS .*(error|shut)")
echo "== Kernel disk lines since $SINCE: $(printf '%s\n' "$K" | grep -c .) line(s); per minute (count, HH:MM, message without the sector)"
printf '%s\n' "$K" | grep . | awk '{t=substr($1,12,5); $1=$2=$3=""; sub(/ sector .*/,""); sub(/^ +/,""); print t " " $0}' | uniq -c | tail -n 80
echo "-- first 12 raw lines"; printf '%s\n' "$K" | grep . | head -n 12 | cut -c1-220
echo "-- last 12 raw lines"; printf '%s\n' "$K" | grep . | tail -n 12 | cut -c1-220
echo "-- I/O error lines in the last 10 minutes: $(sudo -n journalctl -k --since '-10min' --no-pager 2>/dev/null | grep -c 'I/O error')"
echo "== Which running domain uses /dev/$DM now"
for x in $(V list --name); do
  V domblklist "$x" | awk 'NR>2 && $2 ~ /^\// {print $1, $2}' | while read -r t s; do
    r=$(readlink -f "$s" 2>/dev/null); [ "$r" = "/dev/$DM" ] && echo "   $x $t $s -> $r"
  done
done
echo "== Domain $INST"
V list --all | awk -v i="$INST" '$2 == i'
U=$(V domuuid "$INST" | grep -m1 -oE '^[0-9a-f-]{36}$')
echo "@uuid ${U:-none}"
echo "-- state:  $(V domstate --reason "$INST" | head -1)"
echo "-- disks (target, source -> device now):"
DMS="$DM"
while read -r t s; do
  r=$(readlink -f "$s" 2>/dev/null); echo "   $t $s -> ${r:-?}"
  [[ "$r" == /dev/dm-* ]] && DMS="$DMS ${r#/dev/}"
done < <(V domblklist "$INST" | awk 'NR>2 && $2 ~ /^\// {print $1, $2}')
echo "-- disk errors: $(V domblkerror "$INST" | tr '\n' ' ')"
echo "-- job:"; V domjobinfo "$INST" | grep -E "Job type|Operation|Time elapsed" | sed 's/^/   /'
echo "== Multipath maps of $DMS (now)"
MAPS=$(MP)
for d in $(printf '%s\n' $DMS | sort -u); do printf '%s\n' "$MAPS" | block "$d"; echo; done
echo "== nova-compute lines since $SINCE (volumes, migrations, errors)"
sudo -n awk -v s="$SINCE" '($1 " " substr($2,1,5)) >= s' /var/log/containers/nova/nova-compute.log 2>/dev/null \
  | grep -E "$INST|${U:-$INST}|connect_volume|disconnect_volume|[Ll]ive [Mm]igration|rollback|DestinationDiskExists|[Dd]etach|ERROR" \
  | cut -c1-260 | tail -n 80
EOF
)

# runs on the director (stack, overcloudrc): finds the compute, runs the part above there, then Nova's view
REMOTE=$(cat <<'EOF'
set -u
source $RC >/dev/null 2>&1 || { echo "source $RC failed"; exit 1; }
INV=$(ls ~/overcloud-deploy/*/tripleo-ansible-inventory.yaml ~/config-download/*/tripleo-ansible-inventory.yaml \
  ~/tripleo-ansible-inventory.yaml 2>/dev/null | head -1)
DEFUSR=$(grep -q '17\.' /etc/rhosp-release && echo tripleo-admin || echo heat-admin)
read -r IP USR < <(python3 - "$NODE" "$INV" "$DEFUSR" <<'PY'
import sys, yaml
want, path, default = sys.argv[1].split(".")[0].lower(), sys.argv[2], sys.argv[3]
try:
    inv = yaml.safe_load(open(path)) or {}
except Exception:
    inv = {}
for group, body in inv.items():
    for host, hv in ((body or {}).get("hosts") or {}).items() if isinstance(body, dict) else []:
        if host.split(".")[0].lower() == want and isinstance(hv, dict) and (hv.get("ctlplane_ip") or hv.get("ansible_host")):
            print(hv.get("ctlplane_ip") or hv.get("ansible_host"), hv.get("ansible_ssh_user") or default)
            raise SystemExit
print("-", "-")
PY
)
[ "${IP:-"-"}" != "-" ] || { echo "$NODE is not in the director's inventory"; exit 1; }
CO=$(printf 'INST=%q\nDM=%q\nSINCE=%q\n%s\n' "$INST" "$DM" "$SINCE" "$COMPUTE" \
  | ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR "$USR@$IP" bash -s 2>&1)
printf '%s\n' "$CO"
SID=$(printf '%s\n' "$CO" | awk '/^@uuid [0-9a-f-]{36}$/ {print $2; exit}')
echo "== Nova's view of $INST (${SID:-no UUID: the domain is not defined on $NODE})"
[ -n "$SID" ] || exit 0
openstack server show "$SID" -f json -c name -c status -c OS-EXT-STS:task_state -c OS-EXT-STS:vm_state \
  -c OS-EXT-SRV-ATTR:host -c OS-EXT-SRV-ATTR:instance_name -c project_id -c volumes_attached -c updated 2>&1 \
  | tr -d '\n' | sed 's/  */ /g'; echo
echo "-- actions (newest first)"
openstack server event list "$SID" -f value 2>&1 | head -n 10
echo "-- migrations (newest first)"
openstack --os-compute-api-version 2.80 server migration list --server "$SID" -f json 2>&1 | python3 -c '
import json, sys
try:
    rows = json.load(sys.stdin)
except ValueError:
    print("   not read"); raise SystemExit
for r in rows[:6]:
    g = lambda *k: next((str(r[x]) for x in r for w in k if x.lower() == w), "-")
    print("  ", g("id"), g("type", "migration type"), g("status"), g("source compute"), "->", g("dest compute"), g("created at"), g("updated at"))'
echo "-- volumes (status and attachments only)"
for v in $(openstack server show "$SID" -f json -c volumes_attached | python3 -c 'import json,sys; print(" ".join(x.get("id","") for x in json.load(sys.stdin).get("volumes_attached") or []))'); do
  openstack volume show "$v" -f json -c id -c name -c status -c size -c attachments 2>&1 | python3 -c '
import json, sys
try:
    v = json.load(sys.stdin)
except ValueError:
    print("   not read"); raise SystemExit
att = [(a.get("server_id", "")[:8], a.get("host_name"), a.get("device"), str(a.get("attached_at", ""))[:19]) for a in v.get("attachments") or []]
print("  ", v.get("id"), v.get("name") or "-", v.get("status"), str(v.get("size")) + " GB", "attachments:", att)'
done
EOF
)

{
  echo "Read-only, $(date -Is), site $SITE, compute $NODE, $INST, $DM, from $FROM WIB; director $DIR_USER@$DIR_HOST (keys are not printed)"
  printf 'NODE=%q\nINST=%q\nDM=%q\nSINCE=%q\nRC=%s\nCOMPUTE=%q\n%s\n' "$NODE" "$INST" "$DM" "$FROM" "$RC" "$COMPUTE" "$REMOTE" \
    | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
      "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1 | grep -v '^\*\* '
  echo "== exit ${PIPESTATUS[1]}"
} | tee "$OUT"

# the portal's checks and fixes from <from>
if [ -r "$DB" ]; then
  "$PY" - "$DB" "$FROM" "$NODE" "$INST" <<'PY' | tee -a "$OUT"
import json, sqlite3, sys
db, frm, node, inst = sys.argv[1:5]
since = frm.replace(" ", "T")
con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
con.row_factory = sqlite3.Row
print(f"\n== Portal checks from {frm} (id, start, end, user, site, check, host/params, status, summary)")
for r in con.execute("SELECT * FROM wi_runs WHERE ts >= ? ORDER BY id", (since,)):
    print(f"   run {r['id']} {r['ts'][11:19]}-{(r['finished'] or '')[11:19]} {r['username']} {r['site']} {r['check_id']} "
          f"{r['host'] or ''} {(r['params'] or '')[:120]} [{r['status']}] {(r['summary'] or '')[:160]}")
    if node in (r["params"] or "") + (r["host"] or "") and r["result"]:
        try:
            res = json.loads(r["result"])
        except ValueError:
            continue
        for st in res.get("steps") or []:
            print(f"      - {st.get('title')}: {st.get('status')}: {str(st.get('detail') or '')[:300]}")
            tab = st.get("table") or {}
            for row in (tab.get("rows") or [])[:6]:
                print("          " + " | ".join(str(v)[:60] for v in row))
print(f"\n== Portal fixes from {frm} (id, run, item, title, target, user, start-end, status), commands and key output")
for a in con.execute("SELECT * FROM wi_actions WHERE ts >= ? ORDER BY id", (since,)):
    print(f"   fix #{a['id']} run {a['run_id']} item {a['rec_index']} '{(a['title'] or '')[:90]}' target {a['target'] or '-'} "
          f"by {a['username']} {a['ts'][11:19]}-{(a['finished'] or '')[11:19]} [{a['status']}] {(a['error'] or '')[:120]}")
    try:
        cmds = json.loads(a["commands"] or "[]")
    except ValueError:
        cmds = [a["commands"]]
    for c in (cmds if isinstance(cmds, list) else [cmds])[:8]:
        print(f"      $ {str(c)[:220]}")
    try:
        steps = json.loads(a["output"] or "[]")
    except ValueError:
        steps = []
    for i, st in enumerate(steps if isinstance(steps, list) else [], 1):
        lines = [l.strip() for l in str(st.get("out") or "").splitlines() if l.strip() and not l.startswith("@@WI@@")]
        hit = [l for l in lines if node in l or inst in l or any(w in l for w in (
            "Automatic fix", "RESULT", "Attempt", "abort", "refus", "rescan", "scan", "path", "WWID", "error", "Error", "fail"))]
        print(f"      item {i} exit {st.get('rc')}: {len(lines)} line(s)")
        for l in (hit or lines)[-25:]:
            print(f"        | {l[:240]}")
PY
fi
chown deploy: "$OUT"
echo "Saved: $OUT"
