#!/usr/bin/env bash
# Finish a live migration stuck because the DESTINATION cannot open the instance's disks (its incoming QEMU waits on a
# multipath map without a working path, so the migration never starts copying and an abort is not taken). The instance
# keeps running on its source; only the incoming copy on the destination is ended:
#   1. checks (Nova): the instance is MIGRATING, its newest live migration goes to the destination named, and that
#      destination is NOT the compute the instance runs on;
#   2. on the destination only, refused unless all hold: the domain there is paused (an incoming one, never a running
#      one), exactly one QEMU process of it, its disks resolved from that QEMU; a disk is touched only when no running
#      domain of the destination uses it and nothing but that QEMU has it open;
#   3. SIGKILL to that QEMU first (it can then never go on), then fail_if_no_path on its disks without a working path,
#      so the I/O it waits for returns and it ends; libvirt and Nova then roll the migration back;
#   4. followed up to 5 minutes until the instance is ACTIVE on its source, then its volumes' Cinder attachments.
# When the migration has already ended, nothing is changed: the state is only read (also what is left on the destination).
# Same path as the portal: portal service account -> management host -> director -> computes.
# Run on the bastion:  sudo bash ~/finish-stuck-migration.sh <SITE> <instance ID> <destination compute, short name>
set -u
SITE="${1:-}"
SID="${2:-}"
DST="${3:-}"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$SID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || { echo "Instance ID: a UUID"; exit 1; }
[[ "$DST" =~ ^[a-z0-9-]{1,63}$ ]] || { echo "Destination: short name"; exit 1; }
OUT="/home/deploy/finish-stuck-migration-$SITE-$(date +%Y%m%d-%H%M%S).txt"
SVC=opsportal
PY=/opt/ops-portal/.venv/bin/python
OPS=/opt/ops-portal/modules/wi/wi_analysis/wi_ops.py
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
import functools, os, shlex, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wi_ops

print = functools.partial(print, flush=True)

# On the destination. I = the libvirt domain, ACT = 1 to change, 0 to read only. The domain name is only in variables:
# a pgrep for "guest=<domain>," never finds this script itself.
DEST = r"""
c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$')
m=$(podman ps --format '{{.Names}}' | grep -m1 -x multipathd)
[ -n "$c" ] || { echo "@@refused no libvirt container here"; exit 0; }
st=$(timeout 30 podman exec "$c" virsh -c qemu:///system domstate --reason "$I" 2>&1 | head -1)
echo "virsh domstate $I: ${st:-no answer within 30 s}"
P=""; for p in $(pgrep -f "guest=$I,"); do case "$(readlink /proc/$p/exe 2>/dev/null)" in *qemu*) P="$P $p";; esac; done
P=$(echo $P)
for p in $P; do echo "qemu process $p: state $(ps -o stat= -p $p), $(ps -L -o stat= -p $p | grep -c '^D') thread(s) waiting on I/O (D), started $(ps -o lstart= -p $p)"; done
[ -n "$P" ] || { echo "@@nothing no QEMU process of $I here: nothing to end"; exit 0; }
case "$st" in paused*) ;; *) echo "@@refused the domain is not paused here ($st): only a paused incoming copy is ended"; exit 0;; esac
[ "$(echo $P | wc -w)" = 1 ] || { echo "@@refused $(echo $P | wc -w) QEMU processes of $I"; exit 0; }
DISKS=$(timeout 30 podman exec "$c" cat "/run/libvirt/qemu/$I.xml" 2>/dev/null | grep -oE "<source dev='/dev/[^']+'" | cut -d"'" -f2 | sort -u)
[ -n "$DISKS" ] || DISKS=$(timeout 10 cat /proc/$P/cmdline | tr '\0' '\n' | grep -oE '/dev/[A-Za-z0-9/_.:-]+' | sort -u)
echo "disks of the incoming copy: $(echo $DISKS)"
RUNNING=$(timeout 90 podman exec "$c" sh -c 'for y in $(virsh -c qemu:///system list --state-running --name); do virsh -c qemu:///system domblklist $y | awk -v y=$y "\$2 ~ /^\/dev\// {print y, \$2}"; done' |
  while read -r y s; do echo "$y $(basename "$(readlink -f "$s")")"; done)
FAIL=""
for s in $DISKS; do
  k=$(basename "$(readlink -f "$s")")
  case "$k" in dm-*) ;; *) echo "disk $s ($k): not a multipath map, left as it is"; continue;; esac
  case "$(cat /sys/block/$k/dm/uuid 2>/dev/null)" in mpath-*) ;; *) echo "disk $s ($k): not a multipath map, left as it is"; continue;; esac
  n=$(cat /sys/block/$k/dm/name 2>/dev/null); w=$(cat /sys/block/$k/dm/uuid 2>/dev/null)
  act=$(dmsetup status "$n" 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i ~ /^[0-9]+:[0-9]+$/ && $(i+1) == "A") a++} END {if (NR) print a + 0}')
  paths=$(ls /sys/block/$k/slaves 2>/dev/null | paste -sd, -)
  used=$(echo "$RUNNING" | awk -v k="$k" '$2 == k {print $1}' | paste -sd, -)
  openers=$(find /proc/[0-9]*/fd -maxdepth 1 -lname "/dev/$k" 2>/dev/null | cut -d/ -f3 | sort -u | paste -sd, -)
  h=$(ls /sys/block/$k/holders 2>/dev/null | paste -sd, -)
  echo "disk $s: $k ($n, ${w:-?}), working paths $act of ${paths:-none}, open by ${openers:-nobody}, held by ${h:--}, used by running domain(s) ${used:--}"
  [ -z "$used" ] || { echo "@@refused $k is a disk of running domain(s) $used here"; exit 0; }
  [ -z "$h" ] || { echo "@@refused $k is held by $h"; exit 0; }
  for o in $(echo "$openers" | tr , ' '); do [ "$o" = "$P" ] || { echo "@@refused $k is also open by process $o"; exit 0; }; done
  [ "$act" = 0 ] && FAIL="$FAIL $n"
done
[ "$ACT" = 1 ] || { echo "@@read only"; exit 0; }
st=$(timeout 30 podman exec "$c" virsh -c qemu:///system domstate --reason "$I" 2>&1 | head -1)
case "$st" in paused*) ;; *) echo "@@refused the domain is now $st (read again right before the end)"; exit 0;; esac
timeout 5 cat /proc/$P/cmdline 2>/dev/null | tr '\0' ' ' | grep -q "guest=$I," || { echo "@@refused process $P is no longer the QEMU of $I"; exit 0; }
kill -9 "$P" || { echo "@@refused kill -9 $P did not work: nothing else was done"; exit 0; }
echo "@@sent SIGKILL to QEMU $P (incoming copy of $I)"
for n in $FAIL; do
  [ -n "$m" ] && podman exec "$m" multipathd disablequeueing map "$n" >/dev/null 2>&1
  dmsetup message "$n" 0 fail_if_no_path && echo "@@sent fail_if_no_path to $n (no working path: its waiting I/O returns)"
done
for i in $(seq 1 30); do [ -d /proc/$P ] || break; sleep 2; done
[ -d /proc/$P ] && echo "@@still QEMU $P has not ended yet (state $(ps -o stat= -p $P))" || echo "@@ended QEMU $P"
echo "virsh domstate $I now: $(timeout 30 podman exec "$c" virsh -c qemu:///system domstate --reason "$I" 2>&1 | head -1)"
"""


def on_dest(d, host, inst, act):
    ip, user = d.node(host)
    if not ip:
        print(f"{host}: address not in the inventory: nothing done")
        return ""
    inner = f"I={shlex.quote(inst)}; ACT={1 if act else 0}; " + DEST
    rc, out = d.run(wi_ops.SSH + [f"{user}@{ip}", "sudo -n sh -c " + shlex.quote(inner)], show=False, timeout=600)
    print(f"-- {host} ({ip}):")
    print("\n".join("   " + x for x in str(out or "").rstrip().splitlines()) or f"   (no output, exit {rc})")
    return str(out or "")


def state(d, sid, mid):
    s = d.server(sid) or {}
    m = next((x for x in d.migrations(sid) if x["id"] == mid), {}) if mid else {}
    return s, m


def attachments(d, s):
    for v in s.get("volumes") or []:
        atts = d.attachments(v)
        shown = "not readable" if atts is None else ", ".join(f"{a['id'][:8]} {a['status']}" for a in atts) or "none"
        print(f"   volume {v}: {len(atts or [])} attachment(s): {shown}")


def main(d, sid, dst, sleep=time.sleep, clock=time.time):
    s = d.server(sid)
    if not s or s.get("unknown"):
        print(f"Instance {sid} could not be read: nothing done")
        return 1
    print(f"Instance {s['name']}: status {s['status']}, task {s['task'] or '-'}, on {s['host']}, {s['instance']}")
    migs = [m for m in d.migrations(sid) if m["type"] in ("", "live-migration")]
    m = migs[0] if migs else {}
    if m:
        print(f"Newest live migration {m['id']}: {m['status']}, {m['source']} -> {m['dest']}, created {m['created']} (UTC)")
    if wi_ops.short(s["host"]) == dst:
        print(f"RESULT refused: {dst} is the compute the instance runs on: nothing is done there")
        return 1
    busy = s["status"] == "MIGRATING" or s["task"] == "migrating"
    stuck = busy and m and m["status"] in wi_ops.LIVE_BUSY and wi_ops.short(m["dest"]) == dst
    if not stuck:
        print("\nThe migration is not running any more: nothing is changed. What is left on the destination (read-only):")
        on_dest(d, dst, s["instance"], False)
        print("Cinder attachments of its volumes:")
        attachments(d, s)
        ok = s["status"] == "ACTIVE" and not s["task"]
        print("\nRESULT " + ("ok" if ok else "ATTENTION") + f": {s['name']} is {s['status']} (task {s['task'] or '-'}) on {s['host']}")
        return 0 if ok else 2
    print("\n== The incoming copy on the destination (checked, then ended)")
    out = on_dest(d, dst, s["instance"], True)
    if "@@refused" in out or "@@sent SIGKILL" not in out:
        print("\nRESULT refused: nothing was changed (see why above)")
        return 1
    print("\n== Nova (up to 5 minutes, until the instance is ACTIVE on its source)")
    start, seen = clock(), ""
    while clock() - start < 300:
        sleep(10)
        s2, m2 = state(d, sid, m["id"])
        now = f"instance {s2.get('status', '?')}, task {s2.get('task') or '-'}, on {s2.get('host', '?')}; migration {m2.get('status', '?')}"
        if now != seen:
            print(f"  {int(clock() - start)} s: {now}")
            seen = now
        if s2.get("status") in ("ACTIVE", "ERROR") and not s2.get("task") and m2.get("status") not in wi_ops.LIVE_BUSY:
            break
    s2, m2 = state(d, sid, m["id"])
    print("\n== After (read-only)")
    on_dest(d, dst, s["instance"], False)
    print("Cinder attachments of its volumes:")
    attachments(d, s2 or s)
    back = s2.get("status") == "ACTIVE" and not s2.get("task") and wi_ops.short(s2.get("host", "")) == wi_ops.short(s["host"])
    print("\nRESULT " + ("ok: " if back else "ATTENTION: ") + f"{s['name']} is {s2.get('status', '?')} (task {s2.get('task') or '-'}) "
          f"on {s2.get('host', '?')}; migration {m['id']} {m2.get('status', '?')}")
    return 0 if back else 2


if __name__ == "__main__":
    director = wi_ops.Director(write=print)
    try:
        sys.exit(main(director, sys.argv[1], sys.argv[2]))
    finally:
        wi_ops.SSH_POOL.close()
PY
)

REMOTE=$(cat <<'EOF'
set -u
source $RC >/dev/null 2>&1 || { echo "source $RC failed"; exit 1; }
W=$(mktemp -d /tmp/wi-finish.XXXXXXXX) || exit 1
trap 'rm -rf "$W"' EXIT
printf %s "$OPSB" | base64 -d | gunzip > "$W/wi_ops.py"
printf %s "$HB" | base64 -d > "$W/harness.py"
python3 -u "$W/harness.py" "$SID" "$DST"
EOF
)

{
  echo "$(date -Is), site $SITE, instance $SID, destination $DST; wi_ops.py $OPS ($(md5sum < "$OPS" | cut -c1-8)); director $DIR_USER@$DIR_HOST"
  OPSB=$(gzip -c "$OPS" | base64 -w0)
  HB=$(printf '%s\n' "$HARNESS" | base64 -w0)
  printf 'RC=%s\nSID=%q\nDST=%q\nOPSB=%q\nHB=%q\n%s\n' "$RC" "$SID" "$DST" "$OPSB" "$HB" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "$HOP bash -s" 2>&1 | grep -v '^\*\* '
  echo "== exit ${PIPESTATUS[1]}"
} | tee "$OUT"
chown deploy: "$OUT"
echo "Saved: $OUT"
