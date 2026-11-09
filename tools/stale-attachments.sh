#!/usr/bin/env bash
# Read-only: every volume of the site with more than one Cinder attachment (not multiattach), each attachment judged with
# the rules the portal's live / cold migration uses before it starts (wi_ops.leftover_attachments, 2026-10-29):
#   NOVA    the attachment Nova uses (block_device_mapping.attachment_id): never deleted;
#   STALE   safe to delete: of the same instance, error_attaching / reserved / error_detaching / detached, no connection
#           (no host was given the LUN), not of the compute the instance runs on, unchanged for 30 min;
#   REVIEW  anything else (attached twice, connected, of the instance's own compute, recent, another instance).
# A volume whose other attachments are all STALE, while Nova's is attached to the instance's compute, is cleaned by the
# portal before the migration (AUTO); any REVIEW keeps the volume blocked (MANUAL: check "Volume connections of an
# instance"). Database on a controller, SELECT only, never connection_info itself (it holds the CHAP secret).
# Same path as the portal: portal service account -> management host -> director -> controller.
# Run on the bastion:  sudo bash ~/stale-attachments.sh <SITE>
set -u
SITE="${1:-}"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
OUT="/home/deploy/stale-attachments-$SITE-$(date +%Y%m%d-%H%M%S).txt"
SVC=opsportal
PY=/opt/ops-portal/.venv/bin/python

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

SQL="SELECT '@@row', a.volume_id, a.id, IFNULL(a.attach_status,'-'), IFNULL(a.attached_host,'-'),
 IFNULL(JSON_VALUE(a.connector,'\$.host'),'-'), IF(a.connection_info IS NULL,0,1), IFNULL(a.instance_uuid,'-'),
 IFNULL(TIMESTAMPDIFF(MINUTE, IFNULL(a.updated_at,a.created_at), UTC_TIMESTAMP()),-1),
 IFNULL((SELECT b.attachment_id FROM nova.block_device_mapping b WHERE b.volume_id=a.volume_id AND b.instance_uuid=a.instance_uuid
   AND b.deleted=0 AND b.destination_type='volume' LIMIT 1),'-'),
 IFNULL(REPLACE(REPLACE(i.display_name,'\t',' '),'\n',' '),'-'), IFNULL(i.host,'-'), IFNULL(i.vm_state,'-'), IFNULL(i.task_state,'-'),
 IF(v.multiattach,1,0), IFNULL(DATE_FORMAT(IFNULL(a.updated_at,a.created_at),'%Y-%m-%d %H:%i UTC'),'-')
FROM cinder.volume_attachment a JOIN cinder.volumes v ON v.id=a.volume_id AND v.deleted=0
LEFT JOIN nova.instances i ON i.uuid=a.instance_uuid AND i.deleted=0
WHERE a.deleted=0 AND a.volume_id IN (SELECT volume_id FROM cinder.volume_attachment WHERE deleted=0 GROUP BY volume_id HAVING COUNT(*)>1)
ORDER BY a.volume_id, a.created_at;"
QB=$(printf '%s\n' "$SQL" | base64 -w0)

REMOTE=$(cat <<'EOF'
set -u
INV=$(ls ~/overcloud-deploy/*/tripleo-ansible-inventory.yaml ~/config-download/*/tripleo-ansible-inventory.yaml \
  ~/tripleo-ansible-inventory.yaml 2>/dev/null | head -1)
read -r CN CIP CUSR < <(python3 - "$INV" <<'PY'
import sys, yaml
try:
    inv = yaml.safe_load(open(sys.argv[1])) or {}
except Exception:
    inv = {}
for group, body in inv.items():
    for host, hv in ((body or {}).get("hosts") or {}).items() if isinstance(body, dict) else []:
        if "controller" in (group + host).lower() and isinstance(hv, dict):
            print(host.split(".")[0], hv.get("ctlplane_ip") or hv.get("ansible_host") or "-", hv.get("ansible_ssh_user") or "-")
            raise SystemExit
PY
)
[ -n "${CIP:-}" ] && [ "$CIP" != "-" ] || { echo "no controller in the inventory $INV: database not read"; exit 1; }
U="${CUSR:--}"; [ "$U" = "-" ] && U=$(grep -q '17\.' /etc/rhosp-release && echo tripleo-admin || echo heat-admin)
echo "@@controller $CN"
ssh -n -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$U@$CIP" \
  "echo $QB | base64 -d | sudo podman exec -i \$(sudo podman ps -q -f name=galera-bundle | head -1) mysql -N -B"
EOF
)

CLASSIFY=$(cat <<'PY'
import sys
STALE, MINUTES = ("error_attaching", "reserved", "error_detaching", "detached"), 30


def short(h):
    return "" if h in ("", "-", "NULL") else h.split(".")[0].lower()


vols, order, other = {}, [], []
for line in sys.stdin:
    f = line.rstrip("\n").split("\t")
    if f[0] == "@@row" and len(f) == 16:
        if f[1] not in vols:
            vols[f[1]] = []
            order.append(f[1])
        vols[f[1]].append(dict(id=f[2], status=f[3].lower(), host=f[4], connector=f[5], connected=f[6] == "1", server=f[7],
                               minutes=int(f[8]) if f[8].lstrip("-").isdigit() else -1, bdm=f[9], name=f[10], ihost=f[11],
                               vm=f[12], task=f[13], multi=f[14] == "1", changed=f[15]))
    elif line.startswith("@@controller "):
        print("== Database on", line.split()[1], "(SELECT only)")
    elif line.strip() and not line.lstrip().startswith("** "):   # not the SSH client's own warnings
        other.append(line.rstrip())
for line in other[:20]:
    print("  ", line[:300])
auto, manual, multi = [], [], 0
for v in order:
    rows = vols[v]
    if any(r["multi"] for r in rows):
        multi += 1
        continue
    inst = next((r for r in rows if r["bdm"] not in ("", "-")), rows[0])
    nova, host, sid = inst["bdm"], inst["ihost"], inst["server"]
    mine = next((r for r in rows if r["id"] == nova), None)
    why = ""
    if not mine:
        why = "the attachment Nova uses for it is not among them"
    elif mine["status"] != "attached" or (short(mine["host"]) or short(mine["connector"])) != short(host) or not short(host):
        on = short(mine["host"]) or short(mine["connector"]) or "no host"
        why = "the attachment Nova uses (%s) is %s on %s, not attached to %s" % (nova, mine["status"], on, short(host))
    if inst["task"] not in ("-", "", "NULL") and not why:
        why = "the instance has a task running (%s)" % inst["task"]
    lines = []
    for r in rows:
        if r["id"] == nova:
            kind, note = "NOVA  ", "<= Nova uses this one"
        else:
            p = ("it belongs to another instance" if r["server"] != sid else
                 "it is %s" % r["status"] if r["status"] not in STALE else
                 "it has a connection" if r["connected"] else
                 "it is of %s, where the instance runs" % short(host)
                 if short(host) and short(host) in (short(r["host"]), short(r["connector"])) else
                 "it changed %d min ago" % r["minutes"] if r["minutes"] < MINUTES else "")
            kind, note = ("REVIEW", p) if p else ("STALE ", "safe to delete")
            if p and not why:
                why = "attachment %s: %s" % (r["id"], p)
        lines.append("    %s %s %-16s host %-28s connector %-28s %-15s changed %s  %s" % (
            kind, r["id"], r["status"], short(r["host"]) or "-", short(r["connector"]) or "-",
            "connected" if r["connected"] else "never connected", r["changed"], note))
    print("VOLUME %s  instance %s (%s) %s/%s on %s" % (v, inst["name"], sid, inst["vm"], inst["task"], short(host) or "-"))
    print("\n".join(lines))
    if why:
        manual.append((v, inst, why))
        print('  => MANUAL: not deleted automatically: %s. Run the check "Volume connections of an instance" for %s' % (why, sid))
    else:
        stale = [r for r in rows if r["id"] != nova]
        auto.append((v, inst, stale))
        print("  => AUTO: the live / cold migration of the updated portal deletes %d leftover(s) first" % len(stale))
print()
print("== SITE TOTAL: volumes with more than one attachment %d (multiattach, left alone: %d); AUTO %d, MANUAL %d"
      % (len(order), multi, len(auto), len(manual)))
for v, inst, why in manual:
    print("  MANUAL %s (%s) on %s: volume %s: %s" % (inst["name"], inst["server"], short(inst["ihost"]) or "-", v, why))
if auto:
    print("== The AUTO ones by hand, on the director as stack (source ~/overcloudrc), only while the portal is not updated:")
    for v, inst, stale in auto:
        for r in stale:
            print("cinder --os-volume-api-version 3.27 attachment-delete %s   # %s, volume %s, %s" % (r["id"], inst["name"], v, r["status"]))
    print("   then per volume: cinder --os-volume-api-version 3.27 attachment-list --all-tenants --volume-id <volume>"
          " (only Nova's, attached) and openstack volume show <volume> -c status (in-use).")
    print("   Never cinder attachment-show: it prints the CHAP secret.")
PY
)

{
  echo "Read-only, $(date -Is), site $SITE; management host $MGMT_HOST, director $DIR_USER@$DIR_HOST (keys are not printed)"
  printf 'QB=%q\n%s\n' "$QB" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1 | "$PY" -c "$CLASSIFY"
  echo "== exit ${PIPESTATUS[1]}"
} | tee "$OUT"
chown deploy: "$OUT"
echo "Saved: $OUT"
