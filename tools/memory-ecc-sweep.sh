#!/usr/bin/env bash
# Read-only: memory errors (ECC) on every compute of a site, the read of the portal check "Memory errors (ECC) on the
# computes" (compute-memory, next package): on each compute, in-band with ipmitool as sosreport does, the BMC event log
# (SEL) entries about memory / ECC, the memory sensors now, the BMC clock and how full the SEL is; the kernel lines of the
# last days about hardware errors (GHES / APEI, EDAC, machine checks, lockups, panics), the EDAC counters, the crash dumps.
# Nothing is changed (the SEL is never cleared). Summarized with the check's own parser (~/compute_memory.py).
# Same path as the portal: portal service account -> management host -> director -> computes (all at once).
# Run on the bastion:  sudo bash ~/memory-ecc-sweep.sh <SITE> [days, default 7] [compute short name]
set -u
SITE="${1:-}"
DAYS="${2:-7}"
ONE="${3:-}"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$DAYS" =~ ^[0-9]{1,2}$ ]] && [ "$DAYS" -ge 1 ] && [ "$DAYS" -le 30 ] || { echo "Days: 1-30"; exit 1; }
[ -z "$ONE" ] || [[ "$ONE" =~ ^[a-z0-9-]{1,63}$ ]] || { echo "Compute: a short name"; exit 1; }
[ -r /home/deploy/compute_memory.py ] || { echo "/home/deploy/compute_memory.py is missing"; exit 1; }
OUT="/home/deploy/memory-ecc-$SITE-$(date +%Y%m%d-%H%M%S).txt"
RAW="$OUT.raw"
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

# the read itself, exactly as the portal check builds it (overcloud.mem_ecc_command)
CMD=$(cat <<'EOF'
echo "@@now $(date -u '+%Y-%m-%d %H:%M:%S')"; echo "@@serial $(sudo -n cat /sys/class/dmi/id/product_serial 2>/dev/null)"; if ! command -v ipmitool >/dev/null 2>&1; then echo '@@noipmi ipmitool is not installed on this node'; elif ! { [ -e /dev/ipmi0 ] || [ -e /dev/ipmi/0 ] || [ -e /dev/ipmidev/0 ]; }; then echo '@@noipmi no IPMI device (/dev/ipmi0): the ipmi_si / ipmi_devintf modules are not loaded'; else echo "@@bmctime $(sudo -n timeout 30 ipmitool sel time get 2>&1 | head -n 1)"; echo "@@bmcip $(sudo -n timeout 30 ipmitool lan print 2>/dev/null | awk -F': *' '/^IP Address  / {print $2; exit}')"; echo @@selinfo; sudo -n timeout 30 ipmitool sel info 2>&1 | grep -E 'Entries|Percent Used|Overflow|Free Space'; echo @@sel; sudo -n timeout 150 ipmitool sel elist 2>/dev/null | grep -E '[Mm]emory|ECC|DIMM' | tail -n 300 | cut -c1-200; echo @@sdr; sudo -n timeout 90 ipmitool sdr type Memory 2>/dev/null | cut -c1-200; fi; echo @@kernel; sudo -n journalctl _TRANSPORT=kernel --since '-DAYSd' --no-pager -q 2>/dev/null | grep -E 'ghes_notify_nmi|Hardware Error|EDAC|mce: |[Mm]achine [Cc]heck|Memory failure|CMCI storm|hard LOCKUP|Kernel panic' | tail -n 200 | cut -c1-250; echo @@edac; grep -H . /sys/devices/system/edac/mc/mc*/ce_count /sys/devices/system/edac/mc/mc*/ue_count 2>/dev/null | head -n 16; echo @@crash; sudo -n ls -1 /var/crash 2>/dev/null | tail -n 8; echo @@end
EOF
)
CMD=${CMD//-DAYSd/-${DAYS}d}

REMOTE=$(cat <<'EOF'
set -u
INV=$(ls ~/overcloud-deploy/*/tripleo-ansible-inventory.yaml ~/config-download/*/tripleo-ansible-inventory.yaml \
  ~/tripleo-ansible-inventory.yaml 2>/dev/null | head -1)
DEFUSR=$(grep -q '17\.' /etc/rhosp-release && echo tripleo-admin || echo heat-admin)
L=$(mktemp /tmp/wi-mem-list.XXXXXX) || exit 1
python3 - "$INV" "$ONE" <<'PY' > "$L"
import sys, yaml
try:
    inv = yaml.safe_load(open(sys.argv[1])) or {}
except Exception:
    inv = {}
one, seen = sys.argv[2], set()
for group, body in inv.items():
    for host, hv in ((body or {}).get("hosts") or {}).items() if isinstance(body, dict) else []:
        name = host.split(".")[0].lower()
        if not isinstance(hv, dict) or name in seen or "compute" not in (group + name).lower():
            continue
        ip = hv.get("ctlplane_ip") or hv.get("ansible_host")
        if (one and name != one) or not ip:
            continue
        seen.add(name)
        print(name, ip, hv.get("ansible_ssh_user") or "-")
PY
T=$(mktemp -d /tmp/wi-mem.XXXXXX) || exit 1
while read -r N IP USR; do
  [ "$IP" = "-" ] && continue
  [ "$USR" = "-" ] && USR=$DEFUSR
  ( ssh -n -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
      "$USR@$IP" "$CMD" > "$T/$N" 2>&1; echo $? > "$T/$N.rc" ) &
done < "$L"
wait
echo "@@@computes $(wc -l < "$L")"
for f in $(ls "$T" | grep -v '\.rc$' | sort); do echo "@@@node $f $(cat "$T/$f.rc")"; cat "$T/$f"; done
rm -rf "$T" "$L"
EOF
)

{
  echo "Read-only, $(date -Is), site $SITE, last $DAYS days${ONE:+, compute $ONE}; director $DIR_USER@$DIR_HOST"
  printf 'CMD=%q\nONE=%q\n%s\n' "$CMD" "$ONE" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1 | grep -v '^\*\* '
} > "$RAW"

"$PY" - "$RAW" "$DAYS" <<'PY' | tee "$OUT"
import importlib.util, re, sys
sys.path.insert(0, "/opt/ops-portal/modules/wi")
import wi_analysis  # noqa: F401  (the package compute_memory belongs to)
spec = importlib.util.spec_from_file_location("wi_analysis.compute_memory", "/home/deploy/compute_memory.py")
cm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cm)
raw, days = open(sys.argv[1]).read(), int(sys.argv[2])
print(raw.splitlines()[0] if raw else "(no output)")
m = re.search(r"^@@@computes (\d+)", raw, re.M)
print(f"{m.group(1) if m else '?'} compute(s) in the inventory")
nodes = re.split(r"^@@@node ", raw, flags=re.M)[1:]
summary = []
for chunk in nodes:
    head, _, body = chunk.partition("\n")
    name, rc = (head.split() + ["?"])[:2]
    if "@@end" not in body:
        print(f"\n== {name}: NOT READ (exit {rc}): {body.strip()[:200]}")
        summary.append((name, "unread"))
        continue
    seen = cm.parse(body)
    res = cm.rate(seen, days)
    info = seen["selinfo"]
    print(f"\n== {name}: {res['status'].upper()}; BMC {seen['bmcip'] or '?'}, serial {seen['serial'] or '?'}; BMC clock {cm.clock(res['offset'])}; SEL "
          + (f"{info.get('Entries', '?')} entries, {info.get('Percent Used', '?')} used" if info else "-")
          + (f"; in-band IPMI not readable: {seen['noipmi']}" if seen["noipmi"] else ""))
    for dimm, d in sorted(res["dimms"].items()):
        print(f"   DIMM {dimm}: " + "; ".join(f"{ev} x{c}" for ev, c in sorted(d["events"].items()))
              + f" ({cm.stamp(d['first'])} .. {cm.stamp(d['last'])}) -> " + ("REPLACE SOON" if d["status"] == "fail" else "watch"))
    for dimm, h in sorted(res.get("history", {}).items()):
        print(f"   DIMM {dimm}: " + "; ".join(f"{ev} x{c}" for ev, c in sorted(h["events"].items()))
              + f" before the window (last {cm.stamp(h['last'])}), nothing since -> earlier: watch")
    for sname, state, k in res["sensors"]:
        print(f"   sensor now {sname}: {state} ({k})")
    k = res["kernel"]
    if any(k[x] for x in ("ghes", "hw", "mce", "edac", "memfail", "lockup", "edac_ce", "edac_ue")) or res["crashes"]:
        print(f"   kernel: GHES NMI too long {k['ghes']} (max {k['ghes_max']:g} ms), hardware error records {k['hw']} "
              f"({k['hw_fatal']} not corrected{', DIMM ' + ', '.join(k['dimms']) if k['dimms'] else ''}), EDAC error lines "
              f"{k['edac']}, CE {k['edac_ce']} UE {k['edac_ue']}, machine checks logged {k['mce']}, "
              f"lockup/panic {k['lockup']}, crash dumps: {', '.join(res['crashes']) or '-'}")
    for note in res["notes"]:
        print(f"   note: {note}")
    # format check of the parser on this hardware: every raw SEL line read, the first sensor lines as printed
    sec = body.split("@@sel\n", 1)[1].split("@@sdr", 1)[0] if "@@sel\n" in body else ""
    lines = [l for l in sec.splitlines() if l.strip()]
    print(f"   parser: {len(seen['sel'])} of {len(lines)} SEL memory line(s) parsed, {len(seen['sdr'])} memory sensor(s)")
    for l in lines[-6:]:
        print(f"     sel> {l[:160]}")
    sdr = body.split("@@sdr", 1)[1].split("@@kernel", 1)[0] if "@@sdr" in body else ""
    for l in [x for x in sdr.splitlines() if x.strip()][:2]:
        print(f"     sdr> {l[:160]}")
    summary.append((name, res["status"]))
print("\n== Summary: " + ", ".join(f"{n} {s}" for n, s in summary))
print("fail = a DIMM at its ECC logging limit / uncorrectable, or kernel signs of a crash; warn = correctable errors, slow "
      "hardware-error NMIs, a full SEL, or IPMI not readable in-band")
PY
chown deploy: "$OUT" "$RAW"
echo "Saved: $OUT (raw: $RAW)"
