#!/usr/bin/env bash
# Read-only look at the bastion before the Ops Portal cutover (run with sudo). Prints no secret: only names,
# roles, counts, table layouts and SHA-256 fingerprints to compare files.
set -uo pipefail
PY=/opt/ontap_restore/.venv/bin/python
db_report() {   # $1 = label, $2 = database
  echo "---- $1 ($2, $(du -h "$2" | cut -f1))"
  $PY - "$2" <<'PYEOF'
import sqlite3, sys
db = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
for t in tables:
    cols = [r[1] for r in db.execute(f"PRAGMA table_info({t})")]
    n = db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
    print(f"  {t}: {n} rows; {', '.join(cols)}")
def show(sql, label):
    try:
        rows = db.execute(sql).fetchall()
    except sqlite3.Error as e:
        print(f"  ({label}: {e})"); return
    print(f"  {label}:")
    for r in rows:
        print("    " + " | ".join("" if v is None else str(v) for v in r))
if "portal_users" in tables:
    cols = [r[1] for r in db.execute("PRAGMA table_info(portal_users)")]
    show(f"SELECT {', '.join(c for c in cols if c in ('username', 'role', 'source', 'modules', 'display_name', 'added_by', 'created', 'last_login'))} FROM portal_users ORDER BY username", "users")
if "portal_local_users" in tables:
    show("SELECT username, role, display_name FROM portal_local_users ORDER BY username", "local accounts (passwords not shown)")
if "service_credentials" in tables:
    cols = [r[1] for r in db.execute("PRAGMA table_info(service_credentials)")]
    keep = [c for c in cols if c not in ("secret", "password", "token")]
    show(f"SELECT {', '.join(keep)} FROM service_credentials ORDER BY 1", "service credentials (secrets not shown)")
PYEOF
}
echo "== databases"
db_report "ACI Web UI" /var/lib/aci_webui/audit.db
db_report "ONTAP Restore" /var/lib/ontap_restore/restore.db
echo
echo "== keys and settings (fingerprints only)"
for f in /etc/aci_webui/credentials.key /etc/ontap_restore/credentials.key /etc/aci_webui/auth.yml /etc/ontap_restore/auth.yml \
         /etc/aci_webui/authproxy-ldap-ca.pem /etc/ontap_restore/authproxy-ldap-ca.pem; do
  printf '  %-45s %s\n' "$f" "$(sha256sum "$f" | cut -c1-16)"
done
echo "  auth.yml keys (values hidden):"
for f in /etc/aci_webui/auth.yml /etc/ontap_restore/auth.yml; do
  $PY - "$f" <<'PYEOF'
import sys, yaml
def walk(d, p=""):
    out = []
    for k, v in (d or {}).items():
        out += walk(v, f"{p}{k}.") if isinstance(v, dict) else [f"{p}{k}"]
    return out
print("   ", sys.argv[1] + ":", ", ".join(walk(yaml.safe_load(open(sys.argv[1])))))
PYEOF
done
echo "  env files (variable names only):"
for f in /etc/aci_webui/aci-webui.env /etc/ontap_restore/ontap-restore.env; do echo "    $f: $(grep -E '^[A-Z_]+=' "$f" | cut -d= -f1 | tr '\n' ' ')"; done
echo "  ontap keys: $(ls /etc/ontap_restore/keys | tr '\n' ' ')"
echo "  sites.yml (ontap) sites: $($PY -c "import yaml; d=yaml.safe_load(open('/etc/ontap_restore/sites.yml')); print({k: sorted(v) for k, v in (d.get('sites') or d).items() if isinstance(v, dict)})")"
echo "  TLS cert (aci):  $(openssl x509 -in /etc/aci_webui/tls/server.crt -noout -subject -enddate -ext subjectAltName 2>/dev/null | tr '\n' ' ')"
ls /etc/ontap_restore/tls >/dev/null 2>&1 && echo "  TLS cert (ontap): $(openssl x509 -in /etc/ontap_restore/tls/server.crt -noout -subject -enddate -ext subjectAltName 2>/dev/null | tr '\n' ' ')"
grep -h ssl_certificate /etc/nginx/sites-available/ontap-restore | sed 's/^/  nginx ontap: /'
echo
echo "== venvs"
for v in /opt/aci_webui/.venv /opt/ontap_restore/.venv; do echo "  $v: $($v/bin/python --version 2>&1); $($v/bin/pip freeze 2>/dev/null | grep -i -E '^(flask|gunicorn|ansible-core|ansible|cryptography|pyyaml|ldap3|requests|pyvmomi)=' | tr '\n' ' ')"; done
echo "  ansible collections (ontap): $(ls /opt/ontap_restore/.venv/lib/python*/site-packages/ansible_collections 2>/dev/null | tr '\n' ' ')"
echo "  /var/lib/ontap_restore: $(ls /var/lib/ontap_restore | tr '\n' ' ')"
echo "  backups timers: $(systemctl list-timers --all 2>/dev/null | grep -E 'aci|ontap' | awk '{print $NF}' | tr '\n' ' ')"
echo
echo "Done (nothing was changed)."
