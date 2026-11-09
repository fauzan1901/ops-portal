"""Prints the APIC address and the service account of one site from the Ops Portal as JSON, for
aci-access-dump.sh: the host from sites.yml and the account of Administration -> Credentials (target apic:<site>).

    sudo -u opsportal env <portal environment> /opt/ops-portal/.venv/bin/python -I portal_credential.py /opt/ops-portal DCB

Run as the portal's own user, so its database and key are only opened by their owner. Changes nothing: it never
creates the credentials key and never writes a credential.
"""
import json
import os
import sys


def main():
    app, site = sys.argv[1], sys.argv[2].strip().upper()
    sys.path.insert(0, app)
    import portal_auth
    import settings
    import sites

    if not os.path.exists(settings.CREDENTIALS_KEY):
        sys.exit(f"The portal credentials key {settings.CREDENTIALS_KEY} does not exist")
    try:
        apic = sites.get(site).get("apic")
    except ValueError as e:
        sys.exit(str(e))
    host = apic.get("host") if isinstance(apic, dict) else apic
    if not host:
        sys.exit(f"Site {site} has no apic entry in {settings.SITES_FILE}")
    row = portal_auth.Store(settings.DB_PATH).credential_rows().get(f"apic:{site}")
    if not row:
        sys.exit(f"The APIC service account of {site} (apic:{site}) is not set on Administration -> Credentials")
    password = portal_auth.Vault(settings.CREDENTIALS_KEY).decrypt(row["secret"])
    print(json.dumps({"host": str(host).strip(), "username": row["username"], "password": password}))


if __name__ == "__main__":
    main()
