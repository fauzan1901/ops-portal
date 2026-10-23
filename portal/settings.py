"""File locations of the Ops Portal. Every path can be overridden from the environment (server and test mode)."""
import os

APP_DIR = os.path.dirname(os.path.abspath(__file__))
ETC_DIR = os.environ.get("PORTAL_ETC", "/etc/ops-portal")
TITLE = "Ops Portal"
SESSION_COOKIE = "ops_portal_sid"

DATA_DIR = os.environ.get("PORTAL_DATA", os.path.join(APP_DIR, "data"))
# One SQLite database for every module: users, activity, service accounts, ACI changes, restores, Operation Automation runs.
DB_PATH = os.environ.get("PORTAL_DB", os.path.join(DATA_DIR, "portal.db"))
SITES_FILE = os.environ.get("PORTAL_SITES") or next(
    (p for p in (os.path.join(ETC_DIR, "sites.yml"), os.path.join(APP_DIR, "sites.yml")) if os.path.exists(p)),
    os.path.join(ETC_DIR, "sites.yml"))
# Sign-in (Active Directory + Duo, see auth.example.yml) and the key that encrypts the service account passwords.
AUTH_FILE = os.environ.get("PORTAL_AUTH", os.path.join(ETC_DIR, "auth.yml"))
CREDENTIALS_KEY = os.environ.get("PORTAL_CREDENTIALS_KEY", os.path.join(ETC_DIR, "credentials.key"))
# Behind nginx: trust X-Forwarded-* of this many proxies (client IP in the logs, HTTPS detection). 0 = direct access.
TRUSTED_PROXIES = int(os.environ.get("PORTAL_TRUSTED_PROXIES", "0"))
