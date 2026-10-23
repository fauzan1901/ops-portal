"""Ops Portal: one sign-in for every automation module (ACI, ONTAP Restore, Operation Automation). Decision: docs/ADR-003.

/            sign-in, then the modules this account may use; Administration (Users, Credentials, Activity) for admins
/aci/        ACI Web UI module
/ontap/      ONTAP Restore module
/wi/         Operation Automation module (read-only checks from the Knowledge Base work instructions)

Sessions and jobs live in memory: run as a single process (gunicorn --workers 1 --threads 8).
"""
import hashlib
import importlib
import logging
import os

from flask import Flask, jsonify, redirect, render_template
from werkzeug.middleware.proxy_fix import ProxyFix

import settings
from core import PORTAL, modules

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("portal")

app = Flask(__name__)
if settings.TRUSTED_PROXIES:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=settings.TRUSTED_PROXIES, x_proto=settings.TRUSTED_PROXIES)

PORTAL.install(app)   # /api/login, /api/logout, /auth/duo/callback, /auth/sso/*, /api/admin/..., /export/events.csv

# Module order = order of the tiles on the home page and in the application launcher.
# PORTAL_MODULES="wi,ontap" loads only those modules (a site without ACI, or the tests of one module).
MODULE_IDS = ("wi", "ontap", "aci")
_wanted = [m.strip() for m in os.environ.get("PORTAL_MODULES", ",".join(MODULE_IDS)).split(",") if m.strip()]
for _name in [m for m in MODULE_IDS if m in _wanted]:
    app.register_blueprint(importlib.import_module(f"modules.{_name}").blueprint)


def _ui_version():
    """Fingerprint of the portal pages; changes with every new version, so open tabs know they must reload."""
    digest = hashlib.sha256()
    for name in ("static/shell.js", "static/portal.css", "static/switcher.js", "templates/shell.html"):
        with open(os.path.join(app.root_path, name), "rb") as f:
            digest.update(f.read())
    return digest.hexdigest()[:12]


UI_VERSION = _ui_version()


def session_payload():
    """/api/session of the portal: the user, how sign-in works, and the modules (only for a signed-in user)."""
    payload = PORTAL.payload()
    user = payload["user"]
    items = []
    if user:
        for m in modules():
            running = len(m["running_jobs"]()) if m["id"] in user["modules"] else 0
            items.append({"id": m["id"], "title": m["title"], "description": m["description"], "url": m["url"],
                          "icon": m["icon"], "allowed": m["id"] in user["modules"], "running": running})
    return {"ui_version": UI_VERSION, "title": settings.TITLE, **payload, "modules": items}


@app.get("/")
def index():
    return render_template("shell.html", ui_version=UI_VERSION)


@app.get("/admin/")
def admin_page():
    return redirect("/#/users")


@app.get("/api/session")
def session():
    return jsonify(ok=True, **session_payload())


@app.post("/api/keepalive")
def keepalive():
    """Called by open pages while their user is active: keeps the sign-in alive."""
    return jsonify(ok=True, **session_payload())


@app.get("/favicon.ico")
def favicon():
    """Browsers ask for /favicon.ico even when the page names an icon; the portal icon (grid on blue) as SVG."""
    svg = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="3" fill="#0066cc"/>'
           '<path d="M8 8h6v6H8zM18 8h6v6h-6zM8 18h6v6H8zM18 18h6v6h-6z" fill="#fff"/></svg>')
    return svg, 200, {"Content-Type": "image/svg+xml", "Cache-Control": "max-age=86400"}


@app.get("/healthz")
def healthz():
    """For the installer and the updater: running = jobs that a restart would break (the updater waits for them)."""
    return {"status": "ok", "running": sum(len(m["running_jobs"]()) for m in modules())}


if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "8083")), threaded=True)
