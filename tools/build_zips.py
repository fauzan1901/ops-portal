#!/usr/bin/env python3
"""Deploy packages for the bastion: aci_webui_deploy.zip, ontap_restore_deploy.zip and portal_deploy.zip.

Contains the application folder (code, deploy/, static/, templates/, docs, playbooks, wheels/) without tests, the local
venv, caches, databases and configuration with secrets. Usage:  python3 tools/build_zips.py [aci_webui] [ontap_restore] [portal]
"""
import fnmatch
import os
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APPS = ("aci_webui", "ontap_restore", "portal")
SKIP_DIRS = {".venv", "__pycache__", ".pytest_cache", "data", "node_modules", ".git", "tests"}
SKIP_FILES = ("*.db", "*.db-shm", "*.db-wal", "*.db-journal", "*.pyc", ".DS_Store", "*.log", "app.pid", "auth.yml", "sites.yml",
              "credentials.key", "*.bak*")


def build(app):
    src = os.path.join(ROOT, app)
    target = os.path.join(ROOT, f"{app}_deploy.zip")
    files = []
    for folder, dirs, names in os.walk(src):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        rel_folder = os.path.relpath(folder, ROOT)
        files.append((folder, rel_folder + "/"))
        for name in sorted(names):
            if not any(fnmatch.fnmatch(name, pattern) for pattern in SKIP_FILES):
                files.append((os.path.join(folder, name), os.path.join(rel_folder, name)))
    tmp = target + ".tmp"
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as z:
        for path, arcname in files:
            if arcname.endswith("/"):
                z.writestr(zipfile.ZipInfo(arcname), "")
            else:
                z.write(path, arcname)
    os.replace(tmp, target)
    print(f"{target}: {sum(1 for _, a in files if not a.endswith('/'))} files, {os.path.getsize(target) // 1024} KiB")


if __name__ == "__main__":
    for name in sys.argv[1:] or APPS:
        if name not in APPS:
            sys.exit(f"Unknown application {name}; use {' or '.join(APPS)}")
        build(name)
