"""File locations and site configuration of the ONTAP Restore module (sites.yml of the portal, shared by every module
and passed to the Ansible playbooks)."""
import os

import sites as portal_sites
import settings

MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
PLAYBOOK_DIR = os.path.join(MODULE_DIR, "playbooks")
DATA_DIR = settings.DATA_DIR
RESTORE_SUFFIX = "-restore"   # same as the playbook default (restore_suffix)


def sites():
    """Sites from sites.yml that have an ONTAP cluster (key `ontap`), in file order. Re-read when the file changes.
    Sites of other modules only (for example only `apic`) are not ONTAP Restore sites."""
    return {name: cfg for name, cfg in portal_sites.sites().items() if isinstance(cfg, dict) and cfg.get("ontap")}
