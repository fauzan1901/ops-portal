"""ONTAP Restore module (/ontap/): restore OpenStack volumes from NetApp ONTAP snapshots, run with Ansible.

Moved from ontap_restore/ (docs/ADR-003). The views, the playbooks (playbooks/), the restore and deletion history
(tables restores, restore_groups, deletions in the portal database) and the page (templates/ontap/index.html,
static/) belong to this module; sign-in, users, module access and the ONTAP service accounts belong to the portal.
"""
from .views import blueprint  # noqa: F401  (importing views registers the module with core.register)
