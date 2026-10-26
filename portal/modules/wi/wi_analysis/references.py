"""Vendor documentation of the problems the checks find: shown under a recommendation ("Vendor reference") so the engineer
reads what the primary vendor says about it (Red Hat for OpenStack and Pacemaker, Broadcom for vSphere and NSX, Lenovo
and Inspur for their servers).

Every link here was opened and its title checked on 2026-10-11 (Red Hat chunked HTML pages with their anchors, Broadcom
knowledge base articles through their legacy VMware KB number, Lenovo Docs pages of the models listed in LENOVO_MODELS);
a link that could not be verified is not added. A recommendation names the keys: Result.recommend(..., refs=[...]).
"""
import re

URL = re.compile(r"^https://[A-Za-z0-9.-]+\.[a-z]{2,}(/[A-Za-z0-9_\-./%?=&#:+~,;@!]*)?$")
MAX_REFS = 6
RH = "https://docs.redhat.com/en/documentation/red_hat_openstack_platform"
RHEL8_HA = ("https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/"
            "configuring_and_managing_high_availability_clusters")
BKB = "https://knowledge.broadcom.com/external/article"
TECHDOCS_VS8 = "https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/8-0"


def _rh(title, path):
    return {"vendor": "Red Hat", "title": title, "url": f"{RH}/{path}"}


def _bc(title, url):
    return {"vendor": "Broadcom", "title": title, "url": url}


REFS = {
    # ---------------- control plane beyond pcs status (RISET-KNOWN-ISSUES.md, checked 2026-10-25) ----------------
    "rhosp-ovn-raft": [
        _rh("Configuring networking (17.1): working with OVN, the clustered OVN databases",
            "17.1/html/configuring_red_hat_openstack_platform_networking/assembly_work-with-ovn_rhosp-network"),
        {"vendor": "Red Hat", "title": "[OSP 17.1] OVN DB fails to start: remove and recreate the OVN cluster membership (7091792)",
         "url": "https://access.redhat.com/solutions/7091792"},
        {"vendor": "Red Hat", "title": "Bug 2222828: replacing a controller node leads to an OVN database partition",
         "url": "https://bugzilla.redhat.com/show_bug.cgi?id=2222828"},
    ],
    "rhosp-ovn-macbinding": [
        {"vendor": "Red Hat", "title": "neutron-server high memory usage due to OVN mac_binding explosion at scale (6410121)",
         "url": "https://access.redhat.com/node/6410121"},
        _rh("Configuration reference (17.1): [ovn] options", "17.1/html/configuration_reference/_ovn"),
    ],
    "rhosp-rabbitmq-queues": [
        {"vendor": "Red Hat", "title": "OpenStack services slow down while RabbitMQ messages grow without being consumed (2025263)",
         "url": "https://access.redhat.com/solutions/2025263"},
        {"vendor": "Red Hat", "title": "RabbitMQ versioned_notifications.info queue grows with no consumer (3139721)",
         "url": "https://access.redhat.com/solutions/3139721"},
        {"vendor": "RabbitMQ", "title": "Clustering and network partitions", "url": "https://www.rabbitmq.com/docs/3.13/partitions"},
    ],
    "rhosp-galera-connections": [
        {"vendor": "Red Hat", "title": "How to determine the maximum number of connections required for MariaDB (1990433)",
         "url": "https://access.redhat.com/solutions/1990433"},
    ],
    # ---------------- internal certificates (RISET-KNOWN-ISSUES.md, checked 2026-10-25) ----------------
    "vmw-sts": [
        _bc("Checking the STS certificate expiration and replacing expired STS certificates on vCenter Servers (KB 318968)",
            f"{BKB}/318968"),
        _bc("\"Signing certificate is not valid\" or \"No healthy upstream\" when logging in to vCenter (KB 316619)", f"{BKB}/316619"),
        _bc("vSphere Automation API: get the vCenter signing certificate",
            "https://developer.broadcom.com/xapis/vsphere-automation-api/latest/api/vcenter/certificate-management/vcenter/signing-certificate/get/"),
    ],
    "vmw-vcenter-certs": [
        _bc("vCenter services fail to start after the Machine SSL certificate's issuing CA expires (KB 442815)", f"{BKB}/442815"),
        _bc("vCenter Server inaccessible due to expired Solution User certificates (KB 421381)", f"{BKB}/421381"),
        _bc("vCert - Scripted vCenter expired certificate replacement (KB 385107)",
            f"{BKB}/385107/vcert-scripted-vcenter-expired-certific.html"),
    ],
    "vmw-esxi-cert": [
        _bc("\"ESXi Host Certificate Status\" alert (KB 374032)", f"{BKB}/374032/"),
        _bc("ESXi host certificate status remains \"expiration imminent\" after renewal (KB 447355)",
            f"{BKB}/447355/esxi-host-certificate-status-remains-exp.html"),
    ],
    "nsx-certs": [
        _bc("NSX Certificate Expired Alarm (KB 345870)", f"{BKB}/345870/nsx-certificate-expired-alarm.html"),
        _bc("Host and Edge transport nodes Disconnected and MPA Connectivity Down after the APH certificate expires (KB 424553)",
            f"{BKB}/424553"),
        _bc("Alarms indicating CBM certificates have expired prevent NSX Manager upgrades (KB 324175)",
            f"{BKB}/324175/nsx-alarms-indicating-certificates-have.html"),
    ],
    "vcd-certs": [
        _bc("Cloud Director OpenAPI: Certificate Library", "https://developer.broadcom.com/xapis/vmware-cloud-director-openapi/latest/certificate-library/"),
        _bc("Cloud Director OpenAPI: Trusted Certificates", "https://developer.broadcom.com/xapis/vmware-cloud-director-openapi/latest/trusted-certificates/"),
    ],
    "ontap-certs": [
        {"vendor": "NetApp", "title": "How to renew an ONTAP self-signed SSL certificate via command line",
         "url": "https://kb.netapp.com/on-prem/ontap/DM/Encryption/Encryption-KBs/How_to_renew_an_ONTAP_self-signed_SSL_certificate_via_command_line"},
        {"vendor": "NetApp", "title": "ONTAP REST API: retrieve security certificates",
         "url": "https://docs.netapp.com/us-en/ontap-restapi/get-security-certificates.html"},
    ],
    "rhosp-tlse": [
        _rh("Hardening Red Hat OpenStack Platform (17.1): TLS everywhere, manually updating SSL/TLS certificates",
            "17.1/html-single/hardening_red_hat_openstack_platform/index"),
        {"vendor": "Red Hat", "title": "Update expiring SSL certificate in overcloud public endpoints (7088408)",
         "url": "https://access.redhat.com/node/7088408"},
    ],
    "rhosp-undercloud-cert": [
        {"vendor": "Red Hat", "title": "certmonger won't renew undercloud certificate automatically even certificate expired (5508191)",
         "url": "https://access.redhat.com/node/5508191"},
        {"vendor": "Red Hat", "title": "How to change the validity period of the undercloud certificates (7062493)",
         "url": "https://access.redhat.com/node/7062493"},
    ],
    # ---------------- Red Hat OpenStack Platform 16.2 / 17.1 ----------------
    "rhosp-compute-down": [
        _rh("RHOSP 16.2: Troubleshooting Compute node failures",
            "16.2/html/director_installation_and_usage/assembly_troubleshooting-director-errors#sect-Compute_Service_Failures"),
        _rh("RHOSP 17.1: Troubleshooting Compute node failures",
            "17.1/html/installing_and_managing_red_hat_openstack_platform_with_director/assembly_troubleshooting-director-errors"
            "#proc_troubleshooting-compute-node-failures_troubleshooting-director-errors")],
    "rhosp-containers": [
        _rh("RHOSP 16.2: Managing containerized services",
            "16.2/html/director_installation_and_usage/assembly_performing-basic-overcloud-administration-tasks"
            "#proc_managing-containerized-services_performing-basic-overcloud-administration-tasks"),
        _rh("RHOSP 17.1: Managing containerized services",
            "17.1/html/installing_and_managing_red_hat_openstack_platform_with_director/assembly_performing-basic-overcloud-"
            "administration-tasks#proc_managing-containerized-services_performing-basic-overcloud-administration-tasks")],
    "rhosp-evacuate": [
        _rh("RHOSP 16.2: Evacuating an instance",
            "16.2/html/configuring_the_compute_service_for_instance_creation/assembly_managing-instances_managing-instances"
            "#con_evacuating-an-instance_migrating-instances"),
        _rh("RHOSP 17.1: Evacuating an instance",
            "17.1/html/configuring_the_compute_service_for_instance_creation/assembly_migrating-virtual-machine-instances-"
            "between-compute-nodes_migrating-instances#con_evacuating-an-instance_migrating-instances")],
    "rhosp-pcs-resource": [
        _rh("RHOSP 16.2: Investigating Pacemaker resource problems",
            "16.2/html/high_availability_deployment_and_usage/assembly_troubleshooting-ha-resources_rhosp"
            "#proc_investigating-pacemaker-resources_ha-troubleshooting"),
        _rh("RHOSP 17.1: Investigating Pacemaker resource problems",
            "17.1/html/managing_high_availability_services/assembly_troubleshooting-ha-resources_ext-lb-example"
            "#proc_investigating-pacemaker-resources_ha-troubleshooting")],
    "rhosp-cinder-ha": [
        _rh("RHOSP 16.2: High availability of the Block Storage volume service",
            "16.2/html/storage_guide/assembly-configuring-the-block-storage-service_osp-storage-guide"
            "#con-active-active-block-storage-for-high-availability_configuring-cinder"),
        _rh("RHOSP 17.1: High availability of the Block Storage volume service",
            "17.1/html/configuring_persistent_storage/assembly_configuring-the-block-storage-service_osp-storage-guide"
            "#con-active-active-block-storage-for-high-availability_configuring-cinder")],
    "rhosp-ovn": [
        _rh("RHOSP 16.2: Troubleshooting networks (ML2/OVN)", "16.2/html/networking_guide/neutron-troubleshoot_rhosp-network"),
        _rh("RHOSP 17.1: Monitoring and troubleshooting networks",
            "17.1/html/configuring_red_hat_openstack_platform_networking/neutron-troubleshoot_rhosp-network"),
        _rh("RHOSP 16.2: The ovn-controller service on Compute nodes",
            "16.2/html/networking_guide/assembly_work-with-ovn_rhosp-network#ovn-controller-on-compute-nodes_work-ovn"),
        _rh("RHOSP 17.1: The ovn-controller service on Compute nodes",
            "17.1/html/configuring_red_hat_openstack_platform_networking/assembly_work-with-ovn_rhosp-network"
            "#ovn-controller-on-compute-nodes_work-ovn")],
    "rhosp-ovn-metadata": [
        _rh("RHOSP 16.2: OVN metadata agent on Compute nodes",
            "16.2/html/networking_guide/assembly_work-with-ovn_rhosp-network#ovn-metadata-agent-on-compute-nodes_work-ovn"),
        _rh("RHOSP 17.1: OVN metadata agent on Compute nodes",
            "17.1/html/configuring_red_hat_openstack_platform_networking/assembly_work-with-ovn_rhosp-network"
            "#ovn-metadata-agent-on-compute-nodes_work-ovn")],
    "rhosp-floating-ip": [
        _rh("RHOSP 16.2: Managing floating IP addresses", "16.2/html/networking_guide/manage-float-ip_rhosp-network"),
        _rh("RHOSP 17.1: Managing floating IP addresses",
            "17.1/html/configuring_red_hat_openstack_platform_networking/manage-float-ip_rhosp-network"),
        _rh("RHOSP 16.2 CLI: ip availability list", "16.2/html/command_line_interface_reference/ip#ip_availability_list")],
    "rhosp-ironic-power": [
        _rh("RHOSP 16.2: Configuring automatic power fault recovery",
            "16.2/html/bare_metal_provisioning/administering-bare-metal-nodes#configuring-automatic-power-fault-recovery_administering-bare-metal"),
        _rh("RHOSP 17.1: Configuring automatic power fault recovery",
            "17.1/html/configuring_the_bare_metal_provisioning_service/administering-bare-metal-nodes"
            "#configuring-automatic-power-fault-recovery_administering-bare-metal")],
    "rhosp-ironic-troubleshoot": [
        _rh("RHOSP 16.2: Troubleshooting the Bare Metal Provisioning service",
            "16.2/html/bare_metal_provisioning/troubleshooting-the-bare-metal-provisioning-service"),
        _rh("RHOSP 17.1: Troubleshooting the Bare Metal Provisioning service",
            "17.1/html/configuring_the_bare_metal_provisioning_service/troubleshooting-the-bare-metal-provisioning-service")],
    "rhosp-fencing": [
        _rh("RHOSP 16.2: Fencing Controller nodes with STONITH",
            "16.2/html/high_availability_deployment_and_usage/assembly_fencing-controller-nodes_rhosp"),
        _rh("RHOSP 17.1: Fencing Controller nodes with STONITH",
            "17.1/html/managing_high_availability_services/assembly_fencing-controller-nodes_rhosp"),
        {"vendor": "Red Hat", "title": "RHEL 8: Testing a fence device",
         "url": f"{RHEL8_HA}/assembly_configuring-fencing-configuring-and-managing-high-availability-clusters#proc_testing-fence-devices-configuring-fencing"},
        {"vendor": "Red Hat", "title": "Support policies for RHEL High Availability: fencing / STONITH",
         "url": "https://access.redhat.com/articles/2881341"}],
    "rhosp-galera": [
        _rh("RHOSP 16.2: Managing database replication with Galera",
            "16.2/html/high_availability_deployment_and_usage/assembly_managing-db-replication-with-galera_rhosp"),
        _rh("RHOSP 17.1: Managing database replication with Galera",
            "17.1/html/managing_high_availability_services/assembly_managing-db-replication-with-galera_ext-lb-example")],
    "rhosp-bundles": [
        _rh("RHOSP 16.2: Checking bundle status in a high availability cluster",
            "16.2/html/high_availability_deployment_and_usage/assembly_managing-ha-services-with-pacemaker_rhosp"
            "#proc_checking-bundle-status_pacemaker"),
        _rh("RHOSP 17.1: Checking bundle status in a high availability cluster",
            "17.1/html/managing_high_availability_services/assembly_managing-ha-services-with-pacemaker_rhosp"
            "#proc_checking-bundle-status_pacemaker")],
    "rhosp-fence-daemons": [
        _rh("RHOSP 16.2: Checking fencing agent and Pacemaker daemon status",
            "16.2/html/high_availability_deployment_and_usage/assembly_managing-ha-services-with-pacemaker_rhosp"
            "#proc_checking-fencing-daemons-status_pacemaker"),
        _rh("RHOSP 17.1: Checking fencing agent and Pacemaker daemon status",
            "17.1/html/managing_high_availability_services/assembly_managing-ha-services-with-pacemaker_rhosp"
            "#proc_checking-fencing-daemons-status_pacemaker")],
    "rhel-pcs-cleanup": [
        {"vendor": "Red Hat", "title": "RHEL 8: Clearing failure status of cluster resources",
         "url": f"{RHEL8_HA}/assembly_managing-cluster-resources-configuring-and-managing-high-availability-clusters"
                "#proc_cleanup-cluster-resources-managing-cluster-resources"}],
    "rhosp-remove-compute": [
        _rh("RHOSP 16.2: Removing a Compute node manually",
            "16.2/html/director_installation_and_usage/assembly_scaling-overcloud-nodes#proc_removing-a-compute-node-manually_scaling-overcloud-nodes"),
        _rh("RHOSP 17.1: Removing a Compute node manually",
            "17.1/html/installing_and_managing_red_hat_openstack_platform_with_director/assembly_scaling-overcloud-nodes"
            "#proc_removing-compute-node-manually_scaling-overcloud-nodes")],
    "rhosp-cinder-manage": [
        _rh("RHOSP 16.2: Cleaning up after Controller node replacement (cinder-manage service remove)",
            "16.2/html/director_installation_and_usage/assembly_replacing-controller-nodes#cleaning-up-after-the-controller-node-replacement"),
        _rh("RHOSP 17.1: Cleaning up after Controller node replacement (cinder-manage service remove)",
            "17.1/html/installing_and_managing_red_hat_openstack_platform_with_director/assembly_replacing-controller-nodes"
            "#proc_cleaning-up-after-controller-node-replacement_replacing-controller-nodes")],
    # Checked 2026-10-19: migration constraints, live / cold migration, server migration abort / force complete.
    "rhosp-migration": [
        _rh("RHOSP 17.1: Migrating virtual machine instances between Compute nodes",
            "17.1/html/configuring_the_compute_service_for_instance_creation/assembly_migrating-virtual-machine-instances-"
            "between-compute-nodes_migrating-instances")],
    # Checked 2026-10-19: sos report --batch --case-id, the archive name, attaching it to the case (RHEL 9 = RHOSP 17.1 nodes).
    "rh-sos-report": [{"vendor": "Red Hat", "title": "RHEL 9: Generating an sos report for technical support",
                       "url": "https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/getting_the_most_from_"
                              "your_support_experience/generating-an-sos-report-for-technical-support_getting-the-most-from-"
                              "your-support-experience"}],
    "nova-live-migration": [{"vendor": "OpenStack", "title": "Nova (Wallaby): Live-migrate instances (progress, abort, force-complete)",
                             "url": "https://docs.openstack.org/nova/wallaby/admin/live-migration-usage.html"}],
    "cinder-migration": [{"vendor": "OpenStack", "title": "Cinder: Migrate volumes (volumes with snapshots cannot migrate)",
                          "url": "https://docs.openstack.org/cinder/2023.1/admin/volume-migration.html"}],
    # ---------------- Broadcom: vSphere ----------------
    "vmw-apd-pdl": [_bc("KB 2004684: Permanent Device Loss (PDL) and All-Paths-Down (APD) on ESXi host", f"{BKB}?legacyId=2004684")],
    "vmw-vmfs-heartbeat": [_bc("KB 2136081: Understanding lost access to volume messages in ESXi", f"{BKB}?legacyId=2136081")],
    "vmw-latency": [_bc("KB 2007236: Device latency with 'performance has deteriorated' messages", f"{BKB}?legacyId=2007236")],
    "vmw-snapshots": [_bc("KB 1025279: Best practices for using VMware snapshots", f"{BKB}?legacyId=1025279")],
    "vmw-consolidate": [_bc("KB 1002310: Consolidating / committing snapshots in ESXi", f"{BKB}?legacyId=1002310"),
                        _bc("\"Virtual Machine Consolidation Needed\" in the vSphere Client", f"{BKB}/414589")],
    "vmw-host-not-responding": [_bc("KB 1003409: ESXi host not responding or disconnected", f"{BKB}?legacyId=1003409")],
    "vmw-uplink": [_bc("Network uplink redundancy lost due to vmnic down",
                       f"{BKB}/426494/network-uplink-redundancy-lost-due-to-vm.html"),
                   _bc("\"Network uplink redundancy lost\" alert is not cleared when the link is up",
                       f"{BKB}/301538/network-uplink-redundancy-lost-alert-is.html")],
    "vmw-ha": [_bc("KB 2004429: Troubleshooting vSphere High Availability (HA) issues", f"{BKB}?legacyId=2004429"),
               _bc("vSphere 8: Troubleshooting vSphere HA host states",
                   f"{TECHDOCS_VS8}/vcenter-and-host-management/troubleshooting-overview-host-management/troubleshooting-hosts-host-"
                   "management/troubleshooting-vsphere-ha-host-states-host-management.html")],
    "vmw-hardware": [_bc("vSphere 8: Monitoring host health status",
                         f"{TECHDOCS_VS8}/vsphere-monitoring-and-performance/monitoring-host-health-status.html")],
    "vmw-alarms": [_bc("vSphere 8: Preconfigured vSphere alarms",
                       f"{TECHDOCS_VS8}/vsphere-monitoring-and-performance/monitoring-events-and-alarms/preconfigured-vsphere-alarms.html")],
    # ---------------- Broadcom: NSX ----------------
    "nsx-event-catalog": [
        _bc("NSX Event Catalog (events, alarms and recommended actions, 3.0 to 4.2)",
            "https://techdocs.broadcom.com/content/dam/broadcom/techdocs/us/en/dita/vmware/nsx/shared-content/PDF/NSX_Event_Catalog.pdf"),
        _bc("NSX 4.2: Working with events and alarms",
            "https://techdocs.broadcom.com/us/en/vmware-cis/nsx/vmware-nsx/4-2/administration-guide/system-monitoring/working-with-events-and-alarms.html")],
    # ---------------- Lenovo (any model) and Inspur ----------------
    "lenovo-bmc": [{"vendor": "Lenovo", "title": "XClarity Controller: viewing event logs", "url": "https://pubs.lenovo.com/xcc/event_log"},
                   {"vendor": "Lenovo", "title": "XClarity Controller 2: viewing event logs", "url": "https://pubs.lenovo.com/xcc2/event_log"}],
    "inspur-bmc": [{"vendor": "Inspur", "title": "Inspur Server BMC User Manual V2.7 (PDF: System Event Log, SEL)",
                    "url": "https://en.inspur.com/eportal//fileDir/active_download/platformBookZh/6680/"
                           "Inspur%C2%A0Server%C2%A0BMC%C2%A0User%C2%A0Manual%C2%A0V2.7.pdf"}],
}
REFS["nsx-cluster"] = REFS["nsx-event-catalog"]
REFS["nsx-transport-node"] = REFS["nsx-event-catalog"]

# Lenovo Docs pages per server model (verified): the problem pages per component and the list of XClarity Controller
# events of the model (every event ID, e.g. FQXSPMA2010N, has its message and user action there).
LENOVO_MODELS = {
    "sr650-v2": {"memory": "memory_problems", "power": "power_problems", "cooling": "observable_problems",
                 "other": "troubleshooting_by_symptom", "storage": "troubleshooting_by_symptom", "cpu": "troubleshooting_by_symptom",
                 "events": "xcc_error_messages"},
    "sr630-v2": {"memory": "memory_problems", "power": "power_problems", "cooling": "observable_problems",
                 "other": "observable_problems"},
    "sr650-v3": {"memory": "memory_problems_rack_tower", "power": "power_problems_rack_tower",
                 "cooling": "observable_problems_rack_tower", "other": "observable_problems_rack_tower", "events": "xcc_error_messages"},
}
PAGE_TITLES = {"memory_problems": "Memory problems", "power_problems": "Power problems", "observable_problems": "Observable problems",
               "troubleshooting_by_symptom": "Troubleshooting by symptom", "memory_problems_rack_tower": "Memory problems",
               "power_problems_rack_tower": "Power problems", "observable_problems_rack_tower": "Observable problems"}


def lenovo_slug(model):
    """'ThinkSystem SR650 V2' -> 'sr650-v2' ('' when the model is not recognised)."""
    m = re.search(r"\b(s[rdt]\d{3}[a-z]?)(?:\s*(v\d))?\b", str(model or ""), re.I)
    if not m:
        return ""
    return m.group(1).lower() + (f"-{m.group(2).lower()}" if m.group(2) else "")


def lenovo(model, component, event_ids=()):
    """References of a Lenovo server finding: the model's page for the component and its list of XCC events (naming the
    event IDs to look up), when the model's pages are known; always the XCC event log pages."""
    slug = lenovo_slug(model)
    pages = LENOVO_MODELS.get(slug) or {}
    out = []
    if pages.get(component):
        page = pages[component]
        out.append({"vendor": "Lenovo", "title": f"ThinkSystem {slug.upper().replace('-', ' ')}: {PAGE_TITLES.get(page, page)}",
                    "url": f"https://pubs.lenovo.com/{slug}/{page}"})
    if pages.get("events"):
        ids = ", ".join(sorted(set(i for i in event_ids if re.fullmatch(r"FQX[A-Z0-9]{6,12}", str(i))))[:4])
        out.append({"vendor": "Lenovo", "title": f"XClarity Controller events of the {slug.upper().replace('-', ' ')}"
                                                 + (f" (look up {ids})" if ids else ""),
                    "url": f"https://pubs.lenovo.com/{slug}/xcc_error_messages"})
    return out + REFS["lenovo-bmc"]


def resolve(refs):
    """[{"vendor", "title", "url"}] of the keys (or ready items), without duplicates; unknown keys are skipped."""
    out, seen = [], set()
    for ref in refs or []:
        items = REFS.get(ref, []) if isinstance(ref, str) else [ref] if isinstance(ref, dict) else []
        for item in items:
            url = str(item.get("url") or "")
            if not URL.match(url) or url in seen or not item.get("vendor") or not item.get("title"):
                continue
            seen.add(url)
            out.append({"vendor": str(item["vendor"]), "title": str(item["title"]), "url": url})
    return out[:MAX_REFS]
