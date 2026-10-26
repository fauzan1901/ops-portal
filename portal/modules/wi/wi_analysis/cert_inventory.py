"""Internal certificates (RISET-KNOWN-ISSUES.md 1 #2, 2.2 #5, 2.5 #7, 2.6 #1-3, 2.7 #8, 2.8 #5-6): the certificates the check
"Certificates expiring" (cert-expiry) cannot see, because no service presents them on port 443.

cert-inventory (Acme Prime and ONTAP, REST GET and the vCenter inventory with the read-only accounts of the site):
- vCenter: the STS signing certificate (it signs the token of every login: expired = nobody logs in, KB 318968), the
  Machine SSL certificate and the trusted root certificates (vpxd stops once the CA that issued Machine SSL expires);
- the certificate of every ESXi host, with vCenter's own status of it;
- NSX-T Manager: the trust store with the services that use each certificate (APH, cluster, transport nodes);
- vCloud Director: the certificate library (the consumers of those that expire) and the trusted certificates, compared
  with the certificate vCenter and NSX-T present now (an older one still trusted after a renewal: "PKIX path building
  failed");
- ONTAP: the certificates of the cluster and the SVMs (ONTAP makes its server certificates self-signed for a year).
Each system without an account is skipped. Acme Prime stays read-only: the results give the procedure and the vendor
documentation, never a fix.

certmonger-status (Acme Flex, through the director as the other overcloud checks): `getcert list` on the director and
on the overcloud nodes (TLS everywhere with IdM): only MONITORING is healthy; CA_UNREACHABLE means the certificate will
not be renewed. Fix (Run this fix, permission run OpenStack fixes): the operator ticks the requests of the nodes to
resubmit, one at a time, each followed until certmonger monitors its new certificate (wi_ops.py getcert-resubmit); the
director's own requests stay commands for an engineer.
"""
import datetime
import re
import time

from . import overcloud
from .certs import target
from .common import Result, json_of, source, unavailable, worst
from .openstack import os_select
from .overcloud_checks import inventory

VC = "/api/vcenter/certificate-management/vcenter"
ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,120}$")
PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----")
# certmonger prints the expiry in the zone of the machine ("... UTC", "... WIB", "... +07"): a zone name other than
# UTC/GMT is read as UTC (off by hours at most, not days)
DATE_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2}))?(?:\.\d+)?)?\s*"
                     r"(Z|UTC|GMT|([+-])(\d{2})(?::?(\d{2}))?|[A-Za-z]{2,6})?$")
STS_WARN, STS_FAIL = 180, 30   # KB 318968: replace the STS signing certificate when less than 6 months are left
MAX_CHAINS, MAX_CONSUMERS, MAX_NODES = 30, 20, 24
# server / client certificates of the cluster and SVMs are rated; server_ca (the public CAs ONTAP ships with), client_ca and
# root_ca are trust anchors: listed when they expire, not rated
RATED_ONTAP = ("server", "client")
ESXI_STATUS = {"expired": "fail", "expirationImminent": "fail", "revoked": "fail", "expiringShortly": "warn", "expiring": "warn"}
BAD_GETCERT = ("CA_UNREACHABLE", "CA_REJECTED", "NEED_GUIDANCE", "CA_UNCONFIGURED", "NEED_CA")
REQUEST_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")   # a certmonger request ID the fix may name (as wi_ops.py)
COLUMNS = ["Certificate", "Subject", "Issuer", "Expires", "Days left", "Status"]


# ---------------------------------------------------------------- dates, PEM
def thresholds(params):
    warn = int(params["warn_days"]) if params.get("warn_days") is not None else 30
    fail = int(params["fail_days"]) if params.get("fail_days") is not None else 7   # 0 is a valid choice
    return warn, fail


def now_of(ctx):
    """The start of the run (the same in every phase), as an aware datetime."""
    return datetime.datetime.fromtimestamp(int(ctx.get("now") or time.time()), datetime.timezone.utc)


def when(value):
    """An expiry as the systems write it (ISO 8601 with Z, an offset or ' UTC'; epoch seconds or milliseconds) -> an aware
    datetime in UTC, or None."""
    if isinstance(value, datetime.datetime):
        return value if value.tzinfo else value.replace(tzinfo=datetime.timezone.utc)
    if isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0:
        try:
            return datetime.datetime.fromtimestamp(value / 1000 if value > 10 ** 11 else value, datetime.timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value or "").strip()
    if text.isdigit():
        return when(int(text))
    m = DATE_RE.match(text)
    if not m:
        return None
    y, mo, d, h, mi, sec = (int(x or 0) for x in m.groups()[:6])
    offset = datetime.timedelta(0)
    if m.group(8):
        offset = datetime.timedelta(hours=int(m.group(9)), minutes=int(m.group(10) or 0)) * (1 if m.group(8) == "+" else -1)
    try:
        return datetime.datetime(y, mo, d, h, mi, sec, tzinfo=datetime.timezone.utc) - offset
    except ValueError:
        return None


def days_left(after, now):
    return None if after is None else int((after - now).total_seconds() // 86400)


def rate(days, warn, fail):
    """'fail' (expired or within the fail days), 'warn' (within the warn days), 'ok'; 'info' when the expiry is unknown."""
    if days is None:
        return "info"
    return "fail" if days <= fail else "warn" if days <= warn else "ok"


def label(status, days):
    if days is not None and days < 0:
        return "EXPIRED"
    return {"fail": "FAIL", "warn": "WARN", "ok": "OK", "info": "UNKNOWN"}.get(status, str(status).upper())


def day(after):
    return after.strftime("%Y-%m-%d") if after else "-"


def cn(dn):
    """The common name of a distinguished name ('CN=a,O=b' or 'C=US, CN=a'), else the name itself."""
    m = re.search(r"(?:^|[,/]\s*)CN=([^,/]+)", str(dn or ""))
    return m.group(1).strip() if m else str(dn or "").strip()


def name_of(name):
    from cryptography.x509.oid import NameOID
    found = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(found[0].value) if found else name.rfc4514_string()


def pem_certs(text):
    """Every certificate of a PEM text: [{"subject", "issuer", "not_after", "self_signed", "ca", "sha256"}] ([] without a
    readable certificate, or without the cryptography package)."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
    except ImportError:
        return []
    out = []
    for block in PEM_RE.findall(str(text or "")):
        try:   # one malformed certificate (or extension) is skipped, never the whole check
            cert = x509.load_pem_x509_certificate(block.encode())
            after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
            item = {"subject": name_of(cert.subject), "issuer": name_of(cert.issuer), "not_after": after,
                    "self_signed": cert.subject == cert.issuer, "sha256": cert.fingerprint(hashes.SHA256()).hex(),
                    "subject_dn": cert.subject.rfc4514_string(), "issuer_dn": cert.issuer.rfc4514_string(), "ski": "", "aki": ""}
        except Exception:
            continue
        for field, ext in (("ski", x509.SubjectKeyIdentifier), ("aki", x509.AuthorityKeyIdentifier)):
            try:   # key identifiers: which CA issued which certificate (every VMCA root is named CN=CA)
                value = cert.extensions.get_extension_for_class(ext).value
                key = value.digest if field == "ski" else value.key_identifier
                item[field] = key.hex() if key else ""
            except Exception:
                pass
        out.append(item)
    return out


def issued_by(cert, ca):
    """Did ca issue cert: by the key identifiers when both carry them, else by the full names."""
    if cert.get("aki") and ca.get("ski"):
        return cert["aki"] == ca["ski"]
    return bool(cert.get("issuer_dn")) and cert.get("issuer_dn") == ca.get("subject_dn")


def pems(value):
    """The PEM texts of a chain as the vCenter API gives it: {"cert_chain": [...]}, [{"cert_chain": [...]}] or [...]."""
    if isinstance(value, dict):
        return pems(value.get("cert_chain"))
    if isinstance(value, list):
        out = []
        for v in value:
            out.extend(pems(v) if isinstance(v, (dict, list)) else [str(v)])
        return out
    return [str(value)] if value else []


def listed(item, *keys):
    """The list of a REST answer: the first of keys that holds one (results, values, records), or the answer itself."""
    data = json_of(item)
    if isinstance(data, dict):
        return next((data[k] for k in keys if isinstance(data.get(k), list)), [])
    return data if isinstance(data, list) else []


def by_days(rows, col=4):
    return sorted(rows, key=lambda x: x[col] if isinstance(x[col], int) else 10 ** 6)


# ---------------------------------------------------------------- Acme Prime and ONTAP
class CertInventory:
    """Internal certificates of vCenter (STS signing, Machine SSL, trusted roots), the ESXi hosts, NSX-T Manager, vCloud
    Director (library, trusted certificates) and ONTAP, with the days left."""
    sources = ("vcenter", "vsphere", "nsxt", "vcd", "ontap", "tls")
    phases = 2
    # where each step is read (the diagram "Where it was checked"); the overview belongs to none
    at = {"overview": [], "sts": ["vcenter"], "vctrust": ["vcenter"], "esxi": ["vsphere"], "nsx": ["nsxt"], "vcdlib": ["vcd"],
          "vcdtrust": ["vcd", "tls"], "ontap": ["ontap"]}

    @staticmethod
    def live(ctx):
        """The systems vCloud Director connects to, whose present certificate is read (TLS, no account)."""
        return [(n, t) for n, t in (("vCenter", target(ctx.get("vcenter_host"))), ("NSX-T Manager", target(ctx.get("nsxt_host")))) if t]

    @staticmethod
    def chains(data):
        return [str(c["chain"]) for c in listed(source(data, "roots"))
                if isinstance(c, dict) and ID_RE.match(str(c.get("chain") or ""))][:MAX_CHAINS]

    @staticmethod
    def expiring_library(data, params, ctx):
        """The certificate library items that expire within the warning days (their consumers are read in phase 2)."""
        warn, _fail = thresholds(params)
        now, out = now_of(ctx), []
        for x in listed(source(data, "library"), "values"):
            certs = pem_certs(x.get("certificate")) if isinstance(x, dict) else []
            d = days_left(certs[0]["not_after"], now) if certs else None
            if d is not None and d <= warn and ID_RE.match(str(x.get("id") or "")):
                out.append(x)
        return out[:MAX_CONSUMERS]

    @staticmethod
    def reads(phase, data, params, ctx):
        if phase == 1:
            return {"vcenter": {"sts": f"{VC}/signing-certificate", "mssl": f"{VC}/tls", "roots": f"{VC}/trusted-root-chains"},
                    "vsphere": {"esx": "hostcerts"},
                    "nsxt": {"nsx": "/api/v1/trust-management/certificates?details=true"},
                    "vcd": {"library": "/cloudapi/1.0.0/ssl/certificateLibrary?pageSize=128",
                            "trusted": "/cloudapi/1.0.0/ssl/trustedCertificates?pageSize=128"},
                    "ontap": {"ontap": "/api/security/certificates?fields=name,svm.name,type,common_name,expiry_time,scope"
                                       "&max_records=1000", "cluster": "/api/cluster?fields=name"},
                    "tls": {f"live_{i}": t for i, (_n, t) in enumerate(CertInventory.live(ctx))}}
        out = {}
        chains = CertInventory.chains(data)
        if chains:
            out["vcenter"] = {f"root_{i}": f"{VC}/trusted-root-chains/{c}" for i, c in enumerate(chains)}
        library = CertInventory.expiring_library(data, params, ctx)
        if library:
            out["vcd"] = {f"consumers_{i}": f"/cloudapi/1.0.0/ssl/certificateLibrary/{x['id']}/consumers" for i, x in enumerate(library)}
        return out

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("cert-inventory")
        warn, fail = thresholds(params)
        now = now_of(ctx)
        overview = [part(r, data, params, ctx, now, warn, fail)
                    for part in (_sts, _vcenter_trust, _esxi, _nsx, _vcd_library, _vcd_trust, _ontap)]
        rows = []
        for system, key, found in overview:
            st = next((s for s in r.steps if s["key"] == key), None)
            if not found or not st or st["status"] == "skip":
                rows.append([system, "-", "-", "-", "NOT READ", (st or {}).get("detail", "")[:140]])
                continue
            count, soonest, days = found
            rows.append([system, count, day(soonest), days if days is not None else "-",
                         {"fail": "FAIL", "warn": "WARN", "ok": "OK", "info": "LISTED"}.get(st["status"], st["status"].upper()), ""])
        read = [x for x in rows if x[4] != "NOT READ"]
        columns = ["System", "Certificates", "Soonest expiry", "Days left", "Status", "Note"]
        if len(read) == len(rows):   # the note says why a system was not read: no column without one
            columns, rows = columns[:-1], [x[:-1] for x in rows]
        r.steps.insert(0, {"key": "overview", "title": "Overview per system", "status": "info", "open": True,
                           "detail": f"{len(read)} of {len(rows)} certificate store(s) read; thresholds: STS {STS_WARN} / {STS_FAIL} "
                                     f"days (Broadcom KB 318968), the others {warn} / {fail} days. The certificate each system "
                                     "presents on port 443 is the check \"Certificates expiring\".",
                           "table": {"columns": columns, "rows": rows, "more": 0}})
        return r.done()


def _sts(r, data, params, ctx, now, warn, fail):
    system, key = "vCenter STS signing", "sts"
    title = "vCenter STS signing certificate"
    vc = ctx.get("vcenter_host") or "<vCenter>"
    item = source(data, "sts")
    if unavailable(item):
        why = unavailable(item)
        r.step(key, title, "skip", "This vCenter has no API for it (vSphere 7.0 Update 3 and later): check the STS certificate with "
               "checksts.py of Broadcom KB 318968 on the appliance." if why.startswith("HTTP 404") else f"Not read: {why}")
        return system, key, None
    info = json_of(item) or {}
    active = [c for p in pems(info.get("active_cert_chain"))[:1] for c in pem_certs(p)]
    others = []
    for chain in info.get("signing_cert_chains") or []:
        leaf = [c for p in pems(chain)[:1] for c in pem_certs(p)]
        if leaf and not any(leaf[0]["sha256"] == a["sha256"] for a in active + others):
            others.append(leaf[0])
    if not active and others:
        active, others = others[:1], others[1:]
    if not active:
        r.step(key, title, "warn", "vCenter answered without a signing certificate that could be read: check it with checksts.py of "
               "Broadcom KB 318968 on the appliance.")
        return system, key, None
    c = active[0]
    d = days_left(c["not_after"], now)
    st = rate(d, STS_WARN, STS_FAIL)
    rows = [["Active (signs every login token)", c["subject"], c["issuer"], day(c["not_after"]), d, label(st, d)]]
    for o in others:
        od = days_left(o["not_after"], now)
        rows.append(["Other signing chain (validates older tokens)", o["subject"], o["issuer"], day(o["not_after"]), od,
                     "EXPIRED" if od is not None and od < 0 else "listed"])
    r.step(key, title, st,
           (f"Expires on {day(c['not_after'])}: {d} day(s) left, more than {STS_WARN}." if st == "ok" else
            f"Expires on {day(c['not_after'])}: {d} day(s) left. Broadcom advises replacing it when less than 6 months are left: "
            "once it expires nobody can log in to vCenter (\"Signing certificate is not valid\"), nor to the vCenters linked to it."),
           {"columns": COLUMNS, "rows": rows}, marks=[c["subject"]] if st != "ok" else None)
    if st != "ok":
        r.recommend(f"The STS signing certificate of vCenter expires in {d} day(s): after that every login fails (vSphere Client, "
                    "vCloud Director, the portal), on every vCenter linked to it. Replace it through a change request with the "
                    "scripts of Broadcom KB 318968, on the appliance as root.",
                    ["python checksts.py   # KB 318968: the STS certificates and when they expire",
                     "./fixsts.sh   # KB 318968: a new STS signing certificate",
                     "service-control --stop --all && service-control --start --all   # then restart every service"],
                    warning="Take an offline snapshot of the vCenter (of every vCenter linked to it) first. Acme Prime stays "
                            "read-only from the portal: an engineer runs this.",
                    where=f"{vc}, SSH as root (appliance shell)", refs=["vmw-sts"])
    return system, key, (len(rows), c["not_after"], d)


def _vcenter_trust(r, data, params, ctx, now, warn, fail):
    system, key = "vCenter Machine SSL and roots", "vctrust"
    title = "vCenter Machine SSL and trusted roots"
    vc = ctx.get("vcenter_host") or "<vCenter>"
    mssl_item, roots_item = source(data, "mssl"), source(data, "roots")
    if unavailable(mssl_item) and unavailable(roots_item):
        r.step(key, title, "skip", f"Not read: {unavailable(roots_item)}")
        return system, key, None
    rows, rated, findings = [], [], []
    mssl, mssl_days, issuer_days = None, None, None
    if not unavailable(mssl_item):
        info = json_of(mssl_item) or {}
        found = pem_certs(info.get("cert"))
        mssl = found[0] if found else {"subject": cn(info.get("subject_dn")), "issuer": cn(info.get("issuer_dn")),
                                       "not_after": when(info.get("valid_to")), "sha256": ""}
        d = mssl_days = days_left(mssl["not_after"], now)
        st = rate(d, warn, fail)
        rated.append((st, mssl["not_after"], d))
        rows.append(["Machine SSL (vCenter on port 443)", mssl["subject"], mssl["issuer"], day(mssl["not_after"]), d, label(st, d)])
        if st in ("warn", "fail"):
            findings.append(("Machine SSL", mssl, d))
    old, roots = 0, []
    chains = CertInventory.chains(data)
    for i, chain in enumerate(chains):
        item = source(data, f"root_{i}")
        if unavailable(item):
            rows.append([f"Trusted root {chain[:16]}", "-", "-", "-", "-", f"NOT READ: {unavailable(item)[:80]}"])
            continue
        roots += pem_certs("\n".join(pems((json_of(item) or {}).get("cert_chain"))))
    # the CA that issued Machine SSL: by its key / full name; every VMCA root is named CN=CA (linked vCenters, a
    # regenerated root), so a name alone picks the newest of them
    issuer = None
    if mssl:
        found = [c for c in roots if issued_by(mssl, c)] or [c for c in roots if c["subject"] == mssl["issuer"]]
        issuer = max(found, key=lambda c: c["not_after"]) if found else None
    for c in roots:
        d = days_left(c["not_after"], now)
        used = c is issuer
        if used:
            st = rate(d, warn, fail)
            rated.append((st, c["not_after"], d))
            issuer_days = d
            if st in ("warn", "fail"):
                findings.append(("the CA that issued Machine SSL", c, d))
            text = label(st, d)
        else:
            old += 1 if d is not None and d < 0 else 0
            text = "EXPIRED (not in use)" if d is not None and d < 0 else "expires soon (not in use)" if d is not None and d <= warn else "OK"
        rows.append(["Trusted root" + (" (issued Machine SSL)" if used else ""), c["subject"], c["issuer"], day(c["not_after"]), d, text])
    status = worst(*[s for s, _a, _d in rated]) if rated else "info"
    soonest = min(rated, key=lambda x: x[2] if x[2] is not None else 10 ** 6) if rated else (None, None, None)
    r.step(key, title, status,
           (f"Machine SSL: {mssl_days} day(s) left" + (f"; the CA that issued it: {issuer_days} day(s)" if issuer_days is not None else "")
            + ". " if mssl else "Machine SSL not read. ")
           + f"{len(rows) - (1 if mssl else 0)} trusted root certificate(s)"
           + (f", {old} expired and not in use (listed only: remove it once nothing is signed by it)" if old else "") + ". "
           + (f"Only the first {MAX_CHAINS} of {len(listed(roots_item))} trusted root chains were read. "
              if len(listed(roots_item)) > MAX_CHAINS else "")
           + "The Solution User certificates are not in the API: they are read on the appliance (vecs-cli, KB 421381).",
           {"columns": COLUMNS, "rows": by_days(rows)}, marks=[c["subject"] for _w, c, _d in findings])
    if findings:
        r.recommend("The Machine SSL certificate of vCenter, or the CA that issued it, expires soon: the vSphere Client, the "
                    "API and vCloud Director stop trusting vCenter, and vpxd does not start once the issuing CA has expired "
                    "(KB 442815). Renew it through a change request: vSphere Client → Administration → Certificates → "
                    "Certificate Management, or with vCert (KB 385107). Check the Solution User certificates at the same time.",
                    ["/usr/lib/vmware-vmafd/bin/vecs-cli entry list --store MACHINE_SSL_CERT --text | grep -E 'Alias|Not After'",
                     "for s in $(/usr/lib/vmware-vmafd/bin/vecs-cli store list); do echo \"== $s\"; "
                     "/usr/lib/vmware-vmafd/bin/vecs-cli entry list --store \"$s\" --text | grep -E 'Alias|Not After'; done"],
                    warning="Take an offline snapshot of the vCenter first. Acme Prime stays read-only from the portal.",
                    where=f"{vc}, SSH as root (appliance shell)", refs=["vmw-vcenter-certs"],
                    items={"columns": ["Certificate", "Subject", "Expires", "Days left"],
                           "rows": [[w, c["subject"], day(c["not_after"]), d] for w, c, d in findings]})
    return system, key, (len(rows), soonest[1], soonest[2])


def _esxi(r, data, params, ctx, now, warn, fail):
    system, key = "ESXi hosts", "esxi"
    title = "ESXi host certificates"
    vc = ctx.get("vcenter_host") or "<vCenter>"
    item = source(data, "esx")
    inv = {} if unavailable(item) else (json_of(item) or {})
    why = unavailable(item) or (inv.get("errors") or {}).get("hostcerts", "")
    if why:
        r.step(key, title, "skip", f"Not read: {why}")
        return system, key, None
    rows, statuses, bad, unread, soonest = [], [], [], [], (None, None)
    for h in inv.get("hostcerts") or []:
        name = str(h.get("name") or h.get("moid") or "?")
        after = when(h.get("not_after"))
        if h.get("error") or after is None:
            unread.append(name)
            rows.append([name, str(h.get("connection") or "-"), "-", "-", "-", "-", "-", f"NOT READ: {str(h.get('error') or 'no expiry')[:80]}"])
            continue
        d = days_left(after, now)
        st = worst(rate(d, warn, fail), ESXI_STATUS.get(str(h.get("status") or ""), "ok"))
        statuses.append(st)
        if soonest[1] is None or d < soonest[1]:
            soonest = (after, d)
        if st != "ok":
            bad.append((name, after, d, str(h.get("status") or "")))
        rows.append([name, str(h.get("connection") or "-"), cn(h.get("subject")), cn(h.get("issuer")), day(after), d,
                     str(h.get("status") or "-"), label(st, d)])
    if not rows:
        r.step(key, title, "skip", "vCenter lists no ESXi host.")
        return system, key, None
    r.step(key, title, worst(*statuses) if statuses else "skip",
           f"{len(rows)} host(s): {len(bad)} with a certificate expiring within {warn} days or flagged by vCenter"
           + (f", {len(unread)} not read (not connected: see the check vCenter health)" if unread else "") + ".",
           {"columns": ["Host", "Connection", "Subject", "Issuer", "Expires", "Days left", "vCenter status", "Status"],
            "rows": by_days(rows, 5)}, marks=[b[0] for b in bad])
    if bad:
        r.recommend("ESXi host certificates expire soon: vCenter cannot reconnect a host with an expired certificate (after a "
                    "reboot or a restart of its agents), and raises \"ESXi Host Certificate Status\". Renew them from vCenter "
                    "(VMCA mode) through a change request: vSphere Client → the host → Configure → System → Certificate → "
                    "Renew, or with PowerCLI below.",
                    ["$cm = Get-View (Get-View ServiceInstance).Content.CertificateManager"]
                    + [f"$cm.CertMgrRefreshCertificates_Task(@((Get-VMHost {b[0]}).ExtensionData.MoRef))" for b in bad[:6]],
                    warning="Acme Prime stays read-only from the portal: an engineer runs this.",
                    where=f"PowerShell with PowerCLI, after: Connect-VIServer -Server {vc}", refs=["vmw-esxi-cert"],
                    items={"columns": ["Host", "Expires", "Days left", "vCenter status"],
                           "rows": [[n, day(a), d, s or "-"] for n, a, d, s in bad]})
    return system, key, (len(rows), soonest[0], soonest[1])


def _nsx(r, data, params, ctx, now, warn, fail):
    system, key = "NSX-T Manager", "nsx"
    title = "NSX-T certificates (trust store)"
    nsx = ctx.get("nsxt_host") or "<NSX Manager>"
    item = source(data, "nsx")
    if unavailable(item):
        r.step(key, title, "skip", f"Not read: {unavailable(item)}")
        return system, key, None
    rows, statuses, bad, unused_soon, soonest = [], [], [], 0, (None, None)
    for c in listed(item, "results"):
        if not isinstance(c, dict):
            continue
        det = c.get("details")
        det = det[0] if isinstance(det, list) and det and isinstance(det[0], dict) else det if isinstance(det, dict) else {}
        after, subject, issuer = when(det.get("not_after")), det.get("subject_cn"), det.get("issuer_cn")
        if after is None:
            found = pem_certs(c.get("pem_encoded"))
            if found:
                after, subject, issuer = found[0]["not_after"], subject or found[0]["subject"], issuer or found[0]["issuer"]
        used = [u for u in c.get("used_by") or [] if isinstance(u, dict)]
        unknown_use = not isinstance(c.get("used_by"), list)   # not in the answer: rated as if used
        services = sorted({str(s) for u in used for s in u.get("service_types") or []})
        d = days_left(after, now)
        name = str(c.get("display_name") or c.get("id") or "?")
        if used or unknown_use:
            st = rate(d, warn, fail)
            statuses.append(st)
            if d is not None and (soonest[1] is None or d < soonest[1]):
                soonest = (after, d)
            if st in ("warn", "fail"):
                bad.append((name, str(c.get("id") or ""), after, d, ", ".join(services) or ("unknown" if unknown_use else "-")))
            text = label(st, d)
        else:
            unused_soon += 1 if d is not None and d <= warn else 0
            text = "EXPIRED (not in use)" if d is not None and d < 0 else "expires soon (not in use)" if d is not None and d <= warn else "not in use"
        rows.append([name, str(subject or "-"), str(issuer or "-"), day(after), d,
                     (f"{', '.join(services) or 'used'} on {len(used)} node(s)" if used else "unknown" if unknown_use else "-"), text])
    if not rows:
        r.step(key, title, "skip", "NSX Manager lists no certificate.")
        return system, key, None
    r.step(key, title, worst(*statuses) if statuses else "ok",
           f"{len(rows)} certificate(s), {len(statuses)} in use: {len(bad)} of them expiring within {warn} days"
           + (f"; {unused_soon} unused certificate(s) expiring or expired (listed only)" if unused_soon else "") + ".",
           {"columns": ["Certificate", "Subject", "Issuer", "Expires", "Days left", "Used by", "Status"], "rows": by_days(rows)},
           marks=[b[0] for b in bad])
    if bad:
        r.recommend("NSX certificates in use expire soon: an expired APH / transport node certificate disconnects the hosts "
                    "and edges (MPA connectivity down, KB 424553), an expired cluster or API certificate breaks the UI, the "
                    "API and vCloud Director. Replace each one through a change request: NSX Manager → System → Certificates "
                    "(import or generate the new one, then replace it on its service); the internal APH / CBM certificates "
                    "with the procedure of the KB.",
                    [f"curl -sk -u \"$NSX_USER\" 'https://{nsx}/api/v1/trust-management/certificates/{i}?details=true'"
                     for _n, i, _a, _d, _s in bad[:4] if ID_RE.match(i)] + ["get certificate api   # NSX Manager CLI",
                                                                           "get certificate cluster"],
                    warning="Acme Prime stays read-only from the portal: an engineer runs this.",
                    where=f"{nsx}: curl from a jump host (asks for the password), the CLI as admin on the manager", refs=["nsx-certs"],
                    items={"columns": ["Certificate", "Expires", "Days left", "Used by"],
                           "rows": [[n, day(a), d, s] for n, _i, a, d, s in bad]})
    return system, key, (len(rows), soonest[0], soonest[1])


def _vcd_library(r, data, params, ctx, now, warn, fail):
    system, key = "vCloud Director library", "vcdlib"
    title = "vCloud Director certificate library"
    vcd = ctx.get("vcd_host") or "<vCloud Director>"
    item = source(data, "library")
    if unavailable(item):
        r.step(key, title, "skip", f"Not read: {unavailable(item)}")
        return system, key, None
    expiring = {str(x.get("id")): i for i, x in enumerate(CertInventory.expiring_library(data, params, ctx))}
    rows, statuses, bad, soonest = [], [], [], (None, None)
    for x in listed(item, "values"):
        if not isinstance(x, dict):
            continue
        found = pem_certs(x.get("certificate"))
        c = found[0] if found else {"subject": "-", "issuer": "-", "not_after": None}
        d = days_left(c["not_after"], now)
        alias = str(x.get("alias") or x.get("id") or "?")
        consumers, used = "-", True
        if str(x.get("id")) in expiring:
            ci = source(data, f"consumers_{expiring[str(x.get('id'))]}")
            answer = None if unavailable(ci) else json_of(ci)
            values = answer.get("values") if isinstance(answer, dict) else answer if isinstance(answer, list) else None
            if not isinstance(values, list):   # not read, or an answer of another shape: rated as if used
                consumers = "not read"
            else:
                names = [str(u.get("name") or u.get("displayName") or u.get("id") or "?") for u in values if isinstance(u, dict)]
                used = bool(names)
                consumers = f"{len(names)}: {', '.join(names[:3])}" if names else "none"
        if used:
            st = rate(d, warn, fail)
            statuses.append(st)
            if d is not None and (soonest[1] is None or d < soonest[1]):
                soonest = (c["not_after"], d)
            if st in ("warn", "fail"):
                bad.append((alias, c["not_after"], d, consumers))
            text = label(st, d)
        else:
            text = "EXPIRED (not in use)" if d is not None and d < 0 else "expires soon (not in use)"
        rows.append([alias, c["subject"], c["issuer"], day(c["not_after"]), d, consumers, text])
    if not rows:
        r.step(key, title, "ok", "The certificate library is empty.")
        return system, key, (0, None, None)
    total = (json_of(item) or {}).get("resultTotal") if isinstance(json_of(item), dict) else None
    r.step(key, title, worst(*statuses) if statuses else "ok",
           f"{len(rows)} certificate(s): {len(bad)} in use (or whose consumers could not be read) expiring within {warn} days."
           + (f" Only the first {len(rows)} of {total} were read." if isinstance(total, int) and total > len(rows) else ""),
           {"columns": ["Alias", "Subject", "Issuer", "Expires", "Days left", "Consumers", "Status"], "rows": by_days(rows)},
           marks=[b[0] for b in bad])
    if bad:
        r.recommend("Certificates of the vCloud Director certificate library expire soon while in use (cell endpoints such as "
                    "the console proxy, load balancers and IPsec of tenant edges): those services fail once they expire. "
                    "Import the renewed certificate in Administration → Certificate Management → Certificates Library, then "
                    "point each consumer at it, through a change request.", [],
                    warning="Acme Prime stays read-only from the portal: an engineer does this.",
                    where=f"vCloud Director provider portal ({vcd})", refs=["vcd-certs"],
                    items={"columns": ["Alias", "Expires", "Days left", "Consumers"],
                           "rows": [[a, day(e), d, c] for a, e, d, c in bad]})
    return system, key, (len(rows), soonest[0], soonest[1])


def _vcd_trust(r, data, params, ctx, now, warn, fail):
    system, key = "vCloud Director trust", "vcdtrust"
    title = "vCloud Director trusted certificates (trust after a renewal)"
    vcd = ctx.get("vcd_host") or "<vCloud Director>"
    item = source(data, "trusted")
    if unavailable(item):
        r.step(key, title, "skip", f"Not read: {unavailable(item)}")
        return system, key, None
    leafs = []
    for x in listed(item, "values"):
        found = pem_certs(x.get("certificate")) if isinstance(x, dict) else []
        if found:
            leafs.append((str(x.get("alias") or x.get("id") or "?"), found[0]))
    fps = {c["sha256"] for _a, c in leafs}
    expired = [a for a, c in leafs if (days_left(c["not_after"], now) or 0) < 0]
    rows, drift = [], []
    for i, (name, address) in enumerate(CertInventory.live(ctx)):
        li = source(data, f"live_{i}")
        live = {} if unavailable(li) else (json_of(li) or {})
        if not live.get("ok"):
            rows.append([name, address, "-", "-", f"not read: {(live.get('error') or unavailable(li) or 'no answer')[:100]}"])
            continue
        subject, issuer, fp = str(live.get("subject") or ""), str(live.get("issuer") or ""), str(live.get("sha256") or "")
        # full names and key identifiers when the reader gives them (several CAs are named CN=CA), else the common names
        same_name = (lambda c: c["subject_dn"] == live["subject_dn"]) if live.get("subject_dn") else \
            (lambda c: c["subject"].lower() == subject.lower())
        signed_by = (lambda c: issued_by({"aki": live.get("aki"), "issuer_dn": live.get("issuer_dn")}, c)) \
            if live.get("issuer_dn") else (lambda c: c["subject"].lower() == issuer.lower())
        if fp and fp in fps:
            verdict = "trusted (this certificate)"
        elif not live.get("self_signed") and any(signed_by(c) for _a, c in leafs):
            verdict = f"trusted through its CA {issuer}"
        elif any(same_name(c) for _a, c in leafs):
            verdict = "AN OLDER CERTIFICATE IS TRUSTED (same name, other fingerprint)"
            drift.append((name, address, subject))
        else:
            verdict = "not in the trusted certificates (vCloud Director may reach it under another name)"
        rows.append([name, address, subject, str(live.get("not_after") or "")[:10], verdict])
    detail = (f"{len(leafs)} trusted certificate(s)" + (f", {len(expired)} expired (remove them once their system presents a new one)"
                                                        if expired else "") + ". ")
    compared = [x for x in rows if not str(x[4]).startswith("not read")]
    if drift:
        detail += f"vCloud Director still trusts an older certificate of: {', '.join(n for n, _a, _s in drift)}."
    elif compared:
        detail += "The certificate vCenter and NSX-T present now was compared with them."
    else:
        detail += ("Not compared: the certificate vCenter / NSX-T present could not be read from the portal server."
                   if rows else "Not compared: no vCenter / NSX-T address for this site.")
    total = (json_of(item) or {}).get("resultTotal") if isinstance(json_of(item), dict) else None
    if isinstance(total, int) and total > len(listed(item, "values")):
        detail += f" Only the first {len(listed(item, 'values'))} of {total} trusted certificates were read."
    if rows:
        table = {"columns": ["System", "Address", "Presents now", "Expires", "In vCloud Director"], "rows": rows}
    else:
        table = {"columns": ["Alias", "Subject", "Expires", "Days left"],
                 "rows": by_days([[a, c["subject"], day(c["not_after"]), days_left(c["not_after"], now)] for a, c in leafs], 3)}
    r.step(key, title, "warn" if drift else "ok" if compared else "info", detail, table, marks=[n for n, _a, _s in drift])
    if drift:
        r.recommend("vCloud Director trusts an older certificate of a system than the one it presents now: after a renewal "
                    "vCloud Director keeps the old one and its connection to that system fails (\"PKIX path building "
                    "failed\"; subscribed catalogs stop syncing), unless it trusts a CA above the one that issued the new "
                    "certificate. Trust the new certificate, through a change request: "
                    "Administration → Trusted Certificates → Import, or refresh the registration of the vCenter / NSX-T "
                    "Manager (Infrastructure Resources: accept the new certificate).", [],
                    warning="Acme Prime stays read-only from the portal: an engineer does this.",
                    where=f"vCloud Director provider portal ({vcd})", refs=["vcd-certs"],
                    items={"columns": ["System", "Address", "Presents now"], "rows": [list(x) for x in drift]})
    return system, key, (len(leafs), None, None)


def _ontap(r, data, params, ctx, now, warn, fail):
    system, key = "ONTAP", "ontap"
    title = "ONTAP certificates (cluster and SVMs)"
    host = ctx.get("ontap_host") or "<ONTAP cluster>"
    item = source(data, "ontap")
    if unavailable(item):
        r.step(key, title, "skip", f"Not read: {unavailable(item)}")
        return system, key, None
    rows, statuses, bad, anchors, anchors_old, soonest = [], [], [], 0, 0, (None, None)
    cluster = "" if unavailable(source(data, "cluster")) else str((json_of(source(data, "cluster")) or {}).get("name") or "")
    for x in listed(item, "records"):
        if not isinstance(x, dict):
            continue
        kind = str(x.get("type") or "")
        after = when(x.get("expiry_time"))
        d = days_left(after, now)
        # a certificate of the cluster belongs to the admin SVM, named as the cluster (as security certificate show lists it)
        svm = str((x.get("svm") or {}).get("name") or "") or (cluster or "cluster" if x.get("scope") == "cluster" else "-")
        common = str(x.get("common_name") or "-")
        if kind in RATED_ONTAP:
            st = rate(d, warn, fail)
            statuses.append(st)
            if d is not None and (soonest[1] is None or d < soonest[1]):
                soonest = (after, d)
            if st in ("warn", "fail"):
                bad.append((str(x.get("name") or common), svm, kind, common, after, d))
            rows.append([str(x.get("name") or "-"), svm, kind, common, day(after), d, label(st, d)])
        else:
            anchors += 1
            if d is not None and d <= warn:
                anchors_old += 1
                rows.append([str(x.get("name") or "-"), svm, kind, common, day(after), d,
                             "EXPIRED (trust anchor)" if d < 0 else "expires soon (trust anchor)"])
    if not statuses and not anchors:
        r.step(key, title, "skip", "ONTAP lists no certificate.")
        return system, key, None
    r.step(key, title, worst(*statuses) if statuses else "ok",
           f"{len(statuses)} server / client certificate(s): {len(bad)} expire within {warn} days. {anchors} trust anchor(s) "
           f"(root_ca / client_ca, most installed with ONTAP) are not rated" + (f"; {anchors_old} of them expire soon or have "
                                                                                 "expired (listed)" if anchors_old else "") + ".",
           {"columns": ["Certificate", "SVM", "Type", "Common name", "Expires", "Days left", "Status"], "rows": by_days(rows, 5)},
           marks=[b[3] for b in bad])
    if bad:
        servers = [b for b in bad if b[2] == "server"]
        r.recommend("ONTAP certificates expire soon: ONTAP makes its server certificates self-signed for one year, and once "
                    "one expires the clients that verify it (System Manager, the Cinder driver with TLS verification, ONTAP "
                    "Restore) refuse to connect. Create a new certificate and enable it, through a change request (NetApp KB).",
                    ["security certificate show -fields vserver,common-name,serial,ca,type,expiration -type server"]
                    + [f"security certificate create -vserver {svm if svm not in ('-', 'cluster') else '<cluster name>'} "
                       f"-common-name {common} -type server -size 2048 -expire-days 365 -hash-function SHA256"
                       for _n, svm, _k, common, _a, _d in servers[:4]]
                    + [f"security ssl modify -vserver {svm if svm not in ('-', 'cluster') else '<cluster name>'} -server-enabled true "
                       "-ca <ca of the new certificate> -serial <serial of the new certificate>"
                       for _n, svm, _k, _c, _a, _d in servers[:4]] if servers else
                    ["security certificate show -fields vserver,common-name,serial,ca,type,expiration"],
                    warning="Clients that pinned the old certificate (or trust it by fingerprint) must be given the new one.",
                    where=f"the cluster shell of {host} (ssh admin)", refs=["ontap-certs"],
                    items={"columns": ["Certificate", "SVM", "Type", "Common name", "Expires", "Days left"],
                           "rows": [[n, s, k, c, day(a), d] for n, s, k, c, a, d in bad]})
    return system, key, (len(statuses) + anchors, soonest[0], soonest[1])


# ---------------------------------------------------------------- certmonger (Acme Flex)
def parse_getcert(text):
    """`getcert list` -> [{"id", "status", "stuck", "ca", "subject", "expires", "file", "auto_renew", "ca_error"}]."""
    out, cur = [], None
    for line in str(text or "").splitlines():
        m = re.match(r"^Request ID '([^']*)':", line)
        if m:
            cur = {"id": m.group(1), "status": "", "stuck": "", "ca": "", "subject": "", "expires": "", "file": "",
                   "auto_renew": "", "ca_error": ""}
            out.append(cur)
            continue
        m = re.match(r"^\s+(status|stuck|ca-error|CA|subject|expires|certificate|auto-renew):\s?(.*)$", line)
        if not m or cur is None:
            continue
        field, value = m.group(1), m.group(2).strip()
        if field == "certificate":
            loc, nick = re.search(r"location='([^']*)'", value), re.search(r"nickname='([^']*)'", value)
            cur["file"] = (loc.group(1) if loc else value) + (f" ({nick.group(1)})" if nick else "")
        else:
            cur[{"ca-error": "ca_error", "CA": "ca", "auto-renew": "auto_renew"}.get(field, field)] = value
    return out


def node_requests(item):
    """("read" | "absent" | "unread", requests, reason) of the getcert read of one machine."""
    out = str(item.get("out") or "")
    if overcloud.NO_CERTMONGER in out or ("command not found" in out and "getcert" in out):
        return "absent", [], "certmonger is not installed"
    if unavailable(item):
        return "unread", [], unavailable(item)
    return "read", parse_getcert(out), ""


def rate_request(req, now, warn, fail):
    """(rating, days left) of one certmonger request: a CA problem or stuck = fail; another status than MONITORING = warn."""
    d = days_left(when(req["expires"]), now)
    # no expiry (not issued yet) or one that could not be read: listed as UNKNOWN, not rated OK
    st = rate(d, warn, fail) if d is not None else "info" if req["expires"] and req["expires"] != "unknown" else "ok"
    status = req["status"].upper()
    if status in BAD_GETCERT or req["stuck"] == "yes":
        st = "fail"
    elif status and status != "MONITORING":
        st = worst(st, "warn")
    return st, d


class CertmongerStatus:
    """certmonger on the director and on the overcloud nodes: every certificate it tracks, its status (only MONITORING is
    healthy) and its expiry; the requests of the nodes that need it can be resubmitted from the portal."""
    sources = ("undercloud", "overcloud")
    phases = 2

    @staticmethod
    def _targets(data, params, ctx):
        found, controllers, user, version, problem = inventory(data, ctx)
        role = params.get("role") or "controller"
        if role == "all":
            targets = found
        elif role == "compute":
            targets = [n for n in found if n["role"] == "compute"]
        else:
            targets = controllers
        if found and role != "controller":
            problem = ""   # no controller needed
        return targets[:MAX_NODES], user, version, problem, len(targets)

    @staticmethod
    def reads(phase, data, params, ctx):
        if phase == 1:
            return {"undercloud": dict(overcloud.INVENTORY_READS, uc_getcert="sudo -n getcert list")}
        targets, user, _v, problem, _total = CertmongerStatus._targets(data, params, ctx)
        if problem or not targets:
            return {}
        return {"overcloud": {f"use_getcert_{i}": overcloud.read(n["name"], n["ip"], user, "getcert") for i, n in enumerate(targets)}}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("certmonger-status")
        warn, fail = thresholds(params)
        now = now_of(ctx)
        columns = ["Request ID", "Certificate", "Subject", "CA", "certmonger status", "Expires", "Days left", "Auto-renew", "Status"]

        def row(req, st, d):
            status = req["status"] + (" (stuck)" if req["stuck"] == "yes" else "") + (f": {req['ca_error'][:80]}" if req["ca_error"] else "")
            return [req["id"], req["file"] or "-", cn(req["subject"]) or "-", req["ca"] or "-", status or "-",
                    str(req["expires"])[:10] or "-", d if d is not None else "-", req["auto_renew"] or "-", label(st, d)]

        # ---------------- the director
        state, reqs, why = node_requests(source(data, "uc_getcert"))
        uc_bad = []
        if state == "unread":
            r.step("undercloud", "Director (undercloud): certmonger certificates", "skip", f"Not read: {why}")
        elif state == "absent" or not reqs:
            r.step("undercloud", "Director (undercloud): certmonger certificates", "info",
                   "certmonger is not installed on the director." if state == "absent" else "certmonger tracks no certificate on the director.")
        else:
            rows, statuses = [], []
            for q in reqs:
                st, d = rate_request(q, now, warn, fail)
                statuses.append(st)
                if st in ("warn", "fail"):
                    uc_bad.append((q, st, d))
                rows.append(row(q, st, d))
            r.step("undercloud", "Director (undercloud): certmonger certificates", worst(*statuses),
                   f"{len(reqs)} certificate(s): {len(uc_bad)} with a CA problem or expiring within {warn} days.",
                   {"columns": columns, "rows": by_days(rows, 6)}, marks=[q["id"] for q, _s, _d in uc_bad])
            if uc_bad:
                r.recommend("Certificates of the director expire soon or certmonger cannot renew them: the undercloud API and "
                            "the director commands fail once they expire. A certificate of the director's local CA is not "
                            "always renewed by certmonger by itself (Red Hat 5508191): resubmit it, then check its new expiry.",
                            [f"sudo getcert resubmit -i {q['id']}" for q, _s, _d in uc_bad[:4]]
                            + [f"sudo getcert list -i {q['id']}" for q, _s, _d in uc_bad[:2]],
                            where="OpenStack director, as stack", refs=["rhosp-undercloud-cert", "rhosp-tlse"],
                            items={"columns": ["Request ID", "Certificate", "certmonger status", "Days left"],
                                   "rows": [[q["id"], q["file"], q["status"], d if d is not None else "-"] for q, _s, d in uc_bad]})
        # ---------------- the overcloud nodes
        targets, user, version, problem, total = CertmongerStatus._targets(data, params, ctx)
        if problem or not targets:
            r.step("nodes", "Overcloud nodes", "fail" if problem else "skip", problem or "No node of this role.")
            return r.done()
        nrows, down, absent, all_rows, statuses, bad = [], [], [], [], [], []
        for i, n in enumerate(targets):
            state, reqs, why = node_requests(source(data, f"use_getcert_{i}"))
            if state == "unread":
                down.append(n["name"])
                nrows.append([n["name"], n["ip"], n["role"], why[:160]])
                continue
            if state == "absent":
                absent.append(n["name"])
                nrows.append([n["name"], n["ip"], n["role"], "reached: certmonger is not installed"])
                continue
            nrows.append([n["name"], n["ip"], n["role"], f"reached: {len(reqs)} certificate(s) tracked"])
            for q in reqs:
                st, d = rate_request(q, now, warn, fail)
                statuses.append(st)
                if st in ("warn", "fail"):
                    bad.append((n, q, st, d))
                all_rows.append([n["name"]] + row(q, st, d))
        r.step("nodes", "Nodes reached from the director", "fail" if len(down) == len(targets) else "warn" if down else "ok",
               f"{len(targets) - len(down)} of {len(targets)} node(s) answered as {user}" + (f" (RHOSP {version})" if version else "") + "."
               + (f" Only the first {len(targets)} of {total} nodes are read in one run: choose Controllers or Computes, or run "
                  "it again for the others." if total > len(targets) else ""),
               {"columns": ["Node", "ctlplane", "Role", "certmonger"], "rows": nrows}, marks=down)
        if not all_rows:
            if len(down) < len(targets):
                r.step("requests", "Overcloud: certmonger certificates", "info",
                       "No node reached tracks a certificate with certmonger: TLS everywhere is not used on this overcloud. The "
                       "certificate of the public endpoint is checked by \"Certificates expiring\".")
            return r.done()
        order = {"fail": 0, "warn": 1, "info": 2, "ok": 3}
        all_rows.sort(key=lambda x: (order.get({"FAIL": "fail", "EXPIRED": "fail", "WARN": "warn"}.get(x[-1], "ok"), 3),
                                     x[7] if isinstance(x[7], int) else 10 ** 6))
        ca_bad = [(n, q, d) for n, q, st, d in bad if q["status"].upper() in BAD_GETCERT or q["stuck"] == "yes"]
        soon = [(n, q, d) for n, q, st, d in bad if (n, q, d) not in ca_bad]
        r.step("requests", "Overcloud: certmonger certificates", worst(*statuses),
               f"{len(all_rows)} certificate(s) on {len(targets) - len(down) - len(absent)} node(s): {len(ca_bad)} that certmonger "
               f"cannot renew (CA problem or stuck), {len(soon)} expiring within {warn} days or not MONITORING.",
               {"columns": ["Node"] + columns, "rows": all_rows}, marks=[q["id"] for _n, q, _s, _d in bad])
        # ---- the fix: the operator ticks the requests to resubmit (wi_ops.py getcert-resubmit, one request at a time)
        picks = sorted(bad, key=lambda x: x[3] if x[3] is not None else 10 ** 6)
        items = []
        for n, q, _st, _d in picks:
            usable = bool(REQUEST_RE.match(q["id"])) and user in overcloud.USERS
            items.append({"label": f"{q['id']} on {n['name']} ({q['file'] or '-'})",
                          "commands": [f"getcert-resubmit {q['id']} node {n['name']}={n['ip']} user {user}"] if usable else [],
                          "default": (n, q, _d) not in ca_bad,   # IdM first: a CA problem is not renewed by a resubmit
                          "disabled": "" if usable else "request ID or overcloud user not usable"})
        r.recommend("Renew the certificates that expire soon or that certmonger has not renewed: the portal resubmits each "
                    "ticked request to its CA (IdM) on its node and follows it until certmonger monitors the new certificate; "
                    "the post-save command of each request reloads the service that uses it. Requests certmonger cannot renew "
                    "(CA_UNREACHABLE, CA_REJECTED, stuck) are not ticked: fix the reach to IdM first (below).",
                    [f"sudo getcert resubmit -i {q['id']}   # {n['name']}" for n, q, _s, _d in picks[:8]],
                    warning="The node gets a new certificate and the service that uses it reloads (its clients reconnect).",
                    where=f"each node, as {user} with sudo (from the director: ssh {user}@<its ctlplane address>)",
                    refs=["rhosp-tlse"],
                    items={"columns": ["Node", "Request ID", "Certificate", "certmonger status", "Days left"],
                           "rows": [[n["name"], q["id"], q["file"] or "-", q["status"] or "-", d if d is not None else "-"]
                                    for n, q, _s, d in picks]},
                    action=os_select(items, target=", ".join(sorted({n["name"] for n, _q, _s, _d in picks})),
                                     label="Resubmit the ticked certificates", noun="certificates", lock="certmonger",
                                     stop_on_failure=False, item_timeout=600, max_items=40))
        nodes = {}
        for n, q, d in ca_bad:
            nodes.setdefault(n["name"], (n, []))[1].append((q, d))
        for name, (n, ca) in list(nodes.items())[:6]:
            r.recommend(f"certmonger on {name} cannot renew some certificates (its CA, IdM, is unreachable or refuses them): "
                        "they will not be renewed, and once they expire the services that use them (RabbitMQ, MySQL, "
                        "OVN, the APIs) fail the TLS handshake. Check that the node reaches IdM and that its host keytab is "
                        "valid, then resubmit them (the fix above).",
                        [f"sudo getcert list -i {q['id']}   # the ca-error" for q, _d in ca[:2]]
                        + ["sudo kinit -k -t /etc/krb5.keytab && sudo klist"]
                        + [f"sudo getcert resubmit -i {q['id']}" for q, _d in ca[:4]],
                        where=f"{name}, as {user} with sudo (from the director: ssh {user}@{n['ip']})", refs=["rhosp-tlse"],
                        items={"columns": ["Request ID", "Certificate", "certmonger status", "Days left"],
                               "rows": [[q["id"], q["file"], q["status"], d if d is not None else "-"] for q, d in ca]})
        return r.done()
