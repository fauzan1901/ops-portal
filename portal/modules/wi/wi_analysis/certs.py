"""Certificates of the systems of a site (platform health, not from a KB page): vCenter, NSX-T Manager, vCloud Director,
ONTAP, Horizon / the OpenStack public endpoint, and every BMC of the page BMC. The portal server opens a TLS connection
to each address and reads the certificate it presents (no account, nothing sent after the handshake)."""
import re

from .common import Result, source, unavailable, worst

TARGET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,252}:\d{1,5}$")


def target(address, default_port=443):
    """'host', 'host:port' or a URL -> 'host:port' ('' when not usable)."""
    text = re.sub(r"^[a-z]+://", "", str(address or "").strip()).split("/")[0]
    if not text:
        return ""
    if not re.search(r":\d+$", text):
        text = f"{text}:{default_port}"
    return text if TARGET.match(text) else ""


class CertExpiry:
    sources = ("tls",)
    phases = 1

    @staticmethod
    def _targets(ctx):
        out = []
        for label, key in (("vCenter", "vcenter_host"), ("NSX-T Manager", "nsxt_host"), ("vCloud Director", "vcd_host"),
                           ("ONTAP", "ontap_host"), ("Horizon / OpenStack public endpoint", "horizon_host")):
            t = target(ctx.get(key))
            if t:
                out.append((label, t))
        for name, address, port in ctx.get("bmc_targets") or []:
            t = target(f"{address}:{port}")
            if t:
                out.append((f"BMC {name}", t))
        return out[:200]

    @staticmethod
    def reads(phase, data, params, ctx):
        return {"tls": {f"t{i}": t for i, (_label, t) in enumerate(CertExpiry._targets(ctx))}}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("cert-expiry")
        warn = int(params["warn_days"]) if params.get("warn_days") is not None else 30
        fail = int(params["fail_days"]) if params.get("fail_days") is not None else 7   # 0 is a valid choice
        targets = CertExpiry._targets(ctx)
        if not targets:
            r.step("certs", "Certificates", "skip", "No system with an address on this site (sites.yml, Administration → Credentials, page BMC).")
            return r.done()
        rows, statuses, soon, unreachable = [], [], [], []
        for i, (label, t) in enumerate(targets):
            item = source(data, f"t{i}")
            c = item.get("json") if isinstance(item.get("json"), dict) else {}
            if unavailable(item) or not c.get("ok"):
                unreachable.append((label, t, c.get("error") or unavailable(item)))
                rows.append([label, t, "-", "-", "-", "-", "NOT READ"])
                continue
            days = c.get("days_left")
            st = "fail" if days is None or days <= fail else "warn" if days <= warn else "ok"
            statuses.append(st)
            if st != "ok":
                soon.append((label, t, c))
            rows.append([label, t, str(c.get("not_after") or "")[:10], days, c.get("subject") or "",
                         (c.get("issuer") or "") + (" (self-signed)" if c.get("self_signed") else ""),
                         "EXPIRED" if days is not None and days < 0 else st.upper()])
        r.step("certs", f"Certificates expiring within {warn} days", worst(*statuses) if statuses else "skip",
               f"{len(targets)} address(es); {len(soon)} expiring within {warn} days, {len(unreachable)} not read.",
               {"columns": ["System", "Address", "Expires", "Days left", "Subject", "Issuer", "Status"],
                "rows": sorted(rows, key=lambda x: (x[3] if isinstance(x[3], int) else 99999))},
               marks=[x[1] for x in rows if x[6] in ("FAIL", "EXPIRED", "WARN")])
        if unreachable:
            r.step("unreachable", "Addresses the portal could not read", "info",
                   "No TLS answer from the portal server (route, firewall, or the service is down).",
                   {"columns": ["System", "Address", "Reason"], "rows": [[a, b, c] for a, b, c in unreachable]})
        for label, t, c in soon:
            how = ("vSphere Client: Administration → Certificates → Certificate Management (machine SSL certificate)"
                   if label == "vCenter" else "NSX Manager: System → Certificates (import the new one, then replace)"
                   if label.startswith("NSX") else "the certificate store of the BMC web page (or its management tool)"
                   if label.startswith("BMC") else "the certificate procedure of this system")
            r.recommend(f"The certificate of {label} ({t}) expires in {c.get('days_left')} day(s), on {str(c.get('not_after'))[:10]}: "
                        f"after that, browsers and API clients (the portal too) refuse the connection. Renew it with {how}, "
                        "through a change request.", [], where=label)
        return r.done()
