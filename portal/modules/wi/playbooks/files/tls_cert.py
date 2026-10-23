#!/usr/bin/env python3
"""The TLS certificate each address presents (Operation Automation, check "Certificates expiring"):

    tls_cert.py host:port [host:port ...]

Opens a TLS connection (no sign-in, nothing sent after the handshake), takes the certificate without verifying it
(self-signed BMC / vCenter certificates are read too) and prints one JSON document:
    {"host:port": {"ok": true, "subject", "issuer", "not_after", "days_left", "self_signed", "san"} | {"ok": false, "error"}}
"""
import datetime
import json
import re
import socket
import ssl
import sys

TARGET = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]{0,252}):(\d{1,5})$")


def name_of(name):
    from cryptography.x509.oid import NameOID
    cn = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return cn[0].value if cn else name.rfc4514_string()


def read(host, port):
    from cryptography import x509
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=8) as sock:
        with ctx.wrap_socket(sock, server_hostname=host if not re.match(r"^[0-9.]+$", host) else None) as tls:
            der = tls.getpeercert(binary_form=True)
    cert = x509.load_der_x509_certificate(der)
    after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    now = datetime.datetime.now(datetime.timezone.utc)
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)[:5]
    except x509.ExtensionNotFound:
        san = []
    return {"ok": True, "subject": name_of(cert.subject), "issuer": name_of(cert.issuer), "not_after": after.isoformat(),
            "days_left": (after - now).days, "self_signed": cert.subject == cert.issuer, "san": san}


def main():
    out = {}
    for target in sys.argv[1:]:
        m = TARGET.match(target)
        if not m:
            out[target] = {"ok": False, "error": "not host:port"}
            continue
        try:
            out[target] = read(m.group(1), int(m.group(2)))
        except Exception as e:   # unreachable, not TLS, refused: the reason is the finding
            out[target] = {"ok": False, "error": f"{type(e).__name__}: {e}"[:200]}
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
